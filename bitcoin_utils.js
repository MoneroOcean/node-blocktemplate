const bech32 = require('bech32');
const crypto = require('crypto');
const varuint = require('varuint-bitcoin');

const ADVANCED_TRANSACTION_MARKER = 0x00;
const ADVANCED_TRANSACTION_FLAG = 0x01;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEXES = new Map(Array.from(BASE58_ALPHABET, (char, index) => [char, index]));
const MAX_BASE58_ADDRESS_LENGTH = 128;
const MAX_BECH32_ADDRESS_LENGTH = 128;
const UINT64_MAX = (1n << 64n) - 1n;

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

function hash256(buffer) {
  return sha256(sha256(buffer));
}

function packInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeInt32LE(num, 0);
  return buff;
}

function packUInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeUInt32LE(num, 0);
  return buff;
}

function packUInt64LE(value) {
  const amount = BigInt(value);
  if (amount < 0n || amount > UINT64_MAX) throw new Error('Invalid uint64 value');
  const buff = Buffer.alloc(8);
  buff.writeUInt32LE(Number(amount & 0xffffffffn), 0);
  buff.writeUInt32LE(Number(amount >> 32n), 4);
  return buff;
}

function varIntBuffer(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('Invalid varint value');
  return varuint.encode(n, Buffer.alloc(varuint.encodingLength(n)), 0);
}

function decodeBase58Check(value) {
  if (typeof value !== 'string' || value.length > MAX_BASE58_ADDRESS_LENGTH) throw new Error('Base58 address too long');

  let num = 0n;
  for (const char of value) {
    const index = BASE58_INDEXES.get(char);
    if (index === undefined) throw new Error('Invalid base58 character');
    num = (num * 58n) + BigInt(index);
  }

  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = `0${  hex}`;
  let decoded = hex === '00' ? Buffer.alloc(0) : Buffer.from(hex, 'hex');

  let leadingZeros = 0;
  while (leadingZeros < value.length && value[leadingZeros] === '1') leadingZeros++;
  if (leadingZeros > 0) decoded = Buffer.concat([Buffer.alloc(leadingZeros), decoded]);

  if (decoded.length < 5) throw new Error('Invalid base58check payload');
  const payload = decoded.subarray(0, -4);
  const checksum = decoded.subarray(-4);
  const expectedChecksum = hash256(payload).subarray(0, 4);
  if (!crypto.timingSafeEqual(checksum, expectedChecksum)) throw new Error('Invalid base58check checksum');
  return decoded;
}

function p2pkhScript(pubkeyHash) {
  if (!Buffer.isBuffer(pubkeyHash) || pubkeyHash.length !== 20) throw new Error('Invalid pubkey hash');
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pubkeyHash, Buffer.from([0x88, 0xac])]);
}

function base58AddressToHash160(addr) {
  const decoded = decodeBase58Check(addr);
  if (decoded.length !== 25) throw new Error('Invalid base58 address');
  return decoded.slice(1, -4);
}

function addressToScript(addr) {
  if (typeof addr !== 'string') throw new Error('Invalid address');
  if (addr.length > MAX_BECH32_ADDRESS_LENGTH) throw new Error('Invalid address length');

  try {
    return p2pkhScript(base58AddressToHash160(addr));
  } catch (_err) {
    // not base58check; fall through to try bech32 decoding below
  }

  let decoded;
  try {
    decoded = Buffer.from(bech32.bech32.fromWords(bech32.bech32.decode(addr).words.slice(1)));
  } catch (_err) {
    throw new Error('Invalid address');
  }
  if (decoded.length !== 20) throw new Error('Invalid address');
  return Buffer.concat([Buffer.from([0x00, 0x14]), decoded]);
}

function serializeTransaction(tx) {
  const inputs = tx.inputs || [];
  const outputs = tx.outputs || [];
  const parts = [
    packInt32LE(tx.version === undefined ? 1 : tx.version),
    varIntBuffer(inputs.length)
  ];

  for (const input of inputs) {
    if (!Buffer.isBuffer(input.hash) || input.hash.length !== 32) throw new Error('Invalid transaction input hash');
    const script = input.script || Buffer.alloc(0);
    parts.push(
      input.hash,
      packUInt32LE(input.index),
      varIntBuffer(script.length),
      script,
      packUInt32LE(input.sequence === undefined ? 0xffffffff : input.sequence)
    );
  }

  parts.push(varIntBuffer(outputs.length));
  for (const output of outputs) {
    const script = output.script || Buffer.alloc(0);
    parts.push(
      packUInt64LE(output.value),
      varIntBuffer(script.length),
      script
    );
  }

  parts.push(packUInt32LE(tx.locktime === undefined ? 0 : tx.locktime));
  return Buffer.concat(parts);
}

function readRawBitcoinTransaction(buffer, offsetArg) {
  let offset = offsetArg;
  const start = offset;
  if (offset + 4 > buffer.length) throw new Error('Unexpected end of transaction version');
  const version = buffer.readInt32LE(offset);
  offset += 4;

  let hasWitnessMarker = false;
  if (offset + 2 <= buffer.length &&
      buffer[offset] === ADVANCED_TRANSACTION_MARKER &&
      buffer[offset + 1] === ADVANCED_TRANSACTION_FLAG) {
    hasWitnessMarker = true;
    offset += 2;
  }

  const inputCount = readRawVarInt(buffer, offset, 'input count');
  offset = inputCount.offset;
  const ins = [];
  for (let i = 0; i < inputCount.value; i++) {
    const hash = readRawSlice(buffer, offset, 32, 'input hash');
    const index = readRawSlice(buffer, hash.offset, 4, 'input index');
    const script = readRawVarSlice(buffer, index.offset, 'input script');
    const sequence = readRawSlice(buffer, script.offset, 4, 'input sequence');
    ins.push({
      hash: hash.value,
      index: index.value.readUInt32LE(0),
      script: script.value,
      sequence: sequence.value.readUInt32LE(0),
      witness: []
    });
    offset = sequence.offset;
  }

  const outputCount = readRawVarInt(buffer, offset, 'output count');
  offset = outputCount.offset;
  const outs = [];
  for (let i = 0; i < outputCount.value; i++) {
    const value = readRawSlice(buffer, offset, 8, 'output value');
    const script = readRawVarSlice(buffer, value.offset, 'output script');
    outs.push({
      valueBuffer: value.value,
      script: script.value
    });
    offset = script.offset;
  }

  const witnessStart = offset;
  if (hasWitnessMarker) {
    for (let i = 0; i < inputCount.value; i++) {
      const witness = readRawWitnessVector(buffer, offset);
      ins[i].witness = witness.value;
      offset = witness.offset;
    }
    if (!ins.some((input) => input.witness.length > 0)) {
      throw new Error('Transaction has superfluous witness data');
    }
  }

  const locktimeStart = offset;
  const locktime = readRawSlice(buffer, offset, 4, 'locktime');
  offset = locktime.offset;

  const rawWithWitness = buffer.slice(start, offset);
  const rawNoWitness = hasWitnessMarker ?
    Buffer.concat([
      buffer.slice(start, start + 4),
      buffer.slice(start + 6, witnessStart),
      buffer.slice(locktimeStart, offset)
    ]) :
    rawWithWitness;

  return {
    transaction: createRawTransactionView(version, ins, outs, locktime.value.readUInt32LE(0), rawWithWitness, rawNoWitness),
    offset
  };
}

function createRawTransactionView(version, ins, outs, locktime, rawWithWitness, rawNoWitness) {
  return {
    version,
    ins,
    outs,
    locktime,
    isCoinbase() {
      return this.ins.length === 1 && isZeroHash(this.ins[0].hash);
    },
    hasWitnesses() {
      return this.ins.some((input) => input.witness && input.witness.length > 0);
    },
    byteLength(allowWitness) {
      return this.__toBuffer(undefined, undefined, allowWitness).length;
    },
    __toBuffer(_buffer, _initialOffset, allowWitness) {
      return allowWitness && this.hasWitnesses() ? rawWithWitness : rawNoWitness;
    }
  };
}

function readRawVarInt(buffer, offset, context) {
  if (offset >= buffer.length) throw new Error(`Unexpected end of transaction ${context}`);
  const value = varuint.decode(buffer, offset);
  if (!Number.isSafeInteger(value)) throw new Error(`Invalid transaction ${context}`);
  return {
    value,
    offset: offset + varuint.decode.bytes
  };
}

function readRawSlice(buffer, offset, size, context) {
  if (size < 0 || offset + size > buffer.length) throw new Error(`Unexpected end of transaction ${context}`);
  return {
    value: buffer.slice(offset, offset + size),
    offset: offset + size
  };
}

function readRawVarSlice(buffer, offset, context) {
  const parsed = readRawVarInt(buffer, offset, `${context} length`);
  return readRawSlice(buffer, parsed.offset, parsed.value, context);
}

function readRawWitnessVector(buffer, offset) {
  const count = readRawVarInt(buffer, offset, 'witness item count');
  let nextOffset = count.offset;
  const vector = [];
  for (let i = 0; i < count.value; i++) {
    const item = readRawVarSlice(buffer, nextOffset, 'witness item');
    vector.push(item.value);
    nextOffset = item.offset;
  }
  return {
    value: vector,
    offset: nextOffset
  };
}

function isZeroHash(buffer) {
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== 0) return false;
  }
  return true;
}

module.exports = {
  ADVANCED_TRANSACTION_FLAG,
  ADVANCED_TRANSACTION_MARKER,
  addressToScript,
  base58AddressToHash160,
  p2pkhScript,
  readRawBitcoinTransaction,
  serializeTransaction,
  varIntBuffer
};
