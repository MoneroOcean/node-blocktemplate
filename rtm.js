const bech32  = require('bech32');
const bitcoin = require('bitcoinjs-lib');
const crypto = require('crypto');

const { BASE_DIFF, difficultyToFloat } = require('./bigint');

const diff1 = BASE_DIFF;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEXES = new Map(Array.from(BASE58_ALPHABET, (char, index) => [char, index]));
const MAX_RECOVERABLE_TRANSACTION_TAIL_BYTES = 64;
// daemon tx count; +1 for the coinbase must stay <= the consumer's 5000 total-tx merkle cap
// (index.js MAX_TEMPLATE_TRANSACTIONS), else a maximally-full template encodes 5001 and the
// merkle parser (convertRtmBlob / constructNewRtmBlob) rejects it -> lost block at that size.
const MAX_RTM_TEMPLATE_TRANSACTIONS = 4999;
const MAX_RTM_TRANSACTION_BYTES = 1024 * 1024;
const MAX_RTM_TEMPLATE_TRANSACTION_BYTES = 64 * 1024 * 1024;

function reverseBuffer(buff) {
  const reversed = Buffer.alloc(buff.length);
  for (let i = buff.length - 1; i >= 0; i--) reversed[buff.length - i - 1] = buff[i];
  return reversed;
}

function packInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeInt32LE(num, 0);
  return buff;
}

function packUInt16LE(num) {
  const buff = Buffer.alloc(2);
  buff.writeUInt16LE(num, 0);
  return buff;
}

function packUInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeUInt32LE(num, 0);
  return buff;
}

function isValidSatoshisAmount(amount) {
  return Number.isSafeInteger(amount) && amount >= 0;
}

function packInt64LE(num){
  if (!isValidSatoshisAmount(num)) throw new Error('Invalid transaction amount');
  const buff = Buffer.alloc(8);
  buff.writeUInt32LE(num % Math.pow(2, 32), 0);
  buff.writeUInt32LE(Math.floor(num / Math.pow(2, 32)), 4);
  return buff;
}

// Defined in bitcoin protocol here:
// https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
function varIntBuffer(n) {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    const buff = Buffer.alloc(3);
    buff[0] = 0xfd;
    buff.writeUInt16LE(n, 1);
    return buff;
  } else if (n <= 0xffffffff) {
    const buff = Buffer.alloc(5);
    buff[0] = 0xfe;
    buff.writeUInt32LE(n, 1);
    return buff;
  } 
    const buff = Buffer.alloc(9);
    buff[0] = 0xff;
    packUInt16LE(n).copy(buff, 1);
    return buff;
  
}

function readVarInt(buffer, offset) {
  if (offset >= buffer.length) throw new Error('Unexpected end of varint');
  const first = buffer[offset];
  if (first < 0xfd) return { value: first, size: 1 };
  if (first === 0xfd) {
    if (offset + 3 > buffer.length) throw new Error('Unexpected end of varint');
    return { value: buffer.readUInt16LE(offset + 1), size: 3 };
  }
  if (first === 0xfe) {
    if (offset + 5 > buffer.length) throw new Error('Unexpected end of varint');
    return { value: buffer.readUInt32LE(offset + 1), size: 5 };
  }

  if (offset + 9 > buffer.length) throw new Error('Unexpected end of varint');
  const value = buffer.readBigUInt64LE(offset + 1);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Varint exceeds safe integer range');
  return { value: Number(value), size: 9 };
}

function readSlice(buffer, offset, size, context) {
  if (offset + size > buffer.length) throw new Error(`Unexpected end of RTM transaction${  context ? `: ${  context}` : ''}`);
  return {
    value: buffer.slice(offset, offset + size),
    offset: offset + size
  };
}

function readTxVarInt(buffer, offset) {
  const parsed = readVarInt(buffer, offset);
  return {
    value: parsed.value,
    offset: offset + parsed.size
  };
}

function readVarSlice(buffer, offset, context) {
  const parsed = readTxVarInt(buffer, offset);
  const slice = readSlice(buffer, parsed.offset, parsed.value, context);
  return {
    value: slice.value,
    offset: slice.offset
  };
}

function readWitnessVector(buffer, offset) {
  const count = readTxVarInt(buffer, offset);
  let nextOffset = count.offset;
  const vector = [];
  for (let i = 0; i < count.value; i++) {
    const item = readVarSlice(buffer, nextOffset, 'witness item');
    vector.push(item.value);
    nextOffset = item.offset;
  }
  return {
    value: vector,
    offset: nextOffset
  };
}

function hasWitnesses(tx) {
  return tx.ins.some(function(input) {
    return input.witness && input.witness.length > 0;
  });
}

function isCoinbaseHash(hash) {
  for (let i = 0; i < hash.length; i++) {
    if (hash[i] !== 0) return false;
  }
  return true;
}

function createParsedTransaction(version, ins, outs, payload, rawWithWitness, rawNoWitness) {
  return {
    version,
    ins,
    outs,
    payload,
    _rawWithWitness: rawWithWitness,
    _rawNoWitness: rawNoWitness,
    hasWitnesses() {
      return hasWitnesses(this);
    },
    isCoinbase() {
      return this.ins.length === 1 && isCoinbaseHash(this.ins[0].hash);
    },
    byteLength(allowWitness) {
      return this.__toBuffer(undefined, undefined, allowWitness).length;
    },
    __toBuffer(_buffer, _initialOffset, allowWitness) {
      return allowWitness && this.hasWitnesses() ? this._rawWithWitness : this._rawNoWitness;
    }
  };
}

function isSupportedRtmTransactionVersion(version) {
  const txVersion = version & 0xffff;
  const txType = version >>> 16;
  return txVersion >= 1 && txVersion <= 3 && (txVersion >= 3 || txType === 0);
}

function readTransaction(buffer, offsetArg, readPayload) {
  let offset = offsetArg;
  const start = offset;
  const versionSlice = readSlice(buffer, offset, 4, 'version');
  const version = versionSlice.value.readInt32LE(0);
  const txVersion = version & 0xffff;
  const txType = version >>> 16;
  offset = versionSlice.offset;

  if (!isSupportedRtmTransactionVersion(version)) throw new Error('Unsupported RTM transaction version');

  let hasWitnessMarker = false;
  if (offset + 2 <= buffer.length &&
      buffer[offset] === bitcoin.Transaction.ADVANCED_TRANSACTION_MARKER &&
      buffer[offset + 1] === bitcoin.Transaction.ADVANCED_TRANSACTION_FLAG) {
    hasWitnessMarker = true;
    offset += 2;
  }

  const inputCount = readTxVarInt(buffer, offset);
  offset = inputCount.offset;
  const ins = [];
  for (let i = 0; i < inputCount.value; i++) {
    const hash = readSlice(buffer, offset, 32, 'input hash');
    const index = readSlice(buffer, hash.offset, 4, 'input index');
    const script = readVarSlice(buffer, index.offset, 'input script');
    const sequence = readSlice(buffer, script.offset, 4, 'input sequence');
    ins.push({
      hash: hash.value,
      index: index.value.readUInt32LE(0),
      script: script.value,
      sequence: sequence.value.readUInt32LE(0),
      witness: []
    });
    offset = sequence.offset;
  }

  const outputCount = readTxVarInt(buffer, offset);
  offset = outputCount.offset;
  const outs = [];
  for (let i = 0; i < outputCount.value; i++) {
    const value = readSlice(buffer, offset, 8, 'output value');
    const script = readVarSlice(buffer, value.offset, 'output script');
    outs.push({
      valueBuffer: value.value,
      script: script.value
    });
    offset = script.offset;
  }

  const witnessStart = offset;
  if (hasWitnessMarker) {
    for (let i = 0; i < inputCount.value; i++) {
      const witness = readWitnessVector(buffer, offset);
      ins[i].witness = witness.value;
      offset = witness.offset;
    }
    if (!ins.some(function(input) { return input.witness.length > 0; })) {
      throw new Error('Transaction has superfluous witness data');
    }
  }

  const locktimeStart = offset;
  offset = readSlice(buffer, offset, 4, 'locktime').offset;

  let payload = null;
  if (readPayload && txVersion === 3 && txType !== 0) {
    const payloadSlice = readVarSlice(buffer, offset, 'extra payload');
    payload = payloadSlice.value;
    offset = payloadSlice.offset;
  }

  const rawWithWitness = buffer.slice(start, offset);
  const rawNoWitness = hasWitnessMarker ?
    Buffer.concat([
      buffer.slice(start, start + 4),
      buffer.slice(start + 6, witnessStart),
      buffer.slice(locktimeStart, offset)
    ]) :
    rawWithWitness;

  return {
    transaction: createParsedTransaction(version, ins, outs, payload, rawWithWitness, rawNoWitness),
    offset
  };
}

function canReadTransactionAt(buffer, offset, readPayload) {
  if (offset < 0 || offset + 4 > buffer.length) return false;
  if (!isSupportedRtmTransactionVersion(buffer.readInt32LE(offset))) return false;
  try {
    const parsed = readTransaction(buffer, offset, readPayload);
    return parsed.offset > offset && parsed.offset <= buffer.length;
  } catch (_err) {
    return false;
  }
}

function findRecoverableTransactionOffset(buffer, offset, readPayload) {
  if (canReadTransactionAt(buffer, offset, readPayload)) return offset;
  const end = Math.min(buffer.length - 4, offset + MAX_RECOVERABLE_TRANSACTION_TAIL_BYTES);
  for (let nextOffset = offset + 1; nextOffset <= end; nextOffset++) {
    if (canReadTransactionAt(buffer, nextOffset, readPayload)) return nextOffset;
  }
  return offset;
}

function extendTransactionRaw(transaction, tail) {
  if (!tail || tail.length === 0) return transaction;
  return createParsedTransaction(
    transaction.version,
    transaction.ins,
    transaction.outs,
    transaction.payload,
    Buffer.concat([transaction._rawWithWitness, tail]),
    Buffer.concat([transaction._rawNoWitness, tail])
  );
}

function validateRtmTransaction(buffer) {
  const parsed = readTransaction(buffer, 0, true);
  if (parsed.offset !== buffer.length) {
    throw new Error('Transaction has unexpected data');
  }
  return true;
}

function decodeRtmTransactionData(tx) {
  if (!tx || typeof tx.data !== 'string' || tx.data.length % 2 !== 0) {
    throw new Error('Invalid RTM transaction data');
  }
  if (tx.data.length / 2 > MAX_RTM_TRANSACTION_BYTES) {
    throw new Error('RTM transaction data is too large');
  }
  if (!/^[0-9a-fA-F]*$/.test(tx.data)) {
    throw new Error('Invalid RTM transaction data');
  }
  return Buffer.from(tx.data, 'hex');
}

function describeRtmTransaction(tx) {
  if (!tx || typeof tx.data !== 'string') return 'invalid transaction data';
  return `${tx.data.length / 2} byte transaction`;
}

module.exports.readTransaction = readTransaction;
module.exports.findRecoverableTransactionOffset = findRecoverableTransactionOffset;
module.exports.extendTransactionRaw = extendTransactionRaw;

// "serialized CScript" formatting as defined here:
// https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki#specification
// Used to format height and date when putting into script signature:
// https://en.bitcoin.it/wiki/Script
function serializeNumber(nArg) {
  let n = nArg;
  // New version from TheSeven
  if (n >= 1 && n <= 16) return Buffer.from([0x50 + n]);
  let l = 1;
  const buff = Buffer.alloc(9);
  while (n > 0x7f) {
      buff.writeUInt8(n & 0xff, l++);
      n >>= 8;
  }
  buff.writeUInt8(l, 0);
  buff.writeUInt8(n, l++);
  return buff.slice(0, l);
}

// Used for serializing strings used in script signature
function serializeString(s) {
  if (s.length < 253) {
    return Buffer.concat([ Buffer.from([s.length]), Buffer.from(s) ]);
  } else if (s.length < 0x10000) {
    return Buffer.concat([ Buffer.from([253]), packUInt16LE(s.length), Buffer.from(s) ]);
  } else if (s.length < 0x100000000) {
    return Buffer.concat([ Buffer.from([254]), packUInt32LE(s.length), Buffer.from(s) ]);
  } 
    return Buffer.concat([ Buffer.from([255]), packUInt16LE(s.length), Buffer.from(s) ]);
  
}

function uint256BufferFromHash(hex) {
  let fromHex = Buffer.from(hex, 'hex');
  if (fromHex.length !== 32) {
    const empty = Buffer.alloc(32);
    empty.fill(0);
    fromHex.copy(empty);
    fromHex = empty;
  }
  return reverseBuffer(fromHex);
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

const MAX_BASE58_ADDRESS_LENGTH = 128;
const MAX_BECH32_ADDRESS_LENGTH = 128;

function decodeBase58Check(value) {
  if (value.length > MAX_BASE58_ADDRESS_LENGTH) throw new Error('Base58 address too long');

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
  const expectedChecksum = sha256(sha256(payload)).subarray(0, 4);
  if (!crypto.timingSafeEqual(checksum, expectedChecksum)) throw new Error('Invalid base58check checksum');
  return decoded;
}

function addressToScript(addr) {
  if (typeof addr !== 'string') throw new Error('Invalid address');
  if (addr.length > MAX_BECH32_ADDRESS_LENGTH) throw new Error('Invalid address length');
  let decoded;
  try {
    decoded = decodeBase58Check(addr);
  } catch(_err) {
    // not base58check; fall through to try bech32 decoding below
  }
  if (!decoded || decoded.length !== 25) {
    let decoded2;
    try {
      decoded2 = Buffer.from(bech32.bech32.fromWords(bech32.bech32.decode(addr).words.slice(1)));
    } catch(_err) {
      throw new Error('Invalid address');
    }
    if (decoded2.length !== 20) throw new Error('Invalid address');
    return Buffer.concat([Buffer.from([0x0, 0x14]), decoded2]);
  }
  const pubkey = decoded.slice(1, -4);
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pubkey, Buffer.from([0x88, 0xac])]);
}

function createTransactionOutput(amount, payee, rewardToPool, reward, txOutputBuffers, payeeScriptArg) {
  if (!isValidSatoshisAmount(amount) || amount > rewardToPool || amount > reward) {
    throw new Error('Invalid payout amount');
  }

  const payeeReward = amount;
  let payeeScript = payeeScriptArg;
  if (!payeeScript) payeeScript = addressToScript(payee);
  txOutputBuffers.push(Buffer.concat([
    packInt64LE(payeeReward),
    varIntBuffer(payeeScript.length),
    payeeScript
  ]));
  return { reward: reward - amount, rewardToPool: rewardToPool - amount };
}


function validateCoinbaseDevReward(coinbaseDevReward, rewardToPool) {
  if (!coinbaseDevReward || typeof coinbaseDevReward !== 'object') return false;
  if (!isValidSatoshisAmount(coinbaseDevReward.value) || coinbaseDevReward.value > rewardToPool) return false;
  if (typeof coinbaseDevReward.scriptpubkey !== 'string' || !/^(?:[0-9a-fA-F]{2})+$/.test(coinbaseDevReward.scriptpubkey)) return false;
  return true;
}

function hasValidCoinbaseDevReward(rpcData) {
  if (rpcData.coinbasedevreward === undefined || rpcData.coinbasedevreward === null) return false;
  if (!validateCoinbaseDevReward(rpcData.coinbasedevreward, rpcData.coinbasevalue)) throw new Error('Invalid coinbase dev reward');
  return true;
}

function generateTransactionOutputs(rpcData, poolAddress, hasDevReward) {
  let reward       = rpcData.coinbasevalue + (hasDevReward ? rpcData.coinbasedevreward.value : 0);
  let rewardToPool = reward;
  const txOutputBuffers = [];

  if (hasDevReward) {
    const rewards = createTransactionOutput(rpcData.coinbasedevreward.value, null, rewardToPool, reward, txOutputBuffers, Buffer.from(rpcData.coinbasedevreward.scriptpubkey, 'hex'));
    reward        = rewards.reward;
    rewardToPool  = rewards.rewardToPool;
  }

  if (rpcData.smartnode) {
    if (rpcData.smartnode.payee) {
      const rewards = createTransactionOutput(rpcData.smartnode.amount, rpcData.smartnode.payee, rewardToPool, reward, txOutputBuffers);
      reward        = rewards.reward;
      rewardToPool  = rewards.rewardToPool;
    } else if (Array.isArray(rpcData.smartnode)) {
      for (const i in rpcData.smartnode) {
        const rewards = createTransactionOutput(rpcData.smartnode[i].amount, rpcData.smartnode[i].payee, rewardToPool, reward, txOutputBuffers);
	reward        = rewards.reward;
        rewardToPool  = rewards.rewardToPool;
      }
    } 
  }

  if (rpcData.superblock) {
    for (const i in rpcData.superblock) {
      const rewards = createTransactionOutput(rpcData.superblock[i].amount, rpcData.superblock[i].payee, rewardToPool, reward, txOutputBuffers);
      reward        = rewards.reward;
      rewardToPool  = rewards.rewardToPool;
    }
  }

  if (rpcData.founder_payments_started && rpcData.founder) {
    const founderReward = rpcData.founder.amount || 0;
    const rewards = createTransactionOutput(founderReward, rpcData.founder.payee, rewardToPool, reward, txOutputBuffers);
    reward        = rewards.reward;
    rewardToPool  = rewards.rewardToPool;
  }

  createTransactionOutput(rewardToPool, null, rewardToPool, reward, txOutputBuffers, Buffer.from(addressToScript(poolAddress), "hex"));

  if (rpcData.default_witness_commitment) {
    createTransactionOutput(0, null, rewardToPool, reward, txOutputBuffers, Buffer.from(rpcData.default_witness_commitment, 'hex'));
    txOutputBuffers.push(Buffer.concat([
      varIntBuffer(1),
      varIntBuffer(32),
      Buffer.alloc(32, 0)
    ]));
  }

  return Buffer.concat([ varIntBuffer(rpcData.default_witness_commitment ? txOutputBuffers.length - 1 : txOutputBuffers.length), Buffer.concat(txOutputBuffers)]);
}

module.exports.RtmBlockTemplate = function(rpcData, poolAddress) {
  const extraNoncePlaceholderLength = 17;
  const hasDevReward = hasValidCoinbaseDevReward(rpcData);
  const coinbaseVersion = hasDevReward ? Buffer.concat([packUInt16LE(1), packUInt16LE(0)]) : Buffer.concat([packUInt16LE(3), packUInt16LE(5)]);

  if (!rpcData.coinbaseaux || typeof rpcData.coinbaseaux !== 'object') throw new Error('Invalid RTM coinbaseaux');
  const scriptSigPart1 = Buffer.concat([
    serializeNumber(rpcData.height),
    Buffer.from(rpcData.coinbaseaux.flags ? rpcData.coinbaseaux.flags : "", 'hex'),
    serializeNumber(Date.now() / 1000 | 0),
    Buffer.from([extraNoncePlaceholderLength])
  ]);

  const scriptSigPart2 = serializeString('/nodeStratum/');

  const is_witness = rpcData.default_witness_commitment !== undefined;

  const blob1 = Buffer.concat([
    coinbaseVersion,
    // transaction input
    Buffer.from(is_witness ? "0001" : "", 'hex'),
    varIntBuffer(1), // txInputsCount
    uint256BufferFromHash(""), // txInPrevOutHash
    packUInt32LE(Math.pow(2, 32) - 1), // txInPrevOutIndex
    varIntBuffer(scriptSigPart1.length + extraNoncePlaceholderLength + scriptSigPart2.length),
    scriptSigPart1
  ]);

  let blob2 = Buffer.concat([
    scriptSigPart2,
    packUInt32LE(0), // txInSequence
    // end transaction input
    // transaction output
    generateTransactionOutputs(rpcData, poolAddress, hasDevReward),
    // end transaction ouput
    packUInt32LE(0) // txLockTime
  ]);

  const coinbaseTxType = coinbaseVersion.readUInt16LE(2);
  if (rpcData.coinbase_payload || coinbaseTxType !== 0) {
    const coinbasePayload = rpcData.coinbase_payload ? Buffer.from(rpcData.coinbase_payload, 'hex') : Buffer.alloc(0);
    blob2 = Buffer.concat([
      blob2,
      varIntBuffer(coinbasePayload.length),
      coinbasePayload
    ]);
  }

  const prev_hash = reverseBuffer(Buffer.from(rpcData.previousblockhash, 'hex')).toString('hex');
  if (!Number.isInteger(rpcData.version) || rpcData.version < -0x80000000 || rpcData.version > 0x7fffffff) throw new Error('Invalid RTM version');
  const version = packInt32LE(rpcData.version).toString('hex');
  const curtime = packUInt32LE(rpcData.curtime).toString('hex');
  const bits = Buffer.from(rpcData.bits, 'hex');
  if (bits.length !== 4) throw new Error('Invalid RTM bits');
  bits.writeUInt32LE(bits.readUInt32BE());
  if (!Array.isArray(rpcData.transactions)) throw new Error('Invalid RTM transactions');
  if (rpcData.transactions.length > MAX_RTM_TEMPLATE_TRANSACTIONS) throw new Error('Too many RTM transactions');

  const txs = [];
  let txBytes = 0;
  // skip version 1 transaction because they contain some OP_RETURN(0x6A) opcode in the beginning of
  // tx input scripts instead of size of script part so not sure how to parse them
  // just drop them for now
  // example: https://explorer.raptoreum.com/tx/1461d70fa8362b0896e2e9be6312521f2684f22c9b0f9152695f33f67d9f9d3f
  rpcData.transactions.forEach(function(tx) {
    if (tx.version !== 1) {
      let txBuffer;
      try {
        txBuffer = decodeRtmTransactionData(tx);
        validateRtmTransaction(txBuffer);
      } catch(_err) {
        console.error(`Skip RTM tx due to parse error: ${  describeRtmTransaction(tx)}`);
        return; // skip transaction if it is not parsed OK (varint coding seems to be different for RTM)
      }
      txBytes += txBuffer.length;
      if (txBytes > MAX_RTM_TEMPLATE_TRANSACTION_BYTES) throw new Error('RTM transaction data is too large');
      txs.push(txBuffer);
    } else {
      console.error(`Skip RTM v1 tx: ${  describeRtmTransaction(tx)}`);
    }
  });
  const txn = varIntBuffer(txs.length + 1);

  return {
    difficulty:         difficultyToFloat(diff1, rpcData.target, 16, 'RTM target'),
    height:             rpcData.height,
    prev_hash,
    blocktemplate_blob: version + prev_hash + Buffer.alloc(32, 0).toString('hex') + curtime + bits.toString('hex') + Buffer.alloc(4, 0).toString('hex') +
                        txn.toString('hex') + blob1.toString('hex') + Buffer.alloc(extraNoncePlaceholderLength, 0xCC).toString('hex') + blob2.toString('hex')  +
                        Buffer.concat(txs).toString('hex'),
    reserved_offset:    80 + txn.length + blob1.length
  }
}
