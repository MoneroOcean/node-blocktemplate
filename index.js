module.exports = require('bindings')('blocktemplate.node');

const SHA3    = require('sha3');
const bitcoin = require('bitcoinjs-lib');
const varuint = require('varuint-bitcoin');
const crypto  = require('crypto');
const fastMerkleRoot = require('merkle-lib/fastRoot');

const { BASE_DIFF, BASE_RAVEN_DIFF, difficultyToFloat, parsePositiveBigInt } = require('./bigint');
const rtm = require('./rtm');

const MAX_TEMPLATE_TRANSACTIONS = 5000;

function scriptCompile(addrHash) {
  return bitcoin.script.compile([
    bitcoin.opcodes.OP_DUP,
    bitcoin.opcodes.OP_HASH160,
    addrHash,
    bitcoin.opcodes.OP_EQUALVERIFY,
    bitcoin.opcodes.OP_CHECKSIG
  ]);
}

function reverseBuffer(buff) {
  const reversed = Buffer.alloc(buff.length);
  for (let i = buff.length - 1; i >= 0; i--) reversed[buff.length - i - 1] = buff[i];
  return reversed;
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
};

function hash256(buffer) {
  return sha256(sha256(buffer));
};

function sha256_3(buffer) {
  return crypto.createHash('sha3-256').update(buffer).digest();
};

function hash256_3(buffer) {
  return sha256_3(sha256_3(buffer));
};

function transaction_hash(transaction, forWitness) {
  if (forWitness && transaction.isCoinbase()) return Buffer.alloc(32, 0);
  return hash256(transaction.__toBuffer(undefined, undefined, forWitness));
}

function transaction_hash3(transaction, forWitness) {
  if (forWitness && transaction.isCoinbase()) return Buffer.alloc(32, 0);
  return hash256_3(transaction.__toBuffer(undefined, undefined, forWitness));
}

function getMerkleRoot(transactions, transaction_hash_func, merkle_hash_func) {
  if (transactions.length === 0) return Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
  const hashes = transactions.map(transaction => transaction_hash_func(transaction, false));
  return fastMerkleRoot(hashes, merkle_hash_func);
}

let last_epoch_number;
let last_seed_hash;

module.exports.baseDiff = function() {
  return BASE_DIFF;
};

module.exports.baseRavenDiff = function() {
  return BASE_RAVEN_DIFF;
};

module.exports.RavenBlockTemplate = function(rpcData, poolAddress) {
  const poolAddrHash = bitcoin.address.fromBase58Check(poolAddress).hash;

  const txCoinbase = new bitcoin.Transaction();
  let bytesHeight;
  { // input for coinbase tx
    let blockHeightSerial = rpcData.height.toString(16).length % 2 === 0 ?
                                  rpcData.height.toString(16) :
                            `0${  rpcData.height.toString(16)}`;
    bytesHeight = Math.ceil((rpcData.height << 1).toString(2).length / 8);
    const lengthDiff  = blockHeightSerial.length/2 - bytesHeight;
    for (let i = 0; i < lengthDiff; i++) blockHeightSerial = `${blockHeightSerial  }00`;
    const serializedBlockHeight = Buffer.concat([
      Buffer.from(`0${  bytesHeight}`, 'hex'),
      reverseBuffer(Buffer.from(blockHeightSerial, 'hex')),
      Buffer.from('00', 'hex') // OP_0
    ]);

    txCoinbase.addInput(
      // will be used for our reserved_offset extra_nonce
      Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
      0xFFFFFFFF, 0xFFFFFFFF,
      Buffer.concat([serializedBlockHeight, Buffer.alloc(17, 0xCC)]) // 17 bytes
    );

    txCoinbase.addOutput(scriptCompile(poolAddrHash), Math.floor(rpcData.coinbasevalue));

    if (rpcData.CommunityAutonomousAddress && rpcData.CommunityAutonomousValue) {
      txCoinbase.addOutput(
        scriptCompile(bitcoin.address.fromBase58Check(rpcData.CommunityAutonomousAddress).hash),
        Math.floor(rpcData.CommunityAutonomousValue)
      );
    }

    if (rpcData.default_witness_commitment) {
      txCoinbase.addOutput(Buffer.from(rpcData.default_witness_commitment, 'hex'), 0);
    }
  }

  let header = Buffer.alloc(80);
  { let position = 0;
    header.writeUInt32BE(rpcData.height, position, 4);                  // height         42-46
    header.write(rpcData.bits, position += 4, 4, 'hex');                // bits           47-50
    header.writeUInt32BE(rpcData.curtime, position += 4, 4, 'hex');     // nTime          51-54
    header.write('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD', position += 4, 32, 'hex');                 // merkleRoot (placeholder, filled in later)
    header.write(rpcData.previousblockhash, position += 32, 32, 'hex'); // prevblockhash  88-120
    header.writeUInt32BE(rpcData.version, position += 32, 4);           // version        121-153
    header = reverseBuffer(header);
  }

  let blob = Buffer.concat([
    header, // 80 bytes
    Buffer.from('AAAAAAAAAAAAAAAA', 'hex'), // 8 bytes
    Buffer.from('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'hex'), // 32 bytes
    varuint.encode(rpcData.transactions.length + 1, Buffer.alloc(varuint.encodingLength(rpcData.transactions.length + 1)), 0)
  ]);
  const offset1 = blob.length;
  blob = Buffer.concat([ blob, Buffer.from(txCoinbase.toHex(), 'hex') ]);

  rpcData.transactions.forEach(function (value) {
    blob = Buffer.concat([ blob, Buffer.from(value.data, 'hex') ]);
  });

  const EPOCH_LENGTH = 7500;
  const epoch_number = Math.floor(rpcData.height / EPOCH_LENGTH);
  if (last_epoch_number !== epoch_number) {
    const sha3 = new SHA3.SHA3Hash(256);
    if (last_epoch_number && last_epoch_number + 1 === epoch_number) {
      last_seed_hash = sha3.update(last_seed_hash).digest();
    } else {
      last_seed_hash = Buffer.alloc(32, 0);
      for (let i = 0; i < epoch_number; i++) {
        last_seed_hash = sha3.update(last_seed_hash).digest();
        sha3.reset();
      }
    }
    last_epoch_number = epoch_number;
  }

  const difficulty = difficultyToFloat(module.exports.baseRavenDiff(), rpcData.target, 16, 'Raven target');

  return {
    blocktemplate_blob: blob.toString('hex'),
    // reserved_offset to CCCCCC....
    reserved_offset:    offset1 + 4 /* txCoinbase.version */ + 1 /* vinLen */  + 32 /* hash */ + 4 /* index  */ +
                        1 /* vScript len */ + 1 /* coinbase height len */ + bytesHeight + 1 /* trailing zero byte */,
    seed_hash:          last_seed_hash.toString('hex'),
    difficulty,
    height:             rpcData.height,
    bits:               rpcData.bits,
    prev_hash:          rpcData.previousblockhash,
  };
};

function update_merkle_root_hash(offsetArg, payload, blob_in, blob_out, transaction_hash_func, merkle_hash_func = hash256) {
  let offset = offsetArg;
  const nTransactions = varuint.decode(blob_in, offset);
  offset += varuint.decode.bytes;
  if (nTransactions < 1 || nTransactions > MAX_TEMPLATE_TRANSACTIONS) {
    throw new Error('Invalid transaction count in block template');
  }
  const transactions = [];
  for (let i = 0; i < nTransactions; ++i) {
    if (offset >= blob_in.length) {
      throw new Error('Invalid transaction offset in block template');
    }
    let tx;
    if (payload) {
      let parsed;
      try {
        parsed = rtm.readTransaction(blob_in, offset, true);
      } catch (_err) {
        throw new Error('Unable to parse transaction from block template');
      }
      if (!parsed || parsed.offset <= offset || parsed.offset > blob_in.length) {
        throw new Error('Invalid transaction size in block template');
      }
      tx = parsed.transaction;
      offset = parsed.offset;
      if (i + 1 < nTransactions) {
        const nextOffset = rtm.findRecoverableTransactionOffset(blob_in, offset, true);
        if (nextOffset !== offset) {
          tx = rtm.extendTransactionRaw(tx, blob_in.slice(offset, nextOffset));
          offset = nextOffset;
        }
      }
    } else {
      tx = bitcoin.Transaction.fromBuffer(blob_in.slice(offset), true, false);
      offset += tx.byteLength();
    }
    transactions.push(tx);
  }
  if (offset !== blob_in.length) {
    throw new Error('Unexpected data after block template transactions');
  }
  getMerkleRoot(transactions, transaction_hash_func, merkle_hash_func).copy(blob_out, 4 + 32);
};

module.exports.blockHashBuff = function(blobBuffer) {
  return reverseBuffer(hash256(blobBuffer));
};

module.exports.blockHashBuff3 = function(blobBuffer) {
  return reverseBuffer(hash256_3(blobBuffer));
};

module.exports.convertRavenBlob = function(blobBuffer) {
  const header = blobBuffer.slice(0, 80);
  update_merkle_root_hash(80 + 8 + 32, false, blobBuffer, header, transaction_hash);
  return module.exports.blockHashBuff(header);
};

module.exports.constructNewRavenBlob = function(blockTemplate, nonceBuff, mixhashBuff) {
  update_merkle_root_hash(80 + 8 + 32, false, blockTemplate, blockTemplate, transaction_hash);
  nonceBuff.copy  (blockTemplate, 80, 0, 8);
  mixhashBuff.copy(blockTemplate, 88, 0, 32);
  return blockTemplate;
};

module.exports.constructNewDeroBlob = function(blockTemplate, nonceBuff) {
  nonceBuff.copy(blockTemplate, 39, 0, 4);
  return blockTemplate;
};

module.exports.EthBlockTemplate = function(rpcData) {
  const difficulty = Number(module.exports.baseDiff() / parsePositiveBigInt(stripHexPrefix(rpcData[2], 'ETH target'), 16, 'ETH target'));
  return {
    hash:               rpcData[0].substr(2),
    seed_hash:          rpcData[1].substr(2),
    difficulty,
    height:             parseInt(rpcData[3])
  };
};

module.exports.ErgBlockTemplate = function(rpcData) {
  const difficulty = Number(module.exports.baseDiff() / parsePositiveBigInt(rpcData.b, undefined, 'ERG target'));
  return {
    hash:               rpcData.msg,
    hash2:              rpcData.pk,
    difficulty,
    height:             parseInt(rpcData.h)
  };
};

module.exports.RtmBlockTemplate = function(rpcData, poolAddress) {
  return rtm.RtmBlockTemplate(rpcData, poolAddress);
};

module.exports.convertRtmBlob = function(blobBuffer) {
  const header = blobBuffer.slice(0, 80);
  update_merkle_root_hash(80, true, blobBuffer, header, transaction_hash);
  return header;
};

module.exports.convertKcnBlob = function(blobBuffer) {
  const header = blobBuffer.slice(0, 80);
  update_merkle_root_hash(80, false, blobBuffer, header, transaction_hash3, hash256_3);
  return header;
};

module.exports.constructNewRtmBlob = function(blockTemplate, nonceBuff) {
  update_merkle_root_hash(80, true, blockTemplate, blockTemplate, transaction_hash);
  nonceBuff.copy(blockTemplate, 76, 0, 4);
  return blockTemplate;
};

module.exports.constructNewKcnBlob = function(blockTemplate, nonceBuff) {
  update_merkle_root_hash(80, false, blockTemplate, blockTemplate, transaction_hash3, hash256_3);
  nonceBuff.copy(blockTemplate, 76, 0, 4);
  return blockTemplate;
};

function stripHexPrefix(value, label) {
  if (typeof value !== 'string') throw new Error(`Invalid ${label}`);
  return value.startsWith('0x') ? value.slice(2) : value;
}
