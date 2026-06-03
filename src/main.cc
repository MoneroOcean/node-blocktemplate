#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"

using namespace v8;
using namespace cryptonote;
namespace Buffer = node::Buffer;

namespace {

inline Local<String> NewString(Isolate* isolate, const char* value) {
    return String::NewFromUtf8(isolate, value).ToLocalChecked();
}

inline void ThrowError(Isolate* isolate, const char* message) {
    isolate->ThrowException(Exception::Error(NewString(isolate, message)));
}

inline Local<Value> CopyBuffer(Isolate* isolate, const char* data, size_t size) {
    return Buffer::Copy(isolate, data, size).ToLocalChecked();
}

inline int ToInt32(Isolate* isolate, Local<Value> value) {
    return value->Int32Value(isolate->GetCurrentContext()).FromMaybe(0);
}

inline void SetExport(Isolate* isolate, Local<Object> target, const char* name,
                      FunctionCallback callback) {
    target->Set(
        isolate->GetCurrentContext(),
        NewString(isolate, name),
        Function::New(isolate->GetCurrentContext(), callback).ToLocalChecked()
    ).Check();
}

}  // namespace

// cryptonote::append_mm_tag_to_extra writes byte with TX_EXTRA_MERGE_MINING_TAG (1 here) and VARINT DEPTH (2 here)
const size_t MM_NONCE_SIZE = 1 + 2 + sizeof(crypto::hash);
const size_t MAX_TX_HASHES_FOR_PARENT_BLOCK = 16384;
const size_t MAX_BLOCK_ID_TX_HASHES = 65535;

blobdata uint64be_to_blob(uint64_t num) {
    blobdata res = "        ";
    res[0] = num >> 56 & 0xff;
    res[1] = num >> 48 & 0xff;
    res[2] = num >> 40 & 0xff;
    res[3] = num >> 32 & 0xff;
    res[4] = num >> 24 & 0xff;
    res[5] = num >> 16 & 0xff;
    res[6] = num >> 8  & 0xff;
    res[7] = num       & 0xff;
    return res;
}

static bool fillExtra(cryptonote::block& block1, const cryptonote::block& block2) {
    cryptonote::tx_extra_merge_mining_tag mm_tag;
    mm_tag.depth = 0;
    if (!cryptonote::get_block_header_hash(block2, mm_tag.merkle_root)) return false;

    block1.miner_tx.extra.clear();
    if (!cryptonote::append_mm_tag_to_extra(block1.miner_tx.extra, mm_tag)) return false;

    return true;
}


static bool fillExtraMM(cryptonote::block& block1, const cryptonote::block& block2) {
    cryptonote::tx_extra_merge_mining_tag mm_tag;
    mm_tag.depth = 0;
    if (!cryptonote::get_block_header_hash(block2, mm_tag.merkle_root)) {
        fprintf(stderr, "Can't get child block header hash!\n");
        return false;
    }
    std::vector<uint8_t> extra_nonce_replace;
    if (!cryptonote::append_mm_tag_to_extra(extra_nonce_replace, mm_tag)) {
        fprintf(stderr, "Can't append mm_tag extra!\n");
        return false;
    }

    if (extra_nonce_replace.size() != MM_NONCE_SIZE) {
        fprintf(stderr, "Wrong MM_NONCE_SIZE size!\n");
        return false;
    }

    std::vector<uint8_t>& extra = block1.miner_tx.extra;
    size_t pos = 0;

    while (pos < extra.size() && extra[pos] != TX_EXTRA_NONCE) {
       switch (extra[pos]) {
           case TX_EXTRA_TAG_PUBKEY: pos += 1 + sizeof(crypto::public_key); break;
           default: {
               fprintf(stderr, "Not supported extra tag found: %x\n", extra[pos]);
               return false;
           }
       }
    }

    if (pos + 1 >= extra.size()) {
        fprintf(stderr, "Can't find TX_EXTRA_NONCE in extra\n");
        return false;
    }

    const size_t extra_nonce_size = extra[pos + 1];
    const size_t extra_nonce_start = pos + 2;
    if (extra_nonce_start > extra.size() || extra_nonce_start + extra_nonce_size > extra.size()) {
        fprintf(stderr, "Malformed TX_EXTRA_NONCE length in extra\n");
        return false;
    }

    if (extra_nonce_size < MM_NONCE_SIZE) {
        fprintf(stderr, "Too small extra size, can't fit MM tag here\n");
        return false;
    }

    const size_t new_extra_nonce_size = extra_nonce_size - MM_NONCE_SIZE;

    extra[pos + 1] = static_cast<uint8_t>(new_extra_nonce_size);
    std::copy(extra_nonce_replace.begin(), extra_nonce_replace.end(), extra.begin() + extra_nonce_start + new_extra_nonce_size);
    //extra.resize(pos + 1 + extra_nonce_size + 1);

    return true;
}

static bool mergeBlocks(const cryptonote::block& block1, cryptonote::block& block2, const std::vector<crypto::hash>& branch2) {
    block2.timestamp = block1.timestamp;
    block2.parent_block.major_version = block1.major_version;
    block2.parent_block.minor_version = block1.minor_version;
    block2.parent_block.prev_id       = block1.prev_id;
    block2.parent_block.nonce         = block1.nonce;
    block2.parent_block.miner_tx      = block1.miner_tx;
    block2.parent_block.number_of_transactions = block1.tx_hashes.size() + 1;
    block2.parent_block.miner_tx_branch.resize(crypto::tree_depth(block1.tx_hashes.size() + 1));
    std::vector<crypto::hash> transactionHashes;
    transactionHashes.push_back(cryptonote::get_transaction_hash(block1.miner_tx));
    std::copy(block1.tx_hashes.begin(), block1.tx_hashes.end(), std::back_inserter(transactionHashes));
    tree_branch(transactionHashes.data(), transactionHashes.size(), block2.parent_block.miner_tx_branch.data());
    block2.parent_block.blockchain_branch = branch2;
    return true;
}

static bool construct_parent_block(const cryptonote::block& b, cryptonote::block& parent_block) {
    parent_block.major_version = 1;
    parent_block.minor_version = 0;
    parent_block.timestamp = b.timestamp;
    parent_block.prev_id = b.prev_id;
    parent_block.nonce = b.parent_block.nonce;
    parent_block.miner_tx.version = CURRENT_TRANSACTION_VERSION;
    parent_block.miner_tx.unlock_time = 0;
    return fillExtra(parent_block, b);
}

void convert_blob(const FunctionCallbackInfo<Value>& info) { // (parentBlockBuffer, cnBlobType)
    if (info.Length() < 1) return ThrowError(info.GetIsolate(), "You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return ThrowError(isolate, "Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    enum BLOB_TYPE blob_type = BLOB_TYPE_CRYPTONOTE;
    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return ThrowError(isolate, "Argument 2 should be a number");
        blob_type = static_cast<enum BLOB_TYPE>(ToInt32(isolate, info[1]));
    }

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(input, b)) return ThrowError(isolate, "Failed to parse block 2");

    if (blob_type == BLOB_TYPE_FORKNOTE2) {
        block parent_block;
        if (!construct_parent_block(b, parent_block)) return ThrowError(isolate, "convert_blob: Failed to construct parent block");
        if (!get_block_hashing_blob(parent_block, output)) return ThrowError(isolate, "convert_blob: Failed to create mining block");
    } else {
        if (!get_block_hashing_blob(b, output)) return ThrowError(isolate, "convert_blob: Failed to create mining block");
    }

    info.GetReturnValue().Set(CopyBuffer(isolate, output.data(), output.size()));
}

void get_block_id(const FunctionCallbackInfo<Value>& info) {
    if (info.Length() < 1) return ThrowError(info.GetIsolate(), "You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return ThrowError(isolate, "Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    enum BLOB_TYPE blob_type = BLOB_TYPE_CRYPTONOTE;
    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return ThrowError(isolate, "Argument 2 should be a number");
        blob_type = static_cast<enum BLOB_TYPE>(ToInt32(isolate, info[1]));
    }

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(input, b)) return ThrowError(isolate, "Failed to parse block");
    if (b.tx_hashes.size() > MAX_BLOCK_ID_TX_HASHES) return ThrowError(isolate, "Block has too many transaction hashes");

    crypto::hash block_id;
    if (!get_block_hash(b, block_id)) return ThrowError(isolate, "Failed to calculate hash for block");

    char *cstr = reinterpret_cast<char*>(&block_id);
    info.GetReturnValue().Set(CopyBuffer(isolate, cstr, 32));
}

void construct_block_blob(const FunctionCallbackInfo<Value>& info) { // (parentBlockTemplateBuffer, nonceBuffer, cnBlobType)
    if (info.Length() < 2) return ThrowError(info.GetIsolate(), "You must provide two arguments.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> block_template_buf = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    Local<Object> nonce_buf = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf)) return ThrowError(isolate, "Both arguments should be buffer objects.");

    enum BLOB_TYPE blob_type = BLOB_TYPE_CRYPTONOTE;
    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return ThrowError(isolate, "Argument 3 should be a number");
        blob_type = static_cast<enum BLOB_TYPE>(ToInt32(isolate, info[2]));
    }

    if (Buffer::Length(nonce_buf) != (blob_type == BLOB_TYPE_AEON ? 8 : 4)) return ThrowError(isolate, "Nonce buffer has invalid size.");

    uint64_t nonce = blob_type == BLOB_TYPE_AEON ? *reinterpret_cast<uint64_t*>(Buffer::Data(nonce_buf)) : *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));
    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(block_template_blob, b)) return ThrowError(isolate, "Failed to parse block");

    b.nonce = nonce;
    if (blob_type == BLOB_TYPE_FORKNOTE2) {
        if (b.tx_hashes.size() > MAX_TX_HASHES_FOR_PARENT_BLOCK) return ThrowError(isolate, "Block template has too many transaction hashes.");
        block parent_block;
        b.parent_block.nonce = nonce;
        if (!construct_parent_block(b, parent_block)) return ThrowError(isolate, "Failed to construct parent block");
        if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>())) return ThrowError(isolate, "Failed to postprocess mining block");
    }

    if (blob_type == BLOB_TYPE_CRYPTONOTE_XTNC || blob_type == BLOB_TYPE_CRYPTONOTE_CUCKOO) {
        if (info.Length() != 4) return ThrowError(isolate, "You must provide 4 arguments.");
        Local<Array> cycle = Local<Array>::Cast(info[3]);
        for (int i = 0; i < 32; i++ ) b.cycle.data[i] = cycle->Get(isolate->GetCurrentContext(), i).ToLocalChecked()->NumberValue(isolate->GetCurrentContext()).ToChecked();
    }

    if (blob_type == BLOB_TYPE_CRYPTONOTE_TUBE) {
        if (info.Length() != 4) return ThrowError(isolate, "You must provide 4 arguments.");
        Local<Array> cycle = Local<Array>::Cast(info[3]);
        for (int i = 0; i < 40; i++ ) b.cycle40.data[i] = cycle->Get(isolate->GetCurrentContext(), i).ToLocalChecked()->NumberValue(isolate->GetCurrentContext()).ToChecked();
    }

    if (blob_type == BLOB_TYPE_CRYPTONOTE_XTA) {
        if (info.Length() != 4) return ThrowError(isolate, "You must provide 4 arguments.");
        Local<Array> cycle = Local<Array>::Cast(info[3]);
        for (int i = 0; i < 48; i++ ) b.cycle48.data[i] = cycle->Get(isolate->GetCurrentContext(), i).ToLocalChecked()->NumberValue(isolate->GetCurrentContext()).ToChecked();
    }

    if (!block_to_blob(b, output)) return ThrowError(isolate, "Failed to convert block to blob");
    info.GetReturnValue().Set(CopyBuffer(isolate, output.data(), output.size()));
}

void address_decode(const FunctionCallbackInfo<Value>& info) {
    if (info.Length() < 1) return ThrowError(info.GetIsolate(), "You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(target)) return ThrowError(isolate, "Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data)) {
        info.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    account_public_address adr;
    if (!::serialization::parse_binary(data, adr) || !crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key)) {
        if (!data.length()) {
            info.GetReturnValue().Set(Undefined(isolate));
            return;
        }
        data = uint64be_to_blob(prefix) + data;
        info.GetReturnValue().Set(CopyBuffer(isolate, data.data(), data.size()));
    } else {
        info.GetReturnValue().Set(Integer::NewFromUnsigned(isolate, static_cast<uint32_t>(prefix)));
    }
}

void address_decode_integrated(const FunctionCallbackInfo<Value>& info) {
    if (info.Length() < 1) return ThrowError(info.GetIsolate(), "You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(target)) return ThrowError(isolate, "Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data)) {
        info.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    integrated_address iadr;
    if (!::serialization::parse_binary(data, iadr) || !crypto::check_key(iadr.adr.m_spend_public_key) || !crypto::check_key(iadr.adr.m_view_public_key)) {
        if (!data.length()) {
            info.GetReturnValue().Set(Undefined(isolate));
            return;
        }
        data = uint64be_to_blob(prefix) + data;
        info.GetReturnValue().Set(CopyBuffer(isolate, data.data(), data.size()));
    } else {
        info.GetReturnValue().Set(Integer::NewFromUnsigned(isolate, static_cast<uint32_t>(prefix)));
    }
}

void get_merged_mining_nonce_size(const FunctionCallbackInfo<Value>& info) {
    info.GetReturnValue().Set(Integer::NewFromUnsigned(info.GetIsolate(), static_cast<uint32_t>(MM_NONCE_SIZE)));
}

void construct_mm_parent_block_blob(const FunctionCallbackInfo<Value>& info) { // (parentBlockTemplate, blob_type, childBlockTemplate)
    if (info.Length() < 3) return ThrowError(info.GetIsolate(), "You must provide three arguments (parentBlock, blob_type, childBlock).");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    Local<Object> child_target = info[2]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(target)) return ThrowError(isolate, "First argument should be a buffer object.");
    if (!info[1]->IsNumber()) return ThrowError(isolate, "Second argument should be a number");
    if (!Buffer::HasInstance(child_target)) return ThrowError(isolate, "Third argument should be a buffer object.");

    const enum BLOB_TYPE blob_type = static_cast<enum BLOB_TYPE>(ToInt32(isolate, info[1]));

    blobdata input       = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata child_input = std::string(Buffer::Data(child_target), Buffer::Length(child_target));

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(input, b)) return ThrowError(isolate, "construct_mm_parent_block_blob: Failed to parse prent block");
    if (blob_type == BLOB_TYPE_CRYPTONOTE_LOKI || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC) b.miner_tx.version = cryptonote::loki_version_2;
    if (blob_type == BLOB_TYPE_CRYPTONOTE_ARQMA) {
      b.miner_tx.version = static_cast<size_t>(cryptonote_arq::txversion::v3);
      b.miner_tx.arq_tx_type = cryptonote_arq::txtype::standard;
    }

    block b2 = AUTO_VAL_INIT(b2);
    b2.set_blob_type(BLOB_TYPE_FORKNOTE2);
    if (!parse_and_validate_block_from_blob(child_input, b2)) return ThrowError(isolate, "construct_mm_parent_block_blob: Failed to parse child block");

    if (!fillExtraMM(b, b2)) return ThrowError(isolate, "construct_mm_parent_block_blob: Failed to add merged mining tag to parent block extra");

    blobdata output = "";
    if (!block_to_blob(b, output)) return ThrowError(isolate, "construct_mm_parent_block_blob: Failed to convert child block to blob");
    info.GetReturnValue().Set(CopyBuffer(isolate, output.data(), output.size()));
}

void construct_mm_child_block_blob(const FunctionCallbackInfo<Value>& info) { // (shareBuffer, blob_type, childBlockTemplate)
    if (info.Length() < 3) return ThrowError(info.GetIsolate(), "You must provide three arguments (shareBuffer, blob_type, block2).");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> block_template_buf = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    Local<Object> child_block_template_buf = info[2]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(block_template_buf)) return ThrowError(isolate, "First argument should be a buffer object.");
    if (!info[1]->IsNumber()) return ThrowError(isolate, "Second argument should be a number");
    if (!Buffer::HasInstance(child_block_template_buf)) return ThrowError(isolate, "Third argument should be a buffer object.");

    const enum BLOB_TYPE blob_type = static_cast<enum BLOB_TYPE>(ToInt32(isolate, info[1]));

    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata child_block_template_blob = std::string(Buffer::Data(child_block_template_buf), Buffer::Length(child_block_template_buf));

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(block_template_blob, b)) return ThrowError(isolate, "construct_mm_child_block_blob: Failed to parse parent block");

    block b2 = AUTO_VAL_INIT(b2);
    b2.set_blob_type(BLOB_TYPE_FORKNOTE2);
    if (!parse_and_validate_block_from_blob(child_block_template_blob, b2)) return ThrowError(isolate, "construct_mm_child_block_blob: Failed to parse child block");

    if (!mergeBlocks(b, b2, std::vector<crypto::hash>())) return ThrowError(isolate, "construct_mm_child_block_blob: Failed to postprocess mining block");

    blobdata output = "";
    if (!block_to_blob(b2, output)) return ThrowError(isolate, "construct_mm_child_block_blob: Failed to convert child block to blob");
    info.GetReturnValue().Set(CopyBuffer(isolate, output.data(), output.size()));
}

void init(Local<Object> exports, Local<Value>, Local<Context> context, void*) {
    Isolate* isolate = context->GetIsolate();
    SetExport(isolate, exports, "construct_block_blob", construct_block_blob);
    SetExport(isolate, exports, "get_block_id", get_block_id);
    SetExport(isolate, exports, "convert_blob", convert_blob);
    SetExport(isolate, exports, "address_decode", address_decode);
    SetExport(isolate, exports, "address_decode_integrated", address_decode_integrated);
    SetExport(isolate, exports, "get_merged_mining_nonce_size", get_merged_mining_nonce_size);
    SetExport(isolate, exports, "construct_mm_parent_block_blob", construct_mm_parent_block_blob);
    SetExport(isolate, exports, "construct_mm_child_block_blob", construct_mm_child_block_blob);
}

NODE_MODULE_CONTEXT_AWARE(blocktemplate, init)
