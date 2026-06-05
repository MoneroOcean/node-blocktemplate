#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
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

inline void ThrowUnsupportedBlobType(Isolate* isolate) {
    ThrowError(isolate, "Unsupported blob type.");
}

}  // namespace

// Preserve the old exported nonce-size constant for callers that still import it.
const size_t MM_NONCE_SIZE = 1 + 2 + sizeof(crypto::hash);
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
    if (!is_supported_blob_type(blob_type)) return ThrowUnsupportedBlobType(isolate);

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(input, b)) return ThrowError(isolate, "Failed to parse block 2");

    if (!get_block_hashing_blob(b, output)) return ThrowError(isolate, "convert_blob: Failed to create mining block");

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
    if (!is_supported_blob_type(blob_type)) return ThrowUnsupportedBlobType(isolate);

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
    if (!is_supported_blob_type(blob_type)) return ThrowUnsupportedBlobType(isolate);

    if (Buffer::Length(nonce_buf) != 4) return ThrowError(isolate, "Nonce buffer has invalid size.");

    uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));
    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(block_template_blob, b)) return ThrowError(isolate, "Failed to parse block");

    b.nonce = nonce;

    if (blob_type == BLOB_TYPE_CRYPTONOTE_CUCKOO) {
        if (info.Length() != 4) return ThrowError(isolate, "You must provide 4 arguments.");
        Local<Array> cycle = Local<Array>::Cast(info[3]);
        for (int i = 0; i < 32; i++ ) b.cycle.data[i] = cycle->Get(isolate->GetCurrentContext(), i).ToLocalChecked()->NumberValue(isolate->GetCurrentContext()).ToChecked();
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
    return ThrowError(info.GetIsolate(), "Merged mining block construction is unsupported.");
}

void construct_mm_child_block_blob(const FunctionCallbackInfo<Value>& info) { // (shareBuffer, blob_type, childBlockTemplate)
    return ThrowError(info.GetIsolate(), "Merged mining block construction is unsupported.");
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
