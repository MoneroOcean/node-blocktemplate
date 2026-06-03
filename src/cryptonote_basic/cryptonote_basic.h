// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/variant.hpp>
#include <boost/functional/hash/hash.hpp>
#include <iostream>
#include <vector>
#include <cstring>  // memcmp
#include <sstream>
#include "serialization/serialization.h"
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/binary_archive.h"
#include "serialization/crypto.h"
#include "serialization/pricing_record.h"
#include "serialization/zephyr_pricing_record.h"
#include "serialization/keyvalue_serialization.h" // eepe named serialization
#include "string_tools.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "misc_language.h"
#include "tx_extra.h"
#include "ringct/rctTypes.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "cryptonote_protocol/enums.h"
#include "offshore/pricing_record.h"
#include "zephyr_oracle/pricing_record.h"
#include "salvium_oracle/pricing_record.h"
#include "carrot_core/core_types.h"
#include "arq_txtypes.h"


namespace cryptonote
{
  struct block;
  class transaction;
  class transaction_prefix;
  struct tx_extra_merge_mining_tag;

  // Implemented in cryptonote_format_utils.cpp
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h);
  void get_blob_hash(const blobdata& blob, crypto::hash& res);
  bool get_mm_tag_from_extra(const std::vector<uint8_t>& tx, tx_extra_merge_mining_tag& mm_tag);

  const static crypto::hash null_hash = AUTO_VAL_INIT(null_hash);
  const static crypto::public_key null_pkey = AUTO_VAL_INIT(null_pkey);

  typedef std::vector<crypto::signature> ring_signature;

  /* outputs */

  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  // outputs <= HF_VERSION_VIEW_TAGS
  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  // outputs >= HF_VERSION_VIEW_TAGS
  struct txout_to_tagged_key
  {
    txout_to_tagged_key() { }
    txout_to_tagged_key(const crypto::public_key &_key, const crypto::view_tag &_view_tag) : key(_key), view_tag(_view_tag) { }
    crypto::public_key key;
    crypto::view_tag view_tag; // optimization to reduce scanning time

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(view_tag)
    END_SERIALIZE()
  };

  // outputs <= HF_VERSION_VIEW_TAGS
  struct txout_haven_key
  {
    txout_haven_key() { }
    txout_haven_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time, const bool &_is_collateral, const bool &_is_collateral_change) : key(_key), asset_type(_asset_type), unlock_time(_unlock_time), is_collateral(_is_collateral), is_collateral_change(_is_collateral_change) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;
    bool is_collateral;
    bool is_collateral_change;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
      FIELD(is_collateral)
      FIELD(is_collateral_change)
    END_SERIALIZE()
  };

  // outputs >= HF_VERSION_VIEW_TAGS
  struct txout_haven_tagged_key
  {
    txout_haven_tagged_key() { }
    txout_haven_tagged_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time, const bool &_is_collateral, const bool &_is_collateral_change, const crypto::view_tag &_view_tag) : key(_key), asset_type(_asset_type), unlock_time(_unlock_time), is_collateral(_is_collateral), is_collateral_change(_is_collateral_change), view_tag(_view_tag) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;
    bool is_collateral;
    bool is_collateral_change;
    crypto::view_tag view_tag; // optimization to reduce scanning time

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
      FIELD(is_collateral)
      FIELD(is_collateral_change)
      FIELD(view_tag)
    END_SERIALIZE()
  };

  struct txout_offshore
  {
    txout_offshore() { }
    txout_offshore(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  struct txout_xasset
  {
    txout_xasset() { }
    txout_xasset(const crypto::public_key &_key, const std::string &_asset_type) : key(_key), asset_type(_asset_type) { }
    crypto::public_key key;
    std::string asset_type;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
    END_SERIALIZE()
  };

  // ZEPHYR
  struct txout_zephyr_tagged_key
  {
    txout_zephyr_tagged_key() { }
    txout_zephyr_tagged_key(const crypto::public_key &_key, const std::string &_asset_type, const crypto::view_tag &_view_tag) : key(_key), asset_type(_asset_type), view_tag(_view_tag) { }
    crypto::public_key key;
    std::string asset_type;
    crypto::view_tag view_tag; // optimization to reduce scanning time

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      FIELD(view_tag)
    END_SERIALIZE()
  };

  // SALVIUM
  struct txout_salvium_key
  {
    txout_salvium_key() { }
    txout_salvium_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time) :
      key(_key), asset_type(_asset_type), unlock_time(_unlock_time) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
    END_SERIALIZE()
  };

  struct txout_salvium_tagged_key
  {
    txout_salvium_tagged_key() { }
    txout_salvium_tagged_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time, const crypto::view_tag &_view_tag) :
      key(_key), asset_type(_asset_type), unlock_time(_unlock_time), view_tag(_view_tag) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;
    crypto::view_tag view_tag; // optimization to reduce scanning time

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
      FIELD(view_tag)
    END_SERIALIZE()
  };


  struct txout_to_carrot_v1
  {
    crypto::public_key key;                                  // K_o
    std::string asset_type;
    carrot::view_tag_t view_tag;                             // vt
    carrot::encrypted_janus_anchor_t encrypted_janus_anchor; // anchor_enc

    // Encrypted amount a_enc and amount commitment C_a are stored in rct::rctSigBase
    // This allows for reuse of this output type between coinbase and non-coinbase txs

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      FIELD(view_tag)
      FIELD(encrypted_janus_anchor)
    END_SERIALIZE()
  };

  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_offshore
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_onshore
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_haven_key
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(asset_type)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_xasset
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(asset_type)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_zephyr_key
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(asset_type)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_salvium_key
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(asset_type)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key, txin_offshore, txin_onshore, txin_xasset, txin_haven_key> txin_v;
  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_zephyr_key> txin_zephyr_v;
  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_salvium_key> txin_salvium_v;

  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key, txout_to_tagged_key> txout_target_v;
  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key, txout_offshore, txout_xasset, txout_haven_key, txout_haven_tagged_key> txout_xhv_target_v;
  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_salvium_key, txout_salvium_tagged_key> txout_salvium_target_v;
  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_salvium_key, txout_salvium_tagged_key, txout_to_carrot_v1> txout_carrot_target_v;

  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_zephyr_tagged_key> txout_stablero_target_v;

  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  struct tx_out_xhv
  {
    uint64_t amount;
    txout_xhv_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  struct tx_out_zephyr
  {
    uint64_t amount;
    txout_stablero_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  struct tx_out_salvium
  {
    uint64_t amount;
    txout_carrot_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  class protocol_tx_data_t {
  public:
    uint8_t version;
    crypto::public_key return_address;
    crypto::public_key return_pubkey;
    carrot::view_tag_t return_view_tag;
    carrot::encrypted_janus_anchor_t return_anchor_enc;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(version)
      FIELD(return_address)
      FIELD(return_pubkey)
      FIELD(return_view_tag)
      FIELD(return_anchor_enc)
    END_SERIALIZE()
  };

  struct erc_token_t
  {
    uint8_t version;
    std::string contract_address;
    std::string lockbox_address;
    std::string ticker;
    uint64_t erc20_asset_id;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(version)
      FIELD(contract_address)
      FIELD(lockbox_address)
      FIELD(ticker)
      VARINT_FIELD(erc20_asset_id)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(contract_address)
      KV_SERIALIZE(lockbox_address)
      KV_SERIALIZE(ticker)
      KV_SERIALIZE(erc20_asset_id)
    END_KV_SERIALIZE_MAP()
  };

  struct sal_token_t
  {
    uint8_t version;
    uint64_t supply;
    uint64_t size;
    std::string name;
    std::string url;
    crypto::hash signature;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(version)
      VARINT_FIELD(supply)
      VARINT_FIELD(size)
      FIELD(name)
      FIELD(url)
      FIELD(signature)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(supply)
      KV_SERIALIZE(size)
      KV_SERIALIZE(name)
      KV_SERIALIZE(url)
    END_KV_SERIALIZE_MAP()
  };

  #define TOKEN_TYPE_UNSET 0
  #define TOKEN_TYPE_ERC20 1
  #define TOKEN_TYPE_SAL   2

  typedef boost::variant<erc_token_t, sal_token_t> token_v;

  struct token_metadata_t
  {
    uint8_t version;
    std::string asset_type;
    token_v token;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(version)
      FIELD(asset_type)
      FIELD(token)
    END_SERIALIZE()
  };

  class layer2_rollup_tx_t {
  public:
    crypto::hash tx_prefix_hash;
    crypto::key_image first_key_image;
    uint64_t tx_fee;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(tx_prefix_hash)
      FIELD(first_key_image)
      VARINT_FIELD(tx_fee)
    END_SERIALIZE()
  };

  class layer2_rollup_data_t {
  public:
    uint8_t version;
    std::vector<layer2_rollup_tx_t> txs;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(version)
      FIELD(txs)
    END_SERIALIZE()
  };


  enum xeq_xtnc_version
  {
    xeq_xtnc_version_0 = 0,
    xeq_xtnc_version_1,
    xeq_xtnc_version_2,
    xeq_xtnc_version_3_per_output_unlock_times,
    xeq_xtnc_version_4_tx_types,
  };

  class transaction_prefix
  {

  public:
    enum BLOB_TYPE blob_type;
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    cryptonote_arq::txtype arq_tx_type;

    std::vector<txin_v> vin;
    std::vector<txin_zephyr_v> vin_zephyr;
    std::vector<txin_salvium_v> vin_salvium;
    std::vector<tx_out> vout;
    std::vector<tx_out_xhv> vout_xhv;
    std::vector<tx_out_zephyr> vout_zephyr;
    std::vector<tx_out_salvium> vout_salvium;
    //extra
    std::vector<uint8_t> extra;
    // Block height to use PR from
    uint64_t pricing_record_height;
    // Circulating supply information
    std::vector<uint8_t> offshore_data;
    uint64_t amount_burnt;
    uint64_t amount_minted;
    std::vector<uint64_t> output_unlock_times;
    std::vector<uint32_t> collateral_indices;

    // SALVIUM-SPECIFIC FIELDS
    // TX type
    cryptonote::salvium_transaction_type sal_tx_type;
    crypto::public_key return_address;
    // Return address list (must be at least 1 and at most BULLETPROOF_MAX_OUTPUTS-1 - the "-1" is for the change output)
    std::vector<crypto::public_key> return_address_list;
    //return_address_change_mask
    std::vector<uint8_t> return_address_change_mask;
    // Return TX public key
    crypto::public_key return_pubkey;
    // Source asset type
    std::string source_asset_type;
    // Destination asset type (this is only necessary for CONVERT transactions)
    std::string destination_asset_type;
    // Circulating supply information - already provided by Haven
    //uint64_t amount_burnt;
    // Slippage limit
    uint64_t amount_slippage_limit;
    protocol_tx_data_t protocol_tx_data;
    carrot::rollup_binding_tag_t rollup_binding_tag;
    token_metadata_t token_metadata;
    layer2_rollup_data_t layer2_rollup_data;


    //
    // XEQ/XTNC transaction type.
    //
    enum xeq_xtnc_type_t
    {
      xeq_xtnc_type_standard,
      xeq_xtnc_type_deregister,
      xeq_xtnc_type_key_image_unlock,
      xeq_xtnc_type_count,
    };

    union
    {
      bool is_deregister;
      uint16_t type;
    };

    BEGIN_SERIALIZE()
      if (blob_type == BLOB_TYPE_CRYPTONOTE_XHV) {
        VARINT_FIELD(version)
          //if(version == 0 || CURRENT_TRANSACTION_VERSION < version) return false;

        // Only transactions prior to HAVEN_TYPES_TRANSACTION_VERSION are permitted to be anything other than HAVEN_TYPES and need translation
        if (version < HAVEN_TYPES_TRANSACTION_VERSION) {

          if (version < POU_TRANSACTION_VERSION) {
            VARINT_FIELD(unlock_time)
          }
          if (!typename Archive<W>::is_saving()) {
            FIELD(vin)
            FIELD(vout_xhv)
            FIELD(extra)
            if(version >= OFFSHORE_TRANSACTION_VERSION) {
              VARINT_FIELD(pricing_record_height)
              if (version < 5)
                FIELD(offshore_data)
              if (version >= POU_TRANSACTION_VERSION) {
                FIELD(output_unlock_times)
                if (vout_xhv.size() != output_unlock_times.size()) {
                  return false;
                }
              }
              VARINT_FIELD(amount_burnt)
              VARINT_FIELD(amount_minted)
              if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {
                FIELD(collateral_indices)
                if (collateral_indices.size() != 2) {
                  return false;
                }
                for (const auto vout_idx: collateral_indices) {
                  if (vout_idx >= vout_xhv.size())
                    return false;
                }
              }
            }
            std::vector<txin_v> vin_tmp(vin);
            bool is_conversion_tx = (amount_burnt != 0);
            bool is_offshore_tx = is_conversion_tx;
            bool is_onshore_tx = false;
            vin.clear();
            for (auto &vin_entry: vin_tmp) {
              if (vin_entry.type() == typeid(txin_gen)) {
                vin.push_back(vin_entry);
                continue;
              }
              txin_haven_key in;
              if (vin_entry.type() == typeid(txin_to_key)) {
                in.asset_type = "XHV";
                in.amount = boost::get<txin_to_key>(vin_entry).amount;
                in.key_offsets = boost::get<txin_to_key>(vin_entry).key_offsets;
                in.k_image = boost::get<txin_to_key>(vin_entry).k_image;
              } else if (vin_entry.type() == typeid(txin_offshore)) {
                is_offshore_tx = false;
                is_onshore_tx = false;
                in.asset_type = "XUSD";
                in.amount = boost::get<txin_offshore>(vin_entry).amount;
                in.key_offsets = boost::get<txin_offshore>(vin_entry).key_offsets;
                in.k_image = boost::get<txin_offshore>(vin_entry).k_image;
              } else if (vin_entry.type() == typeid(txin_onshore)) {
                is_offshore_tx = false;
                is_onshore_tx = true;
                in.asset_type = "XUSD";
                in.amount = boost::get<txin_onshore>(vin_entry).amount;
                in.key_offsets = boost::get<txin_onshore>(vin_entry).key_offsets;
                in.k_image = boost::get<txin_onshore>(vin_entry).k_image;
              } else if (vin_entry.type() == typeid(txin_xasset)) {
                is_offshore_tx = false;
                is_onshore_tx = false;
                in.amount = boost::get<txin_xasset>(vin_entry).amount;
                in.key_offsets = boost::get<txin_xasset>(vin_entry).key_offsets;
                in.k_image = boost::get<txin_xasset>(vin_entry).k_image;
                in.asset_type = boost::get<txin_xasset>(vin_entry).asset_type;
              } else {
                return false;
              }
              vin.push_back(in);
            }
            std::vector<tx_out_xhv> vout_tmp(vout_xhv);
            vout_xhv.clear();
            for (size_t i=0; i<vout_tmp.size(); i++) {
              txout_haven_key out;
              if (vout_tmp[i].target.type() == typeid(txout_to_key)) {
                out.asset_type = "XHV";
                out.key = boost::get<txout_to_key>(vout_tmp[i].target).key;
              } else if (vout_tmp[i].target.type() == typeid(txout_offshore)) {
                out.asset_type = "XUSD";
                out.key = boost::get<txout_offshore>(vout_tmp[i].target).key;
              } else if (vout_tmp[i].target.type() == typeid(txout_xasset)) {
                out.asset_type = boost::get<txout_xasset>(vout_tmp[i].target).asset_type;
                out.key = boost::get<txout_xasset>(vout_tmp[i].target).key;
              } else {
                return false;
              }
              out.unlock_time = (version >= POU_TRANSACTION_VERSION) ? output_unlock_times[i] : unlock_time;
              out.is_collateral = false;
              out.is_collateral_change = false;
              if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {
                if (((is_onshore_tx) &&
                     (collateral_indices[0] == i)) ||
                    ((!is_onshore_tx) &&
                     (is_offshore_tx) &&
                     (collateral_indices[0] == i && collateral_indices[1] == 0))) {
                    out.is_collateral = true;
                }
                if (is_onshore_tx && collateral_indices[1] == i) {
                  out.is_collateral_change = true;
                }
              }
              tx_out_xhv foo;
              foo.amount = vout_tmp[i].amount;
              foo.target = out;
              vout_xhv.push_back(foo);
            }
            return true;
          }
          bool is_offshore_tx = (amount_burnt != 0);
          bool is_onshore_tx = false;
          std::vector<txin_v> vin_tmp;
          vin_tmp.reserve(vin.size());
          for (auto &vin_entry_v: vin) {
            if (vin_entry_v.type() == typeid(txin_gen)) {
              vin_tmp.push_back(vin_entry_v);
              continue;
            }
            txin_haven_key vin_entry = boost::get<txin_haven_key>(vin_entry_v);
            if (vin_entry.asset_type == "XHV") {
              txin_to_key in;
              in.amount = vin_entry.amount;
              in.key_offsets = vin_entry.key_offsets;
              in.k_image = vin_entry.k_image;
              vin_tmp.push_back(in);
            } else if (vin_entry.asset_type == "XUSD") {
              is_offshore_tx = false;
              int xhv_outputs = std::count_if(vout_xhv.begin(), vout_xhv.end(), [](tx_out_xhv &foo_v) {
                if (foo_v.target.type() == typeid(txout_haven_key)) {
                  txout_haven_key out = boost::get<txout_haven_key>(foo_v.target);
                  return out.asset_type == "XHV";
                } else if (foo_v.target.type() == typeid(txout_haven_tagged_key)) {
                  txout_haven_tagged_key out = boost::get<txout_haven_tagged_key>(foo_v.target);
                  return out.asset_type == "XHV";
                } else {
                  return false;
                }
              });
              if (xhv_outputs) {
                is_onshore_tx = true;
                txin_onshore in;
                in.amount = vin_entry.amount;
                in.key_offsets = vin_entry.key_offsets;
                in.k_image = vin_entry.k_image;
                vin_tmp.push_back(in);
              } else {
                txin_offshore in;
                in.amount = vin_entry.amount;
                in.key_offsets = vin_entry.key_offsets;
                in.k_image = vin_entry.k_image;
                vin_tmp.push_back(in);
              }
            } else {
              is_offshore_tx = false;
              txin_xasset in;
              in.amount = vin_entry.amount;
              in.asset_type = vin_entry.asset_type;
              in.key_offsets = vin_entry.key_offsets;
              in.k_image = vin_entry.k_image;
              vin_tmp.push_back(in);
            }
          }
          std::vector<tx_out_xhv> vout_tmp;
          vout_tmp.reserve(vout_xhv.size());
          output_unlock_times.resize(vout_xhv.size());
          std::vector<uint32_t> collateral_indices_temp;
          collateral_indices_temp.resize(2);
          for (size_t i=0; i<vout_xhv.size(); i++) {
            txout_haven_key outhk = boost::get<txout_haven_key>(vout_xhv[i].target);
            tx_out_xhv foo;
            foo.amount = vout_xhv[i].amount;
            if (outhk.asset_type == "XHV") {
              txout_to_key out;
              out.key = outhk.key;
              foo.target = out;
            } else if (outhk.asset_type == "XUSD") {
              txout_offshore out;
              out.key = outhk.key;
              foo.target = out;
            } else {
              txout_xasset out;
              out.asset_type = outhk.asset_type;
              out.key = outhk.key;
              foo.target = out;
            }
            output_unlock_times[i] = outhk.unlock_time;
            if (outhk.is_collateral) {
              collateral_indices_temp[0] = i;
            } else if (outhk.is_collateral_change) {
              collateral_indices_temp[1] = i;
            }
            vout_tmp.push_back(foo);
          }
          FIELD_N("vin", vin_tmp)
          FIELD_N("vout", vout_tmp)
          FIELD(extra)
          if(version >= OFFSHORE_TRANSACTION_VERSION) {
            VARINT_FIELD(pricing_record_height)
            if (version < 5)
              FIELD(offshore_data)
            if (version >= POU_TRANSACTION_VERSION) {
              FIELD(output_unlock_times)
              if (vout_xhv.size() != output_unlock_times.size()) {
                return false;
              }
            }
            VARINT_FIELD(amount_burnt)
            VARINT_FIELD(amount_minted)
            if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {
              if (collateral_indices.size() != 2) {
                if ((is_offshore_tx || is_onshore_tx) && collateral_indices_temp.size() != 2) {
                  return false;
                }
                if (is_offshore_tx || is_onshore_tx) {
                  collateral_indices = collateral_indices_temp;
                } else {
                  collateral_indices.clear();
                  collateral_indices.push_back(0);
                  collateral_indices.push_back(0);
                }
              }
              FIELD(collateral_indices)
              for (const auto vout_idx: collateral_indices) {
                if (vout_idx >= vout_xhv.size())
                  return false;
              }
            }
          }
          return true;
        }

        FIELD(vin)
        FIELD(vout_xhv)
        FIELD(extra)
        VARINT_FIELD(pricing_record_height)
        VARINT_FIELD(amount_burnt)
        VARINT_FIELD(amount_minted)

      } else if (blob_type == BLOB_TYPE_CRYPTONOTE_SALVIUM) {

        VARINT_FIELD(version)
        if(version == 0 || TRANSACTION_VERSION_ENABLE_TOKENS < version) return false;
        VARINT_FIELD(unlock_time)
        FIELD(vin_salvium)
        FIELD(vout_salvium)
        FIELD(extra)
        VARINT_FIELD(sal_tx_type)
        if (sal_tx_type != cryptonote::salvium_transaction_type::UNSET && sal_tx_type != cryptonote::salvium_transaction_type::PROTOCOL) {
          VARINT_FIELD(amount_burnt)
          if (sal_tx_type != cryptonote::salvium_transaction_type::MINER) {
            if (sal_tx_type == cryptonote::salvium_transaction_type::TRANSFER && version >= TRANSACTION_VERSION_N_OUTS) {
              FIELD(return_address_list)
              FIELD(return_address_change_mask)
            } else {
              if ((sal_tx_type == cryptonote::salvium_transaction_type::STAKE ||
                   sal_tx_type == cryptonote::salvium_transaction_type::CREATE_TOKEN) &&
                  version >= TRANSACTION_VERSION_CARROT)
              {
                FIELD(protocol_tx_data)
              } else {
                FIELD(return_address)
                FIELD(return_pubkey)
              }
            }
            FIELD(source_asset_type)
            FIELD(destination_asset_type)
            VARINT_FIELD(amount_slippage_limit)
          }
        }
        if (version >= TRANSACTION_VERSION_ENABLE_TOKENS) {
          if (sal_tx_type == cryptonote::salvium_transaction_type::CREATE_TOKEN) {
            FIELD(token_metadata)
          } else if (sal_tx_type == cryptonote::salvium_transaction_type::TRANSFER) {
            FIELD(rollup_binding_tag)
          } else if (sal_tx_type == cryptonote::salvium_transaction_type::ROLLUP) {
            FIELD(rollup_binding_tag)
            FIELD(layer2_rollup_data)
          }
        }

      } else {

        VARINT_FIELD(version)
        if (version > xeq_xtnc_version_2 && (blob_type == BLOB_TYPE_CRYPTONOTE_XEQ || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC))
        {
          FIELD(output_unlock_times)
          if (version == xeq_xtnc_version_3_per_output_unlock_times)
            FIELD(is_deregister)
        }

        if (version >= static_cast<size_t>(cryptonote_arq::txversion::v3) && (blob_type == BLOB_TYPE_CRYPTONOTE_ARQMA))
        {
          VARINT_FIELD(arq_tx_type)
          if (static_cast<uint16_t>(arq_tx_type) >= static_cast<uint16_t>(cryptonote_arq::txtype::_count))
            return false;
          FIELD(output_unlock_times)
        }

        VARINT_FIELD(unlock_time)

        if (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR)
          FIELD(vin_zephyr)
        else
          FIELD(vin)

        if (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR)
          FIELD(vout_zephyr)
        else
          FIELD(vout)

        if (blob_type == BLOB_TYPE_CRYPTONOTE_XEQ || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC || blob_type == BLOB_TYPE_CRYPTONOTE_ARQMA)
        {
          if ((version >= xeq_xtnc_version_3_per_output_unlock_times || version >= static_cast<size_t>(cryptonote_arq::txversion::v3)) && vout.size() != output_unlock_times.size())
            return false;
        }
        FIELD(extra)
        if ((blob_type == BLOB_TYPE_CRYPTONOTE_XEQ || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC) && version >= xeq_xtnc_version_4_tx_types)
        {
          VARINT_FIELD(type)
          if (static_cast<uint16_t>(type) >= xeq_xtnc_type_count) return false;
        }
        if (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR) {
          VARINT_FIELD(pricing_record_height)
          VARINT_FIELD(amount_burnt)
          VARINT_FIELD(amount_minted)
        }
      }
    END_SERIALIZE()


  protected:
    transaction_prefix() : blob_type(BLOB_TYPE_CRYPTONOTE) {}
  };

  class transaction: public transaction_prefix
  {
  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    transaction();
    virtual ~transaction();
    void set_null();

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1 && blob_type != BLOB_TYPE_CRYPTONOTE2 && blob_type != BLOB_TYPE_CRYPTONOTE3)
      {
        ar.tag("signatures");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
        bool signatures_not_expected = signatures.empty();
        if (!signatures_not_expected && vin.size() != signatures.size())
          return false;

        for (size_t i = 0; i < vin.size(); ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (signatures_not_expected)
          {
            if (0 == signature_size)
              continue;
            else
              return false;
          }

          PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
          if (signature_size != signatures[i].size())
            return false;

          FIELDS(signatures[i]);

          if (vin.size() - i > 1)
            ar.delimit_array();
        }
        ar.end_array();
      }
      else
      {
        ar.tag("rct_signatures");
        if (blob_type == BLOB_TYPE_CRYPTONOTE_SALVIUM ? !vin_salvium.empty() : (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR ? !vin_zephyr.empty() : !vin.empty()))
        {
          ar.begin_object();
          bool r;
          if (blob_type == BLOB_TYPE_CRYPTONOTE_XHV)
            r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout_xhv.size());
          else if (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR)
            r = rct_signatures.serialize_rctsig_base(ar, vin_zephyr.size(), vout_zephyr.size());
          else if (blob_type == BLOB_TYPE_CRYPTONOTE_SALVIUM)
            r = rct_signatures.serialize_rctsig_base(ar, vin_salvium.size(), vout_salvium.size());
          else
            r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.stream().good()) return false;
          ar.end_object();
          if (rct_signatures.type != rct::RCTTypeNull)
          {
            ar.tag("rctsig_prunable");
            ar.begin_object();
            if (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR) {
              r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin_zephyr.size(), vout_zephyr.size(),
                  vin_zephyr[0].type() == typeid(txin_zephyr_key) ? boost::get<txin_zephyr_key>(vin_zephyr[0]).key_offsets.size() - 1 : 0);
            } else if (blob_type == BLOB_TYPE_CRYPTONOTE_SALVIUM) {
              r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin_salvium.size(), vout_salvium.size(),
                  vin_salvium[0].type() == typeid(txin_salvium_key) ? boost::get<txin_salvium_key>(vin_salvium[0]).key_offsets.size() - 1 : 0);
            } else if (blob_type == BLOB_TYPE_CRYPTONOTE_XHV) {
              r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin.size(), vout_xhv.size(),
                  vin.size() > 0 && vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(vin[0]).key_offsets.size() - 1 :
                  vin.size() > 0 && vin[0].type() == typeid(txin_offshore) ? boost::get<txin_offshore>(vin[0]).key_offsets.size() - 1 :
                  vin.size() > 0 && vin[0].type() == typeid(txin_onshore) ? boost::get<txin_onshore>(vin[0]).key_offsets.size() - 1 :
                  vin.size() > 0 && vin[0].type() == typeid(txin_xasset) ? boost::get<txin_xasset>(vin[0]).key_offsets.size() - 1 :
                  vin.size() > 0 && vin[0].type() == typeid(txin_haven_key) ? boost::get<txin_haven_key>(vin[0]).key_offsets.size() - 1 :
                  0
              );
            } else {
              r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin.size(), vout.size(),
                  vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(vin[0]).key_offsets.size() - 1 : 0);
            }
            if (!r || !ar.stream().good()) return false;
            ar.end_object();
          }
        }
      }
    END_SERIALIZE()

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };

  inline
  transaction::transaction()
  {
    set_null();
  }

  inline
  transaction::~transaction()
  {
    //set_null();
  }

  inline
  void transaction::set_null()
  {
    version = 0;
    unlock_time = 0;
    vin.clear();
    vin_zephyr.clear();
    vout.clear();
    vout_xhv.clear();
    vout_zephyr.clear();
    extra.clear();
    signatures.clear();
    pricing_record_height = 0;
    offshore_data.clear();
    amount_burnt = 0;
    amount_minted = 0;
    output_unlock_times.clear();
    collateral_indices.clear();
    // SAL
    sal_tx_type = cryptonote::salvium_transaction_type::UNSET;
    return_address = cryptonote::null_pkey;
    return_address_list.clear();
    return_address_change_mask.clear();
    return_pubkey = cryptonote::null_pkey;
    protocol_tx_data.return_address = cryptonote::null_pkey;
    protocol_tx_data.return_pubkey = cryptonote::null_pkey;
    protocol_tx_data.return_view_tag = {};
    protocol_tx_data.return_anchor_enc = {};
    source_asset_type.clear();
    destination_asset_type.clear();
    amount_slippage_limit = 0;
    rollup_binding_tag = {0};
    token_metadata = {};
    layer2_rollup_data = {};
    // ARQ
    arq_tx_type = cryptonote_arq::txtype::standard;
  }

  inline
  size_t transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_script& txin) const{return 0;}
      size_t operator()(const txin_to_scripthash& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_offshore& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_onshore& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_xasset& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_haven_key& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_zephyr_key& txin) const {return txin.key_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  const uint8_t CURRENT_BYTECOIN_BLOCK_MAJOR_VERSION = 1;

  struct bytecoin_block
  {
    uint8_t major_version;
    uint8_t minor_version;
    crypto::hash prev_id;
    uint32_t nonce;
    size_t number_of_transactions;
    std::vector<crypto::hash> miner_tx_branch;
    transaction miner_tx;
    std::vector<crypto::hash> blockchain_branch;
  };

  struct serializable_bytecoin_block
  {
    bytecoin_block& b;
    uint64_t& timestamp;
    bool hashing_serialization;
    bool header_only;

    serializable_bytecoin_block(bytecoin_block& b_, uint64_t& timestamp_, bool hashing_serialization_, bool header_only_) :
      b(b_), timestamp(timestamp_), hashing_serialization(hashing_serialization_), header_only(header_only_)
    {
    }

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD_N("major_version", b.major_version);
      VARINT_FIELD_N("minor_version", b.minor_version);
      VARINT_FIELD(timestamp);
      FIELD_N("prev_id", b.prev_id);
      FIELD_N("nonce", b.nonce);

      if (hashing_serialization)
      {
        crypto::hash miner_tx_hash;

        if (b.miner_tx.version < 2) {
          if (!get_transaction_hash(b.miner_tx, miner_tx_hash))
            return false;
        } else {
          get_transaction_prefix_hash(static_cast<const transaction_prefix&>(b.miner_tx), miner_tx_hash);
          const uint8_t data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d, 0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
          blobdata blobdata((char*)data, sizeof(data));
          const unsigned char* p = (unsigned char*)&miner_tx_hash;
          for (int i = 0; i != crypto::HASH_SIZE; ++ i, ++ p) blobdata[i] = *p;
          get_blob_hash(blobdata, miner_tx_hash);
        }

        crypto::hash merkle_root;
        crypto::tree_hash_from_branch(b.miner_tx_branch.data(), b.miner_tx_branch.size(), miner_tx_hash, 0, merkle_root);

        FIELD(merkle_root);
      }

      VARINT_FIELD_N("number_of_transactions", b.number_of_transactions);
      if (b.number_of_transactions < 1)
        return false;

      if (!header_only)
      {
        ar.tag("miner_tx_branch");
        ar.begin_array();
        size_t branch_size = crypto::tree_depth(b.number_of_transactions);
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(branch_size, const_cast<bytecoin_block&>(b).miner_tx_branch);
        if (b.miner_tx_branch.size() != branch_size)
          return false;
        for (size_t i = 0; i < branch_size; ++i)
        {
          FIELDS(b.miner_tx_branch[i]);
          if (i + 1 < branch_size)
            ar.delimit_array();
        }
        ar.end_array();

        FIELD(b.miner_tx);

        tx_extra_merge_mining_tag mm_tag;
        if (!get_mm_tag_from_extra(b.miner_tx.extra, mm_tag))
          return false;

        ar.tag("blockchain_branch");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(mm_tag.depth, const_cast<bytecoin_block&>(b).blockchain_branch);
        if (mm_tag.depth != b.blockchain_branch.size())
          return false;
        for (size_t i = 0; i < mm_tag.depth; ++i)
        {
          FIELDS(b.blockchain_branch[i]);
          if (i + 1 < mm_tag.depth)
            ar.delimit_array();
        }
        ar.end_array();
      }
    END_SERIALIZE()
  };

  // Implemented below
  inline serializable_bytecoin_block make_serializable_bytecoin_block(const block& b, bool hashing_serialization, bool header_only);

  struct block_header
  {
    enum BLOB_TYPE blob_type;

    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash prev_id;
    uint64_t nonce;
    uint64_t nonce8;
    offshore::pricing_record pricing_record;
    zephyr_oracle::pricing_record zephyr_pricing_record;
    salvium_oracle::pricing_record salvium_pricing_record;
    crypto::cycle cycle;
    crypto::cycle40 cycle40;
    crypto::cycle48 cycle48;
    crypto::signature signature;

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      if (blob_type != BLOB_TYPE_FORKNOTE2) VARINT_FIELD(timestamp)
      FIELD(prev_id)
      if (blob_type == BLOB_TYPE_CRYPTONOTE_CUCKOO || blob_type == BLOB_TYPE_CRYPTONOTE_TUBE || blob_type == BLOB_TYPE_CRYPTONOTE_XTA) FIELD(nonce8)
      if (blob_type != BLOB_TYPE_FORKNOTE2) {
        if (blob_type == BLOB_TYPE_AEON) {
          FIELD(nonce)
        } else {
          uint32_t nonce32;
          if (typename Archive<W>::is_saving())  nonce32 = (uint32_t)nonce;
          FIELD_N("nonce", nonce32);
          if (!typename Archive<W>::is_saving()) nonce = nonce32;
        }
      }
      if (blob_type == BLOB_TYPE_CRYPTONOTE_XTNC || blob_type == BLOB_TYPE_CRYPTONOTE_CUCKOO) FIELD(cycle)
      if (blob_type == BLOB_TYPE_CRYPTONOTE_TUBE) FIELD(cycle40)
      if (blob_type == BLOB_TYPE_CRYPTONOTE_XTA) FIELD(cycle48)
      if (blob_type == BLOB_TYPE_CRYPTONOTE_XHV) {
        FIELD(pricing_record)
      } else if (blob_type == BLOB_TYPE_CRYPTONOTE_SALVIUM) {
        if (major_version >= 255) FIELD(salvium_pricing_record)
      } else if (blob_type == BLOB_TYPE_CRYPTONOTE_ZEPHYR) {
        if (major_version >= 6)
        {
          FIELD_N("pricing_record", zephyr_pricing_record)
        }
        else if (major_version >= 4)
        {
          zephyr_oracle::pricing_record_v3 pr_v3;
          if (!typename Archive<W>::is_saving())
          {
            FIELD(pr_v3)
            pr_v3.write_to_pr(zephyr_pricing_record);
          }
          else
          {
            pr_v3.read_from_pr(zephyr_pricing_record);
            FIELD(pr_v3)
          }
        }
        else if (major_version >= 3)
        {
          zephyr_oracle::pricing_record_v2 pr_v2;
          if (!typename Archive<W>::is_saving())
          {
            FIELD(pr_v2)
            pr_v2.write_to_pr(zephyr_pricing_record);
          }
          else
          {
            pr_v2.read_from_pr(zephyr_pricing_record);
            FIELD(pr_v2)
          }
        }
        else
        {
          zephyr_oracle::pricing_record_v1 pr_v1;
          if (!typename Archive<W>::is_saving())
          {
            FIELD(pr_v1)
            pr_v1.write_to_pr(zephyr_pricing_record);
          }
          else
          {
            pr_v1.read_from_pr(zephyr_pricing_record);
            FIELD(pr_v1)
          }
        }
      }
      if (blob_type == BLOB_TYPE_CRYPTONOTE_XLA && major_version >= 13) FIELD(signature)

    END_SERIALIZE()
  };

  struct block: public block_header
  {
    bytecoin_block parent_block;

    transaction miner_tx;
    transaction protocol_tx;
    std::vector<crypto::hash> tx_hashes;
    mutable crypto::hash uncle = cryptonote::null_hash;

    void set_blob_type(enum BLOB_TYPE bt) { miner_tx.blob_type = protocol_tx.blob_type = blob_type = bt; }

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<block_header *>(this))
      if (blob_type == BLOB_TYPE_FORKNOTE2)
      {
        auto sbb = make_serializable_bytecoin_block(*this, false, false);
        FIELD_N("parent_block", sbb);
      }
      FIELD(miner_tx)
      if (blob_type == BLOB_TYPE_CRYPTONOTE_SALVIUM)
      {
        FIELD(protocol_tx)
      }
      FIELD(tx_hashes)
      if (blob_type == BLOB_TYPE_CRYPTONOTE3)
      {
        FIELD(uncle)
      }
    END_SERIALIZE()
  };

  inline serializable_bytecoin_block make_serializable_bytecoin_block(const block& b, bool hashing_serialization, bool header_only)
  {
    block& block_ref = const_cast<block&>(b);
    return serializable_bytecoin_block(block_ref.parent_block, block_ref.timestamp, hashing_serialization, header_only);
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;
    bool m_is_carrot;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()

    bool operator==(const account_public_address& rhs) const
    {
      return m_spend_public_key == rhs.m_spend_public_key &&
             m_view_public_key == rhs.m_view_public_key &&
             m_is_carrot == rhs.m_is_carrot;
    }

    bool operator!=(const account_public_address& rhs) const
    {
      return !(*this == rhs);
    }
  };

  struct integrated_address {
    account_public_address adr;
    crypto::hash8 payment_id;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(adr)
    FIELD(payment_id)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(adr)
    KV_SERIALIZE(payment_id)
    END_KV_SERIALIZE_MAP()
  };
  //---------------------------------------------------------------

}

BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_offshore);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

VARIANT_TAG(binary_archive, cryptonote::txin_gen, 0xff);
VARIANT_TAG(binary_archive, cryptonote::txin_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txin_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txin_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txin_zephyr_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txin_offshore, 0x3);
VARIANT_TAG(binary_archive, cryptonote::txin_salvium_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txin_onshore, 0x4);
VARIANT_TAG(binary_archive, cryptonote::txin_xasset, 0x5);
VARIANT_TAG(binary_archive, cryptonote::txin_haven_key, 0x6);
VARIANT_TAG(binary_archive, cryptonote::txout_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txout_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txout_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_salvium_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_zephyr_tagged_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_to_tagged_key, 0x3);
VARIANT_TAG(binary_archive, cryptonote::txout_salvium_tagged_key, 0x3);
VARIANT_TAG(binary_archive, cryptonote::txout_offshore, 0x3);
VARIANT_TAG(binary_archive, cryptonote::txout_to_carrot_v1, 0x4);
VARIANT_TAG(binary_archive, cryptonote::protocol_tx_data_t, 0x0);
VARIANT_TAG(binary_archive, cryptonote::token_metadata_t, 0x0);
VARIANT_TAG(binary_archive, cryptonote::erc_token_t, 0x0);
VARIANT_TAG(binary_archive, cryptonote::sal_token_t, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txout_xasset, 0x5);
VARIANT_TAG(binary_archive, cryptonote::txout_haven_key, 0x6);
VARIANT_TAG(binary_archive, cryptonote::txout_haven_tagged_key, 0x7);
VARIANT_TAG(binary_archive, cryptonote::transaction, 0xcc);
VARIANT_TAG(binary_archive, cryptonote::block, 0xbb);
