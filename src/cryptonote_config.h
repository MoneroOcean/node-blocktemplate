#pragma once

#include <cstddef>

#define CURRENT_TRANSACTION_VERSION      1
#define HF_VERSION_ENABLE_N_OUTS         2
#define TRANSACTION_VERSION_N_OUTS       3
#define TRANSACTION_VERSION_CARROT       4
#define TRANSACTION_VERSION_ENABLE_TOKENS 5

// UNLOCK TIMES

#define PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK       120  // seconds

enum BLOB_TYPE {
  BLOB_TYPE_CRYPTONOTE        = 0,
  BLOB_TYPE_FORKNOTE1         = 1,
  BLOB_TYPE_CRYPTONOTE_RYO    = 4, // Ryo
  BLOB_TYPE_CRYPTONOTE3       = 6, // Masari
  BLOB_TYPE_CRYPTONOTE_CUCKOO = 8, // MoneroV / Swap
  BLOB_TYPE_CRYPTONOTE_ZEPHYR = 13, // ZEPHYR
  BLOB_TYPE_CRYPTONOTE_XLA    = 14, // XLA
  BLOB_TYPE_CRYPTONOTE_SALVIUM= 15, // Salvium
  BLOB_TYPE_CRYPTONOTE_ARQMA  = 16  // Arqma
};

inline bool is_supported_blob_type(enum BLOB_TYPE blob_type) {
  switch (blob_type) {
    case BLOB_TYPE_CRYPTONOTE:
    case BLOB_TYPE_FORKNOTE1:
    case BLOB_TYPE_CRYPTONOTE_RYO:
    case BLOB_TYPE_CRYPTONOTE3:
    case BLOB_TYPE_CRYPTONOTE_CUCKOO:
    case BLOB_TYPE_CRYPTONOTE_ZEPHYR:
    case BLOB_TYPE_CRYPTONOTE_XLA:
    case BLOB_TYPE_CRYPTONOTE_SALVIUM:
    case BLOB_TYPE_CRYPTONOTE_ARQMA:
      return true;
    default:
      return false;
  }
}

inline bool is_supported_transaction_version(enum BLOB_TYPE blob_type, size_t version) {
  if (version == 0) {
    return false;
  }

  // Keep this bounded to the layouts this parser implements. Future
  // byte-compatible versions must not be interpreted as an older format.
  switch (blob_type) {
    case BLOB_TYPE_CRYPTONOTE_RYO:
    case BLOB_TYPE_CRYPTONOTE_ZEPHYR:
    case BLOB_TYPE_CRYPTONOTE_ARQMA:
      return version <= 3;
    case BLOB_TYPE_CRYPTONOTE_SALVIUM:
      return version <= TRANSACTION_VERSION_ENABLE_TOKENS;
    default:
      return version <= 2;
  }
}
