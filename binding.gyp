{
    "targets": [
        {
            "target_name": "blocktemplate",
            "sources": [
                "src/main.cc",
                "src/cryptonote_basic/cryptonote_format_utils.cpp",
                "src/zephyr_oracle/pricing_record.cpp",
                "src/salvium_oracle/pricing_record.cpp",
                "src/crypto/tree-hash.c",
                "src/crypto/crypto.cpp",
                "src/crypto/crypto-ops.c",
                "src/crypto/crypto-ops-data.c",
                "src/crypto/hash.c",
                "src/crypto/keccak.c",
                "src/common/base58.cpp",
            ],
            "include_dirs": [
                "src",
                "src/contrib/epee/include",
                "/usr/local/opt/boost/include",
            ],
            "link_settings": {
                "libraries": [
                    "-lboost_date_time",
                ]
            },
            "cflags_c":  [
                "-fno-exceptions -std=gnu11 -march=native -fPIC -DNDEBUG -Ofast -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2"
            ],
            "cflags_cc": [
                "-fexceptions -frtti -std=gnu++20 -march=native -fPIC -DNDEBUG -Ofast -s -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2"
            ],
            "xcode_settings": {
                "OTHER_CFLAGS": [ "-fexceptions -frtti" ]
            }
        }
    ]
}
