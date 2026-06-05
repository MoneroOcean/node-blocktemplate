<div align="center">

# node-blocktemplate

Native Node.js block template and blob bindings for MoneroOcean-style pool tooling.

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause%20%2B%20MIT-111111.svg" alt="BSD-3-Clause and MIT"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-111111.svg" alt="Node 18+">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-111111.svg" alt="Linux and macOS">
  <img src="https://img.shields.io/badge/focus-block%20templates-111111.svg" alt="Block templates">
</p>

</div>

## Overview
`node-blocktemplate` is a native addon for Node.js that focuses on multichain block template handling for pool backends and related infrastructure.

It provides:
- native block blob conversion and block ID helpers for Cryptonote-family templates
- legacy merged-mining export compatibility stubs
- address prefix decoding helpers
- JavaScript-side helpers for Raven, RTM, KCN, Dero, ETH, and ERG-oriented template handling

The current test suite covers supported conversion vectors for ARQ, BLOC, MSR, RYO, SAL, XLA, XMR, XMV, and ZEPH; retired blob-type rejection; and RTM coinbase handling.

## Install
From GitHub:

```bash
npm install https://github.com/MoneroOcean/node-blocktemplate
```

For local development:

```bash
npm install
npm test
```

> Build notes
> - Node.js `>=18`
> - Linux and macOS are the intended CI platforms
> - The addon builds locally with `node-gyp`, so you need Python 3, `make`, and a working C/C++ toolchain
> - Boost headers, `boost_date_time`, and `libsodium` headers are required
> - Non-ARM builds use `-march=native`, so build on the target CPU class or inside a compatible build image
> - No prebuilt binaries are shipped in this repository

## Quick Start
```js
const blocktemplate = require("node-blocktemplate");

const converted = blocktemplate.convert_blob(Buffer.from(blockHex, "hex"), 0);
const blockId = blocktemplate.get_block_id(Buffer.from(blockHex, "hex"), 15);

const ravenJob = blocktemplate.RavenBlockTemplate(rpcData, poolAddress);
const nextRtmBlob = blocktemplate.constructNewRtmBlob(
  Buffer.from(rtmTemplateHex, "hex"),
  nonceBuffer
);
```

Exact, vector-backed usage examples live in [`tests/test.js`](tests/test.js).

## API At A Glance
### Native Exports
| Method | Returns | Notes |
| --- | --- | --- |
| `convert_blob(blockBuffer, blobType?)` | `Buffer` | Converts a block template into the hashing blob used by miners. |
| `construct_block_blob(templateBuffer, nonceBuffer, blobType?, cycle?)` | `Buffer` | Reconstructs a solved block blob from a template and nonce. |
| `get_block_id(blockBuffer, blobType?)` | `Buffer` | Returns the 32-byte block ID. |
| `address_decode(addressBuffer)` | `number` or `Buffer` | Returns the address prefix when the payload parses cleanly, otherwise the decoded raw payload. |
| `address_decode_integrated(addressBuffer)` | `number` or `Buffer` | Integrated-address variant of `address_decode`. |
| `get_merged_mining_nonce_size()` | `number` | Returns the legacy merged-mining extra nonce size for callers that still import it. |
| `construct_mm_parent_block_blob(parentTemplate, blobType, childTemplate)` | throws | Legacy export; merged-mining block construction is unsupported. |
| `construct_mm_child_block_blob(parentShare, blobType, childTemplate)` | throws | Legacy export; merged-mining block construction is unsupported. |

### JavaScript Helpers
| Method | Returns | Notes |
| --- | --- | --- |
| `baseDiff()` | `BigInt-like value` | Shared base difficulty helper. |
| `baseRavenDiff()` | `number` | Raven-specific base difficulty constant. |
| `RavenBlockTemplate(rpcData, poolAddress)` | `object` | Builds a Raven/KawPow-oriented blocktemplate payload. |
| `blockHashBuff(headerBuffer)` | `Buffer` | Double-SHA256 hash helper with pool-oriented byte order. |
| `blockHashBuff3(headerBuffer)` | `Buffer` | Double-SHA3-256 variant used by KCN helpers. |
| `convertRavenBlob(blobBuffer)` | `Buffer` | Returns the hashable Raven header. |
| `constructNewRavenBlob(templateBuffer, nonceBuffer, mixHashBuffer)` | `Buffer` | Updates a Raven template with nonce and mix hash. |
| `constructNewDeroBlob(templateBuffer, nonceBuffer)` | `Buffer` | Inserts the Dero nonce into the expected position. |
| `EthBlockTemplate(rpcData)` | `object` | Formats ETH-family RPC data into pool-facing metadata. |
| `ErgBlockTemplate(rpcData)` | `object` | Formats ERG RPC data into pool-facing metadata. |
| `RtmBlockTemplate(rpcData, poolAddress)` | `object` | Builds RTM/Ghostrider-oriented template metadata. |
| `convertRtmBlob(blobBuffer)` | `Buffer` | Returns the RTM hashable header. |
| `convertKcnBlob(blobBuffer)` | `Buffer` | Returns the KCN hashable header. |
| `constructNewRtmBlob(templateBuffer, nonceBuffer)` | `Buffer` | Updates an RTM block template with a nonce. |
| `constructNewKcnBlob(templateBuffer, nonceBuffer)` | `Buffer` | Updates a KCN block template with a nonce. |

## Supported Paths
- Cryptonote-family blob conversion and solved-block reconstruction through the native addon
- Prefix decoding for standard and integrated Cryptonote-family addresses
- JavaScript helpers for Raven/KawPow, RTM/Ghostrider, KCN, Dero, ETH, and ERG pool integration

This repository is a utility layer for pool software and infrastructure. It is not a full miner and does not ship standalone CLI tooling.

## Testing
| Command | What it does |
| --- | --- |
| `npm test` | Runs the active blob conversion and RTM handling suite. This is the path used in GitHub Actions. |

GitHub Actions runs the fast suite only, on Linux and macOS, with the same small Node matrix shape used by `node-pow-hashing`: Node 18, Node 24, and the runner's system Node where useful.

## Contributors
1. [MoneroOcean](https://github.com/MoneroOcean) for the long-running maintenance branch, multi-chain pool support, and most of the current repository direction
2. Lucas Jones / `lucas` for the original addon and early block/blob plumbing that the project still builds on
3. `clintar` for early follow-up maintenance and project evolution
4. `CliffordST` for utility and chain-support updates in the repository history
5. `campurro` / `Campurro` for continued maintenance and fixes
6. `Some Random Crypto Guy` for support and maintenance work in the current-era history
7. `wallet42` for feature and upkeep contributions
8. `Neil Coggins` for maintenance and fix-up work
9. [ZephyrProtocol](https://github.com/ZephyrProtocol) for Zephyr-specific support in the repo history
10. `xmvdev` for MoneroV-related support in the repository history
11. `Ghost-ai-cpu` for follow-up maintenance contributions
