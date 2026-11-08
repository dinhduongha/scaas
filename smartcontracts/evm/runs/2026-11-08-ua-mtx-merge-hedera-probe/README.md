# Hedera testnet probe for chain-neutral releases (T74, Q7), 2026-11-08

`Probe.sol` (with `src/factory/Create3.sol` beside it, solc 0.8.37, via-IR) is a creation-only contract: its constructor
returns the check words as "runtime code", so `eth_call` without `to` reads them. Run against the public Hedera testnet JSON-RPC
relay (chain id 296, `https://testnet.hashio.io/api`), simulation only: no transaction, no key, no fee.

| Check | How | Result |
|---|---|---|
| `0x4e59…956C` present | `eth_getCode` | the standard deterministic-deployment proxy runtime (`0x7fff…f3`) |
| CREATE3 address, HIP-729 contract nonce 1 | `Create3.deploy` in the constructor; `addressOf` vs the instance | equal (`0xfd9c…73e8`), proxy runtime 8 B |
| `EXTCODECOPY` of another account | hash of the instance's code read by the probe | equals keccak of the 52-byte runtime (20 B code + 32 B appended marker) |
| `EXTCODECOPY` of the executing account | the instance hashes `EXTCODECOPY(ADDRESS)` of itself | equal |
| CREATE2 through `0x4e59` | `eth_call` to the deployer with `salt ‖ initcode` | returns `keccak(0xff ‖ 0x4e59… ‖ salt ‖ keccak(initcode))[12:]` |

Limit: the relay simulates on the mirror node's EVM, not by consensus; one real deployment from a funded testnet account confirms
it (pending the owner's faucet funding).
