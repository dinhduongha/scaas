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

**Confirmed by consensus (same day):** one real transaction from a testnet-only account deployed the probe through `0x4e59`
(tx `0xcbf2d331f9bcf4d16bc37ca84918d04b1728c45c91ba5cffdf062bae31b7262e`, block 42,805,771, status 1, gas used 202,337, cost
≈ 0.26 HBAR). The probe sits at the CREATE2 address predicted from `0x4e59`, the salt and its init code
(`0x54bf105f766Fe02fE0cebeB1e11C8552a643a32D`); its stored words: CREATE3 instance `0x06ee…6e48` equals the prediction, the proxy
runtime is 8 B, and both `EXTCODECOPY` hashes equal keccak of the 52-byte runtime; the instance's code on chain is that runtime.

A full `script/hedera/DeployHedera.s.sol` run is not possible from this account today: Hedera allows 15 M gas per transaction,
at a gas price of 1,330 gwei-equivalent (≈ 20 HBAR for one 15 M transaction, at least 80 % of the limit charged), against 10 HBAR.
