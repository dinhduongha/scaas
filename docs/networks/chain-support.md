# Chain support: one row per chain

What each chain has today, against the owner's rule for when the SDK work is done. One table, one place: other documents link
here. State read on 2026-11-22. SPECIFIED (a status table; each cell says what is built).

## 1. The rule (owner 2026-11-21)

Status: SPECIFIED.

- The SDK work is done only when **every row** has: node relay and node index, signing in `ua-rs`, `scaas-rpc` reads, `scaas-rpc`
  writes where they can be done, and SDK support.
- **Native NEAR, native DOT and native BTC need no node relay or index.** For them the rule is signing, `scaas-rpc` reads and direct
  broadcast where feasible, and the SDK. DOT on Substrate and NEAR native are account-based; BTC is read through RPC. Native DOT is
  read from the relay chain and from Asset Hub's Substrate side by one code path; the profile chooses. BTC reads go to Esplora
  (address balances and history) and to Bitcoin Core JSON-RPC (sends and cross-checks).
- **Zether, PQ and PQZ are status columns**, not part of the rule: their missing cells belong to each family's own rounds
  (`zether-<family>`, `ua-<family>`, a `pqz-<family>` round). The SDK's `confidential` module is required wherever the contract
  exists.
- **Contract deployment is not part of the rule.** A public chain deploys when its fork allows it (owner 2026-10-21;
  [NET-EVM-06](evm.md#NET-EVM-06)).
- One row per chain, never a group; every EVM profile of `smartcontracts/evm/chain-uids.json` has its own row, its testnets in the
  same row.

## 2. Legend

Status: SPECIFIED.

| Mark | Meaning |
|---|---|
| `B` | BUILT: code and tests exist |
| `B‡` | built; the deploy waits for the chain (its fork, or its code-size limit) |
| `P` | PLANNED: the named task covers it |
| `M` | MISSING: the named task or round is to build it |
| `n/a` | not applicable, for the reason in §4 |
| `T<n>` | task T<n> of the SDK plan (`docs/superpowers/plans/2026-11-17-scaas-sdk.md`); `rpc T24.<x>` its `scaas-rpc` tasks |
| `CA-T<n>` | task T<n> of the chains-arweave plan (`docs/superpowers/plans/2026-11-21-avax-polkadot-arweave.md`) |
| `ARCH-POS-18` | a software path to measure, or a disablement for the owner to confirm ([ARCH-POS-18](../decisions.md#ARCH-POS-18)) |
| `family round` | the family's own Zether, UA or PQZ round, outside this rule |

Columns: **Contract** the SCaaS contracts for the chain; **Relay** and **Index** the node's submit lanes and indexer; **Signing**
`ua-rs` signs what the chain verifies (a SCaaS operation, or a native transfer on rows 24–26); **rpc read** and **rpc write**
`scaas-rpc` reads and direct broadcast; **SDK** the SDK's reads and writes on the chain; **Zether** classical Zether; **PQ** the PQ
UA kinds (ML-DSA, FN-DSA, SLH-DSA registration and verification, precompile or software); **PQZ** the PQ confidential token.

## 3. The matrix

Status: SPECIFIED.

| # | Chain (testnet in the same row) | Contract | Relay | Index | Signing | rpc read | rpc write | SDK | Zether | PQ | PQZ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | scaas-testnet (7622) | B | B | B | B | B | B | B | B | B | B |
| 2 | Ethereum L1 (1; Sepolia, Hoodi; Holesky unreachable) | B‡ | B | B | B | B | B | M T40 | B‡ | B‡ | B‡ |
| 3 | BNB Smart Chain (56; 97) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ |
| 4 | Polygon PoS (137; Amoy 80002) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ |
| 5 | Base (8453; Base Sepolia 84532) | B‡ | B | B | B | B | B | M T38 | B‡ | B‡ | B‡ |
| 6 | Gnosis (100; Chiado 10200) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ |
| 7 | Celo (42220; Celo Sepolia 11142220; Alfajores unreachable) | B‡ | B | B | B | B | B | M T38 | B‡ | B‡ | B‡ |
| 8 | Ethereum Classic (61; Mordor 63) | B‡ | B | B | B | B | B | M T40 | P T40 | P T40 | P T40 |
| 9 | OP Mainnet (10; OP Sepolia 11155420) | B‡ | B | B | B | B | B | M T38, T40 | P T40 | P T40 | P T40 |
| 10 | Arbitrum One (42161; Arbitrum Sepolia 421614) | B‡ | B | B | B | B | B | M T40 | P T40 | P T40 | P T40 |
| 11 | Linea (59144; Linea Sepolia 59141) | B‡ | B | B | B | B | B | M T40 | P T40 | P T40 | P T40 |
| 12 | Hedera (295; 296) | B‡ | B | B | B | B | B | B | M ARCH-POS-18 | M ARCH-POS-18 | M ARCH-POS-18 |
| 13 | Avalanche C-Chain (43114; Fuji 43113) | B‡ | P CA-T3 | P CA-T3 | B | P CA-T2 | B | P CA-T2 | M ARCH-POS-18 | B‡ | B‡ |
| 14 | Polkadot Hub (EVM; Paseo) | B‡ | P CA-T3, T14 | P CA-T3 | B | P CA-T11, T14 | B | P CA-T14 | P CA-T12 | P CA-T13 | P CA-T14 |
| 15 | Moonbeam (Moonbase Alpha) | B‡ | P CA-T3, T15 | P CA-T3 | B | P CA-T11 | B | P CA-T11 | B‡ | P CA-T15 | P CA-T15 |
| 16 | NEAR (SCaaS family) | B | B | B | B | B | M T30 | M T28, T29 | M family round | P `ua-near` | M family round |
| 17 | Algorand | B | B | B | B | B | M T30 | M T28, T29 | M family round | P `ua-algorand` | M family round |
| 18 | Cosmos (CosmWasm) | B | B | B | M T27 | B | M T30 | M T28, T29 | M family round | M family round | M family round |
| 19 | Aptos | B | B | B | M T27 | B | M T30 | M T28, T29 | M family round | M family round | M family round |
| 20 | Solana | B | B | B | M T27 | B | M T30 | M T28, T29 | M family round | M family round | M family round |
| 21 | Soroban (Stellar; Pi) | B | B | B | M T27 | B | M T30 | M T28, T29 | P `zether-soroban` | M family round | M family round |
| 22 | Sui | B | B | B | M T27 | B | M T30 | M T28, T29 | M family round | M family round | M family round |
| 23 | TON (GRAM) | B | B | B | M T27 | B | M T30 | M T28, T29 | M family round | M family round | M family round |
| 24 | native NEAR | n/a | n/a | n/a | M T31 | B | M T30 | M T31 | n/a | n/a | n/a |
| 25 | native DOT (relay chain and Asset Hub, by profile) | n/a | n/a | n/a | M T33 | M T32 | M T32 | M T34 | n/a | n/a | n/a |
| 26 | native BTC | n/a | n/a | n/a | M T35 | M T36 | M T36 | M T37 | n/a | n/a | n/a |
| 27 | Arweave (store) | n/a | n/a | n/a | P CA-T16, T17 | P CA-T19 | P CA-T19 | P CA-T20 | n/a | n/a | n/a |

Counts (27 rows): Contract B 23 (14 B‡), n/a 4. Relay B 20, P 3, n/a 4. Index B 20, P 3, n/a 4. Signing B 17, P 1, M 9. rpc read B 21, P 4, M 2. rpc write B 15, P 1, M 11. SDK B 5, P 4, M 18. Zether B 8 (7 B‡), P 6, M 9, n/a 4. PQ B 8 (7 B‡), P 8, M 7, n/a 4. PQZ B 8 (7 B‡), P 6, M 9, n/a 4.
## 4. Notes on the cells

Status: SPECIFIED.

- **EVM rows 2–15.** The contracts, the node's EVM runner and indexer, `ua-rs`'s `EvmTx` and `scaas-rpc`'s EVM reader serve every
  EVM chain by profile values. Rows 2 and 8–11 have no profile yet ("unsupported until configured", [evm.md](evm.md)): SDK plan T40
  writes their profiles and runs probes H1–H8 on them. Base, Celo and OP need the OP Stack L1 data fee in the SDK's quote (SDK plan
  T38; the node has it as `params.l1_fee = "op-stack"`).
- **Hedera (row 12), `B‡`.** The token kinds, the DEX, the registry pair and the factory do not fit Hedera until it raises its code
  size (owner 2026-11-09; the public Hedera testnet refused runtime above 24,576 B; each transaction within 15 M gas); a small
  contract that needs none of them can deploy. Classical Zether needs EIP-2537 ([CTR-ZTH-32](../contracts/zether.md#CTR-ZTH-32)),
  PQZ is refused there ([CTR-PQZ-27](../contracts/pq-zero-knowledge.md#CTR-PQZ-27)) and `mldsa87` does not fit the 10.5 M verify
  budget: none of the three is a confirmed disablement under ARCH-POS-18, so each waits for its numbers.
- **Avalanche, Polkadot Hub, Moonbeam (rows 13–15).** The chains-arweave plan's profile, probe and node lane tasks; Avalanche's
  Zether needs a software BLS12-381 path (no EIP-2537), measured first; Hub's precompiles are unknown until its probes.
- **SCaaS families (rows 16–23).** The node relays and indexes all eight; the public gateway door for them (`POST /v1/ops`) is SDK
  plan T28. The SDK reads balances on all eight (plan T24; TON last, T24.ton); its cell stays `M` for the writes (T28, T29). `ua-rs` signs NEAR's and Algorand's operations; the other six families' envelopes are SDK plan T27. TON's paths other
  than the job API's pull path stay blocked until the forward-TON cap lands ([NET-TON-14](ton.md#NET-TON-14)).
- **Native NEAR, DOT, BTC (rows 24–26).** No SCaaS contract, so Contract, Zether, PQ and PQZ are n/a; Relay and Index are n/a by the
  owner's rule (§1).
- **Arweave (row 27).** A store: no SCaaS contract, and a client posts its signed item to a bundler and reads from gateways itself,
  so the node has nothing to relay or index.

The evidence for every cell (file and line) and the designs for the missing ones are in the SDK spec, §27
(`docs/superpowers/specs/2026-11-17-scaas-sdk.md`).
