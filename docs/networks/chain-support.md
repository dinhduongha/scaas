# Chain support: one row per chain

What each chain has today, against the owner's rule for when the SDK work is done. One table, one place: other documents link
here. State read on 2026-11-22. SPECIFIED (a status table; each cell says what is built).

## 1. The rule (owner 2026-11-21, 2026-11-22)

Status: SPECIFIED.

- The SDK work is done only when **every row** has: node relay and node index, signing in `ua-rs`, `scaas-rpc` reads, `scaas-rpc`
  writes where they can be done, and SDK support.
- **Self-relay on every chain with a SCaaS contract** (owner 2026-11-22): a user's own native key submits a signed SCaaS
  operation, its own or one someone else signed and handed over (a payment to that user, for example), and pays the chain's
  fee and storage. It includes, on every such chain, reading the native fee-token balance and signing and broadcasting a
  native transaction with the user's key.
- **A native column on every row** (owner 2026-11-22): the chain's own native account model, its balance read, a plain native
  transfer signed with the user's key and sent, apart from the SCaaS operations. So there is no native NEAR row and no native DOT
  row: NEAR's native account is the NEAR row's Native cell, and DOT's is the Polkadot Hub row's (the Substrate side, plain sr25519
  accounts; Hub's EVM side only maps onto them). Hub's Native read is BUILT (SDK plan T32's read part, before BTC's, as NEAR's was done); its Substrate sends are **deferred** (owner 2026-11-22). Native and Self-relay share
  the native transaction builder, the native balance read and the broadcast on each chain; Self-relay adds the signed SCaaS
  operation it carries.
- **Native BTC** keeps its row: no SCaaS contract exists there, so only its Native cell applies. Native accounts need no node
  relay or index. BTC is read through RPC: Esplora (address balances and history) and Bitcoin Core JSON-RPC (sends and
  cross-checks).
- **Zether, PQ and PQZ are status columns**, not part of the rule: their missing cells belong to each family's own rounds
  (`zether-<family>`, `ua-<family>`, a `pqz-<family>` round). The SDK's `confidential` module is required wherever the contract
  exists.
- **Contract deployment is not part of the rule.** A public chain deploys when its fork allows it (owner 2026-10-21;
  [NET-EVM-06](evm.md#NET-EVM-06)).
- One row per chain, never a group; every EVM profile of `smartcontracts/evm/chain-uids.json` has its own row, its testnets in the
  same row, but Ethereum Classic, dropped by the owner on 2026-11-22 (decisions CLI-SDK-32).

## 2. Legend

Status: SPECIFIED.

| Mark | Meaning |
|---|---|
| `B` | BUILT: code and tests exist |
| `B‡` | built; the deploy waits for the chain (its fork, or its code-size limit) |
| `P` | PLANNED: the named task covers it |
| `M` | MISSING: the named task or round is to build it |
| `n/a` | not applicable, for the reason in §4 |
| `deferred` | deferred by the owner (Polkadot Hub's Substrate sends, 2026-11-22) |
| `after the freeze (owner 2026-11-22)` | moved by the owner to after the freeze: this round's T41 is `evm`, `soroban` and `arweave` only; neither BUILT nor failed (decisions CLI-SDK-32) |
| `disabled` | disabled by the owner (ARCH-POS-18 confirmed: OP, Arbitrum, Base, Celo and Avalanche Fuji, the kinds above the chain's limit, 2026-11-22) |
| `T<n>` | task T<n> of the SDK plan (`docs/superpowers/plans/2026-11-17-scaas-sdk.md`); `rpc T24.<x>` its `scaas-rpc` tasks |
| `CA-T<n>` | task T<n> of the chains-arweave plan (`docs/superpowers/plans/2026-11-21-avax-polkadot-arweave.md`) |
| `ARCH-POS-18` | a software path to measure, or a disablement for the owner to confirm ([ARCH-POS-18](../decisions.md#ARCH-POS-18)) |
| `family round` | the family's own Zether, UA or PQZ round, outside this rule |

Columns: **Contract** the SCaaS contracts for the chain; **Relay** and **Index** the node's submit lanes and indexer; **Signing**
`ua-rs` signs what the chain verifies (a SCaaS operation; a native transfer is the Native column); **rpc read** and **rpc write**
`scaas-rpc` reads and direct broadcast; **SDK** the SDK's reads and writes on the chain; **Zether** classical Zether; **PQ** the PQ
UA kinds (ML-DSA, FN-DSA, SLH-DSA registration and verification, precompile or software); **PQZ** the PQ confidential token; **Self-relay** the user's own native key submits a signed SCaaS operation (its own, or one
handed to it) and pays the fee and storage, with the native fee-token balance read and the native transaction signed and broadcast
by the SDK (§4); **Native** the chain's own native account: its balance read, a plain native transfer signed with the user's key
and sent (`(read B)`: the read is built, the send is not).

## 3. The matrix

Status: SPECIFIED.

| # | Chain (testnet in the same row) | Contract | Relay | Index | Signing | rpc read | rpc write | SDK | Zether | PQ | PQZ | Self-relay | Native |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | scaas-testnet (7622) | B | B | B | B | B | B | B | B | B | B | B T41.evm | B |
| 2 | Ethereum L1 (1; Sepolia, Hoodi; Holesky unreachable) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ | B T41.evm | B |
| 3 | BNB Smart Chain (56; 97) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ | B T41.evm | B |
| 4 | Polygon PoS (137; Amoy 80002) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ | B T41.evm | B |
| 5 | Base (8453; Base Sepolia 84532) | B‡ | B | B | B | B | B | B | B‡ | B‡ (`mldsa44`, `mldsa65`, `mldsa87` disabled on Base mainnet) | B‡ (disabled on Base mainnet) | B T41.evm | B |
| 6 | Gnosis (100; Chiado 10200) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ | B T41.evm | B |
| 7 | Celo (42220; Celo Sepolia 11142220; Alfajores unreachable) | B‡ | B | B | B | B | B | B | B‡ | B‡ (`mldsa44`, `mldsa65`, `mldsa87` disabled) | disabled | B T41.evm | B |
| 9 | OP Mainnet (10; OP Sepolia 11155420) | B‡ | B | B | B | B | B | B | B‡ | B‡ (`mldsa44`, `mldsa65`, `mldsa87` disabled) | disabled | B T41.evm | B |
| 10 | Arbitrum One (42161; Arbitrum Sepolia 421614) | B‡ | B | B | B | B | B | B | B‡ | B‡ (`mldsa44`, `mldsa65`, `mldsa87` disabled) | disabled | B T41.evm | B |
| 11 | Linea (59144; Linea Sepolia 59141) | B‡ | B | B | B | B | B | B | B‡ | B‡ | B‡ | B T41.evm | B |
| 12 | Hedera (295; 296) | B‡ | B | B | B | B | B | B | M ARCH-POS-18 | M ARCH-POS-18 | M ARCH-POS-18 | B T41.evm (EVM side, a `hedera_ecdsa` payer; the native side's: after the freeze (owner 2026-11-22)) | B (EVM side; native side: after the freeze (owner 2026-11-22), T41.hedera read and ed25519 sends, gRPC-web by default, `tonic` under `fam-hedera-grpc`, owner Q-R5) |
| 13 | Avalanche C-Chain (43114; Fuji 43113) | B‡ | B | B | B | B | B | B | M ARCH-POS-18 | B‡ (`mldsa44`, `mldsa65`, `mldsa87` disabled on Fuji) | B‡ (disabled on Fuji) | P T41.evm (after CA-T2's profile) | B |
| 14 | Polkadot Hub (EVM and Substrate sides; Paseo; Westend dropped, owner 2026-11-22) | B‡ | P CA-T14 | B | B | B (`max_tx_gas`: P CA-T14) | B | B (`max_tx_gas`: P CA-T14) | M ARCH-POS-18 (no EIP-2537, CA-T12) | P CA-T13 | P CA-T14 | P T41.evm (after CA-T14's profile) | P T41.dot (read B; the sends, owner 2026-11-22) |
| 15 | Moonbeam (Moonbase Alpha) | B‡ | B | B | B | B (pinned reads refused: `pinnedReads` false) | B | P T41 (the SDK's `pinnedReads` wiring) | B‡ | B‡ (T15 checks its storage gas) | B‡ (T15) | P T41.evm (after CA-T11's profile) | B |
| 16 | NEAR (SCaaS family) | B | B | B | B | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | P `ua-near` | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 17 | Algorand | B | B | B | B | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | P `ua-algorand` | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 18 | Cosmos (CosmWasm) | B | B | B | after the freeze (owner 2026-11-22) | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | M family round | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 19 | Aptos | B | B | B | after the freeze (owner 2026-11-22) | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | M family round | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 20 | Solana | B | B | B | after the freeze (owner 2026-11-22) | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | M family round | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 21 | Soroban (Stellar; Pi) | B | B | B | M T27 | B | M T30 | M T28, T29 | P `zether-soroban` | M family round | M family round | M T41.soroban | M T41.soroban (read B) |
| 22 | Sui | B | B | B | after the freeze (owner 2026-11-22) | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | M family round | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 23 | TON (GRAM) | B | B | B | after the freeze (owner 2026-11-22) | B | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) | M family round | M family round | M family round | after the freeze (owner 2026-11-22) | after the freeze (owner 2026-11-22) (read B) |
| 24 | native BTC (no SCaaS contract) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | after the freeze (owner 2026-11-22): T35 (sign), T36 (send; its reads B), T37 (SDK) |
| 25 | Arweave (store) | n/a | n/a | n/a | B | P CA-T19 | P CA-T19 | P CA-T20 | n/a | n/a | n/a | n/a | P CA-T17, T19, T20 |


Row 8 (Ethereum Classic, 61; Mordor 63) is removed: the owner dropped ETC on 2026-11-22 (decisions CLI-SDK-32, "ETC has no
finalized block"); its profiles are in `smartcontracts/evm/legacy/chains/`. The other rows keep their numbers.

Counts (24 rows): Contract B 22 (13 B‡), n/a 2. Relay B 19, P 3, n/a 2. Index B 19, P 3, n/a 2. Signing B 16, P 1, M 1, after the freeze 5, n/a 1. rpc read B 19, P 4, n/a 1. rpc write B 14, P 1, M 1, after the freeze 7, n/a 1. SDK B 11, P 4, M 1, after the freeze 7, n/a 1. Zether B 11 (10 B‡), P 2, M 9, n/a 2. PQ B 11 (10 B‡; on 4 of them kinds disabled), P 4, M 7, n/a 2. PQZ B 8 (7 B‡; on 1 of them disabled on mainnet), P 2, M 9, disabled 3, n/a 2. Self-relay B 11, P 3, M 1, after the freeze 7, n/a 2. Native B 11, P 3, M 1 (its read built), after the freeze 9 (8 of them with the read built).

## 4. Notes on the cells

Status: SPECIFIED.

- **EVM rows 2–15.** The contracts, the node's EVM runner and indexer, `ua-rs`'s `EvmTx` and `scaas-rpc`'s EVM reader serve every
  EVM chain by profile values. Base, Celo and OP charge the OP Stack L1 data fee: the node prices it (`params.l1_fee =
  "op-stack"`) and the SDK's quote adds it (SDK plan T38: the profile's `l1_fee = OpStack`, `GasPriceOracle.getL1Fee` over the
  unsigned transaction read at the quote's block, again over the signed calldata at `submit`; `FeeAboveCap` counts it); their
  `profile.json` files carry `"l1Fee": "op-stack"`.
- **Rows 2 and 9–11 (SDK plan T40).** `draft` profiles in `smartcontracts/evm/src/chains/<key>/profile.json` ([evm.md](evm.md));
  `scaas-rpc` tests per profile (the chain pair check, a `finalized` read pinned by hash) and the SDK's (each profile loads, a
  native send's type follows the base fee, a disabled kind refused). The probes' first sample (2026-11-22,
  `clients/scaas-rpc/runs/2026-11-22-evm-probes-summary.txt`) decides Zether, PQ and PQZ: EIP-2537 is present on 2, 9, 10 and 11
  (`B‡`, the precompile path). PQ by accounts.md's MD-5 rule (regular × 1.05 < 2^24, (regular + state) × 1.05 within the
  chain's transaction or block limit) on each kind's largest transaction: every kind fits Ethereum (60 M, Sepolia 200 M) and
  Linea (2,000 M); on OP (block 40 M) and Arbitrum (a transaction at most 32 M) the ML-DSA cache's largest part does not
  (`mldsa44` 41.5 M, `mldsa65` 43.5 M, `mldsa87` 45.6 M with state gas) and PQZ does not (an operation about 43 M,
  `storePqzPop` 49.1 M at `n2304-kmax4096`): the owner disabled exactly those there on 2026-11-22 (ARCH-POS-18 confirmed,
  decisions CLI-SDK-32; each profile's `disabledKinds`, the SDK's `KindDisabled`); `fndsa512`, `slhdsa128s` and `fndsa1024`
  fit and stay. The same rule and ruling on Base mainnet (block 40 M) and Celo (block 30 M, mainnet and Sepolia): `mldsa44`,
  `mldsa65`, `mldsa87` and PQZ disabled; on Base Sepolia (block 120 M) every kind fits and none is disabled. Row 8 (ETC) was dropped by the owner the same day. OP's SDK and Native cells take T38's L1 fee.
- **Hedera (row 12), `B‡`.** The token kinds, the DEX, the registry pair and the factory do not fit Hedera until it raises its code
  size (owner 2026-11-09; the public Hedera testnet refused runtime above 24,576 B; each transaction within 15 M gas); a small
  contract that needs none of them can deploy. Classical Zether needs EIP-2537 ([CTR-ZTH-32](../contracts/zether.md#CTR-ZTH-32)),
  PQZ is refused there ([CTR-PQZ-27](../contracts/pq-zero-knowledge.md#CTR-PQZ-27)) and `mldsa87` does not fit the 10.5 M verify
  budget: none of the three is a confirmed disablement under ARCH-POS-18, so each waits for its numbers.
- **Avalanche, Polkadot Hub, Moonbeam (rows 13–15).** Draft profiles (chains-arweave T2, T11; `src/chains/<key>/`) with their
  `scaas-rpc` and SDK profile tests, the node's lanes and indexer audited (T3: `max_inflight` and the in-flight cost alert
  built; the rest held), and one sample of every probe (T12; `clients/scaas-rpc/runs/2026-11-22-evm-probes-summary.txt`).
  Relay, Index, rpc and SDK are the chain-neutral EVM code on these profiles, tested against fakes answering each profile's
  identity, no deploy: every profile stays `draft` until NET-EVM-19's windows pass. The owner's answers of 2026-11-22
  ([ARCH-POS-20](../decisions.md#ARCH-POS-20)): Hub's identity is its Substrate genesis (its eth-rpc serves no block 0 on
  mainnet and Paseo, so each endpoint needs a checkpoint); Moonbeam's pinned reads are not trusted (H2: a made-up block hash
  answered), so `scaas-rpc` refuses them there; Westend Hub is dropped; Moonbeam mainnet needs an independent second source
  before any deploy; Fuji disables `mldsa44`, `mldsa65`, `mldsa87` and PQZ (above its 32 M block), C-Chain keeps every kind.
  Avalanche and Hub have no EIP-2537: Zether needs the software BLS12-381 path (ARCH-POS-18). Hub's gas is no Ethereum gas:
  its relay cap, PQ and PQZ cells wait for the Paseo measurement (T13, a deploy, on the owner's word) and T14.
- **SCaaS families (rows 16–23).** The node relays and indexes all eight; the public gateway door for them (`POST /v1/ops`) is SDK
  plan T28. The SDK reads balances on all eight (plan T24; TON last, T24.ton); its cell stays `M` for the writes (T28, T29). `ua-rs` signs NEAR's and Algorand's operations; the other six families' envelopes are SDK plan T27. TON's paths other
  than the job API's pull path stay blocked until the forward-TON cap lands ([NET-TON-14](ton.md#NET-TON-14)).
- **Native BTC (row 24).** No SCaaS contract, so every column but Native is n/a (owner 2026-11-22; Relay and Index were n/a by the
  owner's rule of 2026-11-21). Its Native cell: `ua-rs` `BitcoinTx` (SDK plan T35), the `scaas-rpc` `bitcoin` module (T36: Esplora
  reads, Bitcoin Core sends and cross-checks), the SDK's balance, UTXOs, history and send (T37).
- **Native (column 12).** EVM rows: the native coin through the EVM account, `balances`' `native` and `prepare_native_send`
  (BUILT, SDK spec §8.5) wherever the row's profile and SDK are (rows 1–7, 9–12; HBAR through the JSON-RPC Relay with an
  `hedera_ecdsa` account; Hedera's native side, `0.0.x` accounts with ed25519 keys, HBAR and HTS under `fam-hedera`: mirror-node
  reads and the HAPI format PLANNED (SDK plan T41.hedera, HCS T43), its broadcast gRPC-web by default and `tonic` gRPC under `fam-hedera-grpc`, the owner's answer to SDK spec Q-R5), else the row's profile task (T38, T40, chains-arweave CA-T2,
  CA-T11). Polkadot Hub (row 14): the Substrate side, plain sr25519 accounts (`ua-rs` sr25519, CLI-SGN-53), `System.Account`
  reads (BUILT: SDK plan T32's read part, before T36, owner 2026-11-22; `scaas-rpc` `substrate`, the profile's
  `FamilyParams::Substrate`, `balances` of an SS58 id; tested on answers recorded from Westend Asset Hub, the public Paseo Hub
  endpoints answering no plain HTTP JSON-RPC that day) and a Substrate transfer extrinsic (T33, T34: deferred, owner
  2026-11-22); this is DOT's native account, and the former native DOT row now lives here. NEAR (row 16): the former native NEAR row, `view_account`'s `amount` (BUILT, T24.near) and
  the native transfer (the former T31, now in T41.near). The other seven families: the fee-token account (ALGO, the Cosmos
  chain's denom, APT, SOL, XLM, SUI, GRAM), its balance BUILT by T24, its send MISSING, in T41.<family> on the builder that
  Self-relay uses (Algorand also needs its key network in `ua-rs`).
- **Self-relay (column 11).** Contracts: every family lets any account submit an operation whose `relayer` is unbound, and an
  operation bound to an account lets that account submit: EVM `MetaTxLib.canon` zeroes an unbound relayer and fee recipient,
  and the payee may self-relay with fee 0 ([CTR-MTX-08](../contracts/metatx.md#CTR-MTX-08), "payee self-relay",
  [metatx §12](../contracts/metatx.md#payers)); NEAR `relayer: Option<AccountId>` against the predecessor, storage from the
  submitter's attached deposit ([NET-NEAR-09](near.md#NET-NEAR-09)); Algorand `relayer` zero = any, the MBR paid by a payment
  in the submitter's group ([NET-ALG-02](algorand.md#NET-ALG-02)); Cosmos `relayer` empty = any, else `info.sender`; Aptos and
  Sui `@0x0` = any, else the sender; Solana `relayer` 0 = any, else exactly the fee payer, who pays the lane PDA's rent
  (refunded to it at `prune`) and any missing ATA; Soroban's `pay` is unbound (the host does not bind the transaction
  source); TON `relayer` = `addr_none` or the sending wallet. So no contract change is needed. On EVM the SDK self-relays the
  holder's **own** operations (`SubmitPath::SelfRelay`) and, since T41.evm, the hand-off: `Op::hand_off` signs and writes the
  row, `Op::import_signed` checks the blob in order and relays it by the payee's key, an `evm` or `hedera_ecdsa` payer
  (decisions CLI-SDK-33 (49)); BUILT on every EVM row whose profile and SDK are. On the eight families the SDK has the native balance read (T24) and no native transaction and no
  self-relay path (T41.<family>, which also builds the Native column's send on the same builder). Design: SDK spec §27.5.
- **Arweave (row 25).** A store: no SCaaS contract, and a client posts its signed item to a bundler and reads from gateways itself,
  so the node has nothing to relay or index; Self-relay is n/a (no SCaaS operation; the client pays for its own item); Native is
  the user's Arweave key signing and posting its own items (chains-arweave CA-T17, CA-T19, CA-T20).

The evidence for every cell (file and line) and the designs for the missing ones are in the SDK spec, §27
(`docs/superpowers/specs/2026-11-17-scaas-sdk.md`).
