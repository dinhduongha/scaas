> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Avalanche and Polkadot EVMs, and Arweave as a ciphertext store

Research of 2026-11-21 for the owner (TODO 8i; decision [ARCH-POS-19](../decisions.md#ARCH-POS-19)). Nothing here is built,
specified or decided beyond that entry; every design below is a proposal and **UNAUDITED**. Tags: **[F]** fact, with its source
(a URL fetched on 2026-11-21, or a repo `file:line` at `2196f81f5`); **[I]** inference; **[E]** estimate. No chain was probed
with a transaction for this note: live figures come from public explorers' JSON-RPC proxies and the chains' own sources.

**Contents**

0. [Summary](#0-summary)
1. [The rules this note applies](#1-the-rules-this-note-applies)
2. [Avalanche](#2-avalanche)
3. [Polkadot EVMs](#3-polkadot-evms)
4. [Arweave](#4-arweave)
5. [`scaas-rpc`](#5-scaas-rpc)
6. [Feasibility per piece and chain](#6-feasibility-per-piece-and-chain)
7. [Recommendations](#7-recommendations)
8. [Open questions for the owner](#8-open-questions-for-the-owner)
9. [Sources](#9-sources)

## 0. Summary

- **No SCaaS contract set deploys on Avalanche C-Chain, Polkadot Hub or Moonbeam today, for one plain reason per contract:
  the runtime code cap of 24,576 B.** [F] 43 of the 55 rows of `smartcontracts/evm/size-baseline.json` are above 24,576 B
  (largest `UARegistryAuxLib` 35,417 B, `OpenFactory` 34,999 B, `SCaaSDex` 33,497 B, `UARegistry` 33,335 B, `PqChat`
  29,111 B; `PqVault` 30,152 B on branch `pqvault-v` at `ea95b9c7b`), and every token kind has at least one body module above
  it (e.g. `NormalTokenA` 25,073 B). The cap is EIP-170 on all three chains, with no switch on the public ones. Each chain also
  lacks the Amsterdam fork that [NET-EVM-06](../networks/evm.md#NET-EVM-06) requires before a public chain is deployed.
- **Avalanche C-Chain / Fuji** [F]: the EVM is go-ethereum v1.13.14 (Cancun) under ava-labs `libevm`, plus P-256 at `0x100`
  (ACP-204). No ACP adopts Prague, Osaka or Amsterdam: no EIP-2537, EIP-7702, EIP-7825, EIP-7954 or EIP-8037. Helicon
  (mainnet 2026-09-22) brought continuous execution (ACP-194). Since then `finalized` = `safe` = the last *settled* block,
  about 5 s behind; a transaction pays at least half its gas limit; the block cap is the sum of gas limits ≤ 20 × target
  (80 M on mainnet, 32 M on Fuji, live). An Avalanche L1 can carry its own stateful precompile (a PQ verifier) only through a
  fork of `subnet-evm` run by every validator. Code size is not a chain-config option.
- **Polkadot** [F]: **Polkadot Hub** (pallet-revive, live on Polkadot since 2026-01-27) runs unmodified solc bytecode on its
  REVM backend, through the `eth-rpc` adapter. Gas is fees in disguise (weights plus a storage deposit). It has no BLS12-381
  precompile and no `eth_getProof`. `finalized` / `safe` map to the GRANDPA-finalized block, `latest` to the best block.
  **Moonbeam** (Frontier) is Ethereum-like: 60 M blocks, 52 M per transaction, EIP-2537 and P-256 present, a storage-growth
  gas of 366 per byte with 160 KiB per block. **Recommendation:** Polkadot Hub first, Moonbeam second (§3.4, Q2).
- **Arweave** [F]: ANS-104 data items, built the way `arbundles` builds them, not as the ANS-104 text reads (the signature type
  and the raw Avro tag bytes enter the SHA-384 deep hash). **Turbo** (ar.io) is the bundler: it takes ETH- and SOL-signed items
  and is paid in ETH, SOL, POL, USDC, ARIO, Base ETH or by card. It is free up to 105 KiB per item, within a 10 MiB lifetime
  cap per IP. Above that it costs USD 46.19 per GiB (about $0.045 per MiB) today. **Irys no longer stores to Arweave**: its
  Arweave nodes retired on 2026-11-01. No gateway endpoint returns a whole data item, so the read check is the `ctSha256`
  that UA-7 already signs inside the message (§4.6).
- **ua-rs proposals of TODO 8i (4)**: confirmed, with three corrections. (1) The deep hash is the `arbundles` one. (2)
  Verification on read is the `ctSha256` check; the data item's own signature is out of reach from a plain gateway read.
  (3) A rotating upload key does not hide the payer: credit-share approvals, x402 payments and the free tier's per-IP cap
  all link uploads (§4.7).
- **Top risks.** Avalanche: Amsterdam may never come, since `libevm` has not left Cancun in 18 months [I]. Polkadot Hub:
  its gas has no Ethereum figure, so our 60 M lines do not transfer, and Zether needs BLS12-381 in software (§6). Arweave:
  every upload is public forever, with its size, time and upload key; the payer path is the leak (§4.7).

## 1. The rules this note applies

- [F] NET-EVM-06: every chain that runs SCaaS contracts requires Glamsterdam; a public chain is deployed only after its own
  fork (`docs/networks/evm.md`, NET-EVM-06). Public profiles stay `draft` until their finality gate is measured and an RPC
  quorum ≥ 2 is configured (`docs/networks/evm.md`, §6). Avalanche is listed among the chains "unsupported until configured"
  (`docs/networks/evm.md:61-66`).
- [F] The deploy condition is per contract: its runtime within the chain's maximum code size, its deploy transaction within
  the chain's gas limits (owner, Hedera, 2026-11-09). The 64 KiB ceiling (EIP-7954) and 131,072 B on the reset chain are
  the SCaaS testnet's; for a public chain this note states the chain's own figures.
- [F] ARCH-POS-18: a missing precompile means the software path with the same checks and caps; a hard limit goes to the
  owner with numbers; disabling a kind on a chain needs the owner's confirmation (`docs/decisions.md`, ARCH-POS-18).
- [F] ARCH-POS-15 / CLI-RPC-02..07: every RPC consumer takes a list; reads that feed a decryption never rest on a discovered
  endpoint alone; every answer bounded (`docs/clients/scaas-rpc.md`).
- [F] ARCH-POS-13: never a decryption oracle. "Never lose ciphertext" binds PQZ and Zether in contract state; Arweave would
  hold PqChat and PqVault **file** ciphertext only, whose binding hash is signed in the message (§4.6).
- [F] A chain is `(chainId, chain_uid)` (NET-ALL-22); Avalanche C-Chain and Fuji share the genesis hash
  `0x31ced5b9…a96b` (`smartcontracts/evm/chain-uids.json:273-298`, confirmed live by the Avalanche agent's block 0 reads).

## 2. Avalanche

### 2.1 Upgrades and EVM level

| Upgrade | Fuji | Mainnet | What matters here | Source |
|---|---|---|---|---|
| Durango | — | 2024-03-06 | Warp precompile `0x0200…0005` (ACP-30) | [F] docs.avax.network ACP-30 |
| Etna (ACP-77) | — | 2024-12-16 | L1s with a continuous per-validator fee | [F] ACP-77 (date from search results) |
| Fortuna (ACP-176) | — | ~2025-04 (UNCONFIRMED) | dynamic gas target, no per-tx cap | [F] ACP-176 |
| Granite (v1.14.0) | 2025-10-29 | 2025-11-19 | P-256 `0x100` (ACP-204), dynamic min block time (ACP-226) | [F] chainstack Granite page |
| Helicon (v1.15.0) | 2026-07-28 | 2026-09-22 | continuous execution (ACP-194), subnet-evm fees (ACP-224), min price vote (ACP-283) | [F] docs.avax.network helicon-upgrade |

- [F] Every `ava-labs/libevm` tag is `v1.13.14-0.x`: go-ethereum v1.13.14 (Cancun). The only later EIP backported is EIP-7951
  (P-256). Coreth was deleted in AvalancheGo v1.15.2; the C-Chain now runs "saevm" (github.com/ava-labs/libevm/releases,
  github.com/ava-labs/avalanchego/releases/tag/v1.15.2).
- [F] Shanghai (ACP-24: PUSH0, EIP-3860) and Cancun (ACP-131: TSTORE/TLOAD, MCOPY, EIP-6780; blob transactions invalid,
  `blobGasUsed` must be 0) are active on the C-Chain and subnet-evm (github.com/avalanche-foundation/ACPs, ACP-131).
- [F] No ACP adopts Prague, Osaka or Amsterdam; the highest ACPs seen are 283 and 285. Hence no EIP-2537, EIP-7623/7976,
  EIP-7825, EIP-7939 (CLZ), EIP-7954 or EIP-8037 (ACPs tree). ACP-224 cites Fusaka's 2^24 cap as context only, not adopted.
- [F] EIP-7702 is not active; ACP-209 ("EIP-7702-style", reserved balances, a new RPC) is only Proposed (ACP-209).
- [I] Our sources use TSTORE and MCOPY (Cancun) and no CLZ (`git grep 'clz('` in `smartcontracts/evm/src` finds none). Whether
  solc's `amsterdam` codegen emits an opcode Cancun lacks was not checked (no build in this round). The blocking facts are
  the code cap (§2.2) and NET-EVM-06, not an opcode.
- [I] Under Cancun pricing the repo's gas pins do not apply: they carry EIP-8037 state gas (97,920 per new slot) and
  EIP-7976's floor. Storage on the C-Chain costs SSTORE's 20,000 (+2,100 cold) per new slot, about a fifth.

### 2.2 Code size

- [F] Max code size is 24,576 B (subnet-evm `params.MaxCodeSize` constant, pkg.go.dev/github.com/ava-labs/subnet-evm/params).
  Neither the subnet-evm chain config nor the "Customize an Avalanche L1" page lists a code-size option
  (docs.avax.network subnet-evm chain config; customize-avalanche-l1).
- [I] Init code 49,152 B (EIP-3860 via ACP-24).
- [I] An L1 above 24,576 B needs a fork of `graft/subnet-evm` inside AvalancheGo, and possibly of `libevm`, run by all of its
  validators (UNCONFIRMED whether `libevm` alone holds the constant).

### 2.3 Gas, fees and limits

- [F] ACP-176: target `T = P·e^(q/D)`, `P` = 1 M gas/s, `D` = 2^25; validators vote `gas-target`; capacity `C = 10T`, refill
  `R = 2T`; minimum price 1 wei; no per-transaction cap (ACP-176).
- [F] ACP-194 (Helicon): a transaction is charged `max(gasUsed, gasLimit / 2)`; a block is invalid when the sum of its
  transactions' gas limits exceeds `R·τ·λ = 20T` (τ = 5 s, λ = 2) (docs.avax.network ACP-194).
- [F] Live 2026-11-21 (Routescan JSON-RPC proxy): mainnet `gasLimit` 80,000,000 (T ≈ 4 M gas/s), Fuji 32,000,000
  (T ≈ 1.6 M gas/s); mainnet `baseFeePerGas` 7.5 gwei, Fuji 12 wei. Since Helicon `baseFeePerGas` is an upper bound, not the
  price paid (docs.avax.network/docs/rpcs/c-chain).
- [F] ACP-283: the minimum gas price is a validator vote, starting at 1 wei.
- [I] A transaction fits when its gas limit ≤ the block cap: 80 M on mainnet, 32 M on Fuji today. Gas-limit padding costs real
  money (at least half the limit is paid), so a relayer prices `eth_estimateGas` closely.

### 2.4 Finality and RPC

- [F] Since Helicon: `latest` and `pending` = the last *executed* block; `safe` and `finalized` = the last *settled* block,
  about τ = 5 s behind; no reorg after acceptance (ACP-194; docs.avax.network/docs/rpcs/c-chain). The block time is about
  0.7 s (computed from the live `minDelayExcess`, [E]).
- [F] Receipts and state reads wait for execution; `eth_getLogs` does not wait and returns no logs for a block not yet executed.
  `eth_pendingTransactions` is always empty. A header's `stateRoot` is the state after the last *settled* block, and its
  `gasUsed` is the sum of gas limits; real gas is in receipts (docs.avax.network/docs/rpcs/c-chain, ACP-194).
- [F] Headers carry extra fields (`blockGasCost`, `extDataHash`, `timestampMilliseconds`, `settledHeight`, …): a generic
  Ethereum decoder cannot recompute the hash (Routescan, latest block). [I] `scaas-rpc` reads the hash the RPC reports
  (alloy `header.hash`, `clients/scaas-rpc/src/evm.rs:772-778`), so this does not matter to it.
- [F] Removed in Helicon: `admin`, `warp`, `personal` namespaces, `eth_accounts`, eight `debug_*` methods. `eth_getProof` is
  served with a 128-state history by default (C-Chain config page). Avalanche adds `eth_baseFee` (an upper bound) and
  `eth_suggestPriceOptions`.
- [F] Chain ids 43114 / 43113; public RPC `https://api.avax.network/ext/bc/C/rpc`, `https://api.avax-test.network/ext/bc/C/rpc`,
  `https://avalanche-c-chain-rpc.publicnode.com`; limits not published (support.avax.network; avalanche.publicnode.com).
- [F] The deterministic deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C` exists on both (Routescan `eth_getCode`).
- [F] Relayer: acceptance checks the nonce and a balance ≥ gas limit × worst-case price + value; acceptance does not promise
  success; 16 executable slots per account in the pool (ACP-194; C-Chain config).

### 2.5 Precompiles and own precompiles

- [F] `0x01`–`0x09` (Cancun; `0x0a` point evaluation UNCONFIRMED), P-256 `0x100` (6,900 gas, since Granite), Warp
  `0x0200…0005`. No BLS12-381 (ACP-204; ACP-30; §2.1).
- [F] Avalanche L1s (subnet-evm) have stateful precompiles in `0x0200…` (deployer and tx allow-lists, native minter, fee
  manager, reward manager, warp), switched by timestamp through `precompileUpgrades`. A **custom** precompile is built in
  AvalancheGo's `graft/subnet-evm` (the `precompile-evm` repo is archived; forks use `0x0300…` upward), every validator runs
  that binary, and since Granite a `DELEGATECALL` to a stateful precompile reverts
  (docs.avax.network custom-precompiles; github.com/ava-labs/precompile-evm).
- [I] So SCaaS **could** ship `PQZ` / `MLDSA*` as stateful precompiles on its own Avalanche L1. Under NET-EVM-15 they would
  sit at addresses of our choosing, probed by the verifiers. The L1 would still be Cancun-level (no EIP-7954, no EIP-8037)
  unless we fork `libevm` too. That is a second own-chain stack beside Nethermind (22776 and the SCaaS testnet).
- [F] An L1 validator pays at least 512 nAVAX/s, about 1.33 AVAX a month (ACP-77).

## 3. Polkadot EVMs

### 3.1 Polkadot Hub (pallet-revive)

- [F] Live: Kusama Hub's PolkaVM preview in runtime v1.6.0 (2025-06-19), its EVM backend in v2.0.4 (2025-12); Polkadot
  Hub in v2.0.5, enacted 2026-01-27 (polkadot-fellows/runtimes CHANGELOG; forum "Revive smart contracts status update").
- [F] Two backends: **REVM** runs unmodified solc bytecode; **PVM** (RISC-V) runs `resolc` or Rust output. Polkadot Hub sets
  `AllowEVMBytecode = true`, `DebugEnabled = false` (developers.polkadot.com dual-vm-stack; fellows `asset-hub-polkadot`
  `lib.rs`).
- [F] REVM opcodes (polkadot-sdk `master`): PUSH0, MCOPY, TSTORE/TLOAD, CLZ handled; SELFDESTRUCT in the EIP-6780 form;
  BLOBHASH invalid. No fork level is declared; only EIP-170, EIP-3860 and EIP-3541 are cited
  (`substrate/frame/revive/src/vm/evm.rs`, `vm/evm/instructions/*`). EIP-7702 merged to `master` 2026-09-07 (PR #12229).
  Hub v2.5.0 ships pallet-revive 0.19.1; whether CLZ, P-256 and 7702 are live there is UNCONFIRMED.
- [F] **Code cap**: REVM refuses runtime above 24,576 B and init above 49,152 B (`BlobTooLarge`). The only bypass is the debug
  setting `is_unlimited_contract_size_allowed`, off on Hub (`vm/evm.rs`; Hub `lib.rs`). PVM blobs may reach 1 MiB
  (`limits.rs`), but that is `resolc` output: another compiler, upload-before-instantiate, `create2` by code hash, other
  memory rules. It is not our bytecode.
- [F] **Gas**: `ref_time`, `proof_size` and a storage deposit are metered; the adapter folds them into one gas figure;
  `evm_block_gas_limit()` returns `u64::MAX`; a dry run's gas = total cost in wei ÷ base fee; Hub sets `GasScale = 80_000`,
  `NativeToEthRatio = 10^8`; `MaxEthExtrinsicWeight` = 50 % of the max extrinsic weight since v2.1.0 (2026-03-09); the
  block weight is 2 s of `ref_time` (developers.polkadot.com gas-model; revive `lib.rs`; fellows CHANGELOG and constants).
  No EIP-7825 cap and no EIP-8037 state gas: state is paid by deposit.
- [F] **Deposits** (Hub = relay deposit / 100): `DepositPerChildTrieItem` 0.002 DOT (cut ×10 in v2.2.1), `DepositPerByte`
  0.00001 DOT, `DepositPerItem` 0.2 DOT, 30 % code-hash lockup, existential deposit 0.01 DOT. The caller pays; clearing
  storage refunds pro rata (fellows relay and system-parachain constants; revive `storage.rs`). [E] One new 32-byte slot
  (64 B key + value) ≈ 0.00264 DOT; 1 KiB of slots ≈ 0.084 DOT. Hub now sets `Deposit = PGasDeposit`, whose meaning is
  UNCONFIRMED.
- [F] **eth-rpc**: 28 methods (`eth_call`, `eth_estimateGas`, `eth_getLogs`, `eth_getStorageAt`, `eth_feeHistory`,
  `eth_getBlockReceipts`, …); missing `eth_getProof` and the filter methods. `latest` / `pending` → the best block,
  `finalized` / `safe` → the latest finalized block. Ethereum and Substrate hashes are mapped, and a lookup by Ethereum hash
  may fall back to a Substrate hash. Transaction types: legacy, 2930, 1559 (type 4 only on `master`)
  (`substrate/frame/revive/rpc/src/apis/execution_apis.rs`, `rpc/src/client.rs`; developers.polkadot.com json-rpc-apis).
- [F] Precompiles: `0x01`–`0x09` documented; `master` adds `0x0a` and P256Verify; **no BLS12-381**. Hub runtime precompiles: ERC-20
  views of assets (`0x120`, `0x220`, `0x320`), XCM, AssetConversion, Vesting. A new precompile is a runtime type and needs a
  runtime upgrade, which on Hub goes through Polkadot governance (`precompiles/builtin.rs`; Hub `lib.rs`).
- [F] Chain ids and RPCs: Polkadot Hub 420420419 `https://eth-rpc.polkadot.io/`; Kusama Hub 420420418
  `https://eth-rpc-kusama.polkadot.io/`; Polkadot Hub TestNet (Paseo, PAS) 420420417 `https://eth-rpc-testnet.polkadot.io/`;
  Westend Asset Hub 420420421 `https://westend-asset-hub-eth-rpc.polkadot.io` (developers.polkadot.com connect; chainlist).
  The temporary "Passet Hub" (420420422) is retired.
- [F] Hub authors a block every 2 s under elastic scaling (CHANGELOG v2.4.0). The GRANDPA finality delay on Hub was not
  found [UNCONFIRMED; [I] seconds to tens of seconds, measured before `enabled`].

### 3.2 Moonbeam family (Frontier)

- [F] Moonbeam 1284, Moonriver 1285, Moonbase Alpha 1287: block 60,000,000 gas, per transaction 52,000,000, 6 s blocks;
  minimum gas price 31.25 / 0.3125 / 0.03125 gwei (moonbeam-docs `variables.yml`; moonbeam runtime `lib.rs`).
- [F] Storage growth (MBIP-5): 366 gas per byte, 160 KiB of new storage per block; effective gas = max(legacy, PoV, storage)
  (moonbeam runtime `lib.rs`; frontier `runner/stack.rs`).
- [F] Frontier `master` uses `Config::osaka()`: code 24,576 B, init 49,152 B, EIP-7702, CLZ. Moonbeam's own 7702 PR merged
  2025-08-27. Whether Moonbeam's pinned Frontier is at that config is UNCONFIRMED.
- [F] Precompiles: `0x01`–`0x09`, **BLS12-381 `0x0b`–`0x11`**, **P-256 `0x100`**, Moonbeam's own from 2048 (moonbeam
  `precompiles.rs`). `finalized` = the relay-finalized block, `safe` = `finalized`; `eth_getProof` and
  `eth_createAccessList` missing (moonbeam-docs `eth-rpc.md`).

### 3.3 What the differences mean for SCaaS

| | Polkadot Hub (REVM) | Moonbeam |
|---|---|---|
| Runtime cap | 24,576 B, hard | 24,576 B (Frontier osaka) |
| Amsterdam | not declared | Osaka config |
| Gas model | fees in weight + refundable deposit | Ethereum gas + storage gas 366 / B |
| Per-tx limit | 50 % of max extrinsic weight (no gas figure) | 52 M gas |
| BLS12-381 / P-256 | no / on `master` | yes / yes |
| `finalized` tag | GRANDPA-finalized | relay-finalized |
| Own precompile | Polkadot governance | Moonbeam's governance |
| EIP-7702 | on `master` only | live |

- [I] EIP-7702 live on Moonbeam (and coming to Hub) is not a SCaaS rule change: the "no EIP-7702" rule is that a SCaaS EOA
  signs with its own key and runs no code; [§5 of evm.md](../networks/evm.md#5-eip-7702-accounts) already covers chains where
  7702 is live.
- [I] Polkadot's native accounts (sr25519, planned in `ua-rs`, TODO 8c) are not needed for the EVM: Hub's `eth-rpc` takes
  ordinary secp256k1 Ethereum transactions. A native account must `map_account` first.

### 3.4 Which to target first

**Recommendation: Polkadot Hub (REVM), testnet 420420417 first; Moonbeam second.** Reasons [I]: Hub is Polkadot's own EVM, on
the relay's security, paid in DOT, with a Paseo testnet. Its runtime tracks Ethereum quickly (CLZ and 7702 landed within
months), so a code-size change is likelier to arrive there. Its deposit is refunded when state is cleared (PqChat and PqVault
clear nothing, so for them it is a fee). Against it: no BLS12-381, so Zether needs the software path (§6.3), and its gas has
no Ethereum figure, so every 60 M line must be measured again by weight. Moonbeam is the better target if Zether and
Ethereum-like gas weigh more (Q2). Neither deploys before its code cap rises (§0).

## 4. Arweave

### 4.1 ANS-104 data item layout

[F] In order, from ANS-104 and `arbundles` (github.com/ArweaveTeam/arweave-standards ANS-104; irys-xyz/arbundles `constants.ts`,
`DataItem.ts`, `tags.ts`):

| Field | Bytes |
|---|---|
| signature type | 2 (little-endian [I], see Q7's probe) |
| signature | by type |
| owner (public key) | by type |
| target | presence byte (0 / 1) + 32 |
| anchor | presence byte + 32 |
| number of tags | 8 |
| number of tag bytes | 8 |
| tags | Avro array of `{name: bytes, value: bytes}` |
| data | rest |

| Type | Name | Signature B | Owner B |
|---|---|---:|---:|
| 1 | Arweave RSA-PSS 4096 | 512 | 512 |
| 2 | ed25519 | 64 | 32 |
| 3 | Ethereum secp256k1 | 65 | 65 |
| 4 | Solana (ed25519) | 64 | 32 |
| 5 | InjectedAptos | 64 | 32 |
| 6 | MultiAptos | 2,052 | 1,025 |
| 7 | TypedEthereum (EIP-712) | 65 | 42 |

- [F] A presence byte other than 0 or 1 is invalid. Limits: ≤ 128 tags, name ≤ 1,024 B, value ≤ 3,072 B, both non-empty,
  and in `arbundles` and Turbo **≤ 4,096 tag bytes in total**; an item is at least 80 B (ANS-104; `DataItem.ts`; Turbo upload docs).
- [F] **What is signed** — the ANS-104 text and the code differ; bundlers run the code. `arbundles` signs
  `deepHash(["dataitem", "1", <signature type as decimal string>, owner, target, anchor, <raw Avro tag bytes>, data])`. An
  absent target or anchor is an empty blob, and an empty tag list is **0 bytes**, not `0x00` (`ar-data-base.ts`, `tags.ts`).
- [F] Deep hash, SHA-384 throughout: a blob → `SHA384(SHA384("blob" ‖ decimal length) ‖ SHA384(data))`; a list starts
  `acc = SHA384("list" ‖ decimal count)`, then `acc = SHA384(acc ‖ deepHash(item))` per item; output 48 B. The signer signs the
  48 bytes; **id = base64url(SHA-256(signature))** (`deepHash.ts`, `ar-data-bundle.ts`).
- [F] Type 2: raw ed25519 over the 48 bytes. Type 3: owner = the uncompressed 65-byte key, signature 65 B `r ‖ s ‖ v` from
  ethers `signMessage(deepHash)`; verification ignores `v` (`curve25519.ts`, `ethereumSigner.ts`). [I] `signMessage` is
  EIP-191 `personal_sign`, prefix `"\x19Ethereum Signed Message:\n48"`.
- [F] Avro: a positive block count, then pairs (zigzag-varint length + bytes), then a terminating `0`; the reader also takes a
  negative count and does not refuse trailing bytes (`tags.ts`). No official cross-language vectors exist; `bundles-rs`
  (load.network) is a Rust implementation without vectors (docs.load.network ANS-104 Rust SDK).

### 4.2 Bundlers

- [F] **Turbo** (ar.io): `POST /tx` or `/tx/:token` with a signed item as `application/octet-stream`; ANS-104 is detected by
  a signature type of 1–8; items up to 4 GiB, chunked uploads above. The receipt carries `id`, `owner`, `payer`,
  `deadlineHeight`, `timestamp`, `signature`, `public`. The docs call it proof of acceptance, "not a blanket guarantee" of later
  retrieval (docs.ar.io turbo upload; receipts).
- [F] Free tier, live `GET https://upload.ardrive.io/v1/info`: `freeUploadLimitBytes` 107,520 (105 KiB) per item,
  `lifetimeBytes` and `ipBytes` 10,485,760 (10 MiB).
- [F] Payment: AR, ETH, SOL, POL, ARIO, USDC, ETH on Base, card; x402 pay-per-upload in USDC on Base (+15 %). Signers accepted:
  Arweave RSA-PSS, EVM ECDSA, Solana ed25519 (docs.ar.io advanced uploading; pricing; turbo-upload-service README).
  AVAX is not on the list.
- [F] A payer may differ from the signer: the payer signs a `shareCredits` approval (a data item tagged with the recipient
  address, an amount and an optional expiry); the uploader sends `x-paid-by: <payer>` (docs.ar.io turbo credit sharing).
- [F] **Irys**: `node1.irys.xyz` and `mainnet.arweave.irys.xyz` sent uploads to Arweave and were retired on 2026-11-01; new
  uploads go to Irys's own L1 (docs.irys.xyz migrating). Irys is no route to Arweave now.
- [F] Settlement on Arweave L1 after a bundler accepts: not documented by Turbo (UNCONFIRMED; Irys quoted > 100 min for its own path).

### 4.3 Gateways

- [F] `GET /{id}` (manifests resolved) and `GET /raw/{id}` (not), both with `Range`. Responses carry `X-AR-IO-Verified`
  (cached and checked against L1), `X-AR-IO-Digest`, `Content-Digest`, the bundle position headers, and **`X-Arweave-Owner`,
  `X-Arweave-Owner-Address`, `X-Arweave-Tag-*`** (docs.ar.io data API; verification headers).
- [F] **No endpoint returns the whole data item.** Getting it means a `Range` read of the root transaction at the item's
  offset, or the chunk route (`/tx/{root}/offset`, `/chunk/{offset}/data`) (docs.ar.io wayfinder retrieval strategies).
- [F] Gateways verify root transactions in the background and may serve data before verifying it (docs.ar.io data
  verification). The Gateway Address Registry lives in ar.io's Solana programs (≤ 3,000 gateways, 20,000 ARIO stake),
  listed by `ARIO.init().getGateways()` (docs.ar.io gateway registry; get-gateways).
- [F] GraphQL `POST /graphql`, `transactions(ids, owners, tags, …)` (docs.ar.io find data).

### 4.4 Cost

- [F] `arweave.net/price/1048576` = 13,545,773,253 winston = 0.01355 AR per MiB; per GiB 13.83 AR (fetched 2026-11-21).
- [F] Turbo `/v1/rates`: **USD 46.19 per GiB** (EUR 42.03), plus a per-item fee of 9,211,119 winc (payment.ardrive.io/v1/rates).
- [E] A 1 MiB padded image ≈ $0.045; a 16 MiB bucket ≈ $0.72; an item of ≤ 105 KiB is free within the 10 MiB per-IP lifetime cap.

### 4.5 The attachment flow (proposal)

```mermaid
sequenceDiagram
  participant A as App (pqchat-core / pqvault-core)
  participant U as ua-rs
  participant R as scaas-rpc
  participant B as Bundlers (list)
  participant G as Gateways (list)
  A->>U: seal_file(file) (fresh file key, handle only)
  U-->>A: ct (padded to a bucket), ctSha256, key handle
  A->>U: sign_data_item(ct, upload key for app label + session)
  U-->>A: signed ANS-104 bytes, id = SHA-256(sig)
  A->>R: upload(bytes) (no key in scaas-rpc)
  R->>B: POST /tx, same bytes to one or more
  B-->>R: receipt {id, ...}; id equal to the local id
  A->>U: message / item with file {url: ar://id, ctSha256, sha256, size, key or keyWrap}
  Note over A: the message goes to chain or Matrix as today
  A->>R: read(ar://id, size cap) (marked: feeds a decryption)
  R->>G: GET /raw/id, failover (or strict majority)
  G-->>R: bytes (bounded by the bucket)
  R-->>A: bytes
  A->>U: open_file(bytes) after SHA-256(bytes) == ctSha256
```

- [F] UA-7's `file` content already carries `ctSha256`, checked on the fetched bytes before decryption, and signed with the
  message; `url` is "1–2,048 B, `https://` or `ipfs://`" (`docs/superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md:534-545`).
  **`ar://` is not an allowed scheme today** (Q4). PqVault's `file` replaces the key by a `keyWrap` under `kFile`
  (`docs/superpowers/specs/2026-11-17-pqvault.md:914-917`).
- [I] ARCH-POS-13 holds: the file key is fresh and symmetric (outside the PQZ/Zether scope), and the `ctSha256` check comes
  first, so no gateway can make a client decrypt bytes of its choosing.

### 4.6 The `ua-rs` proposals of TODO 8i (4), checked

| Proposal | Verdict |
|---|---|
| ANS-104 format: Avro tags, SHA-384 deep hash, id = SHA-256 of the signature; vectors in `clientkeys` first | **Confirmed, corrected**: follow `arbundles`, not the ANS-104 text: the signature type string enters the deep hash, tags are hashed as one raw Avro blob, an empty tag list is 0 bytes, an absent target / anchor an empty blob, ≤ 4,096 tag bytes. Vectors generated from `arbundles` (a positive control, no tags, no target / anchor, one per type), read by every language. |
| Signing by the existing ed25519 and secp256k1 keys | **Confirmed for the format**: type 2 = raw ed25519 over the 48-byte hash; type 3 = EIP-191 `personal_sign` over it [I], 65-byte uncompressed owner. **Open**: Turbo documents "Solana ED25519", so a type 2 item may be refused; then type 4 (same bytes, 32-byte owner) is used. A probe settles it (Q7). Not the UA signing path: a raw-message sign of a derived key, which never signs a UA operation. |
| A per-app upload key, rotated per session or store, never the UA or wallet key | **Confirmed and necessary**: gateways publish the owner key and its address in headers and index it in GraphQL. **Not sufficient**: the payer still links uploads (§4.7). |
| Data item verification on read | **Corrected**: no gateway endpoint returns the signed item, so a reader cannot check the signature on a `/raw` read. The integrity check is `ctSha256`, already signed in the message; the data item check happens at upload (the id the bundler returns equals the locally computed one). |
| No native Arweave RSA-PSS 4096 wallet for now | **Confirmed for Turbo** (non-RSA signers, many payment tokens). Irys is no longer an Arweave route. |

### 4.7 Metadata exposure

- [F] Public per upload: the owner key and its address, every tag, the size, the time (receipt and L1 block); Turbo's receipt
  names the `payer`; the bundler sees the IP (§4.2, §4.3).
- [F] Linking paths beyond the key: a `shareCredits` approval names the recipient upload address; x402 pays by a public USDC
  transfer on Base; the free tier's 10 MiB lifetime cap is per IP.
- [I] Countermeasures, in order of effect: (1) a fresh upload key per session or vault epoch, derived in `ua-rs` from the seed
  and an app label, never shown or exported; (2) no tags except, at most, a fixed `Content-Type: application/octet-stream` (the
  same on every item); (3) the ciphertext padded to a bucket; (4) upload time decoupled from send time where the app allows it;
  (5) one payer for many users (an operator), so the payer names a service, not a person. A per-user payer links all of that
  user's upload keys together.

## 5. `scaas-rpc`

### 5.1 EVM profiles

- [F] The EVM pool is chain-neutral: `EvmPool::connect(list, chain_id, chain_uid)` (`clients/scaas-rpc/src/evm.rs:167`); the
  identity check reads `eth_chainId`, then block 0's hash (`evm.rs:754-797`); `finalized` is `BlockNumberOrTag::Finalized`
  (`evm.rs:706-712`, `815-822`, `1160-1163`); pinned reads name their block by hash under EIP-1898, `requireCanonical`
  (`evm.rs:901-905`). The node's finality modes are `depth` and `tag` (`scaas-node/src/config.rs:723-725`). No crate code
  is chain-specific; `eth_getProof` and filters are not used (`git grep` in `clients/scaas-rpc/src`, `scaas-node/src`).
- [I] **Avalanche**: configuration only (`tag finalized`, the existing `chain-uids.json` rows), plus three notes for the node and
  the indexer. (1) Read logs at or below `finalized`, since `eth_getLogs` is empty for blocks not yet executed. (2) A
  receipt appears only after execution, so "accepted, no receipt yet" is `Pending`, never `dead`. (3) The gas limit
  is priced closely (ACP-194's half-limit charge) and the fee cap read from `eth_baseFee` / `baseFeePerGas` is an upper bound.
  CLI-RPC-03 is unchanged: `eth_chainId` separates C-Chain and Fuji, which share `chain_uid`.
- [I] **Polkadot Hub**: configuration, plus probes before `enabled`. (1) Is block 0's Ethereum hash stable and the same on two
  independent `eth-rpc` instances? CLI-RPC-03 and CLI-RPC-05 compare hashes. (2) Is an EIP-1898 `{blockHash, requireCanonical}`
  parameter accepted on `eth_call` / `eth_getStorageAt`? `strict_majority` needs it. (3) Is `latest`, the best block, ever
  reorganised? The finality mode is `tag finalized` either way. (4) The fee caps of CLI-RPC-05 need a Hub-specific cap,
  since gas is wei ÷ base fee and `evm_block_gas_limit` is `u64::MAX`.
- [I] **Moonbeam**: configuration (`tag finalized`), plus the same EIP-1898 probe.

### 5.2 An Arweave module (proposal, under CLI-RPC-01..11)

- **Endpoints** (CLI-RPC-02): two lists of `{url, class, label, auth}`, gateways and bundlers. `default` = the release's reviewed
  list (e.g. `arweave.net` and well-staked ar.io gateways; Turbo's `upload.ardrive.io`). `named` = the operator's or the holder's.
  `discovered` = from the Gateway Address Registry; the crate discovers nothing, the caller passes them. No redirect followed.
- **Identity** (CLI-RPC-03): a gateway answers `GET /info` with `network` `arweave.N.1`; any other network is dropped for the
  process, as an EVM endpoint on another chain is.
- **Reads** (CLI-RPC-04/05/06): `data(id, max_bytes)` = `GET /raw/{id}`. Failover by default; one gateway answers the whole
  read. Under `strict_majority`, ⌊n/2⌋ + 1 gateways return the same SHA-256 of the bytes. A read that feeds a decryption
  (every attachment read) is marked, so a `discovered` gateway alone never serves it. GraphQL `query(ids | tags)`: the same
  policies, with answers compared as decoded values.
- **Bounds** (CLI-RPC-07): `max_bytes` is the bucket the signed `file.size` names (padded), never more; an announced length
  above it is refused unread. GraphQL answers capped at 16 MiB and depth 64, like every JSON answer.
- **Upload** (CLI-RPC-01, CLI-RPC-08): `upload(bytes)` takes a data item signed by `ua-rs`, computes its id locally
  (`SHA-256(signature)`) and posts the same bytes to one or more bundlers. A bundler answering another id counts as not
  accepting. The outcome is merged `Sent` / `Rejected`, with receipts kept. No key, no signing, no payment in the crate; the
  `x-paid-by` header is a caller field.
- **Status**: "settled on Arweave" is a later read (the item visible through GraphQL, its bundle at a block). A Turbo receipt is
  never final (CLI-RPC-09's spirit).
- **Logs** (CLI-RPC-11): ids and sizes may be logged, never bytes, URLs or credentials.

## 6. Feasibility per piece and chain

### 6.1 The deploy condition, per contract

[F] On each of the five targets the runtime cap is 24,576 B: Avalanche C-Chain and Fuji, Avalanche L1 (stock), Polkadot Hub
REVM, Moonbeam. Every SCaaS piece has contracts above it (`size-baseline.json`):

| Piece | Contracts above 24,576 B (runtime B) |
|---|---|
| UA registry | `UARegistry` 33,335, `UARegistryAuxLib` 35,417, `UARegistryRegLib` 30,209 |
| Factory | `OpenFactory` 34,999 |
| Token kinds | every kind has a module above: e.g. `NormalTokenA` 25,073, `WrappedTokenW` 27,683, `NormalPqzTokenQ` 34,895, `WrappedZetherTokenZ` 30,491 |
| PqChat | `PqChat` 29,111 |
| PqVault | `PqVault` 30,152 (`ea95b9c7b`) |
| DEX | `SCaaSDex` 33,497 |
| Governance | `GovernanceRouter` 27,610 |

So the per-contract verdict is "does not deploy" for every piece on every target, until the chain raises its cap (EIP-7954)
or SCaaS runs its own chain there.

### 6.2 Gas and transaction fit (once code fits)

| Need (repo figures, Amsterdam pricing) | Avalanche C-Chain | Fuji | Polkadot Hub | Moonbeam |
|---|---|---|---|---|
| Largest deploy, ≤ 60 M asked (`UARegistryCoreLib` 56.64 M at T66b; `PqVault` impl 51.19 M) | fits under 80 M [I]; Cancun pricing far lower [I] | 32 M cap: lower Cancun pricing must be measured [E] | weight, unmeasured | 52 M per tx, plus storage gas: measure |
| PQZ `OFFCHAIN` op ≈ 23.0 M incl. state gas (`pq-zero-knowledge.md:2766`) | fits | fits [E] (Cancun pricing) | unmeasured | fits |
| PqChat `storeMessage` 5,100 B: 0.35 M + 8.31 M state (`pqchat.md:599`) | fits | fits | deposit ≈ 0.23 DOT [E] | fits (≈ 85 slots, 2 M storage gas [E]) |
| PqVault `createItem` 16,416 B: 1.10 M + 25.94 M state (`ea95b9c7b`) | fits | fits | ≈ 265 slots ≈ 0.70 DOT [E] | ≈ 6.2 M storage gas; 17 KiB of 160 KiB per block [E] |
| PqVault `createItem` 288 B: 0.17 M + 1.46 M state | fits | fits | ≈ 15 slots ≈ 0.04 DOT [E] | fits |

[E] The Hub deposits count EIP-8037 state gas ÷ 97,920 as new slots, at 0.00264 DOT each; SSTORE2 code bytes pay a code
deposit instead, which was not derived. The Moonbeam storage gas is 366 × 64 B per slot.

### 6.3 Precompiles and the software path (ARCH-POS-18)

| Need | Avalanche | Polkadot Hub | Moonbeam | Without it |
|---|---|---|---|---|
| P-256 (`webauthn` / passkeys) | `0x100` | `master` only | `0x100` | Solidity ≈ 200–330 k gas ([F] `docs/networks/evm.md`, P-256 bullet) |
| EIP-2537 (Zether, `0x0105`, `0x0106`, `0x0121`) | none | none | `0x0b`–`0x11` | Solidity BLS12-381: `0x0121` verify ≈ 3–12 M, registration n = 2 ≈ 4–17 M, n = 64 ≈ 83–350 M ([E] `docs/superpowers/specs/2026-11-19-bls12381-multi.md` §8.5). Zether transfer: with the precompile 2.96 M verify ([F] `docs/contracts/zether.md`, §19); in software [E] tens of M (hundreds of G1 scalar multiplications at ≈ 0.5–1.4 M each by §8.5's unit costs), above 2^24 where a chain has that cap, and on Fuji's 32 M block. Not measured |
| ML-DSA / FN-DSA verify (UA PQ kinds) | none | none | none | already Solidity: FN-DSA-512 ≈ 2.3 M, ML-DSA-65 cached ≈ 5.8 M, ML-DSA-87 cached 8.86 M ([F] `docs/contracts/pqchat.md:588-589`, `docs/contracts/accounts.md:2567`) |
| `PQZ` (`PRECOMPILE` tokens) | none (own L1: a stateful precompile) | none (governance) | none | `OFFCHAIN` tokens (CTR-PQZ-27), ≈ 23 M per op |

[I] Zether on Avalanche and on Polkadot Hub is the one case ARCH-POS-18 sends back to the owner. A software BLS12-381 must be
built and measured first. If a transfer does not fit, the numbers go to the owner (Q3); the kind is not disabled by this round.

## 7. Recommendations

1. **Seed draft profiles now, deploy later.** Seed `avalanche-mainnet` / `avalanche-testnet` (rows exist),
   `polkadot-hub-mainnet` (420420419) / `polkadot-hub-testnet` (420420417; Westend keeps its name, `polkadot-hub-westend`), and later
   `moonbeam-mainnet` / `moonbeam-testnet` (1287). Each gets a `src/chains/<key>/README.md` stating the chain's facts as
   `base-testnet`'s does, and no deploy until the chain's code cap and Amsterdam fork arrive (NET-EVM-06). Watch the ACP list and
   Parity's revive releases for EIP-7954.
2. **Polkadot: Hub first, Moonbeam second** (§3.4).
3. **`scaas-rpc`**: profile data plus the Avalanche notes of §5.1. Run the Hub probes (block 0 hash stability, EIP-1898,
   reorgs of `latest`) before Hub is `enabled`. Add an Arweave module as in §5.2: gateway and bundler lists, failover and
   strict majority over the bytes' SHA-256, decryption-feeding mark, bucket-bounded reads, keyless upload of `ua-rs`-signed
   bytes.
4. **`ua-rs`**: ANS-104 with the `arbundles` deep hash, vectors in `clientkeys` first and read by every language, type 2 or 4
   (ed25519) and type 3 (secp256k1). A per-app, per-session upload key from a new derivation label, never a UA or wallet key.
   `seal_file` / `open_file` with handles only (O9 (b)). Bucket padding in `ua-rs`, so every client pads alike.
5. **Arweave**: Turbo as the first `default` bundler, at least one `named` alternative before mainnet. Its single-vendor status
   is a risk to record, not a blocker: the data, once settled, is on Arweave whoever bundled it.
6. **NET-ALL-25 text**: it says no two chain profiles share a genesis hash, but Avalanche C-Chain and Fuji do (as ETH and
   ETC do), and `chain-uids.json` and the deploy gate already key on `(chainId, chain_uid)`. The rule's text should say so (Q8).

## 8. Open questions for the owner

- **Q1 — Avalanche while the C-Chain stays at Cancun.** (a) Draft profile; deploy when the C-Chain adopts EIP-7954 and Amsterdam
  (may be years [I]). (b) A second build target, `cancun`, with every contract split under 24,576 B: against NET-EVM-06 and a
  module split the owner decides. (c) An own Avalanche L1 on a forked `subnet-evm` with a larger cap and PQ precompiles: a second
  own-chain stack, still Cancun unless `libevm` is forked. **Recommendation: (a)**; (c) only if a customer asks for an
  Avalanche L1.
- **Q2 — First Polkadot EVM.** (a) Polkadot Hub (REVM). (b) Moonbeam. (c) Hub PVM through `resolc`: no, another compiler and
  bytecode. **Recommendation: (a)**, Moonbeam second; choose (b) first if Zether on Polkadot matters more than being on
  Polkadot's own chain.
- **Q3 — Zether without EIP-2537** (Avalanche, Polkadot Hub). (a) Build and measure the software BLS12-381 path, then bring the
  numbers (ARCH-POS-18). (b) Ask now to disable Zether on those chains. **Recommendation: (a)**, after the code-cap question
  is settled for the chain, since nothing deploys there before.
- **Q4 — How a file names its Arweave copy.** (a) UA-7 `url` gains the scheme `ar://<43-char id>` (a UA-7 protocol change with
  vectors). (b) A `store` kind `arweave` with the id as locator; PqVault has no store list, so it would need one. **Recommendation:
  (a)**, as the TODO already writes `url = ar://<id>`.
- **Q5 — Who pays for uploads.** (a) The free tier only (≤ 105 KiB per item, 10 MiB per IP for life). (b) Each user's own Turbo
  credits: links all of that user's upload keys. (c) An operator payer with `shareCredits` approvals to rotating upload keys: the
  payer is a service, but the operator learns which keys it funds. (d) x402 USDC on Base per upload: a public payer per item.
  **Recommendation: (c)**, with (a) for small items, like the relayer that pays gas.
- **Q6 — Size buckets.** (a) Powers of two from 64 KiB (a 64 KiB item stays in the free tier). (b) A short fixed list (100 KiB,
  1 MiB, 4 MiB, 16 MiB, then doubling). **Recommendation: (a)**, one rule in `ua-rs`.
- **Q7 — The ed25519 signature type.** (a) Type 2 (ed25519). (b) Type 4 (Solana; the same bytes, the form Turbo documents).
  (c) Type 3 (secp256k1) only. **Recommendation: probe Turbo with a type 2 and a type 4 item of ≤ 105 KiB first, then (a) if
  accepted, else (b)**. The same probe confirms the little-endian fields.
- **Q8 — NET-ALL-25 and shared genesis hashes.** (a) Amend its text: no two chain profiles share `(chainId, chain_uid)`; a public
  chain pair with one genesis (C-Chain and Fuji) is separated by the chain id. (b) Keep it and refuse Fuji. **Recommendation:
  (a)**.

## 9. Sources

Repo (at `2196f81f5` unless noted): `smartcontracts/evm/size-baseline.json`; `smartcontracts/evm/chain-uids.json:273-298`;
`smartcontracts/evm/src/chains/base-testnet/README.md`; `clients/scaas-rpc/src/evm.rs`; `scaas-node/src/config.rs:723-725`;
`docs/networks/evm.md`; `docs/networks/README.md` (NET-ALL-22, NET-ALL-25); `docs/clients/scaas-rpc.md`; `docs/decisions.md`
(ARCH-POS-13, -15, -18); `docs/contracts/pqchat.md:586-612`; `docs/contracts/zether.md` §19; `docs/contracts/pq-zero-knowledge.md:2760-2772`;
`docs/contracts/accounts.md:348-354`, `:2567`; `docs/superpowers/specs/2026-11-19-bls12381-multi.md` §8.5;
`docs/superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md:534-582`; `docs/superpowers/specs/2026-11-17-pqvault.md:905-920`;
commit `ea95b9c7b` (branch `pqvault-v`, PqVault gas pins and size row); commit `82be3899d` (branch `pqchat-core-build`, CLI-PQC-02).

Avalanche: https://docs.avax.network/docs/primary-network/helicon-upgrade ;
https://github.com/ava-labs/avalanchego/releases/tag/v1.15.2 ; https://github.com/ava-labs/libevm/releases ;
https://github.com/avalanche-foundation/ACPs (ACP-24, -30, -77, -131, -176, -194, -204, -209, -224, -226, -283) ;
https://docs.avax.network/docs/acps/194-continuous-execution ; https://docs.avax.network/docs/acps/224-dynamic-gas-limit-in-subnet-evm ;
https://docs.avax.network/docs/acps/283-dynamic-minimum-gas-price ; https://docs.avax.network/docs/rpcs/c-chain ;
https://docs.avax.network/docs/nodes/chain-configs/primary-network/c-chain ;
https://docs.avax.network/docs/nodes/chain-configs/avalanche-l1s/subnet-evm ;
https://docs.avax.network/docs/avalanche-l1s/upgrade/customize-avalanche-l1 ;
https://docs.avax.network/docs/avalanche-l1s/custom-precompiles/background-requirements ; https://github.com/ava-labs/precompile-evm ;
https://pkg.go.dev/github.com/ava-labs/subnet-evm/params ; https://docs.chainstack.com/docs/avalanche-granite-upgrade.md ;
https://docs.chainstack.com/docs/avalanche-helicon-upgrade.md ; https://support.avax.network/en/articles/6159007-what-apis-are-available-on-avalanche ;
live blocks and code through https://api.routescan.io/v2/network/{mainnet,testnet}/evm/{43114,43113}/etherscan/api .

Polkadot: https://raw.githubusercontent.com/polkadot-fellows/runtimes/main/CHANGELOG.md ;
https://forum.polkadot.network/t/revive-smart-contracts-status-update/16366 ;
https://developers.polkadot.com/smart-contracts/for-eth-devs/dual-vm-stack/ ; …/evm-vs-pvm/ ; …/gas-model/ ; …/json-rpc-apis/ ;
…/blocks-transactions-fees/ ; …/accounts/ ; https://developers.polkadot.com/smart-contracts/connect/ ;
https://developers.polkadot.com/smart-contracts/precompiles/eth-native/ ;
polkadot-sdk `master` `substrate/frame/revive/src/{lib.rs,limits.rs,storage.rs,vm/evm.rs,precompiles/builtin.rs}` and
`substrate/frame/revive/rpc/src/{client.rs,apis/execution_apis.rs}` ; https://github.com/paritytech/polkadot-sdk/pull/12229 ;
polkadot-fellows runtimes `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs`, `system-parachains/constants`,
`relay/polkadot/constants` ; https://chainlist.org/chain/420420421 ;
moonbeam-foundation `moonbeam-docs` `variables.yml`, `builders/ethereum/json-rpc/eth-rpc.md`, `learn/core-concepts/tx-fees.md`;
`moonbeam` `runtime/moonbeam/src/{lib.rs,precompiles.rs}` ; polkadot-evm `frontier` `primitives/evm/src/lib.rs`,
`frame/evm/src/runner/stack.rs` ; https://github.com/moonbeam-foundation/moonbeam/pull/3358 .

Arweave: https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md ;
https://github.com/irys-xyz/arbundles (`src/constants.ts`, `DataItem.ts`, `ar-data-base.ts`, `ar-data-bundle.ts`, `deepHash.ts`,
`tags.ts`, `signing/chains/ethereumSigner.ts`, `signing/keys/curve25519.ts`) ; https://docs.ar.io/apis/turbo/upload-service/upload/ ;
https://docs.ar.io/build/upload/receipts/ ; https://upload.ardrive.io/v1/info ; https://docs.ar.io/build/upload/advanced-uploading-with-turbo/ ;
https://docs.ar.io/apis/turbo/upload-service/pricing/ ; https://docs.ar.io/sdks/turbo-sdk/turbo-credit-sharing/ ;
https://docs.irys.xyz/onchain-storage/migrating ; https://docs.ar.io/apis/ar-io-node/data/ ;
https://docs.ar.io/build/run-a-gateway/manage/verification-headers/ ;
https://docs.ar.io/sdks/wayfinder/wayfinder-core/data-retrieval-strategies/ ; https://docs.ar.io/learn/gateways/data-verification/ ;
https://docs.ar.io/learn/gateways/gateway-registry/ ; https://docs.ar.io/build/access/find-data/ ;
https://arweave.net/price/1048576 ; https://payment.ardrive.io/v1/rates ;
https://docs.load.network/using-load-network/miscellaneous/arweaves-ans-104-rust-sdk .
