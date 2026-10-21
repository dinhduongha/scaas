> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Soroban, NEAR and Algorand: long-term balance storage and candidate families

Written 2026-10-19 at the owner's request (TODO "Family priority for UA and long-lived balances" and "Research note:
Soroban, NEAR and Algorand"); the Solana storage-cost section (§5) was added the same day at the owner's request.
Research only: nothing here is built or measured by us, and there is no PQZ spike. Every URL was read on
**2026-10-19**; values marked "mainnet RPC" were read from a public mainnet endpoint that day. Tags: **[source]** an
official document, specification, protocol source file or live network value; **[inference]** this note's
reasoning; **[estimate]** a number this note computed from sources plus stated assumptions (sizes of SCaaS records
that are not built are estimates).

Baseline for the comparison: Solana [NET-SOL-34](../networks/solana.md#NET-SOL-34) (UA = registry record + key claims + an Account PDA that owns one
token account per mint; rent-exempt deposits, nothing expires), the UA model of `contracts/accounts.md` §1.6–1.8
(kind table, immutable admin-free registry, `msig` structures with ≤ 16 members) and the PQZ sizes of
`contracts/pq-zero-knowledge.md` §4.4 (ciphertext 16,512 B, public key 16,384 B, PQZL transfer proof 42,762 B,
PQZH ≈ 231 KB; ciphertexts kept in state per CTR-PQZ-07 as changed 2026-10-19).

## 1. Result

| Question | Soroban | NEAR | Algorand |
|---|---|---|---|
| Does an idle balance persist without upkeep? | **No, it is archived** when its TTL runs out (≤ ≈ 180 days after the last extension), but under protocol 23+ it is kept by validators and restored automatically, for a fee, on next use | **Yes**, forever; storage is a locked deposit (1 NEAR per 100 kB) | **Yes**, forever; storage is a locked minimum balance (box: 2,500 + 400 µAlgo per byte) |
| Recurring cost? | **Yes**: rent per byte per ledger; today ≈ 0.10 XLM per year for a ≈ 200-byte balance entry, ≈ 8.4 XLM per year for one 16,512-byte ciphertext, up to ≈ 10× more if Soroban state grows to its target size | none (deposit refunded when the data is deleted) | none (minimum balance released when the box / holding is deleted) |
| One balance entry | ≈ 0.10 XLM / year to keep live, or ≈ 0.033 XLM per restore after archival [estimate] | 0.00125 NEAR deposit (NEP-145 bound of the main tokens) [source] | 0.0185 ALGO box deposit (ARC-200-style ledger) or 0.1 ALGO per ASA holding [estimate / source] |
| One 16,512-byte ciphertext | ≈ 8.4 XLM / year; ≈ 84 XLM over 10 years kept live [estimate] | ≈ 0.166 NEAR deposit [estimate] | ≈ 6.62 ALGO deposit [estimate] |
| UA without a native wallet | a `C…` custom account per UA (`__check_auth`), balances as contract data | a sub-account per UA with a global contract, or an internal ledger key | a box record per UA; balances in an app ledger (boxes) or a LogicSig account per UA holding ASAs |
| PQZ (reasoning only) | doubtful: 400 M instructions per transaction in an interpreter, and rent on every ciphertext | **most plausible of the three**: 1 PGas per call, AOT-compiled wasm, 1.5 MiB transactions, no rent | no: 700-unit opcode budget per app call |
| Fit with the owner's priority | last of the three: balances need rent or restores | candidate: storage model like Aptos / Sui (a deposit, no TTL) | candidate for plain balances (deposit, no TTL); compute too small for PQZ |

## 2. Soroban (Stellar, Pi Network)

Current Stellar mainnet protocol is **29** (Horizon `current_protocol_version: 29`, mainnet RPC); protocol 23
"Whisk" (state archival changes) reached mainnet 2025-09-03, 25 "X-Ray" (BN254, Poseidon) 2026-01-22, 26
2026-05-06, 27 2026-07-08, 28 2026-09-16, 29 2026-10-01
([software versions](https://developers.stellar.org/docs/networks/software-versions)) [source]. The older
[protocol upgrades page](https://stellar.org/protocol-upgrades) stops at protocol 24 (stale) [source]. Pi Network is
the same code with its own network settings, which were not checked [inference].

### 2.1 Accounts and keys

- `G…` = a classic account (ed25519 public key), `C…` = a contract, `M…` = a muxed account
  ([SEP-23](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md)) [source].
- A classic account has native multisig: up to 20 signers with weights and thresholds 0–255
  ([multisig](https://developers.stellar.org/docs/learn/fundamentals/transactions/signatures-multisig),
  `MAX_SIGNERS = 20` in stellar-xdr) [source].
- Contracts authorise through `require_auth`; a contract implementing `__check_auth` is a **custom account**; a `G…`
  address authorises through the built-in account contract at the medium threshold
  ([authorization](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization))
  [source]. SCaaS uses both today ([soroban.md NET-SOR-01](../networks/soroban.md#NET-SOR-01)).
- A classic account needs a minimum balance of **2 base reserves = 1 XLM** (base reserve 0.5 XLM), plus 0.5 XLM per
  subentry (trustline, signer, offer)
  ([lumens](https://developers.stellar.org/docs/learn/fundamentals/lumens)) [source]. Classic entries (accounts,
  trustlines) have **no TTL**; only Soroban contract data and code are archived [source: state-archival page below].

### 2.2 Contract VM and limits

Mainnet network settings (read from the config-setting ledger entries by mainnet RPC; they match
[SLP-0004](https://github.com/stellar/stellar-protocol/blob/master/limits/slp-0004.md) and SLP-0005, which raised
the instruction limit from 100 M to 400 M and the footprint from 200 to 400 entries) [source]:

| Limit | Per transaction | Per ledger |
|---|---|---|
| CPU instructions (metered, interpreted wasm) | 400,000,000 | 580,000,000 |
| Memory | 40 MiB | — |
| Transaction size | 132,096 B | 266,240 B |
| Read / write entries | 200 / 200 (footprint 400) | 1,000 / 1,000 |
| Read / write bytes | 200,000 / 132,096 | 400,000 / 286,720 |
| Contract data entry | 65,536 B (key ≤ 250 B) | — |
| Wasm size / events | 131,072 B / 16,384 B | — |

Ledger close target 5 s (`ledgerTargetCloseTimeMilliseconds = 5000`) [source]. Calls are **synchronous**: a
contract calls another inside the same host invocation and a failure reverts the whole transaction; one transaction
carries one host function call [source: authorization page; soroban.md NET-SOR-06].

### 2.3 Tokens and holder lists

- SEP-41 is the token interface; the Stellar Asset Contract (SAC) implements it for classic assets
  ([SAC](https://developers.stellar.org/docs/tokens/stellar-asset-contract)) [source].
- A SAC balance of a `G…` account lives in its **trustline** (classic entry: 0.5 XLM reserve, no TTL); a balance of a
  `C…` address lives in a **persistent contract data entry** [source]. In rs-soroban-env the SAC bumps a balance's TTL
  by 30 days on read and write (`BALANCE_EXTEND_AMOUNT = 30 * DAY_IN_LEDGERS`), below the mainnet minimum persistent
  TTL of 120 days, so the bump does nothing there today [inference from the source and the settings].
- A custom SEP-41 token (the SCaaS `scaas-token`) keeps every balance as persistent contract data; no on-chain holder
  list exists, holders come from events (`getEvents` retention is limited, soroban.md §7) [inference].

### 2.4 Long-term storage and its cost

Rules ([state archival](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival),
[CAP-62](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0062.md),
[CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md)) [source]:

- Storage types: **temporary** (deleted for good when its TTL reaches 0), **persistent** and **instance** (archived at
  TTL 0).
- Mainnet TTLs: minimum persistent **2,073,600 ledgers (≈ 120 days)**, minimum temporary 17,280 (1 day), maximum
  **3,110,400 (≈ 180 days)** (mainnet RPC). An entry can never be prepaid for longer than ≈ 180 days; anyone can
  extend any entry's TTL (`ExtendFootprintTTLOp` or `extend_ttl` from a contract) [source].
- Archived persistent entries move from the live state to the **hot archive**; "evicted entries are not deleted from
  validators" and all state is still written to history archives (CAP-62) [source]. Since protocol 23 an
  `InvokeHostFunctionOp` **restores archived entries automatically** when they are listed in the footprint (CAP-66);
  `RestoreFootprintOp` is rarely needed [source]. The state-archival page still says a restore sets TTL to
  `current + 4095`, which contradicts the 120-day mainnet minimum (stale example) [source, disagreement].
- Rent (CAP-66, `soroban-env-host/src/fees.rs`): `rent = size × ledgers × rate_per_1KB / (1024 × denominator)`;
  persistent denominator 1,215, temporary 2,430; `rate_per_1KB` grows linearly with total Soroban state size from
  −17,000 (at 0) to 10,000 stroops (at the target 3 GB) and faster above it, with a floor of 1,000. Live state
  ≈ 1.75 GB, so today's rate is the **floor, 1,000 stroops**; the floor holds up to ≈ 2.0 GB of state. A write also
  pays 875 stroops per KB plus 2,500 per entry; a restore pays rent for at least the minimum TTL plus read and write
  fees [source for the rules and settings; the state-size position is our decode of the live window].
- A draft [SLP-0007](https://github.com/stellar/stellar-protocol/blob/master/limits/slp-0007.md) (2026-10-06)
  proposes halving fees; protocol not set [source].

Worked costs at today's floor rate, 5-second ledgers (1 year = 6,307,200 ledgers); 1 XLM = 10^7 stroops
[estimate]:

| Entry | Size (incl. key, XDR) | Rent 1 year | 5 years | 10 years | One restore (120-day minimum TTL) |
|---|---|---|---|---|---|
| balance (SEP-41 `Balance(Address)` → i128) | ≈ 200 B (assumed) | 0.10 XLM | 0.51 XLM | 1.01 XLM | 0.033 XLM + fees |
| UA record, 16-member `msig` | ≈ 700 B | 0.35 XLM | 1.77 XLM | 3.55 XLM | 0.12 XLM |
| one PQZ ciphertext | 16,512 + ≈ 100 B | 8.42 XLM | 42.1 XLM | 84.2 XLM | 2.77 XLM |

What happens to an idle holder [inference]: after ≤ 180 days from its last extension the balance is archived; after
1, 5 or 10 years it is still in the hot archive and the next `pay` by or to that holder restores it automatically,
paying ≈ 120 days of rent (the relayer pays and charges the subject, soroban.md NET-SOR-11). Nothing is lost under
the current rules, but (a) every restore makes the transaction larger and costlier, (b) the rent rate is set by
network-wide state size and could rise up to ≈ 10× (at 3 GB) or beyond, and (c) the hot archive is a protocol choice
that a later CAP could change (earlier archival designs described validators dropping archived state and restores
with proofs; nothing in force does this) [inference, uncertain]. Who pays: whoever extends or restores (any
account); a balance kept live continuously costs its keeper, a balance left to archive costs the next user.

### 2.5 Sponsored fees

Fee-bump transactions (CAP-15, protocol 13) let one account pay another transaction's fee; sponsored reserves
(CAP-33, protocol 15) let one account pay another's classic reserves (account, trustline)
([protocol upgrades](https://stellar.org/protocol-upgrades)) [source]. Soroban authorization entries are already a
contract-level meta-transaction (soroban.md NET-SOR-01). Contract-data rent is not covered by CAP-33: it is paid by
whoever submits the extension or the restoring transaction [inference].

### 2.6 Crypto for the UA kinds

From [soroban-sdk 29 `Crypto`](https://docs.rs/soroban-sdk/latest/soroban_sdk/crypto/struct.Crypto.html) and the
CAPs [source]: `ed25519_verify`; `secp256k1_recover` (ECDSA, the `ecrecover` trick also gives BIP-340-style Schnorr
checks); `secp256r1_verify` (CAP-51, protocol 21; WebAuthn P-256); BLS12-381 (CAP-59, protocol 22); BN254 (CAP-74,
protocol 25, extended by CAP-80 in 26); Poseidon / Poseidon2 (CAP-75, protocol 25); `sha256`, `keccak256`. ML-DSA
(CAP-87) is **accepted, protocol not set**. No native Schnorr [source: no CAP found].

### 2.7 UA, `msig` and balances of users without a native wallet

```text
registry contract (persistent entries, TTL upkeep)
├─ Ua(U)          record: kind ‖ keyData; ≤ ≈ 700 B for a 16-member msig
├─ UKey(keyHash)  key claim → U
subject: a SmartKeyAccount C… per UA (deterministic deploy from U), __check_auth verifies the UA kinds
token contract (scaas-token, SEP-41)
└─ Balance(C…)    i128, persistent; one per (token, holder)
```

A user with a passkey, a MetaMask key or an `msig` gets a `C…` custom account; tokens see an ordinary address, so
SEP-41 wallets and the DEX work [inference]. The account instance, the registry record and every balance are
persistent entries: **identity records are archivable** too (restorable, never lost under current rules). `msig`
size is bounded by the CPU budget (400 M instructions) and the 132,096-byte transaction, not by a 1,232-byte cap as on
legacy Solana: a 16-member `msig` with passkey assertions (≈ 300–400 B each) is ≈ 6 KB of signatures [estimate].

## 3. NEAR

Mainnet runs protocol **86** (neard 2.13.4); testnet 87 (mainnet RPC `status`; nearcore
[CHANGELOG](https://github.com/near/nearcore/blob/master/CHANGELOG.md)) [source]. Runtime parameters below are
from [`parameters.yaml`](https://github.com/near/nearcore/blob/master/core/parameters/res/runtime_configs/parameters.yaml)
and the version diffs (`85.yaml`, `87.yaml`), each confirmed with `EXPERIMENTAL_protocol_config` on mainnet [source].

### 3.1 Accounts and keys

- Named accounts (`alice.near`; top-level names through `registrar`), **implicit** accounts (64 hex = an ed25519
  public key) and **ETH-implicit** accounts (`0x` + 40 hex, NEP-518, controlled by a wallet contract, now a globally
  deployed contract) ([account id](https://docs.near.org/protocol/accounts-contracts/account-id),
  [NEP-518](https://github.com/near/NEPs/blob/master/neps/nep-0518.md)) [source].
- Access keys: **full access**, or **function-call** keys limited to one receiver contract, optional method names and
  an optional gas allowance, never attaching NEAR
  ([access keys](https://docs.near.org/protocol/accounts-contracts/access-keys)) [source]. Key schemes: ed25519,
  secp256k1 and, since protocol 85, **ML-DSA-65** (FIPS 204; stored as a SHA3-256 hash) (CHANGELOG 2.13.0,
  [NEP-645](https://github.com/near/NEPs)) [source].
- Since protocol 85 creating an account costs a fixed **0.007 NEAR** and covers up to 770 bytes of storage
  (NEP-642, `account_creation_charge`; before that NEP-448 zero-balance accounts) [source].
- Protocol 87 (testnet only) adds "universal accounts" (`0u…`, one post-quantum-safe derivation for implicit and
  contract-created accounts) [source: CHANGELOG 2.14.0]. Unrelated to the SCaaS UA despite the name [inference].

### 3.2 Contract VM and limits

| Parameter (mainnet, protocol 86) | Value |
|---|---|
| gas per function call / per transaction | **1 PGas** (raised from 300 Tgas in 2.11.0); several docs pages still say 300 Tgas [source, disagreement] |
| gas price | 10^8 yoctoNEAR per gas, so 1 Tgas = 0.0001 NEAR (mainnet `gas_price`); purchase price `max(gas_price, 10^9)` with the difference refunded (protocol 85) [source]; the RPC's `min_gas_price` = 10^9 conflicts with the block price 10^8 (unresolved) |
| wasm op cost | 822,756 gas per op ⇒ ≈ 1.2 × 10^9 wasm ops per PGas [source / estimate] |
| transaction / arguments / receipt | 1.5 MiB / 4 MiB / 4 MiB |
| contract size / wasm memory | 4 MiB / 2,048 pages = 128 MiB |
| storage key / value | 2,048 B / 4 MiB |

Contracts are compiled ahead of time by the node, so metered gas tracks native speed more closely than an
interpreter [inference]. Cross-contract calls are **asynchronous**: the callee and the callback run in later blocks,
"there's no automatic rollback", failures are handled in the callback
([cross-contract](https://docs.near.org/smart-contracts/anatomy/crosscontract)) [source]. Blocks every ≈ 0.6 s,
finality ≈ 1.2 s ([epoch](https://docs.near.org/protocol/network/epoch)) [source].

### 3.3 Tokens and holder lists

NEP-141 (fungible token) and NEP-145 (storage management) are final. A holder must be registered with
`storage_deposit` before receiving; the reference implementation keeps `LookupMap<AccountId, Balance>` and panics on
an unregistered receiver ([FT docs](https://docs.near.org/primitives/ft/ft),
[near-sdk core_impl.rs](https://github.com/near/near-sdk-rs/blob/master/near-contract-standards/src/fungible_token/core_impl.rs))
[source]. The bound is **0.00125 NEAR** for `wrap.near`, native USDC and USDT (mainnet `storage_balance_bounds`)
[source]. No holder list on chain; holders come from events / an indexer [inference].

### 3.4 Long-term storage and its cost

Storage staking: **10^19 yoctoNEAR per byte = 1 NEAR per 100 kB**, locked in the account that holds the data;
a transaction that would leave the balance below it fails; deleting data releases the stake
([storage staking](https://docs.near.org/protocol/storage/storage-staking)) [source]. No rent or TTL parameter exists
in the runtime config, and NEP-642 describes state as "permanent state that every node … must store indefinitely"
[source]. Each stored record adds 40 bytes of overhead (`storage_num_extra_bytes_record`) [source].

| Entry | Bytes (key + value + 40) | Deposit | After 1 / 5 / 10 idle years |
|---|---|---|---|
| NEP-141 balance | ≈ 125 B | 0.00125 NEAR (the token's NEP-145 bound) [source] | unchanged; deposit refunded on `storage_unregister` |
| UA record, 16-member `msig` | ≈ 655 B | ≈ 0.0066 NEAR [estimate] | unchanged |
| one PQZ ciphertext | ≈ 16,585 B | ≈ 0.166 NEAR [estimate] | unchanged |
| sub-account per UA (§3.7) | ≤ 770 B | 0.007 NEAR fixed charge [source] | unchanged |

Who pays: the contract account's balance must cover all its state; NEP-145 passes the cost to the user (or a
sponsor) [source]. A relayer that sponsors a user's `storage_deposit` locks its own NEAR, recoverable only when the
user unregisters [inference].

### 3.5 Meta-transactions

NEP-366 delegate actions (protocol-level since nearcore 1.32): the user signs a `SignedDelegateAction`, a relayer wraps
it and pays the gas ([meta-tx](https://docs.near.org/protocol/transactions/meta-tx)) [source]. It uses the user's
access-key nonce, so it is an account sequence, the ordering lock NET-ALL-02 avoids; SCaaS would keep its own
contract-level lanes and use NEP-366 only where a native NEAR account must act [inference]. NEP-413 is the wallet
`signMessage` (recipient + nonce) and is the natural format for the SCaaS signed op [source / inference].

### 3.6 Crypto for the UA kinds

Host functions on mainnet [source: CHANGELOG, parameters, mainnet protocol config]: `ed25519_verify` (NEP-364);
`ecrecover` (secp256k1; Schnorr through the `ecrecover` trick); **`p256_verify`** (NEP-635, enabled at protocol 85
although the NEP is still Draft and the CHANGELOG has no entry); BN254 `alt_bn128_g1_multiexp` / `g1_sum` /
`pairing_check` (1.28.0, 2022); **BLS12-381** (NEP-488, 2.1.0; a `bls12381_not_in_group_fix` is still nightly);
`keccak256`, `sha256`, `ripemd160`. `ml_dsa_verify` exists from protocol 87 (testnet only). No Schnorr host function.
NEAR also runs MPC "chain signatures" (secp256k1 / ed25519 signing for other chains)
([chain signatures](https://docs.near.org/chain-abstraction/chain-signatures)) [source].

### 3.7 UA, `msig` and balances of users without a native wallet

```text
registry contract (one account, storage staked once, no TTL)
├─ ua:U          record: kind ‖ keyData
├─ ukey:keyHash  claim → U
subject: sub-account u<hex(U)[..k]>.<registry> running a global wallet contract that verifies the UA kinds
         (0.007 NEAR creation charge, ≤ 770 B without further stake)
token (NEP-141): balances[AccountId] — the subject sub-account is an ordinary holder (0.00125 NEAR registration)
```

Alternative: the token keeps an internal ledger keyed by UA id, cheaper (no sub-account) but invisible to NEAR
wallets and DEXs [inference]. Because cross-contract calls are async, the subject contract must consume the op nonce
before calling `ft_transfer` and treat a failed transfer in the callback (no rollback across contracts) [inference].
`msig` is bounded by gas, not size: `p256_verify` costs 1.3 Tgas + 13 Mgas per byte, so 16 passkey members are
≈ 21 Tgas plus parsing, well under 1 PGas; a 1.5 MiB transaction holds any 16-member assertion set [estimate].

## 4. Algorand

Mainnet consensus **v42, AVM v13** (algod v5.0.0-stable, 2026-08-12), which added native Falcon-1024 accounts, 4 KB
notes, up to 7 extra program pages and a per-byte fee surcharge
([consensus.go](https://github.com/algorand/go-algorand/blob/master/config/consensus.go),
[release](https://github.com/algorand/go-algorand/releases/tag/v5.0.0-stable)) [source].

### 4.1 Accounts and keys

- Address = 32-byte ed25519 public key + 4-byte checksum, base32, 58 characters
  ([keys](https://dev.algorand.co/concepts/accounts/keys-signing/)) [source].
- Native multisig: version 1, threshold 1..N, N ≤ 255, ed25519 only, no nested multisig
  (`crypto/multisig.go`; [multisig](https://dev.algorand.co/concepts/accounts/multisig/)) [source].
- Rekeying: `auth-addr` points the account's authority to another single key, multisig, LogicSig or post-quantum
  address ([rekeying](https://dev.algorand.co/concepts/accounts/rekeying/)) [source].
- LogicSig: a TEAL program either *is* an account (contract account, address = hash of the program) or is signed by
  an account to delegate authority ([logic sigs](https://dev.algorand.co/concepts/smart-contracts/logic-sigs/))
  [source].
- Post-quantum accounts: address = `SHA512-256("PQA" ‖ scheme ‖ salt ‖ public key)`, **Falcon-1024 live on mainnet
  since v42 (August 2026)**; Falcon-512 defined but not enabled; existing accounts migrate by rekeying
  ([post-quantum](https://dev.algorand.co/concepts/accounts/post-quantum/),
  [roadmap](https://algorand.co/blog/algorand-post-quantum-cryptography-roadmap)) [source]. The roadmap plans PQ
  multisig by end 2026 while the docs say multisig stays ed25519-only [source, disagreement].
- Every account must hold **0.1 ALGO** [source].

### 4.2 Contract VM and limits

From the [AVM](https://dev.algorand.co/concepts/smart-contracts/avm/),
[costs and constraints](https://dev.algorand.co/concepts/smart-contracts/costs-constraints/),
[resource usage](https://dev.algorand.co/concepts/smart-contracts/resource-usage/) and
[inner transactions](https://dev.algorand.co/concepts/smart-contracts/inner-txn/) pages [source]:

| Limit | Value |
|---|---|
| opcode budget | **700 per app call**, pooled across the group; inner app calls top it up to ≈ 179.2 k (256 inner transactions) |
| LogicSig budget | 20,000 × transactions in the group (pooled since v39) |
| group size | 16 transactions, atomic |
| app arguments | ≤ 16, 2,048 B total (16,384 B for an extra fee; ≤ 4,096 B each) |
| program size | 2,048 B per page, up to 3 extra pages (7 for a fee) ⇒ ≤ 16,384 B |
| box | ≤ 32,768 B, name 1–64 B; I/O 2,048 B per box reference, 16 references per transaction (access list, v41) |
| stack value / scratch | 4,096 B / 256 slots |
| logs | 32 calls, 1,024 B |

The resource page says the foreign accounts array holds 4 entries, the code says 8 (`MaxAppTxnAccounts`)
[source, disagreement]. Calls between apps are **synchronous** inner transactions (depth 8) inside one atomic group
[source]. Blocks every ≈ 2.82 s, final once certified
([blocks](https://dev.algorand.co/concepts/transactions/blocks/)) [source].

### 4.3 Tokens and holder lists

- **ASA**: native asset; the receiver must **opt in**, which raises its minimum balance by 0.1 ALGO per holding;
  manager, reserve, freeze and clawback roles ([assets](https://dev.algorand.co/concepts/assets/overview/)) [source].
  Holders are in each account's record; an indexer lists them [inference].
- **ARC-200**: ERC-20-like interface for app tokens
  ([ARC-200](https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0200.md), status Living). It does **not**
  specify box storage or who pays the box deposit [source]; implementations keep balances in boxes funded by the app
  account [inference].

### 4.4 Long-term storage and its cost

Minimum balance requirement (MBR) ([storage overview](https://dev.algorand.co/concepts/smart-contracts/storage/overview/),
[boxes](https://dev.algorand.co/concepts/smart-contracts/storage/box/), `consensus.go`) [source]: account 0.1 ALGO;
ASA holding 0.1 ALGO; app creation 0.1 ALGO × (1 + extra pages) + 0.0285 per uint + 0.05 per byte slice; **box
2,500 + 400 × (name + size) µAlgo**, paid by the app account and released when the box is deleted. If an app is
deleted its boxes stay and their MBR stays locked [source]. No rent or TTL exists in the protocol parameters, and no
proposal to add one was found; the only status change of an idle account applies to *online* (consensus) accounts,
which are set offline when absent [source:
[staking rewards](https://dev.algorand.co/concepts/protocol/staking-rewards/); absence of rent is our reading].

| Entry | Bytes | Deposit [estimate] | After 1 / 5 / 10 idle years |
|---|---|---|---|
| ASA holding of a native account | — | 0.1 ALGO (+ 0.1 account) [source] | unchanged; released on opt-out / close |
| box balance (name = 32-byte holder id, value u64) | 40 | 0.0185 ALGO | unchanged; released on delete |
| UA record box, 16-member `msig` | 32 + ≈ 582 | 0.248 ALGO | unchanged |
| one PQZ ciphertext box | 32 + 16,512 | 6.62 ALGO | unchanged |

Who pays: the holder for ASA opt-ins (a sponsor may send the ALGO); the app account for boxes, so the token issuer or
a relayer funds it and recovers the deposit only by deleting boxes [inference].

### 4.5 Fee pooling

Minimum fee 1,000 µAlgo per transaction; a per-byte fee applies under congestion; in a group **one transaction can
pay the others' fees**; v42 adds a 0.1 µAlgo surcharge per byte over the standard limits, and Falcon-signed
transactions pay 2× the base fee extra ([fees](https://dev.algorand.co/concepts/transactions/fees/)) [source]. The SCaaS
model fits directly: the subject signs an op, a relayer submits the app call and pays all fees [inference].

### 4.6 Crypto for the UA kinds

[Opcode costs](https://dev.algorand.co/reference/algorand-teal/opcodes/) [source]: `ed25519verify` 1,900;
`ecdsa_verify` secp256k1 1,700 / **secp256r1 2,500** (passkeys, with `sha256`); `ec_pairing_check` BN254 8,000 +
7,400 per pair / BLS12-381 13,000 + 10,000 per pair and `ec_multi_scalar_mul` (AVM v10); **`falcon_verify` 1,700**
(Falcon-1024, AVM v12); `keccak256` / `sha3_256` 130; `mimc`, `poseidon2` (v13). No Schnorr opcode; a BIP-340 check
needs the `ecdsa_pk_recover` trick [inference; that opcode was not re-checked].

### 4.7 UA, `msig` and balances of users without a native wallet

```text
registry app (boxes, MBR from the app account, no TTL)
├─ box "ua"‖U          record
├─ box "uk"‖keyHash    claim → U
token, option 1 (app ledger, ARC-200 interface): box "b"‖U → u64 balance, 0.0185 ALGO each
token, option 2 (ASA): a LogicSig contract account per UA whose program (with U baked in) approves only a group
         where the registry app verified the UA signature; 0.1 ALGO + 0.1 per ASA, funded by a sponsor
```

`msig` is bounded by budget and argument size [estimate]: each P-256 member costs 2,500 of budget and ≈ 300–400 B of
assertion; one group carries 16 × 2,048 B of arguments (16 × 16,384 B with the fee) and ≈ 179 k budget with inner
calls, so a 16-member passkey `msig` (40,000 budget, ≈ 6 KB) fits in one group of ≈ 4 app calls plus budget top-ups.

## 5. Solana storage costs (long form of NET-SOL-34)

### 5.1 Rent today

- Formula: `minimum_balance = (128 + data_len) × lamports_per_byte` (128 B account header). The old form was
  `× 3,480 lamports per byte-year × 2 years` = 6,960
  ([solana-rent 2.2.1](https://docs.rs/solana-rent/2.2.1/src/solana_rent/lib.rs.html)) [source].
- **SIMD-0194** (deprecate the exemption threshold: rate 6,960, threshold 1.0) is active on mainnet since slot
  407,376,000 [source: [SIMD repo](https://github.com/solana-foundation/solana-improvement-documents), mainnet
  feature accounts].
- **SIMD-0437** (reduce `lamports_per_byte` from 6,960 to 696 in five steps: 6,333 → 5,080 → 2,575 → 1,322 → 696):
  steps 1 and 2 are active (slots 444,096,000 and 446,256,000; step 1 at epoch 1028, 2026-09-03); steps 3–5 "expected
  in Agave 4.4" ([reduced rent](https://solana.com/upgrades/reduced-rent), updated September 2026) [source]. **Live
  rate: 5,080 lamports per byte**: `getMinimumBalanceForRentExemption(0)` = 650,240 and `(165)` = 1,488,440 (mainnet
  RPC, read by us 2026-10-19) [source]. Existing accounts keep their deposit and may withdraw the excess (token
  program `WithdrawExcessLamports`) [source]. The SIMD front matter still says "Idea" [source, disagreement].
- **Rent collection is gone**: SIMD-0084 "rent will no longer be collected from accounts", active since slot
  326,592,000; new accounts with data must be rent-exempt (`require_rent_exempt_accounts`, active since slot
  133,488,000) [source]. So an account never expires and never decays.
- Stale official pages: [accounts](https://solana.com/docs/core/accounts) still shows `3,480 × 2`, the ZK Compression
  calculator uses 6,960, and the Anza rent page still describes per-epoch collection [source, disagreement].

### 5.2 Limits

Account ≤ 10 MiB (`MAX_PERMITTED_DATA_LENGTH`); a program grows an account by ≤ 10,240 B per instruction
(`MAX_PERMITTED_DATA_INCREASE`; also the cap for a `CreateAccount` through CPI, by our reading of the CPI resize
rule); ≤ 20 MiB of new account data per transaction; 1.4 M CU per transaction; heap 32 KiB, up to 256 KiB on request
([constants](https://solana.com/docs/core/constants-reference),
[CPI cost model](https://solana.com/docs/core/cpi/cpi-cost-model)) [source]. Transactions: legacy / v0 stay at
1,232 B; **v1 transactions of 4,096 B** are live (SIMD-0296 / SIMD-0385, epoch 1035, 2026-09-15;
[larger transactions](https://solana.com/upgrades/larger-transaction-sizes)) [source].

### 5.3 Worked costs for the SCaaS accounts

Sizes are borsh sizes of the built structs plus the 8-byte Anchor discriminator and the `owner_kind` byte of
NET-SOL-34 (ed25519 keys, no guardian, no origins unless stated); the registry and approval layouts are not built,
so their sizes are estimates [estimate]. SOL = lamports / 10^9.

| Account | Data bytes | Now (5,080) | Before SIMD-0437 (6,960) | After step 5 (696) | Payer / refund |
|---|---|---|---|---|---|
| `["acct", id]`, 1 key | 127 | 0.00130 | 0.00178 | 0.00018 | lane (recorded `rent_payer`); never closed |
| `["acct", id]`, 2 / 3 / 4 keys | 193 / 259 / 325 | 0.00163 / 0.00197 / 0.00230 | 0.00223 / 0.00269 / 0.00315 | ≤ 0.00032 | 〃 (`realloc` top-up per key) |
| `["acct", id]`, 4 keys + guardian + 1 origin | 384 | 0.00260 | 0.00356 | 0.00036 | 〃 |
| `["acct", id]`, maximum (8 keys, 8 × 128-B origins, guardian, recovery) | 1,883 | 0.01022 | 0.01400 | 0.00140 | 〃 |
| `["ua", U]`, one secp256k1 key | ≈ 47 | 0.00089 | 0.00122 | 0.00012 | registrant; never closed |
| `["ua", U]`, 2-of-3 `msig` | ≈ 126 | 0.00129 | 0.00177 | 0.00018 | 〃 |
| `["ua", U]`, 16-member `msig` (keyData ≤ 580 B) | ≈ 594 | 0.00367 | 0.00503 | 0.00050 | 〃 |
| `["ukey", keyHash]` | 40 | 0.00085 | 0.00117 | 0.00012 | 〃 |
| SPL token account / ATA | 165 | 0.00149 | 0.00204 | 0.00020 | first sender; refunded on `CloseAccount` |
| Token-2022 ATA (ImmutableOwner) | 170 | 0.00151 | 0.00207 | 0.00021 | 〃 |
| lane PDA `["lane", acct, lane32]` | 56 | 0.00093 | 0.00128 | 0.00013 | lane; refunded at `prune` |
| approval PDA `["appr", U, digest]` (open design) | ≈ 116 | 0.00124 | 0.00170 | 0.00017 | submitter; refundable at execution |
| one PQZ ciphertext (8 + 16,512) | 16,520 | **0.0846** | 0.1159 | 0.0116 | writer; refundable if closed |
| one account at 10 MiB | 10,485,760 | 53.27 | 72.98 | 7.30 | — |

Token-2022 sizes: 165 + 1 type byte + per extension 4 B of TLV header + value (ImmutableOwner 0, MemoTransfer and
TransferHookAccount 1 each) (token-2022 `extension/mod.rs`) [source; the totals are our arithmetic]. The 2,039,280
lamports often quoted for a token account is the pre-SIMD-0437 value [source]. Closing transfers **all** lamports,
deposit included, to a chosen destination; nothing is burned; a token account must be empty first
([close account](https://solana.com/docs/tokens/basics/close-account)) [source]. A 16,520-byte account needs a create
of ≤ 10 KiB through CPI and one more `realloc`, and its bytes arrive over ≈ 5 v1 transactions or ≈ 15 legacy ones
[inference].

### 5.4 Compressed state as a contrast

ZK Compression (Light Protocol) keeps only Merkle roots on chain (state trees of depth 26), the leaves in the ledger,
served by Photon indexers; a compressed token account costs ≈ 5,000 lamports instead of ≈ 2 M (old rate); each use
needs a 128-byte Groth16 validity proof, ≈ 100 k CU to verify plus ≈ 100 k CU of Poseidon and ≈ 6 k per account
(≈ 292 k CU for a token transfer); per-transaction fees 5,000 lamports per tree, ≈ 300 per new leaf, 10,000 per new
address ([considerations](https://www.zkcompression.com/learn/considerations),
[trees](https://www.zkcompression.com/learn/merkle-trees-validity-proofs)) [source]. The programs are deployed on
mainnet (RPC) [source]. Data availability then rests on history and indexers, the risk CTR-PQZ-07 ruled out for
ciphertexts [inference].

## 6. Comparison

Native-unit costs; prices in fiat are left out on purpose. EVM: 20,000 gas for a new 32-byte slot plus 2,100 cold
access ([EIP-2929](https://eips.ethereum.org/EIPS/eip-2929)); ciphertext write 2.6–8.8 M gas (pq-zero-knowledge.md
CTR-PQZ-07). Sui: 100 storage units per byte at a governance-set price of 76 MIST per unit (≈ 0.0076 SUI per KB),
99 % rebated on deletion ([gas in Sui](https://docs.sui.io/concepts/tokenomics/gas-in-sui),
[Sui storage](https://docs.sui.io/concepts/sui-architecture/sui-storage)). Aptos: 400,000 octas (0.004 APT) per new
state slot plus 400 octas per byte (gas schedule v14+,
[transaction.rs](https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs)),
refunded on deletion ([gas and fees](https://aptos.dev/network/blockchain/gas-txn-fee)). Cosmos: 2,000 + 30 gas per
byte written (`KVGasConfig`, [store/types/gas.go](https://github.com/cosmos/cosmos-sdk/blob/main/store/types/gas.go)),
fee = gas × the chain's minimum gas price, no refund. [source for the parameters; the per-entry figures are
estimates]

| Family | Persistence of an idle balance | Cost of one balance entry | Cost of one 16,512-B ciphertext | Recurring? | UA without a native wallet | `msig` bound per transaction |
|---|---|---|---|---|---|---|
| EVM (SCaaS testnet, public) | forever | ≈ 22,100 gas (one slot) | 2.6–8.8 M gas | no | `SmartKeyAccount` / registry (built) | gas (EIP-7825 cap 2^24 per transaction) |
| Cosmos (CosmWasm) | forever | ≈ 2,000 + 30 × ≈ 60 B ≈ 4 k gas | ≈ 0.5 M gas | no | contract-internal ledger keyed by UA id | block gas |
| Sui | forever | ≈ 0.001–0.002 SUI per object, 99 % rebate | ≈ 0.125 SUI, 99 % rebate | no | `Account<T>` per subject | 128 KB transaction (not re-checked) |
| Aptos | forever | ≈ 0.004–0.005 APT, refundable | ≈ 0.070 APT, refundable | no | `Account` object per subject | 64 KiB transaction (gas schedule) |
| Solana | forever (rent collection disabled) | 0.00149 SOL (ATA, live rate), refundable | 0.0846 SOL, refundable | no | Account PDA + ATAs (NET-SOL-34) | 1,232 B legacy / 4,096 B v1 |
| **Soroban** | **archived after ≤ 180 days**, restorable | ≈ 0.10 XLM / year live, or ≈ 0.033 XLM per restore | ≈ 8.4 XLM / year | **yes (rent)** | `C…` custom account per UA | 132,096 B, 400 M instructions |
| **NEAR** | forever | 0.00125 NEAR deposit | ≈ 0.166 NEAR deposit | no | sub-account per UA or internal ledger | 1 PGas, 1.5 MiB |
| **Algorand** | forever | 0.0185 ALGO (box) or 0.1 ALGO (ASA) | ≈ 6.62 ALGO | no | box record; LogicSig account for ASA | 16 × 2,048 B args, ≈ 179 k budget |

## 7. PQZ and Zether feasibility (reasoning only)

What PQZ needs per transfer (pq-zero-knowledge.md §4.4): ≈ 77 KB of calldata in PQZL (statement parts + 42,762-B
proof; ≈ 231 KB in PQZH), three 16 KB public keys and the 16,512-B balance read from state, ≈ 16.7 KB written, and a
verifier that takes ≈ 8 ms on one native core (§6 of pq-fhe.md quotes the measured figure) [source]. On EVM it runs
as a precompile on the SCaaS testnet only; on a public chain of these families it would have to be contract code [inference].

| Family | Compute | Size | State | Verdict [inference] |
|---|---|---|---|---|
| Soroban | 400 M metered instructions in an interpreter; an 8 ms native verifier is plausibly 10^8–10^9 instructions [estimate] | 132,096 B fits PQZL (not PQZH) | reads ≤ 200 KB, writes ≤ 132 KB: fits; entry ≤ 64 KB fits a ciphertext | doubtful compute; every ciphertext pays rent (≈ 8.4 XLM / year) or restores |
| NEAR | ≈ 1.2 × 10^9 AOT wasm ops per PGas: plausibly fits [estimate] | 1.5 MiB: PQZL and PQZH fit | 0.166 NEAR locked per ciphertext, no TTL | **plausible**; verifier and token in one contract to avoid async rollback gaps; needs a wasm build of the verifier and a gas measurement |
| Algorand | ≤ ≈ 179 k opcode budget per group; one NTT over 16 KB polynomials already exceeds it | args ≤ 256 KB per group with fees | 6.62 ALGO per ciphertext box | **no** |
| Solana | 1.4 M CU per transaction; the verifier would be split over dozens of transactions with intermediate state | 4,096 B v1: ≈ 20 transactions to upload one PQZL transfer's ≈ 77 KB | 0.0846 SOL per ciphertext | no (already "no" in networks/README availability) |

Classical Zether / Groth16 [inference]: all three have BN254 and BLS12-381, so a one-pairing-check Groth16 verifier
fits (Algorand ≈ 8,000 + 4 × 7,400 budget for four pairs, with budget top-ups; NEAR ≈ 30 Tgas; Soroban as soroban.md
§9 says). Bulletproofs-style range proofs do not fit Algorand and may not fit Soroban (to be measured).

## 8. Recommendation per family

Against the owner's order (EVM, Cosmos, Sui, Aptos, Solana first because balances persist) [inference]:

- **Solana** stays in the first group: rent collection is disabled, deposits are one-time and refundable, and the live
  rate fell 27 % (6,960 → 5,080 lamports per byte), with a further 7× cut planned. NET-SOL-34's figures need the new
  rate (done in networks/solana.md alongside this note).
- **NEAR** is the strongest new candidate: a refundable deposit per byte like Aptos / Sui, no TTL, a large compute and
  transaction budget, ed25519 / secp256k1 / P-256 / BN254 / BLS12-381 on mainnet and ML-DSA-65 keys. Costs: async
  cross-contract calls (design the subject contract around callbacks) and NEP-145 registration per holder. PQZ is
  plausible enough to be worth a later measurement.
- **Algorand** can keep balances forever at a fixed refundable deposit (0.0185 ALGO per box balance) and has P-256,
  BN254, BLS12-381 and Falcon on mainnet, but its 700-unit opcode budget and 2 KB arguments make it a
  plain-balances family (no PQZ). Native Falcon-1024 accounts are relevant to the PQ UA kinds (Falcon, EIP-8052
  compatibility to be checked).
- **Soroban** is already built but is the only family where an idle balance is archived and storage costs rent; it
  can keep balances long-term only through restores (≈ 0.033 XLM each for a balance entry) or a keeper paying
  ≈ 0.10 XLM per balance per year, both exposed to rent-rate rises. Keep it after the others for long-lived balances;
  never for PQZ ciphertexts.

## 9. Uncertain points

- Soroban: the rent rate depends on total state size (today at the floor); no official worked rent example exists; the
  state-archival page's `+ 4095` restore TTL contradicts the mainnet minimum; Pi Network settings were not checked.
- NEAR: docs disagree on the gas limit (300 Tgas vs 1 PGas live); `min_gas_price` in the protocol config (10^9)
  disagrees with the block gas price (10^8); several NEPs live on mainnet are still marked Draft / New (518, 635, 642,
  645).
- Algorand: foreign accounts array 4 (docs) vs 8 (code); PQ multisig planned (blog) vs excluded (docs); Falcon
  signature size quoted as ≈ 1.2 KB, ≈ 1,280 B or ≤ 1,423 B; activation dates of consensus v40 / v41 not found.
- Solana: SIMD front matter lags activation (0194 "Accepted", 0437 "Idea", 0296 / 0385 / 0388 "Review" while active);
  feature keys for SIMD-0437 steps 3–5 differ between the Foundation page and Agave master; the 10 KiB cap on
  `CreateAccount` through CPI is our reading of the resize rule.
- All SCaaS record sizes on Soroban, NEAR and Algorand, and the Solana registry / approval records, are estimates of
  designs that do not exist yet.
