# NEAR and Algorand family bring-up — design

**Status:** spec. Nothing is built. Written 2026-10-28 from branch `metatx-split` (worktree
`.claude/worktrees/metatx-split`, head `3c70e5ba`, Task 13 done). Rules are cited by ID, not restated. Every choice marked
**controller call** is the controller's; the owner may override it. Background facts: research note
[near-algorand.md](../../research/near-algorand.md) (2026-10-19).

**Work item.** TODO "NEAR and Algorand family bring-up" (owner 2026-10-27) and the NEAR / Algorand half of "Family
priority for UA and long-lived balances". Order: this spec → plan → branch from `metatx-split` once its Task 16 is
done, built in parallel with its Tasks 17–20; the branch rebases onto `metatx-split` after its Task 18 and adds its
NEAR / Algorand steps to metatx-split Task 20's gate runner.

## 0. Decisions

| Date | Decision | Who |
|---|---|---|
| 2026-10-28 | **Same feature set as the other families:** token with `mtx_pay`, the relayed pay, `mtx_pay_meta` (CTR-MTX-26); mandate; DEX; smart-key / passkey UA accounts; relay-fee router (CTR-MTX-27) from the start; `scaas-node` adapters (jobs and the metatx-split §9 checks); `clientkeys` and UA clients signing for both; devnets, tests, shared vectors; `docs/networks/near.md`, `docs/networks/algorand.md`. | owner |
| 2026-10-28 | **The relayer pays storage** (NEAR storage staking, Algorand MBR). Users, UA users included, hold no NEAR / ALGO. | owner |
| 2026-10-28 | **Standard-compatible where possible:** NEAR NEP-141 + NEP-145 + NEP-148; Algorand ARC-200. | owner |
| 2026-10-28 | The relayer is reimbursed through the fee; the node's fee floor covers first-use storage (as the Solana lane-PDA rent in metatx-split's node work). | controller call, accepted by the owner ("ok rồi") |
| 2026-10-28 | Balances and records are permanent (no TTL, no deletion, no refund); working state (lanes past validity, escrow pending entries) may be pruned with its deposit returned to whoever paid it (as Solana's lane PDAs, NET-SOL-08). Here: lanes are kept (both families **non-pruning**, so CTR-MTX-04 / NET-ALL-01 hold by construction); only NEAR escrow entries are pruned (§3.8). | controller call, accepted by the owner; wording 2026-10-28 |
| 2026-10-28 | NEAR: full NEP-141 / NEP-145 / NEP-148 interface; one deviation: an unregistered receiver is auto-registered, its storage paid from the caller's attached deposit (§3.2). | controller call, accepted by the owner |
| 2026-10-28 | Algorand: the token is an app-held ledger in boxes, **not an ASA** (an ASA needs receiver opt-in, which a UA cannot do); ARC-200 methods through ARC-4 ABI; box MBR paid by the caller (relayer) through a payment transaction in the same atomic group. | controller call, accepted by the owner |
| 2026-10-28 | Languages: NEAR Rust with `near-sdk`; Algorand Algorand Python (Puya). | controller call, accepted by the owner |
| 2026-10-28 | Signatures: NEAR `ed25519_verify` and `ecrecover` host functions, P-256 (passkey) verified in wasm; Algorand `ed25519verify_bare` and `ecdsa_verify Secp256k1 / Secp256r1`. | controller call, accepted by the owner (opcode refined in §4.6) |
| 2026-10-28 | Out of scope: Zether and PQZ (EVM precompile families only), as on Soroban / Aptos. | controller call, accepted by the owner |
| 2026-10-28 | Devnets: `near-sandbox` and an Algorand localnet, run through `scripts/capped` and docker with `--memory`; node e2e on them; public testnets later. | controller call, accepted by the owner |
| 2026-10-28 | No admin on the router; no contract upgradeable: NEAR accounts keep no access key; Algorand approval programs reject update and delete (§3.9, §4.9). | controller call, accepted by the owner |
| 2026-10-28 | **NEAR atomicity:** the fee-less signed entries the router must serve live in the token contract and are fee-paid by static in-contract wrappers `relay_fee_<entry>` (call, then pay, one receipt, atomic). Cross-contract targets go through an **escrow router with a callback** (the TON pattern of metatx-split Task 16). Refund wins whenever success is not provable. **Algorand:** an atomic group, no escrow. | owner "choose the best option yourself" → controller call |
| 2026-10-28 | Algorand target authority: the target call is sent by a keyless **executor** LogicSig account, never the lane (§4.8). | controller call (owner "choose yourself") |
| 2026-10-28 | NEAR DEX settlement is relayer-bound (CTR-DEX-09, README §11 item 6, no exception): order-level `relayer`; the lane calls the DEX, which calls each `token.mtx_trade` (Cosmos pattern) (§3.6). | controller call (owner "choose yourself") |
| 2026-10-28 | NEAR router forwards a relayer-attached `target_deposit`; the executor holds nothing after settlement (§3.8). | controller call (owner "choose yourself") |
| 2026-10-28 | Native UA kinds `0x0017 near-account`, `0x0018 algorand-address` in `kinds.json` and every reproducer; `msig` (kind 288) on both chains (§3.3, §4.3, §8). | controller call (owner "choose yourself") |
| 2026-10-28 | NEAR P-256: the plan's **first task is a spike and a hard gate** (§3.5); NEP-635 `p256_verify` not used. | controller call (owner "choose yourself") |
| 2026-10-28 | Keep this spec short: decisions and rule tables, IDs cited, no code. | owner |

## 1. Intent, goals, non-goals, anti-goals

**Why.** NEAR and Algorand keep balances for good at a one-time deposit (research note §1, §8). The owner wants
them as full SCaaS families with the metatx-split semantics from day one.

**Goals.** (1) Contracts per §3 / §4 with every rule of §2. (2) Adapters `scaas-node/src/adapters/{near,algorand}.rs`.
(3) Clients (§6). (4) Devnets and CI (§7). (5) Vectors (§8). (6) Docs (§9).

**Non-goals.** Zether, PQZ, PQ signers (metatx-split §1: off EVM a payer signs its family's classical op once); the
asset suite, token wrappers, tender (NET-ALL-17/18/19 keep these families PLANNED); the mesh (job API only in this
item; controller call); NET-ALL-26 `MetaCall` / `MetaTransfer` (both families sign the built `MetaOp` v1, §2 row 1,
and migrate with the other families); public testnets and mainnet; receiver-pays (EVM only, README §12).

**Anti-goals** (the plan shows each does not happen): a payer charged for a call that did not happen (CTR-MTX-16); a
router-bound payment settled outside the router; a target that
sees the router as an authority; a balance or record deleted or refunded; a user needing NEAR / ALGO; an upgradeable
deployment; a NEAR native-key or ASA dependency for UA users.

## 2. Rules every family follows — NEAR and Algorand form

| # | Rule (source) | NEAR | Algorand |
|---|---|---|---|
| 1 | Signed op = `MetaOp` v1 (README §3, NET-ALL-26 transitional), names `mtx_*` (NET-ALL-28) | Borsh: `"scaas.metaop.v1"` ‖ network (32) ‖ contract (`AccountId`) ‖ op (u8) ‖ from, to, relayer (`Holder`) ‖ amount (u128) ‖ pay_ref (32) ‖ lane (32) ‖ nonce (u64) ‖ valid_until (u64 s) ‖ extra (32); `Holder` = `Near(AccountId)` \| `Ua([u8;32])`, `relayer` an `Option<AccountId>`; digest `sha256` (controller call) | ARC-4 static tuple, big-endian: same fields, `contract` = token app address (32), each holder = kind (u8: 0 address, 1 UA id) ‖ 32, `relayer` 32 (zero = any); digest `sha256` (controller call) |
| 2 | Network id (NET-ALL-22) | the genesis hash (RPC `status`), passed at `new`, immutable; the node checks it at start | `global GenesisHash` at run time |
| 3 | `payId`, `payLane` (CTR-MTX-26, metatx-split §6.2) | `env::keccak256`, byte-for-byte the EVM derivation | `keccak256` opcode, same |
| 4 | Pay-meta entry requires `pay_ref == metaPayId(salt, meta)`, `lane == payLane(pay_ref)`, `nonce == 0`, signed op = plain pay (§6.2) | `mtx_pay_meta(op, auth, salt, meta)` | ABI `mtx_pay_meta(op, auth, salt: byte[32], meta: byte[])` |
| 5 | `PaymentMeta` before `PaymentSettled`; `meta` never parsed | NEP-297 log, standard `"scaas"` | ARC-28 event |
| 6 | Once-set per payer `(from, pay_ref)`: the payer's lane | `LookupMap<(Holder, lane), u64>` | one box per `(from-kind, from, lane)` → u64 nonce (naming §4.1) |
| 7 | Relayer authorisation explicit (README principle 1, CTR-MTX-27 shape) | `relayer == None` or `== env::predecessor_account_id()` | `relayer == 0` or `== Txn.Sender` (an inner call's sender is the calling app's address) |
| 8 | `ref = keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)`, recomputed on chain from the call actually run; **salt = the payment op's payer-signed `extra`, always** (controller call: one rule, as Solana / Sui, since both families admit targets whose authorisation lies outside the call bytes) | §3.8 | §4.8 |
| 9 | No sender / lane in `ref`; any relayer may submit; open mode (`to == marker`) pays the submitting relayer; a bound payee is paid directly (CTR-MTX-27 step 5) | wrapper: the predecessor; router: the predecessor of `relay`, recorded in the escrow | the `Txn.Sender` of the router call |
| 10 | Marker = an id no transaction can sign for; plain pay refuses it by rule 7 (R17) | wrapper marker = the token's own account id; router marker = the router account; both keyless (§3.9) | the router app's address (only its own inner transactions have it as sender) |
| 11 | Router grants no authority | the router never calls a target itself: an executor account forwards (the target sees the executor); targets authenticate by their own signed op, never by predecessor | the router never calls the target: the target is a top-level transaction of the group sent by the keyless executor (§4.8), never the lane; the router issues inner transactions only to the token's pay (and the MBR forward), never `RekeyTo` / `CloseRemainderTo` |
| 12 | Never pay the router / executor / marker (CTR-MTX-27 step 2) | token refuses `to == self`; router refuses `op.to == executor` | token refuses `to == own app address`; router refuses `op.to == executor`; open mode never credits the router (the token pays the open payee directly, §4.8) |
| 13 | Target exists at relay time (CTR-MTX-27 ninth item) | wrappers: static; router: the target account has code (`view_code` in the adapter; on chain the executor's call fails without code, and a failure refunds) | target app id ≠ 0, exists (`app_params_get`), `OnCompletion == NoOp` (a `ClearState` call cannot fail, so it is refused) |
| 14 | Call first, then payment, atomic (CTR-MTX-16) | wrappers atomic in one receipt; router: escrow + callback, refund unless success is reported (§3.8) | one atomic group: the target call precedes the router call |
| 15 | Balances and records permanent, storage by the relayer (§0) | attached deposit ≥ `Δstorage_usage × storage_byte_cost`, excess refunded to the predecessor in the same receipt | payment txn to the app address immediately before the call, amount **exactly** the MBR of the boxes the call creates (0 ⇒ none) |
| 16 | Vectors `paymeta.json` reproduced (R16) | cargo test reads the file | Python test reads the file |
| 17 | Adapter: §9 checks before simulate, startup errors on bad config, no panic on untrusted input | §5 | §5 |

## 3. NEAR

### 3.1 Contracts and what lives where

| Contract (account, keyless) | Holds | Why there |
|---|---|---|
| `token` (one per token) | NEP-141 ledger of native holders; UA ledger (`Ua` id → balance); lanes; subject accounts (keys, origins, guardian, policy); mandates over this token; order lanes, `filled`, cancel / `min_nonce` of trade legs sold in this token; `relay_fee_<entry>` wrappers | every fee-less signed entry the router serves must run in the same receipt as the payment (§0 NEAR atomicity); reading keys from another contract is asynchronous |
| `dex` | escrowed legs, matching, refunds | two tokens are two contracts: a NEAR DEX cannot move both legs in one receipt, so it is an escrow DEX (NET-TON-09 class: fill-or-kill, refund after expiry), relayer-bound at settlement (§3.6) |
| `relayfee` + `relayexec` | escrow entries in flight only | cross-contract targets (the DEX, third-party contracts) |

Cost (controller call): a subject's keys live per token contract, as Sui's `Account<T>` as built; a key operation is
one signed op per token the subject uses (clients send them together; the relayer submits one transaction per
token). A central key contract is not possible without an asynchronous read.

### 3.2 Token and storage (NEP-141 / NEP-145 / NEP-148)

| Method | Rule |
|---|---|
| `ft_transfer`, `ft_transfer_call` | registered receiver: exactly 1 yoctoNEAR (NEP-141); **unregistered receiver** (deviation): attached ≥ `storage_balance_bounds().min`, the receiver is registered, the excess refunded to the predecessor; a deposit below that panics. `ft_on_transfer` / `ft_resolve_transfer` as NEP-141. Receiver never a UA id (an id in the 64-hex implicit form would be a keyless NEAR account, NET-ALL-21): UA receivers use `transfer_to_ua` (EVM `transferToUA`, 1 yoctoNEAR) |
| `storage_deposit` | NEP-145, anyone for anyone; `min == max` (fixed per-holder cost) |
| `storage_withdraw` | `available` is always 0; `amount` > 0 panics |
| `storage_unregister` | unregistered → `false`; registered → panics, `force` included (deviation: records are permanent, and the stake was usually the relayer's) |
| `ft_metadata` (NEP-148), `ft_total_supply`, `ft_balance_of` | standard; `ua_balance_of(id)` for the UA ledger |
| `mtx_*` entries | not NEP methods: no yoctoNEAR rule (authority is the signature); attached deposit per §2 row 15 covers every record the call creates (receiver registration, lane, account record, mandate) |
| Events | NEP-141 events (`ft_transfer`, `ft_mint`, `ft_burn`, standard `nep141`) for native-holder moves; SCaaS events in standard `"scaas"` (`payment_settled`, `payment_meta`, `meta_transaction_executed`, `relay_fee_paid`, …) |
| Mint | the token's admin, as the other families' tier 1 |

### 3.3 Accounts / UA (Aptos `Account` model, NET-ALL-05 row "Aptos", NET-ALL-21)

- Subject = `Holder`. A `Ua` id is opened lazily on its first signed op (id checked against the key per
  `smartcontracts/vectors/ua/kinds.json`, CTR-UA-05), the relayer paying storage. A `Near` holder adds keys by a direct
  call (it holds NEAR) or by a signed op of a current key.
- **No signature from a NEAR account's own access keys** (controller call): the contract cannot read access keys, and
  an implicit account can rotate its key natively, so an id-derived key could be stale. Native holders use
  `ft_transfer` directly or register SCaaS keys.
- Keys ≤ 8, origins, guardian, `RECOVERY_DELAY` = 2 days, `POLICY_PASSKEY_FOR_VALUE` (NET-ALL-23 item 3).
- Native kind `0x0017 near-account` (accounts.md §1.6 table): id = the raw 32 bytes of an implicit account (64
  lower-case hex), else `sha256(account_id bytes)` (named and ETH-implicit accounts). The two forms are told apart by
  the account-id string, not by the 32 bytes, so a native NEAR member always travels with its account id and the
  contract recomputes the id. Accepted signature: the member is the predecessor of the call (the contract cannot
  read access keys).
- `msig` (kind 288, accounts.md): verified in the token from its key data (id = `UA(288, keyData)`); a native NEAR
  member counts only as the predecessor; the member cap is what fits the §3.5 gas bound, stated in near.md.

### 3.4 Entries

`mtx_pay`, `mtx_pay_meta`, `mtx_transfer`, `mtx_execute_transfer`, `mtx_add_key`, `mtx_remove_key`, `mtx_add_origin`,
`mtx_remove_origin`, `mtx_set_guardian`, `mtx_cancel_recovery`, `mtx_mandate_open`, `mtx_mandate_pay`, `mtx_revoke`,
`mtx_trade` (sells a leg into the DEX escrow), `mtx_cancel`, `mtx_invalidate_nonces`; each with a `*_check` view
returning `(ok | error, storage_needed)` — NEAR has no write simulation (controller call, as Aptos `pay_check`).
Batches: several function-call actions in one transaction to one token (atomic per transaction, README NET-ALL-28
table).

### 3.5 Signatures

| Kind | Check |
|---|---|
| ed25519 | NEP-413: `message` = the op text (NET-ALL-23: as Solana / Sui, first build `"<label>:" ‖ hex(digest)`, moving to the readable form with them), `recipient` = token account, `nonce` = op digest; `env::ed25519_verify` over `sha256(u32 2^31+413 ‖ Borsh(payload))` |
| secp256k1 | `env::ecrecover` over the op digest (kind 0x0108 raw-digest form) |
| P-256 passkey | NET-ALL-04 in wasm (RustCrypto `p256`); challenge = b64url(op digest). NEP-635 `p256_verify` is not used (Draft, chain-specific) |

**P-256 gate (plan Task 1, a spike).** Measure in near-sandbox the gas of a two-passkey `relay_fee_<entry>` (the
entry's passkey auth plus the payment's). Pin: it fits one transaction's protocol gas limit, 300 Tgas (not 1 PGas
from nearcore 2.11: no chain's own limit is assumed). If it does not fit, the owner rules before any passkey wrapper
is built.

### 3.6 Mandate and DEX

Mandate: in the token; funds held in the token ledger under the mandate's id; limits per payment and per period,
payee, expiry, revocation, each `pay_ref` once (README §3 item 2). No pay-meta entry (metatx-split §6.2).
DEX: an escrow (NET-TON-09 class), relayer-bound (CTR-DEX-09, README §11 item 6). The relayer lane calls
`dex.settle(order_a, auth_a, order_b, auth_b)`; the DEX checks each order's `relayer` (None or `==` predecessor), then
calls `token_a.mtx_trade` and `token_b.mtx_trade` (Cosmos pattern), whose leg op is bound `relayer = to = dex`
(predecessor = dex; NET-ALL-29). Each leg moves into the DEX escrow; the join callback pays both out (native holders
`ft_transfer`, UA ids `transfer_to_ua`) when both legs arrived, else refunds the one that did; a permissionless
refund after expiry covers a lost callback (refund wins, as §3.8). Fill-or-kill; README §11 gets a NEAR row (no
partial fill).

### 3.7 Lanes and head-of-line

Lanes as §2 row 6, permanent. Relayer lanes are implicit accounts (ed25519, `m/44'/397'/i'`), each with its own
access-key nonce; receipts are asynchronous, so a stuck lane blocks only itself (NET-ALL-03 statement in near.md).
Every lane is registered (`storage_deposit`) on every token at activation.

### 3.8 Relay fee

**Wrappers (atomic).** `relay_fee_<entry>` for every fee-less signed entry of §3.4 (key ops, `mtx_mandate_open`,
`mtx_revoke`, `mtx_cancel`, `mtx_invalidate_nonces`): entry arguments (its auth included), then the payment op and its
auth; runs the entry, then the pay body with `pay_ref = ref`, `lane = payLane(ref)`, `nonce = 0`, `relayer = token
account id` fixed on chain. `ref` target = the token account id (u8 len ‖ bytes), `call = u8 len ‖ entry name ‖
Borsh(entry arguments)`. A refused entry (e.g. a cancel of a filled order) panics, so nothing is paid. The wrapped
entries make no promise (fully synchronous); `ft_transfer_call` and `mtx_trade` are not wrapped.

**Escrow router (cross-contract targets), one `relay` transaction:**

| Step | Receipt | Rule |
|---|---|---|
| 1 | router `relay(target, method, args, target_gas, target_deposit, token, op, auth)` | `ref` (`call = u8 len ‖ target ‖ u8 len ‖ method ‖ args`), shape (`pay_ref == ref`, `lane == payLane(ref)`, `nonce == 0`, `relayer == router`, `op.to != executor`), `target ∉ {router, executor}`, attached deposit ≥ escrow-entry storage + 2 yoctoNEAR + `target_deposit`, prepaid gas ≥ the pinned sum (below); store `pending[ref] = {token, payer, payee or open, relayer = predecessor, target_deposit, deadline = now + RELAY_TIMEOUT_S}` |
| 2 | token `relay_hold(op, auth)` (predecessor = router) | the plain pay checks; consumes the lane (pay-once); moves `amount` from the payer to `held[ref]` inside the token |
| 3 | router `on_hold` (`#[private]`) | hold failed → delete `pending`; else executor `exec(target, method, args, target_gas)` |
| 4 | executor → target | attaches exactly `target_deposit` (the target's own storage, relayer-paid); the target sees the executor |
| 5 | router `on_call` (`#[private]`, static gas) | `PromiseResult::Successful` → token `relay_release(ref, payee)`; anything else → token `relay_refund(ref)` and executor `return(relayer, target_deposit)` (the failed call's deposit refund lands at the executor) |
| 6 | token | release: `held` → payee (open: the recorded relayer), `payment_settled` (`pay_ref = ref`); refund: `held` → payer; only the router that holds may call either |
| 7 | router `on_settle` | delete `pending`, return its storage deposit to the relayer that staked it, emit `relay_fee_paid` (release only) |

- **Timeout.** `relay_timeout(ref)`, anyone, after `deadline`, while `pending` exists: **refund** (controller call):
  after a lost callback the router cannot prove the target's result, so refund wins; the relayer loses its gas, never
  the payer its fee. `RELAY_TIMEOUT_S` = 3,600 (controller call). The escrow holds nothing once settled, and the
  executor holds nothing above its own storage stake (a test asserts it after every branch; if the deposit refund
  receipt can land after `on_call`, the timeout path forwards it). The quote includes `target_deposit`.
- **Gas sizing** (controller call): `on_hold`, `on_call`, `on_settle` and the token calls get static gas constants =
  the measured maximum of each (both branches) in near-sandbox × 1.5, pinned by tests that fail when a measurement
  exceeds `pinned / 1.2`; `relay` refuses unless prepaid gas ≥ step-2 + step-3 + executor + `target_gas` + steps 5–7,
  so the target can never starve the callbacks; the relayer's job states `target_gas`.
- **Residual (recorded):** the target's effect and the fee are not one atomic step; a target that succeeds and whose
  callback is then lost is refunded at timeout (the relayer did the work unpaid). Same class as the TON escrow (§10 R1).

### 3.9 Upgrade authority

Every SCaaS NEAR account (token, DEX, router, executor) is deployed, initialised, then has **all access keys
deleted** in the same deploy run; no contract code issues `DeployContract`, `AddKey`, `DeleteKey`, `DeleteAccount`
or a whole-balance transfer action; no NEP-591 global contract. Deploy gate: `view_access_key_list` empty, else the run
fails (README principle 5); the node re-checks at start and holds the chain `halted` (NODE-STO-07). The router's
upgrade authority therefore equals the token's: none.

## 4. Algorand

### 4.1 Apps

| App | Holds | Notes |
|---|---|---|
| `token` (one per token) | ARC-200 ledger (box `"b" ‖ address`), UA ledger (box `"u" ‖ id`), lanes, order lanes / `filled` of legs sold in it | account and router app ids fixed at creation |
| `account` (one per deployment) | subject accounts (keys ≤ 8, origins, guardian, `RECOVERY_DELAY`, policy); `verify(holder, digest, auth)` | tokens, mandate and DEX call it by inner app call; keys shared by every token (inner calls are synchronous) |
| `mandate`, `dex` | mandates (funds in the token ledger under the app address); settlement | DEX: EVM shape (README §11 item 1): each leg is its sell token's `mtx_trade`, funds move only into the DEX, both legs in one group |
| `relayfee` | nothing | stateless |

No local state anywhere (`OptIn` refused). Box names ≤ 64 B: a lane box is `from-kind ‖ from ‖ lane` hashed to 32
bytes with a 1-byte prefix where the raw name would exceed 64 B (exact naming: builder).

### 4.2 Token and storage (ARC-200)

| Method | Rule |
|---|---|
| `arc200_name/symbol/decimals/totalSupply/balanceOf/allowance` | ARC-200; `balanceOf` reads native holders only; `ua_balance_of(byte[32])` |
| `arc200_transfer`, `arc200_transferFrom` | standard; a new receiver box needs the exact-MBR payment (§2 row 15) |
| `arc200_approve` | only when the sender is an app (inner call) and the spender is an app address (README principle 4, CTR-TOK-01) |
| `mtx_*` | as NEAR §3.4 without the `*_check` views: algod `simulate` is the check; a read-only `mbr_needed(op)` method returns the MBR to pay |
| Events | ARC-28: `arc200_Transfer`, `arc200_Approval`, `PaymentSettled`, `PaymentMeta`, `MetaTransactionExecuted`, `RelayFeePaid` |

### 4.3 Accounts / UA

Subject = native address or UA id (lazily opened, relayer pays MBR). A native address signs with its **current
authority**: `AcctAuthAddr` if set, else the address itself; an address rekeyed to a LogicSig or multisig signs
through an account record instead (controller call: a rekey is readable on chain, unlike NEAR keys), with keys it added
before the rekey: since the owner rule of 2026-10-30 `add_key_native` refuses a rekeyed sender (NET-ALG-24). Native kind
`0x0018 algorand-address`: id = the address's 32-byte public key; accepted signature as above (`ed25519verify_bare`
by the current authority). `msig` (kind 288) verified in `account` from its key data, native members by that rule;
the member cap is what fits the group's budget and argument limits, stated in algorand.md.

### 4.4 Entries

As NEAR §3.4 (names, ops), on `token` (pay, transfer, trade, cancel, invalidate), `account` (key ops), `mandate`.
`meta`, the op, the auth and the other arguments must fit the app-call argument limit (2,048 B total) and `PaymentMeta`
the per-transaction log limit (1,024 B): the adapter's pay-meta cap is the measured fit, below `max_pay_meta_bytes`
(as Solana's 168 B, metatx-split §6.2).

### 4.5 Lanes and head-of-line

Lanes permanent (§2 row 6). Algorand transactions carry no account sequence (replay is the txid within
`FirstValid..LastValid`), so relayer lanes (`m/44'/283'/i'…`, ed25519) have no head-of-line at all; `LastValid` is
set within the op's `valid_until`.

### 4.6 Signatures

| Kind | Check |
|---|---|
| ed25519 | `ed25519verify_bare` over the wallet's sign-bytes form `"MX" ‖ text` (text as NEAR §3.5). Not `ed25519verify`, which signs `"ProgData" ‖ program hash ‖ data` and so cannot carry a wallet signature (controller call refining §0) |
| secp256k1 | `ecdsa_verify Secp256k1` (1,700) over the op digest |
| P-256 passkey | NET-ALL-04; `ecdsa_verify Secp256r1` (2,500) over `sha256(authData ‖ sha256(clientDataJSON))`; low-s and the `clientDataJSON` grammar in Puya |

Budget: 700 per app call, pooled in the group; the relayer adds budget calls as `simulate` reports (measured per
kind, pinned in tests).

### 4.7 Mandate and DEX

Mandate as NEAR §3.6 on its own app (inner calls to `token` and `account`). DEX: EVM shape, fill-or-kill per pair,
relayer-bound settlement (CTR-DEX-09), `min_nonce < 2^(w−1)` (CTR-DEX-10).

### 4.8 Relay fee — atomic group, no escrow

Group: `[MBR payment to router (optional)] [target app call, sender = executor] [router.relay(token, op, auth)]`, the
target call immediately before the router call. **Executor:** a keyless LogicSig account whose program approves only
an `ApplicationCall` (`OnCompletion` NoOp) whose next group transaction is `router.relay`, with `RekeyTo`,
`CloseRemainderTo` and `AssetCloseTo` zero and fee 0 (the lane pays by fee pooling); it holds nothing (zero balance)
and is never paid (rule 12). The program template carries the router app id; the router derives the executor address
on chain from the template and its own id (no admin step; controller call), and requires the target transaction's
sender == executor, so the target never sees the lane. Router: `call = target app id (u64) ‖ u8 n ‖ (u16 len ‖
arg)×n` (the target's application arguments, ARC-4 selector first; foreign arrays and boxes are resource references,
not semantics, for SCaaS targets — controller call), `target` in `ref` = the target's app address; rule 13 checks;
shape as NEAR step 1 with `relayer == router address`; then inner group `[MBR forward to token (if any), token.mtx_pay
(op, auth, open_payee = Txn.Sender)]`. The token pays `open_payee` only when `op.to == op.relayer == Txn.Sender` (the
calling app), so the router never holds the payment. A failing target, router or pay rejects the whole group:
CTR-MTX-16 holds with no residual. Every target (token's own entries, `account` key ops, `mandate`, `dex`, third-party
apps) goes through this one router; `target == relayfee` refused.

### 4.9 Upgrade authority

Every approval program rejects `UpdateApplication` and `DeleteApplication` unconditionally (creator included); no app
issues an inner transaction with `RekeyTo`, `CloseRemainderTo` or `AssetCloseTo`. Deploy gate and node check: the
deployed approval program's hash equals the built artifact's, and a test proves update and delete fail. The router's
authority equals the token's: none.

## 5. scaas-node adapters

| Item | NEAR (`adapters/near.rs`) | Algorand (`adapters/algorand.rs`) |
|---|---|---|
| Family | `Family::Near`, `"near"` in `adapters::build`, example config row, `example_config_builds_every_family` | `Family::Algorand`, same |
| Lane keys | `lane_secret` SLIP-44 397 | SLIP-44 283 (exact path: open item §11) |
| Simulate | the entry's `*_check` view; gas = pinned per-job constants (no estimate RPC; unused gas refunded) | algod `simulate` (budget, MBR, logs) |
| Before simulate | pay-meta: `pay_ref == metaPayId`, `lane == payLane`, `nonce == 0`, cap; relay fee: `ref` from the call bytes, relayer == marker, target has code / app exists, target ∉ {router, executor}, payee ≠ executor; quote covers gas + storage (`storage_needed` / `mbr_needed`) at the node's price | same |
| Submit | function call with attached deposit = `storage_needed` (+ 1 yocto where a NEP rule needs it) | group with the exact MBR payment and budget calls |
| Escrow tracking | `pending` → released / refunded; `relay_timeout` after `deadline` (as TON, metatx-split §9) | none |
| Startup errors | missing contract ids; genesis hash ≠ the contract's network; a SCaaS account with any access key (halt); a lane not registered on a token | missing app ids; genesis mismatch; approval-program hash mismatch (halt); lane below its minimum balance |
| Untrusted input | every decode returns `Result`; no `unwrap` / index panic on job, RPC or event data | same |
| Events / finality | NEP-297 logs of final blocks | ARC-28 logs; one-round finality |

## 6. Clients

- `clients/clientkeys`: `src/near.js`, `src/algorand.js` — `MetaOp` encode and digest, NEP-413 / sign-bytes forms,
  passkey assertion assembly, `metaPayId`, `payLane`, `relayRef` per family, pay-meta refusal on mismatch, relay-fee
  build in open mode with both intents in one prompt (CTR-MTX-27 Clients), refuse a native send to a UA id
  (NET-ALL-21).
- `clients/ua-rs`: `near` and `algorand` modules (op digest, `relay_ref`, UA-kind signing); `clients/ua-qt`
  invokables over them. The other `ua-*` language clients reproduce the new native kinds now (§8) and get NEAR /
  Algorand signing later (controller call).
- Vectors (§8) in every client's tests.

## 7. Devnets and CI

| | NEAR | Algorand |
|---|---|---|
| Unit | `near-sdk` unit tests (`testing_env!`) | `algorand-python-testing` |
| Integration | `near-workspaces` on `near-sandbox` | localnet (algod + indexer) |
| Run | `scripts/capped`; docker with `--memory` (oomd rule); `smartcontracts/scripts/test.sh near` / `algorand`; `devnet.sh` entries | same; `algokit localnet` only if its containers take the memory cap, else the repo's own compose with `mem_limit` |
| Node e2e | adapter against the devnet, every job kind incl. relay fee (wrapper, router release, refund, timeout) | every job kind incl. relay fee |
| Gates | `near` / `algorand` steps added to metatx-split Task 20's resumable runner after the rebase (§ header) | same |

Layout: `smartcontracts/near/` (cargo workspace: `token`, `dex`, `relayfee`, `relayexec`), `smartcontracts/algorand/`
(Puya: `token`, `account`, `mandate`, `dex`, `relayfee`).

## 8. Vectors

`smartcontracts/vectors/metatx/paymeta.json` (every row, byte-equal); `smartcontracts/test/vectors/webauthn_kat.json`;
`smartcontracts/vectors/ua/kinds.json` (UA ids; gains the native kinds `0x0017 near-account` and `0x0018
algorand-address` with `natives` / `nativeInvalid` rows, generated by `clients/clientkeys/scripts/ua-vectors.mjs` and
reproduced by Solidity `UAKinds`, `clientkeys` `ua.js`, `ua-rs`, `ua-py`, `ua-go`, `ua-cs`; the `UAKinds` change alters
EVM bytecode, so it runs forge at the four sets (`at-set.sh`), the size gate and `docs_check`, not the full pqz-core
gate, and the SCaaS testnet registry is redeployed at its next reset; controller call); per family `smartcontracts/near/vectors/near-vectors.json` and
`smartcontracts/algorand/vectors/algorand-vectors.json`: `MetaOp` encodings and digests, NEP-413 / sign-bytes
messages, `ref` of wrappers and router, MBR and storage figures. Generated by the family's generator, read by
contracts, adapter and clients.

## 9. Docs

`docs/networks/near.md` (NET-NEAR-*) and `docs/networks/algorand.md` (NET-ALG-*) in the shape of `aptos.md`;
`networks/README.md` (§1 rows to BUILT, §4 signing domains, §5 verifier primitives, §7 key lifecycle, §8
head-of-line, §9 finality, §11 DEX differences, §12 availability); `contracts/metatx.md` CTR-MTX-26 / -27 family
tables and §12 per-family payers; `decisions.md` (each §0 row in full, status, commits); node docs (job API, submit
lanes); `TODO.md`; `HANDOFF.md`.

## 10. Risks

| # | Risk | Test |
|---|---|---|
| R1 | **No cross-contract atomicity: NEAR (escrow router) and TON (metatx-split Task 16), one rule.** Fee taken for a failed call, fee both released and refunded, escrow stuck. | sandbox: release on success; refund on target panic, on missing code, on hold failure; timeout refund refused before `deadline`; release and refund exclusive; late callback after timeout pays nothing; `pending` empty and router balance unchanged after settlement |
| R2 | A router-bound or wrapper-bound payment settled outside it (R17) | `near_router_bound_pay_refused_direct`, `near_wrapper_bound_pay_refused_direct`, `algorand_router_bound_pay_refused_direct` |
| R3 | A forwarded call spends another router-bound payment, or the lane's / executor's funds | NEAR: a target call to `relay_hold` / `mtx_pay` of a router-bound op fails (executor is the predecessor); Algorand: a target call that is a pay naming the router fails (sender ≠ router); a target that is `arc200_transfer` from the lane is refused (sender ≠ executor) and from the executor moves nothing (zero balance) |
| R4 | Callback starved or mispriced | NEAR gas pins (§3.8); `relay` refuses short prepaid gas |
| R5 | Storage griefing of the relayer (NEAR deposit, Algorand MBR) | quote covers storage; MBR payment must be exact; checks report `storage_needed` |
| R6 | NEP-145 deviations confuse wallets / DEXs | tests: auto-registration, `storage_unregister` panics, 1-yocto rule for registered receivers unchanged |
| R7 | Stale native keys (NEAR rotation, Algorand rekey) | NEAR refuses access-key signatures; Algorand rekeyed-address cases |
| R8 | P-256 in NEAR wasm too costly; Algorand budget / argument / log limits | §3.5 gate (plan Task 1; owner rules on failure); §4.4 measured caps |
| R9 | Keys per token on NEAR drift between tokens | client test: a key op fans out to every held token; the node shows per-token key sets |
| R10 | A deployment left upgradeable | deploy-gate negative tests (a key left; an update-accepting approval program) |
| R11 | Devnet containers trigger oomd | `--memory` on every container; capped runs |

## 11. Open items left to the builder

Fixed by the vector generators (near-algorand Task 3, controller call 2026-10-28): the NEAR escrow router's `ref`
target is `u8 len ‖ account_id bytes` (the wrapper form of §3.8); every Algorand `u16` length in `call` (§4.8) is
big-endian. Placeholders in the generated vectors (Algorand app ids 1001–1003, `*.test.near` names, the Algorand
method signature) are replaced by the tasks that deploy those contracts.

- Exact Borsh / ARC-4 layouts within §2, private helper names, event field order, Algorand box naming (§4.1).
- SLIP-10 paths of the lane keys — controller call 2026-10-28: fully hardened (ed25519 SLIP-10 has no
  non-hardened derivation): NEAR `m/44'/397'/0'/0'/i'`, Algorand `m/44'/283'/0'/0'/i'`; README's
  `m/44'/283'/0'/0/i` is corrected; pinned with vectors.
- Wallet support for NEP-413 `signMessage` and Algorand sign-bytes (ARC-60 / ARC-47 status): checked; the `"MX"`
  form may change to the wallet API's.
- Every gas, budget, storage and MBR figure: measured and pinned, with run logs.

## 12. References

- NEP-141 https://github.com/near/NEPs/blob/master/neps/nep-0141.md · NEP-145
  https://github.com/near/NEPs/blob/master/neps/nep-0145.md · NEP-148
  https://github.com/near/NEPs/blob/master/neps/nep-0148.md · NEP-297 events
  https://github.com/near/NEPs/blob/master/neps/nep-0297.md · NEP-413
  https://github.com/near/NEPs/blob/master/neps/nep-0413.md
- NEAR storage staking https://docs.near.org/protocol/storage/storage-staking · cross-contract calls
  https://docs.near.org/smart-contracts/anatomy/crosscontract · gas https://docs.near.org/protocol/gas · nearcore
  2.11.0 (1 PGas) https://github.com/near/nearcore/releases · near-sdk-rs https://github.com/near/near-sdk-rs ·
  near-workspaces / near-sandbox https://github.com/near/near-workspaces-rs, https://github.com/near/near-sandbox
- ARC-200 https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0200.md · ARC-4
  https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0004.md · ARC-28
  https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0028.md
- AVM opcodes (`ed25519verify`, `ed25519verify_bare`, `ecdsa_verify`, `keccak256`, `box_create`, `global
  GenesisHash`) https://dev.algorand.co/reference/algorand-teal/opcodes/ · boxes and MBR
  https://dev.algorand.co/concepts/smart-contracts/storage/box/ · costs and limits
  https://dev.algorand.co/concepts/smart-contracts/costs-constraints/ · rekeying
  https://dev.algorand.co/concepts/accounts/rekeying/ · Algorand Python (Puya) https://github.com/algorandfoundation/puya
  · AlgoKit localnet https://dev.algorand.co/algokit/
- Repo: `docs/research/near-algorand.md`; `docs/superpowers/specs/2026-10-27-metatx-split-design.md` §6.2, §7.2, §9,
  §10; `docs/superpowers/plans/2026-10-27-metatx-split.md` Task 16; `docs/contracts/metatx.md` CTR-MTX-03/-04/-10/-16/
  -26/-27; `docs/networks/README.md` NET-ALL-01/-03/-04/-21/-22/-23/-26..-29, §11; `docs/networks/ton.md` NET-TON-09.
