# NEAR (Rust, near-sdk)

Common rules for every family: [networks/README](README.md). Status: contracts, adapter and clients **BUILT** on
branch `near-algorand` (contracts at `smartcontracts/near/`, a cargo workspace `token`, `dex`, `relayfee`,
`relayexec`, `common`; adapter `scaas-node/src/adapters/near.rs`; end to end `scaas-node/tests/e2e_near.rs`; devnet
near-sandbox 2.14.0, protocol 88, RPC port 32060). Nothing is deployed on a public network: `deploy.sh near` has run
only on near-sandbox; testnet and mainnet deployments are the owner's call. Design:
[2026-10-28-near-algorand-design.md](../superpowers/specs/2026-10-28-near-algorand-design.md) §3 and §5 (the spec);
rulings: [decisions.md §35](../decisions.md#35-networks--near). Algorand, built in the same item, has its own page
([algorand.md](algorand.md)); nothing here applies to it.

**Contents**

1. [Overview](#1-overview)
2. [Contracts and accounts](#2-contracts-and-accounts)
3. [Keys](#3-keys)
4. [Lanes](#4-lanes)
5. [Payload](#5-payload)
6. [Signatures](#6-signatures)
7. [Contract entry points](#7-contract-entry-points)
8. [Relayer](#8-relayer)
9. [Finality and events](#9-finality-and-events)
10. [Mandate](#10-mandate)
11. [DEX](#dex)
12. [Deploy](#12-deploy)
13. [Conformance](#13-conformance)
14. [Limitations](#limitations)
15. [References](#15-references)

## 1. Overview

NEP-366 delegate actions still need the user's NEAR account and access key, and receipts run asynchronously, one
contract at a time; SCaaS users hold no NEAR, many no NEAR account. So NEAR uses the contract-level path: the subject
signs a `MetaOp` v1 (§5), the token verifies it against the subject's SCaaS key record, a relayer lane pays gas and
storage.

<a id="NET-NEAR-08"></a>**NET-NEAR-08** — **NEAR has the full SCaaS feature set from the start.** Token with `mtx_pay`,
the relayed pay and `mtx_pay_meta` ([CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26)); mandate; DEX; smart-key and
passkey UA accounts; the relay-fee router ([CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27)); the `scaas-node` adapter;
`clientkeys`, `ua-rs` and `ua-qt` signing; a near-sandbox devnet, tests and shared vectors (owner 2026-10-28). Out of
scope: Zether and PQZ (EVM precompile families only), PQ signers, the asset suite, token wrappers and the tender
([NET-ALL-17](README.md#NET-ALL-17)–[19](README.md#NET-ALL-19) keep them PLANNED), the mesh (job API only),
`MetaCall` / `MetaTransfer` ([NET-ALL-26](README.md#NET-ALL-26): NEAR signs the built `MetaOp` v1 and migrates with
the other families), public testnets and mainnet, receiver-pays (EVM only). BUILT.

<a id="NET-NEAR-09"></a>**NET-NEAR-09** — **The relayer pays every storage stake; users hold no NEAR.** Every call that
creates a record (a registration, a UA balance, a lane, a subject record, a mandate, an order, an escrow entry) takes
its storage from the attached deposit, `Δstorage_usage × env::storage_byte_cost()` (10^19 yocto per byte on
near-sandbox), the excess refunded to the predecessor in the same receipt (spec §2 row 15). The relayer is reimbursed
through the fee: the node's fee floor covers first-use storage, as the Solana lane-PDA rent (owner 2026-10-28; the
fee rule a controller call accepted by the owner). BUILT.

<a id="NET-NEAR-11"></a>**NET-NEAR-11** — **Balances and records are permanent; lanes never prune; only escrow entries
do.** No record is deleted or refunded (no TTL); lanes are kept for good, so [CTR-MTX-04](../contracts/metatx.md#CTR-MTX-04)
and [NET-ALL-01](README.md#NET-ALL-01) hold by construction. Working state that is pruned: the router's pending entries
and the DEX's settle entries, each with its deposit returned to whoever staked it. BUILT.

<a id="NET-NEAR-12"></a>**NET-NEAR-12** — **Contracts are Rust on near-sdk 5.30.0, built with `opt-level = 3`.**
cargo-near 0.22.0 (`target/near/<crate>/<crate>.wasm`), near-workspaces 0.24.0 for the sandbox tests, RustCrypto `p256`
0.13.2 for passkeys. `opt-level = 3` instead of `"z"`: a P-256 verify costs 20.005 Tgas instead of 29.0 (31 % less)
for about 11 KB more wasm (`smartcontracts/near/runs/2026-10-28-p256-spike.txt`). BUILT.

## 2. Contracts and accounts

| Account (keyless) | Holds | Why there |
|---|---|---|
| `token` (one per token) | NEP-141 ledger of native holders; the UA ledger (`Ua` id → balance); lanes; subject records (keys, origins, guardian, policy, key nonce); mandates over this token; order lanes, `filled`, `min_nonce` of the legs it sells; `held` amounts of router relays; the `relay_fee_<entry>` wrappers | every fee-less signed entry the router serves must run in the same receipt as its payment, and reading keys from another contract is asynchronous |
| `dex` | settle entries in flight (escrowed legs) | two tokens are two contracts, so a NEAR DEX cannot move both legs in one receipt |
| `relayfee` (router) + `relayexec` (executor) | pending relays in flight | cross-contract targets |

A holder is `Holder::Near(AccountId)` (Borsh 0) or `Holder::Ua([u8; 32])` (Borsh 1); in JSON views a `[u8; 32]` is a
number array. Subjects keep their keys per token contract: a key operation is one signed op per token the subject uses
(clients fan it out, the relayer submits one transaction per token; NET-NEAR-03).

<a id="NET-NEAR-01"></a>**NET-NEAR-01** — **UA balances are pooled in the token's own NEP-141 account.**
`ft_balance_of(token)` = the UA total (EVM's `UA_POOL`), so `ft_total_supply` stays the sum over native accounts; a
move with a UA side emits NEP-141 `ft_transfer` from or to the token plus `"scaas"` `ua_transfer`, a UA → UA move only
`ua_transfer`. The token refuses to be a payee or a native debit source. BUILT.

<a id="NET-NEAR-02"></a>**NET-NEAR-02** — **A transfer that creates the receiver's record takes its storage from the
attached deposit.** `ft_transfer`, `ft_transfer_call`, `transfer_to_ua` and `mint`: exactly 1 yoctoNEAR when the
receiver's record exists, else at least the new record (registration 125 B, UA record 89 B), the excess refunded.
BUILT.

<a id="NET-NEAR-10"></a>**NET-NEAR-10** — **Full NEP-141 / NEP-145 / NEP-148 interface, with stated deviations.** An
unregistered receiver of `ft_transfer` / `ft_transfer_call` is registered from the attached deposit (≥
`storage_balance_bounds().min`, excess refunded; less panics); `storage_balance_bounds` has `min == max`;
`storage_withdraw` has `available` 0 and panics on any amount; `storage_unregister` returns `false` when unregistered
and panics when registered, `force` included (records are permanent and the stake was usually the relayer's); a
transfer to the token itself is refused everywhere; a UA receiver uses `transfer_to_ua` (an id in the 64-hex form
would be a keyless NEAR account, [NET-ALL-21](README.md#NET-ALL-21)). Events: NEP-297 `nep141` for native moves,
standard `"scaas"` for SCaaS events. BUILT.

<a id="NET-NEAR-18"></a>**NET-NEAR-18** — **Native UA kind `0x0017 near-account`.** Id = the raw 32 bytes of an implicit
account (64 lower-case hex), else `sha256(account_id bytes)` (named and ETH-implicit accounts); the two forms are told
apart by the account-id string, which travels with the member, and cannot collide (a 64-hex id is always implicit; a
named id meets one only through a sha256 preimage); upper-case ids are refused. Accepted signature: the member is the
predecessor of the call (access keys are not readable on chain). Not a registry: the kind names a NEAR account as a
holder or msig member ([accounts.md](../contracts/accounts.md) §1.6 table, vectors `kinds.json` and
`smartcontracts/near/vectors/near-vectors.json` `nativeIds`). The `UAKinds` change altered EVM bytecode; the SCaaS
testnet `UARegistry` learns the kind at its next reset. BUILT.

Storage per record, measured on near-sandbox (10^19 yocto per byte):

| Record | Bytes | Log |
|---|---|---|
| NEP-145 registration (64-char id) | 125 (0.00125 NEAR) | `smartcontracts/near/runs/2026-10-28-near-storage.txt` |
| UA balance | 89 | same |
| subject record, one ed25519 UA key (with `policy`) / two keys | 131 / 169 | 131: test `account.rs:20` (`record_bytes` assert); 169: `…/2026-10-28-near-account-fix1.txt` |
| lane of a UA payer (81 B + Borsh(holder)) | 114 | `…/2026-10-28-near-metatx.txt` |
| first UA → new UA pay (record + lane + receiver) | 334 | same |
| `mtx_mandate_open` / first `mtx_mandate_pay` / next pay / revoke | 610 / 370 / 114 / 0 | `…/2026-10-28-near-mandate-fix1.txt` |
| order records (by shape) / `min_nonce` | 147, 115, 162 / 114 | `…/2026-10-28-near-dex.txt` |
| DEX settle entry / router pending entry | 706 / 314 | `…/2026-10-28-near-dex.txt`, `…/2026-10-28-near-router-fix1.txt` |

Deployed wasm (`smartcontracts/near/runs/2026-10-28-near-e2e.txt`, T19 fix 4 build): token 559,120 B (7.591 NEAR
stake at deploy), dex 148,797 B (3.488 NEAR), relayfee 109,206 B (3.092 NEAR), relayexec 39,699 B (2.397 NEAR).

## 3. Keys

<a id="NET-NEAR-03"></a>**NET-NEAR-03** — **Each token keeps SCaaS key records per holder; key ops are signed with the
key nonce.** Up to 8 keys (ed25519, secp256k1, webauthn-p256, msig) and 8 origins (≤ 128 B), a guardian, a pending
recovery, `key_nonce` and `policy`; signatures are checked against these records only, never a NEAR access key. A `Ua`
id opens lazily on its first signed op by the key it derives from; a `Near` holder adds keys by `add_key_native(key,
origin)` (predecessor) or a signed op. Key ops (codes 6–12) carry the signer's key nonce; recovery is signed by the
guardian at start and at finish (after `RECOVERY_DELAY_S` = 172,800 s), **adds** the recovery key and removes none
([CTR-ACC-03](../contracts/accounts.md#CTR-ACC-03)); any current key cancels during the delay. BUILT.

<a id="NET-NEAR-04"></a>**NET-NEAR-04** — **An msig has at most 12 members; a `near-account` member counts only as the
predecessor.** `MSIG_MAX_MEMBERS` = floor(250 Tgas / 20.005 Tgas per P-256 verify) = 12; no nested msig; a signature
offered for a `near-account` member is refused. BUILT.

<a id="NET-NEAR-05"></a>**NET-NEAR-05** — **`POLICY_PASSKEY_FOR_VALUE` is set by the key-op action `set_policy`.** Entry
`mtx_set_policy(op, auth, policy)`, op code 10 with signed parameters `[6, policy]`; with the bit set a value op
(pay, trade, mandate setup) needs a passkey or an all-passkey msig ([NET-ALL-23](README.md#NET-ALL-23) item 3); key ops
stay open to wallet keys. BUILT.

<a id="NET-NEAR-06"></a>**NET-NEAR-06** — **Key data is checked for length only.** No small-order or on-curve check: a
bad key never verifies and only the subject's own authorised key op (or its guardian) can add one. A `Near` holder whose
implicit-account access key is also a SCaaS key keeps that SCaaS key after a native rotation (by design: the record,
not the access key, is the authority). BUILT.

Member caps (all measured; NEAR's limit is 300 Tgas per transaction, no chain's higher limit is assumed):

| Where | Cap | Bound | Log |
|---|---|---|---|
| subject msig | 12 members | the costliest relayed call (a 12-passkey msig entry plus a passkey payment) burns 266.826 Tgas, 33.174 under 300 | `smartcontracts/near/runs/2026-10-29-t19-fix4.txt` |
| wrapper job (node) | 13 passkey signatures | 21 + 13 × 21 = 294 Tgas prepaid; the e2e burnt 266.291 in its receipt | `…/2026-10-28-near-e2e.txt` |
| DEX leg, passkey msig against an ed25519 leg | 9 signatures (10 before the implicit-transfer gas) | 9 settle at 260.682 Tgas of 300 prepaid; 10 are refused (settle gas 312) | `…/2026-10-29-t19-fix4.txt` |
| two msig legs | by the formula `9 + 18 + leg_gas(a) + leg_gas(b) ≤ 300` (about 5 + 5) | the 1.25 margin on each leg, not physics | same |
| passkey field on a trade leg | `clientDataJSON` and `authenticatorData` ≤ 1 KiB each | real Chrome `clientDataJSON` is about 400 B | same |

Never add a contract account (the DEX, the router) as a `near-account` msig member: as the predecessor of every trade
leg or relay it would count as signed.

## 4. Lanes

<a id="NET-NEAR-07"></a>**NET-NEAR-07** — **Value entries use lanes per payer; `mtx_pay` takes any lane at its next
nonce.** `LookupMap<(Holder, lane), u64>` (the next nonce), one per payer and lane, never removed. `mtx_pay` (op 0),
`mtx_pay_meta` (`pay_ref == metaPayId(salt, meta)`, `lane == payLane(pay_ref)`, nonce 0), `mtx_transfer` (op 4) and
`mtx_execute_transfer` (op 5), each with a `*_check(caller, …)` view; storage charged once per call; events
`payment_meta`, `meta_transaction_executed`, the NEP-141 / `ua_transfer` events, `payment_settled`. A failed receipt
keeps its logs, so indexers book `"scaas"` events only from successful receipts and join by `pay_ref`. No contract cap
on `meta`: the largest that settles is 7,530 B with a 64-character (implicit) relayer (7,540 B with a dev account),
above it NEAR's 16,384 B log limit fails the call whole; the node's `max_pay_meta_bytes` (2,048 B) is the operative
cap. BUILT.

<a id="NET-NEAR-24"></a>**NET-NEAR-24** — **A relayer lane is an implicit ed25519 account at `m/44'/397'/0'/0'/i'`, one
access key, one transaction in flight, registered on every token.** SLIP-10, every level hardened (ed25519 SLIP-10 has
no non-hardened derivation); lane id = the 64-hex public key. Every lane is `storage_deposit`ed on every token at
deploy. Head-of-line ([NET-ALL-03](README.md#NET-ALL-03)): each lane has its own access-key nonce and receipts are
asynchronous, so a stuck lane blocks only itself; the subject sends no transaction and its lanes live in the token. The
anti-lock test `near_lanes_do_not_block_each_other` holds op X on lane 0 while op Y on lane 1 mines, then X mines.
`submit` waits for `wait_until = INCLUDED`: near-sandbox answers a stale-nonce `send_tx` sent with `NONE` as success and
drops it silently, so only `INCLUDED` returns the `InvalidNonce` refusal (one block of latency per submit). BUILT.

## 5. Payload

`MetaOp` v1, Borsh: `"scaas.metaop.v1"` ‖ network (32) ‖ contract (`AccountId`) ‖ op (u8) ‖ `from`, `to` (`Holder`) ‖
`relayer` (`Option<AccountId>`) ‖ amount (u128) ‖ `pay_ref` (32) ‖ lane (32) ‖ nonce (u64) ‖ `valid_until` (u64
seconds) ‖ `extra` (32); digest = `sha256` of that whole labelled encoding. Network = the genesis hash (RPC `status`),
passed at `new` and immutable; the node checks it at start ([NET-ALL-22](README.md#NET-ALL-22)). `payId` / `payLane` /
`ref` use `env::keccak256`, byte for byte the EVM derivation.

| Op | Entry | Op | Entry |
|---|---|---|---|
| 0 | `mtx_pay`, `mtx_pay_meta`, the relayed pay | 8 / 9 | `mtx_add_origin` / `mtx_remove_origin` |
| 1 | `mtx_trade` (a DEX leg) | 10 | `mtx_set_guardian`, `mtx_set_policy` (action in the params) |
| 2 | `mtx_mandate_pay` | 11 | `mtx_start_recovery`, `mtx_finish_recovery` (action in the params) |
| 3 | `mtx_revoke` | 12 | `mtx_cancel_recovery` |
| 4 / 5 | `mtx_transfer` / `mtx_execute_transfer` | 13 | `mtx_mandate_open` |
| 6 / 7 | `mtx_add_key` / `mtx_remove_key` | 14 / 15 | `mtx_cancel` / `mtx_invalidate_nonces` |

<a id="NET-NEAR-28"></a>**NET-NEAR-28** — **The NEAR encodings fixed by the vector generator.** Op codes 0–3 as Solana;
`extra` of a key op = `sha256(Borsh(entry parameters))`, of a trade leg = `sha256(Borsh(Order))`, of a mandate pay or
revoke = `sha256([])`; a relay fee's `call` hashes the entry's full method name with its `mtx_` prefix, as Sui / Aptos;
salt = the payment op's payer-signed `extra`, always; the router's `ref` target is `u8 len ‖ account id` (the wrapper
form). Vectors: `smartcontracts/near/vectors/near-vectors.json`, generated by `famvec.py` and read by the contracts,
the adapter and the clients; the passkey vector is RFC 6979 A.2.5, low-s normalised. BUILT.

## 6. Signatures

<a id="NET-NEAR-13"></a>**NET-NEAR-13** — **ed25519 through NEP-413, secp256k1 through `ecrecover`, P-256 in wasm.**

| Kind | Check |
|---|---|
| ed25519 | `env::ed25519_verify` over `sha256(u32 LE 2^31+413 ‖ Borsh{message = "scaas.metaop.v1:" ‖ hex(digest), nonce = digest, recipient = token, callback_url = None})` |
| secp256k1 | `env::ecrecover` over the digest, malleability flag set, `v` ∈ {0, 1} (a wallet's 27 / 28 minus 27) |
| P-256 passkey | [NET-ALL-04](README.md#NET-ALL-04) in wasm (`p256` 0.13.2): UP and UV, the bounded `clientDataJSON` grammar (closing `}` included), challenge = b64url(digest), exact origin, low-s; NEP-635 `p256_verify` is not used (draft, chain-specific) |

The passkey gate (the plan's first task, a hard gate): a two-passkey `relay_fee_<entry>` modelled at 42.271 Tgas of
300; 19.991 / 20.005 Tgas per verify (`smartcontracts/near/runs/2026-10-28-p256-spike.txt`, neard 2.14.0). BUILT.

**Wallet support (checked 2026-10-29).** NEP-413 is Final; wallets expose it as `signMessage({message, recipient,
nonce})` through NEAR Wallet Selector (MyNearWallet is the standard's own example). The wallet signs with a
**full-access key** and returns an error without one; the Ledger NEAR app signed only transactions when the standard was
written. SCaaS never trusts the access key itself: the wallet's ed25519 key must be a SCaaS key of the subject (a native
holder adds it with `add_key_native`; a UA id derived from it opens lazily), so a later rotation of the access key does
not move authority. The signed text is the first build of [NET-ALL-23](README.md#NET-ALL-23) (`label:hex(digest)`) and
moves to the readable form with Solana and Sui.

<a id="NET-NEAR-29"></a>**NET-NEAR-29** — **Clients sign NEAR ops with the shared vectors.** `clientkeys` `src/near.js`,
`ua-rs` `near` and `ua-qt` invokables: digest = `sha256` of the full labelled encoding (Rust and QML take the encoded
op); `relay_ref` target = `u8 len ‖ account id`; `keyOpFanOut(keyOp, tokens, nonces)` builds one key op (codes 6–12)
per token with that token's key nonce (a missing nonce is refused); `buildPayMeta` and both relay-fee builders enforce
nonce 0; `passkeyAssertion` checks challenge == base64url(digest), strict UTF-8 and `type` `webauthn.get`, normalises
low-s and keeps `clientDataJSON` verbatim; a native send to a UA id is refused. Router, executor and `add_key_native`
refusals stay in the node. BUILT.

## 7. Contract entry points

```text
token:  ft_* / storage_* (NEP-141/145/148), transfer_to_ua, ua_balance_of, mint, admin, network, subject, lane_nonce
        mtx_pay, mtx_pay_meta, mtx_transfer, mtx_execute_transfer
        mtx_add_key, mtx_remove_key, mtx_add_origin, mtx_remove_origin, mtx_set_guardian, mtx_set_policy,
        mtx_start_recovery, mtx_finish_recovery, mtx_cancel_recovery, add_key_native
        mtx_mandate_open, mtx_mandate_pay, mtx_revoke, mandate, mandate_refund
        mtx_trade, mtx_cancel, mtx_invalidate_nonces, filled, order_closed, min_nonce
        relay_fee_<entry> (13 wrappers), relay_hold, relay_release, relay_refund, relay_held
        every signed entry and wrapper has a *_check(caller, …) view -> Check { error, storage_needed }
dex:    settle, on_legs, on_refund, refund_expired, pending(settle_id), leg_settle(digest), implicit_transfer_gas
relayfee: relay, on_hold, on_call, on_settle, relay_timeout, relay_check, pending(ref), executor, implicit_transfer_gas
relayexec: exec, return_deposit, router
```

NEAR has no write simulation, so the `*_check` views are the relayer's check (as Aptos `pay_check`); a view has no
predecessor, so each takes the caller explicitly.

## 8. Relayer

<a id="relayer"></a>

<a id="NET-NEAR-25"></a>**NET-NEAR-25** — **Adapter jobs, ids and states.** `[[chains]] network` = the genesis hash in
base58, chain key `near:<b58>`; job `payload` = hex of label ‖ Borsh `MetaOp`, `signature` = hex Borsh(`Auth`),
`contract` = the token; a relay fee adds `extra.call` (hex), `extra.route` (`wrapper` | `router`) and, for the router,
`target_gas` / `target_deposit` (decimal strings, set by the node from the target's view); tx ids `0x` + 64 hex
(base58 on the RPC); sequence = access-key nonce + 1 (optimistic), signing block hash = the final block's. Jobs run only
on `[[chains]].tokens` (start-checked: keyless, network, lanes registered). Mined or reverted only at
`final_execution_status == FINAL`; any failure is `Reverted` (gas is pinned, a retry would fail the same way). A router
job is mined when `on_settle` returns `true`; else the router's `pending(ref)` decides: gone → reverted ("refunded");
present → pending, and past the deadline the relaying lane sends `relay_timeout(ref)` (also while the relay is still in
flight, `INCLUDED_FINAL` with status `Started`; `wait_until = INCLUDED`; retried every 120 s); 3,600 s past the
deadline the job is reported reverted to free the lane. Price key `params.relay_fee.min_yocto_value = { "<token>" =
"<yocto per base unit>" }`; router targets: configured tokens, `params.dex`, and `params.relay_fee.targets = { "<id>" =
["method", …] }` (strict, per method). The adapter logs a subject's key set per token for account key-op jobs. BUILT.

<a id="NET-NEAR-26"></a>**NET-NEAR-26** — **Relay-fee jobs are checked against every known relayer-loss path before
the call.** Fee shape (ref from the call bytes, lane, nonce 0, relayer = the marker, payee ≠ executor); router target ∈
the allowlist above, token targets through `<method>_check` with the executor as caller; deposit floor = entry storage
+ 2 yocto + 2 × max(the larger leg, the DEX's 2,200 B worst-case leg pin, [NET-NEAR-30](#NET-NEAR-30)), a token
target's deposit == its `storage_needed`; a same-token value target needs
balance ≥ amount + fee; DEX targets: the node rebuilds the DEX's pair check and refuses when `pending(settle_id)` or
`leg_settle(digest)` already holds a leg; `RELAY_EXPIRY_MARGIN_S` = 120 on the payment, the wrapped op, the target op,
DEX orders and legs and `MandateTerms.expiry` (clients sign longer); an unopened subject's payment passkey origins must
be among those the entry opens it with; the node parses a passkey origin byte for byte as the contract's
`common/src/webauthn.rs` `origin_of` (31 parity rows in `vectors/webauthn-origin.json`) and refuses what it would not
parse. `op_consumed` is never asked for a router job (the escrow decides the outcome; a refunded hold still spends the
payment lane, so the payer re-signs with a new salt). Never-pay rule (final review node I1, as Algorand): a configured
token, the router, its executor and the DEX are never the payee of anything the job carries — its payment outside that
payment's own open mode, a router target op's `to` (value entries, mandate pay), a wrapped or routed mandate's
`terms.payee` ([NET-NEAR-32](#NET-NEAR-32)). BUILT.

<a id="NET-NEAR-27"></a>**NET-NEAR-27** — **Gas is pinned per job, from the contracts' measured figures.** Node
constants (Tgas): `GAS_JOB_BASE` 21 (10 + one `IMPLICIT_TRANSFER_GAS`), + 21 per passkey signature (20.005 × 1.05),
+ 1 per ed25519 / secp256k1 key; wrapper jobs carry at most 13 passkey signatures (`MAX_WRAPPER_PASSKEYS`, 294 Tgas);
`ROUTER_FIXED_GAS` 102 (the router's `relay_gas` = 102 + signature gas + `target_gas`), a router job's `target_gas` ≤
173 Tgas with a passkey payment; `DEX_LEG_GAS` 17 per leg; `GAS_RELAY_TIMEOUT` 74. Contract static gas (= measured ×
1.5, tests fail above pin / 1.2): `GAS_HOLD` 16 (+ signature gas), `GAS_ON_HOLD` 16, `GAS_EXEC` 15, `GAS_RELEASE` 16,
`GAS_ON_SETTLE` 14, DEX `GAS_LEG_BASE` 17, `GAS_ON_REFUND` 29; `relay` refuses prepaid gas below the sum, so a target
never starves the callbacks. The relayer's RPC must allow `max_gas_burnt_view` ≥ 300 Tgas (a 13-passkey `_check` view
burns about 265 Tgas); the RPC cannot report it, so it is a stated requirement (devnet.sh sets it). BUILT.

<a id="NET-NEAR-21"></a>**NET-NEAR-21** — **Every transfer to an account the contract does not control is budgeted as a
transfer to an implicit account.** On nearcore 2.14 a transfer to a 64-hex account, new or existing, is charged as an
account creation: 8.35 Tgas (0.825 at send + 7.525 in the receiving receipt: create_account 7.2, add_key 0.102,
transfer 0.115, receipt 0.108; `smartcontracts/near/runs/2026-10-29-near-sandbox-probes.txt`), against 0.22 Tgas to a
named account; relayer lanes are implicit. `IMPLICIT_TRANSFER_GAS` = 11 Tgas (common/, ≥ 1.2 × measured) is added to
`relay_hold`, `relay_release`, `relay_refund`, `on_hold`, `on_settle`, the executor's call and `return_deposit`, the DEX
leg refunds and `prune`; no contract sends a zero-amount refund (the executor's trailing 0-yocto transfer is the one
deliberate exception: it makes the router read the target's own receipt). The router and the DEX expose
`implicit_transfer_gas()`; the node refuses to start when a chain's send + exec cost of that transfer (from its
protocol config, 8,349,895,375,000 gas on protocol 88) exceeds the pin or a contract reports another pin. BUILT.

<a id="NET-NEAR-22"></a>**NET-NEAR-22** — **Action fees are read from the chain, never assumed.** The node reads
`runtime_config.transaction_costs` from `EXPERIMENTAL_protocol_config` at start (receipt creation, function call, per
byte; each priced at max(send, exec), charged at send and at execution), re-reads them every 3,600 s and refuses to
start without them; a fee job with unknown fees is retried, never priced on assumed figures. The old pinned constants
survive only as test fixtures (customer chains may differ). Protocol 88: receipt 108,059,500,000 (send and exec);
function call 200,000,000,000 send / 780,000,000,000 exec; per byte 47,683,715 send / 2,235,934 exec; the node prices a
lane call at 1.809 / 3.341 / 8.028 Tgas of action fees against the sandbox's 1.213 / 2.015 / 4.469 for 321 B / 16 KiB /
64 KiB of args (`smartcontracts/near/runs/2026-10-28-near-e2e.txt`). BUILT.

<a id="NET-NEAR-23"></a>**NET-NEAR-23** — **The quote is the prepaid gas at the node's price plus the attached
deposits** (+ one `relay_timeout` resend for a router job, priced at 75.780 Tgas). The prepaid gas already contains one
`IMPLICIT_TRANSFER_GAS` per transfer the job makes to the lane; the refund receipts NEAR lands at an implicit lane are
paid from that gas or cost the lane nothing, so they are not counted again. The e2e asserts quote ≥ the lane's NEAR
balance decrease per job kind (§13). BUILT.

Config shape: the `near` row of `scaas-node/node.example.toml` (`tokens`, `params.dex`, `params.relay_fee.{router,
executor, min_amount, min_yocto_value, targets}`).

## 9. Finality and events

Final = `final` blocks; transactions are read at `final_execution_status == FINAL`. Events are NEP-297 logs
(`EVENT_JSON:`) of successful receipts only (a failed receipt keeps its logs). Rows carry the transaction's inclusion
block (height, `0x` hash) and tx hash; `log_index` counts every log of the transaction in outcome order; the block hash
of a skipped height is the last block at or before it (≤ 100 heights back). `Transfer` rows: one per holder move (a
side equal to the token itself — the UA pool, a hold — is skipped, its `ua_transfer` or payment row carries the holder
side); `ft_mint` / `ft_burn` are not rows. `payment_meta` and `relay_fee_paid` enrich the `payment_settled` of a
configured token with the same `pay_ref` (a `relay_fee_paid` from an unconfigured token proves nothing: it is
forgeable). DEX trades are booked from the token transfer events and the DEX's `matched` (emitted before the payouts).
Scope: only transactions sent directly to a configured token, router or DEX are read (one RPC per block, per chunk and
per watched transaction); a range holding a non-final transaction to one of them is retried as a whole, so one such
transaction stalls the chain's feed ([limitations](#limitations), accepted risk until fixed).

## 10. Mandate

<a id="NET-NEAR-17"></a>**NET-NEAR-17** — **A NEAR mandate lives in its token: one-shot, funded by the owner's open,
spent by a delegate `Holder`.** `MandateTerms` starts with `delegate: Holder`; `mtx_mandate_open` (op 13, the owner's
signature, the owner's passkey policy) moves the funded amount (`op.amount`, which `terms.funding` must equal) into the
ledger under `Holder::Ua(mandate id)`, id = `sha256` of the terms incl. the id, inside `op.extra` (anyone may top the id
up); `mtx_mandate_pay` (op 2) pays on `payLane(pay_ref)` nonce 0 under the delegate's own passkey policy, limits per
payment and per period, payee, expiry, each `pay_ref` once, `payment_settled.from` = the mandate id; `mtx_revoke` (op 3)
once, by the owner or the delegate, no nonce, and not a value op (the policy never blocks it); `mandate_refund(id)`
(no `mtx_` prefix) is permissionless after revocation or expiry and refuses a refund that would move 0; no epoch, no
pay-meta entry; pay and revoke sign `extra = sha256([])`. Measured: open 3.918, first pay 4.093, next 3.875, revoke
3.383, refund 2.705 Tgas (`smartcontracts/near/runs/2026-10-28-near-mandate-fix1.txt`). BUILT.

## <a id="dex"></a>11. DEX

<a id="NET-NEAR-16"></a>**NET-NEAR-16** — **The NEAR DEX is an escrow, relayer-bound and fill-or-kill.** The relayer lane
calls `dex.settle(order_a, auth_a, order_b, auth_b)`; each order's `relayer` is None, the predecessor, or — through
the router's executor (fixed in `Dex::new(executor)`) — the transaction signer, i.e. the bound lane's own relay
([CTR-DEX-09](../contracts/dex.md#CTR-DEX-09), [NET-NEAR-31](#NET-NEAR-31)); the DEX calls `token_a.mtx_trade` and `token_b.mtx_trade` (leg op 1,
`relayer = to = dex`, `extra = sha256(Borsh(Order))`, a fourth argument `receiver: Holder` registers the payout receiver
and cannot redirect it); each leg moves into the escrow, the join callback pays both out when both arrived, else refunds
the one that did; `refund_expired` (permissionless, after expiry) covers a lost callback. Orders are keyed (holder,
lane, nonce), any nonce ≥ `min_nonce`, each closes once; one settle per leg digest; `settle_id = sha256(digest(op_a) ‖
digest(op_b))`. A failed counter-leg **closes** the maker's order (its funds come back); clients therefore bind orders
to a relayer by default (`Order.relayer = Some(lane)`): only that lane settles them, directly or through the router in
its own relay transaction. `settle` refuses a leg deposit share below `LEG_STORAGE_MAX_BYTES` (2,200 B; the worst
case, a lazily opened 12-member msig with 8 origins of 128 B, measures 1,988 B) and a submit within `SETTLE_MARGIN_S`
(60 s) of the earliest order expiry or leg op `valid_until`, so no submitter can make a settle a no-op whose router fee
is released ([NET-NEAR-30](#NET-NEAR-30)). The DEX derives each leg's static gas from its auth (`leg_gas` = 17
Tgas + 25 per passkey signature + 1 per ed25519 / secp256k1) and refuses `settle` unless prepaid ≥ 9 + 18 +
`leg_gas(a)` + `leg_gas(b)`; a passkey field above 1 KiB is refused on a leg. Events carry the leg digests
(`matched`, `match_failed`, `refunded`; token `order_filled`, `order_cancelled`, `nonces_invalidated`). No DEX fee, no
partial fill. Measured at Task 8: a settle of two passkey legs 59.965 Tgas (`smartcontracts/near/runs/2026-10-28-near-dex.txt`),
an ed25519 settle 19.896 (`…/2026-10-28-near-dex-fix2.txt`). BUILT.

<a id="NET-NEAR-30"></a>**NET-NEAR-30** — **A router-paid settle never releases the fee for a no-op.** `settle`
refuses (panics, so the router refunds) a leg deposit share below `LEG_STORAGE_MAX_BYTES` × the byte cost (2,200 B:
worst case 1,988 B measured, `smartcontracts/near/runs/2026-10-29-near-final-fix.txt`) and a submit within
`SETTLE_MARGIN_S` = 60 s of `min(order expiries, leg op valid_until)`; each token returns its leg's excess to the
signer, and the node attaches entry + 2 + 2 × max(the larger leg, the pin). BUILT.

<a id="NET-NEAR-31"></a>**NET-NEAR-31** — **CTR-DEX-09 holds on the paid path.** `Dex::new(executor)` fixes the
router's executor; an order bound to lane R passes when the predecessor is R, or when the predecessor is that executor
and the transaction signer is R (the lane whose `relay` carries the settle). The node relays orders that are open, bound
to its own lane or bound to the executor, and refuses to start when the DEX's `executor()` is not the router's. BUILT.

<a id="NET-NEAR-32"></a>**NET-NEAR-32** — **Never pay a keyless SCaaS account.** The node refuses a job when any payee
it carries is a configured token, the router, its executor or the DEX: the payment (outside its own open mode), a
router target op's `to` on `mtx_pay` / `mtx_pay_meta` / `mtx_transfer` / `mtx_execute_transfer` / `mtx_mandate_pay`, and
a wrapped or routed `mtx_mandate_open`'s `terms.payee`. The token itself refuses only itself: it does not know the
router or executor ids (spec row 12), so the rule is node-side. BUILT.

## 12. Deploy

<a id="NET-NEAR-19"></a>**NET-NEAR-19** — **Every SCaaS NEAR account is keyless and not upgradeable.** Token, DEX, router
and executor are deployed, initialised (`#[private] new`), lanes registered, then **every access key is deleted** in
the same run; no contract code issues `DeployContract`, `AddKey`, `DeleteKey`, `DeleteAccount` or a whole-balance
transfer (source scan `check_no_authority.sh`, covering every near-sdk 5.30.0 authority API including
`promise_batch_action_add_key`; the list is explicit so `mtx_add_key` is not flagged); no NEP-591 global contract.
Deploy gate: `view_access_key_list` empty for every account, else the run fails; the node re-checks at start and holds
the chain `halted` ([NODE-STO-07](../node/store.md#NODE-STO-07)). The router's upgrade authority equals the token's:
none. BUILT.

<a id="NET-NEAR-20"></a>**NET-NEAR-20** — **`deploy.sh near <rpc>` is resumable and refuses to adopt foreign
accounts.** Accounts are sub-accounts of the funding account F: `<symbol>.F` per `NEAR_TOKENS` entry, `dex.F`,
`relayfee.F`, `relayexec.F`; each is created, funded (code storage + `NEAR_FUND`, default 2 NEAR), given a temporary
full-access key and its code in one transaction; it signs its own `new`; F registers every `NEAR_LANES` lane on every
token. `NEAR_LANES` (each `^[0-9a-f]{64}$`) and `NEAR_TOKENS` are validated before any RPC step; temporary keys go to
`<deployments>/<genesis>.<funder>.resume.json` (0600, fsynced with its directory, git-ignored; a deployments directory
in the checkout that git does not ignore is refused) before use; every step is skipped when done; a resume file holding
accounts outside the plan, an existing account with other code, or a token whose `ft_metadata` or `admin()` differ, is
refused ("not adopted"). Key deletion and the gate run last; then `deployments/<genesis>.json` (network, chain id,
funder, admin, tokens, dex, relayfee, relayexec, lanes, code hashes, time) is written and the resume file removed.
`devnet.sh near up|down` runs the near-sandbox binary near-workspaces downloaded (no docker; RPC 32060, p2p 32061;
`--max-gas-burnt-view "300 Tgas"`, validity period 600, `gc_num_epochs_to_keep` 100000). BUILT.

## 13. Conformance

**Contracts** (`smartcontracts/scripts/test.sh near`, near-workspaces on near-sandbox, one test thread): token, account,
metatx, mandate, DEX, wrappers, router suites, each with RED logs and mutation runs (`runs/*-mutations.txt`), against
an implicit relayer since T19 fix 1; latest GREEN `smartcontracts/near/runs/2026-10-29-t19-fix4.txt` (rc=0). **Node**:
423 lib tests and clippy at the last NEAR adapter change (`scaas-node/runs/2026-10-29-near-adapter-t19-fix3.txt`), RED
→ GREEN per fix. **e2e** (`scaas-node/tests/e2e_near.rs`, 10 tests, `smartcontracts/near/runs/2026-10-28-near-e2e.txt`,
rc=0): deploy gate with a key left, resumable deploy, pay → mined (node tx hash = RPC's, replay `consumed`, stale nonce
`Rejected`), pay-meta, wrapper jobs (incl. 13 passkeys), router release / refund / timeout, native `ft_transfer` events,
lanes anti-lock.

| Job (e2e, protocol 88) | Burnt in its receipt / in all (Tgas) | Prepaid | Quote (NEAR) | Lane decrease (NEAR) |
|---|---|---|---|---|
| `mtx_pay`, ed25519 | 3.628 / 11.477 | 22 | 0.005721 | 0.003735 |
| `mtx_pay_meta` | — | — | 0.005722 | 0.003758 |
| `relay_fee_add_origin`, ed25519 entry + payment | 4.612 / 12.480 | 23 | 0.006505 | 0.004516 |
| `relay_fee_mandate_open`, 12-passkey msig + passkey payment | 266.291 / 274.368 | 294 (headroom 27.709) | 0.043226 | 0.040284 |
| router → `dex.settle`, released | 2.255 in `relay` / 180.248 | 166 | 0.049698 | 0.024345 |
| router → listed target that fails, refunded | — | — | 0.028020 | 0.006667 |
| router in flight, timed out + `relay_timeout` | — | — | 0.030530 | 0.006849 |

Contract-test figures (sandbox): `transfer_to_ua` 2.40 Tgas to an existing UA, 3.01–3.02 creating one
(`…/2026-10-28-near-token-fix1.txt`); a key op about 2.4 Tgas ed25519 / secp256k1, 22.1 passkey
(`…/2026-10-28-near-account-fix2.txt`); two-passkey wrappers 44.3–45.9 Tgas (`…/2026-10-28-near-relayfee-fix1.txt`);
`relay_hold` 4.557 ed25519 / 24.215 passkey (`…/2026-10-29-t19-fix1.txt`).

## <a id="limitations"></a>14. Limitations

<a id="limitations"></a>

- **Router residual** (spec §3.8): a target that succeeds and whose callback is lost is refunded at timeout (the
  relayer did the work unpaid); a very late `on_call` failure (more than an hour past the timeout) asks a deposit return
  without an owed / retry path. A stuck escrow is reported reverted 1 h after its deadline while anyone's
  `relay_timeout` can still refund it later.
- **Relayer-only losses:** a `relay_hold` that panics (a non-SCaaS token, a gas-pin breach) strands the forwarded
  deposit at the keyless router; an executor receipt failure refunds `target_deposit` to the router, `return_deposit`
  pays from the executor's float or stays owed; a trade leg that panics leaves its deposit refund at the keyless DEX
  (≤ one leg's storage deposit; NEP-616 `refund_to` is not assumed); DEX `prune` on the router path refunds the settle
  deposit to the executor (the fee's `target_deposit` covers it); a 12-member + 12-member msig wrapper (about 490 Tgas)
  cannot fit and fails atomically (the node refuses more than 13 passkey signatures per wrapper job).
- **Payer-paid residuals:** listed third-party targets are operator-vouched per method (arguments and method existence
  unchecked; 5 Tgas floor); `mandate_pay` near expiry, relayer races and DEX leg failures cost the payer a fee; the
  same-token balance guard covers the payment's own token only; the 120 s margin refuses honest short-lived payments.
- **`_check` view gaps:** a payment signed by a key the entry adds (check refuses, call succeeds); a revoke whose sweep
  funds the paying owner (check may refuse, call succeeds); an entry that removes the payment key (check passes, call
  fails: relayer gas lost).
- **Stale sequence after a timeout:** the escrow's `relay_timeout` is sent from the relaying lane while the job holds
  it, so the next job's first sequence read may be stale: at worst one `Rejected` requeue.
- **Executor balances are public:** any relay can forward `ft_transfer` with the executor as predecessor, so never send
  tokens to the executor (a wrapper's open-mode fee routed via the executor included; the node refuses every payee
  that is the executor, [NET-NEAR-32](#NET-NEAR-32)). Relayer-bound token ops through the router need `relayer = None`
  (the executor is the predecessor); a DEX order bound to a lane settles through the router in that lane's own relay
  (the DEX checks the signer); a second payer for the same call and salt waits
  until the first settles (pending is keyed by `ref`).
- **Events:** NEP-366 delegate actions and third-party contracts calling a token are not indexed; a busy chain needs
  NEAR Lake or an indexer feed.
- **Indexer stall (accepted risk until fixed, final review node I2):** one non-final transaction sent to a watched
  contract (a token, the router or the DEX) stops NEAR indexing for the whole chain: `events()` refuses the range and
  the next poll retries it, so the client cursor does not move. A NEP-519 yield keeps a transaction short of `FINAL` for
  about 200 blocks and can yield again, so anyone holding one token unit (`ft_transfer_call` to a yielding receiver) or
  calling the router's `relay` with a yielding target stalls the event feed cheaply (≈ 0.0005 NEAR per resend). No funds
  are lost and relaying is not affected (job status is read per transaction). The fix (index each watched receipt by its
  own final outcome, park non-final transactions) is a TODO item.
- **A router-bound payment can be burnt:** a refunded hold spends the payment lane, so any relayer can void a router
  payment op by relaying it with a `target_gas` the target cannot run on; the payer is refunded and re-signs with a new
  salt; no funds move.
- The whole-balance transfer action cannot be caught by the source scan; every NEAR change is reviewed for it. The test
  fixtures build into `target/near`, so deploys name their crates explicitly. The node's passkey origin parser must
  follow every change to `origin_of` (vectors guard it; a non-UTF-8 origin is covered by reasoning only).
- No public-network deployment exists.

## 15. References

NEP-141, -145, -148, -297, -366, -413, -591, -616, -635 (github.com/near/NEPs); docs.near.org (storage staking,
cross-contract calls, gas); nearcore 2.14.0 (protocol 88); near-sdk-rs, near-workspaces-rs, near-sandbox; Wallet
Selector `signMessage` (github.com/near/wallet-selector).

## <a id="paymeta-relayfee"></a>Pay-meta and relay fee (metatx split)

Rules [CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26) and [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27); the NEAR
form below. Status BUILT.

**Pay-meta:** `mtx_pay_meta` (NET-NEAR-07), once per `(payer, payId)` for good; plain `mtx_pay` settles the same op
without `payment_meta`.

<a id="NET-NEAR-14"></a>**NET-NEAR-14** — **The token's own fee-less signed entries are fee-paid by static wrappers
`relay_fee_<entry>`, one receipt, atomic.** Thirteen wrappers: the key ops (`add_key`, `remove_key`, `add_origin`,
`remove_origin`, `set_guardian`, `set_policy`, `start_recovery`, `finish_recovery`, `cancel_recovery`),
`mandate_open`, `revoke`, `cancel`, `invalidate_nonces`, each with a `relay_fee_<entry>_check` view. A wrapper runs the
entry, then the shared pay body through `routed_plan` with `pay_ref = ref`, `lane = payLane(ref)`, nonce 0 and the
token's own id as relayer marker; open mode (`to` = the token) pays the predecessor, a bound payee directly. `ref` =
`keccak256("scaas.relayfee" ‖ network ‖ u8 len ‖ token id ‖ keccak256(call) ‖ salt)`, `call = u8 len ‖ full entry name
‖ Borsh(entry arguments)`, recomputed from the Borsh re-encoding. A refused or no-op entry (a second cancel or revoke,
cancel recovery without one, an unknown key, a non-increasing invalidate) panics, so nothing is paid; revoking an
expired mandate and setting the same policy are state changes and are charged. `relay_fee_paid {ref, target, token,
payer, payee, amount}` is emitted last. `ft_transfer_call` and `mtx_trade` are not wrapped. BUILT.

<a id="NET-NEAR-15"></a>**NET-NEAR-15** — **Cross-contract targets go through an escrow router with a callback; refund
wins whenever success is not provable.** `relay(target, method, args, target_gas, target_deposit, token, op,
auth)`: shape (`pay_ref == ref`, `lane == payLane(ref)`, nonce 0, `relayer` = router, `op.to ≠ executor`), `target ∉
{router, executor}`, args ≤ 16,384 B, attached deposit ≥ entry storage + payee registration + 2 yocto +
`target_deposit`, prepaid gas ≥ `relay_gas`; `pending[ref] = {id, token, payer, payee or open, relayer, target, amount,
deposit, stage, deadline = now + 3,600 s}`. Then token `relay_hold` (pay checks, consumes the lane, moves the amount to
`held`), `on_hold`, the executor's `exec` (attaches exactly `target_deposit`, then a trailing 0-yocto transfer so the
router reads the target's own receipt: the target succeeded = success, child promise failures included), `on_call` →
`relay_release` (payee stored at hold; open → the recorded relayer) or `relay_refund` + the executor's
`return_deposit`, `on_settle` (deletes the entry, returns its deposit, emits `relay_fee_paid`). Every callback checks the
entry's id and stage, so a late callback pays nothing. `relay_timeout(ref)`, anyone, after the deadline: refund. The
router and executor have no admin and no access key; `relay_check(…)` quotes deposit and gas for a 64-character relayer.
BUILT.
