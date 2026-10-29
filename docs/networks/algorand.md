# Algorand (Algorand Python, Puya)

Common rules for every family: [networks/README](README.md). Status: apps, adapter and clients **BUILT** on branch
`near-algorand` (apps at `smartcontracts/algorand/contracts/`: `token`, `account`, `mandate`, `dex`, `relayfee`, the
executor LogicSig; adapter `scaas-node/src/adapters/algorand.rs`; end to end `scaas-node/tests/e2e_algorand.rs`;
devnet: an Algorand localnet, algod 5.0.5 in docker under a memory cap). Nothing is deployed on a public network:
`deploy.sh algorand` has run only on the localnet; testnet and mainnet deployments are the owner's call. Design:
[2026-10-28-near-algorand-design.md](../superpowers/specs/2026-10-28-near-algorand-design.md) §4 and §5 (the spec);
rulings: [decisions.md §36](../decisions.md#36-networks--algorand). NEAR, built in the same item, has its own page
([near.md](near.md)); nothing here applies to it.

**Contents**

1. [Overview](#1-overview)
2. [Apps and accounts](#2-apps-and-accounts)
3. [Keys](#3-keys)
4. [Lanes](#4-lanes)
5. [Payload](#5-payload)
6. [Signatures](#6-signatures)
7. [App methods](#7-app-methods)
8. [Relayer](#8-relayer)
9. [Finality and events](#9-finality-and-events)
10. [Mandate](#10-mandate)
11. [DEX](#dex)
12. [Deploy](#12-deploy)
13. [Conformance](#13-conformance)
14. [Limitations](#limitations)
15. [References](#15-references)

## 1. Overview

<a id="overview"></a>

Algorand transactions carry no account sequence (replay protection is the txid within `FirstValid..LastValid`), fees
can be pooled in an atomic group of up to 16 transactions, and an app call is synchronous, inner calls included. An
ASA needs the receiver's opt-in, which a UA id cannot give, and every account must hold ALGO for its minimum balance.
So Algorand uses the contract-level path of every other family: the subject signs a `MetaOp` v1 (§5), an app verifies
it, and a relayer lane submits the group, paying the fees and the exact minimum-balance requirement (MBR) of the boxes
the group creates.

<a id="NET-ALG-01"></a>**NET-ALG-01** — **Algorand has the full SCaaS feature set from the start.** Token with
`mtx_pay`, the relayed pay and `mtx_pay_meta` ([CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26)); mandate; DEX;
smart-key and passkey UA accounts; the relay-fee router ([CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27)); the
`scaas-node` adapter; `clientkeys`, `ua-rs` and `ua-qt` signing; a localnet devnet, tests and shared vectors (owner
2026-10-28). Out of scope: Zether and PQZ, PQ signers, the asset suite, token wrappers and the tender
([NET-ALL-17](README.md#NET-ALL-17)–[19](README.md#NET-ALL-19) keep them PLANNED), the mesh (job API only),
`MetaCall` / `MetaTransfer` ([NET-ALL-26](README.md#NET-ALL-26)), public testnets and mainnet, receiver-pays. BUILT.

<a id="NET-ALG-02"></a>**NET-ALG-02** — **The relayer pays every MBR, exactly; users hold no ALGO.** A call that creates
boxes is preceded in its group by a payment to the app address of **exactly** their MBR (the app's `AcctMinBalance`
after minus before; 0 ⇒ no payment, a 0-amount payment is refused; a payment with `CloseRemainderTo` or `RekeyTo` is
refused); an app that creates boxes in another app forwards that part by an inner payment just before the inner call,
which checks its own part exactly. The relayer is reimbursed through the fee: the node's fee floor covers the group's
fees and MBR (owner 2026-10-28; the fee rule a controller call accepted by the owner). BUILT.

<a id="NET-ALG-04"></a>**NET-ALG-04** — **Balances and records are permanent; no app has local state.** No box is ever
deleted and no MBR refunded (a record that shrinks keeps its MBR); lanes are kept for good, so
[CTR-MTX-04](../contracts/metatx.md#CTR-MTX-04) and [NET-ALL-01](README.md#NET-ALL-01) hold by construction; `OptIn` is
refused everywhere; Algorand has no escrow entry to prune. BUILT.

<a id="NET-ALG-05"></a>**NET-ALG-05** — **Apps are Algorand Python built with puyapy 5.10.1; the build is pinned by
`artifacts.json`.** algorand-python 4.0.0, py-algorand-sdk 2.12.0 for the tests (no algokit-utils), algod 5.0.5 on the
localnet (`ConsensusProtocol: future`, as AlgoKit's localnet: app-call args 2,048 B (4,096 accepted on future), logs
1,024 B per transaction, budget 700 per app call, the same as mainnet today). `smartcontracts/algorand/artifacts.json`
maps each program (token, account, mandate, dex, relayfee, plus the executor template's prefix and suffix) to its
approval and clear `sha512_256`; `test.sh algorand` fails when the committed file differs from a fresh build. BUILT.

## 2. Apps and accounts

<a id="accounts"></a>

| App | Holds | Notes |
|---|---|---|
| `token` (one per token) | ARC-200 ledger `"b" ‖ address` → uint256; UA ledger `"u" ‖ id`; lanes `"l" ‖ sha256(kind ‖ holder ‖ lane)` → next nonce; allowances `"a"`; orders sold in it `"o"` (1 filled, 2 cancelled) and order lanes' `"n"` (`min_nonce`) | the account app id fixed at creation |
| `account` (one per deployment) | subject records `"s" ‖ kind ‖ id` (keys, origins, guardian, recovery, key nonce, policy) | tokens, mandate and DEX call `verify` / `verify_key` by inner app call; keys are shared by every token |
| `mandate` | mandates `"m" ‖ token ‖ id`, their lanes | funds are its own token balance under its app address |
| `dex` | nothing but the router app id | both legs in one atomic call |
| `relayfee` (router) | one creation-time global, `salt` | the executor LogicSig is derived from it |

<a id="NET-ALG-03"></a>**NET-ALG-03** — **The token is an app-held ARC-200 ledger in boxes, not an ASA.** ARC-200 methods
through ARC-4; amounts are uint256 in ARC-200 and uint128 in `MetaOp`, supply ≤ 2^128 − 1. The token's own address is
the UA pool: `arc200_balanceOf(app)` = the UA total, a move with a UA side is an `arc200_Transfer` to or from it plus
`UaTransfer` (a seventh event beyond spec §4.2's list). `arc200_approve` only when the sender is an app (inner call)
and the spender an app address (the spender = the first foreign app whose address equals it). ARC-200 zero and self
transfers are allowed, the `mtx_*` entries refuse them; a zero-address receiver is accepted (a burn-like lock); an
`mtx_*` payment to the token's own address is refused. Events in order: [`PaymentMeta`], `MetaTransactionExecuted`,
`arc200_Transfer` / `UaTransfer`, [`PaymentSettled`]; a failed group logs nothing. A read-only `mbr_needed(op)` quotes
the MBR. BUILT.

<a id="NET-ALG-20"></a>**NET-ALG-20** — **Native UA kind `0x0018 algorand-address`.** Id = the address's 32-byte public
key. Accepted signature: `ed25519verify_bare` by the address's **current authority** (`AcctAuthAddr` if set, else the
address); an address rekeyed to a LogicSig or a multisig signs through an account record instead (a rekey is readable
on chain). Not a registry: the kind names an Algorand address as a holder or msig member ([accounts.md](../contracts/accounts.md)
§1.6 table). An `algorand-address` member of an msig pays only if the relayer lists it in the target's `accounts`. BUILT.

MBR (µALGO; box MBR = 2,500 + 400 per name and value byte):

| Box / account | MBR | Log |
|---|---|---|
| balance `b`, UA `u`, allowance `a`, the DEX's per-token box, a payout box | 28,500 | `smartcontracts/algorand/runs/2026-10-29-algorand-relayfee-fix1.txt` |
| lane `l`, `min_nonce` `n` | 18,900 | same |
| order `o` | 16,100 | same |
| subject record: 2,500 + 400 × (34 + 118 + 32 per key or origin); ed25519 UA 76,100, passkey UA + origin 88,900, +12,800 per key or origin; a native signer's key-op record 63,300 | as stated | `…/2026-10-28-algorand-account-fix2.txt` |
| mandate box (41 B name + 204 B value) | 100,500 | `…/2026-10-29-algorand-mandate-fix1.txt` |
| an app address's base minimum (each app is funded to it at deploy); the deployer's own minimum grows by each app's schema and pages, read from algod (the e2e's partial deploy hit "below min 1035500") | 100,000 | `…/2026-10-29-algorand-relayfee-fix1.txt`; `…/2026-10-28-algorand-e2e.txt` |

Approval programs (`smartcontracts/algorand/runs/2026-10-28-algorand-e2e.txt`): account 4,945 B (2 extra pages), token
3,661 B (1), mandate 2,304 B (1), relayfee 857 B (0), dex 961 B (0); clear programs 4 B; executor LogicSig 85 B (`…/2026-10-29-algorand-relayfee-fix1.txt`).

## 3. Keys

<a id="keys"></a>

<a id="NET-ALG-07"></a>**NET-ALG-07** — **One `account` app per deployment holds every subject's keys.** Up to 8 keys
and 8 origins (≤ 128 B), a guardian, a pending recovery, a key nonce and `policy`; a record stores key ids and origin
hashes (the node rebuilds key sets from the key-op events). `verify(kind, id, digest, auth)` is the value-op check
(`POLICY_PASSKEY_FOR_VALUE` applies; a refusal fails rather than returning false; a native wallet signature is outside
the policy), `verify_key` the check for ops that move no value (revoke, cancel, invalidate). A UA record opens lazily on
its first signed op (a passkey record with the assertion's origin); natives may sign key ops (a record is opened for the
nonce). Key ops 6–12 sign `extra = sha256(ARC-4 parameter tuple)`; set_policy is op 10 with params `[6, policy]`;
recovery: the guardian (checked before the signature; none = the zero holder) signs `mtx_start_recovery` and, after
`RECOVERY_DELAY_S` = 172,800 s, `mtx_finish_recovery` (op 11, params `[7]`), which **adds** the key
([CTR-ACC-03](../contracts/accounts.md#CTR-ACC-03)); start and finish refuse a key already present or a full 8-key set
(fail fast: keep a slot free). `add_origin` is idempotent; an msig refuses a repeated signing key; a LogicSig- or
msig-rekeyed address can add keys natively but not remove them (NEAR parity). BUILT.

<a id="NET-ALG-09"></a>**NET-ALG-09** — **An msig has at most 3 members.** `MSIG_MAX_MEMBERS` is bound by the 2,048 B of
app-call arguments, not by budget: with a Chrome-shaped `clientDataJSON` (286 B: a 64 B origin and Chrome's extra
member) a passkey member costs 493 B, so 3 members take 1,823 B and 4 take 2,316 B (a 134 B `clientDataJSON` would
allow 4 at 342 B each). A passkey field is ≤ 1 KiB. BUILT (493 / 2,316 B: `smartcontracts/algorand/runs/2026-10-28-algorand-limits.txt`;
1,823 B: `…/2026-10-28-algorand-account-fix2.txt`).

<a id="NET-ALG-08"></a>**NET-ALG-08** — **Apps raise their own opcode budget with relayer-paid inner budget calls.**
Each account entry and signature check calls `ensure_budget(cost + 1,000)`: inner budget calls paid from the group's
fee credit (fee pooling), never from an app's balance (spec §4.6 had only top-level calls; inner calls are pooled 256
per group on algod 5.0.5, so the ceiling, about 180,000, never binds). Two paths do not raise their own budget:
`token.mtx_pay_meta`'s work before its first check (above 700) and the router's tail after its inner pay; they pass
because the node's group carries resource budget calls and, when simulate reports "dynamic cost budget exceeded", one
more bare call per report (up to 16 transactions). A third-party relayer that adds none gets that refusal from
simulate: no loss. BUILT; the contract-side `ensure_budget` for the two paths is an open owner question (TODO.md).

## 4. Lanes

<a id="lanes"></a>

Lanes as spec §2 row 6: one box per `(kind, holder, lane)`, the next nonce, never removed; `mtx_pay` on any lane at its
next nonce, pay-meta on `payLane(pay_ref)` nonce 0. `MAX_PAY_META_BYTES` = 507 (the 1,024 B log limit: `PaymentMeta`
plus the other events; the same on the native and the passkey-UA path; app args 902 / 1,141 of 2,048 B).

<a id="NET-ALG-19"></a>**NET-ALG-19** — **A relayer lane is an ed25519 account at `m/44'/283'/0'/0'/i'` with no
head-of-line at all.** SLIP-10, every level hardened (corrects README's earlier `m/44'/283'/0'/0/i`). Head-of-line
([NET-ALL-03](README.md#NET-ALL-03)): Algorand has no account sequence, so two groups of one lane, or of one subject on
two apps, never wait for each other; `sequence` = the last round, `LastValid` = `FirstValid` + up to 1,000 rounds,
kept within the op's `valid_until` from the measured round time (no measured round time ⇒ the job is retried). A lane
must hold at least algod's `min-balance` (start check); "balance B below min M" naming a lane is retried, naming an
app is a refusal. The fee breaker keeps spent txids for `SPENT_KEEP` = 1 h. BUILT.

## 5. Payload

<a id="payload"></a>

`MetaOp` v1, an ARC-4 static tuple, big-endian, 291 B after the label: network (the genesis hash, `global
GenesisHash` at run time) ‖ contract (the token app address, 32) ‖ op (u8) ‖ `from`, `to` (holder = kind u8: 0 address,
1 UA id ‖ 32) ‖ `relayer` (32, zero = any) ‖ amount (uint128) ‖ `pay_ref` ‖ lane ‖ nonce (uint64) ‖ `valid_until`
(uint64) ‖ `extra`; digest = `sha256("scaas.metaop.v1" ‖ tuple)`. Op codes as NEAR ([near.md §5](near.md#5-payload)),
except 13: unused on Algorand (the mandate's funding op is the open, NET-ALG-10). `payId` / `payLane` / `ref` with the
`keccak256` opcode, byte for byte the EVM derivation.

<a id="NET-ALG-21"></a>**NET-ALG-21** — **The Algorand encodings fixed by the vector generator.** Every `u16` length in
a router `call` is big-endian; box value widths 32 B; `call` hashes the entry's full ARC-4 method signature; salt = the
payment op's payer-signed `extra`, always; the generator's placeholder app ids 1001–1003 are replaced by the deployed
ones. Vectors: `smartcontracts/algorand/vectors/algorand-vectors.json` (read by the apps' tests, the adapter, the
clients); `vectors/algorand-tx.json` pins the node's msgpack against py-algorand-sdk. BUILT.

<a id="NET-ALG-22"></a>**NET-ALG-22** — **Every time check compares with `Global.latest_timestamp`**, the previous
block's timestamp: `valid_until`, mandate and order expiry, the recovery delay. A signer allows for one block of lag.
BUILT.

## 6. Signatures

<a id="signatures"></a>

<a id="NET-ALG-06"></a>**NET-ALG-06** — **Native addresses sign the wallet's sign-bytes form; UA and record keys carry a
tagged auth.**

| Kind | Auth | Check |
|---|---|---|
| native address | 64-byte signature, untagged | `ed25519verify_bare` (1,900) by the current authority over `"MX" ‖ "scaas.metaop.v1:" ‖ hex(digest)`; not `ed25519verify` (it signs `"ProgData" ‖ program hash ‖ data`) |
| ed25519 | tag 1 | `ed25519verify_bare` over the same text |
| secp256k1 | tag 2 | `ecdsa_verify Secp256k1` (1,700) over the digest; high-s refused by the opcode |
| P-256 passkey | tag 3 | [NET-ALL-04](README.md#NET-ALL-04): `ecdsa_verify Secp256r1` (2,500) over `sha256(authData ‖ sha256(clientDataJSON))`, low-s and the bounded grammar in Puya, byte-identical with the node's parser (40 parity rows, `vectors/webauthn-origin.json`, run on the AVM: `smartcontracts/algorand/runs/2026-10-29-algorand-origin-parity-localnet.txt`); `base64_decode` is strict |
| msig (kind 288) | tag 4 | members tag 1–3 or an `algorand-address` member's 64-byte signature; no nested msig |

**Wallet support (checked 2026-10-29).** ARC-60 ("Algorand Wallet Arbitrary Signing API") is still Draft and defines
`signData(StdSigData, metadata)` over `sha256(data)` with an `authenticatorData` domain — a different form from SCaaS's.
What wallets sign today is algosdk's `signBytes` form, `"MX"` ‖ bytes, which Pera Connect's `signData` and algosdk's
`verifyBytes` use; SCaaS checks exactly that. ARC-47 (logic-signature templates) is not a signing API; the executor
template here is SCaaS's own. The `"MX"` form may change to ARC-60's when wallets ship it (spec §11).

<a id="NET-ALG-23"></a>**NET-ALG-23** — **Clients sign Algorand ops with the shared vectors.** `clientkeys`
`src/algorand.js`, `ua-rs` `algorand` and `ua-qt`: digest = `sha256` of the full labelled encoding; `relay_ref` target =
the target app's address bytes; `buildRelayFee` needs the target app; `buildPayMeta` and the relay-fee builder enforce
nonce 0; `passkeyAssertion` as NEAR's (challenge, strict UTF-8, `webauthn.get`, low-s). Key ops need no fan-out (one
account app). BUILT.

## 7. App methods

<a id="contracts"></a>

```text
token:    arc200_name/symbol/decimals/totalSupply/balanceOf/allowance/transfer/transferFrom/approve,
          ua_balance_of, transfer_to_ua, mint, mbr_needed, lane_nonce, filled, min_nonce, budget
          mtx_pay, mtx_pay_meta, mtx_transfer, mtx_execute_transfer, mtx_trade, mtx_cancel, mtx_invalidate_nonces
account:  verify, verify_key, verify_mbr, key_info, key_nonce, add_key_native, budget,
          mtx_add_key, mtx_remove_key, mtx_add_origin, mtx_remove_origin, mtx_set_guardian, mtx_set_policy,
          mtx_start_recovery, mtx_finish_recovery, mtx_cancel_recovery
mandate:  mtx_mandate_open, mtx_mandate_pay, mtx_revoke, mandate_refund, mandate, budget
dex:      settle, carry, budget
relayfee: relay, relay_ref, executor, budget
```

`budget` is a bare method (no arguments) the relayer's budget calls use. algod `simulate` is the check (no `*_check`
views).

## 8. Relayer

<a id="relayer"></a>

<a id="NET-ALG-16"></a>**NET-ALG-16** — **Adapter jobs, ids and states.** `[[chains]] network` = the genesis hash in
base64, chain key `algorand:<b64>`; `params.account_app` (required), `token` app ids in `tokens`, `mandate_app`,
`dex_app`, `relayfee_app` (no `relay_fee.router`: refused with a pointer), `algod_token_env` (env var of the API
token); price key `relay_fee.min_microalgo_value = { "<token app id>" = µALGO per base unit }`; listed targets
`relay_fee.targets = { "<app id>" = ["method(args)ret", …] }`, matched by ARC-4 selector (an app of the deployment, an
empty list or `add_key_native` is a startup error). Job `payload` = hex of label ‖ ARC-4 `MetaOp`, `signature` = hex of
the entry's `auth`, `contract` = the token app id; a relay fee adds `op.extra.call` and the target's `accounts`,
`apps`, `boxes` and `carries` (any other key refused). Tx id = `0x` + hex of the lane's main transaction's txid.
Confirmed ⇒ mined (one round); a pool error ⇒ reverted, never requeued; there is no refund on Algorand, so
`op_consumed` answers for every job kind. Quote = the group's pooled fee + its MBR payments (no resend term: a group
lands at most once). Fee per transaction = max(min fee, algod `fee` per byte × the widest signed size), + one min fee per
inner transaction. Startup: genesis = network; every app exists and its approval and clear hashes equal
`artifacts.json` (else the chain is halted); token and mandate `account_app` and DEX `router_app` = config; the
router's salt rebuilds an off-curve executor equal to `executor()`; every lane and the router address hold their
minimum balance. BUILT.

<a id="NET-ALG-17"></a>**NET-ALG-17** — **Simulate is the check: a discovery run, then the exact group.** Discovery
simulates with unnamed resources allowed, a 64-inner fee credit and `extra-opcode-budget` = 700 × (16 − the group's
transactions) (the most its budget calls could add); its unnamed resources go onto bare budget calls on the token (≤ 4
accounts, ≤ 8 references each). The exact group runs with unnamed resources refused and its own budget, re-simulated
until the inner count settles; on "dynamic cost budget exceeded" one more bare budget call is appended (each distinct,
by its number of empty box references: two equal calls have one txid) until the group is full, then the job is refused.
The node signs only the group its exact simulate just ran, so a failing group costs nothing. Untrusted input: msgpack
depth ≤ 64 (real blocks reach about 35), every decode returns `Result`. BUILT.

<a id="NET-ALG-18"></a>**NET-ALG-18** — **Static checks before simulate.** The payment is op 0 on this network, its
`contract` a configured token; never pay an app of the deployment or the executor (the router as open-mode marker
excepted), also for mandate `terms.payee` and a mandate pay's `to`; pay-meta commitment and cap 507; relay fee: the
router configured, relayer = router address, `ref` from the call bytes with salt = `extra`, the target ∉ {0, router},
no `add_key_native`, the allowlist (the tokens' 6 entries, the account app's 9 key ops, the mandate's 3, DEX `settle`,
listed targets per method, exact argument count); target ops with relayer zero (the mandate funding op names the
mandate), valid ≥ 120 s; payees never an app or the executor; mandate expiry ≥ 120 s; settle orders open or bound to
this lane, both tokens configured, expiries and legs ≥ 120 s; passkey origins parsed as `account.py`; a fee that is the
node's × `min_microalgo_value` ≥ fee + MBR. DEX pair checks, same-token balance and unopened-subject origins are not
replicated: the exact simulate runs the target before the router's pay in one state. BUILT.

```toml
[[chains]]
family = "algorand"; network = "<genesis hash, base64>"  # as scaas-node/node.example.toml
rpc_urls = ["http://127.0.0.1:4001"]                     # algod REST, simulate enabled
lanes = [0, 1]
tokens = [{ address = "1001", decimals = 6 }]            # token app ids
params = { account_app = 1004, mandate_app = 1005, dex_app = 1006, relayfee_app = 1002, algod_token_env = "SCAAS_ALGOD_TOKEN",
           relay_fee = { min_amount = 1, min_microalgo_value = { "1001" = 1000 }, targets = { "2001" = ["ping(uint64)void"] } } }
```

## 9. Finality and events

<a id="events"></a>

One-round finality: a confirmed round is final. Events are ARC-28 logs of algod blocks (msgpack, the top-level txid
recomputed from the stored transaction and `gh`); `log_index` counts a top-level transaction's logs depth first (an
app's own, then its inner transactions'). Tokens: `PaymentSettled`, `PaymentMeta`, `MetaTransactionExecuted`, Transfer
rows (`UaTransfer`; `arc200_Transfer` unless a side is the token itself or zero); router `RelayFeePaid` only for a
configured token; mandate `MandatePaymentSettled` only for a configured token, as that token's `PaymentSettled` from
`0x` ‖ mandate id; DEX legs from the configured DEX's `Matched` plus the tokens' `OrderFilled`. A round algod no longer
has fails the range. Two algod calls per round (block and hash).

## 10. Mandate

<a id="mandate"></a>

<a id="NET-ALG-10"></a>**NET-ALG-10** — **The Algorand mandate is its own app; the owner's funding pay is the open.**
The mandate app holds the funded amount as its own token balance under its app address and moves it with inner
`arc200_transfer` / `transfer_to_ua`. One owner signature: the funding `mtx_pay` op binds the terms (`to` = `relayer` =
the mandate app address, `pay_ref` = the mandate id, `extra = sha256(token ‖ id ‖ terms)`), and
`mtx_mandate_open(token, op, auth, terms, fund_mbr)` runs it as an inner group [payment `fund_mbr` → token]
[`token.mtx_pay(open_payee = own address)`]; a funding op submitted anywhere else is refused by the relayer rule. Op 13
is therefore unused on Algorand (NEAR keeps it). Terms start with `delegate` (a holder); one-shot; state box keyed
(token app id, mandate id) — a fake token reaches only its own mandates; the payee's token box is created at open by a
0-amount inner transfer (a 0-amount `arc200_Transfer` / `UaTransfer` is logged at each open); `mtx_mandate_pay` on
`payLane(pay_ref)` nonce 0, verified by an inner `verify` (the delegate's policy), logs `MandatePaymentSettled(token,
Ua(id), pay_ref)` and no `MetaTransactionExecuted`; `mtx_revoke` by the owner or the delegate, no nonce, through
`verify_key` (never blocked by the passkey policy); `mandate_refund` only after revocation or expiry, closes the
mandate, refuses a refund of 0. Every mandate event carries the token app id. Budgets (ed25519): open 4,367 / 7 inner,
pay 3,804, revoke 3,450, refund 443 (`smartcontracts/algorand/runs/2026-10-29-algorand-relayfee-fix1.txt`). BUILT.

## <a id="dex"></a>11. DEX

<a id="NET-ALG-11"></a>**NET-ALG-11** — **The Algorand DEX is stateless and atomic: both legs in one call.**
`settle(order_a, op_a, auth_a, order_b, op_b, auth_b, mbr: uint64[4])`: each order's `relayer` is zero or the
submitter ([CTR-DEX-09](../contracts/dex.md#CTR-DEX-09): `Txn.Sender`, or for a settle relayed through the router the
sender of the router's `relay` at `group_index + 1`, the router id fixed at creation); the pair crosses and is
fill-or-kill (each side receives the other's whole `sell_amount`); inside the call the DEX makes the inner
`mtx_trade(op, auth, order)` of each sell token (leg op 1, `to` = `relayer` = the DEX address, no open mode; value legs
through `verify`, never `verify_key`) and pays each amount on to the other seller; any failure fails the whole group:
no escrow, no pending state, no refund (the NEAR failed-counter-leg issue does not exist here). `mbr` = the four exact
parts (leg a, leg b, payout at a, payout at b), each checked by its token. An auth too large for 2,048 B (a passkey
msig leg: 2,738 B inline) is passed empty and carried by a `carry(byte[])` call after the settle; the scan starts at
`Txn.group_index + 1`, so batched settles each consume their own carries. Orders keyed (holder, lane, nonce), ARC-4
88 B; cancel (op 14) and invalidate (op 15) through `verify_key`; `min_nonce < 2^63`
([CTR-DEX-10](../contracts/dex.md#CTR-DEX-10)). Events `Matched(settle_id, token_a, token_b, leg_a, leg_b)` and the
tokens' `OrderFilled`, `OrderCancelled`, `NoncesInvalidated`; `filled` cannot tell open from cancelled (read the `o`
box). No DEX fee. Budgets: settle native 7,328 / 12 inner, two passkey legs 12,683 / 19, msig-3 + passkey (carried)
23,054 / 31, two carried msig-3 legs 33,367 / 46 (pin 35,000 / 49) (`smartcontracts/algorand/runs/2026-10-29-algorand-relayfee-fix1.txt`).
BUILT.

## 12. Deploy

<a id="deploy"></a>

<a id="NET-ALG-14"></a>**NET-ALG-14** — **No app is upgradeable.** Every approval program rejects `UpdateApplication` and
`DeleteApplication` unconditionally (creator included; tests per app), no app issues an inner transaction with
`RekeyTo`, `CloseRemainderTo` or `AssetCloseTo` (static proof over every approval), inner fees are 0. Deploy gate and
node start check: each app's approval and clear hashes equal `artifacts.json`. The router's authority equals the
token's: none. BUILT.

<a id="NET-ALG-15"></a>**NET-ALG-15** — **`deploy.sh algorand <algod>` is resumable and gated.** Order: account →
relayfee → one token per `ALGORAND_TOKENS` entry → mandate (with the account id) → dex (with the relayfee id); each
create with the ARC-56 schema and `extra_pages = (len(approval) + len(clear) − 1) // 2048`; every app address funded to
algod's `min-balance` (a lease per app, so at most once). The router's salt is the lowest s < 128 whose executor is
off-curve for the app id a simulate predicts; a router that lands off its prediction with an on-curve executor is
recorded as an orphan (it cannot be deleted; 128,500 µALGO of the funder's minimum balance each) and created again, up
to 3 times. Gate: hashes = `artifacts.json`; token and mandate `account_app`, DEX `router_app` link right (a token or
mandate named without `account=`, a dex without `relayfee=`, is refused); salt < 128 and the executor rebuilt = the
router's `executor()` = the SDK's LogicSig address, off-curve; every app address ≥ its minimum. Resume: the env is
checked first; each create is signed and recorded (txid, signed bytes, `FirstValid`/`LastValid`, a 100-round window)
in `<dir>/<genesis>.<funder>.resume.json` (0600, atomic, fsynced, git-ignored) before it is sent; on a rerun a pending
create is decoded from its signed bytes and refused if its programs or arguments differ from this run's; a lost create
is found in the funder's `created-apps` (role code, create arguments as globals, id ≥ the ledger's transaction counter
when recorded; two matches refused), else resent within its window or rebuilt once `last-round ≥ LastValid`; a role
outside the plan, or an app with other code, creator, parameters or links, is refused ("not adopted"). The deployment
file `deployments/<genesis, URL-safe base64>.json` (network, genesis id, funder, admin, apps by role, tokens, executor
{salt, salt_lowest, address, prefix, suffix}, hashes, orphans, time) is written atomically after the gate.
`devnet.sh algorand up|down` runs the localnet in docker (algod 2 GB, other containers 512 MB, pinned digests);
`scripts/e2e.sh` brings it up, runs the e2e and tears it down on any exit. BUILT.

## 13. Conformance

<a id="conformance"></a>

**Apps** (`smartcontracts/scripts/test.sh algorand`, `algorand-python-testing` and localnet pytest): 110 tests on the
localnet (`smartcontracts/algorand/runs/2026-10-29-algorand-vectors-localnet.txt`), RED logs and mutation runs per app
(`runs/*-mutations.txt`). **Node**: 426 lib tests and clippy (`scaas-node/runs/2026-10-29-algorand-t20-fix1.txt`).
**e2e** (`scaas-node/tests/e2e_algorand.rs`, 8 tests, `smartcontracts/algorand/runs/2026-10-28-algorand-e2e.txt`,
rc=0): deploy gate on a hash mismatch (an update-accepting app is refused by the gate and halts the node), resumable
deploy, pay → mined (txid = algod's, replay `consumed`, under-fee group `Rejected` by the pool), pay-meta, router jobs
to the account, mandate, DEX and a listed third party (the target sees the executor, never the lane), native events.
Real algod refused each mutation of the node's group: under-fee (`group fee … too small`), short inner fee credit, a
box reference removed (`invalid Box reference`), the MBR payment 1 µALGO short (`assert failed`), and the pool an
under-fee submit (`TransactionPool.Remember`).

Quote = lane ALGO decrease, every job kind (µALGO; fee = 1,000 per transaction and per inner transaction):

| Job | Quote | Fee (txns + inner) | MBR |
|---|---|---|---|
| `mtx_pay`, native payer | 54,400 | 7,000 (3 + 4) | 47,400 |
| `mtx_pay_meta`, ed25519 UA payer, record opened | 132,500 | 9,000 (3 + 6) | 123,500 |
| router → `account.mtx_add_origin` (UA subject opened, UA payer) | 228,400 | 16,000 (5 + 11) | 212,400 |
| router → listed `ping`, native payer | 27,900 | 9,000 (4 + 5) | 18,900 |
| router → `ping`, msig-3 Chrome passkey payer (1,791 B of relay args) | 163,300 | 27,000 (4 + 23) | 136,300 |
| router → `token.mtx_invalidate_nonces`, box new / exists | 51,800 / 31,900 | 14,000 / 13,000 | 37,800 / 18,900 |
| router → `mandate.mtx_mandate_open` | 240,800 | 17,000 (6 + 11) | 223,800 |
| router → `mandate.mtx_mandate_pay` (delegate record opened) | 129,900 | 16,000 (6 + 10) | 113,900 |
| router → `mandate.mtx_revoke` | 60,400 | 13,000 (5 + 8) | 47,400 |
| router → `dex.settle`, msig-3 leg carried | 326,500 | 44,000 (8 + 36) | 282,500 |
| router → `account.mtx_set_guardian`, msig-3 subject paid by an msig-3 payer (5 appended budget calls) | 246,700 | 50,000 (10 + 40) | 196,700 |
| a pay-meta with a bad commitment; a failing target (both `dead`) | — | — | lane decrease 0 |

No size fee at 1,791 B of arguments: algod `fee` per byte 0, min fee 1,000, the 27,000 quote is algod's minimum
exactly (fee − 1 refused). Apps' budgets (`…/2026-10-29-algorand-relayfee-fix1.txt`): `mtx_pay` 2,871, `mtx_pay_meta`
3,327, `mtx_transfer` 2,831; relay groups: native `ping` 3,738 / 5 inner, passkey payer 6,506 / 8, msig-3 target +
passkey payer 22,294 / 31, msig-3 + msig-3 32,403 / 45 (pin 35,000 / 47).

## <a id="limitations"></a>14. Limitations

<a id="limitations"></a>

- **Assumed protocol constants** (not in algod's REST): 700 opcodes per app call (sizes discovery only), 2,048 B per
  program page, a 100-round deploy window; `SPENT_KEEP` = 1 h assumes `MaxTxnLife` 1,000 rounds < 1 h, false above
  3.6 s per round. Every fee, minimum balance and MBR is read from algod.
- **Restart without the signed bytes** reports `consumed`, not `mined` (the rebuild fails simulate); a recovered job
  that mines after a restart is not charged to the breaker; no double charge (one lane nonce).
- **Liveness gaps, no loss:** a mandate pay whose payer is also the delegate with an unopened record fails simulate;
  `terms.payee` = the lane on the payment token is refused; an idle dev-mode chain with long rounds makes `last_valid`
  refuse ("expires before round") until blocks are frequent.
- **Router:** the relay-sender rule is on the DEX only, so token, account and mandate ops through the router need
  relayer zero (front-runnable by direct submission: a relayer-only grief); the token has no router id, unlike spec
  §4.1; spec §4.1's "stateless" router now holds one creation-time `salt`; the executor is built with
  `autosalt=False` (puyapy warns, intended); a busy chain can orphan routers at deploy (above).
- **Stray funds:** ALGO or tokens sent to the executor, the router, the mandate or DEX address outside an open or
  settle stay there or are movable by any relayed `arc200_transfer` (the executor); never pay them; the DEX keeps a
  permanent per-token box (28,500 µALGO).
- **Third-party targets** are operator-vouched per method; their ARC-4 reference-type arguments are not covered by
  `ref`; assets, holdings and locals reported unnamed are refused.
- A replayed passkey assertion can lazily open a record pinned to its origin (a recoverable grief). The contract's
  passkey grammar accepts the tail `,"crossOrigin":false,}` edge as the node does. puyapy 5.10.1 drops events from
  ARC-56 when the emitting subroutine is called as a function argument. Event discovery on a busy chain needs an
  indexer feed. No public-network deployment exists.

## 15. References

<a id="references"></a>

- ARC-200, ARC-4, ARC-28, ARC-56, ARC-60 (Draft), ARC-47 (github.com/algorandfoundation/ARCs).
- AVM opcodes (`ed25519verify_bare`, `ecdsa_verify`, `keccak256`, `box_create`, `global GenesisHash`), boxes and MBR,
  costs and limits, rekeying (dev.algorand.co); Algorand Python / Puya (github.com/algorandfoundation/puya); AlgoKit
  localnet; Pera Connect `signData`; algosdk `signBytes` / `verifyBytes`.

## <a id="paymeta-relayfee"></a>Pay-meta and relay fee (metatx split)

Rules [CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26) and [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27); the Algorand
form below. Status BUILT.

- **Pay-meta.** ABI `mtx_pay_meta(op, auth, salt: byte[32], meta: byte[])`, `meta` ≤ 507 B; once per `(payer, payId)`,
  for good.

<a id="NET-ALG-12"></a>**NET-ALG-12** — **One atomic group, no escrow; the target is sent by a keyless executor
LogicSig, never the lane.** Group: [MBR → router]? … [MBR → target]? [target app call, sender = executor, fee 0]
[`router.relay(token, op, auth)`] [carries…] [budget calls…]. The executor approves only an `ApplicationCall` NoOp
followed by `relay` on its router, with `RekeyTo` / `CloseRemainderTo` / `AssetCloseTo` zero and fee 0; it holds
nothing. The router checks the target (exists, NoOp — a `ClearState` cannot fail —, ≠ router, sender = executor, the
selector ≠ `add_key_native`, payee ≠ executor), the shape (`pay_ref == ref`, `lane == payLane(ref)`, nonce 0, relayer =
router address), `ref = keccak256("scaas.relayfee" ‖ network ‖ target app address ‖ keccak256(call) ‖ salt)` with
`call = target app id (u64) ‖ u8 n ‖ (u16 len ‖ arg)×n` and salt = `op.extra`, then makes the inner group [MBR forward
to the token] [`token.mtx_pay(op, auth, open_payee = Txn.Sender)`]: the token pays the open payee only when `op.to ==
op.relayer ==` the calling app, so the router never holds the payment. `RelayFeePaid` carries the target and token app
ids. A failing target, router or pay rejects the whole group: [CTR-MTX-16](../contracts/metatx.md#CTR-MTX-16) holds with
no residual. Every target — the token's own entries, account key ops, the mandate, the DEX, listed third-party apps —
goes through this one router; `target == relayfee` is refused. BUILT.

<a id="NET-ALG-13"></a>**NET-ALG-13** — **The router takes a creation-time salt so its executor is off-curve.** The
executor program = PREFIX ‖ router app id ‖ SUFFIX ‖ `20 01 s` (an `intcblock 1 s`, dead code); the router stores `s`
(uint8 < 128) at creation and derives `executor()` from it; the deployer picks the lowest `s` whose address is not an
ed25519 point (go-algorand `IsEdwards25519Point`), so no private key can exist for the executor even in principle.
Unsalted, 9 of router ids 1000–1019 were on-curve (`smartcontracts/algorand/runs/2026-10-28-algorand-limits.txt`); the
lowest-salt search is `exec_salt` (`smartcontracts/algorand/tests/conftest.py:360`) and `deploy.py`. The
router is no longer fully stateless (one global). BUILT.
