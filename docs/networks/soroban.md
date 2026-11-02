# Soroban (Stellar and Pi Network)

Common rules for every family: [networks/README](README.md). Status: contracts, adapter and client verifier
**BUILT**; the UA base (UA-Soroban, [section 10](#ua-base)) is **BUILT** on branch `ua-soroban` (merge pending the owner's go); items marked SPECIFIED are normative and not yet in code. **Soroban is not on the mesh**: jobs reach a
Soroban lane only through the job API (owner; [NODE-MESH-07](../node/mesh.md#NODE-MESH-07)).

**Contents**

1. [Overview](#1-overview)
2. [Payload](#2-payload)
3. [Signatures](#3-signatures)
4. [Contracts](#contracts)
5. [DEX](#dex)
6. [Relayer](#6-relayer)
7. [Finality and events](#7-finality-and-events)
8. [Conformance](#8-conformance)
9. [Limitations](#9-limitations)
10. [UA base (UA-Soroban)](#ua-base)

## 1. Overview

<a id="overview"></a><a id="NET-SOR-01"></a>**NET-SOR-01** — **On Soroban the contract-level meta operation is the
native Soroban authorization; a relayer lane is the transaction source, and fee-bump lets one lane pay for all.** The
subject never sends a transaction and never uses its account sequence: it signs a
`HashIdPreimage::SorobanAuthorization` (network id + contract + function + args, `i64` nonce, ledger expiry), which is
already a contract-level verifier with a **non-sequential** nonce (each `(address, nonce)` once) and a
domain-separated preimage. No second verifier is written. The relayer places the signature in a
`SorobanAuthorizationEntry` of a transaction whose source is its **lane account** (own sequence, pays the fee);
fee-bump (CAP-15) lets one fee account pay for every lane's transaction. Wallet: Freighter `signAuthEntry`; passkey: a
custom account's `__check_auth` with `secp256r1_verify`. The subject `G…` account must exist on the ledger (a host
requirement). Pi Network is the same family with network passphrases "Pi Testnet" / "Pi Network" and SLIP-44 coin
314159 (passphrases confirmed by the owner at deploy). Networks: Stellar `pubnet`, `testnet`, `standalone`; Pi
`pi-mainnet`, `pi-testnet`.

```mermaid
sequenceDiagram
    participant S as Subject (Freighter, seed signer)
    participant R as Relayer lane (G account)
    participant F as Fee account (optional)
    participant C as Token contract
    S->>S: sign HashIdPreimage SorobanAuthorization (network id, contract, function, args, nonce, expiry)
    S->>R: payload and signature
    R->>R: build SorobanAuthorizationEntry, simulateTransaction
    R->>F: lane transaction (fee-bump CAP-15, optional)
    R->>C: InvokeHostFunction, source = lane, seq = committed + 1
    C->>C: host checks authorization, each (address, nonce) once
    C-->>R: getTransaction SUCCESS or FAILED (billed)
```

## 2. Payload

<a id="payload"></a>

<a id="NET-SOR-16"></a>**NET-SOR-16** — **Target: both kinds are host authorizations of `mtx_` functions**
([NET-ALL-26](README.md#NET-ALL-26)–[NET-ALL-29](README.md#NET-ALL-29); owner 2026-10-08). Status: **SPECIFIED**, except the mandate names, which are **BUILT** in the UA-Soroban deployment (`mtx_set_mandate`, `mtx_set_payee`, `mtx_revoke`, `mtx_withdraw`, `mtx_mandate_pay`; [NET-SOR-21](#NET-SOR-21)); the token's `pay` and the DEX's `settle` / `cancel` keep their names.
Soroban needs no struct and no verifier library: a `MetaCall` is the host authorization entry of an `mtx_<name>`
function (`function_name` + `args`), a `MetaTransfer` that of SEP-41 `transfer` (standard name kept) or `mtx_pay(from,
to, amount, pay_ref, valid_until)`; the contract's own op digest tag becomes `"scaas_metacall_v1"`. No
`mtx_execute_transfer`: host nonces order nothing ([NET-SOR-02](#NET-SOR-02)). Renames: `pay` → `mtx_pay`,
`pay_under_mandate` → `mtx_mandate_pay`, `revoke(token, by)` → `mtx_revoke`, `add_key`/`remove_key` → `mtx_add_key`/
`mtx_remove_key`, DEX `settle`/`cancel` → `mtx_settle`/`mtx_cancel`. Restriction is the missing part, so
[NET-SOR-04](#NET-SOR-04) becomes mandatory. New deployments. The names on this page are **Transitional (BUILT)**.

The subject signs these exact XDR bytes (the client builds them without RPC):

```
HashIdPreimage {
  type = ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9)
  network_id                = sha256(network_passphrase)          -- network separation
  nonce                     = i64(sha256("scaas.soroban.nonce" ‖ entryRef ‖ validUntil_be64)[0..8])
  signature_expiration_ledger = u32 (upper bound, below)
  invocation = { contract_fn: { contract_address = token (C…), function_name = "pay",
                                args = [Address from, Address to, I128 amount, BytesN<32> pay_ref, U64 valid_until] },
                 sub_invocations = [] }
}
signature: ed25519(sha256(payload))   (Freighter signAuthEntry; the seed signer computes the same)
```

The nonce is **deterministic**, not random: one payment request at one validity maps to one host nonce.

`MetaOp` v1 mapping: network → `network_id`; contract → `contract_address`; op → `function_name`; from/to/amount/payRef
→ args; lane + nonce → `nonce` (the host records each used `(address, nonce)` until the signature expires — not
sequential); validUntil → the `valid_until` arg (the contract checks `ledger.timestamp() ≤ valid_until`) **and**
`signature_expiration_ledger`; relayer → unbound (any lane may submit; the host does not bind the transaction source);
extra → none for `pay`.

Replay protection: (a) the host refuses a used `(from, nonce)`; (b) each **`(from, pay_ref)`** pays once
([NET-SOR-09](#NET-SOR-09)); (c) another network ⇒ another `network_id` ⇒ the signature fails; another contract ⇒
another `contract_address` ⇒ the invocation does not match.

**Digest.** The host does not reveal the signature hash to the contract, so the contract computes an **op digest** and
emits it in `MetaTransactionExecuted`:

```
digest = sha256( ScVal::Vec[ Symbol("scaas_metaop_v1"), BytesN<32>(network_id), Address(contract),
                             Symbol(function_name), Vec(args) ].to_xdr() )
```

The client, the contract tests and the Rust adapter compute the same value (cross vectors). The args contain `pay_ref`
and `valid_until`, so every issue (another expiry) has another digest, and a uniqueness key on
`(chain_id, digest_hash)` keeps its meaning. This digest is also what the job API and the indexer use.

<a id="NET-SOR-02"></a>**NET-SOR-02** — **The ledger expiry is computed without RPC as a safe upper bound.**
`signature_expiration_ledger` must lie in `[current ledger, current ledger + max_entry_ttl − 1]`. The client makes
no RPC call, so it uses an **anchor** left by the indexer: each time the event feed advances the Soroban chain's
cursor, the client records `soroban_anchor_ts` (its server time) next to `indexed_block` (the final ledger). Ledgers
never close faster than 1 per second (SCP), so

`exp = indexed_block + (valid_until − soroban_anchor_ts) + 17280`

is an **upper bound**: it never expires before `valid_until` (the real expiry is checked by the contract in seconds);
the 17 280-ledger margin covers indexer lag. The anchor is recorded only when the ingested batch is **shorter than
1000 ledgers** (the node has caught up with the final head; a catch-up batch after a long outage never pairs an old
anchor with a new time). An anchor older than 7 days (indexer stopped) ⇒ refuse to issue (the bound could exceed
`max_entry_ttl`); a chain never indexed ⇒ refuse to issue. Exceeding the bound only lengthens how long the host keeps
the nonce. BUILT.

## 3. Signatures

<a id="signatures"></a>

| `from` kind | Signer | Signature in the auth entry | Client check |
|---|---|---|---|
| `G…` (Freighter, seed key `m/44'/148'/i'`) | the account's ed25519 key (the host checks threshold/signers) | `Vec[Map{public_key: Bytes32, signature: Bytes64}]` (the relayer builds it from the 64 bytes) | real ed25519 with the master key inside the strkey ([INT-ERP-14](../integration.md#INT-ERP-14)) |
| `C…` = `SmartKeyAccount` (multi-key subject account) | a P-256 WebAuthn passkey or an ed25519 seed key | the account's ScVal `Signature` (XDR hex, inserted verbatim by the relayer) | none (`None`) — the node's simulation decides |

**Freighter `signAuthEntry`** (`@stellar/freighter-api`; `@stellar/stellar-sdk`, `stellar/rs-soroban-sdk`):

```typescript
signAuthEntry(entryXdr: string, opts?: { networkPassphrase?: string; address?: string }):
  Promise<{ signedAuthEntry: string | null; signerAddress: string; } & { error?: FreighterApiError }>;
```

Input: a base64 `SorobanAuthorizationEntry` (or `HashIdPreimage`) XDR string. Output: `signedAuthEntry` (base64 XDR with
the credentials filled in) and `signerAddress` (`G...` or `C...`). What is signed: the SHA-256 of the
`HashIdPreimage` XDR — `Signature = Ed25519.sign(sha256(HashIdPreimage.toXDR()))` — whose
`HashIdPreimageSorobanAuthorization` holds `network_id` (SHA-256 of the passphrase), `nonce`,
`signature_expiration_ledger` and `invocation` (`SorobanAuthorizedInvocation` tree). Contract vs account address:
`soroban_sdk::Address` exposes `Address::executable(&self) -> Option<Executable>` with `enum Executable { Wasm(BytesN<32>),
StellarAsset, Account }` — `Some(Executable::Account)` for classic `G...` accounts, `Some(Executable::Wasm(...))` or
`Some(Executable::StellarAsset)` for contracts (`C...`), `None` if the address does not exist on chain;
`Address::to_string(&self) -> String` returns the StrKey (`C...` for contracts, `G...` for accounts). Soroban SDK major version at the time of writing: **`28.0.0`** (protocol 22 /
23+); the contracts build with soroban-sdk 26.1.1 and Rust 1.97.1 (`smartcontracts/soroban/rust-toolchain.toml`; the SDK needs ≥ 1.91).

**`SmartKeyAccount.__check_auth(signature_payload, Signature, contexts)`:**

- `Ed25519{key_id, signature}`: `ed25519_verify(pk, signature_payload, sig)`.
- `WebAuthn{key_id, authenticator_data, client_data_json, signature (r‖s, low-s), proof}`: the challenge is
  `signature_payload` when `proof` is empty, otherwise the sha256 Merkle root of leaves
  `sha256(sha256(0x00 ‖ payload))` with sorted pairs (batching); `clientDataJSON` carries `"type":"webauthn.get"`,
  `"challenge":"<base64url(challenge)>"` and the registered origin; `authenticator_data[0..32] = rp_id_hash`; flags UP
  (`0x01`) and UV (`0x04`); `secp256r1_verify(pk65, sha256(authData ‖ sha256(clientDataJSON)), sig)` (the host refuses
  high-s — CAP-51).
- Key lifecycle: `add_key` / `remove_key` need the account's own authorization (an existing key signs); never zero
  keys. The account is deployed permissionlessly with `__constructor(first_key)` and must exist before it pays.

<a id="NET-SOR-13"></a>**NET-SOR-13** — **The Soroban passkey verifier refuses `"crossOrigin":true` and any
`topOrigin`** (the common grammar, [NET-ALL-04](README.md#NET-ALL-04)). SPECIFIED (as built `verify_webauthn` checks
only `type`/`challenge`/`origin`, `smart-key-account/src/lib.rs:149-153`, so an RP page embeddable in a cross-origin iframe —
Permissions-Policy `publickey-credentials-get` — yields valid assertions under an attacker's page). Test: an assertion
with `crossOrigin:true` ⇒ `BadClientData`.

## <a id="contracts"></a>4. Contracts

<a id="contracts"></a>

`smartcontracts/soroban/contracts/{token,mandate,dex,account,ua-registry,ua-common,relay-fee,relay-executor}/` (the UA contracts: [section 10](#ua-base)):

- **`scaas-token`** — SEP-41 (`balance`, `transfer`, `transfer_from`, `approve`, `allowance`, `burn`, `burn_from`,
  `decimals`, `name`, `symbol`) + admin `mint` + `pay(from, to, amount, pay_ref, valid_until)`: `from.require_auth()`,
  expiry, `pay_ref` once per `from` and `amount > 0` ([NET-SOR-09](#NET-SOR-09)); emits
  `PaymentSettled{from,to | amount,pay_ref}` and `MetaTransactionExecuted{from | digest}`. **`approve` only to a
  contract spender** (`executable()` = Wasm or StellarAsset; [CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)).
  No fee. Storage: balances, allowances and `pay_ref` entries persistent, with TTL extension.
- **`scaas-mandate`** (as the EVM `MandateWallet`): one owner; funds inside the contract; per token: delegate, limits
  per payment and per period, period, expiry, allowed payees; `mtx_mandate_pay(token, payee, amount, pay_ref,
  epoch, valid_until, relayer, auth)` (was `pay_under_mandate`) — the delegate's authorisation (host auth or a UA signature) then `token.pay(self, payee, …)` (the same `PaymentSettled`, so the client
  reconciles it like a manual payment); `pay_ref` once (its own `Key::Ref(pay_ref)`; only the delegate spends it);
  `mtx_revoke(token, by, epoch, …)` by the owner **or** the delegate (kill switch); owner `withdraw`. The owner is gasless naturally:
  its native authorization goes through a relayer (no `executeAsOwner` needed).
- **`SmartKeyAccount`** — the multi-key subject account above.

<a id="pay-ref"></a><a id="NET-SOR-09"></a>**NET-SOR-09** — **`pay_ref` is one-shot per `(from, pay_ref)`, not
globally, and `pay` moves a positive amount.** `Token::pay` keys `Key::PayRef(from, pay_ref)`; `ref_used(from,
pay_ref)`; `pay` with `amount ≤ 0` (`amount <= 0`) ⇒ `Error::NonPositiveAmount` (`i128`: a negative amount is refused too; owner
decision on the error name). The mandate path keys by the mandate's address automatically and keeps its own
`Key::Ref(pay_ref)`. Why: with a global key, a stranger's 0- or 1-unit `pay(attacker, receiver, …, victim_ref)` burns
the victim's ref and blocks the victim's signed payment; booking already sums settlements per `entry_ref` and
receiver, so a stranger's payment with someone else's ref is only money in (same direction as Cosmos, which never
locks `pay_ref`, and the EVM `MetaToken`). The `(from, pay_ref)` key is **BUILT** (`Key::PayRef(from, pay_ref)`, `ref_used(from,
pay_ref)`); the positive-amount rule is SPECIFIED (as built `check_amount` refuses only a negative amount,
`NegativeAmount`, and accepts 0). Tests: a third party `pay(self, x, 0, victim_ref)` ⇒ `NonPositiveAmount`;
`pay(self, x, 1, victim_ref)` does not block the victim's `pay`; the same `from` paying the same `pay_ref` twice (two
signatures) ⇒ `RefUsed`; `pay_under_mandate` cannot be burnt by a third party.

<a id="ttl"></a><a id="NET-SOR-11"></a>**NET-SOR-11** — **Entries in daily use extend their TTL, and an archived
footprint is restored by the lane and retried.** `pay_under_mandate` extends `Key::Payee` on every use;
`SmartKeyAccount.__check_auth` extends the account instance; when simulation returns a `restorePreamble`, the lane
submits `RestoreFootprintOp` with the preamble's footprint and fee, then rebuilds the job; the restore rent is a
lane-paid deposit bounded by `chain.max_deposit_per_job` and charged to the `from` subject
([NODE-LANE-18](../node/submit-lanes.md#NODE-LANE-18)). The node's restore half is **BUILT** (UA-Soroban, [NET-SOR-23](#NET-SOR-23): a simulation that restores archived entries is accepted within `params.max_deposit_per_job`; TTL extension on the UA entries and the mandate and DEX instances, [NET-SOR-22](#NET-SOR-22)); the rest is SPECIFIED (as first written a `restorePreamble` ⇒ `Revert` ⇒ job `dead`,
`soroban.rs:325-327`; only `set_payee` extends the payee, `mandate/src/lib.rs:131-140`, `:167` only `has`; the account
extends only on `save`, `smart-key-account/src/lib.rs:75-78`, `__check_auth` `:215-229` does not — so an account in daily use is
archived ~60 days after its last key change, a payee 60 days after it was allowed). Tests: TTL after
`pay_under_mandate` / `__check_auth` is raised; end to end: archive ⇒ restore ⇒ `mined`. System relayers may also call
`extend_ttl` for long-lived state.

## <a id="dex"></a>5. DEX

<a id="dex"></a>

`scaas-dex` `settle(maker, taker, maker_fill, maker_auth, taker_auth)` (the two `auth` are empty for a native maker; every leg is pull-then-pay, [NET-SOR-21](#NET-SOR-21)): `require_auth_for_args((order,))` for **both** orders (and, per [NET-SOR-10](#NET-SOR-10), `order.relayer.require_auth()`); both price limits
(maker's price; the taker receives at least its own); `filled[order_hash]` never overfills; maker/taker ppm fees per
market (sorted token pair), on/off, cap 1 % (10 000 ppm) and ≤ the signed `max_fee_ppm`; tokens move by
`transfer_from` with the DEX as spender (allowances only to contracts); `cancel(order)` authorised by the maker sets
`filled = sell_amount`, so a cancelled order never settles. `order_hash = sha256(order.to_xdr())`. One fee recipient
for the whole DEX (`Key::FeeRecipient`); no on-chain self-trade check.

<a id="NET-SOR-10"></a>**NET-SOR-10** — **Soroban orders always name their settling relayer; there is no open form.**
`Order.relayer: Address` is mandatory (not an `Option`); `settle` calls `maker.relayer.require_auth()` and requires
`maker.relayer == taker.relayer` — the Soroban application of the bound-settler rule
([CTR-DEX-09](../contracts/dex.md#CTR-DEX-09)), which elsewhere allows "relayer 0 = open". Why: the host only matches
`dex.settle(order)` (`dex/src/lib.rs:158-159`); the counter-order and `maker_fill` (`:153`) are the submitter's choice,
so anyone who sees a pending `settle` (transactions flood to every peer before the ledger closes) re-submits both auth
entries with `maker_fill = 1`: both nonces are consumed for a dust fill, the real `settle` fails (the relayer pays) and
both makers must sign again. Binding the settler means only the DEX operator's lane can spend the auth entries; roles
and `maker_fill` are chosen by the (trusted) operator. Binding `(order, fill)` into the signature is not possible: a
resting order is signed before its fill is known. SPECIFIED (as built `Order` has no relayer, `:35-47`). Test: a third
party re-submits both auth entries with `maker_fill = 1` ⇒ fails; the right relayer settles.

- <a id="NET-SOR-05"></a>**NET-SOR-05** — **One signature settles once.** An auth entry consumes its nonce when used:
  a partially filled order needs the maker to sign again for the rest; `filled[order_hash]` (the hash holds no nonce)
  prevents overfill across re-signed copies of one order.
- <a id="NET-SOR-06"></a>**NET-SOR-06** — **No multi-pair batch per Soroban transaction.** A Soroban transaction is
  one host call; a failure in one pair reverts the whole transaction (no per-pair atomicity), so the matcher submits
  one pair per transaction, in parallel across lanes.
- <a id="NET-SOR-07"></a>**NET-SOR-07** — **A relayed DEX job carries two auth entries.** `settle` needs two auth
  entries: it is a `ua_metatx` job with named `args` (`maker, taker, maker_fill, maker_auth, taker_auth`;
  [job-api.md](../node/job-api.md#soroban-ua-metatx-jobs)), its native legs in `op.auth = [{payload, from, signature}]`, so the
  matcher only queues jobs with two signatures, `payload` named fields, never XDR. A `signed_op` runs only what its subject signed,
  on a contract the chain's `params` name ([job-api.md](../node/job-api.md#soroban-signed-op)); its `extra.auth` takes further entries in
  the same form, and `extra.call` is gone. The Soroban book and matcher are a seam.

## 6. Relayer

<a id="relayer"></a>

- Lane = `G…` account derived at `m/44'/148'/i'` (SEP-0005); one transaction in flight per lane (`lane_runner`); the
  **committed** sequence is read (`getLedgerEntries` of the account); the transaction uses `seq+1` and
  `time_bounds.max_time = valid_until`, so a transaction that never lands expires with the payload and the lane
  sequence never hangs.
- `build`, a `signed_op` ([job-api.md](../node/job-api.md#soroban-signed-op)): rebuild the `SorobanAuthorizationEntry` from the named
  `payload` (Address credentials of `from` with its nonce, expiry and `signature`), the invocation's contract = `op.contract`, and
  that contract one the chain's `params` name, never the registry; `InvokeHostFunction` = exactly the invocation;
  `simulateTransaction` (auth enforced) ⇒ footprint + resource fee; the host checks the signature over the rebuilt bytes on this
  chain's network id, so a signature for another network or for other values is a simulation error, nothing sent; simulation
  error ⇒ `Revert` (job dies); network error ⇒ `Transport`.
- `sign`: `fee = base + min_resource_fee·1.15`, `seq = committed + 1`, ed25519 over
  `sha256(TransactionSignaturePayload)`; `tx_id = 0x‖hex(hash)`.
- `submit`: `sendTransaction`; `tx_status`: `getTransaction` (SUCCESS / FAILED / NOT_FOUND). Classes
  ([NODE-LANE-14](../node/submit-lanes.md#NODE-LANE-14), already right in code): `sendTransaction` `ERROR` = not in a
  ledger: `txSOROBAN_INVALID`, decoded from `errorResultXdr`, plain or inside a fee bump's `txFEE_BUMP_INNER_FAILED`, never passes
  ⇒ `dead` on one claim, the next job runs (the queue is per chain, so back in it the job would hold every lane); any other
  code ⇒ free requeue, the lane backing off (`soroban.rs:368-378`); `TRY_AGAIN_LATER` / network error ⇒ resend the same bytes;
  `getTransaction` `FAILED` = included and **billed** (inclusion fee + non-refundable resource fee) ⇒ final
  `Reverted` (`:380-387`). There is no requeue loop after a billed failure.
- **Fee-bump (CAP-15):** `params.fee_bump_lane = i` wraps every lane's transaction in a `FeeBumpTransaction` signed by
  the fee account `m/44'/148'/i'`; lane accounts need only the minimum balance. The subject's sequence is never used.
- Head-of-line: other lanes continue; the subject has no sequence on the path (the nonce is derived from
  `entryRef ‖ validUntil`, not sequential).

<a id="NET-SOR-15"></a>**NET-SOR-15** — **`build` takes `valid_until` (hence `TimeBounds.max_time` and the runner's
expiry) and `contract` from the signed invocation** (the `valid_until` arg, `contract_address`), never from the job
JSON; a mismatch ⇒ `422 BAD_PAYLOAD` ([NODE-LANE-16](../node/submit-lanes.md#NODE-LANE-16)). SPECIFIED (as built
`op["valid_until"]`, `soroban.rs:313`). Test: a job whose JSON `valid_until` exceeds the signed arg ⇒ refused.

<a id="NET-SOR-14"></a>**NET-SOR-14** — **The Soroban adapter reports `tx_fee` (`feeCharged` from the `resultXdr` of
`getTransaction`, for both `SUCCESS` and `FAILED`) and `lane_balance` (native balance of the account that pays: the lane's,
or under a fee bump the fee account alone; owner ruling 2026-11-01, amending "the lane and the `fee_bump_lane`")** to the
breaker ([NODE-LANE-13](../node/submit-lanes.md#NODE-LANE-13)). **BUILT** (ua8-soroban B9a, owner
ruling 2026-11-01: a working spend stop before the branch merges). `tx_fee` is `feeCharged` of the `resultXdr` for
`SUCCESS` and `FAILED` (under a fee bump the outer result, the fee that left the fee account); any other status, a missing
`resultXdr`, bad bytes or a negative fee is an `Err`, never 0. `lane_balance` is the balance of the account that pays, so a
funded lane behind an empty fee account opens the floor and sends nothing; an account that does not exist is 0, a failed read
or an answer with no `latestLedger` is an `Err` and keeps the last balance. A
landed failure counts: `follow` meters `Reverted` as `Mined`, once per transaction. A Soroban chain with `modules.submit` on
refuses to start unless `breaker.gas_budget_per_hour` and `breaker.min_relayer_balance` are both above 0
([ops.md](../node/ops.md#NODE-OPS-11)). `call` jobs and a plain `signed_op` (no `op.kind`) stop at `breaker.call_budget_pct` of the
budget (default 50, owner decisions 2026-11-01 and 2026-11-02), unless that `signed_op`'s root is a token payment: `pay`, `pay_meta`
or `transfer` on a registered token, read from its named JSON, where the host call is exactly that root and `build` refuses any other
([job-api.md](../node/job-api.md#soroban-signed-op)). Everything else runs to all of the budget, so jobs free to the client cannot stop
a payment. A fee that cannot be read is logged and counted in `scaas_fee_unread_total`, not
guessed. **Measured** on the Protocol 30 quickstart (`e2e_ua8_spend_stop`): `feeCharged` equals the payer's balance drop in
all four cases, 956,837 stroops (`SUCCESS`), 377,361 (`FAILED`), 956,937 (fee bump `SUCCESS`), 377,461 (fee bump `FAILED`),
the sending lane down by 0 under the fee bump. **Entry pre-check:** the host compares the whole `LedgerEntry`, which is
`stateChanges[].after`, with `contract_data_entry_size_bytes` exactly (`after` of 65,520 to 65,536 B landed `SUCCESS`, 65,540
to 65,552 B landed `FAILED`), so `build` refuses a job whose largest `ContractData` `after` is over the limit as `Revert`
(`dead` on one claim, nothing signed); a limit it cannot read lets the job through. The earlier 65,084 B was the
`LedgerEntryData` alone, 8 B less. What a failed over-entry write costs the lane is 0.039 to 0.065 XLM (B7), so the
pre-check saves it. Not exercised end to end: with the pre-check on, no job lands `FAILED` through the node without a race,
so the budget stop on the real host is shown by the runner test with real result bytes, and `meter` by a mined job through
`lane_step_metered`. Test: a
FAILED transaction adds `feeCharged` to `spent`. Residual risk: a `G…`
subject flips state after simulation (transfers everything away, or submits its own auth entry to burn the nonce);
bounded per `from` by the grief score ([NODE-LANE-15](../node/submit-lanes.md#NODE-LANE-15); `subject_grief` not yet in
code).

<a id="NET-SOR-12"></a>**NET-SOR-12** — **`op_consumed` reads the host nonce key** (`getLedgerEntries` of
`ContractData{contract: from, key: LedgerKeyNonce{nonce}, Temporary}`): present ⇒ `Some(true)`; for `pay` also
`ref_used(from, pay_ref)`. An auth entry consumed by someone else (a dust-fill attacker, a stranger's `pay`, or the
subject itself) makes the job `consumed`, not `dead`/`reverted`, so the client never asks the payer to re-sign an op
that already ran ([NODE-LANE-09](../node/submit-lanes.md#NODE-LANE-09)). SPECIFIED (as built the default `Ok(None)`,
`adapter.rs:127-129`). Test: an auth entry already submitted by someone else ⇒ job `consumed`.

<a id="NET-SOR-08"></a>**NET-SOR-08** — **A Soroban token address is a per-family string.** The token configuration
holds the address as the family's own string (`TokenCfg.address`, `config.rs:302-306`) and `index_step` passes it
through; the token list is the node store's per-namespace set (no `params.contracts`). BUILT.

Node-wide rules: value out = 0 ([NODE-LANE-17](../node/submit-lanes.md#NODE-LANE-17)); one custody key per family —
a `G…` ed25519 key signs raw 32 bytes like a Hedera ED25519 key, so one key never serves two families
([NODE-LANE-20](../node/submit-lanes.md#NODE-LANE-20)); no adapter journal of its own. Mesh signature checks do not
apply while Soroban is off the mesh (`mesh/digest.rs:146` returns `FamilyNotSupported`); if it joins, the decoder
verifies a `G…` ed25519 signature locally.

## 7. Finality and events

<a id="finality"></a>

SCP: a closed ledger is final. `final_head` = `getLatestLedger` (+ quorum: the other endpoints return the same hash
through `getLedgers`); `block_hash` through `getLedgers`. Events: `getEvents` (contract = a registered token, ≤ 5 per
filter), normalised to `{event, contract, block_number = ledger, block_hash, tx_hash, log_index, from, to, amount,
entry_ref, digest}` (hashes `0x` + 64 hex, strkey addresses); `log_index` = the event's index in the transaction (one
op per Soroban transaction). `getEvents` serves only the RPC's retention window (quickstart: 120 960 ledgers): a newly
created chain must set `indexed_block` near the current ledger (operations). Event-set agreement across the quorum per
ledger range: SPECIFIED.

## 8. Conformance

<a id="conformance"></a>

- Contracts (`cargo test`): token, mandate, DEX, account with **real** authorization (`set_auths` + real ed25519 / P-256
  signatures through the account), not only `mock_all_auths`; **anti-lock** (X on token 1 and Y on token 2; X held; Y
  succeeds; then X succeeds); a used nonce refuses replay.
- Cross vectors: the same `payload` / `digest` from the client verifier, the contract tests and the Rust adapter (pinned
  constants).
- UA-Soroban (SDK testutils at Protocol 30): `ua-registry` 50 tests (every S3 kind's vectors and negatives incl. the 21 WebAuthn negatives, canonical blob, `msig` members, receivability, a `C…` member refused, interface check), token 31, mandate 11 (epoch, `StaleEpoch`), DEX 16, relay-fee 21 (both attacks on the executor, `BadPayee`, `BadExecutor`), `smart-key-account` 10; `ua-ops.json` reproduced by the contracts, the adapter (63 rows) and `clientkeys`; node `ua_metatx` allow-list, lane-authority, executor-refusal, `StaleEpoch` and auto-restore tests; local end-to-end `e2e_soroban_ua` (6 tests) through `deploy.sh` ([NET-SOR-24](#NET-SOR-24)).
- UA-8 Part B (`ua8-soroban`; [NET-SOR-27](#NET-SOR-27)): `ua-registry` 140 tests at B7c (`smartcontracts/scripts/test.sh soroban`, rc 0: the portable vectors with attributes, the `negatives[]` map, the relayer-checked mode, the `msig` minimal form, the attestation binding per field, `UaRegistered` sizes); `scaas-node` `adapters::soroban` 88 tests at N2's second review round (call jobs, the allow-lists, the size and entry pre-checks, the spend stop, named jobs, the depth bound), clippy `-D warnings` clean; `scaas-ua` and `clientkeys` re-check every `portable.json` row and negative; 10 end-to-end tests in `scaas-node/tests/e2e_ua8.rs` through `smartcontracts/soroban/scripts/e2e-ua8-local.sh` (local Protocol 30 quickstart and two anvils: the EVM to Soroban to EVM copy, the relayer table, the attestation binding, `register_frost` at every size, a relayer-checked `msig` slot, the transaction size limit, the spend stop, and the RPC's behaviour with auth entries), and `e2e-local.sh` (1 + 8 tests, native relay fee and a `settle` of two native makers among them). Logs: `smartcontracts/soroban/runs/2026-11-01-ua8-soroban-*`. Not run on a network: the Stellar testnet (B10).
- Adapter: unit tests + decoder proptest; end-to-end `tests/e2e_soroban.rs` (`#[ignore]`) on a local `stellar/quickstart`
  (port 31980): two lanes from a 24-word mnemonic, payment through `lane_step`, finality through `index_step`,
  anti-lock end to end.

## 9. Limitations

<a id="limitations"></a>

- <a id="NET-SOR-03"></a>**NET-SOR-03** — **Soroban guardian recovery is a seam.** Guardian + delayed recovery is not
  built on Soroban; SPECIFIED as a gap ([NET-ALL-05](README.md#NET-ALL-05)).
- <a id="NET-SOR-04"></a>**NET-SOR-04** — **`__check_auth` checks every entry of `auth_contexts` against the key's allowlist**
  (owner 2026-10-08, [NET-ALL-27](README.md#NET-ALL-27)). Each key of `SmartKeyAccount` carries the `(contract, function)`
  pairs it may authorise (a passkey that pays, only a seed key changes keys…), aligned with Universal Account key
  purposes ([CTR-UA-10](../contracts/accounts.md#CTR-UA-10)); a context outside it fails. SPECIFIED. Transitional
  (BUILT): `_contexts` is ignored (`smart-key-account/src/lib.rs:215`), so any one passkey can `add_key` an attacker's key.
- Not on the mesh (above). Seed role keys of a `C…` account use `kindNo` 18
  ([CLI-SGN-30](../clients/signers-clientkeys.md#CLI-SGN-30)).
- Confidential payments: Soroban has BLS12-381 (CAP-59) and BN254 (CAP-74, protocol 25) host functions plus Poseidon, so
  a Bulletproofs/ElGamal verifier is feasible in principle, but the per-transaction CPU budget (~100 M instructions)
  may not fit a range proof with n = 64 (to be measured); Groth16 over a Zether-like circuit (one pairing check) is the
  more practical candidate. Classical Zether on Soroban is [NET-SOR-25](#NET-SOR-25) (specified, Part Z; the early T0 model puts the transfer verifier over the limit); PQZ is [NET-SOR-26](#NET-SOR-26). Not built.

## <a id="paymeta-relayfee"></a>Pay-meta and relay fee (metatx split)

Spec `docs/superpowers/specs/2026-10-27-metatx-split-design.md` §6.2 / §7.2; rules [CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26) and [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27); decisions CTR-MTX-26 / -27 (commit per family below). Status BUILT unless a line says owed.

- **Pay-meta.** Token `pay_meta(from, to, amount, salt: BytesN<32>, meta: Bytes, valid_until)`: `from.require_auth()` covers
  these arguments (`meta` included), `pay_ref = metaPayId(salt, meta)`, then `pay`'s body (`settle_pay`); event
  `PaymentMeta { pay_id, meta }` before `PaymentSettled`; `MetaTransactionExecuted.digest = op_digest("pay_meta", args)`.
  The token's `PayRef` set is keyed by `(from, pay_ref)` for `pay` and `pay_meta` (the per-payer lane of EVM), so nobody can
  pre-burn another payer's id (T10 fix 1, controller call 2026-10-27, owner may override). Read it with
  `ref_used(from, pay_ref)`.
- **Relay fee.** Contract `contracts/relay-fee`: `relay(payer, target, func, args, salt, token, to, amount, valid_until, relayer)`.
  `payer.require_auth_for_args((target, func, args, salt, token, to, amount, valid_until))`; the payer's auth entry is rooted
  at this router call with the token's `pay` as sub-invocation. `ref = keccak256("scaas.relayfee" ‖ network id ‖ xdr(target) ‖
  keccak256(xdr((func, args))) ‖ salt)`; the payer-signed `salt` is needed because Soroban's target auth is outside `args`.
  Open mode (`to == router`): the router receives, then `token.transfer(router, relayer, amount)`. The target runs
  through `contracts/relay-executor` (`executor.exec`, router-only), never as the router: Soroban grants a contract's
  authority to every contract it calls directly, so a target `token.transfer(router, …)` could take a router balance
  or settle a victim's router-bound `ua_pay` (controller ruling 2026-10-31 after the UA-Soroban T8 review, EVM parity).
  Each constructor names the other, the router checks `executor.router() == self` (`BadExecutor`), a payee equal to
  the router or the executor is `BadPayee`; `deploy.sh soroban <net> relay_fee` derives the router id from a salt and
  deploys the executor, then the router. `ua_relay` is the UA payer form (UA-Soroban spec §5.4). Event `RelayFeePaid`
  topics `ref, target, token`, data `payer, payee, amount` (`payer` / `payee` as `Holder`).
- **Relayer rule.** `relayer.require_auth()` is not satisfied by the transaction source: the node adds an explicit
  `SourceAccount` auth entry rooted at the `relay` call. Node config `params.relay_fee = { router, min_amount }`; the node
  reads `router.executor()` once and refuses a plain pay, a pay-meta or a relay fee to the router or its executor, an
  `approve` to either as spender (an amount 0 withdraws: allowed), a `transfer_from` with either as spender or `to`, and
  a `relay` / `ua_relay` whose relayed target call does any of these (whatever the executor holds or is approved, any
  relay can spend). A router without `executor()` is a config error: its chain's Soroban jobs fail with it (`dead`),
  never requeued (router-fix review, carried to UA-Soroban, controller 2026-10-31).
- **Owed.** A testnet or localnet simulate-and-submit of a `relay_fee` job to prove the `SourceAccount` path (the Rust test
  environment has no transaction source). TODO.md, "metatx split — e2e still owed".
- Commits: pay-meta + router T10 `cd5e508c`, fix 1 `351f67ea`.

## <a id="ua-base"></a>10. UA base (UA-Soroban)

Spec: `docs/superpowers/specs/2026-10-30-ua-soroban-design.md` (rows S1-S18 in §0); decisions: NET-SOR-17 to NET-SOR-27, with the spec rows and the plan's SOR-D1 to SOR-D21 in full. Status: contracts, node adapter, `clientkeys` and the local Protocol 30 end-to-end run **BUILT** on branch `ua-soroban` (tasks T0 to T10, reviewed); UA-8 Part B (`ua8-soroban`, NET-SOR-27) is **BUILT** on branch `ua8-soroban` (tasks M3, B1 to B9a, reviewed; local end-to-end passed; done only after B10, the Stellar testnet run, which waits for T14 on `main` and the date 2026-11-03); classical Zether (`zether-soroban`) is next. Common UA rules are [accounts.md](../contracts/accounts.md#CTR-UA-01) (CTR-UA-*) and the checklist [NET-ALL-84](README.md#NET-ALL-84).

<a id="NET-SOR-17"></a>**NET-SOR-17** — **Records live in a stand-alone `UaRegistry` contract (`contracts/ua-registry`), registered with the portable `register`, no admin and no upgrade.** `register(kind, key_data, attrs, pop, pqz_pop, relayer)` is the CTR-UA-07 form (UA-8 P1); UA-Soroban alone accepted only empty `attrs` (`Attrs`), and UA-8 Part B (`ua8-soroban`) accepts them ([NET-SOR-27](#NET-SOR-27)); `Registration` already has the full layout, so Part B changed no record layout (it added entries, NET-SOR-27). Check order: kind enabled (`KindDisabled`), key data canonical (`KeyData`), id not in the native space (`IdInNativeSpace`, top 96 bits zero), not registered (`AlreadyRegistered`), `keyHash` free (`KeyInUse`), `msig` members known and in MEMBER (`MemberUnknown`), `attrs` (EVM `_attrs`' order, NET-SOR-27; `Attrs` only by UA-Soroban alone), `pop` over `uaMessage(kind, PURPOSE_POP_V2, registrationDigest)` (`Pop`; the typed digest of CTR-UA-07, byte-identical to EVM `UAKinds`: `typed(UARegistration{UAPortableRecord{ua, kind, 0, UAKemRecord{ua, 0, 0, 0}}, 0})` while `attrs` are empty), store, list, event. Nothing is read from the submitter: anyone may submit, a front-runner gets the identical record or a revert. Ids are `keccak256(TAG(kind) ‖ key_data)` with the host keccak, byte-identical to EVM; `Holder { Addr(Address), Ua(BytesN<32>) }` tells a native id from a derived one; a derived id is displayed only as `urn:scaas:ua:v1:<kind name>:<hex32>` ([NET-ALL-21](README.md#NET-ALL-21); the segment is the kind **name** of `kinds.json`, never its code; the hex is lower-case; a `urn:scaas:ua:` prefix in any other case is a UA form refused by `clientkeys`, never read as a strkey). The ML-DSA kinds use only the CAP-0087 host functions (`ml_dsa_44_verify`, `ml_dsa_65_verify`), one `verify.rs` for `register` and `require_authorized`; the registry has no pure-Rust fallback. The `UaRegistered` event (topics `ua`, `kind`) carries the record with `pop` replaced by `pop_hash = keccak256(pop)` ([CTR-UA-33](../contracts/accounts.md#CTR-UA-33)), and `key_data` unless it is over 15,360 B ([NET-SOR-27](#NET-SOR-27)); `pop` stays in the record, read by `registration_of`. Constructor `__constructor(relayers: Vec<Address>)` (may be empty), immutable; tokens, mandate and DEX bind the registry at construction, `None` = the UA ledger is off (`UaLedgerOff`). Shared types (`Holder`, `Order`, `Checked`, `UaAttrs`, `Registration`, `UaRegistryClient`, `op_digest`, `pay_lane`, `meta_pay_id`) and the typed portable helpers (`PORTABLE_DOMAIN_SEPARATOR`, the typehashes, `portable_digest`, `registration_digest`) live in the lib crate `contracts/ua-common` so every contract has one XDR and one digest code. `check-registry-interface.sh` compares the built Wasm's interface with the exact function list (no admin, no upgrade, no setter). **Errors** (`contracterror`, each contract appends and never renumbers): registry `KindDisabled = 1, KeyData = 2, IdInNativeSpace = 3, AlreadyRegistered = 4, KeyInUse = 5, MemberUnknown = 6, Attrs = 7, Pop = 8, NotRegistered = 9, Unauthorized = 10, NotVerifiable = 11, RelayerNotListed = 12` (Part B continues at 13: `PqzHolder`, `KemHolder`, `KemVersion`, `KemKeyLength`, `PqzPopHash`, `KemScheme`, `PqzKeySet`, `KindUnknown`, `KemKeyHash` = 13 to 21, NET-SOR-27); token `UaLedgerOff = 8, UaNotRegistered = 9, UaNotReceivable = 10, UaPoolNotPayable = 11, BadNonce = 12, BadOrder = 13` (after the built 1 to 7); mandate `BadAuth` after its built codes, `Expired = 10, BadNonce = 11, UaLedgerOff = 12, StaleEpoch = 13`; DEX `BadAuth = 9, UaLedgerOff = 10, BadDestination = 11`; relay-fee `BadPayee`, `BadExecutor = 3`. A host crypto failure (an ed25519 / P-256 / ML-DSA verify panic, a P-256 key that is not a curve point) is a host error, not `Pop`. BUILT.

<a id="NET-SOR-18"></a>**NET-SOR-18** — **Seven kinds are enabled; `msig` members are those kinds plus `G…` accounts.** Enabled: `webauthn-p256` 0x0100, `p256` 0x0101, `ed25519` 0x0102, `secp256k1` 0x0108, `msig` 0x0120, `mldsa44` 0x0130, `mldsa65` 0x0131; every other derived kind is `KindDisabled` here and stays valid elsewhere. Checks: `webauthn-p256` the [NET-ALL-04](README.md#NET-ALL-04) grammar (type, challenge = base64url(`ua_msg`), `crossOrigin` absent or false, no `topOrigin`, `rpIdHash`, UP and UV) then `secp256r1_verify`, **no origin compare**; `p256` over `sha256(ua_msg)`; `ed25519` `ed25519_verify` with the contract refusing `y ≥ p`, the eight small-order encodings and the two negative-zero encodings (the host refuses the rest); `secp256k1` `secp256k1_recover` with `s ≤ n/2` and `v ∈ {27, 28}`; ML-DSA over `pq_msg` with the empty context. The WebAuthn signature blob is **canonical only** (owner ruling 2026-10-30, every registry): `webauthn::check` re-encodes the decoded blob and refuses unless it is byte-equal (`Pop`), so a front-runner cannot register the same id with other `pop` bytes (CTR-UA-07 identical-record rule). `msig` (CTR-UA-09 layout, `count ≤ 16`): `auth = abi.encode(MemberSig[])`, canonical encoding only; MEMBER = the enabled single-key kinds plus `stellar-account` 0x0011 (checked by the host, `member.require_auth_for_args((ua, purpose, digest))`; a record with such a member is Soroban-network-local). Change note, owner ruling 2026-10-31, after the final review: 0x0012 dropped from MEMBER (invoker auth): Soroban counts a contract's authority as given for any `require_auth` in a contract it calls directly, and the token, the mandate and the DEX call `registry.require_authorized` directly, so a `soroban-contract` member that is one of them met its own slot for free (an `msig` of an ed25519 UA and the token's `C…` was drained by anyone through `ua_transfer`); an `msig` with a 0x0012 member is `MemberUnknown` at `register`, and `clientkeys` (`soroban.encodeMsig`) refuses one when building; a `C…` stays a native subject and holder; `evm-eoa` 0x0001 members verify the portable purposes only (ECDSA over the record's typed digest by `secp256k1_recover`, no `personal_sign`; `register`'s `pop` today, the `kem` record with Part B) and have **zero signing weight** otherwise (`NotVerifiable`, fails closed as on EVM); `evm-contract` 0x0002 members are never chain-verified here. A **registered** member's slot carries an **empty `keyData`** and the registry reads only that member's `(kind, key_data)` from its own `Signer(ua)` entry, never its `pop` ([CTR-UA-33](../contracts/accounts.md#CTR-UA-33); a non-empty `keyData` is `Pop`); a `G…` member's slot is empty and host-checked. BUILT.

Change (UA-8 Part B, `ua8-soroban` M3, B4; owner rule 2026-10-31 for the minimal form, the rest controller calls, owner may override; BUILT): **(1) Attributes are accepted** ([NET-SOR-27](#NET-SOR-27)). **(2) A stored `msig` signature is minimal**: for the three portable purposes (`register`'s `pop`, `set_kem_key`, `set_pqz_key`) the slots' total weight `T` and the threshold `N` must satisfy `T >= N` and, for every slot `i`, `T - weight(i) < N` (each slot necessary; the check keeps the smallest slot weight, so it is one pass), every slot counting its member's weight, `G…` members included; failure is `Pop` in `register`, `Unauthorized` in the other two. A transaction authorisation (`require_authorized`) is not stored and keeps the old rule (a slot after the threshold fails). Same rule as EVM `UARegistry._msig(…, portable = true)`, which has its own tests; [CTR-UA-07](../contracts/accounts.md#CTR-UA-07). **(3) A classical-dominant `msig` registers with an empty `pop`**, as on EVM (members outside 0x0130 to 0x0133 weigh less than the threshold, `pq_eligible`): a non-empty `pop` is `Pop`, `pop_checked = Chain`, `signable` by member weight as before; one rule on every chain, so a classical `msig` copies byte for byte in both directions. **The `Chain` mark of such an `msig` with relayer-checked members is not a proof of those members:** U8S-D2's "its members proved theirs" holds on EVM, where every member's own registration was chain-verified, and is false here for a member that is a relayer-checked UA (`Relayer(id)`), whose registration was attested by a listed relayer and never verified by the chain. So the mark `Chain` on that `msig` says only that nothing in its `pop` is unverified (it has none); a client that relies on a member re-verifies that member (`checked_of(member)`), as for any relayer-checked record.

<a id="NET-SOR-19"></a>**NET-SOR-19** — **Only a UA that can spend on Soroban may receive.** `receivable(ua)` is true only for a registered, enabled-kind UA whose `pop` the chain checked and, for `msig`, whose Soroban-signable member weight reaches the threshold (`Registration.signable`, fixed at `register`); it is `false` for an unregistered id too. The token tells the two failures apart on the error path only (`record_of(ua).is_none()` is `UaNotRegistered`, else `UaNotReceivable`). In UA-Soroban a signature part the chain cannot verify (an `evm-contract` member slot, any `MemberSig` of a kind outside MEMBER) is `NotVerifiable` whatever `relayer` says; Part B adds the relayer-checked mode on top. BUILT.

<a id="NET-SOR-20"></a>**NET-SOR-20** — **Tokens keep a UA ledger beside the native one: separate `ua_*` entries, lanes in persistent storage, the token's own address as the UA pool.** Entries: views `ua_balance`, `ua_nonce(ua, lane)`, `ua_ref_used`, `registry`; native-to-UA `transfer_to_ua`, `pay_to_ua` (emits the native `MetaTransactionExecuted`, controller ruling 2026-10-30), `mint_to_ua`; signed `ua_transfer`, `ua_pay`, `ua_pay_meta`, `ua_burn`, `ua_cancel_nonce`, `ua_trade`. `from` of a `ua_*` entry is a derived id; natives keep host authorisation. Replay: `UaNonce(ua, lane) → u64` persistent (never temporary, which would reopen spent nonces on expiry); `ua_pay` uses `lane = payLane(pay_ref)`, `nonce = 0`, so `ua_ref_used = ua_nonce(ua, pay_lane(pay_ref)) > 0` (no own entry). `ua_cancel_nonce` signs no nonce, so each digest runs once: persistent `UaCancelUsed(digest)`, checked before the signature, a replay is `BadNonce`. `ua_trade` is called only by a deployed Wasm contract as `dex` (`executable() == Some(Wasm)` before `dex.require_auth()`), requires maker `Holder::Ua` and `sell_token == token`, and keeps a running persistent `UaPulled(order digest) + amount ≤ sell_amount` (EVM `pulled[h]` parity), else `BadOrder`. A relayer-bound entry has `relayer: Option<Address>`; `Some(r)` requires `r.require_auth()` (a lane by an explicit `SourceAccount` entry rooted at the call; the router as the direct invoker of its own fee call). The pool is the token's own address: `balance(token) = Σ UaBalance`, every native to UA move also emits the SEP-41 `transfer` event to or from it; a native `transfer` / `pay` / `mint` to the token's own address is `UaPoolNotPayable`. Events `UaTransfer { from, to, amount }`, `UaPaymentSettled`, `UaMetaTransactionExecuted`. No allowances for UAs. The pool is not checked on `pay_to_ua`'s `from` (native `pay` has no pool check; a pool-held balance could be paid to a UA as to a native address today; controller ruling 2026-10-30). Constructors: token `__constructor(admin, decimals, name, symbol, registry: Option<Address>)`, mandate `(owner: Holder, registry: Option<Address>)`, DEX `(admin, fee_recipient, registry: Option<Address>)`. BUILT.

<a id="NET-SOR-21"></a>**NET-SOR-21** — **The mandate, the DEX and the relay-fee router accept UA holders; the router executes every target through a separate executor.** *Mandate*: owner, delegate and payees are `Holder`; the NET-SOR-16 names are built (`mtx_set_mandate`, `mtx_set_payee`, `mtx_revoke`, `mtx_withdraw`, `mtx_mandate_pay`), each one entry for a native and a UA holder (a native holder: host auth, `auth` empty else `BadAuth`, its lane not consumed). Epoch ([CTR-ACC-07](../contracts/mandates.md#CTR-ACC-07), now on Soroban): `epoch(token)` +1 on every `mtx_set_mandate` and every revoke; the delegate's `mtx_revoke(token, by, epoch, …)` and `mtx_mandate_pay(token, payee, amount, pay_ref, epoch, …)` sign it and are `StaleEpoch` unless current; **the owner may pass any epoch to `mtx_revoke`** (unchecked, EVM parity: the owner's revoke has no epoch and the lane nonce stops replay). *DEX*: `Order` carries `maker: Holder`, `destination: Holder` and the mandatory `relayer` (NET-SOR-10); a UA maker's leg has `auth` over `op_digest(sell_token, "ua_order", (dex, order))` (the sell token's contract id, purpose `trade`; the token's `ua_trade` checks it), `ua_cancel(order, auth)` signs purpose `trade` over `op_digest(dex, "ua_cancel", (order,))`; `filled[order_hash]` bounds partial fills without re-signing. **Every leg is pull-then-pay**, native legs too: the DEX pulls the sell amount into itself (`transfer_from` or `ua_trade`), then pays the destination and the fee (as EVM `settleOne`), so the DEX is a middle hop in events and holds nothing after; a destination equal to the DEX is `BadDestination = 11` before any pull. Differences from EVM: the fee is rounded down (floor; EVM rounds up), there is no `SelfTrade` check, the `Cancelled` event topic is a `Holder`. A relayer that is also a native maker needs two auth entries (its `SourceAccount` entry for `order.relayer` and its order entry). `settle(maker, taker, maker_fill, maker_auth, taker_auth)`. *Router* ([CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27)): `ua_relay(payer, target, func, args, salt, token, to, amount, valid_until, relayer, auth)` with the `relay` ref, then `token.ua_pay(payer, to, amount, ref, valid_until, Some(router), auth)`; `RelayFeePaid` `payer` and `payee` are `Holder`. **Executor** (controller ruling 2026-10-31 after the T8 review, EVM parity; owner may override): Soroban grants a contract's authority to every contract it calls directly, so a router that called the target itself let a relayer submit a victim's router-bound `ua_pay` as the target (fee paid and ref burned without the call; an open-mode fee stuck on the router then drained by `token.transfer(router, attacker)`). The router therefore never calls a target as itself: `executor.exec(target, func, args)` on `contracts/relay-executor` requires `router.require_auth()` and calls the target as the executor, which holds nothing. The two constructors name each other (`RelayFee(executor)`, `RelayExecutor(router)`), the router's constructor checks `executor.router() == self` (`BadExecutor = 3`), a payee equal to the router or the executor is `BadPayee`, and `deploy.sh soroban <net> relay_fee` derives the router id from a salt, then deploys executor and router. The router is **not stateless** (it stores the executor id). BUILT.

<a id="NET-SOR-22"></a>**NET-SOR-22** — **Every UA record, balance, lane and ref is a persistent entry; the lane pays fees, rent and restores; deploy warms every contract.** One entry per key (`Ua(ua)`, `Key(key_hash)`, `List(kind, i)`, `Count(kind)`, `Signer(ua) → (kind, key_data)`, `UaBalance`, `UaNonce`, `UaPulled`, `UaCancelUsed`), instance storage only for constructor constants, temporary only for SEP-41 allowances. `Signer(ua)` is the fifth persistent entry of a record: it duplicates the key data so a member check reads 384 B instead of the 16,768 B record (identical CPU 3,279,036 and memory 87,048), write-once. TTL `extend_ttl(30 days, 60 days)` on each write and in-transaction read, the mandate and DEX instances too; views extend nothing; **no node TTL job**. An archived entry is restored by the next transaction that lists it (Protocol 23), never read as absent, so an archived nonce cannot be replayed. The lane pays the resource fee, rent and restore, bounded per job by `params.max_deposit_per_job`; users and UAs hold no XLM. **First-call rent** (local Protocol 30 run, stroops): a fresh contract's first call pays the 60-day TTL rent (`set_market` 83.8 M, `mtx_set_mandate` 88.0 M, a first relayed `ua_relay` 51.5 M against about 0.7 M warm), so `deploy.sh` **warms every deployed contract** (extends the instance and the code to 60 days, 1,036,800 ledgers, paid by the deployer; token, mandate, DEX, registry, executor, router): after it the same calls cost 181 k, 502 k and 438 k and every relayed job at most about 1.1 M. A per-job resource-fee cap for Soroban jobs is a TODO (operator policy). BUILT.

<a id="NET-SOR-23"></a>**NET-SOR-23** — **The node relays UA jobs as `ua_metatx` and never lends a lane's authority.** Job `{kind: "ua_metatx", op: {contract, function, args, auth?: [{payload, from, signature}], valid_until?}}`, `args` every argument by the contract's name ([job-api.md](../node/job-api.md#soroban-ua-metatx-jobs); a string is `HEX_ARGS_REFUSED`; `op.kind` present is refused; `op.valid_until` is optional and never read); `call` jobs for the registry writes are UA-8 Part B (below). Allow-list by function and contract class (arity includes `auth`): token `ua_transfer`, `ua_pay`, `ua_pay_meta`, `ua_burn`, `ua_cancel_nonce`; router `ua_relay`; DEX `settle`, `ua_cancel`; mandate `mtx_set_mandate`, `mtx_set_payee`, `mtx_revoke`, `mtx_withdraw`, `mtx_mandate_pay`. `valid_until` and the contract come from the signed arguments ([NET-SOR-15](#NET-SOR-15)); the op digest is recomputed and is the job id. `op_consumed`: `ua_nonce(ua, lane) > nonce` or `ua_ref_used` ⇒ consumed ([NET-SOR-12](#NET-SOR-12)). A `signed_op` is no open host call: it runs on a token, a mandate (`params.mandates`), the DEX or the router of the chain's `params`, never on the registry (`CALL_TARGET_REFUSED`), and a plain one that is no token payment counts in the `call` share ([job-api.md](../node/job-api.md#soroban-signed-op)). **Lane-authority rule**: the adapter attaches only the subject's signed entries and, when `relayer = Some(lane)`, one `SourceAccount` entry rooted at exactly the job's top-level call; any other recorded `SourceAccount` entry fails the job before submission (the Protocol 30 host itself refuses the smuggled entry at simulation with `Error(Auth, InvalidAction)`, before the guard; the guard is the second line). The lane's entry is root-only, so a lane that is a `G…` `msig` member never lends that membership: the registry's nested `lane.require_auth_for_args((ua, purpose, digest))` is not in the entry, and a recorded lane entry with a `registry.require_authorized` sub-invocation fails the job. **Executor refusal**: a `pay`, `pay_meta`, `mtx_mandate_pay` payee, `mtx_withdraw` destination, `mtx_set_payee` payee (when allowing), `mtx_set_mandate` delegate (an executor delegate is anyone's: `relay` runs `mtx_mandate_pay` as it), either `settle` destination, or relay-fee job whose recipient is the router or the executor is refused (payments there are stranded or executor-drainable). **Archived entries** (BUILT, NET-SOR-11's node half): a simulation that restores archived footprint is accepted when its declared fee is ≤ `params.max_deposit_per_job` (absent = 0 = none), else `Revert`. **StaleEpoch**: the node holds no delegate key; a delegate job refused `StaleEpoch` re-reads `epoch(token)` and returns the signed and the current epoch in the failure reason; the client re-signs (EVM parity). **Events**: `UaTransfer`, `UaPaymentSettled`, `UaMetaTransactionExecuted`, `UaRegistered` and `RelayFeePaid` rows carry the `Holder` fields as **plain strings** (`G…`, `C…` or `0x` + 64 hex, as the NEAR and Algorand rows; the Holder tag decides the form and the three forms cannot collide; a URN is built by the client from the kind, never by the node; controller ruling 2026-10-30, owner may override); the EVM rows use the pool sentinel with `from_ua` / `to_ua`, a cross-family alignment would need an owner ruling. A lane-bound job (relayer bound to one lane) claimed by another lane goes dead on a two-lane chain: [NODE-JOB-08](../node/job-api.md#NODE-JOB-08) `lane_hint` is the open item (TODO). BUILT.

**`call` jobs** (UA-8 Part B, `ua8-soroban` B6; owner's explicit-parameter rule of 2026-10-31 over UA8-D23's `op.extra.call` XDR; BUILT): `{kind: "call", op: {contract, function, args, valid_until}}`, every field required, any other field refused at every level (no XDR, `auth`, `extra` or `payload` can enter). `contract` must equal `params.ua_registry` (a `C…`; unset: every `call` job is refused); `function` is one of the registry's eight writes (`register`, `register_msig`, `register_webauthn`, `register_musig2`, `register_frost`, `set_kem_key`, `set_pqz_key`, `store_pqz_pop`); `args` holds the contract's own argument names and the node builds the XDR; `valid_until` is the transaction's `max_time`, after now and at most 3,600 s later (`MeshParams.max_valid_for_secs`, no `node.toml` knob). The fields per function are in [job-api.md](../node/job-api.md#soroban-call-jobs). A job that names `relayer` must name this lane, and only when the lane is in the registry's list (`relayers()`, read once and kept, the list being immutable); the node runs `scaas_ua::ua8::check_*` before simulation, only for a part the chain cannot verify, and adds exactly one `SourceAccount` entry rooted at the call whose single argument is `attest_digest` of the call's arguments. A simulation that records any other signer is refused before signing; a transaction over `tx_max_size_bytes` or an entry over the entry limit is `Revert` at `build` (`dead` on one claim, nothing signed); a failed `relayers()` read holds only relayer-mode jobs, never payments. `call` jobs are free to the client (P9) and `max_deposit_per_job` caps only restores, so what a `call` job costs the lane is limited by the spend breaker ([NET-SOR-14](#NET-SOR-14)) alone. **Open for the owner:** (a) an `msig` whose `pop` has a `G…` member's slot beside a relayer-checked slot is refused off chain (`UAKeyData`, B5) and cannot go through a `call` job (a recorded entry that is not the lane's, B6), so such records need another path; (b) whether `call` jobs should stay free to the client. Neither is decided.

<a id="NET-SOR-24"></a>**NET-SOR-24** — **Pins, test order and measured limits.** `soroban-sdk = "=30.0.0-rc.1"` for the whole workspace (swapped to 30.0.0 before the testnet run); `stellar-cli` 30.0.0 (own directory, the older 22.2.0 removed); `stellar/quickstart@sha256:e05d68bb3b2629a829310dc3434fc0ee3f801854bdfa1a7c8c362d2f1c9060f8` (Core v30.0.0, RPC 30.0.0) run `--local --protocol-version 30 --limits testnet` by `scripts/quickstart.sh`. Order: unit tests (SDK testutils at Protocol 30), local quickstart (`e2e-local.sh`: `e2e_soroban` 1/1 and `e2e_soroban_ua` 8/8, every contract deployed through `deploy.sh`), Stellar testnet only after 2026-11-03 and only when the RPC reports Protocol 30. Two branches: `ua-soroban` first, then `ua8-soroban` (Part B) on the owner's go. **Network limits** (`stellar network settings`, quickstart testnet limits): 400,000,000 instructions, 41,943,040 B memory, 200,000 read bytes, 132,096 write bytes, 132,096 B transaction, 65,536 B largest entry, 16,384 B contract events plus return value, 131,072 B Wasm, 400 entries (200 writes). **T0 spike figures** (`runs/2026-10-30-ua-soroban-t0-spike.txt`, SDK 30.0.0-rc.1 over env-host 30.0.0, instructions / events / largest entry): `register` `mldsa65` 4,361,999 (1.1 %) / 2,628 B (16.0 %) / 5,820 B (8.9 %); 3-member `msig` of `mldsa65` 11,639,166 (2.9 %) / 788 B (4.8 %) / 11,292 B (17.2 %); `ua_pay` passkey to an `mldsa65` UA (token and registry) 6,043,670 (1.5 %), 9 entries, 692 B events; ML-DSA verify alone `mldsa44` 1,608,400, `mldsa65` 2,572,818; passkey `require_authorized` 3,152,068. **The largest `msig`** is the spec cap `count ≤ 16`: 16 `mldsa65` members use 58,175,514 instructions (14.5 %), a 57,520 B entry (87.8 % of 65,536 B), 59,352 B transaction, 1,256 B events; the 64 KiB entry limit would bind at about 18. Before the owner ruling on `UaRegistered` and `MemberSig` ([CTR-UA-33](../contracts/accounts.md#CTR-UA-33)) the same 3-member `msig` overran the events limit (17,228 B against 16,384 B). Wasm: registry 21.5 KB at UA-Soroban T10 (stale since UA-8 Part B: 52,519 B after B7b, the last measurement; B7c and later changes not measured). Local end-to-end fees (stroops, `runs/2026-10-31-ua-soroban-e2e-local.txt`): `register` passkey 1,441,492, `mldsa65` 7,010,351; `ua_pay` 176,511; `transfer_to_ua` 17,394; `mtx_mandate_pay` 293,424; `settle` with a UA maker 1,093,539; `ua_relay` 437,890. `ua-ops.json` (`vectors/ua-ops.json`) is generated by `clientkeys` (`scripts/soroban-ua-ops-vectors.mjs`, `--check`) over the passphrase `Standalone Network ; February 2017` and reproduced by the contracts, the adapter and `clientkeys`; the e2e signs through `scripts/soroban-sign.mjs`. BUILT.

<a id="NET-SOR-25"></a>**NET-SOR-25** — **Classical Zether on Soroban is its own track in this round (Part Z, branch `zether-soroban` after `ua-soroban`).** Port the EVM classical Zether (BLS12-381, `NormalZetherToken` / `WrappedZetherToken`) to the BLS12-381 host functions (CAP-59) with the proof bytes of `clients/zether-prover` (one prover, two verifiers, shared vectors), feature parity with the EVM token unless the measurement forces a cut; ciphertexts stay in contract state ([zether.md](../contracts/zether.md); never-lose rule). **Measure first** (Z0): the T0 model estimate of the transfer verifier is 536 M (one recipient) to 2,409 M (eight) instructions against the 400 M limit, so a verify that does not fit is a STOP for the owner (split over transactions, a smaller range, Groth16, cheaper host functions). The Soroban statement header is chain id 0, `chainUid` = the network id, a 32-byte token word; the EVM bytes are unchanged. The Zether PoP kind 0x0141 stays off in the Soroban registry until the token enables it. Status: **SPECIFIED**, not built.

<a id="NET-SOR-26"></a>**NET-SOR-26** — **There is no post-quantum Zether (PQZ) on Soroban.** No PQZ verifier and no PQZ token exist there. Part B stores PQZ attributes unproven (`checked = None`, `proven = false`) with the key and the proof bytes in contract state (`PqzK(ua)`, `PqzP(ua)`), never only a hash; no PQZ ciphertext ever exists on Soroban, so the never-lose rule is met vacuously. Status: the unproven storage is **BUILT** (UA-8 Part B, `ua8-soroban` B2, B3; [NET-SOR-27](#NET-SOR-27)); a PQZ verifier and a PQZ token do not exist and are not built. Classical Zether ([NET-SOR-25](#NET-SOR-25)) and PQZ stay separate items.

<a id="NET-SOR-27"></a>**NET-SOR-27** — **UA-8 records on Soroban (Part B, `ua8-soroban`): `register` with attributes, KEM and PQZ records in state, a `checked` mark per part, a relayer-checked mode for what the chain cannot verify; every limit is a byte count per entry and final for a deployment.** Status: **BUILT** (tasks M3, B1 to B9a; local Protocol 30 end-to-end passed); **done only after B10**, the Stellar testnet run, which has not happened. The rules are the UA-8 spec P1 to P11 ([CTR-UA-31](../contracts/accounts.md#CTR-UA-31), [CTR-UA-34](../contracts/accounts.md#CTR-UA-34)); U8S-D1 to U8S-D12 and UA8-D18 to UA8-D24 are in full in [decisions.md](../decisions.md) (section Networks, Soroban). The registry has no admin and no upgrade, so nothing below can be raised after deployment.

- **Entries (U8S-D3).** `Ua(ua) → Registration` with `attrs.pqz_key` and `attrs.kem_pk` empty (`pqz_pop_hash`, `kem_version` and the hashes kept); `PqzK(ua) → (key, sig, Checked, pqz_pop_hash)` (`sig` empty and `Checked` = `pop_checked` for a key that came with `register`); `PqzP(ua) → Bytes` (the PQZ proof); `Kem(ua, version) → (pk, sig, Checked)`; `KemMax(ua) → u64`; `KeyR(kh)` (below); `Signer(ua)` as before. The PQZ key and proof bytes live in state, never only as hashes (never-lose rule, [NET-SOR-26](#NET-SOR-26)). `registration_of` returns what EVM `registrationOf` returns for the same history. Every entry is persistent and extends `extend_ttl(30 days, 60 days)` on each write and in-transaction read; views extend nothing; no node TTL job ([NET-SOR-22](#NET-SOR-22), UA8-D22).
- **Writes** ([CTR-UA-36](../contracts/accounts.md#CTR-UA-36), explicit typed parameters, no fee form: P9). `register(kind, key_data, attrs, pop, pqz_pop, relayer)`, `register_webauthn`, `register_msig`, `register_musig2`, `register_frost` (typed forms of the same record, same id and bytes as the packed `register`, which stays), `set_kem_key(ua, version, kem, sig, relayer)`, `set_pqz_key(ua, pqz_key, pqz_pop_hash, sig, relayer)`, `store_pqz_pop(ua, pqz_pop)`. `attrs` is `{pqz_key, pqz_pop_hash, kem: {scheme, mlkem_ek, x25519}, kem_pk_hash}`; `register` checks them in EVM `_attrs`' order (PQZ holder `PqzHolder`, KEM holder `KemHolder`, `pqz_pop_hash` rules `PqzPopHash`, a given `pqz_pop` hashing to it, the PQZ key's length, one of the four set lengths 16,384 / 18,432 / 20,480 / 22,528 B else `KeyData`, the KEM key). KEM keys: CTR-UA-32, versions ≥ 1, each `(ua, version)` once, in any order, never revoked; a key given in whole at `register` is not refillable; `set_kem_key` version 0 only fills a hash commit, with an empty `sig`, open to anyone. `set_pqz_key` is write-once (`PqzKeySet`): there is no verifier, so nothing is ever replaced. `store_pqz_pop` is open to anyone, hash-checked, a no-op when stored. The PQZ proof is never checked (`proven = false`, `pqz_pop_checked = None`). Errors 13 to 21 continue the enum ([NET-SOR-17](#NET-SOR-17)).
- **Views.** `registration_of`, `pop_of`, `pqz_pop_of`, `checked_of(ua) → (pop, pqz_pop, kem)`, `kem_key_of(ua) → (version, kem, sig, checked)` (follows `KemMax`), `kem_key_at(ua, version)`, `pqz_key_of(ua) → (key, pqz_pop_hash, proven, checked)`, `pqz_key_sig_of`, `kind_name(kind)`, `record_of`, `key_owner`, `ua_of` and its typed twins `ua_of_msig`, `ua_of_webauthn`, `ua_of_musig2`, `ua_of_frost`, `receivable`, `relayers`, `ua_count`, `ua_at`, `ua_page`.
- **`checked` (U8S-D8, UA8-D20).** `Chain`: the seven enabled kinds (0x0100, 0x0101, 0x0102, 0x0108, 0x0120 with chain-verifiable slots, 0x0130, 0x0131). `Relayer(id)`: `bip340` 0x0103, `schnorr-bn254` 0x0104, `schnorr-bls12381` 0x0105, `bls12381-minsig` 0x0106, `bls-bn254-minsig` 0x0107, the group kinds 0x0110 to 0x0113, `fndsa512` 0x0132, `slhdsa128s` 0x0133 and `zether-bls12381` 0x0141 (classical Zether, until its own round makes it `Chain`); any other kind is `KindDisabled`. A relayer-checked record: key data checked for length and layout only (the relayer checks the canonical form with `scaas_ua::keydata`: 75 of `kinds.json`'s 130 `invalid[]` rows of these kinds store on chain, marked, 55 are `KeyData`), `signable = false`, no `Signer`, never receivable, `require_authorized` is `Unauthorized`. `None` for the PQZ proof always. A part the chain verifies is always verified there, open to anyone, whatever `relayer` says.
- **The relayer list and the attestation (UA8-D18, UA8-D19, S16).** The list is the constructor's `relayers: Vec<Address>`, immutable, no writer. A part the chain cannot verify is stored only through `attest`: no `relayer` is `NotVerifiable`, a relayer outside the list is `RelayerNotListed`, then `relayer.require_auth_for_args((digest,))` with `digest = attest_digest(contract, function, args) = sha256(xdr(Vec[Symbol("scaas_attest_v1"), network_id, contract, Symbol(function), Vec(args)]))` over the whole argument tuple, `relayer` included (owner decision 2026-11-01; it replaced `require_auth()` over the whole call, which carried every argument twice). An attestation never lets a key authorise anything (asserted on both hosts). The part carries `Checked::Relayer(r)` in state and event; an `msig`'s mark follows the slots given, one attestation for all. The node's auth entry is 144 B flat. Measured: an entry on another registry is `Error(Auth, InvalidAction)`, the same transaction signed for another network is `txBAD_AUTH`, a digest of another entry or another field is refused (every class of every entry is tested, B7b).
- **Delisting means a new registry (change to P11.6, controller call, owner may override).** The list is immutable (S16), so "the operator delists such a relayer" cannot happen on a deployment: a bad relayer is removed by a new registry and new tokens bound to it (records of the old one stay readable); the mitigation to state to operators is to list a lane whose signing key can be rotated. A listed relayer that stores a bad record takes that write-once `(ua, version)` slot on this chain only, and also **pins `kem_key_of` through a high version** (`KemMax` follows the highest version stored, a later lower version never lowers it): clients use `kem_key_at(ua, version)` with a version they verified, not `kem_key_of`, and re-verify before using any key read from a relayer-checked record.
- **A marked record blocks no `Chain` kind (change to U8S-D8 and P11.6, controller call, owner may override; B4 review).** A relayer-checked record keeps its key in `KeyR(kh)`, not in `Key(kh)`: a `Chain` kind checks only `Key`, a relayer kind checks both. Without it a listed relayer could store a `bip340` record over a victim's `secp256k1` x with no proof, and the real key would be `KeyInUse` for good. Among relayer kinds P11.6 stands. **`key_owner` can still return a marked-only record** (it returns `Key` before `KeyR`), so a reader that treats `key_owner` as proof of control checks `checked_of(ua)` first.
- **A mixed `msig` keeps `signable` (change to the UA-Soroban spec §6 and S9, controller call, owner may override; B4).** The spec says "a `Relayer` record has `signable = false`" and S9 requires "`pop` checked by the chain". Both read as the single-key rule. For an `msig` whose `pop` is `Relayer` only because a member or slot is relayer-checked, `signable` counts only `Signer` members and `G…`: a relayer-checked member weighs 0 and signs nothing, so an `msig` whose `Signer` members alone reach the threshold is `signable` and receivable even though its `pop` is `Relayer`. Refusing it would let a bad relayer brick such an `msig`, and an honest EVM copy could never sign. If wrong: refuse in `check_msig`, one branch. An `msig` with a classical-dominant empty `pop` and relayer members: see [NET-SOR-18](#NET-SOR-18).
- **Events (U8S-D4, CTR-UA-33.A amended for Soroban, owner 2026-11-01).** `UaRegistered` carries the record with `pop_hash`, `attrs` as stored (so `pqz_key` and `kem_pk` empty) and `key_data` **unless it is over `EVENT_KEY_DATA_MAX` = 15,360 B**, when `key_data` is empty, decided by its length alone: only a `frost-bn254` key reaches it (the events limit is 16,384 B; the event is `key_data` + 892 B, exactly, at every measured shape; 120 shapes, thresholds 2 to 16, all register; 116 keep `key_data`, four are emptied: 15 of 15, 14 of 16, 15 of 16, 16 of 16). **A log-only indexer needs one `record_of` read for those four shapes**, as `pop` already needs on every family (`popHash` is in the event, the bytes are in state). `UaPqzKeySet`, `UaPqzPopStored`, `UaKemKeySet` carry hashes (`pqz_key_hash`, `kem_pk_hash`, `sig_hash`, `checked`), never instead of state; `register` logs its attribute writes with them. The constant is set against a network limit of 16,384 B; a limit voted lower than the largest real event (15,840 B) would refuse those keys again and the contract cannot change.
- **Published limits, bytes per entry, permanent.** A stored signature is bounded by the entry it lives in (65,536 B, `contract_data_entry_size_bytes`) and the transaction by 132,096 B; both are the quickstart's `--limits testnet` figures and T14 / B10 re-read them on a real network. The rules: `PqzK(ua) = key + 64 + Σ slots`, `Kem(ua, v) = 1,601 + 64 + Σ slots`, `Ua(ua)` = the record with `pop = 64 + Σ slots`, where a slot is `192 + ⌈sig / 32⌉ × 32` B: 8,064 B for `slhdsa128s`, 3,520 B for ML-DSA-65, 2,624 B for ML-DSA-44, 864 B for `fndsa512`, 256 B for `ed25519`. Limits that follow (measured on the real host, `e2e_ua8_relayer_table`, `e2e_ua8_network_fit`; the rows use junk signatures of the kind's length, which the chain stores unread, so they measure size, not `check_*`):

  | write | `slhdsa128s` slots | `fndsa512` slots | ML-DSA-65 slots |
  |---|---|---|---|
  | `register` + PQZ key + KEM key, every set, with or without the proof | 7, 8 refused (entry) | 16, 17 refused (`KeyData`, the member cap) | 16 fit by B0, 56,384 B of `pop` |
  | `set_pqz_key` | 6 / 5 / 5 / 5 at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`, one more refused (entry) | 16 at every set | 13 / 13 / 12 / 12, one more refused (entry; no relayer asked) |
  | `set_kem_key`, every set | 7, 8 refused (entry) | 16 | 16 (B0, 58,168 B entry) |

  Beyond these an `msig` that needs more signing slots of that kind than the row says **can never be registered, or never gets that record, on Soroban**: the structure is the id, there is no upgrade, so the limit is final for a deployment. Concretely an `msig` needing 8 or more `slhdsa128s` signatures cannot register here at all; one that registered without a PQZ key and needs more signing slots for `set_pqz_key` than the table's row (`slhdsa128s`: 6 at `n2048-kmax1024`, 5 at the other sets; ML-DSA-65: 13 or 12) can never add one here, and its EVM record cannot be copied with that key. Nothing is lost by the refusal (the record stays valid on every chain that verifies it; a refused write stores nothing). A key can always register through `register` itself (the key in `PqzK`, the `pop` in `Ua(ua)`) at any size B0 measured: with `slhdsa128s` slots the table above applies. The largest transactions by set, last accepted rows of the table (transaction B, largest entry B): `register_msig` 7 `slhdsa128s` + PQZ + KEM 76,380 / 78,428 / 80,476 / 82,524 (57,492); the same with the proof 104,680 / 108,920 / 113,124 / 118,112 (57,492); `set_pqz_key` 5 `slhdsa128s` 56,944 / 58,992 / 61,040 / 63,088 (57,020 to 63,164), and 6 at `n2048-kmax1024` 64,880 (65,084); `set_kem_key` 7 `slhdsa128s` 58,204 (58,340) at every set; `register_msig` 16 `fndsa512` + PQZ + KEM 34,740 / 36,788 / 38,836 / 40,884 (16,636 to 22,780), with the proof 63,040 / 67,280 / 71,484 / 76,472 (28,312 to 35,600). The largest relayer-mode transaction measured is 118,952 B of 132,096 B and the largest entry 65,084 B. Over the entry limit a write lands and fails at the lane's cost (0.039 to 0.065 XLM, B7) unless the build pre-check refuses it first ([NET-SOR-14](#NET-SOR-14)); over the transaction limit `sendTransaction` answers `ERROR` and the node's `build` refuses it first.
- **The B0 limits and the UA8-D21 case (run log `smartcontracts/soroban/runs/2026-10-31-ua8-soroban-b0-spike.txt`).** Case "full in one `register` for every set, `store_pqz_pop` for a proof stored later": a single `mldsa65` with PQZ key, proof and KEM key fits one `register` at every set (largest `n2816-kmax65536`: 66,344 B of transaction, 68,600 B written, largest entry `PqzP` 35,608 B, 10.1 M of 400 M instructions); the split also fits; no STOP (C12). There is no hash-only fallback and none was needed.
- **The largest `msig` with PQZ + KEM** (measured on the real host, `e2e_ua8_network_fit`, before the attestation change, which affects the transaction size by 144 B and not the writes): 16 ML-DSA-65 members at `n2816-kmax65536` in one `register_msig`: 63.7 M of 400 M instructions (15.9 %), 7.18 MB memory, 118,764 B written (89.9 % of 132,096 B), largest entry 57,644 B (88.0 %), 2,068 B of events; `set_kem_key` of the same `msig` 58.1 M instructions, 58,312 B written. `set_pqz_key` for an `msig` whose `pop` has 16 slots is impossible (the minimal rule needs all 16 slots again, over the entry limit).
- **A copy to and from EVM.** An EVM without the ML-DSA precompile refuses an `msig` of two ML-DSA-65 signers (`UAKeyData(0x0120)`: its verify budget), so the `msig-pq` record is not copied there; an `mldsa65` record reaches such an EVM chain only after the two `cacheExpandedKey` transactions (9.6 M and 13.4 M gas, from anyone, on each chain), and a node `call` job cannot send them (the selector is not in the call table), so the copier's own account does. `register` takes the packed key data of `webauthn-p256`, MuSig2 and FROST as well as the typed forms, as EVM does (same bytes, same id, same record), and refuses only `msig`; the `scaas-node/src/abi.rs` comment that said it refuses those kinds is corrected, and the `portable.json` note "register(0x0100, ...) is refused" is wrong for the same reason (it is generator text, not edited: [decisions.md](../decisions.md)).
- **Clients.** `clientkeys` and `scaas-ua` (feature `pq`, exact pins, `slh-dsa =0.2.0-rc.5` is a release candidate to re-pin before the mainnet freeze) re-verify any record read from a relayer-checked chain; a record that fails is ignored. An `msig` with a `G…` member beside a relayer-checked slot is refused off chain, and not through a `call` job either (open for the owner, [NET-SOR-23](#NET-SOR-23)).
- **Measured and not measured.** The row "5 `slhdsa128s` slots + PQZ + KEM without the proof" of the first `network_fit` block was deleted with that block (ua8-soroban B7b review, restored in part in B7c) and is not measured after the attestation change as a row of its own: the table's asserted edge is 7 slots, so 5 lies under it. The only figure on disk for 5 slots is B7's, before the change: 130,912 B of transaction at `n2816-kmax65536` with 6 refused, a figure the change replaced. No figure is given here for the Stellar testnet: B10 has not run.
