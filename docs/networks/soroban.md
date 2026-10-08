# Soroban (Stellar and Pi Network)

Common rules for every family: [networks/README](README.md). Status: contracts, adapter and client verifier
**BUILT**; items marked SPECIFIED are normative and not yet in code. **Soroban is not on the mesh**: jobs reach a
Soroban lane only through the job API (owner; [NODE-MESH-07](../node/mesh.md#NODE-MESH-07)).

## Overview

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

## Payload

<a id="payload"></a>

<a id="NET-SOR-16"></a>**NET-SOR-16** — **Target: both kinds are host authorizations of `mtx_` functions**
([NET-ALL-26](README.md#NET-ALL-26)–[NET-ALL-29](README.md#NET-ALL-29); owner 2026-10-08). Status: **SPECIFIED**.
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

## Signatures

<a id="signatures"></a>

| `from` kind | Signer | Signature in the auth entry | Client check |
|---|---|---|---|
| `G…` (Freighter, seed key `m/44'/148'/i'`) | the account's ed25519 key (the host checks threshold/signers) | `Vec[Map{public_key: Bytes32, signature: Bytes64}]` (the relayer builds it from the 64 bytes) | real ed25519 with the master key inside the strkey ([INT-ERP-14](../integration.md#INT-ERP-14)) |
| `C…` = `scaas-account` (multi-key subject account) | a P-256 WebAuthn passkey or an ed25519 seed key | the account's ScVal `Signature` (XDR hex, inserted verbatim by the relayer) | none (`None`) — the node's simulation decides |

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
23+); the contracts build with soroban-sdk 25.3.0 and Rust 1.90.

**`scaas-account.__check_auth(signature_payload, Signature, contexts)`:**

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
only `type`/`challenge`/`origin`, `account/src/lib.rs:149-153`, so an RP page embeddable in a cross-origin iframe —
Permissions-Policy `publickey-credentials-get` — yields valid assertions under an attacker's page). Test: an assertion
with `crossOrigin:true` ⇒ `BadClientData`.

## Contracts

<a id="contracts"></a>

`smartcontracts/soroban/contracts/{token,mandate,dex,account}/`:

- **`scaas-token`** — SEP-41 (`balance`, `transfer`, `transfer_from`, `approve`, `allowance`, `burn`, `burn_from`,
  `decimals`, `name`, `symbol`) + admin `mint` + `pay(from, to, amount, pay_ref, valid_until)`: `from.require_auth()`,
  expiry, `pay_ref` once per `from` and `amount > 0` ([NET-SOR-09](#NET-SOR-09)); emits
  `PaymentSettled{from,to | amount,pay_ref}` and `MetaTransactionExecuted{from | digest}`. **`approve` only to a
  contract spender** (`executable()` = Wasm or StellarAsset; [CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)).
  No fee. Storage: balances, allowances and `pay_ref` entries persistent, with TTL extension.
- **`scaas-mandate`** (as the EVM `MandateWallet`): one owner; funds inside the contract; per token: delegate, limits
  per payment and per period, period, expiry, allowed payees; `pay_under_mandate(token, payee, amount, pay_ref,
  valid_until)` — `delegate.require_auth()` then `token.pay(self, payee, …)` (the same `PaymentSettled`, so the client
  reconciles it like a manual payment); `pay_ref` once (its own `Key::Ref(pay_ref)`; only the delegate spends it);
  `revoke(token, by)` by the owner **or** the delegate (kill switch); owner `withdraw`. The owner is gasless naturally:
  its native authorization goes through a relayer (no `executeAsOwner` needed).
- **`scaas-account`** — the multi-key subject account above.

<a id="pay-ref"></a><a id="NET-SOR-09"></a>**NET-SOR-09** — **`pay_ref` is one-shot per `(from, pay_ref)`, not
globally, and `pay` moves a positive amount.** `Token::pay` keys `Key::PayRef(from, pay_ref)`; `ref_used(from,
pay_ref)`; `pay` with `amount ≤ 0` (`amount <= 0`) ⇒ `Error::NonPositiveAmount` (`i128`: a negative amount is refused too; owner
decision on the error name). The mandate path keys by the mandate's address automatically and keeps its own
`Key::Ref(pay_ref)`. Why: with a global key, a stranger's 0- or 1-unit `pay(attacker, receiver, …, victim_ref)` burns
the victim's ref and blocks the victim's signed payment; booking already sums settlements per `entry_ref` and
receiver, so a stranger's payment with someone else's ref is only money in (same direction as Cosmos, which never
locks `pay_ref`, and the EVM `MetaToken`). SPECIFIED (as built the key is global, `token/src/lib.rs:203-209`, and
`check_amount` accepts 0, `:113-117`). Tests: a third party `pay(self, x, 0, victim_ref)` ⇒ `NonPositiveAmount`;
`pay(self, x, 1, victim_ref)` does not block the victim's `pay`; the same `from` paying the same `pay_ref` twice (two
signatures) ⇒ `RefUsed`; `pay_under_mandate` cannot be burnt by a third party.

<a id="ttl"></a><a id="NET-SOR-11"></a>**NET-SOR-11** — **Entries in daily use extend their TTL, and an archived
footprint is restored by the lane and retried.** `pay_under_mandate` extends `Key::Payee` on every use;
`scaas-account.__check_auth` extends the account instance; when simulation returns a `restorePreamble`, the lane
submits `RestoreFootprintOp` with the preamble's footprint and fee, then rebuilds the job; the restore rent is a
lane-paid deposit bounded by `chain.max_deposit_per_job` and charged to the `from` subject
([NODE-LANE-18](../node/submit-lanes.md#NODE-LANE-18)). SPECIFIED (as built a `restorePreamble` ⇒ `Revert` ⇒ job `dead`,
`soroban.rs:325-327`; only `set_payee` extends the payee, `mandate/src/lib.rs:131-140`, `:167` only `has`; the account
extends only on `save`, `account/src/lib.rs:75-78`, `__check_auth` `:215-229` does not — so an account in daily use is
archived ~60 days after its last key change, a payee 60 days after it was allowed). Tests: TTL after
`pay_under_mandate` / `__check_auth` is raised; end to end: archive ⇒ restore ⇒ `mined`. System relayers may also call
`extend_ttl` for long-lived state.

## DEX

<a id="dex"></a>

`scaas-dex` `settle(maker, taker, maker_fill)`: `require_auth_for_args((order,))` for **both** orders (and, per [NET-SOR-10](#NET-SOR-10), `order.relayer.require_auth()`); both price limits
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
  entries while a `signed_op` job carries one signature; the adapter accepts
  `extra.auth = [{from, payload, signature, public_key}]` (same rules), so the matcher only queues jobs with two
  signatures. The Soroban book and matcher are a seam.

## Relayer

<a id="relayer"></a>

- Lane = `G…` account derived at `m/44'/148'/i'` (SEP-0005); one transaction in flight per lane (`lane_runner`); the
  **committed** sequence is read (`getLedgerEntries` of the account); the transaction uses `seq+1` and
  `time_bounds.max_time = valid_until`, so a transaction that never lands expires with the payload and the lane
  sequence never hangs.
- `build`: decode `payload` (XDR) → check `network_id` = sha256(configured passphrase) (stops cross-network ops before
  any fee), the invocation's contract = `op.contract`, `from` matches; build the `SorobanAuthorizationEntry` (Address
  credentials with the payload's nonce/expiry + signature); `InvokeHostFunction` = exactly the invocation;
  `simulateTransaction` (auth enforced) ⇒ footprint + resource fee; simulation error ⇒ `Revert` (job dies); network
  error ⇒ `Transport`.
- `sign`: `fee = base + min_resource_fee·1.15`, `seq = committed + 1`, ed25519 over
  `sha256(TransactionSignaturePayload)`; `tx_id = 0x‖hex(hash)`.
- `submit`: `sendTransaction`; `tx_status`: `getTransaction` (SUCCESS / FAILED / NOT_FOUND). Classes
  ([NODE-LANE-14](../node/submit-lanes.md#NODE-LANE-14), already right in code): `sendTransaction` `ERROR` = not in a
  ledger ⇒ free requeue (`soroban.rs:368-378`); `TRY_AGAIN_LATER` / network error ⇒ resend the same bytes;
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
`getTransaction`, for both `SUCCESS` and `FAILED`) and `lane_balance` (native balance of the lane and of the
`fee_bump_lane`)** to the breaker ([NODE-LANE-13](../node/submit-lanes.md#NODE-LANE-13)). SPECIFIED (as built neither is
implemented, `adapter.rs:112-118`, so `gas_budget` and `min_relayer_balance` are blind on Soroban; the breaker fills
only on `Mined`, `adapter.rs:270-276`). Test: a FAILED transaction adds `feeCharged` to `spent`. Residual risk: a `G…`
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

## Finality and events

<a id="finality"></a>

SCP: a closed ledger is final. `final_head` = `getLatestLedger` (+ quorum: the other endpoints return the same hash
through `getLedgers`); `block_hash` through `getLedgers`. Events: `getEvents` (contract = a registered token, ≤ 5 per
filter), normalised to `{event, contract, block_number = ledger, block_hash, tx_hash, log_index, from, to, amount,
entry_ref, digest}` (hashes `0x` + 64 hex, strkey addresses); `log_index` = the event's index in the transaction (one
op per Soroban transaction). `getEvents` serves only the RPC's retention window (quickstart: 120 960 ledgers): a newly
created chain must set `indexed_block` near the current ledger (operations). Event-set agreement across the quorum per
ledger range: SPECIFIED.

## Conformance

<a id="conformance"></a>

- Contracts (`cargo test`): token, mandate, DEX, account with **real** authorization (`set_auths` + real ed25519 / P-256
  signatures through the account), not only `mock_all_auths`; **anti-lock** (X on token 1 and Y on token 2; X held; Y
  succeeds; then X succeeds); a used nonce refuses replay.
- Cross vectors: the same `payload` / `digest` from the client verifier, the contract tests and the Rust adapter (pinned
  constants).
- Adapter: unit tests + decoder proptest; end-to-end `tests/e2e_soroban.rs` (`#[ignore]`) on a local `stellar/quickstart`
  (port 31980): two lanes from a 24-word mnemonic, payment through `lane_step`, finality through `index_step`,
  anti-lock end to end.

## Limitations

<a id="limitations"></a>

- <a id="NET-SOR-03"></a>**NET-SOR-03** — **Soroban guardian recovery is a seam.** Guardian + delayed recovery is not
  built on Soroban; SPECIFIED as a gap ([NET-ALL-05](README.md#NET-ALL-05)).
- <a id="NET-SOR-04"></a>**NET-SOR-04** — **`__check_auth` checks every entry of `auth_contexts` against the key's allowlist**
  (owner 2026-10-08, [NET-ALL-27](README.md#NET-ALL-27)). Each key of `scaas-account` carries the `(contract, function)`
  pairs it may authorise (a passkey that pays, only a seed key changes keys…), aligned with Universal Account key
  purposes ([CTR-UA-10](../contracts/accounts.md#CTR-UA-10)); a context outside it fails. SPECIFIED. Transitional
  (BUILT): `_contexts` is ignored (`account/src/lib.rs:215`), so any one passkey can `add_key` an attacker's key.
- Not on the mesh (above). Seed role keys of a `C…` account use `kindNo` 18
  ([CLI-SGN-30](../clients/signers-clientkeys.md#CLI-SGN-30)).
- Confidential payments: Soroban has BLS12-381 (CAP-59) and BN254 (CAP-74, protocol 25) host functions plus Poseidon, so
  a Bulletproofs/ElGamal verifier is feasible in principle, but the per-transaction CPU budget (~100 M instructions)
  may not fit a range proof with n = 64 (to be measured); Groth16 over a Zether-like circuit (one pairing check) is the
  more practical candidate. Not built.
