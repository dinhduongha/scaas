# Cosmos (CosmWasm)

Common rules for every family: [networks/README](README.md). Status: contracts, adapter and client verifier
**BUILT**; items marked SPECIFIED are normative and not yet in code; deploy tooling is PLANNED.

## Overview

<a id="overview"></a><a id="NET-COS-02"></a>**NET-COS-02** — **Cosmos = a CW20 token with a contract-level meta
operation signed through ADR-036; `x/authz` is never used and `x/feegrant` is only a seam.** The subject signs a JSON
`MetaOp` with Keplr/Leap `signArbitrary` (ADR-036); the contract rebuilds the ADR-036 sign doc, hashes it with
`sha256` and verifies `secp256k1_verify`, and the address `bech32(ripemd160(sha256(pk)))` must equal `from`. Passkeys
use `secp256r1_verify` with our own WebAuthn decoder, not ADR-036. A relayer lane sends `MsgExecuteContract` with its
own account sequence. **feegrant** is used only for transactions the subject sends itself (depositing a native denom
into a wrapper). **authz** is not used: a relayer grantee would be an ordinary account as spender
([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)), and a contract grantee is unnecessary since the funds
already sit in the contract. ICS-29 relayer fees for IBC are out of scope.

Three contracts in `smartcontracts/cosmos/` (own Rust workspace, `cosmwasm-std` 3, tests with `cw-multi-test` 3):
`scaas-token`, `scaas-mandate`, `scaas-dex`, plus the shared crate `scaas-metaop` (payload and signature checks).
Adapter `scaas-node/src/adapters/cosmos.rs`; devnet `cosmwasm/wasmd:v0.61.15` (wasmvm 3, module `x/wasm`), ports 31990–31999. Chains are
keyed `cosmos:<chain-id>`.

## Payload

<a id="payload"></a>

The subject signs **sorted-key JSON** (no whitespace, every field mandatory):

```json
{"amount":"1000","contract":"wasm1…token","domain":"scaas.metaop.v1","extra":"","from":"wasm1…payer",
 "lane":"<64 hex>","network":"<chain-id>","nonce":0,"op":"pay","pay_ref":"<64 hex>","relayer":"",
 "to":"wasm1…payee","valid_until":1790000000}
```

- `amount` is a decimal u128 string; `lane` and `pay_ref` are 32 bytes as lowercase hex without `0x`; `nonce` and
  `valid_until` (unix seconds) are numbers; `relayer` empty = any relayer, non-empty = must equal `info.sender`;
  `extra` = hex `sha256(params)` for `trade`, empty for every other op.
- **The contract receives the exact bytes** (`Relay{payload: Binary, …}`) and never rebuilds the JSON: the signature
  covers exactly what the contract reads, so there is no second normalisation layer to drift. Parsing is strict
  (`deny_unknown_fields`; serde refuses duplicate keys). The entry point is
  `Relay{payload, auth}` with `auth = {scheme (adr036 | passkey), pubkey, signature, authenticator_data?,
  client_data_json?}` (`cosmos/metaop/src/lib.rs`); the payload's `MetaOp.network` and `MetaOp.contract` carry the domain.
- **The domain lives inside the payload** (ADR-036 has `chain_id: ""`): `network == env.block.chain_id`,
  `contract == env.contract.address`, `domain == "scaas.metaop.v1"`; a payload for another contract or network is
  refused.
- **Digest** = `sha256(payload)`, emitted in the `meta_tx_executed` event; the client books its signed op by it.
- **Per-contract lanes/nonces**: `NONCES[(from, lane)]` starts at 0; each op must carry the current nonce, which then
  increments. The client uses a random lane per request (nonce 0), so each request is one lane and the chain executes
  at most one signature for it; the subject's account sequence is never involved (the subject sends no transaction).
- `valid_until` is checked against `env.block.time`; an expired op is refused, never left hanging.

<a id="NET-COS-11"></a>**NET-COS-11** — **`extra` must be empty outside `trade`**: the token refuses `pay`/`revoke`
with `extra != ""`, so the digest is the unique key of one business operation. SPECIFIED (as built the token ignores
`extra` for `pay`/`revoke`, `token/src/lib.rs:201-216`, so two payloads differing only in `extra` authorise one
`pay`). Test: `pay` with a non-empty `extra` ⇒ refused.

Assumption made explicit: a Cosmos chain id is not globally unique (`testing`, `localwasm`, restarted testnets,
forks keeping their chain id), and a classic wasmd contract address = `f(code_id, instance_id)` repeats across chains
with the same prefix, so a `pay` signed on one chain would run on a "twin" (`metaop/src/lib.rs:103-111`, mandate
`mandate/src/lib.rs:131-136`). [NET-COS-07](#NET-COS-07) makes the addresses differ and the node refuses duplicate
chain ids.

## Signatures

<a id="signatures"></a>

| `scheme` | Who | Signed message | On-chain check | Address binding |
|---|---|---|---|---|
| `adr036` | Keplr/Leap `signArbitrary`; our seed signer | the ADR-036 sign doc around `payload` | `sha256(doc)`, `secp256k1_verify` | `bech32(prefix, ripemd160(sha256(pk33))) == from` |
| `passkey` | WebAuthn P-256 | `authData ‖ sha256(clientDataJSON)`, `challenge = base64url(digest)` | `secp256r1_verify(sha256(...))` | owner = the 32-byte `webauthn-p256` UA id ([NET-ALL-21](README.md#NET-ALL-21)) |

The ADR-036 sign doc is built from a **fixed byte template** (amino JSON, keys sorted at every depth, no whitespace):

```
{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData",
 "value":{"data":"<base64(payload)>","signer":"<from>"}}],"sequence":"0"}
```

Field by field: `account_number` `"0"`; `chain_id` `""`; `fee` `{"amount":[],"gas":"0"}` (keys `amount`, `gas`);
`memo` `""`; `msgs` a single element with `type: "sign/MsgSignData"` and `value: {"data": "...", "signer": "..."}`
(keys `data`, `signer`); `sequence` `"0"`. The hash is `SHA-256` of the UTF-8 JSON (32 bytes). The wallet returns a
`StdSignature`:

```typescript
{ pub_key: { type: "tendermint/PubKeySecp256k1", value: "<base64_33_byte_compressed_secp256k1_pubkey>" },
  signature: "<base64_64_byte_compact_r_and_s>" }
```

Leap exposes `window.leap.signArbitrary(chainId, signerAddress, data)` with the same ADR-036 behaviour. Our seed signer
signs exactly this doc with `m/44'/118'/0'/0/i`, so secp256k1 has one verification path. The verifier:

```rust
use cosmwasm_std::{Deps, StdResult, VerificationError};
use sha2::{Digest, Sha256};

pub fn verify_adr036(deps: Deps, canonical_json_bytes: &[u8], signature_bytes: &[u8] /* 64-byte r||s */,
                     pubkey_bytes: &[u8] /* 33-byte compressed */, expected_signer: &str) -> StdResult<bool> {
    let hash = Sha256::digest(canonical_json_bytes);
    let valid = deps.api.secp256k1_verify(&hash, signature_bytes, pubkey_bytes)
        .map_err(|_| VerificationError::InvalidSignature)?;
    if !valid { return Ok(false); }
    // address check: ripemd160(sha256(pubkey_bytes)) formatted to bech32 == expected_signer
    Ok(true)
}
```

A passkey key must be SEC1 uncompressed, 65 bytes (`x‖y` of the COSE key), so one key yields exactly one owner id; the
client normalises DER to `r‖s` with low-s.

<a id="passkey"></a>

<a id="NET-COS-03"></a>**NET-COS-03** — **A Cosmos passkey assertion is bound to the relying party, the origin and
user verification under the common WebAuthn rule.** The verifier reads `rpIdHash` from `authenticatorData` and requires
it to equal the `rpIdHash` inside the owner's `webauthn-p256` key data and to be listed for the contract; it parses the
origin through the shared `clientDataJSON` grammar ([NET-ALL-04](README.md#NET-ALL-04)); it requires UP **and** UV and
`s ≤ n/2` before `secp256r1_verify`. The owner is the 32-byte UA id ([NET-ALL-21](README.md#NET-ALL-21)), not a
truncated address (owner decision); v1 passkey addresses (dev chains only) are no longer accepted — as built the contract
checks `from == bech32(prefix, sha256("scaas.passkey.v1" ‖ pk)[..20])`. SPECIFIED. Why: as built the decoder checks
only the UP flag (`ad[32] & 0x01`) and `type`/challenge by substring `contains` (`cosmos/metaop/src/lib.rs:130-148`;
`metaop/src/lib.rs:131-144`; no low-s check before `secp256r1_verify`, `cosmos/metaop/src/lib.rs:147`), with no rpIdHash, origin, UV or low-s check, so any page that can obtain an assertion
for the rpId (sibling subdomain, related origin, delegated iframe) signs any `MetaOp`. The low-s check closes
signature malleability (the digest identity never depended on the signature). Cost: Cosmos dev passkey accounts
change.

<a id="NET-COS-09"></a>**NET-COS-09** — **The Cosmos passkey verifier checks the stored relying-party hashes and
origins.** The next contract version stores `rp_id_hashes` and `origins` at instantiate (immutable), checks
`authData[0..32] ∈ rp_id_hashes` and `"origin":"<o>"` with `o ∈ origins`, flags UP **and** UV, and refuses
`"crossOrigin":true`. Tests (cw-multi-test): unknown rpIdHash, unknown origin, missing UV ⇒ refused. SPECIFIED.

There is no native P-256 account on Cosmos; a passkey owner is a ledger key inside our contracts, displayed only as
a URN. Until the UA owner ids land, connectors and clients **never** show a passkey owner as a `wasm1…` deposit
address (a bech32 form invites a bank `MsgSend` or IBC transfer to an address nobody holds a key for). Multi-key
accounts and key rotation need a dedicated account contract — a gap ([NET-ALL-05](README.md#NET-ALL-05)).

## Contracts

<a id="contracts"></a>

**`scaas-token`** (CW20 + meta-tx):

- Minimal CW20: `Transfer`, `Send` (with the `Receive` hook — used to fund a mandate), `Mint` (minter), queries
  `Balance`, `TokenInfo`, `Allowance`, `QueryMsg::Nonce{owner, lane}`.
- `Pay{to, amount, pay_ref}`: `info.sender` pays and `payment_settled` is emitted. **`pay_ref` is not locked
  globally in the token** (as on the EVM `MetaToken`): a one-shot lock would let anyone `Pay` 1 unit with the payer's
  `pay_ref` (read from the mempool), burning it and breaking the real payment. Replay protection is the lane nonce;
  the client sums settlements per `entry_ref`.
- `Relay{payload, pubkey, signature, scheme, authenticator_data?, client_data_json?}` checks the payload and
  signature, then by `op`: `pay` moves `from → to` and emits `payment_settled` + `meta_tx_executed`; `trade` is a `pay`
  that **requires** `relayer == to == info.sender` (a leg bound `relayer = to = DEX`) and `info.sender` to be a contract (a DEX leg); `revoke` only
  consumes the nonce (cancels an op or order signed on that lane) and emits `meta_tx_executed`.
- `IncreaseAllowance`/`DecreaseAllowance`: the spender must be a contract (`query_wasm_contract_info` succeeds).
  `TransferFrom`: `info.sender` must be a contract **and** hold the allowance.
- Events (`wasm-<type>`): `payment_settled{from,to,amount,pay_ref}`, `meta_tx_executed{from,digest,lane,nonce}`.

**`scaas-mandate`**: one instance per delegated wallet — `owner`, `token`, `delegate_pubkey` (secp256k1, 33 bytes),
`max_per_payment`, `max_per_period`, `period_secs`, `payees`, `expires_at`. Funded through CW20 `Send` → `Receive`
(right token only). `PayUnderMandate{to, amount, pay_ref, valid_until, signature}`: the delegate signs `sha256` of the
sorted-key JSON `{"amount","contract","domain":"scaas.mandate.v1","network","pay_ref","to","valid_until"}`; the
contract checks not revoked, mandate and signature unexpired, payee allowed, per-payment and per-period limits (fixed
periods of `period_secs`), `pay_ref` once, then calls `token.Pay`, so `payment_settled` carries the same `pay_ref`.
`Revoke` and `Withdraw` are owner-only. The client-side mandate path is EVM-only today (seam).

## DEX

<a id="dex"></a>

An order is a `MetaOp` with `op="trade"` on the sold token (`to = relayer = DEX`, `amount` = amount sold, `extra =
sha256(params)`) plus the verbatim `params` JSON `{"buy_amount_min","buy_token","dex","max_fee_ppm"}`.
`Settle{maker, taker}` (each leg: payload, params, signature): the DEX parses both, checks `extra`, cross-matching
token pair, a configured market (`SetMarket`), the price limit (`received − fee ≥ buy_amount_min`), the market's
maker/taker ppm fee (on/off, cap 10 000 ppm = 1 %, ≤ the signed `max_fee_ppm`), `FILLED[digest]` unset; then it
dispatches atomically `tokenA.Relay(maker)`, `tokenB.Relay(taker)` (the token checks signature, nonce, expiry and
`relayer == DEX`), the cross transfers to both sides and the fee to `fee_recipient`. Any failing step reverts the
whole transaction. Cancel: the subject signs `revoke` on the order's lane/nonce through the token, so the order can
never settle. Settlement relayer binding: [dex per family](README.md#dex-per-family).

<a id="NET-COS-05"></a>**NET-COS-05** — **Cosmos DEX orders are fill-or-kill, and a multi-pair batch is atomic as a
whole.** A leg is a fixed transfer, so it fills completely or not at all (`FILLED` + the token nonce stop a re-fill);
a batch of several pairs is several `MsgExecuteContract` in one transaction, atomic **for the whole batch**, not per
pair — the off-chain book sends single pairs when it needs failure isolation. BUILT.

<a id="NET-COS-04"></a>**NET-COS-04** — **The Cosmos DEX has no `Sweep`**: the DEX never holds balances between
transactions, as on EVM ("no owner, no sweep"); tokens sent to it directly are lost, as on EVM. Admin keeps
`SetMarket` only. SPECIFIED (as built an admin `Sweep` exists, `cosmos/dex/src/lib.rs:137-143`). Test: `Sweep` is no
longer in the message enum; settle/cancel tests unchanged.

## Relayer

<a id="relayer"></a>

- Lane = secp256k1 account `m/44'/118'/0'/0/i`, address `bech32(prefix, ripemd160(sha256(pk)))`.
- `build`: reads `account_number` and the **committed** sequence (REST `/cosmos/auth/v1beta1/accounts`), builds
  `MsgExecuteContract{sender=lane, contract, msg=Relay{…}}`, simulates through `/cosmos/tx/v1beta1/simulate`. gRPC
  Unknown(2) / InvalidArgument(3) (contract refusal, malformed tx) ⇒ `Revert` (the job dies); sequence mismatch,
  Unavailable / Deadline / ResourceExhausted, gateway errors ⇒ `Transport`. Gas = simulation × 1.3; fee = gas × the
  lane's `gas_price`.
- `sign`: protobuf `TxBody/AuthInfo/SignDoc` (SIGN_MODE_DIRECT), `sha256(SignDoc)`, 64-byte low-s signature;
  protobuf encoded by hand (a few types, no `cosmrs` dependency).
- `submit`: `broadcast` SYNC; code 19 (already in mempool) ⇒ ok; 20 (mempool full) ⇒ resend the same bytes; any other
  CheckTx code (32 sequence, 13 fee, 4 signature, 5 balance…) ⇒ `Rejected` ⇒ the job returns to `queued` for a rebuild
  and does not hold the lane until expiry. Start-up refuses an empty `network` and `gas_price` ≤ 0 unless
  `params.zero_fee = true` (devnet).
- **Classes** ([NODE-LANE-14](../node/submit-lanes.md#NODE-LANE-14)): CheckTx refusal ⇒ `Rejected` (not in a block, not
  billed) ⇒ `queued`; DeliverTx failure ⇒ final `Reverted` (billed the full `gas_limit × gas_price`); bounded by
  `max_attempts`.
- `tx_status`: REST `GetTx` (the tx indexer may be disabled or late) — found is certain; not found ⇒ scan `block` +
  `block_results` from the head at submission for `sha256(tx bytes)`. End-to-end tests run a devnet with
  `indexer = "null"`.
- **Head-of-line**: one transaction in flight per lane; sequence read from the chain before each job; the subject
  sends no transaction; nonces are `(contract, from, lane)`, so an op stuck on contract 1 never blocks contract 2
  (anti-lock tests in the contract suite and end to end). An expired transaction is refused by the contract, so the
  lane sequence never hangs.
- **Fees**: the relayer pays in the lane's native denom.
- Configuration: `rpc_urls = [CometBFT RPC]`, `params = {rest, prefix, denom, gas_price, zero_fee?}`.

<a id="NET-COS-08"></a>**NET-COS-08** — **`contract` and `valid_until` come from the signed payload**
([NODE-LANE-16](../node/submit-lanes.md#NODE-LANE-16)): `relay_msg` parses the payload; a job whose JSON differs ⇒
`422 BAD_PAYLOAD` at the door and `Revert` at `build`; `op_consumed` uses `payload.contract`. SPECIFIED (as built
`relay_msg` reads them from the job JSON, `cosmos.rs:177-198`; `op_consumed` asks `op["contract"]`,
`cosmos.rs:414-426`). Tests: a job whose JSON `valid_until` exceeds the signed one ⇒ refused; a different JSON
`contract` ⇒ refused and never a false `consumed`.

<a id="NET-COS-10"></a>**NET-COS-10** — **A transaction dropped from the mempool is resent**: `Unknown` for longer
than `params.resubmit_after_blocks` (default 5) while the send succeeded ⇒ resend the identical bytes (code 19 makes
it idempotent); never new bytes, never a new sequence. SPECIFIED (as built `follow` resends only when the send
failed, `adapter.rs:313`, so a transaction CometBFT evicted on recheck leaves the lane waiting until
`valid_until + grace`). Test: a transaction vanishes from a fake mempool ⇒ resent, included, `mined`.

<a id="NET-COS-06"></a>**NET-COS-06** — **Subject-caused grief after simulation is metered and throttled, not
excluded; the DEX re-reads both legs' nonces before settling.** A subject is an x/auth account and can send its own
transactions: between `simulate` and inclusion it can `Transfer` its whole balance (`token/src/lib.rs:126-130`), or
`Relay` the same payload itself, or send a `revoke` on the same `(from, lane)` (an empty `relayer` lets anyone send,
`token/src/lib.rs:191`) — the lane's transaction then fails in DeliverTx and pays the full fee; a new lane per request
makes it repeatable at no cost to the subject (no relayer fee off EVM). Node: the failed DeliverTx fee feeds the
breaker ([NODE-LANE-13](../node/submit-lanes.md#NODE-LANE-13)) and every billed failure counts against the payload's
`from` ([NODE-LANE-15](../node/submit-lanes.md#NODE-LANE-15); a `consumed` of an unpublished job counts too — that is
exactly the "send it first" pattern). DEX: right before signing `Settle`, re-read `Nonce{owner, lane}` of **both** legs
on both tokens; a consumed nonce ⇒ drop the pair, do not send. Residual, stated: each new `from` can cost a lane up to
3 failed transactions per 24 h before throttling. Tests: a subject empties its balance after simulation ⇒ the failed
transaction counts in `subject_grief`; the third time in 24 h ⇒ only one live job; a maker revokes before settle ⇒
nothing sent. SPECIFIED (as built the runner only reports a revert, `adapter.rs:280-291`; the breaker meters only
mined fees, `adapter.rs:270-276`; `Settle` is open, `dex/src/lib.rs:145`).

Node-wide rules apply as written: billed failures metered, CheckTx/DeliverTx classes, grief per `from`, local
signature verification on the mesh ([NODE-MESH-16](../node/mesh.md#NODE-MESH-16): ADR-036 secp256k1 or passkey before
any `simulate`; as built `mesh/digest.rs:205-225` checks domain, network and contract but no signature, so every peer
pays one REST `simulate` per garbage intent), signed fields from the payload. Cosmos has no value out beyond fees and
no lane-paid deposits (both 0).

## Finality and events

<a id="finality"></a>

CometBFT is final at once: `final_head` = the newest block (`/status`). `events(from,to)` reads `block_results` per
block (stored at commit; **not** `tx_search`, because the tx indexer runs asynchronously after commit, so the newest
block may not be indexed yet and an event would be missed forever) and `block` only for blocks with our events
(`tx_hash = sha256(tx bytes)`), filtered by the registered tokens (node store, in bech32; formerly the client's `node_config.tokens`; an empty list never advances
the cursor, [NET-ALL-06](README.md#NET-ALL-06)), normalised to `{event, contract, block_number, block_hash, tx_hash,
log_index, from, to, amount, entry_ref, digest}`; `log_index` = the event's position in the transaction, so
`(tx_hash, log_index)` is unique. Event attributes: CometBFT < 0.38 returns base64, detected through
`_contract_address` (wasmd always sets it) and decoded. Quorum: head and events are agreed across the configured
`quorum` endpoints (`status` + `block` at the minimum height and the tx events of the range) — SPECIFIED; as built a
single trusted RPC.

## Deploy

<a id="deploy"></a>

<a id="NET-COS-07"></a>**NET-COS-07** — **Cosmos contract addresses differ between chains, contracts are instantiated
without an admin, and duplicate chain ids are refused.** New deployments use `instantiate2` with salt
`sha256("scaas.cosmos.salt.v1" ‖ chain_id ‖ genesis_hash)` (the deploy script reads the genesis hash from RPC), so
the payload's `contract` is unique per chain even when chain ids collide; contracts are instantiated `--no-admin`
(no migrate admin on a contract that holds value, [CTR-GEN-02](../contracts/README.md#CTR-GEN-02)) and the deploy gate
fails if the admin is not empty ([deploy gate](README.md#deploy-gate)); the node records `chain_uid`
([NET-ALL-22](README.md#NET-ALL-22)) and refuses two Cosmos chains with the same chain id in its store. Payload v1 is
unchanged. Deploy tooling is PLANNED (`deploy.sh` exits 2 for Cosmos); older classic `instantiate` deployments rely on
the node's duplicate-chain-id refusal. Tests: the deploy script yields different addresses on two devnets with the
same chain id and different genesis; the node refuses a duplicate chain id.

## Conformance

<a id="conformance"></a>

One fixed payload and a test secp256k1 key: the client verifier, the contracts (`cw-multi-test`) and the Rust adapter
all assert the same `digest`, ADR-036 doc bytes and bech32 address. Self-review findings designed in: no global
`pay_ref` lock (test: a `Pay` with the same `pay_ref` before the relay); `block_results`, not `tx_search`; only
65-byte passkey keys; a payload expiring within one block passes simulation and then `reverted` (accepted: fail-safe,
the payer signs again); wasmvm 3 refuses the bulk-memory feature that Rust ≥ 1.87 emits, so `build-wasm.sh` lowers it
with binaryen and checks MVP.

## Limitations

<a id="limitations"></a>

- No key rotation or guardian ([NET-ALL-05](README.md#NET-ALL-05)); a passkey account contract is a design task.
- Single-provider finality as built (SPECIFIED quorum above).
- <a id="NET-COS-01"></a>**NET-COS-01** — **IBC token transfers (ICS-20) and interchain accounts (ICS-27) are an open
  owner requirement.** Not specified; ICS-29 relayer fees out of scope. Status `open`.
- Confidential payments: CosmWasm 2+ has native `bls12_381_pairing_equality` and BLS12-381 G1/G2 operations but no
  bn254; a Bulletproofs verifier compiled to wasm runs but costs much gas (point multiplication in pure wasm).
  Technically feasible for the BLS12-381 variant with a matching prover; not built (confidential payments are
  EVM-first).
