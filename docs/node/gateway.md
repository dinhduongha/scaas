# Gateway (door A)

The gateway is the node's public intake: anyone — a wallet, the console app, a partner, an agent — may post a signed
meta-transaction, a signed family op, a UA meta-transaction or a DEX order. It is served on `[modules] gateway_bind`
(default `127.0.0.1:8547`, normally behind a reverse proxy). Status: `/v1/metatx` (EVM) and `/v1/dex/*` **BUILT**;
durable door-A jobs, `/v1/gateway`, `/v1/ops`, UA routes, CORS and the error contract **SPECIFIED**.

## Auth

<a id="auth"></a><a id="NODE-GW-02"></a>**NODE-GW-02** — **Gateway auth is `none`, `bearer` or `hmac`** (`bearer|hmac` off loopback)
(`[modules] gateway_auth = "none" | "bearer" | "hmac"`; secret from `gateway_secret_env`, ≥ 16 bytes). `bearer`:
`Authorization: Bearer <secret>`, compared in constant time. `hmac`: `X-Scaas-Timestamp` + `X-Scaas-Signature =
hex(HMAC-SHA256(secret, ts ‖ "." ‖ nonce ‖ "." ‖ METHOD ‖ " " ‖ path?query ‖ "\n" ‖ body))`, clock skew ≤ 300 s,
`X-Scaas-Nonce` (header names are case-insensitive: `X-SCaaS-Nonce` is the same; `[A-Za-z0-9_-]{1,64}`) remembered until its own timestamp expires (ts + 300 s), so nothing replays;
method and path are in the signed string, so a signature for one route is useless on another. **`none` is refused when
the bind is not loopback** (a config error fails fast). Every decoder of untrusted input (`WireMetaTx::to_sol`, the
gateway body, job payloads, every family adapter's decoder — BCS/XDR/protobuf/BOC) has `proptest` fuzz tests
(dev-dependency): no panic, every error is an `Err`. The job API extends the `hmac` mode with per-namespace key ids
([NODE-JOB-05](job-api.md#NODE-JOB-05)).

Limits: body 64 KiB (1 MiB on the PQZ chain profile only); a global concurrency limit (`tower`
`ConcurrencyLimitLayer`, default 32) because every request costs a simulation; a per-IP rate limit at the reverse
proxy in front of an open gateway ([runbooks.md#production-gates](runbooks.md#production-gates)).

## CORS

<a id="cors"></a><a id="NODE-GW-04"></a>**NODE-GW-04** — **Gateway CORS only with gateway auth `none`.**
`[modules] gateway_cors_origins`: exact list, no `*`, no reflection, methods `GET, POST`, header `Content-Type`, no
credentials, `max_age = 600`. `Config::validate` refuses a non-empty `gateway_cors_origins` when the gateway auth is
`bearer` or `hmac`: the CORS profile allows only `Content-Type`, so a preflight would refuse `Authorization` and
`X-Scaas-*` anyway. Browser apps use an unauthenticated gateway behind a host proxy
([CLI-APP-03](../clients/app.md#CLI-APP-03)).

## Routes

<a id="routes"></a><a id="NODE-GW-05"></a>**NODE-GW-05** — **The gateway announces what it serves, allows exact-origin
CORS and answers with one error contract.** `GET /v1/gateway` lists the served chains, tokens, fee recipient, DEX
address, relayer and order policy; without it a client cannot sign a bound DEX order, show the fee recipient, or reach
the gateway cross-origin. Every gateway route keeps the auth mode, the 64 KiB cap, `gateway_cors_origins` (auth `none`
only) and the error contract ([errors](#errors)).

`GET /v1/gateway` (gateway listener, gateway auth applies):

```json
{"api": 1, "chains": [
  {"chain": 100, "chain_key": "evm:100", "family": "evm", "routes": ["metatx", "dex"],
   "tokens": ["0x…"], "fee_recipient": "0x…", "breaker_open": false,
   "max_valid_for_secs": 3600,
   "dex": {"address": "0x…", "relayer": "0x…", "markets": [{"id": 1, "min_base_amount": "1000"}],
           "relayer_fee_policy": {"modes": [0, 1, 2], "max_ppm": 10000},
           "max_open_per_maker": 50, "min_ttl_secs": 5, "max_ttl_secs": 2592000}}]}
```

Shape: `{"api": 1, "chains": [{chain, chain_key, chain_uid?, family, routes, tokens, fee_recipient, breaker_open,
max_valid_for_secs, dex?: {address, relayer, markets: [{id, min_base_amount}], relayer_fee_policy: {modes, max_ppm},
max_open_per_maker, min_ttl_secs, max_ttl_secs}}]}`. `chain` is numeric for EVM and Hedera (the `/v1/metatx` body);
`chain_key` is always present. `routes` ⊆ `metatx`, `ops`, `ua-metatx`, `ua-register`, `dex`. `chain_uid` is present
for chains with a UA registry; clients compare it with the EIP-712 `salt` before signing; UA routes are listed only
while the [chain binding](#chain-binding) holds.

Unlike the job API, gateway doors **simulate before INSERT**. An accepted item is a `~gateway` job (origin key = node
digest = `intent_id`, [NODE-JOB-02](job-api.md#NODE-JOB-02); intake steps 3, 6 and 7a–7c and the in-transaction
authority re-check of [job-api.md#intake](job-api.md#intake) apply) answered `202 {"status": "queued", "intent_id"}`.
A duplicate returns `200` with the stored state (idempotent).

| Route | Body / answer | Accept checks, in order |
|---|---|---|
| `GET /v1/gateway` | above | — |
| `POST /v1/metatx {chain, token, m, signature}` | `202 {"status":"queued"}` today; the target adds `"intent_id"` (+ `exclusive` when published on the mesh) | token registered and active (`TOKEN_NOT_SERVED`); strict parse; normalization ([NODE-LANE-10](submit-lanes.md#NODE-LANE-10)) before simulation; `metaTxDigest` + simulation; [door A rules](#door-a-intake). On Hedera chains (295–298) `sig_bytes` may be **64** bytes (HIP-632 ED25519); 65–2048 bytes elsewhere |
| `POST /v1/ops {chain, op}` | `op` = the job API `signed_op` payload; `202 {"status": "queued", "intent_id": "<digest hex>"}` | below |
| `POST /v1/ua-metatx {chain, token, m: WireUAMetaTransaction, auth}` | `ua_metatx` job | token `features ∋ ua` (v3: `registry() ≠ 0`); `from >> 160 ≠ 0` ⇒ registry record ([UA record cache](#ua-cache), `UA_NOT_REGISTERED`); cheap kinds verified locally ([NODE-GSP-15](gossip.md#NODE-GSP-15)); node computes `uaDigest` |
| `POST /v1/ua/register {chain, kind, keyData, pop, authRef}` (`{chain, kind, keyData: 0x…, pop: 0x…, authRef: 0x…32}`) | `call` job to `chain.ua_registry` ([NODE-GW-03](#NODE-GW-03)) | id recomputed, `>> 160 ≠ 0`; not registered (`UA_ALREADY_REGISTERED`, `UA_KEY_IN_USE`); PoP verified for cheap kinds over `pop_digest` with `chain.chain_uid`; per-chain registration quota |
| `GET /v1/intents/{intent_id}` | the `~gateway` job: `{"intent_id", "state", "consumed_kind"?, "tx_hash"?, "updated_at"}` | **only for gateway-origin rows**: rows from peers or from the job API (incl. private-chain intents) answer 404, the same as unknown or expired ids |
| `POST /v1/dex/orders`, `…/cancel`, `…/cancel-all`; `GET /v1/dex/{markets,depth,trades,ticker,orders}` (`GET /v1/dex/orders?maker=`) | [dex-venue.md#routes](dex-venue.md#routes) | managed markets add `NOT_ELIGIBLE {reason}`, `UNBOUND_FORBIDDEN`, `FEE_FORBIDDEN`, `PAUSED`, `ATTESTATION_SHORTER`; mesh `route_order` ⇒ `MANAGED_LOCAL` ([dex-venue.md#managed-markets](dex-venue.md#managed-markets)) |
| `GET /v1/dex/depth?scope=network`, `GET /v1/dex/homes` | network depth and DEX homes ([dex-venue.md#gossip](dex-venue.md#gossip)) | — |

`POST /v1/ops` (six non-EVM families):

```json
{"chain": "sui:testnet",
 "op": {"family": "sui", "contract": "<account id | token | registry, family canonical>",
        "from": "<subject, family canonical>", "op_kind": "pay",
        "payload": "0x<MetaOp bytes / XDR / BOC, as the family encoder builds>",
        "signature": "<packSignature().signature>", "public_key": "<packSignature().publicKey | null>",
        "auth_kind": "seed | wallet | passkey", "digest": "0x… (optional; must equal the node's)",
        "valid_until": 1790000300, "extra": {"coin_type": "0x2::sui::SUI"}}}
```

`op` is exactly the `signed_op` payload of a job and what every adapter's `build` consumes; `op.family` must be the
chain's. Accept checks, in order:

1. `chain` is served (`UNKNOWN_CHAIN`).
2. `family` equals the chain's family (`BAD_PAYLOAD`).
3. The payload decodes; the node computes the digest; a client digest that differs fails (`BAD_PAYLOAD`).
4. The token or asset is registered (`TOKEN_NOT_SERVED`).
5. `now < valid_until ≤ now + max_valid_for_secs` (`EXPIRED`).
6. The family signature verify, where the node has one (`BAD_SIGNATURE`). A verifier that returns `None` (the key is
   not the payer's) goes on to simulation, which arbitrates ([NET-ALL-14](../networks/README.md#NET-ALL-14)).
7. A bound relayer must be a lane of the chain (`RELAYER_NOT_OURS`).
8. Simulation (`SIMULATION_REVERT`).
9. INSERT a `signed_op` job in `~gateway`, origin key = digest (G2 durable).

Soroban: accepted, never published on the mesh ([NODE-MESH-07](mesh.md#NODE-MESH-07)). TON: `attach_nanoton` is the
node's. Limits: 64 KiB body, the per-chain breaker and the gateway concurrency limit. `/v1/ops` needs lanes that lease
from the store: before that, the built gateway's in-memory `mpsc` feeds only the EVM submitter (Transitional (BUILT):
door A work is not journaled and has no digest guard until it becomes a `~gateway` job).

<a id="ua-register"></a><a id="NODE-GW-03"></a>**NODE-GW-03** — **Gateway `call` jobs exist only for UA
registration.** `POST /v1/ua/register` is the one gateway route that creates a `call` job in `~gateway`: target = the
chain's `chain.ua_registry`, function `register`, calldata built by the node from the checked body. It is a gateway
capability, not an `allow_call` grant ("gateway capability, not a namespace grant") ([NODE-JOB-09](job-api.md#NODE-JOB-09) is unchanged for namespaces);
`job_live_call` dedupes retries; every registration lives in `~gateway`, so the per-namespace index
([NODE-JOB-13](job-api.md#NODE-JOB-13)) dedupes them node-wide. Sponsored registration spam is bounded by the per-chain
registration quota and the sponsor budget; the one `~gateway` `call` sponsor policy shape allowed is `contract =
chain.ua_registry`, `selector` = `register`, `max_tx_per_payer_hour = 0`
([sponsorship.md#admin](sponsorship.md#admin)). The universal-account migration uses this route
([contracts/accounts.md#migration](../contracts/accounts.md#migration)).

### UA record cache

<a id="ua-cache"></a>Per chain, `recordOf(from)` is read once from `chain.ua_registry`; records are immutable, so hits
stay in memory with no expiry and misses for 60 s; cheap kinds (webauthn-p256, p256, ed25519, bip340, schnorr-bn254)
are verified with the shared Rust kind library, the rest by simulation. No store table. Config per chain:
`ua_registry` address and generation; enabled kinds are read from the chain at onboarding. The node never holds UA
keys; lane keys are unaffected.

### Chain binding

<a id="chain-binding"></a>For every chain with `ua_registry`, at start and on every RPC (re)connect, the node checks
that the RPC's genesis block hash (EVM/Hedera: block 0, from ≥ `finality_quorum` endpoints) equals `chain.chain_uid`,
that `ua_registry` has code and that its `chainUid()` equals `chain.chain_uid`; non-EVM families compare the family's
network id where the RPC exposes it (Soroban network id, Solana genesis hash), else trust the profile constant
([NET-ALL-22](../networks/README.md#NET-ALL-22)). A mismatch holds the chain (readiness reason `chain_uid mismatch`,
as `finality violated`): nothing is leased, UA routes answer `UNKNOWN_CHAIN`. `pop_digest`, the registry and v3
EIP-712 domain `salt` and the `metatx-cancel` digest are computed with `chain.chain_uid`, never from the chain id
alone. The post-quantum Zether chain profile adds the same binding for its registry and tokens (RPC genesis hash `==`
profile `genesis_hash` `==` `registry.chainUid()` `==` each token's `chainUid`, [ops.md#pqz](ops.md#pqz)).

### EIP-7702

<a id="eip-7702"></a>The node never classifies a native EVM `from` by reading its code at accept
([CTR-UA-24](../contracts/accounts.md#CTR-UA-24)). A local ECDSA check that recovers the address passes
whether the code is empty or a 7702 designator (`0xef0100 ‖ address`); a signature that does not recover is an
ERC-1271 candidate: refused for sponsoring on public doors (`BAD_SIGNATURE`,
[sponsorship.md#evaluation](sponsorship.md#evaluation)), otherwise left to simulation, which runs the contract's own
rule.

## Intake

<a id="intake"></a><a id="door-a-intake"></a><a id="NODE-GW-01"></a>**NODE-GW-01** — **Door A is not a free gas
faucet.** At gateway intake: (a) a `transfer`/`pay` op with `value == 0` ⇒ `422 ZERO_VALUE`; (b) the `~gateway` door
applies its `min_fee` floor (the mesh policy row's `min_fee`, [mesh.md#acceptance](mesh.md#acceptance)) to the
**effective** fee; a matching sponsor policy waives it and caps the spend with its budget
([NODE-SPN-01](sponsorship.md#NODE-SPN-01)); (c) defaults: `profile = private` keeps fee 0 (the B2B default),
`profile = public` refuses fee-0 door-A intents unless a sponsor policy matches; (d) a per-`from` token bucket
(default 60 per hour, in memory) on top of the reverse-proxy per-IP limit. The hourly gas budget
([NODE-LANE-05](submit-lanes.md#NODE-LANE-05)) can then not be filled by unsponsored fee-0 traffic on public chains;
public fee-0 payers need a sponsor policy row. Every door also applies
[NODE-MESH-16](mesh.md#NODE-MESH-16) and [NODE-LANE-16](submit-lanes.md#NODE-LANE-16)–[NODE-LANE-18](submit-lanes.md#NODE-LANE-18).

The node may refuse fees below its floor; with a fee-taking intent whose `feeRecipient` is **not** bound, whoever
submits takes the fee — that is the open-relayer design (the signer binds the recipient to prevent it).

## Errors

<a id="errors"></a><a id="NODE-GW-06"></a>**NODE-GW-06** — **The gateway error contract is stable.** Every gateway route
(incl. `/v1/dex/*`, `/v1/ops`, `/v1/ua/*`) answers errors as `{"error": "<CODE>", "code": "<CODE>", "detail": "<≤ 300
chars>", "revert_data": "0x…"?}`; the legacy `"error"` keeps the code, so old clients still read a string. Codes:
`UNKNOWN_CHAIN`, `TOKEN_NOT_SERVED`, `BREAKER_OPEN`, `SUBMIT_BUSY`, `EXPIRED`, `BAD_SIGNATURE`, `BAD_PAYLOAD`,
`RELAYER_NOT_OURS`, `SIMULATION_REVERT` (raw `0x…` revert data), `RPC_UNAVAILABLE`, `QUOTA`, `ZERO_VALUE`,
`SUBJECT_DENIED`, `SPONSOR_BUDGET`, `SPONSOR_RATE`, `SPONSOR_TOO_SHORT`, `UA_NOT_REGISTERED`, `UA_ALREADY_REGISTERED`,
`UA_KEY_IN_USE`, and the managed-market codes above. Clients decode revert data with their own ABI and map codes (the console app maps `errors.node.<code>`); it replaces
the earlier `{"error": "<text>"}` bodies and Rust `Debug` reverts; no
logic keys on free text. The gateway and the job API keep per-listener code sets over the same checks (gateway
`TOKEN_NOT_SERVED` and `EXPIRED` for too long a validity, job API `UNKNOWN_TOKEN` and `VALID_TOO_LONG`).
