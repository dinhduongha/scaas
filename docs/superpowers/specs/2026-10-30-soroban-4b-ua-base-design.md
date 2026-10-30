# Soroban UA base (4b) and the Soroban registry of UA-8 step 2 — design

**Status:** draft for owner review, 2026-10-30. Nothing is built. Written from `main` at `920f13d0`. Rules are cited by
ID, not restated. Every choice marked **controller call** is the controller's; the owner may override it. A choice
that an owner ruling already decides cites the ruling.

**What "4b" is.** "4b" is the TODO item **"UA on non-EVM families — every kind, not only PQ"** (owner 2026-10-29; it was
numbered 4b in the order of that day, commit `1a4dab53`, and kept the label when the order was re-cut): per family the
UA id space, the registry or the lazy open, the UA ledger in the tokens, the mtx / account / mandate / DEX paths
accepting UA holders, and the kinds the family verifies — classical first, then PQ where an on-chain verifier exists.
There is no "4a". **4b Soroban** is that item's first family after EVM (TODO "Now (order)" step 4: "4b Soroban (UA
base) + UA-8 step 2 (Soroban registry) in one round — shared ML-DSA verifier (CAP-0087 host functions) and vectors").
NEAR and Algorand have a lazy-opened `Ua` holder on their own branch (classical, native and `msig` kinds); they are
later 4b / UA-8 plans (TODO step 7).

**Inputs.** UA-8 spec [2026-10-25-ua8-portable-registrations.md](2026-10-25-ua8-portable-registrations.md) (P1–P11);
the UA-8 plan [2026-10-30-ua8-portable-registrations.md](../plans/2026-10-30-ua8-portable-registrations.md) Part B
(B0–B10, UA8-D18–D24); the EVM build as merged ([accounts.md](../../contracts/accounts.md) CTR-UA-07, -16, -24, -31,
-32; `smartcontracts/evm/src/ua/`); [soroban.md](../../networks/soroban.md); the metatx-split spec
[2026-10-27-metatx-split-design.md](2026-10-27-metatx-split-design.md) §6.2 / §7.2; the NEAR / Algorand spec
[2026-10-28-near-algorand-design.md](2026-10-28-near-algorand-design.md) (structure, storage-payment precedent);
[research/pq-signatures-per-family.md](../../research/pq-signatures-per-family.md).

## 0. Decisions

Each row: the decision, the options weighed, the choice, why, and the cost if it is wrong.

| # | Decision | Options | Choice and why | Cost if wrong | Who |
|---|---|---|---|---|---|
| S1 | Where the records live | (a) entries in a `SmartKeyAccount` factory (accounts.md "Where the records live" row; no Soroban factory exists — `SmartKeyAccount` is deployed per account); (b) a stand-alone registry contract, the EVM `UARegistry` shape; (c) no registry, lazy open per token (NEAR / Algorand) | **(b)** new crate `smartcontracts/soroban/contracts/ua-registry/`, contract `UaRegistry`. Soroban cross-contract calls are synchronous, so tokens call the registry as EVM tokens do (CTR-UA-17), unlike NEAR; one place for chain-wide `keyHash` uniqueness (CTR-UA-11) and for the UA-8 records; no factory to invent. This crate is the plan's "4b factory crate"; its `ua8` module is Part B (plan: "the 4b name wins") | a rename; the accounts.md row is corrected by the build | controller call |
| S2 | The registration form | (a) a chain-bound PoP first, the portable one in Part B; (b) the portable `register` from day one | **(b)** `register(kind, key_data, attrs, pop, pqz_pop, relayer)` on the CTR-UA-07 digests (UA-8 P1: "`register` accepts only this form (one rule)"). 4b accepts only empty `attrs` (error `Attrs`); Part B lifts that and adds the KEM / PQZ entries, `checked` and the relayer mode. 4b already defines the full `Registration` type, so Part B changes no layout | none found | owner P1 / P2 (2026-10-25); split controller call |
| S3 | Kinds of generation 1 on Soroban | classical first (owner 2026-10-29), then PQ where a host function exists; pure-Rust BIP-340 / FROST / MuSig2, the BLS12-381 kinds (CAP-59 host functions exist), `fndsa512` / `slhdsa128s` pure | **enabled:** `webauthn-p256` 0x0100, `p256` 0x0101, `ed25519` 0x0102, `secp256k1` 0x0108, `msig` 0x0120, `mldsa44` 0x0130, `mldsa65` 0x0131 (§3). Every other derived kind is disabled (`KindDisabled`), stays valid elsewhere (UA-8 P3), and reaches Soroban only through Part B's relayer-checked mode, never as a signer. A later generation may add BLS12-381 or pure-Rust kinds after a budget spike (CTR-UA-05: a new generation) | a UA of a disabled kind cannot use Soroban until that generation | controller call within the owner's list |
| S4 | The ML-DSA verifier | (a) CAP-0087 host functions; (b) pure Rust in the contract (third-party figure: ML-DSA-65 77.5 M instructions, 33–61 KB Wasm) until Protocol 30 is live | **(a) only.** The owner's "no waiting" (2026-10-29) puts all code on a local Protocol 30 network; mainnet votes Protocol 30 on 2026-11-23, before any use. One verifier module (`verify.rs` in `ua-registry`) serves `register`, `require_authorized` (4b) and `set_kem_key` (Part B): the "shared ML-DSA verifier" of TODO step 4. P11's "pure Rust until then" is dropped | a Soroban network without Protocol 30 has no ML-DSA kinds (they are disabled there by the code, not by a flag) | controller call |
| S5 | SDK and network pins | soroban-sdk 26.1.1 (today) / 29.0.1 (latest stable) / 30.0.0-rc.1 (2026-10-21, the first release with `Crypto::ml_dsa_{44,65,87}_verify`) / a git revision | **`soroban-sdk = "=30.0.0-rc.1"`** for the whole Soroban workspace (every crate rebuilds and re-tests); swapped to 30.0.0 when released, **before** the testnet e2e (this closes C16b). `stellar/quickstart` pinned by digest, run `--local --protocol-version 30 --limits testnet` | an RC API change before 30.0.0 means one more rebuild | controller call |
| S6 | The UA ledger in Soroban tokens | (a) a per-UA custom account (`C…` contract at a salt = the UA, whose `__check_auth` asks the registry): every existing entry works unchanged; (b) a `Holder` enum in the existing entries (NEAR shape); (c) a `UaBalance(ua)` ledger with separate `ua_*` entries beside the native ones (EVM CTR-UA-18 / -26 shape) | **(c).** (a) is a contract per user per chain and gives a derived UA a native address, against CTR-UA-02 and NET-ALL-21; (b) changes the built `pay` / `pay_meta` and their cross vectors. The UA pool is the token's own address (§5.1) | more entry points in the token | controller call |
| S7 | UA replay protection | (a) host-style random nonces in temporary storage; (b) lanes `UaNonce(ua, lane) → u64` in persistent storage, EVM `_uaNonce[ua][batch]` | **(b)**; `ua_pay` uses `lane = payLane(pay_ref)`, `nonce = 0` (CTR-MTX-26). Temporary entries are deleted on expiry, so (a) would re-open spent nonces (NET-ALL-01, CTR-MTX-04) | none found | controller call |
| S8 | Relayer binding of UA entries | unbound (native Soroban today, NET-SOR-01) / `relayer: Option<Address>` | **`relayer: Option<Address>`**; `Some(r)` ⇒ `r.require_auth()`: a lane satisfies it by an explicit `SourceAccount` auth entry rooted at the call (as `relay-fee` today), the relay-fee router as the direct invoker. Needed for CTR-MTX-27's router marker | none found | controller call |
| S9 | Which UAs may receive | any registered UA / only a UA that can spend on Soroban | **only a UA that can spend here**: registered, kind enabled, `pop` checked by the chain, and for `msig` the weight of members Soroban can verify for signing ≥ threshold (`Registration.signable`, computed at `register`). Else `UaNotReceivable`. CTR-UA-23: a registrable but unusable account can receive and never spend; UA-8 P11.5 | a few `msig` forms register for discovery only | controller call |
| S10 | `msig` members on Soroban | the EVM MEMBER set; plus Soroban natives; plus EVM natives | **MEMBER = the enabled single-key kinds of S3, plus `stellar-account` 0x0011 and `soroban-contract` 0x0012** (verified by the host: `member.require_auth_for_args((ua, purpose, digest))`, Soroban's form of the EIP-712 `UAAuth`). An `msig` with a 0x0011 / 0x0012 member is a **Soroban-network-local record** (no other registry verifies those members, as EVM's 0x0003 is Hedera-only). **`evm-eoa` 0x0001 members** are verified for the portable purposes only (`pop` v2, `kem`: ECDSA over the EIP-191 `personal_sign` of `memberDigest`, by `secp256k1_recover`, exactly CTR-UA-07), and have **zero signing weight** for every other purpose (no Soroban signing form); `evm-contract` 0x0002 members are never chain-verified here (Part B: the part is `Relayer`) | an EVM `msig` that needs its EOA members to reach its threshold is discovery-only on Soroban (S9) | controller call |
| S11 | Storage class and TTL | instance / persistent / temporary | **persistent, one entry per key**, for every record, balance, lane, pay ref and (Part B) KEM / PQZ entry; instance storage only for constructor constants; temporary only for SEP-41 allowances (a UA never holds one). TTL `extend_ttl(30 days, 60 days)` on each write and each in-transaction read (UA8-D22); **no node TTL job**; an archived entry is restored on its next use (§7) | rent for large entries (§7) | controller call (UA8-D22) |
| S12 | Who pays fees, rent and restores | the user / the relayer | **the relayer** (lane); users and UAs hold no XLM. Reimbursement: the relay-fee router (`ua_relay`, §5.4) or the node's sponsorship policy; registry writes have no fee form (UA-8 P9) | relayer cost on spam (CTR-UA-25: node sponsorship limits) | owner precedent 2026-10-28 (NEAR / Algorand: "the relayer pays storage"), applied here |
| S13 | PQZ and Zether | — | **none on Soroban** (no verifier, no PQZ token). Part B stores PQZ attributes unproven (UA8-D20 / D21) in full; no ciphertext ever exists on Soroban, so "never lose ciphertext" is met vacuously, and the PQZ key and proof bytes live in state, not only as hashes (§6) | — | owner (UA-8 P8, P10; never-lose rule) |
| S14 | Code authority | — | **an account signs with its own key; no delegated code authority** (owner rulings D1–D5, 2026-10-30; NET-ALL-83 lists Soroban as having no analogue). Applied in §8: `G…` accounts only add key / hash / pre-auth-tx signers; a `C…` account is a contract account (the EVM 0x0002 analogue), its own authority, never a key account's delegate; a UA is a key, never code; the node never lends a lane's authority | — | owner |
| S15 | Node job kinds | new names / the EVM names | **`ua_metatx`** for the UA-ledger, mandate and DEX UA entries (the EVM job kind, `scaas-node/src/submit.rs`), **`call`** for the registry writes (UA8-D23) | — | controller call |
| S16 | Upgrade and admin | — | `UaRegistry`: no admin, no upgrade function (`update_current_contract_wasm` is never called), the relayer list a constructor argument (CTR-UA-15; UA8-D19). Tokens bind the registry at construction, immutable; `None` = the UA ledger is off (`UaLedgerOff`), as EVM's registry 0 | a new kind or a bug fix is a new registry generation and new token deployments (all chains test-only today) | CTR-UA-15 (owner) |
| S17 | Test order | — | unit tests (SDK testutils at protocol 30) → local quickstart at Protocol 30 → Stellar testnet e2e **only after 2026-11-03** and only when the RPC reports protocol 30 | — | owner 2026-10-29 ("no waiting") |
| S18 | Order inside the round | one branch for 4b and Part B / two | **two, as the UA-8 plan says:** branch `soroban-4b` from `main` (after the token-family rename merges); on the owner's go it merges, then Part B branches `ua8-soroban`. The testnet e2e of both runs once, as the round's last step | none found | plan (controller), unchanged |

## 1. Scope and non-goals

**In scope (4b).** The `UaRegistry` contract with the S3 kinds, the portable `register` (empty `attrs`), the per-kind
UA list (CTR-UA-29), `require_authorized`; the UA ledger and `ua_*` entries in the Soroban token; UA holders in the
mandate, the DEX and the relay-fee router; the node adapter (§9) and `clientkeys` (§10); vectors and tests (§10);
`docs/networks/soroban.md`, `docs/contracts/accounts.md`, `docs/node/job-api.md`, `docs/decisions.md`.

**In scope (UA-8 step 2, Part B, unchanged except §11).** KEM records, PQZ attributes, `checked`, the relayer-checked
mode, the node `call` jobs, the EVM → Soroban → EVM copy.

**Non-goals.** PQZ, Zether and the PQZ decoy list of key 0x0142 on Soroban (S13); BLS12-381 and pure-Rust kinds (S3);
`SmartKeyAccount` changes (its NET-SOR-04 / NET-SOR-13 items stay as specified, its keys stay `Ed25519` / `Passkey`;
binding UA kinds as its keys is not done); guardian recovery (NET-SOR-03); the mesh (Soroban stays job-API only,
NODE-MESH-07); Pi Network deployment; the governance matrix; mainnet.

**Anti-goals** (the plan shows each does not happen): a derived UA shown or usable as a `G…` / `C…` address; a nonce,
pay ref or record in temporary storage; an archived entry read as absent; a UA that can receive on Soroban but never
spend; a lane's authority spent by a call it did not mean to authorise; any admin or upgrade path in the registry.

## 2. UA id space and display

- **Ids.** A derived UA is `keccak256(TAG(kind) ‖ key_data)` with the host's `crypto().keccak256` (CTR-UA-04),
  byte-identical to EVM; `register` refuses an id whose top 96 bits are zero (`IdInNativeSpace`, CTR-UA-03: one rule
  for derived ids on every family). Native Soroban ids are `Address` values: `G…` (kind 0x0011, the ed25519 public key)
  and `C…` (kind 0x0012, the contract id), both 32 bytes, so native and derived ids share one space and are told apart
  only by an explicit kind (CTR-UA-03, NET-ALL-20). On Soroban that kind is the enum discriminant:

  ```rust
  #[contracttype] pub enum Holder { Addr(Address), Ua(BytesN<32>) }   // Ua = a derived id, never a native one
  ```

  A native subject never travels as `Holder::Ua`; `Holder::Ua` of an unregistered id is `UaNotRegistered`.
- **Display (NET-ALL-21).** A derived id is shown and encoded only as `urn:scaas:ua:v1:<kind>:<hex32>`, never as a
  strkey: 32 bytes encoded as `G…` look like an ed25519 account (a native payment there is lost) and as `C…` like a
  contract. `clientkeys` and the wallets refuse a native payment or SEP-41 `transfer` to the URN form; native ids keep
  their strkeys.
- **Purposes and messages** are CTR-UA-12's: `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)`, the PQ
  kinds sign `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty context (CTR-UA-23). `ua_msg` is always computed in
  the registry, never taken from an argument: the SDK's `Hash<32>` type (accepted by `secp256r1_verify` and
  `secp256k1_recover`) comes from a host hash function unless the SDK's `hazmat` feature is enabled (the registry never
  enables it), so the compiler enforces it.
- **The Soroban digest of a UA operation** is NET-SOR-16's op digest, `sha256(xdr(Vec[Symbol("scaas_metaop_v1"),
  network_id, contract, Symbol(fn), Vec(args)]))`, over the entry's arguments **without** `auth`: network, contract and
  function separated, as EIP-712 is on EVM. Purpose `metatx` for transfers, payments, burns and mandate entries,
  `trade` for orders, `metatx-cancel` for `ua_cancel_nonce`.

## 3. Kinds and verifiers (`ua-registry/src/verify.rs`)

| Kind | Key data | Soroban check of `sig` over the kind's message | Notes |
|---|---|---|---|
| `webauthn-p256` 0x0100 | `x ‖ y ‖ rpIdHash` (96) | NET-ALL-04 grammar (type, challenge = base64url(`ua_msg`), `crossOrigin` absent or false, no `topOrigin`, NET-SOR-13), `authData[0..32] == rpIdHash`, UP and UV, then `secp256r1_verify(0x04‖x‖y, sha256(authData ‖ sha256(clientDataJSON)), r‖s)`; **no origin compare** (accounts.md "Passkey id without origin") | host refuses high-s (CAP-51); the `SmartKeyAccount` parser is not reused (it compares an origin) |
| `p256` 0x0101 | `x ‖ y` (64) | `secp256r1_verify(0x04‖x‖y, sha256(ua_msg), r‖s)` | ECDSA-P256-SHA256 over `ua_msg`, as EVM |
| `ed25519` 0x0102 | `pk` (32) | `ed25519_verify(pk, ua_msg, sig)` | key validation (`y < p`, the eight small-order encodings refused) in the contract unless the `kinds.json` negatives show the host refuses them |
| `secp256k1` 0x0108 | `x ‖ y` (64) | `secp256k1_recover(ua_msg, r‖s, v − 27) == 0x04‖x‖y`, `s ≤ n/2`, `v ∈ {27, 28}` | `ua_msg` is the host keccak's `Hash<32>`: no prehash, as EVM |
| `mldsa44` 0x0130 / `mldsa65` 0x0131 | `pk` (1312 / 1952) | `crypto().ml_dsa_{44,65}_verify(pk, pq_msg, sig, ctx = empty)` (CAP-0087 `verify_sig_ml_dsa_{44,65}`; SDK PR #2138: key and signature as fixed-size `BytesN`, message and context `Bytes`, panics on failure) | sizes 1312 / 2420 and 1952 / 3309 B; FIPS 204 pure interface, empty context valid, exactly our CTR-UA-23 form; the exact Rust signature is recorded by T1 |
| `msig` 0x0120 | CTR-UA-09 layout | members by S10; `auth` = `abi.encode(MemberSig[])` (`{u16 index, bytes keyData, bytes sig}`, UA8-D5) for derived and EVM members, canonical encoding only (re-encode and compare, as EVM m3); a Soroban native member's slot carries empty `keyData` / `sig` and is checked by the host | threshold by weight; ids strictly increasing; `count ≤ 16`; the largest `msig` that fits a transaction (size, CPU) is measured and published, a larger one fails to register here |

`register` checks, in order: kind enabled (`KindDisabled`) → key data canonical (`KeyData`) → id (`IdInNativeSpace`) →
not registered (`AlreadyRegistered`) → `keyHash` free (`KeyInUse`; `msig` has none) → `msig` members registered or
native and in MEMBER (`MemberUnknown`) → `attrs` empty in 4b (`Attrs`) → `pop` over
`uaMessage(kind, PURPOSE_POP_V2, registrationDigest)` (`Pop`) → store, list, event. Nothing is read from the
submitter (CTR-UA-07): anyone may submit, a front-runner gets the identical record or a revert. Cost figures (CPU
instructions per kind, rent per entry) are measured by T0 / T2; CAP-0087 gives no calibration yet ("a few times an
Ed25519 verification", 16–57 KB transient memory).

## 4. The registry contract (`UaRegistry`)

```rust
#[contracttype] pub enum Checked { None, Chain, Relayer(Address) }               // UA-8 P11.3 code points 0 / 1 / 2
#[contracttype] pub struct UaAttrs { pub pqz_key: Bytes, pub pqz_pop_hash: BytesN<32>, pub kem_version: u64, pub kem_pk: Bytes }
#[contracttype] pub struct Registration { pub kind: u32, pub key_data: Bytes, pub attrs: UaAttrs, pub pop: Bytes,
    pub pop_checked: Checked, pub pqz_pop_checked: Checked, pub proven: bool, pub signable: bool, pub index: u32, pub ledger: u32 }
// persistent: Ua(ua) -> Registration; Key(key_hash) -> ua; List(kind, i) -> ua; Count(kind) -> u32
// Part B adds: PqzK(ua), PqzP(ua), Kem(ua, version) -> (pk, sig, Checked), KemMax(ua)
fn __constructor(env, relayers: Vec<Address>);                                    // may be empty; immutable (C13)
fn register(env, kind: u32, key_data: Bytes, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, relayer: Option<Address>) -> BytesN<32>;
fn require_authorized(env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes); // panics on failure
fn registration_of(env, ua) -> Option<(u32, Bytes, UaAttrs, Bytes, Bytes)>;    // exactly the register arguments
fn record_of(env, ua) -> Option<Registration>;  fn key_owner(env, key_hash) -> Option<BytesN<32>>;
fn ua_of(env, kind, key_data) -> BytesN<32>;    fn receivable(env, ua) -> bool;  fn relayers(env) -> Vec<Address>;
fn ua_count(env, kind) -> u32;  fn ua_at(env, kind, i) -> BytesN<32>;  fn ua_page(env, kind, start, n) -> Vec<BytesN<32>>;
```

Errors (`contracterror`): `KindDisabled`, `KeyData`, `IdInNativeSpace`, `AlreadyRegistered`, `KeyInUse`,
`MemberUnknown`, `Attrs` (4b only), `Pop`, `NotRegistered`, `Unauthorized`, `NotVerifiable`, `RelayerNotListed`,
plus Part B's `PqzHolder`, `KemHolder`, `KemVersion`, `KemKeyLength`, `PqzPopHash`. Events: `UaRegistered` (topics
`ua`, `kind`; data the record and `checked`). `Registration.index` is the CTR-UA-29 list position (one rule on every
registry; there is no Soroban consumer of it yet).

- **`require_authorized`** (CTR-UA-17's Soroban form): the record exists (`NotRegistered`) and is `signable`
  (`Unauthorized`), then the S3 check over `ua_msg(kind, purpose, digest)`; an `msig` checks each member under purpose
  `member` (`memberDigest = keccak256(structureUA ‖ ua_msg)`), a Soroban native member by
  `require_auth_for_args((ua, purpose, digest))`, until the threshold weight. It extends `Ua(ua)`'s TTL. The three
  portable purposes are not signed through it (they are `register` / `set_kem_key` only).
- **`signable`** = kind enabled ∧ `pop_checked == Chain` ∧ (`msig` ⇒ Soroban-signable weight ≥ threshold). Fixed at
  `register` (the record never changes, CTR-UA-15); `receivable(ua)` returns it.
- **Never in instance storage:** records grow per user, and the instance is one ledger entry with one size limit.

## 5. UA holders in the contracts

### 5.1 Token: the UA ledger

| Entry | Authority | Mirrors (EVM) |
|---|---|---|
| `ua_balance(ua) -> i128`, `ua_nonce(ua, lane) -> u64`, `ua_ref_used(ua, pay_ref) -> bool`, `registry() -> Option<Address>` | view | `balanceOfUA`, `uaNonce` |
| `transfer_to_ua(from: Address, to: BytesN<32>, amount)` | `from.require_auth()` | `transferToUA` (CTR-UA-28) |
| `pay_to_ua(from: Address, to: BytesN<32>, amount, pay_ref, valid_until)` | `from.require_auth()`; `PayRef(from, pay_ref)` once | `payWithFeeToUA` (the receiver axis; the mandate pays a UA payee through it) |
| `mint_to_ua(to, amount)` | admin | `mintToUA` |
| `ua_transfer(from: BytesN<32>, to: Holder, amount, lane: BytesN<32>, nonce: u64, valid_until: u64, relayer: Option<Address>, auth: Bytes)` | `registry.require_authorized(from, PURPOSE_METATX, digest, auth)`, lane nonce | `uaTransfer` / `uaExecuteTransfer` |
| `ua_pay(from, to: Holder, amount, pay_ref, valid_until, relayer, auth)` | as above, `lane = payLane(pay_ref)`, `nonce = 0` | `uaPay` |
| `ua_pay_meta(from, to, amount, salt, meta, valid_until, relayer, auth)` | `pay_ref = metaPayId(salt, meta)`; `PaymentMeta` before the settlement event | `uaPayMeta` (CTR-MTX-26) |
| `ua_burn(from, amount, lane, nonce, valid_until, relayer, auth)` | as `ua_transfer` | `uaExecute(burn)` |
| `ua_cancel_nonce(ua, lane, valid_until, auth)` | purpose `metatx-cancel` | `uaCancelNonce` |
| `ua_trade(dex: Address, order: Order, auth: Bytes, amount)` | `dex.require_auth()` (the DEX is the direct invoker), purpose `trade` over the order digest | `uaTrade` (CTR-DEX-25 / -26) |

Rules (CTR-UA-27 parity, Soroban form):

- **`from` of a `ua_*` entry is a derived id**; a native subject keeps the native entries with host authorisation
  (NET-SOR-01) and reaches a UA receiver through `transfer_to_ua` / `pay_to_ua`. EVM's `ua*` accept a padded native
  `from` because one EIP-712 struct must carry both; on Soroban the host already gives natives every path, so parity
  holds without it.
- **Receivers:** `Holder::Ua(to)` must be `receivable` (S9: `UaNotRegistered`, `UaNotReceivable`); `Holder::Addr`
  as SEP-41.
- **The UA pool is the token's own address** (the CTR-UA-18 sentinel, here an address no transaction can sign for):
  `balance(token)` = Σ `UaBalance`, every native ↔ UA move also emits the SEP-41 `transfer` event to or from it, so an
  indexer replaying SEP-41 events still matches `balance()`; a native `transfer` / `pay` / `mint` to the token's own
  address is refused (`UaPoolNotPayable`; CTR-MTX-18 `TransferToSelf`). Every UA move emits
  `UaTransfer { from: Holder, to: Holder, amount }`; a payment also `UaPaymentSettled { from, to, amount, pay_ref }`
  and `UaMetaTransactionExecuted { from, digest }` (the job's id, as EVM).
- **No allowances for UAs** (CTR-UA-27): there is no `ua_approve`; a UA trades through `ua_trade`.
- The `PayRef(from, pay_ref)` set of `pay` stays per payer (NET-SOR-09); `ua_pay` is one-shot per `(ua, pay_ref)` by
  its lane, the same property.

### 5.2 Mandate

Owner, delegate and each payee become `Holder` (EVM UA-5c, CTR-ACC-12 `bytes32` ids). Funds stay in the mandate's own
native balance. A native owner or delegate keeps host authorisation; a UA owner signs `mtx_set_mandate`,
`mtx_set_payee`, `mtx_revoke`, `mtx_withdraw` (purpose `metatx`, mandate-own lanes `UaNonce(ua, lane)`); a UA
delegate signs `mtx_mandate_pay(token, payee, amount, pay_ref, valid_until, relayer, auth)`. A UA payee is paid by
`token.pay_to_ua(self, …)`, a withdrawal to a UA owner by `transfer_to_ua`. `pay_ref` once per mandate as today. The
NET-SOR-16 renames apply (new deployment).

### 5.3 DEX

`Order` gains `maker: Holder`, `destination: Holder` and the mandatory `relayer: Address` of NET-SOR-10 (SPECIFIED,
so the order type changes in this deployment anyway). A native maker keeps `require_auth_for_args((order,))` and
`transfer_from`. A UA maker's leg carries `auth` over `order_digest = op digest of ("ua_order", (dex, order))`: the DEX
calls the sell token's `ua_trade(dex, order, auth, fill)`, which verifies the UA (purpose `trade`) and moves `fill`
from the UA ledger to the DEX; proceeds go to `destination` (`transfer_to_ua` from the DEX for a UA). A UA signature is
not consumed by the host, so a UA order fills partially without re-signing; `filled[order_hash]` bounds it
(NET-SOR-05's overfill rule), `ua_cancel(order, auth)` sets `filled = sell_amount`, and the settling relayer stays
bound (`order.relayer.require_auth()`).

### 5.4 Relay fee (CTR-MTX-27)

The router gains `ua_relay(payer: BytesN<32>, target, func, args, salt, token, to: Holder, amount, valid_until, relayer,
auth)`: the same `ref` (`keccak256("scaas.relayfee" ‖ network id ‖ xdr(target) ‖ keccak256(xdr((func, args))) ‖
salt)`), then `env.invoke_contract(target, func, args)`, then `token.ua_pay(payer, to, amount, ref, valid_until,
Some(router), auth)`: the payer's UA signature covers `pay_ref = ref` and `relayer = router`, and only the router
(the direct invoker) satisfies `router.require_auth()`. Open mode (`to == Holder::Addr(router)`) forwards to the
submitting relayer as `relay` does. `RelayFeePaid`'s `payer` becomes a `Holder` (lossless id, the metatx-split §7.2
rule; one event shape, a node decoder change).

### 5.5 Conformance (CTR-MTX-27 and the cross-family rules)

| Rule | Soroban UA form |
|---|---|
| Every state-changing mtx write relayable, fee may be 0 (owner 2026-10-20) | every `ua_*` / UA mandate / UA DEX entry and every registry write is submitted by a lane; no fee field (NET-ALL-28 table: none while non-EVM tokens charge none); payable through `relay` / `ua_relay` |
| `ref` commits to the call, payment consumed only with it | `ua_relay` recomputes `ref` from the call it ran; `relayer = Some(router)` |
| Never pay the router / marker | `to == Holder::Addr(router)` is open mode, not a credit; the token refuses its own address |
| Target exists at relay time | as `relay` today (`TargetNoCode`); the registry is a deployed contract |
| Explicit relayer authorisation | S8 |
| Lanes non-pruning (NET-ALL-01, CTR-MTX-04) | persistent `UaNonce`; archived ≠ deleted (§7) |
| One vector file per rule | §10 |

## 6. UA-8 records on Soroban (Part B, mapped onto 4b)

- **Same bytes and digests as EVM (P1, P10).** `portablePopDigest`, `registrationDigest`, `kemRecordDigest` and
  `uaMessage` are computed with the host keccak over 32-byte words (`abi.encode` of 32-byte words is their
  concatenation; `uint256(version)` is 32 bytes big-endian); `portable.json` is the test oracle. `registration_of`
  returns exactly the `register` arguments, so a record read from Soroban registers on EVM byte for byte.
- **`checked` per part** (UA8-D20): `Chain` for the S3 kinds and an `msig` whose every signature is chain-verifiable
  here; `Relayer(id)` for `fndsa512`, `slhdsa128s`, an `msig` with such a member or an `evm-contract` member; `None`
  for the PQZ proof always (no verifier), `proven = false`. A `Relayer` record has `signable = false`: it serves
  discovery (KEM keys, PQZ key lookup, copying) and authorises nothing (P11.5).
- **The relayer-checked mode** (P11, UA8-D18 / D19): `relayer` ∈ the constructor's list and `relayer.require_auth()`;
  parts the chain verifies are always verified and stay open to anyone.
- **PQZ bytes** (UA8-D21, C12): the key (16,384–22,528 B by set, `n2048-kmax1024` … `n2816-kmax65536`) in `PqzK(ua)`, the
  proof (28,191–35,479 B) in `PqzP(ua)`, each its own persistent entry, given by `register` or by `store_pqz_pop`;
  `Registration.attrs.pqz_key` stays empty in `Ua(ua)` and `registration_of` reassembles it (as `kem_pk`). The
  secondary-source limit of a contract-data entry is 65,536 B (read the real value at T0), so each fits one entry.
- **KEM records** (CTR-UA-32): `Kem(ua, version)` write-once in any order, 1,600-byte keys, `KemMax(ua)`.

## 7. Storage, TTL, archival, fees

- **Archived is not lost.** A persistent entry whose TTL runs out is moved to the archive, not deleted; since
  Protocol 23 (CAP-0066) an `InvokeHostFunction` whose footprint lists it restores it automatically before execution
  (rent and restore fees apply), and `RestoreFootprintOp` restores it explicitly. A temporary entry is deleted for good,
  hence S11. An archived entry is never read as "absent": a transaction that needs it either restores it or fails, so
  an archived nonce cannot be replayed and an archived record cannot be registered over.
- **TTL.** Each write and each in-transaction read extends the entry (`extend_ttl(30 days, 60 days)`, `DAY = 17,280`
  ledgers, as `token` / `mandate`). Views run in simulation and extend nothing, so read-mostly entries (a PQZ key, an
  old KEM version) archive after 60 days and are restored by whoever next needs them in a transaction; a client that
  only reads restores first (or reads the archived value through RPC where the RPC serves it). Long-lived records are
  never refreshed by a node job (UA8-D22).
- **Who pays.** The lane pays the resource fee, the initial rent and any restore (S12), bounded per job by the chain's
  `max_deposit_per_job` (NODE-LANE-18); a self-submitter pays its own. No user or UA holds XLM.
- **Limits** (read with `stellar network settings` at T0, recorded in the run log and soroban.md; the secondary
  figures conflict: 100 M / 400 M / 600 M instructions per transaction, 64 KiB per contract-data entry, 128 KiB per
  Wasm): they bound the largest `msig` and Part B's single-transaction PQZ registration (UA8-D21, B0).

## 8. Code authority (owner rule; NET-ALL-83)

- **`G…` accounts** cannot hand authority to code: their signers are ed25519 keys, pre-authorised transaction hashes
  and hash-x preimages; the host checks thresholds. A `G…` subject's authority is its keys.
- **`C…` accounts** are contract accounts (`__check_auth`), like an EVM contract with ERC-1271 (0x0002): a contract is
  its own authority, not a key account delegating to code, so SCaaS accepts them as natives and as `msig` members
  (S10). SCaaS's own `C…` account is `SmartKeyAccount`.
- **A UA is a key or a set of keys** checked by the registry's own code (§3); no kind delegates to a contract, and the
  registry never accepts an arbitrary verifier address (kinds are compiled in, S3, S16).
- **The node never lends a lane's authority.** A simulation in recording mode returns every auth entry the call
  asked for, including `SourceAccount` ones; the adapter attaches **only** the subject's signed entries it was given
  and, when `relayer = Some(lane)`, one `SourceAccount` entry rooted at exactly the job's top-level call (the
  `relay-fee` rule). Any other recorded `SourceAccount` entry fails the job before submission.
- Wallet guidance stays NET-ALL-83's.

## 9. Node adapter changes (described, not coded; `scaas-node/src/adapters/soroban.rs`)

1. **`ua_metatx` jobs** (S15): `{contract, function, args (XDR), relayer}`; function ∈ the allow-list per contract
   class (token `ua_*`, mandate `mtx_*` UA forms, DEX settle with UA legs, router `ua_relay`); no subject auth entries;
   the §8 auth rule; `valid_until` and the contract taken from the signed arguments (NET-SOR-15); the op digest
   recomputed and recorded as the job id.
2. **`call` jobs** for the registry writes (UA8-D23, Part B B6).
3. **`op_consumed`** for UA jobs: `ua_nonce(ua, lane) > nonce` or `ua_ref_used(ua, pay_ref)` ⇒ `consumed`
   (NET-SOR-12's rule).
4. **Archived entries:** accept a simulation that restores archived footprint entries (Protocol 23 transaction data)
   and pay it within `max_deposit_per_job`, instead of `Revert` on `restorePreamble` (today `soroban.rs:345`): this
   builds NET-SOR-11's node half.
5. **Chain profile:** `params.ua_registry` (contract id); at start the node reads `relayers()` and checks its lanes
   are listed when the relayer mode is configured (Part B).
6. **Indexer:** `UaTransfer`, `UaPaymentSettled`, `UaMetaTransactionExecuted`, `UaRegistered`, `RelayFeePaid` with a
   `Holder` payer.
7. `tx_fee` / `lane_balance` (NET-SOR-14) are not part of 4b.

## 10. Vectors and test plan

**Vectors.** Shared: `smartcontracts/vectors/ua/{kinds,signatures,pq_signatures,structures,portable}.json` read by the
registry's tests (`include_str!`); every row of an S3 kind must verify, every negative must fail. New:
`smartcontracts/soroban/vectors/ua-ops.json` — the op digest, `ua_msg` and a signature per kind for `ua_transfer`,
`ua_pay`, `ua_pay_meta`, `ua_trade`, `ua_relay`, `mtx_mandate_pay`, reproduced by the contract tests, `clientkeys`
(`src/soroban.js`) and the adapter (cross vectors, as NET-SOR-16's digest).

**Tasks (for the plan).** T0 spike (local quickstart at P30: CPU / memory / size of an `mldsa65` registration, a 3-member
`msig` of `mldsa65`, `ua_pay` with a passkey; read the network limits; HARD GATE: over a limit ⇒ owner rules) → T1
SDK `=30.0.0-rc.1` on the workspace, all crates green → T2 `verify.rs` per kind from the vectors → T3 `register`,
`require_authorized`, lists, views → T4 token UA ledger → T5 mandate → T6 DEX → T7 router `ua_relay` → T8 node → T9
`clientkeys` → T10 docs → T11 gates → T12 testnet e2e (after 2026-11-03, protocol read from the RPC, SDK 30.0.0).

**Tests that must exist** (names indicative): `kind_<k>_vectors_verify` / `_negatives_fail` per S3 kind;
`register_portable_pop_from_portable_json` (the S3 rows); `register_any_submitter`; `register_front_run_identical`;
`register_disabled_kind_refused`; `register_attrs_refused_4b`; `id_in_native_space_refused`; `key_hash_unique`;
`msig_soroban_native_member_host_auth`; `msig_evm_eoa_member_portable_only`; `msig_unsignable_not_receivable`;
`require_authorized_each_kind_and_purpose`; `ua_transfer_replay_refused`; `ua_pay_once_per_ref`;
`ua_entry_archived_nonce_restored_not_reset` (archive the lane entry, re-submit the old nonce ⇒ refused);
`pool_address_not_payable`; `sep41_events_match_balance_with_ua_moves`; `relayer_bound_needs_auth`;
`ua_relay_router_only`; `ua_relay_open_mode_pays_submitter`; `ua_trade_dex_only_partial_fill_no_resign`;
`mandate_ua_owner_delegate_payee`; adapter `ua_metatx_refuses_extra_source_account_auth`,
`ua_metatx_allowlist`, `op_consumed_ua_lane`, `auto_restore_within_deposit_cap`; e2e (`#[ignore]`, quickstart, then
testnet): register a passkey UA and an `mldsa65` UA, `transfer_to_ua`, `ua_pay` relayed, `ua_relay` fee, a mandate
payment to a UA payee, one UA DEX leg. Every Soroban crate keeps its tests with real authorisation (soroban.md §8).
Gates: `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban`, the node's `cargo test` / `clippy`,
`clientkeys` `npm test`, `docs_check`; docker runs capped with `--memory`.

## 11. UA-8 Part B conflicts C11–C17, ruled against the 4b names

| Conflict (progress ledger) | Ruling (controller call, owner may override) |
|---|---|
| **C11** B0's spike needs digests B1 creates; B0 claims network figures but runs unit tests | 4b builds the portable digests and `register` (S2), so B1 shrinks to the KEM record digest and the `portable.json` check; the network spike is 4b's T0 (RPC `simulateTransaction` on the local quickstart) and Part B's B0 re-runs it for the full PQZ + KEM registration; spikes are their own gate step (`soroban-spike-local`, docker), never inside the `soroban` unit step |
| **C12** (a) no input path for a hash-only PQZ fallback; (b) two STOP definitions in B0; (c) the PQZ key stored twice | (a) no hash-only fallback: P2 stores the key, so a key or proof that cannot be stored is a **STOP** for the owner; (b) one STOP: any limit exceeded after the `store_pqz_pop` split; (c) the key only in `PqzK(ua)`, `attrs.pqz_key` empty in `Ua(ua)`, reassembled by `registration_of` (§6) |
| **C13** the relayer list appears only in B4 and changes the constructor | 4b's constructor already takes `relayers: Vec<Address>` (empty allowed) and `register` already takes `relayer: Option<Address>` (§4); B4 changes no caller |
| **C14** B5 lets a kind stay unverifiable off chain but requires every KAT to pass | per-kind gating: a crate that disagrees with a KAT row leaves that kind unverifiable off chain (the node refuses relayer mode for it), its KAT tests are marked for that kind, and the finding is reported; not a STOP |
| **C15** the round trip covers kinds Soroban refuses, and the forge test repeats A5 | the Soroban round trip covers the `Chain` rows plus one `fndsa512` through the relayer mode; `ua8-roundtrip.json` carries what only Soroban produces (`checked`, the KEM order); the forge `test_ua8_sorobanRoundTripRegisters` is dropped (A5 covers the bytes); B7's e2e reads EVM `registrationOf` itself (`eth_call`) |
| **C16** `zether-prover` hard-codes `.v1` purpose tags | not a Soroban item; Part A's record, not ruled here |
| **C16b** no task swaps the SDK pin | the swap to soroban-sdk 30.0.0 is the first step of the round's testnet task (4b T12, which Part B's B10 follows) |
| **C17** `NotRegistered` missing | in 4b's error set (§4); B3 reuses it |
| B4 `ua8_relayer_list_immutable` is weak | assert on the contract's exported function list (its spec): no function besides the constructor writes the list |
| B8 says "step 2 done" before B10 | B8 says "built, local e2e passed"; "done" only after B10 |

## 12. Threat notes

- **Front-running `register`:** identical record or a revert (CTR-UA-07); tested.
- **Replay after archival:** impossible by §7 (archived entries restore, never read as absent); tested.
- **Lane authority:** §8; tested by the adapter.
- **Unspendable receiver:** S9.
- **High-s / malleability:** host refuses high-s P-256; the contract refuses high-s secp256k1; ed25519 and ML-DSA
  signatures are not used as ids or nonces.
- **Network id:** Soroban's chain separator is `sha256(passphrase)`; two local standalone networks share it, so a
  signature for one replays on the other where the contract ids match. Test-only; the node binds contract ids per
  chain profile (NET-ALL-22); Stellar testnet, mainnet and Pi have distinct passphrases.
- **Registration spam and rent:** no on-chain gate (CTR-UA-25); relayed registrations are bounded by the node's
  sponsorship limits; self-submitters pay their own rent.
- **Unaudited code:** the WebAuthn parser, the ABI decoder of `MemberSig[]` and the secp256k1 low-s check are new
  code; the ML-DSA arithmetic is the host's.

## 13. Open questions for the owner

None blocks the plan; each has the default stated in §0, and the plan proceeds with it unless the owner overrides.
Two choices are worth the owner's look because they shape the code most:

1. **S6** — the UA ledger with separate `ua_*` entries (EVM shape), not a per-UA custom-account contract. Confirm, or
   choose the custom account (no token changes, but a contract per UA per chain and a native address for a derived UA).
2. **S10** — Soroban native `msig` members (0x0011 / 0x0012) make Soroban-network-local records, and an EVM `msig`'s
   EOA members have no signing weight on Soroban. Confirm, or drop native members (simpler, fewer forms).

## 14. Sources (read 2026-10-30)

- CAP-0087 "ML-DSA signature verification" (status Implemented, Protocol 30; host functions, sizes, cost types 86–94,
  calibration TBD): https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md
- rs-soroban-sdk PR #2138 (ML-DSA wrappers, merged 2026-10-19): https://github.com/stellar/rs-soroban-sdk/pull/2138 ;
  releases (30.0.0-rc.1 of 2026-10-21 is the first with `Crypto::ml_dsa_{44,65,87}_verify`; 29.0.1 latest stable):
  https://github.com/stellar/rs-soroban-sdk/releases
- Protocol 30 "Bell" dates (testnet vote 2026-11-03 17:00 UTC, mainnet vote 2026-11-23; Stellar Core v30.0.0) —
  secondary sources only, re-check before T12: https://www.mitrade.com/insights/news/live-news/article-3-2200229-20261028 ,
  https://www.bitrue.com/blog/stellar-xlm-bell-upgrade
- stellar/quickstart (tags, `--local`, `--protocol-version`, `--limits`): https://github.com/stellar/quickstart
- Resource limits (numbers only via `stellar network settings` / Stellar Lab):
  https://developers.stellar.org/docs/reference/resource-limits-fees ; conflicting secondary figures:
  https://deepwiki.com/stellar/laboratory/9-network-limits-and-resource-constraints ,
  https://mintlify.wiki/stellar/rs-soroban-sdk/migration/breaking-changes
- Protocol 23 automatic restore (CAP-0066) and state archival:
  https://stellar.org/blog/developers/announcing-protocol-23 ,
  https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival
- Third-party pure-Rust ML-DSA figures (self-reported): https://github.com/latticework-dev/soroban-ml-dsa
