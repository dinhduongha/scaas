# Spec: the PQZ three-key model

2026-11-13. Status of every section: **SPECIFIED** (nothing built). Everything cryptographic is **UNAUDITED**.
Written read-only against `ua-mtx-merge` at `cac043bc`; nothing run, nothing measured: every gas and size figure is
paper arithmetic from figures the repository records and is marked [estimate]. PQZ only; Zether is untouched.
Rule ids here are local (`K3-n`); the build round gives them `CTR-PQZ-*` / `CTR-UA-*` / `CLI-SGN-*` / `NODE-JOB-*`
ids and `decisions.md` entries. Background: `q1-design.md`, `triage.md` §3 (finding T-01). Revised after the Fable review
`20261113-09-fable-fable5.2-high-spec-three-keys.md` (findings S-1 … S-19) and the Codex review
`20261113-13-codex-gpt-6.1-sol-medium-spec-three-keys.md` (C-1 … C-6), each finding checked against the code.
**Scope: EVM.** No other family has an `OFFCHAIN` PQZ token at `cac043bc`; a family that gets one takes the same
rules in its own round.

**Build-round ids** (step 1, 2026-11-13; normative text in the component docs, entries in `decisions.md` with the rulings of
§0 verbatim): K3-1 and K3-1b → [CTR-PQZ-37](../../contracts/pq-zero-knowledge.md#CTR-PQZ-37); K3-2 and K3-6b →
[CLI-SGN-50](../../clients/signers-clientkeys.md#CLI-SGN-50); K3-3 → [CTR-UA-43](../../contracts/accounts.md#CTR-UA-43);
K3-4 and K3-4b → [CTR-PQZ-38](../../contracts/pq-zero-knowledge.md#CTR-PQZ-38); K3-5 →
[CTR-PQZ-39](../../contracts/pq-zero-knowledge.md#CTR-PQZ-39); K3-6 → [CTR-PQZ-40](../../contracts/pq-zero-knowledge.md#CTR-PQZ-40);
K3-7 → [CLI-SGN-51](../../clients/signers-clientkeys.md#CLI-SGN-51); K3-8 →
[CTR-PQZ-41](../../contracts/pq-zero-knowledge.md#CTR-PQZ-41); the node's job shape (§13) →
[NODE-JOB-28](../../node/job-api.md#NODE-JOB-28); §8 and §9 as Changes of the rules they name. The reviews cited above
and `q1-design.md` / `triage.md` are review files kept outside the repository.

## 0. Owner rulings this spec implements (2026-11-13, verbatim)

1. "Đồng ý mô hình 3 khóa." (the three-key model, §1).
2. Own-key tokens: "OFFCHAIN khoá riêng: ... Chấp nhận việc này, vì token này thường có verifier của họ. Rủi ro chỉ
   nằm ở TOKEN này mà thôi."
3. "KEM và ARCH-POS-13: Coi là nằm ngoài" (§9.1).
4. "Biện pháp tạm thời: Chưa cần sửa factory, vì kiểu gì cũng phải đổi." (§11).
5. Rejected by the owner: removing a bad credit after the fact by homomorphic subtraction (too costly with many bad
   credits). Bad credits are skipped by mark (§7).
6. Stored `R_REG` proofs for class-2 and class-3 keys: "Lưu". They stay in state; CTR-PQZ-30 is unchanged; the
   cost of about 71–92 M per key record stands (§12).
7. The `PRECOMPILE` `proofSystemId` moves in the same round and carries T-35 / T-36: "Có" (§4, K3-4b).
8. Switching a `proofSystemId`: "reset chain cho tới mainnet" (by chain reset only, until mainnet 22776; §4, §11).
9. "1-4 theo đề xuất." on the four questions then open: an `msig` is refused on shared-key tokens at first (K3-3);
   op 7 is unsupported on shared-key tokens at first, the later form being one group per leg (K3-5); the shared
   key is bound to `chainUid`, one per holder per chain (K3-2, K3-3); `ROLL_MAX` for the signed rollover is measured
   in the build first and then brought to the owner (K3-8).
10. "Q8, Q9 đồng ý theo đề xuất." Q8: the shared-key record carries its own opening KEM key (same hybrid scheme, own
    derivation label, bound to `chainUid`, rotating with the shared key's version); openings are sealed to it, not to
    the chat KEM key (K3-3, K3-6, K3-6b). Q9: the stated guarantee of `auditorMode = FULL` on shared-key tokens is
    that an honest recipient cannot spend a credit the auditor cannot read; two colluding modified wallets can leave
    a leg `unreadable` with both UAs named, which is a compliance event for the issuer, with no contract action in
    this round (K3-7).
11. "cho token OFFCHAIN khoá riêng tuỳ chọn dùng sealed opening. thêm phần matrix cho cả ba loại và cho tổ hợp khoá
    riêng có opening." An own-key `OFFCHAIN` token may be created with the sealed opening (K3-1, K3-1b); the on-chain
    matrix covers the three classes and own key with opening (§15.2).

## 1. The model

<a id="K3-1"></a>**K3-1 — Three key classes; a token's class is fixed at creation.**

| Class (name in ids) | Token | Key | Credit evidence | Rollover |
|---|---|---|---|---|
| 1 `registry` | `PRECOMPILE` | the registry PQZ key, unchanged (CTR-UA-16 / -42) | the on-chain proof | public, as today (CTR-PQZ-08) |
| 2 `offchain-shared` | `OFFCHAIN`, `pqzOwnKey = false` | one second PQZ key per holder, common to all such tokens, never the registry key | a **sealed opening** on every credit (§5); the holder re-encrypts and compares, never decrypts a credit with `s` (§6) | **holder-signed**, with skip marks (§7) |
| 3 `offchain-token`, opening off | `OFFCHAIN`, `pqzOwnKey = true`, `pqzOpening = false` | one PQZ key per `(holder, token)` | none: as an `OFFCHAIN` token today | public, as today |
| 3 `offchain-token`, opening on | `OFFCHAIN`, `pqzOwnKey = true`, `pqzOpening = true` | one PQZ key per `(holder, token)` | a sealed opening on every credit, as class 2 | holder-signed, with skip marks, as class 2 |

`IFactoryToken.ConfidentialConfig` gains two named fields, `bool pqzOwnKey` and `bool pqzOpening` (after
`verifierFeeMax`), both immutable. Valid combinations: `PRECOMPILE` with both `false`; `OFFCHAIN` shared key with
`pqzOwnKey = false`, `pqzOpening = true` (class 2 always has the opening); `OFFCHAIN` own key with `pqzOwnKey = true`
and `pqzOpening` either way. Anything else reverts `PqzVerifyConfigInvalid()`; a non-PQZ kind refuses either set
(`ConfigFieldForOtherKind(4)`).
Written by `init` only, shown by `pqzVerifyConfig()`. There is no `OFFCHAIN` token on the registry key any more: the
old form cannot be created. `init` sets `proofSystemId = PqzSet.PQZL_SPLIT_ID` with the opening on (§4) and
`PQZL_ID` with it off (PQZL only on `OFFCHAIN`, as today).

<a id="K3-1b"></a>**K3-1b — The opening machinery is keyed on `pqzOpening`, not on the key class** (owner 2026-11-13,
ruling 11). An **opening token** is a token with `pqzOpening = true`: every class-2 token, and a class-3 token
created with it. On every opening token, and on no other: split randomness and `PQZL_SPLIT_ID` (K3-4), op 7
unsupported (K3-5), the sealed openings and the deterministic auditor opening (K3-6), the opening KEM key in the
holder's scoped record (K3-3, K3-6b), the holder check (K3-7), the signed rollover with skip marks (K3-8), the
single disclosure kind (§8), `ownTag` over `u_f` and the `memoHash` that covers the openings. The token reads one
flag; the key class only selects the scope of the key record. Where §4–§8, §10 and §12–§14 still say "class 2" or
"shared-key" for this machinery, the rule holds for every opening token; where they say "class 3" for the behaviour
without it (no opening, public rollover, op 7, three disclosure kinds, the accepted exposure), they mean class 3
with the opening off. Differences of class 3 with the opening on are only these: the key and the opening KEM key
are per `(holder, token)` (K3-2, K3-6b); an `msig` may hold the record (K3-3); the auditor's key is not checked at
`init` (K3-3).

What each class guarantees:

- Class 1: unchanged (triage §3.4: provability does not depend on `s`).
- Class 2: no decryption oracle, **if the wallet follows §6**; the contract cannot enforce §6.
- Class 3 with the opening on: as class 2, no decryption oracle if the wallet follows §6; and a wallet that breaks
  §6 exposes that token's key only, not a shared one. The accepted exposure below does not apply to it.
- Class 3 with the opening off: none against that token's verifier. A dishonest or compromised verifier recovers the holder's key **of that
  token** from the holder's public reactions, and every chain observer learns it. The loss is the confidentiality of
  that holder's amounts in that token, nothing else. A holder accepts this per token by registering the key
  (§3); the token's auditor, once named, has no such choice, and its key of that token is exposed the same way and
  opens every audited amount (§9.1).
- Funds: unchanged in every class (every debit needs `PqzAuth`, CTR-PQZ-12); T27's maximum loss is unchanged.

## 2. Key derivation

<a id="K3-2"></a>**K3-2 — One seed per class, version and (class 3) token; domain-separated.** Extends CLI-SGN-49;
class 1 is byte for byte today's rule. `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info)`, 32 bytes,
`pk = KeyGen(seed32)` at the set of §3:

| Class | `info` |
|---|---|
| 1 | `"scaas.ua.pqz-mlwe.v1" ‖ u32(account) ‖ u32(index) [‖ be64(v) for v ≥ 1]` (unchanged) |
| 2 | `"scaas.ua.pqz-mlwe.offchain-shared.v1" ‖ u32(account) ‖ u32(index) ‖ chainUid(32) ‖ be64(v)` (the version always, `v = 0` too) |
| 3 | `"scaas.ua.pqz-mlwe.offchain-token.v1" ‖ u32(account) ‖ u32(index) ‖ chainUid(32) ‖ token(20) ‖ be64(v)` |

- Class 2 binds `chainUid`: one shared `OFFCHAIN` key per holder per chain (owner 2026-11-13), so its record is not
  portable and a key of one chain says nothing about another's. Class 3 binds `chainUid` and the token address.
  Only the class-1 key stays chain-independent.
- An `msig` operator draws each class and version fresh (CLI-SGN-49's rule).
- Derived only in the key worker; vault leaf `vault:pqz:<class>:<account>:<index>[:<chainUid>[:<token>]]:<v>` (class 2 the chain, class 3 the chain and token).
- **`ownTag` on an opening token's op 1 covers `u_f`** (review C-1): `HMAC(K, chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖
  keccak256(P(u_f) ‖ P(v_f)))`, the ciphertext the holder later decrypts, not the leg's `u`. Burn, refresh and unwrap
  keep `u′`; with the opening off CTR-PQZ-34 stays as it is. KAT row in `pq_kat.json`.
- `seed_enc` (CTR-PQZ-19), the memo key (CTR-PQZ-23) and `ownTag`'s key `K` (CTR-PQZ-34) keep their formulas with
  `pqzKeySeed` = the seed of the token's class and version. They already bind `chainUid` and `token`.
- A wallet never loads a class-1 or class-2 secret into a code path that handles a class-3 token's ciphertexts (the
  key handle carries its class; a mismatch is refused before any arithmetic).

## 3. Registry: storage, registration, versions, sets, auditor

<a id="K3-3"></a>**K3-3 — Scoped PQZ key records.** A new record space in `UARegistry` (a new registry generation;
nothing deployed is upgraded), beside the unchanged class-1 records: `(ua, scope, version)` with
`scope = address(0)` for class 2 and `scope = token` for class 3.

- **Write.** `setPqzScopedKey(bytes32 ua, address scope, uint64 version, bytes pqzKey, bytes32 pqzPopHash,
  KemKey openKem, uint64 validUntilBlock, UASig sig)` (`openKem` present exactly when the record carries an opening KEM key, see below; the complete entry point, pinned
  in the vectors),
  relayable by anyone, no fee (as `setKemKey`). `sig` is the UA's own signature (`members` for an `msig`) over
  `uaMessage(kind, PURPOSE_PQZ_SCOPED_KEY, typed(UAPqzScopedKeyRecord{bytes32 ua, uint8 keyClass, bytes32 chainUid,
  address token, uint64 version, bytes32 pqzKeyHash, bytes32 pqzPopHash, bytes32 openKemHash, uint64 validUntilBlock}))`
  (the complete type; `openKemHash = keccak256(kemPk)` when `openKem` is present, else 0)
  (refused after that block, so a signed record the holder no longer wants lapses); both classes sign this
  registry's `chainUid` (a record made for another chain is refused); class 2 signs `token = 0`, class 3 `scope`. Needs the UA registered with a class-1 holder
  kind (CTR-PQZ-12's holder rule, unchanged) and `version == latest(ua, scope) + 1`, the first being 0. **Every version of a scope has version 0's key
  length** (`UAKeyData(0x0142)` otherwise; review S-5): a holder's set is fixed per scope at first registration, so a
  rotation can never strand the balances of the old set.
- **Proof.** `storePqzScopedPop(ua, scope, version, pqzPop)`; the `R_REG` message is
  `uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, digest(ua, keyClass, chainUid, token, version, pqzKeyHash))`, so no
  proof serves another class, chain, token or version. Scoped proofs of both classes are made under **`PQZL_ID`**
  (the registry's id, PQZL only), never the token's id: `0x0142` verifies them where the precompile exists, and a
  class-2 or class-3 verifier checks them under `PQZL_ID` (review S-6). Eligibility and `current` per `(ua, scope)` exactly as CTR-UA-42;
  on an `OFFCHAIN` token CTR-PQZ-30 applies unchanged (length only on chain; the verifier checks the stored
  `pqzPop` bytes off chain). The proof bytes are stored for both classes (owner: "Lưu"); cost in §12.
- **Opening KEM key** (owner 2026-11-13, rulings 10 and 11). A scoped record may carry one more named field,
  `KemKey openKem {uint8 scheme; bytes mlkemEk; bytes32 x25519}` (CTR-UA-32's scheme 1 and length checks, 1,601 B
  stored), signed as `openKemHash`. **It is present if and only if the scope's tokens have the opening on**: always
  on a class-2 record (scope `address(0)`; absent: refused); on a class-3 record the registry reads the token's
  `pqzOpening` (`pqzVerifyConfig()`, one static call to `scope`; a scope that does not answer is refused) and
  refuses a record that has the key for an opening-off token or lacks it for an opening-on token
  (`UAPqzOpenKem(scope)`). It is written once with its version, rotates only with that record's version, and is read
  by `pqzOpenKemAt(ua, scope, version)`. It is not a CTR-UA-32 record: the chat KEM key is never used for an opening,
  and CTR-UA-32 is unchanged.
- **`msig`.** A class-2 record for an `msig` is refused at first (`UAPqzHolder`; ruling 9); nothing in the format
  stands in the way any more, so it may be lifted later. A class-3 record for an `msig` is accepted as today's
  holder rule allows; on an opening-on token it must carry the opening KEM key like any other (the operator keeps it
  as it keeps the PQZ key), else it is refused by the rule above.
- **Never the registry key.** The per-UA marker `pqzKeyUsed(ua, pqzKeyHash)` and `keyOwner` span all three record
  spaces: key bytes stored in one class are refused in every other (`UAKeyInUse`).
- **Views.** `pqzScopedKeyOf(ua, scope) → (version, ptr, pqzPopHash, proven)`, `pqzScopedKeyAt(ua, scope, version)`,
  `pqzScopedKeyLatest(ua, scope)`, `pqzScopedPopOf`, a per-scope holder list (`count` / `at`, as CTR-UA-29) so a
  wallet finds a token's holders from state; events `UAPqzScopedKeyAdded`, `UAPqzScopedPopStored`,
  `UAPqzScopedKeyCurrent`. Nothing is deleted.
- **Token read.** **Every** current and historical PQZ key read of a token uses the token's scope: class 1
  `pqzKeyOf` / `pqzKeyAt`; class 2 scope `address(0)`; class 3 scope `address(this)`. No record:
  `AccountNotRegistered(ua)`, as today. The registry reads at `cac043bc`, each of which switches (review C-3):
  `_creditKey` (`PqzCore.sol:1218`: credits, shields, op 7 legs, and `PqzStateLib:296`), `_debitKey` (`:936` current
  and `:938` the stale version of a migration or refresh), `_keyPtrV` / `_keyPtr` (`:1239`: the auditor's key and
  version at `:311`, `:572`, and the auditor check at `init`, `PqzStateLib:82`, dropped on class 3), `_keyAt`
  (`:1246`: `prepareAcc` at `PqzStateLib:365`, the disclosure at `:794`) and the disclosure's direct read (`:792`).
  One internal function takes the scope; no site calls the registry views directly. The build greps for
  `pqzKeyOf` / `pqzKeyAt` and the list is re-made then.
- **Lazy.** A wallet registers the class-2 key at its first use of any shared-key token, a class-3 key per token. A
  holder without the record cannot be credited on that token (as an unregistered UA today).
- **Versions.** Each `(ua, scope)` has its own sequence; token state stays per `(ua, version)` (CTR-PQZ-31) with the
  version of the token's scope. Rotating one class moves no other. Rotating a class-3 key does not end that token's
  exposure (§1).
- **Sets.** Class 1: as today. Class 2: one key, hence one set, per holder per chain; a shared-key token of another
  set answers `AccountNotRegistered`. Class 3: the token's own set (the release's `PqzSet`), which may differ
  from every other key of the holder; the registry accepts any of the four `PqzCt.PK` lengths and the token checks
  its own.
- **Auditor.** The token's `auditorUA` holds a key of the token's class and scope. On an opening token the auditor's scoped
  record carries its opening KEM key, like any holder's. Class 3: the token address does not exist before creation, so `init` does not check the
  auditor's key; a transfer with the auditor on reverts `AccountNotRegistered(auditorUA)` until the auditor
  registers its key for that token (71–95 M, §12), and for ever if it does not: the issuer and the wallet read
  `pqzScopedKeyOf(auditorUA, token)` first, and the node refuses the job by name (`AUDITOR_KEY_MISSING`) before any
  proving. `AuditorAsParty` unchanged.

## 4. Statement with the opening on: `v_f` in its own randomness group, new `proofSystemId`

<a id="K3-4"></a>**K3-4 — Split randomness.** This is the fallback CTR-PQZ-04 already describes, made the rule for
class 2. Op 1 with the opening on:

- `(r_f, e1_f, e2_f)` from `seed_enc` (CTR-PQZ-19) give `u_f`, `v_f`.
- `seed_leg = SHAKE256("SCAAS-PQZ-ENC-LEG-V1" ‖ seed_enc ‖ be4(0) ‖ toUA ‖ keccak256(pk_t))[0..32)` (recipient and key
  inside, so a salt reused by a wallet fault never hands one recipient another's leg; review S-9; release builds
  take no caller-supplied salt); `Enc` draws `r, e1`, then `e2_t`, then
  `e2_a` from it and gives `u`, `v_t`, `[v_a]`. One-way: `seed_leg` reveals nothing of `seed_enc`, `v_f` or any other
  transfer. The sender still re-derives everything from its seed and the published salt.
- Relation `R_TXS` = `R_TX` plus the rows for `u_f` (CTR-PQZ-04's rows 2′ / 4′); `v_f` no longer shares `(r, e1)`
  with any leg, so the hint assumption of CTR-PQZ-04 is not used with the opening on.
- Statement: the 640-byte header unchanged (word 19 `memoHash` per §5); body `pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ out` with
  `out = u ‖ v_t ‖ v_f ‖ [v_a] ‖ u_f` (`u_f` appended, earlier offsets unchanged). In calldata `u_f` is its own named
  field: `PqzTransferArgs` gains `bytes uFrom` beside `u`, `vTo`, `vFrom`, `vAuditor` (opening on: exactly `PqzCt.PK`
  bytes, canonical lanes, not zero; opening off: empty, else `BadPayload`); node JSON `u_from`. Size = today's + `PqzCt.PK`:
  99,456 / 111,744 / 124,032 / 136,320 B with the auditor, 82,944 / 93,184 / 103,424 / 113,664 B without
  (`n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`). `ZeroU` applies to `u_f` too.
- `proofSystemId`: a new id per set, `PqzSet.PQZL_SPLIT_ID = keccak256(set.toml pqzl_split_id)`, proposed label
  `scaas/pqz/lnp22/mlwe-d64k<k>-q<log2q>l4/split-v1` (controller naming, owner may override). Under it `pqz-stmt`
  accepts `R_TXS`, `R_BURN` / refresh and the one disclosure relation `R_DS` (§8); it refuses `R_TX`, `R_TXM`, `R_REG`
  (K3-3) and `R_DR`. `PQZL_ID` refuses `R_TXS`. The new proof must fit `MAX_PROOF`
  98,304 B and statement + proof `MAX_INPUT` (524,288 B): to be measured at four sets.
- <a id="K3-4b"></a>**K3-4b — The existing ids move in the same round** (owner 2026-11-13: "Có"). T-36 (the
  disclosure `kind` low byte tied to the form: decoder, `pqz_kat.py`, vectors) is in the shared statement codec, so
  `PQZL_ID` gets its next label (`…/v6`, controller naming) and `PQZL_SPLIT_ID` is born with it. T-35 (one-byte role
  tags between Merkle nodes and transcript absorbs) is in PQZH's Ligero code (`pqzh/ligero` `merkle.rs`,
  `transcript.rs`; Fable u2-7), so **`PQZH_ID` moves too** at every set that has PQZH, with T-35 and T-36. The
  retired labels join `gen_set.py` `RETIRED`.
  Opening-off tokens (class 1, class 3 without the opening) therefore run on the new `PQZL_ID`, and the precompile (Nethermind plugin, self-test and probe
  constants in `PqzSet.sol`) is rebuilt for it. One full gate at four sets covers both ids.
- **Roll-out of ids** (owner 2026-11-13: "reset chain cho tới mainnet"): until mainnet 22776 a `proofSystemId` is
  switched by chain reset only. No token, registry or precompile serves an old and a new id side by side, and no
  migration path is built; the testnet stack is reset and redeployed by its controller on the new ids.
- Burn, refresh, unshield, unwrap: unchanged statements under the new id; fresh randomness, no opening (the output
  is the holder's own `v_f`, `ownTag`-checked). Shield: unchanged (TRIVIAL, no noise).
- Every op 1 leg carries an opening, the migration to oneself (CTR-PQZ-31) included: one rule.

<a id="K3-5"></a>**K3-5 — Op 7 with the opening on: unsupported at first.** `mtxConfidentialTransfer` (multi) on an opening
token reverts `OpUnsupported()`; consequence: no decoys on shared-key tokens. The later form is one group per leg
(each with its auditor copy), `M` extra `u`, a second new relation; not in this round (owner 2026-11-13). Reason: a group's seed goes to each of its recipients, so
legs sharing a group would read each other's amounts and tell decoys from payments. Opening-off tokens keep op 7
as today.

## 5. The sealed opening (opening on)

<a id="K3-6"></a>**K3-6 — Format.** One opening per reader of the leg seed: the recipient (`O_t`), and the auditor
(`O_a`) when `v_a` exists. Explicit parameters (calldata, added to `PqzTransferArgs`; empty with the opening off, else
`BadPayload`), the hybrid ciphertext as two fields like the registry's `KemKey` and the chat `Wrap`:

```
struct PqzOpening { bytes mlkemCt; bytes32 x25519Eph; bytes sealedSeed; }
PqzOpening openingTo;        // to toUA's opening KEM key
PqzOpening openingAuditor;   // to auditorUA's; empty when auditorOn = 0
```

- **Deterministic from `seed_leg`** (review S-1). Both openings are functions of `seed_leg` and public bytes, so
  each reader recomputes the other's opening byte for byte:
  `coins = SHAKE256("SCAAS-PQZ-OPEN-COINS-V1" ‖ seed_leg ‖ u8(role) ‖ keccak256(kemPk))[0..64)`, `role` 0 recipient,
  1 auditor, `kemPk` the reader's 1,601-byte opening KEM key: the one in the reader's scoped record (the token's scope) of the key version the
  leg is encrypted to (the recipient's `current`, read once per op as its `pk_t`; the auditor's likewise); `m = coins[0..32)` is the ML-KEM-1024 encapsulation randomness,
  `e = coins[32..64)` the X25519 ephemeral secret (the fixed-randomness `encaps(kemPk, m, e)` the chat code already
  has); `ss` by the combiner of CTR-UA-32 / UA-7 (`SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1")`).
  The coins are one-way in `seed_leg`, distinct per role and key, and are known only to parties that hold `seed_leg`:
  a reader learns nothing it did not have (the other opening seals the same `seed_leg`), and no KEM secret is involved
  in recomputing. No release build takes caller-supplied coins.
- `mlkemCt` 1,568 B, `x25519Eph` 32 B; `sealedSeed` 48 B = `AES-256-GCM(kek, nonce = 0^96, seed_leg, aad)` (UA-7's
  one-shot form), `kek = HKDF-SHA256(ikm = ss, salt = ∅, info = "PQZ/opening/kek/v1")`,
  `aad = chainUid ‖ token(20) ‖ ua ‖ be8(keyVersion) ‖ keccak256(P(u) ‖ P(v))` with `ua`, `keyVersion`, `v` the reader's
  (`toUA`, `v_t`; `auditorUA`, `v_a`; the versions are the account's own and the blob's `kv` tail). The `aad` holds only bytes the reader finds in state: `fromUA` and `sendCounter` are
  not in the blob and no state path leads from a pending slot to them, so they are not bound (review S-13, not
  taken: a leg copied into another op needs a false verdict and is a well-formed, unbacked credit, T27).
- **Label rule.** The label `"PQZ/opening/kek/v1"` is used nowhere else, and no protocol outputs `ss` or a `kek`.
- **Contract checks**, nothing cryptographic: lengths (1,568 / 48). No KEM lookup: the reader's scoped record,
  which the op reads anyway for `pk`, always carries the opening key. There is no `kemVersion` in the opening and no
  version race of its own: a recipient that rotates its scoped key between proof and landing fails the statement's
  key check, as today.
- **In state.** Op blob of a opening-on op 1:
  `R ‖ P(u_f) ‖ P(v_f) ‖ O_t ‖ [O_a] ‖ ownTag(32) ‖ kv(8·n) ‖ u8(n)`,
  `O = mlkemCt ‖ x25519Eph ‖ sealedSeed` (1,648 B; one packed run is the state format). `R` is
  unchanged, so `transferEntry` and `transferCiphertextHash` keep their values; `acc` points at `(u_f, v_f)`; `rOf`
  reads `n` from the last byte. Blob size with the auditor: 25,149 / 30,165 / 35,693 / 41,733 B at the four sets,
  under the 64 KiB ceiling; a build assert beside `DELTA_P_MAX`'s.
- **Binding.** `memoHash = keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))` with the opening on (CTR-PQZ-34's formula on
  class 1 and 3). The word is in the statement and in `PqzAuth`, so the sender's signature and the verdict cover the
  openings and no relayer can swap one.
- **`sealedMemo` is unchanged** (58 B, CTR-PQZ-23) and apart from the opening: keyed by HKDF from the sender's own
  seed, no `s`, no KEM, under the sender's own `entryRef`, written only by a debit the sender signed. Opening it is
  the holder reading its own data; consistent with ARCH-POS-13 and with ruling 3 without needing it.
- The verifier cannot check an opening. A wrong `O_t`, or with the auditor on a wrong `O_a`, makes the credit
  unspendable: the sender's loss (the debit stands, the units stay in `totalShielded`).

<a id="K3-6b"></a>**K3-6b — The opening KEM key is derived from the wallet seed** (review S-2; rulings 10, 11). The
shape of the rule on branch `ua-rs-sign` (`clients/ua-rs/src/wallet/kem.rs`), with a label per class:
`openKemSeed = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.kem.v1", info, L = 96)`, `v` the scoped record's
version:

| Class | `info` |
|---|---|
| 2 | `"scaas.kem.pqz-opening.1" ‖ ua ‖ chainUid(32) ‖ be64(v)` |
| 3, opening on | `"scaas.kem.pqz-opening-token.1" ‖ ua ‖ chainUid(32) ‖ token(20) ‖ be64(v)` |

`(ek, dk) = ML-KEM-1024.KeyGen_internal(d = openKemSeed[0:32], z = openKemSeed[32:64])`, `sk_X = openKemSeed[64:96]`,
`kemPk = 0x01 ‖ ek ‖ X25519(sk_X, 9)`. Derived only in the key worker beside the PQZ seed of the same record, one
vault leaf per version; never given to chat code. An `msig` operator draws it fresh with the PQZ key. KAT rows in
`pq_kat.json` (both classes, two chains, two tokens, versions 0 and 1). Restore test: mnemonic only → the openings
to versions 0 and 1 open, on a class-2 and on a class-3 opening token. The chat KEM key and its derivation are not
part of this spec.

## 6. The holder check (opening on)

<a id="K3-7"></a>**K3-7 — An opening-token wallet never applies `s` to a credit; it re-encrypts from the opening.** For a
pending entry of `(ua, version)` read from state:

1. TRIVIAL entry: accept, the amount is public.
2. Read the slot, the blob, the entry's `u`, `v_t`, `[v_a]`, `O_t`, `[O_a]`.
3. Derive the opening KEM secret of this account's key version (K3-6b).
4. `ss = Decaps(O_t)`: ML-KEM with implicit rejection; an X25519 low-order point is the same outcome, **skip**, on no
   separate path. `kek`, open `sealedSeed` with the `aad` of K3-6. Tag fails: **skip**.
5. `(r, e1, e2_t, e2_a) = Enc-expand(seed_leg)` with the pinned sampler; the relation's norm bounds must hold, else
   **skip**.
6. `P(Aᵀr + e1)` byte-equal to the stored `u`, else **skip**.
7. `w = v_t − pkᵀr − e2_t (mod q)` on the 16 plaintext coefficients with the holder's own `pk` (the token's scope) of that
   version; every `w_i = Δ·d_i` exactly with `d_i ∈ [0, 16)`, else **skip**. The amount is `Σ d_i·16^i`.
8. Recompute `O_t` from `seed_leg` (K3-6) and compare with the stored bytes, else **skip**.
9. With the auditor on (`v_a` in the blob): `v_a = pk_aᵀr + e2_a + Δ·d` byte-equal with the auditor's key from the
   registry, and `O_a` recomputed from `seed_leg` and the auditor's opening KEM key of its key version (the blob's `kv` tail) byte-equal
   to the stored bytes, else **skip**. So no credit is spendable by an honest wallet while the auditor is blinded.
10. **Accept.**

- **The auditor tool** runs the same steps with its own roles swapped (opens `O_a`, checks `v_a` with its `pk_a`,
  recomputes `O_t` and `v_t` with the recipient's public key). It never applies `s`. Its outcomes per credit are
  public and named (review C-4):
  - `read`: the amount; both openings good.
  - `recipient-unreadable`: `O_a` good, `O_t` or `v_t` bad. An honest recipient skips it.
  - `unreadable`: `O_a` fails. An honest recipient skips it too (step 9). The outcome alone says nothing about the
    recipient: any sender can append such a credit to anyone.
  - `unreadable, taken`: an `unreadable` or `recipient-unreadable` entry that is unmarked and that a
    recipient-signed rollover or debit has taken (its index is below the account's `rolled` or `floor`, read from
    state). Only this shows that the recipient's wallet bypassed the check, and it names both UAs.
  Owner 2026-11-13 (ruling 10): the guarantee of `auditorMode = FULL` on shared-key tokens is that an honest
  recipient cannot spend a credit the auditor cannot read; `unreadable, taken` is a compliance event for the issuer,
  and no contract acts on it in this round.
- Inputs are public bytes and the opening KEM secret. `s` is not an input. Every failure is the one outcome "skip"; no
  error detail, step number or timing class leaves the wallet.
- The PQZ secret is applied only to: the holder's own `(u_f, v_f)` after its `ownTag` verifies; a `T` whose every
  part is that, an accepted credit, a TRIVIAL entry or a marked slot (zero). The prover refuses a window with an
  unaccepted, unmarked credit **before** the secret is loaded.
- Debit: the wallet picks `p` so that every entry of the window is accepted, TRIVIAL or skip-marked; a failing
  entry below the wanted `p` is skip-marked first (§7).
- Restore from state alone: last debit record → blob → `ownTag` → own balance; then every later entry by the check
  above (amounts come from the openings).
- **A bad unmarked entry inside a materialised `acc`** (possible only by a wallet fault, since K3-8 binds contents):
  if its index is `≥ floor`, the wallet debits (a refresh) at `p ≤ index`; that `T` holds no bad part, the debit
  un-rolls `[p, rolled)` (CTR-PQZ-08) and the entry is then marked. Only an index `< floor` is beyond repair: the
  wallet stops using that account version, says so locally and does not decrypt.
- Mandatory in `clientkeys`, `ua-rs` (the only signer) and every binding through it; no opening-token "decrypt credit"
  entry exists in release builds.
- An accepted credit is an honest encryption with the sampler's noise, so `K_MAX·B ≤ E` holds as on `PRECOMPILE`.
  Whether its amount is backed is the verifier's soundness (T27), unchanged.

## 7. Signed rollover with skip marks (opening on)

<a id="K3-8"></a>**K3-8 — On an opening token only the holder rolls, and the holder marks bad credits.**

- `mtxRollOver(ua, keyVersion, n)` on an opening token reverts `RollOverSignedOnly()`. `mtxPrepareAcc` stays
  permissionless. Opening off: unchanged; the signed form reverts there.
- Entry point (direct, and relayed on both paths `mtxExecute` / `uaExecute`, fee 0 allowed, in `mtxSelectors` and
  `_uaAllowed`): `mtxRollOverSigned(bytes32 ua, uint64 keyVersion, uint64 n, uint64[] skip, uint64 validUntilBlock,
  IUARegistry.UASig ownerSig)`.
- Typed data in the token's EIP-712 domain, signed by the UA through `requireAuthorized` (the purpose `PqzAuth`
  uses; an `msig` by its m-of-n): `PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,
  uint64[] skip,bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)`. The domain binds the chain id and the
  token; `chainUid` is a field because the domain has none.
  - `rollSeq`: the nonce, a per-`(ua, keyVersion)` counter (uint64 beside `lastDebit`), +1 per accepted call.
  - `rolled`: the state value the holder signed against.
  - `entriesHash` (review S-3): binds **contents**, not positions. `h(i) = keccak256(abi.encode(i, slot_i with the
    skip bit cleared, codehash of slot_i's blob or 0 for a TRIVIAL entry))`;
    `entriesHash = keccak256(h(rolled) ‖ … ‖ h(rolled + n − 1) ‖ h(skip_0) ‖ … )`. The contract recomputes all three
    from state; any difference (a reorg put another op at an index, a debit un-rolled) is `AuthRejected`. A blob
    address alone would not do: it is a CREATE address, a function of the token's nonce.
  - Typehash pinned (`*TypehashIsPinned`); the storage layout pin moves.
- `skip`: strictly ascending absolute pending indices, length `≤ ROLL_MAX`, each in `[rolled, pendingCount)` and a
  credit (`SkipRange(index)`, `SkipTrivial(index)`). Each named slot gets the **skip mark**: bit 63 of the slot's
  `block` field. A mark is never cleared.
- **Readers of the `block` field** (review S-11): one accessor returns `(block, skipped)` and every read goes through
  it: `_window`'s `ROLL_AGE` test (`uint64(e) + ROLL_AGE`, which unmasked would call a marked slot too young for
  ever), `_trivial`'s same-block merge test, the `pqzPending` view (documented as carrying the mark) and every
  client that reads the creation block. View `pqzSkipped(ua, keyVersion, index)`.
- `0 ≤ n ≤ ROLL_MAX`; `n = 0` with a non-empty `skip` only marks (no prepared `acc` needed); `n = 0` with no skip
  reverts `RollOverRange(0)`. For `n > 0`: today's rules (`AccNotPrepared`, `CapReached`, `RollTooYoung`, order).
- A marked slot contributes zero to `_total` (a debit's window) and to a rollover, on every path, un-roll and
  re-roll included. It **counts one unit**: not for safety (it adds no noise) but because `unitsOf(T)` is index
  arithmetic and stays that way; the price is that `K_MAX − 1` junk credits cost the holder one refresh. The slot,
  its blob and its ciphertext stay in state (CTR-PQZ-33, never lose ciphertext). Events, in this order:
  `PqzSkipped(ua, keyVersion, index)` per mark ascending, then `PqzRolledOver` when `n > 0`.
- Nothing periodic: a cold wallet checks, marks and rolls when it next spends. It signs ⌈N / ROLL_MAX⌉ rollovers
  for N pending entries beyond what a debit window takes (§10).
- `ROLL_MAX`: the code bound stays the set's. The owner's fit rule (a relayed full transaction within
  `0.75 · 2^24`) is re-measured for the signed form on both paths. On a chain without the ML-DSA precompile the
  holder's signature is verified in Solidity (cap ≤ 2.5 M for a single key), so the fit likely needs about
  80 / 48 / 32 / 16 at the four sets [estimate]; the build measures first and brings the figures to the owner; a
  set-parameter change (a second value such as `roll_max_signed`) stays the owner's (owner 2026-11-13). Gas pins
  move old → new in the commit.

## 8. Disclosures per class

- `registry` (class 1): unchanged.
- `offchain-shared` (class 2) and every other opening token: **one kind**, `SENDER_S` (relation `R_DS`, knowledge of `r, e1, e2_t`), proven by
  any party that holds `seed_leg`: the sender (re-derived), the recipient or the auditor (from its opening).
  `RECEIVER_X` and `AUDITOR` revert `OpUnsupported()` on an opening token, so no opening-on disclosure path applies `s`
  to a leg (review S-4c). Consequences, to be written in the docs:
  - the kind identifies no party;
  - a disclosure proves the **encrypted amount, not receipt**: a sender that sealed a junk opening still proves the
    amount of a credit nobody can spend. Receipt is "not marked and spent": `pqzSkipped(ua, keyVersion, index)`
    false and a later debit of the recipient whose window holds the entry. With an auditor, the auditor's outcome
    `read` also says the opening was good.
  - The verdict form is required as on every `OFFCHAIN` token (CTR-PQZ-29); the statement carries `PQZL_SPLIT_ID`.
- `offchain-token` with the opening on: as `offchain-shared` above.
- `offchain-token` with the opening off: unchanged from an `OFFCHAIN` token today; a proving attempt on a crafted leg is part of
  the accepted exposure of that token's key.
- All classes: T-09 (one opaque prover error in `pqz-ffi`) is fixed in the same round; it is not replaced by this.

## 9. Docs changed in the build round (exact text)

In the docs the classes go by their names (`registry`, `offchain-shared`, `offchain-token`): "class 1 / 2 / 3"
already means something else in `signers-clientkeys.md`. The numbers are this spec's shorthand only.

### 9.1 ARCH-POS-13

Rule sentence "No exception, no opt-in." becomes "No exception and no opt-in other than the Change of 2026-11-13 for
key class `offchain-token`." Three Changes are appended:

> **Change (owner 2026-11-13, "KEM và ARCH-POS-13: Coi là nằm ngoài").** The rule is about decryption with a PQZ or a
> Zether key. A decapsulation of the hybrid KEM scheme of CTR-UA-32 (ML-KEM-1024 + X25519, IND-CCA by its combiner), under a
> chat key or an opening key, and the
> one-shot AEAD keyed by it are outside the rule. For the sealed opening of a shared-key token the reason is visible:
> the holder's reaction depends only on whether the sender's ciphertext or opening is well formed, which the sender
> already knows. It gives no leave to apply a PQZ or Zether key to anything the decapsulated value has not first
> shown, by re-encryption and byte comparison, to be well formed.

> **Change (owner 2026-11-13, three-key model).** On an `OFFCHAIN` token "real chain state" does not imply "well
> formed": the token's verifier, not a proof, admitted the ciphertext. On a shared-key `OFFCHAIN` token the check of
> the sealed opening (K3-7) replaces it; the reading layer supplies the chain location, the wallet checks the opening.

> **Change (owner 2026-11-13: "OFFCHAIN khoá riêng: ... Chấp nhận việc này, vì token này thường có verifier của họ.
> Rủi ro chỉ nằm ở TOKEN này mà thôi.").** Excepted is exactly one case: a PQZ key of class `offchain-token`
> derived for one `OFFCHAIN` token created with `pqzOwnKey = true` **and `pqzOpening = false`**, used on that token
> alone. An own-key token created with the sealed opening is not excepted: its key stays under the rule, and its
> wallet checks openings as on a shared-key token. On that token a
> wallet, client library, binding, CLI, service, auditor tool or disclosure prover applies that key to ciphertexts
> read from chain state although only the token's verifier admitted them. Whoever can make that verifier sign (the
> verifier, its successor after `pqzSetVerifier`, or who compromises it) can recover the key from the key holder's
> public reactions, and everyone observing the chain learns it. The loss is the confidentiality, past and future
> and across key versions, of every amount encrypted to that key in that token: the holder's balance and credits,
> hence what its counterparties paid it; for the token's auditor key, every audited amount of every holder of that
> token. Rotating the key does not end the exposure. A holder accepts it by registering a key for that token; the
> record is never deleted, so the acceptance is for the token, not for one verifier; the token's auditor has no such
> choice once named. Still forbidden on these tokens too: returning or signalling a decryption result to an outside
> source (RPC, indexer, peer), a bare-ciphertext decrypt entry, an oracle inside an MPC quorum. The registry PQZ
> key, the shared `OFFCHAIN` key and every Zether key are never exposed: they stay under the rule without exception,
> and no code path applies one of them to a ciphertext of an own-key token. KEM keys are outside the rule by the
> Change above; apart from that, a KEM key is never used as a PQZ key and no KEM secret is applied to a PQZ
> ciphertext.

### 9.2 CTR-PQZ-27 and T27 (the doc fix)

- CTR-PQZ-27 trust model, replace "honestly formed data stays confidential — the verifier sees only the statement
  and the proof, which are public, and decrypts nothing" by: "Confidentiality depends on the token's key class
  (K3-1). Shared-key token: a holder's keys are not exposed, provided its wallet follows the holder check (K3-7);
  incoming amounts are as private as the holder's opening KEM key of that chain. Own-key token with the sealed opening: as a shared-key token, with the key and the opening KEM key
  of that token only. Own-key token without it: whoever controls the token's verifier can
  recover a key of that token from its holder's public reactions, and every observer learns it; the loss is stated
  in ARCH-POS-13's Change; no other key is touched." The same correction in spec `2026-11-06-attested-verify.md`
  §2 and in the overview table row "Verification".
- T27, add: "**Key recovery (own-key tokens without the sealed opening only).** A false verdict can plant a crafted credit; the holder's next
  debit, or its absence, answers one question about its key of that token; the auditor's key of that token is
  exposed the same way and opens every audited amount. Accepted by the owner for class `offchain-token` with the opening off (ARCH-POS-13
  Change, with the loss as worded there). Controls: the per-token key (K3-2), registration per token as the
  holder's acceptance, the warning wallets show before it (the Change's loss sentence, word for word). Shared-key
  tokens: closed by K3-6 / K3-7; the control is the planted-probe test (§14)." And a new row: "**Auditor evasion on
  shared-key tokens.** A sender can append a credit whose `O_a` is junk to anyone: the auditor reports it
  `unreadable`, and an honest recipient's wallet refuses it (K3-7 step 9), so it is never spent. Only when the
  recipient's own rollover or debit takes such an entry unmarked (`unreadable, taken`) have both wallets been
  modified; that names both UAs."
- Also Changes on CTR-PQZ-04 (split randomness is the rule on class 2), -08 (public rollover on class 1 and 3 only),
  -14 (one disclosure kind on class 2; amount, not receipt), -19 (`seed_leg`), -23 / -34 (blob tail, `memoHash` on
  class 2), -24 (the auditor's outcomes on class 2), -26 (op 7 not on class 2), -30 (scoped key reads), CTR-UA-42 (scoped records with
  the opening KEM key; CTR-UA-32 itself is unchanged), CLI-SGN-49 (K3-2),
  `integration.md` pqz-offchain-checks, `clients/app.md` (the two warnings), `docs/node/job-api.md`.

## 10. Residuals

1. **KEM.** Settled by ruling 3 (§9.1 first Change).
2. **Class 2 rests on a wallet rule.** A wallet that decrypts a class-2 credit with `s` is exposed as today, on the
   shared key, across every shared-key token of that chain.
3. **Incoming class-2 amounts are as private as the opening KEM key** (review S-8; ruling 10). That key is derived
   from the wallet seed per chain and per class-2 key version, lives beside the PQZ seed and never in chat software.
   Whoever gets its secret reads, from state and for all time, every amount paid to that key version on that chain;
   no PQZ key is involved. Rotating the class-2 key rotates it for new credits only. Wallets say so.
4. **Auditor evasion needs two modified wallets** and shows as `unreadable, taken`; a bare `unreadable` credit accuses
   nobody but its sender. Accepted as the guarantee (ruling 10; K3-7, T27 row).
5. A dishonest class-2 verifier can make holders pay gas to mark junk, and can already freeze the token.
6. Anyone may create a shared-key token and credit any class-2 holder with junk; a holder that never uses that
   token ignores it at no cost.
7. A wrong opening is the sender's loss (K3-6); a disclosure proves an amount, not receipt (§8).
8. **Holder liveness.** No keeper rolls for a class-2 holder: N pending entries cost ⌈N / ROLL_MAX⌉ signed
   rollovers before the holder spends past them (1,000 entries at `n2816-kmax65536` with an estimated 16: 63).
9. A scoped key record, once signed, can be submitted by anyone until its `validUntilBlock` (K3-3).

## 11. Interim and migration

Owner 2026-11-13: "Biện pháp tạm thời: Chưa cần sửa factory, vì kiểu gì cũng phải đổi." No interim factory refusal.
The factory change (K3-1), the CTR-PQZ-27 / T27 correction and the ARCH-POS-13 Changes all land in this spec's build
round. No migration: every chain is test-only; existing `OFFCHAIN` test tokens (registry key) are abandoned at the
next reset, which is also how the new ids arrive (K3-4b: by chain reset only, until mainnet 22776). Until then T-01
stays open on them and is listed as such. The superseded code path (an `OFFCHAIN` token reading the registry key)
moves to `legacy/` in the build round: backup, not delete.

## 12. Cost [estimate, unmeasured]

State gas at ≈ 1,539 per stored byte (`pqz-leg-proof-option.md`); "today" = an `OFFCHAIN` op 1 with the auditor, about
8 M of regular gas and calldata over its blob. Sets in the order `n2048-kmax1024` / `n2304-kmax4096` /
`n2560-kmax16384` / `n2816-kmax65536`. No block limit or gas price is assumed; inclusion needs regular + state gas
within the chain's limit (EIP-8037).

| Op | Class 1 | Class 2, and class 3 with the opening on | Class 3, opening off |
|---|---|---|---|
| op 1, auditor off | as measured today | ≈ 44 / 52 / 61 / 70 M (today + `P(u_f)` 16.5 / 20.4 / 24.6 / 29.3 M + one opening 2.55 M + ≈ 0.6 M calldata) | ≈ 25 / 29 / 33 / 38 M (today's `OFFCHAIN`) |
| op 1, auditor on | as today | ≈ 47 / 55 / 63 / 73 M (second opening + 2.55 M) | as above + `P(v_a)` |
| op 7 | as today | unsupported (K3-5) | as today |
| burn, refresh, unshield | as today | as today's `OFFCHAIN` | as today's `OFFCHAIN` |
| shield | as today | as today | as today |
| rollover | public, as today | signed: today + one UA signature check (68 k with the ML-DSA precompile; up to ≈ 2.5 M in Solidity) + ≈ 5 k per skip mark | public, as today |
| key record + stored `R_REG` proof | once per UA: 84.7 / 91.4 / 98.1 / 106.4 M measured (`accounts.md` gas-ua8) | class 2 once per UA per chain, class 3 with the opening **per (holder, token)**: ≈ 73 / 80 / 87 / 95 M (key 25.2 / 28.4 / 31.5 / 34.7 M + the opening KEM key 1,601 B ≈ 2.5 M + `storePqzPop` 45.6 / 49.1 / 52.6 / 57.5 M measured) | ≈ 71 / 78 / 84 / 92 M (no opening KEM key) **per (holder, token)** |

The registration row is larger than the ≈ 20 M first quoted for it: the proof bytes are stored too (CTR-PQZ-30),
and the owner ruled that they stay ("Lưu"), so the figure stands.
Holder work per credit on an opening token: one decapsulation, one encryption, one or two encapsulations.

Not in the table, to be measured: the larger `R_TXS` proof in calldata (two more witness vectors); the auditor-off
row starts from today's with-auditor figure (about 0.15 M too high). **What a chain must admit** is regular + state
gas of the largest single transaction (EIP-8037): op 1 up to ≈ 73 M, a proof store 57.5 M, a key store 34.7 M
[estimate]. The measuring step outputs "minimum admitted transaction per set and op", and the node refuses by name
(`TX_EXCEEDS_CHAIN_LIMIT`) what the connected chain cannot include instead of sending it.

**Size.** The opening option adds one flag and no second code path: the token branches on "opening on", and
class 3 only selects the scope. The registry gains one static call and one check. Baseline: `NormalPqzRegulatedTokenQ` 33,342 B, about 440 B under its 33,780 B notice line; the other `Q`
modules 28.7–31.4 KB; `PqzTransferLib` 24,731 B; ceiling 64 KiB. The changes (class switch on key reads, skip bit in
`_window` / `_total`, the signed rollover in three forms, opening checks, blob tail, `u_f`) reach every PQZ form and
will pass the notice line. Rule for the build: put bodies in the linked libraries first (`PqzStateLib`,
`PqzTransferLib`; `LinkClosure` release pins move), measure, and **stop and report sizes to the owner before any
module split or size lever**. `size-baseline.json` moves only with the reason. `UARegistry` / `UARegistryLib` grow by
the scoped records: measured in the same report. `OpenFactory` gains one config check.

## 13. Byte formats that move (all in one round)

| Where | What |
|---|---|
| `pqz-core/stmt` | `PQZL_SPLIT_ID` + label per set and the moved `PQZL_ID` and `PQZH_ID` (`set.toml`, `gen_set.py`, `PqzSet.sol`, generated headers, self-test and probe constants); `R_TXS` body layout and decoder bounds; which ops each id accepts; T-36: the disclosure `kind` low byte tied to the form; statement lengths under the two PQZL ids never collide (pinned) |
| `pqz-core/pqzl` (Rust production, C oracle) | relation `R_TXS` (prover, verifier, wasm32, generic and specialised verifiers); transcript absorbs `u_f` |
| `pqz-core/nethermind` | the precompile rebuilt for the moved `PQZL_ID` (class 1); deployed by chain reset only |
| `pqz-core/ffi` | `seed_leg`, `Enc-expand` from a seed as a public entry, the opening coins, `opening::seal` / `open_and_check` (K3-7 as one function with one outcome, the auditor's roles too), no bare class-2 decrypt; T-09 opaque error; selftest |
| `pqzh` | no class-2 form (PQZL only on `OFFCHAIN`); T-35: one-byte role tags in `ligero` `merkle.rs` / `transcript.rs`; `PQZH_ID` moves; inside the full gate |
| EVM | `ConfidentialConfig.pqzOwnKey` and `pqzOpening` (`TokenConfig` encoding moves for every kind); `PqzTransferArgs` + `bytes uFrom` + two `PqzOpening` (its typehash moves for every class); `ownTag` over `u_f` with the opening on; `PqzRollOver` typehash with `entriesHash`; op blob tail; pending slot bit 63 behind one accessor, `pqzSkipped`; `rollSeq`; `RECEIVER_X` / `AUDITOR` refused with the opening on; registry scoped records, `UAPqzScopedKeyRecord` (with `validUntilBlock`, `openKemHash`), the class-2 record's `openKem`, `PURPOSE_PQZ_SCOPED_KEY`; interface ids of `IPqzToken`, `IUARegistry` |
| `clients/clientkeys` (reference) | K3-2 seeds, the opening KEM derivation K3-6b, scoped record builders, opening seal / check, `memoHash` class 2, `PqzRollOver`, `checkPqzDebit` per class |
| `clients/ua-rs`, then `ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart`, `ua-dart-frb` | the same, each reading the same vector rows; `ua-rs` signs every kind |
| `scaas-pqz-verifier` | statement rebuild under `PQZL_SPLIT_ID`; key duties (CTR-PQZ-30) per scope; verdict vectors |
| `scaas-node` | `guard.rs`, `CALL_TABLE`, `typed.rs` equal to `mtxSelectors` / `_uaAllowed` both directions (`mtxRollOverSigned` on both paths, `setPqzScopedKey`, `storePqzScopedPop`); job JSON named fields `opening_to` / `opening_auditor` `{mlkem_ct, x25519_eph, sealed_seed}`, `u_from`, `skip: [u64]`, `entries_hash` (length ≤ `ROLL_MAX`, bounded decode), `owner_sig`; a public rollover job for an opening token is refused by name (`ROLLOVER_SIGNED_ONLY`), no keeper rollover there; key class read from `pqzVerifyConfig()`; note for operators on the job shape |
| `smartcontracts/vectors/` (generated, never edited) | every statement and proof row under the moved ids (all forms, all sets); `statement_disclose.json` for T-36; `pqz/<set>/statement_transfer.json` and `proof_pqzl.json` split rows; `enc.json` rows from `seed_leg`; `negative.json` (§14); `typed_ops.json` (moved and new typehashes, `release` tag); `pq_kat.json` (`pqzSeeds` per class, `openKemSeed` rows, opening KAT from `seed_leg` for both roles, `memoHash` class 2, `entriesHash`); scoped record digests; verdict vectors |

## 14. Tests and mutants that must exist

Each negative has its positive control next to it and changes one thing.

1. **The planted probe (triage §3.3) with the opening on.** Fake verdict, leg `(u*, v*)` with one large coefficient, on top
   of an honest encryption and alone; with a junk opening, and with a valid KEM ciphertext sealing a wrong seed. The
   wallet (`clientkeys`, `ua-rs`) skips it in every variant, the test asserts the PQZ secret was never applied (a
   counting key handle), the signed rollover marks it, the next debit proves and lands. Positive control: the same
   flow with an honest credit is accepted and spent. The whole item runs twice: on a class-2 token and on a class-3 token with
   the opening on. Second control: the same probe on a class-3 token **without** the opening is decrypted
   (documents the accepted exposure) and on the old registry-key form cannot be created.
2. Holder check, one mutant per step of K3-7: the opening key of another key version or chain, flipped `mlkemCt` bit, flipped `x25519Eph` bit, flipped tag, `aad` of another
   token / UA / ciphertext, seed of another leg, `u` off by one coefficient, `v` off by one `e2`, digit 16, norm over
   the bound. All give the identical outcome value.
3. Opening binding: a relayer swaps `openingTo` → `AuthRejected` / `PqzVerdictMismatch`; openings with the opening off →
   `BadPayload`; missing or short with the opening on; a class-2 record without `openKem` or with a wrong length or scheme → refused; a class-3 record with `openKem` for an opening-off token, or without it for an opening-on token → `UAPqzOpenKem`; `pqzOpening = false` with `pqzOwnKey = false`, or either flag on `PRECOMPILE` → `PqzVerifyConfigInvalid`; an opening sealed to the recipient's chat KEM key → skipped by the wallet.
4. Signed rollover: positive on both relay paths with fee 0; replay (same `rollSeq`), wrong signer, expired, another
   token or chain, stale `rolled` after an un-roll; public `mtxRollOver` with the opening on refused; signed form on class
   1 / 3 refused; `skip` unsorted, out of range, TRIVIAL, too long; mark-only `n = 0`.
5. Skip semantics, invariants: a marked slot adds zero in `_total` and in a rollover, before and after an un-roll;
   marks are never cleared; no slot or blob is deleted; `T` rebuilt from state equals the wallet's `T`
   (`PqzVer` handler extended with marks and classes).
6. Classes: every key read uses the token's scope, with the registry and the scoped record at **different version
   numbers** so a wrong read cannot pass by accident, and one independent scope mutant per site (review C-3): credit,
   shield, op 7 leg (class 3), debit at `current`, debit of a stale version (migration, refresh), the auditor's key,
   `prepareAcc`, both disclosure reads; an opening token never reads the registry key;
   the same key bytes in two classes or two tokens → `UAKeyInUse`; a class-3 record for token A is not usable on
   token B; `pqzOwnKey` against the mode → `PqzVerifyConfigInvalid`; the `R_REG` message of one scope fails for
   another; a class-2 or class-3 record signed for another `chainUid` is refused; a class-2 record for an `msig` →
   `UAPqzHolder`; an `msig` with an opening KEM key is credited on a class-3 opening token, and one without it is
   refused there; and the same `msig` is credited on a class-1 and a class-3 token; versions
   rotate per scope.
7. Derivation KAT: the three classes, two tokens, two chains, versions 0 and 1 give pairwise distinct seeds; class 1
   rows unchanged.
8. `pqz-stmt`: each id refuses the other's transfer form; the retired ids are refused (`Reject::ProofSystemId`), a
   proof made under the old `PQZL_ID` fails under the new one (T-35), a disclosure whose `kind` low byte does not
   match its form is refused with its positive control (T-36); `R_TXS` cheating fixtures (`u_f` not from `(r_f, e1_f)`,
   `v_f` under the leg's `r`, swapped `u` / `u_f`); the same class of check in C, Rust, wasm32, generic and
   specialised verifiers.
9. Clients: digest reproduction with a non-zero unbound `relayer` / `feeRecipient`; every `ua-*` reads the same rows.
10. Node: allow-lists both directions; `HEX_ARGS_REFUSED` on old forms; depth and length bounds on the new fields.
11. Gas pins (old → new), `ROLL_MAX` fit for the signed form, size gate, layout and typehash pins.
    Mutant on the flag (K3-1b): each use of `pqzOpening` replaced by "class 2" or by "own key" turns a named test on
    a class-3 opening-on or opening-off token red (signed rollover, op 7 refusal, opening lengths, the id at `init`,
    the disclosure kinds, `uFrom`).
12. Mutation run on `PqzCore` / `PqzStateLib` / the registry's scoped records; every surviving mutant explained.
13. **Auditor (S-1).** Honest proof + valid `O_t` + junk `O_a`: an honest recipient wallet skips, the auditor tool
    reports `unreadable` and never decrypts. Valid `O_a` + junk `O_t`: recipient skips, auditor reports
    `recipient-unreadable`. `O_a` sealed with other coins than K3-6's (a valid opening, not byte-equal): recipient
    skips. Positive control: both good → accepted, `read`. A modified recipient wallet rolls or debits past an
    `unreadable` entry unmarked → the tool reports `unreadable, taken`; the same entry marked, or still pending →
    never `taken` (review C-4).
    `ownTag` (C-1): positive control, and a blob whose `u_f` alone differs is refused before the PQZ secret is loaded.
14. **Restore (S-2).** Mnemonic only → the opening KEM keys of class-2 versions 0 and 1 derived and equal to the
    stored records, every opening opens; two chains give two keys; `openKemSeed` KAT in every client.
15. **Content binding (S-3).** Same index, other blob → signed rollover and signed mark both `AuthRejected`; positive
    control; `entriesHash` over a TRIVIAL entry whose amount changed by a same-block merge → refused.
16. **Disclosure (S-4).** `SENDER_S` on a leg with a junk `O_t` verifies and `pqzSkipped` reports the mark after it
    (documents "amount, not receipt"); `SENDER_S` built by the recipient from `seed_leg` verifies (documents "no
    party"); `RECEIVER_X` / `AUDITOR` with the opening on → `OpUnsupported`.
17. **Records (S-5, S-6, S-8, S-14).** A scope's version 1 of another length refused, with its control; a scoped
    proof under `PQZL_SPLIT_ID` refused, under `PQZL_ID` accepted; an opening sealed to a
    stale class-2 version's key after a rotation fails the statement's key check; a scoped record after its `validUntilBlock` refused.
18. **Key handle (S-18.6).** The counting handle of item 1 also wraps the prover: a debit whose window holds an
    unaccepted, unmarked entry is refused before `s` is loaded; a class-1 or class-2 handle given a class-3
    ciphertext, and the reverse, is refused before arithmetic; positive controls.
19. **K3-7 differential.** `clientkeys` and `ua-rs` give the identical outcome on one shared corpus of mutated
    openings; a low-order X25519 point; an `mlkemCt` valid for another UA's key; the auditor's `sealedSeed` given to
    the recipient. Mutants on the check itself, each turning a named test red: norm check dropped, `d_i < 16` dropped,
    unpacked `u` compared instead of `P(u)`, `e2_t` used for the auditor, step 8 or step 9 dropped.
20. **Marks (S-11).** Mark → roll → debit at `p < rolled` → re-roll: `T` from state equals the wallet's; a mark on an
    index `< rolled` refused; the mask removed in `_window` → "roll over a marked slot after `ROLL_AGE`" goes red;
    the mask removed in `_trivial`; a bad entry at `rolled − 1` recovered by un-roll, then marked (S-10).
21. **Salt (S-9).** Two builds at one counter differ in salt, `u`, `u_f`; the same salt with another recipient gives
    another `seed_leg`; the wallet builder refuses `u_f == u`.
22. **Node.** A `mtxRollOverSigned` job with `skip` at the length and depth bounds; the public rollover job on a
    opening token → `ROLLOVER_SIGNED_ONLY`, zero sends; `AUDITOR_KEY_MISSING`; `TX_EXCEEDS_CHAIN_LIMIT`.

## 15. Build plan (in order; each step ends on its gate; agents stop at the branch)

1. **Docs first**: the rules of this spec into `docs/` with ids and `decisions.md` entries, status SPECIFIED; the
   §9 texts. Gate: `scripts/docs_check.py check`, `scripts/test_docs_check.py`.
2. **`pqz-core`**: `set.toml` labels (the split id, the moved `PQZL_ID` and `PQZH_ID`) → `gen_set.py --all`; T-35 and
   T-36; `stmt` (`R_TXS`, ids); `pqzl` Rust then the C oracle; `ffi` (seed_leg, opening, holder check, T-09); the
   Nethermind plugin; the 3w follow-ups (§15.1). **The core vectors are regenerated here, before the gate**
   (`ffi/vectors/run.sh` in its write mode, which also rebuilds the compiled-in self-test proofs; statements, proofs,
   `enc`, the opening and `openKemSeed` KATs): the gate's `vectors` and `ffi` steps read them and would fail on the
   retired ids. Gate: the **full gate at all four sets** (`PQZ_SET=<set> scripts/capped pqz-core/gate.sh`,
   resumable, read `runs/gate/last` first), since `stmt`, `pqzl` and `ffi/src` change; one gate for all ids.
3. **Registry**: scoped records, a new generation. Gate: the registry is a shared module, so every forge directory
   and the isolate runs of AGENTS.md (subset gates hid reds before).
4. **Token and factory**: the registry-key `OFFCHAIN` path moved to `legacy/` first (backup, not delete);
   `pqzOwnKey`, key switch, split statement and blob, openings, skip mark, signed rollover.
   Gate: `script/pqz/at-set.sh <set> test` at four sets (one work tree per run, restore `PqzSet.sol`), every forge
   directory, size gate. **Stop here with the size report if a notice line is passed.**
5. **Vectors, contract rows**: the rows that depend on contract formats (typehashes, `TokenConfig`, scoped record
   digests, `memoHash` and `ownTag` class 2, `entriesHash`, verdicts) with the generator. Gate: the generator's own
   check and the EVM vector tests. No other reader is checked yet.
6. **Clients**: `clientkeys`, then `ua-rs`, then the other `ua-*`. Gate: each client's suite on the shared rows, run
   when that client supports them.
7. **Verifier and node**. Gate: `cargo test`, `cargo clippy --all-targets -- -D warnings`,
   `cargo test --test e2e -- --ignored` (6 GB, alone), allow-list tests.
7b. **Integration on the final corpus**: every reader's vector check, every forge directory and the node e2e once
   more, against the vectors as they now stand.
7c. **On-chain matrix** (§15.2): the three classes and class 3 with the opening, on the local chain.
8. **Measure** (ask the owner before timing or gas runs): the §12 table at four sets, `ROLL_MAX` for the signed
   form; pins move old → new in the commit.
9. **Mutants and invariants** (§14.12), then reviews: Fable (design, security, crypto) beside Codex on the owner's
   word.
10. Status tags to BUILT only where code and tests exist. The new ids reach a chain by reset and redeploy only
    (K3-4b); the testnet stack is outside this repository and is reset by its controller, not by a build agent.

### 15.2 On-chain matrix (owner 2026-11-13, ruling 11)

Step 7c, on the local chain only (`script/onchain/matrix.sh local`; the testnet stack is not touched). A new group in
`script/onchain/groups.json` (proposed name `pqz-keys`, its script `PqzKeys.s.sol`, the client side in `pq.py`)
deploys four tokens and runs every row on each that applies. `coverage.py gen` must list every new external entry,
and `coverage.py table` must show each reached or carry a written reason in `notrun.json`: `setPqzScopedKey`,
`storePqzScopedPop`, the scoped views (`pqzScopedKeyOf` / `At` / `Latest`, `pqzScopedPopOf`, `pqzOpenKemAt`, the
per-scope holder list), `mtxRollOverSigned` in its three forms, `pqzSkipped`, the moved `mtxConfidentialTransfer*`
entries with `uFrom` and the openings, `pqzVerifyConfig()` with the two flags. Negatives go through
`coverage.py neg` with the expected named error.

| Row | Class 1 (`PRECOMPILE`) | Class 2 | Class 3, opening on | Class 3, opening off |
|---|---|---|---|---|
| Key registration and stored proof | registry key, as today | scoped record, scope 0, with `openKem` | scoped record, scope token, with `openKem` | scoped record, scope token, no `openKem` |
| Record negatives | — | without `openKem`; for an `msig` (`UAPqzHolder`); other `chainUid`; other key length at version 1; expired | `openKem` missing (`UAPqzOpenKem`); `msig` without it refused, with it accepted; other `chainUid`; record of another token | with `openKem` (`UAPqzOpenKem`); other `chainUid` |
| Shield, op 1 credit, debit, unshield | as today, proof on chain | split id, `uFrom`, openings | the same | as today's `OFFCHAIN` |
| Opening accepted by the wallet, credit spent | — | yes | yes | — |
| Planted bad credit (junk opening; valid KEM ciphertext, wrong seed; crafted `u*`) | cannot be created (proof) | skipped, marked, next debit lands | the same | decrypted: documents the accepted exposure |
| Auditor outcomes `read`, `recipient-unreadable`, `unreadable`, `unreadable, taken` | `read` only | all four | all four | `read` only (by decryption) |
| Rollover | public | signed, with `skip` and `entriesHash`; public form refused; stale `entriesHash`, replayed `rollSeq`, mark on a TRIVIAL entry refused; mark-only `n = 0`; relayed on both paths with fee 0 | the same | public; signed form refused |
| Op 7 | runs | `OpUnsupported` | `OpUnsupported` | runs |
| Disclosure | three kinds | `SENDER_S` only, from sender and from recipient; the other two refused | the same | three kinds, verdict form |
| Key rotation and migration to oneself | as today | scoped version 1, opening key rotates with it | the same, per token | scoped version 1 |
| Factory | — | `pqzOpening = false` refused | both flags set | either flag on `PRECOMPILE` refused |

Gate: the matrix green on the local chain at the committed set, `coverage.py` with no uncovered new entry, and the
run's note committed as a summary (no absolute paths; full output in git-ignored logs).

### 15.1 3w follow-ups done in this round (triage §6, Codex u5)

In step 2, on this round's branch (from `pqz-3w-fix`), not in the gate that is running now:

- **u5-2**: `pqz_kat.py` `check_proofs()` refuses a proof-system id that is not in the set's table (today an
  all-zero PQZH id passes with 0 errors); it must know the three new ids and refuse the retired ones.
- **u5-3**: `ligero_params.py --set` no longer crashes on bool constants, and its model takes `S_AUD` (it understates
  the audited M = 4 sizes today).
- **u5-4**: the codegen's extraction / upsilon asserts use the corrected inequalities (R0-C5; they pass on all 56
  headers, smallest margin about 4.65×); regenerate with the check.
- **u5-7**: `n2048-kmax1024` `SET.md` gains the dual-hybrid row beside uSVP (R0-C10).
- **u5-8**: `n2816-kmax65536` `SET.md` rewords the no-PQZH FFT exploration (R0-C13).

Recorded, not in this round: u5-5 and u5-6 (estimator maths, a Sage rerun).

## 16. Open questions for the owner

None. Every question was ruled on 2026-11-13 and is in §0 (rulings 3, 4, 6, 7, 9, 10).

- **Sizes** are a stop in the build, not a question yet: the build stops with measured sizes before any module split
  or size lever (§12).
- Two names remain controller proposals the owner may override: the labels `…/v6` (the moved `PQZL_ID`) and
  `…/split-v1` (`PQZL_SPLIT_ID`).
