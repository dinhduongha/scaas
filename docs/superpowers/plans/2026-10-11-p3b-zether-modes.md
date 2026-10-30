# P3b — Zether disclosure (`BUNDLE` | `COMPACT`) and auditor (`NONE` | `FULL` | `OPTIONAL`) fixed at initialization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The owner decisions of 2026-10-11 on classical Zether, as merged into the spec on `main` (`5b9c423`, the
`zetherTransferCompact` / `COMPACT` rename `de31eb1`, the per-entry storage table `e65ef59`): every `*_ZETHER` token
fixes at `initialize`, through `OpenFactory` and `ConfidentialConfig`, a **disclosure mode** `BUNDLE | COMPACT`
(CTR-ZTH-48) and an **auditor mode** `NONE | FULL | OPTIONAL` (CTR-ZTH-49); the transfer entries follow the mode
(CTR-ZTH-38: `zetherTransfer` = the mode's default, `zetherTransferCompact` = commit-reveal everywhere,
`zetherTransferNoBundle` and `zetherTransferSingle` BUNDLE-only, `zetherTransferBundle` removed); the per-transfer
auditor opt-out exists only under `OPTIONAL` (CTR-ZTH-42); the sender randomness `s` is derived from the seed and a
fresh 16-byte **salt** published with the transfer (CTR-ZTH-30, closes G1/R7); commit-reveal stores a **sender memo**
next to the commitment, so the sender opens its own transfer from its seed and contract storage alone (CTR-ZTH-50).
Both kinds (`NORMAL_ZETHER`, `WRAPPED_ZETHER`); relaying and the envelope binding unchanged except the entry
selectors. PQ Zether (CTR-PQZ-19/23/24) stays spec only.

Owner decision (2026-10-11, Vietnamese, as given): "Ở Zether/PqZether: 1. Chấp nhận hai kiểu: commit-reveal và bundle.
2. Chấp nhận có Auditor hoặc không có Auditor (full hoặc không). Cấu hình khi khởi tạo contract. Nên có lẽ phải thêm
implement." The coordinator's later messages of the same day refined it, and the docs agent wrote the result into the
spec; this plan implements the spec as merged (the readings in between — HASH-only COMMIT tokens, a dropped no-bundle
entry, a two-value auditor mode, a `40·M` memo of `Y` points — are superseded and not built).

**Architecture:** One implementation per kind serves every mode pair (CTR-ZTH-48: COMPACT is a subset of BUNDLE).
`ZetherStorage` gains `disclosureMode` and `auditorMode` in the verifier's slot (no field offset moves) and a `memos`
mapping at its end; `ZetherLib.init` validates them (`BadDisclosureMode`, `BadAuditorMode`). The transfer payloads
carry `salt(16)` right after `be32(provedSendCounter)`, and a commit-reveal payload ends with the memo
(`17 + 40·M` bytes, length checked, content never read); the statement header grows from 416 to **480 bytes** (word
13 = the salt, word 14 = `keccak256(memo)` or 0) under a new proof system id `…/n64-n64/v2`; the stored record is
`R = salt ‖ B_1 ‖ … ‖ B_M`; commit-reveal stores `keccak256(R)` in one slot and the memo next to it, emits
`TransferBundles(entryRef, R)`, and `transferEntry` returns `keccak256(R) ‖ memo`. `_auditorPoint` applies the auditor
mode before the verifier (`AuditorForbidden` / `AuditorRequired` / `AuditorLegsMixed`); `prepareSingle` /
`prepareMulti` refuse the BUNDLE-only entries on a COMPACT token (`TransferEntryDisabled(1)`), so `ZetherStatements`
gives clients the same errors. `ZetherDisclosure` reads `R` with its salt and tells a commitment record from `R` by its
length. The account registry stores `encodedY` (`keyOf(ua)`), so a sender rebuilds `B_j` from the memo's recipient
UAs. The Rust prover follows byte for byte (header, payloads, `derive_s` v2 with the salt re-drawn on `s = 0`, the memo,
`disclosureMode` / `auditorMode` in a request, the default entry `zetherTransfer`) and gains `recoverTransfer`: from
storage (`sendCounter`, `transferEntry`, the registry's keys, `auditorKey`), from a stored record (amounts by BSGS) or
from calldata, to `s`, amounts, `R`, `SENDER_S` and every `SENDER_CP` opening.

**Tech Stack:** Solidity 0.8.37 (`osaka`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0, forge-std 1.16.2; Rust
`clients/zether-prover` (arkworks 0.5, `hkdf` 0.12, `cargo test`, `wasm-smoke.sh`); `scaas-node` e2e (anvil) as the
deploy check.

**Spec (normative, on `main`):** `docs/contracts/zether.md` CTR-ZTH-30, -38, -42, -48, -49, -50, §7 (480-byte header),
§9/§11 payloads, §14 "who can open what", §19 gas, §21 interface; `docs/contracts/pq-zero-knowledge.md` CTR-PQZ-19, -23, -24
(spec only, no code); `docs/contracts/token-wrappers.md` CTR-TOK-25 (`ConfidentialConfig`);
`docs/research/zether-disclosure.md` (status block: R3 by FULL, G1/R7 by the salt, §7 by the memo, R6 open);
`docs/decisions.md` (CTR-ZTH-48/49/50 entries); TODO.md P3b row; HANDOFF.md.

**Base:** `main` at `a21a17c` (P3 merged `dc9d219`, P4 merged `ebacaac`, spec merge `5b9c423`, renames `de31eb1`,
`e65ef59`; 1001 forge tests, 53 prover tests). P4 is merged, so there is nothing to rebase onto: the executor branches
from `main`; if `main` moved, rebase and rerun Task 2 Step 4 (the only files P3b shares with P4 are
`MetaTokenBase.sol` (another hunk), `ZetherDeploy.t.sol` (another hunk), `size-baseline.json`, TODO.md, HANDOFF.md).
Every block below was applied to a scratch worktree from `main` and run green: forge **1018** (1001 + 17: the new
`ZetherModes.t.sol`, 8 tests × 2 kinds, and `test_relayedUnderTheModes`), prover `cargo test` **59** (53 + 6) and
`wasm-smoke.sh` 16 checks, size gate 0 errors, docs checkers 0 errors, e2e 4/4 and 1/1, mutation probe 37/37 killed.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge in `smartcontracts/evm` of the worktree
  `.claude/worktrees/p3b` (branch `p3b-zether-modes` from `main`; `lib/` is not tracked: `mkdir lib`, copy
  `smartcontracts/evm/lib/forge-std` into it and symlink `lib/openzeppelin-contracts →
  /home/ha/work/blockchain/openzeppelin-contracts`, as in the main checkout).
  Heavy commands only through `scripts/capped`, one at a time. `/usr/bin/grep`; in a worktree bare `git` is blocked:
  `/usr/bin/git`. Rust: `CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/clients/zether-prover/target` (and
  `…/scaas-node/target` for the node) reuse the main checkout's caches; `wasm-smoke.sh` builds in the crate's own
  `target/` (it reads the wasm from there), so run it without `CARGO_TARGET_DIR`.
- **Zether is UNAUDITED — NOT FOR PRODUCTION FUNDS**; dev chains only (`ZetherSafety`: 31337, 1337).
- All chains are test chains: no migration of P3 tokens, records or vectors (a P3 proof fails under the new header and
  proof system id; every vector is regenerated).
- Tests: compute anything that makes an external call (`stm.*Statement`, `prover.ciphertexts`, `_rebuild`,
  `tok.envelopeBinding(m)`) **before** `vm.expectRevert`, or the call consumes the cheatcode (hit once in the
  validation: `_rebuild` inside `_vta`'s arguments).
- Solidity string literals stay ASCII (`‖`, `·` need `unicode"…"`; hit twice in the validation).
- `via_ir` stays off: the payload offsets are named constants (`S_PTS = 80`, `M_PTS = 112`), the header takes the
  `Prepared` struct, and the single record is built inline, all to stay under the stack limit (each was hit once).
- Code size is not a concern (owner: wait for Glamsterdam); the ratchet baseline is raised to the measured sizes.
- Owner rules: superseded code goes to `legacy/` only for whole contracts (the removed `zetherTransferBundle` is one
  function: deleted, not backed up; TODO's "to legacy" wording is corrected in Task 4); component docs say "controller
  ruling, pending the owner", never a ruling letter.
- Commit trailer (both lines): `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01GBLbPyQuG5HXALewwBZ7Bb`. Never `git add claude-code-api.txt`.

## Review Focus

- **The modes are fixed and enforced on every path.** `init` refuses unknown values and a key that does not match the
  auditor mode (`test_invalidModesRefused`, both kinds); the token, `ZetherStatements` and the relayed path refuse the
  BUNDLE-only entries on COMPACT (`test_compact*`, `test_relayedUnderTheModes`), the opt-out on FULL and an auditor leg
  on NONE (`test_*Full`, `test_*None`), and keep OPTIONAL as built (`test_*Optional`, `test_auditorLegsMixedReverts`).
- **The salt and the memo are signed.** Header words 13/14 carry them; a salt or memo changed after proving, a memo of
  the wrong length, or a memo on a non-commit form is refused (`test_memoAndSaltBoundByTheProof`,
  `test_statementHeaderCarriesChainUid`, S3 `_checkMemo`); Rust and Solidity build the same 480 bytes (S3 vectors).
- **Storage per form** (CTR-ZTH-38): `R` (salt first) for `zetherTransfer` on BUNDLE and for the single format;
  `keccak256(R)` + memo for commit-reveal (one slot + the memo, `TransferBundles(R)`); nothing for no-bundle
  (`_bundleForms`, `_compactForms`, `_hashForm`, `test_disclosureHashMode` reads slots 9/10/11).
- **Disclosure on every stored form**, all four openings, both kinds; commit-reveal opens with the event's `R` and with
  the `R` the sender rebuilds (`_openAll`, `_hashForm`, `test_s3Disclosure*`).
- **Sender recovery from storage alone** (CTR-ZTH-50): `recover_from_storage_alone` (both curves, M = 3, a tampered
  memo, another chain, a missing key), `recover_an_opt_out` (the flag), `recover_a_record_and_calldata` (BSGS),
  `two_builds_at_one_counter_differ`, `s_inputs` (chainUid, salt, token, counter, sender, key; nothing else).
- **Nothing else moves:** the envelope binding, the allowlist shape (same slots, `zetherTransferCompact` in place of
  `zetherTransferBundle`), roll-over, shield/unshield, the reserve invariant (`ZetherInvariant.t`), the public kinds
  (`test_publicKinds_refuseEveryConfField` with the two new fields).

## Rulings (docs vs code) and defaults taken

- **M1 — What is built.** The merged spec, not the intermediate readings: `disclosureMode ∈ {BUNDLE = 0, COMPACT = 1}`,
  `auditorMode ∈ {NONE = 0, FULL = 1, OPTIONAL = 2}` (zero = the defaults: a config without the fields is a BUNDLE token
  without auditor); entries `zetherTransfer` (BUNDLE: stores `R`; COMPACT: commit-reveal), `zetherTransferCompact`
  (commit-reveal on both), `zetherTransferNoBundle` (BUNDLE only), `zetherTransferSingle` (BUNDLE only; the spec marks
  this a controller ruling); `zetherTransferBundle` is removed.
- **M2 — The config fields are `uint8`** (`ConfidentialConfig.disclosureMode`, `.auditorMode`, appended): an unknown
  value is a typed refusal (`BadDisclosureMode(uint8)`, `BadAuditorMode(uint8)`) instead of an ABI enum-decode failure
  without data; storage and the views use `ZetherTypes.DisclosureMode` / `ZetherTypes.AuditorMode` (ABI `uint8`, as
  zether.md §21). `BadAuditorMode` also covers FULL/OPTIONAL without a key and NONE with one. `MetaTokenBase._requireUnused`
  refuses both fields on the public kinds (`ConfigFieldForOtherKind(4)`).
- **M3 — Storage.** Both modes share the verifier's slot (address + 2 × `uint8`), so `entries` / `entryHashes` keep
  slots 9/10 of `scaas.zether` (the HASH test reads them); `memos` is slot 11. `transferEntry` returns `R`, or
  `keccak256(R) ‖ memo`, or nothing (spec §14); there is no separate memo view.
- **M4 — The record carries the salt.** `R = salt ‖ B_1 ‖ … ‖ B_M` is stored (BUNDLE, single), hashed (commit-reveal)
  and emitted (`TransferBundles`), as CTR-ZTH-38's definition and CTR-ZTH-30 ("the stored record `R`, the commitment")
  say; the `e65ef59` table cell "`keccak256(B_1 ‖ … ‖ B_M)`" is read as shorthand for `keccak256(R)` (open question).
  Without the salt in `R`, a full record would not let the sender rebuild `s` from storage (§14 table).
- **M5 — Entries and forms.** The stored form stays the statement's `opTag` (`…/HASH`, `…/BUNDLE`, `…/NONE` strings
  unchanged, so a relayer cannot switch it): `zetherTransfer` takes `ZetherLib.defaultMode()` (BUNDLE, or HASH on
  COMPACT), `zetherTransferCompact` HASH, `zetherTransferNoBundle` NONE. `ZetherTypes.TransferMode` keeps its member
  names (the stored form); the prover's JSON form names are `bundle | compact | none`. The allowlist keeps its shape
  (8 / 14 entries, `zetherTransferCompact` where `zetherTransferBundle` was).
- **M6 — Where the mode checks run.** `TransferEntryDisabled(disclosureMode)` first thing in `prepareSingle` /
  `prepareMulti` (before any registry call), so `ZetherStatements` raises it too; the memo length (`17 + 40·M` on HASH,
  none otherwise) right after the counters; the auditor mode in `_auditorPoint` before the verifier.
- **M7 — `AuditorForbidden`** is the NONE refusal of a `C_aud ≠ O` (the spec names only `AuditorRequired`; built P3 let
  the verifier reject it as `ProofRejected`): a typed error before the proof, killable by the probe.
- **M8 — Payload and header layout.** Salt at payload bytes 64..80 (unaligned; `be32(M)` then sits at 80..112, the
  points at 80 (single) / 112 (multi)); the memo after the legs on commit-reveal only; header word 13 =
  `uint128(salt)` (16 zero bytes ‖ salt), word 14 = `keccak256(memo)` or 0; burn: both 0. The verifier's `HEADER = 480`,
  `FEE_AT`/`AMOUNT_AT` unchanged. Proof system ids `scaas/zether/sigma-bullets/{bn254,bls12-381}/n64-n64/v2` (and
  `/v2/multi`): the spec asks for "a new `proofSystemId`" without the string (label: controller ruling); the NUMS
  generators do not depend on it, so only the `proofSystemId` fields of the S2 KAT files and `kat.py` change.
- **M9 — Events unchanged.** The spec's events carry no salt: the salt is in `R`, `TransferBundles` and the calldata,
  so `ZetherTransfer` / `ZetherTransferMulti` keep their P3 signatures.
- **M10 — `ZetherDisclosure`.** The caller passes `R` (salt first); a token record whose length is not `16 + 4P·M` is a
  commitment (`49 + 40·M` is odd, `16 + 4P·M` even) checked against `keccak256(R)`; leg `j` is read at `16 + 4P·j`.
- **M11 — The registry keeps the key.** `UniversalAccountRegistry` stores `encodedY` and exposes `keyOf(ua)`: the
  CTR-ZTH-50 recovery takes `Y_tj` "from the registry", and the built registry kept only `keyLength` (`UA =
  keccak256(Y)` cannot be inverted). Cost at registration: +67 k (bn254, 3 slots) / +112 k (BLS12-381, 5 slots), `test_registerGas`.
- **M12 — The prover.** `seed_zether` (the IKM of CTR-ZTH-30/50) is the account's confidential key `x` (an `{x}` key has
  no wallet seed; `x` is a function of it); `s = HKDF-SHA256(x, "ZTX/s/v2" ‖ chainUid ‖ token ‖ fromUA ‖
  be32(sendCounter) ‖ salt, L = 64) mod r`, the salt re-drawn on `s = 0`; memo key / keystream / flags as CTR-ZTH-50.
  Requests take `disclosureMode` (`bundle` default | `compact`) and `auditorMode` (`none` | `full` | `optional`,
  checked against `yAud` when given); `proveTransferMulti` defaults to the token's default form and always emits
  `zetherTransfer` for it (`zetherTransferCompact` only for commit-reveal asked on a BUNDLE token); `proveTransfer`
  refuses a COMPACT token. Outputs gain `salt`, `memo` (multi), `record` (single); `bundles` is `R`.
  `recoverTransfer` is new.
- **M13 — No contract-side `SENDER_S` rebuild.** `ZetherDisclosure` stays a checker of the record the caller supplies;
  the sender's rebuild is `recoverTransfer` off chain (zether-disclosure.md §7 alternative), and the memo makes it
  storage-only.
- **M14 — Size.** The ratchet baseline is raised to the measured sizes: `NormalToken` 23,042 (+56: the two
  conf fields in `_requireUnused`), `WrappedToken` 30,142 (+98), `NormalZetherToken` 31,162 (+495),
  `WrappedZetherToken` 40,706 (+317).
- **M15 — Docs.** The spec rules are already written: the docs task flips them to built (drops the "Transitional
  (BUILT, P3)" notes), writes the measured gas and sizes into §19, records the two old proof-system-id strings in
  `history/dropped-artifacts.tsv` (checker C7), and updates TODO / HANDOFF; pages over budget net ≤ 0 lines.

## Open questions (not blocking)

- **M4:** `R` with the salt as the committed record vs the `e65ef59` table's `keccak256(B_1 ‖ … ‖ B_M)` (one of the two
  spec sentences changes; the code follows the definition).
- **BLS12-381 M = 8 commit-reveal with the auditor no longer fits one transaction** under EIP-7825 (≈ 17.03 M with
  intrinsic and calldata; the memo added ≈ 274 k): cap `M` at 7 for BLS commit-reveal in clients, or accept.
- **M11:** storing `Y` in the built registry (a dev-chain contract the UA registry replaces) vs leaving `Y_tj` to the
  client's contacts; the UA registry (accounts.md CTR-UA-*) should expose the key either way.
- **M7 / M2 names:** `AuditorForbidden`, `BadDisclosureMode(uint8)`, `BadAuditorMode(uint8)`,
  `TransferEntryDisabled(uint8)` (the spec's names are a controller ruling, pending the owner).
- **M8:** the `…/v2` proof-system-id label; the salt at payload offset 64 makes the multi-recipient `be32(M)` unaligned
  with the old layout (no client depends on it yet).
- **M10:** telling a commitment record from `R` by length is sound for these two shapes only; a third stored shape
  needs a tag byte.
- **`zetherTransferSingle` on COMPACT** reverts (spec: controller ruling, pending the owner); the alternative is a
  single-format commit-reveal.
- **M12:** `seed_zether` = `x` (the alternative is the wallet seed under an R33 path, which an `{x}` key cannot serve).
- **R6** (archiving `TransferBundles` for receiver and auditor under commit-reveal) stays open; a BUNDLE token's
  no-bundle transfer is openable only from calldata (by design).

---
### Task 1: The prover — salt, 480-byte header, sender memo, modes in a request, `recoverTransfer`; vectors regenerated

**Model:** Sonnet, effort high (byte layout shared with the contracts; the vectors are the cross-check).

**Files:**
- Modify: `clients/zether-prover/src/{zether.rs, api.rs, abi.rs, curve.rs, envelope.rs, vectors.rs, bin/zether-cli.rs}`,
  `tests/{zether_proofs.rs, envelope_disclosure.rs, read_balance.rs}`, `vectors/s2/generators_{bn254,bls12381}.json`
  (`proofSystemId` only), `vectors/*.json` (regenerated)
- Create: `clients/zether-prover/tests/recover.rs`

**Interfaces:** `Header { …, salt: [u8; 16], memo_hash: [u8; 32] }` (words 13/14, `HEADER_LEN = 480`);
`derive_s(x, h, from_ua, salt)`; `memo_len(m) = 17 + 40·m`; `seal_memo(x, h, from_ua, salt, auditor, legs)`,
`open_memo(x, h, from_ua, memo) -> (salt, auditor, Vec<MemoLeg>)`; `TransferStatement::{payload(), record()}`,
`MultiTransferStatement::{payload(memo), bundles()}` (`bundles()` = `R`); `MultiTransferWitness.memo`;
`api::recover_transfer_json` (command `recoverTransfer`); request fields `disclosureMode`, `auditorMode`; JSON form
names `bundle | compact | none`; proof system labels `…/n64-n64/v2`.

- [ ] **Step 1: the source and test changes** (apply the diff):

```diff
diff --git a/clients/zether-prover/src/abi.rs b/clients/zether-prover/src/abi.rs
index 9bb1dfe..4687dc8 100644
--- a/clients/zether-prover/src/abi.rs
+++ b/clients/zether-prover/src/abi.rs
@@ -40,6 +40,11 @@ pub fn encode(toks: &[Tok]) -> Vec<u8> {
     head
 }
 
+/// The `uint64` in the 32-byte word at `at`, `None` when out of range or wider.
+pub fn word_u64(b: &[u8], at: usize) -> Option<u64> {
+    word_at(b, at)
+}
+
 fn word_at(b: &[u8], at: usize) -> Option<u64> {
     let w = b.get(at..at.checked_add(32)?)?;
     if w[..24].iter().any(|&x| x != 0) {
diff --git a/clients/zether-prover/src/api.rs b/clients/zether-prover/src/api.rs
index 70450ea..5fe1efa 100644
--- a/clients/zether-prover/src/api.rs
+++ b/clients/zether-prover/src/api.rs
@@ -13,7 +13,10 @@ use zeroize::Zeroizing;
 
 use crate::abi::{self, Tok};
 use crate::bulletproofs::Gens;
-use crate::curve::{decode_point, decode_scalar, encode_point, encode_scalar, Bls12381, Bn254, Fr, ZCurve, G};
+use crate::curve::{
+    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, ua_of, Bls12381, Bn254,
+    Fr, ZCurve, G,
+};
 use crate::elgamal::{
     cached_table, cached_table_bits, check_balance, check_ram, encrypt, mem_available, BsgsParams, Ciphertext,
 };
@@ -130,7 +133,8 @@ fn ct_json<C: ZCurve>(c: &Ciphertext<C>) -> Value {
 }
 
 /// `envelopeBinding` (relayed), or `unwrapBinding` (a direct `zetherUnshieldUnwrap`, burns only), or direct.
-/// Both at once, or `unwrapBinding` on a transfer, is refused: the token never builds such a statement.
+/// Both at once, or `unwrapBinding` on a transfer, is refused: the token never builds such a statement. The memo word
+/// is the prove functions' (0 on a burn).
 fn header(v: &Value, amount: u64, recipient: [u8; 20], burn: bool) -> R<Header> {
     let has = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
     let binding = match (has("envelopeBinding"), has("unwrapBinding")) {
@@ -151,6 +155,8 @@ fn header(v: &Value, amount: u64, recipient: [u8; 20], burn: bool) -> R<Header>
         beneficiary: opt_fixed(v, "beneficiary")?,
         amount,
         recipient,
+        salt: [0; 16],
+        memo_hash: [0; 32],
     })
 }
 
@@ -167,19 +173,53 @@ fn sc<C: ZCurve>(s: &Fr<C>) -> String {
 /// `zetherTransferSingle` — a direct call has no outer fee; relayed, the same bytes are the envelope's `data`.
 const TRANSFER_SINGLE: &str = "zetherTransferSingle(bytes,bytes,bytes,bytes32)";
 
-/// `zetherTransfer` (HASH), `zetherTransferBundle`, `zetherTransferNoBundle` (CTR-ZTH-38).
-fn transfer_multi_sig(mode: TransferMode) -> &'static str {
+fn opt_str<'a>(v: &'a Value, k: &str) -> R<Option<&'a str>> {
+    match v.get(k).filter(|x| !x.is_null()) {
+        None => Ok(None),
+        Some(x) => x.as_str().map(Some).ok_or_else(|| format!("`{k}` must be a string")),
+    }
+}
+
+/// The token's `disclosureMode()` (CTR-ZTH-48): `"bundle"` (the default) or `"compact"` (commit-reveal only).
+fn compact_token(v: &Value) -> R<bool> {
+    match opt_str(v, "disclosureMode")? {
+        None | Some("bundle") => Ok(false),
+        Some("compact") => Ok(true),
+        _ => Err("`disclosureMode` must be \"bundle\" or \"compact\"".into()),
+    }
+}
+
+/// `yAud` (absent or null: the auditor left out, every `C_aud = O`), checked against the token's `auditorMode()`
+/// when the request names it (CTR-ZTH-42): `"full"` needs it, `"none"` refuses it, `"optional"` takes either; the
+/// token would revert `AuditorRequired` / `AuditorForbidden` after the proving work.
+fn y_aud<C: ZCurve>(v: &Value) -> R<G<C>> {
+    let y = if v.get("yAud").is_some_and(|x| !x.is_null()) { point::<C>(v, "yAud")? } else { G::<C>::zero() };
+    match (opt_str(v, "auditorMode")?, y.is_zero()) {
+        (None | Some("optional"), _) | (Some("full"), false) | (Some("none"), true) => Ok(y),
+        (Some("full"), true) => Err("a FULL auditor token needs `yAud` (AuditorRequired)".into()),
+        (Some("none"), false) => Err("a token without auditor takes no `yAud` (AuditorForbidden)".into()),
+        _ => Err("`auditorMode` must be \"none\", \"full\" or \"optional\"".into()),
+    }
+}
+
+/// The entry of a stored form (CTR-ZTH-38): `zetherTransfer` is the token's default (BUNDLE, or commit-reveal on a
+/// COMPACT token), `zetherTransferCompact` commit-reveal on every token, `zetherTransferNoBundle` NONE.
+fn transfer_multi_sig(mode: TransferMode, compact: bool) -> &'static str {
     match mode {
-        TransferMode::Hash => "zetherTransfer(bytes,bytes,bytes,bytes32)",
-        TransferMode::Bundle => "zetherTransferBundle(bytes,bytes,bytes,bytes32)",
+        TransferMode::Bundle => "zetherTransfer(bytes,bytes,bytes,bytes32)",
+        TransferMode::Hash if compact => "zetherTransfer(bytes,bytes,bytes,bytes32)",
+        TransferMode::Hash => "zetherTransferCompact(bytes,bytes,bytes,bytes32)",
         TransferMode::NoBundle => "zetherTransferNoBundle(bytes,bytes,bytes,bytes32)",
     }
 }
 
 pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
+    if compact_token(v)? {
+        return Err("a COMPACT token refuses the single format (TransferEntryDisabled)".into());
+    }
     let k = key::<C>(v)?;
     let h = header(v, 0, [0; 20], false)?;
-    let y_aud = if v.get("yAud").is_some_and(|x| !x.is_null()) { point::<C>(v, "yAud")? } else { G::<C>::zero() };
+    let y_aud = y_aud::<C>(v)?;
     let (st, p, w) = zether::prove_transfer(
         gens,
         &k,
@@ -200,6 +240,8 @@ pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v
         "payload": hx(&payload),
         "authDigest": hx(&zether::auth_digest(&stmt)),
         "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), h.send_counter)),
+        "salt": hx(&st.header.salt),
+        "record": hx(&st.record()),
         "directCalldata": hx(&envelope::transfer_call(TRANSFER_SINGLE, &payload, &proof, &[], &h.beneficiary)),
     });
     if include_witness(v) {
@@ -209,29 +251,35 @@ pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v
     Ok(out)
 }
 
-/// `recipients`: `[{"yTo", "amount"}, …]` (decoys with amount 0), `mode`: `hash` (default) | `bundle` | `none`.
-/// `yAud` absent or null leaves the auditor out (statement `Y_a = O`, every `C_aud = O`): required on a token
-/// without auditor, the sender's choice on one with it (Z12); the same holds for `proveTransfer`.
-/// Relayed like the single format (`envelopeBinding`, CTR-ZTH-34).
+/// `recipients`: `[{"yTo", "amount"}, …]` (decoys with amount 0); `mode`, the stored form: `bundle` | `compact` |
+/// `none`, by default the token's (`disclosureMode` `"bundle"`, the default: `bundle`; `"compact"`: `compact`, the only
+/// form it takes), so the calldata calls `zetherTransfer` unless a gas-saving form is asked for. `yAud` absent or null leaves the auditor out (statement `Y_a = O`, every `C_aud = O`): required on a token
+/// without auditor, refused on a `FULL` one, the sender's choice on an `OPTIONAL` one (`auditorMode`, checked when
+/// given); the same holds for `proveTransfer`. Relayed like the single format (`envelopeBinding`, CTR-ZTH-34).
 pub fn prove_transfer_multi_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
     let k = key::<C>(v)?;
     let h = header(v, 0, [0; 20], false)?;
+    let compact = compact_token(v)?;
     let mode = match v.get("mode").filter(|x| !x.is_null()) {
-        None => TransferMode::Hash,
-        Some(m) => m.as_str().and_then(TransferMode::from_name).ok_or("`mode` must be \"hash\", \"bundle\" or \"none\"")?,
+        None if compact => TransferMode::Hash,
+        None => TransferMode::Bundle,
+        Some(m) => m.as_str().and_then(TransferMode::from_name).ok_or("`mode` must be \"bundle\", \"compact\" or \"none\"")?,
     };
+    if compact && mode != TransferMode::Hash {
+        return Err("a COMPACT token takes commit-reveal only (TransferEntryDisabled)".into());
+    }
     let recipients = get(v, "recipients")?
         .as_array()
         .ok_or("`recipients` must be an array")?
         .iter()
         .map(|r| Ok((point::<C>(r, "yTo")?, num(r, "amount")?)))
         .collect::<R<Vec<_>>>()?;
-    let y_aud = if v.get("yAud").is_some_and(|x| !x.is_null()) { point::<C>(v, "yAud")? } else { G::<C>::zero() };
+    let y_aud = y_aud::<C>(v)?;
     let (st, p, w) = zether::prove_transfer_multi(
         gens, &k, h.clone(), mode, &recipients, y_aud, ct::<C>(v, "acc")?, num(v, "balance")?, rng,
     )
     .map_err(e)?;
-    let (stmt, proof, payload) = (st.encode(), p.encode(), st.payload());
+    let (stmt, proof, payload) = (st.encode(), p.encode(), st.payload(&w.memo));
     let mut out = json!({
         "curve": C::NAME,
         "mode": mode.name(),
@@ -241,7 +289,9 @@ pub fn prove_transfer_multi_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens
         "bundles": hx(&st.bundles()),
         "authDigest": hx(&zether::auth_digest(&stmt)),
         "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), h.send_counter)),
-        "directCalldata": hx(&envelope::transfer_call(transfer_multi_sig(mode), &payload, &proof, &[], &h.beneficiary)),
+        "salt": hx(&st.header.salt),
+        "memo": hx(&w.memo),
+        "directCalldata": hx(&envelope::transfer_call(transfer_multi_sig(mode, compact), &payload, &proof, &[], &h.beneficiary)),
     });
     if include_witness(v) {
         out["witness"] = json!({"x": sc::<C>(&w.x), "s": sc::<C>(&w.s), "b": sc::<C>(&w.b), "bPrime": sc::<C>(&w.b_prime),
@@ -277,6 +327,160 @@ pub fn prove_burn_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &V
     Ok(out)
 }
 
+/// Recovery of one of the sender's transfers from its key and chain data only (CTR-ZTH-30, CTR-ZTH-50; disclosure
+/// review G1/R7): no amount, recipient or log remembered. The source is either
+/// - `entry` = `transferEntry(entryRef)` with `sendCounter` (the sender walks `0 … sendCounter(fromUA) − 1`): the record
+///   `R` (BUNDLE, single) or `keccak256(R) ‖ memo` (commit-reveal). A memo gives the amounts and the recipient UAs;
+///   `keys` (their `encodedY`, `registry.keyOf(toUA)`) and, when its flag says so, `yAud` (`auditorKey()`) rebuild `R`,
+///   which must hash to the commitment;
+/// - `payload`, the transfer's calldata argument (any entry, the no-bundle one included).
+/// Without a memo the amounts come by BSGS on `C_out_j − [s]Y_tj` (`tableBits`, `boundBits` as `decrypt`). Returns `s`,
+/// `salt`, `entryRef`, the legs (`toUA`, `yTo`, `amount`), `bundles` (= `R`, the argument of a disclosure on a
+/// commitment), `commitment` (`keccak256(R)`), `auditorIncluded`, and the sender's openings `senderS` (every leg) and
+/// `senderCp[j]` (leg `j`). Needs `chainId`, `chainUid`, `token`.
+pub fn recover_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(v: &Value, rng: &mut Rn) -> R<Value> {
+    let k = key::<C>(v)?;
+    let p = point_len::<C>();
+    let has = |f: &str| v.get(f).is_some_and(|x| !x.is_null());
+    let (send_counter, rec, memo, commitment) = if has("payload") {
+        let b = bytes(v, "payload")?;
+        let (rec, memo) = payload_record::<C>(&b)?;
+        (abi::word_u64(&b, 32).ok_or("payload: sendCounter")?, Some(rec), memo, None)
+    } else {
+        let e = bytes(v, "entry")?;
+        if e.len() > 16 && (e.len() - 16) % (4 * p) == 0 {
+            (num(v, "sendCounter")?, Some(e), None, None)
+        } else if e.len() >= 32 + zether::memo_len(1) {
+            let c: [u8; 32] = e[..32].try_into().unwrap();
+            (num(v, "sendCounter")?, None, Some(e[32..].to_vec()), Some(c))
+        } else {
+            return Err("`entry`: neither a record nor a commitment with its memo (an unknown or no-bundle entry)".into());
+        }
+    };
+    let h = Header {
+        chain_id: num(v, "chainId")?,
+        chain_uid: fixed(v, "chainUid")?,
+        token: fixed(v, "token")?,
+        binding: Binding::Direct,
+        send_counter,
+        acc_seq: 0,
+        fee: 0,
+        beneficiary: [0; 32],
+        amount: 0,
+        recipient: [0; 20],
+        salt: [0; 16],
+        memo_hash: [0; 32],
+    };
+    let salt: [u8; 16] = rec.as_ref().or(memo.as_ref()).ok_or("no record")?[..16].try_into().unwrap();
+    let s = zether::derive_s::<C>(&k.x, &h, &k.ua(), &salt);
+    let g = generator::<C>();
+    let d_out = g * s;
+    let y_aud = |need: bool| -> R<G<C>> { if need { point::<C>(v, "yAud") } else { Ok(G::<C>::zero()) } };
+    let (legs, y_a): (Vec<(G<C>, u64)>, G<C>) = match &memo {
+        Some(m) => {
+            let (_, aud, ml) = zether::open_memo::<C>(&k.x, &h, &k.ua(), m).map_err(e)?;
+            let keys = v.get("keys").and_then(Value::as_array).ok_or("`keys`: the recipients' encodedY (registry.keyOf)")?;
+            let keys = keys
+                .iter()
+                .map(|y| {
+                    let s = y.as_str().ok_or("`keys` must be hex strings")?;
+                    let pt = decode_point::<C>(&hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(e)?).map_err(e)?;
+                    Ok((ua_of::<C>(&pt), pt))
+                })
+                .collect::<R<std::collections::HashMap<_, _>>>()?;
+            let legs = ml
+                .iter()
+                .map(|l| keys.get(&l.to_ua).map(|y| (*y, l.amount)).ok_or_else(|| format!("`keys`: no key for {}", hx(&l.to_ua))))
+                .collect::<R<Vec<_>>>()?;
+            (legs, y_aud(aud)?)
+        }
+        None => {
+            let r = rec.as_ref().unwrap();
+            let bsgs = BsgsParams::for_target();
+            let bp = BsgsParams::new(opt_bits(v, "tableBits", bsgs.table_bits)?, opt_bits(v, "boundBits", bsgs.bound_bits)?)
+                .map_err(e)?;
+            if !cfg!(target_arch = "wasm32") && cached_table_bits::<C>() != Some(bp.table_bits) {
+                check_ram(bp.table_bits, mem_available()).map_err(e)?;
+            }
+            let pt = |o: usize| decode_point::<C>(&r[o..o + p]).map_err(e);
+            let mut legs = Vec::new();
+            let mut aud = false;
+            for o in (16..r.len()).step_by(4 * p) {
+                let (y, c_out, d, c_aud) = (pt(o)?, pt(o + p)?, pt(o + 2 * p)?, pt(o + 3 * p)?);
+                if d != d_out {
+                    return Err("D_out != [s]G: not this key's transfer (or another chainUid / token)".into());
+                }
+                let a = cached_table::<C>(bp.table_bits).map_err(e)?.decrypt(&Ciphertext { c: c_out, d: y }, &s, bp.bound_bits);
+                legs.push((y, a.map_err(e)?));
+                aud |= !c_aud.is_zero();
+            }
+            (legs, y_aud(aud)?)
+        }
+    };
+    let c_aud = |a: u64| if y_a.is_zero() { G::<C>::zero() } else { g * Fr::<C>::from(a) + y_a * s };
+    let mut bundles = salt.to_vec();
+    for (y, a) in &legs {
+        for pt in [*y, g * Fr::<C>::from(*a) + *y * s, d_out, c_aud(*a)] {
+            bundles.extend(encode_point::<C>(&pt));
+        }
+    }
+    if rec.as_ref().is_some_and(|r| *r != bundles) || commitment.is_some_and(|c| c != keccak256(&bundles)) {
+        return Err("the rebuilt record misses the chain's (another key, chainUid, token or counter, a tampered memo, or a wrong `yAud`/`keys`)".into());
+    }
+    let entry_ref = schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), send_counter);
+    let mut cps = Vec::new();
+    for (j, (y, a)) in legs.iter().enumerate() {
+        let entry = schnorr::Entry {
+            chain_id: h.chain_id,
+            chain_uid: h.chain_uid,
+            token: h.token,
+            entry_ref,
+            index: j as u64,
+            y_t: *y,
+            c_out: g * Fr::<C>::from(*a) + *y * s,
+            d_out,
+            y_a,
+            c_aud: c_aud(*a),
+        };
+        cps.push(hx(&schnorr::open_sender_cp(&entry, *a, &s, rng).map_err(e)?));
+    }
+    let legs: Vec<Value> = legs
+        .iter()
+        .map(|(y, a)| json!({"toUA": hx(&ua_of::<C>(y)), "yTo": hx(&encode_point::<C>(y)), "amount": a.to_string()}))
+        .collect();
+    Ok(json!({
+        "s": sc::<C>(&s), "salt": hx(&salt), "sendCounter": send_counter, "entryRef": hx(&entry_ref), "legs": legs,
+        "auditorIncluded": !y_a.is_zero(), "bundles": hx(&bundles), "commitment": hx(&keccak256(&bundles)),
+        "senderS": hx(&schnorr::open_sender::<C>(&s)), "senderCp": cps,
+    }))
+}
+
+/// `R = salt ‖ B_1 ‖ … ‖ B_M` as a transfer payload carries it, and its memo (commit-reveal) if any.
+fn payload_record<C: ZCurve>(b: &[u8]) -> R<(Vec<u8>, Option<Vec<u8>>)> {
+    let p = point_len::<C>();
+    let salt = b.get(64..80).ok_or("payload: too short")?;
+    let cut = |o: usize| &b[o..o + p];
+    let mut r = salt.to_vec();
+    if b.len() == 80 + 6 * p {
+        for o in [80 + p, 80 + 2 * p, 80 + 3 * p, 80 + 5 * p] {
+            r.extend_from_slice(cut(o));
+        }
+        return Ok((r, None));
+    }
+    let m = abi::word_u64(b, 80).ok_or("payload: M")? as usize;
+    let end = 112 + 3 * p * (1 + m);
+    if m == 0 || m > zether::MAX_RECIPIENTS || (b.len() != end && b.len() != end + zether::memo_len(m)) {
+        return Err("payload: neither format".into());
+    }
+    for j in 0..m {
+        let o = 112 + 3 * p * (j + 1);
+        for at in [o, o + p, 112 + p, o + 2 * p] {
+            r.extend_from_slice(cut(at));
+        }
+    }
+    Ok((r, (b.len() > end).then(|| b[end..].to_vec())))
+}
+
 fn verify_multi_json<C: ZCurve>(gens: &Gens<C>, v: &Value) -> R<Value> {
     let (stmt, proof) = (bytes(v, "statement")?, bytes(v, "proof")?);
     let r = MultiTransferStatement::<C>::decode(&stmt).and_then(|st| {
@@ -362,6 +566,7 @@ fn by_curve<C: ZCurve>(cmd: &str, v: &Value, rng: &mut OsRng) -> R<Value> {
         "proveTransfer" => prove_transfer_json::<C, _>(&gens(), v, rng),
         "proveTransferMulti" => prove_transfer_multi_json::<C, _>(&gens(), v, rng),
         "proveBurn" => prove_burn_json::<C, _>(&gens(), v, rng),
+        "recoverTransfer" => recover_transfer_json::<C, _>(v, rng),
         "verifyTransfer" => verify_json::<C>(&gens(), v, false),
         "verifyTransferMulti" => verify_multi_json::<C>(&gens(), v),
         "verifyBurn" => verify_json::<C>(&gens(), v, true),
diff --git a/clients/zether-prover/src/bin/zether-cli.rs b/clients/zether-prover/src/bin/zether-cli.rs
index 2bbff3c..15580a2 100644
--- a/clients/zether-prover/src/bin/zether-cli.rs
+++ b/clients/zether-prover/src/bin/zether-cli.rs
@@ -3,8 +3,8 @@
 //!   zether-cli vectors <dir>      write the deterministic vector files
 //!   zether-cli <command>          JSON request on stdin, JSON result on stdout
 //!
-//! Commands: keygen, encrypt, decrypt, proveTransfer, verifyTransfer, proveBurn, verifyBurn,
-//! pop, shieldCalldata, envelope (see `zether_prover::api`).
+//! Commands: keygen, encrypt, decrypt, proveTransfer, verifyTransfer, proveTransferMulti, verifyTransferMulti,
+//! proveBurn, verifyBurn, recoverTransfer, pop, shieldCalldata, envelope (see `zether_prover::api`).
 
 use std::io::Read;
 use std::process::ExitCode;
diff --git a/clients/zether-prover/src/curve.rs b/clients/zether-prover/src/curve.rs
index a92f539..2ae0736 100644
--- a/clients/zether-prover/src/curve.rs
+++ b/clients/zether-prover/src/curve.rs
@@ -46,7 +46,7 @@ impl ZCurve for ark_bn254::g1::Config {
     const COORD_LEN: usize = 32;
     const KEYGEN_SALT: &'static [u8] = b"SCAAS-ZETHER-BN254-v1";
     const PATH_ROOT: u32 = 254;
-    const PROOF_SYSTEM_LABEL: &'static [u8] = b"scaas/zether/sigma-bullets/bn254/n64-n64/v1";
+    const PROOF_SYSTEM_LABEL: &'static [u8] = b"scaas/zether/sigma-bullets/bn254/n64-n64/v2";
 
     fn bsgs_slot() -> &'static BsgsSlot<Self> {
         static T: BsgsSlot<ark_bn254::g1::Config> = BsgsSlot::new(None);
@@ -78,7 +78,7 @@ impl ZCurve for ark_bls12_381::g1::Config {
     const COORD_LEN: usize = 64;
     const KEYGEN_SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";
     const PATH_ROOT: u32 = 12381;
-    const PROOF_SYSTEM_LABEL: &'static [u8] = b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v1";
+    const PROOF_SYSTEM_LABEL: &'static [u8] = b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v2";
 
     fn bsgs_slot() -> &'static BsgsSlot<Self> {
         static T: BsgsSlot<ark_bls12_381::g1::Config> = BsgsSlot::new(None);
diff --git a/clients/zether-prover/src/envelope.rs b/clients/zether-prover/src/envelope.rs
index 6e46dc3..31c021c 100644
--- a/clients/zether-prover/src/envelope.rs
+++ b/clients/zether-prover/src/envelope.rs
@@ -119,7 +119,7 @@ pub fn selector(sig: &str) -> [u8; 4] {
     keccak256(sig.as_bytes())[..4].try_into().unwrap()
 }
 
-/// Calldata of a confidential transfer (`zetherTransfer`, `…Bundle`, `…NoBundle`, `…Single`, all
+/// Calldata of a confidential transfer (`zetherTransfer`, `…Compact`, `…NoBundle`, `…Single`, all
 /// `(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary)`): the direct call and, unchanged, the envelope's `data`.
 pub fn transfer_call(sig: &str, payload: &[u8], proof: &[u8], auth_sig: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
     let mut d = selector(sig).to_vec();
diff --git a/clients/zether-prover/src/vectors.rs b/clients/zether-prover/src/vectors.rs
index edabb53..f0c2944 100644
--- a/clients/zether-prover/src/vectors.rs
+++ b/clients/zether-prover/src/vectors.rs
@@ -161,12 +161,13 @@ fn per_curve<C: ZCurve>(files: &mut Vec<(String, Value)>, transcripts: &mut Vec<
         }),
     ));
 
-    // multi-recipient: one real recipient and two decoys (amount 0), auditor on, inner fee, HASH.
+    // multi-recipient: one real recipient and two decoys (amount 0), auditor on, inner fee, commit-reveal
+    // (named: a BUNDLE token's default is `bundle`).
     let (d1, d2) = (conf::<C>(2), conf::<C>(3));
     let req = with(json!({
         "recipients": [{"yTo": hx(&d1.encoded_y()), "amount": 0}, {"yTo": hx(&to.encoded_y()), "amount": AMOUNT},
                        {"yTo": hx(&d2.encoded_y()), "amount": 0}],
-        "yAud": hx(&aud.encoded_y()), "fee": 300, "beneficiary": hx(&[0x22; 32]),
+        "yAud": hx(&aud.encoded_y()), "fee": 300, "beneficiary": hx(&[0x22; 32]), "mode": "compact"
     }));
     let mut mv = prove_transfer_multi_json::<C, _>(&gens, &req, &mut rng).unwrap();
     mv["expect"] = json!(true);
diff --git a/clients/zether-prover/src/zether.rs b/clients/zether-prover/src/zether.rs
index 903f389..fc5b906 100644
--- a/clients/zether-prover/src/zether.rs
+++ b/clients/zether-prover/src/zether.rs
@@ -3,13 +3,14 @@
 //! (public amount, §5). The verifier here mirrors the Solidity verifier for tests/vectors.
 
 use ark_ff::{PrimeField, Zero};
+use hkdf::Hkdf;
 use zeroize::Zeroize;
 use rand_core::{CryptoRng, RngCore};
-use sha2::{Digest, Sha512};
+use sha2::Sha256;
 
 use crate::bulletproofs::{self as bp, msm, nz_challenge, Gens, RangeProof};
 use crate::curve::{
-    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, proof_system_id,
+    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, proof_system_id, ua_of,
     proof_system_id_multi, Fr, ZCurve, G,
 };
 use crate::elgamal::Ciphertext;
@@ -22,7 +23,7 @@ use crate::ZError;
 /// soundness comes from `MAX_TOTAL_SHIELDED` instead (zether-design ruling RS-NV64-1).
 pub const N_V: usize = 64;
 pub const N_B: usize = 64;
-pub const HEADER_LEN: usize = 416;
+pub const HEADER_LEN: usize = 480;
 /// `MAX_TOTAL_SHIELDED` (§1): ceiling of `maxDecryptableShielded`.
 pub const MAX_TOTAL_SHIELDED: u64 = 1 << 54;
 
@@ -51,7 +52,8 @@ pub enum Binding {
     Unwrap([u8; 32]),
 }
 
-/// The 416-byte statement header (zether.md §7): `chainUid` is word 3 (CTR-ZTH-36).
+/// The 480-byte statement header (zether.md §7): `chainUid` is word 3 (CTR-ZTH-36), the build salt word 13
+/// (`16 zero bytes ‖ salt`, CTR-ZTH-30), `memoHash` word 14 (`keccak256(memo)` on commit-reveal, CTR-ZTH-50; else 0).
 #[derive(Clone, Debug, PartialEq, Eq)]
 pub struct Header {
     pub chain_id: u64,
@@ -68,6 +70,16 @@ pub struct Header {
     pub amount: u64,
     /// Burn only (transfer: zero address).
     pub recipient: [u8; 20],
+    /// Transfer only (burn: 0): 16 fresh random bytes per build, an input of [`derive_s`]; the prove functions draw it.
+    pub salt: [u8; 16],
+    /// Commit-reveal only (else 0): `keccak256` of the sender memo the payload ends with ([`seal_memo`]).
+    pub memo_hash: [u8; 32],
+}
+
+fn salt_word(salt: &[u8; 16]) -> [u8; 32] {
+    let mut o = [0u8; 32];
+    o[16..].copy_from_slice(salt);
+    o
 }
 
 fn be32_u64(v: u64) -> [u8; 32] {
@@ -107,7 +119,7 @@ impl Header {
             Binding::Relayed(b) => (keccak256(b"ZTX_V1_RELAYED"), b),
             Binding::Unwrap(b) => (keccak256(b"ZTX_V1_DIRECT"), b),
         };
-        let words: [[u8; 32]; 13] = [
+        let words: [[u8; 32]; 15] = [
             op_tag,
             psid,
             be32_u64(self.chain_id),
@@ -121,6 +133,8 @@ impl Header {
             self.beneficiary,
             be32_u64(self.amount),
             be32_addr(&self.recipient),
+            salt_word(&self.salt),
+            self.memo_hash,
         ];
         words.concat()
     }
@@ -148,6 +162,9 @@ impl Header {
         } else {
             return Err(ZError::BadStatement("bindingTag"));
         };
+        if w(13)[..16].iter().any(|&b| b != 0) {
+            return Err(ZError::BadStatement("salt word has dirty high bytes"));
+        }
         Ok(Self {
             chain_id: u64_of(w(2))?,
             chain_uid: w(3).try_into().unwrap(),
@@ -159,6 +176,8 @@ impl Header {
             beneficiary: w(10).try_into().unwrap(),
             amount: u64_of(w(11))?,
             recipient: addr_of(w(12))?,
+            salt: w(13)[16..].try_into().unwrap(),
+            memo_hash: w(14).try_into().unwrap(),
         })
     }
 
@@ -276,14 +295,22 @@ impl<C: ZCurve> TransferStatement<C> {
         Ok(st)
     }
 
-    /// `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud` (§9).
+    /// `be32(accSeq) ‖ be32(sendCounter) ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud` (§9).
     pub fn payload(&self) -> Vec<u8> {
         let mut b = be32_u64(self.header.acc_seq).to_vec();
         b.extend(be32_u64(self.header.send_counter));
+        b.extend_from_slice(&self.header.salt);
         b.extend(cat::<C>(&[&self.y_f, &self.y_t, &self.c_out, &self.d_out, &self.c_deb, &self.c_aud]));
         b
     }
 
+    /// The record the token stores, `R = salt ‖ Y_t ‖ C_out ‖ D_out ‖ C_aud` (CTR-ZTH-38).
+    pub fn record(&self) -> Vec<u8> {
+        let mut b = self.header.salt.to_vec();
+        b.extend(cat::<C>(&[&self.y_t, &self.c_out, &self.d_out, &self.c_aud]));
+        b
+    }
+
     pub fn auditor_on(&self) -> bool {
         !self.y_a.is_zero()
     }
@@ -506,20 +533,109 @@ pub fn verify_transfer<C: ZCurve>(
     Ok(tr)
 }
 
-/// Transfer randomness `s` as a PRF of the conf key (zether-design §5 "PRF `s` phía client"):
-/// the sender can re-derive `s` for a `SENDER_S` disclosure, re-proving the same transfer gives
-/// the same ciphertexts, and two different transfers never share `s` (which would leak `v1 - v2`).
-pub fn derive_s<C: ZCurve>(x: &Fr<C>, h: &Header, y_to: &G<C>, v: u64) -> Fr<C> {
-    let mut d = Sha512::new();
-    d.update(b"SCAAS-ZETHER-S-V1");
-    d.update(encode_scalar::<C>(x));
-    d.update(h.chain_id.to_be_bytes());
-    d.update(h.chain_uid);
-    d.update(h.token);
-    d.update(h.send_counter.to_be_bytes());
-    d.update(encode_point::<C>(y_to));
-    d.update(v.to_be_bytes());
-    Fr::<C>::from_be_bytes_mod_order(&d.finalize())
+/// `info = tag ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt` (CTR-ZTH-30, CTR-ZTH-50).
+fn sender_info(tag: &[u8], h: &Header, from_ua: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
+    [tag, &h.chain_uid, &h.token, from_ua, &be32_u64(h.send_counter), salt].concat()
+}
+
+/// `HKDF-SHA256(IKM = seed_zether, salt = ∅, info, L)`; `seed_zether` is the R33 conf key `x` (the per-account Zether
+/// secret the wallet seed determines; controller ruling, pending the owner).
+fn sender_hkdf<C: ZCurve>(x: &Fr<C>, info: &[u8], out: &mut [u8]) {
+    let mut ikm = encode_scalar::<C>(x);
+    Hkdf::<Sha256>::new(None, &ikm).expand(info, out).expect("L <= 255*32");
+    ikm.zeroize();
+}
+
+/// The transfer randomness `s` (CTR-ZTH-30): `OKM mod r`, `OKM = HKDF-SHA256(seed_zether, "ZTX/s/v2" ‖ chainUid ‖ token
+/// ‖ fromUA ‖ be32(sendCounter) ‖ salt, L = 64)`. The salt (16 fresh random bytes per build, re-drawn on `s = 0`) and
+/// `sendCounter` are on chain, so the sender rebuilds `s` from its key and chain data alone, remembers no amount, and two
+/// builds at one counter (a retry after a failed transaction) never share `s` (which would leak `v1 − v2` through
+/// `C_aud`). One `s` per transfer, every recipient (owner Z3).
+pub fn derive_s<C: ZCurve>(x: &Fr<C>, h: &Header, from_ua: &[u8; 32], salt: &[u8; 16]) -> Fr<C> {
+    let mut okm = [0u8; 64];
+    sender_hkdf::<C>(x, &sender_info(b"ZTX/s/v2", h, from_ua, salt), &mut okm);
+    let s = Fr::<C>::from_be_bytes_mod_order(&okm);
+    okm.zeroize();
+    s
+}
+
+/// A fresh salt whose `s` is not 0 (CTR-ZTH-30: re-drawn on 0), and that `s`.
+fn draw_salt<C: ZCurve, R: RngCore>(x: &Fr<C>, h: &Header, from_ua: &[u8; 32], rng: &mut R) -> ([u8; 16], Fr<C>) {
+    loop {
+        let mut salt = [0u8; 16];
+        rng.fill_bytes(&mut salt);
+        let s = derive_s::<C>(x, h, from_ua, &salt);
+        if !s.is_zero() {
+            return (salt, s);
+        }
+    }
+}
+
+/// Length of the sender memo of `m` legs: `17 + 40·m` (CTR-ZTH-50).
+pub fn memo_len(m: usize) -> usize {
+    17 + 40 * m
+}
+
+/// The memo keystream: `key = HKDF-SHA256(seed_zether, "ZTX/memo/v1" ‖ chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖
+/// salt)` (32 B), `ks = HKDF-Expand-SHA256(key, "ZTX/memo/ks/v1", L)`.
+fn memo_stream<C: ZCurve>(x: &Fr<C>, h: &Header, from_ua: &[u8; 32], salt: &[u8; 16], len: usize) -> Vec<u8> {
+    let mut key = [0u8; 32];
+    sender_hkdf::<C>(x, &sender_info(b"ZTX/memo/v1", h, from_ua, salt), &mut key);
+    let mut ks = vec![0u8; len];
+    Hkdf::<Sha256>::from_prk(&key).expect("32-byte PRK").expand(b"ZTX/memo/ks/v1", &mut ks).expect("L <= 255*32");
+    key.zeroize();
+    ks
+}
+
+/// The sender memo (CTR-ZTH-50): `salt ‖ ((flags ‖ (be8(v_j) ‖ toUA_j)_j) XOR ks)`, `flags` bit0 = the auditor included.
+/// The token stores it next to the commitment; with it, the key and `sendCounter` the sender rebuilds every bundle from
+/// storage alone (the recipients' keys from the registry). No MAC: a wrong key or a tampered memo rebuilds a record that
+/// misses the commitment.
+pub fn seal_memo<C: ZCurve>(
+    x: &Fr<C>,
+    h: &Header,
+    from_ua: &[u8; 32],
+    salt: &[u8; 16],
+    auditor: bool,
+    legs: &[(G<C>, u64)],
+) -> Vec<u8> {
+    let mut plain = vec![u8::from(auditor)];
+    for (y, v) in legs {
+        plain.extend_from_slice(&v.to_be_bytes());
+        plain.extend_from_slice(&ua_of::<C>(y));
+    }
+    let ks = memo_stream::<C>(x, h, from_ua, salt, plain.len());
+    let mut memo = salt.to_vec();
+    memo.extend(plain.iter().zip(&ks).map(|(a, b)| a ^ b));
+    memo
+}
+
+/// One leg of an opened memo.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct MemoLeg {
+    pub amount: u64,
+    pub to_ua: [u8; 32],
+}
+
+/// [`seal_memo`] backwards: the salt, the auditor flag and every `(v_j, toUA_j)`; `h` needs `chainUid`, `token` and
+/// `sendCounter`. A wrong key gives garbage, caught by the commitment.
+pub fn open_memo<C: ZCurve>(
+    x: &Fr<C>,
+    h: &Header,
+    from_ua: &[u8; 32],
+    memo: &[u8],
+) -> Result<([u8; 16], bool, Vec<MemoLeg>), ZError> {
+    if memo.len() < memo_len(1) || (memo.len() - 17) % 40 != 0 {
+        return Err(ZError::BadStatement("memo length"));
+    }
+    let salt: [u8; 16] = memo[..16].try_into().unwrap();
+    let ks = memo_stream::<C>(x, h, from_ua, &salt, memo.len() - 16);
+    let plain: Vec<u8> = memo[16..].iter().zip(&ks).map(|(a, b)| a ^ b).collect();
+    let legs = plain[1..]
+        .chunks(40)
+        .map(|c| MemoLeg { amount: u64::from_be_bytes(c[..8].try_into().unwrap()), to_ua: c[8..].try_into().unwrap() })
+        .collect();
+    Ok((salt, plain[0] & 1 == 1, legs))
 }
 
 /// Build the statement from the sender's state and prove it.
@@ -539,6 +655,7 @@ pub fn prove_transfer<C: ZCurve, R: RngCore + CryptoRng>(
     v: u64,
     rng: &mut R,
 ) -> Result<(TransferStatement<C>, TransferProof<C>, TransferWitness<C>), ZError> {
+    let mut header = header;
     let g = generator::<C>();
     if !value_in_range(v) {
         return Err(ZError::OutOfRange);
@@ -549,7 +666,8 @@ pub fn prove_transfer<C: ZCurve, R: RngCore + CryptoRng>(
     let b_prime = (balance as u128)
         .checked_sub(v as u128 + header.fee as u128)
         .ok_or(ZError::BadStatement("insufficient balance"))? as u64;
-    let s = derive_s::<C>(&key.x, &header, &y_to, v);
+    let (salt, s) = draw_salt::<C, R>(&key.x, &header, &key.ua(), rng);
+    header.salt = salt;
     let (vf, sf) = (Fr::<C>::from(v), s);
     let st = TransferStatement {
         y_f: key.y,
@@ -587,9 +705,10 @@ pub const MAX_RECIPIENTS: usize = 16;
 /// Where the token keeps the disclosure bundles; part of `opTag`, so a relayer cannot switch it.
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
 pub enum TransferMode {
-    /// `keccak256(B_1 ‖ … ‖ B_M)` stored, the bundles in an event (the default).
+    /// Commit-reveal: `keccak256(R)` and the sender memo stored, `R` in an event
+    /// (`zetherTransferCompact`; `zetherTransfer` on a `COMPACT` token, its only form). JSON `compact`.
     Hash,
-    /// `B_1 ‖ … ‖ B_M` stored.
+    /// `B_1 ‖ … ‖ B_M` stored (`zetherTransfer` on a `BUNDLE` token, the default).
     Bundle,
     /// Nothing stored; disclosure off chain from calldata.
     NoBundle,
@@ -606,10 +725,10 @@ impl TransferMode {
         })
     }
 
-    /// The JSON name (the token functions are `zetherTransfer`, `…Bundle`, `…NoBundle`).
+    /// The JSON name (the entries: `zetherTransfer` the token's default, `…Compact`, `…NoBundle`).
     pub fn name(self) -> &'static str {
         match self {
-            Self::Hash => "hash",
+            Self::Hash => "compact",
             Self::Bundle => "bundle",
             Self::NoBundle => "none",
         }
@@ -683,19 +802,24 @@ impl<C: ZCurve> MultiTransferStatement<C> {
         Ok(Self { header, mode, y_f, y_a, acc, d_out, c_deb, legs })
     }
 
-    /// `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
-    pub fn payload(&self) -> Vec<u8> {
+    /// `be32(accSeq) ‖ be32(sendCounter) ‖ salt(16) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`, then
+    /// `memo` (the witness's: commit-reveal only, empty otherwise).
+    pub fn payload(&self, memo: &[u8]) -> Vec<u8> {
         let mut b = be32_u64(self.header.acc_seq).to_vec();
         b.extend(be32_u64(self.header.send_counter));
+        b.extend_from_slice(&self.header.salt);
         b.extend(be32_u64(self.legs.len() as u64));
         b.extend(cat::<C>(&[&self.y_f, &self.d_out, &self.c_deb]));
         b.extend(self.leg_bytes());
+        b.extend_from_slice(memo);
         b
     }
 
-    /// `B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` — what the token stores or hashes.
+    /// The record `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` — what the token stores or hashes.
     pub fn bundles(&self) -> Vec<u8> {
-        self.legs.iter().flat_map(|l| cat::<C>(&[&l.y_t, &l.c_out, &self.d_out, &l.c_aud])).collect()
+        let mut b = self.header.salt.to_vec();
+        b.extend(self.legs.iter().flat_map(|l| cat::<C>(&[&l.y_t, &l.c_out, &self.d_out, &l.c_aud])));
+        b
     }
 
     pub fn auditor_on(&self) -> bool {
@@ -739,6 +863,8 @@ pub struct MultiTransferWitness<C: ZCurve> {
     pub b_prime: Fr<C>,
     pub gamma_v: Vec<Fr<C>>,
     pub gamma_b: Fr<C>,
+    /// The sender memo a commit-reveal payload ends with ([`seal_memo`]); empty for the other forms.
+    pub memo: Vec<u8>,
 }
 
 impl<C: ZCurve> Drop for MultiTransferWitness<C> {
@@ -945,23 +1071,6 @@ pub fn verify_transfer_multi<C: ZCurve>(
     Ok(tr)
 }
 
-/// One `s` for the whole transfer (owner Z3): a PRF of the conf key over the header and every
-/// `(Y_to, v)`, as [`derive_s`] is for one recipient.
-pub fn derive_s_multi<C: ZCurve>(x: &Fr<C>, h: &Header, recipients: &[(G<C>, u64)]) -> Fr<C> {
-    let mut d = Sha512::new();
-    d.update(b"SCAAS-ZETHER-S-MULTI-V1");
-    d.update(encode_scalar::<C>(x));
-    d.update(h.chain_id.to_be_bytes());
-    d.update(h.chain_uid);
-    d.update(h.token);
-    d.update(h.send_counter.to_be_bytes());
-    for (y, v) in recipients {
-        d.update(encode_point::<C>(y));
-        d.update(v.to_be_bytes());
-    }
-    Fr::<C>::from_be_bytes_mod_order(&d.finalize())
-}
-
 /// Build the statement for `recipients` (`(Y_to, v)`, decoys with `v = 0`) and prove it; the
 /// same checks as [`prove_transfer`], with `balance ≥ Σv + fee`.
 #[allow(clippy::too_many_arguments)]
@@ -976,6 +1085,7 @@ pub fn prove_transfer_multi<C: ZCurve, R: RngCore + CryptoRng>(
     balance: u64,
     rng: &mut R,
 ) -> Result<(MultiTransferStatement<C>, MultiTransferProof<C>, MultiTransferWitness<C>), ZError> {
+    let mut header = header;
     let g = generator::<C>();
     if acc.c - acc.d * key.x != g * Fr::<C>::from(balance) {
         return Err(ZError::BadStatement("balance does not decrypt from acc"));
@@ -984,7 +1094,17 @@ pub fn prove_transfer_multi<C: ZCurve, R: RngCore + CryptoRng>(
     let b_prime = (balance as u128)
         .checked_sub(total + header.fee as u128)
         .ok_or(ZError::BadStatement("insufficient balance"))? as u64;
-    let s = derive_s_multi::<C>(&key.x, &header, recipients);
+    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
+        return Err(ZError::BadStatement("recipient count"));
+    }
+    let (salt, s) = draw_salt::<C, R>(&key.x, &header, &key.ua(), rng);
+    header.salt = salt;
+    let memo = if mode == TransferMode::Hash {
+        seal_memo::<C>(&key.x, &header, &key.ua(), &salt, !y_aud.is_zero(), recipients)
+    } else {
+        Vec::new()
+    };
+    header.memo_hash = if memo.is_empty() { [0; 32] } else { keccak256(&memo) };
     let vs: Vec<Fr<C>> = recipients.iter().map(|(_, v)| Fr::<C>::from(*v)).collect();
     let legs = recipients
         .iter()
@@ -1015,6 +1135,7 @@ pub fn prove_transfer_multi<C: ZCurve, R: RngCore + CryptoRng>(
         b: Fr::<C>::from(balance),
         b_prime: Fr::<C>::from(b_prime),
         gamma_b: n.next::<C>(),
+        memo,
     };
     let p = prove_transfer_multi_core(gens, &st, &w, rng)?;
     Ok((st, p, w))
@@ -1061,6 +1182,9 @@ impl<C: ZCurve> BurnStatement<C> {
         if self.header.amount == 0 || self.header.amount > MAX_TOTAL_SHIELDED {
             return Err(ZError::BadStatement("burn amount outside (0, 2^54]"));
         }
+        if self.header.salt != [0u8; 16] || self.header.memo_hash != [0u8; 32] {
+            return Err(ZError::BadStatement("salt or memo on a burn"));
+        }
         if self.y_f.is_zero() {
             return Err(ZError::BadStatement("Y = O"));
         }
diff --git a/clients/zether-prover/tests/envelope_disclosure.rs b/clients/zether-prover/tests/envelope_disclosure.rs
index f737e67..eda3fe2 100644
--- a/clients/zether-prover/tests/envelope_disclosure.rs
+++ b/clients/zether-prover/tests/envelope_disclosure.rs
@@ -101,6 +101,8 @@ fn relayed_and_disclosure<C: ZCurve>() {
         beneficiary: [0; 32],
         amount: 0,
         recipient: [0; 20],
+        salt: [0; 16],
+        memo_hash: [0; 32],
     };
     let (st, p, w) = prove_transfer(&gens, &from, h, to.y, aud.y, acc, 5000, 1234, &mut rng).unwrap();
     verify_transfer(&gens, &st, &p).unwrap();
@@ -216,8 +218,8 @@ fn relayed_and_disclosure_bls12_381() {
 
 #[test]
 fn entry_point_selectors_match_the_spec() {
-    // CTR-ZTH-45: the zether-prefixed names; the multi-recipient HASH transfer is `zetherTransfer`, the single format
-    // `zetherTransferSingle` (same four arguments, no outer fee on a direct call).
+    // CTR-ZTH-45: the zether-prefixed names; the multi-recipient default is `zetherTransfer`, commit-reveal
+    // `zetherTransferCommit`, the single format `zetherTransferSingle` (same four arguments, no outer fee on a direct call).
     assert_eq!(hex::encode(selector("zetherTransfer(bytes,bytes,bytes,bytes32)")), "d228e5c0");
     assert_eq!(hex::encode(selector("zetherTransferSingle(bytes,bytes,bytes,bytes32)")), "4d2e578f");
     assert_eq!(hex::encode(selector("zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)")), "983c7842");
diff --git a/clients/zether-prover/tests/read_balance.rs b/clients/zether-prover/tests/read_balance.rs
index 0c94b16..bc4f48c 100644
--- a/clients/zether-prover/tests/read_balance.rs
+++ b/clients/zether-prover/tests/read_balance.rs
@@ -65,9 +65,9 @@ fn big_balance_cache_spend_and_cli_recovery() {
         "amount": v.to_string(), "fee": fee, "beneficiary": hx(&[0x22; 32]),
     })).unwrap();
     assert_eq!(api("verifyTransfer", json!({"curve": "bn254", "statement": t["statement"], "proof": t["proof"]})).unwrap()["ok"], json!(true));
-    // The token's debit: acc −= (C_deb + [fee]G, D_out). Payload = 64 B ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud.
+    // The token's debit: acc −= (C_deb + [fee]G, D_out). Payload = 64 B ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud.
     let pl = hex::decode(&t["payload"].as_str().unwrap()[2..]).unwrap();
-    let at = |i: usize| decode_point::<Bn254>(&pl[64 + 64 * i..128 + 64 * i]).unwrap();
+    let at = |i: usize| decode_point::<Bn254>(&pl[80 + 64 * i..144 + 64 * i]).unwrap();
     let (d_out, c_deb) = (at(3), at(4));
     let g = generator::<Bn254>();
     let acc2 = Ciphertext::<Bn254> { c: pt(&acc["C"]) - c_deb - g * Fr::<Bn254>::from(fee), d: pt(&acc["D"]) - d_out };
diff --git a/clients/zether-prover/tests/zether_proofs.rs b/clients/zether-prover/tests/zether_proofs.rs
index 51d2d61..e1b7881 100644
--- a/clients/zether-prover/tests/zether_proofs.rs
+++ b/clients/zether-prover/tests/zether_proofs.rs
@@ -31,6 +31,8 @@ fn header(fee: u64) -> Header {
         beneficiary: if fee > 0 { [0x22; 32] } else { [0; 32] },
         amount: 0,
         recipient: [0; 20],
+        salt: [0; 16],
+        memo_hash: [0; 32],
     }
 }
 
@@ -72,7 +74,9 @@ fn valid_and_effects<C: ZCurve>() {
         assert_eq!(enc.len(), if point_len::<C>() == 64 { 3200 } else { 5888 });
         assert!(TransferProof::<C>::decode(&enc).unwrap() == p);
         assert!(TransferStatement::<C>::decode(&st.encode()).unwrap() == st);
-        assert_eq!(st.payload().len(), 64 + 6 * point_len::<C>());
+        assert_eq!(st.payload().len(), 80 + 6 * point_len::<C>(), "accSeq ‖ sendCounter ‖ salt ‖ points");
+        assert_eq!(st.record().len(), 16 + 4 * point_len::<C>(), "R = salt ‖ B");
+        assert_eq!(&st.record()[..16], &st.header.salt);
         // On-chain effects (§5), then decrypt both sides.
         let g = generator::<C>();
         let fee = g * Fr::<C>::from(300u64);
@@ -251,6 +255,12 @@ fn burn_suite<C: ZCurve>() {
     let mut h = header(300);
     h.amount = 400_000;
     h.recipient = [0x44; 20];
+    let mut memo = h.clone();
+    memo.memo_hash = [1; 32];
+    assert!(prove_burn(&f.gens, &f.from, memo, f.acc, BAL, &mut rng()).is_err(), "a burn has no memo");
+    let mut salted = h.clone();
+    salted.salt = [1; 16];
+    assert!(prove_burn(&f.gens, &f.from, salted, f.acc, BAL, &mut rng()).is_err(), "a burn has no salt");
     let (st, p, w) = prove_burn(&f.gens, &f.from, h.clone(), f.acc, BAL, &mut rng()).unwrap();
     verify_burn(&f.gens, &st, &p).unwrap();
     let enc = p.encode();
@@ -370,15 +380,18 @@ fn multi_valid_and_effects<C: ZCurve>() {
         (vec![0, 7, 0, 100], false, TransferMode::Bundle),
         (vec![1, 2, 3, 4, 5, 6, 7, 8], true, TransferMode::NoBundle),
     ] {
-        let (st, p, _) = multi(&f, header(300), mode, aud, &vs);
+        let (st, p, w) = multi(&f, header(300), mode, aud, &vs);
         verify_transfer_multi(&f.gens, &st, &p).unwrap();
         let m = vs.len();
         let enc = p.encode();
         assert_eq!(enc.len(), MultiTransferProof::<C>::wire_len(m));
         assert!(MultiTransferProof::<C>::decode(&enc, m).unwrap() == p);
         assert!(MultiTransferStatement::<C>::decode(&st.encode()).unwrap() == st);
-        assert_eq!(st.payload().len(), 96 + (3 + 3 * m) * point_len::<C>());
-        assert_eq!(st.bundles().len(), 4 * m * point_len::<C>());
+        let memo = if mode == TransferMode::Hash { memo_len(m) } else { 0 };
+        assert_eq!(w.memo.len(), memo, "a memo on commit-reveal only");
+        assert_eq!(st.header.memo_hash == [0; 32], memo == 0, "memoHash in the header exactly then");
+        assert_eq!(st.payload(&w.memo).len(), 112 + (3 + 3 * m) * point_len::<C>() + memo, "… ‖ legs [‖ memo]");
+        assert_eq!(st.bundles().len(), 16 + 4 * m * point_len::<C>(), "R = salt ‖ B_1 ‖ … ‖ B_M");
         // Effects: the sender loses Σv + fee, each recipient decrypts its own v (decoys: 0).
         let g = generator::<C>();
         let acc2 = Ciphertext { c: st.acc.c - st.c_deb - g * Fr::<C>::from(300u64), d: st.acc.d - st.d_out };
@@ -481,12 +494,48 @@ fn multi_negatives_bls12_381() {
     multi_negatives::<Bls12381>();
 }
 
-/// K1: `s` is chain-specific — the same transfer on a re-created chain (same chainId, other chainUid) never reuses it.
+/// CTR-ZTH-30: `s` depends on the chain (K1: a re-created chain keeps chainId and the CREATE2 token address), the
+/// salt (a retry at the same counter), the token, the sender, the counter and the key — and on nothing else: not on
+/// the amounts, the recipients, the fee or the binding (so the sender rebuilds it from its key and chain data alone).
 #[test]
-fn s_depends_on_chain_uid() {
-    let (x, y) = (Fr::<Bn254>::from(7u64), generator::<Bn254>());
-    let mut other = header(0);
-    other.chain_uid[31] ^= 1;
-    assert_ne!(derive_s::<Bn254>(&x, &header(0), &y, 5), derive_s::<Bn254>(&x, &other, &y, 5));
-    assert_ne!(derive_s_multi::<Bn254>(&x, &header(0), &[(y, 5)]), derive_s_multi::<Bn254>(&x, &other, &[(y, 5)]));
+fn s_inputs() {
+    let (x, ua, salt) = (Fr::<Bn254>::from(7u64), [0x77u8; 32], [0x5a; 16]);
+    let base = derive_s::<Bn254>(&x, &header(0), &ua, &salt);
+    let mut h = header(0);
+    h.chain_uid[31] ^= 1;
+    assert_ne!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "chainUid");
+    assert_ne!(derive_s::<Bn254>(&x, &header(0), &ua, &[0x5b; 16]), base, "salt");
+    let mut h = header(0);
+    h.token[0] ^= 1;
+    assert_ne!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "token");
+    let mut h = header(0);
+    h.send_counter += 1;
+    assert_ne!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "sendCounter");
+    assert_ne!(derive_s::<Bn254>(&x, &header(0), &[0x78; 32], &salt), base, "fromUA");
+    assert_ne!(derive_s::<Bn254>(&Fr::<Bn254>::from(8u64), &header(0), &ua, &salt), base, "the key");
+    let mut h = header(300);
+    (h.chain_id, h.acc_seq, h.binding, h.memo_hash, h.salt) = (1, 9, Binding::Relayed([1; 32]), [2; 32], [3; 16]);
+    assert_eq!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "chainId, accSeq, fee, beneficiary, binding, the header fields are not inputs (the salt argument is)");
+}
+
+/// CTR-ZTH-50: the memo opens under the sender's key and header to the flag and the legs, and under nothing else.
+#[test]
+fn memo_roundtrip() {
+    let (x, ua, salt) = (Fr::<Bn254>::from(7u64), [0x77u8; 32], [0x5a; 16]);
+    let (y1, y2) = (generator::<Bn254>() * Fr::<Bn254>::from(3u64), generator::<Bn254>());
+    let memo = seal_memo::<Bn254>(&x, &header(0), &ua, &salt, true, &[(y1, 1200u64), (y2, 0)]);
+    assert_eq!(memo.len(), memo_len(2));
+    assert_eq!(memo.len(), 17 + 2 * 40);
+    assert_eq!(&memo[..16], &salt, "the salt in clear");
+    let (s2, aud, legs) = open_memo::<Bn254>(&x, &header(0), &ua, &memo).unwrap();
+    assert!(s2 == salt && aud);
+    assert_eq!(legs[0], MemoLeg { amount: 1200, to_ua: zether_prover::curve::ua_of::<Bn254>(&y1) });
+    assert_eq!(legs[1].amount, 0);
+    let mut h = header(0);
+    h.chain_uid[0] ^= 1;
+    assert_ne!(open_memo::<Bn254>(&x, &h, &ua, &memo).unwrap().2, legs, "another chain: garbage");
+    assert_ne!(open_memo::<Bn254>(&Fr::<Bn254>::from(8u64), &header(0), &ua, &memo).unwrap().2, legs, "another key");
+    assert!(open_memo::<Bn254>(&x, &header(0), &ua, &memo[..memo.len() - 1]).is_err(), "length");
+    let off = seal_memo::<Bn254>(&x, &header(0), &ua, &salt, false, &[(y1, 1200u64)]);
+    assert!(!open_memo::<Bn254>(&x, &header(0), &ua, &off).unwrap().1, "the auditor flag");
 }
diff --git a/clients/zether-prover/vectors/s2/generators_bls12381.json b/clients/zether-prover/vectors/s2/generators_bls12381.json
index d58257b..609acab 100644
--- a/clients/zether-prover/vectors/s2/generators_bls12381.json
+++ b/clients/zether-prover/vectors/s2/generators_bls12381.json
@@ -1,6 +1,6 @@
 {
  "curve": "bls12381",
- "proofSystemId": "0x87f6843e3f9ef837578a87499bf0094169341ef82358817d2f2a25502c6e5f5d",
+ "proofSystemId": "0xa3ab9e33ec9df9e3825269609544c2297fc753fee898466f98bf34e20aaf3536",
  "h": "0x000000000000000000000000000000000a7bc97a0c4c3e37a4be57106ae428c4a56aefadaea3421110ca2993f68ff0425588cdb19ff491628e19310f925bcdf60000000000000000000000000000000012095790623f66413e7886d7d92471528fde76e44c0f483c987bf284bd27d4d5682e14bf7e8ff7bc75066fb1abe8d2b9",
  "U": "0x00000000000000000000000000000000132ae1e96c5088a78ec49340176fce84772684ca478a019b494fe2daa01d0c4a7795347cc1a0e204df8ea1c63abc71e900000000000000000000000000000000023b49bc1aa4de8639b7949ff04d98b47e88a22238f98915071a0ee4fc6b26e8a690bfb61f1b47c14fbdd7ced21aee60",
  "G": [
diff --git a/clients/zether-prover/vectors/s2/generators_bn254.json b/clients/zether-prover/vectors/s2/generators_bn254.json
index a530897..dba04fa 100644
--- a/clients/zether-prover/vectors/s2/generators_bn254.json
+++ b/clients/zether-prover/vectors/s2/generators_bn254.json
@@ -1,6 +1,6 @@
 {
  "curve": "bn254",
- "proofSystemId": "0xacc73a11033f169964b58ca141ba081641db22c5d4a46bc356a4e9d1e83d53a0",
+ "proofSystemId": "0x8decdb706f7dc6baf2cf3b9f91b845e0d79bea9ef54f04ff285cf6e0a733de49",
  "h": "0x1f5b2f4b53ea4b173b00eec464742c0013d39ed45fa833a8d5a7feae56c3403b0d194dd017288a46a78c44b90c6e92ef5098e6b29f1028d67d9c1ac09bc281f4",
  "U": "0x02b664c30ebff58b898c56aae146b14a3576cdd682866960852c6e9a0717851513b1e5b9c75c13a2e5e60024bd14fac87297b71d606acc66cd8e0a9f233686ac",
  "G": [
```

- [ ] **Step 2: `tests/recover.rs`** (new):

```rust
//! CTR-ZTH-30 / CTR-ZTH-50: `s`, the amounts and every bundle of a transfer from the sender's key and chain data alone
//! (`recoverTransfer`): from storage (no logs; the commitment and its memo, or the stored record) or from calldata; a
//! fresh salt per build; the token's modes in a request (`disclosureMode`, `auditorMode`, CTR-ZTH-38/48/49).

use serde_json::{json, Value};
use zether_prover::api::call;
use zether_prover::curve::keccak256;

fn ok(cmd: &str, v: &Value) -> Value {
    serde_json::from_str(&call(cmd, &v.to_string()).unwrap()).unwrap()
}

fn err(cmd: &str, v: &Value) -> String {
    call(cmd, &v.to_string()).unwrap_err()
}

const UID: &str = "0x2424242424242424242424242424242424242424242424242424242424242424";
const TOKEN: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";

fn key(account: u32) -> Value {
    json!({"seed": format!("0x{}", "07".repeat(64)), "coin": 60, "account": account})
}

fn y(curve: &str, a: u32) -> Value {
    ok("keygen", &json!({"curve": curve, "key": key(a)}))["Y"].clone()
}

fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap()
}

fn hx(b: &[u8]) -> Value {
    json!(format!("0x{}", hex::encode(b)))
}

/// A commit-reveal transfer on a COMPACT token (its default entry): three recipients, one a decoy, the auditor in.
fn multi(curve: &str) -> Value {
    let acc = ok("encrypt", &json!({"curve": curve, "Y": y(curve, 0), "amount": 5000}));
    json!({
        "curve": curve, "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN, "sendCounter": 4, "accSeq": 1,
        "acc": acc, "balance": 5000, "includeWitness": true, "yAud": y(curve, 9), "disclosureMode": "compact",
        "recipients": [{"yTo": y(curve, 1), "amount": 1200}, {"yTo": y(curve, 2), "amount": 0},
                       {"yTo": y(curve, 3), "amount": 77}],
    })
}

/// What `transferEntry(entryRef)` returns after a commit-reveal transfer: `keccak256(R) ‖ memo`.
fn entry(t: &Value) -> Value {
    hx(&[keccak256(&hexb(&t["bundles"])).to_vec(), hexb(&t["memo"])].concat())
}

/// The storage-only request: the counter, the entry, the registry's keys (`keyOf`) and the token's auditor key.
fn from_storage(curve: &str, entry: &Value, uid: &str) -> Value {
    json!({"curve": curve, "key": key(0), "chainId": 31337, "chainUid": uid, "token": TOKEN, "sendCounter": 4,
        "entry": entry, "keys": [y(curve, 3), y(curve, 1), y(curve, 2), y(curve, 5)], "yAud": y(curve, 9)})
}

#[test]
fn recover_from_storage_alone() {
    for curve in ["bn254", "bls12381"] {
        let t = ok("proveTransferMulti", &multi(curve));
        assert_eq!(t["mode"], json!("compact"));
        let r = ok("recoverTransfer", &from_storage(curve, &entry(&t), UID));
        assert_eq!(r["s"], t["witness"]["s"], "{curve}: s");
        assert_eq!(r["salt"], t["salt"]);
        assert_eq!(r["bundles"], t["bundles"], "{curve}: R, every leg");
        assert_eq!(r["entryRef"], t["entryRef"]);
        assert_eq!(r["legs"][0]["amount"], json!("1200"));
        assert_eq!(r["legs"][2]["amount"], json!("77"));
        assert_eq!(r["legs"][2]["yTo"], y(curve, 3));
        assert_eq!(r["auditorIncluded"], json!(true));
        assert_eq!(r["senderS"].as_str().unwrap().len(), 2 + 64);
        assert_eq!(r["senderCp"].as_array().unwrap().len(), 3);
        // a tampered memo, another chainUid, a missing key: refused
        let mut bad = hexb(&entry(&t));
        bad[32 + 20] ^= 1;
        assert!(!err("recoverTransfer", &from_storage(curve, &hx(&bad), UID)).is_empty(), "tampered memo");
        assert!(!err("recoverTransfer", &from_storage(curve, &entry(&t), &format!("0x{}", "25".repeat(32)))).is_empty());
        let mut no_key = from_storage(curve, &entry(&t), UID);
        no_key["keys"] = json!([y(curve, 1)]);
        assert!(err("recoverTransfer", &no_key).contains("keys"));
    }
}

/// An `OPTIONAL` opt-out: the memo's flag says the auditor was left out; no `yAud` needed.
#[test]
fn recover_an_opt_out() {
    let mut req = multi("bn254");
    req["yAud"] = Value::Null;
    let t = ok("proveTransferMulti", &req);
    let mut q = from_storage("bn254", &entry(&t), UID);
    q["yAud"] = Value::Null;
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["auditorIncluded"], json!(false));
    assert_eq!(r["bundles"], t["bundles"]);
}

/// A full record (`zetherTransfer` on a BUNDLE token, the single format) from storage, and any entry from calldata: the
/// salt in `R` or the payload gives `s`, BSGS the amounts.
#[test]
fn recover_a_record_and_calldata() {
    let mut req = multi("bn254");
    req["disclosureMode"] = Value::Null; // a BUNDLE token: `zetherTransfer` stores R
    let t = ok("proveTransferMulti", &req);
    assert_eq!(t["memo"], json!("0x"), "no memo off commit-reveal");
    let base = json!({"curve": "bn254", "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN,
        "yAud": y("bn254", 9), "tableBits": 18, "boundBits": 24});
    let mut q = base.clone();
    (q["entry"], q["sendCounter"]) = (t["bundles"].clone(), json!(4));
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["s"], t["witness"]["s"]);
    assert_eq!(r["legs"][0]["amount"], json!("1200"), "BSGS");
    let mut q = base.clone();
    q["payload"] = t["payload"].clone();
    assert_eq!(ok("recoverTransfer", &q)["bundles"], t["bundles"], "from calldata");
    let mut one = req.clone();
    (one["yTo"], one["amount"]) = (req["recipients"][0]["yTo"].clone(), json!(1200));
    let t1 = ok("proveTransfer", &one);
    let mut q = base.clone();
    (q["entry"], q["sendCounter"]) = (t1["record"].clone(), json!(4));
    let r1 = ok("recoverTransfer", &q);
    assert_eq!(r1["s"], t1["witness"]["s"], "single");
    assert_eq!(r1["legs"][0]["amount"], json!("1200"));
    q["key"] = key(1);
    assert!(err("recoverTransfer", &q).contains("D_out"), "another key");
}

/// A retry at the same counter (the first transaction failed, its calldata public): a fresh salt, so another memo key
/// and another `s`.
#[test]
fn two_builds_at_one_counter_differ() {
    let req = multi("bn254");
    let (a, b) = (ok("proveTransferMulti", &req), ok("proveTransferMulti", &req));
    assert_ne!(a["salt"], b["salt"]);
    assert_ne!(a["witness"]["s"], b["witness"]["s"]);
    assert_ne!(hexb(&a["memo"])[16..], hexb(&b["memo"])[16..], "memo keystream");
}

/// The default entry follows the token: `zetherTransfer` stores R on a BUNDLE token (the default) and commits on a
/// COMPACT token, which refuses the other forms and the single format; `auditorMode` FULL needs `yAud`, NONE refuses it.
#[test]
fn modes_in_the_request() {
    let mut req = multi("bn254");
    req["disclosureMode"] = Value::Null;
    let sel = |t: &Value| t["directCalldata"].as_str().unwrap()[2..10].to_string();
    let t = ok("proveTransferMulti", &req);
    assert_eq!(t["mode"], json!("bundle"));
    assert_eq!(sel(&t), "d228e5c0", "zetherTransfer, the default");
    let mut h = req.clone();
    h["mode"] = json!("compact");
    let compact = hex::encode(zether_prover::envelope::selector("zetherTransferCompact(bytes,bytes,bytes,bytes32)"));
    assert_eq!(sel(&ok("proveTransferMulti", &h)), compact, "commit-reveal on a BUNDLE token");
    let mut c = req.clone();
    c["disclosureMode"] = json!("compact");
    let t = ok("proveTransferMulti", &c);
    assert_eq!(t["mode"], json!("compact"));
    assert_eq!(sel(&t), "d228e5c0", "zetherTransfer: commit-reveal on a COMPACT token");
    for m in ["bundle", "none"] {
        c["mode"] = json!(m);
        assert!(err("proveTransferMulti", &c).contains("TransferEntryDisabled"));
    }
    let mut one = c.clone();
    (one["yTo"], one["amount"]) = (req["recipients"][0]["yTo"].clone(), json!(1));
    assert!(err("proveTransfer", &one).contains("TransferEntryDisabled"), "no single format on COMPACT");
    let mut a = req.clone();
    a["auditorMode"] = json!("none");
    assert!(err("proveTransferMulti", &a).contains("AuditorForbidden"));
    a["yAud"] = Value::Null;
    a["auditorMode"] = json!("full");
    assert!(err("proveTransferMulti", &a).contains("AuditorRequired"));
    a["auditorMode"] = json!("optional");
    ok("proveTransferMulti", &a);
}
```

- [ ] **Step 3: regenerate the vectors** (deterministic; `committed_vectors_are_current_and_verify` fails on drift):

```bash
cd clients/zether-prover
CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/clients/zether-prover/target \
  /home/ha/work/ainative/scaas/scripts/capped cargo run --release --bin zether-cli vectors vectors
```

  Changes `burn_*`, `disclosure_*`, `transcript_s3`, `transfer_*`, `transfer_multi_*`, `transfer_multi_noaud_*`,
  `transfer_noaud_*` (new header, payloads with the salt, `R` with the salt, the memo of the commit-reveal multi vector,
  the `v2` proof system id); `envelope.json`, `r33_*`, `schnorr_*` stay byte-identical.

- [ ] **Step 4: Run** — `CARGO_TARGET_DIR=… scripts/capped cargo test --release` → **59 passed** (53 + `recover.rs` 5
  + `memo_roundtrip`; `s_depends_on_chain_uid` became `s_inputs`); `scripts/capped ./wasm-smoke.sh` (without
  `CARGO_TARGET_DIR`) → `wasm smoke: 16 checks passed`.

- [ ] **Step 5: Commit** — `git add clients/zether-prover` →
  `P3b: prover — salt and 480-byte header, sender memo, disclosure/auditor modes in requests, recoverTransfer; vectors`

---
### Task 2: The contracts — modes at `initialize`, the entries, the auditor rule, salt and memo, `R`, `keyOf`; the tests

**Model:** Opus, effort high (money paths and the byte layout; every refusal has a pinned test).

**Files:**
- Modify: `smartcontracts/evm/src/factory/IFactoryToken.sol`, `src/metatx/MetaTokenBase.sol`,
  `src/registry/{IUniversalAccountRegistry,UniversalAccountRegistry}.sol`, `src/zether/{ZetherTypes, IZetherToken,
  ITransferDisclosure, ZetherLib, ZetherLayer, NormalZetherToken, WrappedZetherToken, ZetherStatements,
  ZetherDisclosure, ZetherVerifier}.sol`, `size-baseline.json`;
  tests `test/v2/FactoryZether.t.sol`, `test/zether/{helpers/ZetherFixture, helpers/ZetherProver, ZetherMulti,
  ZetherNormal, ZetherRelay, ZetherRevertPaths, ZetherS3Vectors, ZetherWrapped, ZetherVerifier, ZetherInvariant,
  ZetherDeploy, UniversalAccountRegistry}.t.sol`, `test/vectors/zether/{kat.py, generators_bn254.json,
  generators_bls12381.json}`, `test/vectors/zether/s3/*.json` (copied from Task 1)
- Create: `smartcontracts/evm/test/zether/ZetherModes.t.sol`

**Interfaces:** `ConfidentialConfig.{disclosureMode, auditorMode}` (`uint8`); `ZetherTypes.DisclosureMode {BUNDLE,
COMPACT}`, `ZetherTypes.AuditorMode {NONE, FULL, OPTIONAL}`; `IZetherToken.disclosureMode()`, `auditorMode()`,
`zetherTransferCompact(...)`, errors `TransferEntryDisabled(uint8)`, `BadDisclosureMode(uint8)`,
`BadAuditorMode(uint8)`, `AuditorRequired()`, `AuditorForbidden()` (`AuditorLegsMixed` kept); removed
`zetherTransferBundle`; `IUniversalAccountRegistry.keyOf(UA)`; `ZetherLib.defaultMode()`; verifier `HEADER = 480`,
proof system ids `…/v2`.

- [ ] **Step 1: the source changes** (apply the diff):

```diff
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index c6230f9..57f24f4 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,7 +1,7 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
-  "NormalToken": 22986,
-  "WrappedToken": 30044,
-  "NormalZetherToken": 30667,
-  "WrappedZetherToken": 40389
+  "NormalToken": 23042,
+  "WrappedToken": 30142,
+  "NormalZetherToken": 31162,
+  "WrappedZetherToken": 40706
 }
diff --git a/smartcontracts/evm/src/factory/IFactoryToken.sol b/smartcontracts/evm/src/factory/IFactoryToken.sol
index 5ccd681..31f5bd1 100644
--- a/smartcontracts/evm/src/factory/IFactoryToken.sol
+++ b/smartcontracts/evm/src/factory/IFactoryToken.sol
@@ -23,12 +23,18 @@ interface IFactoryToken {
 
     /// @notice `*_ZETHER` kinds only; every other kind requires it empty. `maxShielded` (the total cap, `≤ 2^54`) and
     ///         `confidentialFee` (the inner fee, `< 2^64` and `< maxShielded`) are per token (CTR-ZTH-04, CTR-ZTH-05).
+    ///         The two modes are fixed for the token's life (CTR-ZTH-38, CTR-ZTH-42): `disclosureMode` 0 `BUNDLE` (the
+    ///         default: every transfer entry, the bundle one by default) or 1 `COMMIT` (the hash entry only);
+    ///         `auditorMode` 0 `NONE` (no key, every `C_aud = O`), 1 `FULL` (key, every transfer includes the auditor)
+    ///         or 2 `OPTIONAL` (key, the sender may leave the auditor out per transfer). `ZetherTypes` names the values.
     struct ConfidentialConfig {
         address verifier;
         bytes auditorKey;
         uint256 shieldScale;
         uint256 maxShielded;
         uint256 confidentialFee;
+        uint8 disclosureMode;
+        uint8 auditorMode;
     }
 
     /// @notice CTR-TOK-25. Fields of another kind must be empty (`ConfigFieldForOtherKind`), so a token never carries a
diff --git a/smartcontracts/evm/src/metatx/MetaTokenBase.sol b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
index f4296d0..697d3b2 100644
--- a/smartcontracts/evm/src/metatx/MetaTokenBase.sol
+++ b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
@@ -79,7 +79,7 @@ abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IER
         if (rate && (cfg.rate.rateDelay != 0 || cfg.rate.maxRateStepBps != 0)) revert ConfigFieldForOtherKind(3);
         ConfidentialConfig calldata c = cfg.conf;
         if (conf && (c.verifier != address(0) || c.auditorKey.length != 0 || c.shieldScale != 0 || c.maxShielded != 0
-            || c.confidentialFee != 0)) revert ConfigFieldForOtherKind(4);
+            || c.confidentialFee != 0 || c.disclosureMode != 0 || c.auditorMode != 0)) revert ConfigFieldForOtherKind(4);
     }
 
     function _setMetadata(string memory n, string memory sym, uint8 d) internal {
diff --git a/smartcontracts/evm/src/registry/IUniversalAccountRegistry.sol b/smartcontracts/evm/src/registry/IUniversalAccountRegistry.sol
index 6f84a1b..c9f066d 100644
--- a/smartcontracts/evm/src/registry/IUniversalAccountRegistry.sol
+++ b/smartcontracts/evm/src/registry/IUniversalAccountRegistry.sol
@@ -54,6 +54,10 @@ interface IUniversalAccountRegistry {
     /// @notice 64 (bn254) | 128 (BLS12-381) | 0 (chưa đăng ký). Token so với `verifier.g1EncodedBytes()`.
     function keyLengthOf(ZetherTypes.UA ua) external view returns (uint256);
 
+    /// @notice `encodedY` of a registered UA (empty otherwise): the recipient keys of a sender's storage-only recovery
+    ///         (zether.md CTR-ZTH-50).
+    function keyOf(ZetherTypes.UA ua) external view returns (bytes memory);
+
     /// @notice Thông điệp PoP mà `account` phải ký cho `encodedY`.
     function popChallenge(bytes calldata encodedY, address account) external view returns (bytes32);
 
diff --git a/smartcontracts/evm/src/registry/UniversalAccountRegistry.sol b/smartcontracts/evm/src/registry/UniversalAccountRegistry.sol
index 583be9f..666c84e 100644
--- a/smartcontracts/evm/src/registry/UniversalAccountRegistry.sol
+++ b/smartcontracts/evm/src/registry/UniversalAccountRegistry.sol
@@ -31,6 +31,8 @@ contract UniversalAccountRegistry is IUniversalAccountRegistry {
         uint16 keyLength;
         address linked;
         bytes authData;
+        /// @dev `encodedY`: a sender rebuilds its commit-reveal record from the memo's recipient UAs (zether.md CTR-ZTH-50).
+        bytes key;
     }
 
     bytes private constant SCHNORR_TAG = "SCAAS-ZETHER-SCHNORR-V1"; // ASCII thô, 23 byte (§11.1)
@@ -87,7 +89,8 @@ contract UniversalAccountRegistry is IUniversalAccountRegistry {
             linked = msg.sender;
         }
         _accounts[ua] = Account({
-            registered: true, scheme: authScheme, keyLength: uint16(len), linked: linked, authData: authData
+            registered: true, scheme: authScheme, keyLength: uint16(len), linked: linked, authData: authData,
+            key: encodedY
         });
         emit AccountRegistered(ua, authScheme, linked, authData);
     }
@@ -113,6 +116,10 @@ contract UniversalAccountRegistry is IUniversalAccountRegistry {
         return _accounts[ua].keyLength;
     }
 
+    function keyOf(ZetherTypes.UA ua) external view returns (bytes memory) {
+        return _accounts[ua].key;
+    }
+
     // ------------------------------------------------------------------ uỷ quyền
 
     function requireAuthorized(ZetherTypes.UA ua, bytes32 digest, bytes calldata sig, bool zkCovered) external view {
diff --git a/smartcontracts/evm/src/zether/ITransferDisclosure.sol b/smartcontracts/evm/src/zether/ITransferDisclosure.sol
index 4293ce8..1d78b4f 100644
--- a/smartcontracts/evm/src/zether/ITransferDisclosure.sol
+++ b/smartcontracts/evm/src/zether/ITransferDisclosure.sol
@@ -23,8 +23,9 @@ pragma solidity ^0.8.20;
 ///     D_transfer = g^s
 ///
 /// nên mở nó là chứng minh số tiền, và nó ràng buộc TUYỆT ĐỐI vào đúng giao dịch đó.
-/// Chi phí lúc chuyển: token lưu bản ghi để mở on-chain — bundle đầy đủ (định dạng một người nhận, mode BUNDLE,
-/// 4 điểm mỗi leg), một slot hash (mode HASH), hoặc không gì (mode NONE: chỉ off-chain), CTR-ZTH-14/38.
+/// Chi phí lúc chuyển: token lưu bản ghi để mở on-chain — `R = salt ‖ B_1 ‖ … ‖ B_M` đầy đủ (định dạng một người nhận,
+/// mode BUNDLE, 4 điểm mỗi leg), một slot hash cộng memo người gửi (commit-reveal, CTR-ZTH-50), hoặc không gì (mode
+/// NONE: chỉ off-chain), CTR-ZTH-14/38.
 interface ITransferDisclosure {
     /// Ba đường mở, ba chủ thể khác nhau. Giữ cả ba — mỗi cái giải một tình huống
     /// tranh chấp mà hai cái kia không giải được.
@@ -59,7 +60,8 @@ interface ITransferDisclosure {
     /// @param amount   số tiền được tuyên bố, đơn vị che giấu
     /// @param kind     đường mở nào
     /// @param opening  `s` cho SENDER_S; `abi.encode(A1, A2, z)` (Chaum-Pedersen) cho RECEIVER_X, AUDITOR, SENDER_CP
-    /// @param bundles  mode HASH: `B_1 ‖ … ‖ B_M` (từ event `TransferBundles` hoặc calldata), khớp hash đã lưu;
+    /// @param bundles  commit-reveal: `R = salt ‖ B_1 ‖ … ‖ B_M` (từ event `TransferBundles`, calldata, hoặc người gửi
+    ///                 dựng lại từ memo), khớp hash đã lưu;
     ///                 bỏ qua khi bundle nằm trong storage. Mode NONE: không có gì để kiểm (`UnknownEntry`).
     ///
     /// @dev Phần lớn nhu cầu — kiểm toán, đối soát ERP, trả lời cơ quan thuế — chỉ
diff --git a/smartcontracts/evm/src/zether/IZetherToken.sol b/smartcontracts/evm/src/zether/IZetherToken.sol
index 331271e..fd221d5 100644
--- a/smartcontracts/evm/src/zether/IZetherToken.sol
+++ b/smartcontracts/evm/src/zether/IZetherToken.sol
@@ -47,7 +47,7 @@ interface IZetherToken {
         ZetherTypes.UA[] recipients,
         ZetherTypes.TransferMode mode
     );
-    /// @notice Mode HASH: `B_1 ‖ … ‖ B_M`, whose hash `entryRef` stores.
+    /// @notice Commit-reveal (HASH): the record `R = salt ‖ B_1 ‖ … ‖ B_M`, whose hash `entryRef` stores.
     event TransferBundles(bytes32 indexed entryRef, bytes bundles);
     /// @notice `recipient` received `amount · shieldScale` public units (`zetherUnshield`) or the underlying they are
     ///         worth (`zetherUnshieldUnwrap`).
@@ -68,8 +68,18 @@ interface IZetherToken {
     error RollOverExpired(uint256 validUntilBlock);
     error PendingSeqMismatch(uint256 expected, uint256 got);
     error ZeroRecipient();
-    /// @notice With the token's auditor on, every `C_aud_j` is `O` (left out) or none is (CTR-ZTH-42).
+    /// @notice `OPTIONAL` auditor: every `C_aud_j` is `O` (left out) or none is (CTR-ZTH-42).
     error AuditorLegsMixed();
+    /// @notice `FULL` auditor: a transfer left the auditor out (some `C_aud_j = O`).
+    error AuditorRequired();
+    /// @notice `NONE` auditor: a transfer carries an auditor leg (some `C_aud_j ≠ O`).
+    error AuditorForbidden();
+    /// @notice A `COMPACT` token refuses `zetherTransferNoBundle` and `zetherTransferSingle` (CTR-ZTH-48).
+    error TransferEntryDisabled(uint8 disclosureMode);
+    /// @notice `ConfidentialConfig.disclosureMode` is neither BUNDLE nor COMPACT (CTR-ZTH-48).
+    error BadDisclosureMode(uint8 mode);
+    /// @notice `ConfidentialConfig.auditorMode` unknown, FULL or OPTIONAL without a key, or NONE with one (CTR-ZTH-49).
+    error BadAuditorMode(uint8 mode);
     /// @notice A `ConfidentialConfig` the token refuses (CTR-ZTH-04, CTR-ZTH-26).
     error BadInit();
     /// @notice `zetherWrapShield`: the public-equivalent of the deposit is not a whole number of shielded units.
@@ -83,8 +93,13 @@ interface IZetherToken {
     function shieldScale() external view returns (uint256);
     /// @notice The inner fee, `< 2^64` and `< maxDecryptableShielded`; never a function of `v` (CTR-ZTH-07).
     function confidentialFee() external view returns (uint256);
-    /// @notice The auditor key (`ITransferDisclosure.AUDITOR`), empty when off (CTR-ZTH-09).
+    /// @notice The auditor key (`ITransferDisclosure.AUDITOR`), empty exactly when `auditorMode()` is `NONE` (CTR-ZTH-09).
     function auditorKey() external view returns (bytes memory);
+    /// @notice `NONE`, `FULL` (every transfer includes the auditor) or `OPTIONAL` (the sender's choice per transfer).
+    function auditorMode() external view returns (ZetherTypes.AuditorMode);
+    /// @notice `BUNDLE` (`zetherTransfer` stores the record; `zetherTransferCompact`, `zetherTransferNoBundle` save gas)
+    ///         or `COMPACT` (`zetherTransfer` and `zetherTransferCompact` are commit-reveal; no-bundle and single refused).
+    function disclosureMode() external view returns (ZetherTypes.DisclosureMode);
     /// @notice The canonical `ZetherDisclosure` (stateless, shared), an implementation immutable (CTR-ZTH-43).
     function disclosure() external view returns (ITransferDisclosure);
     function verifier() external view returns (IZetherVerifier);
@@ -93,8 +108,8 @@ interface IZetherToken {
 
     // ------------------------------------------------------------------ state
 
-    /// @notice Raw record of `entryRef` for `disclosure()`: `B_1 ‖ … ‖ B_M` (single format, BUNDLE), the 32-byte hash
-    ///         (HASH), empty (NONE, unknown). `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
+    /// @notice Raw record of `entryRef` for `disclosure()`: `R = salt ‖ B_1 ‖ … ‖ B_M` (BUNDLE, the single format),
+    ///         `keccak256(R) ‖ memo` (commit-reveal, CTR-ZTH-50), empty (NONE, unknown). `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
     function transferEntry(bytes32 entryRef) external view returns (bytes memory);
     /// @notice Σ of every `acc` and `pending` exponent (shielded units); `totalSupply()` counts public units only.
     function totalShielded() external view returns (uint256);
@@ -123,14 +138,18 @@ interface IZetherToken {
 
     /// @notice Burns `amount · shieldScale` public units of the caller; `pending[ua] += [amount]G` (CTR-ZTH-35).
     function zetherShield(bytes calldata encodedY, uint256 amount) external;
-    /// @notice `M` recipients, one proof; stores the hash of the bundles (HASH, the default, CTR-ZTH-38).
+    /// @notice `M` recipients, one proof, the token's default (CTR-ZTH-38): the record stored (BUNDLE) on a `BUNDLE`
+    ///         token, commit-reveal (HASH: the commitment and the sender memo stored, the record in `TransferBundles`) on
+    ///         a `COMPACT` token.
     function zetherTransfer(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
         external returns (bytes32 entryRef);
-    function zetherTransferBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
+    /// @notice Commit-reveal (HASH) on every token: the commitment and the sender memo stored, the record in the event.
+    function zetherTransferCompact(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
         external returns (bytes32 entryRef);
+    /// @notice Stores nothing (NONE, disclosure off chain from calldata); `TransferEntryDisabled` on a `COMPACT` token.
     function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
         external returns (bytes32 entryRef);
-    /// @notice The single-recipient format, its bundle stored in full.
+    /// @notice The single-recipient format, its record stored in full; `TransferEntryDisabled` on a `COMPACT` token.
     function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
         external returns (bytes32 entryRef);
     /// @notice Proves the unshield statement, then mints `amount · shieldScale` public units to `to`.
diff --git a/smartcontracts/evm/src/zether/NormalZetherToken.sol b/smartcontracts/evm/src/zether/NormalZetherToken.sol
index f13566c..dec81d7 100644
--- a/smartcontracts/evm/src/zether/NormalZetherToken.sol
+++ b/smartcontracts/evm/src/zether/NormalZetherToken.sol
@@ -59,7 +59,7 @@ contract NormalZetherToken is NormalToken, ZetherLayer {
         (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
         (s[2], c[2]) = (this.zetherShield.selector, FEE_CLASS_ABSOLUTE);
         (s[3], c[3]) = (this.zetherTransfer.selector, FEE_CLASS_ABSOLUTE);
-        (s[4], c[4]) = (this.zetherTransferBundle.selector, FEE_CLASS_ABSOLUTE);
+        (s[4], c[4]) = (this.zetherTransferCompact.selector, FEE_CLASS_ABSOLUTE);
         (s[5], c[5]) = (this.zetherTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
         (s[6], c[6]) = (this.zetherTransferSingle.selector, FEE_CLASS_ABSOLUTE);
         (s[7], c[7]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);
diff --git a/smartcontracts/evm/src/zether/WrappedZetherToken.sol b/smartcontracts/evm/src/zether/WrappedZetherToken.sol
index e60335d..0601f03 100644
--- a/smartcontracts/evm/src/zether/WrappedZetherToken.sol
+++ b/smartcontracts/evm/src/zether/WrappedZetherToken.sol
@@ -138,7 +138,7 @@ contract WrappedZetherToken is WrappedToken, ZetherLayer {
         (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
         (s[6], c[6]) = (this.zetherShield.selector, FEE_CLASS_ABSOLUTE);
         (s[7], c[7]) = (this.zetherTransfer.selector, FEE_CLASS_ABSOLUTE);
-        (s[8], c[8]) = (this.zetherTransferBundle.selector, FEE_CLASS_ABSOLUTE);
+        (s[8], c[8]) = (this.zetherTransferCompact.selector, FEE_CLASS_ABSOLUTE);
         (s[9], c[9]) = (this.zetherTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
         (s[10], c[10]) = (this.zetherTransferSingle.selector, FEE_CLASS_ABSOLUTE);
         (s[11], c[11]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);
diff --git a/smartcontracts/evm/src/zether/ZetherDisclosure.sol b/smartcontracts/evm/src/zether/ZetherDisclosure.sol
index 2f7d91c..c033363 100644
--- a/smartcontracts/evm/src/zether/ZetherDisclosure.sol
+++ b/smartcontracts/evm/src/zether/ZetherDisclosure.sol
@@ -97,8 +97,9 @@ contract ZetherDisclosure is ITransferDisclosure {
         return _isO(l.v.g1Msm(pts, sc));
     }
 
-    /// @dev `B_index` của `entryRef`: bản ghi của token, hoặc (mode HASH, 32 byte) `bundles` sau khi khớp hash.
-    ///      Token không ghi gì (mode NONE, ref lạ) ⇒ `UnknownEntry`. Transfer một người nhận: chỉ `index = 0`.
+    /// @dev `B_index` của `entryRef` trong `R = salt(16) ‖ B_1 ‖ … ‖ B_M`: bản ghi của token, hoặc (commit-reveal: token trả
+    ///      `keccak256(R) ‖ memo`, độ dài `49 + 40·M` không bao giờ bằng `16 + 4P·M`) `R` do người gọi đưa sau khi khớp
+    ///      hash. Token không ghi gì (NONE, ref lạ) ⇒ `UnknownEntry`. Transfer một người nhận: chỉ `index = 0`.
     function _leg(address token, bytes32 entryRef, uint256 index, bytes calldata bundles)
         private view returns (Leg memory l)
     {
@@ -107,13 +108,13 @@ contract ZetherDisclosure is ITransferDisclosure {
         l.r = l.v.groupOrder();
         bytes memory all = IZetherToken(token).transferEntry(entryRef);
         if (all.length == 0) revert UnknownEntry(entryRef);
-        if (all.length == 32) {
+        uint256 len = 4 * l.p;
+        if ((all.length - 16) % len != 0) {
             if (keccak256(bundles) != bytes32(all)) revert BundlesMismatch(entryRef);
             all = bundles;
         }
-        uint256 len = 4 * l.p;
-        if ((index + 1) * len > all.length) revert BadRecipientIndex(index);
-        uint256 o = index * len;
+        if (16 + (index + 1) * len > all.length) revert BadRecipientIndex(index);
+        uint256 o = 16 + index * len;
         (l.yt, l.cOut, l.dOut, l.cAud) =
             (_cut(all, o, l.p), _cut(all, o + l.p, l.p), _cut(all, o + 2 * l.p, l.p), _cut(all, o + 3 * l.p, l.p));
     }
diff --git a/smartcontracts/evm/src/zether/ZetherLayer.sol b/smartcontracts/evm/src/zether/ZetherLayer.sol
index ee4adf9..d25cfe9 100644
--- a/smartcontracts/evm/src/zether/ZetherLayer.sol
+++ b/smartcontracts/evm/src/zether/ZetherLayer.sol
@@ -16,7 +16,8 @@ import {ZetherLib} from "./ZetherLib.sol";
 /// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only (`ZetherSafety`, CTR-ZTH-02). A layer over the
 ///         public ERC-20 balance: `zetherShield` burns public units, `zetherUnshield` mints them; the confidential layer
 ///         keeps no underlying of its own. The registry and the disclosure contract are implementation immutables; the
-///         verifier (the curve) and the auditor key are chosen at creation. Every entry point is `nonReentrant`.
+///         verifier (the curve), the auditor key and the two modes (`disclosureMode`, `auditorMode`) are chosen at
+///         creation and never change. Every entry point is `nonReentrant`.
 abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
     address internal immutable _REGISTRY;
     ITransferDisclosure private immutable _DISCLOSURE;
@@ -41,12 +42,14 @@ abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
     function maxDecryptableShielded() external view returns (uint256) { return ZetherLib.$().maxShielded; }
     function confidentialFee() external view returns (uint256) { return ZetherLib.$().confidentialFee; }
     function auditorKey() external view returns (bytes memory) { return ZetherLib.$().auditorKey; }
+    function auditorMode() external view returns (ZetherTypes.AuditorMode) { return ZetherLib.$().auditorMode; }
+    function disclosureMode() external view returns (ZetherTypes.DisclosureMode) { return ZetherLib.$().disclosureMode; }
     function totalShielded() external view returns (uint256) { return ZetherLib.$().totalShielded; }
-    /// @notice The raw record for `disclosure()`: the bundles (single format, BUNDLE), the 32-byte hash (HASH, stored in
+    /// @notice The raw record for `disclosure()`: `R` (BUNDLE, single), `keccak256(R) ‖ memo` (commit-reveal; the hash in
     ///         one slot), empty (NONE, unknown).
     function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
         bytes32 h = ZetherLib.$().entryHashes[entryRef];
-        return h != bytes32(0) ? abi.encodePacked(h) : ZetherLib.$().entries[entryRef];
+        return h != bytes32(0) ? abi.encodePacked(h, ZetherLib.$().memos[entryRef]) : ZetherLib.$().entries[entryRef];
     }
     function sendCounter(ZetherTypes.UA ua) external view returns (uint256) { return ZetherLib.$().acct[ua].sendCounter; }
 
@@ -81,16 +84,17 @@ abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
 
     // ------------------------------------------------------------------ transfer (CTR-ZTH-37, CTR-ZTH-38)
 
+    /// @notice The token's default: the record stored (`BUNDLE` token) or commit-reveal (`COMPACT` token).
     function zetherTransfer(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
         external nonReentrant returns (bytes32)
     {
-        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.HASH, _env());
+        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherLib.defaultMode(), _env());
     }
 
-    function zetherTransferBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
+    function zetherTransferCompact(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
         external nonReentrant returns (bytes32)
     {
-        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.BUNDLE, _env());
+        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.HASH, _env());
     }
 
     function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
@@ -164,7 +168,7 @@ abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
     ///      listed (they carry their own signature or none).
     function _isZetherOp(bytes4 sel) internal pure returns (bool) {
         return sel == this.zetherShield.selector || sel == this.zetherTransfer.selector
-            || sel == this.zetherTransferBundle.selector || sel == this.zetherTransferNoBundle.selector
+            || sel == this.zetherTransferCompact.selector || sel == this.zetherTransferNoBundle.selector
             || sel == this.zetherTransferSingle.selector || sel == this.zetherUnshield.selector;
     }
 
diff --git a/smartcontracts/evm/src/zether/ZetherLib.sol b/smartcontracts/evm/src/zether/ZetherLib.sol
index a73db32..ae7e54e 100644
--- a/smartcontracts/evm/src/zether/ZetherLib.sol
+++ b/smartcontracts/evm/src/zether/ZetherLib.sol
@@ -34,6 +34,9 @@ library ZetherLib {
     /// @custom:storage-location erc7201:scaas.zether
     struct ZetherStorage {
         IZetherVerifier verifier;
+        /// @dev Both modes share the verifier's slot (the offsets of the fields below are unchanged).
+        ZetherTypes.DisclosureMode disclosureMode;
+        ZetherTypes.AuditorMode auditorMode;
         uint256 shieldScale;
         uint256 maxShielded;
         uint256 confidentialFee;
@@ -42,10 +45,12 @@ library ZetherLib {
         bytes32 psid;
         uint256 p;
         mapping(ZetherTypes.UA => Account) acct;
-        /// @dev `B_1 ‖ … ‖ B_M` (single format, BUNDLE); NONE writes nothing.
+        /// @dev The record `R = salt ‖ B_1 ‖ … ‖ B_M` (BUNDLE, the single format); NONE writes nothing.
         mapping(bytes32 => bytes) entries;
-        /// @dev HASH: `keccak256(B_1 ‖ … ‖ B_M)` in one slot (CTR-ZTH-38).
+        /// @dev Commit-reveal (HASH): `keccak256(R)` in one slot (CTR-ZTH-38).
         mapping(bytes32 => bytes32) entryHashes;
+        /// @dev Next to every commitment: the sender memo (CTR-ZTH-50), as given.
+        mapping(bytes32 => bytes) memos;
     }
 
     /// @notice The token's immutables a call needs, and the statement's binding: `(ZTX_V1_DIRECT, 0)` for a direct
@@ -70,6 +75,8 @@ library ZetherLib {
         uint256 fee;
         uint256 maxShielded;
         bytes auditorKey;
+        ZetherTypes.AuditorMode auditorMode;
+        ZetherTypes.DisclosureMode disclosureMode;
         bytes32 tag;
         bytes32 binding;
     }
@@ -89,6 +96,10 @@ library ZetherLib {
         bytes statement;
         uint256 fee;
         uint64 sendCounter;
+        /// @dev The payload's salt (CTR-ZTH-30, header word 13) and, on commit-reveal, `keccak256(memo)` (CTR-ZTH-50,
+        ///      header word 14); both 0 for an unshield.
+        bytes16 salt;
+        bytes32 memoHash;
         ZetherTypes.UA[] to; // multi-recipient only
     }
 
@@ -109,6 +120,10 @@ library ZetherLib {
     bytes32 private constant TAG_SET_MODE = keccak256("ZETHER_SET_ROLLOVER_MODE_V1");
     bytes private constant AUTH_TAG = "SCAAS-ZETHER-AUTH-V1";
     uint256 private constant MAX_RECIPIENTS = 16;
+    /// @dev Where the points start: the single payload after `accSeq ‖ sendCounter ‖ salt(16)`, the multi-recipient one
+    ///      after `… ‖ salt(16) ‖ be32(M)` (zether.md §9, §11).
+    uint256 private constant S_PTS = 80;
+    uint256 private constant M_PTS = 112;
     uint256 private constant MAX_TOTAL_SHIELDED = 1 << 54;
     /// @dev `2^n_v` (n_v = 64, CTR-ZTH-18): the bound of `confidentialFee`.
     uint256 private constant VALUE_BOUND = 1 << 64;
@@ -120,7 +135,9 @@ library ZetherLib {
     // ------------------------------------------------------------------ init
 
     /// @notice The kind's `_init` (dev chains only, CTR-ZTH-02): verifier, scale, cap `≤ 2^54`, inner fee `< 2^64` and
-    ///         `< cap`, auditor key empty or a valid point `≠ O` of the verifier's curve; `cap · scale` must not overflow.
+    ///         `< cap`, auditor key empty or a valid point `≠ O` of the verifier's curve; `cap · scale` must not overflow;
+    ///         `disclosureMode` BUNDLE or COMPACT (CTR-ZTH-48), `auditorMode` NONE without a key, FULL or OPTIONAL with
+    ///         one (CTR-ZTH-49).
     function init(IFactoryToken.ConfidentialConfig calldata c) public {
         ZetherSafety.requireDevChain();
         IZetherVerifier v = IZetherVerifier(c.verifier);
@@ -132,8 +149,15 @@ library ZetherLib {
             revert IZetherToken.BadInit();
         }
         if (c.maxShielded > type(uint256).max / c.shieldScale) revert IZetherToken.BadInit();
+        if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) revert IZetherToken.BadDisclosureMode(c.disclosureMode);
+        if (c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)
+            || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))) {
+            revert IZetherToken.BadAuditorMode(c.auditorMode);
+        }
         ZetherStorage storage s = $();
         s.verifier = v;
+        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);
+        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);
         s.shieldScale = c.shieldScale;
         s.maxShielded = c.maxShielded;
         s.confidentialFee = c.confidentialFee;
@@ -158,8 +182,9 @@ library ZetherLib {
 
     // ------------------------------------------------------------------ transfer
 
-    /// @notice The single-recipient format: checks, authority, proof, then `acc_f −= (C_deb + [fee]G, D_out)`,
-    ///         `pend_t += (C_out, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++`; the bundle stored in full.
+    /// @notice The single-recipient format (BUNDLE tokens only): checks, authority, proof, then
+    ///         `acc_f −= (C_deb + [fee]G, D_out)`, `pend_t += (C_out, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++`;
+    ///         the record `salt ‖ B` stored in full.
     function transferSingle(
         bytes calldata payload,
         bytes calldata proof,
@@ -182,19 +207,20 @@ library ZetherLib {
 
     function _settleSingle(Ctx memory c, Prepared memory pp, bytes calldata payload) private returns (bytes32 entryRef) {
         ZetherStorage storage s = $();
-        bytes calldata pts = payload[64:];
+        bytes calldata pts = payload[S_PTS:];
         uint256 p = c.p;
         ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
         _debit(c, s.acct[pp.from], pts[4 * p:5 * p], pts[3 * p:4 * p], pp.fee);
         _credit(s, to, pts[2 * p:3 * p], pts[3 * p:4 * p]);
         _payFee(s, c, pp);
         entryRef = _sent(s, c, pp);
-        s.entries[entryRef] = bytes.concat(pts[p:2 * p], pts[2 * p:4 * p], pts[5 * p:6 * p]);
+        s.entries[entryRef] = bytes.concat(pp.salt, pts[p:2 * p], pts[2 * p:4 * p], pts[5 * p:6 * p]);
         emit IZetherToken.ZetherTransfer(pp.from, to, pp.beneficiary, pp.fee, pp.sendCounter, entryRef);
     }
 
     /// @notice `M` recipients, one proof (CTR-ZTH-37/38): `acc_f −= (C_deb + [fee]G, D_out)`, every
-    ///         `pend_tj += (C_out_j, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++` once; the bundles by `mode`.
+    ///         `pend_tj += (C_out_j, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++` once; the record by `mode` (the stored
+    ///         form, CTR-ZTH-38), which a `COMPACT` token allows only as HASH.
     function transferMulti(
         bytes calldata payload,
         bytes calldata proof,
@@ -221,19 +247,19 @@ library ZetherLib {
     {
         ZetherStorage storage s = $();
         uint256 p = c.p;
-        _debit(c, s.acct[pp.from], payload[96 + 2 * p:96 + 3 * p], payload[96 + p:96 + 2 * p], pp.fee);
+        _debit(c, s.acct[pp.from], payload[M_PTS + 2 * p:M_PTS + 3 * p], payload[M_PTS + p:M_PTS + 2 * p], pp.fee);
         _creditLegs(s, pp.to, payload, p);
         _payFee(s, c, pp);
         entryRef = _sent(s, c, pp);
-        if (mode != ZetherTypes.TransferMode.NONE) _storeBundles(s, p, entryRef, payload, pp.to.length, mode);
+        if (mode != ZetherTypes.TransferMode.NONE) _storeRecord(s, p, entryRef, payload, pp, mode);
         emit IZetherToken.ZetherTransferMulti(pp.from, pp.beneficiary, pp.fee, pp.sendCounter, entryRef, pp.to, mode);
     }
 
     /// @dev Every `pend_tj += (C_out_j, D_out)`, decoys included.
     function _creditLegs(ZetherStorage storage s, ZetherTypes.UA[] memory to, bytes calldata payload, uint256 p) private {
-        bytes calldata dOut = payload[96 + p:96 + 2 * p];
+        bytes calldata dOut = payload[M_PTS + p:M_PTS + 2 * p];
         for (uint256 j; j < to.length; ++j) {
-            uint256 o = 96 + 3 * p * (j + 1);
+            uint256 o = M_PTS + 3 * p * (j + 1);
             _credit(s, to[j], payload[o + p:o + 2 * p], dOut);
         }
     }
@@ -346,6 +372,8 @@ library ZetherLib {
         c.fee = s.confidentialFee;
         c.maxShielded = s.maxShielded;
         c.auditorKey = s.auditorKey;
+        c.auditorMode = s.auditorMode;
+        c.disclosureMode = s.disclosureMode;
         c.tag = e.tag;
         c.binding = e.binding;
     }
@@ -354,6 +382,13 @@ library ZetherLib {
         return Acct(_pt(a.accC, p), _pt(a.accD, p), a.accSeq, a.sendCounter);
     }
 
+    /// @notice The form `zetherTransfer` takes: BUNDLE on a `BUNDLE` token, HASH (commit-reveal) on a `COMPACT` token.
+    function defaultMode() internal view returns (ZetherTypes.TransferMode) {
+        return $().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
+            ? ZetherTypes.TransferMode.HASH
+            : ZetherTypes.TransferMode.BUNDLE;
+    }
+
     /// @notice `ZTX_V1_RELAYED` for a non-zero envelope binding, else `ZTX_V1_DIRECT`.
     function tagOf(bytes32 binding) internal pure returns (bytes32) {
         return binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED;
@@ -371,19 +406,24 @@ library ZetherLib {
         return keccak256(abi.encode(TAG_ENTRY, block.chainid, c.chainUid, c.token, from, uint256(counter)));
     }
 
-    /// @notice Single format: `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud`.
+    /// @notice Single format: `be32(accSeq) ‖ be32(sendCounter) ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud`.
     function singleFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
-        if (payload.length != 64 + 6 * p) revert IZetherToken.BadPayload(payload.length);
-        return ZetherTypes.toUA(payload[64:64 + p]);
+        if (payload.length != S_PTS + 6 * p) revert IZetherToken.BadPayload(payload.length);
+        return ZetherTypes.toUA(payload[S_PTS:S_PTS + p]);
     }
 
-    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
+    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ salt(16) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`,
+    ///         then the sender memo (`17 + 40·M` bytes, CTR-ZTH-50) on commit-reveal only (checked by the form,
+    ///         `prepareMulti`).
     function multiFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
-        if (payload.length < 96 + 3 * p) revert IZetherToken.BadPayload(payload.length);
-        uint256 m = uint256(bytes32(payload[64:96]));
+        if (payload.length < M_PTS + 3 * p) revert IZetherToken.BadPayload(payload.length);
+        uint256 m = uint256(bytes32(payload[80:M_PTS]));
         if (m == 0 || m > MAX_RECIPIENTS) revert IZetherToken.BadRecipientCount(m);
-        if (payload.length != 96 + 3 * p * (1 + m)) revert IZetherToken.BadPayload(payload.length);
-        return ZetherTypes.toUA(payload[96:96 + p]);
+        uint256 legsEnd = M_PTS + 3 * p * (1 + m);
+        if (payload.length != legsEnd && payload.length != legsEnd + 17 + 40 * m) {
+            revert IZetherToken.BadPayload(payload.length);
+        }
+        return ZetherTypes.toUA(payload[M_PTS:M_PTS + p]);
     }
 
     /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f`.
@@ -392,12 +432,15 @@ library ZetherLib {
         return ZetherTypes.toUA(payload[64:64 + p]);
     }
 
-    /// @notice Every cheap check before verification: self, registration, fee, `accSeq`, `sendCounter`.
+    /// @notice Every cheap check before verification: the mode, self, registration, fee, `accSeq`, `sendCounter`.
     function prepareSingle(Ctx memory c, Acct memory a, bytes calldata payload, ZetherTypes.UA beneficiary)
         internal view returns (Prepared memory pp)
     {
+        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT) {
+            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
+        }
         uint256 p = c.p;
-        bytes calldata pts = payload[64:];
+        bytes calldata pts = payload[S_PTS:];
         pp.from = ZetherTypes.toUA(pts[0:p]);
         ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
         if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert IZetherToken.SelfTransfer();
@@ -406,13 +449,15 @@ library ZetherLib {
         pp.beneficiary = beneficiary;
         pp.fee = _innerFee(c, beneficiary);
         pp.sendCounter = _checkSeqs(a, payload);
+        pp.salt = bytes16(payload[64:S_PTS]);
         pp.statement = bytes.concat(
-            _header(c, OP_TRANSFER, c.psid, a, pp.fee, beneficiary, 0, address(0)),
+            _header(c, OP_TRANSFER, c.psid, a, pp, 0, address(0)),
             pts[0:2 * p], _auditorPoint(c, _isO(pts[5 * p:6 * p]) ? 1 : 0, 1), a.accC, a.accD, pts[2 * p:6 * p]
         );
     }
 
-    /// @notice As `prepareSingle`, for `M` recipients: pairwise distinct, none the sender, all registered.
+    /// @notice As `prepareSingle`, for `M` recipients: pairwise distinct, none the sender, all registered; a `COMPACT`
+    ///         token takes HASH only; the memo exactly on HASH, its hash in the header.
     function prepareMulti(
         Ctx memory c,
         Acct memory a,
@@ -420,14 +465,23 @@ library ZetherLib {
         ZetherTypes.UA beneficiary,
         ZetherTypes.TransferMode mode
     ) internal view returns (Prepared memory pp) {
+        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {
+            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
+        }
         uint256 p = c.p;
-        pp.from = ZetherTypes.toUA(payload[96:96 + p]);
+        pp.from = ZetherTypes.toUA(payload[M_PTS:M_PTS + p]);
         _requireRegistered(c, pp.from);
-        pp.to = _recipients(c, payload, pp.from, uint256(bytes32(payload[64:96])));
+        pp.to = _recipients(c, payload, pp.from, uint256(bytes32(payload[80:M_PTS])));
         pp.beneficiary = beneficiary;
         pp.fee = _innerFee(c, beneficiary);
         pp.sendCounter = _checkSeqs(a, payload);
-        pp.statement = _multiStatement(c, a, payload, pp.fee, beneficiary, mode);
+        pp.salt = bytes16(payload[64:80]);
+        bytes calldata memo = payload[M_PTS + 3 * p * (1 + pp.to.length):];
+        if (memo.length != (mode == ZetherTypes.TransferMode.HASH ? 17 + 40 * pp.to.length : 0)) {
+            revert IZetherToken.BadPayload(payload.length);
+        }
+        if (memo.length != 0) pp.memoHash = keccak256(memo);
+        pp.statement = _multiStatement(c, a, payload, pp, mode);
     }
 
     /// @notice `0 < amount ≤ maxShielded` before the statement (`amount + fee < 2^65 < r`), recipient non-zero.
@@ -448,26 +502,21 @@ library ZetherLib {
         pp.fee = _innerFee(c, beneficiary);
         pp.sendCounter = _checkSeqs(a, payload);
         pp.statement = bytes.concat(
-            _header(c, OP_BURN, c.psid, a, pp.fee, beneficiary, amount, recipient), payload[64:64 + p], a.accC, a.accD
+            _header(c, OP_BURN, c.psid, a, pp, amount, recipient), payload[64:64 + p], a.accC, a.accD
         );
     }
 
     // ------------------------------------------------------------------ internals
 
-    /// @dev The 416-byte header (zether.md §7), `chainUid` at word 3.
-    function _header(
-        Ctx memory c,
-        bytes32 op,
-        bytes32 psid,
-        Acct memory a,
-        uint256 fee,
-        ZetherTypes.UA beneficiary,
-        uint256 amount,
-        address recipient
-    ) private view returns (bytes memory) {
+    /// @dev The 480-byte header (zether.md §7): `chainUid` at word 3, the salt at word 13 (16 zero bytes ‖ salt,
+    ///      CTR-ZTH-30), `memoHash` at word 14 (CTR-ZTH-50): both are in what the sender proves and signs, so a relayer
+    ///      can neither alter nor drop them.
+    function _header(Ctx memory c, bytes32 op, bytes32 psid, Acct memory a, Prepared memory pp, uint256 amount, address recipient)
+        private view returns (bytes memory)
+    {
         return bytes.concat(
-            abi.encode(op, psid, block.chainid, c.chainUid, c.token, c.tag, c.binding),
-            abi.encode(uint256(a.sendCounter), uint256(a.accSeq), fee, beneficiary, amount, recipient)
+            abi.encode(op, psid, block.chainid, c.chainUid, c.token, c.tag, c.binding, uint256(a.sendCounter)),
+            abi.encode(uint256(a.accSeq), pp.fee, pp.beneficiary, amount, recipient, uint128(pp.salt), pp.memoHash)
         );
     }
 
@@ -476,8 +525,7 @@ library ZetherLib {
         Ctx memory c,
         Acct memory a,
         bytes calldata payload,
-        uint256 fee,
-        ZetherTypes.UA beneficiary,
+        Prepared memory pp,
         ZetherTypes.TransferMode mode
     ) private view returns (bytes memory) {
         uint256 p = c.p;
@@ -485,10 +533,11 @@ library ZetherLib {
             ? OP_MULTI_HASH
             : mode == ZetherTypes.TransferMode.BUNDLE ? OP_MULTI_BUNDLE : OP_MULTI_NONE;
         bytes memory head = bytes.concat(
-            _header(c, op, c.ver.proofSystemIdMulti(), a, fee, beneficiary, 0, address(0)),
-            payload[96:96 + p], _auditorPoint(c, _audOff(payload, p), uint256(bytes32(payload[64:96]))), a.accC, a.accD
+            _header(c, op, c.ver.proofSystemIdMulti(), a, pp, 0, address(0)),
+            payload[M_PTS:M_PTS + p], _auditorPoint(c, _audOff(payload, p, pp.to.length), pp.to.length), a.accC, a.accD
         );
-        return bytes.concat(head, payload[96 + p:96 + 3 * p], payload[64:96], payload[96 + 3 * p:]);
+        head = bytes.concat(head, payload[M_PTS + p:M_PTS + 3 * p], payload[80:M_PTS]);
+        return bytes.concat(head, payload[M_PTS + 3 * p:M_PTS + 3 * p * (1 + pp.to.length)]);
     }
 
     /// @dev The recipients: none the sender, pairwise distinct, registered.
@@ -498,7 +547,7 @@ library ZetherLib {
         uint256 p = c.p;
         to = new ZetherTypes.UA[](m);
         for (uint256 j; j < m; ++j) {
-            uint256 o = 96 + 3 * p * (j + 1);
+            uint256 o = M_PTS + 3 * p * (j + 1);
             to[j] = ZetherTypes.toUA(payload[o:o + p]);
             bytes32 t = ZetherTypes.UA.unwrap(to[j]);
             if (t == ZetherTypes.UA.unwrap(from)) revert IZetherToken.SelfTransfer();
@@ -579,42 +628,51 @@ library ZetherLib {
         emit IZetherToken.RolledOver(ua, a.accSeq);
     }
 
-    function _storeBundles(
+    /// @dev BUNDLE: the record `R` stored; HASH (commit-reveal): `keccak256(R)` in one slot, the sender memo next to it,
+    ///      `R` in `TransferBundles` (CTR-ZTH-38, CTR-ZTH-50).
+    function _storeRecord(
         ZetherStorage storage s,
         uint256 p,
         bytes32 entryRef,
         bytes calldata payload,
-        uint256 m,
+        Prepared memory pp,
         ZetherTypes.TransferMode mode
     ) private {
-        bytes memory bundles = _bundles(payload[96 + 3 * p:], payload[96 + p:96 + 2 * p], m, p);
+        uint256 legsEnd = M_PTS + 3 * p * (1 + pp.to.length);
+        bytes memory r = _record(pp.salt, payload[M_PTS + 3 * p:legsEnd], payload[M_PTS + p:M_PTS + 2 * p], p);
         if (mode == ZetherTypes.TransferMode.BUNDLE) {
-            s.entries[entryRef] = bundles;
+            s.entries[entryRef] = r;
         } else {
-            s.entryHashes[entryRef] = keccak256(bundles);
-            emit IZetherToken.TransferBundles(entryRef, bundles);
+            s.entryHashes[entryRef] = keccak256(r);
+            s.memos[entryRef] = payload[legsEnd:];
+            emit IZetherToken.TransferBundles(entryRef, r);
         }
     }
 
-    /// @dev `B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
-    function _bundles(bytes calldata legs, bytes calldata dOut, uint256 m, uint256 p) private pure returns (bytes memory b) {
-        for (uint256 j; j < m; ++j) {
-            uint256 o = 3 * p * j;
+    /// @dev `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
+    function _record(bytes16 salt, bytes calldata legs, bytes calldata dOut, uint256 p) private pure returns (bytes memory b) {
+        b = abi.encodePacked(salt);
+        for (uint256 o; o < legs.length; o += 3 * p) {
             b = bytes.concat(b, legs[o:o + 2 * p], dOut, legs[o + 2 * p:o + 3 * p]);
         }
     }
 
-    /// @dev `Y_a` of the statement (CTR-ZTH-42): the key when every `C_aud_j ≠ O`, `O` when every one is `O` or the
-    ///      token has no auditor (the verifier then requires every `C_aud_j = O`); a mix reverts.
+    /// @dev `Y_a` of the statement (CTR-ZTH-42) by the token's auditor mode: `NONE` takes every `C_aud_j = O` (`Y_a = O`);
+    ///      `FULL` every `C_aud_j ≠ O` (the key); `OPTIONAL` either, all or nothing across the legs (a mix reverts).
     function _auditorPoint(Ctx memory c, uint256 nOff, uint256 m) private pure returns (bytes memory) {
-        if (c.auditorKey.length == 0 || nOff == m) return new bytes(c.p);
-        if (nOff != 0) revert IZetherToken.AuditorLegsMixed();
-        return c.auditorKey;
+        if (c.auditorMode == ZetherTypes.AuditorMode.NONE) {
+            if (nOff != m) revert IZetherToken.AuditorForbidden();
+            return new bytes(c.p);
+        }
+        if (nOff == 0) return c.auditorKey;
+        if (c.auditorMode == ZetherTypes.AuditorMode.FULL) revert IZetherToken.AuditorRequired();
+        if (nOff != m) revert IZetherToken.AuditorLegsMixed();
+        return new bytes(c.p);
     }
 
-    /// @dev Number of legs with `C_aud_j = O`.
-    function _audOff(bytes calldata payload, uint256 p) private pure returns (uint256 n) {
-        for (uint256 o = 96 + 6 * p; o <= payload.length; o += 3 * p) if (_isO(payload[o - p:o])) ++n;
+    /// @dev Number of the `m` legs with `C_aud_j = O`.
+    function _audOff(bytes calldata payload, uint256 p, uint256 m) private pure returns (uint256 n) {
+        for (uint256 o = M_PTS + 6 * p; o <= M_PTS + 3 * p * (1 + m); o += 3 * p) if (_isO(payload[o - p:o])) ++n;
     }
 
     /// @dev The stored point, or `O` when never written.
diff --git a/smartcontracts/evm/src/zether/ZetherStatements.sol b/smartcontracts/evm/src/zether/ZetherStatements.sol
index 283e8e1..f104e50 100644
--- a/smartcontracts/evm/src/zether/ZetherStatements.sol
+++ b/smartcontracts/evm/src/zether/ZetherStatements.sol
@@ -9,12 +9,15 @@ import {ZetherLib} from "./ZetherLib.sol";
 /// @title The prover views of every Zether token (CTR-ZTH-46): the statement a token will build at this block.
 /// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Stateless, no admin, no upgrade, one instance for every token on
 ///         every curve (as `ZetherDisclosure`). It reads the token's views (`verifier`, `registry`, `chainUid`,
-///         `confidentialFee`, `maxDecryptableShielded`, `auditorKey`, `accountState`) and runs the token's own
-///         builders (`ZetherLib`, internal), so the bytes are the token's, with the same cheap checks. The caller picks
-///         the token it trusts. `envelopeBinding` 0 = a direct call (`ZTX_V1_DIRECT`), else the envelope's binding
+///         `confidentialFee`, `maxDecryptableShielded`, `auditorKey`, `auditorMode`, `disclosureMode`, `accountState`)
+///         and runs the token's own builders (`ZetherLib`, internal), so the bytes are the token's, with the same cheap
+///         checks. The caller picks the token it trusts. `envelopeBinding` 0 = a direct call (`ZTX_V1_DIRECT`), else the envelope's binding
 ///         (`ZTX_V1_RELAYED`, `IZetherToken.envelopeBinding`).
 contract ZetherStatements {
-    /// @notice The multi-recipient statement (`zetherTransfer`, `…Bundle`, `…NoBundle` by `mode`).
+    /// @notice The multi-recipient statement by its stored form `mode`: BUNDLE (`zetherTransfer` on a `BUNDLE` token), HASH
+    ///         (`zetherTransferCompact`, and `zetherTransfer` on a `COMPACT` token; the payload ends with the memo), NONE
+    ///         (`zetherTransferNoBundle`); `TransferEntryDisabled` for a form other than HASH on a `COMPACT` token, the
+    ///         auditor errors by `auditorMode`.
     function transferStatement(
         address token,
         bytes calldata payload,
@@ -99,6 +102,8 @@ contract ZetherStatements {
         c.fee = t.confidentialFee();
         c.maxShielded = t.maxDecryptableShielded();
         c.auditorKey = t.auditorKey();
+        c.auditorMode = t.auditorMode();
+        c.disclosureMode = t.disclosureMode();
         c.tag = tag;
         c.binding = binding;
     }
diff --git a/smartcontracts/evm/src/zether/ZetherTypes.sol b/smartcontracts/evm/src/zether/ZetherTypes.sol
index f885616..4ca73f5 100644
--- a/smartcontracts/evm/src/zether/ZetherTypes.sol
+++ b/smartcontracts/evm/src/zether/ZetherTypes.sol
@@ -23,9 +23,23 @@ library ZetherTypes {
 
     /// Nơi giữ bundle tiết lộ của một transfer nhiều người nhận (nằm trong opTag, relayer không đổi được).
     enum TransferMode {
-        HASH,   // mặc định: lưu keccak256(B_1 ‖ … ‖ B_M), bundle phát trong event
-        BUNDLE, // lưu B_1 ‖ … ‖ B_M
-        NONE    // không lưu: tiết lộ off-chain từ calldata
+        HASH,   // commit-reveal (`zetherTransferCompact`; `zetherTransfer` trên token COMPACT): keccak256(R) một slot +
+                // memo người gửi, R = salt ‖ B_1 ‖ … ‖ B_M phát trong event
+        BUNDLE, // `zetherTransfer` trên token BUNDLE: lưu R
+        NONE    // `zetherTransferNoBundle`: không lưu, tiết lộ off-chain từ calldata
+    }
+
+    /// Cách lưu bundle của token, cố định từ `initialize` (CTR-ZTH-38).
+    enum DisclosureMode {
+        BUNDLE, // mặc định: `zetherTransfer` lưu R, `…Compact` / `…NoBundle` tiết kiệm gas; single lưu R
+        COMPACT // mọi transfer là commit-reveal (`zetherTransfer` = `…Compact`); `…NoBundle` và single bị từ chối
+    }
+
+    /// Auditor của token, cố định từ `initialize` (CTR-ZTH-09, CTR-ZTH-42).
+    enum AuditorMode {
+        NONE,    // không khoá auditor: mọi C_aud = O
+        FULL,    // có khoá: mọi transfer phải có auditor (mọi C_aud ≠ O)
+        OPTIONAL // có khoá: người gửi được bỏ auditor theo transfer (mọi C_aud = O hoặc không cái nào)
     }
 
     function toUA(bytes memory encodedY) internal pure returns (UA) {
diff --git a/smartcontracts/evm/src/zether/ZetherVerifier.sol b/smartcontracts/evm/src/zether/ZetherVerifier.sol
index 40d58c5..5b0b81a 100644
--- a/smartcontracts/evm/src/zether/ZetherVerifier.sol
+++ b/smartcontracts/evm/src/zether/ZetherVerifier.sol
@@ -24,8 +24,9 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
     uint256 internal constant MAX_RECIPIENTS = 16;
     uint256 internal constant NV = 64; // limits D1 (RS-NV64-1)
     uint256 internal constant NB = 64;
-    /// @dev Statement header (zether.md §7): 13 words, `chainUid` the 4th (CTR-ZTH-36); `fee` and `amount` are read here.
-    uint256 internal constant HEADER = 416;
+    /// @dev Statement header (zether.md §7): 15 words, `chainUid` the 4th (CTR-ZTH-36), the salt the 14th (CTR-ZTH-30),
+    ///      `memoHash` the 15th (CTR-ZTH-50); `fee` and `amount` are read here.
+    uint256 internal constant HEADER = 480;
     uint256 internal constant FEE_AT = 288;
     uint256 internal constant AMOUNT_AT = 352;
     uint256 internal constant NGEN = 130; // h, U, G_0..63, H_0..63
@@ -180,7 +181,7 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
         (x.st, x.c) = T.challenge(x.st, "sigma.c", x.r);
     }
 
-    /// @dev Điểm thứ `i` của phần điểm statement (sau header 416 byte).
+    /// @dev Điểm thứ `i` của phần điểm statement (sau header 480 byte).
     function _sp(Ctx memory x, uint256 i) private pure returns (bytes memory) {
         return _slice(x.s, HEADER + i * x.p, x.p);
     }
@@ -575,7 +576,7 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
 ///         confidential trên public chain phải được giả định giải mã được trong khoảng 2035–2045.
 contract ZetherVerifierBn254 is ZetherVerifierBase {
     function _psidLabel() internal pure override returns (string memory) {
-        return "scaas/zether/sigma-bullets/bn254/n64-n64/v1";
+        return "scaas/zether/sigma-bullets/bn254/n64-n64/v2";
     }
 
     function curveName() external pure returns (string memory) { return "bn254"; }
@@ -618,7 +619,7 @@ contract ZetherVerifierBls12381 is ZetherVerifierBase {
     bytes internal constant GEN_DST = "SCAAS-ZETHER-GEN-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
 
     function _psidLabel() internal pure override returns (string memory) {
-        return "scaas/zether/sigma-bullets/bls12-381/n64-n64/v1";
+        return "scaas/zether/sigma-bullets/bls12-381/n64-n64/v2";
     }
 
     function curveName() external pure returns (string memory) { return "bls12-381"; }
```

- [ ] **Step 2: the test changes** (apply the diff; the fixture gains `dMode` / `aMode` (default: BUNDLE, and
  `OPTIONAL` for a token with a key, the built behaviour every opt-out test relies on), `audForce`, the salt and
  `_memo(m)`; payload offsets move by 16; HASH proofs go through `zetherTransferCompact`):

```diff
diff --git a/smartcontracts/evm/test/v2/FactoryZether.t.sol b/smartcontracts/evm/test/v2/FactoryZether.t.sol
index 8f77447..a545cd7 100644
--- a/smartcontracts/evm/test/v2/FactoryZether.t.sol
+++ b/smartcontracts/evm/test/v2/FactoryZether.t.sol
@@ -178,7 +178,7 @@ contract FactoryZetherTest is Test {
         f.createToken(UZ, 1, c, "a");
     }
 
-    /// A public kind refuses every `conf` field, the two new ones included.
+    /// A public kind refuses every `conf` field, the two modes included.
     function test_publicKinds_refuseEveryConfField() public {
         OpenFactory g = new OpenFactory(registrar, UID_);
         NormalToken none = new NormalToken(address(g), address(0), UID_, false);
@@ -196,6 +196,14 @@ contract FactoryZetherTest is Test {
         c.conf.verifier = address(okVer);
         vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
         g.createToken(IOpenFactory.TokenKind.NORMAL, 1, c, "a");
+        c.conf.verifier = address(0);
+        c.conf.disclosureMode = 1;
+        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
+        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, c, "a");
+        c.conf.disclosureMode = 0;
+        c.conf.auditorMode = 1;
+        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
+        g.createToken(IOpenFactory.TokenKind.NORMAL, 1, c, "a");
     }
 
     /// CTR-MTX-02: the confidential kinds sign under "SCaaS ZetherToken", the public ones under "SCaaS MetaToken".
diff --git a/smartcontracts/evm/test/vectors/zether/generators_bls12381.json b/smartcontracts/evm/test/vectors/zether/generators_bls12381.json
index d58257b..609acab 100644
--- a/smartcontracts/evm/test/vectors/zether/generators_bls12381.json
+++ b/smartcontracts/evm/test/vectors/zether/generators_bls12381.json
@@ -1,6 +1,6 @@
 {
  "curve": "bls12381",
- "proofSystemId": "0x87f6843e3f9ef837578a87499bf0094169341ef82358817d2f2a25502c6e5f5d",
+ "proofSystemId": "0xa3ab9e33ec9df9e3825269609544c2297fc753fee898466f98bf34e20aaf3536",
  "h": "0x000000000000000000000000000000000a7bc97a0c4c3e37a4be57106ae428c4a56aefadaea3421110ca2993f68ff0425588cdb19ff491628e19310f925bcdf60000000000000000000000000000000012095790623f66413e7886d7d92471528fde76e44c0f483c987bf284bd27d4d5682e14bf7e8ff7bc75066fb1abe8d2b9",
  "U": "0x00000000000000000000000000000000132ae1e96c5088a78ec49340176fce84772684ca478a019b494fe2daa01d0c4a7795347cc1a0e204df8ea1c63abc71e900000000000000000000000000000000023b49bc1aa4de8639b7949ff04d98b47e88a22238f98915071a0ee4fc6b26e8a690bfb61f1b47c14fbdd7ced21aee60",
  "G": [
diff --git a/smartcontracts/evm/test/vectors/zether/generators_bn254.json b/smartcontracts/evm/test/vectors/zether/generators_bn254.json
index a530897..dba04fa 100644
--- a/smartcontracts/evm/test/vectors/zether/generators_bn254.json
+++ b/smartcontracts/evm/test/vectors/zether/generators_bn254.json
@@ -1,6 +1,6 @@
 {
  "curve": "bn254",
- "proofSystemId": "0xacc73a11033f169964b58ca141ba081641db22c5d4a46bc356a4e9d1e83d53a0",
+ "proofSystemId": "0x8decdb706f7dc6baf2cf3b9f91b845e0d79bea9ef54f04ff285cf6e0a733de49",
  "h": "0x1f5b2f4b53ea4b173b00eec464742c0013d39ed45fa833a8d5a7feae56c3403b0d194dd017288a46a78c44b90c6e92ef5098e6b29f1028d67d9c1ac09bc281f4",
  "U": "0x02b664c30ebff58b898c56aae146b14a3576cdd682866960852c6e9a0717851513b1e5b9c75c13a2e5e60024bd14fac87297b71d606acc66cd8e0a9f233686ac",
  "G": [
diff --git a/smartcontracts/evm/test/vectors/zether/kat.py b/smartcontracts/evm/test/vectors/zether/kat.py
index ccb8e41..3992d9b 100644
--- a/smartcontracts/evm/test/vectors/zether/kat.py
+++ b/smartcontracts/evm/test/vectors/zether/kat.py
@@ -102,8 +102,8 @@ def generators(curve):
     H = [g("H", i) for i in range(64)]
     blob = h + u + b"".join(G) + b"".join(H)
     psid = keccak(
-        b"scaas/zether/sigma-bullets/bn254/n64-n64/v1" if curve == "bn254"
-        else b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v1")  # n_v = n_b = 64 (RS-NV64-1)
+        b"scaas/zether/sigma-bullets/bn254/n64-n64/v2" if curve == "bn254"
+        else b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v2")  # n_v = n_b = 64 (RS-NV64-1); v2: the 480-byte header (P3b)
     return {
         "curve": curve, "proofSystemId": hx(psid), "h": hx(h), "U": hx(u),
         "G": [hx(p) for p in G], "H": [hx(p) for p in H], "blobKeccak": hx(keccak(blob)),
diff --git a/smartcontracts/evm/test/zether/UniversalAccountRegistry.t.sol b/smartcontracts/evm/test/zether/UniversalAccountRegistry.t.sol
index 8e253ea..905d6a3 100644
--- a/smartcontracts/evm/test/zether/UniversalAccountRegistry.t.sol
+++ b/smartcontracts/evm/test/zether/UniversalAccountRegistry.t.sol
@@ -47,6 +47,10 @@ contract UniversalAccountRegistryTest is Test {
         assertTrue(reg.isRegistered(a) && reg.isRegistered(b));
         assertEq(reg.keyLengthOf(a), 64);
         assertEq(reg.keyLengthOf(b), 128);
+        // the key itself, for a sender's storage-only recovery of a commit-reveal transfer (zether.md CTR-ZTH-50)
+        assertEq(keccak256(reg.keyOf(a)), ZetherTypes.UA.unwrap(a));
+        assertEq(keccak256(reg.keyOf(b)), ZetherTypes.UA.unwrap(b));
+        assertEq(reg.keyOf(ZetherTypes.UA.wrap(bytes32(uint256(1)))).length, 0, "unregistered: empty");
         assertEq(ZetherTypes.UA.unwrap(reg.links(address(this))), ZetherTypes.UA.unwrap(a));
         assertEq(reg.link_eth(a), address(this));
         assertEq(reg.link_eth(b), address(0));
diff --git a/smartcontracts/evm/test/zether/ZetherDeploy.t.sol b/smartcontracts/evm/test/zether/ZetherDeploy.t.sol
index fc5b72e..f1015d5 100644
--- a/smartcontracts/evm/test/zether/ZetherDeploy.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherDeploy.t.sol
@@ -66,7 +66,7 @@ contract ZetherDeployTest is Test {
         // a token from the deployed catalogue, on the deployed verifier
         IFactoryToken.TokenConfig memory c;
         (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
-        c.conf = IFactoryToken.ConfidentialConfig(bn, "", 1, 1 << 40, 0);
+        c.conf = IFactoryToken.ConfidentialConfig(bn, "", 1, 1 << 40, 0, 0, 0);
         ZetherLayer t = ZetherLayer(f.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, c, "z"));
         assertEq(address(t.verifier()), bn);
         assertEq(t.chainUid(), ZUID);
diff --git a/smartcontracts/evm/test/zether/ZetherInvariant.t.sol b/smartcontracts/evm/test/zether/ZetherInvariant.t.sol
index 953fc7a..aeaf6ed 100644
--- a/smartcontracts/evm/test/zether/ZetherInvariant.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherInvariant.t.sol
@@ -40,7 +40,7 @@ contract ZetherHandler is ZetherFixture {
         c.legs = new IFactoryToken.Leg[](2);
         c.legs[0] = IFactoryToken.Leg(address(leg[0]), 1, 1);
         c.legs[1] = IFactoryToken.Leg(address(leg[1]), 3, 7);
-        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, MAX, FEE);
+        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, MAX, FEE, 0, 0);
         w = WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, c, "inv")));
         tok = ZetherLayer(address(w));
         _users();
diff --git a/smartcontracts/evm/test/zether/ZetherMulti.t.sol b/smartcontracts/evm/test/zether/ZetherMulti.t.sol
index b511629..2318822 100644
--- a/smartcontracts/evm/test/zether/ZetherMulti.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherMulti.t.sol
@@ -28,14 +28,14 @@ abstract contract ZetherMultiSuite is ZetherFixture {
     }
 
     function _send(ZetherLayer t, ZetherTypes.TransferMode mode, Tx memory x, ZetherTypes.UA ben) internal returns (bytes32) {
-        if (mode == ZetherTypes.TransferMode.HASH) return t.zetherTransfer(x.payload, x.proof, "", ben);
-        if (mode == ZetherTypes.TransferMode.BUNDLE) return t.zetherTransferBundle(x.payload, x.proof, "", ben);
+        if (mode == ZetherTypes.TransferMode.HASH) return t.zetherTransferCompact(x.payload, x.proof, "", ben);
+        if (mode == ZetherTypes.TransferMode.BUNDLE) return t.zetherTransfer(x.payload, x.proof, "", ben);
         return t.zetherTransferNoBundle(x.payload, x.proof, "", ben);
     }
 
     function _selector(ZetherTypes.TransferMode mode) internal pure returns (bytes4) {
-        if (mode == ZetherTypes.TransferMode.HASH) return ZetherLayer.zetherTransfer.selector;
-        if (mode == ZetherTypes.TransferMode.BUNDLE) return ZetherLayer.zetherTransferBundle.selector;
+        if (mode == ZetherTypes.TransferMode.HASH) return ZetherLayer.zetherTransferCompact.selector;
+        if (mode == ZetherTypes.TransferMode.BUNDLE) return ZetherLayer.zetherTransfer.selector;
         return ZetherLayer.zetherTransferNoBundle.selector;
     }
 
@@ -48,13 +48,14 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         for (uint256 i; i < len; ++i) out[i] = a[off + i];
     }
 
-    /// @dev `B_1 ‖ … ‖ B_M` dựng lại từ payload (đúng thứ một client đọc được từ calldata).
+    /// @dev `R = salt ‖ B_1 ‖ … ‖ B_M` dựng lại từ payload (đúng thứ một client đọc được từ calldata).
     function _bundlesOf(bytes memory payload) internal view returns (bytes memory b) {
         uint256 p = ver.g1EncodedBytes();
-        uint256 m = (payload.length - 96 - 3 * p) / (3 * p);
-        bytes memory dOut = _cut(payload, 96 + p, p);
+        uint256 m = uint256(bytes32(_cut(payload, 80, 32)));
+        bytes memory dOut = _cut(payload, 112 + p, p);
+        b = _cut(payload, 64, 16);
         for (uint256 j; j < m; ++j) {
-            uint256 o = 96 + 3 * p + 3 * p * j;
+            uint256 o = 112 + 3 * p + 3 * p * j;
             b = bytes.concat(b, _cut(payload, o, 2 * p), dOut, _cut(payload, o + 2 * p, p));
         }
     }
@@ -144,6 +145,11 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         (vs[0], vs[1], vs[2], vs[3]) = (0, 300, 0, 50);
         uint256 seq = tok.accountState(rs[1].ua).pendingSeq;
         Tx memory t = _proveMulti(tok, alice, _to(4), vs, 1000, carol.ua, ZetherTypes.TransferMode.HASH);
+        ZetherTypes.UA[] memory uas = new ZetherTypes.UA[](4);
+        for (uint256 j; j < 4; ++j) uas[j] = rs[j].ua;
+        bytes32 expected = _ref(tok, alice, 0);
+        vm.expectEmit(true, true, false, true, address(tok));
+        emit IZetherToken.ZetherTransferMulti(alice.ua, carol.ua, FEE, 0, expected, uas, ZetherTypes.TransferMode.HASH);
         bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, carol.ua);
         assertEq(ref, _ref(tok, alice, 0), "entryRef carries chainUid (CTR-ZTH-36)");
         assertTrue(_holds(tok, alice, 1000 - 350 - FEE, true), "sender debited sum + fee");
@@ -178,47 +184,51 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         uint256 p = ver.g1EncodedBytes();
         // M = 0 and M = 17
         bytes memory pl = bytes.concat(t.payload);
-        pl[95] = bytes1(0);
+        pl[111] = bytes1(0);
         vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 0));
-        tok.zetherTransfer(pl, t.proof, "", _none());
-        pl[95] = bytes1(uint8(17));
+        tok.zetherTransferCompact(pl, t.proof, "", _none());
+        pl[111] = bytes1(uint8(17));
         vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 17));
-        tok.zetherTransfer(pl, t.proof, "", _none());
+        tok.zetherTransferCompact(pl, t.proof, "", _none());
         // M = 3 with two legs: length
-        pl[95] = bytes1(uint8(3));
+        pl[111] = bytes1(uint8(3));
         vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
-        tok.zetherTransfer(pl, t.proof, "", _none());
+        tok.zetherTransferCompact(pl, t.proof, "", _none());
         // duplicate recipient, self, unregistered
         User[] memory dup = _to(2);
         dup[1] = dup[0];
         Tx memory d = _proveMultiUnchecked(dup, vs);
         vm.expectRevert(abi.encodeWithSelector(IZetherToken.DuplicateRecipient.selector, rs[0].ua));
-        tok.zetherTransfer(d.payload, t.proof, "", _none());
+        tok.zetherTransferCompact(d.payload, t.proof, "", _none());
         User[] memory self = _to(2);
         self[1] = alice;
         d = _proveMultiUnchecked(self, vs);
         vm.expectRevert(IZetherToken.SelfTransfer.selector);
-        tok.zetherTransfer(d.payload, t.proof, "", _none());
+        tok.zetherTransferCompact(d.payload, t.proof, "", _none());
         User[] memory stranger = _to(2);
         stranger[1].y = _pubOf(0x5757);
         stranger[1].ua = ZetherTypes.toUA(stranger[1].y);
         d = _proveMultiUnchecked(stranger, vs);
         vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, stranger[1].ua));
-        tok.zetherTransfer(d.payload, t.proof, "", _none());
+        tok.zetherTransferCompact(d.payload, t.proof, "", _none());
         // tampered C_deb, C_out_2, C_aud_1
-        uint256[3] memory offs = [96 + 2 * p, 96 + 3 * p + 3 * p + p, 96 + 3 * p + 2 * p];
+        uint256[3] memory offs = [112 + 2 * p, 112 + 3 * p + 3 * p + p, 112 + 3 * p + 2 * p];
         for (uint256 i; i < 3; ++i) {
             bytes memory tampered = _replacePoint(t.payload, offs[i]);
             vm.expectRevert(IZetherToken.ProofRejected.selector);
-            tok.zetherTransfer(tampered, t.proof, "", _none());
+            tok.zetherTransferCompact(tampered, t.proof, "", _none());
         }
-        // a HASH proof under another mode
+        // a HASH proof under another form (`zetherTransfer` stores R on this BUNDLE token): with its memo the payload
+        // has the wrong shape for that form, without it the statement (opTag, memoHash) is another one
+        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
+        tok.zetherTransfer(t.payload, t.proof, "", _none());
+        bytes memory bare = _cut(t.payload, 0, t.payload.length - 17 - 40 * 2);
         vm.expectRevert(IZetherToken.ProofRejected.selector);
-        tok.zetherTransferBundle(t.payload, t.proof, "", _none());
+        tok.zetherTransfer(bare, t.proof, "", _none());
         // valid, then replay
-        tok.zetherTransfer(t.payload, t.proof, "", _none());
+        tok.zetherTransferCompact(t.payload, t.proof, "", _none());
         vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
-        tok.zetherTransfer(t.payload, t.proof, "", _none());
+        tok.zetherTransferCompact(t.payload, t.proof, "", _none());
     }
 
     /// @dev Payload thôi (chưa proof) — các phép kiểm hình dạng chạy trước verify.
@@ -238,8 +248,8 @@ abstract contract ZetherMultiSuite is ZetherFixture {
     {
         uint256 p = ver.g1EncodedBytes();
         bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP
-            ? _cut(payload, 96 + 3 * p + 3 * p * j, p)
-            : _cut(payload, 96 + p, p);
+            ? _cut(payload, 112 + 3 * p + 3 * p * j, p)
+            : _cut(payload, 112 + p, p);
         return _cpOpening(tok, x, ref, j, amount, kind, base);
     }
 
@@ -257,7 +267,9 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         uint256 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
         assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 10))), keccak256(bundles));
         assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 9))), bytes32(0));
-        assertEq(tok.transferEntry(ref), abi.encodePacked(keccak256(bundles)));
+        assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 11))), bytes32(uint256(_memo(3).length * 2 + 1)),
+            "the memo next to it (a long `bytes`: 2 * len + 1)");
+        assertEq(tok.transferEntry(ref), abi.encodePacked(keccak256(bundles), _memo(3)), "keccak256(R) then the memo");
         _discloseAll(ref, t, bundles);
         // bundles that do not match the stored hash
         bytes memory wrong = bytes.concat(bundles);
@@ -287,7 +299,7 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, ref));
         _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), bundles);
         // off chain: the sender's s opens the leg read from calldata
-        bytes memory b1 = _cut(_bundlesOf(t.payload), 4 * ver.g1EncodedBytes(), 4 * ver.g1EncodedBytes());
+        bytes memory b1 = _cut(_bundlesOf(t.payload), 16 + 4 * ver.g1EncodedBytes(), 4 * ver.g1EncodedBytes());
         uint256 p = ver.g1EncodedBytes();
         assertEq(ver.g1MulBase(t.s), _cut(b1, 2 * p, p), "D_out = [s]G");
         assertEq(ver.g1Add(ver.g1MulBase(77), ver.g1Mul(rs[1].y, t.s)), _cut(b1, p, p), "C_out = [v]G + [s]Y_t");
@@ -340,9 +352,9 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         Tx memory on = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
         // Y_a nằm trong statement: proof của lựa chọn này không qua dưới lựa chọn kia
         vm.expectRevert(IZetherToken.ProofRejected.selector);
-        tok.zetherTransferBundle(t.payload, on.proof, "", _none());
+        tok.zetherTransfer(t.payload, on.proof, "", _none());
         vm.expectRevert(IZetherToken.ProofRejected.selector);
-        tok.zetherTransferBundle(on.payload, t.proof, "", _none());
+        tok.zetherTransfer(on.payload, t.proof, "", _none());
         bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
         assertTrue(_holds(tok, rs[1], 77, false));
         assertTrue(_holds(tok, alice, 423, true));
@@ -357,23 +369,25 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
         uint256 p = ver.g1EncodedBytes();
         bytes memory pl = bytes.concat(t.payload);
-        for (uint256 i; i < p; ++i) pl[96 + 5 * p + i] = 0; // C_aud_1 = O, C_aud_2 ≠ O
+        for (uint256 i; i < p; ++i) pl[112 + 5 * p + i] = 0; // C_aud_1 = O, C_aud_2 ≠ O
         vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
-        tok.zetherTransfer(pl, t.proof, "", _none());
+        tok.zetherTransferCompact(pl, t.proof, "", _none());
         vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
         stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.HASH, 0);
     }
 
-    /// Token không có auditor: C_aud ≠ O không "bật" được auditor — statement giữ Y_a = O, verifier từ chối.
+    /// Token không có auditor (`NONE`): C_aud ≠ O không "bật" được auditor — bị từ chối trước verify, statement cũng vậy.
     function test_auditorOffTokenRejectsCAud() public {
         tok = _newToken(false, "noaud2");
         _funded(500);
         uint256[] memory vs = new uint256[](1);
         vs[0] = 5;
         Tx memory t = _proveMulti(tok, alice, _to(1), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
-        bytes memory pl = _replacePoint(t.payload, 96 + 5 * ver.g1EncodedBytes());
-        vm.expectRevert(IZetherToken.ProofRejected.selector);
-        tok.zetherTransfer(pl, t.proof, "", _none());
+        bytes memory pl = _replacePoint(t.payload, 112 + 5 * ver.g1EncodedBytes());
+        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
+        tok.zetherTransferCompact(pl, t.proof, "", _none());
+        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
+        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.HASH, 0);
     }
 
     // ------------------------------------------------------------------ bên thứ ba on-chain
@@ -443,7 +457,7 @@ abstract contract ZetherMultiSuite is ZetherFixture {
         _funded(1_000_000);
         Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, 1_000_000, _none(), 0);
         bytes32 ref = _direct(tok, t, _none());
-        bytes memory dOut = _cut(t.payload, 64 + 3 * ver.g1EncodedBytes(), ver.g1EncodedBytes()); // Y_f Y_t C_out D_out …
+        bytes memory dOut = _cut(t.payload, 80 + 3 * ver.g1EncodedBytes(), ver.g1EncodedBytes()); // salt Y_f Y_t C_out D_out …
         bytes[4] memory o = [
             abi.encode(t.s),
             _cpOpening(tok, rs[0].x, ref, 0, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut),
diff --git a/smartcontracts/evm/test/zether/ZetherNormal.t.sol b/smartcontracts/evm/test/zether/ZetherNormal.t.sol
index fde89c2..6800029 100644
--- a/smartcontracts/evm/test/zether/ZetherNormal.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherNormal.t.sol
@@ -130,19 +130,21 @@ abstract contract ZetherNormalSuite is ZetherFixture {
 
     // ------------------------------------------------------------------ the statement (zether.md §7)
 
-    /// The token's statement carries the 13-word header with `chainUid` at word 3 (CTR-ZTH-36), the token, the
-    /// binding tag; the view and the token build the very same bytes (a proof of the view's statement passes).
+    /// The token's statement carries the 15-word header with `chainUid` at word 3 (CTR-ZTH-36), the token, the
+    /// binding tag, the salt at word 13 (CTR-ZTH-30) and `memoHash` at word 14 (0 off commit-reveal and on an unshield,
+    /// CTR-ZTH-50); the view and the token build the very same bytes (a proof of the view's statement passes); a salt
+    /// changed after proving is refused.
     function test_statementHeaderCarriesChainUid() public {
         _fund(tok, alice, 500);
         tok.zetherRollOver(alice.ua);
         Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, 0);
         bytes memory st = stm.transferStatementSingle(address(tok), t.payload, carol.ua, 0);
-        bytes memory head = new bytes(416);
-        for (uint256 i; i < 416; ++i) head[i] = st[i];
+        bytes memory head = new bytes(480);
+        for (uint256 i; i < 480; ++i) head[i] = st[i];
         bytes memory expected = bytes.concat(
             abi.encode(keccak256("SCAAS-ZETHER-OP-TRANSFER-V1"), ver.proofSystemId(), block.chainid, ZUID, address(tok),
                 keccak256("ZTX_V1_DIRECT"), bytes32(0)),
-            abi.encode(uint256(0), uint256(1), FEE, carol.ua, uint256(0), address(0))
+            abi.encode(uint256(0), uint256(1), FEE, carol.ua, uint256(0), address(0), uint256(uint128(salt)), bytes32(0))
         );
         assertEq(head, expected);
         assertEq(tok.chainUid(), ZUID);
@@ -154,6 +156,16 @@ abstract contract ZetherNormalSuite is ZetherFixture {
         assertEq(rcp, address(0xD00D));
         assertEq(bytes32(_cut(st, 0, 32)), keccak256("SCAAS-ZETHER-OP-BURN-V1"));
         assertEq(bytes32(_cut(st, 96, 32)), ZUID);
+        assertEq(_cut(st, 416, 64), new bytes(64), "no salt, no memo on an unshield");
+        bytes memory tampered = bytes.concat(t.payload);
+        tampered[70] ^= 0x01; // the salt
+        vm.expectRevert(IZetherToken.ProofRejected.selector);
+        tok.zetherTransferSingle(tampered, t.proof, "", carol.ua);
+        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length - 1));
+        tok.zetherTransferSingle(_cut(t.payload, 0, t.payload.length - 1), t.proof, "", carol.ua);
+        bytes32 ref = _ref(tok, alice, 0);
+        vm.expectEmit(true, true, true, true, address(tok));
+        emit IZetherToken.ZetherTransfer(alice.ua, bob.ua, carol.ua, FEE, 0, ref);
         _direct(tok, t, carol.ua);
     }
 
diff --git a/smartcontracts/evm/test/zether/ZetherRelay.t.sol b/smartcontracts/evm/test/zether/ZetherRelay.t.sol
index 905c2d8..082b098 100644
--- a/smartcontracts/evm/test/zether/ZetherRelay.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherRelay.t.sol
@@ -82,14 +82,14 @@ contract ZetherRelayTest is ZetherFixture {
     }
 
     function test_relayedMultiTransfer_unshield_shield() public {
-        // zetherTransfer (HASH), relayed
+        // zetherTransferCompact (HASH), relayed
         MetaTxLib.MetaTransaction memory m = _mt("", 1, RR | FIX, 3);
         User[] memory to = new User[](2);
         (to[0], to[1]) = (bob, carol);
         uint256[] memory vs = new uint256[](2);
         (vs[0], vs[1]) = (40, 0);
         Tx memory t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.HASH, tok.envelopeBinding(m));
-        m.data = abi.encodeCall(ZetherLayer.zetherTransfer, (t.payload, t.proof, bytes(""), _none()));
+        m.data = abi.encodeCall(ZetherLayer.zetherTransferCompact, (t.payload, t.proof, bytes(""), _none()));
         _exec(m, _sign(PAYER_PK, m));
         assertTrue(_holds(tok, bob, 40, false));
         assertTrue(_holds(tok, alice, 460, true));
@@ -117,6 +117,43 @@ contract ZetherRelayTest is ZetherFixture {
         _assertConservation(tok, 1100);
     }
 
+    /// The modes hold relayed: on a `COMPACT` / `FULL` token `zetherTransfer` relays as commit-reveal, the no-bundle entry
+    /// reverts `TransferEntryDisabled`, an opt-out reverts `AuditorRequired` (the refusal reverts the envelope: nonce
+    /// unused).
+    function test_relayedUnderTheModes() public {
+        (dMode, aMode) = (1, 1);
+        tok = _newToken(true, "commit-full");
+        _public(tok, payer, 1000);
+        _fund(tok, alice, 500);
+        tok.zetherRollOver(alice.ua);
+        User[] memory to = new User[](2);
+        (to[0], to[1]) = (bob, carol);
+        uint256[] memory vs = new uint256[](2);
+        vs[0] = 40;
+        MetaTxLib.MetaTransaction memory m = _mt("", 1, RR | FIX, 3);
+        Tx memory t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.HASH, tok.envelopeBinding(m));
+        m.data = abi.encodeCall(ZetherLayer.zetherTransfer, (t.payload, t.proof, bytes(""), _none()));
+        _exec(m, _sign(PAYER_PK, m));
+        assertTrue(_holds(tok, bob, 40, false));
+        bytes memory entry = tok.transferEntry(_ref(tok, alice, 0));
+        assertEq(entry.length, 32 + 17 + 40 * 2, "the commitment, then the sender memo");
+        bytes memory pl = _multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua));
+        m = _mt(abi.encodeCall(ZetherLayer.zetherTransferNoBundle, (pl, bytes(""), bytes(""), _none())), 2, RR, 0);
+        bytes memory sig = _sign(PAYER_PK, m);
+        vm.prank(relayer);
+        vm.expectRevert(abi.encodeWithSelector(IZetherToken.TransferEntryDisabled.selector, uint8(1)));
+        tok.mtxExecute(m, sig);
+        audOut = true;
+        pl = bytes.concat(_multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua)), _memo(2));
+        audOut = false;
+        m = _mt(abi.encodeCall(ZetherLayer.zetherTransfer, (pl, bytes(""), bytes(""), _none())), 2, RR, 0);
+        sig = _sign(PAYER_PK, m);
+        vm.prank(relayer);
+        vm.expectRevert(IZetherToken.AuditorRequired.selector);
+        tok.mtxExecute(m, sig);
+        assertEq(tok.mtxNonce(payer, 2), 0, "nonce not consumed");
+    }
+
     function test_proofLiftedOutOfEnvelopeRejected() public {
         (, Tx memory t) = _relayedSingle(7, 25);
         vm.expectRevert(IZetherToken.ProofRejected.selector); // statement DIRECT ≠ RELAYED
@@ -225,7 +262,7 @@ contract ZetherRelayTest is ZetherFixture {
         (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = tok.mtxSelectors();
         bytes4[8] memory want = [
             IMetaTx.cancelNonce.selector, NormalToken.burn.selector, ZetherLayer.zetherShield.selector,
-            ZetherLayer.zetherTransfer.selector, ZetherLayer.zetherTransferBundle.selector,
+            ZetherLayer.zetherTransfer.selector, ZetherLayer.zetherTransferCompact.selector,
             ZetherLayer.zetherTransferNoBundle.selector, ZetherLayer.zetherTransferSingle.selector,
             ZetherLayer.zetherUnshield.selector
         ];
@@ -237,6 +274,7 @@ contract ZetherRelayTest is ZetherFixture {
         }
         assertEq(bytes4(keccak256("zetherShield(bytes,uint256)")), ZetherLayer.zetherShield.selector);
         assertEq(bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)")), ZetherLayer.zetherTransfer.selector);
+        assertEq(bytes4(keccak256("zetherTransferCompact(bytes,bytes,bytes,bytes32)")), ZetherLayer.zetherTransferCompact.selector);
         assertEq(bytes4(keccak256("zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)")),
             ZetherLayer.zetherUnshield.selector);
         bytes[4] memory refused = [
diff --git a/smartcontracts/evm/test/zether/ZetherRevertPaths.t.sol b/smartcontracts/evm/test/zether/ZetherRevertPaths.t.sol
index d16cb11..0c38f18 100644
--- a/smartcontracts/evm/test/zether/ZetherRevertPaths.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherRevertPaths.t.sol
@@ -77,14 +77,14 @@ contract ZetherRevertPathsTest is ZetherFixture {
 
     function test_transferToSelfRejected() public {
         Tx memory t = _aliceTx();
-        for (uint256 i; i < 64; ++i) t.payload[128 + i] = t.payload[64 + i]; // Y_to := Y_from
+        for (uint256 i; i < 64; ++i) t.payload[144 + i] = t.payload[80 + i]; // Y_to := Y_from
         _call(t.payload, t.proof, _none(), abi.encodeWithSelector(IZetherToken.SelfTransfer.selector));
     }
 
     function test_transferToUnregisteredRejected() public {
         Tx memory t = _aliceTx();
         bytes memory gy = ZetherKeys.pub(0x6057, false);
-        for (uint256 i; i < 64; ++i) t.payload[128 + i] = gy[i];
+        for (uint256 i; i < 64; ++i) t.payload[144 + i] = gy[i];
         _call(t.payload, t.proof, _none(),
             abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(gy)));
     }
@@ -116,7 +116,7 @@ contract ZetherRevertPathsTest is ZetherFixture {
         bytes[10] memory calls = [
             abi.encodeCall(ZetherLayer.zetherShield, (alice.y, 1)),
             abi.encodeCall(ZetherLayer.zetherTransfer, ("", "", "", n)),
-            abi.encodeCall(ZetherLayer.zetherTransferBundle, ("", "", "", n)),
+            abi.encodeCall(ZetherLayer.zetherTransferCompact, ("", "", "", n)),
             abi.encodeCall(ZetherLayer.zetherTransferNoBundle, ("", "", "", n)),
             abi.encodeCall(ZetherLayer.zetherTransferSingle, ("", "", "", n)),
             abi.encodeCall(ZetherLayer.zetherUnshield, ("", "", "", n, address(0xD), 1)),
diff --git a/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol b/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol
index 5f8b570..d266d22 100644
--- a/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol
@@ -79,7 +79,7 @@ contract ZetherS3VectorsTest is Test {
         if (op == Op.MULTI) {
             // every leg point of the statement is bound; so is the mode (opTag)
             for (uint256 k = 1; k <= 5; ++k) {
-                assertFalse(_ok(v, _flip(st, st.length - (st.length - 416) * k / 6), pr, op), "tampered leg accepted");
+                assertFalse(_ok(v, _flip(st, st.length - (st.length - 448) * k / 6), pr, op), "tampered leg accepted");
             }
             assertFalse(_ok(v, _flip(st, 31), pr, op), "mode switch accepted");
         }
@@ -104,13 +104,13 @@ contract ZetherS3VectorsTest is Test {
         (bytes32 op, bytes32 psid) = abi.decode(_head(j.readBytes(".statement"), 0), (bytes32, bytes32));
         assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH"));
         assertEq(psid, bn.proofSystemIdMulti());
-        assertEq(bn.proofSystemIdMulti(), keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v1/multi"));
+        assertEq(bn.proofSystemIdMulti(), keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v2/multi"));
         string memory k = vm.readFile(string.concat(DIR, "transfer_multi_noaud_bls12381.json"));
         (op,) = abi.decode(_head(k.readBytes(".statement"), 0), (bytes32, bytes32));
         assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE"));
     }
 
-    /// Header statement của S3 đúng bố cục zether.md §7 (416 byte, `chainUid` là word 3) với các trường của `request`.
+    /// Header statement của S3 đúng bố cục zether.md §7 (448 byte, `chainUid` là word 3) với các trường của `request`.
     function test_s3StatementHeaderMatchesRequest() public view {
         string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
         bytes memory st = j.readBytes(".statement");
@@ -134,9 +134,11 @@ contract ZetherS3VectorsTest is Test {
         assertEq(accSeq, j.readUint(".request.accSeq"));
         assertEq(fee, j.readUint(".request.fee"));
         assertEq(ben, j.readBytes32(".request.beneficiary"));
+        _checkMemo(j, st);
+        _checkMemo(vm.readFile(string.concat(DIR, "transfer_multi_bls12381.json")), "");
         // entryRef (CTR-ZTH-36) = keccak(tag, chainId, chainUid, token, keccak(Y_f), sendCounter)
         bytes memory yf = new bytes(64);
-        for (uint256 i; i < 64; ++i) yf[i] = st[416 + i];
+        for (uint256 i; i < 64; ++i) yf[i] = st[480 + i];
         assertEq(
             keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), j.readUint(".request.chainId"),
                 j.readBytes32(".request.chainUid"), j.readAddress(".request.token"), keccak256(yf), sc)),
@@ -144,6 +146,24 @@ contract ZetherS3VectorsTest is Test {
         );
     }
 
+    /// Header word 13 is the salt (16 zero bytes ‖ salt), the payload's bytes 64..80 too (CTR-ZTH-30); word 14 is
+    /// `keccak256(memo)` on commit-reveal, the payload then ending with the memo of `17 + 40·M` bytes, else 0
+    /// (CTR-ZTH-50).
+    function _checkMemo(string memory j, bytes memory st) internal view {
+        if (st.length == 0) st = j.readBytes(".statement");
+        bytes memory pl = j.readBytes(".payload");
+        bytes16 salt = bytes16(j.readBytes(".salt"));
+        assertEq(bytes32(_head(st, 416)), bytes32(uint256(uint128(salt))), "salt, word 13");
+        assertEq(bytes16(_head(pl, 64)), salt, "salt after sendCounter");
+        bytes memory memo = vm.keyExistsJson(j, ".memo") ? j.readBytes(".memo") : bytes("");
+        assertEq(bytes32(_head(st, 448)), memo.length == 0 ? bytes32(0) : keccak256(memo), "memoHash, word 14");
+        if (memo.length == 0) return;
+        bytes memory tail = new bytes(memo.length);
+        for (uint256 i; i < memo.length; ++i) tail[i] = pl[pl.length - memo.length + i];
+        assertEq(tail, memo, "the payload ends with the memo");
+        assertEq((memo.length - 17) % 40, 0);
+    }
+
     function _head(bytes memory st, uint256 off) internal pure returns (bytes memory out) {
         out = new bytes(192);
         for (uint256 i; i < 192; ++i) out[i] = st[off + i];
@@ -180,7 +200,7 @@ contract ZetherS3VectorsTest is Test {
             bytes memory leg = bytes.concat(j.readBytes(string.concat(c, ".Yt")), j.readBytes(string.concat(c, ".Cout")),
                 j.readBytes(string.concat(c, ".Dout")), j.readBytes(string.concat(c, ".Caud")));
             S3Token(tok).set(v, uid == 0 ? j.readBytes32(string.concat(c, ".chainUid")) : uid,
-                j.readBytes(string.concat(c, ".Ya")), bytes.concat(new bytes(idx * leg.length), leg, leg));
+                j.readBytes(string.concat(c, ".Ya")), bytes.concat(new bytes(16 + idx * leg.length), leg, leg)); // R = salt ‖ …
             vm.chainId(j.readUint(string.concat(c, ".chainId")));
             if (!_disclose(j, c, tok, idx)) continue;
             ++ok;
diff --git a/smartcontracts/evm/test/zether/ZetherWrapped.t.sol b/smartcontracts/evm/test/zether/ZetherWrapped.t.sol
index b16549a..01b5a17 100644
--- a/smartcontracts/evm/test/zether/ZetherWrapped.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherWrapped.t.sol
@@ -106,7 +106,8 @@ contract ZetherWrappedTest is ZetherFixture {
         c.legs = new IFactoryToken.Leg[](legs.length);
         for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], nums[i], dens[i]);
         c.conf = IFactoryToken.ConfidentialConfig(
-            address(ver), auditor ? ZetherKeys.pub(X_AUD, false) : bytes(""), SCALE, uint256(1) << 40, FEE
+            address(ver), auditor ? ZetherKeys.pub(X_AUD, false) : bytes(""), SCALE, uint256(1) << 40, FEE, dMode,
+            auditor ? aMode : 0
         );
         return WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, c, salt)));
     }
@@ -204,7 +205,7 @@ contract ZetherWrappedTest is ZetherFixture {
         c.rate = IFactoryToken.RateConfig(2 days, 1000);
         c.legs = new IFactoryToken.Leg[](1);
         c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
-        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE);
+        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE, 0, 0);
         z = WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, c, "small")));
     }
 
@@ -312,7 +313,7 @@ contract ZetherWrappedTest is ZetherFixture {
         bytes32 ref = _direct(tok, t, _none());
         assertEq(address(w.disclosure()), address(dis));
         assertEq(w.auditorKey(), ZetherKeys.pub(X_AUD, false));
-        assertEq(w.transferEntry(ref).length, 4 * 64, "the single format stores its bundle");
+        assertEq(w.transferEntry(ref).length, 16 + 4 * 64, "the single format stores R = salt, then B");
         (bytes memory ct,) = dis.transferCiphertext(address(w), ref, 0, "");
         bytes memory dOut = new bytes(64);
         for (uint256 i; i < 64; ++i) dOut[i] = ct[64 + i];
@@ -356,7 +357,7 @@ contract ZetherWrappedTest is ZetherFixture {
         (c.name, c.symbol, c.decimals, c.features) = ("F", "F", 6, 1 << AdminLib.FREEZE);
         c.legs = new IFactoryToken.Leg[](1);
         c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
-        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE);
+        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE, 0, 0);
         vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.FREEZE));
         factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, c, "freeze");
         c.features = 1 << AdminLib.MINTABLE;
@@ -487,6 +488,10 @@ contract ZetherWrappedTest is ZetherFixture {
         assertEq(s[12], WrappedZetherToken.zetherWrapShield.selector);
         assertEq(s[13], WrappedZetherToken.zetherUnshieldUnwrap.selector);
         assertEq(s[6], ZetherLayer.zetherShield.selector);
+        assertEq(s[7], ZetherLayer.zetherTransfer.selector);
+        assertEq(s[8], ZetherLayer.zetherTransferCompact.selector);
+        assertEq(s[9], ZetherLayer.zetherTransferNoBundle.selector);
+        assertEq(s[10], ZetherLayer.zetherTransferSingle.selector);
         assertEq(s[11], ZetherLayer.zetherUnshield.selector);
         for (uint256 i = 6; i < 14; ++i) {
             assertEq(c[i], 1, "ABSOLUTE");
diff --git a/smartcontracts/evm/test/zether/ZetherVerifier.t.sol b/smartcontracts/evm/test/zether/ZetherVerifier.t.sol
index 58b10c9..9304551 100644
--- a/smartcontracts/evm/test/zether/ZetherVerifier.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherVerifier.t.sol
@@ -8,7 +8,7 @@ import {G1Bls12381} from "../../src/zether/ZetherCurves.sol";
 import {ZetherProver} from "./helpers/ZetherProver.sol";
 
 /// @notice Verifier đứng một mình: proof đúng qua, mọi thay đổi một bit / một trường / một witness sai
-///         đều bị từ chối. Statement dựng tay theo zether.md §7 (header 416 byte, `chainUid` là word 3; token và
+///         đều bị từ chối. Statement dựng tay theo zether.md §7 (header 480 byte, `chainUid` là word 3; token và
 ///         `ZetherStatements` dựng y hệt — xem ZetherNormal.t.sol `test_statementHeaderCarriesChainUid`).
 contract ZetherVerifierTest is Test {
     bytes32 constant OP_T = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
@@ -42,9 +42,10 @@ contract ZetherVerifierTest is Test {
     function _header(IZetherVerifier v, bytes32 op, uint256 fee, uint256 amount, address recipient)
         internal view returns (bytes memory)
     {
-        return abi.encode(
-            op, v.proofSystemId(), block.chainid, keccak256("verifier test chain"), address(0x70CE), DIRECT, bytes32(0),
-            uint256(7), uint256(3), fee, fee == 0 ? bytes32(0) : bytes32(uint256(0xBE)), amount, recipient
+        return bytes.concat(
+            abi.encode(op, v.proofSystemId(), block.chainid, keccak256("verifier test chain"), address(0x70CE), DIRECT),
+            abi.encode(bytes32(0), uint256(7), uint256(3), fee, fee == 0 ? bytes32(0) : bytes32(uint256(0xBE))),
+            abi.encode(amount, recipient, op == OP_B ? bytes32(0) : bytes32(uint256(0x5A17)), bytes32(0))
         );
     }
 
@@ -155,7 +156,7 @@ contract ZetherVerifierTest is Test {
         bytes memory pr = _proveTransfer(k, st, k.amount);
         assertTrue(bls.verifyTransfer(st, pr));
         // chainId, chainUid, token, bindingTag, binding, sendCounter, accSeq, fee, beneficiary, rồi một bit trong C_acc
-        uint256[10] memory offs = [uint256(95), 127, 159, 191, 223, 255, 287, 319, 351, 416 + 3 * 128 + 100];
+        uint256[12] memory offs = [uint256(95), 127, 159, 191, 223, 255, 287, 319, 351, 447, 479, 480 + 3 * 128 + 100];
         for (uint256 i; i < offs.length; ++i) {
             bytes memory t = bytes.concat(st);
             t[offs[i]] = bytes1(uint8(t[offs[i]]) ^ 0x01);
@@ -183,7 +184,7 @@ contract ZetherVerifierTest is Test {
         bytes memory st = _transferStatement(k, k.amount);
         bytes memory lie = _cts(Case(bls, 1000, 1, 5, true), 1); // C_aud của v = 1
         uint256 p = 128;
-        for (uint256 i; i < p; ++i) st[416 + 8 * p + i] = lie[3 * p + i];
+        for (uint256 i; i < p; ++i) st[480 + 8 * p + i] = lie[3 * p + i];
         assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
     }
 
@@ -201,7 +202,7 @@ contract ZetherVerifierTest is Test {
         // nhét một C_aud khác O khi auditor tắt
         bytes memory t = bytes.concat(st);
         bytes memory junk = bn.g1MulBase(42);
-        for (uint256 i; i < 64; ++i) t[416 + 8 * 64 + i] = junk[i];
+        for (uint256 i; i < 64; ++i) t[480 + 8 * 64 + i] = junk[i];
         assertFalse(_ok(bn, t, pr, true));
     }
 
@@ -239,10 +240,10 @@ contract ZetherVerifierTest is Test {
         bytes memory pr = _proveTransfer(k, st, k.amount);
         assertTrue(_ok(bls, st, pr, true));
         bytes memory good = bls.g1MulBase(7);
-        for (uint256 i; i < 128; ++i) st[416 + i] = good[i]; // Y_f
+        for (uint256 i; i < 128; ++i) st[480 + i] = good[i]; // Y_f
         assertFalse(bls.verifyTransfer(st, pr));
         bytes memory bad = vm.parseJsonBytes(vm.readFile("test/vectors/zether/curve_misc.json"), ".blsNonSubgroup");
-        for (uint256 i; i < 128; ++i) st[416 + i] = bad[i];
+        for (uint256 i; i < 128; ++i) st[480 + i] = bad[i];
         vm.expectRevert(G1Bls12381.BadPoint.selector);
         bls.verifyTransfer(st, pr);
         uint256[] memory one = new uint256[](1);
diff --git a/smartcontracts/evm/test/zether/helpers/ZetherFixture.sol b/smartcontracts/evm/test/zether/helpers/ZetherFixture.sol
index 3f6b3cd..5c45e81 100644
--- a/smartcontracts/evm/test/zether/helpers/ZetherFixture.sol
+++ b/smartcontracts/evm/test/zether/helpers/ZetherFixture.sol
@@ -46,6 +46,15 @@ abstract contract ZetherFixture is Test {
     bool internal bls;
     /// @dev CTR-ZTH-42: the sender leaves the auditor out (every `C_aud = O`) on a token with an auditor.
     bool internal audOut;
+    /// @dev The sender puts the auditor key in (every `C_aud ≠ O`) even on a token without one.
+    bool internal audForce;
+    /// @dev The modes of the next token (`ZetherTypes`): disclosure `BUNDLE` (the default); with a key, auditor
+    ///      `OPTIONAL` (the opt-out tests), set to `FULL` where a test needs it.
+    uint8 internal dMode;
+    /// @dev The sender's salt (CTR-ZTH-30) of every transfer the fixture builds; the memo of a commit-reveal transfer
+    ///      starts with it, the rest is filler here (the token never reads it, CTR-ZTH-50).
+    bytes16 internal salt = bytes16(uint128(0x5A17));
+    uint8 internal aMode = uint8(ZetherTypes.AuditorMode.OPTIONAL);
     /// @dev Public units the fixture created per token (`mint` or wrap): `totalSupply + totalShielded·SCALE` stays equal.
     mapping(address => uint256) internal minted;
 
@@ -94,7 +103,8 @@ abstract contract ZetherFixture is Test {
         c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.MINTABLE) | (1 << AdminLib.BURNABLE);
         c.roles.minter = address(this);
         c.conf = IFactoryToken.ConfidentialConfig(
-            address(ver), auditor ? ZetherKeys.pub(X_AUD, bls) : bytes(""), SCALE, maxShielded, FEE
+            address(ver), auditor ? ZetherKeys.pub(X_AUD, bls) : bytes(""), SCALE, maxShielded, FEE, dMode,
+            auditor ? aMode : 0
         );
     }
 
@@ -157,16 +167,29 @@ abstract contract ZetherFixture is Test {
     function _payload(ZetherLayer t, User memory from, User memory to, uint256 v, uint256 s, IZetherToken.AccountState memory st)
         internal view returns (bytes memory)
     {
-        return bytes.concat(abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), from.y, to.y, _cts(t, from.y, to.y, v, s));
+        return bytes.concat(
+            abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), salt, from.y, to.y, _cts(t, from.y, to.y, v, s)
+        );
     }
 
     function _cts(ZetherLayer t, bytes memory yf, bytes memory yt, uint256 v, uint256 s) internal view returns (bytes memory) {
-        bytes memory aud = t.auditorKey();
-        if (aud.length == 0 || audOut) aud = ver.identity();
+        bytes memory aud = _aud(t);
         (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) = prover.ciphertexts(ver, yf, yt, aud, v, s);
         return bytes.concat(cOut, dOut, cDeb, cAud);
     }
 
+    /// @dev A memo of `m` legs (CTR-ZTH-50): the salt, then `1 + 40·m` filler bytes.
+    function _memo(uint256 m) internal view returns (bytes memory memo) {
+        memo = bytes.concat(salt, new bytes(1 + 40 * m));
+        for (uint256 i = 16; i < memo.length; ++i) memo[i] = bytes1(uint8(i));
+    }
+
+    /// @dev The `Y_a` the sender encrypts to: the token's key, `O` without one or when left out, the test key if forced.
+    function _aud(ZetherLayer t) internal view returns (bytes memory aud) {
+        aud = audForce ? ZetherKeys.pub(X_AUD, bls) : t.auditorKey();
+        if (aud.length == 0 || audOut) aud = ver.identity();
+    }
+
     /// @dev `from → to[j]`, value `vs[j]` (decoys 0), one shared `s`, from the acc balance `b`.
     function _proveMulti(
         ZetherLayer t,
@@ -193,6 +216,7 @@ abstract contract ZetherFixture is Test {
         IZetherToken.AccountState memory st = t.accountState(from.ua);
         r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, vs, address(t), "multi"))) % ver.groupOrder();
         r.payload = _multiPayload(t, from, to, vs, r.s, st);
+        if (mode == ZetherTypes.TransferMode.HASH) r.payload = bytes.concat(r.payload, _memo(to.length));
         if (ZetherTypes.UA.unwrap(ben) != 0) b -= t.confidentialFee();
         r.proof = prover.proveTransferMulti(
             ver, stm.transferStatement(address(t), r.payload, ben, mode, binding), _multiWitness(from.x, r.s, vs, b)
@@ -212,7 +236,7 @@ abstract contract ZetherFixture is Test {
         w = ZetherProver.MultiWitness(x, s, vs, bPrime, gv, 0x5678 + bPrime, keccak256(abi.encode(s)));
     }
 
-    /// @dev `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
+    /// @dev `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j` (`salt(16)` after `sendCounter`); `_proveMulti` appends the memo on commit-reveal.
     function _multiPayload(
         ZetherLayer t,
         User memory from,
@@ -221,8 +245,7 @@ abstract contract ZetherFixture is Test {
         uint256 s,
         IZetherToken.AccountState memory st
     ) internal view returns (bytes memory payload) {
-        bytes memory aud = t.auditorKey();
-        if (aud.length == 0 || audOut) aud = ver.identity();
+        bytes memory aud = _aud(t);
         bytes memory legs;
         uint256 total;
         for (uint256 j; j < to.length; ++j) {
@@ -232,7 +255,7 @@ abstract contract ZetherFixture is Test {
         }
         (,bytes memory dOut, bytes memory cDeb,) = prover.ciphertexts(ver, from.y, from.y, aud, total, s);
         payload = bytes.concat(
-            abi.encode(uint256(st.accSeq), uint256(st.sendCounter), to.length), from.y, dOut, cDeb, legs
+            abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), salt, abi.encode(to.length), from.y, dOut, cDeb, legs
         );
     }
 
@@ -269,12 +292,18 @@ abstract contract ZetherFixture is Test {
             Tx memory t = _proveTransfer(tok, alice, bob, 10, bal, _none(), b);
             return abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), _none()));
         }
-        ZetherTypes.TransferMode mode = sel == ZetherLayer.zetherTransfer.selector ? ZetherTypes.TransferMode.HASH
-            : sel == ZetherLayer.zetherTransferBundle.selector ? ZetherTypes.TransferMode.BUNDLE : ZetherTypes.TransferMode.NONE;
+        ZetherTypes.TransferMode mode = sel == ZetherLayer.zetherTransferCompact.selector ? ZetherTypes.TransferMode.HASH
+            : sel == ZetherLayer.zetherTransfer.selector ? _defaultForm(tok) : ZetherTypes.TransferMode.NONE;
         require(mode != ZetherTypes.TransferMode.NONE || sel == ZetherLayer.zetherTransferNoBundle.selector, "not a Zether op");
         return _multiCall(sel, mode, bal, b);
     }
 
+    /// @dev The stored form of `zetherTransfer` on `t` (CTR-ZTH-38): BUNDLE, or HASH on a `COMMIT` token.
+    function _defaultForm(ZetherLayer t) internal view returns (ZetherTypes.TransferMode) {
+        return t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? ZetherTypes.TransferMode.HASH
+            : ZetherTypes.TransferMode.BUNDLE;
+    }
+
     function _multiCall(bytes4 sel, ZetherTypes.TransferMode mode, uint256 bal, bytes32 b) internal view returns (bytes memory) {
         User[] memory to = new User[](1);
         to[0] = bob;
diff --git a/smartcontracts/evm/test/zether/helpers/ZetherProver.sol b/smartcontracts/evm/test/zether/helpers/ZetherProver.sol
index d8dbd40..1114e9c 100644
--- a/smartcontracts/evm/test/zether/helpers/ZetherProver.sol
+++ b/smartcontracts/evm/test/zether/helpers/ZetherProver.sol
@@ -31,7 +31,7 @@ contract ZetherProver {
         bytes32 seed;
     }
 
-    uint256 constant HEADER = 416; // zether.md §7: chainUid is word 3
+    uint256 constant HEADER = 480; // zether.md §7: chainUid is word 3, salt word 13, memoHash word 14
 
     function _env(IZetherVerifier v, bytes32 seed) internal view returns (Env memory e) {
         e.v = v;
```

- [ ] **Step 3: `test/zether/ZetherModes.t.sol`** (new): the six mode pairs × both kinds, the invalid configs, the
  signed salt and memo:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// @notice The two modes fixed at `initialize` (CTR-ZTH-48, CTR-ZTH-49), every pair on a kind: `disclosureMode`
///         `BUNDLE` (`zetherTransfer` stores `R = salt ‖ B_1 ‖ … ‖ B_M`, `zetherTransferCompact` commits, `…NoBundle`
///         stores nothing, single stores `R`) or `COMPACT` (`zetherTransfer` and `…Compact` commit with the sender memo,
///         no-bundle and single refused); `auditorMode` `NONE` (every `C_aud = O`), `FULL` (every `C_aud ≠ O`) or
///         `OPTIONAL` (the sender's choice, all or nothing). Every stored form opens with the four openings; a
///         commit-reveal transfer opens with `R` from its event and with the `R` the sender rebuilds from `s` and the
///         values (CTR-ZTH-38, CTR-ZTH-42, CTR-ZTH-50).
abstract contract ZetherModesSuite is ZetherFixture {
    uint8 constant BUNDLE = 0;
    uint8 constant COMPACT = 1;
    uint8 constant NONE = 0;
    uint8 constant FULL = 1;
    uint8 constant OPTIONAL = 2;

    ITransferDisclosure.OpeningKind constant S = ITransferDisclosure.OpeningKind.SENDER_S;
    ITransferDisclosure.OpeningKind constant RX = ITransferDisclosure.OpeningKind.RECEIVER_X;
    ITransferDisclosure.OpeningKind constant AUD = ITransferDisclosure.OpeningKind.AUDITOR;
    ITransferDisclosure.OpeningKind constant CP = ITransferDisclosure.OpeningKind.SENDER_CP;

    /// @dev Alice's acc balance (plaintext), the transfers' source.
    uint256 internal bal;

    function _kind() internal pure virtual returns (IOpenFactory.TokenKind);

    /// @dev The kind's config: `_cfg` (`dMode`, `aMode`) plus the kind's own fields.
    function _kindCfg(bool auditor) internal view virtual returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(auditor, uint256(1) << 40);
    }

    function _newToken(bool auditor, bytes32 salt_, uint256) internal virtual override returns (ZetherLayer) {
        return ZetherLayer(factory.createToken(_kind(), 1, _kindCfg(auditor), salt_));
    }

    // ------------------------------------------------------------------ the matrix

    function test_bundleNone() public { _pair(BUNDLE, NONE); }
    function test_bundleFull() public { _pair(BUNDLE, FULL); }
    function test_bundleOptional() public { _pair(BUNDLE, OPTIONAL); }
    function test_compactNone() public { _pair(COMPACT, NONE); }
    function test_compactFull() public { _pair(COMPACT, FULL); }
    function test_compactOptional() public { _pair(COMPACT, OPTIONAL); }

    function _pair(uint8 d, uint8 a) internal {
        (dMode, aMode) = (d, a);
        tok = _newToken(a != NONE, bytes32(uint256(16 * d + a + 1)), 0);
        assertEq(uint8(tok.disclosureMode()), d, "disclosureMode");
        assertEq(uint8(tok.auditorMode()), a, "auditorMode");
        assertEq(tok.auditorKey().length != 0, a != NONE, "a key exactly when the auditor is on");
        _fund(tok, alice, 1000);
        tok.zetherRollOver(alice.ua);
        bal = 1000;
        _auditorRule(d, a);
        if (d == BUNDLE) _bundleForms(a);
        else _compactForms(a);
        _assertConservation(tok, 1000);
    }

    /// @dev `NONE` refuses an auditor leg, `FULL` an opt-out, both before the verifier and in the statement views (the
    ///      single format on a BUNDLE token too); `OPTIONAL` takes the opt-out (the AUDITOR opening then fails).
    function _auditorRule(uint8 d, uint8 a) internal {
        if (a == OPTIONAL) {
            audOut = true;
            (bytes32 ref, Tx memory t) = _multi(ZetherTypes.TransferMode.HASH, ZetherLayer.zetherTransferCompact.selector, 5);
            _openAll(ref, t.s, 5, _rebuild(_two(), _vs(5), t.s), false);
            audOut = false;
            return;
        }
        bytes4 err = a == NONE ? IZetherToken.AuditorForbidden.selector : IZetherToken.AuditorRequired.selector;
        (audForce, audOut) = (a == NONE, a == FULL);
        bytes memory multi = bytes.concat(_multiPayload(tok, alice, _two(), _vs(5), 7, tok.accountState(alice.ua)), _memo(2));
        bytes memory single = _payload(tok, alice, bob, 5, 7, tok.accountState(alice.ua));
        (audForce, audOut) = (false, false);
        vm.expectRevert(err);
        tok.zetherTransferCompact(multi, "", "", _none());
        vm.expectRevert(err);
        stm.transferStatement(address(tok), multi, _none(), ZetherTypes.TransferMode.HASH, 0);
        if (d == COMPACT) return;
        vm.expectRevert(err);
        tok.zetherTransferSingle(single, "", "", _none());
        vm.expectRevert(err);
        stm.transferStatementSingle(address(tok), single, _none(), 0);
    }

    /// @dev `BUNDLE`: `zetherTransfer` stores `R`, `zetherTransferCompact` commits, `zetherTransferNoBundle` stores
    ///      nothing, the single format stores `R` with its one leg.
    function _bundleForms(uint8 a) internal {
        bool audIn = a != NONE;
        (bytes32 ref, Tx memory t) = _multi(ZetherTypes.TransferMode.BUNDLE, ZetherLayer.zetherTransfer.selector, 11);
        bytes memory r = _rebuild(_two(), _vs(11), t.s);
        assertEq(tok.transferEntry(ref), r, "zetherTransfer on BUNDLE: R, the salt first");
        _openAll(ref, t.s, 11, "", audIn);
        _hashForm(audIn, ZetherLayer.zetherTransferCompact.selector);
        (ref, t) = _multi(ZetherTypes.TransferMode.NONE, ZetherLayer.zetherTransferNoBundle.selector, 13);
        assertEq(tok.transferEntry(ref).length, 0, "NONE: nothing stored");
        r = _rebuild(_two(), _vs(13), t.s); // before `expectRevert`: it calls out
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, ref));
        _vta(tok, ref, 0, 13, S, abi.encode(t.s), r);
        t = _proveTransfer(tok, alice, bob, 14, bal, _none(), 0);
        ref = _direct(tok, t, _none());
        bal -= 14;
        assertEq(tok.transferEntry(ref), _rebuild(_one(), _vs1(14), t.s), "single: R with its one leg");
        _openAll(ref, t.s, 14, "", audIn);
    }

    /// @dev `COMPACT`: `zetherTransfer` and `zetherTransferCompact` both commit; the no-bundle entry, the single format
    ///      and every form but HASH are refused (token and statement views).
    function _compactForms(uint8 a) internal {
        bool audIn = a != NONE;
        bytes memory dis_ = abi.encodeWithSelector(IZetherToken.TransferEntryDisabled.selector, COMPACT);
        bytes memory pl = _multiPayload(tok, alice, _two(), _vs(11), 7, tok.accountState(alice.ua));
        bytes memory single = _payload(tok, alice, bob, 5, 7, tok.accountState(alice.ua));
        vm.expectRevert(dis_);
        tok.zetherTransferNoBundle(pl, "", "", _none());
        vm.expectRevert(dis_);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.BUNDLE, 0);
        vm.expectRevert(dis_);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.NONE, 0);
        vm.expectRevert(dis_);
        tok.zetherTransferSingle(single, "", "", _none());
        vm.expectRevert(dis_);
        stm.transferStatementSingle(address(tok), single, _none(), 0);
        _hashForm(audIn, ZetherLayer.zetherTransfer.selector);
        _hashForm(audIn, ZetherLayer.zetherTransferCompact.selector);
    }

    /// @dev Commit-reveal through `sel`: `keccak256(R)` in one slot and the memo next to it (`transferEntry` = both),
    ///      `R` in the event; the openings take the event's `R` and the sender's rebuilt one (the same bytes), and refuse
    ///      others.
    function _hashForm(bool audIn, bytes4 sel) internal {
        vm.recordLogs();
        (bytes32 ref, Tx memory t) = _multi(ZetherTypes.TransferMode.HASH, sel, 12);
        bytes memory r = _eventBundles(ref);
        assertEq(_rebuild(_two(), _vs(12), t.s), r, "the sender rebuilds R from s and the values");
        assertEq(tok.transferEntry(ref), abi.encodePacked(keccak256(r), _memo(2)), "keccak256(R) then the memo");
        _openAll(ref, t.s, 12, r, audIn);
        r[20] = bytes1(uint8(r[20]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        _vta(tok, ref, 0, 12, S, abi.encode(t.s), r);
    }

    // ------------------------------------------------------------------ the memo and the salt are signed

    /// The memo's hash (header word 14) and the salt (word 13) are in the statement: a relayer that changes either after
    /// proving is refused; the memo has exactly `17 + 40·M` bytes on commit-reveal and none elsewhere (CTR-ZTH-50).
    function test_memoAndSaltBoundByTheProof() public {
        tok = _newToken(true, "memo", 0);
        _fund(tok, alice, 100);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveMulti(tok, alice, _two(), _vs(9), 100, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory memo1 = bytes.concat(t.payload);
        memo1[memo1.length - 1] ^= 0x01;
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferCompact(memo1, t.proof, "", _none());
        bytes memory salt1 = bytes.concat(t.payload);
        salt1[70] ^= 0x01;
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferCompact(salt1, t.proof, "", _none());
        bytes memory short = new bytes(t.payload.length - 1);
        for (uint256 i; i < short.length; ++i) short[i] = t.payload[i];
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, short.length));
        tok.zetherTransferCompact(short, t.proof, "", _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
        tok.zetherTransfer(t.payload, t.proof, "", _none()); // a memo on the BUNDLE form
        tok.zetherTransferCompact(t.payload, t.proof, "", _none());
        assertTrue(_holds(tok, bob, 9, false));
    }

    // ------------------------------------------------------------------ invalid configs (both kinds)

    /// `FULL` / `OPTIONAL` need a key, `NONE` refuses one, an unknown mode is refused (`BadAuditorMode`,
    /// `BadDisclosureMode`).
    function test_invalidModesRefused() public {
        IFactoryToken.TokenConfig[6] memory bad;
        (bad[0], bad[1], bad[2], bad[3], bad[4], bad[5]) =
            (_kindCfg(false), _kindCfg(false), _kindCfg(true), _kindCfg(false), _kindCfg(false), _kindCfg(true));
        bad[0].conf.auditorMode = FULL;
        bad[1].conf.auditorMode = OPTIONAL;
        bad[2].conf.auditorMode = NONE;
        bad[3].conf.disclosureMode = 2;
        bad[4].conf.auditorMode = 3;
        bad[5].conf.auditorMode = 3; // with a key: only the bound refuses it
        bytes[6] memory errs = [
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, FULL),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, OPTIONAL),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, NONE),
            abi.encodeWithSelector(IZetherToken.BadDisclosureMode.selector, uint8(2)),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, uint8(3)),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, uint8(3))
        ];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(errs[i]);
            factory.createToken(_kind(), 1, bad[i], bytes32(i + 200));
        }
        IFactoryToken.TokenConfig memory ok = _kindCfg(true);
        ok.conf.auditorMode = FULL;
        ok.conf.disclosureMode = COMPACT;
        ZetherLayer t = ZetherLayer(factory.createToken(_kind(), 1, ok, "ok"));
        assertEq(uint8(t.auditorMode()), FULL);
        assertEq(uint8(t.disclosureMode()), COMPACT);
    }

    // ------------------------------------------------------------------ helpers

    function _two() internal view returns (User[] memory to) {
        to = new User[](2);
        (to[0], to[1]) = (bob, carol);
    }

    function _one() internal view returns (User[] memory to) {
        to = new User[](1);
        to[0] = bob;
    }

    /// @dev Bob gets `v`, carol is a decoy.
    function _vs(uint256 v) internal pure returns (uint256[] memory vs) {
        vs = new uint256[](2);
        vs[0] = v;
    }

    function _vs1(uint256 v) internal pure returns (uint256[] memory vs) {
        vs = new uint256[](1);
        vs[0] = v;
    }

    /// @dev A transfer proved for the stored form `mode`, sent through the entry `sel`.
    function _multi(ZetherTypes.TransferMode mode, bytes4 sel, uint256 v) internal returns (bytes32 ref, Tx memory t) {
        t = _proveMulti(tok, alice, _two(), _vs(v), bal, _none(), mode);
        (bool ok, bytes memory r) = address(tok).call(abi.encodeWithSelector(sel, t.payload, t.proof, bytes(""), _none()));
        if (!ok) assembly ("memory-safe") { revert(add(r, 32), mload(r)) }
        ref = abi.decode(r, (bytes32));
        bal -= v;
    }

    /// @dev What a sender rebuilds off chain from the salt, `s`, the values, the recipients' keys and the token's auditor
    ///      key: `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` (the client's `recoverTransfer`
    ///      does it from the memo and the registry's `keyOf`).
    function _rebuild(User[] memory to, uint256[] memory vs, uint256 s) internal view returns (bytes memory b) {
        bytes memory aud = _aud(tok);
        b = abi.encodePacked(salt);
        for (uint256 j; j < to.length; ++j) {
            (bytes memory cOut, bytes memory dOut,, bytes memory cAud) = prover.ciphertexts(ver, alice.y, to[j].y, aud, vs[j], s);
            b = bytes.concat(b, to[j].y, cOut, dOut, cAud);
        }
    }

    function _eventBundles(bytes32 ref) internal returns (bytes memory) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == IZetherToken.TransferBundles.selector && logs[i].topics[1] == ref) {
                return abi.decode(logs[i].data, (bytes));
            }
        }
        revert("no TransferBundles");
    }

    /// @dev The four openings of bob's leg (index 0); AUDITOR opens only with the auditor in.
    function _openAll(bytes32 ref, uint256 s, uint256 v, bytes memory bundles, bool audIn) internal view {
        bytes memory dOut = ver.g1MulBase(s);
        assertTrue(_vta(tok, ref, 0, v, S, abi.encode(s), bundles), "SENDER_S");
        assertFalse(_vta(tok, ref, 0, v + 1, S, abi.encode(s), bundles), "SENDER_S wrong amount");
        assertTrue(_vta(tok, ref, 0, v, RX, _cpOpening(tok, bob.x, ref, 0, v, RX, dOut), bundles), "RECEIVER_X");
        assertEq(_vta(tok, ref, 0, v, AUD, _cpOpening(tok, X_AUD, ref, 0, v, AUD, dOut), bundles), audIn, "AUDITOR");
        assertTrue(_vta(tok, ref, 0, v, CP, _cpOpening(tok, s, ref, 0, v, CP, bob.y), bundles), "SENDER_CP");
    }
}

contract ZetherModesNormalTest is ZetherModesSuite {
    function setUp() public {
        _stack(false);
        _users();
    }

    function _kind() internal pure override returns (IOpenFactory.TokenKind) {
        return IOpenFactory.TokenKind.NORMAL_ZETHER;
    }
}

contract ZetherModesWrappedTest is ZetherModesSuite {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack(false);
        WrappedZetherToken impl = new WrappedZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, address(impl));
        _users();
    }

    function _kind() internal pure override returns (IOpenFactory.TokenKind) {
        return IOpenFactory.TokenKind.WRAPPED_ZETHER;
    }

    /// @dev One USD leg 1:1, `PAYABLE` only.
    function _kindCfg(bool auditor) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(auditor, uint256(1) << 40);
        c.features = 1 << AdminLib.PAYABLE;
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
    }

    /// @dev Public units by a USD wrap.
    function _public(ZetherLayer t, address to, uint256 units) internal override {
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        WrappedToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
        minted[address(t)] += units;
    }
}
```

- [ ] **Step 4: copy the vectors and run** (each through `scripts/capped`, one at a time):

```bash
for f in clients/zether-prover/vectors/*.json; do b=$(basename "$f")
  [ -f smartcontracts/evm/test/vectors/zether/s3/$b ] && cp "$f" smartcontracts/evm/test/vectors/zether/s3/$b; done
```

  `forge test` → **1018 passed**, 0 failed (77 + 1 suites); `forge build src --sizes --json > /tmp/sizes.json` then
  `python3 scripts/size_gate.py /tmp/sizes.json smartcontracts/evm/size-baseline.json` → `0 error(s)`
  (`NormalToken` 23,042, `WrappedToken` 30,142, `NormalZetherToken` 31,162, `WrappedZetherToken`
  40,706; `ZetherLib` 17,247, `ZetherStatements` 8,671, `ZetherDisclosure` 5,063, `UniversalAccountRegistry` 15,026).

- [ ] **Step 5: Commit** — `git add smartcontracts/evm` →
  `P3b: disclosure (BUNDLE | COMPACT) and auditor (NONE | FULL | OPTIONAL) modes at initialize; salt, sender memo, keyOf`

---
### Task 3: Deploy check, e2e, gas, the mutation probe

**Model:** Sonnet, effort medium (no code change; the probe is the gate).

**Files:** none committed (`DeployBase` is unchanged: P3b deploys nothing new; the registry's `keyOf` ships with the
dev-chain registry it already deploys).

- [ ] **Step 1: e2e** — `forge build` (full), then in `scaas-node`
  (`CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/scaas-node/target`): `cargo test --test e2e -- --ignored
  --test-threads=1` → 4 passed; `cargo test --test e2e_hedera -- --ignored` → 1 passed (no node change: the node reads
  nothing of Zether; the e2e chains are not dev chains).

- [ ] **Step 2: gas** — `forge test --match-path 'test/zether/*' -vv | grep -E '^\s+(bn254|bls12-381)'` and
  `forge test --match-test test_registerGas -vv`; the figures go into zether.md §19 in Task 4 (validated values are in
  the Task 4 diff).

- [ ] **Step 3: the mutation probe** (not committed; save as a scratch file, run with
  `scripts/capped python3 <file>`, set `R` to the worktree). Every mutant must be `KILLED`. Validated: 37/37 killed (31 forge mutants, 6 cargo mutants; the first run left P2 alive — an unknown auditor mode with a key passed the key check — and `test_invalidModesRefused` gained that case; P2 is killed on the rerun).

```python
import os, subprocess, sys
R='/home/ha/work/ainative/scaas/.claude/worktrees/p3b'
W=R+'/smartcontracts/evm'
P=R+'/clients/zether-prover'
L=W+'/src/zether/ZetherLib.sol'
Y=W+'/src/zether/ZetherLayer.sol'
S=W+'/src/zether/ZetherStatements.sol'
D=W+'/src/zether/ZetherDisclosure.sol'
V=W+'/src/zether/ZetherVerifier.sol'
T=W+'/src/metatx/MetaTokenBase.sol'
G=W+'/src/registry/UniversalAccountRegistry.sol'
RZ=P+'/src/zether.rs'
RA=P+'/src/api.rs'
Z='test/zether/*'
FZ='test/v2/FactoryZether.t.sol'
muts=[
 ('P1 init: disclosureMode unbounded', L, 'if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) revert IZetherToken.BadDisclosureMode(c.disclosureMode);', '', Z),
 ('P2 init: auditorMode unbounded', L, 'if (c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)\n            || (aud.length', 'if ((aud.length', Z),
 ('P3 init: key and auditorMode unmatched', L, '            || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))) {', ') {', Z),
 ('P4 disclosureMode not stored', L, '        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);\n', '', Z),
 ('P5 auditorMode not stored', L, '        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);\n', '', Z),
 ('P6 single open on COMPACT', L, '''        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT) {
            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
        }
        uint256 p = c.p;
        bytes calldata pts''', '''        uint256 p = c.p;
        bytes calldata pts''', Z),
 ('P7 every form open on COMPACT', L, 'if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {', 'if (false) {', Z),
 ('P8 memo length unchecked', L, 'if (memo.length != (mode == ZetherTypes.TransferMode.HASH ? 17 + 40 * pp.to.length : 0)) {', 'if (false) {', Z),
 ('P9 memoHash not in the header', L, '        if (memo.length != 0) pp.memoHash = keccak256(memo);\n', '', Z),
 ('P10 salt not in the header', L, 'uint128(pp.salt), pp.memoHash)', 'uint128(0), pp.memoHash)', Z),
 ('P11 salt not in the payload read', L, '        pp.salt = bytes16(payload[64:80]);\n', '', Z),
 ('P12 salt not in the record R', L, '        b = abi.encodePacked(salt);\n', '', Z),
 ('P13 memo not stored', L, '            s.memos[entryRef] = payload[legsEnd:];\n', '', Z),
 ('P14 commitment not stored', L, '            s.entryHashes[entryRef] = keccak256(r);\n', '', Z),
 ('P15 TransferBundles not emitted', L, '            emit IZetherToken.TransferBundles(entryRef, r);\n', '', Z),
 ('P16 NONE takes an auditor leg', L, '            if (nOff != m) revert IZetherToken.AuditorForbidden();\n', '', Z),
 ('P17 FULL takes an opt-out', L, '        if (c.auditorMode == ZetherTypes.AuditorMode.FULL) revert IZetherToken.AuditorRequired();\n', '', Z),
 ('P18 OPTIONAL takes a mix', L, '        if (nOff != m) revert IZetherToken.AuditorLegsMixed();\n', '', Z),
 ('P19 zetherTransfer always BUNDLE', L, '''        return $().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;''', '        return ZetherTypes.TransferMode.BUNDLE;', Z),
 ('P20 single record without salt', L, 's.entries[entryRef] = bytes.concat(pp.salt, pts[p:2 * p]', 's.entries[entryRef] = bytes.concat(pts[p:2 * p]', Z),
 ('Y1 transferEntry without the memo', Y, 'abi.encodePacked(h, ZetherLib.$().memos[entryRef])', 'abi.encodePacked(h)', Z),
 ('Y2 zetherTransferCompact stores R', Y, 'return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.HASH, _env());', 'return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.BUNDLE, _env());', Z),
 ('Y3 zetherTransferCompact not relayable', Y, '|| sel == this.zetherTransferCompact.selector || sel == this.zetherTransferNoBundle.selector', '|| sel == this.zetherTransferNoBundle.selector', Z),
 ('Y4 auditorMode view constant', Y, 'function auditorMode() external view returns (ZetherTypes.AuditorMode) { return ZetherLib.$().auditorMode; }', 'function auditorMode() external view returns (ZetherTypes.AuditorMode) { return ZetherTypes.AuditorMode.NONE; }', Z),
 ('S1 statement view ignores auditorMode', S, '        c.auditorMode = t.auditorMode();\n', '', Z),
 ('S2 statement view ignores disclosureMode', S, '        c.disclosureMode = t.disclosureMode();\n', '', Z),
 ('D1 record read without the salt', D, 'uint256 o = 16 + index * len;', 'uint256 o = index * len;', Z),
 ('D2 commitment by its old 32-byte length', D, 'if ((all.length - 16) % len != 0) {', 'if (all.length == 32) {', Z),
 ('V1 header 448', V, 'uint256 internal constant HEADER = 480;', 'uint256 internal constant HEADER = 448;', Z),
 ('T1 public kinds take the modes', T, ' || c.disclosureMode != 0 || c.auditorMode != 0', '', FZ),
 ('G1 registry keeps no key', G, '            key: encodedY\n', '            key: ""\n', 'test/zether/UniversalAccountRegistry.t.sol'),
 # prover (cargo test)
 ('R1 s without the salt', RZ, '[tag, &h.chain_uid, &h.token, from_ua, &be32_u64(h.send_counter), salt].concat()', '[tag, &h.chain_uid, &h.token, from_ua, &be32_u64(h.send_counter)].concat()', 'cargo'),
 ('R2 s without chainUid', RZ, '[tag, &h.chain_uid, &h.token, from_ua, &be32_u64(h.send_counter), salt].concat()', '[tag, &h.token, from_ua, &be32_u64(h.send_counter), salt].concat()', 'cargo'),
 ('R3 memo flag always on', RZ, '    let mut plain = vec![u8::from(auditor)];', '    let mut plain = vec![1u8];', 'cargo'),
 ('R4 recovery skips the commitment', RA, ' || commitment.is_some_and(|c| c != keccak256(&bundles))', '', 'cargo'),
 ('R5 COMPACT default form BUNDLE', RA, '        None if compact => TransferMode::Hash,', '        None if compact => TransferMode::Bundle,', 'cargo'),
 ('R6 salt not drawn', RZ, '        rng.fill_bytes(&mut salt);\n        let s = derive_s', '        let s = derive_s', 'cargo'),
]
sel=sys.argv[1:]
env=dict(os.environ, CARGO_TARGET_DIR='/home/ha/work/ainative/scaas/clients/zether-prover/target')
for name,f,a,b,path in muts:
    if sel and name.split()[0] not in sel: continue
    src=open(f).read(); assert src.count(a)==1,(name, src.count(a))
    open(f,'w').write(src.replace(a,b))
    try:
        if path=='cargo':
            r=subprocess.run(['cargo','test','--release','--no-fail-fast'],cwd=P,capture_output=True,text=True,env=env)
            out=r.stdout+r.stderr
            fails=[l for l in out.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
        else:
            r=subprocess.run(['forge','test','--fail-fast','--match-path',path],cwd=W,capture_output=True,text=True)
            out=r.stdout+r.stderr
            fails=[l for l in out.splitlines() if l.startswith('[FAIL')]
        comp='Compiler run failed' in out or 'error[E' in out
        status='KILLED' if fails or comp or r.returncode!=0 else 'SURVIVED'
        print(name, '|', status, '|', (fails[0][:150] if fails else ('compile' if comp else '')), flush=True)
    finally:
        open(f,'w').write(src)
```

| Mutant | Killed by (first failing test of the run) |
  |---|---|
  | P1 init: disclosureMode unbounded | `test_invalidModesRefused` |
  | P2 init: auditorMode unbounded | `test_invalidModesRefused` (the keyed case, added after the first run) |
  | P3 init: key and auditorMode unmatched | `test_invalidModesRefused` |
  | P4 disclosureMode not stored | `test_compactFull` |
  | P5 auditorMode not stored | `test_auditorSeesTransferButNoBalance` |
  | P6 single open on COMPACT | `test_compactFull` |
  | P7 every form open on COMPACT | `test_compactFull` |
  | P8 memo length unchecked | `test_memoAndSaltBoundByTheProof` |
  | P9 memoHash not in the header | `test_memoAndSaltBoundByTheProof` |
  | P10 salt not in the header | `test_statementHeaderCarriesChainUid` (the expected 480-byte header) |
  | P11 salt not in the payload read | `test_bundle*` (`_bundleForms`: "R, the salt first") |
  | P12 salt not in the record R | `test_bundle*` (`_bundleForms`: "R, the salt first") |
  | P13 memo not stored | `test_*` (`_hashForm` / `test_disclosureHashMode`: "keccak256(R) then the memo") |
  | P14 commitment not stored | `test_*` (`_hashForm` / `test_disclosureHashMode`: "keccak256(R) then the memo") |
  | P15 TransferBundles not emitted | `test_bundleFull` |
  | P16 NONE takes an auditor leg | `test_bundleNone` |
  | P17 FULL takes an opt-out | `test_relayedUnderTheModes` |
  | P18 OPTIONAL takes a mix | `test_auditorLegsMixedReverts` |
  | P19 zetherTransfer always BUNDLE | `test_compactFull` |
  | P20 single record without salt | `test_disclosureOnTheWrappedKind` |
  | Y1 transferEntry without the memo | `test_*` (`_hashForm` / `test_disclosureHashMode`: "keccak256(R) then the memo") |
  | Y2 zetherTransferCompact stores R | `test_bundleFull` |
  | Y3 zetherTransferCompact not relayable | `test_everyListedSelectorRuns_wrappedZether` |
  | Y4 auditorMode view constant | `test_batch_eachItemItsOwnBinding` |
  | S1 statement view ignores auditorMode | `test_auditorSeesTransferButNoBalance` |
  | S2 statement view ignores disclosureMode | `test_compactFull` |
  | D1 record read without the salt | `test_bundleFull` |
  | D2 commitment by its old 32-byte length | `test_bundleFull` |
  | V1 header 448 | `test_zether*` (every proof: the statement no longer parses) |
  | T1 public kinds take the modes | `test_publicKinds_refuseEveryConfField` |
  | G1 registry keeps no key | `test_registerSelfSchnorrBothCurves` (`keyOf`) |
  | R1 s without the salt | `two_builds_at_one_counter_differ` |
  | R2 s without chainUid | `recover_from_storage_alone` |
  | R3 memo flag always on | `recover_an_opt_out` |
  | R4 recovery skips the commitment | `recover_from_storage_alone` |
  | R5 COMPACT default form BUNDLE | `recover_an_opt_out` |
  | R6 salt not drawn | `two_builds_at_one_counter_differ` |

---
### Task 4: Docs — the rules flip to built, the measured gas, TODO, HANDOFF

**Model:** Sonnet, effort medium.

**Files:** `docs/contracts/{zether.md, settlement.md, token-wrappers.md}`, `docs/research/zether-disclosure.md`,
`docs/decisions.md`, `docs/history/dropped-artifacts.tsv`, `TODO.md`, `HANDOFF.md` (no edit to `pq-zero-knowledge.md`: PQZ
stays specified). Line deltas: zether.md 75/75, decisions.md 2/2, settlement/token-wrappers/research 1/1 (net 0 on
every page over budget); dropped-artifacts +2; TODO 2/2; HANDOFF +9.

- [ ] **Step 1: apply the diff** (status flips — "SPECIFIED, P3b" → "built in P3b", the "Transitional (BUILT, P3)" notes
  dropped — the §3 proof system ids, the §9/§11 payloads, §19 (a)/(b)/sizes/node cap re-measured, two C7 rows; the
  `settlement.md` row still said `...Commit`):

```diff
diff --git a/HANDOFF.md b/HANDOFF.md
index 6542ed6..2024b88 100644
--- a/HANDOFF.md
+++ b/HANDOFF.md
@@ -1,5 +1,14 @@
 # HANDOFF — scaas
 
+## Session 2026-10-11 (P3b)
+
+**State:** P3b (Zether storage and auditor modes, owner 2026-10-11) built from the plan `docs/superpowers/plans/2026-10-11-p3b-zether-modes.md`;
+the spec rules CTR-ZTH-30/38/42/48/49/50 flipped to built, §19 re-measured, PQZ (CTR-PQZ-19/23/24) spec only.
+
+**Rulings to confirm (controller, pending the owner):** the record `R = salt ‖ B…` also for the commitment (CTR-ZTH-38's table says `keccak256(B_1 ‖ … ‖ B_M)`), the `…/v2` proof system id label, `seed_zether` = the R33 conf key `x`, `AuditorForbidden` for NONE, the registry's `keyOf`, the `uint8` config fields with typed errors.
+
+**Not done / next:** R6 (archive of `TransferBundles` for receiver and auditor), the BLS12-381 M = 8 commit-reveal with the auditor now over the EIP-7825 cap, the client ABI (P5).
+
 ## Session 2026-10-11 (P4)
 
 **State:** P4 on branch `p4-accounts`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
diff --git a/TODO.md b/TODO.md
index c77dfc5..40f2795 100644
--- a/TODO.md
+++ b/TODO.md
@@ -15,7 +15,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 | P0 | Spec and fold into the component docs and `decisions.md` | done |
 | P1 | The complete base on the new tree: `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer; kinds `NORMAL`, `WRAPPED`; factory `createToken`; the v1/v2 lines to the backup (v2 done in P1e, v1 renamed `…V1` until P3/P5) | MT-1, MT-2, MT-3, MT-4 |
 | P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done, merged `d85fc8b`) | MT-5 |
-| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done, merged `dc9d219`; P3b modes pending) | MT-6 |
+| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done, merged `dc9d219`; P3b modes done) | MT-6 |
 | P4 | `MandateWallet`, `SmartKeyAccount` (rename: EVM, Solana, Soroban) on `MetaTxBase`; the typed-struct line to `legacy/p4/` (done, merged `ebacaac`) | MT-7 (+ rename in NM-*) |
 | P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |
 | P6 | PQ Zether after P5 (owner 2026-10-11): the E-S0…E-S8 stream ([pq-zero-knowledge.md](docs/contracts/pq-zero-knowledge.md)) on the finished token tree (`PqzToken` with CTR-PQZ-23/24 modes); PQ signatures as compatible as possible with the Ethereum drafts, both directions: ML-DSA ([EIP-8051](https://eips.ethereum.org/EIPS/eip-8051), [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355): empty FIPS 204 context with domain separation in the message, the EIP key and message encodings incl. the expanded key) and Falcon/FN-DSA ([EIP-8052](https://eips.ethereum.org/EIPS/eip-8052): its hash variant and encoding); precompiles found by probe at the EIP addresses, the 7622 addresses moved out of the EIP-1352 range; see [pq-eips-vs-scaas.md](docs/research/pq-eips-vs-scaas.md) Q1–Q3, Q6; owner 2026-10-11 ([CTR-UA-23](docs/contracts/accounts.md#CTR-UA-23)): ML-DSA with the empty context and the kind tag in the message (`pq_msg = keccak256(TAG(kind) ‖ ua_msg)`), vectors regenerated; new kind `slhdsa128s` (0x0133, SLH-DSA-SHA2-128s, FIPS 205) with a gas-measurement gate before any public chain enables it | UA PQ kinds, E-S* |
@@ -77,7 +77,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 - [ ] v1 line to backup (P5): `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1` (and `MetaToken`/`HederaMetaToken`/`MetaTxDex`) wait for the node and clientkeys (the e2e deploys them); the Zether part moved in P3 (E1; owner: backup, not delete).
 - [ ] `mtxBatch` needs a not-batchable hook for PQZ selectors (`MtxNotBatchable(selector)`, pq-zero-knowledge.md CTR-PQZ-21): with `PqzToken` (no PQZ selector exists yet; P3 left the room: the binding hook takes a PQZ tag).
 - [~] **MT-6** Zether (done in P3: transient envelope binding, `zetherShield` from the public balance, `mtxWrap` inherited, the `zether*` renames, binding without `to`/`value`, prover `Header.chain_uid`, `HEADER_LEN` 416; open: `PqzToken` on the one base, PQZ selectors not batchable, CTR-PQZ-21, with the PQZ stream).
-- [ ] **P3b** Zether storage and auditor modes (owner 2026-10-11; spec: zether.md CTR-ZTH-30/38/42/48/49/50, pq-zero-knowledge.md CTR-PQZ-19/23/24, already written): `ConfidentialConfig.disclosureMode`/`auditorMode` + factory and `initialize` validation (`BadDisclosureMode`, `BadAuditorMode`); entry renames (`zetherTransfer` = mode default, `zetherTransferCompact`, `zetherTransferNoBundle` BUNDLE-only, `zetherTransferBundle` to legacy) and guards (`TransferEntryDisabled`, `AuditorRequired`); auditor modes NONE/FULL/OPTIONAL; `s` v2 with the 16-byte salt in payload and the 480-byte header (new `proofSystemId`); sender memo + `memoHash` and a recovery helper in the prover (seed + storage → openings); relay allowlist and selectors; vectors/KATs regenerated; gas re-measured (§19). PQZ: spec only.
+- P3b (done): `ConfidentialConfig.disclosureMode` (BUNDLE / COMPACT) and `auditorMode` (NONE / FULL / OPTIONAL) fixed at `initialize` (`BadDisclosureMode`, `BadAuditorMode`); `zetherTransfer` = the mode's default, `zetherTransferCompact` (commit-reveal), `zetherTransferNoBundle` and `zetherTransferSingle` BUNDLE-only (`TransferEntryDisabled`), `zetherTransferBundle` removed; `AuditorRequired` / `AuditorForbidden`; `s` v2 with the 16-byte salt, the 480-byte header (`…/v2` proof system id), the record `R = salt ‖ B_1 ‖ … ‖ B_M`, the sender memo next to the commitment (`transferEntry` = `keccak256(R) ‖ memo`), the registry's `keyOf`; prover `recoverTransfer` (seed + storage or calldata → `s`, amounts, `R`, `SENDER_S` / `SENDER_CP`), `disclosureMode` / `auditorMode` in requests; vectors regenerated; §19 re-measured. PQZ: spec only. Plan `docs/superpowers/plans/2026-10-11-p3b-zether-modes.md`.
 
 **P4 — MT-7**
 - P4 (done, merged `ebacaac`): `SmartKeyAccount` / `SmartKeyAccountFactory(chainUid)` and `MandateWallet(owner, chainUid)` / `HederaMandateWallet` on `MetaTxBase` (domains `SCaaS SmartKeyAccount`, `SCaaS MandateWallet`, `salt = chain_uid`), the account signs its own key management (`_selfSender` hook), `mtxExecuteAsOwner`, `mtxPayUnderMandate`, `mtxRevoke` with derived lanes, `revoke(token, epoch)` and `payUnderMandate(token, payee, amount, entryRef, epoch)` (selector `0x781fc8a8`; a revoke or any `setMandate` voids queued delegate pays; `setMandate` keeps the running period when delegate and period are unchanged; controller rulings, pending the owner; CTR-ACC-07), `mtxExecuteAsOwnerRaw`; Solana `state::SmartKeyAccount`; clientkeys `checkOwnerCall` on the salted `MetaTransaction`; KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`, `mandate_revoke_kat.json`, `smart_key_account_create2.json`; deploy JSON `smart_key_account_factory` / `_implementation`; the typed-struct `SubjectAccount`, `MandateWallet`, `HederaMandateWallet` and their tests in `smartcontracts/evm/legacy/p4/`. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
diff --git a/docs/contracts/settlement.md b/docs/contracts/settlement.md
index 8cc2236..dfd235a 100644
--- a/docs/contracts/settlement.md
+++ b/docs/contracts/settlement.md
@@ -241,7 +241,7 @@ Confidential tokens are meta-tx tokens: the target is a `ZetherLayer` on `MetaTo
 point an allowlisted self-call of `mtxExecute` with `ABSOLUTE` fee class ([CTR-ZTH-08](zether.md#CTR-ZTH-08),
 [CTR-ZTH-34](zether.md#CTR-ZTH-34)). Kinds of settlement: **shield** from the public balance (`zetherShield`,
 [CTR-ZTH-35](zether.md#CTR-ZTH-35)), **transfer** to one or several recipients with decoys and one proof
-(`zetherTransfer`, `...Single`, `...Commit` (built: `...Bundle`), `...NoBundle`, [CTR-ZTH-37](zether.md#CTR-ZTH-37),
+(`zetherTransfer`, `...Single`, `...Compact`, `...NoBundle`, [CTR-ZTH-37](zether.md#CTR-ZTH-37),
 [CTR-ZTH-38](zether.md#CTR-ZTH-38)), **unshield** (`zetherUnshield`) and **roll-over** of pending credits
 ([CTR-ZTH-45](zether.md#CTR-ZTH-45)). The proof carries an envelope binding, so a proof lifted out of its envelope
 fails ([CTR-ZTH-06](zether.md#CTR-ZTH-06)). PQZ mirrors the names with `pqz` and relays the same way
diff --git a/docs/contracts/token-wrappers.md b/docs/contracts/token-wrappers.md
index f103101..d993356 100644
--- a/docs/contracts/token-wrappers.md
+++ b/docs/contracts/token-wrappers.md
@@ -664,7 +664,7 @@ struct TokenConfig {
     uint256 initialSupply; address initialHolder;   // NORMAL* only; initialHolder is ignored when initialSupply == 0
     Leg[] legs;                                // underlying (address(0) = native coin, CTR-TOK-26), num, den — WRAPPED* only, 1..8
     RateConfig rate;                           // with RATE_ADJUSTABLE
-    ConfidentialConfig conf;                   // verifier, auditorKey (empty = none), shieldScale, maxShielded, confidentialFee, disclosureMode {BUNDLE, COMPACT}, auditorMode {NONE, FULL, OPTIONAL} — *_ZETHER only (modes: CTR-ZTH-48/49, specified for P3b; the factory refuses a key that does not match auditorMode)
+    ConfidentialConfig conf;                   // verifier, auditorKey (empty = none), shieldScale, maxShielded, confidentialFee, disclosureMode {BUNDLE, COMPACT}, auditorMode {NONE, FULL, OPTIONAL} — *_ZETHER only (modes: CTR-ZTH-48/49, built in P3b; the factory refuses a key that does not match auditorMode)
 }
 struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool listedOnly; }
 ```
diff --git a/docs/contracts/zether.md b/docs/contracts/zether.md
index 81abf7a..7556a22 100644
--- a/docs/contracts/zether.md
+++ b/docs/contracts/zether.md
@@ -8,7 +8,7 @@ tests (P3; `smartcontracts/evm/src/zether/**`, `src/registry/**`). Every Zether
 deploy or initialize outside chain ids 31337/1337, and `OpenFactory.zetherEnabled` defaults to `false` ([safety
 gate](#safety-gate)). Post-quantum confidential balances are a separate class ([pq-zero-knowledge.md](pq-zero-knowledge.md)). Relaying is
 the generic self-call ([relaying](#envelope)), `chainUid` is in every chain-bound digest; the built `ZetherToken` with its
-`ZetherMetaTx` envelope is backed up, not built, in `smartcontracts/evm/legacy/p3/`. **SPECIFIED, not built (P3b):** the storage and auditor modes, the salted `s` and the sender memo ([CTR-ZTH-38](#CTR-ZTH-38), [CTR-ZTH-48](#CTR-ZTH-48)–[CTR-ZTH-50](#CTR-ZTH-50), [CTR-ZTH-30](#CTR-ZTH-30)).
+`ZetherMetaTx` envelope is backed up, not built, in `smartcontracts/evm/legacy/p3/`. **Built (P3b):** the storage and auditor modes, the salted `s` and the sender memo ([CTR-ZTH-38](#CTR-ZTH-38), [CTR-ZTH-48](#CTR-ZTH-48)–[CTR-ZTH-50](#CTR-ZTH-50), [CTR-ZTH-30](#CTR-ZTH-30)).
 
 This file is the contract between the prover and the Solidity verifier: **every byte** of the statement, the
 transcript and the proof must be exactly as written here. An ambiguity is a bug of this document — report it, do not
@@ -153,7 +153,7 @@ strong Fiat-Shamir). NUMS generators are computed in the verifier constructor an
 | Precompiles | `0x06` add, `0x07` mul (MSM = a mul+add loop) | `0x0b` G1ADD, `0x0c` G1MSM (subgroup check), `0x10` MAP_FP_TO_G1 |
 | Security | ~100 bit | ~117–126 bit |
 | Chains | any EVM since Byzantium | Prague (EIP-2537) |
-| `proofSystemId` | `keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v1")` | `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v1")` |
+| `proofSystemId` | `keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v2")` | `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v2")` (`v2`: the 480-byte header, P3b; label: controller ruling, pending the owner) |
 
 Both curves are supported; the token creator chooses the verifier. BLS12-381 buys security, **not** gas (measured: it
 is more expensive; an earlier "45–60 % cheaper" claim is wrong). Which curve production tokens should use is open
@@ -331,7 +331,7 @@ protocol change that needs its own cryptographic review; epochs are not the fall
 ## <a id="statement-byte-layout"></a>7. Statement (byte layout)
 
 The token **builds** the statement from storage + payload; the prover builds exactly the same. `P` = the bytes of one
-point. Header (common to every op, `chainUid` at offset 96, [CTR-ZTH-36](#CTR-ZTH-36); the verifier reads `fee` at 288 and `amount` at 352). **Built (P3): 416 bytes**, offsets 0–384; **SPECIFIED (P3b): 480 bytes** with `salt` and `memoHash` (a new `proofSystemId`; both transfer payloads carry `salt(16)` right after `be32(provedSendCounter)`, and a commit-reveal payload appends `memo` after the legs):
+point. Header (common to every op, `chainUid` at offset 96, [CTR-ZTH-36](#CTR-ZTH-36); the verifier reads `fee` at 288 and `amount` at 352). **480 bytes** (built in P3b; P3: 416) with `salt` and `memoHash`, under the `…/v2` `proofSystemId`; both transfer payloads carry `salt(16)` right after `be32(provedSendCounter)`, and a commit-reveal payload appends `memo` after the legs:
 
 | Offset | Len | Field |
 |---|---|---|
@@ -348,8 +348,8 @@ point. Header (common to every op, `chainUid` at offset 96, [CTR-ZTH-36](#CTR-ZT
 | 320 | 32 | `beneficiary` (UA receiving the fee; 0 if none) |
 | 352 | 32 | `amount` (burn; transfer = 0) |
 | 384 | 32 | `recipient` (burn: 12 zero bytes ‖ address; transfer = 0) |
-| 416 | 32 | `salt` — 16 zero bytes ‖ the build salt of [CTR-ZTH-30](#CTR-ZTH-30) (burn = 0); SPECIFIED (P3b; offsets 416/448: controller ruling, pending the owner) |
-| 448 | 32 | `memoHash` — `keccak256(memo)` on commit-reveal ([CTR-ZTH-50](#CTR-ZTH-50)), else 0; SPECIFIED (P3b) |
+| 416 | 32 | `salt` — 16 zero bytes ‖ the build salt of [CTR-ZTH-30](#CTR-ZTH-30) (burn = 0; offsets 416/448: controller ruling, pending the owner) |
+| 448 | 32 | `memoHash` — `keccak256(memo)` on commit-reveal ([CTR-ZTH-50](#CTR-ZTH-50)), else 0 |
 
 <a id="CTR-ZTH-36"></a>**CTR-ZTH-36** — **Every chain-bound Zether digest carries `chainUid` beside `chainid`** (owner):
 the statement header (above), the envelope binding ([CTR-ZTH-06](#CTR-ZTH-06)), the disclosure challenge
@@ -501,7 +501,7 @@ burn     = V_b ‖ A_y ‖ A_bal ‖ A_Vb ‖ z_x ‖ z_b ‖ z_gb ‖ BP(64)
 Payload (calldata for the token, from which the statement takes its points):
 
 ```
-transfer payload = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud   (64 + 6P)
+transfer payload = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud   (80 + 6P)
 burn payload     = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ Y_f                                       (64 + P)
 ```
 
@@ -547,7 +547,7 @@ aggregation). Soundness as [CTR-ZTH-18](#CTR-ZTH-18): the only sum of proven val
 **Encoding.**
 
 ```text
-payload   = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_{j=1..M}
+payload   = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ salt(16) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_{j=1..M} [‖ memo]
 statement = header(opTag) ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_{j=1..M}
 opTag     = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/" ‖ mode)     mode ∈ {"HASH", "BUNDLE", "NONE"}
 proof     = sigma commitments ‖ sigma responses ‖ BP(v_1) … BP(v_M) ‖ BP(b')
@@ -564,7 +564,7 @@ matches it. Relaying through the meta-transaction envelope is the generic self-c
 once. `entryRef` as in the single format (one per transfer); recipient `j` is addressed as `(entryRef, j)`.
 
 <a id="storage-modes"></a>
-<a id="CTR-ZTH-38"></a>**CTR-ZTH-38** — **Three transfer entries; the plain name is the mode's default** (owner 2026-10-08, 2026-10-11; SPECIFIED, P3b). `zetherTransfer`, `zetherTransferCompact`, `zetherTransferNoBundle`, all `(bytes payload, bytes proof, bytes authSig, UA beneficiary) returns (bytes32 entryRef)`; the salt ([CTR-ZTH-30](#CTR-ZTH-30)) and the sender memo ([CTR-ZTH-50](#CTR-ZTH-50)) travel inside `payload`, so they are signed and the ABI shape is the same for every entry. The bundle of leg `j` is `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` (bn254 256 B, BLS12-381 512 B per leg); the record is `R = salt ‖ B_1 ‖ … ‖ B_M`. Commit-reveal stores `keccak256(R)` (one slot) ‖ `memo` and emits `TransferBundles(entryRef, R)`; on-chain disclosure then takes `R` from the caller and `ZetherDisclosure` checks the hash. Every entry emits `ZetherTransferMulti(from, beneficiary, fee, sendCounter, entryRef, recipients, mode)`; `mode` in the event and the `opTag` names what is stored:
+<a id="CTR-ZTH-38"></a>**CTR-ZTH-38** — **Three transfer entries; the plain name is the mode's default** (owner 2026-10-08, 2026-10-11; built in P3b). `zetherTransfer`, `zetherTransferCompact`, `zetherTransferNoBundle`, all `(bytes payload, bytes proof, bytes authSig, UA beneficiary) returns (bytes32 entryRef)`; the salt ([CTR-ZTH-30](#CTR-ZTH-30)) and the sender memo ([CTR-ZTH-50](#CTR-ZTH-50)) travel inside `payload`, so they are signed and the ABI shape is the same for every entry. The bundle of leg `j` is `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` (bn254 256 B, BLS12-381 512 B per leg); the record is `R = salt ‖ B_1 ‖ … ‖ B_M`. Commit-reveal stores `keccak256(R)` (one slot) ‖ `memo` and emits `TransferBundles(entryRef, R)`; on-chain disclosure then takes `R` from the caller and `ZetherDisclosure` checks the hash. Every entry emits `ZetherTransferMulti(from, beneficiary, fee, sendCounter, entryRef, recipients, mode)`; `mode` in the event and the `opTag` names what is stored:
 
 | Entry | BUNDLE token ([CTR-ZTH-48](#CTR-ZTH-48)): stored per transfer | COMPACT token: stored per transfer |
 |---|---|---|
@@ -573,13 +573,13 @@ once. `entryRef` as in the single format (one per transfer); recipient `j` is ad
 | `zetherTransferNoBundle` | nothing (cheapest; disclosure off chain from calldata) | reverts `TransferEntryDisabled` (owner, 2026-10-11: every transfer stays openable) |
 | `zetherTransferSingle` | stores `R` with its one leg (`j = 0`), event `ZetherTransfer` | reverts `TransferEntryDisabled` (controller ruling, pending the owner) |
 
-Every entry also updates `acc_f`, `pending_tj` and `sendCounter`; the commitment entries put the full bundles in `TransferBundles(entryRef, bundles)` and calldata. The prover and client default to `zetherTransfer`; a caller on a BUNDLE token may pick commit-reveal or no-bundle to save gas. `s` of one transfer opens only that transfer ([CTR-ZTH-30](#CTR-ZTH-30)). Off-chain checking needs no storage. Who can open what under each storage: [who can open what](#who-opens); costs: [gas](#gas). **Transitional (BUILT, P3):** `zetherTransfer` = HASH (the documented default), `zetherTransferBundle` = BUNDLE, `zetherTransferNoBundle` = NONE, open on every token; no salt in the record, HASH stores a 32-byte `bytes` (two slots) and no memo. P3b renames as above (`zetherTransferBundle` goes; selectors, the relay allowlist, the prover API and the vectors change).
+Every entry also updates `acc_f`, `pending_tj` and `sendCounter`; the commitment entries put the full bundles in `TransferBundles(entryRef, bundles)` and calldata. The prover and client default to `zetherTransfer`; a caller on a BUNDLE token may pick commit-reveal or no-bundle to save gas. `s` of one transfer opens only that transfer ([CTR-ZTH-30](#CTR-ZTH-30)). Off-chain checking needs no storage. Who can open what under each storage: [who can open what](#who-opens); costs: [gas](#gas). The P3 entry `zetherTransferBundle` is gone (`zetherTransfer` was HASH there).
 
 <a id="disclosure-mode"></a>
-<a id="CTR-ZTH-48"></a>**CTR-ZTH-48** — **`disclosureMode ∈ {BUNDLE, COMPACT}` is chosen at `initialize` and immutable** (owner, 2026-10-11; SPECIFIED, P3b). It is `ConfidentialConfig.disclosureMode` through `OpenFactory` ([CTR-TOK-25](token-wrappers.md#CTR-TOK-25)), readable as `disclosureMode()`; an unknown value reverts `BadDisclosureMode`. BUNDLE: every entry of [CTR-ZTH-38](#CTR-ZTH-38) is open and `zetherTransfer` stores the full record. COMPACT: commit-reveal only (`zetherTransfer` = `zetherTransferCompact`); `zetherTransferNoBundle` and `zetherTransferSingle` revert `TransferEntryDisabled(disclosureMode)`. One implementation per kind serves both modes: COMPACT is a subset of BUNDLE, the modes are config flags and the kinds stay `NORMAL_ZETHER` / `WRAPPED_ZETHER` ([CTR-TOK-21](token-wrappers.md#CTR-TOK-21)); separate implementations were rejected and are revisited only if EIP-170 forces smaller bytecode. **Transitional (BUILT, P3):** no field; every token offers all entries, with HASH as the default.
+<a id="CTR-ZTH-48"></a>**CTR-ZTH-48** — **`disclosureMode ∈ {BUNDLE, COMPACT}` is chosen at `initialize` and immutable** (owner, 2026-10-11; built in P3b). It is `ConfidentialConfig.disclosureMode` through `OpenFactory` ([CTR-TOK-25](token-wrappers.md#CTR-TOK-25)), readable as `disclosureMode()`; an unknown value reverts `BadDisclosureMode`. BUNDLE: every entry of [CTR-ZTH-38](#CTR-ZTH-38) is open and `zetherTransfer` stores the full record. COMPACT: commit-reveal only (`zetherTransfer` = `zetherTransferCompact`); `zetherTransferNoBundle` and `zetherTransferSingle` revert `TransferEntryDisabled(disclosureMode)`. One implementation per kind serves both modes: COMPACT is a subset of BUNDLE, the modes are config flags and the kinds stay `NORMAL_ZETHER` / `WRAPPED_ZETHER` ([CTR-TOK-21](token-wrappers.md#CTR-TOK-21)); separate implementations were rejected and are revisited only if EIP-170 forces smaller bytecode.
 
 <a id="auditor-mode"></a>
-<a id="CTR-ZTH-49"></a>**CTR-ZTH-49** — **`auditorMode ∈ {NONE, FULL, OPTIONAL}` is chosen at `initialize` and immutable** (owner, 2026-10-11; SPECIFIED, P3b), `ConfidentialConfig.auditorMode` beside `auditorKey` ([CTR-ZTH-09](#CTR-ZTH-09)), readable as `auditorMode()`. The rule binds every transfer, single and multi-recipient:
+<a id="CTR-ZTH-49"></a>**CTR-ZTH-49** — **`auditorMode ∈ {NONE, FULL, OPTIONAL}` is chosen at `initialize` and immutable** (owner, 2026-10-11; built in P3b), `ConfidentialConfig.auditorMode` beside `auditorKey` ([CTR-ZTH-09](#CTR-ZTH-09)), readable as `auditorMode()`. The rule binds every transfer, single and multi-recipient:
 
 | Mode | `auditorKey` | Each transfer | The auditor reads |
 |---|---|---|---|
@@ -587,13 +587,13 @@ Every entry also updates `acc_f`, `pending_tj` and `sendCounter`; the commitment
 | FULL | set | every `C_aud_j ≠ O`, `Y_a` = the key; an opt-out reverts `AuditorRequired` | every transfer from token creation; exact balances by bookkeeping (balances start at 0, shield and unshield are public) |
 | OPTIONAL | set | all legs in or all out, the sender's choice ([CTR-ZTH-42](#CTR-ZTH-42)) | every transfer except the publicly visible opt-outs; balance reconstruction breaks after an opt-out |
 
-The factory and `initialize` refuse FULL or OPTIONAL without a key, NONE with a key and an unknown value (`BadAuditorMode`; the error names `BadAuditorMode`, `AuditorRequired`, `BadDisclosureMode`, `TransferEntryDisabled` are a controller ruling, pending the owner). Reading still needs the leg data: the stored record, or `TransferBundles` / calldata ([who can open what](#who-opens)). One implementation serves the three modes: the token-side difference is a few checks, the E6 check lives in the shared verifier, and an immutable public config gives the same assurance as a separate kind. **Transitional (BUILT, P3):** no field; a token with a key behaves as OPTIONAL, one without as NONE.
+The factory and `initialize` refuse FULL or OPTIONAL without a key, NONE with a key and an unknown value (`BadAuditorMode`; the error names `BadAuditorMode`, `AuditorRequired`, `BadDisclosureMode`, `TransferEntryDisabled` are a controller ruling, pending the owner). Reading still needs the leg data: the stored record, or `TransferBundles` / calldata ([who can open what](#who-opens)). One implementation serves the three modes: the token-side difference is a few checks, the E6 check lives in the shared verifier, and an immutable public config gives the same assurance as a separate kind. Built: the NONE refusal of an auditor leg is `AuditorForbidden` (controller ruling, pending the owner).
 
 <a id="auditor-per-transfer"></a>
-<a id="CTR-ZTH-42"></a>**CTR-ZTH-42** — **Under `auditorMode = OPTIONAL` the sender may leave the auditor out of a transfer**, in both formats (owner; mode: [CTR-ZTH-49](#CTR-ZTH-49), SPECIFIED). Either every `C_aud_j ≠ O` (statement `Y_a` = the token key) or every `C_aud_j = O` (statement `Y_a = O`, E6 skipped); a mix reverts (`AuditorLegsMixed`). `Y_a` is in the statement and the transcript, so a proof made for one choice never verifies under the other. The single format follows the same rule with its one `C_aud`. Owner-accepted consequence: on such a transfer the auditor reads nothing, and the opt-out is publicly visible (`C_aud = O`). NONE forces every `C_aud_j = O`, FULL every `C_aud_j ≠ O`. **Transitional (BUILT, P3):** the opt-out is open on every token with an auditor key.
+<a id="CTR-ZTH-42"></a>**CTR-ZTH-42** — **Under `auditorMode = OPTIONAL` the sender may leave the auditor out of a transfer**, in both formats (owner; mode: [CTR-ZTH-49](#CTR-ZTH-49), SPECIFIED). Either every `C_aud_j ≠ O` (statement `Y_a` = the token key) or every `C_aud_j = O` (statement `Y_a = O`, E6 skipped); a mix reverts (`AuditorLegsMixed`). `Y_a` is in the statement and the transcript, so a proof made for one choice never verifies under the other. The single format follows the same rule with its one `C_aud`. Owner-accepted consequence: on such a transfer the auditor reads nothing, and the opt-out is publicly visible (`C_aud = O`). NONE forces every `C_aud_j = O`, FULL every `C_aud_j ≠ O`.
 
 <a id="sender-memo"></a>
-<a id="CTR-ZTH-50"></a>**CTR-ZTH-50** — **Commit-reveal stores a sender memo, so the sender opens its transfer from its seed and contract storage alone** (owner, 2026-10-11; SPECIFIED, P3b; both disclosure modes; no logs, nothing remembered). Next to the 32-byte commitment:
+<a id="CTR-ZTH-50"></a>**CTR-ZTH-50** — **Commit-reveal stores a sender memo, so the sender opens its transfer from its seed and contract storage alone** (owner, 2026-10-11; built in P3b; both disclosure modes; no logs, nothing remembered). Next to the 32-byte commitment:
 
 ```text
 key  = HKDF-SHA256(seed_zether, info = "ZTX/memo/v1" ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt)   (32 B)
@@ -601,7 +601,7 @@ ks   = HKDF-Expand-SHA256(key, info = "ZTX/memo/ks/v1", L = 1 + 40·M)
 memo = salt ‖ ((flags ‖ (be8(v_j) ‖ toUA_j)_{j=1..M}) XOR ks)      flags: u8, bit0 = auditor included   (17 + 40·M B)
 ```
 
-No MAC: a wrong decryption rebuilds bundles that fail the commitment. The memo travels in `payload`; `memoHash = keccak256(memo)` is in the statement header ([Statement](#statement-byte-layout)), so `authSig` covers it and a relayer can neither alter nor drop it; the token checks `|memo| = 17 + 40·M`. The keystream label `"ZTX/memo/ks/v1"` and the `flags` byte are a controller ruling, pending the owner. Only what cannot be recomputed is stored (the sender's choices: amounts, decoys at 0, recipients); `s`, the memo key and `Y_a` are recomputed. The `flags` byte records the auditor choice, so recovery needs no guessing (it matters under OPTIONAL). Size at `M = 1`: 32 + 57 B ≈ 3 slots against ≈ 9 for a full bn254 bundle (gas: [§19](#gas), to be measured in P3b). The receiver and the auditor do not know `s` and still read `R` from `TransferBundles` / calldata: commit-reveal guarantees recovery from storage for the sender only; theirs depends on log availability (an archive of `TransferBundles` is an open item). Recovery:
+No MAC: a wrong decryption rebuilds bundles that fail the commitment. The memo travels in `payload`; `memoHash = keccak256(memo)` is in the statement header ([Statement](#statement-byte-layout)), so `authSig` covers it and a relayer can neither alter nor drop it; the token checks `|memo| = 17 + 40·M`. The keystream label `"ZTX/memo/ks/v1"` and the `flags` byte are a controller ruling, pending the owner. Only what cannot be recomputed is stored (the sender's choices: amounts, decoys at 0, recipients); `s`, the memo key and `Y_a` are recomputed. The `flags` byte records the auditor choice, so recovery needs no guessing (it matters under OPTIONAL). Size at `M = 1`: 32 + 57 B (the commitment slot, the memo's length slot and two data slots) against ≈ 9 slots for a full bn254 record (gas: [§19](#gas)). The recipients' keys come from the registry's `keyOf(toUA)` (added in P3b; the built registry kept only the key length). The prover's `recoverTransfer` runs the flow below (and the same from a stored record `R` or from calldata). The receiver and the auditor do not know `s` and still read `R` from `TransferBundles` / calldata: commit-reveal guarantees recovery from storage for the sender only; theirs depends on log availability (an archive of `TransferBundles` is an open item). Recovery:
 
 ```mermaid
 flowchart LR
@@ -614,8 +614,6 @@ flowchart LR
     H -->|yes| O["SENDER_S / SENDER_CP openings"]
 ```
 
-**Transitional (BUILT, P3):** no memo; HASH stores only the hash, so the sender needs calldata or logs.
-
 **PQZ.** The PQZ encryption is already multi-recipient with shared randomness ([CTR-PQZ-04](pq-zero-knowledge.md#CTR-PQZ-04)); an extra recipient there costs a full `u ‖ v_j` credit at rollover ([CTR-PQZ-11](pq-zero-knowledge.md#CTR-PQZ-11)), and no PQZ multi-recipient proof exists yet. The storage and auditor modes, the salt and the sender memo carry over ([CTR-PQZ-23](pq-zero-knowledge.md#CTR-PQZ-23), [CTR-PQZ-24](pq-zero-knowledge.md#CTR-PQZ-24)).
 
 ## 12. Meta-transaction envelope and replay protection
@@ -875,7 +873,7 @@ e = hashToScalar(keccak256("SCAAS-ZETHER-DISCLOSE-V1" ‖ be32(chainid) ‖ chai
 
 Additional checks: `amount < 2^n_v = 2^64` (otherwise `amount + r` would also "pass", because `[amount]G` depends only on `amount mod r`; `2^64 < r`, so each `[amount]G` has exactly one valid `amount`), `z < r`, `e ≠ 0`; `A1`, `A2` go into the same MSM (subgroup check on BLS12-381). The auditor reads exactly the per-transfer `C_aud_j` and never anyone's `acc`/`pending` (encrypted under the owners' keys). Disclosure is irrevocable once an opening is handed over (the sender's `s` opens only this transfer, [CTR-ZTH-30](#CTR-ZTH-30)).
 
-<a id="who-opens"></a>**Who can open what, per storage** (SPECIFIED, P3b; [CTR-ZTH-38](#CTR-ZTH-38), [CTR-ZTH-49](#CTR-ZTH-49), [CTR-ZTH-50](#CTR-ZTH-50)). The auditor column assumes FULL, or OPTIONAL and a transfer that included it; under NONE, or after an opt-out, the auditor opens nothing.
+<a id="who-opens"></a>**Who can open what, per storage** (built in P3b; [CTR-ZTH-38](#CTR-ZTH-38), [CTR-ZTH-49](#CTR-ZTH-49), [CTR-ZTH-50](#CTR-ZTH-50)). The auditor column assumes FULL, or OPTIONAL and a transfer that included it; under NONE, or after an opt-out, the auditor opens nothing.
 
 | Storage | Sender (`s`, every leg; or `SENDER_CP`, one leg) | Receiver `j` (`RECEIVER_X`, its leg) | Auditor (`AUDITOR`, every leg) |
 |---|---|---|---|
@@ -893,7 +891,7 @@ Additional checks: `amount < 2^n_v = 2^64` (otherwise `amount + r` would also "p
 <a id="CTR-ZTH-41"></a>**CTR-ZTH-41** — **The auditor key should be a k-of-n threshold key** (owner), e.g. company, audit firm and regulator: `Y_a` stays one public key and `x_a` is split off chain by a DKG, so decrypting or an `AUDITOR` opening needs k parties (FULL and OPTIONAL tokens). No contract change; the prover/CLI protocol follows with [CTR-ZTH-29](#CTR-ZTH-29).
 
 <a id="sender-randomness"></a>
-<a id="CTR-ZTH-30"></a>**CTR-ZTH-30** — **The sender randomness `s` is derived from the seed and a published salt, not stored** (owner; salt form 2026-10-11, SPECIFIED, P3b): `s = OKM mod r`, `OKM = HKDF-SHA256(seed_zether, info = "ZTX/s/v2" ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt, L = 64)`, where `salt` = 16 fresh random bytes per build, published with the transfer (statement header and payload, hence in the event, the stored record `R`, the commitment and the no-bundle calldata) and not checked by the contract; the prover re-draws on `s = 0` (`OKM mod r` and the re-draw: controller ruling, pending the owner). The sender rebuilds `s` from its seed and the published salt, and opens the transfer from storage alone through the memo ([CTR-ZTH-50](#CTR-ZTH-50)). Why the salt: the counter-only form (`"ZTX/s/v1" ‖ chainId ‖ tokenAddress ‖ fromUA ‖ sendCounter`) reuses `s` on a retry at the same counter, and `C_aud₁ − C_aud₂ = [v₁ − v₂]G` leaks the amount difference (failed-transaction calldata is public); mixing the amounts into `s` made the sender remember amounts. (An earlier rule "the client must store every `s`" is superseded.) **Transitional (BUILT, P3):** the prover derives `s` as `SHA-512("SCAAS-ZETHER-S-V1" ‖ x ‖ chainId ‖ chainUid ‖ token ‖ sendCounter ‖ Y_to ‖ v)` (every `(Y_j, v_j)` for a multi-recipient transfer; `clients/zether-prover/src/zether.rs`, `derive_s`), with no salt.
+<a id="CTR-ZTH-30"></a>**CTR-ZTH-30** — **The sender randomness `s` is derived from the seed and a published salt, not stored** (owner; salt form 2026-10-11, built in P3b): `s = OKM mod r`, `OKM = HKDF-SHA256(seed_zether, info = "ZTX/s/v2" ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt, L = 64)`, where `salt` = 16 fresh random bytes per build, published with the transfer (statement header and payload, hence in the event, the stored record `R`, the commitment and the no-bundle calldata) and not checked by the contract; the prover re-draws on `s = 0` (`OKM mod r` and the re-draw: controller ruling, pending the owner). The sender rebuilds `s` from its seed and the published salt, and opens the transfer from storage alone through the memo ([CTR-ZTH-50](#CTR-ZTH-50)). Why the salt: the counter-only form (`"ZTX/s/v1" ‖ chainId ‖ tokenAddress ‖ fromUA ‖ sendCounter`) reuses `s` on a retry at the same counter, and `C_aud₁ − C_aud₂ = [v₁ − v₂]G` leaks the amount difference (failed-transaction calldata is public); mixing the amounts into `s` made the sender remember amounts. (An earlier rule "the client must store every `s`" is superseded.) `seed_zether` is the account's confidential key `x` (the IKM; controller ruling, pending the owner); `clients/zether-prover/src/zether.rs` `derive_s`.
 
 <a id="independent-verifier"></a>
 <a id="CTR-ZTH-29"></a>**CTR-ZTH-29** — **An independent, open-source disclosure verifier CLI** (owner, PLANNED): any third party (an auditor, a dispute resolver) verifies an opening against chain data without trusting SCaaS. The chain of evidence holds in both directions: the sender cannot open falsely (the ciphertext binds `v` and `s`), and the receiver cannot deny the amount (its own key opens it). The CLI takes `(entryRef, v, s)`, reads an archive node or a signed chain export, and prints PASS/FAIL with every intermediate value, deterministically (two examiners get the same result); the client exports a standalone evidence file `(entryRef, v, s, chainId, tokenAddress)` that the CLI checks without the app.
@@ -935,7 +933,7 @@ leg may be the native coin like on every `WRAPPED*` kind ([CTR-TOK-26](token-
 |---|---|
 | `zetherShield(ua, amount)` | `_burn(sender, amount·shieldScale)` from the public balance; `pending[ua] += [amount]G` |
 | `zetherWrapShield(u, amountIn, ua)` | `WrappedLib` pulls `amountIn` of leg `u` and computes the public-equivalent `minted` at the leg's rate **without minting**; `minted % shieldScale ≠ 0` ⇒ `AmountNotScaled` (the client sends an exact amount); `pending[ua] += [minted / shieldScale]G` |
-| `zetherTransfer`, `zetherTransferCompact`, `zetherTransferNoBundle`, `zetherTransferSingle` (built: `zetherTransfer` = HASH, `zetherTransferBundle`) | the multi-recipient transfers of [CTR-ZTH-37](#CTR-ZTH-37)/[CTR-ZTH-38](#CTR-ZTH-38) |
+| `zetherTransfer`, `zetherTransferCompact`, `zetherTransferNoBundle`, `zetherTransferSingle` | the multi-recipient transfers of [CTR-ZTH-37](#CTR-ZTH-37)/[CTR-ZTH-38](#CTR-ZTH-38) |
 | `zetherUnshield(payload, proof, authSig, beneficiary, to, amount)` | the proof of the unshield statement ([Burn](#burn)); `_mint(to, amount·shieldScale)` |
 | `zetherUnshieldUnwrap(payload, proof, authSig, beneficiary, u, recipient, amount, minOut)` | the same proof; burns `amount·shieldScale` public-equivalent units from `totalShielded` and `WrappedLib` pays leg `u` that value **rounded down**, bounded by `minOut`, nothing minted; the holder loses less than one raw underlying unit to the rounding (a public `unwrap` burns only `⌈out·q⌉`), so a client picks `amount` with `previewUnwrap(u, amount·shieldScale).burned == amount·shieldScale` |
 | `zetherRollOver`, `zetherRollOverBatch`, `zetherSetRollOverMode`, `zetherRollOverSigned` | the roll-over functions of [ElGamal state and lifecycle](#rollover) |
@@ -1159,15 +1157,15 @@ the first column; `zetherUnshield` is on `NORMAL_ZETHER` (public mint, no underlyi
 
 | Operation (test) | bn254 | BLS12-381 | Earlier estimate (bn254 unless noted) | Deviation (n_v = 64) |
 |---|---|---|---|---|
-| `verifyTransfer` (verifier, auditor off; `ZetherVerifier.t` `test_transferBn254` / `Bls`) | **2,738,256** | **2,966,900** | BP 1,507 k + Σ 171 k = 1,678 k | +63 % |
-| `verifyTransfer` (auditor on; `test_transferBn254Auditor` / `BlsAuditor`) | **2,766,515** | **3,009,535** | +27.5 k | matches (+28 k / +43 k) |
-| `verifyBurn` (`test_burnBn254` / `Bls`) | **1,349,042** | **1,448,067** | ~1.27 M | +6 % |
+| `verifyTransfer` (verifier, auditor off; `ZetherVerifier.t` `test_transferBn254` / `Bls`) | **2,738,357** | **2,967,069** | BP 1,507 k + Σ 171 k = 1,678 k | +63 % |
+| `verifyTransfer` (auditor on; `test_transferBn254Auditor` / `BlsAuditor`) | **2,766,616** | **3,009,705** | +27.5 k | matches (+28 k / +43 k) |
+| `verifyBurn` (`test_burnBn254` / `Bls`) | **1,349,144** | **1,448,212** | ~1.27 M | +6 % |
 | `zetherTransferSingle` / `zetherTransfer` (multi) | see tables (a) and (b) below | | earlier single-recipient figures: 3.29 M / 3.92 M (direct, auditor, inner fee) | superseded by (a) |
-| `zetherUnshield` (`ZetherNormal.t` `test_lifecycleShieldTransferRollOverUnshield`) | **1,439,032** | **1,564,583** | ~1.27 M | +13 % |
+| `zetherUnshield` (`ZetherNormal.t` `test_lifecycleShieldTransferRollOverUnshield`) | **1,439,816** | **1,565,410** | ~1.27 M | +13 % |
 | `zetherShield` (first credit / warm; `test_shieldAndRollOverGas`) | 159,788 / 25,384 | 215,748 / 33,639 | — | −16 % / −11 % against the old token |
 | `zetherRollOver` (work / no-op; `test_shieldAndRollOverGas`) | 115,783 / 3,093 | 166,975 / 3,083 | ~66 k execution | unchanged |
-| `zetherRollOverSigned` (Schnorr; `test_ownerOnlyRollOver`) | **135,724** | **199,706** | ~31 k | ×4 |
-| `register` SELF_SCHNORR (`UniversalAccountRegistry.t` `test_registerGas`) | **102,659** | **83,440** | ~105,750; BLS ~160 k | matches; BLS cheaper |
+| `zetherRollOverSigned` (Schnorr; `test_ownerOnlyRollOver`) | **135,768** | **199,750** | ~31 k | ×4 |
+| `register` SELF_SCHNORR (`UniversalAccountRegistry.t` `test_registerGas`) | **169,802** | **194,966** | ~105,750; BLS ~160 k | +67 k / +112 k in P3b: the key kept for `keyOf` (CTR-ZTH-50) |
 
 `n_v` 32 → 64 (measured 2026-10-05) adds exactly one inner-product round and 64 pairs `G_i`/`H_i` to the BP-2 MSM of Bulletproof #1:
 ≈ +538 k (bn254) / +519 k (BLS) execution gas, ≈ +20 %/+15 % on a single-recipient transfer. The relayed form adds ≈ +85 k (bn254, `ZetherRelay.t` `test_relayedTransferSingle_outerFeeFromPublicBalance_innerFeeToBeneficiary`) to a direct transfer. Burn is unchanged (BP#2 only).
@@ -1189,82 +1187,84 @@ from earlier estimates, so nobody "fixes" the wrong thing:
 - **rollOver:** 4 `bytes` points rewritten + 2 additions through the verifier; the estimate counted 10 warm SSTOREs.
 
 <a id="gas-multi"></a>
-**(a) Transfer, single and multi-recipient** (2026-10-11, the P3 kinds: `NormalZetherToken`, `ZetherLib`,
-`ZetherDisclosure`). `test/zether/ZetherMulti.t.sol` `test_gas*`, forge 1.3.5, Osaka, `gasleft()` around the call: execution gas
+**(a) Transfer, single and multi-recipient** (2026-10-11, re-measured on P3b: the salt, the 480-byte header, the memo;
+`NormalZetherToken`, `ZetherLib`, `ZetherDisclosure`). `test/zether/ZetherMulti.t.sol` `test_gas*`, forge 1.3.5, Osaka, `gasleft()` around the call: execution gas
 without the 21,000 intrinsic and calldata, each cell from a fresh state (every recipient and the beneficiary get their
 first credit), inner fee to a beneficiary, one real recipient and `M − 1` decoys at 0, real proofs (test prover
 `ZetherProver.sol`). **on** = auditor on; **out** = the same auditor-on token, the sender leaves the auditor out
 ([CTR-ZTH-42](#CTR-ZTH-42): every `C_aud = O`, statement `Y_a = O`). Calldata = the ABI-encoded call in bytes (same for
-on and out).
+on and out). Compact = `zetherTransferCompact` (and `zetherTransfer` on a COMPACT token), BUNDLE = `zetherTransfer` on a
+BUNDLE token, NONE = `zetherTransferNoBundle`.
 
 | Curve | Entry | Aud. | M = 1 | M = 2 | M = 4 | M = 8 | Calldata (M = 1 / 2 / 4 / 8) |
 |---|---|---|---|---|---|---|---|
-| bn254 | `zetherTransferSingle` | on | 3,329,407 | — | — | — | 3,876 |
-| bn254 | `zetherTransferSingle` | out | 3,261,491 | — | — | — | 3,876 |
-| bn254 | HASH | on | 3,168,046 | 4,693,119 | 7,754,641 | 13,924,113 | 3,908 / 5,604 / 8,996 / 15,780 |
-| bn254 | HASH | out | 3,140,793 | 4,637,989 | 7,643,210 | 13,697,894 | same |
-| bn254 | BUNDLE | on | 3,342,044 | 5,042,477 | 8,454,719 | 15,325,287 | same |
-| bn254 | BUNDLE | out | 3,274,991 | 4,907,747 | 8,184,088 | 14,780,667 | same |
-| bn254 | NONE | on | 3,139,717 | 4,661,297 | 7,715,761 | 13,870,048 | same |
-| bn254 | NONE | out | 3,112,464 | 4,606,167 | 7,604,330 | 13,643,827 | same |
-| BLS12-381 | `zetherTransferSingle` | on | 3,945,458 | — | — | — | 6,948 |
-| BLS12-381 | `zetherTransferSingle` | out | 3,823,389 | — | — | — | 6,948 |
-| BLS12-381 | HASH | on | 3,608,690 | 5,354,205 | 8,906,523 | 16,258,599 | 6,980 / 10,148 / 16,484 / 29,156 |
-| BLS12-381 | HASH | out | 3,567,318 | 5,269,721 | 8,732,900 | 15,895,039 | same |
-| BLS12-381 | BUNDLE | on | 3,958,048 | 6,054,283 | 10,308,041 | **19,061,962** | same |
-| BLS12-381 | BUNDLE | out | 3,837,076 | 5,810,599 | 9,816,018 | **18,061,599** | same |
-| BLS12-381 | NONE | on | 3,578,217 | 5,318,071 | 8,858,923 | 16,185,680 | same |
-| BLS12-381 | NONE | out | 3,536,845 | 5,233,587 | 8,685,300 | 15,822,115 | same |
-
-- **Per extra recipient** (slope M = 1 → 8, auditor on): bn254 HASH ≈ 1.54 M, BUNDLE ≈ 1.71 M, NONE ≈ 1.53 M;
-  BLS12-381 HASH ≈ 1.81 M, BUNDLE ≈ 2.16 M, NONE ≈ 1.80 M — against ≈ 3.33 M / 3.95 M for another separate transfer.
+| bn254 | `zetherTransferSingle` | on | 3,352,792 | — | — | — | 3,908 |
+| bn254 | `zetherTransferSingle` | out | 3,284,946 | — | — | — | 3,908 |
+| bn254 | Compact | on | 3,239,635 | 4,809,467 | 7,916,175 | 14,198,340 | 4,004 / 5,732 / 9,220 / 16,164 |
+| bn254 | Compact | out | 3,212,449 | 4,754,406 | 7,804,810 | 13,972,187 | same |
+| bn254 | BUNDLE | on | 3,368,038 | 5,068,803 | 8,481,710 | 15,353,653 | 3,940 / 5,636 / 9,028 / 15,812 |
+| bn254 | BUNDLE | out | 3,301,051 | 4,954,040 | 8,270,846 | 14,948,398 | same |
+| bn254 | NONE | on | 3,142,904 | 4,664,842 | 7,720,023 | 13,875,749 | as BUNDLE |
+| bn254 | NONE | out | 3,115,717 | 4,609,779 | 7,608,659 | 13,649,593 | as BUNDLE |
+| BLS12-381 | `zetherTransferSingle` | on | 3,968,916 | — | — | — | 6,980 |
+| BLS12-381 | `zetherTransferSingle` | out | 3,846,915 | — | — | — | 6,980 |
+| BLS12-381 | Compact | on | 3,680,488 | 5,470,832 | 9,068,513 | **16,533,815** | 7,076 / 10,276 / 16,708 / 29,540 |
+| BLS12-381 | Compact | out | 3,639,184 | 5,386,415 | 8,894,955 | 16,170,317 | same |
+| BLS12-381 | BUNDLE | on | 3,984,226 | 6,080,832 | 10,335,337 | **19,090,805** | 7,012 / 10,180 / 16,516 / 29,188 |
+| BLS12-381 | BUNDLE | out | 3,863,321 | 5,837,216 | 9,843,379 | **18,090,504** | same |
+| BLS12-381 | NONE | on | 3,581,588 | 5,321,839 | 8,863,490 | 16,191,841 | as BUNDLE |
+| BLS12-381 | NONE | out | 3,540,283 | 5,237,423 | 8,689,932 | 15,828,339 | as BUNDLE |
+
+- **Per extra recipient** (slope M = 1 → 8, auditor on): bn254 Compact ≈ 1.57 M, BUNDLE ≈ 1.71 M, NONE ≈ 1.53 M;
+  BLS12-381 Compact ≈ 1.84 M, BUNDLE ≈ 2.16 M, NONE ≈ 1.80 M — against ≈ 3.35 M / 3.97 M for another separate transfer.
+- **What P3b added** (against P3): the commit-reveal memo +72 k at M = 1, +274 k at M = 8 (either curve: storage); the
+  salt in a stored `R` +26 k (one slot); the 480-byte header and the salt in calldata ≈ +3 k (NONE).
 - **The auditor scan:** the multi cells carry ≈ 1 k per leg for the `C_aud` scan that picks `Y_a` ([CTR-ZTH-42](#CTR-ZTH-42)).
-- **Leaving the auditor out** saves E6 per leg (bn254 ≈ 27–28 k, BLS12-381 ≈ 41–45 k) and, where the bundle is stored, the
-  zero `C_aud` words: single −68 k / −122 k, BUNDLE M = 8 −545 k / −1.0 M (bn254 / BLS12-381).
+- **Leaving the auditor out** (OPTIONAL only) saves E6 per leg (bn254 ≈ 27–28 k, BLS12-381 ≈ 41–45 k) and, where the
+  record is stored, the zero `C_aud` words: single −68 k / −122 k, BUNDLE M = 8 −405 k / −1.0 M (bn254 / BLS12-381).
 - **EIP-7825 cap (16,777,216 per transaction, intrinsic + calldata included):** every bn254 cell fits; on BLS12-381
-  M = 8 BUNDLE does not, auditor on or out; M = 8 HASH on ≈ 16.75 M and NONE on ≈ 16.67 M fit with < 1 % headroom, out
-  ≈ 16.38 M / 16.31 M. The node gas cap below applies to M = 1; a chain that relays larger `M` raises it to the cell plus
+  M = 8 BUNDLE does not, auditor on or out, nor (since the memo) M = 8 Compact with the auditor (≈ 17.03 M); M = 8
+  Compact out ≈ 16.66 M and NONE on ≈ 16.68 M fit with < 1 % headroom, NONE out ≈ 16.32 M. The node gas cap below applies to M = 1; a chain that relays larger `M` raises it to the cell plus
   intrinsic and calldata.
 - **Prover** (release `zether-cli proveTransferMulti`, one process per call; median of 3 on the chain-7622 host, AMD
   Ryzen 5 7235HS): bn254 single 74 ms, M = 1/2/4/8 = 75 / 114 / 181 / 322 ms; BLS12-381 single 162 ms, M = 1/2/4/8 =
   159 / 231 / 361 / 660 ms.
 
-**P3b (to be measured):** commit-reveal with its memo (32 B + 17 + 40·M B, ≈ 3 slots at `M = 1`), the 16-byte salt in every record and commitment, the 480-byte header, and the mode checks of [CTR-ZTH-48](#CTR-ZTH-48)/[CTR-ZTH-49](#CTR-ZTH-49). The cells above are the P3 build (no salt, no memo).
-
 **(b) Disclosure** (`ZetherDisclosure.verifyTransferAmount`, `test_gasDisclose*`): an on-chain call from a contract
 (`Escrow3P.measure`: `token.disclosure()`, then `gasleft()` around the call), every opening true, on the real leg
 `j = M − 1`. Token, `ZetherDisclosure` and verifier cooled with `vm.cool` before each call (cold accounts and slots as
-in a new transaction; the token account itself is warm, the caller just read `disclosure()`). HASH: the bundles are
-passed in calldata — their size in the last column; their transaction calldata cost (≤ 16 gas/B) is not included.
+in a new transaction; the token account itself is warm, the caller just read `disclosure()`). Compact: `R` is passed in
+calldata — its size in the last column, its transaction calldata cost (≤ 16 gas/B) not included — and the token's
+`transferEntry` returns the commitment with the memo (P3b).
 
 | Curve | Entry | `SENDER_S` | `RECEIVER_X` | `AUDITOR` | `SENDER_CP` | Bundles in calldata |
 |---|---|---|---|---|---|---|
-| bn254 | Single (stored) | 77,123 | 101,008 | 109,924 | 101,057 | — |
-| bn254 | BUNDLE M = 1 | 77,123 | 101,008 | 109,924 | 101,057 | — |
-| bn254 | BUNDLE M = 8 | 199,141 | 223,048 | 231,969 | 223,097 | — |
-| bn254 | HASH M = 1 | 57,636 | 81,519 | 90,435 | 81,568 | 256 B |
-| bn254 | HASH M = 8 | 58,847 | 82,743 | 91,662 | 82,792 | 2,048 B |
-| BLS12-381 | Single (stored) | 120,279 | 151,745 | 165,059 | 151,794 | — |
-| BLS12-381 | BUNDLE M = 1 | 120,279 | 151,745 | 165,059 | 151,794 | — |
-| BLS12-381 | BUNDLE M = 8 | 364,482 | 396,010 | 409,338 | 396,059 | — |
-| BLS12-381 | HASH M = 1 | 83,538 | 115,000 | 128,314 | 115,049 | 512 B |
-| BLS12-381 | HASH M = 8 | 86,005 | 117,504 | 130,825 | 117,553 | 4,096 B |
+| bn254 | Single (stored) | 79,651 | 103,580 | 112,496 | 103,629 | — |
+| bn254 | BUNDLE M = 1 | 79,651 | 103,580 | 112,496 | 103,629 | — |
+| bn254 | BUNDLE M = 8 | 201,670 | 225,622 | 234,543 | 225,671 | — |
+| bn254 | Compact M = 1 | 64,926 | 88,855 | 97,771 | 88,904 | 272 B |
+| bn254 | Compact M = 8 | 86,068 | 110,013 | 118,933 | 110,062 | 2,064 B |
+| BLS12-381 | Single (stored) | 122,807 | 154,318 | 167,632 | 154,367 | — |
+| BLS12-381 | BUNDLE M = 1 | 122,807 | 154,318 | 167,632 | 154,367 | — |
+| BLS12-381 | BUNDLE M = 8 | 367,013 | 398,586 | 411,915 | 398,635 | — |
+| BLS12-381 | Compact M = 1 | 90,829 | 122,337 | 135,651 | 122,386 | 528 B |
+| BLS12-381 | Compact M = 8 | 113,235 | 144,785 | 158,106 | 144,834 | 4,112 B |
 
 - `SENDER_CP` costs as `RECEIVER_X` (+49 gas: the bases swap); `AUDITOR` adds the cold `auditorKey()` read (≈ 9 k /
-  13 k). A stored entry is read whole: BUNDLE M = 8 pays ≈ 65 / 129 cold slots for 2 / 4 KiB, which is why HASH (one
-  slot + calldata) is the cheaper on-chain check at large `M`. Off chain (`eth_call`) every kind is free.
+  13 k). A stored entry is read whole: BUNDLE M = 8 pays ≈ 65 / 129 cold slots for 2 / 4 KiB, which is why commit-reveal
+  (the commitment, the memo + calldata) is the cheaper on-chain check at large `M`. Off chain (`eth_call`) every kind is free.
 
 **Sizes** (`forge build --sizes`, runtime bytes, optimizer 200 runs; EIP-170 limit 24,576 B):
 
-| Contract | Built (P3, solc 0.8.37) |
+| Contract | Built (P3b, solc 0.8.37) |
 |---|---|
-| `NormalZetherToken` / `WrappedZetherToken` | 30,659 / 40,381 (over EIP-170: ratchet baseline; owner: size waits for Glamsterdam) |
-| `ZetherLib` / `ZetherStatements` / `ZetherDisclosure` | 15,662 / 7,311 / 5,021 |
+| `NormalZetherToken` / `WrappedZetherToken` | 31,162 / 40,706 (over EIP-170: ratchet baseline; owner: size waits for Glamsterdam) |
+| `ZetherLib` / `ZetherStatements` / `ZetherDisclosure` | 17,247 / 8,671 / 5,063 |
 | `ZetherVerifierBn254` / `ZetherVerifierBls12381` | 15,955 / 16,312 |
 
 
-**Node gas cap:** the default `max_gas_per_tx = 3,000,000` (`scaas-node/src/config.rs:415-416`) is below a classical transfer (3.33 M direct / 3.41 M relayed, bn254), so the node refuses to relay Zether with the default; a chain with Zether sets `max_gas_per_tx` ≥ 4.2 M (BLS direct 3.96 M, `test_lifecycleShieldTransferRollOverUnshield`; a BLS
-relayed transfer was not re-measured: ≈ 3.96 M + the envelope delta (bn254 +85 k) + 21 k + ≈ 99 k calldata ≈ 4.2 M). The node's configuration check warns when a
+**Node gas cap:** the default `max_gas_per_tx = 3,000,000` (`scaas-node/src/config.rs:415-416`) is below a classical transfer (3.35 M direct / 3.44 M relayed, bn254), so the node refuses to relay Zether with the default; a chain with Zether sets `max_gas_per_tx` ≥ 4.2 M (BLS direct 3.99 M, `test_lifecycleShieldTransferRollOverUnshield`; a BLS
+relayed transfer was not re-measured: ≈ 3.99 M + the envelope delta (bn254 +85 k) + 21 k + ≈ 99 k calldata ≈ 4.2 M). The node's configuration check warns when a
 Zether token is registered on a chain whose cap is below that ([NODE-STO-01](../node/store.md#NODE-STO-01)).
 
 The 2.5 M per-transfer kill criterion of the original plan is exceeded by the bn254 transfer (3.33 M direct after
@@ -1327,7 +1327,7 @@ interface IZetherToken is IERC20MetaTx {  // target; built (P3): standalone, the
     function shieldScale() external view returns (uint256);
     function confidentialFee() external view returns (uint256);
     function auditorKey() external view returns (bytes memory);
-    function disclosureMode() external view returns (uint8); function auditorMode() external view returns (uint8);   // CTR-ZTH-48/49, SPECIFIED (P3b)
+    function disclosureMode() external view returns (uint8); function auditorMode() external view returns (uint8);   // CTR-ZTH-48/49 (enums, ABI uint8)
     function disclosure() external view returns (ITransferDisclosure);   // implementation immutable (CTR-ZTH-43)
     function transferEntry(bytes32 entryRef) external view returns (bytes memory);   // raw record: R | keccak256(R) ‖ memo | empty
     function totalShielded() external view returns (uint256);
@@ -1343,9 +1343,9 @@ interface IZetherToken is IERC20MetaTx {  // target; built (P3): standalone, the
     function zetherShield(bytes calldata ua, uint256 amount) external;   // burns amount·shieldScale public units (CTR-ZTH-35)
     // multi-recipient (CTR-ZTH-37/38); enum TransferMode { HASH, BUNDLE, NONE }
     function zetherTransfer(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
-                                  ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);          // BUNDLE token: R; COMPACT: commit-reveal (built: HASH)
+                                  ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);          // BUNDLE token: R; COMPACT: commit-reveal
     function zetherTransferCompact(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
-                                        ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);    // commit-reveal (built instead: zetherTransferBundle, BUNDLE)
+                                        ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);    // commit-reveal
     function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
                                           ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);  // NONE; BUNDLE tokens only
     function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
diff --git a/docs/decisions.md b/docs/decisions.md
index b101afe..72bb1f5 100644
--- a/docs/decisions.md
+++ b/docs/decisions.md
@@ -2650,7 +2650,7 @@ Change (2026-10-08): `MetaTransaction` has no `to`/`value`, so the binding drops
 ### CTR-ZTH-30 — Derive s from seed via PRF
 - old: UD:§13.2 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-30 · superseded-by: —
 
-Change (2026-10-11): owner — `s = HKDF-SHA256(seed_zether, "ZTX/s/v2" ‖ chainUid ‖ token ‖ fromUA ‖ sendCounter ‖ salt)` with 16 fresh random bytes per build, published with the transfer and not checked by the contract (SPECIFIED, P3b). The counter-only form reused `s` on a retry (`C_aud₁ − C_aud₂ = [v₁ − v₂]G`, failed-transaction calldata is public); the built amount-mixing form made the sender remember amounts. Source add: owner, 2026-10-11.
+Change (2026-10-11): owner — `s = HKDF-SHA256(seed_zether, "ZTX/s/v2" ‖ chainUid ‖ token ‖ fromUA ‖ sendCounter ‖ salt)` with 16 fresh random bytes per build, published with the transfer and not checked by the contract (built in P3b). The counter-only form reused `s` on a retry (`C_aud₁ − C_aud₂ = [v₁ − v₂]G`, failed-transaction calldata is public); the built amount-mixing form made the sender remember amounts. Source add: owner, 2026-10-11.
 
 **Why.** The sender randomness `s` is derived from the seed by a PRF, so nothing per transfer needs storing. The research sketch was s = HKDF-SHA256(seed_zether, info = "ZTX/s/v1" ‖ chainId ‖ tokenAddress ‖ fromUA ‖ sendCounter) with the `sendCounter` read from the chain, so a wallet restored from its seed alone can still prove every past transfer.
 **Cost if wrong.** Stored randomness is one more secret to lose or leak.
@@ -2785,7 +2785,7 @@ Change (2026-10-11): owner — only under `auditorMode = OPTIONAL` (CTR-ZTH-49);
 ### CTR-ZTH-48 — disclosureMode BUNDLE or COMPACT, chosen at initialize
 - old: — · status: current · owner: yes · date: 2026-10-11 · normative: contracts/zether.md#CTR-ZTH-48 · superseded-by: —
 
-**Rule.** Owner decisions of 2026-10-11, in one place: (1) `disclosureMode ∈ {BUNDLE, COMPACT}` at `initialize`, immutable: on BUNDLE `zetherTransfer` stores the full bundle (default) and a caller may save gas with `zetherTransferCompact` or `zetherTransferNoBundle`; on COMPACT only commit-reveal, the no-bundle entry reverts typed (CTR-ZTH-38). (2) `auditorMode ∈ {NONE, FULL, OPTIONAL}` at `initialize`, immutable; FULL refuses opt-outs, OPTIONAL keeps CTR-ZTH-42 (CTR-ZTH-49). (3) `s` from the seed with a fresh published 16-byte salt per build (CTR-ZTH-30). (4) Commit-reveal stores a sender memo (salt ‖ amounts and recipients XOR an HKDF keystream) so the sender opens from seed + storage alone (CTR-ZTH-50). (5) A who-can-open table per storage (zether.md §14). (6) PQ Zether follows the same rules (CTR-PQZ-19, CTR-PQZ-23, CTR-PQZ-24). All SPECIFIED; code in P3b.
+**Rule.** Owner decisions of 2026-10-11, in one place: (1) `disclosureMode ∈ {BUNDLE, COMPACT}` at `initialize`, immutable: on BUNDLE `zetherTransfer` stores the full bundle (default) and a caller may save gas with `zetherTransferCompact` or `zetherTransferNoBundle`; on COMPACT only commit-reveal, the no-bundle entry reverts typed (CTR-ZTH-38). (2) `auditorMode ∈ {NONE, FULL, OPTIONAL}` at `initialize`, immutable; FULL refuses opt-outs, OPTIONAL keeps CTR-ZTH-42 (CTR-ZTH-49). (3) `s` from the seed with a fresh published 16-byte salt per build (CTR-ZTH-30). (4) Commit-reveal stores a sender memo (salt ‖ amounts and recipients XOR an HKDF keystream) so the sender opens from seed + storage alone (CTR-ZTH-50). (5) A who-can-open table per storage (zether.md §14). (6) PQ Zether follows the same rules (CTR-PQZ-19, CTR-PQZ-23, CTR-PQZ-24). Built in P3b (PQZ: spec only).
 **Why.** The creator, not each sender, decides whether a token keeps its disclosure data on chain. COMPACT is a subset of BUNDLE, so one implementation per kind serves both and the kinds stay `NORMAL_ZETHER` / `WRAPPED_ZETHER` (CTR-TOK-21); separate implementations per mode were rejected, to be revisited only if EIP-170 forces smaller bytecode.
 **Cost if wrong.** A per-sender choice leaves no on-chain guarantee of where disclosure data lives; a separate implementation per mode doubles the audit surface.
 **Source.** owner, 2026-10-11; background `research/zether-disclosure.md` §4, §6, §7, §9.
diff --git a/docs/history/dropped-artifacts.tsv b/docs/history/dropped-artifacts.tsv
index 83bc164..b142ed7 100644
--- a/docs/history/dropped-artifacts.tsv
+++ b/docs/history/dropped-artifacts.tsv
@@ -838,3 +838,5 @@ scaas-account.__check_auth	renamed	`SmartKeyAccount.__check_auth`, networks/soro
 ownerNonce	removed	the owner call is a MetaTransaction lane 0 (P4), networks/hedera.md#NET-HED-03
 subjectAccountFactory	renamed	`smartKeyAccountFactory` (P4), clients/app.md
 bundle = u ‖ v_t ‖ v_a ‖ toUA	renamed	the PQZ bundle gains the build salt: `R = salt ‖ u ‖ v_t ‖ v_a ‖ toUA`, contracts/pq-zero-knowledge.md#CTR-PQZ-23
+keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v1")	renamed	the `…/n64-n64/v2` proof system id with the 480-byte header (P3b), contracts/zether.md#statement-byte-layout
+keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v1")	renamed	the `…/n64-n64/v2` proof system id with the 480-byte header (P3b), contracts/zether.md#statement-byte-layout
diff --git a/docs/research/zether-disclosure.md b/docs/research/zether-disclosure.md
index 7769826..6964039 100644
--- a/docs/research/zether-disclosure.md
+++ b/docs/research/zether-disclosure.md
@@ -2,7 +2,7 @@
 
 # Zether disclosure — who can reveal what, under which conditions (2026-10-11)
 
-**Status (owner decisions, 2026-10-11; SPECIFIED for P3b, see [contracts/zether.md](../contracts/zether.md) CTR-ZTH-30, -38, -42, -48 to -50, and CTR-PQZ-19, -23, -24):**
+**Status (owner decisions, 2026-10-11; built in P3b, see [contracts/zether.md](../contracts/zether.md) CTR-ZTH-30, -38, -42, -48 to -50, and CTR-PQZ-19, -23, -24):**
 - **R3** (opt-out undermines compliance, Q1) is addressed by `auditorMode = FULL` (no opt-out); the opt-out is kept by choice under `OPTIONAL`.
 - **G1 / R7** (`s` derivation) are closed by the salt rule: `s = HKDF(seed_zether, "ZTX/s/v2" ‖ chainUid ‖ token ‖ fromUA ‖ sendCounter ‖ salt)` with a fresh published 16-byte salt per build.
 - **§7** (alternatives to storing the bundle) is superseded by the sender-memo rule: commit-reveal stores the commitment plus a 17 + 40·M byte memo (a flags byte records the auditor choice), and the sender recovers from seed + storage alone; tokens choose `disclosureMode ∈ {BUNDLE, COMPACT}` at creation.
```

- [ ] **Step 2: Run** — `python3 scripts/docs_check.py check` → `0 error(s)` (2 warnings, as on `main`);
  `python3 scripts/test_docs_check.py`.

- [ ] **Step 3: Commit** — `git add docs TODO.md HANDOFF.md` →
  `P3b: docs — modes, salt and sender memo built; §19 re-measured; TODO, HANDOFF`

---
### Final

- [ ] Whole-branch review (`superpowers:requesting-code-review`), then `superpowers:finishing-a-development-branch`
  (merge to `main` with `--no-ff`, message `Merge branch 'p3b-zether-modes': Zether disclosure and auditor modes at
  initialize, salted s, sender memo (P3b)`); do not push unless asked.
