# PQZ vectors (P6e Task 11; op 7 `R_TXM`: P6-ANON Task S4)

The one canonical directory of the PQ Zether known-answer vectors ([P6e plan](../../../docs/superpowers/plans/2026-10-14-p6e-relations.md)
decision D9): every consumer (the precompile and its fuzz targets, the contracts' forge tests, the clients) reads the
files **in place**; no copies (the copies to `smartcontracts/evm/test/vectors/pqz/` and
`clients/zether-prover/vectors/pq/` of [pq-zero-knowledge.md](../../../docs/contracts/pq-zero-knowledge.md) §14 are dropped).

- **Generator:** `pqz-ffi`'s binary [`pqz-vectors`](../../../pqz-core/ffi/src/bin/pqz-vectors.rs) (feature `prove`,
  plan R4). Every value comes from the crate's API: the C core (KeyGen, Enc, Dec, the matrix, `encrypt` with chosen
  vectors, PQZL proofs), Ligero (PQZH proofs, THE proven preset); every expected output from the C ABI
  `pqz_precompile` (P6f's entry) and `selftest::selftest()`, and for PQZL the generic verifier must agree with the
  precompile's specialised one. It writes all files of this directory except this README and `pqz_kat.py`. `pqz-ffi`'s
  `build.rs` compiles the self-test's `R_REG` proofs in from the REGISTER rows of `proof_*.json` (no copy).
- **Independent check:** [`pqz_kat.py`](pqz_kat.py) (Python 3 stdlib) recomputes every non-proof field of every file
  from the seeds; a `*.json` here without a checker fails (by design).
- **Frozen.** Proof bytes for a fixed `rnd32` are part of the vectors: a change that alters them is a
  `proofSystemId` bump (plan D4). `pqz-vectors --check` regenerates everything and compares byte for byte.
- **PQZL v3** (plan [2026-10-19-pqzl-fs3](../../../docs/superpowers/plans/2026-10-19-pqzl-fs3.md) Task 5,
  `pqz-core/ffi/vectors/runs/fs5-*`). The PQZL rows are under the v3 id `0x8079d65b…16baef`
  (`keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3")`, the Fiat–Shamir fix of
  [lazer#28](https://github.com/lazer-crypto/lazer/issues/28) with the prover fixes D-2 / D-3). The v2 id
  (`keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`) is retired as forgeable
  ([pq-zero-knowledge.md](../../../docs/contracts/pq-zero-knowledge.md) §8) and appears only in `negative.json`'s 16
  rows "retired PQZL v2 proofSystemId" (each PQZL form and op 7 shape; reason `ProofSystemId`). Regenerated with
  `pqz-vectors`: every PQZL proof, the statements (bytes 32..63 hold the id; same sizes), `fee0.json`,
  `negative.json`, `worstcase_noise.json` and `selftest.json` (only the PQZL REGISTER `proof_keccak`). PQZH proofs are
  byte-unchanged. The self-test hash stays `ed910a2c…1333d205` (verified: it covers verdicts, not proof bytes).
- **The set's own ids (plan 5h Task 8d part 1)**, `pqz-core/ffi/vectors/runs/t8d1-n2048-kmax1024-*`: PQZL
  `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v4")` = `0x19fad50a…9a326d`, PQZH
  `keccak256("scaas/pqz/pqzh/ligero-fq42-n32756k817t121-keccak256-zk-proven/v2")` = `0x9d945089…a7dca4` (the set's
  `set.json`; decisions CTR-PQZ-09; both retired by the R0 review fix, next item). What changed against the v3 / D3 files, and only that: every statement's bytes
  32..63 (the id word; same sizes); every proof of both systems (the transcripts hash the statement) with its
  `proof_bytes` / `proof_fnv` / `proof_keccak`, the `stmt_keccak` / `auth_digest` / opening fields over them;
  `proof_*.json`'s `proof_system_id` and description; `negative.json` (745 → 774 rows): 30 new rows "retired PQZL v3 proofSystemId"
  (16) / "retired PQZH v1 proofSystemId" (14) beside the v2 rows, and the edits / input hashes that depend on proof
  bytes or lengths (the "coder padding" rows follow the new proofs' last bytes: 3 forms out, 2 in); `selftest.json`'s
  two REGISTER `proof_keccak`. Unchanged: `cbd.json`, `enc.json`, `keygen.json`, `matrix.json`, every key, ciphertext
  and header value, and the self-test hash `ed910a2c…1333d205`. The contracts' tests read these files and still pin the
  v3 / D3 ids until plan 5h Task 8d part 2.
- **The R0 review fix (2026-10-25)**, `pqz-core/ffi/vectors/runs/r01a-n2048-kmax1024-*`: the current ids, PQZL
  `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v5")` = `0xc752e7f5…c6cdfe`, PQZH
  `keccak256("scaas/pqz/pqzh/ligero-fq42-n32756k817t121-keccak256-zk-proven/v3")` = `0x56293621…a7df5d`; v4 / v2 above
  only in `negative.json`'s "retired … proofSystemId" rows. Audited op 7 groups of `S_AUD` = 2 legs, the auditor copy of
  leg j at window j mod 2, KeyGen tag V2, the op 7 disclosures; every proof and statement regenerated.

## Run

```sh
scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]  # pqz-core/ffi/vectors/runs/<label>-*.txt; exit 1 on a failure
python3 -I smartcontracts/vectors/pqz/pqz_kat.py --check     # light: ≈ 43 s, no build needed
```

`run.sh` builds `pqz-ffi` with `pqz-vectors`; `write` regenerates the files and rebuilds (the self-test's proofs);
then `pqz-vectors --check` (a second generation, byte for byte; every honest proof and every negative input through
`pqz_precompile`, PQZL also through the generic verifier, which must agree; the self-test hash through `pqz_precompile`
on `06 00000000`; stale compiled-in self-test proofs fail); `pqz_kat.py --check`; `tamper.py` (leaves spread over each
file are changed one at a time in a copy; each must make that file's checker fail); `pqz-ffi`'s tests; `replay_wasm.mjs`
(every proof proved again by `pqz-ffi` in wasm32: byte-equal with the files, valid through its precompile).

## Files

Common conventions: hex strings are big-endian bytes without `0x`; statements are written once, under the PQZL id
(the PQZH statement differs only in bytes 32..63, the `proofSystemId` word); `*_keccak` is Keccak-256; "seed" fields
are KeyGen seeds (`keygen.json`) and Enc objects are `{seed_enc, recipients (KeyGen seeds), values}`.

| File | Bytes | Content | Checked by `pqz_kat.py` |
|---|---|---|---|
| `matrix.json` | 1,051 | `keccak256(A)` (A[0][0], A[0][1], …, 64 `be8` coefficients each), first / last 8 coefficients of `A[0][0]`, `A[31][31]` | A from SHAKE128 |
| `cbd.json` | 4,293 | CBD_1 / CBD_20 samples of the C core's KeyGen (2 seeds) and Enc (3 recipients) streams at given bit offsets | samples from SHAKE256 |
| `keygen.json` | 2,897 | 8 seeds → counter, `keccak256(pk)`, first 4 coefficients, ‖s‖², ‖e‖². No searched-resample row (≈ 2^-70 per seed; dropped by the controller 2026-10-14): the resample path and the counter-64 error are pinned by the test-hook KATs (`pqz-core/pqzl/test/pqz_keys_kat.c`, `pqz_kat.py --c-keys`) | KeyGen |
| `enc.json` | 7,897 | 6 Enc rows (ctr, `keccak256(u)`, each `v_j`, Dec by each recipient: M, value; noise omitted, §14); Trivial; Add / Sub with Trivial and with a ciphertext | Enc, Dec, Add / Sub |
| `statement_transfer.json` | 304,699 | `TRANSFER` (auditor on, 83,072 B) and `TRANSFER0` (off, 66,560 B): header fields, objects (keys, `T` = Enc + Trivial(`plainUsed`), `out`), statement bytes, per id `keccak256(stmt)` and `authDigest`; `entryRef`; the disclosure bundle (16,688 / 16,560 B) | rebuilt from the seeds |
| `statement_burn.json`, `statement_refresh.json` | 102,686, 102,610 | `BURN`, `REFRESH` (50,048 B) the same way | rebuilt |
| `statement_register.json` | 34,421 | `REGISTER` (16,480 B): the self-test's statement (key `0x51…`, message `keccak256("SCAAS-PQZ-SELFTEST-V1")`) | rebuilt |
| `statement_disclose.json` | 203,876 | `DISCLOSE-SENDER` / `-RECEIVER` / `-AUDITOR` (33,184 B) of the transfer's receiver and auditor legs | rebuilt |
| `statement_transfer_multi.json` | 2,861,546 | Op 7 `R_TXM` (P6-ANON plan §4, D15): 11 statements, every built `(M, auditorOn)` of each id (PQZL M ∈ {1, 2, 4, 8}, PQZH {1, 2, 4}) with one real leg at a position that varies by shape, plus a two-real-leg row (`M2-off-two-real`), an all-decoy row (`M4-off-decoys`, fee 0) and a group-boundary row (`M8-on-boundary`: real legs b − 1 and b, b = s⌈4/s⌉ with s = `S_AUD`, the last leg of one audited group and the first of the next: 3 and 4 here); per row `case`, `ids` (the ids that build M), header (word 192 `recipientsHash`, word 320 `M`), objects (leg keys, UAs, `T`, the multi-group Enc with each group's `seed_enc_g` and counter), the sender memo (§5.4), statement, per id `keccak256` / `authDigest`, `entryRef`; `memo_open`: 9 memos opened by the sender (the canonical one, another key, wrong lengths, flipped flags / M / amount / salt bytes) | rebuilt from the seeds (Enc per group, `recipientsHash`, memo by HKDF-SHA256, `memoHash`), the debit balance, `parse` under each id (PQZH M = 8: `Legs`), the memo opens |
| `proof_pqzl.json` | 2,103,044 | PQZL (the set's id `…/mlwe-d64k32-q42l4/v5`), 8 rows = the six relations + REFRESH + AUDITOR, then 11 op 7 rows (`form` TRANSFER-MULTI, `case`, statement = the row of `statement_transfer_multi.json`): statement reference, witness (prover API, R3), `rnd32`, proof, `keccak256`, FNV-1a, disclosures' `opening = abi.encode(bundle, proof)`, `expect: true` | statement hash, witness from the seeds, framing (length, final coder byte), hashes, opening, decoder accepts |
| `proof_pqzh.json` | 7,408,593 | PQZH (Ligero, THE preset; the set's id `…/ligero-fq42-n32756k817t121-…/v3`), the same 8 rows, then the 8 op 7 rows with M ≤ 4; preset parameters; the verifier's exact bound per form and op 7 shape | as above; F_q elements of `w`, `q`, `h` canonical; preset; the bounds equal the values recorded in decisions.md (`LIGERO_MAX`) |
| `fee0.json` | 2,794,855 | fee = 0 (owner 2026-10-14: accepted for PQZ and classical Zether): an honest `TRANSFER`, `TRANSFER0`, `BURN` and `REFRESH` with fee word 0 and no beneficiary, as statement rows plus witness, `rnd32` and both ids' proofs | statements and witnesses rebuilt, fee 0, hashes, framing, decoder accepts |
| `negative.json` | 262,771 | 774 precompile inputs (412 of ops 1–6, then 362 of op 7: `form` TRANSFER-MULTI and `case`; per built shape and id lengths ± 1, op bytes 0–6, both id cases (PQZL M = 8 under the PQZH id: `Legs`), the proof edits and the PQZH / PQZL proof encodings; the `M` word (0, 3, 16, 2^64 + 2, PQZH 8, another built M), `auditorOn` (2, flipped), header-only and cut statements, amount ≠ 0, fee / amount ≥ 2^64, salt, coefficients, `recipientsHash` / `memoHash` / fee / chainId / key bits, legs swapped within and across groups, `(1, on)` read as `(2, off)`, op 1's proof on M = 1, another shape's proof, the limits at the PQZH `(4, on)` boundary) that give `0` (or revert: `MAX_INPUT + 1`) as edits of an honest input: every D15 / R6 decoder rule, op / opTag / id confusion (each form under every other op byte, swapped opTags, unknown and the other system's id, the retired PQZL v2 id), lengths ± 1, the limits (`MAX_PROOF(id)` exactly: decoder accepts, verifier rejects; `MAX_PROOF(id) + 1`; `MAX_INPUT` exactly: `ProofLength`, not a revert; PQZH `max_proof_len(form) + 1`), framing, SELFTEST misuse, truncated / extended / bit-flipped proofs, proof encodings (D15: PQZH element = q in `w` and in an opened column, opened columns swapped or repeated; PQZL coder padding bit set after the final 1-bit), statement bits the decoder accepts, another form's proof; per row the reason (`pqz-stmt` `Reject`, or `verify`) and `SHA3-256(input)`; plus 9 disclosure openings (`abi.encode(bundle, proof)`: the canonical one and 8 `Opening` rejections) | edits replayed, Python decoder gives the same reason, no edit yields an honest input; every `Reject` variant present, and per form and id the lengths ± 1, every other op byte, both id cases, the five proof edits; openings by a Python `parse_opening` |
| `selftest.json` | 2,356 | `OP_SELFTEST` (D13): every input of the hash and the hash (from `pqz-ffi`'s `selftest::report()` and `pqz_precompile(06 00000000)`) | the whole hash (A, KeyGen, Enc, Dec, a mixed-radix DFT over 1,634 points); proof references; `fft_ok` and the four results are generator-pinned |
| `worstcase_noise.json` | 3,465,086 | `bound`: the worst the verifier accepts (below); `illustrative`: an honest key with aligned credits | `bound`: key, `R_REG` statement, credit, the sender statements and witness, `T`, noise, margins, debit; `illustrative`: alignment, every credit through `T` (linearity), `ctHash` of every 32nd credit, `T`, noise, debit |

Total 19,662,681 B of JSON (P6e: 11,371,429 B; S4 added `statement_transfer_multi.json` and the op 7 rows; PQZL v3: 19,650,288 → 19,655,565; B-1 / A-2, 5h Task 8a: → 19,656,112, the PQZL proofs and the coder-padding rows of
`negative.json`, which follow the proofs' last byte; the set's own ids, 5h Task 8d part 1: → 19,662,681, every proof and
the retired-id rows); PQZH proof hex is most of it.

**S4 regeneration of frozen files** (P6-ANON S4, `pqz-core/ffi/vectors/runs/s4a-*`): every P6e file is byte-unchanged
except `proof_pqzl.json`, `proof_pqzh.json` and `negative.json`, which gained rows **appended** after the P6e rows (the
P6e rows byte-identical), and two `negative.json` reasons: `TRANSFER: under op 7` (pqzl, pqzh) now decode to `OpTag`
instead of `Op`, because op 7 decodes since S3 (an op 1 statement under op byte 7 fails at its opTag); output `…00`,
input bytes unchanged. The self-test hash is unchanged.

### Scenario

Keys: F = KeyGen(`0x46…`) (sender), T = KeyGen(`0x54…`) (receiver), A = KeyGen(`0x41…`) (auditor), the self-test key
KeyGen(`0x51…`). F's balance `T = Enc_F(1,000,000; 0x61…) + Trivial(1,000)` (`plainUsed` 1,000). Transfer 123,456 with
fee 7 to T, auditor A: `out = Enc({T: 123,456, F: 877,537, A: 123,456}; 0x62…)` (auditor off: the first two legs, same
seed, so `u`, `v_t`, `v_f` are equal). Burn 123,456 (fee 7): `Enc_F(877,537; 0x64…)`; refresh (fee 7): `Enc_F(1,000,993;
0x65…)`. Disclosures of the transfer's receiver leg (sender, receiver) and auditor leg. Header: chain id 22,776, the
other words fixed filler that the decoder accepts (D15). `rnd32`: `0x53…` for REGISTER (the self-test's), `0x80 + i`
repeated for the i-th form of `pqz-stmt`'s `FORMS`, `0x90…` for the worst-case debit. `fee0.json`: the same with fee
0 and no beneficiary (`out` from `0x72…`, burn `0x74…`, refresh `0x75…`; `rnd32` `0xA0 + i`).

### Op 7 (`R_TXM`)

Sender F, auditor A and `T` as the scenario (`T = Enc_F(1,000,000; 0x61…) + Trivial(1,000)`); recipient j = KeyGen(`0x60
+ j`), UA j = the address `(0xB0 + j)` × 20; fee 7 with the auditor and 0 without (`M2-off-two-real`: 7, `M4-off-decoys`:
0); real legs 123,456 (`M2-off-two-real` and `M8-on-boundary`: 123,456 and 7,000), decoys 0; row i has `seed_enc` `0x70 +
i`, `sendCounter` 3 + i and `rnd32` `0xB0 + i`; memo key seed `0x4d…` (`pqz-ffi` `fixture::MEMO_KEY_SEED`). The
statement is written once under the PQZL id; `ids` lists where M is built (M = 8: PQZL only). In wasm32 the replay proves
PQZL M = 8 again on `pqz-ffi`'s Rust backend (the default; `WASM_PQZL_MAX_LEGS` = 8 since the Rust port's Task 12); the
C backend (opt-in) does not prove it (`WASM_PQZL_MAX_LEGS` = 4, one 512 MiB arena, S3), and the replay verifies the
native proof there. No op 7
disclosure bundle (§5.4) vectors: `pqz-stmt` has no codec for it yet.

### Worst-case noise

`bound` is the worst case the **verifier** accepts (controller 2026-10-14): a receiver key at the norm bounds, `s` = 36
at coefficient 0 of poly 1 (poly 0 carries `R_REG`'s approximate ℓ∞ filler, |coefficients| ≤ 1) and `e` = 164 at
coefficient 0 of poly 0, registered (its `R_REG` proves and verifies in both systems). A credit's decryption noise in
coefficient 0 is `⟨rot(e), r⟩ − ⟨rot(s), e1⟩ + e2[0]`; with `r` = 36 along `rot(e)`, `e1` = −164 against `rot(s)` and
`e2_t = (64, 0, …)` it is B_FRESH = 11,872 exactly (the maximum is unique, so every credit is the same ciphertext). The
sender's `R_TX` of that credit (`e2_t` at PQZL's B′ = 64 filler) proves and verifies in both systems (credit 0 and the
last, `sendCounter` 0 and 1,022). `T` = 1,023 credits + the plain unit (noise 0): noise 1,023 · 11,872 = **12,145,056**
in coefficient 0 (the analytic 12,156,928 of pq-zero-knowledge.md §4.3 counts 1,024 units), 1.38× below the proven range
2^24 = 16,777,216 and 4.14× below the mint threshold Δ − 2^24 = 50,331,647; `M_i` = 1,024 · 15 = 15,360 < 2^14 (credits
and plain unit carry digits 15 in their low 12 digits). The receiver's debit `R_TX` over `T` proves and verifies in
both systems.

`illustrative` keeps the first construction: an honest key, KeyGen(`0x57…`), `r` the same for every credit (greedy max
of `⟨rot(e), r⟩` under ‖r‖² ≤ 36²), `e1` a level on the support of `rot(s)` with a seeded choice of which coordinates
get one more (every credit a different ciphertext); noise 10,024 per credit, `T` 10,254,552 (margin 1.63× to 2^24).

### Self-test (D13)

`selftest.json` is `pqz-ffi`'s `selftest::report()` (`src/selftest.rs`): `keccak256(kat_digest ‖
u8(pqzl_valid) ‖ u8(pqzl_invalid) ‖ u8(pqzh_valid) ‖ u8(pqzh_invalid))`, `kat_digest = keccak256(A digest ‖
keccak256(pk) ‖ keccak256(u ‖ v) ‖ M ‖ keccak256(fft) ‖ u8(fft_ok))`; the compiled-in `R_REG` proofs are the
REGISTER rows of `proof_pqzl.json` / `proof_pqzh.json` (`pqz-ffi`'s `build.rs` reads them). Hash
`ed910a2c…1333d205`, unchanged since `p6e-a3` measured it (`pqz-core/ffi/vectors/runs/vec1-selftest-xcheck-p6e-a3.txt`).

## What `pqz_kat.py` pins and what only the generator pins

Python recomputes everything except proof validity. Generator-pinned (checked by `pqz-vectors --check` only): proof
bytes beyond framing and hashes (validity: `pqz_precompile`, the generic PQZL verifier, Ligero, the wasm32 replay); the
PQZH exact bounds (`LIGERO_MAX` in `pqz_kat.py` copies the values decisions.md records, it does not derive them); the
self-test's `fft_ok` and four results (Python checks the hash over them, not the verifies); `rnd32` of the non-REGISTER
rows (any `rnd32` gives a valid proof); in `illustrative`, the `ctHash` of the credits Python does not sample (every
32nd is hashed; every credit enters `T`, and `credits_keccak` binds the list). `cbd.json`'s streams are checked
indirectly: Python re-derives the samples from the recorded stream bytes, and KeyGen / Enc (`keygen.json`, `enc.json`,
the statements) re-derive the same streams from the seeds.

## Native = wasm32

Every proof of `proof_pqzl.json`, `proof_pqzh.json`, `fee0.json` and `worstcase_noise.json` (53) is proved again in
wasm32 by `pqz-ffi` (node) from the same statement, witness and `rnd32`: byte-equal, and valid through its precompile;
the three PQZL op 7 rows with M = 8 are verified only (the native proof through the wasm32 precompile)
(`pqz-core/ffi/vectors/runs/s4a-wasm.txt`; P6e: `vec3-wasm.txt`, 34).
