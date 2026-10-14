# PQZ vectors (P6e Task 11)

The one canonical directory of the PQ Zether known-answer vectors ([P6e plan](../../../docs/superpowers/plans/2026-10-14-p6e-relations.md)
decision D9): every consumer (the precompile and its fuzz targets, the contracts' forge tests, the clients) reads the
files **in place**; no copies (the copies to `smartcontracts/evm/test/vectors/pqz/` and
`clients/zether-prover/vectors/pq/` of [pq-zether.md](../../../docs/contracts/pq-zether.md) §14 are dropped).

- **Generator:** [`pqz-core/vecgen/`](../../../pqz-core/vecgen/src/main.rs) (`pqz-vectors`, plan R4). Every PQZL value
  is computed by the C core (`libpqz.a` of `pqz-core/build.sh`: KeyGen, Enc, Dec, the matrix, proofs, both verifiers),
  every PQZH proof by the Ligero crate (THE proven preset, production build); the binary only drives them and writes
  JSON. It writes all files of this directory except this README and `pqz_kat.py`.
- **Independent check:** [`pqz_kat.py`](pqz_kat.py) (Python 3 stdlib) recomputes every non-proof field of every file
  from the seeds; a `*.json` here without a checker fails (by design).
- **Frozen.** Proof bytes for a fixed `rnd32` are part of the vectors: a change that alters them is a
  `proofSystemId` bump (plan D4). `pqz-vectors --check` regenerates everything and compares byte for byte.

## Run

```sh
scripts/capped pqz-core/vecgen/run.sh <label> [write]       # pqz-core/vecgen/runs/<label>-*.txt
python3 -I smartcontracts/vectors/pqz/pqz_kat.py --check    # light: ≈ 18 s, no build needed
```

`run.sh` builds the C core (native and freestanding wasm32), the generator and the wasm32 Ligero module, then:
`write` regenerates the files; `pqz-vectors --check` (a second generation, byte for byte; every honest proof and every
negative input through the precompile path: `pqz-stmt` `decode_input`, then the specialised **and** the generic PQZL
verifier, which must agree, or Ligero); `pqz_kat.py --check`; `tamper.py` (leaves spread over each file are changed one
at a time in a copy; each must make that file's checker fail); `replay_wasm.mjs` (every proof proved again in wasm32,
PQZL from the freestanding C core, PQZH from the Ligero crate: byte-equal with the files, and verifies).

## Files

Common conventions: hex strings are big-endian bytes without `0x`; statements are written once, under the PQZL id
(the PQZH statement differs only in bytes 32..63, the `proofSystemId` word); `*_keccak` is Keccak-256; "seed" fields
are KeyGen seeds (`keygen.json`) and Enc objects are `{seed_enc, recipients (KeyGen seeds), values}`.

| File | Bytes | Content | Checked by `pqz_kat.py` |
|---|---|---|---|
| `matrix.json` | 1,045 | `keccak256(A)` (A[0][0], A[0][1], …, 64 `be8` coefficients each), first / last 8 coefficients of `A[0][0]`, `A[31][31]` | A from SHAKE128 |
| `cbd.json` | 4,287 | CBD_1 / CBD_20 samples of the C core's KeyGen (2 seeds) and Enc (3 recipients) streams at given bit offsets | samples from SHAKE256 |
| `keygen.json` | 2,891 | 8 seeds → counter, `keccak256(pk)`, first 4 coefficients, ‖s‖², ‖e‖². No searched-resample row (≈ 2^-70 per seed; dropped by the controller 2026-10-14): the resample path and the counter-64 error are pinned by the test-hook KATs (`pqz-core/test/pqz_keys_kat.c`, `pqz_kat.py --c-keys`) | KeyGen |
| `enc.json` | 7,891 | 6 Enc rows (ctr, `keccak256(u)`, each `v_j`, Dec by each recipient: M, value; noise omitted, §14); Trivial; Add / Sub with Trivial and with a ciphertext | Enc, Dec, Add / Sub |
| `statement_transfer.json` | 304,693 | `TRANSFER` (auditor on, 83,072 B) and `TRANSFER0` (off, 66,560 B): header fields, objects (keys, `T` = Enc + Trivial(`plainUsed`), `out`), statement bytes, per id `keccak256(stmt)` and `authDigest`; `entryRef`; the disclosure bundle (16,688 / 16,560 B) | rebuilt from the seeds |
| `statement_burn.json`, `statement_refresh.json` | 102,680, 102,604 | `BURN`, `REFRESH` (50,048 B) the same way | rebuilt |
| `statement_register.json` | 34,415 | `REGISTER` (16,480 B): the self-test's statement (key `0x51…`, message `keccak256("SCAAS-PQZ-SELFTEST-V1")`) | rebuilt |
| `statement_disclose.json` | 203,870 | `DISCLOSE-SENDER` / `-RECEIVER` / `-AUDITOR` (33,184 B) of the transfer's receiver and auditor legs | rebuilt |
| `proof_pqzl.json` | 721,986 | PQZL (id v2, D2), 8 rows = the six relations + REFRESH + AUDITOR: statement reference, witness (prover API, R3), `rnd32`, proof, `keccak256`, FNV-1a, disclosures' `opening = abi.encode(bundle, proof)`, `expect: true` | statement hash, witness from the seeds, framing (length, final coder byte), hashes, opening, decoder accepts |
| `proof_pqzh.json` | 3,499,045 | PQZH (Ligero, id D3), the same 8 rows; preset parameters; the verifier's exact bound per form | as above; F_q elements of `w`, `q`, `h` canonical; preset and bounds |
| `negative.json` | 108,407 | 337 precompile inputs that give `0` (or revert: `MAX_INPUT + 1`) as edits of an honest input: every D15 / R6 decoder rule, op / opTag / id confusion (each form under every other op byte, swapped opTags, unknown and the other system's id), lengths ± 1, `MAX_PROOF(id) + 1`, framing, SELFTEST misuse, truncated / extended / bit-flipped proofs, statement bits the decoder accepts, another form's proof; per row the reason (`pqz-stmt` `Reject`, or `verify`) and `SHA3-256(input)` | edits replayed, Python decoder gives the same reason; no edit yields an honest input |
| `selftest.json` | 2,305 | `OP_SELFTEST` (D13): every input of the hash and the hash | the whole hash (A, KeyGen, Enc, Dec, a mixed-radix DFT over 1,634 points); proof references |
| `worstcase_noise.json` | 818,747 | `K_MAX − 1` = 1,023 aligned credits to a known receiver key (seeds, per-credit `ctHash`, the aggregate `T`), the debit `R_TX` over `T` with both proofs | alignment, every credit through `T` (linearity), `ctHash` of every 32nd credit, `T`, noise, debit statement and witness |

Total 5,914,866 B of JSON (`proof_pqzh.json` alone 59 %, with the worst-case PQZH proof 67 %); the plan expected ≈ 7–8 MB.

### Scenario

Keys: F = KeyGen(`0x46…`) (sender), T = KeyGen(`0x54…`) (receiver), A = KeyGen(`0x41…`) (auditor), the self-test key
KeyGen(`0x51…`). F's balance `T = Enc_F(1,000,000; 0x61…) + Trivial(1,000)` (`plainUsed` 1,000). Transfer 123,456 with
fee 7 to T, auditor A: `out = Enc({T: 123,456, F: 877,537, A: 123,456}; 0x62…)` (auditor off: the first two legs, same
seed, so `u`, `v_t`, `v_f` are equal). Burn 123,456 (fee 7): `Enc_F(877,537; 0x64…)`; refresh (fee 7): `Enc_F(1,000,993;
0x65…)`. Disclosures of the transfer's receiver leg (sender, receiver) and auditor leg. Header: chain id 22,776, the
other words fixed filler that the decoder accepts (D15). `rnd32`: `0x53…` for REGISTER (the self-test's), `0x80 + i`
repeated for the i-th form of `pqz-stmt`'s `FORMS`, `0x90…` for the worst-case debit.

### Worst-case noise

The receiver key is KeyGen(`0x57…`). A credit's decryption noise in coefficient 0 is `⟨rot(e), r⟩ − ⟨rot(s), e1⟩ +
e2[0]`; `r` (the same for every credit) maximises the first term under ‖r‖² ≤ 36² (greedy over integer increments),
`e1` the second under ‖e1‖² ≤ 164² (a level on the support of `rot(s)`, a seeded choice of which coordinates get one
more: so every credit is a different ciphertext), `e2 = (64, 0, …)`. Each credit carries digits 15 in its low 12
digits, the plain unit the same, so `M_i` = 1,024 · 15 = 15,360 < 2^14. Measured: noise 10,024 per credit, `T`'s
noise 10,254,552 in coefficient 0 (= 1,023 · 10,024) against the proven range 2^24 = 16,777,216 (margin 1.64×)
and the cap bound `K_MAX · B_FRESH` = 12,156,928 (which assumes the worst key; this key's ‖e‖ is below the 164 the
bound uses). The debit proves and verifies in both systems (PQZL 42,750 B, PQZH 233,166 B).

### Self-test (D13)

`selftest.json` follows the derivation of `pqz-ffi`'s `selftest.rs` (branch `p6e-a3`): `keccak256(kat_digest ‖
u8(pqzl_valid) ‖ u8(pqzl_invalid) ‖ u8(pqzh_valid) ‖ u8(pqzh_invalid))`, `kat_digest = keccak256(A digest ‖
keccak256(pk) ‖ keccak256(u ‖ v) ‖ M ‖ keccak256(fft) ‖ u8(fft_ok))`; the compiled-in `R_REG` proofs are the
REGISTER rows of `proof_pqzl.json` / `proof_pqzh.json`. Hash ``ed910a2c…1333d205``, equal to the value `p6e-a3` measured, and the
REGISTER proofs are byte-identical to its `ffi/selftest/{pqzl,pqzh}_reg.hex` (`pqz-core/vecgen/runs/vec1-selftest-xcheck-p6e-a3.txt`).

## Native = wasm32

Every proof of `proof_pqzl.json`, `proof_pqzh.json` and the worst-case debit (18) is proved again in wasm32 (node) from
the same statement, witness and `rnd32`: byte-equal, and it verifies (`pqz-core/vecgen/runs/vec1-wasm.txt`).
