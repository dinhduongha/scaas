# I — Codex review of PQZH Rust (round 2)

**Date:** 2026-10-19. **Reviewer:** Codex CLI 0.163.0 (one read-only task, thread `01a153d0-927f-78a0-bef6-489ab516dcb1`;
owner-requested: "Dùng Codex, agy và sub-agent để review PQZH Rust, sau đó PQZL bản C"). **Target:** frozen detached
worktree at `e9cabd1`: `pqzh/ligero`, the pqz-ffi PQZH path, `stmt`, `xcheck` (primary, live); `pqzh/stark-backup`
(secondary, not live). Brief: same nine dimensions as G / H (soundness, decoding, panics, wasm32, allocation, features /
`unsafe`, constant time, wiping, spec). No builds, tests or timing. Triage: [J-agy-pqzh-rust.md](J-agy-pqzh-rust.md).

## Findings (Codex's text, condensed)

No P0 or P1 in the live PQZH verification path; every round-1 finding of reports A and B is still present.

1. **B-F1 — P1 (backup)** — `Params::DEFAULT` is non-hiding (`stark-backup/src/config.rs:211`, `rel.rs:236/368/523`):
   28 queries vs 16-row amount / new-balance columns ⇒ a proof reader interpolates them. Hiding presets have no usable
   size policy (`MAX_PROOF` 163,840 B; `tests/smoke.rs:22/46` lift the cap; `runs/s4-native-zk.jsonl:18` exceeds it).
   Narrowed: "every hiding configuration exceeds the cap" not established.
2. **A-F1 — P2** — sparse-FFT shortcut filters witness zeros (`ligero/src/fft.rs:121–124`, from `ligero.rs:290`); at
   k = 817 the radix-43 stage sees raw witness slots before the random tail mixes in.
3. **B-F2 — P2 (backup)** — overlong varints (`enc.rs:221`, verifier `rel.rs:475`): `01` ↔ `81 00`, proof
   malleable without the witness.
4. **B-F3 — P2 (backup)** — hiding masks seeded from `rnd32` alone (`rel.rs:496`, `config.rs:252`, `whirpcs.rs:78`),
   violates CTR-PQZ-19.
5. **A-F2 — P3** — `dot_int` skips zero secret coefficients (`ring.rs:70`; callers `ring.rs:93/106/115`,
   `cs.rs:480/554`); sign branch `cs.rs:485`; secret centring `ring.rs:82`; `Fq::from_i64` remainder `fq.rs:78`.
6. **A-Note — P3** — the live prover wipes nothing (`cs.rs:401/438`, `ligero.rs:165/279/285/335`), SHAKE state and
   seed copies included.
7. **B-F4 — P3 (backup)** — preprocessed cache keyed by (op, Params) while candidate selection depends on coefficient
   values (`rel.rs:436`, `air.rs:236/282`); latent at `mv_width = 1`, default 9 safe.
8. **B-F5 — P3 (backup)** — no op tag / id / auditor / salt / zero-word checks, two relations only (`rel.rs:155/212/392`).

## Checked and clean (Codex)

Transcript seeded with op and the whole statement incl. the id (`transcript.rs:16`); commitment before challenges,
responses before grinding and query indices (`ligero.rs:465`); unbiased rejection sampling (`transcript.rs:45`);
fixed-depth Merkle reconstruction, full proof consumption (`ligero.rs:487`), leaf / node preimage lengths distinct;
canonical field decoding (`fq.rs:99`), fixed polynomial counts; `stmt` fixed lengths, multi-leg allowlist, checked
offsets (`stmt/src/lib.rs:501/737/844/897`); exact proof bound before parsing (`ligero.rs:448`); linear / quadratic /
proximity identities and weights (`cs.rs:702/753/168`); live mask hedge = statement ‖ witness ‖ op ‖ `rnd32`
(`ligero.rs:169`); production disables Ligero defaults (`ffi/Cargo.toml:18`), pins parameters (`ffi/src/pqzh.rs:6`),
refuses `oversize` (`ffi/src/lib.rs:27`), checks lengths before forming slices (`ffi/src/lib.rs:133`); self-test
(`selftest.rs:94`), fixtures, xcheck. Noted: verifier allocations are infallible, so OOM aborts despite panic catching
(documented, `pq-zero-knowledge.md:1574`); the bench wasm wrapper traps on misuse (`ligero/wasm/lib.rs:49/124`).

## Not checked (Codex)

Dynamic validation, generated code, allocation-failure injection, the modified Ligero theorem, Plonky3 internals,
backup lookup ZK, entropy sources.
