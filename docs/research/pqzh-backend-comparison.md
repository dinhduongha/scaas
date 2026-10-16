> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH backend comparison and soundness regimes (2026-10-14)

Status: research summary, written 2026-10-14 (session 4) at the owner's request ("lưu tất cả thông tin nghiên cứu
vào file"). It collects in one place what was so far only said in the session: the side-by-side comparison of every
PQZH backend that was built and measured, the explanation of proven vs conjectured vs Johnson-bound soundness, and the
owner decisions of the day with their status. Every number comes from a research note and its run files, named in each
row; nothing here is newly measured.

Tags as in the other notes: **[measured]** from a named run file, **[estimate]** from a model, **[inference]**
reasoning.

## 1. Result

**Ligero over F_q, proven regime (radix-431 preset n = 32,756, k = 817, t = 121) is the PQZH backend.** It meets every
criterion except the original 160 KB proof line (`R_TX` ≈ 231 KB; the controller proposal raises the PQZH limit to
256 KB, exact maximum 235,470 B) and on-chain use without the precompile, which no candidate meets in one transaction.
The FRI + ZK STARK and ZK WHIR lose to it on every axis except native verify, where they are comparable.

## 2. Side-by-side, `R_TX`, zero knowledge, 128-bit target

| Criterion | Ligero proven (THE preset) | Ligero conjectured (reference) | Ligero Johnson (reference) | FRI + ZK STARK, Goldilocks⁵, proven | FRI + ZK STARK, Goldilocks⁵, conjectured | ZK WHIR, Goldilocks⁵, Johnson |
|---|---|---|---|---|---|---|
| Soundness basis | unique decoding, Ligero Thm 4.7 — **proven 128** | up-to-capacity conjecture (disproved in general, Crites–Stewart ePrint 2025/2046) | list decoding up to Johnson (BCIKS20), counted once; needs an unverified property (`pqzh-ligero.md` §5.3) | proven 128 | conjectured 128 | 124.2 bits composed (126.3 per opening) |
| Proof bytes | 231,000–232,430 (5 seeds), exact max 235,470 [measured, `ligero/runs/l7-proven.jsonl`] | 92,072 [measured, `ligero/runs/l2-conj-r431-*.jsonl`] | 257,592 [measured, `ligero/runs/l4-johnson.jsonl`] | 622,448 (worst ≈ 672 KB) [measured, `pqzh-zk-ext5.md` §7] | 340,431 (worst ≈ 365 KB) [measured, same] | 1,948,901 [measured, `runs/w2-zkwhir5-r3.jsonl`] |
| ≤ 160 KB (owner line 2026-10-13) | no | yes | no | no | no | no |
| ≤ 256 KB (controller proposal) | yes | yes | no (worst case 273,288) | no | no | no |
| Prove native | 0.65 s, 43 MB [measured, l7] | 0.93 s, 50 MB | 0.61 s | 20.4 s, 2.82 GB | 20.3 s, 2.82 GB | 43.0 s after the adapter fix (206 s before: a point-by-point periodic LDE in our adapter, fixed in the re-examination) [measured, `runs/wr-tx3.jsonl`], 2.42 GB |
| Verify p99 native | 10.8 ms [measured, l7] | 3.5 ms | 12.2 ms | 19.1 ms | 15.5 ms | 46.5 ms |
| Verify p99 wasm32 (limit 60 ms) | **18.7 ms** over 1,000 verifies [measured, `ligero/runs/l9-proven-wasm.jsonl`; 59.7 ms before the 21-bit multiply, `l8-*`] | 16.8 ms (before the 21-bit multiply) | 60.3 ms (before the 21-bit multiply) | 28.7 ms | 24.1 ms | 93.5 ms |
| Relations built | 5 of 5 (+ `R_TX0` pending P6e Task 8) | 5 (bench feature only) | 2 (bench feature only) | 2 of 5 | 2 of 5 | 2 of 5 |
| Mutated proofs accepted | 0 of 4,800 (+ 9,600 in benches) | 0 | 0 of 960 | 0 of 960 | 0 of 960 | 0 of 1,440 native / 240 wasm32 |
| EVM, one tx, no precompile (cap 16,777,216) | 534.6 M gas (31.9×) [measured, `ligero/runs/l6-forge.txt`]; ≈ 124 M at the opcode floor [estimate, `e1-evm-model.txt`] | 179.0 M | 649.7 M | 21.4 M calldata floor alone (`pqzh-solidity-verifier.md`) | ≈ 15 M with a tuned verifier [estimate] | not measured |
| EVM split over several txs (StarkEx style) | 19 txs, ≈ 319 M [estimate, `pqz-core/pqzh/stark-backup/sol/starkex_split.txt`] | — | — | ≈ 21.4 M over 4 txs with a tuned Yul verifier, ≈ 38.5 M as test-level code [estimate, same] | — | — |

Sources: `pqzh-ligero.md` §6, §11, §12; `pqzh-zk-ext5.md` §7; `pqzh-zk-whir.md` §7–§9 and §10 (the re-examination); `pqzh-solidity-verifier.md`; `pqzh-starkex-verifier.md` §6. Non-ZK WHIR (`p3-multi-stark`, 257,530 B at
125.3 bits, `pqzh-zk-ext5.md` §8) is left out: zero knowledge is required (owner 2026-10-13).

**ZK WHIR re-examined (owner "Xem lại WHIR", 2026-10-14; `pqzh-zk-whir.md` §10, merged):** the 1.95 MB measurement is
right (a fresh proof's byte breakdown sums exactly; ≈ 357–363 KB masked base case + 111–121 KB rounds per opening, four
openings); the ≈ 360 KB per opening is inherent to HVZK WHIR as ePrint 2026/391 defines it (the paper gives only an
asymptotic Õ(k·λ) overhead; its Construction 7.2 built as written gives the same size); p3-whir's soundness counting
(eight list sizes multiplied) is why Goldilocks² shows 0 bits. The 206 s prove was an adapter bug (now 43.0 s, same
proof bytes). Best untried route — ZK at the STARK layer with plain WHIR, a coset domain and a full-size random
polynomial in one batched opening — is ≈ 270–330 KB and ≈ 15–25 s [estimate], 2–3 weeks, ZK argued only by analogy;
non-ZK WHIR alone is already 238,932–257,530 B. No WHIR variant matches Ligero proven; recommendation: build no more
ZK WHIR (adapter kept with the fix as the record).

## 3. Proven vs conjectured vs Johnson [inference, from the notes' §5 analyses]

All three regimes use the same field, hash, Merkle tree and protocol; they differ only in how many soundness bits one
opened column (query) is credited with, and so in the query count t that reaches 128 bits.

The prover commits to rows of a Reed–Solomon code of rate ρ = k/n; the verifier opens t random columns. A cheating
prover's committed word must be δ-far from the code, and each query catches it with probability about δ, so the
query error is about (1 − δ)^t. The regimes assume different δ:

| Regime | Assumed δ | Bits per query (at the presets' rates) | t for `R_TX` | `R_TX` bytes | Status of the claim |
|---|---|---|---|---|---|
| Proven, unique decoding | (1 − ρ)/2 | ≈ 1 | 121 | ≈ 231 KB | theorem (Ligero Thm 4.7 / App. C form); 128 bits are 128 bits |
| Johnson bound | 1 − √ρ | ≈ 2.7 at ρ = 1/40 | 152 at its own optimum (n 6,536, k 862) | 257,592 B | theorem for RS proximity gaps (BCIKS20) with field-size error terms; 128 only if that error is counted once for the whole combination (124.4 bits counted per row), and it relies on mutual correlated agreement up to the Johnson radius for Ligero's consistency tests, not verified for this setting (`pqzh-ligero.md` §5.3) |
| Conjectured, up to capacity | 1 − ρ | ≈ 5.8 at ρ = 1/54 | 24 | 92,072 B | conjecture disproved in general (Crites–Stewart ePrint 2025/2046); the claimed bits may overstate real security by an unknown amount |

The Johnson preset came out larger than the proven one: its gain per query is eaten by the error terms and by the
domain sizes reachable in F_q, so it gives nothing over the proven analysis in this setting.

## 4. Owner decisions of 2026-10-14 (session 4) for PQZH, in full

1. **ZK WHIR path accepted, with an FRI fallback** (adapter over `HidingWhirPcs`, no ZK `p3-multi-stark`; stop and
   settle on FRI if `R_TX` lands above 340,431 B). Status: done — measured 1,948,901 B, stop rule triggered, merged
   `a1bfbd8` as a negative result; re-examination requested ("Xem lại WHIR", in progress on branch
   `pqzh-whir-review`).
2. **Ligero: radix-431 FFT stage and the modified ZK construction** (blinding rows at full degree inside the proximity
   test, in F_q⁴). Status: done, merged `9e7cd20`.
3. **Verify limit raised from 50 ms to 60 ms p99** (chain host, also bounding wasm32), so Ligero passes. Status: done,
   CTR-PQZ-09 and `decisions.md` (`896e16e`); after the 21-bit multiply Ligero's wasm32 p99 is 13.3–19.9 ms.
4. **PQZH soundness regime = proven** (unique decoding); conjectured not used; Johnson-bound preset measured and
   documented as reference only. Status: done (`00b600f`, `pqzh-ligero.md` §9).
5. **PQZH without the precompile:** first (2026-10-14) "if it fits the limits, use it" (withdrawing the 2026-10-13
   ruling "no chain needs it", `3253c30`); measured: Ligero does not fit (534.6 M), a StarkEx-style split FRI + ZK
   verifier would (≈ 21.4 M over 4 txs); then, after the StarkEx study, **do not build PQZH for chains without the
   precompile** — PQZH runs only where the PQZ precompile exists (7622 / 22776). Status: closed, no work planned
   (`3e2675b`).

Controller proposals (owner may override), from the P6e plan and the Ligero note: PQZH proof limit 256 KB with
precompile `MAX_INPUT` 393,216 B (statement + proof); PQZH `proofSystemId` =
`keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")`; the Plonky3 STARK crate stays as backup and is
never linked; gate-B wasm32 timing measured over ≥ 1,000 verifies under `scripts/capped`. Owner step before
production: external review of the Ligero ZK argument (`pqzh-ligero.md` §4.1) with the cryptographic audit.

## 5. Notes this summary draws on

`pqzh-design.md` (study), `pqzh-prototype.md` (first STARK), `pqzh-zk-ext5.md` (FRI + ZK, Goldilocks⁵, non-ZK
WHIR), `pqzh-zk-whir.md` (ZK WHIR), `pqzh-ligero.md` (Ligero, EVM verifier, P6e Part B), `pqzh-solidity-verifier.md`
(STARK on the EVM), `pqzh-starkex-verifier.md` (StarkWare's split verifier).

## 6. Where each confidential kind can run (owner question 2026-10-14)

| | Classical Zether | PQZ (PQZL / PQZH) |
|---|---|---|
| Verifier | Solidity on existing precompiles (bn254 `0x06`/`0x07`, BLS12-381 EIP-2537) | native precompile (`pqz-ffi`, one address for both proof systems, CTR-PQZ-10) |
| Gas per transfer | ≈ 3.6 M (bn254) / ≈ 4.3 M (BLS12-381) minimum gas limit, single recipient (`docs/contracts/zether.md`, node gas cap row) | precompile priced per id in P6f; without the precompile: PQZL has no Solidity verifier, PQZH Ligero 534.6 M (§2), StarkEx-style split FRI + ZK ≈ 21.4 M over 4 txs not built (owner) |
| Ethereum mainnet / public L2 | possible once the token contracts fit (31,162 / 40,706 B runtime > EIP-170 24,576 B; owner: size waits for Glamsterdam) and after an audit; today `ZetherSafety` allows dev chains only (31337 / 1337) | no, unless that chain adds the PQZ precompile |
| Private chains 7622 / 22776 (64 KiB code limit) | yes | yes, once P6f deploys the precompile (owner: live on 7622) |
| Post-quantum | no (ElGamal over elliptic curves: a quantum adversary decrypts amounts and balances) | yes (MLWE encryption; PQZL lattice / PQZH hash-based proofs) |
