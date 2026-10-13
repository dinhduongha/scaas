# HANDOFF — scaas

## Session 2026-10-14 (shutdown 3: z21 merged, PQZH next steps, artifact WIP) — resume here

**State:** main pushed at the HANDOFF commit. Merged and pushed since the last HANDOFF (`c2f2e0d`): `pqz-l2-domain` +
`pqz-tbox-soundness` (P6-SZ / P6-L2 fixes, `5361946`), `pqz-relfix` (`04ccd85`), `pqz-v2` (proofSystemId v2 =
`keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`, `98695de`), `ua5b` (UA-5b trade and DEX, `1b9e244`),
`pqzh-proto` (`f78056c`), `pqzh-sol` (`be81b7c`), `pqz-sv-relfix` (P6-SV specialised verifier on all five relations,
`dcf0da3`), `pqz-v2-run` (`0e7da0c`), `pqz-publish` (tbox write-ups, `099039a`), `glic-inventory` (G-LIC step 1,
`9f6677f`), `pqz-z21` (z21 norm check, lazer#26, `a8b5b66`), `pqzh-next` (PQZH ZK + Goldilocks⁵, Merkle caps, WHIR,
Plonky3 0.9.0-rc.1, `9fc5714`); research note `pqz-anonymity.md` (`623a455`). LaZer issues public: lazer#24, #25, #26;
follow-up comment on #26 (paper condition LNP22 Fig. 18, impact β 452–461 → 286–311, fix, hint ℓ∞ side note).

**Owner decisions this session (recorded in TODO / decisions.md):** priority "P6 first, finish the WIP, then focus on
PQZ" (UA-5c and UA F5 paused); token-family rename `UnderlyingToken` → `WrappedToken`, `NoUnderlyingToken` →
`IssuedToken` after P6; z21: merge `pqz-z21` (done) and **no proofSystemId bump** (every v2 verifier checks
‖z21‖² + ‖w − γ·w1‖² ≤ Bsq; decisions.md CTR-PQZ-03); merge `pqzh-next` with the Plonky3 0.9.0-rc.1 upgrade (pin 0.9.0
final when released); **PQZH is not shelved**: next build and measure a ZK WHIR path and a Ligero backend, then decide
soundness regime, proof limit / `MAX_INPUT`, prover memory target, the PQZH proofSystemId string and the backend;
P6-PUB (ethresear.ch + ePrint, PQZL only, source-only reproducibility package, numbers frozen after the z21 merge,
README §11 PQZ subsection + headline line without LaZer-findings text, results mail to the LaZer maintainers after the
freeze, separate from the G-LIC letter); G-LIC is a production gate, not a publication prerequisite (step 1 done,
step 2 letter drafted, step 3 preliminary patent search done, step 4 lawyer = owner); order changed 2026-10-14:
Docker package before the freeze run.

**WIP branches (worktrees under `.claude/worktrees/`; local only, not pushed; agents stop at the branch):**

1. **`pqz-artifact`** (worktree `artifact`, last `ed0aa43`) — P6-PUB reproducibility package `pqz-core/artifact/`,
   written, **not tested**: `Dockerfile` (ubuntu:24.04 by digest, apt from snapshot `20261013T000000Z`, clang/lld 18.1.3,
   gcc 13.3.0, cmake 3.28.3, node 26.8.1 by sha256, LaZer 3330e48 source only), `reproduce.sh` (quick default, `--full`,
   `--serve`, `--upstream` building x86-64-v3 + AVX-512 IFMA, running the latter only with `avx512ifma`),
   `results.py` (`check` / `freeze`), `web/index.html`, `README.md` with a "Status / resume" section,
   `expected-results.json` PROVISIONAL (pre-z21 times; `proofs_fnv` match post-z21). The one image build failed at apt
   (snapshot archive is HTTPS-only, base image lacks `ca-certificates`); fixed, not rebuilt (owner: no build before
   shutdown). Risks to check first: `xcheck/shim` compiling against current headers; `http.server` serving `pqz.wasm`
   as `application/wasm`. Runs: `rel3/runs/final-*` complete post-z21 run (rc 0, KAT 19/19, tbox fixes ok, `proofs_fnv`
   equal to v2; times not compared with `v2full` yet); `sv/runs/final-*` interrupted by the owner (portable
   differential 2,710 cases / 0 mismatches kept, rest not run). Resume (owner: no measuring this session): the commands
   in `pqz-core/artifact/README.md` "Status / resume" — image build, quick / `--upstream` / `--serve` tests,
   `docker image rm`; then the freeze `OUT=pqz-core/artifact/runs/freeze-2026-10-14 scripts/capped
   pqz-core/artifact/reproduce.sh --full` + `results.py freeze` → `expected-results.json`, frozen table in
   `pqz-core/STATUS.md` and `pqz-core/README.md`; then (separate tasks) README §11 PQZ subsection + headline,
   ethresear.ch post, ePrint draft, the results mail (`scratchpad/sz-private/results-letter-lazer.md`). Agent's
   question: add a CI workflow running quick mode that stores text / JSON only?
2. **`pqzh-zkwhir`** (worktree `zkwhir`, `9d748ed`) — design note `docs/research/pqzh-zk-whir.md` only, no code. Chosen
   path: Plonky3's ZK batch STARK unchanged + an adapter (`src/whirpcs.rs`, ≈ 600–900 lines) implementing
   `UnivariateStarkPcs` over `p3-whir`'s `HidingWhirPcs` (HVZK WHIR, ePrint 2026/391); rejected: ZK `p3-multi-stark`
   (weeks of unanalysed protocol work), random rows around the non-ZK prover (leaks), recursion, BlindFold. Effort
   3–5 days + 1–2 days measuring; expected `R_TX` ≈ 400–500 KB at Goldilocks⁵ (not measured). Resume: note §7.
   Agent's questions for the owner: (1) accept this path; (2) if it lands above FRI+ZK conjectured (340,431 B), build a
   batched multi-round WHIR opening or settle on FRI; (3) report Goldilocks² only at its reachable 96–100-bit targets.
3. **`pqzh-ligero`** (worktree `ligero`, `11d1493`) — design note `docs/research/pqzh-ligero.md` + parameter model
   `pqz-core/pqzh/ligero/ligero_params.py`, no Rust yet. Field F_q itself (q − 1 = 2^3·19·43·431·1,561,243, generator 3,
   domains 2^a·19^b·43^c ≤ 6,536), challenges in F_q^4 = F_q[X]/(X^4 − 3); model `R_TX` ZK 128 bits ≈ 298 KB proven
   (rate 1/8, t = 166) / ≈ 112 KB conjectured (rate 1/19, t = 35), prove ≈ 0.1–0.3 s, verify ≈ 15–40 / 3–8 ms
   (inferred). Resume: note §7 (crate, tests ≥ 960 mutations, bench + wasm32, capped runs). Agent's questions: (1) add a
   radix-431 FFT stage for longer codes (could lower the proven size); (2) use its modified ZK construction (blinding
   rows at full degree inside the proximity test) instead of the paper's §4.7 text.

**Open owner questions:** the five above; P6e (codegen, serialization v1, `pqz-ffi`, fuzzing, freeze proofSystemId) in
parallel or after PQZH; anonymity (`docs/research/pqz-anonymity.md`: ring N ≈ 8 practical, ≈ 10–12 M gas; or one-time
receiver accounts) — read Lether in full before deciding.

**Owner steps outstanding:** send the G-LIC letter (`scratchpad/sz-private/g-lic-letter-lazer.md`); after the freeze,
the results mail; tag + Zenodo source snapshot for P6-PUB; AVX-512 IFMA run of the upstream comparison; chain 22776
genesis; 7622 registry redeploy in P6g (gas limit 16,777,216, all four PQ kinds usable); lawyer (G-LIC step 4,
scope PQZ and classical Zether, private note `scratchpad/glic/`) and a cryptographic audit before production.

**Rules in force:** no built binaries on GitHub (no release assets, hosted wasm, pushed images; the xcheck/static
bundle stays local); never push `pqz-sv-fixed`, `pqz-sv-fixed-l2`, `backup/pre-sanitize-60ec820`; `pqz-verifier-floor`
kept local; `scratchpad/` and `docs/reviews/` never committed; heavy jobs only via `scripts/capped`, agents never poll
with until/sleep or `pgrep -f`.

## Session 2026-10-13 (shutdown 2: UA-5b, PQZH, PQZ relations WIP) — resume here

**State:** main pushed at the HANDOFF commit (after `af8ccf5`). Merged and pushed this session: UA-5a (`04bad29`; C5a-15
confirmed), `ua-followups` (UA-2c follow-ups + clientkeys `checkReceiverFee`, `5c5b6f5`), `pqzh-design` (PQZH design
study, `475b066`), `pqz-rel3` (`R_BURN` / `R_DS` / `R_DR` in pqz-core with the generic verifier, `3ad4069`), research:
`pqz-specialised-verifier.md` (P6-SV results; code branch not merged yet), `pqz-proof-alternatives.md` §6 candidates and
§7 prior art (Lether, MatRiCT+, backends), pq-zether.md "Why LaZer" refreshed. Private notes live in `scratchpad/`
(git-ignored); read them before touching PQZ branches.

**Owner decisions this session (recorded in TODO):** PQZL not killed (P6-SV: specialised verifier `R_TX` ≈ 8 ms p50
portable, all five relations ≤ 10 ms p99 portable). PQZH: six answers in TODO P6-PQZH — ≤ 160 KB proof for PQZH (PQZL
keeps 96 KB), sweep provable vs conjectured (leaning provable), PQZH tokens register with a PQZH `R_REG`, **"two kinds" =
PQZL and PQZH as one configuration value (`proofSystemId` at `initialize`), the four reserved PQZ `TokenKind`s stay**,
Keccak / SHAKE transcript, prototype now. PQZ relation points A, B, 1–5 accepted (A: merge `pqz-rel3` and push, done `3ad4069`; B: burn randomness fresh; 1: R_TX on the
§7.7 layout; disclosure `kind` a 32-byte word; precompile checks opTag / proofSystemId; e′ ∈ [−2^24, 2^24); lazy keys).
Credit cap stays 1024 units for now.

**WIP branches (resume in this order; none merged, none pushed; agents stop at the branch, owner approves merge/push):**

1. **UA-5b** — branch `ua5b`, worktree `.claude/worktrees/ua5b`, last `39cd048` (from `279b5d8`). Tasks 1–6 of 8 done
   (purpose `trade` in UAKinds + six libraries; `UATradeOrder` / `uaTrade` / `uaCancelOrder` / `uaInvalidateNonces`;
   `uaWrap`; `SCaaSDex` tagged legs; DEX conservation invariant; `uatrade_kat.json` + clientkeys typed data). Plan
   `docs/superpowers/plans/2026-10-13-ua5b-trade-dex.md`. **Node does not build until Task 7** (leg ABI changed):
   `scaas-node/src/abi.rs` tagged `Leg {sellToken, shape, order, sig, fill}`, `UATradeOrder`, `SelfTrade(bytes32)`,
   `UALegSettled`; `dex.rs::to_settlement` (shape-0 legs `abi_encode(TradeOrder)`, mtxSettle selector assertion ~l.1239,
   KAT ~l.840); `dex/venue.rs` watcher filter / `encode_event` / `book.settled` / mock decoder ~l.1312. Then Task 8 docs
   (dex.md CTR-DEX-15/16/23/25/26, accounts.md CTR-UA-14/-19/-26/-27 + §1.7, token-wrappers.md CTR-TOK-20, metatx.md
   CTR-MTX-18, decisions.md, TODO), full checks (forge default + `private7622`, `test/ua/**`, `--isolate` UAGas /
   UARegistryGroups, size gate, clientkeys, vectors regenerate byte-identical), mutations (`_uaMove` amount in
   `uaTrade`, `pulled[h] == 0`, `_sendTo` branch, `_payLeg` refund, `uaWrap` destination, `UAVerifyGas` re-raise), self-review.
   **Owner to confirm rulings** C5b-1/-7 (one internal order form, trailing bytes ignored), C5b-2 (`ua*` trade revert
   `UALedgerOff` when the ledger is off), C5b-3 (`SelfTrade(bytes32)`), C5b-4 (`LegShapeUnknown`), C5b-5 (DEX "ledger
   on" = listing + `registry() != 0`, no ERC-165), C5b-6 (derived destination checked only at payout → `MatchFailed`),
   C5b-9 (`uaWrap` emits only `UAWrapped`), C5b-11 (node: tagged legs + `UALegSettled` only; intake / bytes32 book / PQ
   gossip wait for UA F5), C5b-12, C5b-14 (`SCaaSDex` 23,493 B stays out of the size baseline). Numbers so far: two
   `mldsa65` legs 12,124,252 gas (three revert `UAVerifyGas`); `UNDERLYING` size pin raised 45,056 → 49,152.
   Then **UA-5c** (from `ua5b`).
2. **PQZ relation fix-ups** — branch `pqz-relfix`, worktree `.claude/worktrees/relfix`, `53f5ab3` WIP (from `3ad4069`).
   Decisions B, 1–5 done in code + spec; builds, KAT 19/19, tamper `fails 0`, ASan/UBSan clean, docs_check 0 errors.
   R_TX `proofs_fnv` changed by design (native `cb562b47` → `4690aaa0`, wasm `834d6853` → `f1c3e7f6`); R_REG unchanged.
   Lazy keys: wasm R_TX arena 251 → 221 MiB (13.6 % under 256 MiB); arena block-class rebuild fixed. Remaining: timing run
   (`scripts/capped pqz-core/rel3/relfix.sh f2`, > 10 min, background), numbers into
   `pqz-relations-burn-disclose.md` §1/§3/§4/§5 + `pqz-core/README.md` / `STATUS.md`, final non-WIP commit. Then the
   specialised-verifier part on its private branch (see the private notes).
3. **PQZH prototype** — branch `pqzh-proto`, worktree `.claude/worktrees/pqzhp`, `e1fa752` WIP. Crate `pqz-core/pqzh/`,
   Plonky3 `=0.8.0` (needs Rust 1.97.1, pinned in `rust-toolchain.toml`), Goldilocks² + FRI + Keccak Merkle, transcript
   seeded by SHAKE256(tag ‖ op ‖ be32(len) ‖ stmt); NTT(A) and the statement in periodic columns. R_REG and R_TX prove
   and verify honestly (constraint-checked). Single-run sizes: R_REG 130.7 KB; R_TX 178 KB at blowup 8 / 38 queries
   (over 160 KB), **144 KB at blowup 16 / 28 queries** (conjectured); prove ≈ 0.7–1.0 s R_REG, 1.9 s R_TX native.
   Next: default to blowup 16 / 28 queries (the first test in `tests/attacks.rs` expects ≤ 160 KB), run attacks + full
   bench, wasm build + node runner, ZK mode (pad the 16-row Digit table to ≥ 128 rows), C cross-check of statement bytes
   against `pqz_bench.c`, `p3-security` provable vs conjectured sweep, then `docs/research/pqzh-prototype.md`.
4. **PQZH Solidity verifier gas** — branch `pqzh-sol` (= main, nothing committed), worktree `.claude/worktrees/pqzhsol`
   (`smartcontracts/evm/lib` symlinked). Plan: stdlib Python references (Goldilocks, Fp2/Fp3, pure-Python keccak,
   depth-10 Merkle, FRI folds arity 2/8/16, LogUp sum) → `test/pqzh/Pqzh.sol` + `PqzhTest.t.sol` (test-only, per-component
   gas, synthetic end-to-end skeleton with Merkle checks enforced) → `pqz-core/pqzh/sol/model.py` grid (blowup 4/8/16 ×
   arity 2/8/16 × conjectured/Johnson, five relations) with calldata (EIP-2028 / EIP-7623) vs the 16,777,216 cap →
   `docs/research/pqzh-solidity-verifier.md`. Pre-measurement guess only: R_TX ≈ 2.3–4 M verify + ≈ 2 M calldata; risks:
   SHAKE over the statement in Solidity (≈ 15 M) — use the keccak opcode or a Horner fingerprint. Owner asked: measure,
   write into research, push.

**Owner steps outstanding:** the items in the private notes; 7622 registry redeploy after
the gas limit; PQ verifier audit; chain 22776 genesis; run the static bench tarball on an AVX-512 IFMA machine.


## Session 2026-10-13 (shutdown: P6d WIP, UA-1c draft) — resume here

**State:** main pushed. Merged this session: UA-3, UA client dirs rename, the license rename (Vegan Community / Vegan
Enterprise License), README (§10 relayer diagram, §13–§17, use cases grouped with fee payers, Free Pay), UA-4 (UA
ledger), P6c (PQ kinds in registry gen 1), P6b (E-S0 estimator, gate met). Spec edits on main (owner 2026-10-13,
pq-zether.md): why LaZer and no equivalent (`#why-lazer`); upstream cross-check = one-shot golden dump (no AVX-512 CI
runner); no on-chain attestation for PQZ; three disclosure kinds, no `SENDER_CP`; `be32(sendCounter)` in the HKDF info,
`be8(v)` amount kept (amounts < 2^64 by encoding; Zether's 2^54 is a token-wide BSGS cap, see `shieldScale`).

**P6d WIP (resume first):** branch `p6d-pqz-core`, worktree `.claude/worktrees/p6d`, commits `c91b3ab` (LaZer 3330e48
subset, MIT), `c397a6d` (six layers rewritten + golden dump: 19/19 equal under Intel SDE 9.48 `-spr`, AVX2 build too;
upstream strict-aliasing bug in `aes256ctr-amd64.c` worked around with `-fno-strict-aliasing`), `9ba594d` (relations
driver WIP). Read `pqz-core/STATUS.md`. Resume: (1) rerun `params/run_e_s1.sh` (~20 min, capped) and
`params/codegen/run.sh` for both relations, add the ℓ∞ filler proof in `pqz_rel.c`; (2) fix the arena crash
(`spolyvec_free`; upstream enlarges `nelems_max` after allocation) with upstream's tbox test; get `pqz_bench` to prove
and verify R_REG / R_TX; (3) measure native + wasm32 (clang 18, wasm-ld-18, node), symbol scan, README, research note
`docs/research/pqz-core-e-s1.md`, roadmap P6d row (golden-dump wording), docs_check — then the owner's kill decision.
Findings so far: LaZer's default MSIS target gives β 353 < Kyber-512's 406 — the stricter target gives R_TX kmsis 23 /
m2 64 (β 456 / 470), R_REG 22 / 63 (β 452 / 470); real constants ω 8, η 140, λ 4, binding 4η√(B1²+B2²) (E-S0 assumed
8η), JL 41 confirmed; codegen estimates R_REG ≈ 27 KB, R_TX ≈ 42 KB (+2 KB filler) — not measured.

**UA-1c draft:** `docs/superpowers/plans/2026-10-13-ua1c-c-abi.md` (DRAFT, not spiked; 13 rulings U1C-1…13: caller
buffers, `int32_t` status + `scaas_ua_last_error`, `catch_unwind`, cbindgen `=0.28.0` dev-dep with a header-drift test,
surface = ua-cxx's, no `verify`). Resume at "Spike (Task 1, Step 1)"; check first that cbindgen 0.28.0 builds offline.
Existing bindings unchanged (owner: "only add ua-c").

**Owner steps open (TODO):** P6c — redeploy UA registry gen 1 on chain 7622 after reading its block gas limit; audit
the PQ verifiers before any public chain. SCaaS Chain 22776 genesis hash when the chain is up. A one-time cross-check of
the golden dump on real AVX-512 hardware (recommended).

**Next steps:** finish P6d → owner kill decision → P6e/P6g; UA-1c (spike, execute); the template-library spec.

## Session 2026-10-13 (P6b merged)

**State:** P6b (E-S0 parameter spike) merged into main (`676366a`) and pushed; branch `p6b-estimator` kept. Outputs:
`pqz-core/params/{estimator.txt,e_s0.py,run.sh,README.md}` (Sage `sagemath/sagemath:10.7` @ sha256:4f5589eb…d528,
lattice-estimator `53da598`, `RC.ADPS16`) and `docs/research/pqz-parameters-e-s0.md`. **Gate met:** every PQZ instance
beats Kyber-512 (115.5 / 106.3 bits classical / quantum) — key and encryption 136.1 / 124.3, with 32 hints 133.5 / 121.6
(DDGR20 worst direction β 464 vs the spec's 466), proof ABDLOP MLWE 132.7 / 121.1, MSIS 132.6 / 120.3 — and every
Fiat–Shamir round ≥ 128 bits (JL 128.0, Z_q λ=4 168, R_q 672, final κ=8 129.8). Constraints for P6d: keep κ ≥ 8,
λ ≥ 4, n ≥ 24, m2 ≥ 66. Approximations: the DDGR20 hint estimator was re-implemented (matches the estimator's usvp);
LNP22 / LaZer constants marked [unverified] — P6d reruns with LaZer's values; `bdd_mitm_hybrid` only on two instances;
`estimator.txt` produced once (a full byte-for-byte rerun not yet done).

**Blocked on the owner for P6d (E-S1 `pqz-core`):** the spike's KAT equality runs against upstream LaZer's AVX-512 build —
this machine has no AVX-512 (`/proc/cpuinfo`), so an AVX-512 runner is needed; and its result is the owner's kill
decision (CTR-PQZ-09). P6e / P6g follow P6d; P6f is owner-gated chain-7622 work.

## Session 2026-10-13 (P6c merged)

**State:** P6c merged into main (`06629d8`) and pushed; branch `p6c-pq-kinds` and worktree `.claude/worktrees/p6c` kept.
Plan `docs/superpowers/plans/2026-10-13-p6c-pq-kinds.md` (rulings C6-1…C6-19). Forge 1104 passed / 10 skipped on merged
main; `test/ua` 232; `--isolate` UARegistryPq/UAGas/UARegistryGroups 34; size gate 0 errors (UARegistry 23,658 B);
`private7622` build ok; clientkeys 101 / 99 / 2 skipped (generator rerun byte-identical); `scripts/e2e-zether.sh` 3/3;
scaas-node e2e 4 + e2e_hedera 1; docs and facts checks clean.

**Built (P6c):** PQ verifiers registry-ready (`verifyPop`; ML-DSA `expandKeyRows` / `expandedKeyPart` / `verifyCached` /
`verifyExpanded`; SSTORE2 length guard); `pq_signatures.json` (PoPs, signatures, 27 negatives, msig treasury / hybrid,
metatx3 rows; in the byte-for-byte regeneration test); `UARegistry` slots 0x0130–0x0133 (stored keys, registry-derived
ML-DSA expanded-key cache `cacheExpandedKey` / `expandedKeyOf` — -44 one part, -65 two parts, never caller-supplied;
an uncached ML-DSA PoP fails `UAPoP` where there is no precompile) and the `pqz-mlwe` 0x0142 slot with its authRef rule
(verifier and enabling in P6g); msig gas bound counts the caller's hold for caps > 400 k, own-generation and handed to
gen 1; PQ signers on the UA ledger; DeployBase enables the PQ kinds on dev chains + 7622 only, caps 4.25 M / 5.95 M /
2.5 M / 1.4 M (cold headroom ML-DSA-44 75.8 k, ML-DSA-65 56.2 k, pinned ≥ 30 k by a test).

**Owner steps (open, in TODO):** redeploy UA registry gen 1 on chain 7622 after reading its block gas limit (an
ML-DSA-65 cache part needs a ~13.5 M-gas tx; with a lower limit only fndsa512 / slhdsa128s are usable); audit the PQ
verifiers and the cache before any public chain enables a PQ kind.

**Controller rulings (P6c):** fixed the plan's C6-8 gap — gen 2 also holds for PQ members it hands to gen 1 (a gen-2
msig could otherwise register within budget yet need ~47 k more to authorize); the final wave removed the now-dead
hold tag bit (behaviour-identical), stated the real cap headroom and pinned it; malformed msig `authPop` still reverts
without data (fails closed). Deferred minors: `verifyCached` edge-branch tests, UAMetaTx3Pq events/gas ceilings,
UADeploy public chain ids.

**Next steps:** the P6 E-streams (P6b E-S0 spike, P6d E-S1 `pqz-core`, P6e relations; P6f chain-7622 precompiles is
owner-gated; P6g `PqzToken` + `UAPqzVerifier`); the template-library spec; SCaaS Chain 22776 onboarding when the
chain is up.

## Session 2026-10-13 (UA-4 merged)

**State:** UA-4 merged into main (`8152ee7`) and pushed; branch `ua4-ledger` and worktree `.claude/worktrees/ua4` kept.
Plan `docs/superpowers/plans/2026-10-12-ua4-ledger.md` (rulings L4-1…L4-20). Forge 1086 passed / 10 skipped on merged
main; `test/ua` 214; size gate 0 errors; `private7622` build ok; clientkeys 97 / 95 / 2 skipped; `scripts/e2e-zether.sh`
3/3; scaas-node e2e 4 + e2e_hedera 1; docs and facts checks clean.

**Built (UA-4):** `UAMetaTransaction` / `UAMetaTransfer` (MetaTxLib), `UA_POOL`, one `bytes32` nonce map with the signer
as an id (`pad(addr)` for native ids), `SigCheck.isValid7702`; the UA ledger in `ERC20MetaTx` (registry bound at
`initialize`, balances in the ERC-7201 `scaas.ua.ledger` struct, `UA_POOL`'s own ERC-20 slot = the ledger total (L4-2),
`transferToUA`, `uaExecute` / `uaBatch` / `uaExecuteTransfer` / `uaBatchTransfer`, `uaCancelNonce`, `IUALedger`, a
derived UA may self-call only the two `unwrap`s (L4-3/L4-4), a ledger move to the token itself reverts `TransferToSelf`);
named `uaTransfer` / `uaTransferWithFee` / `uaPay` / `uaUnwrap`; T-V3-1/2/3 (the invariants fuzz NONE and a 1:1
UNDERLYING clone incl. the burn under a UA, per-UA replay, reserve; a mutation check confirmed they catch ledger bugs);
`metatx3.json` + clientkeys typed data; unwrap refuses `UA_POOL` as recipient. MT-2's UA path closed. T-V3-4 (size)
deferred to Glamsterdam.

**Owner-visible consequence:** every token implementation now exceeds EIP-170 (NONE 31,770 B; UnderlyingZetherToken
49,778 B, init 51,473 B > EIP-3860) — deploys need `--code-size-limit 65536` (test chains / anvil only); public chains with
the 24 KiB limit cannot take the tokens until Glamsterdam (owner rule: no size optimisation). `deploy.sh evm` now also
runs forge `--slow` (parallel broadcast vs anvil automine left a deploy tx pending forever; per-tx gas fits 2^24).

**Controller rulings (UA-4):** fixed the plan's fee-to-token gap (CTR-MTX-18) in `_uaMove`; `--slow` on the evm deploy
path (multiplier 105 kept); final fix wave added the burn-under-UA invariant handler and the `UA_POOL` unwrap-recipient
refusal. Deferred minors: `uaBatch` / `uaPay` not fuzzed; `metatx3.json` negatives / mode-0 row; `isValid7702` malformed-sig
tests; Hedera HIP-632 UA branch test; node `ua_metatx` jobs (UA F5, L4-17).

**Next steps:** P6c (PQ kinds in registry gen 1 incl. `pqz-mlwe`), then the P6 E-streams; the template-library spec;
SCaaS Chain 22776 onboarding when the chain is up.

## Session 2026-10-12 (UA-3 merged, license, README)

**State:** UA-3 merged into main (`520642c`) and pushed; branch `ua3-zether` and worktree `.claude/worktrees/ua3` kept.
Plan `docs/superpowers/plans/2026-10-12-ua3-zether.md` (rulings Z1–Z19). Forge 1047 passed / 10 skipped on merged main;
`--isolate` UAGas 6 / UARegistryGroups 14 / UARegistryZether 13; prague verifiers 52 + 1 skipped; size gate 0 errors;
ZetherProverCross 10; zether-prover cargo + wasm-smoke 18; clientkeys green; `scripts/e2e-zether.sh` 3/3 on anvil;
scaas-node e2e 4 + e2e_hedera 1; docs and facts checks clean.

**Built (UA-3):** `zether-bn254` 0x0140 / `zether-bls12381` 0x0141 in `UARegistry` gen 1 (PoP over
`popDigest(ua, authRef)`, the authority co-signs with purpose `authref`, `Y` stored by SSTORE2, `keyOf`,
`requireZetherAuthorized(ua, digest, auth, zkCovered)`: purpose follows the digest — `zether-auth` spends, `zether-owner`
roll-over/mode), dev-only `ZetherSchnorrBn254Verifier` / `ZetherSchnorrBls12381Verifier`; tokens on tagged `toUA` +
`kindOf`; `UniversalAccountRegistry`, `AuthScheme` and their tests in `legacy/ua3/` (`test/MultiSig.t.sol` restored);
zether-prover API `pop` / `ownerAuth`, vectors regenerated (`r33_keys.json` registered on a real registry by forge);
clientkeys `zetherPop` / `zetherOwnerAuth` / `zetherKind`; `DeployBase` deploys the UA registry on every chain with the
§1.9 kind set, `script/UAPrecompileProbe.sol` via `eth_call` (subgroup rows, MSM/pairing prices, G1ADD and MAP_FP_TO_G1),
fail closed; JSON `ua_registry` (+ `zether_registry` = same with `DEPLOY_ZETHER`).

**Controller rulings this session (UA-3):** SPDX of the plan updated to the new license before execution; MultiSig's 4
tests restored (`MultiSig.sol` stays, owner rule); no CREATE2 address pin for the registry (init code carries `uid` and the
probe-dependent kind array); the probe also checks G1ADD / MAP_FP_TO_G1 (reviewer: not a CTR-UA-23 violation since a
missing precompile makes the kind unregistrable, taken anyway). Deferred minors (test gaps, e2e port hygiene, prover
`authRef` null parsing, an owner-auth cross-language vector) → UA F3 / next touch.

**Also this session (on main):** license renamed — Vegan Community License 1.0 / Vegan Enterprise License, SPDX
`LicenseRef-Vegan-Community-1.0` (terms unchanged); README §10 relayer diagram + `docs/assets/relayer-network.svg`, §15
links, §13 "Node", §16 Use cases (34 rows in 8 groups, who can pay the fee), §17 Free Pay (Tu Viện Chơn Như), License
last; `clients/ua-cs/scaas.slnx`; UA client dirs renamed (`ua-rs`, `ua-cxx`, `ua-qt`, `ua-dart-frb`).

**Owner decisions this session:** template library = implementations deployed once per chain, instances by
clone/CREATE2 with parameters, incl. commercial contracts (TODO §0, spec first); "SCaaS Chain" chain id 22776 is a new
chain beside the others (ports 22776+; 7622 and `m/7622'` unchanged; TODO); family-tree use case stores every record on
chain; `claude-code-api.txt` hidden by `.git/info/exclude`.

**Next steps:** UA-4 (UA ledger) or P6c (PQ kinds incl. `pqz-mlwe`); the template-library spec; onboarding SCaaS Chain
22776 when the owner's chain is up (genesis hash needed). P6b can run beside.

## Session 2026-10-12 (UA-2c merged)

**State:** UA-2c merged into main (`c35f494`) and pushed; branch `ua2c-groups` kept, worktree `.claude/worktrees/ua2c`
kept; then the UA client dirs rename merged (flat `clients/ua-<lang>`: `ua-rs`, `ua-cxx`, `ua-qt`, `ua-dart-frb`; branch `ua-dirs-rename` kept). Plan `docs/superpowers/plans/2026-10-12-ua2c-groups.md` (rulings C1–C19). Forge 1052 passed / 10 skipped on merged
main; `--isolate` UAGas 6 / UARegistryGroups 14; prague verifiers 52 + 1 skipped; size gate 0 errors; `scaas-ua` with and
without `signers` + clippy clean; node 13/13; docs and facts checks clean; binding crates build `--locked` again (Qt needs
`QMAKE=~/usr/Qt/6.8.2/gcc_64/bin/qmake6`).

**Built:** `src/common/SSTORE2.sol`; `UARegistry` stored kinds 0x0110–0x0113 (`keyPtr` = SSTORE2(vk), `auth.keyData` empty,
group PoP capped at `verifyBudget` without hold, gen-2 hand-off, stored msig members); verifiers `Musig2Secp256k1Verifier`
(BIP-327 KeyAgg with `ecrecover` hints), `Musig2Bn254Verifier`, `UAFrostSecp256k1Verifier` (RFC 9591), `FrostBn254Verifier`,
`library Bip340` (extracted from `Bip340Verifier`, behaviour unchanged); `scaas-ua` `src/groups.rs` (registry-side checks) and
feature `signers` (BIP-327, ZF frost-core 3.0.0, FROST(bn254, keccak256)); `smartcontracts/vectors/ua/groups.json` (20 groups,
57 negatives, T-FROST); noble cross-check `test/ua-groups.test.js`; `test/ua/UARegistryGroups.t.sol`, `UAFrost.t.sol`,
`Musig2Verifiers.t.sol`; accounts.md §1.6.1/§1.8/§1.15/§1.16 updated.

**Controller rulings (final review upheld):** a starved group registration reverts `UAPoP`, or `SSTORE2WriteFailed` when gas
runs out at the key write after the PoP passed — never a record (`test_registerStoredStarved`, spec §1.8 step 6); if the
owner wants `UAPoP` only, map the SSTORE2 failure in `UARegistry`. FROST(secp256k1) repeated/cancelling `C_i0` is refused
on chain but accepted by Rust/noble (fails closed; §1.6.1) — mirror deferred to UA F3. Follow-ups listed under UA-2c in TODO.

**Next steps:** UA-3 (deployment, Zether kinds). P6b
can run beside.

## Session 2026-10-12 (UA-2c in progress, paused)

**State:** main has UA-2a and UA-2b merged and pushed (up to `3eb2e2b`); unpushed on main since then: the README
scorecard was pushed (`8bbac31`), then `e26749a` (TODO: UA client dirs rename), `2d40f69` (plan UA-2c), `fd900ec`,
`5cf6c35`, `a670d90` (TODO: scaas-node docker-compose) and this HANDOFF commit. **UA-2c is mid-execution**
(subagent-driven): worktree `.claude/worktrees/ua2c`, branch `ua2c-groups` from `fd900ec`; Task 1 committed (`49a3aab`:
`scaas-ua` signers behind feature `signers` — BIP-327 MuSig2 + bn254 port, ZF frost-core 3.0.0 FROST secp256k1 + the
FROST(bn254, keccak256) ciphersuite — registry-side checks `src/groups.rs`, `smartcontracts/vectors/ua/groups.json`
444,457 B sha256 `92348225…`, node cross-check `test/ua-groups.test.js`); its Opus review was stopped before finishing;
Task 2 was stopped and its partial edits discarded (worktree clean).

**Resume UA-2c:** in the worktree, read `.superpowers/sdd/2026-10-12-ua2c-groups/progress.md` (ledger, preflight table,
the pause note) — then re-dispatch the Task 1 review (package `review-fd900ec..49a3aab.diff` is there) and the Task 2
implementer (BASE `49a3aab`, brief `task-2-brief.md`), and continue Tasks 3–7, final review, merge (owner). Plan:
`docs/superpowers/plans/2026-10-12-ua2c-groups.md` (task order fixed: 1 → 2 → 3 FROST → 4 MuSig2 + `library Bip340` → 5
registry on groups.json → 6 binding lockfiles → 7 docs; rulings C1–C19). The scratch dry-run under `/tmp` may be gone after
a reboot — the briefs are self-contained.

**Owner decisions this session:** UA client dirs → flat `clients/ua-<lang>` (`ua-rs` keeps crate `scaas-ua`, `ua-cxx`,
`ua-qt`, `ua-dart-frb`; ports unchanged) — one commit right after UA-2c merges; scaas-node docker-compose deferred until
node streams P2 + P3 + P4 + P6 (P5 Odoo client not yet; the legacy pull path NODE-JOB-10 is decided to go after the
per-chain push cutover, push is not built yet); README scorecard row e) Privacy & data is a chain advantage (Zether / PQZ,
immutable records).

**Known issue:** the binding crates' `Cargo.lock` (`scaas-ua-cxx`, `-qt`, `-frb/rust`) have been stale since UA-2a, so
their `--locked` CI fails on main; UA-2c Task 6 refreshes them (+7 packages, no version moves, dry-run checked).

**Next steps:** finish UA-2c → UA client dirs rename → UA-3 (deployment, Zether kinds). P6b can run beside.

## Session 2026-10-12 (UA-2b merged)

**State:** UA-2b merged into main and pushed (branch `ua2b-ed25519` kept); plan
`docs/superpowers/plans/2026-10-12-ua2b-ed25519.md` (rulings B1–B9). Next UA-2c (MuSig2 KeyAgg with hints, FROST
secp256k1/bn254 with the DKG check, `groups.json`, `keyPtr` storage, T-FROST).

**Built:** `src/common/Sha512.sol` (unrolled, 30 k gas per block), `src/common/Ed25519.sol` (Straus–Shamir 4-bit windows,
precomputed base table, MODEXP sqrt/inversion, R compared by encoding), `src/ua/verifiers/Ed25519Verifier.sol` — strict RFC
8032 = ed25519-dalek `verify_strict` (S < L, canonical and not small-order A and R, cofactorless equation; mixed-order A
accepted when the equation holds; A with y ≥ p refused on top of dalek); ~168 k gas valid, 171 k worst, cap 210 k.
`signatures.json` gained derived[7] `ed25519` and `ed25519Rfc8032`; `ed25519_fuzz.json` (2144 cases, dalek verdicts; noble
`zip215:false` differs on small-order R and torsion components — dalek is the reference); `scaas-ua` `verify_strict` arm
(`ed25519-dalek =2.2.0`). Registry tests enable ed25519 (KINDS = 8). `Bip340Verifier` reads `returndatasize()` after its
MODEXP call (Yul evaluates arguments right to left). forge 1009 passed / 10 skipped.

**Carried to UA-2c's docs task (optional minors):** test/comment wording "+~20 %" (real margin +23 %); §1.9 canonical-A
phrase; an audit note on the ed25519 per-chain row; a mixed-order key through the registry with the real verifier; the
rejecting-side cap measurement. Stale `Cargo.lock` of `scaas-ua-cxx`/`-qt`/`-frb` (missing UA-2a/2b crates): refresh when
those crates are next built.

**Next steps:** UA-2c (or UA-3 in parallel). P6b can run beside it.

## Session 2026-10-12 (UA-2a merged)

**State:** UA-2a merged into main and pushed (branch `ua2a-registry` kept); plan
`docs/superpowers/plans/2026-10-12-ua2a-registry.md` (rulings R1–R24). UA-2 is split in three (owner): UA-2a done, next
UA-2b (`ed25519` verifier in Solidity, T-FUZZ) and UA-2c (MuSig2 KeyAgg with hints, FROST secp256k1/bn254 with the DKG
check, `groups.json`, `keyPtr` storage, T-FROST).

**Built:** `src/ua/UARegistry.sol` + `IUARegistry.sol` (gen 1: records, `keyOwner`, PoP `register`, `requireAuthorized` for
derived / native ECDSA-7702-1271 with `UAAuth` / `msig` with the structure bound incl. gen 1's hold for handed members,
generations, `chainUid`, `hederaNative`, ERC-5267; kind table = one immutable per slot from `KindConfig[]`; ed25519 slot
exists, MuSig2/FROST/PQ/Zether refused with `UAConfig`), `src/ua/IUAVerifier.sol`, verifiers in `src/ua/verifiers/`
(P-256 + WebAuthn with a constructor probe of P256VERIFY, BIP-340 via the ecrecover trick, Schnorr bn254/BLS12-381 and BLS
min-sig BLS12-381/bn254 under a bounded self-call), `src/common/CurveSigs.sol`, `WebAuthnClientData.sol`;
`smartcontracts/vectors/ua/signatures.json` from `clients/clientkeys/scripts/ua-sig-vectors.mjs`, re-verified by noble and by
`scaas-ua::verify` (Rust). forge 995 passed / 10 skipped; measured gas in accounts.md §1.15.

**Open:** HIP-632 for `hedera-native` cannot run in a `view` (R19; verified as ECDSA/1271 for now); member kinds outside
MEMBER give `UAKeyData` (R20); `bls-bn254-minsig` register needs ≥ 450 k call gas plus calldata (R23); msig worst-case
cold slack ~4 k under the bound. Carry-overs for UA-3: per-chain precompile probes (0x08/0x0c/0x0e outside-subgroup rows),
EIP-2537/pairing prices ≤ 2× before enabling those kinds.

**Next steps:** UA-2b, then UA-2c (or UA-3 in parallel with UA-2b). P6b can run beside it.

## Session 2026-10-12 (UA-1b merged, license)

**State:** UA-1b (UA identity layer bindings) and the SCaaS Community License 1.0 merged into main and pushed; branches
`ua1b-bindings` and `license-community` kept. Plan `docs/superpowers/plans/2026-10-12-ua1b-bindings.md`.

**UA-1b built:** `clients/scaas-ua-cxx` (C++17 over `scaas-ua` with cxx 1.0.202; `scaas::ua::Error`; ctest 6/6),
`clients/scaas-ua-qt` (QML singleton `Scaas.Ua/UaKinds` in Rust with CXX-Qt 0.10.0, Qt 6.8.2 at `~/usr/Qt/6.8.2/gcc_64`;
hex strings + `lastError`; Qt Quick Test 12/12 offscreen), `clients/scaas-ua-frb` (flutter_rust_bridge 2.13.0, sync API,
`int` kinds/chain ids with range checks, committed generated code; `dart test` 7/7, Linux only), `clients/ua-dart`
(pure Dart, in-package Keccak; VM, node and asserts-off runs 7/7). The final review caught the pure-Dart Keccak being wrong
with asserts off (fixed; CI runs the vectors with asserts off). Open: FRB as a Flutter plugin with Android/iOS/web builds
(does `scaas-ua` build for wasm?), Qt packaging for Windows/macOS.

**License (owner 2026-10-12):** `LICENSE` (SCaaS Community License 1.0, Licensor Dinh Duong Ha), `LICENSE.vi.md`
(non-binding summary), CLA in `CONTRIBUTING.md` (`git commit -s`), README "License" section; SPDX headers
`LicenseRef-SCaaS-Community-1.0` (Solidity, UA-1b sources), clientkeys/Move manifests. Terms: prohibited at any scale for
groups that kill animals (every species, any life stage; incl. commercial pest control), food service serving any
prohibited animal product (meat, fish, seafood, insects, silk, carmine, gelatin…, fertilized eggs, honey and bee products;
milk, unfertilized eggs, shorn wool allowed), groups with > 10% revenue from such products, and anyone trading in
human-derived products (hair, organs, tissue, blood, gametes…; only donation for medical treatment excepted; human milk
allowed); free (rights as MIT or Apache-2.0, license kept on redistribution) for fully vegan groups or groups under
USD 10 M revenue (90-day grace); everyone else an Enterprise License with the same prohibitions. A lawyer's review is
recommended before relying on it; earlier public versions stay under their old headers.

**Next steps:** UA-2 (registry and verifiers, PoP signatures, `groups.json`; carry-overs in the UA roadmap's UA-2 row).
P6b (E-S0 spike) can run beside it.

## Session 2026-10-12 (UA-1 merged)

**State:** UA-1 (UA F0, Universal Account kind libraries) merged into main and pushed; branch `ua1-kinds` kept. UA phase
roadmap `docs/superpowers/plans/2026-10-12-ua-roadmap.md` (owner: UA F0/F1 + F2 as their own phase before P6c; UA-1,
UA-1b, UA-2 registry and verifiers, UA-3 Zether re-point, UA-4 UA ledger). Plan `docs/superpowers/plans/2026-10-12-ua1-kind-libraries.md`.
Forge 926 passed / 10 skipped, clientkeys 80 (78 pass, 2 skipped), scaas-ua 6, ua-py 7, ua-go ok, ua-cs 6; size gate 0
errors; docs checks clean.

**Built:** the UA identity layer (kind table, tags, ids, keyHash with `GROUP(g) = keccak256("scaas.ua.group.<g>.v1")`,
purpose tags, `ua_msg`, `popDigest`, the registry's `UAAuth` digest, member digests, canonical ids, closed sets with
`slhdsa128s` in SIGNING/MEMBER, key-data validation incl. curve and subgroup checks, MuSig2/FROST/`msig` layouts) in six
libraries: Solidity `src/ua/UAKinds.sol` (internal; precompile calls capped at 2× the EIP price, a gas shortage reverts
`UAVerifyGas`, never `UAKeyData`), clientkeys `src/ua.js` (reference) + `scripts/ua-vectors.mjs`, Rust `clients/scaas-ua`
(independent cross-check), Python `clients/ua-py`, Go `clients/ua-go`, C# `clients/ua-cs`; vectors
`smartcontracts/vectors/ua/kinds.json` (27 valid / 201 invalid rows) and `structures.json`; CI jobs; `docs/clients/ua-libraries.md`.
The final review ran the six libraries on 6,060 inputs: identical outputs, no panics. No signatures yet (PoP signatures and
`groups.json` are UA-2). Rulings and carry-overs: plan header (U1–U10), the UA roadmap's UA-2 row (probe 0x08/0x0c/0x0e on
each target chain, `ecrecover` address(0) vs an `evm-eoa` member with id 0, ~165k gas for bn254 G2 validation, precompile
prices ≤ 2× EIP before enabling BLS / bn254-G2 kinds).

**Owner decisions 2026-10-12:** Go and C# client libraries added; Python in this repo; UA ledger as UA-4; UA-1b next:
C++ as a plain `cxx` bridge plus CXX-Qt (a `QObject` in Rust for QML; Qt 6 must be installed — not on this machine),
Dart as both flutter_rust_bridge v2 and a pure-Dart port, all on the shared vectors. ML-DSA stored key: the FIPS 204 pk;
the expanded key an optional registry-computed cache (P6c).

**Next steps:** write the UA-1b plan (bindings), then UA-2 (registry and verifiers). P6b (E-S0 spike) can run beside them.

## Session 2026-10-12 (P6a merged)

**State:** P6a (PQ signature verifiers) merged into main and pushed; branches `p6a-pq` and `p6a-val` kept (owner).
Plan `docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md`. Forge 917 passed / 10 skipped, clientkeys 75 (73 pass,
2 skipped), size gate 0 errors (verifiers fit, baseline unchanged), `private7622` build ok, docs checks clean.

**Built:** `src/ua/PqUA.sol` (IUAKindVerifier, kind tags 0x0130–0x0133, `pq_msg`, probe), `SlhDsa.sol`
(SLH-DSA-SHA2-128s), `Shake.sol` + `PqNtt.sol`, `FnDsa.sol` (Falcon-512, EIP-8052), `MlDsa.sol` (ML-DSA-44/65, FIPS 204
key and EIP-8051 expanded key, EIP-8355 probe); clientkeys `src/pq.js`, generated vectors `pq_kat.json` and
`pq_external.json` (SHA-256-pinned downloads). Measured verify gas: SLH-DSA 787,953 (worst 1,321,231), Falcon 2,266,895,
ML-DSA-44/65 FIPS key 11,379,929 / 18,896,958, expanded key 4,093,867 / 5,771,287; `expandKey` 8,519,511 / 15,304,306.

**Reviews:** T1–T4 task reviews, one fix wave (pinned SHA-256 check, `u32` range, context negatives, Falcon KAT format;
tests pinning every Falcon/ML-DSA malformed-input check by mutation; `Shake` reverts `ShakeMemory()` without `reserve()`;
probe vector lengths; expanded-key NatSpec warning), final review (Opus) clean after three docs/NatSpec minors.
Deferred minors (T2 test polish, probe of wrong length falls back silently, the `reserve()` guard is a heuristic) are
non-blocking; P6c carry-overs are in the TODO P6 row.

**Owner decisions 2026-10-12:** (1) UA F0/F1 run first as their own phase; P6c then only adds the PQ kinds (UA F9) to
registry gen 1. (2) ML-DSA stored key = the FIPS 204 pk (UA id, keyHash, EIP-8355 path); the EIP-8051 expanded key is
an optional cache attachable later, computed by the registry itself with `expandKey(pk)` — never caller-supplied (the T4
review probed two universal forgeries on an unchecked expanded key) — stored once per UA id by SSTORE2 chunks under
EIP-170 (-44 one, -65 two), read by EXTCODECOPY per verify; -65's cache registration (≈ 15.3 M + ≈ 7.4 M) spans several
transactions. No hybrid (classical + PQ) kind. The verifiers are home-written and unaudited — audit before any public
chain enables them.

**Next steps:** P6b (E-S0 parameter spike, independent); write the UA F0/F1 phase plan (kind libraries in four
languages + vectors; `UARegistry` gen 1 with the classical verifiers incl. BIP-340, Schnorr-bn254/BLS12-381, MuSig2,
FROST, ed25519, msig; Zether re-point; UA ledger split); then P6c. Chain-7622 docker/chainspec changes (P6f) need the
owner's approval.

## Session 2026-10-11 (P5)

**State:** P5 merged (`d245a29`, pushed); main's P3b merged in before the merge. Plan `docs/superpowers/plans/2026-10-11-p5-node-clients-new-abi.md`.
890 forge tests (main 1047 + `DexKatTest` 1 − 158 v1 tests moved to `legacy/p5/`; 10 skipped, P3b's env-gated measurements); size gate 0 errors; `scaas-node` lib 278, mesh vectors (46 cases, sha256 `bde85091870f6bea608d6e3430b70fcf00b34f73c6e6d3dc659009582b39c4ad`) + fuzz, clippy clean; e2e 4/4 and e2e_hedera 1/1; clientkeys 62 (60 pass, 2 skipped); node mutation probe 110/110 killed (fix-wave-1 95, final review W1–W10, fix wave 3 5) (private `CARGO_TARGET_DIR`; a shared target gave false survivors).

**Built:** `scaas-node` on the new tree: `src/abi.rs` (`MetaTransaction`, `MetaTransfer`, `TradeOrder`, `Leg`, `DexOrder`,
`Settlement`, `IToken`, `ISCaaSDex`, `IMandateWallet` errors), `src/metatx.rs` (`Mtx { Call, Transfer }`, salted
`Domain`, wire forms with `struct`), `src/guard.rs` (call table with the P4 rows, `chainUid()` binding, selector tables
from `mtxSelectors()`, `mtxSettle` gas by simulation, ERC-1271 floor 432,349, `already_invalidated`), `src/dex.rs` and
`src/dex/venue.rs` on the `SCaaSDex` clone (`TradeOrder`/`DexOrder`, `mtxSettle`, outside legs, cancels where the order
lives, `SigCheckGasStarved` split, empty `MatchFailed` = `out_of_gas`), the mesh EVM body with `salt`, `Chain::uid()`
(block 0 or `chain_uid`; a wrong pin refuses the lane); clientkeys `checkPayment` on `MetaTransfer` with `chainUid`,
`checkCall`, `tradeOrderTypedData`, `orderCancelTypedData`, `checkTradeOrder`; KATs with relayed calldata and the new
`dex_order_kat.json`, `hedera_kat.json` v3; deploy: two demo tokens from `OpenFactory` (`demo_token`, `demo_token_2`),
v1 keys gone. The v1 line (`MetaToken`, `HederaMetaToken`, `OpenFactoryV1`, `MetaTxDex`, `SCaaSDexV1`, their tests and
vectors, the Hedera smoke) is in `smartcontracts/evm/legacy/p5/`; the node's and clientkeys' v1 encoders in their
`legacy/p5/` (not built).

**After the reviews (fix wave).** The outbox normalizes `feeRecipient`/`relayer` for every origin (`work_from_job`) and keys
in-flight work by the token's own digest, read after the guard; the guard runs in `Submitter::submit`, and metatx/entry
targets must be registered tokens (entry: or a listed DEX), else `TOKEN_NOT_SERVED`; token lists refresh every 15 s; a job
with `receiver_fee` is refused. The venue's signature check mirrors `SigCheck` (7702 designators ECDSA only, ERC-1271 capped
by codehash, exactly 32 bytes returned); a revert naming no order probes each SCaaS leg for evidence, else 503, never 400;
pending amount per order, closing fills wait for it; drops are committed before the 503. The Hedera lane checks `chain_uid`
at start and reports `already_invalidated`; jobs rebuilt after a restart pass the guard and the 2^24 gas clamp (a refused
one is only logged and gap-filled).
Fix wave 2 changed the clientkeys API: every check takes the client-built intent (`checkPayment` needs `payee`, `entryRef`,
`expectedToken`, `amount`; `checkCall` takes `call = {contract, data}`; `checkTradeOrder` the client's `order`; new
`checkCancel`, `payLane`), pins the payment lane and returns the fee. Fix wave 3 (final review): venue/guard/adapter
chain-I/O tests; a lane whose `chain_uid` check fails stays stopped and retries with backoff (the node keeps running);
the gateway runs the guard before simulating; settle refusals name the failing settlements; a guard-refused rebuilt
job is reported (`mined` from its hash, `dead` when the gap-fill lands); `node.example.toml` pins `chain_uid`.

**Rulings N1–N18 (plan header).** **N1** `struct` absent = `transfer`, unknown fields refused; **N2** `chain_uid` from block 0
or config, a mismatch stops the lane; **N3** call table only for built contracts, `mtxExecuteAsOwner` under the wallet rule,
token entries as `metatx` jobs; **N5** `mtxSettle` gas ×1.5 until every settlement settles, a whole-call revert is final;
**N6** `MinNonceNotIncreasing` = consumed `already_invalidated`; **N7** venue rules (one settlement per taker, crossing
remainder dropped, makers restored first, `ESCROW` refused, fee rate by role); **N13** deploy without v1; **N14** v1 to
`legacy/p5/`, `MetaTxGasV2.t` against frozen v1 numbers.

**Not done / next:** bamboo-dms follows before the P5 node reaches a chain Odoo uses (TODO P5: jobs with `struct` and
salted digests, KAT repoints, DEX book shapes, events, `already_invalidated`, mesh vectors, deploy keys, the portal
bundle); deferred (TODO MT-8): batching and the per-selector breaker (NODE-LANE-11, -25), TradeEngine (P7),
NODE-IDX-06 `repeat_of`, `ua_metatx`, client Zether encoders after P3b, the per-poll market re-check; open questions in
the plan.
## Session 2026-10-11 (P3b)

**State:** P3b (Zether storage and auditor modes, owner 2026-10-11) built from the plan `docs/superpowers/plans/2026-10-11-p3b-zether-modes.md`;
the spec rules CTR-ZTH-30/38/42/48/49/50 flipped to built, §19 re-measured, PQZ (CTR-PQZ-19/23/24) spec only.

**Rulings to confirm (controller, pending the owner):** the commitment `keccak256(R)` over `R = salt ‖ B_1 ‖ … ‖ B_M` (the spec table now says so), the `…/v2` proof system id label, `seed_zether` = the R33 conf key `x`, `AuditorForbidden` for NONE, the registry's `keyOf`, the `uint8` config fields with typed errors.

**Not done / next:** R6 (archive of `TransferBundles` for receiver and auditor), transfers over the EIP-7825 cap (the prover refuses them by its measured transaction gas limits per curve, form, auditor and direct / relayed, zether.md §19; no contract cap), the client ABI (P5). Done in P5: the node's gas padding clamped to 2^24.

## Session 2026-10-11 (P4)

**State:** P4 on branch `p4-accounts`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
1001 forge tests; size gate 0 errors (every token +8 B for the `_selfSender` hook, baseline raised; `MandateWallet` 15,509 B, `HederaMandateWallet` 15,997 B, both under the cap); clientkeys 56 (54 pass, 2 skipped);
Solana 42, Sui 68, Aptos 105 (+ entry check), Soroban 28, Cosmos 10, TON 28; e2e 4/4 and e2e_hedera 1/1; mutation probe 79/79 killed.

**Built:** `src/account/SmartKeyAccount.sol` and `SmartKeyAccountFactory.sol` (`chainUid` constructor argument, `chainUid()`),
`src/wallet/MandateWallet.sol` (`owner`, `chainUid`; `epoch[token]`, `revoke(token, epoch)`, `payUnderMandate(…, epoch)` (selector `0x781fc8a8`), `mtxPayUnderMandate`, `mtxRevoke`,
`mtxExecuteAsOwner`, `mandatePayLane`, `mandateRevokeLane`), `src/hedera/HederaMandateWallet.sol` (HIP-632 for 64-byte signatures,
`mtxExecuteAsOwnerRaw`), `MetaTxBase._selfSender`; Solana `state::SmartKeyAccount`; clientkeys `metaTxTypedData`,
`ownerCallTypedData`/`checkOwnerCall` on the salted `MetaTransaction`; KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`,
`mandate_revoke_kat.json`, `smart_key_account_create2.json`; deploy JSON `smart_key_account_factory` / `_implementation`. Tests
`test/account/SmartKeyAccount.t`, `AccountKat.t`, `test/wallet/MandateWallet.t`. The typed-struct line is in
`smartcontracts/evm/legacy/p4/` (not built).

**Rulings L1–L18 (plan header).** **L1** the `_selfSender` hook; **L2** the account checks itself through its own
`isValidSignature`; **L3** `cancelRecovery` allowlisted; **L4** `SubjectKey` keeps its name; **L6** pre-P4 clones and wallets are
redeployed (every chain is a test chain); **L7** `NotDelegate`, lane encodings; **L11** Hedera HIP-632 on every wallet entry; **L12** (reversed by the owner) the rename
covers the contract accounts (EVM, Solana, Soroban); Sui/Aptos keep `meta::Account<T>` (a per-token balance object), TON/Cosmos have none; **L13** Solana discriminator follows
the name, no state migration; **L14** deploy JSON keys renamed.
Controller rulings after the reviews, pending the owner (mandates.md CTR-ACC-07): the delegate's pay names the mandate epoch (`StaleEpoch(current, signed)`; a revoke, and any `setMandate` even a plain expiry extension, voids queued delegate pays; the pay job re-reads `epoch(token)` and re-signs); `setMandate` keeps `periodStart`/`spentInPeriod` when the delegate and `periodSeconds` are unchanged. Documented, no code: an owner hand-pay plus a delegate pay of the same `entryRef` can pay twice; the kill-switch revoke job must re-read the epoch after a `setMandate`. M1/M2 are EVM-only (TODO: one follow-up per other family).

**Not done / next:** bamboo-dms follows before P4 contracts reach a chain Odoo uses (owner call with `chainUid`, mandate digests and the pay calldata with the epoch, its relay job still on pre-P4 names like `revokeWithSig`, CREATE2 file, JSON key; TODO P4); the node's
call table for the renamed rows (P5); open questions in the plan (agent mandates from `docs/research/node-ai-agents.md`).

## Session 2026-10-11 (P3)

**State:** P3 on branch `p3-zether`, merge pending; head is the fix-wave-2 commit on `f847471` (final review I1, m1–m7). Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`.
977 forge tests; `zether-prover` `cargo test` 53 green (the `read_balance` BrokenPipe flake fixed); e2e 4/4 and 1/1; real `deploy.sh evm` broadcasts on anvil 31337 green both default and with `DEPLOY_ZETHER=1` (27 txs, BLS verifier 14.08 M gas). Fix wave 2: the Zether deploy is opt-in (`DEPLOY_ZETHER`), `deploy.sh` adds `--code-size-limit 65536 --gas-estimate-multiplier 105` and keeps the previous JSON on a failed broadcast, `ZetherDeploy.t` checks JSON keys, the SmartKeyAccount implementation and per-tx gas under EIP-7825, kind 3 `initialSupply` pinned, stale docs. Fix wave 1 (review follow-ups): S3 disclosure vectors through `ZetherDisclosure` (chain-B negative), every published selector relayed once on both kinds, the stronger invariant (legs 1:1 and 3/7, rate changes, surplus never drops), `OpenFactory._checkZether` probes low level (typed error on a permissive fallback), the prover API refuses `unwrapBinding` outside `proveBurn`.

**Built:** `src/zether/ZetherLib.sol` (external, `scaas.zether`), `ZetherLayer.sol`, `NoUnderlyingZetherToken.sol` (kind 2),
`UnderlyingZetherToken.sol` (kind 3: `zetherWrapShield`, `zetherUnshieldUnwrap`), `ZetherStatements.sol`, the new
`IZetherToken.sol`; `MetaTxBase._envelopeBinding` / `_ticketBinding` (transient `scaas.mtx.binding`); `ERC20MetaTx._domainName`
(`"SCaaS ZetherToken"`); `ConfidentialConfig.maxShielded` / `confidentialFee`; `OpenFactory` Zether gate and verifier check;
verifier header 416 B and `ZetherDisclosure` challenge with `chainUid`; `DeployBase` deploys the Zether stack on dev chains when `DEPLOY_ZETHER=1` (opt-in; `deploy.sh` adds the forge flags);
the Rust prover on the new header, digests and ABI (vectors regenerated, `envelope.json`); from the disclosure review,
HASH stored in one `bytes32` slot and the `ITransferDisclosure` NatSpec corrected (G2, G5). Tests: `ZetherNone.t`,
`ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherRelay.t`, `ZetherUnderlying.t`, `ZetherInvariant.t`, `ZetherDeploy.t`,
`v2/FactoryZether.t`. The old `ZetherToken` line is in `smartcontracts/evm/legacy/p3/` (not built). Sizes:
`NoUnderlyingZetherToken` 30,659 B, `UnderlyingZetherToken` 40,381 B, `ZetherLib` 15,662 B (ratchet baseline).

**Rulings K1-K18 (plan header).** **K1** `chainUid` in every token-side digest, the prover's `s` too; registry unchanged.
**K2** the kinds are the public kinds plus the layer. **K3** domain `"SCaaS ZetherToken"` by a hook. **K4** two config
fields. **K5** the gate on `OpenFactory`. **K6** every confidential op allowlisted `ABSOLUTE`. **K7** the ticket binding
hook, not cleared. **K8** a direct unshield-unwrap binds its leg and `minOut`. **K9** reserve invariant by construction,
`executeRate` counts the shielded part. **K10** events. **K11** shapes, standalone `IZetherToken`. **K12** statement views
take `envelopeBinding`. **K13** `TransferToSelf` for a fee to the token. **K14** old line to `legacy/p3/`, no node change.
**K15** prover ABI. **K16** deploy on dev chains. **K17** size. **K18** not built (PQZ batch hook, registry `chainUid`).
**K19** disclosure carried over, the review's G2–G5 folded (HASH one slot, relayed HASH, `chainUid` in the challenge).

**Not done / next:** P4 (`MandateWallet`, `SmartKeyAccount` on `MetaTxBase`); the disclosure review's answers (open
questions in the plan); a real-passkey Zether envelope test; gas of `zetherWrapShield` / `zetherUnshieldUnwrap` (the zether.md tables were re-measured on the new kinds, these two are not in them); open questions for the owner: the prover's `s` derivation (SHA-512, not the spec's HKDF), binding the leg and `minOut` in a relayed unshield-unwrap.

## Session 2026-10-11 (P2c)

**State:** P2c on branch `p2c-dex`, merged `d85fc8b` (code `dbf27a5`, tests `ae23be1`). Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`.
949 forge tests.

**Built:** the exchange path on `SCaaSDex` (`src/dex/SCaaSDex.sol`, `ISCaaSDex.sol` with `IExchangeExecutor`): `mtxExchange`
(interactions), `mtxExchangeVia` (executor), `setExchangeTarget`, `setListedOnly`, `exchangeTarget`, `tokenKnown`;
`ExchangeLegSettled`, `ExchangeTargetSet`, `ListedOnlySet`; `NoLegs`, `TokenNotKnown`, `ForbiddenTarget`, `ForbiddenSelector`,
`TargetNotListed`, `InsufficientOutput`. Tests `test/v2/DexExchange.t.sol` 36 (mock router, v2-style pairs, executor,
hostile targets). Sizes: `SCaaSDex` 21,826 B (was 14,722); tokens unchanged; no deploy change.

**Rulings J1-J11 (plan header).** **J1** Path A bounds at the pull (token or `TradeLib`), Path B by the DEX, as in
`mtxSettle`. **J2** known = a side of a listed market, counted per market. **J3** a pull check refuses an inexact sell
token before any interaction. **J4** every `approve` interaction reset to 0 after the last one (stricter than the spec), and `increaseAllowance` and Permit2 `approve` are refused (controller ruling, pending the owner; other raising selectors such as `increaseApproval` stay open).
**J5** leftovers fail the final conservation check. **J6** error arguments. **J7** under the listing condition the tokens
an interaction calls are targets too. **J8** `NoLegs`. **J9** `receivedFloor` is gross. **J10** no Uniswap fork test yet.
**J11** no deploy change; two storage fields appended.

**Not done / next:** the Uniswap fork test and the DEX invariant suite (dex.md section 14); the node's TradeEngine (P7);
`checkOrder` (H7) and the Hedera ED25519 limitation stay as in P2b-2.

## Session 2026-10-11 (P2b-2)

**State:** P2b-2 on branch `p2b2-dex`, merged `7049c78` (code `f4afbca`, plan `7b77cd1`, tests `6b9c645`). Plan
`docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. 913 forge tests.

**Built:** `src/dex/DexPuller.sol` (`pull(token, from, amount)`, only the DEX), `ISCaaSDex.sol` and `SCaaSDex.sol` extended: outside
legs as `DexOrder` in the DEX domain (`dexOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `pulled`, `minNonce`,
`puller()`), `TradeLib` on the DEX's own `scaas.trade` state, `mtxCancelOrders` / `mtxInvalidateNonces`, the ERC-1271 cap by
codehash (the constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes,
`SigCheckGasStarved` reverting the whole `mtxSettle`, payouts by `SafeERC20`. Tests: `Dex.t.sol` 36, `DexOutside.t.sol` 21
(19 plus a hook-token re-entry test pinning `nonReentrant` on all entries, and a starved check inside a SCaaS leg).
Sizes: `SCaaSDex` 14,722 B, `DexPuller` 624 B, every token +9 B (the `precheck` argument; baseline raised).

**Rulings H1-H10 (plan header).** **H1** an outside leg is a `DexOrder` checked by `TradeLib` on the DEX's state; `ESCROW`
refused. **H2** the `DexPuller` is deployed by `initialize` (a clone runs no constructor). **H3** the cap by codehash;
Hedera passes no implementation, so 50 k. **H4** `MatchFailed` keeps 256 bytes (an `Error(string)` of ~160 bytes whole).
**H5** `SigCheckGasStarved` reverts the whole call; a listed token, or a party's contract `destination` through a hook
token, can forge the selector, so hook tokens are never listed and the node splits such a batch per settlement. **H6** DEX
cancels: bad-signature or closed items skipped, never expire. **H7** `checkOrder` not built (pending the owner). **H8**
inexact tokens are the admin's listing job, conservation the backstop. **H9** tests. **H10** size baseline +9 B per token.

**Not done / next:** `checkOrder` for the new DEX (H7, with the node's P7 intake); the DEX invariant suite (dex.md section 14);
Hedera ED25519 accounts cannot sign `DexOrder` or DEX cancels (no HIP-632 branch; `IS_HEDERA` in `SCaaSDex` later); P2c plan:
`mtxExchange` / `mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`.

## Session 2026-10-11 (P2b-1)

**State:** P2b-1 on branch `p2b-dex`, merged `0510c7d` (code `27b9e92`, plan `80303f9`). Plan
`docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. 891 forge tests.

**Built:** `src/dex/ISCaaSDex.sol`, `SCaaSDex.sol` (clone implementation, ERC-7201 `scaas.dex`, salted domain `("SCaaS
Dex","1",chainId,clone,chain_uid)`): `mtxSettle` (one taker, many makers, each settlement a self-call `settleOne`),
`setMarket(base, quote, listed)` classifying tokens from the factory, `setFeeSplit`, `LegSettled`/`MatchFailed`;
`OpenFactory` DEX catalogue (`registerDexImplementation`, `dexImplementationOf`, `latestDexVersion`, `createDex`, `isDex`,
`dexVersionOf`, events `DexImplementationRegistered`, `DexCreated`); `script/DeployBase.sol` deploys and registers the DEX
implementation (JSON `dex_implementation`, no clone). Tests `test/v2/Dex.t.sol` (36). The built DEX is `SCaaSDexV1`
(contract and its two test files renamed), still deployed for the node (`dex.rs`, `dex_kat.json`, `scaas_dex`) until P5.

**Rulings G1–G7 (plan header).** **G1** P2b is split: P2b-1 SCaaS legs, P2b-2 outside legs, P2c exchange path; an
outside-token market lists but settles `OutsideLegNotBuilt(token)`. **G2** `SCaaSDexV1` kept for the node until P5, then
`legacy/` (owner: backup, not delete). **G3** Path A bounds are the token's; the DEX checks Path B on the matched part
(`Overfill`, `BelowMinFill`, `PriceLimit`). **G4** arrangement checks `TokenMismatch`, `SelfTrade` (a maker's `from` =
the taker's), `DuplicateOrder`, `WrongRelayer`, `DexMismatch`, `NoMakers`, `FillMismatch`. **G5** registry names with
`dexVersionOf` (the token `versionOf` stays the token one); the implementation answers `factory()`/`chainUid()`. **G6**
conservation on the settlement's two tokens, `LegSettled` per leg. **G7** scripts register the implementation, no clone.
Sizes (owner: not a concern, waiting for Glamsterdam): `SCaaSDex` 9,574 B, `OpenFactory` 8,476 B, `SCaaSDexV1` 13,204 B.

**Not done / next = P2b-2 plan:** outside-token legs (`DexOrder`, `DexPuller`), DEX-side `mtxCancelOrders` and
`mtxInvalidateNonces`, `checkOrder`, the ERC-1271 cap; then P2c (exchange path, `setExchangeTarget`, `setListedOnly`). The
spec's `FeeWouldStick` is not a named error in `SCaaSDex` (the split is validated at `setFeeSplit`/`initialize`).

## Session 2026-10-11 (P2a)

**State:** P2a merged into `main` as `6a5c6b0` and pushed (code `a78d4d8`, fixes `341e3eb`, `a930c27`; plan `dbbaed5`). Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. 855 forge tests.

**Built:** `src/trade/ITradeToken.sol` (structs, events, errors) and `TradeLib` (ERC-7201 `scaas.trade`
`0x2c9c6bfc…2f00`; `precheck` → the token's signature check → `record`); in `ERC20MetaTx` (every kind) `mtxTrade`,
`mtxCancelOrder`, `mtxInvalidateNonces`, `tradeOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `pulled`,
`minNonce`; on `UnderlyingToken` `mtxWrap` (`UnderlyingLib.wrapBySig`) with `NativeNotGasless`, `WrapOrderInvalid`,
`WrapReceivedMismatch`. Tests `Trade.t` (21), `MtxWrap.t` (16), `TradeKat.t` (1, `test/vectors/trade_kat.json`).
Neither `mtx…` trade entry nor `mtxWrap` is allowlisted; `MsgSenderLint` pins their direct `msg.sender` reads.

**Rulings F1–F6 (plan header).** **F1** `TradeLib` is split around the signature (two delegatecalls) because the
signature check, with the Hedera branch, stays the token's. **F2** error names the spec leaves open:
`MinNonceNotIncreasing(current, requested)`, `MinNonceAboveCap(requested)`, `NotDex(caller)`, `DexNotContract(dex)`.
**F3** `mtxWrap` errors; the relayer binding is the underlying's `mtxTrade` (the wrapper passes `msg.sender` as
`submitter`). **F4 (flag to the owner):** size. `NoUnderlyingToken` 22,951 B is **over its 20,480 B budget** (under
EIP-170), `UnderlyingToken` 29,974 B, `ZetherToken` 28,860 B; all in the ratchet baseline, size-pin tests NONE ≤ 23,552 and
UNDERLYING ≤ 30,720; `TradeLib` 3,104 B, `UnderlyingLib` 11,654 B. Optimise later (owner). **F5** the new KAT is
`trade_kat.json`; `dex_kat.json` stays the built `SCaaSDex` `Order` vector the node reads until P2b/P5. **F6** the trade
entries live in `ERC20MetaTx`, so every kind on `MetaTokenBase` (NONE, UNDERLYING) has them; `ZetherToken` (on `ZetherMetaTx`) and v1 `MetaToken` have no `mtxTrade` (Zether in P3). `EscrowFillShape`, `NotDex`, `DexNotContract` are named by the spec; only the arguments of the last two were open. Fix commits: 341e3eb and the final-review wave.

**Not done / next = P2b plan:** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` (Path A/B), `DexPuller`;
the old `SCaaSDex` is kept as `SCaaSDexV1` for the node until P5 (done in P2b-1 except `DexPuller`). Then P2c (exchange path). `mtxWrap` on `ZetherToken`
comes with P3.

## Session 2026-10-11 (toolchain + chains)

**State:** on `main` (pushed): solc **0.8.37**, `evm_version = "osaka"` for every profile (owner: all chains Osaka,
Celo included); BSC (56), Polygon PoS (137), Base (8453) seeded `draft` in `docs/networks/evm.md` §1 with profiles
`bsc`/`polygon`/`base` (survey of 2026-10-11, RPC-probed: EIP-2537, EIP-7702, P-256 `0x100` and the CREATE2 deployer live
on all three; Polygon: 32,768-byte code and 2^25 tx gas cap, no `safe` tag; Base: L1 data fee, `l1_batch` finality).
e2e runs anvil `--hardfork osaka --gas-limit 16777216` (EIP-7825: a tx without a gas field got the 30M block limit and
was refused). Under Osaka, forge has native P256VERIFY at `0x100`: the passkey gas tests use it (no etched stub).
Size baseline: `ZetherToken` 28,860 (solc 0.8.37). 817 forge tests (two stub/estimate passkey tests merged into one).
Not done: the Odoo `blockchain.chain` seeds for the three chains (bamboo-dms; owner asked why it matters — not needed
for SCaaS itself); EIP-7954 (64 KiB code) is a draft, chain 7622 keeps `maxCodeSize` 24,576.

## Session 2026-10-11 (P1e)

**State:** P1e merged into `main` as `e433bf5` and pushed (819 forge tests; e2e 4/4 and e2e_hedera 1/1;
docs checker 0 errors). Plan `docs/superpowers/plans/2026-10-11-p1e-openfactory.md`. P1 is complete except these
parked items: MT-1 (the v1 line is kept as `…V1` until P3/P5), MT-3 (the v1 approve rule), MT-4 (`salt = chain_uid` in the other
domains, E10), and the P1d test gaps in TODO.

**P1e delivered:** `OpenFactory(registrar, chainUid)` (`createToken`, `createTokenUnregistered`, `TokenConfig`, one
`TokenCreated`, `isToken`; registration reads `kind()`, `factory()`, `chainUid()`); both token kinds implement
`initialize(creator, version, TokenConfig)` and a constant `kind()`; a field of another kind reverts
`ConfigFieldForOtherKind`; the factory indexes the same `cfg.legs` the token reads. The v1 line is renamed
`OpenFactoryV1`/`IOpenFactoryV1`/`IFactoryTokenV1`; factory v2 is backed up in `smartcontracts/evm/legacy/p1e/`.
`script/DeployBase.sol`: every contract by CREATE2 through forge's deterministic deployer (`DEPLOY_SALT`), `_setup`
requires the deployer, `_gate` checks `chainUid()`; both deploy scripts on it; JSON keys `token_factory`,
`implementation_none`, `chain_uid` (`factory_v2` and `implementation_meta_none` are gone). CI size gate
`scripts/size_gate.py` with `smartcontracts/evm/size-baseline.json`.

**Rulings E1–E10 (plan header).** For the owner: **E1** the v1 line stays in the build as `…V1` until the node and
clientkeys (P5) and Zether (P3) move, then `git mv` to `legacy/` (backup, not delete). **E7** CREATE2 for every deployed
contract, `forge script --broadcast` needs `--sender` (`deploy.sh` and the e2e pass it); linked libraries are still
placed by forge from the sender, not by CREATE2. **E9** the size gate is a ratchet: token implementations ≤ 20,480 B,
others ≤ 24,576 B, init ≤ 49,152 B; baseline `UnderlyingToken` 26,449, `ZetherToken` 28,849; it does not tighten itself.
Also: E2 v2 becomes `OpenFactory` (`git mv`); E3 no Zether or DEX creation yet (P3, P2); E4 `kind()` is a pure constant;
E5 `ConfigFieldForOtherKind`; E6 one source for the legs (the P1d D8 cross-check is gone); E8 the deploy gate; E10 other
domains' `salt = chain_uid` is not in P1e (MT-4 stays open for them).

**Sizes (forge build src --sizes, runtime B):** `NoUnderlyingToken` 20,196 (284 left of 20,480), `UnderlyingToken` 26,449
(over EIP-170), `UnderlyingLib` 10,096, `OpenFactory` 6,850, `OpenFactoryV1` 6,057, `ZetherToken` 28,849.

**For integrators:** the factory's underlying index is only as truthful as the implementation; trust it for registered
versions (`versionOf(token).version != 0`); `createTokenUnregistered` records version 0.

**Parked (TODO, P1e follow-ups):** the ratchet does not auto-tighten; `deploy.sh` requires `PRIVATE_KEY`; the P1d parked
test gaps stay; `OpenFactory` accepts registration of kinds 2 and 3 before P3 (only the PQZ kinds 4–7 are reserved).
Main has a newer commit (`7c90483`, Gnosis profile `prague`, `docs/networks/evm.md` table row) that this branch lacks;
the merge should be clean (that table row was not touched).

**Next action:** write the **P2** plan (`TradeLib`, `SCaaSDex` as a clone, `createDex`): find room in `NoUnderlyingToken`
first (284 B left).

## Session 2026-10-11 (P1d)

**State:** P1d merged into `main` as `d03d894` (814 forge tests; e2e 4/4 and e2e_hedera 1/1;
docs checker 0 errors). Not pushed. Plan `docs/superpowers/plans/2026-10-11-p1d-underlyingtoken.md`.

**P1d delivered:** one `UnderlyingToken` (kind `UNDERLYING`, 1–8 legs) over the external `UnderlyingLib`
(`scaas.underlying`, slot formula in CTR-TOK-24); `SingleUnderlyingToken`, `MultiUnderlyingToken`, `HederaTokensV2` and the
Hedera children are gone (HTS check and association run in `UnderlyingLib` init under `IS_HEDERA`). Native-coin leg
(CTR-TOK-26). Rate admin and guardian are `AdminLib` roles (`renounceRole(bit)`; `rateAdmin()`, `guardian()`,
`renounceRateAdmin`, `renounceGuardian` removed). `IUnderlyingToken` carries the events and errors. `_legCount` is removed:
linear layout is ERC-20 slots 0–4. Tests: `Underlying.t.sol` (9), `NativeLeg.t.sol` (13), the rest ported.

**Rulings D1–D12 (plan header).** For the owner: **D2** size is out of scope: `UnderlyingToken` 25,408 B is over EIP-170
(24,576) and the 20,480 B budget, so it cannot be deployed on a real chain; the deploy scripts still deploy only
`META_NONE`; the size work (at the latest the P1e CI gate) must bring it down. **D4** rate admin and guardian are roles,
a role may have several holders, `renounceRole` leaves the rate and a pending change. **D6** native leg has 18 decimals,
8 on Hedera (tinybars; display only). Also: D1 `mtxWrap` and `NativeNotGasless` move to P2; D5
`disableFeature(RATE_ADJUSTABLE)` cancels a pending change; D7 `NativeValueMismatch(value, expected)`; D8 init =
`abi.encode(UnderlyingInit)`, legs must equal the factory's `underlyings`; D9 `META_SINGLE` takes 1–8 legs, nothing
implements `META_MULTI`.

**Sizes (forge build --sizes):** `UnderlyingToken` 25,408, `UnderlyingLib` 11,018, `NoUnderlyingToken` 20,038,
`AdminLib` 3,406, `HederaLib` 753; over 24,576: `UnderlyingToken` and `ZetherToken` (28,849) only.

**e2e:** the first `e2e` run failed all four ("forge script failed", 0.6 s); a second run and each test alone passed 4/4.
Cause found in P1e: `e2e.rs` did not create `deployments/` on a fresh checkout, so the script's `writeJson` failed on the
first run (not a cold forge build); fixed in P1e. `e2e_hedera` 1/1.

**Parked (TODO, P1d follow-ups):** test gaps (single-asset selector through `mtxExecute` on a two-leg token, native
`UnderlyingTransferMismatch`, native `addReserve` with value > amount, guardian revoke); `OpenFactoryV2` `META_MULTI`
count branch is dead until P1e.

**Next action:** write the P1e plan (factory
`createToken`/`TokenConfig`, CREATE2 deployer, deletions of the v1/v2 lines, size gate; D2 lands here at the latest).

## Session 2026-10-10 (P1c)

**State:** P1c merged into `main` as `3a43c2e`, not pushed (792 forge tests, e2e 4/4 + e2e_hedera 1/1, KAT vectors
unchanged, docs checker 0 errors). Base `d827062`; not pushed.

**P1c delivered:** `AdminLib` (flags, owner, roles in `scaas.token`; CTR-TOK-22) with all events and errors in the new
`ITokenAdmin` (`src/metatx/ITokenAdmin.sol`), so they are in the token ABI; new `RoleAccountZero(uint8)`. `MetaTokenBase`
on `AdminLib`: `PAYABLE` gate on `mtxPay`/`payWithFee`/`mtxPayReceiverFee`, ERC-165, `IS_HEDERA`. `HederaLib` replaces
`HederaV2Lib` (`requireValid` public view, linked); `HederaNoUnderlyingToken` deleted. `NoUnderlyingToken` uses the
`MINTABLE`/`BURNABLE` flags and roles (no `minter()`, `MinterRenounced`, `NotMinter`). Wrappers report legacy powers as flags (C5).
`test/v2/Features.t.sol` (13 tests).

**Rulings for the owner:** C1 own `AdminLib`, not OZ `AccessControlDefaultAdminRules` (two-step owner, no delay); C2 flags
5–8 refused at init with `FeatureNotBuilt` until the asset suite; C3 no external `PayLib` (pay is inline over the
`MetaTransfer` core, gated by `PAYABLE`; +2.6 k gas on a fresh lane), so PAYABLE is advisory for payments (a signed payment still settles
through `mtxExecuteTransfer`); gating `entryRef ≠ 0` would contradict T2 — owner to decide; C9 NONE has 442 B left, P2 must find room;
`ITokenAdmin` carries the admin functions, events and errors; `RoleAccountZero` refuses granting a role to address 0.

**Sizes (runtime B):** `NoUnderlyingToken` 20,038 (<= 20,480); over EIP-170: `Single` 28,296, `Multi` 29,147, `HederaSingle`
29,201, `HederaMulti` 30,052, `ZetherToken` 28,849 (until P1d); `AdminLib` 3,403, `HederaLib` 753.

**Next action:** (superseded by the P1d section above) write the **P1d** plan (`UnderlyingLib` + `UnderlyingToken`).

## Shutdown 2026-10-10

**State:** P1b merged into `main` as `fb2a234` (branch `p1b-erc20metatx`, 758 forge tests, e2e 4/4 + e2e_hedera 1/1); not pushed.
758 forge tests pass; docs checker 0 errors; the node e2e suites (`e2e`, `e2e_hedera`) pass against the deploy scripts,
which deploy only `META_NONE` on factory v2 until P1d and default `CHAIN_UID` to block 0's hash. The bamboo-dms repoint
is done on branch `scaas-metatx-v1-kat` (commit `81cea08`) in `/home/dockers/odoo19/custom-addons/bamboo-dms` — not
merged into its main; the owner merges.

**P1b delivered:** v1 names suffixed `…V1`; `MetaTransfer` + `IERC20MetaTx`/`IERC20Payment`; `ERC20MetaTx` on `MetaTxBase`; the v2
line moved onto it (named builders, per-kind allowlists, gasless burn/wrap/unwrap; `MetaTxCore` and the op dispatch removed);
receiver-pays (`mtxPayReceiverFee`, `ReceiverFee` co-signature, token as fee recipient refused as `TransferToSelf`, HIP-632 payee
test); conformance + `msg.sender` lint; KATs `metatx_kat.json` (unchanged) and `metatransfer_kat.json` (new) written on a
`NoUnderlyingToken` clone.

**Rulings for the owner:** R3 wrappers over EIP-170 until P1d; R4 UA ledger split moved to UA F1; R7 SmartKeyAccount name on the
token side now (`SMART_KEY_ACCOUNT_IMPL`; the account contract stays `SubjectAccount` until P4).

**Sizes (runtime B):** `NoUnderlyingToken` 17,602, `HederaNoUnderlyingToken` 18,057 (both <= 20,480); over EIP-170: `Single` 26,102,
`Multi` 26,951, `HederaSingle` 27,417, `HederaMulti` 28,266, `ZetherToken` 28,849.

## Shutdown 2026-10-09 (evening)

**State:** `main` = `1d51d22` (P1a merged), pushed; tag `ref/pre-token-tree` (→ `dc429c4`) pushed. Tree clean. 712 forge
tests pass; docs checker 0 errors (2 known budget warnings: `token-wrappers.md` 986 > 845, `dex.md` 538 > 520 — owner call).

**Next action:** write the **P1b** plan (`ERC20MetaTx` on `MetaTxBase`: `MetaTransfer` + `mtxExecuteTransfer`/`mtxBatchTransfer`,
fee classes on tokens, receiver-pays, approve only by contracts, UA path, KATs `metatransfer_kat.json`), against the code P1a
left; then execute subagent-driven like P1a. P1b notes (a)–(h) are in TODO §00 under P1.

**P1a delivered** (plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`, 9 tasks + final review):
- `legacy/` (27 reference copies, not built) + tag `ref/pre-token-tree`.
- `src/common/SigCheck.sol` — one signature check (ECDSA low-s; ERC-1271 capped, ≤32 B returndata, starvation guard
  `SigCheckGasStarved`; 7702 designator = EOA); the three built bases use it; `SigLib` deleted.
- `src/common/SaltedEIP712.sol` — salt = chain_uid, clone-safe, `eip712Domain()` 0x1f, `ChainUidZero()`.
- `MetaTxLib`: v3 `MetaTransaction` (typehash pinned); built struct renamed `LegacyMetaTransaction` (digests unchanged).
- `src/metatx/MetaTxBase.sol` + `IMetaTx.sol` — `mtxExecute` (+ alias), `mtxBatch`, lanes, `cancelNonce`, transient sender +
  one-shot ticket (fail-closed: an allowlisted target without `nonReentrant` reverts), allowlist + fee classes
  (1 = ABSOLUTE, 2 = AMOUNT), `_chargeFee` NONE only, `_checkEnvelope`/`_useNonce` for the P1b `MetaTransfer` path.
  Mock `MtxRegistryMock` ≈ 9.4 KB — the 20,480 B token budget needs care in P1b/P1c.
- KAT: `metatx_kat.json` = v3; `metatx_v1_kat.json` = built v1 (node + clientkeys repointed).
- **Cross-repo breakage:** bamboo-dms `dms_blockchain/tests/test_eip712.py:14` reads the old path — repoint to
  `metatx_v1_kat.json` there (resolved 2026-10-10: branch `scaas-metatx-v1-kat`).

**Owner decisions 2026-10-09:** `OrderBookDex` → **`SCaaSDex`** (done 2026-10-09, domain `"SCaaS Dex"`); integration.md rewrite later
(TODO §0); docs: README map as per-area tables, architecture.md numbered sections + contents, §1 lists smart contracts first.

**Controller rulings during P1a** (review if you disagree): RA tag on `dc429c4`; RC/RF/RG/RH/RJ several test gaps upgraded
to required (signature refusal branches, per-flag canon, end-to-end binding, alias coverage, batch replay/rollback, fee
basis offset, fee after call, per-item fees); RE refuse zero chain_uid (NET-ALL-22); RJ feeClass ≥ 3 refused; RK
`_checkEnvelope`/`_useNonce` + fail-closed ticket added in the final review. Plan defaults: refusal error
`MetaTxUnknownMode`, ERC-1271 margin 5,000 gas, fee class checked before `supportedModes()`.

## Shutdown 2026-10-09

**State:** `main` = P0 merged and pushed (`4bad99b`) + 3 local commits (TODO note, P1a plan). Tree clean. Nothing of P1 started:
no tag `ref/pre-token-tree`, no `legacy/` yet (Task 1 of the P1a plan does both).

**Next action:** execute `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md` (9 tasks; the owner has not yet chosen
subagent-driven vs native — recommended subagent-driven). Then write P1b…P1e one at a time, each against the code P1a/b/… left:

| Plan | Scope |
|---|---|
| P1a | tag + `legacy/`; `SigCheck`; `SaltedEIP712` (salt = chain_uid); `MetaTxBase` (MetaTransaction, lanes, transient sender + ticket, allowlist, `mtxExecute`/`mtxBatch`/`cancelNonce`, fee NONE only); KAT — **plan written** |
| P1b | `ERC20MetaTx` on `MetaTxBase` (`git mv MetaTxCore`): `MetaTransfer`, `mtxExecuteTransfer`/`mtxBatchTransfer`, fee classes, receiver-pays, approve-only-by-contracts, UA path, KATs |
| P1c | `MetaTokenBase`: features + owner model (`AdminLib`, regulated flags), `PayLib`, init/provenance, `IS_HEDERA` + `HederaLib`; kind `NONE` |
| P1d | `UnderlyingLib` + `UnderlyingToken` (Single+Multi merged, native-coin leg, `mtxWrap`) |
| P1e | factory `createToken`, CREATE2 deployer, deploy scripts + `chainUid()` gate, delete v1/v2 lines, CI size gate |

**P1a plan notes:** the plan's code was run in a scratch copy (692 tests pass, KAT matches `cast`). (1) The bare
`MetaTxBase` mock is 9,410 B — almost half the 20,480 B token budget (CTR-TOK-24): watch it in P1b. (2) `metatx_kat.json`
becomes the v3 vector; the v1 vector moves to `metatx_v1_kat.json` and in-repo readers are repointed — the bamboo-dms test
`dms_blockchain/tests/test_eip712.py:14` breaks until repointed there (resolved 2026-10-10: branch `scaas-metatx-v1-kat`). (3) Defaults taken in the plan: fee classes
1 = ABSOLUTE, 2 = AMOUNT; refusal error `MetaTxUnknownMode`; ERC-1271 starvation margin 5,000 gas + error
`SigCheckGasStarved`; KAT on a mock (P1b regenerates it on a real token).

**Done today (2026-10-08/09):**
- Zether code: multi-recipient transfer + three storage modes; Z9–Z13 (no attestation, `SENDER_CP`, per-transfer auditor
  opt-out, threshold auditor key = docs only, disclosure in a stateless `ZetherDisclosure`). `ZetherToken` still 28,939 B
  (over EIP-170) — solved by P3 (`ZetherLib`).
- P0 docs fold (9 tasks, each reviewed, plus a whole-branch review): ids CTR-ZTH-37…47, CTR-TOK-21…26, CTR-MTX-25,
  CTR-AS-17, CTR-DEX-24, CTR-ACC-11, CTR-PQZ-22; `docs/README.md` absorbed `SCaaS-v2.md`; `architecture.md` 421 → 879 lines.
- `smartcontracts/evm/chain-uids.json`: genesis hashes of 26 live EVM chains (two RPC sources each). ETH/ETC and
  Avalanche/Fuji share a genesis (a chain = `(chainId, chain_uid)`); Base Sepolia / Celo Sepolia official RPCs prune block 0;
  Hedera values derived from the mirror node (first 32 bytes) — confirm against the relay; Holesky and Alfajores are dead.

**Owner rulings 2026-10-08/09 (all folded):** features chosen at creation; one owner grants/revokes per-flag roles,
disables disableable flags, `renounceOwnership` (role holders keep roles; full lock = revoke all, then renounce);
`PAYABLE` default off; Hedera = per-chain parameter; Single+Multi merged; native-coin leg (some chains lack WETH-like
tokens); confidential layer over the public balance with direct wrap-shield / unshield-unwrap; minter never mints shielded;
regulated flags refused on confidential kinds; factory creates DEX clones, `isDex` advisory only (tokens never consult it);
`SubjectAccount` → `SmartKeyAccount`; keep old code (tag + `legacy/`); refactor in place.

**Controller rulings during P0 (review if you disagree):** R4/R8 budget warnings left as warnings (`token-wrappers.md`
986 > 845, `dex.md` 538 > 520 — owner to accept or ask for a split); R7 native leg on every `UNDERLYING*` kind incl.
`UNDERLYING_ZETHER`; R10 target `zetherUnshield(payload, proof, authSig, beneficiary, to, amount)` order; R12 target EIP-712
domain `"SCaaS SmartKeyAccount"` (P4); R14 `PAYABLE`/`BURNABLE` always locked (`disableFeature` reverts `FeatureLocked`);
R5 owner acts on a flag only by granting itself the role, OZ `AccessControlDefaultAdminRules` is the P1 candidate.

**Open (owner):** PQZ multi-recipient (hint-count risk with shared randomness) and PQZ Z9/Z10/Z12; the two budget
warnings; `docs/integration.md` rewrite (TODO §0, later). Deferred P0 minors are listed in TODO §0 ("P0 follow-ups").

## Session 2026-10-08 (evening)

Token-tree design accepted by the owner and folded (P0 done); record frozen at `docs/history/specs/2026-10-08-token-tree-design.md`
(Status line holds the id map). The Zether multi-recipient record is frozen too. Code is unchanged: every affected
section carries a "Transitional (BUILT)" note naming the phase.

- **Tree:** `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → four kinds by code (`NONE`, `UNDERLYING`, `NONE_ZETHER`,
  `UNDERLYING_ZETHER`; `*_PQZ` reserved), features by flags (payable, mint, burn, adjustable rate, wrap-disable, freeze,
  force, pause, allowlist); one owner model; Hedera as an `IS_HEDERA` branch; the native coin as an underlying leg; libraries
  `AdminLib`, `PayLib`, `UnderlyingLib`, `HederaLib`, `TradeLib`, `ZetherLib`; `SCaaSDex` as a clone. Ids CTR-TOK-21…26,
  CTR-MTX-25, CTR-AS-17, CTR-DEX-24, CTR-ZTH-37…47, CTR-ACC-11, CTR-PQZ-22.
- **TODO §00 is now phases P1–P5** (P1 = MT-1…MT-4 on the new tree, P2 = MT-5, P3 = MT-6, P4 = MT-7 + rename, P5 = MT-8/9).
- **Owner decisions for P1:** (1) keep the old code for reference: git tag `ref/pre-token-tree` on the last commit before
  P1, plus the v1/v2 token sources and the old `ZetherToken` copied to `smartcontracts/evm/legacy/` (not built, not
  tested; README "reference only"); (2) P1 refactors in place (`git mv` + edit), not a rewrite — reuse map in TODO §00;
  `TradeLib` (P2) reuses the prototype in `/home/ha/work/blockchain/metatx/contracts`.
- **`smartcontracts/evm/chain-uids.json`** (genesis hashes of live EVM chains, two sources each) is linked from NET-ALL-22;
  a chain is identified by `(chainId, chain_uid)`.
- PQZ multi-recipient and PQZ Z9/Z10/Z12 are not owner-ruled: recorded as `open` only.

Next: P1 plan (one plan per phase, written against the folded rules), then P1 code.

## Session 2026-10-08 (afternoon)

Three designs accepted by the owner and folded (drafts frozen in `docs/history/specs/`), root README updated:

- **Generic meta-tx call** (`2026-10-08-metatx-generic-call-design.md`): `MetaTransaction{from, data, …}` for a call of
  any allowlisted function of **any** SCaaS contract (base `MetaTxBase`, fee `NONE` unless a token overrides it; gas
  paid by a sponsor), typed `MetaTransfer{from, to, value, entryRef, …}` on tokens; named functions kept, plus
  `mtxExecuteTransfer`/`mtxBatchTransfer`; `MandateWallet`/`SubjectAccount` on `MetaTxBase` (account signs as itself);
  UA ledger split the same way; `PqzToken` relays like Zether. Ids CTR-MTX-22…24, CTR-ACC-10, CTR-UA-26, CTR-PQZ-21.
- **DEX exchange** (`2026-10-08-dex-exchange-design.md`): `mtxExchange` (DEX calls AMM interactions) and
  `mtxExchangeVia` (solver executor) fill `TradeOrder`s against AMMs, multi-hop, `receiveToken` may equal the sell token;
  surplus to signers on chain; `DexPuller` holds outside-token allowances; allowlist via order flag `LISTED_POOLS` and
  admin `setListedOnly`; node TradeEngine keeps only the relayer share. Ids CTR-DEX-20…23, NODE-DEX-17/18, CLI-SGN-37.
- **Non-EVM** (`2026-10-08-nonevm-metacall-design.md`): `MetaCall` + `MetaTransfer` per family, one verification library
  + typed `mtx_*` entries (CosmWasm/TON one `MtxExecute`), `KeyOp`/mandate structs → `MetaCall`, EVM parity. Ids
  NET-ALL-26…29 and one per family. Streams NM-APT…NM-SOL in TODO §00.
- Owner rulings: PQZ is meant for public chains but **waits for a lattice precompile there** (CTR-PQZ-01 change);
  `contracts/metatx.md` line budget accepted. Phase 4 fixes from the lost `fix-cnc`/`fix-node` worktrees landed (`9476617`).

Next: code streams in TODO §00 (MT-1 first); Codex reviews still owed (needs credit). The Odoo side (`SCAAS_ROOT` in
four `dms_blockchain` tests, compose mount) is uncommitted in bamboo-dms/odoo19, left to another instance.

**Repo moved 2026-10-08** from `bamboo-dms/scaas/` to `/home/ha/work/ainative/scaas` (standalone). The bamboo-dms
`dms_blockchain` tests read vectors via env `SCAAS_ROOT` (fallback `../../scaas`); the Odoo container mounts the repo
read-only at `/mnt/scaas` with `SCAAS_ROOT=/mnt/scaas` (`/home/dockers/odoo19/docker-compose.yml`). Older sections
below still say `bamboo-dms/scaas/`. The move also surfaced two never-committed Phase 4 fix worktrees (`fix-cnc`,
`fix-node`); their fixes are now on `main` (`9476617`), so "28 findings fixed" below holds only from that commit.

## Shutdown 2026-10-08 — read this first

**Meta-transaction redesign accepted and folded.** Design record: `docs/history/specs/2026-10-07-metatx-generic.md`
(rev 5, two Claude reviews: `docs/reviews/specs/2026-10-07-metatx-generic-claude-review-{1,2}.md`, git-ignored). Rules
now live in the component docs (`contracts/metatx.md`, `token-wrappers.md`, `dex.md`, `zether.md`, `accounts.md`,
`mandates.md`, `node/job-api.md`, `node/dex-venue.md`, `networks/README.md`, `clients/signers-clientkeys.md`, …) and
`decisions.md` (30 new ids, 58 updated, 5 superseded: CTR-TOK-12/14, CTR-DEX-06/07, CTR-ZTH-11). **Code is unchanged**:
every affected section carries a "Transitional (BUILT)" note — the code streams below implement it.

Owner rulings 2026-10-07/08 (all in decisions.md, owner: yes):
- `mtxExecute`: the token calls **itself** with the signer's calldata on a fixed per-implementation selector allowlist
  (transient sender + one-shot ticket; all or nothing; never calls another contract). No `approve`, no role functions
  in any allowlist. `executeMetaTransaction` kept as an alias. Every signed entry point starts with `mtx`.
- **Only a contract may call `approve`** on a SCaaS token (EOAs never, in any form; outside tokens excepted); wrapping a
  SCaaS underlying by signature (`mtxWrap`).
- One base **`ERC20MetaTx`**; the v1 line (`MetaToken`, `HederaMetaToken`, v1 `OpenFactory`) is deleted; one factory.
- `salt = chain_uid` (genesis hash) in **every** EIP-712 domain; implementation immutable; deploys via **CREATE2**; a
  fork of a chain we run is a new chain.
- DEX: one signed **`TradeOrder`** (`from, receiveToken, amount, receiveAmount, minFill, fee, relayer, dex,
  destination, flags, batch, nonce, validUntil`) — the owner's old `MtxTradeOrder` modernized; no role in the order;
  funds move **only into `dex`**; `relayer` = matching party (0 = anyone); minimum fill = max(minFill, 50 %); one `fee`
  paid out by the DEX in the same call per an admin-set split; Path A (resting, `pulled[orderHash]`) and Path B
  (escrow + refund, IOC); one taker + many makers per call; DEX balance-conservation invariant. **Owner-accepted
  residual risk:** `dex` only has to be a contract — clients must refuse an unlisted `dex`, the node never routes one.
- NODE-IDX-06: a repeated `entryRef` is flagged by the node (`repeat_of`) **and** checked by the client (refund decision).
- Nothing is deployed anywhere: no compatibility/migration work.

Also today (all pushed except the meta-tx commits listed in `git log origin/main..main`):
- Docs reorg closed: Phase 4 reviews (28 findings fixed), 10 % second sample (111 items, 3 minor fixed), every diagram
  Mermaid, checker **C11** (ASCII art refused), plan in `docs/history/plans/`.
- Root `README.md` rewritten: chain as infrastructure, IaaS/BaaS comparison, contracts as API services, standards
  (incl. EIP-6963), shared code/upgradeability, Universal Accounts, fee models, transaction flow, open relayers,
  Zether/PQZ, design evolution.
- `clientkeys/` and `zether-prover/` moved to **`clients/`** (app planned at `clients/app/`); CI jobs `clientkeys` and
  `zether-prover` added (first GitHub run pending).
- `contracts/accounts.md` (Universal Account + passkeys + optional SubjectAccount) and `contracts/mandates.md`.

Open for the next session: the code streams in `TODO.md` §0; points the fold left open — PqzToken's envelope on the
self-call path, the Zether statement header now 416 bytes with `chainUid` at offset 96 (verify against the prover),
ExchangeOffer's gasless leg as a `TradeOrder`; non-EVM families' equivalent of `mtxExecute`/`mtx` names (separate
draft).

## Docs reorg 2026-10-07 — read this first

The specs, `SCaaS.md` and `integration.md` were replaced by one set of self-contained component docs (plan
`docs/history/plans/2026-10-07-docs-reorg.md`, tag `docs-pre-reorg` = state before). **Reading order:**

1. [`docs/README.md`](docs/README.md) — map, precedence (owner rulings > component docs > code > history > research),
   status tags, id scheme.
2. [`docs/SCaaS-v2.md`](docs/SCaaS-v2.md) — product introduction.
3. [`docs/architecture.md`](docs/architecture.md) — system overview.
4. Component docs for the area you touch: `docs/node/`, `docs/contracts/`, `docs/networks/`, `docs/clients/`,
   `docs/integration.md` (+ `integration-odoo-example.md`).
5. [`docs/decisions.md`](docs/decisions.md) — every ruling (`<AREA>-<TOPIC>-NN`), why, and the alias index. Old ids in
   code comments (`R91`, `RS5-9`, `CR-PD-1`, `UD:§23`) stay valid: `python3 scripts/docs_check.py resolve <id>`.
   Section refs in code (`NI §5.2`, `TW2 §7`) point into the frozen copies in `docs/history/specs/` (abbreviations:
   `docs/history/README.md`).

Frozen: `docs/history/` (specs, plans, `SCaaS-2026-10-07.md`, `integration-2026-10-07.md`, `blockchain.md` + trace,
reorg ledgers in `history/reorg/`); background: `docs/research/`. Checks (CI `docs` job): `python3 scripts/docs_check.py
check`, `… facts check`, `python3 scripts/test_docs_check.py`.

| Phase | Commits | What |
|---|---|---|
| 0 | `08250aa`…`a59909a` | history frozen (pure renames), checker, old-id inventory (746), id map, fact ledger |
| 1 | `a492fa9`…`4cc227c` | node, contracts, networks/clients/integration docs + register fragments, every fact placed |
| 2 | `2e9bf4e`…`e13be84` | README, architecture, SCaaS-v2, decisions.md (merged register + alias index), history README, `_work` retired |
| — | `9513731` | owner rulings: lane keys hold no roles (NODE-JOB-01/19), `max_inflight` tunable default (NODE-LANE-24), decisions.md budget accepted |
| 3 | this commit | outside references: README, TODO (stream table → Doc/Scope), this file, scaas-node README (English, rewritten), smartcontracts READMEs, code-comment spec paths, CI `docs` job |

Left: Phase 4 reviewer pass (§6.4, ≤ 3 read-only reviewers, fixes by area); then move the plan to `docs/history/plans/`.
New design work: draft in `docs/superpowers/specs/`, rules into the component docs on acceptance (docs/README "Ids").

## Shutdown 2026-10-07 (before the docs reorg)

Spec phase is almost closed: **every spec has had at least one independent review and every review is folded**.
Remaining spec work = TODO §0 (SCaaS.md/integration.md sync, a few cross-spec nits, 9 Codex reviews owed, the
9000 → 7622 sweep). No code was written today (owner rule); all bugs the reviews found in BUILT code are now spec
rulings + named fix streams (TODO §1 "Fix first").

### Today (2026-10-07), all pushed on `main` (head `df45e59` + this handoff)

| Commit | What |
|---|---|
| d9c227a, 4fd706c, df45e59 | NI rev 3.5 (Codex: C1 admin-user escalation, tombstones, empty token subset, live-call per namespace, `outer_tx`, atomic intake, CORS) → 3.6 (spec B + UA 1.4 sync, `chain_uid` check) → 3.7 (R340–R349: breaker meters fees/value/deposits, attempt cap, grief score, mesh sig verify, payload-sourced fields, value-out cap, deposit rule, journals in store, immutable programs, one custody key) |
| bb75ad7 | UA rev 1.4 (Codex: R330 `chain_uid` = genesis hash in PoP/domain salt; R331 EIP-7702; hedera-native member; BBS not legal evidence) |
| f3c521f, 39e42ce, 991d835 | PQZ rev 1.3 (Codex: MSG_TAG, authRef binding, hint leakage on `e1`, inline lengths, self-test price, chain 7622) → 1.4 (**owner: `PqzToken` implements `IERC20MetaTx`** like ZetherToken; v3 `UAMetaTransaction` for a PQ-only payer; `wrap`/`unwrap` parity; gasless exit = envelope `burn`) |
| 9fe2534 | spec B rev 1.3 (Codex: sponsorship accounting at accept, `min_valid_secs`, per-namespace dedupe, EIP-1153 prerequisite, itemized erasure log) |
| 9e27d35 | SCaaS.md/integration.md aligned (admin API keys removed, spec register, §8.12 PQZ, §9.8 UA, chain 7622) — needs one more sync (TODO §0) |
| 5ea19e6 | DEX + Zether + zether-limits + consensys-max (Claude review; DX-FIX1–5, ZF-FIX1–3) |
| a23f14a, 7e986f8 | payments, wallets addendum, round3, signing formats, infra-service (Claude review; PAY/ADW/R3/WSF-FIX streams) + **owner: programs immutable at deploy** (CR-R3-11) |
| df45e59 | net-{ton,cosmos,sui,hedera,soroban,aptos,solana} (Claude review; **TON C1 BLOCK**: unbounded forward TON) |
| 191c2ed | `blockchain.md` Mermaid fix (quoted edge label with parentheses) |

### Owner rulings today
- Private chain id **9000 → 7622** (9000 is Evmos Testnet); dev chain gets a new genesis; `chain_uid` = genesis hash bound everywhere (UA R330).
- `PqzToken` follows `IERC20MetaTx` (PQZ R284).
- Aptos/Sui/Solana programs **immutable at deploy** (fix = new deploy + migrate); agent extended it to Cosmos `--no-admin` per SCaaS §1.3 — owner may drop that line.
- MuSig2/FROST kinds kept; Soroban `C…` keys kindNo 18.

### Reviewer state
- Codex works **only with `-m gpt-5.5`** (default `gpt-6.1-sol` rejected for a ChatGPT account; the `codex:codex-rescue` agent fails on it). Credit ran out after 4 reviews; 9 owed (TODO §0).
- Claude reviews of the 16 older specs: `docs/reviews/specs/*-claude-review-1.md`.

### Next session
1. TODO §0 (≈ 1 hour of docs).
2. Code: TODO §1 "Fix first" (NET-TON-FIX1 first), then NI P2 → P3, UA F0 → F1, app A1.

## Earlier: shutdown 2026-10-06

SCaaS = **SmartContract as a Service: the smart contracts themselves are the API services**. `scaas-node`
(doubles as relayer) is infrastructure anyone can run, with its own policies; it is not the product.
Repo `git@github.com:dinhduongha/scaas.git`, checked out as an independent nested repo at
`bamboo-dms/scaas/` (ignored by bamboo-dms). The Odoo addons (`dms_blockchain*`) stay in bamboo-dms and read
vectors from `scaas/…`.

### State

| | |
|---|---|
| `main` | pushed (see `git log`). Merge commits were linearised by `pull --rebase` — content is complete |
| Layout | `smartcontracts/{evm,move/{aptos,sui},soroban,cosmos,ton,solana,scripts}`, `scaas-node/`, `clients/{clientkeys,zether-prover,app (planned)}/`, `docs/` |
| Code landed this session | mesh S0 (gateway fee binding), S1a (consumed state, in bamboo-dms), S2 (R80), S3 (envelope + 32 vectors), P1 store v2 SQLite + review fixes, TW2 token wrappers v2 (EVM + Hedera), TON tx-hash fix, `bamboo → scaas` rename |
| Last gates | scaas-node `cargo test` 239/0 + clippy + e2e 4/4 (after P1 fix); forge 550/0 (TW2); every family e2e 1/1 (after rename); Odoo blockchain suite 432/0 (after rename) |
| Not deployed anywhere | domain tags renamed `bamboo.* → scaas.*` ⇒ every dev/test contract must be redeployed; DB rows `blockchain.token.domain_name` ("Bamboo MetaToken") and Cosmos `network_key` (`bamboo-1`) need updating after redeploy; operators rename env `BAMBOO_* → SCAAS_*`; every node needs `scaas-node store init` once (migration 0001 was edited in place — recreate dev `node.db`) |
| Worktrees | `.claude/worktrees/{p1,p1fix,rename,s3,tonhash,tw2}` — all merged; remove when convenient |

### Specs (all on `main`, frozen in `docs/history/specs/` since the 2026-10-07 docs reorg), rulings and review state

| Spec | Rulings | Rev | Review |
|---|---|---|---|
| `docs/history/SCaaS-2026-10-07.md` (system) + `docs/history/integration-2026-10-07.md` | precedence | — | PLANNED material owner-review pending |
| `2026-10-05-relayer-mesh-design.md` | R70–R86 | 3 | ×2 |
| `2026-10-06-node-independence-design.md` (NI) | R87–R111 | 3.3 | ×1 + P1 code review |
| `2026-10-06-mesh-gossip-amendment.md` (A2) | R112–R128 | 2.1 | ×1 |
| `2026-10-06-token-wrappers-v2.md` (TW2) | R129–R149 | 1.2 | ×1 + impl review — **BUILT** |
| `2026-10-06-scaas-app-design.md` | R150–R179 | 1.2 | ×1 |
| `2026-10-06-tender-sponsorship-shredding.md` | R180–R199 | 1.2 | ×1 |
| `2026-10-06-asset-suite-design.md` (AS) | R200–R217 | 1.1 | ×1 |
| `2026-10-06-operations-design.md` (OPS) | R230–R247 | 1.2 | ×1 |
| `2026-10-06-signers-followups.md` (S4F) | R250–R268 | 1.0 → 1.1 in flight at shutdown | ×1 |
| `2026-10-06-pq-zether-design.md` (PQZ) | R270–R289 | 1.1 | review in flight at shutdown |
| `2026-10-06-universal-account-design.md` (UA) | R290–R318 | 1.2 (all owner items closed) | review in flight at shutdown |

Reviews (local, git-ignored): `docs/reviews/specs/`. Owner decisions are recorded inside each spec (owner-answers tables).

### Key owner rulings this session (details in the specs)

- Node independent of Odoo; Odoo is a client (push jobs, poll feeds). Store SQLite/PostgreSQL/MySQL (storage only).
- Admin auth: built-in users (CLI bootstrap) + optional OIDC; roles viewer ⊂ operator ⊂ admin + key_custodian.
  **API keys = external server-side clients only** (never in browser/mobile apps); automation = OIDC
  client-credentials or host CLI.
- Mesh: HTTP pull bus + libp2p gossip (QUIC default, hybrid X25519MLKEM768; TCP+Noise; HTTPS); private peers PQ-only.
- Universal Account: key-derived 32-byte kind-tagged ids, no wallet contract; native single-key accounts and 1271
  need no registration; one key = one purpose; purpose `m/7622'`; MetaToken v3 UA ledger; PQ + ed25519 everywhere;
  SubjectAccount kept as option (b); VC/eKYC optional.
- Token wrappers v2: three tiers, rates fixed/adjustable (issuer option), multi-underlying any-of, named `mtx*`
  functions, gasless unwrap with `minOut`.
- Owner wants **all specs finished before app code**.

### Constraints that bit this session

- Max 3 sub-agents; one heavy build at a time: wrap with `scaas/scripts/capped` (also `CARGO_BUILD_JOBS=4`).
- Worktrees need gitignored deps: copy `smartcontracts/evm/lib` (OpenZeppelin is a symlink to
  `/home/ha/work/blockchain/openzeppelin-contracts`), `mkdir smartcontracts/evm/deployments`, `npm ci` where needed;
  soroban e2e needs `STELLAR_BIN=~/.local/bin/stellar28`.
- `rtk` mangles `git diff`/`grep`/`ls` output in scripts — use `rtk proxy …` or `/usr/bin/grep`.
- Never `git commit -a` in scaas while an agent edits a spec in the main checkout (happened once: 9ad8711).
- Ruling-number ranges collided twice — reserve a range per spec before dispatching.
