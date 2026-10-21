## Session 2026-10-21 (5h part B: Task 7 done, Task 8a paused) — resume here

**State:** main has this note only (local commit, not pushed). Part B work on branch **`pqz-16k`** (worktree
`.claude/worktrees/pqz-16k`, from main `56943a36`, not pushed): Task 7 `a87795da`, fix `161121d2` (review + re-review
clean). SDD ledger with every ruling (git-ignored, on disk):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`. No agent, capped job, docker or
background shell left running.
- **Task 7 (16k parameters, owner summary `pqz-core/pqzl/params/p16k/results-16k.md`):** q = 2^50 − 42,310,535, Δ =
  2^30 − 41, n = 2560, `K_MAX` 16,384; min β 455 with proof MLWE rank 39 (rank 38 → dual_hybrid 446 / 447); encryption
  uSVP 508 / dual 499; max PQZL proof 60,882 B (txm8 G = 1) < `MAX_PROOF` 98,304; max input 309,591 B < 512 KiB;
  n = 2304 out (β 415 at 80 hints).
- **Owner checkpoint 2026-10-21 (approved):** (1) the 16k set above incl. rank 39; (2) **`ROLL_MAX` = 192** (full
  relayed tx 11,934,843 gas, 208 is over 0.75·2^24); (3) **op 7 M = 8 uses one randomness group G = 1** (dual_hybrid at
  144 hints 453.68 / 455.68 ≥ 450, thin; relayed gas ≈ 15.69 M fits 2^24, G = 2 ≈ 20.96 M does not); (4) **PQZH
  `MAX_PROOF_PQZH` raised to 320 KiB = 327,680** (every debit proof ≈ 302.7 KB).
- **Risk carried to Task 9:** G = 1 fits 2^24 relayed only while the 16k op 7 M = 8 precompile price ≤ 8.81 M (1.43×
  today); today's M = 8 relayed is already ≈ 17.0 M > 2^24 (pre-existing, fixed by 16k + G = 1).
- **Task 8 split (ruling):** 8a transcript on today's parameters (B-1 V3 / V4 from the post-`tg` hash in C generic,
  C SV, Rust generic, Rust `verify_fast` + both provers, `tg`-mutation test, review A's cheating prover
  `scratchpad/reviewA/poc/` as a committed fixture; A-2 distinct Schwartz–Zippel challenges; `R_REG`) → 8b PQZL C +
  Rust at 16k (+ txm8 G = 1 relation) → 8c PQZH Ligero over the new q → 8d `pqz-stmt`, Nethermind, Solidity (`PqzCt`,
  `ROLL_MAX` 192 re-pin, `PqzSafety`, new `UAPqzVerifier` / Env / releases), vectors, one `proofSystemId` bump,
  `gate.sh fin`. Briefs `task-8a-brief.md`, `task-8-brief.md` in the ledger dir.
- **Task 8a paused before code:** the implementer mapped every B-1 / A-2 line and designed the fixture
  (`pqzl/rust/tests/cheat_b1.rs` + test-only hooks); resume steps in `task-8a-report.md` § "Paused". Ruling: `R_REG` —
  UA-6 §9 keeps relation / statement / verifier, only the message pre-image changed (UA-6 built it) → 8a documents the
  message in `pqz-stmt`, re-pins `UAPqzVerifier.PROBE_PQZL`; PQZ vectors keep an opaque 32-byte message.
- **Metatx split:** spike on branch `metatx-lib` (`bbca6985`, worktree `.claude/worktrees/metatx-lib`, report
  `scratchpad/metatx-lib-report.md`): NoUnderlyingToken 38,351 B; A (library) token 34,588 + lib 11,577, +7–8.7k gas
  cold; B (module behind `fallback`) token 7,083, +2.7k cold; B′ 3,347. Owner 2026-10-21: size vs 24,576 is not an
  argument (wait for Glamsterdam); the real ceiling is 64 KiB — `UnderlyingPqzToken` ≈ 61 KB + governance. **Timing
  (controller ruling on the owner's ask):** after part B merges, before fs3 Tasks 12 / 6 / 13 and before governance code.

- **Spike A on `UnderlyingPqzToken` (owner ask, done `a12cd06b` on `metatx-lib`; report section in
  `scratchpad/metatx-lib-report.md`, log `smartcontracts/evm/runs/2026-10-21-metatx-lib-spike-pqz.txt`; 49 / 49 tests,
  parity prod / A / A2):** runtime 61,045 (headroom 4,491 under 65,536) → **A 56,898 (8,638)** with `SpikeMtxLib`
  11,577 → A2 (+ `SpikePqzMtxLib` 4,212) 54,321 (11,215). PQZ layer stays ≈ 12.7 KB (its auth / digest / nonce / fee are
  already in the PQZ libraries; ceiling ≈ 13.5 KB headroom). Gas cold: relayed +7.1–9.4k (A) / +13–15k (A2); relayed
  op 1 ≈ +20k / +25k (+0.5–0.66 %); warm +5.9k / +8.2k; direct calls unchanged. **Concern:** A passes the envelope data
  to the library a second time → a ≈ 340 KB op 7 would pay ≈ +1.0 M gas (computed); fix if A is chosen: keep the
  self-call in the token, pass the library only the data hash. Governance code in the shared base lands in every kind.
- **Owner question 2026-10-21 (answered in chat, recorded in TODO §0 governance item):** mint allowance per minter
  (total, per window, expiry); moderator transfer without the user's signature (bounded, public balances only, never
  confidential kinds); hybrid underlying + mint under one cap (reserve accounting: unbacked units not redeemable).

**Next:** (1) resume Task 8a (resume the ledger; dispatch a fresh implementer with `task-8a-brief.md` + the report's
"Paused" section); then 8b → 8c → 8d → Task 9 (timing only on the owner's go).

## Session 2026-10-20 (night; 5h part A merged) — resume here

**State:** main pushed (this note). **5h part A merged** (branch `pqz-state-b`, `0b499439..`; merge commit "Merge branch
'pqz-state-b'"). Gates on the branch head: forge 1325 / 0 / 9, size gate 0 (`UnderlyingPqzToken` ≈ 61 KB, all tokens
< 65,536 B), PQZ statement vectors byte-identical, docs_check 0 errors, clientkeys 107 / 0 / 2, zether-prover cargo +
wasm smoke green. **Not exercised:** `script/pqz/e2e.py` on a chain (fs3 Task 13). No agent, capped job or Codex run
left running. SDD ledger with every ruling (git-ignored, kept for part B):
`.claude/worktrees/pqz-state-b/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`.
- **Built:** T1 library split; T2 state in contract + B + TRIVIAL shield + CHAIN-01 (`ROLL_AGE` 5, `ROLL_MAX` 256);
  T3z / T3 `SHIELD_POOL` on both layers, txFee + decoyFee (op 7, sender word `d ≥ minDecoyFee`, both layers), PQZ NONE
  retired, libraries return what the debit moved (`PqzCore.Paid` / Zether `fee`); T3b `IConfidentialToken`, `mtx*`
  names, shared signature `(payload, proof, auth, beneficiary, accHint[, …])` (Zether `auth` / `accHint` empty), UA-5c
  (a) Zether UA envelope `SCAAS-ZETHER-UA-ENVELOPE-V1`, (b) one `mtxUnshield(…, uint256 amount, bytes32 recipient)`,
  `UnderlyingLib.payOutTo`; T4 e2e.py / zether-prover (32-byte recipient) / clientkeys; T5 docs + decisions.
- **Final review fixes:** `ACC_MARK` on every stored `acc` word (a shield-only rollover zeroed them → next `ROLL_MAX`
  20.9 M gas; now 12.09 M); Zether decoyFee built (owner ruling 4).
- **Owner rulings today (night):** keep the shared arg order as built (`mtxUnshield(…, amount, recipient)` vs
  `Unwrap{underlying, recipient, amount, minOut}`); **every `mtx*` write is relayable, the outer fee may be 0** —
  rollovers relayed on both layers (PQZ `mtxRollOver`, `mtxPrepareAcc`; Zether `mtxRollOver`, `mtxRollOverBatch`,
  `mtxRollOverSigned`, `mtxSetRollOverMode`; relayed `ROLL_MAX` 12.19 M gas), fee class `ABSOLUTE` kept; **`MtxRule`
  (feeClass 0 = not relayable) — owner reviews it, do not change** (TODO item).
- **Behaviour to know:** a multi transfer with no beneficiary still pays decoyFee to every leg (fee word = M·d, both
  layers); `Shielded.from` = `UA_POOL` for a UA signer; `mtxWrapShield` stays off the UA allow-list (two-step, CTR-ZTH-51).

**Next:** 5h part B (plan `docs/superpowers/plans/2026-10-20-pqz-state-redesign.md` Tasks 7–9: 16k parameters,
B-1 + A-2 + `R_REG` under one `proofSystemId`; ask the owner before any timing run), then the Codex review order in TODO.

## Session 2026-10-20 (evening; UA-6 merged, 5h part A in progress) — resume here

**State:** main pushed (this note). **UA-6 merged** `f007da31` (see the UA-6 note below). **5h part A in progress** on
branch `pqz-state-b` (worktree `.claude/worktrees/pqz-state-b`, NOT pushed), subagent-driven; ledger with every ruling:
`.claude/worktrees/pqz-state-b/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md` (git-ignored; task briefs and
reports beside it). No agent, capped job or Codex run left running.
- **Done on the branch (reviewed):** Task 1 library split `b978cf89` (`PqzStateLib` / `PqzTransferLib` / `PqzBurnLib` /
  `PqzViewLib` + internal `PqzCore`); Task 2 state + B + TRIVIAL shield + CHAIN-01 `85680d55..f4d367c4` (ROLL_MAX 256 =
  12.13 M gas, prepare-acc halves 5.76 M, **ROLL_AGE = 5** owner); Task 3z Zether `SHIELD_POOL` + kinds 6/7 dropped
  `7733910e..171d4884`, merged `f8715b65` (the pool guard lives in `ERC20MetaTx._uaMove`; layers move the pool only via
  `_poolMove`).
- **Done, NOT reviewed:** Task 3 `ff4e6948` — PQZ `SHIELD_POOL`, **txFee** (= today's `confidentialFee`) + **decoyFee**
  (op 7 only, sender-chosen payload word ≥ token `minDecoyFee`, same to every leg, check `fee == txFee + M·decoyFee`),
  fees to public UA balances, NONE mode retired, disclosure from the blob, events/views, relayed mode binding. forge
  1290 / 0 / 9, statement vectors unchanged, `UnderlyingPqzToken` 60,754 B.
- **Owner rulings today (5h):** ROLL_AGE 5 blocks; decoyFee explicit sender field (no derivation); txFee unchanged;
  **no view `fallback`** — views stay direct token functions calling the library; the 4 KiB size margin dropped (only
  the hard 65,536 B limit); UA-5c (a) confidential ops through the UA envelope + (b) unshield to a `bytes32` UA → Task
  3b; UA-5c (c)(d) → step 5c′; Zether owner ops accept a Zether UA only (in UA-6).

**Next (order):** (1) review Task 3 (opus) → fix loop; (2) **Task 3b**: shared `IConfidentialToken`, `mtx*` rename
(`mtxShield`, `mtxConfidentialTransfer…`, `mtxUnshield`, …), one selector per shared function with an `auth` argument
(PQZ signer signature; Zether must be empty), UA-5c (a)(b) on both layers; (3) Task 4 clients / tools / vectors (incl.
`script/pqz/e2e.py`, broken since Task 2/3); (4) Task 5 spec + decisions (incl. D18–D24, the T2 deviations: pending slot
byte offsets, floor raised with cleared, prepare-acc refusals; §5.6 race wording; `_poolMove` trust boundary); (5) Task 6
final review → owner approval → merge. Then 5h part B (16k regen) and the agreed review order in TODO ("Review order with
Codex": Codex + agy run 1 on pqz-core after the 16k regen).

## Session 2026-10-20 (reviews done, Z1 merged; UA / shield redesign decided) — resume here

**State:** main pushed (this note). Two WIP branches stopped for the shutdown (not merged, not pushed). No agent, capped job
or Codex run is left running.
- **Reviews of round 2 done:** review A (Task 10, PQZL Rust, `W-review-a-pqzl-rust.md`), review B (Task 11, `X-review-b-transcript.md`),
  Codex T2 on-chain re-run (`T2-codex-chain.md`, no new P0/P1). **P0 B-1 = A-1 CONFIRMED by a cheating prover** (V3/V4
  drawn from `hash0` before `tg`: z3/z4 errors cancelled through g are accepted by Rust `verify` and `verify_fast` on all
  14 codes). **Owner: keep the fold-in** — the fix (V3/V4 from the post-`tg` hash) ships with the K_MAX 16k parameter
  regeneration, one `proofSystemId` bump (CTR-PQZ-09); A-2 (β4 / υ share a challenge) renumbered in the same bump. The
  cheating-prover harness stays in `scratchpad/reviewA/poc/` (git-ignored) until the fix lands, then becomes the
  regression fixture. lazer#28 comment draft updated with B-1 (`scratchpad/lazer28-comment-draft.md`; post only after
  owner approval, also the D-2/D-3 issue draft).
- **5g-Z Z1 merged** `77f7478` (canonical Zether / PQZ verifiers pinned by `OpenFactory`, split transfer / burn /
  inner-product verifiers, deprecated versions refused, `isRegisteredToken`; review APPROVE + fixes m1–m8, o1, o4);
  full forge 1323 pass / 0 fail / 14 skip. The SCaaS testnet needs a redeploy with the new factory (Task 13).
- **Owner rulings today (all in decisions.md):** CTR-PQZ-06 `plainPending` removed (fees straight to the recipients'
  public UA balances; `pqzShield` = a proven debit funded by the signer's public balance moved to the pool, one
  call into `acc`; no shielding into another account); CTR-PQZ-15 / CTR-ZTH-51 **`SHIELD_POOL` sentinel
  instead of burn** for PQZ and Zether (shield / unshield / fees are transfers from / to the pool; `totalSupply()` stays
  the true total); **CTR-UA-30** (research `docs/research/ua-identity.md`): a UA is one signature-verifying entity, ids
  unchanged; classical Zether option (A) — the Zether key is itself the UA, "self" mode kept; a PQZ key is an attribute
  of a PQ-signing UA only (ML-DSA or PQ-dominant msig), supplied in `register`, immutable, one UA per key; `pqz-mlwe` kind
  and `authRef` go. Also answered (no change): EIP-7976 calldata floor (64 gas/byte) — keep it off on 22776 unless the
  tx gas cap rises; PQZ state is per (UA, token), blobs per token, pk per UA.

**WIP branches (resume each in its worktree):**
- `rev2-zether-z2` head `fd672de9`, worktree `.claude/worktrees/rev2-zether-z2`: Z2 (generic `Env`, `deployImplementation`,
  `initialize(creator, version, initArgs)`, release hashes, `usableFrom`); `forge build src` OK, **test tree does not
  compile yet**; resume notes `smartcontracts/evm/runs/2026-10-20-5gz2-wip.txt`. Owner questions, answered 2026-10-20 (chat):
  notice period defaults (10 min on the SCaaS testnet, 3 days on 22776) — **OK**; `initialize` without Env — **answered**: keep the split explicit — the implementation carries what never changes for it
  (Env: verifier addresses, registry, chain, libraries; fixed in its constructor), the contract instance carries its own
  configuration from `initArgs` (e.g. a wrapped USDC → VND token at 1 : 25,000 and a USDC → RUB token at another rate;
  mint / burn / blacklist / … allowed or not), and both feed the governance matrix below; `deployImplementation` binds the kind's latest Env — **No**, to be discussed
  together with smart-contract governance and token governance; library pins = registrar list checked by code hash, not
  compared with the init code's link references — **OK**.
- `rev2-small-fixes` head `8c7c00f2`, worktree `.claude/worktrees/rev2-small-fixes`: CHAIN-02 (first-activation future
  guard, `--check` ok) and CHAIN-03 (`Math.mulDiv`, 3 tests at 2^250; full forge 1326 / 0 / 14; size baseline raised,
  `UnderlyingPqzToken` 60,352 B) done; **A-3 (Rust secret wiping) WIP `aee749df`**: finish with
  `scripts/capped sh pqz-core/pqzl/rust/run.sh a3` (proof bytes must be unchanged), then mark A-3 fixed and drop the
  WIP prefix. Expect a `size-baseline.json` conflict with Z2.

**Next (order):** (1) `rev2-small-fixes` **merged 2026-10-20** `1003b871` (A-3 + review fixes, proof bytes unchanged; CHAIN-02 / -03; merge fixes: Dex test API, size baseline, DEX KAT regenerated); (2) Z2 **merged
2026-10-20** (review APPROVE-WITH-FIXES, fixes applied; forge 1330 / 0 / 14; notice period 3 days minimum on every mainnet, owner); (3) **UA-6** spec + plan from CTR-UA-30 (registry: PQZ key
in `register` for PQ signers, `keyOwner` uniqueness, `pqz-mlwe` kind / `authRef` removed, `R_REG` message bound to the
UA id; Zether stays a key-UA) — before 5h; (4) **5h** (PQZ state in contract, ordered rollovers, ROLL_AGE 24, per-credit
fee to public balances, `plainPending` removed, `SHIELD_POOL` for PQZ and Zether, CHAIN-01 all-zero `u` refused) then the
**16k parameter regeneration** with B-1 + A-2 + the R_REG change under one new `proofSystemId`, plus the 16k
measurements; (5) Task 12 gate fin → Task 6 package → Task 13 SCaaS testnet reset (image `pqz4`; ask the owner before timing)
→ Task 14 wasm32 limb path. Leftover worktrees: `rev2-zether-canon` (merged; removable), `rev4` (Codex T2, read-only;
removable).

**Later the same day (owner chat, 2026-10-20):** done — HANDOFF / TODO compacted, finished work moved verbatim to
`COMPLETED.md`; README §6 rewritten with the owner's UA definition (a UA is the actor that signs and answers for a write
to a contract, tokens included; recorded under CTR-UA-30). Owner later: Otterscan **dropped** (not needed); Zether `authRef` **removed entirely** (decisions CTR-UA-30). Were open: (a) **Otterscan on the SCaaS testnet** — not
possible on Nethermind 1.39 (no `ots_` / `erigon_` RPC, NethermindEth/nethermind#11990; node container stopped, nothing
changed): Blockscout from the commented stack in `/home/dockers/mba-chain-nethermind/docker-compose.yml` (recommended,
≈ 1.5–3 GB, pin tags, `mem_limit`, ports 22776+) or an own `ots_` shim; (b) Z2 `initialize` without Env (answered: implementation / instance split); (c) Zether
`authRef` (decided: removed); still open (d) the four transfer flows and shielding into another account (decided: all four on both layers, shield proof-free; names `mtxShield` / `mtxUnshield`, built in 5h; decisions CTR-PQZ-06, CTR-ZTH-45), proof-free
`pqzShield` (trivial pending entry folded by the permissionless rollover) into 5h — analysis
`docs/research/shield-and-key-reuse.md`.

Older session notes (2026-10-06 … 2026-10-19) are archived verbatim in [COMPLETED.md](COMPLETED.md#from-handoffmd).

**Plans merged (2026-10-20, late):** UA-6 spec + plan and the updated 5h spec + plan are on main with the owner's
plan-review rulings at the top of each plan (q = 2^50 − 42,310,535; third-party shield free; `mtx*` names incl.
`mtxConfidentialTransfer…`; fees `txFee` + `decoyFee` with token `minDecoyFee` ≥ 0 and sender-chosen `d`, op 7 only;
Zether signs every write; bn254 Zether to `legacy/` inside UA-6). **Next: UA-6 code (plan Task 1 onward), then 5h.**

**Review order agreed (owner 2026-10-20):** UA-6 → 5h part A (contracts) → 5h part B (16k regen in pqz-core) → **Codex
run 1 on pqz-core Rust + C** → fixes, fuzz, gate, freeze → **Codex run 2 on contracts** → fs3 Task 13 (TODO "Review
order with Codex"). UA-6 in progress on branch `ua6` (worktree `.claude/worktrees/ua6`; SDD ledger
`.superpowers/sdd/2026-10-20-ua6-encryption-key-attributes/progress.md` there): Tasks 1, 2, 5 done and merged into
`ua6`; Task 4 (Zether, bn254 to legacy) running in `.claude/worktrees/ua6-t4`.

**UA-6 merged (2026-10-20, late):** branch `ua6` (Tasks 1–9 + final review fix wave + the owner's Zether owner-op
kind check `4ce03f50`), subagent-driven with a reviewer per task and a whole-branch review (no on-chain authorization
hole found). Gates on the merged tree: forge 1243 / 0 / 9, size gate 0, docs_check 0; clientkeys 107 / 0 / 2,
zether-prover, ua-rs, ua-c, ua-cxx, ua-qt (Qt 6.12 at `~/usr/Qt/6.12.0/gcc_64`), ua-dart-frb, ua-py, ua-go, ua-cs,
ua-dart green. Not yet exercised: `script/pqz/e2e.py` on a PQZ chain and a real `R_REG` proof in evm tests (fs3 Task 13
/ 16k regen). Every controller ruling is in decisions.md under CTR-UA-30 with commits. **Next: 5h part A** (plan
`docs/superpowers/plans/2026-10-20-pqz-state-redesign.md`, owner rulings at its top).
