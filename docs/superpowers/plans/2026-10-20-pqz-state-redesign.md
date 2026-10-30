# PQZ state and credit-cap redesign (plan Task 5h): implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (one implementer and one reviewer per task). Steps use checkbox (`- [ ]`) syntax.

**Status:** plan (designer for plan Task 5h, 2026-10-20). The owner ruled O1–O9 on the first version (CTR-PQZ-07
Change 2026-10-20); **updated 2026-10-20 (later the same day)** to the owner's further rulings (tags below, each changed
row names its source). Waiting for the owner's answers to Q1–Q3 (end of this plan). Nothing here is built.

**Base:** `main` at `c173de37` (5g-Z1 `77f7478` and 5g-Z2 merged). **Dependencies:** **UA-6** (registry rework from
CTR-UA-30; spec and plan written separately) merges **before** this plan's branches start; task **Z-BLS** (Zether bn254
line to `legacy/`, D22) merges before Task 3b.

**Update tags** (spec "Update 2026-10-20"): **[16k]** CTR-PQZ-06 Change `K_MAX = 16,384`; **[noPP]** CTR-PQZ-06 Change
`plainPending` removed; **[4flows]** CTR-PQZ-06 Change "all four transfer flows, shield without a proof"; **[pool]**
CTR-PQZ-15 / CTR-ZTH-51 Change `SHIELD_POOL`; **[mtx]** CTR-ZTH-45 Change `mtxShield` / `mtxUnshield`; **[kinds]**
CTR-TOK-21 Change kinds 6, 7 dropped; **[bls]** CTR-ZTH-32 Change Zether BLS12-381 only; **[ua]** CTR-UA-30 and its
Changes (UA-6); **[id]** CTR-PQZ-09 Change (B-1 / A-2 fold-in, one bump); **[Z2]** 5g-Z2 merged.

**Goal.** The owner rulings of 2026-10-19 and 2026-10-20 (decisions CTR-PQZ-06, -07, -08, -09, -15, CTR-ZTH-32, -45,
-51, CTR-TOK-21, CTR-UA-30; plan [`2026-10-19-pqzl-fs3.md`](2026-10-19-pqzl-fs3.md) Task 5h):
1. ciphertexts in contract state (not only hashes), so they survive EIP-4444 history expiry;
2. **B**: credits are never refused, the pending queue is unbounded, rollovers go strictly in order and never lose or
   skip an entry, a rollover stops before `acc` exceeds the cap, the owner's refresh resets it;
3. `ROLL_MAX` raised to the largest batch under 2^24 gas with ≈ 25 % margin;
4. **[16k]** larger lattice parameters: n = 2560, q ≈ 2^50, `K_MAX = 16,384`, with B-1, A-2 and UA-6's `R_REG` message
   under **one** new `proofSystemId` for PQZL and PQZH [id];
5. **[4flows] [noPP]** all four flows on both layers; a shield needs no proof on either layer; `plainPending` removed,
   `plainUsed` → `shieldIn`, fees to public UA balances;
6. **[pool]** `SHIELD_POOL` instead of burn / mint on both layers; **[mtx]** one `mtx*` interface for both layers;
   **[kinds]** kinds 6 and 7 dropped.
Order: B, the state layout and items 5–6 first (today's parameters, no relation change), then the 16k regeneration.

**Spec:** [`docs/superpowers/specs/2026-10-20-pqz-state-redesign.md`](../specs/2026-10-20-pqz-state-redesign.md)
(options with numbers, the recommendation, risks, rulings O1–O9, owner questions Q1–Q3). Normative text after the
review: `docs/contracts/pq-zero-knowledge.md` §4.1, §4.3, §4.4, §7.1, §7.3–§7.8, CTR-PQZ-06, -07, -08, -15, threats
T7, T8, T22, T23; `docs/contracts/zether.md` CTR-ZTH-45, -51; `docs/contracts/token-wrappers.md` kind table.

## Owner rulings on this plan (2026-10-20, plan review) — these override the rows below

1. **Q1 — modulus:** q = **2^50 − 42,310,535** (prime; q − 1 = 2^3·19·43·431·5659·70627, so the Ligero subgroup of
   today's PQZH exists), Δ = 2^30 − 41; replaces 2^50 − 71 everywhere in this plan and the spec. PQZL and PQZH share q.
2. **Q2 — third-party shield:** free (gas only); no per-credit / decoy fee on any shield; tx fee only when relayed.
3. **Q3 — names:** the `mtx*` table (D20) approved, confidential transfers are **`mtxConfidentialTransfer…`** (not
   `mtxZKTransfer`; wallets may label it "Secure Transfer"); one selector per shared function across both layers.
4. **Fees (supersedes D10's per-credit fee and O4's floor):** two fees. **`txFee`** (today `confidentialFee`): per
   transaction, any op, to the beneficiary. **`decoyFee`** (today `multiLegFee`): **op 7 only** (op 1 has no decoys and
   never pays it), the same amount to **every** leg, real recipient included (uniform, so it reveals no decoy); the
   token sets an immutable **`minDecoyFee`** at `initialize` (may be 0); the **sender chooses the per-leg amount
   `d ≥ minDecoyFee`** (public, in the payload, bound by the statement: `fee = txFee + M·d`). No chain-level floor.
   Both layers (Zether may now set a non-zero `minDecoyFee`; default 0).
5. **bn254 Zether to `legacy/`:** done in **UA-6** (its U10), not in a separate Z-BLS task: drop D22's Z-BLS task and
   the bn254 steps from Task 3b; 5h assumes BLS12-381-only Zether.

## Global constraints

- Heavy jobs under `scripts/capped` (forge, cargo `-j2`, the Sage image); Docker always with `--memory`; never poll; stop
  every background shell before reporting.
- No merge, no push by implementers; the controller merges after the owner's approval.
- Decisions into `docs/decisions.md` in full (content + status), "controller proposal, owner may override".
- Timing measurements (precompile calibration, verify p99) only with the owner's go-ahead; forge gas tests are fine.
- `scripts/size_gate.py` for every contract whose bytecode changes; every PQZ token implementation stays at least
  **4 KiB under** the 65,536-byte test-chain limit (D14).
- All chains are test-only: no migration or compatibility path for renamed entry points, removed kinds or ids.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions (O1–O9 ruled; the rest controller proposals, the owner may override)

Numbers: the spec, measured by `smartcontracts/evm/test/research/PqzStateGas.t.sol`
(`smartcontracts/evm/runs/2026-10-20-5h-state-gas.txt`) and `pqz-core/pqzl/params/aprime/`; 16k figures are
interpolations marked [estimate] until Task 7 measures them.

| # | Decision | Proposal | Why |
|---|---|---|---|
| D1 | Where ciphertexts live | One SSTORE2 **op blob** per debit operation: transfers `salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ UA_j)_{j<M} ‖ v_f` (= today's bundle `R` plus `v_f`), burn / refresh `u' ‖ v_f`. Written once, never deleted. | One shared `u` per operation (CTR-PQZ-04) stored once; 200 gas per byte; reads are ≈ 4 k gas per 16 KB (EXTCODECOPY). Slots cost 11.4 M per ciphertext (rejected), one SSTORE2 per credit repeats `u` M times (rejected). |
| D2 | A pending entry | **One slot** `blob(160) ‖ g(8) ‖ G(8) ‖ j(8) ‖ block(64)` in `pending[ua][i]`; `pendingHash` removed. **Changed 2026-10-20 [4flows]:** `blob = 0` marks a TRIVIAL entry whose amount sits in the low 64 bits of the blob field (D18). | The bytes are in the blob; 22.1 k per credit instead of keccak + slot; the block feeds D6. |
| D3 | `acc` | After a debit: a **reference** to the debit's blob (`u_0`, `v_f`), one slot. After a rollover: **materialised** in `CT/32` slots (516; **644 under 16k** [16k]; 708 under the superseded A'), overwritten in place (5 k per slot), plus `accHash` for D5. The slots are never zeroed. | A debit costs no `acc` write; rollovers overwrite instead of growing state. The first materialisation of an account is zero → non-zero (22.1 k per slot): D8. |
| D4 | Debit effects | `acc` = the fresh reference, `accUnits = 1`, **`rolled = floor = p`** (a debit with `p < rolled` un-rolls `[p, rolled)`: those entries — credits and TRIVIAL entries — are pending again and will be rolled again; nothing lost, nothing skipped); the dead pending slots `[cleared, p)` deleted (≤ 2·`INLINE_MAX`). | Every debit leaves a fresh, unmaterialised `acc`; one rule for both cases. |
| D5 | How a debit gets `acc` and `inline` | The contract reads them from state (`inline` from the blobs; a TRIVIAL entry is `Trivial(digits(amount))`). Optional calldata **hint**: the materialised `acc`, used when `keccak == accHash`, else ignored. The `acc` / `inline` arguments of every debit entry point are replaced by `bytes accHint`. | A stale hint never reverts; the hint saves the cold SLOADs (≈ 1.1 M today) of a materialised `acc`. |
| D6 | Race-freedom without W-E's base | **Remove** `baseHash` / `baseRolled` / `baseUnits` and the base branch of `_total`. **`ROLL_AGE = 24` blocks, enforced** (O6 ruled): a rollover may roll entry `i` only if `block.number ≥ block_i + ROLL_AGE` (TRIVIAL entries too). After `ROLL_AGE`, `p ≥ rolled − INLINE_MAX` is still accepted (D4). | With `acc` in state no calldata can go stale; the only race left needs young entries. |
| D7 | B: credits | No `RefreshRequired` on a credit (op 1 and op 7) or a shield; `pendingCount` uint64, unbounded. | Owner ruling B. |
| D8 | B: rollover | `mtxRollOver(ua, n)` (was `pqzRollOver`, [mtx]): anyone; strictly `[rolled, rolled + n')` with `n' = min(n, K_MAX − 1 − accUnits)`, `CapReached(ua)` when `n' = 0`, `RollTooYoung` per D6; `n ≤ ROLL_MAX`; `AccNotPrepared` until `mtxPrepareAcc(ua, half)` (permissionless, idempotent, ≈ 5.7 M per half today, **≈ 7.1 M under 16k**) wrote both halves; deletes the pending slots below `rolled − INLINE_MAX`. Pinned by gas tests: **today's parameters `ROLL_MAX = 256`** (12.11 M, 72.2 % of 2^24). **Changed 2026-10-20 [16k]:** under 16k ≈ 3.47 M + 43.2 k per entry, **`ROLL_MAX` ≈ 208** [estimate], measured in Task 7, pinned in Task 8 (supersedes A' 176 of O9). A TRIVIAL entry ≈ 9 k [estimate]. | Ordered, never skipping, stops at the cap; the first materialisation (11.4 M; 16k ≈ 14.2 M) cannot share a transaction with a batch. |
| D9 | Units | `accUnits` uint32; `unitsOf(T) = accUnits + (p − rolled) + 1 ≤ K_MAX` stays the debit check (a TRIVIAL entry counts one). **Changed [16k]:** `K_MAX = 16,384` would fit uint16; uint32 kept (free in the packed slot). | Review carry-over. |
| D10 | Credit fee (decoy flood) | `ConfidentialConfig.multiLegFee` becomes the **per-credit fee** of both transfer paths (op 1 too: `fee = confidentialFee + creditFee`). **Changed 2026-10-20 [noPP] [pool]:** paid out of `SHIELD_POOL` to every credited UA's **public UA-ledger balance** (not `plainPending`). On the SCaaS chains (`PqzSafety.requireAllowedChain`) `initialize` refuses an amount below the floor (O4 ruled: ≥ the state cost of one pending slot, ≈ 26.3 k gas at the chain's gas price, per chain profile). Field name kept, so the Zether kinds still refuse non-zero. **Third-party shields (Q2, proposal):** a shield whose `toUA` is not the signer's UA pays the same fee from the signer's public balance straight to `toUA`'s public balance; self-shields free. | The sender pays the recipient for the state and rollover work it causes; the same for every leg (reveals nothing). |
| D11 | Storage modes | **Changed 2026-10-20 (O5 ruled): NONE retired** for PQZ (`pqzTransferNoBundle`, `pqzTransferSingleNoBundle` removed). BUNDLE: `entryPtr[ref]` = the op blob (no second SSTORE2); COMPACT (HASH): the blob plus the memo (the hash of `R` dropped). Disclosure reads `R` out of the blob. W-A bindings of the two kept modes unchanged. | The blob is `R`; NONE no longer saves anything. |
| D12 | Events | Pointers instead of bytes, under the shared names of D20 [mtx]: `ConfidentialTransfer(…, blob)`, `ConfidentialTransferMulti(…, blob)`, `Unshielded(ua, amount, recipient, blob)`, `Shielded(toUA, from, amount, index)`, `Credited`, new `Debited(ua, rolled, floor, blob)` (review N4), `RolledOver(ua, rolled, accUnits, accHash)`. `PqzPlainCredit` removed [noPP]. | The bytes are in state; logs cost 8 gas per byte (≈ 134 k per transfer). |
| D13 | Views | `pqzAccount(ua)` (counters, `accUnits`, flags, `sendCounter`, the `acc` blob; **`plainPending` removed** [noPP]), `pqzAcc(ua)`, `pqzPending(ua, i)` (credit or TRIVIAL fields), `pqzPendingCt(ua, i)`, `pqzEntryBlob(entryRef)`. Names unchanged (CTR-ZTH-45 is about entry points). | Wallets restore from state alone (owner ruling); review N4. |
| D14 | Library split (controller 2026-10-20) | `PqzLib` splits into four DELEGATECALL libraries in the same ERC-7201 namespace: **`PqzStateLib`** (init, shield, entry append, rollover, views), **`PqzTransferLib`** (op 1, op 7), **`PqzBurnLib`** (burn, refresh, unwrap), **`PqzViewLib`** (statement views, disclosure); shared internals in an internal library compiled into each. **Changed [Z2]:** the four are the release's `Env.libs` (code hashes checked by `deployImplementation`). **Changed (size):** after Z2 `WrappedPqzToken` is 60,621 B (819 B under the 4 KiB target), so the view `fallback` (spec §8) is part of Task 1 unless the split alone restores the margin. Every library < 24,576 B. | Room for the 5h logic; per-call code loads only what the call needs. |
| D15 | Relayed mode binding (review L1, T18) | Fold the transfer mode into every binding: relayed `binding = keccak256(abi.encode(envelopeBinding, uint8(mode)))`; the unwrap leg / `minOut` likewise. | Done with the API change of D5 and the rename of D20 (one client break). |
| D16 | Parameters | **Changed 2026-10-20 [16k] (supersedes A' n = 2816 / q = 2^54 − 327 and O2):** **n = 2560 (k = 40), q ≈ 2^50 (ruled 2^50 − 71; Q1 proposes 2^50 − 42,310,535, D25), Δ = ⌊q / 2^20⌋ ≈ 2^30, β_s = 40, β_e = 182, `K_MAX = 16,384`, `e_T ∈ [−2^28, 2^28)`, `M_i < 2^18`, carries 15 bits** (R_TX ≈ 1,105 bits, 18 binary polys [estimate]). Encryption β 508 / 497.3 / 482.4 at 0 / 32 / 80 hints (≥ 450; the β 446 exception lapses), mint margin 3.36×, keys / ciphertexts +25 %. **To measure (Task 7):** LaZer codegen proof sizes (with the proof MLWE rank re-tuned to dual_hybrid ≥ 450), rollover gas and `ROLL_MAX`, op 7 M = 8 under 2^24 (G = 1 at 144 hints ≈ 462 extrapolated, else M ≤ 4), n = 2304 at 80 hints (an owner checkpoint if it clears 450, not assumed). | Owner ruling: refresh about every 16k units instead of 65k, for +25 % instead of +37.5 % sizes. |
| D17 | Order | **Changed 2026-10-20:** B + state + shield / pool / names / kinds (Tasks 1–6) on today's parameters and ids, reviewed and merged; **then the 16k regeneration** with B-1, A-2 and `R_REG` as one id bump (Tasks 7–9); then plan fs3 Task 12 (final gate), Task 6 (package) and Task 13 (SCaaS testnet reset, gas). | Owner: "B and the state layout first"; B changes no relation, 16k changes every relation, B-1 / A-2 / `R_REG` change the transcript and `R_REG`: one bump (CTR-PQZ-09). |
| D18 | Proof-free shield, its ordered position [4flows] | `mtxShield(toUA, amount)`: anyone, any registered UA, no proof. Public units signer → `SHIELD_POOL`; a **TRIVIAL entry** `(amount, block)` appended to `pending[toUA]`, or **merged** into the tail entry when it is TRIVIAL, of the current block and still pending (index `≥ max(floor, rolled)`). Rollovers and debits add each TRIVIAL entry as its own `Trivial(digits(amount))` (one unit, zero noise). `shieldIn` (was `plainUsed`) = the same-call top-up from the signer's public balance, as one `Trivial(digits(shieldIn))` term (relation unchanged). Wrap-shield mints to `SHIELD_POOL` and writes the same entry. | Ordered like a credit, so D4 / D6 cover it: an un-roll keeps the amount; a merge only touches an entry of the current block, which no in-flight debit (proven on an earlier block) can have inlined. A separate integer accumulator would break D4's exact rebuild; folding a run as one normalised term would break the un-roll's exact subtraction (spec §5.9). |
| D19 | `SHIELD_POOL`, both layers [pool] [noPP] | `SHIELD_POOL = address(uint160(uint256(keccak256("scaas.shield.pool.v1"))))`, not payable, cannot spend. Shield: transfer to the pool; wrap-shield: mint to the pool; unshield: transfer from the pool; unshield-unwrap: burn from the pool, then the leg pays; every fee from a hidden balance (PQZ beneficiary and per-credit fees; **Zether's beneficiary fee too**, which today is `pend_ben += [fee]G`) moves from the pool to the recipient's public balance. Invariants: `totalSupply()` unchanged by shield / unshield / fees, `Σ balanceOf == totalSupply`, `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`, `reserve ≥ totalSupply()`. | Owner ruling; relations unchanged. |
| D20 | One interface, `mtx*` names [mtx] | The old → new table of spec §5.11 (proposal, Q3): `mtxShield`, `mtxWrapShield`, `mtxConfidentialTransfer` / `…Compact` / `…NoBundle` (Zether only) / `…Single` / `…SingleCompact` (PQZ only), `mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver(ua, n)`, Zether-only `mtxRollOverBatch` / `mtxRollOverSigned` / `mtxSetRollOverMode`, PQZ-only `mtxPrepareAcc`; events `Shielded`, `ConfidentialTransfer(Multi)`, `Unshielded`, `RolledOver`, `Credited`, `Debited`. Shared functions keep one selector across layers in `IConfidentialToken` (proof-taking: `(payload, proof, authSig, beneficiary, accHint[, …])`; PQZ requires `beneficiary` = the payload's, Zether an empty `accHint`). Relay allow-lists follow; rollovers stay off them. | `mtxTransfer` is taken (public meta-transfer); one selector per function lets one client and one relayer serve both layers. |
| D21 | Kinds 6 and 7 dropped [kinds] | `NORMAL_ZETHER_PQZ` / `WRAPPED_ZETHER_PQZ` removed from `IOpenFactory.TokenKind`; ids not reused; the four `KindReserved` checks and the error go (the ABI decoder rejects 6, 7). | Owner ruling; no layer argument needed (D20). |
| D22 | Zether bn254 to `legacy/` [bls] | **A separate task "Z-BLS", not in 5h** (controller proposal): the bn254 Zether verifier instances, `proofSystemId` `…/bn254/…`, deploy steps and `Env` publication, vectors and bn254 suites move to `legacy/`; the prover builds and tests BLS12-381 only. After UA-6 (which removes UA kind `zether-bn254` 0x0140 and its Schnorr verifier), before Task 3b. | Independent of the PQZ state work, reviewable alone, can run beside Tasks 1–3; Task 3b then renames only the BLS line. |
| D23 | One `proofSystemId` bump [id] | 16k parameters + **B-1** (V3 / V4 from the post-`tg` hash, all four implementations and both provers, `tg`-mutation test, review A's cheating prover as the regression fixture) + **A-2** (β4 / υ challenges renumbered) + **`R_REG` bound to the UA id** (message from UA-6) under PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k40-q50l4/v4")` and a PQZH Ligero v2 id; a new `UAPqzVerifier`, a new `Env` version and new PQZ releases [Z2]. | Owner: fold B-1 into the 16k regeneration, nothing deploys v3 meanwhile (the SCaaS testnet stays on v2 until fs3 Task 13). |
| D24 | All-zero `u` (Codex T2 CHAIN-01) | Refuse an operation whose shared `u` (any `u_g`, or a burn's `u'`) is all zero; TRIVIAL entries are contract-made and exempt. | An all-zero credit leaves `acc` unchanged while `rolled` advances (fs3 plan carry-over). |
| D25 | q for PQZH | **Q1 (owner):** q = 2^50 − 71 has no Ligero FFT domain (q − 1 = 2^3 · 17 · 8,278,675,785,607); proposal q = **2^50 − 42,310,535** (q − 1 divisible by 2^3 · 19 · 43 · 431, Δ = 2^30 − 41, every check of spec §6.1 holds). | PQZL and PQZH share q; spec §6.5. |

## Review Focus (inputs most likely to bite)

1. **Un-roll (D4) and deletion (D8) together.** A debit with `p < rolled` needs `pending[p .. rolled)`; rollovers delete only
   below `rolled − INLINE_MAX`, and `p ≥ rolled − INLINE_MAX`. A test must debit at exactly `p = rolled − INLINE_MAX`
   right after a rollover of `ROLL_MAX` entries, with TRIVIAL entries inside the un-rolled range.
2. **The hint (D5) must never decide `T`.** Only `keccak(hint) == accHash` with the materialised flag set selects it;
   every other case reads state. Test a stale hint (a rollover in between) and a hint on a fresh `acc`.
3. **`ROLL_AGE` vs the owner's own debit.** Debits may include young entries inline; only rollovers are age-gated.
4. **The cap clamp.** `n' = min(n, K_MAX − 1 − accUnits)`; a rollover at the cap reverts `CapReached`; the debit's
   `unitsOf(T)` check stays (defence in depth).
5. **Lane overflow.** 64-bit lanes hold `2^64 / q` terms (2^22 today, 2^14 under 16k): `ROLL_MAX + 1 + INLINE_MAX` stays
   below (asserted by a test with every coefficient at `q − 1`).
6. **First materialisation gas.** `mtxPrepareAcc` halves stay under `0.75 · 2^24` (16k too); a rollover before both
   halves reverts; the `ROLL_MAX` gas test runs on a prepared account with every entry from a distinct cold blob, in a
   transaction of its own (forge: fill in `setUp`, as `PqzStateSteadyGasTest*`; a slot rewritten twice in one test
   is "dirty" and understates by 2,800).
7. **Disclosure reads `R` from the blob.** `R` = the blob minus the trailing `v_f`; `ciphertextHash` / the bundle shape
   rules stay byte-identical with today's `R` (vectors `statement_*` unchanged).
8. **Size gate.** D14 before the logic (Task 1), so later tasks see real headroom; the view `fallback` must not route a
   state-changing selector.
9. **TRIVIAL entries (D18).** Merge only into a still-pending TRIVIAL tail of the *current* block (never into one a
   same-block debit already spent); a debit proven before a shield
   (same block or earlier) settles; a third-party shield between prove and submit never changes the debit's `T`; a
   rollover adds `Trivial(digits(a))` per entry, so `T` is exact for `p < rolled` with TRIVIAL entries on both sides of
   `p`; `unitsOf` counts each one; `mtxWrapShield` writes the same entry and mints to the pool.
10. **`SHIELD_POOL` (D19) on both layers.** A forge invariant per layer: `totalSupply` constant under shield / unshield /
    fees, `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`, `reserve ≥ totalSupply()`; the pool cannot be a
    payee or spender; the Zether beneficiary fee lands in the public balance and no longer in `pend_ben`.
11. **Rename completeness (D20, D21).** No `zether*` / `pqz*` entry point or event left in `src/`, clients, scripts or
    the e2e flows; `mtxSelectors` allow-lists list the new selectors and still exclude rollovers; one selector per
    shared function across both layers; kinds 6 / 7 fail ABI decoding.
12. **CHAIN-01 (D24)** on every op form (op 1, op 7 per group, burn, refresh).
13. **The id bump (D23, Task 8).** B-1's `tg`-mutation test and review A's cheating prover rejected by all four
    verifiers; A-2's distinct challenges; `R_REG` bound to the UA id against UA-6's vectors; the q of D25 has the
    Ligero domains and passes every budget check of spec §6.1.

## Tasks

| Task | What | Depends on | Estimate |
|---|---|---|---|
| 0 | rulings, decisions, worktree | UA-6 merged | S (controller) |
| 1 | library split, view `fallback` if needed | 0 | S–M, 1 session |
| 2 | state layout, B, TRIVIAL shield, CHAIN-01 | 1 | L, 2–3 sessions |
| 3 | PQZ fees, `SHIELD_POOL`, events, views, bindings, NONE retired | 2 | M, 1–2 sessions |
| 3b | Zether side, shared interface, `mtx*` rename, kinds | 3, Z-BLS merged | M–L, 2 sessions |
| 4 | clients, tools, vectors (both layers) | 3b | M, 1–2 sessions |
| 5 | spec and decisions | 4 | M, 1 session |
| 6 | review and merge of the first half | 5 | M |
| 7 | 16k parameters and measurements | 6, Q1 | M, 1–2 sessions + Sage / estimator compute |
| 8 | 16k + B-1 + A-2 + `R_REG` in cores, PQZH, codec, contracts; one id bump | 7 | L, 3–4 sessions |
| 9 | review, calibration, roll-out | 8, owner timing window | M |

(Estimates are agent sessions of the size of the 5g / Z2 tasks; S < half a session.)

### Task 0: Owner review and rulings
- [x] The owner ruled O1–O9 (CTR-PQZ-07 Change 2026-10-20); O2 and O9's A' figures superseded by [16k].
- [ ] The owner answers Q1–Q3 (end of this plan).
- [ ] Record D1–D25 as updated in `docs/decisions.md` (Change lines under CTR-PQZ-06, -07, -08, -09, -15, CTR-ZTH-45,
  -51, CTR-TOK-21, CTR-ZTH-32; D14 under CTR-PQZ-07 or a new CTR id per the docs rules).
- [ ] Worktree `pqz-state-b` from main after UA-6.

### Task 1: Library split, no behaviour change (D14)
**Files:** `smartcontracts/evm/src/pqz/PqzLib.sol` → `PqzStateLib.sol`, `PqzTransferLib.sol`, `PqzBurnLib.sol`,
`PqzViewLib.sol`, `PqzCore.sol` (internal); `PqzLayer.sol`, `NormalPqzToken.sol`, `WrappedPqzToken.sol`;
`test/pqz/helpers/PqzFixture.sol` and the suites (linking); `script/pqz/e2e.py` (the PQZ deploy path: four
libraries in `Env.libs` with their code hashes, `publishEnv`, `deployImplementation`); `size-baseline.json`.
- [ ] Move the public functions per D14; the shared private steps become `internal` in `PqzCore`.
- [ ] Every existing PQZ forge suite green with no test change other than linking; statement views byte-identical
  (`test_transferStatementMatchesVector`).
- [ ] `forge build --sizes` + `scripts/size_gate.py`: tokens ≥ 4 KiB under 65,536 B, libraries < 24,576 B; if not, the
  view `fallback` (spec §8) in the same task. Log `smartcontracts/evm/runs/<date>-5h-split-sizes.txt`. Commit.

### Task 2: State layout, B and the proof-free shield (D1–D9, D18, D24)
**Files:** `PqzStateLib.sol`, `PqzTransferLib.sol`, `PqzBurnLib.sol`, `PqzCore.sol`, `PqzCt.sol` (`loadBlob`, lane add
from memory, `addTrivial` per entry), `IPqzToken.sol` (errors `CapReached`, `RollTooYoung`, `AccNotPrepared`,
`ZeroU`; `RefreshRequired`, `AccMismatch`, `InlineMismatch`, `PlainOverdraw` removed), `PqzLayer.sol` (entry points without `acc` /
`inline`, rollover `(ua, n)`, prepare-acc, shield without `plainPending`).
- [ ] `Account`: scalars in ≤ 3 slots (`pendingCount`, `rolled`, `floor`, `cleared`; the `acc` reference, `accUnits`
  uint32, flags; `sendCounter`), `accHash`, `pending` mapping, `uint256[CT/32]` acc words; `plainPending` gone.
- [ ] Debit: `_total` from state (D5) with TRIVIAL entries as `Trivial(digits(amount))`, the `shieldIn` top-up from the
  signer's public balance; effects D4; credits D2 / D7; op blob D1 (single, multi, burn / refresh); D24.
- [ ] Shield D18 (append / same-block merge), wrap-shield into the same path.
- [ ] Rollover D8 with `ROLL_AGE` (D6); deletion below `rolled − INLINE_MAX`; prepare-acc.
- [ ] Tests (new file `test/pqz/PqzState.t.sol` + updates): credits beyond the old 1,024 accepted; ordered rollover,
  clamp at the cap, `CapReached`, refresh resets; un-roll at `p = rolled − INLINE_MAX` with TRIVIAL entries (Review
  Focus 1); stale and fresh hints (2); `RollTooYoung` and a debit with young inline entries (3); the three W-E race
  tests rewritten as "a rollover between prove and submit still settles" (kept as regressions); TRIVIAL merge / append
  and the third-party-shield-between-prove-and-submit case (9); all-zero `u` refused (12); restore-from-state: rebuild
  `acc` and the pending ciphertexts from the views only and compare; a forge invariant "every entry `< p` of a debit is
  in exactly one of: the spent `T`, `acc`, pending".
- [ ] Gas tests pinning `ROLL_MAX` and the prepare-acc halves (each under `0.75 · 2^24` with distinct cold blobs; Review
  Focus 6), the shield (append, merge) and the per-op gas table of spec §5.4; log `runs/<date>-5h-b-gas.txt`. Commit.

### Task 3: PQZ fees, `SHIELD_POOL`, events, views, bindings (D10–D13, D15, D19)
- [ ] D19 for PQZ: shield / wrap-shield / unshield / unshield-unwrap through `SHIELD_POOL`; beneficiary and per-credit
  fees from the pool to public UA balances (UA ledger per UA-6); the pool not payable (`UAPoolNotPayable` pattern).
- [ ] D11: NONE retired, storage modes on the blob; disclosure from the blob; `ciphertextHash` unchanged in value.
- [ ] D10: credit fee on op 1 and op 7; the SCaaS-chain floor in `initialize`; the third-party shield fee if Q2 says
  yes; Zether kinds untouched (still refuse non-zero `multiLegFee`).
- [ ] D12 events, D13 views; D15 relayed mode binding and unwrap parameters (statement views, `e2e.py`).
- [ ] Tests: fee per credit on both paths, to public balances; floor on the SCaaS testnet / 22776 ids; the D19 invariant (Review
  Focus 10); each event; each view; relayed `…NoBundle`-style replay of a BUNDLE envelope fails (L1). Commit.

### Task 3b: Zether side, one interface, `mtx*` names, kinds (D19 Zether, D20, D21) — after Z-BLS
**Files:** `src/zether/ZetherLayer.sol`, `ZetherLib.sol` (shield to the pool, unshield from the pool, beneficiary fee
to the public balance), `WrappedZetherToken.sol`, `IZetherToken.sol`; `src/pqz/PqzLayer.sol`,
`WrappedPqzToken.sol`, `IPqzToken.sol`; new `src/confidential/IConfidentialToken.sol` (shared functions and
events); `src/factory/IOpenFactory.sol`, `OpenFactory.sol` (kinds); the tokens' `mtxSelectors`; Zether and PQZ test
suites; `script/ZetherE2E.s.sol`, `script/pqz/e2e.py`, `script/DeployBase.sol`.
- [ ] D19 on Zether: `SHIELD_POOL` moves, the beneficiary fee to the public balance, the invariant test.
- [ ] D20: the name table of spec §5.11 (as approved under Q3) on both layers, `IConfidentialToken`, one selector per
  shared function; events renamed; allow-lists.
- [ ] D21: enum entries 6, 7 and `KindReserved` removed; factory tests to "decoding reverts".
- [ ] `forge` full suite green; size gate for all four confidential kinds. Commit.

### Task 4: Clients, tools, vectors
- [ ] `smartcontracts/evm/script/pqz/e2e.py`, `pqz-core/nethermind/chain/e2e.py`, `script/ZetherE2E.s.sol`, the Zether
  prover / client callers (`clients/`): new names, no `acc` / `inline` in calldata, rollover by count, shield without a
  proof, wallet restore from the views; the P6h wallet TODO gets the view list.
- [ ] Statement vectors unchanged (no relation change; `shieldIn` is a header-word rename); the relayed-binding
  statements of D15 regenerated where a vector holds one; list every changed artefact. Commit.

### Task 5: Spec and decisions
- [ ] `docs/contracts/pq-zero-knowledge.md`: §7.1 state table and flow, §7.3 shield, §7.4 / §7.4.1 checks and effects,
  §7.5, §7.6 rollover, §7.8 events, CTR-PQZ-06 (B, shield, `shieldIn`), -07 (state), -08 (no base; `ROLL_AGE`), -15
  (pool), threats T7, T8, T22, T23 rewritten with the measured numbers; CTR-PQZ-23 / -25 for D11.
- [ ] `docs/contracts/zether.md` (CTR-ZTH-45 names, -51 pool and fee), `token-wrappers.md` (kind table without 6 / 7,
  `SHIELD_POOL`), `contracts/README.md`.
- [ ] `docs/decisions.md` statuses; `python3 -I scripts/docs_check.py check` 0 errors. Commit.

### Task 6: Review and merge of the first half
- [ ] Reviewer (Claude sub-agent; Codex only on the owner's request): spec conformance, Review Focus 1–12, gas
  logs, sizes. Fixes, then the controller merges after the owner's approval.

### Task 7: 16k parameters and measurements (D16, D25)
**Files:** `pqz-core/pqzl/params/` (new `*_params.sage` for every relation: reg, tx, tx0, burn, ds, dr, txm2 / 4 / 8
with and without the auditor, at n = 2560 and the q of Q1), headers by `regen.sh`, `to_rust.py` output,
`estimator-*.txt`, `anon/hints-anon.txt` rerun; `aprime/` gains the 16k candidate (or a sibling `p16k/`);
`smartcontracts/evm/test/research/PqzStateGas.t.sol` parameterised on n.
- [ ] Budget and security for the chosen q (both models), DDGR20 hint table at 16–144 hints; 144 worst-case hints for
  one randomness group of 8 legs + auditor (≈ 462 extrapolated): if ≥ 450, op 7 M = 8 uses G = 1 (new relation spec),
  else M ≤ 4 on chain (O9 rule); n = 2304 at 80 hints (report; owner checkpoint if ≥ 450).
- [ ] `run_e_s1.sh` on every new spec; proof MLWE rank raised until uSVP **and** dual_hybrid β ≥ 450; LaZer codegen
  proof sizes per relation.
- [ ] PQZH: `ligero_params.py` preset search at the chosen q (domains, proof sizes per form, prover budget).
- [ ] Rollover gas at 644 words (`PqzStateSteadyGasTest2560`): `ROLL_MAX` = largest multiple of 16 under
  `0.75 · 2^24`; prepare-acc halves; op 7 M = 8 total gas against 2^24 from the blob and the measured proof size.
- [ ] `e_s0.py` adapted (exactness, Fiat–Shamir rounds with the new q).
- [ ] Owner checkpoint on the measured proof sizes vs `MAX_PROOF` (98,304) and `MAX_INPUT` (512 KiB, O8) before Task 8.

### Task 8: 16k + B-1 + A-2 + `R_REG` in the cores, PQZH, codec, contracts (D16, D23)
- [ ] C and Rust PQZL: `N`, `k`, `q`, `Δ`, norm bounds, bit layouts (M 18, carries 15, `e_T` 29 bits), `K_MAX`, NTT
  constants for the new q (q ≡ 9 mod 16 keeps `l = 4`), the keys / Enc / Dec KATs; heap peaks re-measured.
- [ ] B-1 in all four implementations and both provers (V3 / V4 from the post-`tg` hash), the `tg`-mutation binding
  test, review A's cheating prover (`scratchpad/reviewA/poc/`) as the regression fixture; A-2 renumbering.
- [ ] `R_REG` bound to the UA id per UA-6 (relation statement, `pqz-stmt`, the registry probe, vectors).
- [ ] PQZH Ligero: the field changes to the new q (50-bit products fit u128; the wasm32 21-bit split becomes three
  17-bit limbs), the domains of Task 7, constraint systems for the new widths; its id bumps.
- [ ] `pqz-stmt`: lengths per form, `MAX_PROOF(id)`, `MAX_INPUT` 512 KiB, the new ids; the Nethermind plugin limits.
- [ ] Solidity: `PqzCt` (`Q`, `DELTA`, `PK`, `CT`, `ZERO_HASH`), `ROLL_MAX` re-pinned (Task 7's measurement),
  `PqzSafety` ids, probe proofs and the self-test hash; a new `UAPqzVerifier`, a new `Env` version and releases.
- [ ] Vectors, `pqz_kat.py`, fuzz seeds regenerated; native = wasm32; C = Rust; `gate.sh fin`.

### Task 9: Review, gas re-calibration, roll-out
- [ ] Independent review of the parameter and transcript change (the budget of spec §6.1 at the chosen q, the
  estimator logs, B-1 / A-2 / `R_REG`).
- [ ] Precompile gas calibration with the owner's go-ahead (timing), the 60 ms p99 verify limit checked for every form
  (risk: R_TXM M = 8 was 51.0 ms p99 in wasm32 at today's size).
- [ ] Then plan fs3 Task 12 (final gate), Task 6 (package) and Task 13 (SCaaS testnet reset, gas), which wait for 5h.

## Related tasks outside this plan

- **UA-6** (CTR-UA-30; spec / plan by another agent): registry — PQZ key in `register` for PQ signers, `keyOwner`
  uniqueness, the `pqz-mlwe` kind and `authRef` removed (Zether's too), the `R_REG` message bound to the UA id, the
  `zether-bn254` kind 0x0140 removed. **Before 5h.** 5h implements UA-6's `R_REG` message inside the id bump (Task 8).
- **Z-BLS** (D22): the bn254 Zether line to `legacy/`. After UA-6, before Task 3b; may run beside Tasks 1–3.

## Out of scope
Mainnet 22776. Relation or proof changes to classical Zether (none: its shield, transfer and burn statements stay).
The bn254 Zether removal (task Z-BLS) and the registry work (UA-6). Node-level rate limits for credit-creating
transactions (an operations item, named in the spec). Keeper software (P6i).

## Critical files
- `smartcontracts/evm/src/pqz/PqzLib.sol` (`shield` 183, `_receiver` 232, `_credit` 303, `_legs` 402, `_creditLegs`
  456, `rollOver` 581, `_total` 770, `_debit` 829; lines at `c173de37`), `PqzCt.sol`, `PqzLayer.sol` (entry points
  139–200), `WrappedPqzToken.sol`, `IPqzToken.sol`, `PqzSafety.sol`
- `smartcontracts/evm/src/zether/ZetherLayer.sol` (entry points 116–190), `ZetherLib.sol` (`shield` 186, `unshield`
  285, `_credit` 633), `WrappedZetherToken.sol`, `IZetherToken.sol`
- `smartcontracts/evm/src/factory/IOpenFactory.sol` (`TokenKind`), `OpenFactory.sol` (`KindReserved` 72, 101, 122,
  310), `IFactoryToken.sol` (`Env`), `src/metatx/MetaTokenBase.sol` (`mtxTransfer`, the `UA_POOL` pattern)
- `smartcontracts/evm/test/pqz/PqzNormal.t.sol` (race tests 534–620), `PqzMulti.t.sol`, `helpers/PqzFixture.sol`,
  `test/v2/Factory.t.sol`, the Zether suites
- `smartcontracts/evm/test/research/PqzStateGas.t.sol` (the measurement prototype)
- `smartcontracts/evm/script/DeployBase.sol` (Zether deploy steps), `script/ZetherE2E.s.sol`, `script/pqz/e2e.py`
  (PQZ deploy), `size-baseline.json`
- `pqz-core/pqzl/params/aprime/` (budget, estimates, sizing specs), `pqz-core/stmt/src/lib.rs` (98–101 limits),
  `pqz-core/pqzh/ligero/ligero_params.py`, `src/fq.rs`, `src/fft.rs` (the field and domains of D25)
- `docs/contracts/pq-zero-knowledge.md` §4.1–§4.4, §7.1–§7.8; `docs/research/shield-and-key-reuse.md` §2–§3

## Owner questions (2026-10-20 update)

Only what blocks a task (research items are measured in Task 7, not asked). Details: spec §11.

| # | Question | Recommendation | Blocks |
|---|---|---|---|
| Q1 | q = 2^50 − 71 has no FFT domain for PQZH's Ligero (q − 1 = 2^3 · 17 · 8.3·10^12). Change q, or leave PQZH without a 16k id? | q = **2^50 − 42,310,535** (q − 1 divisible by today's radices 2^3 · 19 · 43 · 431; Δ = 2^30 − 1 → 2^30 − 41; `K_MAX`, margin 3.36× and security unchanged). | Task 7 |
| Q2 | Charge a PQZ shield into **another** account the per-credit fee (to the recipient's public balance), shields to oneself free? | Yes; Zether shields stay free. | Task 2 / 3 |
| Q3 | Approve the `mtx*` name table (spec §5.11), incl. `mtxConfidentialTransfer…` and one selector per shared function across both layers. | Approve. | Task 3b |
