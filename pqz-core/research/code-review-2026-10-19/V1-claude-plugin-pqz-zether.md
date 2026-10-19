# V1: Claude, part 1 of 3: Nethermind PQZ plugin, `src/pqz/`, `src/zether/`

Static reading only, tree `/home/ha/work/ainative/scaas/.claude/worktrees/rev3` at `7aab1fe` (detached). Paths below
are relative to that tree. No build, no tests, no chain.

Summary: **no P0 or P1 found.** Two P2 findings. The first is T-lead, the controller's lead, now confirmed. Five P3 findings.

| id | sev | title |
|---|---|---|
| T-lead | P2 | PQZ storage mode not bound: a direct transfer can be front-run through the `…NoBundle` entry, so no disclosure entry is stored |
| V1-02 | P2 | PQZ (and Zether) tokens trust a creator-chosen verifier / precompile; `PqzLib.init` lacks the self-test the spec requires |
| V1-03 | P3 | Public rollover reverts in-flight PQZ debits (`AccMismatch`), contrary to threat T8 "impossible by construction" |
| V1-04 | P3 | `add-schedule.py` can silently drop gas rows (shapes become `…00`) |
| V1-05 | P3 | Supply chain: the FFI hash pin is circular; the plugin logs the library hash but does not compare it; `apt` is not pinned |
| V1-06 | P3 | A node fault or lock contention on the RPC path stops or stalls the whole node (hypothesis) |
| V1-07 | P3 | Hygiene: error order in `_parseMulti`; `verifyTransferAmount` reverts where its doc says "false"; the bn254 wrappers do not check return size |

---

### T-lead — P2 — PQZ storage mode not bound: a direct transfer can be front-run through the `…NoBundle` entry, so no disclosure entry is stored

**Verdict on the lead: confirmed.**

**Locations**
- Entry points that differ only in `mode`:
  - `smartcontracts/evm/src/pqz/PqzLayer.sol:133-149`: `pqzTransfer` uses `_defaultMode()` (BUNDLE on a BUNDLE token); `pqzTransferNoBundle` uses `NONE`.
  - `PqzLayer.sol:152-168` has the same pair for op 1: `pqzTransferSingle` and `pqzTransferSingleNoBundle`.
- What the statement binds:
  - `PqzLib.sol:859-864` (`_header`): `opTag`, psid, chainid, token, registry, from, to, ben, fee, amount, recipient, sendCounter, p, validUntil, auditorOn, plainUsed, chainUid, binding, salt, memoHash. **The mode is not among them.**
  - `opTag` is `OP_TRANSFER` (`PqzLib.sol:261`) or `OP_TRANSFER_MULTI` (`PqzLib.sol:359`) whatever the mode.
  - The only mode-dependent word is `memoHash`, which is non-zero only on HASH (`PqzLib.sol:252, 268-272`, `:362, 375-379`). So BUNDLE and NONE give byte-identical statements.
- Authorization:
  - `PqzLib.sol:780-796` (`_check`): `authDigest = keccak("SCAAS-PQZ-AUTH-V1" ‖ keccak(stmt))`, checked by `requireZetherAuthorized(from, d, authSig, true)`. Nothing ties it to `msg.sender` or to the selector.
  - For a self UA with no `authRef`, `auth` must be empty (`ua/UARegistry.sol:551-552`).
- Envelope binding:
  - Direct calls have `binding = 0` (`metatx/MetaTxBase.sol:276-279`, `PqzLayer.sol:189-195`).
  - Relayed calls are safe: the envelope signature covers `keccak256(m.data)` (`common/MetaTxLib.sol:100, 189`), selector included.
- Effect of the two modes:
  - `_settleTransfer` writes the entry only for `mode != NONE` (`PqzLib.sol:281`). `_settleMulti` does the same (`PqzLib.sol:433`).
  - Without an entry, `ciphertextHash(ref) == 0` (`PqzLib.sol:650-654`), and `disclosureBuffer` reverts `UnknownEntry` (`PqzLib.sol:599-600`). So `verifyTransferAmount` can never succeed for that `entryRef` (`PqzLayer.sol:102-109`).
- Spec:
  - `docs/contracts/pq-zero-knowledge.md:839-840` (CTR-PQZ-25): "The storage mode is the user's per transfer through the entry they call: the contract never switches it."
  - CTR-PQZ-23 says entries work "as CTR-ZTH-38".
  - Classical Zether binds the mode: `zether/ZetherLib.sol:535-537` puts it in `opTag`, and `docs/contracts/zether.md:558` says "The mode is in `opTag`, so a relayer cannot switch the mode of a signed proof".

**Trigger**
1. The token has `disclosureMode = BUNDLE`.
2. Alice sends a direct `pqzTransfer(payload, acc, inl, proof, authSig)` or `pqzTransferSingle(...)` with no memo.
3. Mallory copies the five arguments from the mempool and calls `pqzTransferNoBundle(...)` (or `pqzTransferSingleNoBundle(...)`) with a higher priority fee.
4. Mallory's call rebuilds the same statement (`binding = 0`, the same counter, `memoHash = 0`). `authSig` and the proof pass, the debit and credits settle, `sendCounter` increments, and no entry is stored. Alice's own tx then reverts on the stale `acc` / counter.

The reverse switch (NONE to BUNDLE) also works but only costs Mallory gas. A COMPACT token is immune: every non-HASH mode reverts (`PqzLib.sol:249-251`). HASH cannot be switched either, because the statement carries `memoHash ≠ 0`.

**Impact**
- No theft and no change to balances.
- The sender permanently loses the on-chain disclosure for that transfer. `verifyTransferAmount` and `disclosureStatement` revert `UnknownEntry` for every leg and every kind: SENDER_S, RECEIVER_X and AUDITOR. That is the compliance and audit path of CTR-PQZ-14 / -26.
- The ciphertexts survive only in the `PqzTransfer` / `PqzTransferMulti` event logs.
- It also breaks the documented guarantee that the user picks the storage mode.

Reach: direct calls on BUNDLE tokens only. Gas is free on 7622, so the attack costs nothing.

**Confirmed or hypothesis:** confirmed by the trace above.

**Suggested fix:** mirror Zether and put the mode in what the proof binds. Two options:
- **(a)** A per-mode `opTag` for op 1 and op 7. This changes `pqz-stmt`, both relations' opTag sets, the proof vectors, the self-test hash (no; REGISTER only) and the gas rows (no, rows are keyed by op / id / len). Heavy.
- **(b) Cheaper, recommended:** fold the mode into a header word the contract already fills. For example, a direct call's `envelopeBinding` (word 17) becomes `keccak256(TAG_PQZ_DIRECT_MODE ‖ uint8(mode))` instead of 0. This is analogous to `unwrapBinding` for `pqzUnshieldUnwrap` (`UnderlyingPqzToken.sol:73-90`). It changes deployed bytecode and the statement views (`transferStatement`, `transferSingleStatement`) and clients; it does not change the chainspec, the gas rows or the proof systems. Proof vectors with `binding = 0` for direct transfers would need regenerating.

---

### V1-02 — P2 — PQZ (and Zether) tokens trust a creator-chosen verifier / precompile; `PqzLib.init` lacks the self-test the spec requires

**Locations**
- `factory/OpenFactory.sol:221-226` (`_checkPqz`): the gate is `pqzEnabled`, the chain id, and `verifier.isSupportedOnThisChain() == 1`. That answer comes from the verifier, a creator-supplied contract.
- `pqz/PqzLib.sol:139-167` (`init`):
  - `PqzSafety.requireAllowedChain()` only.
  - `s.pqz = v.PRECOMPILE(); s.psid = v.PROOF_SYSTEM_ID();` with no check that `s.pqz == PqzSafety.PQZ` (`PqzSafety.sol:10`), no `requireSelfTest(s.pqz)`, and no check that `psid ∈ {PQZL_ID, PQZH_ID}`.
- `pqz/PqzLib.sol:657-663, 795`: every op's verdict is a `staticcall` to `s.pqz`, which counts as accepted when the answer is the word 1.
- `pqz/UAPqzVerifier.sol:29-37`: the constructor's self-test and probe run against the `pqz` argument with a caller-supplied probe vector. There is no `SELFTEST_VECTOR_HASH` pin.
- Spec, `docs/contracts/pq-zero-knowledge.md:1858-1863`:
  - "`UAPqzVerifier`'s constructor and `PqzToken.initialize` call `OP_SELFTEST` and require the expected hash …"
  - "… also take a valid `R_REG` vector …, require `keccak256(vector) == SELFTEST_VECTOR_HASH` …"
  - "This, not the allowlist alone, is what keeps PQZ off chains whose client is not ours."
- `factory/IOpenFactory.sol:53`: "a `*_PQZ` creation needs … a `UAPqzVerifier` this chain runs".
- Zether has the same class: `zether/ZetherLib.sol:141-167`, `factory/OpenFactory.sol:208-218`, plus `ZetherLib.sol:592-594` (the verifier decides the proofs) and `:611-621` (it does the group operations). Zether is dev-chain only (`ZetherSafety.sol:11-14`).

**Trigger**
1. Deploy `FakePqz`:
   - It answers `06 00000000` with `SELFTEST`.
   - It answers every other input with the word 1.
2. Deploy `FakeVerifier` with:
   - `PRECOMPILE() = FakePqz`;
   - `PROOF_SYSTEM_ID() = PQZL_ID`;
   - `isSupportedOnThisChain() = 1`.

   A genuine `UAPqzVerifier` with `pqz = FakePqz` and a probe that FakePqz answers 1 / 0 also passes.
3. `OpenFactory.createToken(UNDERLYING_PQZ, …, conf.verifier = FakeVerifier)` succeeds. The token is listed under its legs (`_wrappers`, `_byUnderlying`).
4. Victims `pqzWrapShield` real underlying into it.
5. Anyone with a registered `pqz-mlwe` UA (self, `authRef = 0`, empty `authSig` accepted) calls `pqzUnshieldUnwrap` with arbitrary payload bytes that pass the cheap checks and any proof. It pays out up to `totalShielded·shieldScale` of the reserve.

**Impact:** the whole confidential pool of a factory-listed PQZ wrapper can be drained by anyone. The creator decides beforehand whether that is possible, and the factory gate presents the token as "a `UAPqzVerifier` this chain runs".
- Reach is limited to users who deposit into a token with a malicious config.
- It is visible through `precompile()` / `verifier()` (`PqzLayer.sol:27-29`).
- It contradicts the spec's contract self-test and the factory's stated gate.
- Zether is the same, on dev chains only.

**Confirmed or hypothesis:** confirmed (code trace; the spec's `initialize` self-test is absent).

**Suggested fix:**
- In `PqzLib.init` (deployed bytecode only):
  - `if (s.pqz != PqzSafety.PQZ) revert`;
  - `PqzSafety.requireSelfTest(PqzSafety.PQZ)`;
  - `psid` must be `PQZL_ID` or `PQZH_ID`.
- In `UAPqzVerifier`'s constructor, require `pqz == PqzSafety.PQZ`, or pin the probe vector hash as the spec says.
- For Zether, a registrar-set verifier allowlist in `OpenFactory`, or pinned verifier code hashes.
- No chainspec, gas or vector change.

---

### V1-03 — P3 — Public rollover reverts in-flight PQZ debits (`AccMismatch`), contrary to threat T8 "impossible by construction"

**Locations**
- `pqz/PqzLayer.sol:183-185` and `pqz/PqzLib.sol:563-582`: anyone may roll 1–16 credits. That changes `accHash` and `rolled`.
- `pqz/PqzLib.sol:752`: every debit requires the calldata `acc` to hash to the current `accHash`.
- Spec: `docs/contracts/pq-zero-knowledge.md:934` (CTR-PQZ-08) and the threat table T8 (`:1975`): "impossible by construction … clients retry once".

**Trigger**
1. Alice has `pendingCount > rolled`. She signs or sends a debit with `acc` = her current acc.
2. Mallory front-runs with `pqzRollOver(alice, acc, [pending[rolled]])`.
3. Alice's tx reverts `AccMismatch`.

`T` is indeed unchanged (lane-wise mod q, `PqzCt.sol:43-94`), so the proof stays valid; only the calldata is stale. On the relayed path the envelope signature covers `data` (`MetaTxLib.sol:100,189`), so the user must **re-sign** the envelope (ML-DSA on the UA path), not just resubmit. Mallory can repeat this while Alice has unrolled credits, and anyone can create those by sending her credits.

**Impact:** liveness griefing of debits, at no cost on 7622. No fund loss.

**Confirmed or hypothesis:** confirmed; the impact rating is a judgment.

**Suggested fix:** keep `prevAccHash` / `prevRolled` (one slot) and accept `acc` matching either, computing `T` from the matching `rolled`. Alternatively, restate T8: "a rollover between build and inclusion forces a rebuilt call, not a re-proof". Deployed bytecode only.

---

### V1-04 — P3 — `add-schedule.py` can silently drop gas rows

**Locations:** `pqz-core/nethermind/chain/add-schedule.py:45-48`. `s["pqz"] = [rows not picked] + new_rows` with no check that the replaced key set `KEY(r)` equals the new one.

**Trigger:** a calibration file that lacks one shape (for example PQZL op 7 `M=8`, `auditorOn=1`) is used with `--ops 7`.

**Impact:**
- From the new timestamp, that shape misses (`PqzSchedule.RowGas` gives null): `…00` without an FFI call (`PqzPrecompile.cs:51`). Every honest proof of that shape then fails (`ProofRejected`).
- Only another fork-time schedule fixes it.
- A duplicate key among `new_rows` instead makes every node refuse to start at the restart (`PqzChainSpecEngineParameters.cs:112-113`). That fails closed, but on all nodes at once.

**Confirmed or hypothesis:** confirmed (script logic).

**Suggested fix:** require `{KEY(r) for r in removed} == {KEY(r) for r in new_rows}` and no duplicates (or an explicit `--allow-drop`), and add it to `--check`. Tooling only.

---

### V1-05 — P3 — Supply chain: the FFI hash pin is circular; the plugin does not compare the library hash; `apt` is not pinned

**Locations**
- `pqz-core/nethermind/build-image.sh:21-24`: `FFI_SHA256` is the hash of the same build's `ffi-export`. `Dockerfile:64` therefore only checks that two BuildKit runs agree; it does not check a reviewed value.
- `Nethermind.Pqz/PqzPlugin.cs:48-51`: `LibrarySha256()` is logged, never compared. The only enforced check is `OP_SELFTEST` (`SelfTest.cs:11-20`), a behavioural KAT. A modified library that keeps the KAT and the four R_REG verdicts passes it.
- `Dockerfile:15`: `apt-get install clang` without versions. The base images are pinned by digest (`Dockerfile:8-10`), and cargo uses `--locked`.

**Impact:**
- Images built on different hosts or at different times may differ undetected.
- The node accepts any `libpqz_ffi.so` that matches the self-test.
- Consensus would rely on the operator.

**Confirmed or hypothesis:** confirmed for the mechanism. No tampered build was tried.

**Suggested fix:**
- Commit the expected `libpqz_ffi.so` sha256 per release, and have `build-image.sh` / the Dockerfile compare against it. Optionally do the same in the plugin, or make it a chainspec-pinned value refused at start.
- Pin the `clang` package version or use a toolchain image with it.
- Image and plugin only.

---

### V1-06 — P3 — A node fault or lock contention on the RPC path stops or stalls the whole node (hypothesis)

**Locations**
- `PqzPrecompile.cs:64-80`: any status other than 0, 1 or 3 calls `Environment.Exit(120)`, including inside `eth_call` / `eth_estimateGas` / tracing.
- `pqz-core/ffi/src/pqzl.rs:8-18` and `ffi/src/pqzl/rust.rs:1-20, 58-100`: one process-wide lock and one worker for every PQZL verify (block processing and RPC alike).
- `ffi/src/pqzh.rs:10-12`: PQZH `Oom` maps to `NodeFault`.

**Trigger (hypothesis):**
- Many concurrent `eth_call`s with PQZH inputs that pass the row check drive the node to memory pressure. A `try_reserve` failure then gives status 4, and the process exits.
- Or PQZL calls queue on the lock and delay block import.

On Linux overcommit, `try_reserve` rarely fails (the OOM killer acts instead), so the exit path is unlikely. Lock contention is plausible. The RUNBOOK puts public RPC on a rate-limited follower (`chain/RUNBOOK.md:285-286`), which limits reach to that follower, unless the signer exposes RPC.

**Impact:** liveness of an RPC-serving node. Consensus is unaffected: a fault is never a verdict, which is correct.

**Confirmed or hypothesis:** hypothesis. The mechanism is confirmed by reading; whether it is reachable needs a load test.

**Suggested fix:**
- Keep RPC off the signer (document it as a hard rule).
- Optionally, outside block processing, map status 4 to a failed call instead of an exit. Nethermind knows whether it is in a trace/RPC context.
- No consensus change.

---

### V1-07 — P3 — Hygiene

- **`_parseMulti` error order.** `pqz/PqzLib.sol:364` computes `payload.length - T_OUT - 32*m - memo` before the bound check at `:365`. A short payload panics `0x11` instead of reverting `BadPayload`. The effect is the same; only the error differs.
- **`verifyTransferAmount` reverts where its doc says "false".** `pqz/PqzLayer.sol:99-109` documents "Any malformed input is false", but `abi.decode(opening, (bytes, bytes))` at `:105` reverts on malformed offsets. Wrap it in `try this.…` or decode manually.
- **The bn254 wrappers do not check return size.**
  - `zether/ZetherCurves.sol:37, 66, 88-89, 106, 138` (`G1Bn254`) check only the success flag, not `returndatasize`.
  - On an EVM without `0x06` / `0x07`, every MSM would return the zeros already in memory, so every proof would pass.
  - This is mitigated by `isSupportedOnThisChain` (`ZetherVerifier.sol:585-593`) at factory creation (`OpenFactory.sol:208-218`) and by the dev-only gate.
  - Add `eq(returndatasize(), 64)` as defence in depth, as `G1Bls12381` already does (`ZetherCurves.sol:172-173, 202-203, 222-223`).

---

## Checked and clean

### Plugin (`pqz-core/nethermind/`)

**Determinism**
- Gas is a function of the input bytes and the active schedule only (`PqzPrecompile.cs:36-41`):
  - the row key is `(op, be32 len, id = input[37..69], M word 325, auditorOn word 453)`, read with no validation (`PqzChainSpecEngineParameters.cs:141-152`);
  - the offsets match `pqz-stmt` `H_LEGS = 10`, `H_AUDITOR_ON = 14` (`stmt/src/lib.rs:43-61, 586-588`) and the id at statement word 1.
- Hex keys use `Convert.ToHexString`, which is culture-free.
- A miss gets `MinGas` plus the length term and returns `…00` with no FFI call (`PqzPrecompile.cs:51`). That keeps unknown ids and shapes out of the verifier.
- Op 6 has a fixed `selftestGas`. The FFI answers only the exact `06 00000000`, from cache (`ffi/src/lib.rs:92`, `selftest.rs:115-123`). Any other op-6 input is rejected in `decode_input` (`stmt/src/lib.rs:441-443, 901-912`), so a long op-6 input is cheap work at a fixed price.

**Activation**
- Timestamp-keyed schedules (`PqzChainSpecEngineParameters.cs:56-79`).
- The strict section: unknown keys, an empty schedule, unsorted entries, duplicate rows, op 6 rows, bad op-7 legs / auditorOn, and ML-DSA prices below EIP-8355 are each a start-up error (`:30-42, 97-120`).
- The stock provider fails closed (`:73-79`).
- `PQZ-REFUSE` on a missing library, a wrong self-test, or a provider that lost the registration (`PqzPlugin.cs:35-63`).
- The precompile set and the schedule are found through decorators (`PqzReleaseSpec.cs:17-34`).

**Statuses**
- 0 → the output word.
- 1 → a failed call.
- 3 → `…00` plus a warning (input-caused, deterministic).
- Anything else → exit 120, never a verdict (`PqzPrecompile.cs:54-80`).

The FFI side matches:
- worker / lock / OOM → `NodeFault`;
- core panic → status 3;
- `with_ctx` recovers a poisoned lock;
- the self-test failure is not cached (`ffi/src/lib.rs:87-154`, `pqzl.rs:62-96`, `pqzl/rust.rs:58-110`).

**P/Invoke**
- Exact-path load, no search path (`Native.cs:16-23`).
- Spans pinned with `fixed`; the output is checked to be ≥ 32 bytes; length `nuint`; an empty input is a null pointer (allowed by the ABI) (`Native.cs:30-36`).
- `MAX_INPUT` is checked before the native call on both sides (`PqzPrecompile.cs:49`, `ffi/src/lib.rs:139-143`).
- Test hooks are not in the image: a feature gate plus a scan in `build-image.sh:43`.

**ML-DSA (`MlDsaPrecompile.cs:13-56`)**
- `L < PK + SIG` gives 32 zero bytes.
- Exact slices; a new key object per call.
- Gas = price + 6 per word of message.
- `MLDsa.IsSupported` is checked at start.
- Determinism rests on the digest-pinned base image's OpenSSL.

**Tooling**
- `patch-chainspec.py:22-50` refuses an existing `engine.Pqz`, allocations at the precompile addresses, and any other diff.
- `add-schedule.py:37-40` requires a timestamp at least 5 minutes in the future and after the last one.

### `smartcontracts/evm/src/pqz/`

**Statement equals `pqz-stmt`, byte for byte**
- Header word order and the salt word (`uint256(uint128(salt))`, i.e. 16 zero bytes ‖ salt) match `PqzLib.sol:859-864` against `stmt/src/lib.rs:41-61, 485-487`.
- Zero words per form match: transfer amount and recipient are 0; burn `to`, `auditorOn` and salt are 0; refresh adds amount and recipient (`stmt/src/lib.rs:230-244`).
- Object order, op 1: `pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ u ‖ v_t ‖ v_f ‖ [v_a]` (`PqzLib.sol:233-244`).
- Object order, op 7: `pk_f ‖ pk_0… ‖ [pk_a] ‖ T ‖ u_g… ‖ v_j… ‖ v_f ‖ [v_a…]`, with M at word 320 and `recipientsHash` at word 192 (`PqzLib.sol:402-422`). This matches `stmt/src/lib.rs:617-621, 735-745`.
- Burn: `pk_f ‖ T ‖ u' ‖ v_f` (`:542-558`).
- Disclosure: 9 words (opTag, psid, chainId, chainUid, token, registry, entryRef, amount, kind) ‖ pk ‖ u ‖ v (`PqzLib.sol:603-610, 643-647`), which matches `stmt/src/lib.rs:62-65, 166-168`.
- `fee < 2^64` is guaranteed by `init`, including `+ 8·multiLegFee` (`PqzLib.sol:142-147`). `amount ≤ maxShielded ≤ 2^62`.
- Every field is built from contract state or registry keys, except the proven payload parts (`p`, `validUntil`, `plainUsed`, the UAs, salt, `out`). Those are checked against state: `plainUsed ≤ plainPending`, `p ∈ [floor, pendingCount]`, `INLINE_MAX`, inline hashes, `acc` hash, canonical `out`, recipient caps (`PqzLib.sol:215-222, 384-399, 735-777`).

**Replay and cross-binding**
- chainid, chainUid, token, registry, sendCounter, validUntil and binding are all in the header.
- `entryRef` includes chainid, chainUid, token and counter (`:836-838`).
- Direct and relayed calls differ by `binding` (T19).
- `pqzUnshieldUnwrap` binds the leg and `minOut` (`UnderlyingPqzToken.sol:72-90`).

**State transitions**
- The rollover / debit algebra (`p ≥ rolled` and `p < rolled`), `floor`, `accUnits` and the clearing window all hold. I traced the invariants: `accUnits + (pendingCount − rolled)` never grows past the credit-time cap, and indexes `< floor` are never read again (`PqzLib.sol:563-582, 749-820`).
- Lane arithmetic has no carry, `minus` has no borrow, and `addTrivial` digit order matches `selftest.rs:45-47` (`PqzCt.sol:43-94`).
- CEI holds; every entry is `nonReentrant` (`PqzLayer.sol`).
- External calls go only to the registry (view), the precompile (staticcall) and the leg token after state changes (`UnderlyingLib.payOut`).

**Supply conservation**
- shield: `+totalShielded`, with the public burn or the underlying pull (`PqzLayer.sol:124-127`, `UnderlyingPqzToken.sol:50-55`; `UnderlyingLib.wrap` mints nothing, `metatx/UnderlyingLib.sol:133-144`).
- burn: `−totalShielded`, then mint, or a reserve payout floored ≤ reserve (`PqzLib.sol:507-513`, `UnderlyingPqzToken.sol:66-70`, `UnderlyingLib.sol:247-271`).
- Fees: the beneficiary share plus `M·multiLegFee` to the legs equals the header fee (`PqzLib.sol:332, 431-432, 450`).
- `executeRate` counts the shielded value (`UnderlyingPqzToken.sol:99-101`).

**Precompile calls**
- An answer is accepted only when the call succeeds, returns exactly 32 bytes and the word is 1. A chain without the precompile therefore gives false, and the op reverts.
- Out of gas reverts the op, so no state is written (`PqzLib.sol:657-663`, `UAPqzVerifier.sol:55-64`, `PqzSafety.sol:28-37`).

**Gas / DoS**
- Loops are bounded: M ≤ 8, inline ≤ 16, roll ≤ 16, clear ≤ 32.
- Queue flooding (`K_MAX`) is the accepted threat T7 / T22.

**Selectors**
- PQZ ops cannot be batched (`PqzLayer.sol:229-240`).

### `smartcontracts/evm/src/zether/` (dev chains only, `ZetherSafety.sol:11-14`)

**Σ protocol**
- E1–E8 checked as algebra (`ZetherVerifier.sol:202-245, 334-354`):
  - E5 gives `bal = b + v + fee` (burn: `b + amount + fee`);
  - E3 / E4 share `z_v` and `z_s`;
  - E6 has the auditor all-or-nothing;
  - E7 / E8 tie `z_v` and `z_b` to the Bulletproof commitments.
- No wrap: `v`, `b < 2^64`, `fee < 2^64`, `M ≤ 16`, `r > 2^250`.
- The multi variant uses Σ`z_vj` (`:249-326`).
- Non-zero `Y_f`, `D_out` and `Y_t`, with `Y_t ≠ Y_f`.
- Scalars `< r`; `c ≠ 0`.

**Bulletproofs and transcript**
- BP-1 `δ` and BP-2 scalars match standard Bulletproofs: the `H_i` coefficient is `z + y^{-i}(z²2^i − b·s_i^{-1})`, U is weighted by `w`, and the L/R exponents are `u²` / `u^{-2}` (`:408-479`).
- Every transcript challenge is checked non-zero.
- The V commitments are absorbed in the Σ commit, before the BP challenges (`:171-182`, `:373-386`).
- The transcript framing is length-prefixed (`ZetherTranscript.sol:13-31`).

**Points**
- BLS12-381: every verification point goes through G1MSM `0x0c` (subgroup check) with a return-length check (`ZetherCurves.sol:199-231`).
- bn254: cofactor 1, and the precompiles reject invalid points (revert `BadPoint`).

**Token layer**
- Header offsets: `FEE_AT 288` and `AMOUNT_AT 352` match `ZetherLib._header` (`ZetherLib.sol:517-524`).
- The single statement point order matches the verifier (`:453-456` against `ZetherVerifier.sol:200-201`).
- The multi mode is in `opTag` (`ZetherLib.sol:535-537`).
- The `accSeq` / `sendCounter` nonce rule (`:562-568`).
- Supply: shield `+`, unshield `−`, the fee as `[fee]G` (`:173-181, 272-290, 599-615`).
- Rollover griefing in PUBLIC mode is an accepted spec item (`zether.md:312-329`).

**Disclosure**
- The Chaum–Pedersen relations for RECEIVER_X / SENDER_CP / AUDITOR are correct, and the `pre` binds token, entryRef, index, amount and kind (`ZetherDisclosure.sol` `verifyTransferAmount`, `_chaumPedersen`).
- The HASH or record length test cannot collide by parity.

## Not checked

- **Nethermind internals** (the base image's source was not in the tree):
  - how `ChainSpecBasedSpecProvider` builds block-number transitions relative to timestamp ones;
  - which `startTimestamp` `ApplyToReleaseSpec` gets for them. 7622's reset chainspec has only block-0 transitions (path B sets `maxCodeSizeTransition 0`), but the test genesis keeps `maxCodeSizeTransition: 6432`;
  - whether a stock Nethermind with no plugin refuses a chainspec that carries `engine.Pqz` (the "PQZ-REFUSE without the library" case);
  - how Nethermind handles an exception thrown from `IPrecompile.Run` (the ML-DSA path relies on it).
- **The proof cores and `pqz-stmt` decoding** beyond the layout comparison (out of scope, rounds 1–2), including whether every core panic is truly input-deterministic.
- **Gas-row adequacy against worst-case verifier time.** No timing runs; that is the calibration's job. Whether `MAX_INPUT` holds every honest PQZH op-7 M=4-with-auditor input (statement 132,992 + `MAX_PROOF_PQZH` 262,144 > 393,211) depends on real PQZH proof sizes, which I did not measure.
- **Parts 2 and 3:**
  - `UARegistry._authorized` and the ML-DSA / msig verifier paths behind `requireZetherAuthorized`;
  - the `MetaTxBase` fee / nonce ordering (T20);
  - `OpenFactory` beyond `_checkPqz` / `_checkZether`.
- **Plugin tests**, the harness and `Calibrate` were read only to understand intent.
