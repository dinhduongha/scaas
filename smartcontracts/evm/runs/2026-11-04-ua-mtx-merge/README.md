# T0 of the `ua*` / `mtx*` merge: the harness

Plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` task T0; spec `docs/superpowers/specs/2026-11-04-ua-mtx-merge.md`
§9. Results: [`results.txt`](results.txt). Research harness, kept (git-tracked); full forge output stays in git-ignored
`.log` files. Forge gas is deterministic: none of this is a timing calibration.

## The scratch code (never merged)

The merged contracts were built on the local branch `ua-mtx-merge-t0` from `main` at `bf6f3d04`, in a worktree, as scratch:
enough to compile and measure, not production code. That branch is never merged and never pushed. Onto `ua-mtx-merge` only this directory's
results and scripts are copied, no Solidity: `adapters/*.sol` (the measuring tests) and `TokenBodyLib.sol.txt` (lever L's
scratch library, `lib_split.py`'s input) stay on `ua-mtx-merge-t0`.

| Run | What | How it was built |
|---|---|---|
| base | `main` at `bf6f3d04` | a detached worktree at that commit, `test/merge/` = `adapters/` with `T0Sel.base.sol` |
| M | A + B + C (MD-2): every pair merged, an EOA on the merged path with no registry call, a registry only for a derived side; plus Q2's ordered cancel, R47's `UASig` on `mtxExecute` / `mtxBatch` / `mtxShield`, R17, the router's 19 pairs (R14), one `envelopeBinding` view (§2.3) | cherry-pick of the spike's `77fb0ef9` (A), `2094aa70` (B), `5d068cce` (C) onto `bf6f3d04`, conflicts resolved by hand onto today's code; then `merge_router.py`, `merge_zether_libs.py`, `merge_binding_views.py`, and the Q2 / R47 / R17 edits by hand (scratch commit `4df14232`) |
| M + L | lever L | `lib_split.py` on M (`TokenBodyLib.sol.txt`) |
| M + D | lever D by deletion (no module built, plan T0 step 4) | `lever3_delete.py` on M |
| M + L + D | both | `lever3_delete.py` on M + L |
| `<run>`, stand-in | the regulated stand-in (§9 step 2): six direct stubs and the hook in `_update` and `_uaMove` | `standin.py` on the run's tree, measured, then `git checkout` (never committed) |

The spike's `merge_pairs.py` was not re-run: the cherry-pick replays its result together with the spike's hand edits; the
renames and deletions it made are in the spike commit `77fb0ef9`. `no_twin.py` (A2) is out of scope (§4) and not ported.

## How to run (from `smartcontracts/evm`, foreground, one at a time)

```text
# a run's sizes, deploy gas and gas (test/merge/ holds adapters/*, T0Sel.sol = the tree's form)
runs/2026-11-04-ua-mtx-merge/measure.sh <run>
# the D runs: the merged-entry suite and the registry rows read views D moves (no module is built)
T0_SKIP="test/merge/MergedEntry.t.sol test/merge/T0GasReg.t.sol" runs/2026-11-04-ua-mtx-merge/measure.sh MD
# the stand-in: deploy rows only
python3 runs/2026-11-04-ua-mtx-merge/standin.py
T0_SKIP="test/merge/MergedEntry.t.sol test/merge/T0GasReg.t.sol test/merge/T0Gas.t.sol" runs/2026-11-04-ua-mtx-merge/measure.sh MD-reg
git checkout -- src/metatx/ERC20MetaTx.sol src/metatx/MetaTokenBase.sol
# mutants on M (one at a time, src restored from the M commit after each)
runs/2026-11-04-ua-mtx-merge/run_mutants.sh <M commit>
# the test recount on a scratch copy of the M tree (git archive of smartcontracts/evm at M, lib/ copied in)
runs/2026-11-04-ua-mtx-merge/run_red_skip.sh <copy> ../../scripts/capped
python3 runs/2026-11-04-ua-mtx-merge/red_skip_count.py <copy>
# the tables
python3 runs/2026-11-04-ua-mtx-merge/results.py
```

| File | What |
|---|---|
| `measure.sh` | `forge build src --sizes --json` → `sizes.py`; `FOUNDRY_TEST=test/merge forge test -vv` → `t0-<run>.txt`, `suites-<run>.txt` |
| `sizes.py` | `sizes-<run>.json`: runtime and init bytes; the wallets' runtime hash without the CBOR metadata (equal on every run) |
| `adapters/T0Deploy.t.sol` | deploy gas of every implementation and library, each its own CREATE2 transaction, `GovDeploy.t.sol`'s method; the factory frame once |
| `adapters/T0DeployL.t.sol` | the same for `TokenBodyLib` (L runs) |
| `adapters/T0Gas.t.sol`, `T0GasReg.t.sol` | the gas rows, `GovGas.t.sol`'s method; ABI-free, the calldata from `T0Sel` |
| `adapters/T0Sel.base.sol`, `T0Sel.merged.sol` | the same rows in the base form and in the merged form (copied to `test/merge/T0Sel.sol`) |
| `adapters/T0Digest.sol` | an EIP-712 digest in the salted domain (ERC-5267), for structs with no digest view |
| `merge_router.py`, `merge_zether_libs.py`, `merge_binding_views.py` | parts of M the spike had no code for (the router, the Zether libraries after CTR-ZTH-94, §2.3's view) |
| `lib_split.py`, `TokenBodyLib.sol.txt` | lever L |
| `lever3_delete.py` | lever D (ported from the spike; today's names; `factory()`, `hasRole`, `pendingOwner` and the views other contracts read stay) |
| `standin.py` | the regulated stand-in |
| `mutants.py`, `run_mutants.sh`, `mutants.txt` | the spike's eight mutants on M (anchors moved) and two new (R17, the Q2 cancel's lane) |
| `red_skip.py`, `run_red_skip.sh`, `red_skip_count.py`, `red_skip-passes.txt`, `red_skip.jsonl`, `red_skip-summary.txt` | the test recount on M (ported from the spike) |
| `results.py`, `results.txt` | the tables and the Q3 reading (`results.txt` = a written head and tail around `results.py`'s tables) |
| `sizes-<run>.json`, `t0-<run>.txt`, `suites-<run>.txt` | each run's figures and suite results (`<run>-reg` = with the stand-in) |
| `t1_mutants.py`, `run_t1_mutants.sh` | plan T1 step 6 on the `ua-mtx-merge` branch itself (not the scratch): the spike's eight with T1's anchors, then R17, the derived `UALedgerOff` guard, the cancel's nonce check, the cancel self-calling `cancelNonce`, the cancel's lane, `canon` binding `relayer` with its bit off, `inNativeSpace` replaced by `from >> 160 < 2`; each against `test/merge`; rows in `../2026-11-04-ua-mtx-merge-t1-mutants.txt` |
| `t2_mutants.py`, `run_t2_mutants.sh` | plan T2 step 6, as T1's: `_checkTo` skipped on `mtxPay`, the fee before the call (the relay router; receiver-pays' fee before the payment it is paid from), `mtxBatchTransfer`'s length check dropped, `relay` / `mtxRelayFee` reading `from` unsigned, a native receiver credited through the UA ledger, `PaymentSettled` on a merged path; each against `test/merge`; rows in `../2026-11-04-ua-mtx-merge-t2-mutants.txt` |
| `t3_mutants.py`, `run_t3_mutants.sh` | plan T3 step 6, as T2's (a mutant may edit two files): `IUALedger` asked of every leg in `mtxWrapOrder`, the hybrid cap skipped on it, `mtxUnwrapToUA` accepting a native receiver (the leg's receiver rule), `mtxWrap` moved onto `UAEnvelope`; each against `test/merge`; rows in `../2026-11-04-ua-mtx-merge-t3-mutants.txt` |
