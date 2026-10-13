# sz and l2dom: the LaZer tbox soundness fixes (proofSystemId v2)

Two Schwartz–Zippel findings in LaZer's `tbox` (`lazer/lnp-tbox.c`), confirmed by the LaZer maintainers and public as
[lazer-crypto/lazer#24](https://github.com/lazer-crypto/lazer/issues/24) and
[#25](https://github.com/lazer-crypto/lazer/issues/25). Both are fixed in the fork (`PQZ (P6-SZ)` / `PQZ (P6-L2)`
comments); together they change the transcript, hence `proofSystemId` v2 (`src/pqz.h`, pq-zether.md §8).

- **P6-SZ (#24).** `__schwartz_zippel_accumulate2` drew one challenge pair and reused it for all λ/2 accumulator pairs
  (2 independent tests instead of λ = 4). Fix: the full λ × M matrix, rows 2i / 2i+1 for pair i.
- **P6-L2 (#25).** `__schwartz_zippel_accumulate_l2` gave every exact-ℓ2 equation the same domain, so only the sum of
  the block norms was checked. Fix: `dom + i`.

## Harnesses

- `sz/sz_trace.c`, `sz/build.sh`: one honest R_REG prove with the `-DPQZ_SZ_TRACE` hook in `lnp-tbox.c`; reports, per
  transcript domain, whether the four evaluation-step challenge rows are distinct. Exit 0 only if they are.
- `l2dom/l2dom_poc.c` (R_REG), `l2dom/l2dom_tx.c` (R_TX, a sender with a colluding recipient), `l2dom/build.sh`: the
  pooled-slack cheating prover (`set_upsilon` in `src/pqz_rel.c` under `-DPQZ_L2DOM_POC`): blocks above their own ℓ2
  bound, the sum within the pooled budget. `build.sh` builds it twice: on a copy of `lnp-tbox.c` with the P6-L2 fix
  undone (control: its verifier must accept the cheating proofs) and on the tree (the production `libpqz.a` must reject
  them).
- `../check_tbox_fixes.sh`: runs both and exits 1 unless both fixes are in place (run by `rel3/relfix.sh`).

The trace hook and the PoC are compiled only with `-DPQZ_SZ_TRACE` / `-DPQZ_L2DOM_POC`; `./build.sh native|wasm|all`
defines neither, so the library objects are unchanged by them.

```sh
../scripts/capped sh -c './build.sh native && ./check_tbox_fixes.sh'
```
