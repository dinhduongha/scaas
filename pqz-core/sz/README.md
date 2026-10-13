# sz — Schwartz–Zippel challenge trace (P6-SZ protocol review)

A small diagnostic harness for the ongoing `tbox` protocol review tracked as **P6-SZ**. It instruments the
evaluation-equation Schwartz–Zippel step of `lazer/lnp-tbox.c` and records, for one honest proof, the Fiat–Shamir
challenge vectors derived from the transcript for each accumulator. It is a read-only observability tool: it only
prints what the honest prover samples.

## Build and run

```sh
../scripts/capped sz/build.sh     # builds build/sz/sz_trace (with -DPQZ_SZ_TRACE) and runs it
```

The trace hook in `lnp-tbox.c` is guarded by `#ifdef PQZ_SZ_TRACE`. The normal `./build.sh native|wasm|all` never
defines it, so production library objects are byte-for-byte unaffected (the symbol scan and KAT confirm this).

## Files

- `sz_trace.c` — registers the trace callback, runs one honest R_REG prove, groups the recorded challenge vectors
  by transcript domain separator and reports whether the per-accumulator vectors are distinct.
- `build.sh` — compiles the kept LaZer code + rewritten layers with `-DPQZ_SZ_TRACE` and links the harness.

The analysis, findings and any follow-up are tracked out-of-tree under the review for P6-SZ (not in the public
repo while the review is open).
