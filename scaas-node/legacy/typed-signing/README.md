# legacy/typed-signing — reference only, not built

The node code the owner's explicit-parameter rule (2026-10-31) replaced (owner: backup, not delete). `soroban_hex_jobs.rs`: the
Soroban `ua_metatx` job with `op.args` as hex XDR, `op.extra.call` as `InvokeContractArgs` XDR on `signed_op` and the relay fee, and
the tests over those forms. Cargo builds only `src/` and `tests/`; nothing imports this directory.
