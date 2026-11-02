# legacy/typed-signing — reference only, not built

The node code the owner's explicit-parameter rule (2026-10-31) replaced (owner: backup, not delete). Cargo builds only `src/` and `tests/`; nothing imports this directory.

## EVM, superseded by typed-signing N1

Not compiled. The EVM job API before the named entries: hex `data` / `calldata` jobs (`metatx` with `struct = call`, `call`
with `calldata`), the `entry` jobs (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap`), `Leg` / `ExchangeLeg` with encoded
orders, the flat `cancelOrderDigest(orderHash)`, the `MetaTransfer`-paid `relay` / `uaRelay`, the chain-view dedup key
(`mtxDigest`, `digest_of`) and the published-allowlist intake (`Table`, `self_call_ok`). The live code is
`src/typed.rs` and the files of the same name in `src/`. `guard.rs` holds the old `CALL_TABLE` rows. The wallet's four flat builders
(`mtxPayUnderMandate`, `mtxRevoke`, `mtxExecuteAsOwner`, `mtxExecuteAsOwnerRaw`) are not superseded: they stay as rows of `typed.rs`,
beside the named entries (owner 2026-11-01).

## Soroban, superseded by ua8-soroban N2

`soroban_hex_jobs.rs`: the Soroban `ua_metatx` job with `op.args` as hex XDR, `op.extra.call` as `InvokeContractArgs` XDR on `signed_op` and the relay fee, and the tests over those forms.
