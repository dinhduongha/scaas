# scaas-node: superseded by typed-signing N1

Not compiled. The EVM job API before the named entries: hex `data` / `calldata` jobs (`metatx` with `struct = call`, `call`
with `calldata`), the `entry` jobs (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap`), `Leg` / `ExchangeLeg` with encoded
orders, the flat `cancelOrderDigest(orderHash)`, the `MetaTransfer`-paid `relay` / `uaRelay`, the chain-view dedup key
(`mtxDigest`, `digest_of`) and the published-allowlist intake (`Table`, `self_call_ok`). The live code is
`src/typed.rs` and the files of the same name in `src/`. `guard.rs` holds the old `CALL_TABLE` rows. The wallet's four flat builders
(`mtxPayUnderMandate`, `mtxRevoke`, `mtxExecuteAsOwner`, `mtxExecuteAsOwnerRaw`) are not superseded: they stay as rows of `typed.rs`,
beside the named entries (owner 2026-11-01).
