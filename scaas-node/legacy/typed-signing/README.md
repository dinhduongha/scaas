# scaas-node: superseded by typed-signing N1

Not compiled. The EVM job API before the named entries: hex `data` / `calldata` jobs (`metatx` with `struct = call`, `call`
with `calldata`), the `entry` jobs (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap`), `Leg` / `ExchangeLeg` with encoded
orders, the flat `cancelOrderDigest(orderHash)`, the `MetaTransfer`-paid `relay` / `uaRelay`, the chain-view dedup key
(`mtxDigest`, `digest_of`) and the published-allowlist intake (`Table`, `self_call_ok`). The live code is
`src/typed.rs` and the files of the same name in `src/`. `guard.rs` holds the old `CALL_TABLE` rows, including the wallets'
pre-named `mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)` and `mtxRevoke(address,uint64,uint256,bytes)`.
