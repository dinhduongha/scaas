# legacy/ua-mtx-merge — reference only, not built

The node files as they stood at local tag `ref/pre-ua-mtx-merge` (plan `2026-11-04-ua-mtx-merge`, MD-4), before T14 moved the
node onto the merged EVM entries (CTR-MTX-30: one signed `mtx<Op>(UAEnvelope, …, UASig)` per operation). Cargo builds only
`src/` and `tests/`; nothing imports this directory (backup, not delete).

What these copies hold and the live code no longer does:

- `typed.rs`: the `TYPED` rows of the address forms of merged operations (`mtxBurn(Envelope, …, bytes)`, `mtxUnwrap`, the
  `Zether*` / `Pqz*` address rows, `ReceiverFee`, `RelayFee`, `WrapOrder`, `CancelOrder`, `CancelWrapOrder`, the 19 router
  address rows, the six `MandateWallet` address rows) beside the `ua<Op>` rows under their old entry names; the `PLAIN` rows
  `mtxExecuteAsOwnerRaw`, the flat `mtxPayUnderMandate` and `mtxRevoke` (MD-11 (a)); `mtxExecuteAsOwner` on the wallet.
- `guard.rs`: the wallet's flat-builder selector pins, the `uaInvalidateNonces` / `uaRelay` selectors, the registry gate on
  every `ua*` row.
- `abi.rs`: `IUALedger.uaExecute` (`bytes auth`), `uaExecuteTransfer`, `uaPayMeta`, `uaNonce`, `IMtxRelayFee.relay` on
  addresses beside `uaRelay`, `IMandateWallet.PayeeNotAllowed(address)`.
- `dex.rs`, `dex/venue.rs` (T17): the book on `TradeOrder` legs only (shape 0 for a SCaaS sell token too), the token-side
  `TradeOrder` hash and the address `CancelOrder`, the address `mtxCancelOrder` / `mtxInvalidateNonces` jobs on a token and
  the token's address `OrderCancelled` / `NoncesInvalidated` read by the watcher.
- `metatx.rs`: `UaMtx` relayed as `uaExecute` / `uaExecuteTransfer` / `uaPayMeta`.
- `submit.rs`, `chain.rs`: the `ua` flag choosing `uaNonce` / `mtxNonce(address)`, the job decoder that relays an address
  `MetaTransfer` on a token.
- `gateway.rs` (T15): `POST /v1/metatx` building the address `mtxExecuteTransfer(MetaTransfer, bytes)` for a token, and
  `POST /v1/op` refusing every merged entry `FEATURE_UNSUPPORTED` (no `/v1/ua-metatx` door).
- `mesh/` (T16): the mesh's EVM body on the address structs (`evm.meta_tx` = `MetaTransaction` / `MetaTransfer`, `signature`
  as `bytes`, intent id the address digest, any contract) in `digest.rs`, `accept.rs`'s tests on that body, and
  `mesh_vectors.rs` with its file `mesh-envelope-v1.2.json` (case 3a the address `metatransfer_kat.json`).
- `tests/e2e.rs`, `tests/e2e_hedera.rs`, `adapters/hedera.rs` (T18): the anvil e2e on the address forms (`metatx` jobs with an
  address `MetaTransfer` / `MetaTransaction` and a `bytes` signature, `POST /v1/metatx` on a token, `TradeOrder` legs for a SCaaS
  sell token, the address cancel / invalidate digests, the flat wallet rows, `PaymentSettled` asserted on every payment), and
  the Hedera vector reader on the address `MetaTransfer` (`hedera_kat.json` before T8: 20-byte long-zero `from`, no `type_hash`).

## 3e (pay-meta-tax, ua-mtx-merge T42), under `3e/`

As they stood at f2cc725d (the T43 tip), before the node moved to the pay entries' `PayMeta`: `abi.rs` (`mtxPayMeta` on ids and
addresses, `PaymentMeta(bytes32, bytes)`, the eight-argument `relay`), `metatx.rs` (`meta_pay_id(salt, meta)`, `pay_meta_calldata`,
the `payLane` / nonce-0 shape check), `typed.rs` (the receiver-fee and mandate rows without `PayMeta`, `UARelayFee` without
`batch` / `nonce`), `guard.rs` (`mtxPay` in `NOT_ROWS`, the struct job's `mtxPayMeta`, the old counts), `submit.rs` (the `salt` +
hex `meta` struct job), `indexer.rs` (`meta` hex on the joined row), `gateway.rs`, `e2e.rs`. Not built.
