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
