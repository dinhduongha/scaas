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

## 3g (versioned PQZ keys, ua-mtx-merge T55), under `3g/`

As they stood at 937b454f (before T55), before the node moved to the versioned PQZ API: `typed.rs` (the PQZ args structs without
`keyVersion`, one `UARollOver` row on Zether and PQZ, `UAPrepareAcc` without `keyVersion`, `setPqzKey` / `storePqzPop` without a
version), `abi.rs` (the unversioned registry calls), `guard.rs` and `submit.rs` (no intake pending check, no PQZ key-version
refusals, the old row counts), `indexer.rs` (no key-version events), `e2e.rs`, `e2e_ua8.rs` (the unversioned registry ABI). Not
built.

## 3f (PQZ verifier mode, ua-mtx-merge T47), under `3f/`

As they stood at 134560c1, before the node moved to the PQZ entries' trailing `PqzSignedVerdict` (spec 2026-11-06-attested-verify
§11.1): `typed.rs` (the six PQZ debit rows without the verdict, no `pqz_verdict` sub-object, no router verifier rows), `submit.rs`
(no verdict fill, no verifier refusals), `guard.rs` (no shield switch, the old counts), `gateway.rs`, `adapters/evm.rs` (no verdict
fill), `indexer.rs` (no `PqzVerified` join, no verifier alerts), `abi.rs` (no verdict ABI), `config.rs` (no `[pqz_verifier]`). Not
built.
Group 3h (T59, spec 2026-11-06-pqz-proof-path §3.2), under `3h/`, as they stood at e35d1d16: `typed.rs` (the three PQZ args
structs without `ownTag`), `e2e.rs` (its op 1 args without `ownTag`). Not built.
Group 3h (T63, spec §10, NODE-JOB-24), under `3h/`, as they stood at 77e9ddf4 (T62's tip): `submit.rs` (a PQZ debit over the lane's
cap refused like any job, no `proofStore()` read), `indexer.rs` (no `ProofStoreSet` row or alert). Not built.
Plan T83 (owner 2026-11-09, `payNo` as `bytes32`), under `t83/`, as they stood at 32d73310: `abi.rs` (`PayMeta` with `string
payNo`, `PaymentMeta(payId, string payNo, schema, body)`, `PayNoTooLong`), `metatx.rs` (`meta_pay_id` v2, `PAY_NO_MAX`),
`typed.rs` (a text `meta.payNo`, `PAY_NO_TOO_LONG`, `max_pay_meta_bytes` over `payNo + body`), `indexer.rs` (`pay_no` text).
Not built.
