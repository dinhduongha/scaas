# legacy/typed-signing — reference only, not built

The raw portable digests as they stood before the typed-signing round (owner 2026-10-31: typed EIP-712 for the portable
records under `EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"); native EOA `msig` members sign the
typed digest, `eth_signTypedData_v4`, instead of `personal_sign`): `ua-portable-raw.js` (`portablePopDigest`, the raw
`registrationDigest` / `kemRecordDigest` / `pqzKeyDigest` / `pqzKeyRecordDigest`, `KEM_RECORD_TAG`, `PQZ_KEY_RECORD_TAG`,
`personalSignDigest`; formerly in `src/ua.js`). The old vector files are in `smartcontracts/vectors/ua/legacy/typed-signing/`;
`ref/pre-typed-signing` holds the same bytes. Not exported, not bundled; load-bearing for one negative (see the file
header); `test/ua-groups.test.js` read the raw PoP until typed-signing P2 regenerated `groups.json` on the typed records.

`evm-pre-named.js` (typed-signing C1): what `src/evm.js` built before the named typed entries, verbatim: `ownerCallTypedData` and
the `MetaTransaction` `checkOwnerCall`, `ReceiverFee` over `paymentDigest` and its `checkReceiverFee`, `orderCancelTypedData`
(`CancelOrder(bytes32 orderHash)`) and its `checkCancel`, the `MetaTransfer` `buildRelayFee`. Since C6 nothing on the branch hashes
`ReceiverFee` over `paymentDigest` or `CancelOrder(bytes32)`: `scripts/ua-sig-vectors.mjs` builds `metatx3.json` / `uatrade_kat.json`
on the nested structs. `test/evm.test.js` still loads the generic `ownerCallTypedData` / `checkOwnerCall` for the wallets' `mtxExecute` KAT.

`zether-owner-auth.js` (typed-signing C3): `zetherOwnerAuth`, the `abi.encode(bytes(""), sig)` of an owner op before
`mtxRollOverSigned` / `mtxSetRollOverMode` took `UASig` (`zetherOwnerSig`).
