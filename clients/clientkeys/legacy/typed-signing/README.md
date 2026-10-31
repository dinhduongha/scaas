# legacy/typed-signing — reference only, not built

The raw portable digests as they stood before the typed-signing round (owner 2026-10-31: typed EIP-712 for the portable
records under `EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"); native EOA `msig` members sign the
typed digest, `eth_signTypedData_v4`, instead of `personal_sign`): `ua-portable-raw.js` (`portablePopDigest`, the raw
`registrationDigest` / `kemRecordDigest` / `pqzKeyDigest` / `pqzKeyRecordDigest`, `KEM_RECORD_TAG`, `PQZ_KEY_RECORD_TAG`,
`personalSignDigest`; formerly in `src/ua.js`). The old vector files are in `smartcontracts/vectors/ua/legacy/typed-signing/`;
`ref/pre-typed-signing` holds the same bytes. Not exported, not bundled; load-bearing for one negative (see the file
header); `test/ua-groups.test.js` read the raw PoP until typed-signing P2 regenerated `groups.json` on the typed records.
