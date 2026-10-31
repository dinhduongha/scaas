# legacy/typed-signing — reference only, not built

The raw portable-record digests and the EIP-191 `personal_sign` native msig member path as they stood before
typed-signing P7 (owner: backup, not delete): `ua.go.txt` and `ua_test.go.txt`, the whole files as of tag `ref/pre-typed-signing`.
Removed or changed there: PortablePopDigest, RegistrationDigest(portable, pqzPopHash), KemRecordDigest (raw), PqzKeyDigest / PqzKeyRecordDigest (raw), PqzRegMessage(ua, …), PersonalSignDigest, KemRecordTag, PqzKeyRecordTag.
typed-signing P7 replaced them with the typed EIP-712 records under the name + version domain
(`EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"), TS-D1 … TS-D4), as clientkeys `src/ua.js` (P1) and
ua-rs `src/ua8.rs` (P2). Stored as `.txt` so the project does not build them.
