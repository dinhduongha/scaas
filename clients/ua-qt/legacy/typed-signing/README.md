# legacy/typed-signing — reference only, not built

The raw portable-record digests and the EIP-191 `personal_sign` native msig member path as they stood before typed-signing P6
(owner: backup, not delete): `tst_ua.qml.txt`, `ua_kinds.rs.txt`, as of tag `ref/pre-typed-signing`. typed-signing P6 moved this
wrapper onto the typed EIP-712 records of ua-rs (TS-D1 … TS-D6): removed `kem_record_tag`, `pqz_key_record_tag`,
`portable_pop_digest` and `personal_sign_digest`; `registration_digest` / `pqz_key_record_digest` take the record's words,
`pqz_reg_message` takes the registering kind first, `HolderPop.portable_pop_digest` became `portable_record_digest`; added
`portable_domain_separator`, `kem_record_hash` and `portable_record_digest`.
Names above are the Rust ones (camelCase in the C++ / QML / Dart API).
Stored as `.txt` so the project does not build them; the Rust files build only against the ua-rs of `ref/pre-typed-signing`
(the raw digests are in `clients/ua-rs/legacy/typed-signing/portable_raw.rs`).
