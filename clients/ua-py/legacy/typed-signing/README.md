# legacy/typed-signing — reference only, not built

The raw portable-record digests and the EIP-191 `personal_sign` native msig member path as they stood before
typed-signing P7 (owner: backup, not delete): `__init__.py.txt` and `test_vectors.py.txt`, the whole files as of tag `ref/pre-typed-signing`.
Removed or changed there: portable_pop_digest, registration_digest(portable, pqz_pop_hash), kem_record_digest (raw), pqz_key_digest / pqz_key_record_digest (raw), pqz_reg_message(ua, …), personal_sign_digest, KEM_RECORD_TAG, PQZ_KEY_RECORD_TAG.
typed-signing P7 replaced them with the typed EIP-712 records under the name + version domain
(`EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"), TS-D1 … TS-D4), as clientkeys `src/ua.js` (P1) and
ua-rs `src/ua8.rs` (P2). Stored as `.txt` so the project does not build them.
