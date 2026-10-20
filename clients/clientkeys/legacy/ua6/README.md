# legacy/ua6 — reference only, not built

The bn254 Zether path as it stood before UA-6 (owner: backup, not delete): `zether.js` (both curves, `authRef` PoP),
`zether.test.js`, and the pinned vectors it read (`vectors/r33_keys.json` with the bn254 section, `schnorr_bn254.json`).
bn254 / kind 0x0140 left the contracts in UA-6; `src/zether.js` is BLS12-381 only. Not exported, not tested, not bundled.
