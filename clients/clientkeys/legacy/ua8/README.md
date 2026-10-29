# legacy/ua8 — reference only, not built

The chain-bound proof of possession as it stood before UA-8 (owner: backup, not delete): `ua-pop-v1.js` (`popDigestV1`,
`holderPopMessageV1`, `pqzRegMessageV1`, `zetherPopV1`; formerly `popDigest`, `holderPopMessage`, `pqzRegMessage` of
`src/ua.js` and `zetherPop` of `src/zether.js`) and the four test files that checked them (`ua.test.js`, `ua-sig.test.js`,
`pq-sig.test.js`, `zether.test.js`, as of `ref/pre-ua8`). UA-8 P1 replaced them with the portable digests. The old vector
files are in `smartcontracts/vectors/ua/legacy/`. Not exported, not bundled. Two readers: `scripts/ua-sig-vectors.mjs` signs
`holderPopMessageV1` for the `chain-bound-pop` negatives (a pre-UA-8 PoP must be refused), and `test/ua-groups.test.js`
reads `popDigestV1` until `groups.json` is regenerated on the portable PoP (UA-8 A2).
