# legacy/p5 — reference only, not built

`evm.js` as it stood before P5 (owner: backup, not delete): its `checkPayment` checked the v1 token's unsalted
`MetaTransaction{from, to, value, data = pay(bytes32), …}` (vector `metatx_v1_kat.json`, now in
`smartcontracts/evm/legacy/p5/test/vectors/`). Not exported, not tested, not bundled.
