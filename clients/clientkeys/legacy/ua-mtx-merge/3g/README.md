# legacy/ua-mtx-merge/3g — reference only, not built

The files as they stood at 192587dd (the T53 tip, versioned PQZ keys group 3g), before T54 moved clientkeys onto the
versioned PQZ token API:

- `src/evm.js`: `PqzTransferArgs` / `PqzMultiArgs` / `PqzBurnArgs` without `keyVersion`, `UAPrepareAcc` without
  `keyVersion`, one `UARollOver(bytes32 ua,uint256 n)` row on the Zether and the PQZ kinds.
- `scripts/typed-ops-vectors.mjs`: the generator of that `typed_ops.json` (its copy:
  `smartcontracts/vectors/typed/legacy/ua-mtx-merge/3g/typed_ops.json`).
- `test/typed-ops.test.js`: the pins and op counts T54 moves.

`portable.json` and `pq_kat.json` gained tables only (`pqzKeyVersions`, `pqzKeyVersionNegatives`, `pqzSeeds`, two typed
types); their earlier rows are unchanged, so they have no copy here.

Not exported, not tested, not bundled.
