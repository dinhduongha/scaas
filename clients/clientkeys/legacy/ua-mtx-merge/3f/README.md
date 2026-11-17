# legacy/ua-mtx-merge/3f — reference only, not built

The files as they stood at b70efd83 (before T46, PQZ verifier mode group 3f), before T46 moved clientkeys onto the PQZ
entries that take the verdict last (`PqzSignedVerdict`, spec 2026-11-06-attested-verify §5.3) and added the router's three
verifier ops:

- `src/evm.js`: the six signed PQZ entries (`UAPqzTransferSingle`, `…SingleCompact`, `UAPqzTransfer`, `…Compact`,
  `UAPqzUnshield`, `UAPqzUnshieldUnwrap`) ending at `UASig auth`, with no `PqzSignedVerdict`; the router table without
  `UAPqzSetVerifier`, `UAPqzCancelVerifier`, `UAPqzRevokeVerifier`.
- `scripts/typed-ops-vectors.mjs`, `scripts/typed-ops-expected.mjs`: the generator and decoder of that 83-row
  `typed_ops.json` (its copy: `smartcontracts/vectors/typed/legacy/ua-mtx-merge/3f/typed_ops.json`).
- `test/typed-ops.test.js`: the counts and the calldata checks T46 moves.

Not exported, not tested, not bundled.
