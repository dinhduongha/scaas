# legacy/ua-mtx-merge — reference only, not built

The files as they stood at local tag `ref/pre-ua-mtx-merge` (owner: backup, not delete; plan MD-4), before T12 moved the
prover's named relayed entries onto the merged ones (CTR-MTX-30: one signed entry per operation, `mtx<Op>(UAEnvelope, …,
UASig)` over `UA<Op>`; R35: a relayed proof on a merged entry binds `SCAAS-ZETHER-UA-ENVELOPE-V1`):

- `src/envelope.rs`: `named_transfer_single_call`, `named_transfer_multi_call`, `named_unshield_call`,
  `named_unshield_unwrap_call` on the address `Envelope` (`address from`) and a packed `bytes sig`, the entries T4 retired.
  The address `envelope_binding` (`SCAAS-ZETHER-ENVELOPE-V1`) stays in the build for `executeMetaTransaction`.
- `src/typed.rs`: `OPS` with the 47 Zether rows of the 112-row `typed_ops.json` (the address `Burn`, `Unwrap`, `Shield`,
  `RollOver`, `Zether*`, `ReceiverFee`, `RelayFee`, `WrapOrder`, cancel rows, the unordered `UACancelNonce`), and
  `named_call` on the address ops (`ZetherTransferSingle`, …, `ZetherUnshieldUnwrap`).
- `tests/typed_ops.rs`: the test over those rows (`NOT_ZETHER` of the 112-row file).

Not compiled, not tested.
