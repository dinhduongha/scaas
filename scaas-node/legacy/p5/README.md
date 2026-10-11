# legacy/p5 — reference only, not built

The node's v1-line modules as they stood on `main` before P5 moved the node onto the token tree (owner: backup, not
delete): `abi.rs` (the v1 `MetaTransaction` with `to`/`value`, `IMetaToken`, `IMetaTxDex`, v1 `IOpenFactory`),
`metatx.rs` (its wire form and unsalted digest), `dex.rs` and `dex/venue.rs` (the order book in front of `SCaaSDexV1`:
DEX-domain `Order`, `checkOrder`, `settle(Match[])`, allowances to the DEX), and `e2e.rs` (the e2e suite that drove
them on the v1 deploy). Cargo builds only `src/` and `tests/`; nothing imports
this directory. The contracts they spoke to are in `smartcontracts/evm/legacy/p5/`; their vectors
(`metatx_v1_kat.json`, `dex_kat.json`) too.
