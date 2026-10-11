# legacy/ — reference only, not built, not tested

Copies of the token code as it stood at tag `ref/pre-token-tree`, the last commit before P1 of the token tree
(`docs/history/specs/2026-10-08-token-tree-design.md`): the v1 line (`ERC20MetaTx` mixin, `MetaToken`,
`HederaMetaToken`, v1 `OpenFactory`, `MetaTxDex`), the v2 line (`MetaTxCore`, `MetaTokenBase`, the three tiers, their
Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`, plus the shared files they import
(`MetaTxLib`, `FeePolicy`, `SigLib`, the factory interfaces, `HederaAccountAuth`).

- **Not compiled.** Foundry builds only `src/`, `test/` and `script/` (`foundry.toml`); nothing imports this tree.
- **Not tested, not maintained, never deployed.** Relative imports point at their old neighbours and may not resolve.
- The authoritative copy is the tag: `git show ref/pre-token-tree:smartcontracts/evm/src/<path>`.
- Why it exists: owner decision of 2026-10-08 (CTR-MTX-07; TODO.md §00, P1 start checklist).
- `p1e/`: `OpenFactoryV2`, `IOpenFactoryV2`, `IFactoryTokenV2` as they stood on `main` before P1e (the factory v2 that
  P1e rewrote into `OpenFactory`); not built. (The v1 line follows into `legacy/` when node/clientkeys stop using it, P5, E1.)
- `p3/`: the built `ZetherToken`, `ZetherMetaTx` and the old `IZetherToken` (384-byte statement header, own envelope,
  own underlying) with their tests (`ZetherToken.t`, `ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherGate.t` and the
  fixture), as they stood on `main` before P3 replaced them by the `*_ZETHER` kinds; not built. Nothing in the node or
  the e2e read them. `OpenFactoryV1` keeps its `ZETHER` kind (mock-tested) until the v1 line moves (P5).
- `p4/`: the built `SubjectAccount` and `SubjectAccountFactory` (typed `OwnerCall`, own nonce, domain `SCaaS SubjectAccount`
  without salt) and their test `SubjectAccount.t.sol`, as they stood on `main` before P4 put `SmartKeyAccount` on
  `MetaTxBase` (CTR-ACC-10, CTR-ACC-11); not built. Clones deployed from them keep working with their own code.
