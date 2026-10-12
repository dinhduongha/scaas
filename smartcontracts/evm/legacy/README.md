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
  P1e rewrote into `OpenFactory`); not built. (The v1 line followed in P5: `p5/`.)
- `p3/`: the built `ZetherToken`, `ZetherMetaTx` and the old `IZetherToken` (384-byte statement header, own envelope,
  own underlying) with their tests (`ZetherToken.t`, `ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherGate.t` and the
  fixture), as they stood on `main` before P3 replaced them by the `*_ZETHER` kinds; not built. Nothing in the node or
  the e2e read them. `OpenFactoryV1` kept its `ZETHER` kind (mock-tested) until the v1 line moved (P5).
- `p4/`: the built `SubjectAccount` and `SubjectAccountFactory` (typed `OwnerCall`, own nonce, domain `SCaaS SubjectAccount`
  without salt) and their test `SubjectAccount.t.sol`, as they stood on `main` before P4 put `SmartKeyAccount` on
  `MetaTxBase` (CTR-ACC-10, CTR-ACC-11); and the built `MandateWallet` / `HederaMandateWallet` (typed `PayUnderMandate`,
  `RevokeMandate`, `OwnerCall`, no epoch, no salt) with `MandateWallet.t.sol`, `MandateWalletKat.t.sol` and the Hedera
  wallet test cut from `test/hedera/HederaMetaToken.t.sol` (CTR-ACC-06, CTR-ACC-07); not built. Clones and wallets
  deployed from them keep working with their own code.
  The backed-up `SubjectAccount.t.sol` reads `test/vectors/subject_account_create2.json`, which is now
  `smart_key_account_create2.json` (only its `note` differs); restore the old name to run it.
- `p5/`: the v1 line as it stood on `main` before P5 moved the node and clientkeys onto the token tree (E1; owner:
  backup, not delete): `MetaToken`, `ERC20MetaTxV1`, `IERC20MetaTxV1`, `IERC20PaymentV1`, `HederaMetaToken`,
  `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1`, `MetaTxDex`, `SCaaSDexV1`; their tests (`MetaToken.t`,
  `MetaTxDex.t`, `MetaTxKat.t`, `OpenFactoryV1.t`, `SCaaSDexV1.t`, `SCaaSDexV1Invariant.t`, `MetaApprove.t`, `Erc1271.t`,
  `Invariants.t`, `ContractOnlyAllowance.t`, `MetaTxGas.t`, `hedera/HederaMetaToken.t`, the v1 Hedera KAT test, the
  `Fixtures` helper) and the tests cut from live files (`SmartKeyAccountV1.t`, `FeePolicyV1.t`, `MockZetherImpl`); the
  vectors `metatx_v1_kat.json`, `dex_kat.json` and the v1 `hedera_kat.json`; the v1 Hedera smoke script; `MetaTxLib`
  with its `LegacyMetaTransaction` and the v1/v2 gas table `MetaTxGasV2.t` as they were. The node's and clientkeys'
  v1 modules are in `scaas-node/legacy/p5/` and `clients/clientkeys/legacy/p5/`. Nothing deployed: every chain is a
  test chain and is redeployed.
- `ua3/`: the Zether-era account registry as it stood on `main` before UA-3 re-pointed Zether to the UA registry
  (CTR-UA-22; owner: backup, not delete): `src/registry/UniversalAccountRegistry.sol`, `IUniversalAccountRegistry.sol`
  (`UA = keccak256(encodedY)`, eight `AuthScheme`s, PoP bound to `msg.sender`, `links`/`link_eth`, `keyOf`),
  `src/common/AuthScheme.sol`, and their tests `test/zether/UniversalAccountRegistry.t.sol`, `test/AuthScheme.t.sol`;
  not built. `src/common/MultiSig.sol` stays in `src/` (accounts.md §1.13).
