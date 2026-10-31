# legacy/ — reference only, not built, not tested

Copies of the token code as it stood at tag `ref/pre-token-tree`, the last commit before P1 of the token tree
(`docs/history/specs/2026-10-08-token-tree-design.md`): the v1 line (`ERC20MetaTx` mixin, `MetaToken`,
`HederaMetaToken`, v1 `OpenFactory`, `MetaTxDex`), the v2 line (`MetaTxCore`, `MetaTokenBase`, the three tiers, their
Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`, plus the shared files they import
(`MetaTxLib`, `FeePolicy`, `SigLib`, the factory interfaces, `HederaAccountAuth`).

- **Not compiled.** Foundry builds only `src/`, `test/` and `script/` (`foundry.toml`); nothing imports this tree.
- **Not tested, not maintained, never deployed.** Relative imports point at their old neighbours and may not resolve.
- The authoritative copy is the tag: `git show ref/pre-token-tree:smartcontracts/evm/src/<path>`.
- Why it exists: owner decision of 2026-10-08 (CTR-MTX-07; COMPLETED.md "From TODO.md" §00, P1 start checklist; formerly TODO.md).
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
- `ua6/`: the UA registry and its consumers as they stood on `main` before UA-6 Task 2 removed `authRef`
  (CTR-UA-30 Change 2026-10-20; spec `docs/superpowers/specs/2026-10-20-ua6-encryption-key-attributes.md`; owner:
  backup, not delete): `src/ua/UARegistry.sol`, `IUARegistry.sol`, `UAKinds.sol` (`register(kind, keyData, pop,
  authRef, authPop)`, `_authRef`, `_checkAuthRef`, `_checkPqzAuthRef`, `_coSign`, `PURPOSE_AUTHREF`, error `UAAuthRef`,
  `pqz-mlwe` 0x0142 as a stored kind), `src/pqz/PqzLib.sol` (the PQZ account as a `pqz-mlwe` UA, authorized by its
  `authRef` through `requireZetherAuthorized`), and the tests with the `authRef` cases: `test/ua/UARegistry.t.sol`
  (T-REG-3b), `UARegistryZether.t.sol` (native / derived / `msig` / same-curve-BLS `authRef`), `UARegistryPq.t.sol`
  (the `pqz-mlwe` `authRef` rule), `test/pqz/UAPqzVerifier.t.sol` and `helpers/PqzRegistryBase.sol` (the `pqz-mlwe`
  registration), `test/zether/ZetherAuthRef.t.sol` (moved, not copied); not built. UA-6 Task 4 (U8–U10, CTR-ZTH-32)
  added the whole bn254 Zether line and the `authSig` path as they stood before it: `src/zether/` (`ZetherVerifier.sol`
  with `ZetherBn254Curve` and the three bn254 verifier contracts, `ZetherLib.sol` with `AUTH_TAG` and the
  `requireZetherAuthorized` calls, `ZetherLayer.sol` / `IZetherToken.sol` / `UnderlyingZetherToken.sol` /
  `NoUnderlyingZetherToken.sol` with the `authSig` argument, `ZetherTypes.sol` with `KIND_ZETHER_BN254` /
  `TAG_ZETHER_BN254`, `IZetherVerifier.sol`), `src/ua/verifiers/PairingVerifiers.sol` (`ZetherSchnorrBn254Verifier`),
  `script/DeployBase.sol` and `script/ZetherE2E.s.sol` (the bn254 deploy steps, versions 1 bn254 / 2 BLS12-381),
  `scripts/e2e-zether.sh` (the bn254 / `authRef` e2e), and every `test/zether/` file it cut bn254 suites from (the
  fixture with `useBls`, the bn254 KATs, S3 vector and prover-cross suites, the bn254 gas rows). The registry side
  (kind 0x0140, slot 12, `requireZetherAuthorized`) is in the pre-UA-6 `src/ua/` copies above. The vector JSON
  (`test/vectors/zether/*bn254*`, the 0x0140 rows of `../vectors/ua/kinds.json`) stays in place until UA-6 Task 8.
- `ua8/`: the UA registry as it stood on `main` (`ref/pre-ua8`) before UA-8 made registrations portable (plan
  `docs/superpowers/plans/2026-10-30-ua8-portable-registrations.md`; owner: backup, not delete): `src/ua/UARegistry.sol`,
  `IUARegistry.sol`, `UAKinds.sol` (`register(kind, keyData, pop, pqzKey, pqzPop)` with the chain-bound `popDigest`).
  UA-8 Task A5 (the portable `register`) added, as they stood at commit `e8a6a711`, the tests built on the chain-bound
  PoP (verbatim backups; they do not resolve from here): `test/ua/UARegistryBase.sol` (`_pop` over `popDigest`),
  `UARegistry.t.sol` (T-CHAIN: a PoP of one registry refused on another; T-REG-3b: `UAKindDisabled(0x0142)`),
  `UARegistryVectors.t.sol` / `UARegistryPq.t.sol` (`popOther` refused), `UARegistryUA6.t.sol` /
  `UARegistryPqzBound.t.sol` (R_REG and the holder PoP over `popDigest(ua, h)`, every PQZ key claimed),
  `UARegistryGroups.t.sol` (PoPs re-signed per registry), `verifiers/EccVerifiers.t.sol` /
  `verifiers/PairingVerifiers.t.sol` (context-bound PoP digests), `test/pqz/UAPqzVerifier.t.sol` and
  `helpers/PqzRegistryBase.sol` (R_REG over `popDigest`), `test/zether/ZetherS3Vectors.t.sol` (`test_s3PopRegisters`
  at the vector's registry address); not built.
- `metatx-v1/`: the token meta-tx pipeline before the metatx split (spec
  `docs/superpowers/specs/2026-10-27-metatx-split-design.md`; owner: backup, not delete), taken from `main` commit
  `f50d18a4` (`src/metatx/` identical to the branch base `0c191232`): `src/metatx/ERC20MetaTx.sol`, `MetaTokenBase.sol`,
  `MetaTxBase.sol` whole. Superseded there by `MtxPipelineLib` (Tasks 2–4): `MetaTxBase._checkCall` / `_checkIntent`
  (still the wallets' path, now on the library's internals), `ERC20MetaTx._chargeFee` / `_callFee` (the fee after the
  call; now before it, owner 2026-10-27), `_checkTransfer`, `_checkUATransfer`, `_uaAuthorize`,
  `_requireNativeUASignature`, and the Hedera overrides of `MetaTokenBase` (`_requireValidSignature`,
  `_requireNativeUASignature`, `_erc1271Gas`); the trade, cancel, invalidate and receiver-fee signatures now go through
  `MtxPipelineLib.requireSignature` / `authorize`. Not built.
- `dex-round/`: the DEX before the DEX round (spec `docs/superpowers/specs/2026-10-30-dex-round-design.md`, DX1; owner:
  backup, not delete), taken from `main` commit `c2cfc223`: `TradeLib.sol`, `SCaaSDex.sol`, `ISCaaSDex.sol` whole, and
  `FloorTests.txt` (`test_minFill_oddAmountRoundsTheHalfUp`, `test_minFillPpm_halvingEncodesIt`). Superseded by: the 50 %
  minimum-fill floor (`MIN_FILL_PPM`) is gone; the signer's `minFill` is the only per-fill minimum. Not built.
- `zether-ungate/`: the classical-Zether dev-chain gate before branch `zether-ungate` removed it (owner ruling
  2026-10-31: classical Zether is open on every chain like PQZ, testnet 7622 and mainnet 22776; CTR-ZTH-02 superseded;
  owner: backup, not delete), taken from `main` commit `d9af46c3`: `src/zether/ZetherSafety.sol` whole (`isDevChain`
  = chain id 31337 / 1337, `requireDevChain`, error `ZetherNotDevChain`; called by the Zether verifier constructors,
  `ZetherLib.init`, `ZetherSchnorrBls12381Verifier` and `DeployBase`), and the tests as they stood with the
  off-dev-chain revert cases: `test/zether/ZetherRevertPaths.t.sol` (`test_verifiersOnlyDeployOnDevChain`,
  `test_createToken_enabledKindOnANonDevChain_reverts`, the hand-made clone in `test_initializeRevertPaths`),
  `test/zether/ZetherDeploy.t.sol` (`DEPLOY_ZETHER: dev chains only`), `test/ua/UARegistryZether.t.sol` (the 7622
  constructor revert). The factory's per-kind gate `setKindEnabled` stays. Not built.
  The same branch removed PQZ's chain-id allowlist (a separate item; owner ruling 2026-10-31: no chain lock for PQZ,
  capability only): `src/pqz/PqzSafety.sol` as it stood (`isAllowedChain` = 31337 / 1337 / 7622,
  `requireAllowedChain`, error `NotAllowedChain`, called by `PqzStateLib.init` and the `UAPqzVerifier` constructor;
  the self-test `requirePqz` stays in `src/`), and the tests with the allowlist cases: `test/pqz/PqzCt.t.sol`
  (`test_safetyAllowlist`), `test/pqz/PqzNormal.t.sol` (`test_createToken_enabledKindOnAForbiddenChain_reverts`),
  `test/pqz/UAPqzVerifier.t.sol` (the 22776 constructor revert). Not built.
