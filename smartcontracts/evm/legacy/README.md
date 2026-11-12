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
- `zether-msm/`: the per-equation classical Zether verifier as it stood on `main` before branch `zether-msm` folded every
  equation into one MSM (CTR-ZTH-53; owner: backup, not delete): `ZetherVerifierPerEquation.sol` (eight Σ MSMs and two per
  Bulletproof, `verifyRange` called per proof) and `IZetherVerifierPerEquation.sol`. Byte-faithful to `src/zether/` at that
  commit but for three things: the file names, a `Legacy` / `ILegacy` prefix on every contract and interface name, and the
  imports re-pointed at `src/`. The new names keep these artifacts off the production paths: forge moves a same-named source
  aside, and `script/verify-blockscout.sh` globs `out/*/<name>.json`. **The one exception to "not compiled" above:**
  `test/zether/helpers/ZetherLegacyVerifiers.sol` imports them, so the differential suite
  `test/zether/ZetherMsmDifferential.t.sol` runs old and new side by side. Never deployed.
- `typed-signing/`: `UAKindsPortableRaw.sol` — the raw UA-8 portable digests (`portablePopDigest`, `registrationDigest`,
  `kemRecordDigest`, `pqzKeyDigest`, `pqzKeyRecordDigest`), the record tags `KEM_RECORD_TAG` / `PQZ_KEY_RECORD_TAG` and
  UARegistry's `personal_sign` path for a native `msig` member of a portable record, as they stood in `src/ua/` before
  typed-signing P3 replaced them by typed EIP-712 records (TS-D1 … TS-D4). Not built.
  `IUARegistryPacked.sol` — `src/ua/IUARegistry.sol` before typed-signing R1 (registry explicit ABI, TS-D10 … TS-D12; owner
  KEM rulings 2026-10-31): `register` for every kind incl. the packed `msig` key data and `abi.encode(MemberSig[])` pop,
  `UAAttrs{pqzKey, pqzPopHash, kemVersion, kemPk}`, `setKemKey(…, bytes kemPk, bytes sig)`, `setPqzKey(…, bytes sig)`,
  `requireAuthorized(…, bytes auth)` and `kemKeyOf` / `kemKeyAt` returning bytes. Not built.
  `IUARegistryPackedKeys.sol` — `register` as it stood after typed-signing R1 and before R1b (TS-D13): the packed key
  data of `webauthn-p256`, MuSig2 and FROST, now `registerWebAuthn` / `registerMuSig2` / `registerFrost` (typed keys, the
  same assembled bytes and ids; `register` refuses those kinds). Not built.
  `MtxExecuteWithFee.sol` — `mtxExecuteWithFee` of `MetaTokenBase` before typed-signing C2 (TS-D14): it duplicated
  `mtxExecute` behind a shape check. `executeMetaTransaction` stays in `MetaTxBase` (owner 2026-11-01). Not built.
  `FlatUaUnwrap.sol` — the flat `uaUnwrap(bytes32 from, …)` of `MetaTokenBase` before the typed-signing C2 review: it
  duplicated the named `uaUnwrap(UAEnvelope, …, UASig)` / `uaUnwrapLeg` (owner 2026-11-01). Not built.
- `msig-nested/`: `test/ua/UARegistrySplit.t.sol`, the differential of the registry split against
  `typed-signing/UARegistryPreSplit.sol`, as it stood before nested `msig` (spec `2026-11-02-msig-nested`) replaced
  `MemberSig.keyData` by `InnerSig[] members`: the pre-split source reads `keyData`, so neither side compiles any more. A
  finished refactor's check; its `abi.decode` of `MemberSig[]` would be `Stack too deep` here too. What still applies is in
  `test/ua/UARegistryLibMsig.t.sol`: `_msigIndexGuards`, the nested-offset note, `test_gasHotPath` against the figures of
  `159d267e`. `test/ua/SplitDiff.sol` and `test/ua/UARegistryUA8-split.sol.txt`, the two `test_split_*` of `UARegistryUA8.t.sol`
  with their helpers and `BurnAccept`, moved here on landing. Not built.
- `governance/`: `AdminLib.sol` and `ITokenAdmin.sol` as they stood at `main` (`db9f9d86`), before `GovernanceLib` /
  `IGovernance` replaced them (CTR-GOV-01, governance T3), and `RequireRole.sol.txt`, the prototype's
  `GovernanceLib.requireRole`, removed by spec G14 (B-31: it skipped a limited holder's grant). Not built.
- `ua-mtx-merge/`: the files the `ua*` / `mtx*` merge round rewrites, copied whole as they stood at local tag
  `ref/pre-ua-mtx-merge` (`9a4b8c5a`, spec `docs/superpowers/specs/2026-11-04-ua-mtx-merge.md`, CTR-MTX-30, plan MD-4).
  T1 (the generic path): `src/metatx/{MetaTxBase,UAMetaTxBase,MtxPipelineLib,IMetaTx,IUALedger,ERC20MetaTx}.sol`,
  `src/ua/UAKinds.sol`, `src/governance/GovernanceRouterBase.sol`, `src/zether/ZetherLayer.sol`, `src/pqz/PqzLayer.sol`:
  the generic `uaExecute` / `uaBatch` with `bytes auth`, the `bytes auth` `_namedUA` overload and `uaShield`'s
  `bytes auth`, `MtxPipelineLib`'s `bytes` `_authorize` and `UAKinds.uaAuthCall` (R47), the unordered
  `uaCancelNonce` / `uaCancelDigest` and their `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)` (Q2; the
  `cancelUsed` slot stays in `UALedgerStorage`), the registry guard on every `ua*` (C), the `_uaAllowed` check for a
  native id (B), and the address `mtxNonce` / `mtxDigest` / `mtxExecute` / `mtxBatch` / `mtxCancelNonce` on tokens and
  the router (now `MetaTxAddressBase`, the wallets only, MD-1). Tests: `test/metatx/MetaTxParity.t.sol` with
  `test/vectors/legacy/ua-mtx-merge/metatx-parity.json` (the metatx split's replay, recorded on the pre-split code; its
  seven token rigs live on in `test/metatx/helpers/KindRigs.sol`), `test/ua/UARegistryNested.t.sol` (its two
  `uaAuthCall` tests), and `test/ua/UALedger.t.sol`, `test/metatx/{TypedOps,TradeTyped}.t.sol` as they stood before
  their cancel tests and rows changed meaning (the unordered cancel, the address cancel on tokens and the router).
  T2 (the transfer group, payments, receiver-pays, the relay fee): `src/metatx/{MetaTokenBase,MtxRelayFee,IERC20MetaTx,
  IMetaTokenV2}.sol` and `src/common/MetaTxLib.sol` (and T1's `ERC20MetaTx.sol`, `MtxPipelineLib.sol`, `IUALedger.sol`):
  the address `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayMeta`, `mtxPayReceiverFee`, `mtxRelayFee`,
  `mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxTransferDigest`, `receiverFeeDigest` over `MetaTransfer` (R1, R4, R20,
  R21, R27, R28), `_executeTransfer`, `_pay`, `_payMeta`, `_padded`, `_notPool`, `MtxPipelineLib.preTransfer` and its
  `ReceiverFee` typehash, the `RelayFee` typehash, `MtxRelayFee.relay(address …)`, `ReceiverFeePaid`, and
  `MetaTxLib.MetaTransfer` with its typehash and `hashStruct` (R46; the test copy that signs the retired form is
  `test/helpers/LegacyMetaTransfer.sol`). Their `ua*` bodies took the `mtx*` names. Tests as they stood before their
  meaning changed: `test/metatx/{ERC20MetaTx,MtxRelayFee,PayMeta,TokenKat}.t.sol`, `test/v2/{Base,MetaTxGasV2,
  ReceiverPays}.t.sol`; vectors `test/vectors/legacy/ua-mtx-merge/{metatx_kat,metatransfer_kat}.json` (the address
  `MetaTransaction` / `MetaTransfer` KATs; the files of the same name now hold the UA structs).
  T3 (the token kinds' own pairs): `src/metatx/{NormalToken,WrappedToken,WrappedLib,IWrappedToken}.sol` and
  `src/trade/ITradeToken.sol`: the address `mtxBurn` over `Burn`, `mtxUnwrap` / `mtxUnwrapLeg` / `mtxUnwrapToUA` over
  `Unwrap` / `UnwrapLeg` / `UnwrapToUA` with their typehashes (R23), and `mtxWrapOrder(address, WrapOrder, bytes)` with
  the `WrapOrder` struct, `WrappedLib.wrapBySig` and `_tradeOf` (R39); their `ua*` bodies took the `mtx*` names. Tests as
  they stood before their meaning changed: `test/v2/MtxWrap.t.sol` (the address wrap order), `test/metatx/NamedEntry.t.sol`
  (the address `Unwrap` entry), `test/governance/GovHybrid.t.sol` (the cap on both wrap-order entries).
  T3b (the mandate wallets, Q6, MD-11): `src/wallet/MandateWallet.sol` and `src/hedera/HederaMandateWallet.sol` on
  `WalletExecute` with `address` ids: the address-form bodies and events, the named entries over `SetMandate`,
  `SetPayee`, `RevokeMandate`, `PayUnderMandate`, `DelegateRevoke`, `Execute` with `bytes` signatures, the flat builders
  `mtxPayUnderMandate(token, …)`, `mtxRevoke`, `mtxExecuteAsOwner` and Hedera's `mtxExecuteAsOwnerRaw` (MD-11 (a)), the
  wallets' address generic path and `executeMetaTransaction`. Tests as they stood before their meaning changed:
  `test/wallet/{MandateWallet,NamedWallets}.t.sol`, `test/account/AccountKat.t.sol` (the writer of the vectors
  `test/vectors/legacy/ua-mtx-merge/{mandate_pay_kat,mandate_revoke_kat}.json`). Not built.
  T4 (Zether, R35): `src/zether/{ZetherLib,ZetherWrappedLib,WrappedZetherToken,IZetherToken}.sol` (and `ZetherLayer.sol`,
  copied at T1): the address signed entries `mtxShield`, `mtxConfidentialTransfer`, `mtxConfidentialTransferCompact`,
  `mtxConfidentialTransferSingle`, `mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver`, `mtxRollOverBatch`,
  `mtxRollOverSigned`, `mtxSetRollOverMode` over `Envelope` + `bytes sig`, their typehashes (`ZetherTransfer`,
  `ZetherTransferCompact`, `ZetherTransferSingle`, `ZetherUnshield`, `ZetherUnshieldUnwrap`, `RollOver`, `RollOverBatch`,
  `RollOverSigned`, `SetRollOverMode`) and builders (`ZetherLib.multiCall`, `singleCall`, `unshieldCall`,
  `ZetherWrappedLib.unwrapCall`), and the public address `envelopeBinding(MetaTransaction)` view; their `ua*` bodies took
  the `mtx*` names and `uaEnvelopeBinding` the name `envelopeBinding`. Tests as they stood before their meaning changed:
  `test/zether/{ZetherTyped,ZetherUA5c,ZetherRelay,ZetherProverCross,ZetherGasLimit}.t.sol`. Not built.
  T5 (PQZ, R36): `src/pqz/{WrappedPqzToken,IPqzToken}.sol` (and `PqzLayer.sol`, `src/common/MetaTxLib.sol`, copied
  earlier): the address signed entries `mtxShield`, `mtxConfidentialTransfer`, `mtxConfidentialTransferCompact`,
  `mtxConfidentialTransferSingle`, `mtxConfidentialTransferSingleCompact`, `mtxUnshield`, `mtxUnshieldUnwrap`,
  `mtxRollOver`, `mtxPrepareAcc` over `Envelope` + `bytes sig`, their typehashes (`PqzTransfer`, `PqzTransferCompact`,
  `PqzTransferSingle`, `PqzTransferSingleCompact`, `PqzUnshield`, `PqzUnshieldUnwrap`, `RollOver`, `PrepareAcc`,
  `MetaTxLib.SHIELD_TYPEHASH` (`Shield`)), and the public address `envelopeBinding(MetaTransaction)` view; their `ua*`
  bodies took the `mtx*` names and `uaEnvelopeBinding` the name `envelopeBinding`. Tests as they stood before their
  meaning changed: `test/pqz/{PqzTyped,PqzRelay,PqzPool}.t.sol` (and `test/metatx/NamedEntry.t.sol`, copied earlier).
  Not built.
  T6 (DEX, R12, R38): `src/trade/TradeLib.sol`, `src/dex/{SCaaSDex,ISCaaSDex}.sol` (and `src/metatx/ERC20MetaTx.sol`,
  `src/trade/ITradeToken.sol`, copied earlier): the token's address `TradeOrder` side — `mtxTrade(TradeOrder, bytes,
  TradeFill)`, `mtxCancelOrder(TradeOrder, bytes)`, `mtxInvalidateNonces(address, …, bytes)`, `restorePulled(TradeOrder,
  …)`, `tradeOrderDigest` / `cancelOrderDigest(TradeOrder)`, `invalidateNoncesDigest(address, …)`, `minNonce(address, …)`
  — and the typehashes only that side read (`CancelOrder`, `WrapOrder`, `CancelWrapOrder`), the `ua` flag of
  `TradeLib.orderHash` / `cancelHash`, and the DEX's shape-0 SCaaS leg; the `ua*` trade bodies took the `mtx*` / plain
  names. `TradeOrder`, `DexOrder`, `InvalidateNonces` stay for the DEX's outside legs. Tests as they stood before their
  meaning changed: `test/v2/{Trade,Dex,DexHybrid,DexModes,DexExchange,UniswapExecutor}.t.sol`,
  `test/ua/{UADex,UATrade}.t.sol`, `test/metatx/TradeKat.t.sol`, `test/helpers/DexLegs.sol` (its `wire` made shape-0
  legs); the vectors `test/vectors/legacy/ua-mtx-merge/{trade_kat,dex_order_kat}.json`. Not built.
  T7 (`GovernanceRouter`, R14, Q2): `src/governance/GovernanceRouter.sol` (and `GovernanceRouterBase.sol`, copied
  earlier): the 19 address signed entries `mtx<Op>(Envelope, …, bytes sig)` (`_mtxCall`: `GrantRole`, `RevokeRole`,
  `SetGrant`, `CancelGrant`, `DisableFeature`, `TransferOwnership`, `AcceptOwnership`, `RenounceOwnership`,
  `RenounceRole`, `Mint`, `MintToUA`, `DisableWrap`, `ProposeRate`, `CancelRate`, `ExecuteRate`, `SetMarket`,
  `SetExchangeTarget`, `SetListedOnly`, `SetFeeSplit`) and their 19 address typehashes; the `ua<Op>` bodies (`_uaCall`)
  took the `mtx<Op>` names. Tests as they stood before their meaning changed: `test/governance/{GovRouter,
  GovRouterTypehash}.t.sol` (and `test/metatx/TypedOps.t.sol`, copied earlier). Not built.
  T8 (Hedera, R42): `test/hedera/{HederaKat.t.sol,gen_hedera_kat.py}` and the vector
  `test/vectors/legacy/ua-mtx-merge/hedera_kat.json`: the Hedera `MetaOp` v1 as the token's address `MetaTransfer`
  (`from` an `address`); the file of the same name now holds `UAMetaTransfer` with the long-zero `from` padded to
  `bytes32`. Not built.
  T10 (deploy and scripts, Q4, R40): `script/DeployBase.sol` with one deploy gate on every chain, `runtime x 1,530 + 2^24`
  (now the SCaaS testnet's; a public chain declares the measured gate); `script/ZetherE2E.s.sol` with the relayed
  section on the prover's address `namedCall` forms and the address `envelopeBinding(MetaTransaction)` view;
  `script/pqz/e2e.py` and `script/pqz/test_e2e_linked.py` with the address named entries and generic path (`mtxExecute`
  over `MetaTransaction`, `mtxNonce(address,uint256)`, `envelopeBinding` / `mtxDigest` over `MetaTransaction`), the `ua*`
  twins (`uaExecute` with `bytes auth`, `uaNonce`, `uaEnvelopeBinding`, `uaDigest`, the `ua<Op>` named entries) and
  `uaShield`'s `bytes auth`. Not run.
  T24 (regulated kinds: `GovernanceLib`'s relaxation state machine, `msig` holders, issuer and compliance roles; spec
  `2026-11-05-regulated-kinds.md` §3.6, RK-1..3): `src/governance/{GovernanceLib,GovernanceBase,GovernanceBits,
  IGovernance}.sol` with `PendingGrant.termsHash` (the terms' hash, 0 for a grant, no action and no proposer check),
  `revokeRole` / `renounceRole` / `disableFeature` in one call on every bit, a void `disableFeature`, `init` refusing
  `roles.issuer` / `roles.compliance` and 5-9 as `FeatureNotBuilt` on the plain kinds, contract-only bits for a native id
  with code alone. Tests as they stood before their meaning changed: `test/governance/{GovRegulatedBits,GovDelay}.t.sol`,
  `test/metatx/GovernanceLib.t.sol` with `test/metatx/helpers/GovernanceLibHarness.sol`, `test/v2/Features.t.sol`. Not built.
  T25 (regulated kinds: `TokenConfig.reg`, the init ripple; spec `2026-11-05-regulated-kinds.md` §2.4), as they stood at
  `5981f2c4`: `src/factory/IFactoryToken.sol` with `TokenConfig` of fifteen fields (no `reg`, `ConfigFieldForOtherKind`
  fields 1-5) and `src/pqz/PqzWrappedLib.sol` whose `init` passes the fixed `KIND_WRAPPED_PQZ` and `GovernanceBits.WRAPPED_*`
  masks (`ZetherWrappedLib` as it stood before the round is the T4 copy). Not built.
  T26 (regulated kinds: the eight empty hooks at their seats; spec `2026-11-05-regulated-kinds.md` §2.2, §3.2, §4.1,
  §4.2): no copy. It supersedes no body, typehash, struct, builder, row or handler: it adds calls of empty `internal view
  virtual` hooks, makes `supportsInterface` `virtual` and names `_update`'s resolved sender in a local. Its eight files
  (`src/metatx/{UAMetaTxBase,ERC20MetaTx,MetaTokenBase,WrappedToken}.sol`, `src/zether/{ZetherLayer,WrappedZetherToken}.sol`,
  `src/pqz/{PqzLayer,WrappedPqzToken}.sol`) keep their pre-round copies above, not overwritten; as they stood before T26:
  `d973a70d`.
  T27 (regulated kinds: the skeleton of kinds 9 and 13, measured first; spec `2026-11-05-regulated-kinds.md` §2.1, §3.1,
  §6.2): no copy. It adds `src/regulated/` and supersedes no body, typehash, struct, builder, row or handler: in the built
  kinds it only marks `WrappedPqzToken`'s overrides and `MetaTokenBase._scalarBits` `virtual` and makes
  `MetaTokenBase.supportsInterface` `public` (so a regulated kind can extend it with `super`); `DeployBase` gains a path.
  The touched files keep their pre-round copies above; as they stood before T27: `a2325004`.
  T28 (regulated kinds: `RegulatedLib`, `RegulatedBase`, kinds 8 and 9; spec `2026-11-05-regulated-kinds.md` §2.3, §2.4,
  §3.1-§3.4): no copy. It replaces T27's placeholders (`RegulatedNotBuilt` bodies of a skeleton never deployed with value),
  not a built body, typehash, struct, builder, row or handler; `RegulatedNotBuilt` stays for T29 / T32. New:
  `src/regulated/NormalRegulatedToken.sol` and the `scaas.regulated` namespace. As they stood before T28: `59f18aae`.
  T29 (the receiver check: `ComplianceRegistry`, the bounded registry call, the code pin; spec
  `2026-11-05-regulated-kinds.md` §2.4, §5): no copy. It replaces T28's placeholders (`RegulatedBase._eligible` and
  `canReceive` reverting `RegulatedNotBuilt`, `RegulatedLib.init` refusing any registry), not a built body, typehash,
  struct, builder, row or handler; `RegulatedNotBuilt` stays for T32. `RegulatedLib.init` gains a parameter (the release's
  `REGISTRY_CODEHASH`), each regulated kind's constructor passes `implArgs` to `RegulatedBase`. New:
  `src/regulated/{ComplianceRegistry,IComplianceRegistry}.sol`. As they stood before T29: `70d0b751`.
  T30 (the regulated Zether kinds 10 and 11; spec `2026-11-05-regulated-kinds.md` §4.1, §4.3): no copy. It supersedes no
  built body, typehash, struct, builder, row or handler: `ZetherLayer`'s `_regZetherSender` seat (T26) keeps its empty
  body on kinds 2 and 3; `NormalZetherToken` and `WrappedZetherToken` only mark their overrides `virtual` (same
  runtime size, the metadata hash moves); `DeployBase._deployZether` gains `_deployZetherRegulated`. New:
  `src/regulated/{NormalZetherRegulatedToken,WrappedZetherRegulatedToken}.sol`. As they stood before T30: `b0727dfc`.
  Owner ruling 2026-11-06 (`ComplianceRegistry`: only the admin overwrites or revokes an admin-written slot; spec
  `2026-11-05-regulated-kinds.md` §5): no copy. `attest` keeps its signature and body and gains one check before the write
  (`AdminWrittenSlot`); no entry, struct, row or handler is dropped; the runtime hash moves. As it stood before: `4ba3decb`.
  T31 (the regulated PQZ kinds 12 and 13; spec `2026-11-05-regulated-kinds.md` §4.2, §4.3): no copy. It supersedes no built
  body, typehash, struct, builder, row or handler: the PQZ seats in `PqzLayer` and `WrappedPqzToken` (T26) and kind 13
  (T27-T29) are unchanged; `NormalPqzToken` only marks its overrides `virtual` (same runtime size); `script/pqz/e2e.py`
  publishes the releases 12 and 13 beside 0, 4 and 5. New: `src/regulated/NormalPqzRegulatedToken.sol`. As they stood
  before T31: `024e143c`.
  Group 3e (payment metadata, free pay lanes, tax; spec `2026-11-05-pay-meta-tax.md`), under `ua-mtx-merge/3e/` because the
  pre-round copies of the same paths above stay as they are. T37 (pay entries with `PayMeta`, free pay lanes, the mandate
  wallets), as they stood at `86751e34`: `src/metatx/{MetaTokenBase,IMetaTokenV2,IERC20Payment}.sol` with the flat
  `mtxPay(bytes32 from, …, bytes32 payId, …)` on lane `payLane(payId)` at nonce 0, `mtxPayMeta`, `_uaPayMeta`, `_uaPay`,
  `metaPayId(bytes32 salt, bytes meta)` under the tag `scaas.pay.meta`, `PaymentMeta(bytes32 indexed payId, bytes meta)`,
  the six-argument `payWithFee` / `payWithFeeToUA` (any `entryRef`, 0 included) and the receiver-fee shape
  `t.batch == payLane(t.entryRef)`, `t.nonce == 0`; `src/wallet/MandateWallet.sol` with `payUnderMandate` /
  `mtxPayUnderMandate` without `PayMeta`. Tests as they stood before their meaning changed:
  `test/metatx/PayMeta.t.sol`, `test/v2/{Base,ReceiverPays,MetaTxGasV2}.t.sol`, `test/ua/{UAReceiverFee,UALedgerNamed}.t.sol`,
  `test/wallet/{MandateWallet,MandateWalletMerged}.t.sol`, `test/merge/TransferGroup.t.sol`, `test/account/AccountKat.t.sol`
  and its vector `test/vectors/mandate_kat.json`; the shared vector `smartcontracts/vectors/metatx/paymeta.json` (the old
  formula, which the non-EVM families keep until their rounds) is at `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/`.
  Not built.
  T38 (the relay fee on free lanes), as they stood at 2ced92b5 (the T37 tip): `src/metatx/{MtxRelayFee,IERC20MetaTx}.sol` and
  `MetaTokenBase.sol` (copied at T37) with `UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,
  uint256 value,uint256 validUntil,address relayer)`, the token's seven-argument `mtxRelayFee` on lane `payLane(ref)` at
  nonce 0, `_relayHash` and the router's eight-argument `relay`; `test/metatx/{MtxRelayFee,TradeTyped}.t.sol` as they stood before their
  meaning changed. Not built.
  T39 (bit 23 `TAX`, the tax rate and recipient, router ops), as they stood at e273978e (the T38 tip):
  `src/governance/GovernanceBits.sol` with `ISSUER_BITS` = 5, 6, 7; `src/regulated/{RegulatedLib,RegulatedBase,IRegulatedToken}.sol`
  with `RegulatedLib.init(initArgs, valid, registryCodehash)`, `scaas.regulated` up to +4, `_delayedRelaxBits()` =
  `ISSUER_BITS`; `src/factory/IFactoryToken.sol` with `RegulatedParams` of four fields. Tests as they stood before their
  meaning changed: `test/as/RegulatedSkeleton.t.sol` (the masks without bit 23), `test/governance/GovBitsVector.t.sol` (rows
  0-22). Not built.
  T40 (`mtxPayWithTax` and `payWithTax` on kinds 8-13), as it stood at ff5f18f5 (the T39 tip): `src/metatx/ERC20MetaTx.sol`
  with the three-argument `_uaExecuteTransfer(t, signed, auth)` (no withheld leg). `RegulatedBase`, `RegulatedLib` and
  `IRegulatedToken` before T40 are the pre-T39 copies above plus T39's commit. Not built.
  T41 (pay-meta and tax vectors, clientkeys and ua-rs rows), as they stood at bc6592b1 (the T40 tip): `test/metatx/TypedOps.t.sol`
  (`UAPayUnderMandate`'s row finding no entry), `test/ua/{UAMetaTx3Pq,UAMetaTx3Vectors}.t.sol` (the receiver-fee rows refused
  `PayMetaMismatch`, the two-`mldsa65` run waiting for a commitment row). The vector copies: `smartcontracts/vectors/typed/legacy/
  ua-mtx-merge/3e/typed_ops.json`, `smartcontracts/vectors/ua/legacy/ua-mtx-merge/3e/{metatx3,pq_signatures}.json`. Not built.
  Group 3g (versioned PQZ keys; spec `2026-11-06-pqz-key-versions.md`), under `ua-mtx-merge/3g/`. T51 (the registry's
  versioned PQZ key records), as they stood at 55347848 (the 3e tip): `src/ua/{UARegistryLib,UARegistry,IUARegistry,UAStore}.sol`
  with the four-argument `setPqzKey(ua, pqzKey, pqzPopHash, sig)`, the two-argument `storePqzPop(ua, pqzPop)`, one PQZ key per
  UA (`UAStore` slots 2, 7, 8, 9 keyed by UA alone), ruling R-cross-set's replacement (`_pqzKeyFree`, the kept `register`
  key in slots 13 and 14, `registrationOf`'s fallback to it) and the three-word `pqzKeyOf`; `test/ua/UARegistryUA8.t.sol` as
  it stood before its meaning changed (`test_ua8_crossSetKeyReplaced`, `test_ua8_crossSetGen2ReplacesGen1Key`: the
  replacement, retired by R2). Not built.
  T52 (the PQZ token's per-version state), as they stood at 28a099a1 (the T51 tip): `src/pqz/{PqzCore,PqzStateLib,
  PqzTransferLib,PqzBurnLib,PqzViewLib,PqzLayer,IPqzToken,WrappedPqzToken,NormalPqzToken,PqzWrappedLib}.sol` with one account per
  UA (`acct[ua]`, `sendCounter` a field of it), the args structs without `keyVersion`, the two-argument `mtxRollOver(ua, n)` /
  `mtxPrepareAcc(ua, half)` (direct and signed, `UARollOver` / `UAPrepareAcc` without `keyVersion`, 68-byte static shape), the
  views `pqzAccount(ua)`, `pqzPending(ua, i)`, `pqzAcc(ua)`, `pqzPendingCt(ua, i)`, `Credited` / `Debited` without the version,
  the shared `RolledOver`; `src/confidential/IConfidentialToken.sol` with `mtxRollOver(bytes32,uint256)` shared by both layers.
  Tests as they stood before their meaning changed: `test/pqz/{PqzPool,PqzTyped,PqzGuards}.t.sol`,
  `test/confidential/ConfidentialSelectors.t.sol`. Not built.
  T53 (the PQZ disclosure by key version): the four-argument `disclosureStatement(entryRef, leg, amount, kind)` and the
  five-argument `verifyTransferAmount(entryRef, leg, amount, kind, proof)` (checked against the owner's current key) are in the
  T52 copies above (`src/pqz/{PqzCore,PqzViewLib,PqzLayer}.sol`, unchanged by T52); Zether's `ITransferDisclosure` forms stay.
  Factory index and extensible catalogue (spec `2026-11-07-factory-contract-index.md`), under `ua-mtx-merge/factory-index/`.
  T67 (the record, the per-class lists, the paged views), as they stood at e1336e60 (the 3g tip):
  `src/factory/{OpenFactory,IOpenFactory}.sol` with the per-token `Info {creator, kind, version, exists}` (`_info`) and the DEX
  version map `_dexVersion`, which the record `Created` replaces; no list of the contracts of an owner or a creator (a log
  only). Not built.
  Chain-neutral releases (spec `2026-11-07-chain-neutral-releases.md`, option I), under `ua-mtx-merge/chain-neutral/`. T71 +
  T72 (one segment: the factory's constructor `(registrar)` and `configureChain`, CREATE3 on every creation path, the
  creator a `bytes32 creatorId`; every kind's chain values in its clone's code), as they stood at 846167ba (the T67 tip):
  `src/factory/{OpenFactory,IOpenFactory,IFactoryToken}.sol` with the constructor `(registrar, chainUid, noticePeriod)`, the
  published `Env` carrying `factory`, `chainUid` and `govRouter`, releases `CREATE2`d with `abi.encode(envVersion, env,
  implArgs)` appended (per-chain code), clones by `Clones.cloneDeterministic` over `keccak256(abi.encode(creator, salt))`,
  `predictAddress(implementation, creator, salt)`, `getWrapper*(address creator, …)`, `TokenCreated` / `DexCreated` with
  `address indexed creator`, `initialize(address creator, …)`; `src/common/SaltedEIP712.sol`, `src/metatx/{MetaTxBase,
  UAMetaTxBase,ERC20MetaTx,MetaTokenBase,NormalToken,WrappedToken}.sol`, `src/governance/GovernanceBase.sol`,
  `src/zether/{ZetherLayer,ZetherLib,NormalZetherToken,WrappedZetherToken}.sol` (the transfer verifier copied into storage
  at `init`), `src/pqz/{PqzLayer,PqzStateLib,NormalPqzToken,WrappedPqzToken}.sol`, `src/regulated/{RegulatedBase,Normal,
  Wrapped,NormalZether,WrappedZether,NormalPqz,WrappedPqz}RegulatedToken.sol` (the six kinds' files), `src/dex/{SCaaSDex,
  ISCaaSDex}.sol` with the chain values as constructor immutables (`CHAIN_UID`, `_REGISTRY`, `IS_HEDERA`,
  `_SMART_KEY_CLONE_CODEHASH`, `SMART_KEY_ACCOUNT_IMPL`, `GOV_ROUTER`, the Zether and PQZ verifiers) and the env checks in
  the constructors; `script/DeployBase.sol` and `script/pqz/e2e.py` with that factory. Tests as they stood before their meaning changed:
  `test/v2/{Factory,Base,Dex,FactoryZether,Tier2}.t.sol`, `test/ua/{UALedger,UADeploy}.t.sol`,
  `test/governance/{GovIdentity,GovDeploy}.t.sol`, `test/zether/{ZetherRevertPaths,ZetherDeploy,ZetherModes}.t.sol`,
  `test/pqz/PqzNormal.t.sol`;
  `test/vectors/legacy/ua-mtx-merge/chain-neutral/selector_audit.json` with the `initialize(address,uint64,bytes)` rows.
  Not built.
  The generic catalogue (factory index spec §8, plan T70), under `ua-mtx-merge/generic-catalogue/`:
  `src/factory/{OpenFactory,IOpenFactory}.sol` as they stood at 612981b9 (the T72 tip), the env maps keyed by a `uint8`
  domain (a `TokenKind` or `DEX_DOMAIN`) and `EnvUnknown` / `EnvAlreadyPublished` taking it; no generic class, no
  `createInstance`, no `creating()`. Not built.
  The deploy scripts before the release list (chain-neutral spec §6.2, plan T73), under `ua-mtx-merge/release-list/`:
  `script/{DeployBase,Deploy.s}.sol` and `script/hedera/DeployHedera.s.sol` as they stood at the T70 tip, `configureChain`
  without a reference block, no `chain-uids.json` check, no sibling order, no release list. Not built.
  The router and the factory before the creations through the router (chain-neutral spec §4.4, S3; plan T76), under
  `ua-mtx-merge/router-create/`: `src/governance/{GovernanceRouter,GovernanceRouterBase}.sol` without `mtxCreateToken`,
  `mtxCreateDex`, `mtxCreateInstance`; `src/factory/{OpenFactory,IOpenFactory}.sol` with the creator always
  `pad(msg.sender)`; `test/vectors/legacy/ua-mtx-merge/router-create/selector_audit.json` and
  `../vectors/typed/legacy/ua-mtx-merge/router-create/typed_ops.json` without the three rows. Not built.
  PQZ verifier mode (group 3f, spec 2026-11-06-attested-verify.md; plan T44, T45), under `ua-mtx-merge/3f/`: the files as they
  stood at 8e756a47 (the factory index group's tip): `src/factory/IFactoryToken.sol` (`ConfidentialConfig` without
  `pqzVerifyMode`, `pqzVerifierUA`, `pqzVerifierFixed`), `src/pqz/{PqzCore,PqzStateLib,PqzLayer,IPqzToken,PqzTransferLib,
  PqzBurnLib,PqzViewLib,PqzWrappedLib,NormalPqzToken,WrappedPqzToken}.sol` (the precompile the only verdict, the proof-carrying
  entries without the verdict pair, no verifier UA), `src/regulated/{NormalPqzRegulatedToken,WrappedPqzRegulatedToken}.sol`,
  `src/governance/{GovernanceRouter,GovernanceRouterBase}.sol` (no `mtxPqz*Verifier` ops), `src/metatx/MetaTokenBase.sol` and
  `src/zether/ZetherLib.sol` (the config checks without the three fields), `script/pqz/e2e.py` (no zero-dep release);
  `test/vectors/legacy/ua-mtx-merge/3f/selector_audit.json`. Not built.
  The registry block (plan T66a, owner 2026-11-08: `requirePortable`, no KEM key for an `msig`, the `pop` slot bitmap and
  `popSlotsOf`), under `ua-mtx-merge/t66a/`: the files as they stood at 05f23be2 (3f's tip): `src/ua/{IUARegistry,UARegistry,
  UARegistryLib,UAStore,UAKinds}.sol` (no portable check view, a PQ-eligible `msig` a KEM holder, no `pop` slot word),
  `script/pqz/e2e.py` (its `msig` holder registered with a KEM key). Not built.
  The PQZ proof path, contract side (group 3h, spec 2026-11-06-pqz-proof-path.md; plan T58-T61), under `ua-mtx-merge/3h/`: the
  files as they stood at 7558a364 (the T66a block's tip), each copied by the first task of 3h that replaces it: T58
  `src/pqz/{PqzCore,PqzStateLib,PqzViewLib,PqzLayer,IPqzToken}.sol` (pending slots deleted by a debit and a rollover, no debit
  record, no `lastDebit`). Not built.
  T59 (`ownTag` and the key-version tail): `src/pqz/WrappedPqzToken.sol` (the unwrap typehash without `ownTag`) and
  `script/pqz/e2e.py` (the args tuples without `ownTag`, blobs without the tail), as they stood at 7558a364;
  `test/vectors/legacy/ua-mtx-merge/3h/selector_audit.json` at e35d1d16 (the six PQZ entries' signatures before `ownTag`).
  T60 (`proofStore` `NONE` / `LOG`): `src/factory/IFactoryToken.sol` (no `ConfidentialConfig.proofStore`),
  `src/metatx/MetaTokenBase.sol`, `src/zether/ZetherLib.sol` (the other-kind field checks without it),
  `src/pqz/{PqzTransferLib,PqzBurnLib}.sol` (no `PqzDebitProof` event), as they stood at 7558a364.
  T61 (bit 24 `PQZ_PROOF`): `src/governance/{GovernanceBits,GovernanceRouter,GovernanceRouterBase}.sol` (no bit 24, no
  `mtxSetProofStore`), `src/pqz/NormalPqzToken.sol`, `src/regulated/{NormalPqzRegulatedToken,WrappedPqzRegulatedToken,
  RegulatedBase}.sol` (the masks without bit 24), as they stood at 7558a364.
  T83 (owner 2026-11-09, `payNo` as `bytes32`, `PayMeta.save`, the on-chain pay records), under `ua-mtx-merge/t83/`, as they
  stood at 32d73310: `src/common/MetaTxLib.sol` (`PayMeta {salt, string payNo, schema, body}`), `src/metatx/{IMetaTokenV2,
  MtxPipelineLib,MetaTokenBase}.sol` (`metaPayId` under `scaas.pay.meta.v2`, `PayNoTooLong`, `PaymentMeta(payId, string payNo,
  schema, body)`, no records), `src/regulated/RegulatedBase.sol` (the tax entries without a record),
  `test/metatx/PayMeta.t.sol` and `test/helpers/PayMetaKit.sol` (the v2 rows and formula), `test/vectors/legacy/ua-mtx-merge/
  t83/mandate_kat.json` (the pay calldata with the v2 tuple). Not built.
  T66b (spec 2026-11-09-t66b-library-organisation.md, the library organisation and the 60 M fit), under `ua-mtx-merge/t66b/`, as
  they stood at 5e5fbce2: task 3.1 (the registry pair, R-1 then R-2) `src/ua/{UARegistry,UARegistryLib}.sol` (every `pure` view
  in the registry, every writer in the library). Not built.
  Task 4.1 (the token split: bodies to internal functions, faces, body modules), as they stood at 83cfa8b8 (the 3.1b
  commit): the token tree `src/metatx/{ERC20MetaTx,MetaTokenBase,MetaTxBase,UAMetaTxBase,NormalToken,WrappedToken,
  IERC20MetaTx}.sol`, `src/zether/{ZetherLayer,NormalZetherToken,WrappedZetherToken}.sol`, `src/pqz/{PqzLayer,NormalPqzToken,
  WrappedPqzToken}.sol`, `src/regulated/` (RegulatedBase and the six kinds), `src/common/SaltedEIP712.sol`,
  `src/governance/{GovernanceBase,GovernanceRouterBase}.sol`, the shared bases' other users `src/{dex/SCaaSDex,
  wallet/MandateWallet,account/SmartKeyAccount}.sol`, and `src/factory/{OpenFactory,IFactoryToken}.sol` (the release checks).
  Not built.
- `ua-mtx-fix-contracts/`: `src/common/MetaTxLibHash.sol`, the three `MetaTxLib.hashStruct` overloads (`MetaTransaction`,
  `UAMetaTransaction`, `UAMetaTransfer`) and `MetaTxLib.validateMode`, as they stood before the Fable review fix B P3-3
  (2026-11-11): no contract called them; every contract hashes through `MtxPipelineLib._structHash` / `_namedHash` and
  checks the mode in `_checkEnvelope`, and the tests now reproduce digests through those (`test/helpers/MtxHash.sol`).
  `MetaTxLib.canon` stays in `src/` (Zether and PQZ use it). Not built.
- `ua-mtx-fix2-contracts/`: the Safe-style one-level ERC-1271 wrap of `SmartKeyAccount` and `MandateWallet` (commit
  `be8d0772`, B P3-2): `src/common/Erc1271SafeWrap.sol` (`MetaTxLib.ERC1271_MESSAGE_TYPEHASH`, the wallets' `erc1271Digest`
  and `isValidSignature` bodies), `test/account/Erc1271SafeWrap.t.sol` (its KAT writer and tests) and
  `test/vectors/erc1271_kat.json`; superseded by ERC-7739 the same day (owner 2026-11-12: "only ERC-7739"; a wallet shows
  only `hash: 0x…` for the Safe-style message). clientkeys' `erc1271Digest` / `erc1271TypedData` and their test are in
  `clients/clientkeys/legacy/ua-mtx-fix2-contracts/`. Not built.
  `src/dex/DexPuller.sol` as it stood at `829006be`: `DexConfig.rescueTo` 0 meant no rescue (`RescueOff()`); superseded
  by CTR-GOV-25 (owner 2026-11-12: 0 is the constant dev address `SCAAS_DEV_RESCUE`). Not built.
  The admin entries without the chain word (Fable recheck-2 P3-1, owner 2026-11-12, CTR-GOV-27), as they stood at
  `a18e9464`: `src/governance/AdminEntriesV1.sol` (`renounceAdmin()`, the three release deploys without the last `chainUid_`,
  `mtxRenounceAdmin` and its `UARenounceAdmin` typehash without `chainUid`), the selector-audit rows they had
  (`test/vectors/selector_audit.json`); the old typed row in `smartcontracts/vectors/typed/legacy/ua-mtx-fix2-contracts/`,
  clientkeys' and ua-rs's old table rows in `clients/{clientkeys,ua-rs}/legacy/ua-mtx-fix2-contracts/`. Not built.
