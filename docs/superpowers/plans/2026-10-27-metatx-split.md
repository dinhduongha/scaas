# Metatx split + `mtxPayMeta` / `uaPayMeta` + `MtxRelayFee` (all families) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the EVM tokens' meta-tx checks into one DELEGATECALL library `MtxPipelineLib` with no change of behaviour (one recorded exception), then build CTR-MTX-26 (pay metadata by commitment) and CTR-MTX-27 (a token fee for a fee-less call) on EVM and on every other family — Soroban, Solana, Cosmos, Sui, Aptos, TON — with the node and the clients.

**Architecture:** Branch `metatx-split` (spec commit `a858a5d5`, from `main` `0c191232`). EVM first, because the other families mirror its semantics: a parity fixture on the pre-split code (Task 1); the library and `MetaTxBase` on its internals (Task 2); the token kinds on the library (Tasks 3–4); the PQZ / Zether relayed paths and the data-size bound (Task 5); release pins with the full link closure (Task 6); `mtxPayMeta` / `uaPayMeta` and the shared vectors (Task 7); the re-measure with the final token bytecode and every re-pin (Task 8); `MtxRelayFee` (Task 9). Then one task per other family for both CTR-MTX-26 and -27, with that family's node adapter (Tasks 10–16), the EVM node and clients (Tasks 17–18), docs (Task 19) and a resumable per-step gate runner over every family (Task 20).

**Tech Stack:** Solidity 0.8.37 / Foundry (Amsterdam profile, `via_ir = false`), Python stdlib (`e2e.py`, `gen_set.py`), Rust (`scaas-node`, `clients/zether-prover`, `clients/ua-rs`, Soroban SDK, Anchor + LiteSVM, CosmWasm + cw-multi-test), Sui Move 2024, Aptos Move, Tact 1.6.13 + jest sandbox, Node `node --test` (`clients/clientkeys`), Qt 6.12 / CMake (`clients/ua-qt`).

**Spec:** `docs/superpowers/specs/2026-10-27-metatx-split-design.md` (§0 owner rulings incl. the 2026-10-27 answers; §3 the library boundary; §5.3 the re-measure list; §6.1 / §6.2 pay-meta per family; §7.1 / §7.2 router per family; §9 node and clients; §10 risks R1–R19; §11.1 the four gaps). Normative texts: `docs/contracts/metatx.md` CTR-MTX-10, -17, -26, -27; background `docs/research/mtx-relay-fees.md`.

## Global Constraints

- Every state-changing `mtx*` is relayable (through the relayer; the outer fee may be 0). The one recorded exception is the native-coin `mtxWrapShield` (review C0-18, 2026-10-27).
- Never assume gas price 0 or a chain's own block limit: EIP-7825 (2^24 regular gas per transaction), EIP-7976 (calldata floor), EIP-8037 (state gas). The contracts may run on customer chains.
- One rule for every chain kind (never split a rule by L1 / L2 or chain kind).
- Ciphertexts stay in contract state, never only a hash plus calldata / events.
- Decisions recorded in full in `docs/decisions.md`: each with its content, who decided ("owner ruling 2026-10-27" or "controller call, owner may override"), status and commit; no bare labels.
- Parameter sets named only `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`.
- Library code hashes pinned in every release: a release's `Env.libs` equals the transitive link closure of its implementation; no SELFDESTRUCT, no CALLCODE in any library, DELEGATECALL only to a library the code names.
- `data` is never passed to, copied for or ABI-encoded for the library (variant A, owner 2026-10-21).
- Heavy commands only through `scripts/capped` (cargo, forge, npm, sui / aptos, cmake), never inside `timeout`; `at-set.sh` one run per worktree at a time; after a capped `dotnet` run `dotnet build-server shutdown` (not expected here).
- No code-size micro-optimisation; ceiling 65,536 B; the size gate's ratchet baseline `size-baseline.json` gets a comment entry per change.
- `set.toml` re-pins of this item (`debit_min_gas`, maybe `roll_max`): only the affected gate steps (owner 2026-10-27): `gen_set.py --all --check`, forge at the four sets, sizes, `docs_check`.
- `ROLL_MAX` rule (owner 2026-10-27): the largest multiple of 16 whose relayed full rollover stays ≤ 0.75 · 2^24 regular gas through both `mtxExecute` and `uaExecute`.
- Superseded EVM pipeline code goes to `smartcontracts/evm/legacy/metatx-v1/` (backup, not deleted).
- No `via_ir` switch; no change of `MtxRule`, any typehash, domain, selector, transient slot or storage layout.
- Commit per task on `metatx-split`, message ends `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no merge, no push (owner's go only). Timing runs (wall clock) only on the owner's go; forge gas runs are correctness runs.

## Review Focus

1. A relayed ≈ 340 KB PQZL op 7 (and the largest PQZH debit) must cost the split no more than 8,000 gas over the smallest envelope on either relay path — `test_splitOverhead_dataSizeBound` (Task 5).
2. A `SmartKeyAccount`-signed `mtxExecute` submitted at the node's floor must not starve the ERC-1271 call now two frames deep — `test_minGas_smartKeyAccountMtxExecute` (Task 3) and `erc1271_floor_covers_forge_minimum` (Task 17).
3. A payment signed for the router must never settle through a plain pay entry, on any family — `test_routerBoundPayment_refusedOutsideRouter` (Task 9) and each family task's `*_router_bound_pay_refused_direct` test (Tasks 10–16).
4. A pay-meta whose `(salt, meta)` does not hash to `pay_ref`, or a second pay-meta of the same `(payer, payId)`, must be refused on every family — `test_payMeta_mismatchAndReplayRefused` (Task 7) and each family's `*_pay_meta_mismatch_and_replay` test (Tasks 10–15).
5. A TON escrow must never both release and refund, and must refund a target that ran without replying only after `deadline` — `relayfee.spec.ts › release and refund are exclusive` (Task 16).

---

### Task 1: Parity fixture and gas baseline on the pre-split code (R1, Part 0)

**Files:**
- Create: `smartcontracts/evm/test/metatx/MetaTxParity.t.sol`, `smartcontracts/evm/test/vectors/metatx-parity.json`, `smartcontracts/evm/runs/2026-10-27-metatx-split-baseline.txt`

**Interfaces:**
- Produces: `contract MetaTxParityTest` with `test_parity()` (env `PARITY_WRITE=1` writes the JSON, else replays and compares) and `test_ruleTableParity()`; JSON per case `{kind, entry, path: "addr"|"ua", case, ok, ret, revert, events[], digests{}, nonces{}, balances{}, gas, expect?}`; `expect = "fee-error-first"` marks the §3.8 cases (filled in Task 3).

- [ ] **Step 1: Write the fixture test.** On a clone of each of the six kinds (the `DeployBase`-built factory of `test/v2/Base.t.sol`), run: every signed entry point (`mtxExecute`, `executeMetaTransaction`, `mtxExecuteWithFee`, `mtxBatch`, `uaExecute`, `uaBatch`, `uaUnwrap`, the typed paths of spec §3.4, `mtxPayReceiverFee`, `uaPayReceiverFee`, `mtxTrade`, `uaTrade`, `mtxCancelOrder`, `uaCancelOrder`, `mtxInvalidateNonces`, `uaInvalidateNonces`) × success and each error of CTR-MTX-17 steps 1–4 and the fee rule, including the both-fail case (fee rule broken and call reverting); the PQZ and Zether relayed ops at `n2304-kmax4096`. Record outcome, return data, revert data, emitted events (topics + data), the digest views (`mtxDigest`, `uaDigest`, `mtxTransferDigest`, `uaTransferDigest`) of every case's struct, nonces, balances (`SHIELD_POOL`, `UA_POOL` included) and `gasleft` deltas. `test_ruleTableParity` records, per kind, `mtxSelectors()` and `_uaAllowed(sel)` for every selector.
- [ ] **Step 2: Write the fixture.** Run `cd smartcontracts/evm && PARITY_WRITE=1 ../../scripts/capped forge test --match-path test/metatx/MetaTxParity.t.sol -vv | tee runs/2026-10-27-metatx-split-baseline.txt`. Expected: PASS, JSON written.
- [ ] **Step 3: Replay on the same code.** Run without `PARITY_WRITE`. Expected: PASS (every field equal, gas equal).
- [ ] **Step 4: Gas baseline.** Append `../../scripts/capped forge test --match-path test/v2/MetaTxGasV2.t.sol -vv` output to the baseline log.
- [ ] **Step 5: Commit** `metatx-split T1: parity fixture + gas baseline on the pre-split code`.

### Task 2: `MtxPipelineLib` and `MetaTxBase` on its internals (§3.1, §3.2, §3.7)

**Files:**
- Create: `smartcontracts/evm/src/metatx/MtxPipelineLib.sol`, `smartcontracts/evm/test/metatx/MtxPipelineLib.t.sol`
- Modify: `smartcontracts/evm/src/metatx/MetaTxBase.sol` (`_execute` → `internal virtual`; `_checkEnvelope`, `_checkCall`, `_useNonce`, the struct hash and `_mtxStorage()` call the library's internal functions)

**Interfaces:**
- Produces (exactly spec §3.2): `library MtxPipelineLib` with `struct Ctx { bytes32 domainSeparator; address registry; bytes32 skaCloneCodehash; bool hedera; }`, `struct Envelope { bytes32 from; bytes32 dataHash; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode; address relayer; uint256 fee; address feeRecipient; }`, `struct CallFacts { bytes4 sel; uint256 len; uint8 feeClass; uint8 amountArg; uint32 staticLen; uint256 basis; bool uaAllowed; }`, `struct Out { bytes32 digest; uint256 fee; address feeTo; }`; external `preCall(Ctx calldata, Envelope calldata, CallFacts calldata, bool ua, bytes calldata auth) returns (Out memory)`, `preTransfer(Ctx calldata, MetaTxLib.UAMetaTransfer calldata, bool ua, uint256 have, bytes calldata auth) returns (Out memory)`, `requireSignature(Ctx calldata, address from, bytes32 digest, bytes calldata sig) view`, `authorize(Ctx calldata, bytes32 from, bytes32 purpose, bytes32 digest, bytes calldata auth) view`, `callDigest(bytes32, bytes32 typehash, Envelope calldata) pure returns (bytes32)`, `transferDigest(bytes32, bool ua, MetaTxLib.UAMetaTransfer calldata) pure returns (bytes32)`; internal `_checkEnvelope`, `_structHash`, `_checkCall`, `_callFee`, `_checkTransfer`, `_checkTo`, `_useNonce`, `_mtxStorage`; the ERC-7201 `scaas.metatx` slot constant defined here only.

- [ ] **Step 1: Failing tests** in `MtxPipelineLib.t.sol` (a harness token that DELEGATECALLs the library): `test_preCall_orderAddressPath` (envelope error beats signature error beats call-shape error beats fee error, `SelfSender` for `from == address(this)`), `test_preCall_orderUaPath` (`UALedgerOff`, envelope, `authorize(PURPOSE_METATX)`, `MetaTxUnknownOp` for `len < 4 || !uaAllowed`, `_checkCall`, nonce, fee with `UAPoolNotPayable`), `test_preCall_writesOnlyTheNonceSlot` (`vm.record` / `vm.accesses`: one written slot), `test_preTransfer_matchesTodayOrder`, `test_directCallReverts` (a plain CALL of `preCall` reverts: solc's library guard), `test_digestsEqualMetaTxLib` (`callDigest` / `transferDigest` against `MetaTxLib` hashing of the same struct for both typehashes).
- [ ] **Step 2:** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/metatx/MtxPipelineLib.t.sol` — FAIL (library missing).
- [ ] **Step 3: Implement** the library with no state variable, no immutable, no constructor; the HIP-632 branch calls `HederaLib` (linked into the library). Rewire `MetaTxBase` to the internal functions (inlined, no link) so `SmartKeyAccount`, `MandateWallet`, `HederaMandateWallet` keep their `_execute` and overrides.
- [ ] **Step 4:** The new tests and the wallets' and base suites pass: `../../scripts/capped forge test --match-path 'test/metatx/*'`, `--match-path test/account/SmartKeyAccount.t.sol`, `--match-path test/wallet/MandateWallet.t.sol`, `--match-path 'test/hedera/*'` (R13).
- [ ] **Step 5: Commit** `metatx-split T2: MtxPipelineLib + MetaTxBase on its internals`.

### Task 3: Token call paths on the library (§3.3, §3.4, §3.8; R1, R2, R7, R8, R12, R15)

**Files:**
- Modify: `smartcontracts/evm/src/metatx/ERC20MetaTx.sol` (`_mtxCtx`, `_execute` override, `_uaExecute`, `_executeTransfer`, `_uaExecuteTransfer`, the four digest views), `smartcontracts/evm/src/metatx/MetaTokenBase.sol` (named builders feed the same paths)
- Modify: `smartcontracts/evm/test/metatx/MetaTxParity.t.sol` (the §3.8 cases' `expect`), `smartcontracts/evm/test/vectors/metatx-parity.json` (only the `expect` fields)
- Create: `smartcontracts/evm/test/metatx/MtxCtx.t.sol`

**Interfaces:**
- Consumes: Task 2's `MtxPipelineLib`.
- Produces: `function _mtxCtx() internal view returns (MtxPipelineLib.Ctx memory)` in `ERC20MetaTx` (the only builder of `Ctx`).

- [ ] **Step 1: Failing tests.** `MtxCtx.t.sol`: `test_ctxEqualsTokenViews` (per kind on a clone: `domainSeparator` equals the one from `eip712Domain()`, `registry` equals `registry()`, `skaCloneCodehash` equals the clone code hash of `SMART_KEY_ACCOUNT_IMPL`, `hedera` equals `IS_HEDERA`), `test_digestViewsEqualKats` (the four views against `test/vectors/metatx_kat.json`, `metatransfer_kat.json` and the clientkeys / zether-prover envelope vectors), `test_relayedCall_writesRecordedSlots` (R7, per path), `test_minGas_smartKeyAccountMtxExecute` and `test_minGas_mldsa65UaExecute` (binary search of the smallest working gas; log it; assert the SigCheck starvation error below it), `test_hedera_hip632CallerIsToken` (R12). In the fixture, mark the both-fail cases `expect = "fee-error-first"` with the fee error as revert data.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path test/metatx/MtxCtx.t.sol` and the parity replay — FAIL.
- [ ] **Step 3: Implement.** `_execute`: build `Envelope` (with `dataHash = keccak256(m.data)` over the memory copy) and `CallFacts` (selector zero-padded for `len < 4`, the basis word by the existing assembly), `preCall`, `_selfCall`, fee move, event. `_uaExecute` the same with `ua = true`. Typed paths read `have`, call `preTransfer`, move fee and value, emit. Digest views call `callDigest` / `transferDigest`.
- [ ] **Step 4:** Parity replay passes with only the marked differences: `../../scripts/capped forge test --match-path test/metatx/MetaTxParity.t.sol -vv`; `MtxCtx.t.sol` passes; `test/v2/Layout.t.sol` passes unchanged (R15); `test/v2/*` pass.
- [ ] **Step 5: Commit** `metatx-split T3: token call paths on MtxPipelineLib (fee checked before the call, owner 2026-10-27)`.

### Task 4: Trade and receiver-fee signatures through the library; moved overrides to legacy (§3.4, owner 2026-10-27 Q3; R4)

**Files:**
- Modify: `smartcontracts/evm/src/metatx/ERC20MetaTx.sol` (`mtxTrade`, `uaTrade`, `mtxCancelOrder`, `uaCancelOrder`, `mtxInvalidateNonces`, `uaInvalidateNonces`), `smartcontracts/evm/src/metatx/MetaTokenBase.sol` (`mtxPayReceiverFee`, `uaPayReceiverFee` payee check; delete `_chargeFee`, `_requireNativeUASignature`, `_erc1271Gas`, the Hedera branch of `_requireValidSignature`), token interfaces for any error that now lives only in the library
- Create: `smartcontracts/evm/legacy/metatx-v1/` (copies of `_checkCall`, `_callFee`, `_checkTransfer`, `_checkUATransfer`, `_uaAuthorize`, the Hedera overrides as on `main`, with a README line naming the commit)
- Modify: `smartcontracts/evm/test/v2/Underlying.t.sol` (`test_libraryErrorsAreInTheTokenAbi` over `MtxPipelineLib` × every kind's artifact)

- [ ] **Step 1: Failing test.** Extend `test_libraryErrorsAreInTheTokenAbi`: every error selector in `out/MtxPipelineLib.sol/MtxPipelineLib.json` `abi` appears in each of the six kinds' artifact ABIs (`SigCheckGasStarved`, `ModeFeeInvalid`, `FeeRecipientRequired`, `HtsQueryFailed` named in the assertion message).
- [ ] **Step 2:** `../../scripts/capped forge test --match-test test_libraryErrorsAreInTheTokenAbi` — FAIL.
- [ ] **Step 3: Implement.** The address-path trade / cancel / invalidate calls use `requireSignature(_mtxCtx(), …)`; the UA twins `authorize(_mtxCtx(), from, PURPOSE_TRADE, …)`; receiver-pays payee through `requireSignature` / `authorize(PURPOSE_RECEIVER_FEE)`. Declare missing errors on the token interfaces. Move the superseded code to `legacy/metatx-v1/`.
- [ ] **Step 4:** The ABI test, the parity replay (trade, receiver-pays and DEX cases included: `test/v2/Trade.t.sol`, `Dex*.t.sol`, `ReceiverPays.t.sol`) and `test_allowlistPinned*` pass.
- [ ] **Step 5: Commit** `metatx-split T4: trade + receiver-fee signatures through MtxPipelineLib; v1 pipeline to legacy`.

### Task 5: PQZ / Zether relayed paths and the data-size bound (§3.6, §5.2; R9)

**Files:**
- Modify (only if the compiler requires it): `smartcontracts/evm/src/pqz/PqzLayer.sol`, `smartcontracts/evm/src/zether/ZetherLayer.sol`
- Create: `smartcontracts/evm/test/pqz/MtxSplitOverhead.t.sol`, log `smartcontracts/evm/runs/2026-10-27-metatx-split-overhead.txt`

**Interfaces:**
- Consumes: Tasks 3–4. `_isPqzOp`, `_pqzRule`, the Zether op list, `mtxSelectors`, `_envelopeBinding`, `_uaEnvelopeBinding`, `_batchable` stay in the kinds.

- [ ] **Step 1: Failing test** `test_splitOverhead_dataSizeBound`: for each accepted fee-UA kind (ECDSA address path; `mldsa65`, `fndsa512` on `uaExecute`) relay the smallest envelope and the largest built one (PQZL op 7 M = 8 with auditor at `n2304-kmax4096`; the largest PQZH debit at `n2048-kmax1024`), each against the pre-split figure from Task 1's fixture / the `runs/2026-10-26-t8d2b-fix-gas-<set>.txt` rows; assert `(overhead_largest − overhead_smallest) ≤ 8_000`.
- [ ] **Step 2:** `scripts/capped smartcontracts/evm/script/pqz/at-set.sh n2304-kmax4096 test --match-path test/pqz/MtxSplitOverhead.t.sol -vv` and the same at `n2048-kmax1024` — FAIL before the measurement code exists.
- [ ] **Step 3: Implement** the measurement (the PQZ helpers of `test/pqz/PqzStateGas.t.sol`); no change of the layers' semantics.
- [ ] **Step 4:** PASS at both sets; the PQZ / Zether suites pass at the committed set: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh n2304-kmax4096 test --match-path 'test/pqz/*'`, `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/zether/*'`; the parity replay's PQZ / Zether cases equal. Log to `runs/2026-10-27-metatx-split-overhead.txt`.
- [ ] **Step 5: Commit** `metatx-split T5: PQZ / Zether relayed paths on the split; data-size bound measured`.

### Task 6: Release pins — `DeployBase`, factory fixtures, `e2e.py` link closure (§4; R5, R6; gap §11.1 (2))

**Files:**
- Modify: `smartcontracts/evm/script/DeployBase.sol` (`_deployTokenFactory` NONE env `libs` += `MtxPipelineLib`; `_deployZether` env += `MtxPipelineLib`), `smartcontracts/evm/test/v2/Factory.t.sol` and every fixture building an `Env` by hand, `smartcontracts/evm/script/pqz/e2e.py` (`Deployer.linked()` transitive)
- Create: `smartcontracts/evm/test/v2/LinkClosure.t.sol`, `smartcontracts/evm/script/pqz/test_e2e_linked.py`

**Interfaces:**
- Produces: `Deployer.linked(name, src=None) -> (code, libs)` returning every library of the transitive closure, deployed leaf first (each library's own `linkReferences` resolved by `D.lib()`).

- [ ] **Step 1: Failing tests.** `LinkClosure.t.sol`: `test_envLibsEqualLinkClosure` (per kind, read `out/<Kind>.sol/<Kind>.json` `bytecode.linkReferences` and recursively each library's; assert the `Env.libs` set built by `DeployBase` equals it); `test_libraryOpcodes` (R6: walk each closure library's `deployedBytecode`, PUSH data skipped: no `0xff` SELFDESTRUCT, no `0xf2` CALLCODE; `0xf4` DELEGATECALL only in `MtxPipelineLib`). `test_e2e_linked.py`: a fake artifact tree (token → `MtxPipelineLib` → `HederaLib`) gives both libraries, `HederaLib` first.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path test/v2/LinkClosure.t.sol`; `python3 -I smartcontracts/evm/script/pqz/test_e2e_linked.py` — FAIL.
- [ ] **Step 3: Implement** the env additions and the transitive `linked()`. Update the `DeployBase` comment figures after Task 8's sizes (left as a Task 8 step).
- [ ] **Step 4:** Both tests pass; `test/v2/Factory.t.sol`, `FactoryZether.t.sol` pass; `OpenFactory._deploy`'s code-hash check passes on every release.
- [ ] **Step 5: Commit** `metatx-split T6: release link closure pinned (DeployBase, fixtures, e2e.py transitive)`.

### Task 7: `mtxPayMeta` / `uaPayMeta` and the shared vectors (CTR-MTX-26, §6.1; R11)

**Files:**
- Modify: `smartcontracts/evm/src/metatx/IMetaTokenV2.sol`, `smartcontracts/evm/src/metatx/MetaTokenBase.sol`, `smartcontracts/evm/foundry.toml` (`fs_permissions` += `{ access = "read-write", path = "../vectors/metatx" }`)
- Create: `smartcontracts/evm/test/metatx/PayMeta.t.sol`, `smartcontracts/vectors/metatx/paymeta.json`

**Interfaces:**
- Produces: `event PaymentMeta(bytes32 indexed payId, bytes meta)`; `metaPayId(bytes32 salt, bytes calldata meta) external pure returns (bytes32)` = `keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(meta)))`; `mtxPayMeta(address from, address to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature) external returns (bool)`; `uaPayMeta(bytes32 from, bytes32 to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata auth) external returns (bool)`. Vectors JSON: `[{name, schema, salt, meta, payId, payLane}]` (hex), schemas 1–4, empty body, a 4,096-byte body. Read by every family (Tasks 10–15) and `clientkeys` (Task 18).

- [ ] **Step 1: Failing tests** in `PayMeta.t.sol`, per kind (six clones): `test_payMeta_settlesLikeMtxPay` (same digest as `mtxPay` with `payId = metaPayId(salt, meta)`; `PaymentMeta` emitted before `PaymentSettled`; lane `payLane(payId)`, nonce 0), `test_uaPayMeta_settlesLikeUaPay`, `test_payMeta_mismatchAndReplayRefused` (a signature over another `payId` → `MetaTxBadSignature`; a second call with the same `(from, payId)` → `MetaTxBadNonce`), `test_payMeta_requiresPayable`, `test_payMetaVectors` (env `PAYMETA_WRITE=1` writes `../vectors/metatx/paymeta.json`, else compares every row with `metaPayId` / `payLane`).
- [ ] **Step 2:** `../../scripts/capped forge test --match-path test/metatx/PayMeta.t.sol` — FAIL.
- [ ] **Step 3: Implement** both entries in `MetaTokenBase`: `nonReentrant`, `AdminLib.requireFeature(PAYABLE)`, `payId = metaPayId(salt, meta)`, emit, then the `mtxPay` / `uaPay` body through one private helper that takes the built struct (stack depth with `via_ir` off). Write the vectors once with `PAYMETA_WRITE=1`.
- [ ] **Step 4:** PASS; size gate still 0 errors (`cd smartcontracts/evm && j=$(mktemp) && ../../scripts/capped forge build src --sizes --json > $j && python3 -I ../../scripts/size_gate.py $j size-baseline.json`).
- [ ] **Step 5: Commit** `metatx-split T7: mtxPayMeta / uaPayMeta (CTR-MTX-26) + shared paymeta vectors`.

### Task 8: Re-measure with the final token bytecode and re-pin (§5.3; gaps §11.1 (3); owner 2026-10-27 affected-steps gate)

**Files:**
- Modify: `pqz-core/params/sets/{n2048-kmax1024,n2304-kmax4096,n2560-kmax16384,n2816-kmax65536}/set.toml` (`debit_min_gas`, comment with the run log line; `roll_max` at `n2560-kmax16384` only if the rule moves it), the generated `PqzSet.sol` files (`gen_set.py --all`), `smartcontracts/evm/src/pqz/PqzSet.sol` (committed set), `smartcontracts/evm/test/v2/MetaTxGasV2.t.sol` (rows), `smartcontracts/evm/test/pqz/PqzStateGas.t.sol` (`PqzStatePinGasTest` expectations if `ROLL_MAX` moves), `smartcontracts/evm/test/ua/UARegistryPqzBound.t.sol` (re-pinned boundary), `smartcontracts/evm/size-baseline.json` (ratchet + comment entry), `smartcontracts/evm/script/DeployBase.sol` (size comment figures), `clients/zether-prover/src/zether.rs` (`gas_limits` relayed rows, only if a row moves)
- Create: logs `smartcontracts/evm/runs/2026-10-27-metatx-split-gas-<set>.txt` (four), `…-rollscan-n2560-kmax16384.txt`, `…-sizes.txt`, `…-node-floor.txt`

**Interfaces:**
- Produces: the measured `ERC1271_FLOOR` input (forge minimum gas of a `SmartKeyAccount`-signed `mtxExecute`, from Task 3's `test_minGas_smartKeyAccountMtxExecute`) for Task 17; the relayed overhead per call kind for Task 18's zether-prover check; the per-kind sizes for Task 19.

- [ ] **Step 1: Overhead table.** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/v2/MetaTxGasV2.t.sol -vv`; compare with Task 1's baseline; re-pin the rows; every row cold and warm per call kind in the log.
- [ ] **Step 2: Gas tables at the four sets.** For each set: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --match-path test/pqz/PqzStateGas.t.sol -vv | tee smartcontracts/evm/runs/2026-10-27-metatx-split-gas-<set>.txt`. Read: the cheapest PQZL debit on `uaExecute` (`burn 1 to an address, fresh ref` regular gas), `test_gas_rollMax_relayedFullTx` on both paths, `test_gas_prepareAcc_half{0,1}_relayedFullTx` (≤ 0.75 · 2^24), and at `n2048-kmax1024` `test_gasTable_holderRows` (`mldsa65`, `fndsa512` fit on `uaExecute`, `slhdsa128s` excluded) with the PQZH debit headroom.
- [ ] **Step 3: Rollscan at `n2560-kmax16384`.** `scripts/capped smartcontracts/evm/script/pqz/at-set.sh n2560-kmax16384 test --match-test test_pack_scanRoll -vv | tee …-rollscan-n2560-kmax16384.txt`. If 64 no longer fits ≤ 12,582,912 on either path: set `roll_max = 48` in that `set.toml` with the measured figures in its comment (owner rule 2026-10-27, no new ruling), regenerate, update `PqzStatePinGasTest` expectations, and note it for Task 19's CTR-PQZ-07 Change line and the owner report. The other three sets are re-asserted, not expected to move.
- [ ] **Step 4: Re-pin `debit_min_gas`** at all four sets from Step 2; `python3 -I pqz-core/params/sets/gen_set.py --all`; re-pin `UARegistryPqzBound.t.sol` (`test_register_msigHolderBoundary` at the new `C`). If a PQZH form stops fitting, it leaves option (A)'s on-chain list (that ruling's own rule): record for Task 19 and the report.
- [ ] **Step 5: Zether prover rows.** `cd smartcontracts/evm && ZETHER_GAS_PROBE=1 ../../scripts/capped forge test --match-path test/zether/ZetherGasLimit.t.sol -vv`; if a relayed row moves past the 1 % margin, re-pin `gas_limits` in `clients/zether-prover/src/zether.rs` and `cd clients/zether-prover && ../../scripts/capped cargo test -j2 gas_table_edges`.
- [ ] **Step 5b: Node floor input.** `../../scripts/capped forge test --match-test test_minGas_smartKeyAccountMtxExecute -vv | tee runs/2026-10-27-metatx-split-node-floor.txt` (from `smartcontracts/evm`); the logged minimum is Task 17's input.
- [ ] **Step 6: Sizes.** Size gate (Task 7 Step 4 command) `| tee …-sizes.txt`; ratchet `size-baseline.json` with a comment entry ("metatx split + PayMeta, 2026-10-27"); `DeployBase` comment figures.
- [ ] **Step 7: Affected-steps gate** (owner 2026-10-27): `python3 -I pqz-core/params/sets/gen_set.py --all --check`; forge at the four sets (`at-set.sh <set> test`, one at a time); the size gate; `python3 -I scripts/docs_check.py check`. Expected: all rc=0, logs under `smartcontracts/evm/runs/`.
- [ ] **Step 8: Commit** `metatx-split T8: re-measure on the final bytecode; debit_min_gas re-pinned at four sets (+ UARegistry), sizes ratcheted`.

### Task 9: `MtxRelayFee` + `MtxRelayExecutor` (CTR-MTX-27, §7.1; R14)

**Files:**
- Create: `smartcontracts/evm/src/metatx/MtxRelayFee.sol`, `smartcontracts/evm/test/metatx/MtxRelayFee.t.sol`
- Modify: `smartcontracts/evm/script/DeployBase.sol` (`new MtxRelayFee{salt: salt}()`; JSON keys `mtx_relay_fee`, `mtx_relay_executor`; check `EXECUTOR()` has code and `ROUTER()` names the router)

**Interfaces:**
- Produces: `relay(address target, bytes calldata callData, address token, MetaTxLib.MetaTransfer calldata t, bytes calldata sig)`, `uaRelay(address target, bytes calldata callData, address token, MetaTxLib.UAMetaTransfer calldata t, bytes calldata auth)`, `relayRef(address target, bytes calldata callData) view returns (bytes32)` = `keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, keccak256(callData)))`, `EXECUTOR() view returns (address)`, `event RelayFeePaid(bytes32 indexed ref, address indexed target, address indexed token, bytes32 payer, address payee, uint256 amount)`, `error RelayFeeShape()`; `MtxRelayExecutor.ROUTER()`, `exec(address target, bytes calldata callData)`.

- [ ] **Step 1: Failing tests** (CTR-MTX-27's eight conformance items plus): `test_relay_openModePaysCaller`, `test_relay_boundPayee`, `test_uaRelay_mldsa65Payer`, `test_relay_shapeRefused` (wrong `entryRef`, `batch ≠ payLane(ref)`, `nonce ≠ 0`, relayer not bound or not the router, fee mode not `NONE`, `fee ≠ 0` → `RelayFeeShape`), `test_relay_innerRevertBubbles`, `test_routerBoundPayment_refusedOutsideRouter` (the same `t, sig` straight to `mtxExecuteTransfer` → `MetaTxUnauthorizedRelayer`), `test_relay_callDataIsAnotherRouterPayment` (fails: the token sees the executor), `test_executor_onlyRouter`, `test_router_holdsNothingAfterOpenMode`, `test_relay_reentryRefused`, `test_relay_targetEnvelopeBoundToExecutor` (an inner mtx envelope with `MODE_RESTRICT_RELAYER` and relayer = executor works), `test_relayGas_ecdsaAndMldsa65` (logged).
- [ ] **Step 2:** `../../scripts/capped forge test --match-path test/metatx/MtxRelayFee.t.sol` — FAIL.
- [ ] **Step 3: Implement** per spec §7.1 (transient-slot `nonReentrant`, no stored state, executor by CREATE in the constructor; failure bubbles the inner revert data).
- [ ] **Step 4:** PASS; `DeployBase` dry run in `test/v2/Factory.t.sol` (or its deploy test) finds the router and executor.
- [ ] **Step 5: Commit** `metatx-split T9: MtxRelayFee + executor (CTR-MTX-27), DeployBase CREATE2`.

### Tasks 10–16: the other families (§6.2, §7.2; R16–R19)

Each family task builds that family's pay-meta entry and router exactly as the spec's §6.2 and §7.2 rows state, and its node adapter (spec §9 "For the other families"). Shared, from Task 7: `paymeta.json`. Each task also writes the family's own `ref` vectors (two rows: a short and a long call) in its vector path, generated by its existing generator.

### Task 10: Soroban

**Files:**
- Modify: `smartcontracts/soroban/contracts/token/src/lib.rs` (`pay_meta`, private `settle_pay`, event `PaymentMeta`), `smartcontracts/soroban/contracts/token/src/test.rs`, `smartcontracts/soroban/Cargo.toml` (workspace member)
- Create: `smartcontracts/soroban/contracts/relay-fee/{Cargo.toml,src/lib.rs,src/test.rs}`
- Modify: `scaas-node/src/adapters/soroban.rs` (pay-meta job, relay-fee job)

**Interfaces:**
- Produces: `pay_meta(env, from: Address, to: Address, amount: i128, salt: BytesN<32>, meta: Bytes, valid_until: u64)`; `RelayFee::relay(env, payer, target, func: Symbol, args: Vec<Val>, token, to, amount: i128, valid_until: u64, relayer: Address)`; `RelayFee::relay_ref(env, target, func, args) -> BytesN<32>`; event `RelayFeePaid`.

- [ ] **Step 1: Failing tests.** token: `pay_meta_vectors_match` (every `paymeta.json` row, `env.crypto().keccak256`), `pay_meta_settles_and_emits_meta_first`, `soroban_pay_meta_mismatch_and_replay` (second `pay_meta` with the same `pay_ref` → `RefUsed`). relay-fee: `relay_open_mode_pays_relayer`, `relay_bound_payee`, `relay_target_failure_reverts_all`, `soroban_router_bound_pay_refused_direct` (the payer's auth entry rooted at `relay` does not authorise a direct `token.pay`), `relay_ref_vectors`. Target: the mandate's signed revoke.
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2` — FAIL.
- [ ] **Step 3: Implement** per §6.2 / §7.2 Soroban rows (`payer.require_auth_for_args((target, func, args, token, to, amount, valid_until))`, `relayer.require_auth()`).
- [ ] **Step 4:** PASS; adapter: `cd scaas-node && ../scripts/capped cargo test -j2 adapters::soroban` with new `soroban_pay_meta_job_builds_pay_meta`, `soroban_relay_fee_job_checks_ref`.
- [ ] **Step 5: Commit** `metatx-split T10: Soroban pay_meta + relay-fee router + adapter`.

### Task 11: Solana

**Files:**
- Modify: `smartcontracts/solana/programs/scaas/src/{lib.rs,account.rs}` (`relay_pay_meta`, `relay_fee`, events `PaymentMeta`, `RelayFeePaid`, error `RelayFeeShape`), `smartcontracts/solana/programs/scaas/Cargo.toml` (`solana-keccak-hasher` direct), `smartcontracts/solana/programs/scaas/tests/{pay.rs,vectors.rs}`, `smartcontracts/solana/scripts/gen_vectors.py`
- Create: `smartcontracts/solana/programs/scaas/tests/relay_fee.rs`, a test-only target program `smartcontracts/solana/programs/relay_target/` (next to `cpi_wrapper`, never deployed)
- Modify: `scaas-node/src/adapters/solana.rs`

**Interfaces:**
- Produces: `relay_pay_meta(ctx: Context<RelayPay>, owner: [u8; 32], args: PayArgs, salt: [u8; 32], meta: Vec<u8>, auth: Auth)`; `relay_fee(ctx: Context<RelayFee>, owner: [u8; 32], args: PayArgs, target_data: Vec<u8>, target_accounts: u8, auth: Auth)`; marker PDA seeds `[b"relayfee"]`.

- [ ] **Step 1: Failing tests.** `pay_meta_vectors_match`, `pay_meta_emits_meta_then_settled`, `solana_pay_meta_mismatch_and_replay` (lane ≠ `payLane`, nonce ≠ 0, second pay → `BadNonce`); `relay_fee_open_mode_pays_lane`, `relay_fee_bound_payee`, `relay_fee_target_failure_reverts`, `relay_fee_self_target_refused`, `relay_fee_indirect_reentry_refused` (target = `cpi_wrapper` wrapping a `scaas` call), `solana_router_bound_pay_refused_direct` (`relay_pay` with `relayer` = marker → `WrongRelayer`), `relay_ref_vectors`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh solana` — FAIL.
- [ ] **Step 3: Implement** per §6.2 / §7.2 Solana rows; `relay_pay`'s body shared by the three entries.
- [ ] **Step 4:** PASS; `cd scaas-node && ../scripts/capped cargo test -j2 adapters::solana` with `solana_pay_meta_job_builds_ix`, `solana_relay_fee_job_checks_ref`.
- [ ] **Step 5: Commit** `metatx-split T11: Solana relay_pay_meta + relay_fee + adapter`.

### Task 12: Cosmos

**Files:**
- Modify: `smartcontracts/cosmos/Cargo.toml` (workspace dep `sha3`, members), `smartcontracts/cosmos/metaop/src/lib.rs` (`meta_pay_id`, `pay_lane`, `relay_ref`), `smartcontracts/cosmos/token/src/lib.rs` (`RelayPayMeta`), `smartcontracts/cosmos/tests/tests/{flows.rs,vector.txt}`, `smartcontracts/cosmos/build-wasm.sh` if it lists contracts
- Create: `smartcontracts/cosmos/relayfee/`, `smartcontracts/cosmos/relayexec/`
- Modify: `scaas-node/src/adapters/cosmos.rs`

**Interfaces:**
- Produces: `scaas_metaop::{meta_pay_id(salt: &[u8; 32], meta: &[u8]) -> [u8; 32], pay_lane(p: &[u8; 32]) -> [u8; 32], relay_ref(chain_id: &str, target: &[u8], msg: &[u8]) -> [u8; 32]}`; token `ExecuteMsg::RelayPayMeta { payload, auth, salt: HexBinary, meta: Binary }`; router `ExecuteMsg::Relay { target: String, msg: Binary, token: String, payload: Binary, auth: Auth }`, `InstantiateMsg { executor_code_id: u64 }`; executor `ExecuteMsg::Exec { target: String, msg: Binary }`.

- [ ] **Step 1: Failing tests** (cw-multi-test in `flows.rs`): `pay_meta_vectors_match`, `pay_meta_emits_meta_then_settled`, `cosmos_pay_meta_mismatch_and_replay`, `relay_fee_open_mode_pays_sender`, `relay_fee_bound_payee`, `relay_fee_target_failure_reverts_all`, `relay_fee_target_sees_executor` (a `msg` that is a token `Relay` of another router-bound payment fails), `relayexec_only_router`, `cosmos_router_bound_pay_refused_direct` (token `Relay` sent by anyone but the router → bound-relayer error), `relay_ref_vectors`.
- [ ] **Step 2:** `cd smartcontracts/cosmos && ../../scripts/capped cargo test -j2` — FAIL.
- [ ] **Step 3: Implement** per §6.2 / §7.2 Cosmos rows (messages in order: `Exec`, token `Relay`, open-mode `Transfer`).
- [ ] **Step 4:** PASS; `cd scaas-node && ../scripts/capped cargo test -j2 adapters::cosmos` with `cosmos_pay_meta_job_builds_msg`, `cosmos_relay_fee_job_checks_ref`.
- [ ] **Step 5: Commit** `metatx-split T12: Cosmos RelayPayMeta + relayfee / relayexec + adapter`.

### Task 13: Sui

**Files:**
- Modify: `smartcontracts/move/sui/sources/meta.move` (`relay_pay_meta`, `public(package) fun pay_routed`, `PaymentMeta`), `smartcontracts/move/sui/tests/{meta_tests.move,vectors.move}`, `smartcontracts/move/sui/scripts/gen_vectors.py`
- Create: `smartcontracts/move/sui/sources/relayfee.move`, `smartcontracts/move/sui/tests/relayfee_tests.move`
- Modify: `scaas-node/src/adapters/sui.rs`

**Interfaces:**
- Produces: `relay_pay_meta<T>(account: &mut Account<T>, to: address, amount: u128, salt: vector<u8>, meta: vector<u8>, valid_until: u64, relayer: address, extra: vector<u8>, a: Auth, clock: &Clock, ctx: &mut TxContext)`; `pay_routed<T>(account: &mut Account<T>, marker: address, to: address, amount: u128, pay_ref: vector<u8>, valid_until: u64, extra: vector<u8>, a: Auth, clock: &Clock, ctx: &mut TxContext)`; `relayfee::{RelayFee (shared), relay_manage, relay_revoke_with_sig, relay_cancel, relay_invalidate_nonces, relay_ref}`.

- [ ] **Step 1: Failing tests.** `pay_meta_vectors_match`, `pay_meta_emits_meta_then_settled`, `sui_pay_meta_mismatch_and_replay`; per wrapped target one success test, `relay_open_mode_pays_sender`, `relay_target_abort_aborts_all`, `sui_router_bound_pay_refused_direct` (`relay_pay` with `relayer` = the `RelayFee` object address → `EWrongRelayer`), `relay_ref_vectors`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh sui` — FAIL.
- [ ] **Step 3: Implement** per §6.2 / §7.2 Sui rows (`sui::hash::keccak256`; `call = bcs` of the target name and every argument).
- [ ] **Step 4:** PASS; `cd scaas-node && ../scripts/capped cargo test -j2 adapters::sui` with `sui_pay_meta_job_builds_ptb`, `sui_relay_fee_job_checks_ref`.
- [ ] **Step 5: Commit** `metatx-split T13: Sui relay_pay_meta + relayfee module + adapter`.

### Task 14: Aptos

**Files:**
- Modify: `smartcontracts/move/aptos/sources/meta.move` (`relay_pay_meta`, `pay_meta_check`, `package fun pay_routed`, `PaymentMeta`), `smartcontracts/move/aptos/scripts/check_entry_visibility.sh`, `smartcontracts/move/aptos/tests/{meta_tests.move,vectors.move}`, `smartcontracts/move/aptos/scripts/gen_vectors.py`
- Create: `smartcontracts/move/aptos/sources/relayfee.move`, `smartcontracts/move/aptos/tests/relayfee_tests.move`
- Modify: `scaas-node/src/adapters/aptos.rs`

**Interfaces:**
- Produces: `package entry fun relay_pay_meta(lane: &signer, owner: address, asset: Object<Metadata>, to: address, amount: u128, salt: vector<u8>, meta: vector<u8>, valid_until: u64, relayer: address, extra: vector<u8>, public_key: vector<u8>, sig: vector<u8>, envelope: vector<u8>)`; `#[view] pay_meta_check(…same minus signer, plus lane: address) : vector<u8>`; `relayfee::{relay_manage_signed, relay_mandate_open, relay_revoke_signed, relay_cancel_signed, relay_invalidate_nonces_signed, relay_ref, marker()}` with `marker() = object::create_object_address(&@scaas, b"scaas.relayfee")`.

- [ ] **Step 1: Failing tests.** `pay_meta_vectors_match`, `pay_meta_check_matches_relay_pay_meta`, `aptos_pay_meta_mismatch_and_replay`; per wrapped target one success test, `relay_open_mode_pays_lane`, `relay_target_abort_aborts_all`, `aptos_router_bound_pay_refused_direct`, `relay_ref_vectors`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh aptos` — FAIL.
- [ ] **Step 3: Implement** per §6.2 / §7.2 Aptos rows; list the new entries in `check_entry_visibility.sh`.
- [ ] **Step 4:** PASS (tests and the visibility check); `cd scaas-node && ../scripts/capped cargo test -j2 adapters::aptos` with `aptos_pay_meta_payload_bytes`, `aptos_relay_fee_job_checks_ref`.
- [ ] **Step 5: Commit** `metatx-split T14: Aptos relay_pay_meta + relayfee module + adapter`.

### Task 15: TON — pay-meta on the jetton wallet

**Files:**
- Modify: `smartcontracts/ton/contracts/common.tact` (`PaymentMeta` opcode `0x9b1c0d04`, `metaPayId`, `payLane`), `smartcontracts/ton/contracts/jetton.tact` (`OP_PAY` with `params`), `smartcontracts/ton/tests/{jetton.spec.ts,vectors.spec.ts}`, `smartcontracts/ton/vectors/ton-vectors.json`
- Modify: `scaas-node/src/adapters/ton.rs` (pay-meta job: `params` cell)

**Interfaces:**
- Produces: `fun metaPayId(salt: Int, meta: Cell): Int`, `fun payLane(p: Int): Int`, message `PaymentMeta { master: Address; payId: Int as uint256; meta: Cell }`; `SignedOp.params` on `OP_PAY` = `salt:uint256 ^meta`.

- [ ] **Step 1: Failing tests.** `paymeta vectors match` (Tact `keccak256` over the snake chain = every `paymeta.json` row, the 4,096-byte body included), `pay with params emits PaymentMeta then PaymentSettled`, `ton pay meta mismatch and replay`, `pay without params unchanged`.
- [ ] **Step 2:** `cd smartcontracts/ton && ../../scripts/capped npm test` — FAIL.
- [ ] **Step 3: Implement** per §6.2 TON row.
- [ ] **Step 4:** PASS; `cd scaas-node && ../scripts/capped cargo test -j2 adapters::ton` with `ton_pay_meta_job_builds_params`.
- [ ] **Step 5: Commit** `metatx-split T15: TON pay-meta on OP_PAY + adapter`.

### Task 16: TON — relay-fee escrow router

**Files:**
- Create: `smartcontracts/ton/contracts/relayfee.tact` (messages `RelayCall` `0x5b0a1d30`, `RelayRefund` `0x5b0a1d31`, event `RelayFeePaid` `0x9b1c0d05`), `smartcontracts/ton/tests/relayfee.spec.ts`
- Modify: `smartcontracts/ton/tact.config.json`, `scaas-node/src/adapters/ton.rs` (relay-fee job: escrow tracking, `RelayRefund` after `deadline`)

**Interfaces:**
- Produces: `RelayCall { target: Address; call: Cell; payWallet: Address; payOp: Cell; payAuth: Cell; payStateInit: Cell?; master: Address; deadline: Int as uint32 }`, `RelayRefund { ref: Int as uint256 }`, getter `pending(ref): Pending?`, `relayRef(target, call): Int`.

- [ ] **Step 1: Failing tests** (sandbox): `release on target excess`, `refund on call bounce`, `refund by RelayRefund after deadline, refused before`, `release and refund are exclusive` (target runs without excess: no release; refund after `deadline`; a late excess after refund pays nothing), `second RelayCall to a pending target refused`, `payment bounce clears pending`, `ton router bound pay refused direct` (a `SignedOp` naming the router sent by anyone else → `E_RELAYER`), `call that is a SignedOp naming the router refused`, `notification from a foreign jetton wallet ignored`, `relay ref vectors`.
- [ ] **Step 2:** `cd smartcontracts/ton && ../../scripts/capped npm test` — FAIL.
- [ ] **Step 3: Implement** per §7.2 TON row (open mode only; one pending per target).
- [ ] **Step 4:** PASS; `cd scaas-node && ../scripts/capped cargo test -j2 adapters::ton` with `ton_relay_fee_job_tracks_escrow`, `ton_relay_fee_refunds_after_deadline`.
- [ ] **Step 5: Commit** `metatx-split T16: TON relay-fee escrow router + adapter`.

### Task 17: `scaas-node` — EVM (§9; gap §11.1 (4))

**Files:**
- Modify: `scaas-node/src/guard.rs` (`ERC1271_FLOOR`, the relay-fee call-table row, `mtxPayMeta` / `uaPayMeta` selectors), `scaas-node/src/metatx.rs` (pay-meta checks, submit `mtxPayMeta` / `uaPayMeta` or `mtxExecuteTransfer`), `scaas-node/src/config.rs` (`max_pay_meta_bytes`, default 2,048), `scaas-node/src/indexer.rs` (`PaymentMeta`, `RelayFeePaid` joined by `entry_ref`), `scaas-node/src/abi.rs`, `scaas-node/src/submit.rs` (the two floor tests)

**Interfaces:**
- Consumes: Task 8's measured minimum gas; Task 9's `relay` / `uaRelay` ABI and `mtx_relay_fee` deployment key.
- Produces: `pub const ERC1271_FLOOR: u64` = the forge minimum + the frame margin of spec §9.

- [ ] **Step 1: Failing tests:** `erc1271_floor_covers_forge_minimum` (the constant ≥ the measured minimum in `runs/2026-10-27-metatx-split-node-floor.txt`, and `== 21_000 + (400_000 * 64 / 63 + 5_000) * 64 / 63 + prefix`), `pay_meta_job_checks_commitment_lane_nonce`, `pay_meta_cap_refused`, `relay_fee_row_requires_router_and_registered_token`, `relay_fee_submits_only_when_fee_covers_gas`, `indexer_joins_payment_meta`.
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2` — FAIL.
- [ ] **Step 3: Implement** per spec §9 (simulation +20 %, capped; no gas price or block limit assumed).
- [ ] **Step 4:** PASS, the whole crate.
- [ ] **Step 5: Commit** `metatx-split T17: scaas-node EVM — floor re-pinned, pay-meta jobs, relay-fee row, indexer`.

### Task 18: Clients — `clientkeys`, `ua-rs`, `ua-qt`, zether-prover check (§9)

**Files:**
- Modify: `clients/clientkeys/src/evm.js` (`metaPayId`, `buildMtxPayMeta`, `buildUaPayMeta`, refuse when `entryRef != metaPayId(salt, meta)`, `relayRef`, `buildRelayFee` open mode), `clients/clientkeys/test/` (new `paymeta.test.js`, `relayfee.test.js`), `clients/ua-rs/src/lib.rs` (hash helpers next to `keccak256`: `meta_pay_id`, `pay_lane`, `relay_ref`), `clients/ua-qt/src/ua_kinds.rs` (`#[qinvokable]` `metaPayId`, `payLane`, `relayRef` over `scaas-ua`), `clients/ua-qt/tests/tst_ua.qml`, `clients/zether-prover/src/zether.rs` (no change expected; assert)

**Interfaces:**
- Consumes: `paymeta.json`; Task 9's `relayRef` formula.
- Produces: `scaas_ua::{meta_pay_id(salt: &[u8; 32], meta: &[u8]) -> [u8; 32], pay_lane(p: &[u8; 32]) -> [u8; 32], relay_ref(chain_id: u64, target: &[u8; 20], call_data: &[u8]) -> [u8; 32]}`; QML `UaKinds.metaPayId(saltHex, metaHex)`, `payLane(hex)`, `relayRef(chainId, targetHex, callDataHex)` (hex strings).

- [ ] **Step 1: Failing tests:** `clientkeys` `paymeta vectors`, `refuses a payId that does not commit to meta`, `relayRef matches the contract vector`; `ua-rs` `meta_pay_id_vectors`, `relay_ref_matches_vector`; `ua-qt` `tst_ua.qml` cases for the three invokables against the same vectors; zether-prover `ua_signer_gas` unchanged (`cargo test -j2 ua_signer`).
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test`; `cd clients/ua-rs && ../../scripts/capped cargo test -j2`; ua-qt: `QMAKE=/home/ha/usr/Qt/6.12.0/gcc_64/bin/qmake6 LD_LIBRARY_PATH=/home/ha/usr/Qt/6.12.0/gcc_64/lib QT_QPA_PLATFORM=offscreen scripts/capped sh -c 'cmake -S clients/ua-qt -B /tmp/claude-1000/ua-qt-build -DCMAKE_PREFIX_PATH=/home/ha/usr/Qt/6.12.0/gcc_64 && cmake --build /tmp/claude-1000/ua-qt-build -j2 && cd /tmp/claude-1000/ua-qt-build && ctest --output-on-failure'` — FAIL.
- [ ] **Step 3: Implement.** `clientkeys` `buildRelayFee` shows both intents (call + payment) in one prompt object and sets an inner mtx envelope's relayer (with `MODE_RESTRICT_RELAYER`) to the executor's address; `ua-rs` / `ua-qt` give the hashes the Qt and Rust wallets need.
- [ ] **Step 4:** All PASS.
- [ ] **Step 5: Commit** `metatx-split T18: clients — pay-meta + relay-fee (clientkeys), hash helpers (ua-rs, ua-qt)`.

### Task 19: Docs, decisions, TODO (§11; gap §11.1 (1))

**Files:**
- Modify: `docs/decisions.md` (CTR-MTX-07, -17, -26, -27 Change lines with owner 2026-10-27 and commits; NET-EVM-06 addendum figures; CTR-PQZ-07 Change if `ROLL_MAX` moved; CTR-PQZ-14 `debit_min_gas` re-pin under the C0-5 heading with the affected-steps gate), `docs/contracts/metatx.md` (CTR-MTX-07 and §1, CTR-MTX-17 table: step 3 fee checks, step 6 fee move; §8 gas; §11 interfaces; §12 per-family equivalents; CTR-MTX-26 / -27 BUILT), `docs/networks/{evm,soroban,solana,cosmos,sui,aptos,ton}.md`, `docs/networks/README.md` (NEAR / Algorand carry CTR-MTX-26 / -27), `docs/networks/evm.md` NET-EVM-06 rows for `MtxPipelineLib` and `MtxRelayFee` (information), `docs/contracts/pq-zero-knowledge.md` §9.3, `docs/contracts/zether.md` §19 (if moved), `pqz-core/params/sets/*/SET.md` and the sets README (figures), `docs/node/job-api.md`, `docs/node/submit-lanes.md` (new NODE-LANE rules), `docs/clients/signers-clientkeys.md`, `TODO.md` (this item done; NEAR / Algorand bring-up next; the line "neither `mtxRollOver` nor `mtxPrepareAcc` is relayable" → "both are relayable (CTR-MTX-19); the prover may also call `mtxPrepareAcc` directly"), `HANDOFF.md`

- [ ] **Step 1:** Write every change with measured figures from Tasks 5, 8, 9 (no `[estimate]` left for a measured item; each figure names its run log).
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check` — 0 errors.
- [ ] **Step 3:** `grep -n "neither \`mtxRollOver\` nor" TODO.md` — no match.
- [ ] **Step 4: Commit** `metatx-split T19: docs + decisions (CTR-MTX-07/-17/-26/-27, NET-EVM-06, PQZ re-pins), TODO line fixed`.

### Task 20: Closing gates — resumable per-step runner over every family

**Files:**
- Create: `smartcontracts/evm/runs/2026-10-27-metatx-split-gates.sh` (modelled on `smartcontracts/evm/runs/2026-10-27-review2-gates.sh`), logs `smartcontracts/evm/runs/2026-10-27-metatx-split-<step>.txt`

**Interfaces:**
- Produces: `2026-10-27-metatx-split-gates.sh [--only <step>]`, `GATES_FRESH=1` re-runs all; each log's first line `# <step> at commit <sha>`, last line `rc=<n>`; a step is skipped when its log ends `rc=0` at the current short HEAD and the tree is clean apart from `smartcontracts/evm/runs/`; stop at the first failure.

- [ ] **Step 1: Write the runner.** Steps: `forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 sizes gen-set docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys ua-rs ua-qt soroban solana cosmos sui aptos ton named-tests`. The first twelve as in the review2 runner; `ua-rs` / `ua-qt` as Task 18; each family step `scripts/capped smartcontracts/scripts/test.sh <family>` with its output tee'd into the log. `named-tests` greps the step logs and fails unless every new test of this plan appears as passed: the forge names of Tasks 1–9 as `[PASS] <name>` in the forge logs; each family's names of Tasks 10–16 in that family's log in its tool's pass form (cargo `test <name> ... ok`, Move `[ PASS    ] …::<name>`, jest `✓ <name>`); `ua-qt`'s ctest names; and no family log reports `0 passed`, `ignored` for a new test, or a skipped suite. `zether-cross` keeps "6 passed; 0 failed; 0 skipped".
- [ ] **Step 2: Self-check the guard.** Run `--only named-tests` against a copy of one family log with one new test name removed (a scratch file named by `NAMED_TESTS_LOG_DIR`): it must exit non-zero. Then restore.
- [ ] **Step 3: Run** `smartcontracts/evm/runs/2026-10-27-metatx-split-gates.sh`. Expected: every step `rc=0`. On a failure: fix in the owning task's files, commit, re-run (finished steps at the old commit re-run, since HEAD moved).
- [ ] **Step 4: Commit** the runner and every log: `metatx-split T20: closing gates, all families (resumable runner)`.
- [ ] **Step 5:** Report to the owner: commits, measured overheads, `ROLL_MAX` (moved or not), `debit_min_gas` figures, PQZH forms still on chain, sizes; ask for the go to merge / push.
