// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console} from "forge-std/Script.sol";
import {DeployBook} from "./DeployBook.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../src/factory/ChainEnvCode.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {GovernanceLib} from "../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../src/governance/GovernanceBits.sol";
import {GovernanceRouter} from "../src/governance/GovernanceRouter.sol";
import {TokenStore} from "../src/metatx/TokenStore.sol";
import {WrappedLib} from "../src/metatx/WrappedLib.sol";
import {MtxPipelineLib} from "../src/metatx/MtxPipelineLib.sol";
import {HederaLib} from "../src/hedera/HederaLib.sol";
import {TradeLib} from "../src/trade/TradeLib.sol";
import {ZetherLib} from "../src/zether/ZetherLib.sol";
import {ZetherWrappedLib} from "../src/zether/ZetherWrappedLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NormalToken} from "../src/metatx/NormalToken.sol";
import {WrappedToken} from "../src/metatx/WrappedToken.sol";
import {NormalRegulatedToken} from "../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../src/regulated/WrappedRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../src/regulated/WrappedZetherRegulatedToken.sol";
import {RegulatedLib} from "../src/regulated/RegulatedLib.sol";
import {ComplianceRegistry} from "../src/regulated/ComplianceRegistry.sol";
import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
import {PqChat} from "../src/pqchat/PqChat.sol";
import {IPqChat} from "../src/pqchat/IPqChat.sol";
import {PqVault} from "../src/pqvault/PqVault.sol";
import {IPqVault} from "../src/pqvault/IPqVault.sol";
import {UARegistry} from "../src/ua/UARegistry.sol";
import {IUARegistry} from "../src/ua/IUARegistry.sol";
import {UARegistryCoreLib} from "../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../src/ua/UARegistryAuxLib.sol";
import {UARegistryRegLib} from "../src/ua/UARegistryRegLib.sol";
import {RelayFeeRouter, RelayFeeExecutor} from "../src/metatx/RelayFeeRouter.sol";
import {UAKinds} from "../src/ua/UAKinds.sol";
import {PqUA} from "../src/ua/PqUA.sol";
import {WebAuthnP256Verifier} from "../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {P256Verifier} from "../src/ua/verifiers/P256Verifier.sol";
import {Ed25519Verifier} from "../src/ua/verifiers/Ed25519Verifier.sol";
import {Bip340Verifier} from "../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../src/ua/verifiers/Secp256k1Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier,
    ZetherSchnorrBls12381Verifier
} from "../src/ua/verifiers/PairingVerifiers.sol";
import {Musig2Secp256k1Verifier} from "../src/ua/verifiers/Musig2Secp256k1Verifier.sol";
import {BlsMultiBls12381Verifier} from "../src/ua/verifiers/BlsMultiBls12381Verifier.sol";
import {FrostSecp256k1Verifier} from "../src/ua/verifiers/FrostSecp256k1Verifier.sol";
import {Musig2Bn254Verifier} from "../src/ua/verifiers/Musig2Bn254Verifier.sol";
import {FrostBn254Verifier} from "../src/ua/verifiers/FrostBn254Verifier.sol";
import {MldsaVerifier} from "../src/ua/MlDsa.sol";
import {MldsaVerifyOnly, MldsaVerifyOnly44, MldsaVerifyOnly65, MldsaVerifyOnly87} from "../src/ua/MlDsaVerifyOnly.sol";
import {FndsaVerifier} from "../src/ua/FnDsa.sol";
import {SlhdsaVerifier} from "../src/ua/SlhDsa.sol";
import {UAPrecompileProbe} from "./UAPrecompileProbe.sol";
import {kindModuleNames, kindImplArgs} from "./KindModules.sol";
import {ImplArgs} from "../src/metatx/ITokenModule.sol";
import {ZetherDisclosure} from "../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../src/zether/ZetherStatements.sol";
import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../src/zether/ZetherVerifier.sol";
import {IZetherInnerProductVerifier} from "../src/zether/IZetherVerifier.sol";
import {NormalZetherToken} from "../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../src/zether/WrappedZetherToken.sol";
import {PqzKeyVerifier} from "../src/pqz/PqzKeyVerifier.sol";
import {PqzSafety} from "../src/pqz/PqzSafety.sol";
import {PqzStateLib} from "../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../src/pqz/PqzViewLib.sol";
import {PqzWrappedLib} from "../src/pqz/PqzWrappedLib.sol";
import {PqPrecompileProbe} from "./PqPrecompileProbe.sol";
import {DeployGas} from "./DeployGas.sol";

/// @notice The public-chain gate's probe (Q4): one CREATE2 of `code`, so a release that is not a call (the UA registry, its
///         library) is measured as its own transaction. Deployed only inside the gate's snapshot, never sent.
contract ReleaseProbe {
    function deploy(bytes calldata code) external returns (address a) {
        bytes memory c = code;
        assembly ("memory-safe") { a := create2(0, add(c, 32), mload(c), 0) }
        require(a != address(0), "ReleaseProbe: the creation reverted");
    }
}

/// @title Shared deploy steps (CTR-GEN-05, CTR-GEN-06, NET-EVM-05): `chain_uid` from the RPC, the deterministic CREATE2
///        deployer, the UA registry with its verifiers, the token factory with its implementations, the `chainUid()` gate.
/// @notice `new X{salt: DEPLOY_SALT}(…)` inside a broadcast goes through the deterministic deployer at `CREATE2_FACTORY`
///         (forge-std), so an address depends only on the init code and the salt: a contract that takes `chain_uid`
///         gets a different address on each chain, the others the same one. Re-running on the same chain collides:
///         a new version needs a new `DEPLOY_SALT`.
abstract contract DeployBase is DeployBook {
    /// @notice CREATE2 salt of every contract: `DEPLOY_SALT` env, default `keccak256("scaas.deploy.v1")`.
    bytes32 internal salt;
    /// @notice The chain's genesis hash (`DeployBook._chainUid`).
    bytes32 internal uid;
    /// @notice `DEPLOY_ZETHER` env (default false): also deploy the Zether stack (`_deployZether`, any chain
    ///         but Hedera; owner ruling 2026-10-31).
    bool internal deployZether;
    /// @notice `DEPLOY_WRAPPED` env (default false): also deploy the `WRAPPED` release (`_deployWrapped`, GD-12; CTR-GOV-19:
    ///         every kind runs on the SCaaS testnet).
    bool internal deployWrapped;
    /// @notice `DEPLOY_REGULATED` env (default false): also deploy the regulated releases (`_deployRegulated`, regulated-kinds
    ///         spec §6.1): kinds 8 and 9, enabled (plan T28), and the canonical `ComplianceRegistry` (plan T33).
    bool internal deployRegulated;
    /// @notice `DEPLOY_PQCHAT` env (default false): also register `PqChat` (UA-7, D22: class 3, kind 0 on the generic path) and,
    ///         when the chain's notice period is 0, create one instance (`_deployPqChat`, plan 3c T92).
    bool internal deployPqChat;
    /// @notice `DEPLOY_PQVAULT` env (default false): also register `PqVault` (CTR-PQV-02, CTR-PQV-13: class 4, kind 0 on the generic
    ///         path, no body module) and, when the chain's notice period is 0, create one instance (`_deployPqVault`, PqVault
    ///         plan V7).
    bool internal deployPqVault;
    /// @notice `DEPLOY_PQZ` env (default false; on for the SCaaS testnet, owner 2026-11-15): also the PQZ releases 4, 5, 12, 13
    ///         on this factory (`_deployPqz`), their one dependency `PQZ_KEY_VERIFIER`.
    bool internal deployPqz;
    /// @notice `PQZ_KEY_VERIFIER` / `MLDSA44_VERIFIER` / `MLDSA65_VERIFIER` / `MLDSA87_VERIFIER` env (default 0): the verifiers
    ///         whose constructors probe the chain's own precompiles, so forge's EVM cannot build them; `deploy.sh evm`'s first
    ///         step (`script/pq_verifiers.py`, e2e.py's builders) deploys each by CREATE2 with `DEPLOY_SALT` on the real chain
    ///         after its probe passed. The gen-1 registry lists `pqz-mlwe` 0x0142 and, with `MLDSA_PRECOMPILE=on`, the ML-DSA
    ///         kinds 0x0130 / 0x0131 / 0x0134 on them; a registry that misses a kind whose precompile the chain answers is
    ///         refused by name (`_pqPrecompiles`, `_mldsaVerifier`, `_checkGen1Kinds`).
    address internal pqzKeyVerifier;
    address internal mldsa44Verifier;
    address internal mldsa65Verifier;
    address internal mldsa87Verifier;
    /// @notice `MLDSA_PRECOMPILE` env, `on` (default) or `off` (owner 2026-11-15, CTR-UA-23 / CTR-UA-39; a runtime flag, no
    ///         codegen). The ML-DSA kinds have two paths only: `on` = the chain's EIP-8355 precompile where its probe passes
    ///         (the verifier from `MLDSA<x>_VERIFIER`, or one this run's EVM probes), else, where no precompile answers, pure
    ///         Solidity on the registry's expanded-key cache; `off` = pure Solidity with the cache on every ML-DSA kind, as on
    ///         a chain without a precompile (the `MLDSA<x>_VERIFIER` env refused). `on` is the safe default: on a chain without
    ///         an ML-DSA precompile it deploys what `off` does, and on one with it the gate below refuses a registry that would
    ///         miss it. The SCaaS testnet's main registry deploys `on`; the matrix's `mldsaalt` group deploys the opposite.
    bool internal mldsaPrecompile;
    /// @notice `COMPLIANCE_ADMIN` env, a UA id (`bytes32`), required with `DEPLOY_REGULATED`, no default (round 3r, spec §6):
    ///         the canonical `ComplianceRegistry`'s first admin, native or derived (the router is its constructor argument;
    ///         CTR-AS-07, regulated-kinds spec §6.1, F-21); the registry's constructor refuses 0 (`AdminZero`).
    bytes32 internal complianceAdmin;
    /// @notice `FACTORY_ADMIN_NEXT` env (optional `bytes32`, round 3r spec §6): the run's last transaction is the factory's
    ///         `transferAdmin(next, chainUid)`; `next` accepts by its own signed `mtxAcceptAdmin`, a separate step. JSON `factory_admin`,
    ///         `factory_pending_admin`.
    bytes32 internal factoryAdminNext;
    /// @notice The chain's `SmartKeyAccountFactory` (`Deploy.s.sol` sets it first), the directory's entry; 0 leaves it open.
    address internal accountFactory;
    /// @notice The relay pair's salt on every stack (spec §13.2, Fable P2-2): one address on every chain, reused when there;
    ///         `DEPLOY_SALT` moves only the rest.
    bytes32 internal constant RELAY_SALT = keccak256("scaas.deploy.v1");
    /// @notice The directory's entries this run deployed or reused (`_deployShared`), written by `_writeDirectory`.
    address internal relayFeeRouter;
    address internal relayFeeExecutor;
    address internal complianceRegistry;
    address internal zetherStatements;
    /// @notice `OpenFactory.noticePeriod` (plan 5g-Z2; owner ruling 2026-10-20): `NOTICE_PERIOD` env. Safe by default:
    ///         every chain not in `_isTestChain` is a mainnet (22776, Hedera 295, Ethereum, BSC, an unknown chain), with
    ///         default and floor 3 days; 7622 defaults to 10 minutes, the other test / dev chains to 0. At most 30 days
    ///         (`MAX_NOTICE_PERIOD`, the factory's).
    uint64 internal noticePeriod;
    /// @notice The chain's per-transaction gas cap (owner X1, spec 2026-11-19-registry-verify-only-kinds §9): `TX_GAS_CAP`
    ///         (env), required, no default: the deploy book's value, which `script/tx_gas_cap.py` probes. The registry's
    ///         constructor argument `txGasCap` and every deploy gate that counted EIP-7825's 2^24 read it. 0 until `_setup`:
    ///         `_deployUARegistry` refuses it by name.
    uint64 internal txGasCap;
    /// @notice This chain's `GovernanceRouter` (`_deployGovRouter`), the factory's one-time `govRouter`; 0 until deployed.
    address internal govRouter;
    /// @notice Its code hash from this build (`_builtHash`), what `configureChain` pins; 0 with no router.
    bytes32 internal govRouterCodeHash;
    /// @notice The release list (chain-neutral spec §6.2, Fable P3-5): `RELEASES_JSON` (default `./releases.json`).
    ///         `RELEASES_WRITE=true` writes it from this deployment (the first chain's); otherwise, when the file exists, the
    ///         deploy refuses a factory, library, release or registrar whose address or code hash differs from its row.
    string internal releasesPath;
    bool internal releasesWrite;
    string internal releasesJson;
    uint256 internal releaseRows;
    /// @notice Set by `_configureChain` on a chain id `chain-uids.json` lists more than once while `SIBLINGS_CONFIGURED`
    ///         is not set: the registrar's run stops after `configureChain` (the sibling order, chain-neutral spec §3.3).
    bool internal configureOnly;
    /// @notice How many `chain-uids.json` rows name this chain id (`_setup`; a test harness leaves it 0).
    uint256 internal chainSiblings;

    /// @notice `UA_VERIFY_BUDGET = min(12 M, ⌊0.7 × the chain's per-transaction gas cap⌋)` (CTR-UA-23): EIP-7825
    ///         chains (16,777,216) 12 M, Hedera (15 M) 10.5 M.
    uint64 internal constant UA_VERIFY_BUDGET = 12_000_000;
    uint64 internal constant UA_VERIFY_BUDGET_HEDERA = 10_500_000;
    /// @notice Gen-1 caps of the PQ kinds without an ML-DSA precompile (P6c, `test/ua/PqGas.t.sol`, accounts.md §1.15):
    ///         ML-DSA on the registry's cached expanded key (measured valid 4.11 M / 5.80 M; `verifyCached`'s self-call loses
    ///         1/64, so the least working caps are 4,174,074 / 5,893,303 warm, ~5 k more cold, and the caps leave ~73 k (~1.7 %) /
    ///         ~52 k (~0.9 %) over the cold minimum, pinned by `PqGas.t.sol`; ML-DSA-65's
    ///         cap keeps the treasury {mldsa65 ×3} t=2 over the budget), FN-DSA (2.27–2.35 M measured) + ~6 %,
    ///         SLH-DSA above its 1.32 M worst case. Each ≤ 50 % of the 12 M budget (the deploy rule is ≤ 75 %, `_pqKindFits`).
    ///         The margin policy of the ML-DSA caps: the least multiple of 50,000 at least 30,000 above the least working gas of
    ///         the worst accepting input, cold pointers (round 3zh F-2, `PqGas.t.sol` asserts `max + 30,000 <= cap` over the
    ///         `pq_kat.json` row, the `pq_signatures.json` PoP and signatures, `mldsa_cache.json`'s 16-signature batch and its
    ///         exactly-ω-hint signature): 4,187,757 (44) and 5,910,464 (65, the ω row) measured 2026-11-15, under their caps.
    uint64 internal constant CAP_MLDSA44 = 4_250_000;
    uint64 internal constant CAP_MLDSA65 = 5_950_000;
    /// @notice `mldsa87` without a precompile (CTR-UA-39 Q1 as rewritten by the owner 2026-11-15): `verifyCached` on its
    ///         three-part cache; the worst accepting input (the exactly-ω-hint signature, three cold pointers) least working
    ///         8,772,934 ± 1,000 (`PqGas.t.sol`, 2026-11-15) plus the margin policy above: 8,850,000 (spec MD-11's 8,800,000 came
    ///         from one signature, F-2). 73.75 % of the 12 M budget (≤ 75 %, `_pqKindFits`): enabled on every EIP-7825 chain, not
    ///         on Hedera's 10.5 M (7,875,000 at 75 %).
    uint64 internal constant CAP_MLDSA87 = 8_850_000;
    /// @notice The ML-DSA caps of the precompile path (`MLDSA_PRECOMPILE=on` where the probe passes): `mldsa44` / `mldsa65`
    ///         200,000, the cap of `script/pqz/e2e.py` (`CAP_ML`, P6g; `requireAuthorized` measured 301,776 on the SCaaS
    ///         testnet with the transaction's intrinsic and calldata); `mldsa87` 250,000, PROVISIONAL (spec 2026-11-04-mldsa87
    ///         §4; reset 4's T-GAS on the SCaaS testnet measured ~140,360 execution, `runs/2026-11-15-scaas-testnet-reset4/tgas.py`).
    uint64 internal constant CAP_MLDSA44_PRECOMPILE = 200_000;
    uint64 internal constant CAP_MLDSA65_PRECOMPILE = 200_000;
    uint64 internal constant CAP_FNDSA512 = 2_500_000;
    uint64 internal constant CAP_SLHDSA128S = 1_400_000;
    /// @notice `fndsa1024` (CTR-UA-40, owner 2026-11-04): pure Solidity on every chain whose budget holds the cap at ≤ 66 % (every
    ///         budget ≥ 7,954,546). PROVISIONAL until T-GAS: the largest NIST KAT verify measured (4,932,967) + 6.4 %, the margin of
    ///         `fndsa512`'s cap (spec 2026-11-04-fndsa1024 F6).
    uint64 internal constant CAP_FNDSA1024 = 5_250_000;
    uint64 internal constant CAP_MLDSA87_PRECOMPILE = 250_000;
    /// @notice `pqz-mlwe` 0x0142 (CTR-PQZ-13): `PqzKeyVerifier`'s R_REG PoP through the `PQZ` precompile, the cap of
    ///         `script/pqz/e2e.py` (`CAP_PQZ`, the P6g gen-1 registry of the SCaaS testnet).
    uint64 internal constant CAP_PQZ_MLWE = 4_500_000;
    /// `bls12381-multi` (0x0121): `BlsMultiBls12381Verifier.CHECK_GAS` (300,000) + 1/63 + 5,000 plus the call around it with the
    /// stored `p` (up to 12,644 B) as calldata (spec 2026-11-19-bls12381-multi §8.2). Plan Task 9 (`UAGas.t.sol`
    /// `test_T_GAS_blsMultiLeastCap`): the least cap at n = 64, k = 33 is 310,778 on the hot path (`verify`) and 310,823 on a stored
    /// path (`verifyMinimal`), both set by `CHECK_GAS`'s floor; 330,000 keeps 19,177 (6.2 %) over it.
    uint64 internal constant CAP_BLS12381_MULTI = 330_000;

    /// @notice The ML-DSA precompile candidates, probed in order (CTR-UA-69, owner R9; CTR-UA-23 / CTR-UA-39): by default the
    ///         addresses of an EIP in Final status (none for ML-DSA today) and the chain's own, the SCaaS chains'
    ///         `0x…5caa0012` / `…0013` / `…0014`; EIP-8355's Draft `0x12` / `0x13` / `0x14` only after them and only under the
    ///         chain's `probe_draft_precompiles` flag with the owner's confirmation in the book (`_draftProbe`), probed then with
    ///         the fuller probe (`_mldsaPrecompile`). `i` 0, 1, 2 = 44, 65, 87.
    function _mldsaCandidates(uint256 i) internal view returns (address[] memory c) {
        bool draft = _draftProbe();
        c = new address[](draft ? 2 : 1);
        c[0] = address(uint160(0x5caa0012 + i));
        if (draft) c[1] = address(uint160(0x12 + i));
    }

    /// @notice CTR-UA-69 (owner R9, C5): the Draft candidates are probed only where the chain's row in `chain-uids.json` sets
    ///         `probe_draft_precompiles: true` and the chain's book records the owner's confirmation
    ///         (`probe_draft_precompiles_owner`, its reason); the flag without it refuses by name (`DRAFT_PROBE_UNCONFIRMED`).
    function _draftProbe() internal view returns (bool) {
        if (!_draftFlag()) return false;
        require(
            _draftConfirmed(),
            "DRAFT_PROBE_UNCONFIRMED: chain-uids.json sets probe_draft_precompiles, the book has no probe_draft_precompiles_owner (CTR-UA-69)"
        );
        return true;
    }

    /// @notice The chain's `probe_draft_precompiles` (its `chain-uids.json` row by chain id and `uid`; absent: false).
    function _draftFlag() internal view virtual returns (bool) {
        string memory j = vm.readFile("./chain-uids.json");
        for (uint256 i;; ++i) {
            string memory p = string.concat(".chains[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, p)) return false;
            if (
                vm.parseJsonUint(j, string.concat(p, ".chainId")) == block.chainid
                    && vm.parseJsonBytes32(j, string.concat(p, ".chainUid")) == uid
            ) {
                string memory f = string.concat(p, ".probe_draft_precompiles");
                return vm.keyExistsJson(j, f) && vm.parseJsonBool(j, f);
            }
        }
    }

    /// @notice The owner's confirmation of the Draft probe in the chain's book (`probe_draft_precompiles_owner`, non-empty).
    function _draftConfirmed() internal view virtual returns (bool) {
        string memory path = _bookPath(uid, ".json");
        if (!vm.exists(path)) return false;
        string memory b = vm.readFile(path);
        return vm.keyExistsJson(b, ".probe_draft_precompiles_owner")
            && bytes(vm.parseJsonString(b, ".probe_draft_precompiles_owner")).length != 0;
    }

    /// @notice C5-1, NET-EVM-06. A release is one CREATE2 of the whole implementation in the registrar's transaction.
    ///         Under EIP-8037 the code deposit is state gas, `STATE_GAS_PER_BYTE` per byte of runtime, on top of the
    ///         regular gas, which EIP-7825 caps at the chain's `txGasCap` (2^24 there; owner X1: `TX_GAS_CAP`). Two gates, chosen by the declared
    ///         `RELEASE_GAS_GATE` (`_publicGate`; Q4 of CTR-MTX-30, R40), each refusing by name before anything is sent:
    ///         the SCaaS testnet's (`testnet`, the default, the owner's formula): the transaction needs
    ///         `runtime x 1,530 + 2^24` and may not exceed the block gas limit, runtime sizes from `size-baseline.json`
    ///         (the contracts over the EIP-170 limit; any other is priced at `EIP170_LIMIT`). At ua-mtx-merge T10:
    ///         `NormalToken` 32,089 B = 65.9 M, `WrappedToken` 42,669 B = 82.1 M, `NormalZetherToken` 40,543 B = 78.8 M,
    ///         `WrappedZetherToken` 51,031 B = 94.9 M, `NormalPqzToken` 46,384 B = 87.7 M, `WrappedPqzToken` 56,223 B =
    ///         102.8 M, `SCaaSDex` 33,399 B = 67.9 M, `UARegistry` 29,710 B = 62.2 M, `UARegistryLib` (since T66b 3.1b split into `UARegistryCoreLib` and `UARegistryAuxLib`) 36,192 B = 72.2 M:
    ///         each fits a 200 M block (the figures move with the baseline; `GovDeploy.t.sol` reads it). A public chain's
    ///         (`public`): the release transaction measured (`_measuredGas`), regular + state x 1.05 within the block
    ///         gas limit and regular x 1.05 < 2^24 (`_checkMeasuredGas`).
    uint256 internal constant STATE_GAS_PER_BYTE = 1530;
    uint256 internal constant EIP170_LIMIT = 24_576;

    /// @notice EIP-7954's code size limit, the default of `CHAIN_CODE_LIMIT` (GD-4).
    uint256 internal constant EIP7954_CODE_LIMIT = 65_536;

    /// @notice The runtime size of contract `name` by `size-baseline.json` (any contract outside it is priced at
    ///         `EIP170_LIMIT`: the size gate refuses one above that limit with no baseline row).
    function _baselineRuntime(string memory name) internal view returns (uint256) {
        string memory key = string.concat(".", name);
        string memory base = vm.readFile("./size-baseline.json");
        return vm.keyExistsJson(base, key) ? vm.parseJsonUint(base, key) : EIP170_LIMIT;
    }

    /// @notice The block gas limit the release of contract `name` needs.
    function _releaseGasNeed(string memory name) internal view returns (uint256) {
        return _baselineRuntime(name) * STATE_GAS_PER_BYTE + txGasCap;
    }

    /// @notice CTR-GOV-19, GD-4: the chain's code size limit is declared, never derived from a chain id. `CHAIN_CODE_LIMIT`
    ///         (env), default 65,536 B (EIP-7954); the SCaaS testnet's runbook sets 131,072 (`maxCodeSize` `0x20000`,
    ///         EIP-7954 left out). One rule on every chain. The chain's own limit stays the last word: a deploy it refuses
    ///         fails closed.
    function _chainCodeLimit() internal view virtual returns (uint256) {
        return vm.envOr("CHAIN_CODE_LIMIT", EIP7954_CODE_LIMIT);
    }

    /// @notice Refuses a release whose runtime exceeds `limit`, naming the contract, before anything is sent.
    function _checkCodeFits(string memory name, uint256 limit) internal view {
        uint256 runtime = _baselineRuntime(name);
        if (runtime > limit) {
            revert(
                string.concat(
                    name,
                    " runtime ",
                    vm.toString(runtime),
                    " B > chain code limit ",
                    vm.toString(limit),
                    " B (CHAIN_CODE_LIMIT, CTR-GOV-19)"
                )
            );
        }
    }

    function _checkReleaseGas(string memory name, uint256 limit) internal view {
        uint256 need = _releaseGasNeed(name);
        if (limit < need) {
            revert(
                string.concat(
                    "block gas limit ",
                    vm.toString(limit),
                    " < ",
                    vm.toString(need),
                    " needed to deploy the ",
                    name,
                    " release (NET-EVM-06)"
                )
            );
        }
    }

    /// @notice The block gas limit the deploy gate reads: the chain's actual `block.gaslimit`.
    function _blockGasLimit() internal view virtual returns (uint256) {
        return block.gaslimit;
    }

    /// @notice The SCaaS testnet's gate: refuses before anything is sent when the release's runtime exceeds the chain's
    ///         declared code limit, or the chain's block gas limit cannot hold `runtime x 1,530 + 2^24`.
    function _requireReleaseGas(string memory name) internal view {
        _checkCodeFits(name, _chainCodeLimit());
        _checkReleaseGas(name, _blockGasLimit());
    }

    /// @notice Q4 (CTR-MTX-30, R40): the gate is declared per deploy, never derived from a chain id (one rule on every
    ///         chain): `RELEASE_GAS_GATE` env, `testnet` (default: the SCaaS testnet's formula, `_requireReleaseGas(name)`)
    ///         or `public` (the measured release transaction). Any other value refuses.
    function _publicGate() internal view virtual returns (bool) {
        bytes32 g = keccak256(bytes(vm.envOr("RELEASE_GAS_GATE", string("testnet"))));
        require(g == keccak256("testnet") || g == keccak256("public"), "RELEASE_GAS_GATE: testnet or public");
        return g == keccak256("public");
    }

    /// @notice The gate of the release `name`, sent next as the call `to.call(data)` (`to` 0: a CREATE2 of the init code
    ///         `data`): on `testnet` `_requireReleaseGas(name)`; on `public` the declared code limit, then the transaction
    ///         measured and checked (`_checkMeasuredGas`), its figures kept in `releaseGas`.
    function _requireReleaseGas(string memory name, address to, bytes memory data) internal {
        if (!_publicGate()) return _requireReleaseGas(name);
        _checkCodeFits(name, _chainCodeLimit());
        (uint256 regular, uint256 state) = _measuredGas(to, data);
        releaseGas[name] = [regular, state];
        _checkMeasuredGas(name, regular, state, _blockGasLimit());
    }

    /// @notice The measured figures of each release the public gate passed: `[regular, state]`.
    mapping(string => uint256[2]) internal releaseGas;

    /// @notice The release transaction run once in a snapshot of this simulation (the RPC's fork under `forge script`,
    ///         else the local EVM), from the sender that sends it next, then reverted; a broadcast is paused around it, so
    ///         nothing of it is sent. Regular gas is forge's `lastCallGas` (the call is its own transaction under
    ///         `isolate`, intrinsic and calldata included) x 64/63, the gas a CREATE2 frame keeps back
    ///         (`GovDeploy.t.sol`'s method); state gas is EIP-8037's.
    function _measuredGas(address to, bytes memory data) internal returns (uint256 regular, uint256 state) {
        (VmSafe.CallerMode mode, address sender,) = vm.readCallers();
        bool broadcasting = mode == VmSafe.CallerMode.RecurrentBroadcast;
        if (broadcasting) vm.stopBroadcast();
        else sender = address(this);
        uint256 snap = vm.snapshotState();
        if (to == address(0)) (to, data) = (address(new ReleaseProbe()), abi.encodeCall(ReleaseProbe.deploy, (data)));
        vm.prank(sender);
        (bool ok,) = to.call(data);
        Vm.Gas memory g = vm.lastCallGas();
        vm.revertToStateAndDelete(snap);
        if (broadcasting) vm.startBroadcast(sender);
        require(ok && g.gasStateUsed >= 0, "release gas: the measured run reverted");
        return (g.gasTotalUsed * 64 / 63, uint256(int256(g.gasStateUsed)));
    }

    /// @notice The public-chain gate (Q4, R40): a release fits when `(regular + state) x 1.05` (the gas limit the deploy sends,
    ///         `DeploySend.s.sol`, NET-EVM-11; EIP-8037: a transaction is included only if regular + state fits, never by
    ///         a block's `gas_used`) is within the chain's block gas limit, and `regular x 1.05 < 2^24` (EIP-7825).
    function _checkMeasuredGas(string memory name, uint256 regular, uint256 state, uint256 limit) internal view {
        uint256 asked = (regular + state) * 105 / 100;
        if (regular * 105 / 100 >= txGasCap) {
            revert(
                string.concat(
                    name,
                    " release: regular gas x 1.05 = ",
                    vm.toString(regular * 105 / 100),
                    " >= txGasCap ",
                    vm.toString(uint256(txGasCap)),
                    " (EIP-7825, NET-EVM-06)"
                )
            );
        }
        if (limit < asked) {
            revert(
                string.concat(
                    "block gas limit ",
                    vm.toString(limit),
                    " < ",
                    vm.toString(asked),
                    " asked by the ",
                    name,
                    " release (measured regular + state x 1.05, NET-EVM-06)"
                )
            );
        }
        console.log(
            string.concat(
                "release gas | ",
                name,
                " | regular ",
                vm.toString(regular),
                " | state ",
                vm.toString(state),
                " | asked ",
                vm.toString(asked),
                " | block gas limit ",
                vm.toString(limit)
            )
        );
    }

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
        txGasCap = _txGasCapEnv();
        deployZether = vm.envOr("DEPLOY_ZETHER", false);
        deployWrapped = vm.envOr("DEPLOY_WRAPPED", false);
        deployRegulated = vm.envOr("DEPLOY_REGULATED", false);
        deployPqChat = vm.envOr("DEPLOY_PQCHAT", false);
        deployPqVault = vm.envOr("DEPLOY_PQVAULT", false);
        deployPqz = vm.envOr("DEPLOY_PQZ", false);
        pqzKeyVerifier = vm.envOr("PQZ_KEY_VERIFIER", address(0));
        mldsa44Verifier = vm.envOr("MLDSA44_VERIFIER", address(0));
        mldsa65Verifier = vm.envOr("MLDSA65_VERIFIER", address(0));
        mldsa87Verifier = vm.envOr("MLDSA87_VERIFIER", address(0));
        bytes32 mp = keccak256(bytes(vm.envOr("MLDSA_PRECOMPILE", string("on"))));
        require(mp == keccak256("on") || mp == keccak256("off"), "MLDSA_PRECOMPILE: on or off");
        mldsaPrecompile = mp == keccak256("on");
        complianceAdmin = vm.envOr("COMPLIANCE_ADMIN", bytes32(0));
        require(
            !deployRegulated || complianceAdmin != bytes32(0),
            "COMPLIANCE_ADMIN: a UA id (bytes32), required with DEPLOY_REGULATED"
        );
        factoryAdminNext = vm.envOr("FACTORY_ADMIN_NEXT", bytes32(0));
        noticePeriod = _checkedNotice(block.chainid, vm.envOr("NOTICE_PERIOD", _defaultNotice(block.chainid)));
        uid = _chainUid();
        releasesPath = vm.envOr("RELEASES_JSON", string("./releases.json"));
        releasesWrite = vm.envOr("RELEASES_WRITE", false);
        bool listedUid;
        (chainSiblings, listedUid) = _chainUidListed();
        require(chainSiblings == 0 || listedUid, "chain_uid is not chain-uids.json's for this chain id (NET-ALL-22)");
        require(
            CREATE2_FACTORY.code.length != 0,
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)"
        );
    }

    function _defaultNotice(uint256 c) internal pure returns (uint256) {
        return !_isTestChain(c) ? 3 days : c == 7622 ? 10 minutes : 0;
    }

    /// @dev The period is immutable: a mainnet never gets a factory with a short notice (review 5g-Z2 P2-4, owner
    ///      2026-10-20); no silent `uint64` truncation.
    function _checkedNotice(uint256 c, uint256 notice) internal pure returns (uint64) {
        require(notice <= type(uint64).max, "NOTICE_PERIOD exceeds uint64");
        require(
            _isTestChain(c) || notice >= 3 days, "NOTICE_PERIOD below 3 days on a mainnet (not a listed test chain)"
        );
        return uint64(notice);
    }

    /// @notice The test / dev chains (owner ruling 2026-10-20), a fixed list: local dev (31337, 1337), the node e2e's
    ///         anvils (31900–31999), 7622, Hedera 296–298 and the public testnets of chain-uids.json (Ethereum Sepolia,
    ///         Hoodi, Holesky; ETC Mordor; BSC, Gnosis Chiado, Polygon Amoy, Base, Celo Sepolia and Alfajores, OP,
    ///         Arbitrum, Avalanche Fuji, Linea). Every other chain is a mainnet.
    function _isTestChain(uint256 c) internal pure returns (bool) {
        if (c == 31337 || c == 1337 || (c >= 31900 && c <= 31999) || c == 7622 || (c >= 296 && c <= 298)) return true;
        uint32[14] memory t = [
            uint32(11155111),
            560048,
            17000,
            63,
            97,
            10200,
            80002,
            84532,
            11142220,
            44787,
            11155420,
            421614,
            43113,
            59141
        ];
        for (uint256 i; i < t.length; ++i) {
            if (c == t[i]) return true;
        }
        return false;
    }

    /// @notice The token factory (`noticePeriod`) and the UA registry (`_deployUARegistry`, with its libraries `UARegistryCoreLib`, `UARegistryAuxLib` and `UARegistryRegLib`) by CREATE2; when the deployer
    ///         is the registrar (plan 5g-Z2: only the factory deploys releases), env version 1 of `NORMAL` and of the DEX
    ///         (`_env`: the factory, `chain_uid`, the registry, the `SmartKeyAccount` implementation, Hedera, the linked
    ///         libraries with their code hashes), then the `NORMAL` release (on that registry: the UA ledger, CTR-UA-18)
    ///         and the `SCaaSDex` release, each version 1; otherwise the registrar publishes and deploys them later from
    ///         the same init code. Writes `token_factory`, `implementation_normal`, `dex_implementation`, `ua_registry`,
    ///         `ua_registry_core_lib`, `ua_registry_aux_lib`,
    ///         `relay_fee_router`, `relay_fee_executor`, `governance_router`, `chain_uid` into the JSON object `"deploy"`; with
    ///         `DEPLOY_WRAPPED` also the `WRAPPED` release (`_deployWrapped`, GD-12), with `DEPLOY_ZETHER` the Zether stack
    ///         (`_deployZether`, not on Hedera). NORMAL and `WRAPPED` both exceed EIP-170 (the UA ledger).
    ///         Each release is refused first when its runtime exceeds the chain's declared `CHAIN_CODE_LIMIT`
    ///         (`_checkCodeFits`, CTR-GOV-19, GD-4).
    function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
        internal
        returns (OpenFactory f)
    {
        _requireKindHere("OpenFactory", uid); // NET-ALL-25 (C18), where the factory is created (review P3-1)
        if (deployZether) {
            require(!isHedera, "DEPLOY_ZETHER: not on Hedera (ZetherLayer refuses a Hedera env)");
            (bool bls,) = _precompiles(); // fail before deploying anything (CTR-ZTH-52: the only chain requirement)
            require(bls, "DEPLOY_ZETHER: the chain has no EIP-2537 (BLS12-381 precompiles)");
        }
        // round 3r (spec §6, §13.10): the relay pair under RELAY_SALT (reused when there), the UA registry, the router, the
        // compliance registry and ZetherStatements, then the factory: the registrar's native id is its only constructor
        // argument, its first admin, and its address depends on none of them; this chain's values are its one-time
        // `configureChain`, then the directory (`setChainEntries`). The admin deploys the releases itself: its own deploy is
        // its own approval (spec §5.6).
        UARegistry reg = _deployShared(smartKeyAccountImpl, isHedera);
        f = new OpenFactory{salt: salt}(MetaTxLib.pad(registrar));
        if (register) _configureChain(f, registrar);
        if (register && !configureOnly) _writeDirectory(f, reg);
        vm.serializeAddress("deploy", "token_factory", address(f));
        if (register && !configureOnly) {
            // the link closure of NormalToken's release (task 6; T66b §4.5: its body modules' link references): MtxPipelineLib,
            // which links HederaLib, and GovernanceLib (TradeLib's code is compiled into the module T)
            address[] memory libs = new address[](3);
            (libs[0], libs[1], libs[2]) = (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib));
            _libRows(libs);
            address none = _kindRelease(
                f,
                IOpenFactory.TokenKind.NORMAL,
                "NormalToken",
                type(NormalToken).creationCode,
                "",
                _env(f, address(reg), smartKeyAccountImpl, isHedera, new address[](0), libs)
            );
            _gateInstance(f, none, f.tokenEnvOf(IOpenFactory.TokenKind.NORMAL, 1)); // one instance's chainUid (§6.2)
            vm.serializeAddress("deploy", "implementation_normal", none);
            // The DEX release (CTR-DEX-24): clones come from `createDex`; DEX version 1.
            address[] memory dexLibs = new address[](2);
            (dexLibs[0], dexLibs[1]) = (address(GovernanceLib), address(TradeLib));
            // T66b §4.2, the liquidity spec §9.1: the DEX's governance and liquidity modules first, pinned in the DEX env beside
            // the libraries, named in `implArgs` in that order
            address[] memory dexModules = new address[](2);
            dexModules[0] = _module("SCaaSDexAdmin.sol:SCaaSDexGovernanceModule", abi.encode(address(f), bytes("")), 0);
            dexModules[1] =
                _module("SCaaSDexLiquidityModule.sol:SCaaSDexLiquidityModule", abi.encode(address(f), bytes("")), 0);
            bytes memory dexArgs = abi.encode(ImplArgs(dexModules));
            _publishDexEnv(f, smartKeyAccountImpl, isHedera, dexLibs, dexModules);
            vm.serializeAddress("deploy", "dex_implementation", _dexRelease(f, dexArgs));
        }
        if (deployWrapped && register && !configureOnly) {
            _deployWrapped(f, address(reg), smartKeyAccountImpl, isHedera);
        }
        if (deployRegulated && register && !configureOnly) {
            _deployRegulated(f, address(reg), smartKeyAccountImpl, isHedera);
        }
        if (deployPqChat && register && !configureOnly) _deployPqChat(f, address(reg));
        if (deployPqVault && register && !configureOnly) _deployPqVault(f, address(reg));
        if (deployPqz && register && !configureOnly) _deployPqz(f, address(reg), smartKeyAccountImpl, isHedera);
        if (deployZether && !configureOnly) _deployZether(f, register, smartKeyAccountImpl, address(reg));
        if (register && !configureOnly && factoryAdminNext != bytes32(0)) {
            f.transferAdmin(factoryAdminNext, f.chainUid());
        }
        if (register) {
            require(
                f.admin() == MetaTxLib.pad(registrar)
                    && f.pendingAdmin() == (configureOnly ? bytes32(0) : factoryAdminNext),
                "factory admin gate (admin, pendingAdmin)"
            );
        }
        vm.serializeBytes32("deploy", "factory_admin", f.admin());
        vm.serializeBytes32("deploy", "factory_pending_admin", f.pendingAdmin());
        vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    /// @notice DEX env 1: the libraries and the modules, under the factory's chain word (CTR-GOV-27; its own frame: the
    ///         caller's stack is full).
    function _publishDexEnv(
        OpenFactory f,
        address smartKeyAccountImpl,
        bool isHedera,
        address[] memory dexLibs,
        address[] memory dexModules
    ) internal {
        f.publishDexEnv(
            1,
            uid,
            _withModules(_env(f, address(0), smartKeyAccountImpl, isHedera, new address[](0), dexLibs), dexModules)
        );
    }

    /// @notice The shared contracts before the factory (spec §13.10): the relay pair under `RELAY_SALT` (reused when there),
    ///         the UA registry, the router (before every release: its address is in the env), the `ComplianceRegistry` with
    ///         `DEPLOY_REGULATED`, `ZetherStatements` with `DEPLOY_ZETHER`.
    function _deployShared(address smartKeyAccountImpl, bool isHedera) internal returns (UARegistry reg) {
        (relayFeeRouter, relayFeeExecutor) = _deployRelayFeeRouter();
        reg = _deployUARegistry(smartKeyAccountImpl, isHedera);
        _deployGovRouter(address(reg), smartKeyAccountImpl, isHedera);
        if (deployRegulated) complianceRegistry = _deployComplianceRegistry();
        if (deployZether) zetherStatements = address(new ZetherStatements{salt: salt}());
    }

    /// @notice `setChainEntries` of what `_deployShared` left (0 leaves an entry open), then the gate: `directory()` equals
    ///         what this run deployed (spec §13.7).
    ///         Every expected code hash comes from this build (spec §13.7; Fable 3r3s3t P3-6), never from an address alone:
    ///         `keccak256(runtimeCode)` for a contract without immutables, else the code at this build's CREATE2 address of
    ///         its init code (`_builtHash`; the executor: the router's CREATE at nonce 1).
    function _writeDirectory(OpenFactory f, UARegistry reg) internal {
        require(relayFeeExecutor == vm.computeCreateAddress(relayFeeRouter, 1), "relay executor: not this build's");
        f.setChainEntries(
            IOpenFactory.ChainEntries(
                relayFeeRouter,
                _builtHash(relayFeeRouter, type(RelayFeeRouter).creationCode, RELAY_SALT),
                relayFeeExecutor.codehash,
                complianceRegistry,
                complianceRegistry == address(0) ? bytes32(0) : _complianceRegistryCodehash(),
                accountFactory,
                _builtHash(
                    accountFactory, abi.encodePacked(type(SmartKeyAccountFactory).creationCode, abi.encode(uid)), salt
                ),
                zetherStatements,
                zetherStatements == address(0) ? bytes32(0) : keccak256(type(ZetherStatements).runtimeCode)
            ),
            f.chainUid()
        );
        IOpenFactory.Directory memory d = f.directory();
        require(
            d.uaRegistry == address(reg) && d.govRouter == govRouter && d.relayFeeRouter == relayFeeRouter
                && d.relayFeeExecutor == relayFeeExecutor && d.complianceRegistry == complianceRegistry
                && d.smartKeyAccountFactory == accountFactory && d.zetherStatements == zetherStatements,
            "directory gate"
        );
    }

    /// @notice The code hash of `at` only when `at` is this build's CREATE2 address of `initCode` under `s` (the init code
    ///         fixes the runtime, immutables included); 0 for 0. Fable 3r3s3t P3-6.
    function _builtHash(address at, bytes memory initCode, bytes32 s) internal view returns (bytes32) {
        if (at == address(0)) return bytes32(0);
        address d = vm.isContext(VmSafe.ForgeContext.ScriptGroup) ? CREATE2_FACTORY : address(this);
        require(
            at == vm.computeCreate2Address(s, keccak256(initCode), d), "code hash: not this build's CREATE2 address"
        );
        return at.codehash;
    }

    /// @notice Plan 3c T92 (UA-7 D22, topics spec §11): `PqChat` on the factory's generic path, with no factory code: its
    ///         body module `PqChatTopics` (CTR-TOK-30, 3C-D2) by CREATE2 with `DEPLOY_SALT` (`_module`, its own gate), the
    ///         class env 1 of `(3, 0)` (the registry; `params[0]` the chain's declared code-size limit, `CHAIN_CODE_LIMIT`;
    ///         the module pinned in `libs`), release 1 from the chain-neutral init code with `implArgs` naming the module,
    ///         the `(3, 0)` switch on, and one instance owned by no UA when the notice period lets it be created now (JSON
    ///         `pqchat_instance`; else created after the notice period by anyone, `createInstance`). JSON
    ///         `pqchat_implementation`, `pqchat_topics`. **UNAUDITED.**
    function _deployPqChat(OpenFactory f, address reg) internal {
        _requireKindHere("PqChat", uid); // NET-ALL-25 (C18), where PqChat is created (review P3-1)
        address topics = _module("PqChatTopics.sol:PqChatTopics", abi.encode(address(f)), 3, 0);
        f.publishClassEnv(3, 0, 1, f.chainUid(), _pqchatEnv(reg, topics));
        address impl = _pqchatRelease(f, abi.encode(topics));
        f.setClassKindEnabled(3, 0, true, f.chainUid());
        vm.serializeAddress("deploy", "pqchat_topics", topics);
        vm.serializeAddress("deploy", "pqchat_implementation", impl);
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(3, 0, 1);
        if (f.classReleaseOf(id).usableFrom <= block.timestamp) {
            address inst = f.createInstance(
                id, keccak256("scaas.pqchat.instance.1"), abi.encodeCall(IPqChat.initialize, (bytes32(0)))
            );
            vm.serializeAddress("deploy", "pqchat_instance", inst);
        }
    }

    /// @notice PqVault plan V7 (CTR-PQV-02, CTR-PQV-13): `PqVault` on the factory's generic path, as `PqChat` with no body module:
    ///         the class env 1 of `(4, 0)` (the registry; `params[0]` the chain's declared code-size limit, `CHAIN_CODE_LIMIT`),
    ///         release 1 from the chain-neutral init code with empty `implArgs`, the `(4, 0)` switch on, and one instance owned by
    ///         no UA when the notice period lets it be created now (JSON `pqvault_instance`; else created after the notice period
    ///         by anyone). JSON `pqvault_implementation`. **UNAUDITED.**
    function _deployPqVault(OpenFactory f, address reg) internal {
        _requireKindHere("PqVault", uid); // NET-ALL-25 (C18), where PqVault is created (review P3-1)
        IFactoryToken.Env memory e;
        e.registry = reg;
        e.params = new bytes32[](1);
        e.params[0] = bytes32(_chainCodeLimit());
        f.publishClassEnv(4, 0, 1, f.chainUid(), e);
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(4, 0, 1);
        bytes memory code = type(PqVault).creationCode;
        bytes memory call = abi.encodeCall(
            f.deployImplementation,
            (id, 1, IPqVault.initialize.selector, type(IPqVault).interfaceId, code, "", f.chainUid())
        );
        _requireReleaseGas("PqVault", address(f), call);
        address impl = f.deployImplementation(
            id, 1, IPqVault.initialize.selector, type(IPqVault).interfaceId, code, "", f.chainUid()
        );
        _releaseRow(
            "PqVault",
            4,
            0,
            1,
            impl,
            keccak256(abi.encodePacked(code, abi.encode(id, address(f), bytes("")))),
            keccak256("")
        );
        f.setClassKindEnabled(4, 0, true, f.chainUid());
        vm.serializeAddress("deploy", "pqvault_implementation", impl);
        if (f.classReleaseOf(id).usableFrom <= block.timestamp) {
            address inst = f.createInstance(
                id, keccak256("scaas.pqvault.instance.1"), abi.encodeCall(IPqVault.initialize, (bytes32(0)))
            );
            vm.serializeAddress("deploy", "pqvault_instance", inst);
        }
    }

    /// @notice The class env 1 of `(3, 0)`: the registry, `params[0]` the declared code-size limit, the module in `libs`.
    function _pqchatEnv(address reg, address topics) internal view returns (IFactoryToken.Env memory e) {
        e.registry = reg;
        e.params = new bytes32[](1);
        e.params[0] = bytes32(_chainCodeLimit());
        e.libs = new address[](1);
        e.libs[0] = topics;
        e.libCodeHashes = new bytes32[](1);
        e.libCodeHashes[0] = topics.codehash;
    }

    /// @notice DEX release 1 on env 1 after its gate, with the factory's chain word (Fable recheck-2 P3-1); its release row.
    function _dexRelease(OpenFactory f, bytes memory dexArgs) internal returns (address dexImpl) {
        bytes memory dexCode = type(SCaaSDex).creationCode;
        bytes32 u = f.chainUid();
        _requireReleaseGas(
            "SCaaSDex", address(f), abi.encodeCall(f.deployDexImplementation, (1, 1, dexCode, dexArgs, u))
        );
        dexImpl = f.deployDexImplementation(1, 1, dexCode, dexArgs, u);
        _releaseRow(
            "SCaaSDex",
            2,
            0,
            1,
            dexImpl,
            keccak256(abi.encodePacked(dexCode, abi.encode(address(f), dexArgs))),
            keccak256(dexArgs)
        );
    }

    /// @notice Release 1 of `(3, 0)` after its gate, `implArgs` naming the module; its row in the release list.
    function _pqchatRelease(OpenFactory f, bytes memory args) internal returns (address impl) {
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(3, 0, 1);
        bytes memory code = type(PqChat).creationCode;
        _requireReleaseGas(
            "PqChat",
            address(f),
            abi.encodeCall(
                f.deployImplementation,
                (id, 1, IPqChat.initialize.selector, type(IPqChat).interfaceId, code, args, f.chainUid())
            )
        );
        impl = f.deployImplementation(
            id, 1, IPqChat.initialize.selector, type(IPqChat).interfaceId, code, args, f.chainUid()
        );
        _releaseRow(
            "PqChat",
            3,
            0,
            1,
            impl,
            keccak256(abi.encodePacked(code, abi.encode(id, address(f), args))),
            keccak256(args)
        );
    }

    /// @notice GD-12 (CTR-GOV-19: every kind runs on the SCaaS testnet), in the form of `_deployZether`: env version 1 of
    ///         `WRAPPED` (the UA registry, the `SmartKeyAccount` implementation, Hedera, the link closure with `WrappedLib`, the
    ///         router), the release, version 1, refused first by `_requireReleaseGas`; the kind is on from the factory's start.
    ///         JSON `implementation_wrapped`. The release is above EIP-170: `CHAIN_CODE_LIMIT` must hold it.
    function _deployWrapped(OpenFactory f, address reg, address smartKeyAccountImpl, bool isHedera) internal {
        address[] memory libs = new address[](4);
        (libs[0], libs[1], libs[2], libs[3]) =
        (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(WrappedLib));
        address w = _kindRelease(
            f,
            IOpenFactory.TokenKind.WRAPPED,
            "WrappedToken",
            type(WrappedToken).creationCode,
            "",
            _env(f, reg, smartKeyAccountImpl, isHedera, new address[](0), libs)
        );
        vm.serializeAddress("deploy", "implementation_wrapped", w);
    }

    /// @notice Regulated-kinds spec §6.1, in the form of `_deployWrapped`: env version 1 of `NORMAL_REGULATED` (8) and of
    ///         `WRAPPED_REGULATED` (9), each its base kind's link closure with `RegulatedLib` added (which links only
    ///         `GovernanceLib`, already in it), the releases, version 1, each refused first by `_requireReleaseGas`, then both
    ///         kinds enabled (plan T28). JSON `implementation_normal_regulated`, `implementation_wrapped_regulated`. Hedera
    ///         takes both (`IS_HEDERA` from the env). The confidential regulated kinds deploy with their stacks (10, 11 under
    ///         `DEPLOY_ZETHER`, `_deployZetherRegulated`; 12, 13 by `script/pqz/e2e.py`). Each release's `implArgs` is `abi.encode(COMPLIANCE_REGISTRY_CODEHASH)`,
    ///         the canonical `ComplianceRegistry` runtime's code hash (spec §5, F-11; plan T29): a token naming a registry of
    ///         other code is refused at init. The registry itself: `_deployComplianceRegistry` (plan T33).
    function _deployRegulated(OpenFactory f, address reg, address smartKeyAccountImpl, bool isHedera) internal {
        address[] memory libs = new address[](4);
        (libs[0], libs[1], libs[2], libs[3]) =
        (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(RegulatedLib));
        bytes memory coreArgs = abi.encode(_complianceRegistryCodehash());
        address n = _kindRelease(
            f,
            IOpenFactory.TokenKind.NORMAL_REGULATED,
            "NormalRegulatedToken",
            type(NormalRegulatedToken).creationCode,
            coreArgs,
            _env(f, reg, smartKeyAccountImpl, isHedera, new address[](0), libs)
        );
        vm.serializeAddress("deploy", "implementation_normal_regulated", n);
        libs = new address[](5);
        (libs[0], libs[1], libs[2], libs[3], libs[4]) =
        (
            address(GovernanceLib),
            address(HederaLib),
            address(MtxPipelineLib),
            address(WrappedLib),
            address(RegulatedLib)
        );
        address w = _kindRelease(
            f,
            IOpenFactory.TokenKind.WRAPPED_REGULATED,
            "WrappedRegulatedToken",
            type(WrappedRegulatedToken).creationCode,
            coreArgs,
            _env(f, reg, smartKeyAccountImpl, isHedera, new address[](0), libs)
        );
        vm.serializeAddress("deploy", "implementation_wrapped_regulated", w);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true, f.chainUid());
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_REGULATED, true, f.chainUid());
    }

    /// @notice Regulated-kinds spec §6.1 (F-21, plan T33), under `DEPLOY_REGULATED`: the canonical `ComplianceRegistry` by
    ///         CREATE2, after the chain's router (round 3r, spec §5.3: its router is a constructor argument, written once),
    ///         its admin the native id of `COMPLIANCE_ADMIN` (none refused by the registry's own constructor, `AdminZero`;
    ///         any account, round 3r) and its router `govRouter`; its runtime the code every regulated release pins
    ///         (`COMPLIANCE_REGISTRY_CODEHASH`, F-11), equal for every admin and router. JSON `compliance_registry`,
    ///         `compliance_registry_codehash`. Not a release: no factory; its `chainUid()` the run's (CTR-GOV-27); the code pin is its gate. The
    ///         `ELIGIBLE_CONTRACT` rows of a DEX venue (`createDex`, after this deploy) and of its `puller()` are the admin's
    ///         own `setCompliance` call: this script holds no key of the admin.
    function _deployComplianceRegistry() internal returns (address) {
        ComplianceRegistry r = new ComplianceRegistry{salt: salt}(complianceAdmin, govRouter, uid);
        require(
            address(r).codehash == _complianceRegistryCodehash(),
            "ComplianceRegistry: code differs from COMPLIANCE_REGISTRY_CODEHASH (F-11)"
        );
        vm.serializeAddress("deploy", "compliance_registry", address(r));
        vm.serializeBytes32("deploy", "compliance_registry_codehash", address(r).codehash);
        return address(r);
    }

    /// @notice The canonical `ComplianceRegistry` runtime's code hash, every regulated release's `implArgs` (spec §5, F-11).
    function _complianceRegistryCodehash() internal pure returns (bytes32) {
        return keccak256(type(ComplianceRegistry).runtimeCode);
    }

    /// @notice `RelayFeeRouter` (CTR-MTX-27) by CREATE2 under `RELAY_SALT`, the same address on every chain and stack (no
    ///         constructor argument, no `chainUid()`: it is stateless), reused when its code is there (spec §13.2); its
    ///         executor is its CREATE at nonce 1. JSON `relay_fee_router`, `relay_fee_executor`.
    function _deployRelayFeeRouter() internal returns (address, address ex) {
        address d = vm.isContext(VmSafe.ForgeContext.ScriptGroup) ? CREATE2_FACTORY : address(this);
        address p = vm.computeCreate2Address(RELAY_SALT, keccak256(type(RelayFeeRouter).creationCode), d);
        RelayFeeRouter rf = p.code.length != 0 ? RelayFeeRouter(p) : new RelayFeeRouter{salt: RELAY_SALT}();
        ex = rf.EXECUTOR();
        require(ex.code.length != 0 && RelayFeeExecutor(ex).ROUTER() == address(rf), "RelayFeeRouter executor");
        vm.serializeAddress("deploy", "relay_fee_router", address(rf));
        vm.serializeAddress("deploy", "relay_fee_executor", ex);
        return (address(rf), ex);
    }

    /// @notice The chain's `GovernanceRouter` (CTR-GOV-15 Change, owner 2026-11-04; plan T11) by CREATE2: no owner, no
    ///         state, `chain_uid` and the UA registry in its constructor, so one predictable address per chain. Deployed
    ///         before the releases, whose `Env.govRouter` names it. JSON `governance_router`. **UNAUDITED.**
    function _deployGovRouter(address reg, address smartKeyAccountImpl, bool isHedera) internal {
        GovernanceRouter r = new GovernanceRouter{salt: salt}(uid, reg, smartKeyAccountImpl, isHedera);
        _gate(address(r));
        govRouter = address(r);
        govRouterCodeHash = _builtHash(
            govRouter,
            abi.encodePacked(type(GovernanceRouter).creationCode, abi.encode(uid, reg, smartKeyAccountImpl, isHedera)),
            salt
        );
        vm.serializeAddress("deploy", "governance_router", govRouter);
    }

    /// @notice The factory's release of `kind`, version 1 on env 1, with its `implArgs` (T66b: `kindImplArgs`), after its gate
    ///         (`_requireReleaseGas`).
    function _release(
        OpenFactory f,
        IOpenFactory.TokenKind kind,
        string memory name,
        bytes memory code,
        bytes memory implArgs
    ) internal returns (address) {
        _requireReleaseGas(
            name, address(f), abi.encodeCall(f.deployTokenImplementation, (kind, 1, 1, code, implArgs, f.chainUid()))
        );
        address at = f.deployTokenImplementation(kind, 1, 1, code, implArgs, f.chainUid());
        _releaseRow(
            name,
            1,
            uint8(kind),
            1,
            at,
            keccak256(abi.encodePacked(code, abi.encode(address(f), implArgs))),
            keccak256(implArgs)
        );
        return at;
    }

    /// @notice T66b §4.5: `kind`'s body modules (`_modules`, with the kind's own constructor arguments `coreArgs`: "" on 0-5,
    ///         `abi.encode(COMPLIANCE_REGISTRY_CODEHASH)` on 8-13), env version 1 of `kind` = `e` with the modules pinned beside its
    ///         libraries, then the release, version 1, its `implArgs` naming the modules (`kindImplArgs`).
    function _kindRelease(
        OpenFactory f,
        IOpenFactory.TokenKind kind,
        string memory name,
        bytes memory code,
        bytes memory coreArgs,
        IFactoryToken.Env memory e
    ) internal returns (address) {
        string[] memory n = kindModuleNames(uint8(kind));
        address[] memory ms = new address[](n.length);
        for (uint256 i; i < n.length; ++i) {
            ms[i] = _module(n[i], abi.encode(address(f), coreArgs), uint8(kind));
        }
        f.publishTokenEnv(kind, 1, f.chainUid(), _withModules(e, ms));
        return _release(f, kind, name, code, kindImplArgs(uint8(kind), ms, coreArgs));
    }

    /// @notice One body module (T66b §4.5): the artifact's init code with `args`, by CREATE2 through the deterministic
    ///         deployer with `DEPLOY_SALT` (the same address on every chain: a module holds no chain value), after its own
    ///         gate (`_requireReleaseGas`, a release of its own); code already there is reused. Its row in the release list:
    ///         class 0 (no factory class), `kind` the token kind (0 for the DEX's D), version 1.
    function _module(string memory artifact, bytes memory args, uint8 kind) internal returns (address at) {
        return _module(artifact, args, 0, kind);
    }

    /// @notice `_module` of a generic class's body module (`PqChatTopics`: class 3, kind 0): its row names the class.
    function _module(string memory artifact, bytes memory args, uint16 cls, uint16 kind) internal returns (address at) {
        bytes memory init = bytes.concat(vm.getCode(artifact), args);
        string memory name = vm.split(artifact, ":")[1];
        at = vm.computeCreate2Address(salt, keccak256(init), CREATE2_FACTORY);
        if (at.code.length == 0) {
            _requireReleaseGas(name, address(0), init);
            (bool ok,) = CREATE2_FACTORY.call(bytes.concat(salt, init));
            require(ok && at.code.length != 0, string.concat(name, ": the CREATE2 of the module failed"));
        }
        _releaseRow(name, cls, kind, 1, at, keccak256(init), keccak256(args));
    }

    /// @notice `e` with `ms` pinned after its libraries (`OpenFactory` refuses a release whose `modules()` it lacks).
    function _withModules(IFactoryToken.Env memory e, address[] memory ms)
        internal
        view
        returns (IFactoryToken.Env memory)
    {
        uint256 k = e.libs.length;
        address[] memory l = new address[](k + ms.length);
        bytes32[] memory h = new bytes32[](l.length);
        for (uint256 i; i < k; ++i) {
            (l[i], h[i]) = (e.libs[i], e.libCodeHashes[i]);
        }
        for (uint256 i; i < ms.length; ++i) {
            (l[k + i], h[k + i]) = (ms[i], ms[i].codehash);
        }
        (e.libs, e.libCodeHashes) = (l, h);
        return e;
    }

    /// @notice Chain-neutral spec §3.1, §3.3 (Fable P1-1): this chain's values, once, the registrar's transaction on the
    ///         factory: `chain_uid` (the RPC's genesis hash, `_chainUid`), the notice period, the router, and a reference block (the head's parent and
    ///         its hash as this chain's RPC reports it; `_setup` checked the genesis hash against `chain-uids.json`), so the transaction is void on a sibling with the same chain id;
    ///         `NO_REF_BLOCK=true` on a chain whose `BLOCKHASH` is not its own block's (a pseudo-blockhash). `forge script`
    ///         without `--broadcast` is the dry run (the same call by `eth_call` against the RPC). On a chain id
    ///         `chain-uids.json` lists more than once (siblings), the run stops after this step until `SIBLINGS_CONFIGURED`
    ///         is set: the operator configures every sibling, each with its own reference, before any other registrar
    ///         transaction on any of them. Then the gate: the factory's `chainUid()` the genesis hash, its address and the
    ///         registrar's code hash the release list's.
    function _configureChain(OpenFactory f, address registrar) internal {
        uint256 ref = vm.envOr("NO_REF_BLOCK", false) || block.number < 2 ? 0 : block.number - 1;
        // the router's code hash from this build (spec §13.7, Fable 3r3s3t P3-6: `_builtHash` at `_deployGovRouter`)
        f.configureChain(uid, noticePeriod, govRouter, govRouterCodeHash, ref, ref == 0 ? bytes32(0) : blockhash(ref));
        _gate(address(f));
        _releaseRow(
            "OpenFactory",
            0,
            0,
            0,
            address(f),
            keccak256(abi.encodePacked(type(OpenFactory).creationCode, abi.encode(MetaTxLib.pad(registrar)))),
            keccak256(abi.encode(MetaTxLib.pad(registrar)))
        );
        _releaseRow("admin", 0, 0, 0, registrar, bytes32(0), bytes32(0)); // the factory's first admin (round 3r, spec §6)
        if (chainSiblings > 1 && !vm.envOr("SIBLINGS_CONFIGURED", false)) {
            configureOnly = true;
            console.log(
                "chain id shared by siblings (chain-uids.json): configure every one, then SIBLINGS_CONFIGURED=true"
            );
        }
    }

    /// @notice How many `chain-uids.json` rows name this chain id, and whether one of them has this `chain_uid`.
    function _chainUidListed() internal view returns (uint256 n, bool match_) {
        string memory path = "./chain-uids.json";
        if (!vm.exists(path)) return (0, false);
        string memory j = vm.readFile(path);
        for (uint256 i;; ++i) {
            string memory p = string.concat(".chains[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, p)) break;
            if (vm.parseJsonUint(j, string.concat(p, ".chainId")) != block.chainid) continue;
            ++n;
            if (vm.parseJsonBytes32(j, string.concat(p, ".chainUid")) == uid) match_ = true;
        }
    }

    /// @notice One instance of `implementation` on this chain answers this chain's `chainUid()` (§6.2): its clone code
    ///         (the EIP-1167 proxy with the env the factory appends: its `chain_uid` and router, the release's env)
    ///         etched at a scratch address in this script's EVM only, never sent.
    function _gateInstance(OpenFactory f, address implementation, IFactoryToken.Env memory e) internal {
        bytes memory env = ChainEnvCode.encode(
            IFactoryToken.ChainEnv(
                f.chainUid(), e.registry, f.govRouter(), e.smartKeyAccountImpl, e.hedera, e.deps, e.params
            )
        );
        address probe = address(uint160(uint256(keccak256(abi.encode("scaas.deploy.instance-probe", implementation)))));
        vm.etch(
            probe, abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3", env)
        );
        _gate(probe);
        vm.etch(probe, "");
    }

    /// @notice The linked libraries' rows (address and code hash).
    function _libRows(address[] memory libs) internal {
        for (uint256 i; i < libs.length; ++i) {
            _releaseRow(string.concat("lib-", vm.toString(libs[i])), 0, 0, 0, libs[i], bytes32(0), bytes32(0));
        }
    }

    /// @notice One row of the release list (§6.2): `class`, `kind`, `version`, `address`, `codeHash` (the runtime's),
    ///         `initcodeHash`, `implArgsHash`; written with `RELEASES_WRITE`, else checked against the file when it exists
    ///         and lists `name` (a later chain may add a release the file does not list yet: it is reported).
    function _releaseRow(
        string memory name,
        uint16 cls,
        uint16 kind,
        uint64 version,
        address at,
        bytes32 initHash,
        bytes32 argsHash
    ) internal {
        string memory k = string.concat("releases.", name);
        vm.serializeUint(k, "class", cls);
        vm.serializeUint(k, "kind", kind);
        vm.serializeUint(k, "version", version);
        vm.serializeAddress(k, "address", at);
        vm.serializeBytes32(k, "initcodeHash", initHash);
        vm.serializeBytes32(k, "implArgsHash", argsHash);
        string memory row = vm.serializeBytes32(k, "codeHash", at.codehash);
        releasesJson = vm.serializeString("releases", name, row);
        ++releaseRows;
        if (releasesWrite || bytes(releasesPath).length == 0 || !vm.exists(releasesPath)) return;
        string memory file = _checkBook(vm.readFile(releasesPath), releasesPath);
        string memory p = string.concat(".", name);
        if (!vm.keyExistsJson(file, p)) {
            console.log(string.concat("release list: ", name, " not listed (a release the first chain has not)"));
            return;
        }
        require(
            vm.parseJsonAddress(file, string.concat(p, ".address")) == at,
            string.concat("release list: ", name, " at another address")
        );
        require(
            vm.parseJsonBytes32(file, string.concat(p, ".codeHash")) == at.codehash,
            string.concat("release list: ", name, " with another code hash")
        );
    }

    /// @notice Writes the release list (`RELEASES_WRITE`), after every row, behind this chain's book header (NET-EVM-13);
    ///         call last in `run()`.
    function _writeReleases() internal {
        if (releasesWrite && releaseRows != 0) _writeBook(uid, releasesPath, releasesJson);
    }

    /// @notice A release environment of this chain's factory (plan 5g-Z2): the registry, the `SmartKeyAccount`
    ///         implementation, Hedera, the deps, each library's current code hash. Chain-neutral releases (plan T71): the
    ///         factory fills its own `chain_uid` and router (`configureChain`), they are not in the env.
    function _env(OpenFactory, address reg, address ska, bool hedera, address[] memory deps, address[] memory libs)
        internal
        view
        returns (IFactoryToken.Env memory e)
    {
        bytes32[] memory h = new bytes32[](libs.length);
        for (uint256 i; i < libs.length; ++i) {
            h[i] = libs[i].codehash;
        }
        e = IFactoryToken.Env(reg, ska, hedera, deps, new bytes32[](0), libs, h);
    }

    /// @notice UA registry generation 1 (accounts.md §1.8, CTR-UA-22) on every chain, with per-chain enablement (§1.9):
    ///         `webauthn-p256`, `p256`, `ed25519`, `bip340`, `secp256k1`, `schnorr-bn254`, the four group kinds and `msig`
    ///         everywhere;
    ///         `schnorr-bls12381` and `bls12381-minsig` where `UAPrecompileProbe` passes EIP-2537; `bls-bn254-minsig` where
    ///         it passes the bn254 G2 check (no chain-id lock, owner ruling 2026-10-31); `zether-bls12381` with
    ///         EIP-2537 on every chain but Hedera (owner ruling 2026-10-31; `zether-bn254` is in `legacy/ua6/`, UA-6 U10);
    ///         `bls12381-multi` (spec 2026-11-19-bls12381-multi §7, ARCH-POS-18) where the probe passes EIP-2537, Hedera's profile
    ///         excepted, and the deploy book names its path (`ua_kind_0x0121`): Hedera disabled (owner-confirmed 2026-11-19,
    ///         Q-SW1), any other chain without EIP-2537 refused (no software BLS12-381 path in this round; the owner decides); the PQ
    ///         signing kinds (P6c; unaudited, CTR-UA-23) on every chain where the kind's cap is at most 75 % of the chain's
    ///         verify budget (`_pqKindFits`; owner rulings 2026-10-31: no chain-id lock; 2026-11-15: 75 % instead of 66 %) —
    ///         ML-DSA on the chain's precompile or on the registry's cached expanded key (`MLDSA_PRECOMPILE`, `_mldsaVerifier`);
    ///         `pqz-mlwe` on `PQZ_KEY_VERIFIER` only. Caps: the gen-1 defaults measured in
    ///         `test/ua/UAGas.t.sol` and `test/ua/PqGas.t.sol` (accounts.md §1.15). A disabled kind gets no verifier
    ///         (never "registrable but unusable", CTR-UA-23). JSON `ua_registry`. **UNAUDITED.**
    /// @notice The PQ signing kinds' deploy rule (CTR-UA-23; owner ruling 2026-10-31, threshold 66 % -> 75 % by the owner
    ///         2026-11-15): the kind's cap is at most 75 % of the chain's verify budget, integer-exact as
    ///         `cap * 100 <= budget * 75` (12 M: 9.0 M; Hedera 10.5 M: 7,875,000). One rule on every chain, no exception: Hedera's
    ///         budget disables the cached `mldsa87` by itself. The registry's own `cap <= budget` check is separate and unchanged.
    function _pqKindFits(uint64 cap, uint64 budget) internal pure returns (bool) {
        return uint256(cap) * 100 <= uint256(budget) * 75;
    }

    /// @notice The verifier and cap of ML-DSA kind `i` (0, 1, 2 = `mldsa44`, `mldsa65`, `mldsa87`; owner 2026-11-15, two paths
    ///         only). `MLDSA_PRECOMPILE=on`: the `MLDSA<x>_VERIFIER` the first step built (an `MldsaVerifier` of the kind with a
    ///         precompile, else refused by name), or one built here when a candidate answers the probe in this run's EVM, at the
    ///         precompile cap; a chain whose own probe passes (`answers`, `_pqPrecompiles`) with neither is refused by name
    ///         (the gen-1 kind rule). Otherwise, and always with `off` (where `MLDSA<x>_VERIFIER` is refused), the pure-Solidity
    ///         verifier at the cached cap: the registry verifies on its expanded-key cache only. A cap `_pqKindFits` refuses on
    ///         `budget`: no verifier (0), the kind disabled.
    function _mldsaVerifier(uint256 i, bool answers, uint64 budget) internal returns (address v, uint64 cap) {
        uint16 kind = [UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.MLDSA87][i];
        address given = [mldsa44Verifier, mldsa65Verifier, mldsa87Verifier][i];
        string memory env = ["MLDSA44_VERIFIER", "MLDSA65_VERIFIER", "MLDSA87_VERIFIER"][i];
        string memory hex4 = vm.toString(abi.encodePacked(kind));
        if (!mldsaPrecompile) {
            require(
                given == address(0),
                string.concat(env, ": set with MLDSA_PRECOMPILE=off (pure Solidity with the cache)")
            );
        } else if (given != address(0)) {
            require(
                given.code.length != 0 && MldsaVerifier(given).KIND() == kind
                    && MldsaVerifier(given).PRECOMPILE() != address(0),
                string.concat(env, ": not an MldsaVerifier(", hex4, ") with a precompile on this chain")
            );
            require(
                given == _mldsaCreate2(i, MldsaVerifier(given).PRECOMPILE()),
                string.concat(
                    env,
                    ": not this build's CREATE2 address of MldsaVerifier(",
                    hex4,
                    ", its precompile, pq_kat.json's probe) with DEPLOY_SALT (F-6)"
                )
            );
            cap = [CAP_MLDSA44_PRECOMPILE, CAP_MLDSA65_PRECOMPILE, CAP_MLDSA87_PRECOMPILE][i];
            return (_pqKindFits(cap, budget) ? given : address(0), cap);
        } else {
            (address p, bytes memory ok, bytes memory bad) = _mldsaPrecompile(i);
            if (p != address(0)) {
                cap = [CAP_MLDSA44_PRECOMPILE, CAP_MLDSA65_PRECOMPILE, CAP_MLDSA87_PRECOMPILE][i];
                if (_pqKindFits(cap, budget)) v = address(new MldsaVerifier{salt: salt}(kind, p, ok, bad));
                return (v, cap);
            }
            require(
                !answers,
                string.concat(
                    "gen-1 registry: PQ precompile kind ",
                    hex4,
                    " the probe passes is missing (",
                    env,
                    ": deploy.sh evm's pq-verifiers step)"
                )
            );
        }
        cap = [CAP_MLDSA44, CAP_MLDSA65, CAP_MLDSA87][i];
        if (_pqKindFits(cap, budget) && _cacheFits(i)) {
            v = address(new MldsaVerifier{salt: salt}(kind, address(0), "", ""));
        }
    }

    /// @notice F-6 (owner 2026-11-15): the CREATE2 address (`DEPLOY_SALT`, the deterministic deployer) of
    ///         `MldsaVerifier(kind i, precompile p, pq_kat.json's EIP-8355 probe valid, invalid)` as `script/pq_verifiers.py` builds
    ///         it; `_mldsaVerifier` requires a handed-in verifier to be exactly it (a contract that only answers the two getters is
    ///         refused). The candidate is the one the verifier names (`PRECOMPILE()`), so both candidates are covered.
    function _mldsaCreate2(uint256 i, address p) internal view returns (address) {
        (bytes memory valid, bytes memory invalid) = _mldsaProbe(i);
        bytes memory init = abi.encodePacked(
            type(MldsaVerifier).creationCode,
            abi.encode([UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.MLDSA87][i], p, valid, invalid)
        );
        return vm.computeCreate2Address(salt, keccak256(init), CREATE2_FACTORY);
    }

    /// @notice MD-5 (owner 2026-11-15, F-5): an ML-DSA kind on the cache is enabled only if every part transaction fits this chain:
    ///         the least working regular gas x 1.05 < 2^24 (EIP-7825) and (regular + state) x 1.05 <= the block gas limit
    ///         (EIP-8037 inclusion, NET-EVM-06), from `DeployGas` (measured). A deploy-time check of the chain's limit as it is now:
    ///         a later cut under it stops new keys of that kind from being cached (fail closed: no registration, so no funds), the
    ///         chain operator's change, named in the runbook. A part that does not fit: the kind is disabled (no verifier), by name.
    function _cacheFits(uint256 i) internal view returns (bool) {
        uint64[3][3] memory r = DeployGas.regular();
        uint64[3][3] memory st = DeployGas.state();
        uint256 limit = _blockGasLimit();
        for (uint256 p; p < PqUA.mldsaParts([UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.MLDSA87][i]); ++p) {
            uint256 reg = r[i][p];
            uint256 total = (reg + st[i][p]) * 105 / 100;
            if (reg * 105 / 100 >= txGasCap || total > limit) {
                console.log(
                    string.concat(
                        "ML-DSA kind ",
                        ["mldsa44", "mldsa65", "mldsa87"][i],
                        " disabled (MD-5): cache part ",
                        vm.toString(p),
                        " asks regular ",
                        vm.toString(reg),
                        " + state ",
                        vm.toString(uint256(st[i][p])),
                        " x 1.05 = ",
                        vm.toString(total),
                        " (2^24 on the regular, block gas limit ",
                        vm.toString(limit),
                        ")"
                    )
                );
                return false;
            }
        }
        return true;
    }

    /// @notice `TX_GAS_CAP` (owner X1): required, no default; a missing or zero value reverts by name.
    function _txGasCapEnv() internal view returns (uint64 cap) {
        cap = uint64(vm.envUint("TX_GAS_CAP"));
        require(cap != 0, "TX_GAS_CAP: the chain's per-transaction gas cap from the deploy book (owner X1)");
    }

    function _deployUARegistry(address smartKeyAccountImpl, bool isHedera) internal returns (UARegistry reg) {
        _requireKindHere("UARegistry", uid); // NET-ALL-25: UAMsigUpdate and the scoped keys bind chain_uid, no chain id
        require(txGasCap != 0, "TX_GAS_CAP: the chain's per-transaction gas cap from the deploy book (owner X1)");
        (bool bls, bool bnG2) = _precompiles();
        (bool pqz, bool[3] memory ml) = _pqPrecompiles();
        uint64 budget = isHedera ? UA_VERIFY_BUDGET_HEDERA : UA_VERIFY_BUDGET;
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](22);
        uint256 n;
        k[n++] = UARegistry.KindConfig(
            UAKinds.WEBAUTHN_P256, address(new WebAuthnP256Verifier{salt: salt}()), 400_000, false, 0
        );
        k[n++] = UARegistry.KindConfig(UAKinds.P256, address(new P256Verifier{salt: salt}()), 400_000, false, 0);
        k[n++] = UARegistry.KindConfig(UAKinds.ED25519, address(new Ed25519Verifier{salt: salt}()), 210_000, false, 0);
        k[n++] = UARegistry.KindConfig(UAKinds.BIP340, address(new Bip340Verifier{salt: salt}()), 50_000, false, 0);
        k[n++] =
            UARegistry.KindConfig(UAKinds.SECP256K1, address(new Secp256k1Verifier{salt: salt}()), 50_000, false, 0);
        k[n++] = UARegistry.KindConfig(
            UAKinds.SCHNORR_BN254, address(new SchnorrBn254Verifier{salt: salt}()), 50_000, false, 0
        );
        if (bls) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.SCHNORR_BLS12381, address(new SchnorrBls12381Verifier{salt: salt}()), 70_000, false, 0
            );
            k[n++] = UARegistry.KindConfig(
                UAKinds.BLS12381_MINSIG, address(new BlsMinSigBls12381Verifier{salt: salt}()), 200_000, false, 0
            );
        }
        if (bnG2) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.BLS_BN254_MINSIG, address(new BlsMinSigBn254Verifier{salt: salt}()), 345_000, false, 0
            );
        }
        k[n++] = UARegistry.KindConfig(
            UAKinds.MUSIG2_SECP256K1, address(new Musig2Secp256k1Verifier{salt: salt}()), 50_000, false, 0
        );
        k[n++] = UARegistry.KindConfig(
            UAKinds.FROST_SECP256K1, address(new FrostSecp256k1Verifier{salt: salt}()), 50_000, false, 0
        );
        k[n++] = UARegistry.KindConfig(
            UAKinds.MUSIG2_BN254, address(new Musig2Bn254Verifier{salt: salt}()), 50_000, false, 0
        );
        k[n++] =
            UARegistry.KindConfig(UAKinds.FROST_BN254, address(new FrostBn254Verifier{salt: salt}()), 50_000, false, 0);
        if (bls && !isHedera) {
            // ARCH-POS-18: the probe chooses the path; the EIP-2537 one, the only one built (spec 2026-11-19-bls12381-multi §7)
            k[n++] = UARegistry.KindConfig(
                UAKinds.BLS12381_MULTI,
                address(new BlsMultiBls12381Verifier{salt: salt}()),
                CAP_BLS12381_MULTI,
                false,
                0
            );
        }
        vm.serializeString("deploy", "ua_kind_0x0121", _blsMultiPath(bls, isHedera));
        if (bls && !isHedera) {
            // never on Hedera: no Zether token can exist there (`ZetherLayer`)
            k[n++] = UARegistry.KindConfig(
                UAKinds.ZETHER_BLS12381, address(new ZetherSchnorrBls12381Verifier{salt: salt}()), 70_000, false, 0
            );
        }
        // the PQ signing kinds (CTR-UA-23): wherever the kind's cap is at most 75 % of the chain's verify budget; ML-DSA on
        // the chain's precompile or on the registry's cache (`MLDSA_PRECOMPILE`)
        for (uint256 i; i < 2; ++i) {
            (address v, uint64 cap) = _mldsaVerifier(i, ml[i], budget);
            if (v != address(0)) {
                k[n++] = UARegistry.KindConfig([UAKinds.MLDSA44, UAKinds.MLDSA65][i], v, cap, false, 0);
            }
        }
        if (_pqKindFits(CAP_FNDSA512, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.FNDSA512, address(new FndsaVerifier{salt: salt}(UAKinds.FNDSA512)), CAP_FNDSA512, false, 0
            );
        }
        if (_pqKindFits(CAP_SLHDSA128S, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.SLHDSA128S, address(new SlhdsaVerifier{salt: salt}()), CAP_SLHDSA128S, false, 0
            );
        }
        if (_pqKindFits(CAP_FNDSA1024, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.FNDSA1024, address(new FndsaVerifier{salt: salt}(UAKinds.FNDSA1024)), CAP_FNDSA1024, false, 0
            );
        }
        { // `mldsa87` after the FN-DSA kinds, as before (the kind table's order moves the registry's address)
            (address v, uint64 cap) = _mldsaVerifier(2, ml[2], budget);
            if (v != address(0)) k[n++] = UARegistry.KindConfig(UAKinds.MLDSA87, v, cap, false, 0);
        }
        if (pqzKeyVerifier != address(0) && _pqKindFits(CAP_PQZ_MLWE, budget)) {
            require(
                pqzKeyVerifier.code.length != 0 && PqzKeyVerifier(pqzKeyVerifier).PRECOMPILE() == PqzSafety.PQZ
                    && PqzKeyVerifier(pqzKeyVerifier).PROOF_SYSTEM_ID() == PqzSafety.PQZL_ID,
                "PQZ_KEY_VERIFIER: not a PqzKeyVerifier on the PQZ precompile and the set's PQZL id"
            );
            k[n++] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, pqzKeyVerifier, CAP_PQZ_MLWE, false, 0);
        }
        assembly ("memory-safe") {
            mstore(k, n)
        }
        // `UARegistryCoreLib`, `UARegistryAuxLib` (T66b 3.1b) and `UARegistryRegLib` (owner 2026-11-19) are linked like every library: forge deploys each by CREATE2
        // before the script's first transaction (`create2_library_salt`), so their addresses, and through the code that embeds
        // them the registry's, depend on the sources only. Each one's own transaction is a release like the registry's: the
        // same gate.
        _requireRegistryGas(address(0), isHedera, budget, smartKeyAccountImpl, k);
        reg = new UARegistry{salt: salt}(uid, address(0), isHedera, budget, txGasCap, smartKeyAccountImpl, true, k);
        _checkGen1Kinds(reg, bls, isHedera, pqz, ml[2] && mldsaPrecompile);
        _gate(address(reg));
        vm.serializeAddress("deploy", "ua_registry", address(reg));
        if (reg.kindEnabled(UAKinds.PQZ_MLWE)) vm.serializeAddress("deploy", "pqz_key_verifier", pqzKeyVerifier);
        // the ML-DSA verifiers the registry lists (the matrix's `verifiers` group reads them) and the flag it was built with
        for (uint256 i; i < k.length; ++i) {
            uint16 kk = k[i].kind;
            if (kk == UAKinds.MLDSA44 || kk == UAKinds.MLDSA65 || kk == UAKinds.MLDSA87) {
                string memory lv = kk == UAKinds.MLDSA44 ? "44" : kk == UAKinds.MLDSA65 ? "65" : "87";
                vm.serializeAddress("deploy", string.concat("mldsa", lv, "_verifier"), k[i].verifier);
                address pc = MldsaVerifier(k[i].verifier).PRECOMPILE();
                vm.serializeString(
                    "deploy",
                    string.concat("mldsa", lv, "_path"), // MD-15: the path each kind took
                    pc == address(0) ? "cache" : string.concat("precompile ", vm.toString(pc))
                );
            }
        }
        vm.serializeString("deploy", "mldsa_precompile", mldsaPrecompile ? "on" : "off");
        vm.serializeAddress("deploy", "ua_registry_core_lib", address(UARegistryCoreLib));
        vm.serializeAddress("deploy", "ua_registry_aux_lib", address(UARegistryAuxLib));
        vm.serializeAddress("deploy", "ua_registry_reg_lib", address(UARegistryRegLib));
        _genBookCommon(reg);
    }

    /// @notice Spec 2026-11-19-registry-verify-only-kinds §9 (F14): the line fields every generation's book carries (generation 1's
    ///         too, so a later deploy can check its walk against them): generation, predecessor, code hash, the three libraries
    ///         with their code hashes, `tx_gas_cap`.
    function _genBookCommon(UARegistry reg) internal {
        vm.serializeUint("deploy", "ua_registry_generation", reg.generation());
        vm.serializeAddress("deploy", "ua_registry_predecessor", reg.predecessor());
        vm.serializeBytes32("deploy", "ua_registry_codehash", address(reg).codehash);
        vm.serializeUint("deploy", "tx_gas_cap", txGasCap);
        string memory l = "ua_registry_libraries";
        address[3] memory a = [address(UARegistryCoreLib), address(UARegistryAuxLib), address(UARegistryRegLib)];
        string[3] memory n = ["UARegistryCoreLib", "UARegistryAuxLib", "UARegistryRegLib"];
        string memory o;
        for (uint256 i; i < 3; ++i) {
            vm.serializeAddress(n[i], "address", a[i]);
            o = vm.serializeString(l, n[i], vm.serializeBytes32(n[i], "codehash", a[i].codehash));
        }
        vm.serializeString("deploy", l, o);
    }

    /// @notice A book field `path` as a number, `dflt` when absent.
    function _bookUint(string memory book, string memory path, uint256 dflt) internal view returns (uint256) {
        return vm.keyExistsJson(book, path) ? vm.parseJsonUint(book, path) : dflt;
    }

    /// @notice The owner's confirmation of refusal `name`, recorded in the book with its reason (`owner_override_<name>`, W5, M9).
    function _ownerOverride(string memory book, string memory name) internal view returns (bool) {
        string memory p = string.concat(".owner_override_", name);
        return vm.keyExistsJson(book, p) && bytes(vm.parseJsonString(book, p)).length != 0;
    }

    /// @notice The later-generation mode (spec 2026-11-19-registry-verify-only-kinds §9, CTR-UA-64; owner W5, M9, M10 d, X1): generation
    ///         n + 1 over the book's registry `ua_registry` (generation n). Before anything is sent, each refused by name:
    ///         `GEN_NOT_LATEST` (the book's `ua_registry_latest` is another registry; only with the owner's override), `GEN_DEPTH`
    ///         (n + 1 over `MAX_GENERATION`), `GEN_WALK_MISMATCH <g>` (the walk from the predecessor to generation 1 against the
    ///         book: every address, code hash and generation, `ua_registry_line[g - 1]` for the generations below n, and the
    ///         libraries' code hashes), `GEN_TX_CAP_UNKNOWN` (no `tx_gas_cap` in the book: `script/tx_gas_cap.py` writes it) and
    ///         `GEN_TX_CAP_MISMATCH` (`TX_GAS_CAP` other than the book's), then the kinds of `_genKinds`. Carries `msig` in full,
    ///         `0x0142` where a predecessor enables it, the book's `gen_verify_only` kinds. A kind no predecessor enables (an
    ///         ordinary later-generation kind) is not built in this mode. **UNAUDITED.**
    function _deployUARegistryGen(string memory book, address ska) internal returns (UARegistry reg) {
        _requireKindHere("UARegistry", uid); // NET-ALL-25, as _deployUARegistry: before the book is read
        UARegistry pred = UARegistry(vm.parseJsonAddress(book, ".ua_registry"));
        address latest = vm.keyExistsJson(book, ".ua_registry_latest")
            ? vm.parseJsonAddress(book, ".ua_registry_latest")
            : address(pred);
        // Task 21 review P2-2: a book of the next generation already written (`<key>-ua-gen<n + 1>.json`) means the line has
        // moved past this predecessor: a deploy over it would be a sibling
        require(
            !_newerGenBook(_bookUint(book, ".ua_registry_generation", 1) + 1) || _ownerOverride(book, "GEN_NOT_LATEST"),
            "GEN_NOT_LATEST: a book of the next generation exists, the predecessor is not the line's latest"
        );
        require(
            latest == address(pred) || _ownerOverride(book, "GEN_NOT_LATEST"),
            string.concat(
                "GEN_NOT_LATEST: the predecessor ",
                vm.toString(address(pred)),
                " is not the book's latest ",
                vm.toString(latest)
            )
        );
        uint256 g = _bookUint(book, ".ua_registry_generation", 1) + 1;
        require(
            g <= MAX_GEN,
            string.concat("GEN_DEPTH: generation ", vm.toString(g), " over MAX_GENERATION ", vm.toString(MAX_GEN))
        );
        _walkCheck(book, address(pred), g - 1);
        uint64 cap = uint64(_bookUint(book, ".tx_gas_cap", 0));
        require(cap != 0, "GEN_TX_CAP_UNKNOWN: no tx_gas_cap in the book (script/tx_gas_cap.py, owner X1)");
        require(
            txGasCap == 0 || txGasCap == cap,
            string.concat(
                "GEN_TX_CAP_MISMATCH: TX_GAS_CAP ", vm.toString(txGasCap), ", the book's ", vm.toString(uint256(cap))
            )
        );
        txGasCap = cap;
        bool hedera = pred.hederaNative();
        uint64 budget = hedera ? UA_VERIFY_BUDGET_HEDERA : UA_VERIFY_BUDGET;
        UARegistry.KindConfig[] memory k = _genKinds(book, pred, g, budget);
        _requireRegistryGas(address(pred), hedera, budget, ska, k);
        reg = new UARegistry{salt: salt}(uid, address(pred), hedera, budget, cap, ska, true, k);
        require(reg.generation() == g, "gen registry: not the generation the book gives");
        _gate(address(reg));
        vm.serializeAddress("deploy", "ua_registry", address(reg));
        vm.serializeString("deploy", "ua_registry_walk_check", string.concat("ok: generations 1-", vm.toString(g - 1)));
        vm.serializeBool("deploy", "gen_pqz", reg.kindEnabled(UAKinds.PQZ_MLWE));
        vm.serializeString("deploy", "owner_overrides", _overridesUsed(book));
        _genBookCommon(reg);
    }

    /// @notice The owner's overrides this deploy used, with their reasons (W5, M9): an object keyed by the refusal's name.
    function _overridesUsed(string memory book) internal returns (string memory ov) {
        ov = "{}";
        string[2] memory names = ["GEN_NOT_LATEST", "GEN_PQZ_OMITTED"];
        for (uint256 i; i < 2; ++i) {
            if (!_ownerOverride(book, names[i])) continue;
            string memory why = vm.parseJsonString(book, string.concat(".owner_override_", names[i]));
            ov = vm.serializeString("owner_overrides", names[i], why);
        }
    }

    uint256 internal constant MAX_GEN = 16; // `UARegistry.MAX_GENERATION`

    /// @notice Whether this chain's book of generation `g` exists (`deployments/<key>-ua-gen<g>.json`, `DeployUAGen.s.sol`).
    function _newerGenBook(uint256 g) internal view virtual returns (bool) {
        return vm.exists(_bookPath(uid, string.concat("-ua-gen", vm.toString(g), ".json")));
    }

    /// @notice W5: the walk from `p` (generation `n`) to generation 1 against the book, else `GEN_WALK_MISMATCH <g>`.
    function _walkCheck(string memory book, address p, uint256 n) internal view {
        for (uint256 g = n; g != 0; --g) {
            string memory at = g == n ? "." : string.concat(".ua_registry_line.gen", vm.toString(g), ".");
            string memory a = string.concat(at, g == n ? "ua_registry" : "registry");
            string memory h = string.concat(at, g == n ? "ua_registry_codehash" : "codehash");
            string memory err = string.concat("GEN_WALK_MISMATCH ", vm.toString(g));
            require(vm.keyExistsJson(book, a) && vm.keyExistsJson(book, h), string.concat(err, ": not in the book"));
            require(
                p.code.length != 0 && p == vm.parseJsonAddress(book, a) && p.codehash == vm.parseJsonBytes32(book, h)
                    && UARegistry(p).generation() == g,
                string.concat(err, ": address, code hash or generation differs from the book")
            );
            p = UARegistry(p).predecessor();
        }
        require(p == address(0), "GEN_WALK_MISMATCH 1: generation 1 has a predecessor");
        if (!vm.keyExistsJson(book, ".ua_registry_libraries")) return;
        string[3] memory names = ["UARegistryCoreLib", "UARegistryAuxLib", "UARegistryRegLib"];
        for (uint256 i; i < 3; ++i) {
            string memory q = string.concat(".ua_registry_libraries.", names[i]);
            if (!vm.keyExistsJson(book, q)) continue;
            address l = vm.parseJsonAddress(book, string.concat(q, ".address"));
            require(
                l.code.length != 0 && l.codehash == vm.parseJsonBytes32(book, string.concat(q, ".codehash")),
                string.concat("GEN_WALK_MISMATCH ", vm.toString(n), ": library ", names[i])
            );
        }
    }

    /// @notice The kinds of generation `g` over `pred`: `0x0142` with the home's `pqz-mlwe` verifier and cap wherever a
    ///         predecessor enables it (M9; leaving it out, `gen_pqz: false`, is `GEN_PQZ_OMITTED` unless the owner's override),
    ///         and each `gen_verify_only` entry `{kind, verifier, cap, keyForm}` (`_voKind`).
    function _genKinds(string memory book, UARegistry pred, uint256 g, uint64 budget)
        internal
        returns (UARegistry.KindConfig[] memory k)
    {
        uint256 m;
        while (vm.keyExistsJson(book, string.concat(".gen_verify_only[", vm.toString(m), "]"))) ++m;
        k = new UARegistry.KindConfig[](m + 1);
        uint256 n;
        address ph = pred.kindHome(UAKinds.PQZ_MLWE);
        if (ph != address(0)) {
            if (!vm.keyExistsJson(book, ".gen_pqz") || vm.parseJsonBool(book, ".gen_pqz")) {
                address v = UARegistry(ph).verifierOf(UAKinds.PQZ_MLWE);
                require(
                    v.code.length != 0 && PqzKeyVerifier(v).PRECOMPILE() == PqzSafety.PQZ
                        && PqzKeyVerifier(v).PROOF_SYSTEM_ID() == PqzSafety.PQZL_ID,
                    "gen registry: the home's pqz-mlwe verifier is not a PqzKeyVerifier on the PQZ precompile"
                );
                k[n++] =
                    UARegistry.KindConfig(UAKinds.PQZ_MLWE, v, UARegistry(ph).verifyCap(UAKinds.PQZ_MLWE), false, 0);
                vm.serializeBytes32("deploy", "pqz_key_verifier_codehash", v.codehash);
            } else {
                require(
                    _ownerOverride(book, "GEN_PQZ_OMITTED"),
                    "GEN_PQZ_OMITTED: a predecessor enables 0x0142; leaving it out needs the owner's override in the book (M9)"
                );
            }
        }
        string memory list = "{}"; // `verify_only`: an object keyed by the kind (forge's JSON writer keeps no array of objects)
        for (uint256 i; i < m; ++i) {
            string memory e = string.concat(".gen_verify_only[", vm.toString(i), "]");
            UARegistry.KindConfig memory c = UARegistry.KindConfig(
                uint16(vm.parseJsonUint(book, string.concat(e, ".kind"))),
                vm.parseJsonAddress(book, string.concat(e, ".verifier")),
                uint64(vm.parseJsonUint(book, string.concat(e, ".cap"))),
                true,
                uint8(vm.parseJsonUint(book, string.concat(e, ".keyForm")))
            );
            // P2-3 (spec §9, F4, R5): the differential probe ran for this verifier and found no difference
            // (`script/pq_verifiers.py differential ... --book-out`, its `differential` field "ok" and the verifier's address)
            require(
                vm.keyExistsJson(book, string.concat(e, ".differential"))
                    && keccak256(bytes(vm.parseJsonString(book, string.concat(e, ".differential"))))
                        == keccak256(bytes(string.concat("ok ", vm.toString(c.verifier)))),
                string.concat(
                    "GEN_DIFFERENTIAL_MISSING ",
                    vm.toString(abi.encodePacked(c.kind)),
                    ": no differential probe ok for ",
                    vm.toString(c.verifier)
                )
            );
            _voKind(pred, c, g, budget, ph != address(0));
            k[n++] = c;
            string memory o = vm.toString(abi.encodePacked(c.kind));
            vm.serializeUint(o, "kind", c.kind);
            vm.serializeAddress(o, "verifier", c.verifier);
            vm.serializeBytes32(o, "codehash", c.verifier.codehash);
            vm.serializeUint(o, "cap", c.cap);
            vm.serializeUint(o, "keyForm", c.keyForm);
            list = vm.serializeString("verify_only", o, vm.serializeAddress(o, "precompile", _precompileOf(c.verifier)));
        }
        vm.serializeString("deploy", "verify_only", list);
        assembly ("memory-safe") {
            mstore(k, n)
        }
    }

    /// @notice One verify-only kind (§2, §9): an eligible ML-DSA kind (§7) a predecessor enables; `GEN_KEY_FORM_IMPOSSIBLE <kind>`
    ///         for key form 1 where the home's verifier has a precompile (N8); `GEN_VERIFY_ONLY_NO_PRECOMPILE <kind>` for a verifier
    ///         whose probe found none (N16, P11); the verifier's `KIND` and `KEY_FORM`; the 75 % rule; where `0x0142` is on the
    ///         line, `GEN_PQZ_DEBIT_BOUND <kind>` (M10 d, `UARegistryRegLib.voDebitFits`, the registry constructor's own check).
    function _voKind(UARegistry pred, UARegistry.KindConfig memory c, uint256 g, uint64 budget, bool pqzLine)
        internal
        view
    {
        string memory kh = vm.toString(abi.encodePacked(c.kind));
        require(
            c.kind == UAKinds.MLDSA44 || c.kind == UAKinds.MLDSA65 || c.kind == UAKinds.MLDSA87,
            string.concat("gen registry: kind ", kh, " is not eligible verify-only (ML-DSA only, spec section 7)")
        );
        address home = pred.kindHome(c.kind);
        require(home != address(0), string.concat("gen registry: no predecessor enables kind ", kh));
        require(
            c.keyForm == 0 || (c.keyForm == 1 && _precompileOf(UARegistry(home).verifierOf(c.kind)) == address(0)),
            string.concat("GEN_KEY_FORM_IMPOSSIBLE ", kh, ": the home's verifier has a precompile, no cache can exist")
        );
        require(
            c.verifier.code.length != 0 && _precompileOf(c.verifier) != address(0),
            string.concat("GEN_VERIFY_ONLY_NO_PRECOMPILE ", kh, ": the verifier's probe found no precompile")
        );
        require(
            MldsaVerifier(c.verifier).KIND() == c.kind && MldsaVerifyOnly(c.verifier).KEY_FORM() == c.keyForm,
            string.concat("gen registry: the verify-only verifier of ", kh, " has another kind or key form")
        );
        uint256 callGas = MldsaVerifyOnly(c.verifier).CALL_GAS();
        // Task 21 review P2-3: the verifier is this build's CREATE2 of its kind over this chain's candidates, pq_kat.json's valid
        // row and every edge row (the flipped row, each mutation row): what the chain's precompile was probed on is bound
        require(
            c.verifier == _voCreate2(c.kind, c.keyForm, callGas),
            string.concat(
                "GEN_VERIFY_ONLY_UNBOUND ",
                kh,
                ": not this build's CREATE2 of MldsaVerifyOnly over the candidates and pq_kat.json's rows (DEPLOY_SALT)"
            )
        );
        // P2-4: the cap covers the precompile call and the alive-check at CALL_GAS each and the verifier's own work, so a
        // precompile that burns its gas cannot starve the alive-check into a caller-forced fallback (M7)
        require(
            c.cap >= 2 * callGas + VO_VERIFIER_OVERHEAD,
            string.concat(
                "GEN_VERIFY_ONLY_CAP ",
                kh,
                ": cap ",
                vm.toString(uint256(c.cap)),
                " below 2 x CALL_GAS ",
                vm.toString(callGas),
                " + ",
                vm.toString(VO_VERIFIER_OVERHEAD)
            )
        );
        require(
            _pqKindFits(c.cap, budget), string.concat("gen registry: the cap of ", kh, " is over 75 % of the budget")
        );
        if (!pqzLine) return;
        uint256 hc = UARegistry(home).verifyCap(c.kind);
        require(
            UARegistryRegLib.voDebitFits(c.kind, c.cap, hc, g - UARegistry(home).generation(), txGasCap),
            string.concat(
                "GEN_PQZ_DEBIT_BOUND ",
                kh,
                ": cap ",
                vm.toString(uint256(c.cap)),
                " + the home's ",
                vm.toString(hc),
                " + PQZ_DEBIT_MIN_GAS over txGasCap ",
                vm.toString(uint256(txGasCap))
            )
        );
    }

    /// @notice The verify-only verifier's own work beside its two limited calls (lengths, the message hash, the valid row read back,
    ///         the encoding), `test/ua/MlDsaVerifyOnly.t.sol` `OVERHEAD` (its worst input measured 134,921 within 2 x 100,000 + this).
    uint256 internal constant VO_VERIFIER_OVERHEAD = 40_000;

    /// @notice The init code of `MldsaVerifyOnly<x>` for `kind` (key form `form`, precompile limit `callGas`) as `pq_verifiers.py
    ///         verify-only` builds it: this chain's candidates (`_mldsaCandidates`), pq_kat.json's EIP-8355 valid row, the flipped
    ///         row then every mutation row (`_mldsaEdgeRows`).
    function _voInit(uint16 kind, uint8 form, uint256 callGas) internal view returns (bytes memory) {
        uint256 i = kind == UAKinds.MLDSA44 ? 0 : kind == UAKinds.MLDSA65 ? 1 : 2;
        (bytes memory valid, bytes memory flipped) = _mldsaProbe(i);
        bytes[] memory edge = _mldsaEdgeRows(i);
        bytes[] memory rows = new bytes[](edge.length + 1);
        rows[0] = flipped;
        for (uint256 r; r < edge.length; ++r) {
            rows[r + 1] = edge[r];
        }
        bytes memory code = i == 0
            ? type(MldsaVerifyOnly44).creationCode
            : i == 1 ? type(MldsaVerifyOnly65).creationCode : type(MldsaVerifyOnly87).creationCode;
        return abi.encodePacked(code, abi.encode(_mldsaCandidates(i), valid, rows, form, callGas));
    }

    function _voCreate2(uint16 kind, uint8 form, uint256 callGas) internal view returns (address) {
        return vm.computeCreate2Address(salt, keccak256(_voInit(kind, form, callGas)), CREATE2_FACTORY);
    }

    /// @notice A verifier's `PRECOMPILE()`, 0 when it has none or does not answer one word.
    function _precompileOf(address v) internal view returns (address) {
        (bool ok, bytes memory r) = v.staticcall(abi.encodeWithSignature("PRECOMPILE()"));
        return ok && r.length == 32 ? abi.decode(r, (address)) : address(0);
    }

    /// @notice `bls12381-multi`'s line in the deploy book (spec 2026-11-19-bls12381-multi §7, §10; ARCH-POS-18): its path where the
    ///         probe passes, else why the chain has none: on Hedera disabled by the owner's confirmation for that kind and chain
    ///         (2026-11-19, Q-SW1); anywhere else refused, the software BLS12-381 path not being built, a case for the owner.
    function _blsMultiPath(bool bls, bool isHedera) internal pure returns (string memory) {
        if (isHedera) return "disabled: Hedera, owner-confirmed 2026-11-19 (Q-SW1, ARCH-POS-18)";
        if (bls) return "precompile: EIP-2537";
        return "refused: no EIP-2537 and no software BLS12-381 path built (ARCH-POS-18): a case for the owner";
    }

    /// @notice The gates of the registry's release and of its three libraries', each its own transaction (CREATE2 of the
    ///         registry's init code with these arguments; each library's creation code).
    function _requireRegistryGas(
        address pred,
        bool isHedera,
        uint64 budget,
        address ska,
        UARegistry.KindConfig[] memory k
    ) internal {
        _requireReleaseGas(
            "UARegistry",
            address(0),
            abi.encodePacked(
                type(UARegistry).creationCode, abi.encode(uid, pred, isHedera, budget, txGasCap, ska, true, k)
            )
        );
        _requireReleaseGas("UARegistryCoreLib", address(0), vm.getCode("UARegistryCoreLib.sol:UARegistryCoreLib"));
        _requireReleaseGas("UARegistryAuxLib", address(0), vm.getCode("UARegistryAuxLib.sol:UARegistryAuxLib"));
        _requireReleaseGas("UARegistryRegLib", address(0), vm.getCode("UARegistryRegLib.sol:UARegistryRegLib"));
    }

    /// @notice The gen-1 kind gate (U8S-D9, owner ruling 2026-10-31, option (a)): every gen-1 deploy carries every kind the
    ///         chain can run, so when the probe passes EIP-2537 (`bls`) the gen-1 registry `reg` must enable
    ///         `schnorr-bls12381` 0x0105, `bls12381-minsig` 0x0106 and, except on Hedera (no Zether token can exist there,
    ///         `ZetherLayer`; `bls12381-multi` disabled there, owner-confirmed 2026-11-19), `zether-bls12381` 0x0141 and
    ///         `bls12381-multi` 0x0121; otherwise the deploy reverts before anything is sent. No
    ///         `UARegistry` change. A probe that fails (the RPC refuses the call) requires nothing (`_precompiles`).
    ///         Owner 2026-11-15: the same for the chain's own PQ precompiles (`_pqPrecompiles`): `pqz` (the `PQZ` self-test
    ///         answers) requires `pqz-mlwe` 0x0142, `ml87` (an ML-DSA-87 precompile answers the KAT probe, with
    ///         `MLDSA_PRECOMPILE=on`) `mldsa87` 0x0134; that the ML-DSA kinds are on the precompile is `_mldsaVerifier`'s check.
    function _checkGen1Kinds(IUARegistry reg, bool bls, bool isHedera, bool pqz, bool ml87) internal view {
        require(reg.generation() == 1, "gen-1 registry: not generation 1");
        require(
            !pqz || reg.kindEnabled(UAKinds.PQZ_MLWE),
            "gen-1 registry: PQ precompile kind 0x0142 the probe passes is missing (PQZ_KEY_VERIFIER: deploy.sh evm's pq-verifiers step)"
        );
        require(
            !ml87 || reg.kindEnabled(UAKinds.MLDSA87),
            "gen-1 registry: PQ precompile kind 0x0134 the probe passes is missing (MLDSA87_VERIFIER: deploy.sh evm's pq-verifiers step)"
        );
        if (!bls) return;
        uint16[4] memory need =
            [UAKinds.SCHNORR_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.ZETHER_BLS12381, UAKinds.BLS12381_MULTI];
        for (uint256 i; i < (isHedera ? 2 : 4); ++i) {
            require(
                reg.kindEnabled(need[i]),
                string.concat(
                    "gen-1 registry: EIP-2537 kind ",
                    vm.toString(abi.encodePacked(need[i])),
                    " the probe passes is missing"
                )
            );
        }
    }

    /// @notice `PqPrecompileProbe`'s init code with the three levels' probe inputs.
    function _pqProbeInit() internal view returns (bytes memory) {
        (bytes memory v44, bytes memory b44) = _mldsaProbe(0);
        (bytes memory v65, bytes memory b65) = _mldsaProbe(1);
        (bytes memory v87, bytes memory b87) = _mldsaProbe(2);
        return
            abi.encodePacked(
                type(PqPrecompileProbe).creationCode, abi.encode(v44, b44, v65, b65, v87, b87, _draftProbe())
            );
    }

    /// @notice The `pq_kat.json` EIP-8355 probe inputs of ML-DSA kind `i` (0, 1, 2 = 44, 65, 87): valid ⇒ the word 1, flipped ⇒ 0.
    function _mldsaProbe(uint256 i) internal view returns (bytes memory valid, bytes memory invalid) {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        string memory k = string.concat(".kinds.mldsa", ["44", "65", "87"][i]);
        valid = vm.parseJsonBytes(kat, string.concat(k, ".eip8355_probe_valid"));
        invalid = vm.parseJsonBytes(kat, string.concat(k, ".eip8355_probe_invalid"));
    }

    /// @notice The `pq_kat.json` mutation rows of ML-DSA kind `i` as EIP-8355 inputs `pk ‖ sig ‖ pq_msg` (each invalid).
    function _mldsaEdgeRows(uint256 i) internal view returns (bytes[] memory rows) {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        string memory k = string.concat(".kinds.mldsa", ["44", "65", "87"][i], ".mutations");
        uint256 n;
        while (vm.keyExistsJson(kat, string.concat(k, "[", vm.toString(n), "]"))) ++n;
        rows = new bytes[](n);
        bytes32 t = PqUA.tag([UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.MLDSA87][i]);
        for (uint256 r; r < n; ++r) {
            string memory m = string.concat(k, "[", vm.toString(r), "]");
            rows[r] = abi.encodePacked(
                vm.parseJsonBytes(kat, string.concat(m, ".pk")),
                vm.parseJsonBytes(kat, string.concat(m, ".sig")),
                PqUA.pqMessage(t, vm.parseJsonBytes32(kat, string.concat(m, ".ua_msg")))
            );
        }
    }

    /// @notice CTR-UA-23 / CTR-UA-39: the first candidate (`_mldsaCandidates`) that answers ML-DSA kind `i`'s probe exactly in
    ///         this run's EVM, with the probe inputs the verifier checks again; else 0 (forge's EVM: none, unless a test mocks one).
    ///         A Draft candidate (`0x12` + i) is taken only with the fuller probe of CTR-UA-69: the valid row, the flipped row and
    ///         every `pq_kat.json` mutation row as its EIP-8355 input (`_mldsaEdgeRows`), each answered exactly.
    function _mldsaPrecompile(uint256 i) internal view returns (address p, bytes memory valid, bytes memory invalid) {
        (valid, invalid) = _mldsaProbe(i);
        address[] memory c = _mldsaCandidates(i);
        for (uint256 j; j < c.length && p == address(0); ++j) {
            if (!PqUA.probe(c[j], valid, invalid)) continue;
            if (c[j] == address(uint160(0x12 + i))) {
                bytes[] memory rows = _mldsaEdgeRows(i);
                bool all = true;
                for (uint256 r; r < rows.length && all; ++r) {
                    all = PqUA.probe(c[j], valid, rows[r]);
                }
                if (!all) continue;
            }
            p = c[j];
        }
    }

    /// @notice The chain's own verdict on its PQ precompiles (`PqPrecompileProbe`: the `PQZ` self-test; each ML-DSA kind's KAT
    ///         probe at its candidates, `ml` = 44, 65, 87), by `eth_call` with no `to` as `_precompiles` (anvil answers: all
    ///         false). With `MLDSA_PRECOMPILE=on` a call that fails or answers no 128 bytes refuses the deploy by name (MD-15);
    ///         with `off` it requires no kind. Tests override it.
    function _pqPrecompiles() internal virtual returns (bool pqz, bool[3] memory ml) {
        bytes memory init = _pqProbeInit();
        bool answered;
        // gas 2^24: EIP-7825's cap, which Nethermind applies to eth_call too (F-7)
        bytes memory out;
        try vm.rpc(
            "eth_call", string.concat('[{"data":"', vm.toString(init), '","gas":"0x1000000"},"latest"]')
        ) returns (
            bytes memory o
        ) {
            out = o;
        } catch {}
        if (out.length == 128) {
            answered = true;
            (pqz, ml[0], ml[1], ml[2]) = abi.decode(out, (bool, bool, bool, bool));
        }
        // MD-15 (owner 2026-11-15, F-7): with `on`, only an answered "no" selects the cache, never a failed probe
        require(
            answered || !mldsaPrecompile,
            "MLDSA_PRECOMPILE=on: the chain's PQ precompile probe (PqPrecompileProbe by eth_call) failed or answered no 128 bytes: refused (MD-15)"
        );
    }

    /// @notice The chain's own verdict on its pairing precompiles (`UAPrecompileProbe`), asked through `eth_call` with
    ///         no `to` — the node's precompiles, not forge's. An RPC that refuses the call disables both kind sets (fail
    ///         closed). Tests override it with a local probe.
    function _precompiles() internal virtual returns (bool bls12381, bool bn254G2) {
        string memory params =
            string.concat('[{"data":"', vm.toString(type(UAPrecompileProbe).creationCode), '"},"latest"]');
        try vm.rpc("eth_call", params) returns (bytes memory out) {
            if (out.length == 64) (bls12381, bn254G2) = abi.decode(out, (bool, bool));
        } catch {}
    }

    /// @notice The link closure of a Zether token (task 6): `WrappedLib` and `ZetherWrappedLib` only in `WRAPPED_ZETHER`.
    function _zetherLibs(bool underlying) internal view returns (address[] memory l) {
        l = new address[](underlying ? 6 : 4);
        (l[0], l[1], l[2], l[3]) =
        (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(ZetherLib));
        if (underlying) (l[4], l[5]) = (address(WrappedLib), address(ZetherWrappedLib));
    }

    /// @notice Any chain but Hedera (CTR-ZTH-52; `_deployTokenFactory` requires the EIP-2537 probe first, and a chain
    ///         without EIP-2537 would revert at the inner-product verifier): `ZetherStatements`,
    ///         `ZetherDisclosure`, the BLS12-381 inner-product verifier (the generators, ~14 M gas) and the transfer and
    ///         burn verifiers on it (classical Zether is BLS12-381 only, CTR-ZTH-32; the bn254 steps are in
    ///         `legacy/ua6/`); when the deployer is the registrar, an env of `NORMAL_ZETHER` and `WRAPPED_ZETHER`
    ///         (version 1; `deps` = transfer, burn, inner-product verifier, disclosure, CTR-ZTH-20) and the two releases
    ///         on it, then the kinds enabled, then the regulated Zether releases 10, 11 (`_deployZetherRegulated`, plan
    ///         T30). JSON `zether_registry` (= `ua_registry`), `zether_statements`,
    ///         `zether_disclosure`, `zether_{inner_product_,,burn_}verifier_bls12381`,
    ///         `implementation_{normal,wrapped}_zether_bls12381`. **UNAUDITED.** The
    ///         implementations exceed EIP-170 and the BLS inner-product verifier takes ~14 M gas: anvil
    ///         `--code-size-limit 65536`, forge script `--disable-code-size-limit` (deploy.sh passes it; each transaction's
    ///         gas limit is explicit, NET-EVM-11; docs/networks/evm.md). Each release is checked against `CHAIN_CODE_LIMIT` first (`_checkCodeFits`).
    function _deployZether(OpenFactory f, bool register, address smartKeyAccountImpl, address reg) internal {
        address dis = address(new ZetherDisclosure{salt: salt}());
        IZetherInnerProductVerifier ip = new ZetherInnerProductVerifierBls12381{salt: salt}();
        address tv = address(new ZetherTransferVerifierBls12381{salt: salt}(ip));
        address bv = address(new ZetherBurnVerifierBls12381{salt: salt}(ip));
        vm.serializeAddress("deploy", "zether_inner_product_verifier_bls12381", address(ip));
        vm.serializeAddress("deploy", "zether_verifier_bls12381", tv);
        vm.serializeAddress("deploy", "zether_burn_verifier_bls12381", bv);
        if (register) {
            address[] memory deps = new address[](4);
            (deps[0], deps[1], deps[2], deps[3]) = (tv, bv, address(ip), dis);
            _zetherReleases(f, reg, smartKeyAccountImpl, deps);
            f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER, true, f.chainUid());
            f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER, true, f.chainUid());
            _deployZetherRegulated(f, reg, smartKeyAccountImpl, deps);
        }
        vm.serializeAddress("deploy", "zether_disclosure", dis);
        vm.serializeAddress("deploy", "zether_registry", reg); // = ua_registry
        vm.serializeAddress("deploy", "zether_statements", zetherStatements);
    }

    /// @notice `_deployZether`'s two releases (`NORMAL_ZETHER`, `WRAPPED_ZETHER`) on `deps`, each with its body modules.
    function _zetherReleases(OpenFactory f, address reg, address smartKeyAccountImpl, address[] memory deps) internal {
        address none = _kindRelease(
            f,
            IOpenFactory.TokenKind.NORMAL_ZETHER,
            "NormalZetherToken",
            type(NormalZetherToken).creationCode,
            "",
            _env(f, reg, smartKeyAccountImpl, false, deps, _zetherLibs(false))
        );
        address und = _kindRelease(
            f,
            IOpenFactory.TokenKind.WRAPPED_ZETHER,
            "WrappedZetherToken",
            type(WrappedZetherToken).creationCode,
            "",
            _env(f, reg, smartKeyAccountImpl, false, deps, _zetherLibs(true))
        );
        vm.serializeAddress("deploy", "implementation_normal_zether_bls12381", none);
        vm.serializeAddress("deploy", "implementation_wrapped_zether_bls12381", und);
    }

    /// @notice Regulated-kinds spec §6.1 (plan T30): with the Zether stack, env version 1 of `NORMAL_ZETHER_REGULATED` (10)
    ///         and `WRAPPED_ZETHER_REGULATED` (11), each its base kind's `deps` and link closure with `RegulatedLib` added,
    ///         the releases, version 1, each refused first by `_requireReleaseGas`, `implArgs` the canonical
    ///         `ComplianceRegistry` runtime's code hash (F-11), then both kinds enabled. JSON
    ///         `implementation_{normal,wrapped}_zether_regulated_bls12381`. Never on Hedera (`ZetherLayer`).
    function _deployZetherRegulated(OpenFactory f, address reg, address smartKeyAccountImpl, address[] memory deps)
        internal
    {
        bytes memory coreArgs = abi.encode(_complianceRegistryCodehash());
        address n = _kindRelease(
            f,
            IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED,
            "NormalZetherRegulatedToken",
            type(NormalZetherRegulatedToken).creationCode,
            coreArgs,
            _env(f, reg, smartKeyAccountImpl, false, deps, _withRegulatedLib(_zetherLibs(false)))
        );
        address w = _kindRelease(
            f,
            IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED,
            "WrappedZetherRegulatedToken",
            type(WrappedZetherRegulatedToken).creationCode,
            coreArgs,
            _env(f, reg, smartKeyAccountImpl, false, deps, _withRegulatedLib(_zetherLibs(true)))
        );
        vm.serializeAddress("deploy", "implementation_normal_zether_regulated_bls12381", n);
        vm.serializeAddress("deploy", "implementation_wrapped_zether_regulated_bls12381", w);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, true, f.chainUid());
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, true, f.chainUid());
    }

    /// @notice Owner 2026-11-15 (`DEPLOY_PQZ`): the PQZ releases on this factory as `script/pqz/e2e.py` publishes them on its own:
    ///         env version 1 of `NORMAL_PQZ` (4), `WRAPPED_PQZ` (5), `NORMAL_PQZ_REGULATED` (12), `WRAPPED_PQZ_REGULATED` (13), its one
    ///         dependency `PQZ_KEY_VERIFIER` (CTR-ZTH-20; a PRECOMPILE token takes the precompile and proof system from it), the
    ///         link closure `_pqzLibs` (the regulated kinds with `RegulatedLib`), the body modules (`_kindRelease`), `implArgs`
    ///         with `COMPLIANCE_REGISTRY_CODEHASH` on 12, 13; each release and module after its gate (`_requireReleaseGas`,
    ///         NET-EVM-06); then the four kinds enabled. JSON `implementation_{normal,wrapped}_pqz`,
    ///         `implementation_{normal,wrapped}_pqz_regulated`, `pqz_key_verifier`. **UNAUDITED.**
    function _deployPqz(OpenFactory f, address reg, address ska, bool isHedera) internal {
        require(
            pqzKeyVerifier != address(0),
            "DEPLOY_PQZ: no PQZ_KEY_VERIFIER (deploy.sh evm's pq-verifiers step needs the chain's PQZ precompile)"
        );
        IOpenFactory.TokenKind k = IOpenFactory.TokenKind.NORMAL_PQZ;
        _pqzRelease(
            f,
            k,
            "NormalPqzToken",
            vm.getCode("NormalPqzToken.sol:NormalPqzToken"),
            "implementation_normal_pqz",
            _pqzEnv(f, reg, ska, isHedera, k)
        );
        k = IOpenFactory.TokenKind.WRAPPED_PQZ;
        _pqzRelease(
            f,
            k,
            "WrappedPqzToken",
            vm.getCode("WrappedPqzToken.sol:WrappedPqzToken"),
            "implementation_wrapped_pqz",
            _pqzEnv(f, reg, ska, isHedera, k)
        );
        k = IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED;
        _pqzRelease(
            f,
            k,
            "NormalPqzRegulatedToken",
            vm.getCode("NormalPqzRegulatedToken.sol:NormalPqzRegulatedToken"),
            "implementation_normal_pqz_regulated",
            _pqzEnv(f, reg, ska, isHedera, k)
        );
        k = IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED;
        _pqzRelease(
            f,
            k,
            "WrappedPqzRegulatedToken",
            vm.getCode("WrappedPqzRegulatedToken.sol:WrappedPqzRegulatedToken"),
            "implementation_wrapped_pqz_regulated",
            _pqzEnv(f, reg, ska, isHedera, k)
        );
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, f.chainUid());
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ, true, f.chainUid());
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, true, f.chainUid());
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true, f.chainUid());
    }

    /// @notice One PQZ release of `_deployPqz` on env `e` (`_pqzEnv`), `coreArgs` the registry pin on 12, 13. The init code by
    ///         `vm.getCode` (linked as `_module`'s), not embedded in this script: four more embedded releases would grow every
    ///         contract that inherits `DeployBase` (the test harness) past the test's gas.
    function _pqzRelease(
        OpenFactory f,
        IOpenFactory.TokenKind kind,
        string memory name,
        bytes memory code,
        string memory key,
        IFactoryToken.Env memory e
    ) internal {
        bytes memory coreArgs = uint8(kind) >= 8 ? abi.encode(_complianceRegistryCodehash()) : bytes("");
        vm.serializeAddress("deploy", key, _kindRelease(f, kind, name, code, coreArgs, e));
    }

    /// @notice A PQZ kind's env 1: deps `[PQZ_KEY_VERIFIER]`, its closure (`_pqzLibs`; `RegulatedLib` on 12, 13).
    function _pqzEnv(OpenFactory f, address reg, address ska, bool isHedera, IOpenFactory.TokenKind kind)
        internal
        view
        returns (IFactoryToken.Env memory)
    {
        address[] memory deps = new address[](1);
        deps[0] = pqzKeyVerifier;
        bool underlying =
            kind == IOpenFactory.TokenKind.WRAPPED_PQZ || kind == IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED;
        address[] memory libs = uint8(kind) >= 8 ? _withRegulatedLib(_pqzLibs(underlying)) : _pqzLibs(underlying);
        return _env(f, reg, ska, isHedera, deps, libs);
    }

    /// @notice The link closure of a PQZ token (`test/helpers/Catalogue.sol` `closureLibs`, the order of e2e.py's link
    ///         references as a set): `WrappedLib` and `PqzWrappedLib` only in `WRAPPED_PQZ`.
    function _pqzLibs(bool underlying) internal pure returns (address[] memory l) {
        l = new address[](underlying ? 9 : 7);
        (l[0], l[1], l[2]) = (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib));
        uint256 n = 3;
        if (underlying) l[n++] = address(WrappedLib);
        (l[n], l[n + 1], l[n + 2], l[n + 3]) =
        (address(PqzStateLib), address(PqzTransferLib), address(PqzBurnLib), address(PqzViewLib));
        if (underlying) l[n + 4] = address(PqzWrappedLib);
    }

    /// @notice `libs` and `RegulatedLib` last: a regulated kind's closure (it links only `GovernanceLib`, already in `libs`).
    function _withRegulatedLib(address[] memory libs) internal pure returns (address[] memory l) {
        l = new address[](libs.length + 1);
        for (uint256 i; i < libs.length; ++i) {
            l[i] = libs[i];
        }
        l[libs.length] = address(RegulatedLib);
    }

    /// @notice Two kind-`NORMAL` demo tokens from `f` (dev chains; only when the deployer is the registrar): 6 decimals,
    ///         `PAYABLE`, `supply` each to the deployer, half of each to `holder`; JSON `demo_token`, `demo_token_2`.
    function _demoTokens(OpenFactory f, uint256 supply, address deployer, address holder)
        internal
        returns (address demo, address demo2)
    {
        require(f.noticePeriod() == 0, "DEMO_SUPPLY needs NOTICE_PERIOD=0: a new release is not usable yet");
        demo = _demoToken(f, "SCaaS Demo USD", "bUSD", supply, deployer, "demo");
        demo2 = _demoToken(f, "SCaaS Demo Points", "bPTS", supply, deployer, "demo2");
        if (holder != deployer) {
            IERC20(demo).transfer(holder, supply / 2);
            IERC20(demo2).transfer(holder, supply / 2);
        }
        vm.serializeAddress("deploy", "demo_token_2", demo2);
        vm.serializeAddress("deploy", "demo_token", demo);
    }

    function _demoToken(
        OpenFactory f,
        string memory name,
        string memory symbol,
        uint256 supply,
        address holder,
        bytes32 tokenSalt
    ) private returns (address) {
        IFactoryToken.TokenConfig memory c;
        c.name = name;
        c.symbol = symbol;
        c.decimals = 6;
        c.features = 1 << GovernanceBits.PAYABLE;
        c.initialSupply = supply;
        c.initialHolder = holder;
        return f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), tokenSalt);
    }

    /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
    function _gate(address c) internal view {
        (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
        require(ok && ret.length == 32 && abi.decode(ret, (bytes32)) == uid, "chainUid() gate");
    }
}
