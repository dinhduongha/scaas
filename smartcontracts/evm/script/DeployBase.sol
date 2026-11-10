// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../src/factory/ChainEnvCode.sol";
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
import {UARegistry} from "../src/ua/UARegistry.sol";
import {IUARegistry} from "../src/ua/IUARegistry.sol";
import {UARegistryCoreLib} from "../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../src/ua/UARegistryAuxLib.sol";
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
import {UAFrostSecp256k1Verifier} from "../src/ua/verifiers/UAFrostSecp256k1Verifier.sol";
import {Musig2Bn254Verifier} from "../src/ua/verifiers/Musig2Bn254Verifier.sol";
import {FrostBn254Verifier} from "../src/ua/verifiers/FrostBn254Verifier.sol";
import {UAMldsaVerifier} from "../src/ua/MlDsa.sol";
import {UAFndsaVerifier} from "../src/ua/FnDsa.sol";
import {UASlhdsaVerifier} from "../src/ua/SlhDsa.sol";
import {UAPrecompileProbe} from "./UAPrecompileProbe.sol";
import {kindModuleNames, kindImplArgs} from "./KindModules.sol";
import {ImplArgs} from "../src/metatx/ITokenModule.sol";
import {ZetherDisclosure} from "../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../src/zether/ZetherStatements.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../src/zether/ZetherVerifier.sol";
import {IZetherInnerProductVerifier} from "../src/zether/IZetherVerifier.sol";
import {NormalZetherToken} from "../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../src/zether/WrappedZetherToken.sol";

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
abstract contract DeployBase is Script {
    /// @notice CREATE2 salt of every contract: `DEPLOY_SALT` env, default `keccak256("scaas.deploy.v1")`.
    bytes32 internal salt;
    /// @notice The chain's genesis hash (`_chainUid`).
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
    /// @notice `COMPLIANCE_ADMIN` env (read with `DEPLOY_REGULATED`): the canonical `ComplianceRegistry`'s admin, a contract
    ///         the operator names (CTR-AS-07, regulated-kinds spec §6.1, F-21); the registry's constructor refuses any other.
    address internal complianceAdmin;
    /// @notice `OpenFactory.noticePeriod` (plan 5g-Z2; owner ruling 2026-10-20): `NOTICE_PERIOD` env. Safe by default:
    ///         every chain not in `_isTestChain` is a mainnet (22776, Hedera 295, Ethereum, BSC, an unknown chain), with
    ///         default and floor 3 days; 7622 defaults to 10 minutes, the other test / dev chains to 0. At most 30 days
    ///         (`MAX_NOTICE_PERIOD`, the factory's).
    uint64 internal noticePeriod;
    /// @notice This chain's `GovernanceRouter` (`_deployGovRouter`), the factory's one-time `govRouter`; 0 until deployed.
    address internal govRouter;
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
    ///         SLH-DSA above its 1.32 M worst case. Each ≤ 50 % of the 12 M budget (the deploy rule is ≤ 66 %, `_pqKindFits`).
    uint64 internal constant CAP_MLDSA44 = 4_250_000;
    uint64 internal constant CAP_MLDSA65 = 5_950_000;
    uint64 internal constant CAP_FNDSA512 = 2_500_000;
    uint64 internal constant CAP_SLHDSA128S = 1_400_000;
    /// @notice `fndsa1024` (CTR-UA-40, owner 2026-11-04): pure Solidity on every chain whose budget holds the cap at ≤ 66 % (every
    ///         budget ≥ 7,954,546). PROVISIONAL until T-GAS: the largest NIST KAT verify measured (4,932,967) + 6.4 %, the margin of
    ///         `fndsa512`'s cap (spec 2026-11-04-fndsa1024 F6).
    uint64 internal constant CAP_FNDSA1024 = 5_250_000;
    /// @notice `mldsa87` (CTR-UA-39, owner 2026-11-04): enabled only through an ML-DSA-87 precompile in the EIP-8355 layout,
    ///         probed at `0x14` (EIP-8355) and then at the SCaaS testnet's `MLDSA87`; without one it gets no verifier (Q1: the
    ///         Solidity verify, ≈ 8.8 M on a cached key, fails the 66 % rule). The cap of the precompile path is a PROVISIONAL
    ///         ESTIMATE (spec 2026-11-04-mldsa87 §4: 0.2–0.3 M; the `mldsa65` precompile path measured ≈ 236 k), measured by T-GAS on
    ///         a chain before it is final. The probe runs in this script's EVM: forge's has no such precompile, so the SCaaS
    ///         testnet deploys its `mldsa87` verifier the way it deploys `mldsa65`'s, outside `forge script` (P6g D15, `e2e.py`).
    uint64 internal constant CAP_MLDSA87 = 250_000;
    address internal constant MLDSA87_EIP8355 = address(0x14);
    address internal constant MLDSA87_SCAAS_TESTNET = 0x000000000000000000000000000000005caA0014;

    /// @notice C5-1, NET-EVM-06. A release is one CREATE2 of the whole implementation in the registrar's transaction.
    ///         Under EIP-8037 the code deposit is state gas, `STATE_GAS_PER_BYTE` per byte of runtime, on top of the
    ///         regular gas, which EIP-7825 caps at `TX_REGULAR_GAS_CAP` (2^24). Two gates, chosen by the declared
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
    uint256 internal constant TX_REGULAR_GAS_CAP = 1 << 24;
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
        return _baselineRuntime(name) * STATE_GAS_PER_BYTE + TX_REGULAR_GAS_CAP;
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
            revert(string.concat(name, " runtime ", vm.toString(runtime), " B > chain code limit ", vm.toString(limit),
                " B (CHAIN_CODE_LIMIT, CTR-GOV-19)"));
        }
    }

    function _checkReleaseGas(string memory name, uint256 limit) internal view {
        uint256 need = _releaseGasNeed(name);
        if (limit < need) {
            revert(string.concat("block gas limit ", vm.toString(limit), " < ", vm.toString(need),
                " needed to deploy the ", name, " release (NET-EVM-06)"));
        }
    }

    /// @notice The block gas limit the deploy gate reads: the chain's actual `block.gaslimit`.
    function _blockGasLimit() internal view virtual returns (uint256) { return block.gaslimit; }

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
    function _checkMeasuredGas(string memory name, uint256 regular, uint256 state, uint256 limit) internal pure {
        uint256 asked = (regular + state) * 105 / 100;
        if (regular * 105 / 100 >= TX_REGULAR_GAS_CAP) {
            revert(string.concat(name, " release: regular gas x 1.05 = ", vm.toString(regular * 105 / 100),
                " >= 2^24 (EIP-7825, NET-EVM-06)"));
        }
        if (limit < asked) {
            revert(string.concat("block gas limit ", vm.toString(limit), " < ", vm.toString(asked), " asked by the ", name,
                " release (measured regular + state x 1.05, NET-EVM-06)"));
        }
        console.log(string.concat("release gas | ", name, " | regular ", vm.toString(regular), " | state ", vm.toString(state),
            " | asked ", vm.toString(asked), " | block gas limit ", vm.toString(limit)));
    }

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
        deployZether = vm.envOr("DEPLOY_ZETHER", false);
        deployWrapped = vm.envOr("DEPLOY_WRAPPED", false);
        deployRegulated = vm.envOr("DEPLOY_REGULATED", false);
        deployPqChat = vm.envOr("DEPLOY_PQCHAT", false);
        complianceAdmin = vm.envOr("COMPLIANCE_ADMIN", address(0));
        noticePeriod = _checkedNotice(block.chainid, vm.envOr("NOTICE_PERIOD", _defaultNotice(block.chainid)));
        uid = _chainUid();
        releasesPath = vm.envOr("RELEASES_JSON", string("./releases.json"));
        releasesWrite = vm.envOr("RELEASES_WRITE", false);
        bool listedUid;
        (chainSiblings, listedUid) = _chainUidListed();
        require(chainSiblings == 0 || listedUid, "chain_uid is not chain-uids.json's for this chain id (NET-ALL-22)");
        require(CREATE2_FACTORY.code.length != 0,
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)");
    }

    function _defaultNotice(uint256 c) internal pure returns (uint256) {
        return !_isTestChain(c) ? 3 days : c == 7622 ? 10 minutes : 0;
    }

    /// @dev The period is immutable: a mainnet never gets a factory with a short notice (review 5g-Z2 P2-4, owner
    ///      2026-10-20); no silent `uint64` truncation.
    function _checkedNotice(uint256 c, uint256 notice) internal pure returns (uint64) {
        require(notice <= type(uint64).max, "NOTICE_PERIOD exceeds uint64");
        require(_isTestChain(c) || notice >= 3 days, "NOTICE_PERIOD below 3 days on a mainnet (not a listed test chain)");
        return uint64(notice);
    }

    /// @notice The test / dev chains (owner ruling 2026-10-20), a fixed list: local dev (31337, 1337), the node e2e's
    ///         anvils (31900–31999), 7622, Hedera 296–298 and the public testnets of chain-uids.json (Ethereum Sepolia,
    ///         Hoodi, Holesky; ETC Mordor; BSC, Gnosis Chiado, Polygon Amoy, Base, Celo Sepolia and Alfajores, OP,
    ///         Arbitrum, Avalanche Fuji, Linea). Every other chain is a mainnet.
    function _isTestChain(uint256 c) internal pure returns (bool) {
        if (c == 31337 || c == 1337 || (c >= 31900 && c <= 31999) || c == 7622 || (c >= 296 && c <= 298)) return true;
        uint32[14] memory t = [uint32(11155111), 560048, 17000, 63, 97, 10200, 80002, 84532, 11142220, 44787, 11155420,
            421614, 43113, 59141];
        for (uint256 i; i < t.length; ++i) if (c == t[i]) return true;
        return false;
    }

    /// @notice `CHAIN_UID` env (chain-uids.json), default block 0's hash as the RPC reports it; either way it must
    ///         equal that hash (CTR-GEN-05). BLOCKHASH only sees the 256 blocks before the current one, and a script
    ///         runs at the head, so roll to block 1: the fork database then fetches block 0 from the RPC at any head.
    function _chainUid() internal returns (bytes32 u) {
        uint256 head = block.number;
        vm.roll(1);
        bytes32 rpcGenesis = blockhash(0);
        vm.roll(head);
        u = vm.envOr("CHAIN_UID", rpcGenesis);
        require(u == rpcGenesis, "CHAIN_UID differs from the RPC's block 0 hash");
        require(u != bytes32(0), "RPC gave no block 0 hash");
    }

    /// @notice The token factory (`noticePeriod`) and the UA registry (`_deployUARegistry`, with its libraries `UARegistryCoreLib` and `UARegistryAuxLib`) by CREATE2; when the deployer
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
        internal returns (OpenFactory f)
    {
        if (deployZether) {
            require(!isHedera, "DEPLOY_ZETHER: not on Hedera (ZetherLayer refuses a Hedera env)");
            (bool bls,) = _precompiles(); // fail before deploying anything (CTR-ZTH-52: the only chain requirement)
            require(bls, "DEPLOY_ZETHER: the chain has no EIP-2537 (BLS12-381 precompiles)");
        }
        // chain-neutral releases (plan T71, T72): the registrar is the factory's only constructor argument; this chain's
        // values are its one-time `configureChain`, after the router it names (T73: the deterministic deployer, the
        // reference block and the dry run)
        f = new OpenFactory{salt: salt}(registrar);
        UARegistry reg = _deployUARegistry(smartKeyAccountImpl, isHedera);
        _deployGovRouter(address(reg), smartKeyAccountImpl, isHedera); // before every release: its address is in the env
        _deployRelayFeeRouter();
        if (deployRegulated) _deployComplianceRegistry();
        if (register) _configureChain(f, registrar);
        vm.serializeAddress("deploy", "token_factory", address(f));
        if (register && !configureOnly) {
            // the link closure of NormalToken's release (task 6; T66b §4.5: its body modules' link references): MtxPipelineLib,
            // which links HederaLib, and GovernanceLib (TradeLib's code is compiled into the module T)
            address[] memory libs = new address[](3);
            (libs[0], libs[1], libs[2]) = (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib));
            _libRows(libs);
            address none = _kindRelease(f, IOpenFactory.TokenKind.NORMAL, "NormalToken", type(NormalToken).creationCode, "",
                _env(f, address(reg), smartKeyAccountImpl, isHedera, new address[](0), libs));
            _gateInstance(f, none, f.envOf(IOpenFactory.TokenKind.NORMAL, 1)); // one instance's chainUid (§6.2)
            vm.serializeAddress("deploy", "implementation_normal", none);
            // The DEX release (CTR-DEX-24): clones come from `createDex`; DEX version 1.
            address[] memory dexLibs = new address[](2);
            (dexLibs[0], dexLibs[1]) = (address(GovernanceLib), address(TradeLib));
            // T66b §4.2: the DEX's admin module D first, pinned in the DEX env beside the libraries, named in `implArgs`
            address[] memory dexModules = new address[](1);
            dexModules[0] = _module("SCaaSDexAdmin.sol:SCaaSDexD", abi.encode(address(f), bytes("")), 0);
            bytes memory dexArgs = abi.encode(ImplArgs(dexModules));
            f.publishDexEnv(1, _withModules(_env(f, address(0), smartKeyAccountImpl, isHedera, new address[](0), dexLibs),
                dexModules));
            bytes memory dexCode = type(SCaaSDex).creationCode;
            _requireReleaseGas("SCaaSDex", address(f), abi.encodeCall(f.deployDexImplementation, (1, 1, dexCode, dexArgs)));
            address dexImpl = f.deployDexImplementation(1, 1, dexCode, dexArgs);
            _releaseRow("SCaaSDex", 2, 0, 1, dexImpl, keccak256(abi.encodePacked(dexCode, abi.encode(address(f), dexArgs))),
                keccak256(dexArgs));
            vm.serializeAddress("deploy", "dex_implementation", dexImpl);
        }
        if (deployWrapped && register && !configureOnly) _deployWrapped(f, address(reg), smartKeyAccountImpl, isHedera);
        if (deployRegulated && register && !configureOnly) _deployRegulated(f, address(reg), smartKeyAccountImpl, isHedera);
        if (deployPqChat && register && !configureOnly) _deployPqChat(f, address(reg));
        if (deployZether && !configureOnly) _deployZether(f, register, smartKeyAccountImpl, address(reg));
        vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    /// @notice Plan 3c T92 (UA-7 D22, topics spec §11): `PqChat` on the factory's generic path, with no factory code: its
    ///         body module `PqChatTopics` (CTR-TOK-30, 3C-D2) by CREATE2 with `DEPLOY_SALT` (`_module`, its own gate), the
    ///         class env 1 of `(3, 0)` (the registry; `params[0]` the chain's declared code-size limit, `CHAIN_CODE_LIMIT`;
    ///         the module pinned in `libs`), release 1 from the chain-neutral init code with `implArgs` naming the module,
    ///         the `(3, 0)` switch on, and one instance owned by no UA when the notice period lets it be created now (JSON
    ///         `pqchat_instance`; else created after the notice period by anyone, `createInstance`). JSON
    ///         `pqchat_implementation`, `pqchat_topics`. **UNAUDITED.**
    function _deployPqChat(OpenFactory f, address reg) internal {
        address topics = _module("PqChatTopics.sol:PqChatTopics", abi.encode(address(f)), 3, 0);
        f.publishClassEnv(3, 0, 1, _pqchatEnv(reg, topics));
        address impl = _pqchatRelease(f, abi.encode(topics));
        f.setClassKindEnabled(3, 0, true);
        vm.serializeAddress("deploy", "pqchat_topics", topics);
        vm.serializeAddress("deploy", "pqchat_implementation", impl);
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(3, 0, 1);
        if (f.classReleaseOf(id).usableFrom <= block.timestamp) {
            address inst =
                f.createInstance(id, keccak256("scaas.pqchat.instance.1"), abi.encodeCall(IPqChat.initialize, (bytes32(0))));
            vm.serializeAddress("deploy", "pqchat_instance", inst);
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

    /// @notice Release 1 of `(3, 0)` after its gate, `implArgs` naming the module; its row in the release list.
    function _pqchatRelease(OpenFactory f, bytes memory args) internal returns (address impl) {
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(3, 0, 1);
        bytes memory code = type(PqChat).creationCode;
        _requireReleaseGas("PqChat", address(f), abi.encodeCall(f.deployRelease,
            (id, 1, IPqChat.initialize.selector, type(IPqChat).interfaceId, code, args)));
        impl = f.deployRelease(id, 1, IPqChat.initialize.selector, type(IPqChat).interfaceId, code, args);
        _releaseRow("PqChat", 3, 0, 1, impl, keccak256(abi.encodePacked(code, abi.encode(id, address(f), args))),
            keccak256(args));
    }

    /// @notice GD-12 (CTR-GOV-19: every kind runs on the SCaaS testnet), in the form of `_deployZether`: env version 1 of
    ///         `WRAPPED` (the UA registry, the `SmartKeyAccount` implementation, Hedera, the link closure with `WrappedLib`, the
    ///         router), the release, version 1, refused first by `_requireReleaseGas`; the kind is on from the factory's start.
    ///         JSON `implementation_wrapped`. The release is above EIP-170: `CHAIN_CODE_LIMIT` must hold it.
    function _deployWrapped(OpenFactory f, address reg, address smartKeyAccountImpl, bool isHedera) internal {
        address[] memory libs = new address[](4);
        (libs[0], libs[1], libs[2], libs[3]) =
            (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(WrappedLib));
        address w = _kindRelease(f, IOpenFactory.TokenKind.WRAPPED, "WrappedToken", type(WrappedToken).creationCode, "",
            _env(f, reg, smartKeyAccountImpl, isHedera, new address[](0), libs));
        vm.serializeAddress("deploy", "implementation_wrapped", w);
    }

    /// @notice Regulated-kinds spec §6.1, in the form of `_deployWrapped`: env version 1 of `NORMAL_REGULATED` (8) and of
    ///         `WRAPPED_REGULATED` (9), each its base kind's link closure with `RegulatedLib` added (which links only
    ///         `GovernanceLib`, already in it), the releases, version 1, each refused first by `_requireReleaseGas`, then both
    ///         kinds enabled (plan T28). JSON `implementation_normal_regulated`, `implementation_wrapped_regulated`. Hedera
    ///         takes both (`IS_HEDERA` from the env). The confidential regulated kinds deploy with their stacks (10, 11 under
    ///         `DEPLOY_ZETHER`, `_deployZetherRegulated`; 12, 13 by `script/pqz/e2e.py`). Each release's `implArgs` is `abi.encode(REGISTRY_CODEHASH)`,
    ///         the canonical `ComplianceRegistry` runtime's code hash (spec §5, F-11; plan T29): a token naming a registry of
    ///         other code is refused at init. The registry itself: `_deployComplianceRegistry` (plan T33).
    function _deployRegulated(OpenFactory f, address reg, address smartKeyAccountImpl, bool isHedera) internal {
        address[] memory libs = new address[](4);
        (libs[0], libs[1], libs[2], libs[3]) =
            (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(RegulatedLib));
        bytes memory coreArgs = abi.encode(_registryCodehash());
        address n = _kindRelease(f, IOpenFactory.TokenKind.NORMAL_REGULATED, "NormalRegulatedToken",
            type(NormalRegulatedToken).creationCode, coreArgs, _env(f, reg, smartKeyAccountImpl, isHedera, new address[](0), libs));
        vm.serializeAddress("deploy", "implementation_normal_regulated", n);
        libs = new address[](5);
        (libs[0], libs[1], libs[2], libs[3], libs[4]) = (address(GovernanceLib), address(HederaLib),
            address(MtxPipelineLib), address(WrappedLib), address(RegulatedLib));
        address w = _kindRelease(f, IOpenFactory.TokenKind.WRAPPED_REGULATED, "WrappedRegulatedToken",
            type(WrappedRegulatedToken).creationCode, coreArgs, _env(f, reg, smartKeyAccountImpl, isHedera, new address[](0), libs));
        vm.serializeAddress("deploy", "implementation_wrapped_regulated", w);
        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);
        f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_REGULATED, true);
    }

    /// @notice Regulated-kinds spec §6.1 (F-21, plan T33), under `DEPLOY_REGULATED`: the canonical `ComplianceRegistry` by
    ///         CREATE2, its admin `COMPLIANCE_ADMIN` (CTR-AS-07: a contract; none or an EOA is refused by the registry's own
    ///         constructor, `AdminNotContract`), its runtime the code every regulated release pins (`REGISTRY_CODEHASH`,
    ///         F-11). JSON `compliance_registry`, `compliance_registry_codehash`. Not a release: no factory, no `chainUid()`;
    ///         the code pin is its gate. The `ELIGIBLE_CONTRACT` rows of a DEX venue (`createDex`, after this deploy) and of
    ///         its `puller()` are the admin's own `attest` call: this script holds no key of the admin.
    function _deployComplianceRegistry() internal {
        ComplianceRegistry r = new ComplianceRegistry{salt: salt}(complianceAdmin);
        require(address(r).codehash == _registryCodehash(), "ComplianceRegistry: code differs from REGISTRY_CODEHASH (F-11)");
        vm.serializeAddress("deploy", "compliance_registry", address(r));
        vm.serializeBytes32("deploy", "compliance_registry_codehash", address(r).codehash);
    }

    /// @notice The canonical `ComplianceRegistry` runtime's code hash, every regulated release's `implArgs` (spec §5, F-11).
    function _registryCodehash() internal pure returns (bytes32) {
        return keccak256(type(ComplianceRegistry).runtimeCode);
    }

    /// @notice `RelayFeeRouter` (CTR-MTX-27) by CREATE2, the same address on every chain (no constructor argument, no
    ///         `chainUid()`: it is stateless); its executor is its CREATE at nonce 1. JSON `relay_fee_router`,
    ///         `relay_fee_executor`.
    function _deployRelayFeeRouter() internal {
        RelayFeeRouter rf = new RelayFeeRouter{salt: salt}();
        address ex = rf.EXECUTOR();
        require(ex.code.length != 0 && RelayFeeExecutor(ex).ROUTER() == address(rf), "RelayFeeRouter executor");
        vm.serializeAddress("deploy", "relay_fee_router", address(rf));
        vm.serializeAddress("deploy", "relay_fee_executor", ex);
    }

    /// @notice The chain's `GovernanceRouter` (CTR-GOV-15 Change, owner 2026-11-04; plan T11) by CREATE2: no owner, no
    ///         state, `chain_uid` and the UA registry in its constructor, so one predictable address per chain. Deployed
    ///         before the releases, whose `Env.govRouter` names it. JSON `governance_router`. **UNAUDITED.**
    function _deployGovRouter(address reg, address smartKeyAccountImpl, bool isHedera) internal {
        GovernanceRouter r = new GovernanceRouter{salt: salt}(uid, reg, smartKeyAccountImpl, isHedera);
        _gate(address(r));
        govRouter = address(r);
        vm.serializeAddress("deploy", "governance_router", govRouter);
    }

    /// @notice The factory's release of `kind`, version 1 on env 1, with its `implArgs` (T66b: `kindImplArgs`), after its gate
    ///         (`_requireReleaseGas`).
    function _release(OpenFactory f, IOpenFactory.TokenKind kind, string memory name, bytes memory code,
        bytes memory implArgs) internal returns (address)
    {
        _requireReleaseGas(name, address(f), abi.encodeCall(f.deployImplementation, (kind, 1, 1, code, implArgs)));
        address at = f.deployImplementation(kind, 1, 1, code, implArgs);
        _releaseRow(name, 1, uint8(kind), 1, at, keccak256(abi.encodePacked(code, abi.encode(address(f), implArgs))),
            keccak256(implArgs));
        return at;
    }

    /// @notice T66b §4.5: `kind`'s body modules (`_modules`, with the kind's own constructor arguments `coreArgs`: "" on 0-5,
    ///         `abi.encode(REGISTRY_CODEHASH)` on 8-13), env version 1 of `kind` = `e` with the modules pinned beside its
    ///         libraries, then the release, version 1, its `implArgs` naming the modules (`kindImplArgs`).
    function _kindRelease(OpenFactory f, IOpenFactory.TokenKind kind, string memory name, bytes memory code,
        bytes memory coreArgs, IFactoryToken.Env memory e) internal returns (address)
    {
        string[] memory n = kindModuleNames(uint8(kind));
        address[] memory ms = new address[](n.length);
        for (uint256 i; i < n.length; ++i) ms[i] = _module(n[i], abi.encode(address(f), coreArgs), uint8(kind));
        f.publishEnv(kind, 1, _withModules(e, ms));
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
    function _withModules(IFactoryToken.Env memory e, address[] memory ms) internal view returns (IFactoryToken.Env memory) {
        uint256 k = e.libs.length;
        address[] memory l = new address[](k + ms.length);
        bytes32[] memory h = new bytes32[](l.length);
        for (uint256 i; i < k; ++i) (l[i], h[i]) = (e.libs[i], e.libCodeHashes[i]);
        for (uint256 i; i < ms.length; ++i) (l[k + i], h[k + i]) = (ms[i], ms[i].codehash);
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
        f.configureChain(uid, noticePeriod, govRouter, ref, ref == 0 ? bytes32(0) : blockhash(ref));
        _gate(address(f));
        _releaseRow("OpenFactory", 0, 0, 0, address(f), keccak256(abi.encodePacked(type(OpenFactory).creationCode,
            abi.encode(registrar))), keccak256(abi.encode(registrar)));
        _releaseRow("registrar", 0, 0, 0, registrar, bytes32(0), bytes32(0));
        if (chainSiblings > 1 && !vm.envOr("SIBLINGS_CONFIGURED", false)) {
            configureOnly = true;
            console.log("chain id shared by siblings (chain-uids.json): configure every one, then SIBLINGS_CONFIGURED=true");
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
        bytes memory env = ChainEnvCode.encode(IFactoryToken.ChainEnv(f.chainUid(), e.registry, f.govRouter(),
            e.smartKeyAccountImpl, e.hedera, e.deps, e.params));
        address probe = address(uint160(uint256(keccak256(abi.encode("scaas.deploy.instance-probe", implementation)))));
        vm.etch(probe, abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3", env));
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
    function _releaseRow(string memory name, uint16 cls, uint16 kind, uint64 version, address at, bytes32 initHash,
        bytes32 argsHash) internal
    {
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
        string memory file = vm.readFile(releasesPath);
        string memory p = string.concat(".", name);
        if (!vm.keyExistsJson(file, p)) {
            console.log(string.concat("release list: ", name, " not listed (a release the first chain has not)"));
            return;
        }
        require(vm.parseJsonAddress(file, string.concat(p, ".address")) == at,
            string.concat("release list: ", name, " at another address"));
        require(vm.parseJsonBytes32(file, string.concat(p, ".codeHash")) == at.codehash,
            string.concat("release list: ", name, " with another code hash"));
    }

    /// @notice Writes the release list (`RELEASES_WRITE`), after every row; call last in `run()`.
    function _writeReleases() internal {
        if (releasesWrite && releaseRows != 0) vm.writeJson(releasesJson, releasesPath);
    }

    /// @notice A release environment of this chain's factory (plan 5g-Z2): the registry, the `SmartKeyAccount`
    ///         implementation, Hedera, the deps, each library's current code hash. Chain-neutral releases (plan T71): the
    ///         factory fills its own `chain_uid` and router (`configureChain`), they are not in the env.
    function _env(OpenFactory, address reg, address ska, bool hedera, address[] memory deps, address[] memory libs)
        internal view returns (IFactoryToken.Env memory e)
    {
        bytes32[] memory h = new bytes32[](libs.length);
        for (uint256 i; i < libs.length; ++i) h[i] = libs[i].codehash;
        e = IFactoryToken.Env(reg, ska, hedera, deps, new bytes32[](0), libs, h);
    }

    /// @notice UA registry generation 1 (accounts.md §1.8, CTR-UA-22) on every chain, with per-chain enablement (§1.9):
    ///         `webauthn-p256`, `p256`, `ed25519`, `bip340`, `secp256k1`, `schnorr-bn254`, the four group kinds and `msig`
    ///         everywhere;
    ///         `schnorr-bls12381` and `bls12381-minsig` where `UAPrecompileProbe` passes EIP-2537; `bls-bn254-minsig` where
    ///         it passes the bn254 G2 check (no chain-id lock, owner ruling 2026-10-31); `zether-bls12381` with
    ///         EIP-2537 on every chain but Hedera (owner ruling 2026-10-31; `zether-bn254` is in `legacy/ua6/`, UA-6 U10); the PQ
    ///         signing kinds (P6c; unaudited, CTR-UA-23) on every chain where the kind's cap is at most 66 % of the chain's
    ///         verify budget (`_pqKindFits`; owner rulings 2026-10-31: no chain-id lock, 66 % instead of 50 %) — ML-DSA
    ///         in Solidity on the registry's cached expanded key (no chain has an ML-DSA precompile yet; P6g passes chain
    ///         7622's to the verifier's probe); `pqz-mlwe` nowhere (its verifier is P6g's). Caps: the gen-1 defaults measured in
    ///         `test/ua/UAGas.t.sol` and `test/ua/PqGas.t.sol` (accounts.md §1.15). A disabled kind gets no verifier
    ///         (never "registrable but unusable", CTR-UA-23). JSON `ua_registry`. **UNAUDITED.**
    /// @notice The PQ signing kinds' deploy rule (owner ruling 2026-10-31, CTR-UA-23): the kind's cap is at most 66 % of the
    ///         chain's verify budget, integer-exact as `cap * 100 <= budget * 66` (12 M: 7.92 M; Hedera 10.5 M: 6.93 M). The
    ///         registry's own `cap <= budget` check is separate and unchanged.
    function _pqKindFits(uint64 cap, uint64 budget) internal pure returns (bool) {
        return uint256(cap) * 100 <= uint256(budget) * 66;
    }

    function _deployUARegistry(address smartKeyAccountImpl, bool isHedera) internal returns (UARegistry reg) {
        (bool bls, bool bnG2) = _precompiles();
        uint64 budget = isHedera ? UA_VERIFY_BUDGET_HEDERA : UA_VERIFY_BUDGET;
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](21);
        uint256 n;
        k[n++] = UARegistry.KindConfig(UAKinds.WEBAUTHN_P256, address(new WebAuthnP256Verifier{salt: salt}()), 400_000);
        k[n++] = UARegistry.KindConfig(UAKinds.P256, address(new P256Verifier{salt: salt}()), 400_000);
        k[n++] = UARegistry.KindConfig(UAKinds.ED25519, address(new Ed25519Verifier{salt: salt}()), 210_000);
        k[n++] = UARegistry.KindConfig(UAKinds.BIP340, address(new Bip340Verifier{salt: salt}()), 50_000);
        k[n++] = UARegistry.KindConfig(UAKinds.SECP256K1, address(new Secp256k1Verifier{salt: salt}()), 50_000);
        k[n++] = UARegistry.KindConfig(UAKinds.SCHNORR_BN254, address(new SchnorrBn254Verifier{salt: salt}()), 50_000);
        if (bls) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.SCHNORR_BLS12381, address(new SchnorrBls12381Verifier{salt: salt}()), 70_000
            );
            k[n++] = UARegistry.KindConfig(
                UAKinds.BLS12381_MINSIG, address(new BlsMinSigBls12381Verifier{salt: salt}()), 200_000
            );
        }
        if (bnG2) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.BLS_BN254_MINSIG, address(new BlsMinSigBn254Verifier{salt: salt}()), 345_000
            );
        }
        k[n++] = UARegistry.KindConfig(
            UAKinds.MUSIG2_SECP256K1, address(new Musig2Secp256k1Verifier{salt: salt}()), 50_000
        );
        k[n++] = UARegistry.KindConfig(UAKinds.FROST_SECP256K1, address(new UAFrostSecp256k1Verifier{salt: salt}()), 50_000);
        k[n++] = UARegistry.KindConfig(UAKinds.MUSIG2_BN254, address(new Musig2Bn254Verifier{salt: salt}()), 50_000);
        k[n++] = UARegistry.KindConfig(UAKinds.FROST_BN254, address(new FrostBn254Verifier{salt: salt}()), 50_000);
        if (bls && !isHedera) { // never on Hedera: no Zether token can exist there (`ZetherLayer`)
            k[n++] = UARegistry.KindConfig(
                UAKinds.ZETHER_BLS12381, address(new ZetherSchnorrBls12381Verifier{salt: salt}()), 70_000
            );
        }
        // the PQ signing kinds (CTR-UA-23): wherever the kind's cap is at most 66 % of the chain's verify budget
        if (_pqKindFits(CAP_MLDSA44, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.MLDSA44, address(new UAMldsaVerifier{salt: salt}(UAKinds.MLDSA44, address(0), "", "")), CAP_MLDSA44
            );
        }
        if (_pqKindFits(CAP_MLDSA65, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.MLDSA65, address(new UAMldsaVerifier{salt: salt}(UAKinds.MLDSA65, address(0), "", "")), CAP_MLDSA65
            );
        }
        if (_pqKindFits(CAP_FNDSA512, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.FNDSA512, address(new UAFndsaVerifier{salt: salt}(UAKinds.FNDSA512)), CAP_FNDSA512
            );
        }
        if (_pqKindFits(CAP_SLHDSA128S, budget)) {
            k[n++] = UARegistry.KindConfig(UAKinds.SLHDSA128S, address(new UASlhdsaVerifier{salt: salt}()), CAP_SLHDSA128S);
        }
        if (_pqKindFits(CAP_FNDSA1024, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.FNDSA1024, address(new UAFndsaVerifier{salt: salt}(UAKinds.FNDSA1024)), CAP_FNDSA1024
            );
        }
        (address p87, bytes memory v87, bytes memory i87) = _mldsa87Precompile();
        if (p87 != address(0) && _pqKindFits(CAP_MLDSA87, budget)) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.MLDSA87, address(new UAMldsaVerifier{salt: salt}(UAKinds.MLDSA87, p87, v87, i87)), CAP_MLDSA87
            );
        }
        assembly ("memory-safe") {
            mstore(k, n)
        }
        // `UARegistryCoreLib` and `UARegistryAuxLib` (T66b 3.1b) are linked like every library: forge deploys each by CREATE2
        // before the script's first transaction (`create2_library_salt`), so their addresses, and through the code that embeds
        // them the registry's, depend on the sources only. Each one's own transaction is a release like the registry's: the
        // same gate.
        _requireRegistryGas(isHedera, budget, smartKeyAccountImpl, k);
        reg = new UARegistry{salt: salt}(uid, address(0), isHedera, budget, smartKeyAccountImpl, true, k);
        _checkGen1Kinds(reg, bls, isHedera);
        _gate(address(reg));
        vm.serializeAddress("deploy", "ua_registry", address(reg));
        vm.serializeAddress("deploy", "ua_registry_core_lib", address(UARegistryCoreLib));
        vm.serializeAddress("deploy", "ua_registry_aux_lib", address(UARegistryAuxLib));
    }

    /// @notice The gates of the registry's release and of its two libraries', each its own transaction (CREATE2 of the
    ///         registry's init code with these arguments; each library's creation code).
    function _requireRegistryGas(bool isHedera, uint64 budget, address ska, UARegistry.KindConfig[] memory k) internal {
        _requireReleaseGas("UARegistry", address(0),
            abi.encodePacked(type(UARegistry).creationCode, abi.encode(uid, address(0), isHedera, budget, ska, true, k)));
        _requireReleaseGas("UARegistryCoreLib", address(0), vm.getCode("UARegistryCoreLib.sol:UARegistryCoreLib"));
        _requireReleaseGas("UARegistryAuxLib", address(0), vm.getCode("UARegistryAuxLib.sol:UARegistryAuxLib"));
    }

    /// @notice The gen-1 kind gate (U8S-D9, owner ruling 2026-10-31, option (a)): every gen-1 deploy carries every kind the
    ///         chain can run, so when the probe passes EIP-2537 (`bls`) the gen-1 registry `reg` must enable
    ///         `schnorr-bls12381` 0x0105, `bls12381-minsig` 0x0106 and, except on Hedera (no Zether token can exist there,
    ///         `ZetherLayer`), `zether-bls12381` 0x0141; otherwise the deploy reverts before anything is sent. No
    ///         `UARegistry` change. A probe that fails (the RPC refuses the call) requires nothing (`_precompiles`).
    function _checkGen1Kinds(IUARegistry reg, bool bls, bool isHedera) internal view {
        require(reg.generation() == 1, "gen-1 registry: not generation 1");
        if (!bls) return;
        uint16[3] memory need = [UAKinds.SCHNORR_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.ZETHER_BLS12381];
        for (uint256 i; i < (isHedera ? 2 : 3); ++i) {
            require(reg.kindEnabled(need[i]), string.concat(
                "gen-1 registry: EIP-2537 kind ", vm.toString(abi.encodePacked(need[i])), " the probe passes is missing"
            ));
        }
    }

    /// @notice CTR-UA-39: the first candidate (`0x14`, then the SCaaS testnet's address) that answers the `mldsa87` probe of
    ///         `pq_kat.json` exactly (valid ⇒ the word 1, flipped ⇒ 0), with the probe inputs the verifier checks again; else 0.
    function _mldsa87Precompile() internal view returns (address p, bytes memory valid, bytes memory invalid) {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        valid = vm.parseJsonBytes(kat, ".kinds.mldsa87.eip8355_probe_valid");
        invalid = vm.parseJsonBytes(kat, ".kinds.mldsa87.eip8355_probe_invalid");
        if (PqUA.probe(MLDSA87_EIP8355, valid, invalid)) p = MLDSA87_EIP8355;
        else if (PqUA.probe(MLDSA87_SCAAS_TESTNET, valid, invalid)) p = MLDSA87_SCAAS_TESTNET;
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
        (l[0], l[1], l[2], l[3]) = (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(ZetherLib));
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
        ZetherStatements stm = new ZetherStatements{salt: salt}();
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
            f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER, true);
            f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER, true);
            _deployZetherRegulated(f, reg, smartKeyAccountImpl, deps);
        }
        vm.serializeAddress("deploy", "zether_disclosure", dis);
        vm.serializeAddress("deploy", "zether_registry", reg); // = ua_registry
        vm.serializeAddress("deploy", "zether_statements", address(stm));
    }

    /// @notice `_deployZether`'s two releases (`NORMAL_ZETHER`, `WRAPPED_ZETHER`) on `deps`, each with its body modules.
    function _zetherReleases(OpenFactory f, address reg, address smartKeyAccountImpl, address[] memory deps) internal {
        address none = _kindRelease(f, IOpenFactory.TokenKind.NORMAL_ZETHER, "NormalZetherToken",
            type(NormalZetherToken).creationCode, "", _env(f, reg, smartKeyAccountImpl, false, deps, _zetherLibs(false)));
        address und = _kindRelease(f, IOpenFactory.TokenKind.WRAPPED_ZETHER, "WrappedZetherToken",
            type(WrappedZetherToken).creationCode, "", _env(f, reg, smartKeyAccountImpl, false, deps, _zetherLibs(true)));
        vm.serializeAddress("deploy", "implementation_normal_zether_bls12381", none);
        vm.serializeAddress("deploy", "implementation_wrapped_zether_bls12381", und);
    }

    /// @notice Regulated-kinds spec §6.1 (plan T30): with the Zether stack, env version 1 of `NORMAL_ZETHER_REGULATED` (10)
    ///         and `WRAPPED_ZETHER_REGULATED` (11), each its base kind's `deps` and link closure with `RegulatedLib` added,
    ///         the releases, version 1, each refused first by `_requireReleaseGas`, `implArgs` the canonical
    ///         `ComplianceRegistry` runtime's code hash (F-11), then both kinds enabled. JSON
    ///         `implementation_{normal,wrapped}_zether_regulated_bls12381`. Never on Hedera (`ZetherLayer`).
    function _deployZetherRegulated(OpenFactory f, address reg, address smartKeyAccountImpl, address[] memory deps) internal {
        bytes memory coreArgs = abi.encode(_registryCodehash());
        address n = _kindRelease(f, IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, "NormalZetherRegulatedToken",
            type(NormalZetherRegulatedToken).creationCode, coreArgs,
            _env(f, reg, smartKeyAccountImpl, false, deps, _withRegulatedLib(_zetherLibs(false))));
        address w = _kindRelease(f, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, "WrappedZetherRegulatedToken",
            type(WrappedZetherRegulatedToken).creationCode, coreArgs,
            _env(f, reg, smartKeyAccountImpl, false, deps, _withRegulatedLib(_zetherLibs(true))));
        vm.serializeAddress("deploy", "implementation_normal_zether_regulated_bls12381", n);
        vm.serializeAddress("deploy", "implementation_wrapped_zether_regulated_bls12381", w);
        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, true);
        f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, true);
    }

    /// @notice `libs` and `RegulatedLib` last: a regulated kind's closure (it links only `GovernanceLib`, already in `libs`).
    function _withRegulatedLib(address[] memory libs) internal pure returns (address[] memory l) {
        l = new address[](libs.length + 1);
        for (uint256 i; i < libs.length; ++i) l[i] = libs[i];
        l[libs.length] = address(RegulatedLib);
    }

    /// @notice Two kind-`NORMAL` demo tokens from `f` (dev chains; only when the deployer is the registrar): 6 decimals,
    ///         `PAYABLE`, `supply` each to the deployer, half of each to `holder`; JSON `demo_token`, `demo_token_2`.
    function _demoTokens(OpenFactory f, uint256 supply, address deployer, address holder)
        internal returns (address demo, address demo2)
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

    function _demoToken(OpenFactory f, string memory name, string memory symbol, uint256 supply, address holder,
        bytes32 tokenSalt) private returns (address)
    {
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
