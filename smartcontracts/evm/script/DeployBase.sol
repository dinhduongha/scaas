// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {AdminLib} from "../src/metatx/AdminLib.sol";
import {WrappedLib} from "../src/metatx/WrappedLib.sol";
import {MtxPipelineLib} from "../src/metatx/MtxPipelineLib.sol";
import {HederaLib} from "../src/hedera/HederaLib.sol";
import {TradeLib} from "../src/trade/TradeLib.sol";
import {ZetherLib} from "../src/zether/ZetherLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NormalToken} from "../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
import {UARegistry} from "../src/ua/UARegistry.sol";
import {MtxRelayFee, MtxRelayExecutor} from "../src/metatx/MtxRelayFee.sol";
import {UAKinds} from "../src/ua/UAKinds.sol";
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
import {ZetherSafety} from "../src/zether/ZetherSafety.sol";
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
    /// @notice `DEPLOY_ZETHER` env (default false): also deploy the Zether stack (`_deployZether`, dev chains only).
    bool internal deployZether;
    /// @notice `OpenFactory.noticePeriod` (plan 5g-Z2; owner ruling 2026-10-20): `NOTICE_PERIOD` env. Safe by default:
    ///         every chain not in `_isTestChain` is a mainnet (22776, Hedera 295, Ethereum, BSC, an unknown chain), with
    ///         default and floor 3 days; 7622 defaults to 10 minutes, the other test / dev chains to 0. At most 30 days
    ///         (`MAX_NOTICE_PERIOD`, the factory's).
    uint64 internal noticePeriod;

    /// @notice `UA_VERIFY_BUDGET = min(12 M, ⌊0.7 × the chain's per-transaction gas cap⌋)` (CTR-UA-23): EIP-7825
    ///         chains (16,777,216) 12 M, Hedera (15 M) 10.5 M.
    uint64 internal constant UA_VERIFY_BUDGET = 12_000_000;
    uint64 internal constant UA_VERIFY_BUDGET_HEDERA = 10_500_000;
    /// @notice Gen-1 caps of the PQ kinds without an ML-DSA precompile (P6c, `test/ua/PqGas.t.sol`, accounts.md §1.15):
    ///         ML-DSA on the registry's cached expanded key (measured valid 4.11 M / 5.80 M; `verifyCached`'s self-call loses
    ///         1/64, so the least working caps are 4,174,074 / 5,893,303 warm, ~5 k more cold, and the caps leave ~73 k (~1.7 %) /
    ///         ~52 k (~0.9 %) over the cold minimum, pinned by `PqGas.t.sol`; ML-DSA-65's
    ///         cap keeps the treasury {mldsa65 ×3} t=2 over the budget), FN-DSA (2.27–2.35 M measured) + ~6 %,
    ///         SLH-DSA above its 1.32 M worst case. Each ≤ 50 % of the 12 M budget.
    uint64 internal constant CAP_MLDSA44 = 4_250_000;
    uint64 internal constant CAP_MLDSA65 = 5_950_000;
    uint64 internal constant CAP_FNDSA512 = 2_500_000;
    uint64 internal constant CAP_SLHDSA128S = 1_400_000;

    /// @notice C5-1, NET-EVM-06. A release is one CREATE2 of the whole implementation in the registrar's transaction.
    ///         Under EIP-8037 the code deposit is state gas, `STATE_GAS_PER_BYTE` per byte of runtime, on top of the
    ///         regular gas, which EIP-7825 caps at `TX_REGULAR_GAS_CAP` (2^24): the transaction needs
    ///         `runtime x 1,530 + 2^24` and may not exceed the block gas limit. Runtime sizes are `size-baseline.json`'s
    ///         (the contracts over the EIP-170 limit; any other is priced at `EIP170_LIMIT`).
    ///         `NormalToken` 38,195 B = 75.2 M, `WrappedZetherToken` 60,282 B = 109.0 M,
    ///         `WrappedPqzToken` 61,137 B = 110.3 M (the figures move with the baseline).
    uint256 internal constant STATE_GAS_PER_BYTE = 1530;
    uint256 internal constant TX_REGULAR_GAS_CAP = 1 << 24;
    uint256 internal constant EIP170_LIMIT = 24_576;

    /// @notice The block gas limit the release of contract `name` needs.
    function _releaseGasNeed(string memory name) internal view returns (uint256) {
        string memory key = string.concat(".", name);
        string memory base = vm.readFile("./size-baseline.json");
        uint256 runtime = vm.keyExistsJson(base, key) ? vm.parseJsonUint(base, key) : EIP170_LIMIT;
        return runtime * STATE_GAS_PER_BYTE + TX_REGULAR_GAS_CAP;
    }

    function _checkReleaseGas(string memory name, uint256 limit) internal view {
        uint256 need = _releaseGasNeed(name);
        if (limit < need) {
            revert(string.concat("block gas limit ", vm.toString(limit), " < ", vm.toString(need),
                " needed to deploy the ", name, " release (NET-EVM-06)"));
        }
    }

    /// @notice Refuses before anything is sent when the chain's actual `block.gaslimit` cannot hold the release.
    function _requireReleaseGas(string memory name) internal view { _checkReleaseGas(name, block.gaslimit); }

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
        deployZether = vm.envOr("DEPLOY_ZETHER", false);
        noticePeriod = _checkedNotice(block.chainid, vm.envOr("NOTICE_PERIOD", _defaultNotice(block.chainid)));
        uid = _chainUid();
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

    /// @notice The token factory (`noticePeriod`) and the UA registry (`_deployUARegistry`) by CREATE2; when the deployer
    ///         is the registrar (plan 5g-Z2: only the factory deploys releases), env version 1 of `NORMAL` and of the DEX
    ///         (`_env`: the factory, `chain_uid`, the registry, the `SmartKeyAccount` implementation, Hedera, the linked
    ///         libraries with their code hashes), then the `NORMAL` release (on that registry: the UA ledger, CTR-UA-18)
    ///         and the `SCaaSDex` release, each version 1; otherwise the registrar publishes and deploys them later from
    ///         the same init code. Writes `token_factory`, `implementation_normal`, `dex_implementation`, `ua_registry`,
    ///         `mtx_relay_fee`, `mtx_relay_executor`, `chain_uid` into the JSON object `"deploy"`; with `DEPLOY_ZETHER` also the Zether stack (`_deployZether`,
    ///         dev chains only). NORMAL and `WRAPPED` both exceed EIP-170 (the UA ledger): deploy with
    ///         `--code-size-limit 65536` (deploy.sh); `WRAPPED` is still not deployed here (owner: wait for Glamsterdam).
    function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
        internal returns (OpenFactory f)
    {
        if (deployZether) require(ZetherSafety.isDevChain(), "DEPLOY_ZETHER: dev chains only (CTR-ZTH-02)");
        f = new OpenFactory{salt: salt}(registrar, uid, noticePeriod);
        UARegistry reg = _deployUARegistry(smartKeyAccountImpl, isHedera);
        _deployRelayFee();
        _gate(address(f));
        vm.serializeAddress("deploy", "token_factory", address(f));
        if (register) {
            // the link closure of NormalToken (task 6): MtxPipelineLib, which links HederaLib
            address[] memory libs = new address[](4);
            (libs[0], libs[1], libs[2], libs[3]) =
                (address(AdminLib), address(HederaLib), address(TradeLib), address(MtxPipelineLib));
            f.publishEnv(IOpenFactory.TokenKind.NORMAL, 1,
                _env(f, address(reg), smartKeyAccountImpl, isHedera, new address[](0), libs));
            _requireReleaseGas("NormalToken");
            address none = f.deployImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(NormalToken).creationCode, "");
            _gate(none);
            vm.serializeAddress("deploy", "implementation_normal", none);
            // The DEX release (CTR-DEX-24): clones come from `createDex`; DEX version 1.
            address[] memory dexLibs = new address[](1);
            dexLibs[0] = address(TradeLib);
            f.publishDexEnv(1, _env(f, address(0), smartKeyAccountImpl, isHedera, new address[](0), dexLibs));
            _requireReleaseGas("SCaaSDex");
            address dexImpl = f.deployDexImplementation(1, 1, type(SCaaSDex).creationCode, "");
            _gate(dexImpl);
            vm.serializeAddress("deploy", "dex_implementation", dexImpl);
        }
        if (deployZether) _deployZether(f, register, smartKeyAccountImpl, address(reg));
        vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    /// @notice `MtxRelayFee` (CTR-MTX-27) by CREATE2, the same address on every chain (no constructor argument, no
    ///         `chainUid()`: it is stateless); its executor is its CREATE at nonce 1. JSON `mtx_relay_fee`,
    ///         `mtx_relay_executor`.
    function _deployRelayFee() internal {
        MtxRelayFee rf = new MtxRelayFee{salt: salt}();
        address ex = rf.EXECUTOR();
        require(ex.code.length != 0 && MtxRelayExecutor(ex).ROUTER() == address(rf), "MtxRelayFee executor");
        vm.serializeAddress("deploy", "mtx_relay_fee", address(rf));
        vm.serializeAddress("deploy", "mtx_relay_executor", ex);
    }

    /// @notice A release environment of this chain's factory `f` (plan 5g-Z2), each library's current code hash.
    function _env(OpenFactory f, address reg, address ska, bool hedera, address[] memory deps, address[] memory libs)
        internal view returns (IFactoryToken.Env memory e)
    {
        bytes32[] memory h = new bytes32[](libs.length);
        for (uint256 i; i < libs.length; ++i) h[i] = libs[i].codehash;
        e = IFactoryToken.Env(address(f), uid, reg, ska, hedera, deps, libs, h);
    }

    /// @notice UA registry generation 1 (accounts.md §1.8, CTR-UA-22) on every chain, with per-chain enablement (§1.9):
    ///         `webauthn-p256`, `p256`, `ed25519`, `bip340`, `secp256k1`, `schnorr-bn254`, the four group kinds and `msig`
    ///         everywhere;
    ///         `schnorr-bls12381` and `bls12381-minsig` where `UAPrecompileProbe` passes EIP-2537; `bls-bn254-minsig` on
    ///         private chains (the dev chains and 7622) where it passes the bn254 G2 check; `zether-bls12381` with
    ///         EIP-2537 on the dev chains only (CTR-ZTH-02; `zether-bn254` is in `legacy/ua6/`, UA-6 U10); the PQ
    ///         signing kinds (P6c) on the private chains (the dev chains and 7622) only — unaudited, CTR-UA-23 — ML-DSA
    ///         in Solidity on the registry's cached expanded key (no chain has an ML-DSA precompile yet; P6g passes chain
    ///         7622's to the verifier's probe); `pqz-mlwe` nowhere (its verifier is P6g's). Caps: the gen-1 defaults measured in
    ///         `test/ua/UAGas.t.sol` and `test/ua/PqGas.t.sol` (accounts.md §1.15). A disabled kind gets no verifier
    ///         (never "registrable but unusable", CTR-UA-23). JSON `ua_registry`. **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
    function _deployUARegistry(address smartKeyAccountImpl, bool isHedera) internal returns (UARegistry reg) {
        (bool bls, bool bnG2) = _precompiles();
        bool dev = ZetherSafety.isDevChain();
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
        if (bnG2 && (dev || block.chainid == 7622)) {
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
        if (dev && bls) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.ZETHER_BLS12381, address(new ZetherSchnorrBls12381Verifier{salt: salt}()), 70_000
            );
        }
        if (dev || block.chainid == 7622) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.MLDSA44, address(new UAMldsaVerifier{salt: salt}(UAKinds.MLDSA44, address(0), "", "")), CAP_MLDSA44
            );
            k[n++] = UARegistry.KindConfig(
                UAKinds.MLDSA65, address(new UAMldsaVerifier{salt: salt}(UAKinds.MLDSA65, address(0), "", "")), CAP_MLDSA65
            );
            k[n++] = UARegistry.KindConfig(UAKinds.FNDSA512, address(new UAFndsaVerifier{salt: salt}()), CAP_FNDSA512);
            k[n++] = UARegistry.KindConfig(UAKinds.SLHDSA128S, address(new UASlhdsaVerifier{salt: salt}()), CAP_SLHDSA128S);
        }
        assembly ("memory-safe") {
            mstore(k, n)
        }
        uint64 budget = isHedera ? UA_VERIFY_BUDGET_HEDERA : UA_VERIFY_BUDGET;
        reg = new UARegistry{salt: salt}(uid, address(0), isHedera, budget, smartKeyAccountImpl, true, k);
        _gate(address(reg));
        vm.serializeAddress("deploy", "ua_registry", address(reg));
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

    /// @notice The link closure of a Zether token (task 6): `WrappedLib` only in `WRAPPED_ZETHER`.
    function _zetherLibs(bool underlying) internal view returns (address[] memory l) {
        l = new address[](underlying ? 6 : 5);
        (l[0], l[1], l[2], l[3], l[4]) =
            (address(AdminLib), address(HederaLib), address(TradeLib), address(MtxPipelineLib), address(ZetherLib));
        if (underlying) l[5] = address(WrappedLib);
    }

    /// @notice Dev chains only (CTR-ZTH-02; elsewhere the verifiers refuse to deploy): `ZetherStatements`,
    ///         `ZetherDisclosure`, the BLS12-381 inner-product verifier (the generators, ~14 M gas) and the transfer and
    ///         burn verifiers on it (classical Zether is BLS12-381 only, CTR-ZTH-32; the bn254 steps are in
    ///         `legacy/ua6/`); when the deployer is the registrar, an env of `NORMAL_ZETHER` and `WRAPPED_ZETHER`
    ///         (version 1; `deps` = transfer, burn, inner-product verifier, disclosure, CTR-ZTH-20) and the two releases
    ///         on it, then the kinds enabled. JSON `zether_registry` (= `ua_registry`), `zether_statements`,
    ///         `zether_disclosure`, `zether_{inner_product_,,burn_}verifier_bls12381`,
    ///         `implementation_{normal,wrapped}_zether_bls12381`. **UNAUDITED — NOT FOR PRODUCTION FUNDS.** The
    ///         implementations exceed EIP-170 and the BLS inner-product verifier takes ~14 M gas: anvil
    ///         `--code-size-limit 65536`, forge script `--code-size-limit 65536 --gas-estimate-multiplier 105` (deploy.sh
    ///         passes both; docs/networks/evm.md).
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
            f.publishEnv(IOpenFactory.TokenKind.NORMAL_ZETHER, 1,
                _env(f, reg, smartKeyAccountImpl, false, deps, _zetherLibs(false)));
            f.publishEnv(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1,
                _env(f, reg, smartKeyAccountImpl, false, deps, _zetherLibs(true)));
            _requireReleaseGas("NormalZetherToken");
            _requireReleaseGas("WrappedZetherToken");
            address none = f.deployImplementation(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, 1,
                type(NormalZetherToken).creationCode, "");
            address und = f.deployImplementation(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, 1,
                type(WrappedZetherToken).creationCode, "");
            _gate(none);
            _gate(und);
            vm.serializeAddress("deploy", "implementation_normal_zether_bls12381", none);
            vm.serializeAddress("deploy", "implementation_wrapped_zether_bls12381", und);
            f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER, true);
            f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER, true);
        }
        vm.serializeAddress("deploy", "zether_disclosure", dis);
        vm.serializeAddress("deploy", "zether_registry", reg); // = ua_registry
        vm.serializeAddress("deploy", "zether_statements", address(stm));
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
        c.features = 1 << AdminLib.PAYABLE;
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
