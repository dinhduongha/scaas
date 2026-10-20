// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {AdminLib} from "../src/metatx/AdminLib.sol";
import {UnderlyingLib} from "../src/metatx/UnderlyingLib.sol";
import {HederaLib} from "../src/hedera/HederaLib.sol";
import {TradeLib} from "../src/trade/TradeLib.sol";
import {ZetherLib} from "../src/zether/ZetherLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
import {UARegistry} from "../src/ua/UARegistry.sol";
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
    ZetherSchnorrBn254Verifier,
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
    ZetherInnerProductVerifierBn254,
    ZetherTransferVerifierBn254,
    ZetherBurnVerifierBn254,
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../src/zether/ZetherVerifier.sol";
import {IZetherInnerProductVerifier} from "../src/zether/IZetherVerifier.sol";
import {NoUnderlyingZetherToken} from "../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../src/zether/UnderlyingZetherToken.sol";

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
    /// @notice `OpenFactory.noticePeriod` (plan 5g-Z2): `NOTICE_PERIOD` env, default 10 minutes on 7622, 3 days on 22776,
    ///         0 elsewhere (the dev chains, the e2e).
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

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
        deployZether = vm.envOr("DEPLOY_ZETHER", false);
        noticePeriod = uint64(vm.envOr("NOTICE_PERIOD",
            block.chainid == 7622 ? uint256(10 minutes) : block.chainid == 22776 ? uint256(3 days) : 0));
        uid = _chainUid();
        require(CREATE2_FACTORY.code.length != 0,
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)");
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
    ///         is the registrar (plan 5g-Z2: only the factory deploys releases), env version 1 of `NONE` and of the DEX
    ///         (`_env`: the factory, `chain_uid`, the registry, the `SmartKeyAccount` implementation, Hedera, the linked
    ///         libraries with their code hashes), then the `NONE` release (on that registry: the UA ledger, CTR-UA-18)
    ///         and the `SCaaSDex` release, each version 1; otherwise the registrar publishes and deploys them later from
    ///         the same init code. Writes `token_factory`, `implementation_none`, `dex_implementation`, `ua_registry`,
    ///         `chain_uid` into the JSON object `"deploy"`; with `DEPLOY_ZETHER` also the Zether stack (`_deployZether`,
    ///         dev chains only). NONE and `UNDERLYING` both exceed EIP-170 (the UA ledger): deploy with
    ///         `--code-size-limit 65536` (deploy.sh); `UNDERLYING` is still not deployed here (owner: wait for Glamsterdam).
    function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
        internal returns (OpenFactory f)
    {
        if (deployZether) require(ZetherSafety.isDevChain(), "DEPLOY_ZETHER: dev chains only (CTR-ZTH-02)");
        f = new OpenFactory{salt: salt}(registrar, uid, noticePeriod);
        UARegistry reg = _deployUARegistry(smartKeyAccountImpl, isHedera);
        _gate(address(f));
        vm.serializeAddress("deploy", "token_factory", address(f));
        if (register) {
            address[] memory libs = new address[](3);
            (libs[0], libs[1], libs[2]) = (address(AdminLib), address(HederaLib), address(TradeLib));
            f.publishEnv(IOpenFactory.TokenKind.NONE, 1,
                _env(f, address(reg), smartKeyAccountImpl, isHedera, new address[](0), libs));
            address none = f.deployImplementation(IOpenFactory.TokenKind.NONE, 1, 1, type(NoUnderlyingToken).creationCode, "");
            _gate(none);
            vm.serializeAddress("deploy", "implementation_none", none);
            // The DEX release (CTR-DEX-24): clones come from `createDex`; DEX version 1.
            address[] memory dexLibs = new address[](1);
            dexLibs[0] = address(TradeLib);
            f.publishDexEnv(1, _env(f, address(0), smartKeyAccountImpl, isHedera, new address[](0), dexLibs));
            address dexImpl = f.deployDexImplementation(1, 1, type(SCaaSDex).creationCode, "");
            _gate(dexImpl);
            vm.serializeAddress("deploy", "dex_implementation", dexImpl);
        }
        if (deployZether) _deployZether(f, register, smartKeyAccountImpl, address(reg));
        vm.serializeBytes32("deploy", "chain_uid", uid);
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
    ///         private chains (the dev chains and 7622) where it passes the bn254 G2 check; `zether-bn254` (and
    ///         `zether-bls12381` with EIP-2537) on the dev chains only (CTR-ZTH-02); the PQ signing kinds (P6c) on the
    ///         private chains (the dev chains and 7622) only — unaudited, CTR-UA-23 — ML-DSA in Solidity on the
    ///         registry's cached expanded key (no chain has an ML-DSA precompile yet; P6g passes chain 7622's to the
    ///         verifier's probe); `pqz-mlwe` nowhere (its verifier is P6g's). Caps: the gen-1 defaults measured in
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
        if (dev) {
            k[n++] = UARegistry.KindConfig(
                UAKinds.ZETHER_BN254, address(new ZetherSchnorrBn254Verifier{salt: salt}()), 50_000
            );
            if (bls) {
                k[n++] = UARegistry.KindConfig(
                    UAKinds.ZETHER_BLS12381, address(new ZetherSchnorrBls12381Verifier{salt: salt}()), 70_000
                );
            }
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

    /// @notice Dev chains only (CTR-ZTH-02; elsewhere the verifiers refuse to deploy): `ZetherStatements`,
    ///         `ZetherDisclosure` and per curve the inner-product verifier (the generators, ~14 M gas on BLS12-381) and
    ///         the transfer and burn verifiers on it; when the deployer is the registrar, per curve an env of
    ///         `NONE_ZETHER` and `UNDERLYING_ZETHER` (version 1 bn254, 2 BLS12-381; `deps` = transfer, burn,
    ///         inner-product verifier, disclosure, CTR-ZTH-20) and the two releases on it (versions 1 and 2: the curve is
    ///         the release's attribute, `curve()`), then the kinds enabled. JSON `zether_registry` (= `ua_registry`),
    ///         `zether_statements`, `zether_disclosure`, `zether_{inner_product_,,burn_}verifier_<curve>`,
    ///         `implementation_{none,underlying}_zether_<curve>`. **UNAUDITED — NOT FOR PRODUCTION FUNDS.** The
    ///         implementations exceed EIP-170 and the BLS inner-product verifier takes ~14 M gas: anvil
    ///         `--code-size-limit 65536`, forge script `--code-size-limit 65536 --gas-estimate-multiplier 105` (deploy.sh
    ///         passes both; docs/networks/evm.md).
    function _deployZether(OpenFactory f, bool register, address smartKeyAccountImpl, address reg) internal {
        ZetherStatements stm = new ZetherStatements{salt: salt}();
        address dis = address(new ZetherDisclosure{salt: salt}());
        IZetherInnerProductVerifier[2] memory ip =
            [IZetherInnerProductVerifier(new ZetherInnerProductVerifierBn254{salt: salt}()),
                IZetherInnerProductVerifier(new ZetherInnerProductVerifierBls12381{salt: salt}())];
        address[2] memory tv = [address(new ZetherTransferVerifierBn254{salt: salt}(ip[0])),
            address(new ZetherTransferVerifierBls12381{salt: salt}(ip[1]))];
        address[2] memory bv = [address(new ZetherBurnVerifierBn254{salt: salt}(ip[0])),
            address(new ZetherBurnVerifierBls12381{salt: salt}(ip[1]))];
        string[2] memory n = ["bn254", "bls12381"];
        address[] memory libs = new address[](5);
        (libs[0], libs[1], libs[2], libs[3], libs[4]) =
            (address(AdminLib), address(HederaLib), address(TradeLib), address(UnderlyingLib), address(ZetherLib));
        for (uint16 c; c < 2; ++c) {
            vm.serializeAddress("deploy", string.concat("zether_inner_product_verifier_", n[c]), address(ip[c]));
            vm.serializeAddress("deploy", string.concat("zether_verifier_", n[c]), tv[c]);
            vm.serializeAddress("deploy", string.concat("zether_burn_verifier_", n[c]), bv[c]);
            if (!register) continue;
            address[] memory deps = new address[](4);
            (deps[0], deps[1], deps[2], deps[3]) = (tv[c], bv[c], address(ip[c]), dis);
            IFactoryToken.Env memory e = _env(f, reg, smartKeyAccountImpl, false, deps, libs);
            f.publishEnv(IOpenFactory.TokenKind.NONE_ZETHER, c + 1, e);
            f.publishEnv(IOpenFactory.TokenKind.UNDERLYING_ZETHER, c + 1, e);
            address none = f.deployImplementation(IOpenFactory.TokenKind.NONE_ZETHER, c + 1, c + 1,
                type(NoUnderlyingZetherToken).creationCode, "");
            address und = f.deployImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, c + 1, c + 1,
                type(UnderlyingZetherToken).creationCode, "");
            _gate(none);
            _gate(und);
            vm.serializeAddress("deploy", string.concat("implementation_none_zether_", n[c]), none);
            vm.serializeAddress("deploy", string.concat("implementation_underlying_zether_", n[c]), und);
        }
        if (register) {
            f.setKindEnabled(IOpenFactory.TokenKind.NONE_ZETHER, true);
            f.setKindEnabled(IOpenFactory.TokenKind.UNDERLYING_ZETHER, true);
        }
        vm.serializeAddress("deploy", "zether_disclosure", dis);
        vm.serializeAddress("deploy", "zether_registry", reg); // = ua_registry
        vm.serializeAddress("deploy", "zether_statements", address(stm));
    }

    /// @notice Two kind-`NONE` demo tokens from `f` (dev chains; only when the deployer is the registrar): 6 decimals,
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
        return f.createToken(IOpenFactory.TokenKind.NONE, 1, abi.encode(c), tokenSalt);
    }

    /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
    function _gate(address c) internal view {
        (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
        require(ok && ret.length == 32 && abi.decode(ret, (bytes32)) == uid, "chainUid() gate");
    }
}
