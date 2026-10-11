// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {AdminLib} from "../src/metatx/AdminLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
import {UniversalAccountRegistry} from "../src/registry/UniversalAccountRegistry.sol";
import {ZetherSafety} from "../src/zether/ZetherSafety.sol";
import {ZetherDisclosure} from "../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../src/zether/ZetherStatements.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../src/zether/ZetherVerifier.sol";
import {NoUnderlyingZetherToken} from "../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../src/zether/UnderlyingZetherToken.sol";

/// @title Shared deploy steps (CTR-GEN-05, CTR-GEN-06, NET-EVM-05): `chain_uid` from the RPC, the deterministic CREATE2
///        deployer, the token factory with its implementations, the `chainUid()` gate.
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

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
        deployZether = vm.envOr("DEPLOY_ZETHER", false);
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

    /// @notice The token factory, the `NONE` implementation and the `SCaaSDex` implementation by CREATE2, each
    ///         registered as version 1 when the deployer is the registrar; writes `token_factory`,
    ///         `implementation_none`, `dex_implementation`, `chain_uid` into the JSON object `"deploy"`; with `DEPLOY_ZETHER`
    ///         also the Zether stack (`_deployZether`, dev chains only). `UNDERLYING` is not deployed: over EIP-170 on real chains
    ///         (owner: wait for Glamsterdam).
    function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
        internal returns (OpenFactory f)
    {
        f = new OpenFactory{salt: salt}(registrar, uid);
        NoUnderlyingToken none = new NoUnderlyingToken{salt: salt}(address(f), smartKeyAccountImpl, uid, isHedera);
        if (register) f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(none));
        _gate(address(f));
        _gate(address(none));
        vm.serializeAddress("deploy", "token_factory", address(f));
        vm.serializeAddress("deploy", "implementation_none", address(none));
        // The DEX implementation (CTR-DEX-24): clones come from `createDex`; registered as DEX version 1.
        SCaaSDex dexImpl = new SCaaSDex{salt: salt}(address(f), uid, smartKeyAccountImpl);
        require(dexImpl.SMART_KEY_ACCOUNT_IMPL() == none.SMART_KEY_ACCOUNT_IMPL(), "DEX and token SmartKeyAccount implementation differ");
        if (register) f.registerDexImplementation(1, address(dexImpl));
        _gate(address(dexImpl));
        vm.serializeAddress("deploy", "dex_implementation", address(dexImpl));
        if (deployZether) {
            require(ZetherSafety.isDevChain(), "DEPLOY_ZETHER: dev chains only (CTR-ZTH-02)");
            _deployZether(f, register, smartKeyAccountImpl);
        }
        vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    /// @notice Dev chains only (CTR-ZTH-02; elsewhere the registry and the verifiers refuse to deploy): the account
    ///         registry, `ZetherDisclosure`, `ZetherStatements`, both verifiers, the two confidential implementations
    ///         registered as version 1 of `NONE_ZETHER` and `UNDERLYING_ZETHER`, and the factory's Zether gate switched on
    ///         when the deployer is the registrar. **UNAUDITED — NOT FOR PRODUCTION FUNDS.** The implementations exceed
    ///         EIP-170 and the BLS verifier takes ~14.1 M gas: anvil `--code-size-limit 65536`, forge script
    ///         `--code-size-limit 65536 --gas-estimate-multiplier 105` (deploy.sh adds both; docs/networks/evm.md).
    function _deployZether(OpenFactory f, bool register, address smartKeyAccountImpl) internal {
        UniversalAccountRegistry reg = new UniversalAccountRegistry{salt: salt}();
        ZetherDisclosure dis = new ZetherDisclosure{salt: salt}();
        ZetherStatements stm = new ZetherStatements{salt: salt}();
        ZetherVerifierBn254 bn = new ZetherVerifierBn254{salt: salt}();
        ZetherVerifierBls12381 bls = new ZetherVerifierBls12381{salt: salt}();
        NoUnderlyingZetherToken none =
            new NoUnderlyingZetherToken{salt: salt}(address(f), smartKeyAccountImpl, uid, address(reg), dis);
        UnderlyingZetherToken und =
            new UnderlyingZetherToken{salt: salt}(address(f), smartKeyAccountImpl, uid, address(reg), dis);
        if (register) {
            f.registerImplementation(IOpenFactory.TokenKind.NONE_ZETHER, 1, address(none));
            f.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(und));
            f.setZetherEnabled(true);
        }
        _gate(address(none));
        _gate(address(und));
        vm.serializeAddress("deploy", "zether_registry", address(reg));
        vm.serializeAddress("deploy", "zether_disclosure", address(dis));
        vm.serializeAddress("deploy", "zether_statements", address(stm));
        vm.serializeAddress("deploy", "zether_verifier_bn254", address(bn));
        vm.serializeAddress("deploy", "zether_verifier_bls12381", address(bls));
        vm.serializeAddress("deploy", "implementation_none_zether", address(none));
        vm.serializeAddress("deploy", "implementation_underlying_zether", address(und));
    }

    /// @notice Two kind-`NONE` demo tokens from `f` (dev chains; only when the deployer is the registrar): 6 decimals,
    ///         `PAYABLE`, `supply` each to the deployer, half of each to `holder`; JSON `demo_token`, `demo_token_2`.
    function _demoTokens(OpenFactory f, uint256 supply, address deployer, address holder)
        internal returns (address demo, address demo2)
    {
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
        return f.createToken(IOpenFactory.TokenKind.NONE, 1, c, tokenSalt);
    }

    /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
    function _gate(address c) internal view {
        (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
        require(ok && ret.length == 32 && abi.decode(ret, (bytes32)) == uid, "chainUid() gate");
    }
}
