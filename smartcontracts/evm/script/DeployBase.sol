// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../src/dex/SCaaSDex.sol";

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

    /// @notice Call first in `run()`, before the broadcast.
    function _setup() internal {
        salt = vm.envOr("DEPLOY_SALT", keccak256("scaas.deploy.v1"));
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
    ///         `implementation_none`, `dex_implementation`, `chain_uid` into the JSON object `"deploy"`. `UNDERLYING` is
    ///         not deployed: over EIP-170 on real chains (owner: wait for Glamsterdam).
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
        if (register) f.registerDexImplementation(1, address(dexImpl));
        _gate(address(dexImpl));
        vm.serializeAddress("deploy", "dex_implementation", address(dexImpl));
        vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
    function _gate(address c) internal view {
        (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
        require(ok && ret.length == 32 && abi.decode(ret, (bytes32)) == uid, "chainUid() gate");
    }
}
