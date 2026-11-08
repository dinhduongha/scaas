// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";

/// @notice Chain-neutral releases for tests (chain-spec §2, §3; plan T71, T72): a factory configured for one chain, and
///         clones with an appended `ChainEnv` for the tests that play the factory themselves (the test is `FACTORY`).
library EnvKit {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function env(bytes32 uid, address registry, address ska, bool hedera)
        internal pure returns (IFactoryToken.ChainEnv memory e)
    {
        (e.chainUid, e.registry, e.smartKeyAccountImpl, e.hedera) = (uid, registry, ska, hedera);
    }

    function env(bytes32 uid, address registry, address ska, bool hedera, address govRouter)
        internal pure returns (IFactoryToken.ChainEnv memory e)
    {
        e = env(uid, registry, ska, hedera);
        e.govRouter = govRouter;
    }

    /// @dev The runtime code of a clone of `impl` with `e` appended (for `vm.etch` at a vector's address).
    function runtime(address impl, IFactoryToken.ChainEnv memory e) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3", ChainEnvCode.encode(e));
    }

    /// @dev A clone of `impl` with `e` appended, created by the caller (which plays the factory).
    function clone(address impl, IFactoryToken.ChainEnv memory e) internal returns (address c) {
        bytes memory code = ChainEnvCode.initCode(impl, ChainEnvCode.encode(e));
        assembly ("memory-safe") {
            c := create(0, add(code, 0x20), mload(code))
        }
        require(c != address(0) && c.code.length != 0, "EnvKit: clone not created");
    }

    function factory(address registrar, bytes32 uid, uint64 notice) internal returns (OpenFactory f) {
        return factory(registrar, uid, notice, address(0));
    }

    /// @dev `new OpenFactory(registrar)` and its `configureChain(uid, notice, router)`, on a chain whose genesis hash
    ///      is `uid` (`BLOCKHASH(0)`, provable while `block.number <= 256`). Pranks the registrar once: no `startPrank`.
    function factory(address registrar, bytes32 uid, uint64 notice, address router) internal returns (OpenFactory f) {
        f = new OpenFactory(registrar);
        configure(f, uid, notice, router);
    }

    function configure(OpenFactory f, bytes32 uid, uint64 notice, address router) internal {
        genesis(uid);
        vm.prank(f.registrar());
        f.configureChain(uid, notice, router, 0, bytes32(0));
    }

    /// @dev EIP-2935's history contract (forge runs it at Amsterdam): its ring buffer keeps block `n` at slot `n % 8191`.
    address internal constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;

    /// @dev This chain's genesis hash `uid`, as `BLOCKHASH(0)` answers it (within 256 blocks) and as EIP-2935 does.
    function genesis(bytes32 uid) internal {
        if (block.number >= 1 && block.number <= 256) vm.setBlockhash(0, uid);
        if (HISTORY.code.length != 0) vm.store(HISTORY, bytes32(0), uid);
    }
}
