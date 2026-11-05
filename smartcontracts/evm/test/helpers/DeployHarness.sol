// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {DeployBase} from "../../script/DeployBase.sol";
import {UAPrecompileProbe} from "../../script/UAPrecompileProbe.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// The deploy steps without the RPC parts (`_setup`, the `eth_call` probe): the salt, `chain_uid`, `DEPLOY_ZETHER` and
/// the profile set directly; the precompile probe runs in this EVM (or its verdict is forced).
contract DeployHarness is DeployBase {
    bool internal forced;
    bool internal forcedBls;
    bool internal forcedBnG2;
    uint256 internal gateLimit;
    uint256 internal codeLimit;
    uint8 internal gate; // 0 = `RELEASE_GAS_GATE` (env, or its default), 1 = testnet, 2 = public

    function force(bool bls12381, bool bn254G2) external {
        (forced, forcedBls, forcedBnG2) = (true, bls12381, bn254G2);
    }

    /// Stands in for `block.gaslimit` at the deploy gate (no cheatcode sets it); 0 = the chain's own.
    function limitBlockGas(uint256 limit) external { gateLimit = limit; }

    /// Stands in for `CHAIN_CODE_LIMIT` (the process env is shared by parallel tests); 0 = the env, or its default.
    function limitCode(uint256 limit) external { codeLimit = limit; }

    function chainCodeLimit() external view returns (uint256) { return _chainCodeLimit(); }

    /// Stands in for `RELEASE_GAS_GATE` (the process env is shared by parallel tests): 1 = `testnet`, 2 = `public`, 0 = the env.
    function setGate(uint8 g) external { gate = g; }

    function publicGate() external view returns (bool) { return _publicGate(); }

    /// The public gate's figures of release `name` (`[regular, state]`; 0 when the testnet gate ran).
    function measured(string calldata name) external view returns (uint256 regular, uint256 state) {
        return (releaseGas[name][0], releaseGas[name][1]);
    }

    function checkMeasured(string calldata name, uint256 regular, uint256 state, uint256 limit) external pure {
        _checkMeasuredGas(name, regular, state, limit);
    }

    /// `DEPLOY_WRAPPED` for the next `deploy`.
    function setWrapped(bool w) external { deployWrapped = w; }

    function deploy(bytes32 uid_, bool zether, address ska) external returns (OpenFactory f, string memory json) {
        return deploy(uid_, zether, ska, false);
    }

    function deploy(bytes32 uid_, bool zether, address ska, bool hedera)
        public
        returns (OpenFactory f, string memory json)
    {
        salt = keccak256("scaas.deploy.v1");
        uid = uid_;
        deployZether = zether;
        f = _deployTokenFactory(address(this), true, ska, hedera);
        json = vm.serializeBytes32("deploy", "chain_uid", uid);
    }

    function gasNeed(string calldata name) external view returns (uint256) { return _releaseGasNeed(name); }

    function checkGas(string calldata name, uint256 limit) external view { _checkReleaseGas(name, limit); }

    function requireGas(string calldata name) external view { _requireReleaseGas(name); }

    function noticeFor(uint256 chainId, uint256 notice) external pure returns (uint64) {
        return _checkedNotice(chainId, notice);
    }

    function pqKindFits(uint64 cap, uint64 budget) external pure returns (bool) { return _pqKindFits(cap, budget); }

    function checkGen1Kinds(IUARegistry reg, bool bls, bool hedera) external view { _checkGen1Kinds(reg, bls, hedera); }

    function defaultNotice(uint256 chainId) external pure returns (uint256) { return _defaultNotice(chainId); }

    function _blockGasLimit() internal view override returns (uint256) {
        return gateLimit == 0 ? super._blockGasLimit() : gateLimit;
    }

    function _publicGate() internal view override returns (bool) {
        return gate == 0 ? super._publicGate() : gate == 2;
    }

    function _chainCodeLimit() internal view override returns (uint256) {
        return codeLimit == 0 ? super._chainCodeLimit() : codeLimit;
    }

    function _precompiles() internal override returns (bool, bool) {
        if (forced) return (forcedBls, forcedBnG2);
        return abi.decode(address(new UAPrecompileProbe()).code, (bool, bool));
    }
}
