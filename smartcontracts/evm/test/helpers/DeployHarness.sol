// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {DeployBase} from "../../script/DeployBase.sol";
import {UAPrecompileProbe} from "../../script/UAPrecompileProbe.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";

/// The deploy steps without the RPC parts (`_setup`, the `eth_call` probe): the salt, `chain_uid`, `DEPLOY_ZETHER` and
/// the profile set directly; the precompile probe runs in this EVM (or its verdict is forced).
contract DeployHarness is DeployBase {
    bool internal forced;
    bool internal forcedBls;
    bool internal forcedBnG2;

    function force(bool bls12381, bool bn254G2) external {
        (forced, forcedBls, forcedBnG2) = (true, bls12381, bn254G2);
    }

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

    function defaultNotice(uint256 chainId) external pure returns (uint256) { return _defaultNotice(chainId); }

    function _precompiles() internal override returns (bool, bool) {
        if (forced) return (forcedBls, forcedBnG2);
        return abi.decode(address(new UAPrecompileProbe()).code, (bool, bool));
    }
}
