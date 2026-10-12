// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {SmartKeyAccount, SubjectKey} from "./SmartKeyAccount.sol";

/// @title Permissionless, predictable `SmartKeyAccount` deploys (CTR-ACC-01, CTR-ACC-05).
/// @notice EIP-1167 clones by CREATE2, salt = `keccak256(abi.encode(firstKey, guardian))`: whoever deploys gets the
///         same account for the same key and guardian, and a repeated `deploy` returns that address instead of
///         reverting. The guardian is in the salt, or the first deployer would choose it. The factory takes the
///         chain's `chain_uid` and passes it to `new SmartKeyAccount(chainUid)` (the account's salted domain), so the
///         implementation, and every account, has a different address on each chain.
contract SmartKeyAccountFactory {
    address public immutable IMPLEMENTATION;

    event AccountDeployed(address indexed account, bytes32 indexed firstKeyId, address guardian);

    constructor(bytes32 chainUid_) {
        IMPLEMENTATION = address(new SmartKeyAccount(chainUid_));
    }

    /// @notice The `chain_uid` of the accounts (the deploy gate reads it, CTR-GEN-05).
    function chainUid() external view returns (bytes32) {
        return SmartKeyAccount(payable(IMPLEMENTATION)).chainUid();
    }

    function salt(SubjectKey calldata firstKey, address guardian) public pure returns (bytes32) {
        return keccak256(abi.encode(firstKey, guardian));
    }

    function predict(SubjectKey calldata firstKey, address guardian) public view returns (address) {
        return Clones.predictDeterministicAddress(IMPLEMENTATION, salt(firstKey, guardian));
    }

    function deploy(SubjectKey calldata firstKey, address guardian) external returns (address account) {
        account = predict(firstKey, guardian);
        if (account.code.length != 0) return account;
        Clones.cloneDeterministic(IMPLEMENTATION, salt(firstKey, guardian));
        SmartKeyAccount(payable(account)).initialize(firstKey, guardian);
        emit AccountDeployed(account, keccak256(abi.encode(firstKey)), guardian);
    }
}
