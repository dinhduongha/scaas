// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {SubjectAccount, SubjectKey} from "./SubjectAccount.sol";

/// @title Deploy `SubjectAccount` không cần quyền, địa chỉ biết trước (review S3, RS4-1).
/// @notice Clone EIP-1167 qua CREATE2, salt = `keccak256(abi.encode(firstKey, guardian))`. Ai
///         deploy cũng ra cùng account với cùng (khoá, guardian); `deploy` gọi lại trên account
///         đã có thì trả địa chỉ đó, không revert — job deploy lặp của Odoo không hỏng.
///         Guardian nằm trong salt: nếu không, người deploy trước chọn được guardian.
contract SubjectAccountFactory {
    address public immutable IMPLEMENTATION;

    event AccountDeployed(address indexed account, bytes32 indexed firstKeyId, address guardian);

    constructor() {
        IMPLEMENTATION = address(new SubjectAccount());
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
        SubjectAccount(payable(account)).initialize(firstKey, guardian);
        emit AccountDeployed(account, keccak256(abi.encode(firstKey)), guardian);
    }
}
