// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

interface ISaltedDomain {
    function eip712Domain() external view returns (bytes1, string memory, string memory, uint256, address, bytes32,
        uint256[] memory);
}

/// The EIP-712 digests a test signs, computed from the type strings and the contract's `eip712Domain()` (ERC-5267). A
/// token has no address `mtxDigest` view since ua-mtx-merge T1 (MD-1: the wallets keep it); its `executeMetaTransaction`
/// (R3) still takes a `MetaTransaction`, whose digest a client computes, as this does.
library MtxDigest {
    function domainSeparator(address c) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) =
            ISaltedDomain(c).eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    }

    function typed(address c, bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(c), structHash));
    }

    /// The digest of a `MetaTransaction` in `c`'s domain (relayer / fee recipient zeroed when unbound).
    function metaTx(address c, MetaTxLib.MetaTransaction memory m) internal view returns (bytes32) {
        return typed(c, MetaTxLib.hashStruct(m));
    }
}
