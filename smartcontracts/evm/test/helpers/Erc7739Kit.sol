// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// ERC-7739 for tests (CTR-ACC-02): what a wallet key signs and the signature the wallet's `isValidSignature` takes,
/// written from the EIP text independently of `src/common/ERC7739Lib.sol`.
library Erc7739Kit {
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    string internal constant METATX_TYPE =
        "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_TRANSFER_TYPE =
        "UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    /// The salted separator of a contract's `eip712Domain()` (every SCaaS domain has the five fields).
    function separator(address c) internal view returns (bytes32) {
        (, string memory n, string memory v, uint256 id, address vc, bytes32 s,) = IDomain(c).eip712Domain();
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(n)), keccak256(bytes(v)), id, vc, s));
    }

    /// `hashStruct(TypedDataSign{contents, the wallet's five domain fields})` for `contentsName` / `contentsType`.
    function typedDataSignStruct(address wallet, string memory contentsName, string memory contentsType, bytes32 contents)
        internal view returns (bytes32)
    {
        (, string memory n, string memory v, uint256 id, address vc, bytes32 s,) = IDomain(wallet).eip712Domain();
        bytes32 th = keccak256(abi.encodePacked("TypedDataSign(", contentsName,
            " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)", contentsType));
        return keccak256(abi.encode(th, contents, keccak256(bytes(n)), keccak256(bytes(v)), id, vc, s));
    }

    /// The `TypedDataSign` message a key of `wallet` signs for the app hash `keccak256(0x1901 ‖ app ‖ contents)`.
    function nested(address wallet, bytes32 app, string memory contentsName, string memory contentsType, bytes32 contents)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked(hex"1901", app, typedDataSignStruct(wallet, contentsName, contentsType, contents)));
    }

    /// `inner ‖ app ‖ contents ‖ contentsDescription ‖ uint16(contentsDescription.length)`.
    function wrap(bytes memory inner, bytes32 app, bytes32 contents, string memory descr) internal pure returns (bytes memory) {
        return abi.encodePacked(inner, app, contents, descr, uint16(bytes(descr).length));
    }

    /// The `PersonalSign` message a key of `wallet` signs for `hash`.
    function personal(address wallet, bytes32 hash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", separator(wallet),
            keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), hash))));
    }
}

interface IDomain {
    function eip712Domain() external view returns (bytes1, string memory, string memory, uint256, address, bytes32,
        uint256[] memory);
}
