// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title ERC-7739 nested typed data for the ERC-1271 answer of a wallet (CTR-ACC-02, B P3-2, owner 2026-11-12).
/// @notice The layout and both workflows of EIP-7739 (draft, `TypedDataSign` and `PersonalSign`), as OpenZeppelin
///         Contracts v5.4.0 `draft-ERC7739Utils.sol` / `draft-ERC7739.sol` encode them, with the EIP's recommended
///         `contentsName` checks:
///         - `TypedDataSign`: `signature = inner ‖ APP_DOMAIN_SEPARATOR ‖ contents ‖ contentsDescription ‖
///           uint16(contentsDescription.length)`, valid only when `hash == keccak256(0x1901 ‖ APP_DOMAIN_SEPARATOR ‖
///           contents)`; the key signed `keccak256(0x1901 ‖ APP_DOMAIN_SEPARATOR ‖ hashStruct(TypedDataSign{contents,
///           name, version, chainId, verifyingContract, salt}))`, the wallet's own domain fields inside the struct.
///         - `PersonalSign` otherwise: the key signed `keccak256(0x1901 ‖ WALLET_DOMAIN_SEPARATOR ‖
///           keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), hash)))` with the whole `signature`.
///         Either way the message names the wallet (`verifyingContract`) and its chain, never the raw `hash`.
library ERC7739Lib {
    /// @dev `isValidSignature(DETECT, "")` answers `SUPPORTED` (the EIP's support detection).
    bytes32 internal constant DETECT = 0x7739773977397739773977397739773977397739773977397739773977397739;
    bytes4 internal constant SUPPORTED = 0x77390001;
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)");

    /// @notice The message the wallet's key signed for `hash`, and the inner signature over it.
    /// @param walletSeparator the wallet's own EIP-712 domain separator (the `PersonalSign` workflow)
    /// @param walletDomain    `abi.encode(keccak256(name), keccak256(version), chainId, verifyingContract, salt)` of the
    ///                        wallet's `eip712Domain()` (the `TypedDataSign` struct's last five fields)
    function unwrap(bytes32 hash, bytes calldata sig, bytes32 walletSeparator, bytes memory walletDomain)
        internal pure returns (bytes32 message, bytes calldata inner)
    {
        (bool nested, bytes32 typed, uint256 innerEnd) = _typedDataSign(hash, sig, walletDomain);
        if (nested) return (typed, sig[:innerEnd]);
        return (MessageHashUtils.toTypedDataHash(walletSeparator, keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, hash))), sig);
    }

    /// @dev The `TypedDataSign` message when `sig` carries the suffix, its app separator and contents rebuild `hash`, and
    ///      its `contentsDescription` is valid; `innerEnd` ends the inner signature.
    function _typedDataSign(bytes32 hash, bytes calldata sig, bytes memory walletDomain)
        private pure returns (bool ok, bytes32 message, uint256 innerEnd)
    {
        uint256 n = sig.length;
        if (n < 66) return (false, 0, 0);
        uint256 descrEnd = n - 2;
        uint256 descrLen = uint16(bytes2(sig[descrEnd:]));
        if (n < 66 + descrLen) return (false, 0, 0);
        uint256 contentsEnd = descrEnd - descrLen;
        innerEnd = contentsEnd - 64;
        bytes32 app = bytes32(sig[innerEnd:innerEnd + 32]);
        bytes32 contents = bytes32(sig[innerEnd + 32:contentsEnd]);
        if (MessageHashUtils.toTypedDataHash(app, contents) != hash) return (false, 0, 0);
        bytes32 structHash = _typedDataSignStruct(sig[contentsEnd:descrEnd], contents, walletDomain);
        if (structHash == 0) return (false, 0, 0);
        return (true, MessageHashUtils.toTypedDataHash(app, structHash), innerEnd);
    }

    /// @dev `hashStruct(TypedDataSign{contents, the wallet's five domain fields})`; 0 for an invalid description.
    function _typedDataSignStruct(bytes calldata descr, bytes32 contents, bytes memory walletDomain)
        private pure returns (bytes32)
    {
        (bool ok, bytes calldata name, bytes calldata contentsType) = _contentsDescr(descr);
        if (!ok) return 0;
        bytes32 typehash = keccak256(abi.encodePacked("TypedDataSign(", name,
            " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)", contentsType));
        return keccak256(abi.encodePacked(typehash, contents, walletDomain));
    }

    /// @notice The `walletDomain` argument of `unwrap` from a wallet's `eip712Domain()` fields.
    function domainFields(string memory name, string memory version, uint256 chainId, address verifyingContract,
        bytes32 salt) internal pure returns (bytes memory)
    {
        return abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
    }

    /// @dev `contentsDescription`: implicit mode (`contentsType`, which starts with `contentsName`, ends with `)`) or
    ///      explicit mode (`contentsType ‖ contentsName`). `contentsName` must be non-empty, hold none of `, )(` or NUL,
    ///      and not start with `a`-`z` (the EIP's recommended checks).
    function _contentsDescr(bytes calldata d)
        private pure returns (bool ok, bytes calldata name, bytes calldata contentsType)
    {
        uint256 n = d.length;
        name = d[:0];
        contentsType = d[:0];
        if (n == 0) return (false, name, contentsType);
        if (d[n - 1] == ")") {
            for (uint256 i; i < n; ++i) {
                bytes1 c = d[i];
                if (c == "(") {
                    if (i == 0) return (false, name, contentsType);
                    name = d[:i];
                    contentsType = d;
                    break;
                }
                if (_forbidden(c)) return (false, name, contentsType);
            }
        } else {
            for (uint256 i = n; i > 0; --i) {
                bytes1 c = d[i - 1];
                if (c == ")") {
                    name = d[i:];
                    contentsType = d[:i];
                    break;
                }
                if (_forbidden(c)) return (false, name, contentsType);
            }
        }
        if (name.length == 0 || (name[0] >= "a" && name[0] <= "z")) return (false, name, contentsType);
        return (true, name, contentsType);
    }

    function _forbidden(bytes1 c) private pure returns (bool) {
        return c == 0x00 || c == " " || c == "," || c == "(" || c == ")";
    }
}
