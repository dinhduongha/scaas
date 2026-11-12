// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";

/// ERC-7739 for tests (CTR-ACC-02): what a wallet key signs and the signature the wallet's `isValidSignature` takes,
/// written from the EIP text independently of `src/common/ERC7739Lib.sol`.
library Erc7739Kit {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    string internal constant METATX_TYPE =
        "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant DEX_ORDER_TYPE =
        "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)";
    string internal constant UA_CANCEL_NONCE_TYPE =
        "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_AUTH_TYPE = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)";
    /// `UAReceiverFee`'s own member list; it nests `UAMetaTransfer`, which sorts first (explicit `contentsDescription`).
    string internal constant UA_RECEIVER_FEE_OWN =
        "UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)";
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

    /// The two real wallets of one secp256k1 key `pk` on chain `uid`: a `SmartKeyAccount` (key 0) and a `MandateWallet`
    /// (native owner).
    function wallets(uint256 pk, bytes32 uid) internal returns (address ska, address mw) {
        bytes32 id = bytes32(uint256(uint160(VM.addr(pk))));
        ska = new SmartKeyAccountFactory(uid).deploy(SubjectKey(KeyKind.SECP256K1, id, 0, 0, 0), address(0));
        mw = address(new MandateWallet(id, uid, address(0), false));
    }

    /// The ERC-1271 inner signature of `wallet` by `pk` over `m`: the `SmartKeyAccount` encoding (key 0, no proof) or the
    /// owner's plain ECDSA for a `MandateWallet`.
    function inner(uint256 pk, address wallet, bytes32 m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(pk, m);
        bytes memory e = abi.encodePacked(r, s, v);
        return wallet.code.length == 45 ? abi.encode(uint256(0), new bytes32[](0), e) : e;
    }

    /// `wallet`'s ERC-7739 `TypedDataSign` signature by `pk` for the app struct `contents` of `app` (`descr` its
    /// `contentsDescription`, implicit: `contentsType` itself).
    function sign(uint256 pk, address wallet, address app, string memory name, string memory contentsType,
        string memory descr, bytes32 contents) internal view returns (bytes memory)
    {
        bytes32 sep = separator(app);
        return wrap(inner(pk, wallet, nested(wallet, sep, name, contentsType, contents)), sep, contents, descr);
    }

    /// `wallet`'s signature by `pk` over the raw `hash` (what ERC-7739 refuses).
    function raw(uint256 pk, address wallet, bytes32 hash) internal view returns (bytes memory) {
        return inner(pk, wallet, hash);
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
