// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ZetherTranscript} from "./ZetherTranscript.sol";

/// @title Tiết lộ có chọn lọc cho MỌI Zether token (owner Z13): không state, không admin, không nâng cấp.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Đọc từ token qua view (`transferEntry`, `verifier`,
///         `auditorKey`, `chainUid`); đường cong do verifier của token quyết. Tách khỏi token (CTR-ZTH-43).
///         Challenge ràng địa chỉ TOKEN, không phải contract này: opening không phụ thuộc nơi deploy.
contract ZetherDisclosure is ITransferDisclosure {
    bytes private constant DISCLOSE_TAG = "SCAAS-ZETHER-DISCLOSE-V1";
    /// @dev `2^n_v` (n_v = 64, RS-NV64-1): trần của số tiền tiết lộ.
    uint256 private constant VALUE_BOUND = 1 << 64;

    /// @dev Leg `index` của một entry, cùng verifier và tham số đường cong của token.
    struct Leg {
        IZetherVerifier v;
        uint256 p;
        uint256 r;
        bytes yt;
        bytes cOut;
        bytes dOut;
        bytes cAud;
        // Chaum-Pedersen `log_G(K) == log_B(M − [amount]G)`
        bytes k;
        bytes m;
        bytes b;
    }

    function verifyTransferAmount(
        address token,
        bytes32 entryRef,
        uint256 index,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening,
        bytes calldata bundles
    ) external view returns (bool) {
        Leg memory l = _leg(token, entryRef, index, bundles);
        if (amount >= VALUE_BOUND) return false; // [amount]G chỉ phụ thuộc amount mod r
        if (kind == OpeningKind.SENDER_S) {
            if (opening.length != 32) revert OpeningMalformed();
            uint256 s = abi.decode(opening, (uint256));
            if (s >= l.r) return false;
            uint256[] memory sc = new uint256[](3);
            (sc[0], sc[1], sc[2]) = (amount, s, l.r - 1);
            return keccak256(l.v.g1MulBase(s)) == keccak256(l.dOut)
                && _isO(l.v.g1Msm(bytes.concat(l.v.g1MulBase(1), l.yt, l.cOut), sc));
        }
        if (kind == OpeningKind.RECEIVER_X) {
            (l.k, l.m, l.b) = (l.yt, l.cOut, l.dOut);
        } else if (kind == OpeningKind.SENDER_CP) {
            (l.k, l.m, l.b) = (l.dOut, l.cOut, l.yt);
        } else {
            bytes memory ya = IZetherToken(token).auditorKey();
            if (ya.length == 0 || _isO(l.cAud)) return false; // token không auditor, hoặc người gửi bỏ auditor (Z12)
            (l.k, l.m, l.b) = (ya, l.cAud, l.dOut);
        }
        bytes memory pre = abi.encodePacked(
            DISCLOSE_TAG, block.chainid, IMetaTx(token).chainUid(), token, entryRef, index, amount, uint8(kind)
        );
        return _chaumPedersen(l, pre, amount, opening);
    }

    function transferCiphertext(address token, bytes32 entryRef, uint256 index, bytes calldata bundles)
        external view returns (bytes memory encodedCiphertext, bytes memory encodedYTo)
    {
        Leg memory l = _leg(token, entryRef, index, bundles);
        return (bytes.concat(l.cOut, l.dOut, l.cAud), l.yt);
    }

    /// @dev `[z]G − A1 − [e]K == O` và `[z]B − A2 − [e]M + [e·amount]G == O`,
    ///      `e = H(DISCLOSE_TAG ‖ chainid ‖ chainUid ‖ token ‖ entryRef ‖ index ‖ amount ‖ kind ‖ A1 ‖ A2)` (CTR-ZTH-36).
    function _chaumPedersen(Leg memory l, bytes memory pre, uint256 amount, bytes calldata opening)
        private view returns (bool)
    {
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(opening, (bytes, bytes, uint256));
        if (a1.length != l.p || a2.length != l.p || z >= l.r) revert OpeningMalformed();
        uint256 e = ZetherTranscript.hashToScalar(keccak256(bytes.concat(pre, a1, a2)), l.r);
        if (e == 0) return false;
        amount = mulmod(e, amount, l.r); // từ đây: e·amount
        bytes memory g = l.v.g1MulBase(1);
        if (!_cpEq(l, bytes.concat(g, a1, l.k), z, e, 0)) return false;
        return _cpEq(l, bytes.concat(l.b, a2, l.m, g), z, e, amount);
    }

    /// @dev `[z]P0 − P1 − [e]P2 (+ [extra]P3) == O`.
    function _cpEq(Leg memory l, bytes memory pts, uint256 z, uint256 e, uint256 extra) private view returns (bool) {
        uint256 n = pts.length / l.p;
        uint256[] memory sc = new uint256[](n);
        (sc[0], sc[1], sc[2]) = (z, l.r - 1, l.r - e);
        if (n == 4) sc[3] = extra;
        return _isO(l.v.g1Msm(pts, sc));
    }

    /// @dev `B_index` của `entryRef` trong `R = salt(16) ‖ B_1 ‖ … ‖ B_M`: bản ghi của token, hoặc (commit-reveal: token trả
    ///      `keccak256(R) ‖ memo`, độ dài `49 + 40·M` không bao giờ bằng `16 + 4P·M`) `R` do người gọi đưa sau khi khớp
    ///      hash. Token không ghi gì (NONE, ref lạ) ⇒ `UnknownEntry`. Transfer một người nhận: chỉ `index = 0`.
    function _leg(address token, bytes32 entryRef, uint256 index, bytes calldata bundles)
        private view returns (Leg memory l)
    {
        l.v = IZetherToken(token).verifier();
        l.p = l.v.g1EncodedBytes();
        l.r = l.v.groupOrder();
        bytes memory all = IZetherToken(token).transferEntry(entryRef);
        if (all.length == 0) revert UnknownEntry(entryRef);
        uint256 len = 4 * l.p;
        if (all.length < 16 || (all.length - 16) % len != 0) {
            if (keccak256(bundles) != bytes32(all)) revert BundlesMismatch(entryRef);
            all = bundles;
        }
        if (16 + (index + 1) * len > all.length) revert BadRecipientIndex(index);
        uint256 o = 16 + index * len;
        (l.yt, l.cOut, l.dOut, l.cAud) =
            (_cut(all, o, l.p), _cut(all, o + l.p, l.p), _cut(all, o + 2 * l.p, l.p), _cut(all, o + 3 * l.p, l.p));
    }

    function _isO(bytes memory a) private pure returns (bool) {
        return keccak256(a) == keccak256(new bytes(a.length));
    }

    function _cut(bytes memory a, uint256 off, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            let d := add(out, 32)
            let s := add(add(a, 32), off)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(d, i), mload(add(s, i))) }
        }
    }
}
