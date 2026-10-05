// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title Thay thế `metatx/SignatureValidator.sol`. Hai thay đổi, cả hai đều bắt buộc.
///
/// 1. **EIP-712, không `personal_sign`.** File cũ dùng `toEthSignedMessageHash()`, tức
///    ví hiển thị 32 byte mù cho người ký. Với EIP-712 ví hiển thị đúng "gửi 500.000
///    Z-VND cho 0xabc, phí 1.000, hết hạn 14:05". Người ký nhìn thấy được thứ mình ký
///    là hàng phòng thủ đầu tiên, và nó là hàng duy nhất không phụ thuộc code.
///
/// 2. **`verifySignature2` BỊ LOẠI.** Nó gọi `ecrecover` thô: không chặn malleability
///    của `s` (EIP-2 low-s), và trả `address(0)` thành công nếu chữ ký rác. Hiện chưa
///    ai gọi nó — nhưng nó là súng đã lên đạn nằm trong repo. OZ `ECDSA.recover` làm
///    đúng cả hai và revert thay vì trả `address(0)`.
///
/// Thêm một thứ file cũ không có: **ERC-1271**. Không có nó thì ví smart-contract
/// (Safe, ví passkey, mọi thứ account-abstraction) không ký được meta-transaction nào —
/// và outlet onboarding bằng passkey chính là luồng đó.
library SigLib {
    error SignatureInvalid(address expected);

    /// @notice Digest EIP-712 đầy đủ: `0x1901 ‖ domainSeparator ‖ structHash`.
    function digest(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /// @notice Kiểm chữ ký của `signer`, chấp nhận cả EOA (ECDSA) và contract (ERC-1271).
    function requireValid(address signer, bytes32 fullDigest, bytes memory signature) internal view {
        if (!SignatureChecker.isValidSignatureNow(signer, fullDigest, signature)) {
            revert SignatureInvalid(signer);
        }
    }

    /// @notice Chỉ EOA. Dùng khi cần chính địa chỉ khôi phục được chứ không chỉ "hợp lệ".
    function recoverEOA(bytes32 fullDigest, bytes memory signature) internal pure returns (address) {
        return ECDSA.recover(fullDigest, signature);
    }
}
