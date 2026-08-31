// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title N-of-M ECDSA thô, cho `AuthScheme.ECDSA_MULTISIG`.
/// @notice **Đọc mục này trước khi dùng: phần lớn trường hợp KHÔNG cần nó.**
///
/// Ở tầng meta-transaction, `m.from` là một địa chỉ EVM, nên multisig đã được phục vụ
/// **miễn phí** bởi ERC-1271: đặt `from` là một Safe, và `SigLib.requireValid` gọi
/// `isValidSignature` của Safe. Safe đã được audit, xử lý xoay chủ sở hữu, đổi ngưỡng,
/// và thu hồi — ba thứ mà library này **không** làm.
///
/// Library này tồn tại cho đúng một chỗ: tầng **Zether**, nơi danh tính không phải một
/// địa chỉ EVM mà là `keccak(pkX, pkY)` của một điểm đường cong. Ở đó không có contract
/// nào để gọi `isValidSignature`, nên contract phải tự kiểm.
///
/// Nếu bạn đang định dùng nó ở tầng meta-tx: dùng Safe.
library MultiSig {
    error DuplicateOrUnsorted(address signer);
    error NotAnOwner(address signer);
    error ThresholdNotMet(uint256 got, uint256 need);
    error BadThreshold(uint256 threshold, uint256 owners);

    /// @notice Kiểm `threshold` chữ ký khác nhau, mỗi cái của một chủ sở hữu khác nhau.
    /// @param owners  Tập chủ sở hữu, **phải đã sắp tăng dần** và không trùng.
    /// @param sigs    Chữ ký, **phải xếp theo địa chỉ người ký tăng dần**.
    /// @dev Ba cái bẫy, và cả ba đều đã làm mất tiền ở đâu đó:
    ///
    ///      1. **Đếm trùng.** Không ép thứ tự thì cùng một chữ ký nộp `threshold` lần là
    ///         qua. Ép `recovered > last` giải quyết bằng một phép so sánh, và nó rẻ hơn
    ///         một mapping `seen` (không SSTORE, không xoá).
    ///      2. **`ecrecover` trả `address(0)`.** Chữ ký rác cho ra 0; nếu 0 lọt vào tập
    ///         chủ sở hữu thì mọi chữ ký rác đều hợp lệ. `ECDSA.recover` của OZ revert
    ///         thay vì trả 0, và cũng chặn `s` cao (EIP-2 malleability).
    ///      3. **Ngưỡng 0.** `threshold == 0` làm hàm luôn trả về true trên mảng rỗng.
    ///         Kiểm ở đây chứ không tin caller.
    function requireQuorum(
        address[] memory owners,
        uint256 threshold,
        bytes32 fullDigest,
        bytes[] memory sigs
    ) internal pure {
        if (threshold == 0 || threshold > owners.length) {
            revert BadThreshold(threshold, owners.length);
        }
        if (sigs.length < threshold) revert ThresholdNotMet(sigs.length, threshold);

        address last = address(0);
        uint256 valid;
        for (uint256 i; i < sigs.length; ++i) {
            address rec = ECDSA.recover(fullDigest, sigs[i]);   // revert nếu rác hoặc s cao
            if (rec <= last) revert DuplicateOrUnsorted(rec);   // ép tăng dần ⇒ không trùng
            if (!_isOwner(owners, rec)) revert NotAnOwner(rec);
            last = rec;
            unchecked { ++valid; }
            if (valid == threshold) return;                     // đủ rồi thì dừng, khỏi tốn gas
        }
        revert ThresholdNotMet(valid, threshold);
    }

    /// @dev `owners` đã sắp tăng dần nên tìm nhị phân. Với M = 7 thì tuyến tính cũng được,
    ///      nhưng M là tham số của người dùng và một vòng lặp O(N·M) là chỗ để họ tự
    ///      grief mình.
    function _isOwner(address[] memory owners, address a) private pure returns (bool) {
        uint256 lo;
        uint256 hi = owners.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            if (owners[mid] < a) lo = mid + 1; else hi = mid;
        }
        return lo < owners.length && owners[lo] == a;
    }
}
