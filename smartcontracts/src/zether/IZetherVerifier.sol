// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ZetherTypes} from "./ZetherTypes.sol";

/// @title Verifier ZK, INJECT bằng địa chỉ — không `import` thẳng vào token.
///
/// @notice Đây là chỗ duy nhất trong hệ thống mà trừu tượng hoá sớm đáng giá, vì nó
///         là chỗ duy nhất ta BIẾT CHẮC sẽ có nhánh thứ hai:
///
///         D1 chốt `bn254` cho giai đoạn private (spike S7: BLS12-381 không rẻ hơn,
///         ở k=277 đắt hơn ~2%; và chain private 9000 không có EIP-2537). Nhưng D1
///         PHẢI mở lại trước khi lên public chain, vì bn254 ~100 bit sau
///         Kim–Barbulescu và ciphertext trên public chain là vĩnh viễn.
///
///         Với verifier inject: đổi curve = deploy verifier khác + token mới. Với
///         verifier import cứng: đổi curve = viết lại token.
///
///         Một token ĐÃ DEPLOY không đổi được verifier. Không có setter, và đó là
///         chủ ý — đổi verifier dưới chân một số dư đang lưu hành là đổi ý nghĩa của
///         mọi ciphertext đã tồn tại. Migrate nghĩa là token mới + bridge.
interface IZetherVerifier {
    /// @notice Định danh hệ chứng minh, khoá cứng cặp (curve, mạch).
    /// @dev Odoo lưu chính chuỗi này ở `blockchain.zether.token.proof_system_id` và
    ///      từ chối deploy nếu nó không khớp verifier trên chain.
    function proofSystemId() external pure returns (bytes32);

    /// @notice Kích thước ring mà verifier này chấp nhận.
    /// @dev Gas tỉ lệ theo ring size, nên MỌI con số gas trong tài liệu phải gắn với
    ///      một `m` cụ thể. Yêu cầu AML là lộ danh tính ⇒ ring = 2, rẻ hơn nhiều so
    ///      với anonymous-zether mà code hiện tại đang cài.
    function ringSize() external pure returns (uint256);

    function verifyTransfer(
        ZetherTypes.G1Point[] calldata cLn,
        ZetherTypes.G1Point[] calldata cRn,
        ZetherTypes.G1Point[] calldata c,
        ZetherTypes.G1Point calldata d,
        ZetherTypes.G1Point[] calldata y,
        uint256 epoch,
        ZetherTypes.G1Point calldata u,
        bytes calldata proof
    ) external view returns (bool);

    function verifyBurn(
        ZetherTypes.G1Point calldata cLn,
        ZetherTypes.G1Point calldata cRn,
        ZetherTypes.G1Point calldata y,
        uint256 epoch,
        ZetherTypes.G1Point calldata u,
        address sender,
        bytes calldata proof
    ) external view returns (bool);
}
