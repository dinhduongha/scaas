// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

/// @title Verifier ZK — inject bằng địa chỉ, KHÔNG import thẳng vào token.
///
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
///
///         Factory mở cho toàn thế giới ⇒ **hệ thống hỗ trợ nhiều curve cùng lúc, và không ưu tiên cái
///         nào**. Người tạo token truyền địa chỉ verifier họ muốn; token đã deploy **không đổi được
///         verifier** (đổi verifier dưới một số dư đang lưu hành là đổi nghĩa mọi ciphertext).
///
///         Ngoài kiểm proof, verifier là **nơi duy nhất biết đường cong**: token (một implementation cho
///         mọi curve) làm phép cộng đồng hình qua các hàm `g1*` ở đây. Đặc tả byte-exact:
///         `docs/contracts/zether.md` (bản đóng băng `docs/history/specs/2026-10-03-zether-design.md`).
interface IZetherVerifier {
    /// @notice Khoá cứng bộ ba (curve, mạch, mã hoá điểm). Nằm trong statement (§6) ⇒ trong transcript.
    function proofSystemId() external pure returns (bytes32);

    /// @notice Id của transfer nhiều người nhận: nhãn của `proofSystemId` thêm "/multi".
    function proofSystemIdMulti() external pure returns (bytes32);

    /// @notice `"bn254"` | `"bls12-381"`.
    function curveName() external pure returns (string memory);

    /// @notice 64 cho bn254, **128** cho BLS12-381 (EIP-2537 pad mỗi Fp thành 64 byte).
    function g1EncodedBytes() external pure returns (uint256);

    /// @notice Luôn 2: lộ danh tính người gửi/nhận (SRS §7.1), không có anonymity set.
    function ringSize() external pure returns (uint256);

    /// @notice Bậc nhóm `r` (scalar field).
    function groupOrder() external pure returns (uint256);

    /// @notice Precompile mà verifier cần có thật và trả đúng vector đã biết trên chain này không.
    /// @dev Precompile vắng mặt trả về staticcall THÀNH CÔNG với output rỗng — không revert, không
    ///      triệu chứng lúc deploy. Factory gọi hàm này và từ chối nếu false.
    function isSupportedOnThisChain() external view returns (bool);

    /// @notice Kiểm proof chuyển khoản (đặc tả §6–§9). `statement` do token dựng từ storage.
    /// @dev Verifier KHÔNG kiểm `chainId`/token trong header — đó là việc của token, nó tự dựng
    ///      header từ `block.chainid`/`address(this)`. Verifier chỉ kiểm `opTag` và `proofSystemId`.
    function verifyTransfer(bytes calldata statement, bytes calldata proof) external view returns (bool);

    /// @notice Kiểm proof rút ra dạng công khai. `amount`, `recipient` nằm trong `statement`.
    function verifyTransferMulti(bytes calldata statement, bytes calldata proof) external view returns (bool);

    function verifyBurn(bytes calldata statement, bytes calldata proof) external view returns (bool);

    /// @notice Blob generator NUMS `h ‖ U ‖ G_0..G_63 ‖ H_0..H_63` (§3), tính trong constructor.
    function generators() external view returns (bytes memory);

    // ----------------------------------------------------------- phép nhóm cho token / test

    function identity() external pure returns (bytes memory);
    function isValidPoint(bytes calldata a) external view returns (bool);
    function g1Add(bytes calldata a, bytes calldata b) external view returns (bytes memory);
    function g1Sub(bytes calldata a, bytes calldata b) external view returns (bytes memory);
    function g1Mul(bytes calldata a, uint256 k) external view returns (bytes memory);
    function g1MulBase(uint256 k) external view returns (bytes memory);
    /// @param pts các điểm nối liền; `scalars.length` số hạng.
    function g1Msm(bytes calldata pts, uint256[] calldata scalars) external view returns (bytes memory);
}
