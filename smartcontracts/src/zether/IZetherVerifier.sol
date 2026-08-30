// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Verifier ZK — inject bằng địa chỉ, KHÔNG import thẳng vào token.
///
/// @notice Factory mở cho toàn thế giới ⇒ **hệ thống hỗ trợ nhiều curve cùng lúc, và
///         không ưu tiên cái nào**. Người tạo token truyền địa chỉ verifier họ muốn.
///         Factory không phán xét, chỉ ghi lại bất biến để ví và indexer tự quyết
///         có tin hay không.
///
///         Một verifier độc hại (nhận proof giả) chỉ hại đúng những token đã CHỌN nó.
///         Đó là lý do `verifier()` của token phải công khai và bất biến: nó là thứ
///         người dùng kiểm được trước khi nạp tiền.
///
///         Token đã deploy **không đổi được verifier**. Không setter, và đó là chủ ý —
///         đổi verifier dưới chân một số dư đang lưu hành là đổi ý nghĩa của mọi
///         ciphertext đã tồn tại. Migrate = token mới + bridge.
interface IZetherVerifier {
    /// @notice Định danh hệ chứng minh. Khoá cứng bộ ba (curve, mạch, mã hoá điểm).
    /// @dev Ví/SDK đọc cái này để biết dùng prover backend nào và giải mã payload ra
    ///      sao. Ví dụ: `keccak256("zether/bulletproofs/bn254/ring2/v1")`.
    function proofSystemId() external pure returns (bytes32);

    /// @notice Tên curve, dạng người đọc được. `"bn254"` | `"bls12-381"`.
    function curveName() external pure returns (string memory);

    /// @notice Số byte của một điểm G1 theo mã hoá của verifier này.
    /// @dev 64 cho bn254, **128** cho BLS12-381 (EIP-2537 pad mỗi Fp thành 64 byte).
    ///      SDK cần nó để cắt payload; test dùng nó để chặn nhầm curve.
    function g1EncodedBytes() external pure returns (uint256);

    /// @notice Ring size verifier này chấp nhận.
    /// @dev Gas tỉ lệ theo ring size, nên mọi con số gas phải gắn với một `m` cụ thể.
    ///      Ring = 2 là lộ danh tính người gửi/nhận; ring lớn là ẩn danh trong đám
    ///      đông. **Đây là lựa chọn của người tạo token, không phải của protocol** —
    ///      hai thị trường khác nhau muốn hai thứ khác nhau.
    function ringSize() external pure returns (uint256);

    /// @notice Verifier này có chạy được trên chain HIỆN TẠI không?
    /// @dev Implementation staticcall thử chính precompile nó cần với một vector đã
    ///      biết và so kết quả. Lý do hàm này tồn tại: một verifier BLS12-381 deploy
    ///      thành công trên chain không có EIP-2537 — bytecode hợp lệ, constructor
    ///      chạy xong, địa chỉ có code — rồi **revert ở mọi proof, mãi mãi**.
    ///      Precompile vắng mặt trả về staticcall thành công với output rỗng, không
    ///      revert, nên không có triệu chứng nào lúc deploy.
    ///
    ///      Factory gọi hàm này trước khi cho ai deploy token, và từ chối nếu false.
    ///      Đó không phải gác cổng — đó là không để người ta đốt gas vào một cái brick.
    function isSupportedOnThisChain() external view returns (bool);

    /// @notice Kiểm proof chuyển khoản.
    /// @param payload C[], D, y[], u — mã hoá theo `proofSystemId()`, opaque với contract gọi
    /// @param epoch   epoch toàn cục lúc verify
    function verifyTransfer(bytes calldata payload, uint256 epoch, bytes calldata proof)
        external
        view
        returns (bool);

    /// @notice Kiểm proof rút tiền ra dạng công khai.
    function verifyBurn(
        bytes calldata payload,
        uint256 epoch,
        address recipient,
        bytes calldata proof
    ) external view returns (bool);
}
