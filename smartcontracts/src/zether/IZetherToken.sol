// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20MetaTx} from "../metatx/IERC20MetaTx.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Token có số dư bí mật. Kế thừa TOÀN BỘ meta-transaction từ tầng nền.
interface IZetherToken is IERC20MetaTx {
    // ------------------------------------------------------------------
    // Tham số per-token. KHÔNG phải `constant`.
    // ------------------------------------------------------------------

    /// @notice Trần số dư che giấu, tính theo đơn vị đã chia `shieldScale()`.
    /// @dev `ZSC.sol:21` khai `uint256 constant MAX = 4294967295` — `constant` nên
    ///      không thể per-token. Z-VND và Z-ETH cần trần khác nhau. Phải là biến đặt
    ///      trong `initialize()`, không có setter (đổi trần của một token đã lưu hành
    ///      là đổi ý nghĩa của mọi ciphertext đang tồn tại).
    function maxDecryptableShielded() external view returns (uint256);

    /// @notice Bao nhiêu raw unit ERC-20 = 1 đơn vị che giấu.
    /// @dev Bất biến enforce trong `initialize()`, không setter:
    ///          maxSupply / shieldScale() <= maxDecryptableShielded()
    ///      Tăng `shieldScale` RẺ HƠN mua thêm bit giải mã, và chỉ trả bằng độ mịn.
    function shieldScale() external view returns (uint256);

    /// @notice Phí Zether cho token này. CỐ ĐỊNH, đơn vị che giấu.
    /// @dev Không nhận `amount` làm tham số, và đó là chủ ý: phí Zether KHÔNG ĐƯỢC
    ///      là hàm của `v` dưới bất kỳ dạng nào. Không phần trăm (`v = fee/p` lộ hết),
    ///      không bậc thang (mỗi bậc rò ~1,6 bit, cộng dồn dựng lại được hồ sơ).
    ///      Đổi bằng governance, không đổi theo giao dịch.
    function confidentialFee() external view returns (uint256);

    // ------------------------------------------------------------------
    // Vòng đời số dư
    // ------------------------------------------------------------------

    event Registered(ZetherTypes.UA indexed account, uint256 schemaIdx);
    event Funded(ZetherTypes.UA indexed account, uint256 amount);
    event ConfidentialTransfer(
        ZetherTypes.UA indexed from,
        ZetherTypes.UA indexed to,
        ZetherTypes.UA indexed beneficiary,
        uint256 fee,
        uint256 sendCounter,
        bytes32 entryRef
    );
    event Burned(ZetherTypes.UA indexed account, uint256 amount);
    event RolledOver(ZetherTypes.UA indexed account, uint256 epoch);

    error AccountNotRegistered(ZetherTypes.UA account);
    error AmountOutOfRange(uint256 amount, uint256 max);
    error ProofRejected();
    error NonceSeen(bytes32 uHash);

    function registered(ZetherTypes.UA account) external view returns (bool);

    /// @notice Số dư mã hoá, đã cộng pending nếu epoch đã tiến.
    /// @dev Trả về CIPHERTEXT. Nó không giải mã gì cả — contract không có `x`.
    function simulateAccounts(ZetherTypes.G1Point[] calldata y, uint256 epoch)
        external
        view
        returns (ZetherTypes.Ciphertext[] memory);

    /// @notice Gộp `pending` vào `acc` cho một tài khoản, không cần chữ ký của ai.
    /// @dev Code hiện tại của user gọi `rollOver` NGẦM ở đầu mọi thao tác chạm tài
    ///      khoản, và đó là thiết kế đúng — không có bề mặt chối cãi, không có tiền
    ///      kẹt vĩnh viễn ở pending. Hàm public này KHÔNG thay thế cơ chế ngầm đó;
    ///      nó chỉ thêm đường cho một tài khoản nhận tiền rồi im lặng (không gửi gì,
    ///      không được ai gửi thêm) vẫn được người thứ ba đẩy `pending` sang `acc`.
    ///      Idempotent trong cùng epoch: gọi lại là no-op, không revert.
    ///
    ///      Đây là yêu cầu của user: "Thêm hàm để không gửi gì cũng có thể rollOver."
    function rollOverPublic(ZetherTypes.UA account) external;

    /// @notice `rollOverPublic` cho nhiều tài khoản trong một giao dịch.
    /// @dev Tồn tại vì gọi lẻ tốn 21.000 gas base mỗi lần. Indexer quét ra danh sách
    ///      tài khoản có pending cũ rồi dọn một lượt.
    function rollOverBatch(ZetherTypes.UA[] calldata accounts) external;

    function fund(ZetherTypes.G1Point calldata y, uint256 amount) external;

    /// @notice Chuyển bí mật.
    /// @param outerFeeMode phí TẦNG NGOÀI. Bắt buộc NONE hoặc FIXED — PERCENT bị
    ///        `FeePolicy.requireConfidentialSafe` chặn ở tầng contract.
    /// @param beneficiary UA nhận phí TẦNG TRONG. Phí này công khai (cộng homomorphic
    ///        `g^fee` vào pending), và nó PHẢI công khai để relayer trên mesh mở thẩm
    ///        định được lợi nhuận trước khi nhận việc.
    /// @return entryRef khoá ràng buộc giao dịch này, dùng lại ở `verifyTransferAmount`.
    /// @dev Ba tổ hợp phí, ba luồng khác nhau:
    ///      1. chỉ phí ngoài  — user có ERC-20 công khai
    ///      2. chỉ phí trong  — user CHỈ có số dư bí mật; đây là luồng duy nhất mở
    ///                          được nút "tài khoản Zether thuần bị kẹt"
    ///      3. cả hai = 0     — user tự trả native gas, gọi thẳng, không qua relayer
    function transferConfidential(
        ZetherTypes.G1Point[] calldata c,
        ZetherTypes.G1Point calldata d,
        ZetherTypes.G1Point[] calldata y,
        ZetherTypes.G1Point calldata u,
        bytes calldata proof,
        ZetherTypes.UA beneficiary,
        FeeMode outerFeeMode,
        uint256 outerFee,
        address outerFeeRecipient
    ) external returns (bytes32 entryRef);

    function burn(
        ZetherTypes.G1Point calldata y,
        uint256 amount,
        ZetherTypes.G1Point calldata u,
        bytes calldata proof
    ) external;

    /// @notice Bộ đếm gửi của một UA, đọc TỪ CHUỖI.
    /// @dev Client suy `s` bằng PRF:
    ///          s = HKDF(seed, "ZTX/s/v1" ‖ chainId ‖ token ‖ fromUA ‖ sendCounter)
    ///      nên client không lưu gì ngoài seed, và khôi phục ví trắng vẫn chứng minh
    ///      được mọi giao dịch quá khứ.
    ///
    ///      Counter PHẢI đọc từ đây, không phải từ bộ đếm cục bộ. Giao dịch fail làm
    ///      tăng counter cục bộ nhưng không tăng counter on-chain ⇒ `s` lặp ⇒ TÁI
    ///      DÙNG RANDOMNESS ElGamal ⇒ lộ số dư. Lỗi thảm hoạ, phải có test phủ định.
    function sendCounter(ZetherTypes.UA account) external view returns (uint256);
}
