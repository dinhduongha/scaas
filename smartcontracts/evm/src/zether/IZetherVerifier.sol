// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Verifier ZK — inject bằng địa chỉ, KHÔNG import thẳng vào token.
///
/// @notice **UNAUDITED.**
///
///         Hai curve cùng được hỗ trợ, không ưu tiên cái nào; mỗi implementation token gắn một curve qua
///         verifier immutable của nó, nên token đã deploy **không đổi được verifier** (đổi verifier dưới một số dư
///         đang lưu hành là đổi nghĩa mọi ciphertext).
///
///         Ngoài kiểm proof, verifier là **nơi duy nhất biết đường cong**: token (một mã nguồn cho mọi curve) làm
///         phép cộng đồng hình qua các hàm `g1*` của transfer verifier. Đặc tả byte-exact:
///         `docs/contracts/zether.md` (bản đóng băng `docs/history/specs/2026-10-03-zether-design.md`).
///
///         CTR-ZTH-20 (owner 2026-10-19): one canonical transfer verifier (`IZetherVerifier`) and one burn verifier
///         (`IZetherBurnVerifier`) per curve, implementation immutables of the token, recorded by `OpenFactory`. The
///         creator no longer passes an address. `IZetherVerifierCommon` is what both answer.
interface IZetherVerifierCommon {
    /// @notice Khoá cứng bộ ba (curve, mạch, mã hoá điểm). Nằm trong statement (§6) ⇒ trong transcript.
    function proofSystemId() external pure returns (bytes32);

    /// @notice Id của transfer nhiều người nhận: nhãn của `proofSystemId` thêm "/multi".
    function proofSystemIdMulti() external pure returns (bytes32);

    /// @notice `"bls12-381"` (the bn254 verifiers, `"bn254"`, are in `legacy/ua6/` since UA-6).
    function curveName() external pure returns (string memory);

    /// @notice **128** cho BLS12-381 (EIP-2537 pad mỗi Fp thành 64 byte; 64 cho bn254 trong `legacy/ua6/`).
    function g1EncodedBytes() external pure returns (uint256);

    /// @notice Bậc nhóm `r` (scalar field).
    function groupOrder() external pure returns (uint256);

    /// @notice Precompile mà verifier cần có thật và trả đúng vector đã biết trên chain này không.
    /// @dev Precompile vắng mặt trả về staticcall THÀNH CÔNG với output rỗng — không revert, không
    ///      triệu chứng lúc deploy. Factory gọi hàm này và từ chối nếu false.
    function isSupportedOnThisChain() external view returns (bool);

    /// @notice Blob generator NUMS `h ‖ U ‖ G_0..G_63 ‖ H_0..H_63` (§3), tính trong constructor.
    function generators() external view returns (bytes memory);
}

/// @title The transfer verifier of a curve: the transfer proofs and the group operations.
interface IZetherVerifier is IZetherVerifierCommon {
    /// @notice Luôn 2: lộ danh tính người gửi/nhận (SRS §7.1), không có anonymity set.
    function ringSize() external pure returns (uint256);

    /// @notice Kiểm proof chuyển khoản (đặc tả §6–§9). `statement` do token dựng từ storage.
    /// @dev Verifier KHÔNG kiểm `chainId`/token trong header — đó là việc của token, nó tự dựng
    ///      header từ `block.chainid`/`address(this)`. Verifier chỉ kiểm `opTag` và `proofSystemId`.
    function verifyTransfer(bytes calldata statement, bytes calldata proof) external view returns (bool);

    /// @notice Transfer tới nhiều người nhận (zether.md §7.1 multi).
    function verifyTransferMulti(bytes calldata statement, bytes calldata proof) external view returns (bool);

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

/// @title The burn verifier of a curve (unshield, unshield-unwrap).
interface IZetherBurnVerifier is IZetherVerifierCommon {
    /// @notice Kiểm proof rút ra dạng công khai. `amount`, `recipient` nằm trong `statement`.
    function verifyBurn(bytes calldata statement, bytes calldata proof) external view returns (bool);
}

/// @title The inner-product (Bulletproof) verifier of a curve (CTR-ZTH-20 split, candidate (2)): it holds the NUMS
///        generators and checks the 64-bit range proofs for the curve's transfer and burn verifiers, which fix it in
///        their constructor.
interface IZetherInnerProductVerifier is IZetherVerifierCommon {
    /// @notice The SSTORE2 data contract of the generator blob (`0x00 ‖ blob`).
    function generatorStore() external view returns (address);

    /// @notice One range proof (`n = 64`) of `V` on the running transcript `st`; returns the verdict and the new state.
    /// @dev Precondition: `V` is not absorbed here; `st` must already bind `V` (the caller absorbs it, as `_ctx` does
    ///      as `"sigma.commit"`). With an unbound `st` the proof is a weak-Fiat-Shamir forgery target.
    function verifyRange(bytes32 st, bytes calldata V, bytes calldata proof) external view returns (bool, bytes32);
}
