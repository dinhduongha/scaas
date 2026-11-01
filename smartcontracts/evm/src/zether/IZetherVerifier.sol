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
    ///      triệu chứng lúc deploy. Factory gọi hàm này và từ chối nếu false. It also requires G1MSM to refuse a point
    ///      outside the subgroup, which the merged check rests on (zether.md §9.1).
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
    ///      Precondition: the header's `fee` and `amount` enter E5 mod `r`, a congruence, with no range check here. The token
    ///      bounds `fee < 2^64` and `0 < amount ≤ maxShielded ≤ 2^54` first, so `E5` holds over the integers (§8.1, §8.2).
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
///        generators, checks the 64-bit range proofs for the curve's transfer and burn verifiers, which fix it in their
///        constructor, and runs the one MSM of the merged check (zether.md §9.1, CTR-ZTH-53).
interface IZetherInnerProductVerifier is IZetherVerifierCommon {
    /// @notice The caller's side of the merged check, before the range proofs. A fold slot is a position of
    ///         `G ‖ Hb ‖ U ‖ G_0..63 ‖ H_0..63 ‖ points`.
    /// @param rho the fold challenge; `≡ 0` mod `r` and the call answers false.
    /// @param weight the weight of the first range-proof equation: must be `ρ^e ≠ 0` after the caller's `e` equations; `≡ 0`
    ///        mod `r` would switch every range equation off, and the call answers false.
    /// @param points the caller's untrusted points, concatenated, slots from 131.
    /// @param scalars the caller's weighted sum per slot, `131 + points` entries.
    /// @param commitments the slot of each range proof's commitment `V`, in proof order.
    struct SigmaFold {
        uint256 rho;
        uint256 weight;
        bytes points;
        uint256[] scalars;
        uint256[] commitments;
    }

    /// @notice The SSTORE2 data contract of the generator blob (`0x00 ‖ blob`).
    function generatorStore() external view returns (address);

    /// @notice One range proof (`n = 64`) of `V` on the running transcript `st`, its two equations folded alone; returns the
    ///         verdict and the new state.
    /// @dev Precondition: `V` is not absorbed here; `st` must already bind `V` (the caller absorbs it, as `_ctx` does
    ///      as `"sigma.commit"`). With an unbound `st` the proof is a weak-Fiat-Shamir forgery target.
    function verifyRange(bytes32 st, bytes calldata V, bytes calldata proof) external view returns (bool, bytes32);

    /// @notice The merged check: `rangeProofs` (`BP(64)` concatenated) on the running transcript `st`, their equations added to
    ///         `sigma`, and one MSM that must equal `O`.
    /// @dev A pure function of its inputs. The caller owns the soundness of `sigma`: `st` must bind the commitments, and `ρ`
    ///      must hash the full statement and the full proof, this one's `rangeProofs` included (zether.md §9.1).
    function verifyFold(bytes32 st, SigmaFold calldata sigma, bytes calldata rangeProofs) external view returns (bool);
}
