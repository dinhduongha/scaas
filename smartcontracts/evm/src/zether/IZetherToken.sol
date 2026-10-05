// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20MetaTx} from "../metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";

/// @title Token có số dư bí mật (SRS §7, §9.3). Kế thừa TOÀN BỘ meta-transaction từ tầng nền.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Đặc tả byte-exact:
///         `docs/superpowers/specs/2026-10-03-zether-design.md`. Chỗ lệch SRS: ruling RS2-n ở §16.
interface IZetherToken is IERC20MetaTx {
    /// @notice Ảnh chụp một tài khoản tại MỘT block (canon C5.2). Điểm rỗng = `O`.
    struct AccountState {
        bytes accC;
        bytes accD;
        bytes pendingC;
        bytes pendingD;
        uint64 accSeq;
        uint64 pendingSeq;
        uint64 sendCounter;
        uint64 modeNonce;
        ZetherTypes.RollOverMode mode;
    }

    event Funded(ZetherTypes.UA indexed account, uint256 amount);
    event ConfidentialTransfer(
        ZetherTypes.UA indexed from,
        ZetherTypes.UA indexed to,
        ZetherTypes.UA indexed beneficiary,
        uint256 fee,
        uint256 sendCounter,
        bytes32 entryRef
    );
    event Burned(ZetherTypes.UA indexed account, uint256 amount, address indexed recipient);
    event RolledOver(ZetherTypes.UA indexed account, uint256 accSeq);
    event RollOverModeChanged(ZetherTypes.UA indexed account, ZetherTypes.RollOverMode mode);

    error AccountNotRegistered(ZetherTypes.UA account);
    error AmountOutOfRange(uint256 amount, uint256 max);
    error ProofRejected();
    error StaleAccSeq(uint256 expected, uint256 got);
    error StaleSendCounter(uint256 expected, uint256 got);
    error SelfTransfer();
    error BadPayload(uint256 length);
    error RollOverOwnerOnly(ZetherTypes.UA account);
    error RollOverExpired(uint256 validUntilBlock);
    error PendingSeqMismatch(uint256 expected, uint256 got);
    error ZeroRecipient();
    error EscrowInvariant(uint256 held, uint256 owed);
    error UnsupportedUnderlying();
    error ZetherOpNotCanonical();

    // ------------------------------------------------------------------ tham số per-token (bất biến)

    /// @notice Trần tổng số dư che giấu (đơn vị che giấu), `≤ 2^54` (đặc tả §1).
    function maxDecryptableShielded() external view returns (uint256);
    /// @notice Raw unit underlying cho một đơn vị che giấu (RS2-3).
    function shieldScale() external view returns (uint256);
    /// @notice Phí tầng trong, cố định theo token, `< 2^64` (`2^n_v`) và `< maxDecryptableShielded`. Không bao giờ là hàm của `v`.
    function confidentialFee() external view returns (uint256);
    /// @notice Khoá auditor (`ITransferDisclosure.AUDITOR`), rỗng nếu tắt. Bất biến (RS2-8).
    function auditorKey() external view returns (bytes memory);
    function totalShielded() external view returns (uint256);

    // ------------------------------------------------------------------ vòng đời

    function registered(ZetherTypes.UA account) external view returns (bool);
    function accountState(ZetherTypes.UA account) external view returns (AccountState memory);
    function sendCounter(ZetherTypes.UA account) external view returns (uint256);

    /// @notice `PUBLIC`: ai cũng gộp được; no-op im lặng khi không có gì mới. `OWNER_ONLY`: revert.
    function rollOverPublic(ZetherTypes.UA account) external;
    /// @notice Bỏ qua phần tử `OWNER_ONLY`, không revert cả lô.
    function rollOverBatch(ZetherTypes.UA[] calldata accounts) external;
    /// @notice Đường có chữ ký (bắt buộc cho `OWNER_ONLY`), digest §5.
    function rollOverSigned(ZetherTypes.UA account, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external;
    function setRollOverMode(
        ZetherTypes.UA account,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig
    ) external;

    /// @notice Kéo `amount · shieldScale` underlying (spender = token này, R26) ⇒ `pending += [amount]G`.
    function fund(bytes calldata encodedY, uint256 amount) external;

    /// @notice Chuyển bí mật, lời gọi thẳng (§10): `msg.sender` tự trả gas nên không có phí ngoài —
    ///         phí ngoài sống trong phong bì meta-tx (RS2-14).
    function transferConfidential(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary
    ) external returns (bytes32 entryRef);

    /// @notice Rút ra underlying công khai; `recipient` và `amount` nằm trong statement.
    function burn(
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        bytes calldata proof,
        bytes calldata authSig
    ) external;

    /// @notice Underlying ⇄ số dư ERC-20 công khai 1:1 (để trả phí ngoài).
    function wrap(uint256 amount) external;
    function unwrap(uint256 amount, address recipient) external;

    // ------------------------------------------------------------------ cho prover / SDK

    /// @notice Statement §6 mà token sẽ dựng tại block này. `envelopeBinding = 0` ⇒ DIRECT.
    function transferStatement(bytes calldata payload, ZetherTypes.UA beneficiary, bytes32 envelopeBinding)
        external view returns (bytes memory);
    function burnStatement(
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory);
    /// @notice §10: binding của một phong bì (mọi trường trừ `data`).
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);

    // ------------------------------------------------------------------ xuất xứ

    function verifier() external view returns (IZetherVerifier);
    function registry() external view returns (address);
    function factory() external view returns (address);
    function creator() external view returns (address);
    function implementation() external view returns (address);
    function version() external view returns (uint64);
    function underlying() external view returns (address);
}
