// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20Payment} from "../metatx/IERC20Payment.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Ví của MỘT người trả, uỷ quyền có giới hạn cho thanh toán tự động (ruling R25).
/// @notice Người trả (`owner`) giữ khoá; platform giữ một khoá `delegate` (qua custody
///         adapter) chỉ tiêu được trong mandate mà owner đặt — mọi giới hạn kiểm Ở ĐÂY,
///         on-chain: hạn mức mỗi lần, hạn mức mỗi kỳ, danh sách người nhận, hạn dùng, và
///         một `entryRef` chỉ trả được một lần.
///
///         Không allowance: tiền nằm trong ví, và ví trả bằng `IERC20Payment.payWithFee`
///         với chính nó là `msg.sender`. `PaymentSettled` vẫn mang `entryRef`, nên Odoo đối
///         soát y hệt một thanh toán tay. Owner vẫn trả tay được từ ví này qua meta-tx: ví
///         hiện thực ERC-1271 cho chữ ký của owner.
contract MandateWallet is EIP712, IERC1271 {
    struct Mandate {
        address delegate;      // 0 = không có / đã thu hồi
        uint64 expiry;         // unix giây
        uint64 periodSeconds;
        uint64 periodStart;
        uint128 maxPerPayment;
        uint128 maxPerPeriod;
        uint128 spentInPeriod;
    }

    bytes32 public constant PAY_TYPEHASH = keccak256(
        "PayUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256 validUntil)");
    bytes32 public constant REVOKE_TYPEHASH = keccak256("RevokeMandate(address token,uint256 validUntil)");
    bytes32 public constant OWNER_CALL_TYPEHASH =
        keccak256("OwnerCall(bytes data,uint256 nonce,uint256 validUntil)");

    address public immutable owner;
    mapping(address token => Mandate) public mandates;
    mapping(address token => mapping(address payee => bool)) public payeeAllowed;
    mapping(bytes32 entryRef => bool) public refUsed;
    uint256 public ownerNonce;

    event MandateSet(address indexed token, address indexed delegate, uint256 maxPerPayment,
                     uint256 maxPerPeriod, uint256 periodSeconds, uint256 expiry);
    event MandateRevoked(address indexed token, address indexed by);
    event PayeeSet(address indexed token, address indexed payee, bool allowed);
    event PaidUnderMandate(address indexed token, address indexed payee, uint256 amount, bytes32 indexed entryRef);

    error NotOwner();
    error NoMandate();
    error MandateExpired();
    error SignatureExpired();
    error PayeeNotAllowed(address payee);
    error OverPaymentCap(uint256 amount, uint256 cap);
    error OverPeriodCap(uint256 wouldSpend, uint256 cap);
    error RefAlreadyPaid(bytes32 entryRef);
    error BadSignature();
    error BadNonce();
    error CallFailed(bytes reason);
    error ZeroOwner();
    error BadMandate();
    error PayFailed();

    modifier onlyOwner() {
        if (msg.sender != owner && msg.sender != address(this)) revert NotOwner();
        _;
    }

    constructor(address owner_) EIP712("SCaaS MandateWallet", "1") {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    // ------------------------------------------------------------------ owner

    function setMandate(address token, address delegate, uint128 maxPerPayment, uint128 maxPerPeriod,
                        uint64 periodSeconds, uint64 expiry) external onlyOwner {
        // periodSeconds == 0 sẽ reset hạn mức kỳ ở MỌI lần trả (review W5).
        if (delegate == address(0) || periodSeconds == 0 || maxPerPayment == 0
            || maxPerPayment > maxPerPeriod) revert BadMandate();
        mandates[token] = Mandate(delegate, expiry, periodSeconds, uint64(block.timestamp),
                                  maxPerPayment, maxPerPeriod, 0);
        emit MandateSet(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry);
    }

    function setPayee(address token, address payee, bool allowed) external onlyOwner {
        payeeAllowed[token][payee] = allowed;
        emit PayeeSet(token, payee, allowed);
    }

    function revoke(address token) external onlyOwner {
        _revoke(token);
    }

    /// @notice Owner làm gì cũng được với tiền của mình (rút về, đổi chỗ).
    function execute(address target, uint256 value, bytes calldata data)
        external onlyOwner returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    /// @notice Gasless cho owner: owner ký, ai cũng nộp được (relayer). Mọi hàm `onlyOwner`
    ///         đi qua đây với `msg.sender == address(this)`.
    function executeAsOwner(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata sig)
        external returns (bytes memory)
    {
        if (block.timestamp > validUntil) revert SignatureExpired();
        if (nonce != ownerNonce) revert BadNonce();
        if (ECDSA.recover(ownerCallDigest(data, nonce, validUntil), sig) != owner) revert BadSignature();
        ownerNonce = nonce + 1;
        (bool ok, bytes memory ret) = address(this).call(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    // ------------------------------------------------------------------ delegate

    /// @notice Ai cũng nộp được; quyền đến từ chữ ký của delegate, giới hạn đến từ mandate.
    function payUnderMandate(address token, address payee, uint256 amount, bytes32 entryRef,
                             uint256 validUntil, bytes calldata sig) external {
        Mandate storage md = mandates[token];
        if (md.delegate == address(0)) revert NoMandate();
        if (block.timestamp > md.expiry) revert MandateExpired();
        if (block.timestamp > validUntil) revert SignatureExpired();
        if (!payeeAllowed[token][payee]) revert PayeeNotAllowed(payee);
        if (amount == 0 || amount > md.maxPerPayment) revert OverPaymentCap(amount, md.maxPerPayment);
        if (refUsed[entryRef]) revert RefAlreadyPaid(entryRef);
        if (ECDSA.recover(payDigest(token, payee, amount, entryRef, validUntil), sig) != md.delegate) {
            revert BadSignature();
        }
        if (block.timestamp >= uint256(md.periodStart) + md.periodSeconds) {
            md.periodStart = uint64(block.timestamp);
            md.spentInPeriod = 0;
        }
        uint256 spent = uint256(md.spentInPeriod) + amount;
        if (spent > md.maxPerPeriod) revert OverPeriodCap(spent, md.maxPerPeriod);
        md.spentInPeriod = uint128(spent);
        refUsed[entryRef] = true;
        if (!IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, address(0), entryRef)) {
            revert PayFailed();
        }
        emit PaidUnderMandate(token, payee, amount, entryRef);
    }

    /// @notice Kill switch của platform: delegate tự thu hồi quyền của chính nó, nộp qua relayer.
    function revokeWithSig(address token, uint256 validUntil, bytes calldata sig) external {
        Mandate storage md = mandates[token];
        if (md.delegate == address(0)) revert NoMandate();
        if (block.timestamp > validUntil) revert SignatureExpired();
        if (ECDSA.recover(revokeDigest(token, validUntil), sig) != md.delegate) revert BadSignature();
        _revoke(token);
    }

    // ------------------------------------------------------------------ views

    function payDigest(address token, address payee, uint256 amount, bytes32 entryRef, uint256 validUntil)
        public view returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(PAY_TYPEHASH, token, payee, amount, entryRef, validUntil)));
    }

    function revokeDigest(address token, uint256 validUntil) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REVOKE_TYPEHASH, token, validUntil)));
    }

    function ownerCallDigest(bytes calldata data, uint256 nonce, uint256 validUntil) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(OWNER_CALL_TYPEHASH, keccak256(data), nonce, validUntil)));
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && rec == owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    function _revoke(address token) private {
        delete mandates[token];
        emit MandateRevoked(token, msg.sender);
    }
}
