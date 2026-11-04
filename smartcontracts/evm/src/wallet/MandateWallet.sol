// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IERC20Payment} from "../metatx/IERC20Payment.sol";
import {IMetaTokenV2} from "../metatx/IMetaTokenV2.sol";
import {FeeMode} from "../common/FeePolicy.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title The wallet of ONE payer with limited delegated payment (CTR-ACC-06, CTR-ACC-07, CTR-ACC-12), on `UAMetaTxBase`.
/// @notice The payer (`owner`) keeps its key; a delegate (the platform's custody key, or an agent key) may pay only
///         within the mandate the owner set per token, every limit checked here on chain: per payment, per period,
///         approved payees, an expiry, and an `entryRef` that pays once per wallet. No allowance: the funds sit in the
///         wallet, which pays by `payWithFee` (a native payee) or `payWithFeeToUA` (a derived one, CTR-UA-28) as
///         `msg.sender`, so the payment event carries `entryRef` as a manual payment does.
///         Ids are `bytes32` (ua-mtx-merge Q6, spec §2.7): `owner`, the delegate and the payees, a native address
///         zero-padded or a derived UA. Every authority check compares `_subject()` with the stored id, never
///         `_msgSender()` (`UA_POOL` for a derived subject). One signed entry per operation, in the domain
///         `("SCaaS MandateWallet", "1", chainId, wallet, chain_uid)`, fee mode `NONE`, each over its `UA<Op>` struct:
///         the owner's `mtxSetMandate`, `mtxSetPayee`, `mtxRevokeMandate`, `mtxExecute`; the delegate's
///         `mtxPayUnderMandate` and `mtxDelegateRevoke`, whose `batch` is the signer's (the node puts them on
///         `mandatePayLane(entryRef)` / `mandateRevokeLane(token, epoch)` at nonce 0): a signature cannot move lanes,
///         `batch` is signed, and `refUsed` and `epoch` stop a new signature by the delegate for the same payment or
///         revoke. From `UAMetaTxBase`: the generic `mtxExecute` / `mtxBatch` and the ordered `mtxCancelNonce` on ids.
///         A native signer signs with its own key (no registry call); a derived one through `UARegistry`
///         (`UALedgerOff` at registry 0). `executeMetaTransaction` refuses every call (MD-11 (b)).
///         ERC-1271 answers for a native owner (ECDSA), so it also pays by hand with `from = wallet`; a derived owner
///         gets no answer and acts through `mtxExecute`.
contract MandateWallet is UAMetaTxBase, IERC1271 {
    struct Mandate {
        bytes32 delegate;      // 0 = none or revoked
        uint64 expiry;         // unix seconds
        uint64 periodSeconds;
        uint64 periodStart;
        uint128 maxPerPayment;
        uint128 maxPerPeriod;
        uint128 spentInPeriod;
    }

    bytes32 public immutable owner;
    mapping(address token => Mandate) public mandates;
    mapping(address token => mapping(bytes32 payee => bool)) public payeeAllowed;
    mapping(bytes32 entryRef => bool) public refUsed;
    /// @notice Bumped by every `setMandate` and every revoke (CTR-ACC-07): a delegate's signed pay and revoke name it.
    mapping(address token => uint64) public epoch;

    event MandateSet(address indexed token, bytes32 indexed delegate, uint256 maxPerPayment,
                     uint256 maxPerPeriod, uint256 periodSeconds, uint256 expiry);
    event MandateRevoked(address indexed token, bytes32 indexed by);
    event PayeeSet(address indexed token, bytes32 indexed payee, bool allowed);
    event PaidUnderMandate(address indexed token, bytes32 indexed payee, uint256 amount, bytes32 indexed entryRef);

    error NotOwner();
    error NotDelegate();
    error NoMandate();
    error MandateExpired();
    error PayeeNotAllowed(bytes32 payee);
    error OverPaymentCap(uint256 amount, uint256 cap);
    error OverPeriodCap(uint256 wouldSpend, uint256 cap);
    error RefAlreadyPaid(bytes32 entryRef);
    error StaleEpoch(uint64 current, uint64 signed);
    error CallFailed(bytes reason);
    error ZeroOwner();
    error BadMandate();
    error PayFailed();

    modifier onlyOwner() {
        if (_subject() != owner) revert NotOwner();
        _;
    }

    /// @param chainUid_ the chain's `chain_uid` from its profile (CTR-GEN-05); the node checks `chainUid()` before relaying.
    /// @param registry_ the chain's UA registry, needed only when a side is derived (0: `UALedgerOff` for a derived id).
    /// @param hedera_   HIP-632 for a 64-byte signature from an account without code (`HederaMandateWallet`).
    constructor(bytes32 owner_, bytes32 chainUid_, address registry_, bool hedera_)
        UAMetaTxBase("SCaaS MandateWallet", chainUid_, registry_, address(0), hedera_)
    {
        if (owner_ == 0) revert ZeroOwner();
        owner = owner_;
    }

    receive() external payable {}

    // ------------------------------------------------------------------ owner

    function setMandate(address token, bytes32 delegate, uint128 maxPerPayment, uint128 maxPerPeriod,
                        uint64 periodSeconds, uint64 expiry) external nonReentrant onlyOwner {
        // periodSeconds == 0 would reset the period cap at every payment.
        if (delegate == 0 || periodSeconds == 0 || maxPerPayment == 0
            || maxPerPayment > maxPerPeriod) revert BadMandate();
        // Same delegate and period length: the running period and what it spent carry over, so an edit (a new expiry,
        // new caps) never grants a fresh period budget; a new delegate or period length (or a revoke first) restarts it.
        Mandate storage md = mandates[token];
        bool keep = md.delegate == delegate && md.periodSeconds == periodSeconds;
        mandates[token] = Mandate(delegate, expiry, periodSeconds, keep ? md.periodStart : uint64(block.timestamp),
                                  maxPerPayment, maxPerPeriod, keep ? md.spentInPeriod : 0);
        ++epoch[token];
        emit MandateSet(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry);
    }

    function setPayee(address token, bytes32 payee, bool allowed) external nonReentrant onlyOwner {
        payeeAllowed[token][payee] = allowed;
        emit PayeeSet(token, payee, allowed);
    }

    function revoke(address token) external nonReentrant onlyOwner {
        _revoke(token);
    }

    /// @notice The owner does what it wants with its funds (withdraw, move, pay by hand).
    function execute(address target, uint256 value, bytes calldata data)
        external nonReentrant onlyOwner returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    // ------------------------------------------------------------------ delegate

    /// @notice The delegate's payment: `_subject()` is the mandate's delegate, `epoch_` the current epoch (so a revoke,
    ///         or any `setMandate`, voids every pay signed before it, also when the same delegate is set again), the
    ///         mandate is live, the payee approved, `0 < amount ≤ maxPerPayment`, the period total `≤ maxPerPeriod`,
    ///         `entryRef` unused. Periods are fixed windows of `periodSeconds` on the grid of `periodStart` (CTR-ACC-06):
    ///         at most `2 · maxPerPeriod` across one boundary, at boundaries the owner can compute.
    function payUnderMandate(address token, bytes32 payee, uint256 amount, bytes32 entryRef, uint64 epoch_)
        external nonReentrant
    {
        Mandate storage md = mandates[token];
        if (md.delegate == 0) revert NoMandate();
        if (_subject() != md.delegate) revert NotDelegate();
        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);
        if (block.timestamp > md.expiry) revert MandateExpired();
        if (!payeeAllowed[token][payee]) revert PayeeNotAllowed(payee);
        if (amount == 0 || amount > md.maxPerPayment) revert OverPaymentCap(amount, md.maxPerPayment);
        if (refUsed[entryRef]) revert RefAlreadyPaid(entryRef);
        if (block.timestamp >= uint256(md.periodStart) + md.periodSeconds) {
            // the window that holds `now` on the grid of the mandate's start (W-L): a pause never moves the boundaries
            md.periodStart += uint64((block.timestamp - md.periodStart) / md.periodSeconds * md.periodSeconds);
            md.spentInPeriod = 0;
        }
        uint256 spent = uint256(md.spentInPeriod) + amount;
        if (spent > md.maxPerPeriod) revert OverPeriodCap(spent, md.maxPerPeriod);
        md.spentInPeriod = uint128(spent);
        refUsed[entryRef] = true;
        bool paid = UAKinds.inNativeSpace(payee)
            ? IERC20Payment(token).payWithFee(address(uint160(uint256(payee))), amount, FeeMode.NONE, 0, address(0), entryRef)
            : IMetaTokenV2(token).payWithFeeToUA(payee, amount, FeeMode.NONE, 0, address(0), entryRef);
        if (!paid) revert PayFailed();
        emit PaidUnderMandate(token, payee, amount, entryRef);
    }

    /// @notice The platform's kill switch: the delegate revokes its own mandate, bound to the current epoch so a public
    ///         revoke signature cannot delete a mandate the owner re-established (CTR-ACC-07).
    function revoke(address token, uint64 epoch_) external nonReentrant {
        Mandate storage md = mandates[token];
        if (md.delegate == 0) revert NoMandate();
        if (_subject() != md.delegate) revert NotDelegate();
        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);
        _revoke(token);
    }

    // ------------------------------------------------------------------ one signed entry per operation (Q6)

    /// @notice The owner's signed `setMandate`: struct `UASetMandate`, submitted by anyone.
    function mtxSetMandate(MetaTxLib.UAEnvelope calldata e, address token, bytes32 delegate, uint128 maxPerPayment,
        uint128 maxPerPeriod, uint64 periodSeconds, uint64 expiry, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        return _namedUA(_UA_SET_MANDATE_TYPEHASH, MandateWallet.setMandate.selector, e,
            abi.encode(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry), auth);
    }

    /// @notice The owner's signed `setPayee`: struct `UASetPayee`.
    function mtxSetPayee(MetaTxLib.UAEnvelope calldata e, address token, bytes32 payee, bool allowed,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        return _namedUA(_UA_SET_PAYEE_TYPEHASH, MandateWallet.setPayee.selector, e, abi.encode(token, payee, allowed), auth);
    }

    /// @notice The owner's signed `revoke(token)`: struct `UARevokeMandate`.
    function mtxRevokeMandate(MetaTxLib.UAEnvelope calldata e, address token, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        return _namedUA(_UA_REVOKE_MANDATE_TYPEHASH, _REVOKE_OWNER, e, abi.encode(token), auth);
    }

    /// @notice The delegate's signed `payUnderMandate`: struct `UAPayUnderMandate`, bound to `epoch_` (CTR-ACC-07).
    function mtxPayUnderMandate(MetaTxLib.UAEnvelope calldata e, address token, bytes32 payee, uint256 amount,
        bytes32 entryRef, uint64 epoch_, IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        return _namedUA(_UA_PAY_UNDER_MANDATE_TYPEHASH, MandateWallet.payUnderMandate.selector, e,
            abi.encode(token, payee, amount, entryRef, epoch_), auth);
    }

    /// @notice The delegate's signed `revoke(token, epoch)`: struct `UADelegateRevoke`, bound to `epoch_` (CTR-ACC-07).
    function mtxDelegateRevoke(MetaTxLib.UAEnvelope calldata e, address token, uint64 epoch_,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        return _namedUA(_UA_DELEGATE_REVOKE_TYPEHASH, _REVOKE_SIGNED, e, abi.encode(token, epoch_), auth);
    }

    /// @notice The owner's signed `execute`: struct `UAExecute`, `data` signed as its hash; the wallet shows target and
    ///         value, `data` stays hex.
    function mtxExecute(MetaTxLib.UAEnvelope calldata e, address target, uint256 value, bytes calldata data,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        return _namedCallUA(_UA_EXECUTE_TYPEHASH, e, abi.encode(target, value, keccak256(data)),
            abi.encodeCall(MandateWallet.execute, (target, value, data)), auth);
    }

    // ------------------------------------------------------------------ views

    function mandatePayLane(bytes32 entryRef) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.mandate.pay", entryRef)));
    }

    function mandateRevokeLane(address token, uint64 epoch_) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.mandate.revoke", token, epoch_)));
    }

    /// @inheritdoc IERC1271
    /// @dev A native owner: ECDSA by its address. A derived owner has no ERC-1271 answer (CTR-ACC-12).
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        if (!UAKinds.inNativeSpace(owner)) return bytes4(0xffffffff);
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && rec == address(uint160(uint256(owner)))
            ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    /// @notice The allowlist (CTR-MTX-19): the base `cancelNonce`, the delegate's two, the owner's four; fee `NONE` only.
    function mtxSelectors() public pure override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a) {
        s = new bytes4[](7);
        c = new uint8[](7);
        a = new uint8[](7);
        s[0] = IMetaTx.cancelNonce.selector;
        s[1] = MandateWallet.payUnderMandate.selector;
        s[2] = _REVOKE_SIGNED;
        s[3] = MandateWallet.setMandate.selector;
        s[4] = MandateWallet.setPayee.selector;
        s[5] = _REVOKE_OWNER;
        s[6] = MandateWallet.execute.selector;
        for (uint256 i; i < 7; ++i) c[i] = FEE_CLASS_ABSOLUTE;
    }

    // ------------------------------------------------------------------ internals

    bytes4 private constant _REVOKE_OWNER = bytes4(keccak256("revoke(address)"));
    bytes4 private constant _REVOKE_SIGNED = bytes4(keccak256("revoke(address,uint64)"));
    bytes32 private constant _UA_SET_MANDATE_TYPEHASH = keccak256(
        "UASetMandate(bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant _UA_SET_PAYEE_TYPEHASH = keccak256(
        "UASetPayee(bytes32 from,address token,bytes32 payee,bool allowed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant _UA_REVOKE_MANDATE_TYPEHASH = keccak256(
        "UARevokeMandate(bytes32 from,address token,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant _UA_PAY_UNDER_MANDATE_TYPEHASH = keccak256(
        "UAPayUnderMandate(bytes32 from,address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant _UA_DELEGATE_REVOKE_TYPEHASH = keccak256(
        "UADelegateRevoke(bytes32 from,address token,uint64 epoch,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant _UA_EXECUTE_TYPEHASH = keccak256(
        "UAExecute(bytes32 from,address target,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    /// @dev A native subject reads `_mtxRule` (B): the six wallet operations and the base `cancelNonce`.
    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == MandateWallet.payUnderMandate.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 164);
        if (sel == _REVOKE_SIGNED) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == MandateWallet.setMandate.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 196);
        if (sel == MandateWallet.setPayee.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (sel == _REVOKE_OWNER) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == MandateWallet.execute.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    /// @dev A derived subject reads this list only (B): the six wallet operations; `cancelNonce` is not on it (its body
    ///      refuses `UA_POOL`; a derived id cancels through `mtxCancelNonce`).
    function _uaAllowed(bytes4 sel) internal pure override returns (bool) {
        return sel == MandateWallet.payUnderMandate.selector || sel == _REVOKE_SIGNED
            || sel == MandateWallet.setMandate.selector || sel == MandateWallet.setPayee.selector
            || sel == _REVOKE_OWNER || sel == MandateWallet.execute.selector;
    }

    /// @dev `executeMetaTransaction` refuses every call (MD-11 (b)): the EIP-1776 alias is the token's exception (R3).
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata) internal pure override returns (bytes memory) {
        revert MtxSelectorNotAllowed(bytes4(m.data));
    }

    function _revoke(address token) private {
        delete mandates[token];
        ++epoch[token];
        emit MandateRevoked(token, _subject());
    }
}
