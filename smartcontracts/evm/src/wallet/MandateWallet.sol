// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IERC20Payment} from "../metatx/IERC20Payment.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title The wallet of ONE payer with limited delegated payment (CTR-ACC-06, CTR-ACC-07), on `MetaTxBase`.
/// @notice The payer (`owner`) keeps its key; a delegate (the platform's custody key, or an agent key) may pay only
///         within the mandate the owner set per token, every limit checked here on chain: per payment, per period,
///         approved payees, an expiry, and an `entryRef` that pays once per wallet. No allowance: the funds sit in the
///         wallet, which pays by `IERC20Payment.payWithFee` as `msg.sender`, so `PaymentSettled` carries `entryRef`
///         as a manual payment does. Every signed action is a `MetaTransaction` self-call (domain `("SCaaS
///         MandateWallet", "1", chainId, wallet, chain_uid)`, fee mode `NONE`): the delegate signs
///         `payUnderMandate(…, epoch)` and `revoke(token, epoch)`; the owner signs `setMandate`, `setPayee`,
///         `revoke(token)` and `execute`. `mtxPayUnderMandate`, `mtxRevoke` and `mtxExecuteAsOwner` are the named builders and derive
///         their lanes. ERC-1271 answers for the owner (ECDSA), so the owner also pays by hand with `from = wallet`.
contract MandateWallet is MetaTxBase, IERC1271 {
    struct Mandate {
        address delegate;      // 0 = none or revoked
        uint64 expiry;         // unix seconds
        uint64 periodSeconds;
        uint64 periodStart;
        uint128 maxPerPayment;
        uint128 maxPerPeriod;
        uint128 spentInPeriod;
    }

    address public immutable owner;
    mapping(address token => Mandate) public mandates;
    mapping(address token => mapping(address payee => bool)) public payeeAllowed;
    mapping(bytes32 entryRef => bool) public refUsed;
    /// @notice Bumped by every `setMandate` and every revoke (CTR-ACC-07): a delegate's signed pay and revoke name it.
    mapping(address token => uint64) public epoch;

    event MandateSet(address indexed token, address indexed delegate, uint256 maxPerPayment,
                     uint256 maxPerPeriod, uint256 periodSeconds, uint256 expiry);
    event MandateRevoked(address indexed token, address indexed by);
    event PayeeSet(address indexed token, address indexed payee, bool allowed);
    event PaidUnderMandate(address indexed token, address indexed payee, uint256 amount, bytes32 indexed entryRef);

    error NotOwner();
    error NotDelegate();
    error NoMandate();
    error MandateExpired();
    error PayeeNotAllowed(address payee);
    error OverPaymentCap(uint256 amount, uint256 cap);
    error OverPeriodCap(uint256 wouldSpend, uint256 cap);
    error RefAlreadyPaid(bytes32 entryRef);
    error StaleEpoch(uint64 current, uint64 signed);
    error CallFailed(bytes reason);
    error ZeroOwner();
    error BadMandate();
    error PayFailed();

    modifier onlyOwner() {
        if (_msgSender() != owner) revert NotOwner();
        _;
    }

    /// @param chainUid_ the chain's `chain_uid` from its profile (CTR-GEN-05); the node checks `chainUid()` before relaying.
    constructor(address owner_, bytes32 chainUid_) MetaTxBase("SCaaS MandateWallet", chainUid_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    receive() external payable {}

    // ------------------------------------------------------------------ owner

    function setMandate(address token, address delegate, uint128 maxPerPayment, uint128 maxPerPeriod,
                        uint64 periodSeconds, uint64 expiry) external nonReentrant onlyOwner {
        // periodSeconds == 0 would reset the period cap at every payment.
        if (delegate == address(0) || periodSeconds == 0 || maxPerPayment == 0
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

    function setPayee(address token, address payee, bool allowed) external nonReentrant onlyOwner {
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

    /// @notice The delegate's payment: `_msgSender()` is the mandate's delegate, `epoch_` the current epoch (so a revoke,
    ///         or any `setMandate`, voids every pay signed before it, also when the same delegate is set again), the
    ///         mandate is live, the payee approved, `0 < amount ≤ maxPerPayment`, the period total `≤ maxPerPeriod`,
    ///         `entryRef` unused.
    function payUnderMandate(address token, address payee, uint256 amount, bytes32 entryRef, uint64 epoch_)
        external nonReentrant
    {
        Mandate storage md = mandates[token];
        if (md.delegate == address(0)) revert NoMandate();
        if (_msgSender() != md.delegate) revert NotDelegate();
        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);
        if (block.timestamp > md.expiry) revert MandateExpired();
        if (!payeeAllowed[token][payee]) revert PayeeNotAllowed(payee);
        if (amount == 0 || amount > md.maxPerPayment) revert OverPaymentCap(amount, md.maxPerPayment);
        if (refUsed[entryRef]) revert RefAlreadyPaid(entryRef);
        if (block.timestamp >= uint256(md.periodStart) + md.periodSeconds) {
            md.periodStart = uint64(block.timestamp);
            md.spentInPeriod = 0;
        }
        uint256 spent = uint256(md.spentInPeriod) + amount;
        if (spent > md.maxPerPeriod) revert OverPeriodCap(spent, md.maxPerPeriod);
        md.spentInPeriod = uint128(spent);
        refUsed[entryRef] = true;
        if (!IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, address(0), entryRef)) revert PayFailed();
        emit PaidUnderMandate(token, payee, amount, entryRef);
    }

    /// @notice The platform's kill switch: the delegate revokes its own mandate, bound to the current epoch so a public
    ///         revoke signature cannot delete a mandate the owner re-established (CTR-ACC-07).
    function revoke(address token, uint64 epoch_) external nonReentrant {
        Mandate storage md = mandates[token];
        if (md.delegate == address(0)) revert NoMandate();
        if (_msgSender() != md.delegate) revert NotDelegate();
        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);
        _revoke(token);
    }

    // ------------------------------------------------------------------ named builders (CTR-MTX-21)

    /// @notice `MetaTransaction{from: delegate, data: payUnderMandate(…, epoch), batch: mandatePayLane(entryRef),
    ///         nonce: 0}`.
    function mtxPayUnderMandate(address token, address payee, uint256 amount, bytes32 entryRef, uint64 epoch_,
                                uint256 validUntil, bytes calldata sig) external nonReentrant {
        _named(_delegateOf(token),
            abi.encodeCall(MandateWallet.payUnderMandate, (token, payee, amount, entryRef, epoch_)),
            mandatePayLane(entryRef), 0, validUntil, sig);
    }

    /// @notice `MetaTransaction{from: delegate, data: revoke(token, epoch), batch: mandateRevokeLane(token, epoch), nonce: 0}`.
    function mtxRevoke(address token, uint64 epoch_, uint256 validUntil, bytes calldata sig) external nonReentrant {
        _named(_delegateOf(token), abi.encodeWithSelector(_REVOKE_SIGNED, token, epoch_),
            mandateRevokeLane(token, epoch_), 0, validUntil, sig);
    }

    /// @notice `MetaTransaction{from: owner, data, batch: 0, nonce}`.
    function mtxExecuteAsOwner(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(owner, data, 0, nonce, validUntil, sig);
    }

    // ------------------------------------------------------------------ views

    function mandatePayLane(bytes32 entryRef) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.mandate.pay", entryRef)));
    }

    function mandateRevokeLane(address token, uint64 epoch_) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.mandate.revoke", token, epoch_)));
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && rec == owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
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

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == MandateWallet.payUnderMandate.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 164);
        if (sel == _REVOKE_SIGNED) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == MandateWallet.setMandate.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 196);
        if (sel == MandateWallet.setPayee.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (sel == _REVOKE_OWNER) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == MandateWallet.execute.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    function _delegateOf(address token) private view returns (address d) {
        d = mandates[token].delegate;
        if (d == address(0)) revert NoMandate();
    }

    /// @dev The named builders' struct: no relayer or fee binding (mode 0, fee 0), run through the base pipeline.
    function _named(address from, bytes memory data, uint256 batch, uint256 nonce, uint256 validUntil,
                    bytes calldata sig) internal returns (bytes memory) {
        MetaTxLib.MetaTransaction memory m;
        m.from = from;
        m.data = data;
        m.batch = batch;
        m.nonce = nonce;
        m.validUntil = validUntil;
        return _execute(m, sig);
    }

    function _revoke(address token) private {
        delete mandates[token];
        ++epoch[token];
        emit MandateRevoked(token, _msgSender());
    }
}
