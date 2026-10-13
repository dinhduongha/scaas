// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";

/// @title Kind `UNDERLYING` (CTR-TOK-21): 1–8 legs, each an ERC-20 or the native coin (`address(0)`, CTR-TOK-26).
/// @notice Events and errors raised by `UnderlyingLib` (an external library) are declared here so that they are in the
///         token ABI. The creation config is `IFactoryToken.TokenConfig` (`legs`, `rate`).
interface IUnderlyingToken {
    event Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted);
    event Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned,
        uint256 underlyingOut);
    /// @notice `unwrapToUA` (accounts.md CTR-UA-28): `account` is `UA_POOL` under a derived subject (its burn's
    ///         `UATransfer(ua, 0)` names the UA).
    event UnwrappedToUA(address indexed account, address indexed underlying, bytes32 indexed to, uint256 burned,
        uint256 out);
    event ReserveAdded(address indexed from, address indexed underlying, uint256 amount);
    event RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen,
        uint64 eta);
    event RateChangeCancelled(address indexed underlying);
    event RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen);
    event WrapDisabled(address indexed underlying, address indexed guardian, bytes32 reason);

    error UnderlyingInvalid(address u);
    error DecimalsUnreadable(address u);
    error DuplicateUnderlying(address u);
    error RateInvalid(uint256 num, uint256 den);
    error RateConfigInvalid();
    error WrapTooSmall();
    error UnwrapTooSmall();
    error UnwrapBelowMin(uint256 out, uint256 minOut);
    error UnwrapRecipientInvalid(address recipient);
    error InsufficientReserve(address u, uint256 out, uint256 reserve);
    error ReserveShortfall(address u, uint256 balance, uint256 reserve);
    error UnderlyingTransferMismatch(address u, uint256 expected, uint256 actual);
    error UnknownUnderlying(address u);
    error WrapDisabledFor(address u);
    error UnderlyingRequired();
    error RateFixed();
    error NotRateAdmin();
    error NotGuardian();
    error RateChangePending();
    error NoRateChangePending();
    error RateChangeNotReady(uint64 eta);
    error RateChangeExpired(uint64 eta);
    error RateStepTooLarge();
    error RateChangeUndercollateralized(uint256 collateral, uint256 supply);
    error RateDecreaseWithDisabledLeg();
    error WrapPausedForRateChange(address u);
    /// @notice `msg.value` must equal `amount` on the native leg and be 0 on any other leg (CTR-TOK-26).
    error NativeValueMismatch(uint256 value, uint256 expected);
    /// @notice `mtxWrap` (CTR-TOK-20): a signature cannot carry coin; the order must buy this token; the underlying
    ///         must deliver exactly `o.amount`.
    error NativeNotGasless();
    error WrapOrderInvalid(address receiveToken);
    error WrapReceivedMismatch(uint256 expected, uint256 received);
    /// @notice Raised by OpenZeppelin inside UnderlyingLib (same selectors), listed for the ABI.
    error FailedCall();
    error SafeERC20FailedOperation(address token);
    error InsufficientBalance(uint256 balance, uint256 needed);
    /// @notice Raised by `HederaLib` at init on Hedera (same selectors), listed here for the ABI.
    error HtsQueryFailed(address u, int64 responseCode);
    error AssociateFailed(int64 responseCode);

    function wrap(uint256 amount) external payable returns (uint256 minted);
    function wrap(address underlying, uint256 amount) external payable returns (uint256 minted);
    function unwrap(uint256 wrapped, address recipient) external returns (uint256 out);
    function unwrap(uint256 wrapped, address recipient, uint256 minOut) external returns (uint256 out);
    function unwrap(address underlying, uint256 wrapped, address recipient, uint256 minOut)
        external returns (uint256 out, uint256 burned);
    function addReserve(address underlying, uint256 amount) external payable;
    /// @notice `wrap(underlying, amount)` minted into the registered SIGNING UA `to` (CTR-UA-28).
    function wrapToUA(address underlying, uint256 amount, bytes32 to) external payable returns (uint256 minted);
    /// @notice `unwrap(underlying, …)` paid into `to` in the leg's UA ledger; the leg must be a SCaaS ledger token.
    function unwrapToUA(address underlying, uint256 wrapped, bytes32 to, uint256 minOut)
        external returns (uint256 out, uint256 burned);
    /// @notice Wrap a SCaaS underlying by the holder's `TradeOrder` (`dex` = this token, `receiveToken` = this
    ///         token, `receiveAmount` = the minimum minted, `minFill = amount`); `fee` pays the submitter in minted units.
    function mtxWrap(address underlying, ITradeToken.TradeOrder calldata o, bytes calldata sig)
        external returns (uint256 minted);
    function disableWrap(address underlying, bytes32 reason) external;
    function proposeRate(address underlying, uint96 num, uint96 den) external;
    function cancelRate() external;
    function executeRate() external;

    function underlying() external view returns (address);
    function underlyings() external view returns (address[] memory);
    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled);
    function collateralValue() external view returns (uint256);
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used);
    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned);
    function rateAdjustable() external view returns (bool);
    function rateDelay() external view returns (uint32);
    function maxRateStepBps() external view returns (uint16);
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta);
}
