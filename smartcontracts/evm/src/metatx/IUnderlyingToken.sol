// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AdminLib} from "./AdminLib.sol";

/// @title Kind `UNDERLYING` (CTR-TOK-21): 1–8 legs, each an ERC-20 or the native coin (`address(0)`, CTR-TOK-26).
/// @notice Events and errors raised by `UnderlyingLib` (an external library) are declared here so that they are in the
///         token ABI.
interface IUnderlyingToken {
    /// @notice One leg at creation: `underlying` (`address(0)` = the native coin), rate `num/den` (CTR-TOK-04).
    ///         `uint256` so a value `≥ 2^96` reverts `RateInvalid` instead of failing to decode.
    struct LegInit {
        address underlying;
        uint256 num;
        uint256 den;
    }

    /// @notice With `RATE_ADJUSTABLE`: `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000`; without: both 0.
    struct RateConfig {
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    /// @notice The UNDERLYING subset of `TokenConfig` (CTR-TOK-25); `legs[i].underlying == underlyings[i]` of the
    ///         factory call.
    struct UnderlyingInit {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        AdminLib.Roles roles;
        LegInit[] legs;
        RateConfig rate;
    }

    event Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted);
    event Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned,
        uint256 underlyingOut);
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
