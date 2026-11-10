// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Kind `WRAPPED` (CTR-TOK-21): 1–8 legs, each an ERC-20 or the native coin (`address(0)`, CTR-TOK-26).
/// @notice Events and errors raised by `WrappedLib` (an external library) are declared here so that they are in the
///         token ABI. The creation config is `IFactoryToken.TokenConfig` (`legs`, `rate`).
interface IWrappedToken {
    /// @notice One wrap or unwrap limit of a leg (group 3l, spec 2026-11-10-wrap-limits.md §2, §6): `perUser` quanta per id
    ///         and window, `tokenWide` quanta for all ids together, each off at 0; `period` the fixed window in seconds, a
    ///         whole number of minutes, `60 ≤ period ≤ (2^23 − 1)·60` when a part is on, 0 when both are off.
    struct WrapLimit {
        uint24 perUser;
        uint64 tokenWide;
        uint32 period;
    }

    /// @notice A leg's limits, in quanta of `10^unitExp` raw units of `underlying` (fixed by the first configuration);
    ///         `decayDays` the horizon `H` of the net-wrapped entitlement's linear decay, 0 = off (§2.1).
    struct WrapLegLimits {
        address underlying;
        uint8 unitExp;
        uint16 decayDays;
        WrapLimit wrapShort;
        WrapLimit wrapLong;
        WrapLimit unwrapShort;
        WrapLimit unwrapLong;
    }

    /// @notice A window's state (§7): `left` in raw units, `type(uint256).max` when the part is off; `resetAt` the end of
    ///         the active window, 0 when none is active.
    struct WindowView {
        uint256 left;
        uint64 resetAt;
    }

    /// @notice An id's quota on one leg (§7): the four per-user windows, `netWrapped` (`b`, undecayed, raw units), the
    ///         `entitlement` now (raw units; `type(uint256).max` when no rule applies or for a redeemer), the time the
    ///         decayed entitlement reaches 0 (0 without the decay; the start is an absolute minute, R26), the lists and the
    ///         redeemer role.
    struct WrapQuota {
        WindowView wrapShort;
        WindowView wrapLong;
        WindowView unwrapShort;
        WindowView unwrapLong;
        uint256 netWrapped;
        uint256 entitlement;
        uint64 entitlementZeroAt;
        bool canWrap;
        bool canUnwrap;
        bool redeemer;
    }

    /// @notice A leg's token-wide windows (§7), by name.
    struct WrapQuotaTotal {
        WindowView wrapShort;
        WindowView wrapLong;
        WindowView unwrapShort;
        WindowView unwrapLong;
    }

    /// @notice `account` is credited `minted`: the caller of a direct wrap.
    event Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted);
    event Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned,
        uint256 underlyingOut);
    /// @notice `unwrapToUA` (accounts.md CTR-UA-28): `account` is `UA_POOL` under a derived subject (its burn's
    ///         `UATransfer(ua, 0)` names the UA).
    event UnwrappedToUA(address indexed account, address indexed underlying, bytes32 indexed to, uint256 burned,
        uint256 out);
    /// @notice `mtxWrapOrder` (CTR-TOK-20, UA-5b): `to` is credited `minted`: the order's `destination` (or `from`) and the
    ///         units net of the submitter's fee (W-Q).
    event UAWrapped(bytes32 indexed to, address indexed underlying, uint256 underlyingIn, uint256 minted);
    event ReserveAdded(address indexed from, address indexed underlying, uint256 amount);
    event RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen,
        uint64 eta);
    event RateChangeCancelled(address indexed underlying);
    event RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen);
    event WrapDisabled(address indexed underlying, bytes32 indexed guardian, bytes32 reason);
    /// @notice Group 3l (§7): a configuration applied; one that waits the factory's `noticePeriod()`; a list membership.
    event WrapLimitsSet(bytes32 indexed by, WrapLegLimits[] legs, bool netUnwrap, bool wrapList, bool unwrapList);
    event WrapLimitsProposed(bytes32 indexed by, uint64 eta, WrapLegLimits[] legs, bool netUnwrap, bool wrapList,
        bool unwrapList);
    event WrapMemberSet(bytes32 indexed account, bytes32 indexed by, bool canWrap, bool canUnwrap);

    error UnderlyingInvalid(address u);
    error DecimalsUnreadable(address u);
    error DuplicateUnderlying(address u);
    error RateInvalid(uint256 num, uint256 den);
    error RateConfigInvalid();
    /// @notice At creation `MINTABLE` without `maxSupply`, or `maxSupply` without `MINTABLE` (spec §5.2).
    error MaxSupplyInvalid();
    /// @notice A hybrid's cap (spec §5.2): a wrap, a wrap order or a mint would take `totalSupply()` to `supply`.
    error MaxSupplyExceeded(uint256 supply, uint256 maxSupply);
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
    /// @notice `mtxWrapOrder` (CTR-TOK-20): a signature cannot carry coin; the order must buy this token; the underlying
    ///         must deliver exactly `o.amount`.
    error NativeNotGasless();
    error WrapOrderInvalid(address receiveToken);
    error WrapReceivedMismatch(uint256 expected, uint256 received);
    /// @notice Raised by OpenZeppelin inside WrappedLib (same selectors), listed for the ABI.
    error FailedCall();
    error SafeERC20FailedOperation(address token);
    error InsufficientBalance(uint256 balance, uint256 needed);
    /// @notice Raised by `HederaLib` at init on Hedera (same selectors), listed here for the ABI.
    error HtsQueryFailed(address u, int64 responseCode);
    error AssociateFailed(int64 responseCode);
    /// @notice Group 3l (§7), amounts in the leg's raw units; `limit` 0 `wrapShort`, 1 `wrapLong`, 2 `unwrapShort`, 3
    ///         `unwrapLong`.
    error WrapLimitExceeded(address underlying, uint8 limit, bytes32 account, uint256 amount, uint256 remaining);
    error WrapCapExceeded(address underlying, uint8 limit, uint256 amount, uint256 remaining);
    error UnwrapAboveNetWrapped(address underlying, bytes32 account, uint256 amount, uint256 entitlement);
    error WrapperNotListed(bytes32 account);
    error UnwrapperNotListed(bytes32 account);
    error WrapLimitInvalid(address underlying, uint8 limit);
    error WrapLegMismatch(uint256 index, address underlying);
    error WrapUnitInvalid(address underlying, uint8 unitExp);
    /// @notice Bits 25, 26, 27 at the creation of a pure-wrap token (`maxSupply == 0`, R12).
    error WrapControlNeedsHybrid(uint8 bit);
    /// @notice `disableFeature` of bit 25, 26 or 27 while a control under it is on (27: while it has holders).
    error WrapControlActive(uint8 bit);
    /// @notice An unwrap check with no subject (`holder == 0`) on a token with a wrap control on.
    error WrapSubjectZero();

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
    /// @notice Wrap a SCaaS underlying by the holder's `UAWrapOrder` (CTR-TOK-20, UA-5b; R39): the order is the
    ///         underlying's `UATradeOrder` with `dex` = `receiveToken` = this token; a derived holder needs a ledger
    ///         underlying, and a leg with no `mtxTrade` is refused (`UALegNotLedger` both); `minted − fee` to `o.destination` (0 ⇒ `o.from`), a derived id into the UA
    ///         ledger; `fee` pays the submitter in minted units.
    function mtxWrapOrder(address underlying, ITradeToken.UAWrapOrder calldata o, IUARegistry.UASig calldata auth)
        external returns (uint256 minted);
    /// @notice The named typed entries (TS-D14): the envelope, the op's own parameters, the signature.
    function mtxWrap(MetaTxLib.Envelope calldata e, uint256 amount, bytes calldata sig) external returns (bytes memory);
    function mtxWrapLeg(MetaTxLib.Envelope calldata e, address underlying, uint256 amount, bytes calldata sig)
        external returns (bytes memory);
    function mtxWrapToUA(MetaTxLib.Envelope calldata e, address underlying, uint256 amount, bytes32 to, bytes calldata sig)
        external returns (bytes memory);
    function mtxAddReserve(MetaTxLib.Envelope calldata e, address underlying, uint256 amount, bytes calldata sig)
        external returns (bytes memory);
    /// @notice The unwraps' pairs on ids (R23): a native id by its own key, a derived UA through the registry.
    function mtxUnwrap(MetaTxLib.UAEnvelope calldata e, uint256 wrapped, address recipient, uint256 minOut,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxUnwrapLeg(MetaTxLib.UAEnvelope calldata e, address underlying, uint256 wrapped, address recipient,
        uint256 minOut, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxUnwrapToUA(MetaTxLib.UAEnvelope calldata e, address underlying, uint256 wrapped, bytes32 to, uint256 minOut,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    /// @notice A hybrid's issuer (spec §5.2): `MINTABLE` and its holder, under `maxSupply`, into a public balance.
    function mint(address to, uint256 amount) external;
    function mintToUA(bytes32 to, uint256 amount) external;
    function disableWrap(address underlying, bytes32 reason) external;
    function proposeRate(address underlying, uint96 num, uint96 den) external;
    function cancelRate() external;
    function executeRate() external;
    /// @notice Group 3l (§6): the owner's limits of every leg (in leg order), the net rule and the two lists; a wrap-side
    ///         relaxation or an unwrap-side tightening waits the factory's `noticePeriod()` (two calls), the rest applies
    ///         at once. Reached through `GovernanceRouter`.
    function setWrapLimits(WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList) external;
    /// @notice Bit 26's holder: `account`'s membership of the wrapper and unwrapper lists, at once.
    function setWrapMember(bytes32 account, bool canWrap, bool canUnwrap) external;

    function underlying() external view returns (address);
    function underlyings() external view returns (address[] memory);
    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled);
    function collateralValue() external view returns (uint256);
    /// @notice The hybrid's cap on `totalSupply()`, wraps included; 0 = not a hybrid, fully backed (spec §5.5).
    function maxSupply() external view returns (uint256);
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used);
    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned);
    function rateAdjustable() external view returns (bool);
    function rateDelay() external view returns (uint32);
    function maxRateStepBps() external view returns (uint16);
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta);
    /// @notice Group 3l (§7): the configuration in force and the pending one.
    ///         `delay`: the factory's `noticePeriod()` in force (0: every change applies at once).
    function wrapLimits() external view returns (WrapLegLimits[] memory legs, bool netUnwrap, bool wrapList, bool unwrapList,
        bytes32 pendingCommit, uint64 pendingEta, bool pendingLive, uint64 delay);
    function wrapQuotaOf(bytes32 account, address underlying) external view returns (WrapQuota memory);
    function wrapQuotaTotal(address underlying) external view returns (WrapQuotaTotal memory);
}
