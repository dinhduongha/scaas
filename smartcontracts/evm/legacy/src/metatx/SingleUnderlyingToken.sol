// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {MetaTokenBase} from "./MetaTokenBase.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Tầng 2 v2 (kind `META_SINGLE`, TW2 §5–§6): wrapper một underlying, tỉ lệ `num/den`, reserve nội bộ.
/// @notice Tỉ lệ `q = num/den` = đơn vị wrapped thô trên một đơn vị underlying thô (R133). Mọi đầu ra làm tròn
///         XUỐNG, có lợi cho hợp đồng: `minted = ⌊in·q⌋`, `out = ⌊w/q⌋`, unwrap chỉ đốt `⌈out·q⌉ ≤ w`.
///
///         Bất biến (R134): `collateralValue() = Σ⌊reserve_i·q_i⌋ ≥ totalSupply()`. `reserve` chỉ đổi qua wrap,
///         unwrap, `addReserve`; `balanceOf(this)` thô không định giá gì cả (quà tặng nằm ngoài reserve và bị khoá).
///
///         Tỉ lệ chọn lúc tạo (R135): `fixed` (mặc định, không setter) hoặc `adjustable` qua một `rateAdmin` có code,
///         timelock `rateDelay`, chỉ admin thực thi, một thay đổi chờ cho cả token, và khi có thay đổi chờ thì wrap
///         dừng trên MỌI chân (unwrap vẫn mở, `minOut` bảo vệ người giữ).
contract SingleUnderlyingToken is MetaTokenBase {
    using SafeERC20 for IERC20;

    /// @notice Cấu hình tỉ lệ trong `initData` (TW2 §5.1).
    struct RateConfig {
        bool adjustable;
        address rateAdmin;
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    /// @dev slot a: token ‖ decimals ‖ wrapEnabled ‖ adjustable (bản sao, để wrap tỉ lệ cố định không đọc config);
    ///      slot b: num ‖ den; slot c: reserve.
    struct Leg {
        address token;
        uint8 decimals;
        bool wrapEnabled;
        bool adjustable;
        uint96 num;
        uint96 den;
        uint256 reserve;
    }

    /// @dev Một slot; `eta == 0` ⇒ không có.
    struct PendingRate {
        uint8 leg;
        uint96 num;
        uint96 den;
        uint56 eta;
    }

    uint256 internal constant MAX_RATE = type(uint96).max;
    /// @notice Cửa sổ thực thi sau `eta`. Hết cửa sổ thì thay đổi coi như không có, ở mọi nơi.
    uint256 public constant RATE_WINDOW = 7 days;

    mapping(uint256 => Leg) internal _legs;           // slot 11: mapping, không mảng — không SLOAD độ dài
    mapping(address => uint256) internal _legIndex;   // slot 12: index + 1
    PendingRate internal _pending;                    // slot 13
    // slot 14 (đọc chỉ bởi hàm tỉ lệ)
    address public rateAdmin;
    uint32 public rateDelay;
    uint16 public maxRateStepBps;
    bool public rateAdjustable;

    event Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted);
    event Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned,
        uint256 underlyingOut);
    event ReserveAdded(address indexed from, address indexed underlying, uint256 amount);
    event RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen,
        uint64 eta);
    event RateChangeCancelled(address indexed underlying);
    event RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen);
    event RateAdminRenounced();

    error UnderlyingInvalid(address u);
    error DecimalsUnreadable(address u);
    error DuplicateUnderlying(address u);
    error RateInvalid(uint256 num, uint256 den);
    error RateConfigInvalid();
    error RateAdminNotContract(address a);
    error WrapTooSmall();
    error UnwrapTooSmall();
    error UnwrapBelowMin(uint256 out, uint256 minOut);
    error UnwrapRecipientInvalid(address recipient);
    error InsufficientReserve(address u, uint256 out, uint256 reserve);
    error ReserveShortfall(address u, uint256 balance, uint256 reserve);
    error UnderlyingTransferMismatch(address u, uint256 expected, uint256 actual);
    error UnknownUnderlying(address u);
    error WrapDisabledFor(address u);
    error RateFixed();
    error NotRateAdmin();
    error RateChangePending();
    error NoRateChangePending();
    error RateChangeNotReady(uint64 eta);
    error RateChangeExpired(uint64 eta);
    error RateStepTooLarge();
    error RateChangeUndercollateralized(uint256 collateral, uint256 supply);
    error RateDecreaseWithDisabledLeg();
    error WrapPausedForRateChange(address u);

    constructor(address factory_, address subjectAccountImpl_) MetaTokenBase(factory_, subjectAccountImpl_) {}

    function tokenKind() external pure virtual override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_SINGLE;
    }

    /// @param initData `abi.encode(string name, string symbol, uint8 decimals, uint96 num, uint96 den,
    ///        RateConfig cfg)`. Tỉ lệ giải mã như `uint256` để `≥ 2^96` báo `RateInvalid` thay vì revert rỗng.
    function _init(address, address[] calldata underlyings, bytes calldata initData) internal virtual override {
        if (underlyings.length != 1) revert UnderlyingCountInvalid(underlyings.length);
        (string memory n, string memory s, uint8 d, uint256 num, uint256 den, RateConfig memory cfg) =
            abi.decode(initData, (string, string, uint8, uint256, uint256, RateConfig));
        _setMetadata(n, s, d);
        _setRateConfig(cfg);
        _addLeg(underlyings[0], num, den);
    }

    function _setRateConfig(RateConfig memory cfg) internal {
        if (!cfg.adjustable) {
            if (cfg.rateAdmin != address(0) || cfg.rateDelay != 0 || cfg.maxRateStepBps != 0) {
                revert RateConfigInvalid();
            }
            return;
        }
        if (!_isContract(cfg.rateAdmin)) revert RateAdminNotContract(cfg.rateAdmin);
        if (cfg.rateDelay < 2 days || cfg.rateDelay > 30 days || cfg.maxRateStepBps == 0 || cfg.maxRateStepBps > 1000) {
            revert RateConfigInvalid();
        }
        rateAdmin = cfg.rateAdmin;
        rateDelay = cfg.rateDelay;
        maxRateStepBps = cfg.maxRateStepBps;
        rateAdjustable = true;
    }

    /// @dev Thứ tự chân là thứ tự `underlyings` của factory, không bao giờ đổi.
    function _addLeg(address u, uint256 num, uint256 den) internal {
        _checkUnderlying(u);
        (bool ok, bytes memory ret) = u.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
        if (!ok || ret.length != 32 || uint256(bytes32(ret)) > type(uint8).max) revert DecimalsUnreadable(u);
        if (num == 0 || den == 0 || num > MAX_RATE || den > MAX_RATE) revert RateInvalid(num, den);
        if (_legIndex[u] != 0) revert DuplicateUnderlying(u);
        uint256 i = _legCount;
        _legs[i] = Leg({
            token: u, decimals: uint8(uint256(bytes32(ret))), wrapEnabled: true, adjustable: rateAdjustable,
            num: uint96(num), den: uint96(den), reserve: 0
        });
        _legIndex[u] = i + 1;
        _legCount = uint8(i + 1);
    }

    /// @dev `virtual`: Hedera thêm kiểm HTS (R144).
    function _checkUnderlying(address u) internal virtual {
        if (u == address(0) || u == address(this) || u.code.length == 0) revert UnderlyingInvalid(u);
    }

    // ------------------------------------------------------------------ wrap / unwrap / reserve

    /// @notice Selector v1. Mint đúng phần THỰC nhận theo tỉ lệ, làm tròn xuống.
    function wrap(uint256 amount) external virtual nonReentrant returns (uint256 minted) {
        return _wrap(0, amount);
    }

    /// @notice Selector v1: `minOut = 0`.
    function unwrap(uint256 wrapped, address recipient) external virtual nonReentrant returns (uint256 out) {
        (out,) = _unwrap(0, wrapped, recipient, 0);
    }

    function unwrap(uint256 wrapped, address recipient, uint256 minOut)
        external virtual nonReentrant returns (uint256 out)
    {
        (out,) = _unwrap(0, wrapped, recipient, minOut);
    }

    /// @notice Ai cũng nạp được; không mint. Để issuer thế chấp dư trước một lần hạ tỉ lệ (§6.3); ngoài ra là quà
    ///         tặng nâng backing của mọi người giữ. Chân đã tắt wrap thì từ chối.
    function addReserve(address u, uint256 amount) external nonReentrant {
        Leg storage L = _legs[_legOf(u)];
        if (!L.wrapEnabled) revert WrapDisabledFor(u);
        emit ReserveAdded(msg.sender, u, _pull(L, amount));
    }

    function _wrap(uint256 i, uint256 amount) internal returns (uint256 minted) {
        Leg storage L = _legs[i];
        if (!L.wrapEnabled) revert WrapDisabledFor(L.token);
        if (L.adjustable && _isPending()) revert WrapPausedForRateChange(L.token);
        uint256 received = _pull(L, amount);
        minted = Math.mulDiv(received, L.num, L.den);
        if (minted == 0) revert WrapTooSmall();
        _mint(msg.sender, minted);
        emit Wrapped(msg.sender, L.token, received, minted);
    }

    /// @dev Kéo `amount` từ `msg.sender`, ghi phần đo được vào reserve. Một `balanceOf` trước phục vụ cả kiểm
    ///      thiếu hụt (R134: không wrap/nạp khi `balanceOf < reserve`) lẫn phép đo.
    function _pull(Leg storage L, uint256 amount) private returns (uint256 received) {
        IERC20 u = IERC20(L.token);
        uint256 reserve = L.reserve;
        uint256 before = u.balanceOf(address(this));
        if (before < reserve) revert ReserveShortfall(address(u), before, reserve);
        u.safeTransferFrom(msg.sender, address(this), amount);
        received = u.balanceOf(address(this)) - before;
        L.reserve = reserve + received;
    }

    function _unwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        internal returns (uint256 out, uint256 burned)
    {
        _checkRecipient(recipient);
        out = _quoteUnwrap(_legs[i], wrapped, minOut);
        burned = _settleUnwrap(i, msg.sender, recipient, out);
    }

    function _checkRecipient(address recipient) private view {
        if (recipient == address(0) || recipient == address(this)) revert UnwrapRecipientInvalid(recipient);
    }

    /// @dev Kiểm trọn trước mọi hiệu ứng: `0 < out`, `out ≥ minOut`, `out ≤ reserve`.
    function _quoteUnwrap(Leg storage L, uint256 wrapped, uint256 minOut) private view returns (uint256 out) {
        out = Math.mulDiv(wrapped, L.den, L.num);
        if (out == 0) revert UnwrapTooSmall();
        if (out < minOut) revert UnwrapBelowMin(out, minOut);
        uint256 reserve = L.reserve;
        if (out > reserve) revert InsufficientReserve(L.token, out, reserve);
    }

    /// @dev Hiệu ứng trước (đốt, trừ reserve), rồi lời gọi ngoài duy nhất, dưới guard toàn hợp đồng (CEI). Số dư
    ///      phải giảm ĐÚNG `out`: underlying thu phí người gửi thì revert (R143).
    function _settleUnwrap(uint256 i, address from, address recipient, uint256 out) private returns (uint256 burned) {
        Leg storage L = _legs[i];
        burned = Math.mulDiv(out, L.num, L.den, Math.Rounding.Ceil);
        _burn(from, burned);
        L.reserve -= out;
        IERC20 u = IERC20(L.token);
        uint256 before = u.balanceOf(address(this));
        u.safeTransfer(recipient, out);
        uint256 after_ = u.balanceOf(address(this));
        uint256 sent = before > after_ ? before - after_ : 0;
        if (sent != out) revert UnderlyingTransferMismatch(address(u), out, sent);
        emit Unwrapped(from, address(u), recipient, burned, out);
    }

    // ------------------------------------------------------------------ R148: op unwrap

    function _checkUnwrap(address u, address recipient, address to, uint256 wrapped, uint256 minOut)
        internal view override
    {
        uint256 i = _legOf(u);
        _checkRecipient(recipient);
        if (to != recipient) revert UnwrapRecipientMismatch();
        _quoteUnwrap(_legs[i], wrapped, minOut);
    }

    function _executeUnwrap(address from, address u, address recipient, uint256 wrapped) internal override {
        uint256 i = _legIndex[u] - 1;
        Leg storage L = _legs[i];
        _settleUnwrap(i, from, recipient, Math.mulDiv(wrapped, L.den, L.num));
    }

    // ------------------------------------------------------------------ tỉ lệ (§6.2)

    modifier onlyRateAdmin() {
        if (!rateAdjustable) revert RateFixed();
        if (msg.sender != rateAdmin) revert NotRateAdmin();
        _;
    }

    /// @notice Bước được kiểm MỘT lần, ở đây, so với tỉ lệ hiện tại (tỉ lệ hiện tại không đổi được khi đang chờ).
    function proposeRate(address u, uint96 num, uint96 den) external onlyRateAdmin {
        if (_isPending()) revert RateChangePending();
        uint256 i = _legOf(u);
        if (num == 0 || den == 0) revert RateInvalid(num, den);
        Leg storage L = _legs[i];
        (uint96 n0, uint96 d0) = (L.num, L.den);
        // |num'·den − num·den'|·10⁴ ≤ num·den'·bps — chính xác trong số nguyên, mọi tích < 2^207.
        uint256 a = uint256(num) * d0;
        uint256 b = uint256(n0) * den;
        if ((a > b ? a - b : b - a) * 10_000 > b * maxRateStepBps) revert RateStepTooLarge();
        uint64 eta = uint64(block.timestamp + rateDelay);
        _pending = PendingRate({leg: uint8(i), num: num, den: den, eta: uint56(eta)});
        emit RateChangeProposed(u, n0, d0, num, den, eta);
    }

    function cancelRate() external onlyRateAdmin {
        if (!_isPending()) revert NoRateChangePending();
        address u = _legs[_pending.leg].token;
        delete _pending;
        emit RateChangeCancelled(u);
    }

    /// @notice Chỉ admin (rev 1.2): bên thứ ba không gói được việc thực thi với wrap/unwrap của chính nó.
    function executeRate() external onlyRateAdmin {
        PendingRate memory p = _pending;
        if (p.eta == 0) revert NoRateChangePending();
        if (block.timestamp < p.eta) revert RateChangeNotReady(p.eta);
        if (block.timestamp > uint256(p.eta) + RATE_WINDOW) revert RateChangeExpired(p.eta);
        bool anyDisabled = _requireCollateral(p);
        Leg storage T = _legs[p.leg];
        (uint96 n0, uint96 d0) = (T.num, T.den);
        if (anyDisabled && uint256(p.num) * d0 < uint256(n0) * p.den) revert RateDecreaseWithDisabledLeg();
        T.num = p.num;
        T.den = p.den;
        delete _pending;
        emit RateChanged(T.token, n0, d0, p.num, p.den);
    }

    /// @dev Mọi chân: `balanceOf ≥ reserve` (không reserve ảo, review M1); rồi `C' ≥ totalSupply` với tỉ lệ mới,
    ///      dừng cộng khi đã đủ (review L1) nhưng vẫn kiểm số dư mọi chân. Trả về "có chân nào đã tắt wrap".
    function _requireCollateral(PendingRate memory p) private view returns (bool anyDisabled) {
        uint256 supply = totalSupply();
        uint256 c;
        uint256 n = _legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = _legs[i];
            uint256 r = L.reserve;
            uint256 bal = IERC20(L.token).balanceOf(address(this));
            if (bal < r) revert ReserveShortfall(L.token, bal, r);
            if (!L.wrapEnabled) anyDisabled = true;
            if (c < supply) {
                c = Math.saturatingAdd(c, i == p.leg ? _value(r, p.num, p.den) : _value(r, L.num, L.den));
            }
        }
        if (c < supply) revert RateChangeUndercollateralized(c, supply);
    }

    /// @notice Một chiều: bỏ thay đổi đang chờ, tỉ lệ thành cố định, `rateAdmin = 0` mãi mãi.
    function renounceRateAdmin() external onlyRateAdmin {
        delete _pending;
        rateAdmin = address(0);
        rateAdjustable = false;
        emit RateAdminRenounced();
    }

    function _isPending() internal view returns (bool) {
        uint256 eta = _pending.eta;
        return eta != 0 && block.timestamp <= eta + RATE_WINDOW;
    }

    // ------------------------------------------------------------------ view

    /// @notice Underlying duy nhất (tầng 2). Tầng 3 trả `address(0)`.
    function underlying() external view virtual returns (address) {
        return _legs[0].token;
    }

    function underlyings() external view returns (address[] memory us) {
        uint256 n = _legCount;
        us = new address[](n);
        for (uint256 i; i < n; ++i) us[i] = _legs[i].token;
    }

    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals_, bool wrapEnabled)
    {
        Leg storage L = _legs[_legOf(u)];
        return (L.num, L.den, L.reserve, L.decimals, L.wrapEnabled);
    }

    /// @notice `Σ⌊reserve_i·num_i/den_i⌋`, bão hoà ở `type(uint256).max` thay vì tràn (review L1).
    function collateralValue() external view returns (uint256 c) {
        uint256 n = _legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = _legs[i];
            c = Math.saturatingAdd(c, _value(L.reserve, L.num, L.den));
        }
    }

    /// @notice `(⌊amount·q⌋, ⌈minted/q⌉)`: client làm tròn `amount` xuống `used` để không để bụi trong reserve.
    ///         Bỏ qua phí-chuyển (giả định `received == amount`).
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used) {
        Leg storage L = _legs[_legOf(u)];
        minted = Math.mulDiv(amount, L.num, L.den);
        used = Math.mulDiv(minted, L.den, L.num, Math.Rounding.Ceil);
    }

    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned) {
        Leg storage L = _legs[_legOf(u)];
        out = Math.mulDiv(wrapped, L.den, L.num);
        burned = Math.mulDiv(out, L.num, L.den, Math.Rounding.Ceil);
    }

    /// @notice Toàn 0 khi không có gì chờ hoặc thay đổi đang chờ đã hết cửa sổ.
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta) {
        if (!_isPending()) return (address(0), 0, 0, 0);
        PendingRate memory p = _pending;
        return (_legs[p.leg].token, p.num, p.den, p.eta);
    }

    function _legOf(address u) internal view returns (uint256) {
        uint256 x = _legIndex[u];
        if (x == 0) revert UnknownUnderlying(u);
        return x - 1;
    }

    /// @dev `⌊r·num/den⌋`, bão hoà khi kết quả vượt 256 bit (`mulDiv` sẽ revert).
    function _value(uint256 r, uint256 num, uint256 den) internal pure returns (uint256) {
        (uint256 hi,) = Math.mul512(r, num);
        return hi >= den ? type(uint256).max : Math.mulDiv(r, num, den);
    }
}
