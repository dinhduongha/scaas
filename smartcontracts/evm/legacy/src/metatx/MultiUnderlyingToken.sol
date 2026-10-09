// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {SingleUnderlyingToken} from "./SingleUnderlyingToken.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Tầng 3 v2 (kind `META_MULTI`, TW2 §8, R136): wrapper ANY-OF của 2–8 underlying.
/// @notice Wrap MỘT underlying chọn được, unwrap ra MỘT underlying chọn được, trong giới hạn reserve của chân đó.
///         Tập underlying và thứ tự chân cố định từ lúc tạo, không thêm, không bớt. Bất biến là tổng hợp:
///         `Σ⌊reserve_i·q_i⌋ ≥ totalSupply()` — không có bất biến theo chân, backing là chung.
///
///         Rủi ro depeg (§8.4): ở tỉ lệ danh nghĩa token coi các underlying là ngang nhau; khi một chân mất giá,
///         ai cũng wrap được chân rẻ và unwrap chân tốt. Người giữ mang rủi ro của underlying tệ nhất trong tập,
///         và khoá admin của MỖI underlying lấy được cả rổ (review L12).
///
///         `guardian` (tuỳ chọn, có thể là EOA) có đúng một quyền: `disableWrap` — một chiều; unwrap khỏi chân đã
///         tắt vẫn mở. Tỉ lệ điều chỉnh được theo chân là tuỳ chọn lúc tạo (R147, mặc định tắt): rủi ro còn lại ở §8.5.
contract MultiUnderlyingToken is SingleUnderlyingToken {
    uint256 internal constant MAX_LEGS = 8;

    /// @dev Slot 15.
    address public guardian;

    event WrapDisabled(address indexed underlying, address indexed guardian, bytes32 reason);
    event GuardianRenounced();

    error UnderlyingRequired();
    error NotGuardian();

    constructor(address factory_, address subjectAccountImpl_) SingleUnderlyingToken(factory_, subjectAccountImpl_) {}

    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_MULTI;
    }

    /// @param initData `abi.encode(string name, string symbol, uint8 decimals, uint96[] nums, uint96[] dens,
    ///        RateConfig cfg, address guardian)`; hai mảng dài bằng `underlyings`.
    function _init(address, address[] calldata underlyings, bytes calldata initData) internal override {
        uint256 n = underlyings.length;
        if (n < 2 || n > MAX_LEGS) revert UnderlyingCountInvalid(n);
        (string memory nm, string memory sy, uint8 d, uint256[] memory nums, uint256[] memory dens,
            RateConfig memory cfg, address guardian_) =
            abi.decode(initData, (string, string, uint8, uint256[], uint256[], RateConfig, address));
        if (nums.length != n) revert UnderlyingCountInvalid(nums.length);
        if (dens.length != n) revert UnderlyingCountInvalid(dens.length);
        _setMetadata(nm, sy, d);
        _setRateConfig(cfg);
        for (uint256 i; i < n; ++i) _addLeg(underlyings[i], nums[i], dens[i]);
        guardian = guardian_;
    }

    // ------------------------------------------------------------------ wrap / unwrap theo chân

    function wrap(address u, uint256 amount) external nonReentrant returns (uint256 minted) {
        return _wrap(_legOf(u), amount);
    }

    function unwrap(address u, uint256 wrapped, address recipient, uint256 minOut)
        external nonReentrant returns (uint256 out, uint256 burned)
    {
        return _unwrap(_legOf(u), wrapped, recipient, minOut);
    }

    /// @notice ABI một tài sản thừa kế: không có chân mặc định.
    function wrap(uint256) external pure override returns (uint256) {
        revert UnderlyingRequired();
    }

    function unwrap(uint256, address) external pure override returns (uint256) {
        revert UnderlyingRequired();
    }

    function unwrap(uint256, address, uint256) external pure override returns (uint256) {
        revert UnderlyingRequired();
    }

    /// @notice Không có underlying duy nhất; client đọc `underlyings()`.
    function underlying() external pure override returns (address) {
        return address(0);
    }

    // ------------------------------------------------------------------ guardian

    /// @notice Một chiều. Không mở lại: một guardian bị chiếm mà mở lại được một dòng vào đã mất giá thì rút
    ///         cạn các chân tốt. Tắt nhầm là vĩnh viễn cho chân đó; người giữ không mất gì.
    function disableWrap(address u, bytes32 reason) external {
        _onlyGuardian();
        Leg storage L = _legs[_legOf(u)];
        if (!L.wrapEnabled) revert WrapDisabledFor(u);
        L.wrapEnabled = false;
        emit WrapDisabled(u, msg.sender, reason);
    }

    function renounceGuardian() external {
        _onlyGuardian();
        guardian = address(0);
        emit GuardianRenounced();
    }

    function _onlyGuardian() private view {
        if (guardian == address(0) || msg.sender != guardian) revert NotGuardian();
    }
}
