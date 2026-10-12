// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Tầng 1 v2 (kind `META_NONE`, TW2 §4): token tự phát hành, không underlying.
/// @notice Ngữ nghĩa tầng 1 của v1 (`initialSupply` cho `creator`, `minter` tuỳ chọn, `minter == 0` ⇒ cung cố
///         định) cộng `burn` của người giữ và `renounceMinter` một chiều (R141). Trần cung hay giới hạn tốc độ mint
///         nếu issuer cần thì nằm trong hợp đồng minter của họ, không ở đây.
contract NoUnderlyingToken is MetaTokenBase {
    /// @dev Slot 11.
    address public minter;

    event MinterRenounced();

    error NotMinter();

    constructor(address factory_, address subjectAccountImpl_) MetaTokenBase(factory_, subjectAccountImpl_) {}

    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_NONE;
    }

    /// @param initData `abi.encode(string name, string symbol, uint8 decimals, uint256 initialSupply,
    ///        address minter)` — ABI của v1.
    function _init(address creator_, address[] calldata underlyings, bytes calldata initData) internal override {
        if (underlyings.length != 0) revert UnderlyingCountInvalid(underlyings.length);
        (string memory n, string memory s, uint8 d, uint256 supply, address minter_) =
            abi.decode(initData, (string, string, uint8, uint256, address));
        _setMetadata(n, s, d);
        minter = minter_;
        if (supply != 0) _mint(creator_, supply);
    }

    function mint(address to, uint256 amount) external {
        _onlyMinter();
        _mint(to, amount);
    }

    /// @notice Một chiều: sau đó cung cố định mãi mãi.
    function renounceMinter() external {
        _onlyMinter();
        minter = address(0);
        emit MinterRenounced();
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function _onlyMinter() private view {
        if (minter == address(0) || msg.sender != minter) revert NotMinter();
    }
}
