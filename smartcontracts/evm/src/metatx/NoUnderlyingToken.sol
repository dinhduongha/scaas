// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Tầng 1 v2 (kind `META_NONE`, TW2 §4): token tự phát hành, không underlying.
/// @notice Ngữ nghĩa tầng 1 của v1 (`initialSupply` cho `creator`, `minter` tuỳ chọn, `minter == 0` ⇒ cung cố
///         định) cộng `burn` của người giữ và `renounceMinter` một chiều (R141). Trần cung hay giới hạn tốc độ mint
///         nếu issuer cần thì nằm trong hợp đồng minter của họ, không ở đây.
contract NoUnderlyingToken is MetaTokenBase {
    /// @dev Slot 8.
    address public minter;

    event MinterRenounced();

    error NotMinter();

    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_)
        MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_)
    {}

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

    /// @notice Allowlisted `AMOUNT(0)` (CTR-MTX-19): gasless through `mtxExecute`.
    function burn(uint256 amount) external nonReentrant {
        _burn(_msgSender(), amount);
    }

    /// @notice The allowlist (CTR-MTX-19): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`.
    function mtxSelectors()
        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](2);
        c = new uint8[](2);
        a = new uint8[](2);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.burn.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        return super._mtxRule(sel);
    }

    function _onlyMinter() private view {
        if (minter == address(0) || _msgSender() != minter) revert NotMinter();
    }
}
