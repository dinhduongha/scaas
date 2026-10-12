// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "../../../src/metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../../src/metatx/IMetaTx.sol";
import {FeeMode} from "../../../src/common/FeePolicy.sol";

/// The smallest token on `ERC20MetaTx`: `burn(uint256)` is `AMOUNT(0)`, `touch()` is `ABSOLUTE` (moves nothing).
contract ERC20MetaTxHarness is ERC20MetaTx {
    event Touched(address who);

    constructor(bytes32 chainUid_) ERC20MetaTx(chainUid_, address(0)) {}

    function mint(address to, uint256 v) external { _mint(to, v); }

    function burn(uint256 v) external nonReentrant { _burn(_msgSender(), v); }

    function touch() external nonReentrant { emit Touched(_msgSender()); }

    /// Not allowlisted: `payWithFee` lives in `MetaTokenBase`; the harness only satisfies the interface.
    function payWithFee(address, uint256, FeeMode, uint256, address, bytes32) external pure returns (bool) {
        revert("harness");
    }

    function mtxSelectors()
        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](3);
        c = new uint8[](3);
        a = new uint8[](3);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
        (s[2], c[2]) = (this.touch.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.burn.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        if (sel == this.touch.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        return super._mtxRule(sel);
    }
}
