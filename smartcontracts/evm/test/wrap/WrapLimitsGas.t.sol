// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {WrapLimitsBase} from "./WrapLimitsBase.sol";

/// Group 3l, plan T100 (wrap limits spec §10): the gas of a wrap and an unwrap, each its own transaction (`isolate`,
/// `vm.lastCallGas`): a hybrid without the bits, with them never configured, and tracked (the net rule and a per-user
/// window on), the id's first use (a new quota slot) and a later one. Pinned; a move is old -> new in the commit. UNAUDITED.
contract WrapLimitsGasTest is WrapLimitsBase {
    function _g() internal view returns (uint256) {
        return vm.lastCallGas().gasTotalUsed;
    }

    function _pair(WrappedToken w) internal returns (uint256 wrap1, uint256 wrap2, uint256 unwrap1, uint256 unwrap2) {
        _fundW(w, alice, 300);
        vm.prank(alice);
        w.wrap(u, 100);
        wrap1 = _g();
        vm.prank(alice);
        w.wrap(u, 100);
        wrap2 = _g();
        vm.prank(alice);
        w.unwrap(u, 50, alice, 0);
        unwrap1 = _g();
        vm.prank(alice);
        w.unwrap(u, 50, alice, 0);
        unwrap2 = _g();
    }

    function test_gas_wrapUnwrap() public {
        (uint256 a1, uint256 a2, uint256 a3, uint256 a4) = _pair(_hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE), u, 1));
        (uint256 b1, uint256 b2, uint256 b3, uint256 b4) = _pair(_hyb());
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 730, L(1000, 0, 1 days), OFF(), L(1000, 0, 1 days), OFF()), true, false, false);
        (uint256 c1, uint256 c2, uint256 c3, uint256 c4) = _pair(w);
        emit log_named_uint("off: wrap first", a1);
        emit log_named_uint("off: wrap later", a2);
        emit log_named_uint("off: unwrap first", a3);
        emit log_named_uint("off: unwrap later", a4);
        emit log_named_uint("bits, unconfigured: wrap first", b1);
        emit log_named_uint("bits, unconfigured: wrap later", b2);
        emit log_named_uint("bits, unconfigured: unwrap first", b3);
        emit log_named_uint("bits, unconfigured: unwrap later", b4);
        emit log_named_uint("tracked: wrap first", c1);
        emit log_named_uint("tracked: wrap later", c2);
        emit log_named_uint("tracked: unwrap first", c3);
        emit log_named_uint("tracked: unwrap later", c4);
        assertEq(b2, a2, "+0: a later wrap with the bits unconfigured");
        assertEq(b4, a4, "+0: a later unwrap with the bits unconfigured");
        // the pins (group 3l, new): regular gas of the transaction (EIP-8037 state gas apart)
        assertEq(a1, 114_814, "off wrap");
        assertEq(a3, 113_481, "off unwrap");
        assertEq(b1, 114_814, "unconfigured wrap");
        assertEq(b3, 113_481, "unconfigured unwrap");
        assertEq(c1, 135_718, "tracked wrap first");
        assertEq(c2, 135_855, "tracked wrap later");
        assertEq(c3, 140_032, "tracked unwrap first");
        assertEq(c4, 140_446, "tracked unwrap later");
    }
}
