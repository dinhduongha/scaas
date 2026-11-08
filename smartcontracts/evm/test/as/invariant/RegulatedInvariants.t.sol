// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {RegCore, RegPublicHandler, RegZetherHandler, RegZetherHandler10, RegZetherHandler11, RegPqzHandler, RegPqzHandler12,
    RegPqzHandler13} from "./RegulatedHandler.t.sol";

interface IRegH {
    function vio(uint256) external view returns (uint256);
    function hits(uint256) external view returns (uint256);
    function calls(uint256) external view returns (uint256);
    function why() external view returns (string memory);
    function errs(uint256) external view returns (bytes4);
    function errCount(bytes4) external view returns (uint256);
    function errsLength() external view returns (uint256);
}

/// Plan T36 (regulated-kinds spec §8): the invariants I1-I13 over the handlers of `RegulatedHandler.t.sol`, one suite per
/// kind 8-13. Each invariant reads its handler's violation count (the first reason in the message); `afterInvariant` logs
/// how often each check had something to check (`-vv`), so a vacuous pass is visible. I0 is `PlusZero.t.sol`; I10's
/// per-signer-class pins are T28's, T30's and T31's tests (here: every regulated refusal of a run within its bound); I11 is
/// `SelectorAudit.t.sol` and the node's `regulated_kinds_rows_equal_contract_*` (no handler state). The PQZ suites run at
/// the four sets (`script/pqz/at-set.sh <set> test --match-contract 'RegInv1[23]'`).
abstract contract RegInvBase is Test {
    IRegH internal h;

    function _sel() internal view virtual returns (bytes4[] memory s);

    function _core(bytes4[] memory s) internal pure {
        (s[0], s[1], s[2], s[3]) = (RegCore.freeze.selector, RegCore.unfreeze.selector, RegCore.recordOrder.selector,
            RegCore.revokeOrder.selector);
        (s[4], s[5], s[6], s[7]) = (RegCore.forceTransfer.selector, RegCore.pause.selector, RegCore.unpause.selector,
            RegCore.operatorTransfer.selector);
        (s[8], s[9], s[10], s[11]) = (RegCore.relax.selector, RegCore.handover.selector, RegCore.attest.selector,
            RegCore.warp.selector);
    }

    function _target(address hh) internal {
        h = IRegH(hh);
        targetContract(hh);
        targetSelector(FuzzSelector(hh, _sel()));
    }

    function _ok(uint256 i) internal view {
        assertEq(h.vio(i), 0, h.why());
    }

    function invariant_I1_supplyAndCollateral() public view { _ok(1); }
    function invariant_I2_forcedTransfers() public view { _ok(2); }
    function invariant_I3_frozenNeverDebited() public view { _ok(3); }
    function invariant_I4_pause() public view { _ok(4); }
    function invariant_I5_receivers() public view { _ok(5); }
    function invariant_I6_regulatedCallsKeepTheRest() public view { _ok(6); }
    function invariant_I7_episodes() public view { _ok(7); }
    function invariant_I8_shieldedUntouched() public view { _ok(8); }
    function invariant_I9_legsUnread() public view { _ok(9); }
    function invariant_I10_refusalGas() public view { _ok(10); }
    function invariant_I12_controlsMirror() public view { _ok(12); }
    function invariant_I13_pendings() public view { _ok(13); }

    /// The family's scripted ledger calls between the record (`_force`) and the relaxation (`_end`), and the invariants it
    /// must reach.
    function _script() internal virtual;
    /// The invariants reached, as a bit mask (bit `k` for I`k`).
    function _reached() internal pure virtual returns (uint256);

    /// A record of `s` for `b`, the record-backed freeze and a force (I2, I3), an issuer-only freeze of id 2 (T1, I7), a pause
    /// and its end (I4), an operator transfer (I6, on 10-13 I8).
    function _force(uint256 s, uint256 b) internal {
        RegCore c = RegCore(address(h));
        c.recordOrder(s, b, 500, 30, 3);
        c.forceTransfer(0, 50);
        c.freeze(2, 0, false);
        c.pause(1 days);
        c.unpause();
        c.operatorTransfer(b, s, 10);
    }

    /// The owner's revoke of the issuer's bit 5, then its confirm in `[eta, eta + gd]` (I13).
    function _end() internal {
        RegCore(address(h)).relax(0, 0, 1, 2);
    }

    /// Non-vacuity: one scripted run reaches every check the family has, and breaks none.
    function test_everyCheckReached() public {
        _script();
        uint256 r = _reached();
        for (uint256 k = 1; k <= 13; ++k) {
            if (r & (1 << k) != 0) assertGt(h.hits(k), 0, string.concat("I", vm.toString(k), " reached"));
        }
        for (uint256 i = 1; i <= 13; ++i) assertEq(h.vio(i), 0, h.why());
    }

    function afterInvariant() public view {
        string memory s = "hits";
        for (uint256 i = 1; i <= 13; ++i) if (i != 11) s = string.concat(s, " I", vm.toString(i), "=", vm.toString(h.hits(i)));
        console.log(s);
        string memory c = "calls ok/tried";
        for (uint256 k; k < 8; ++k) c = string.concat(c, " k", vm.toString(k), "=", vm.toString(h.calls(k + 10)), "/",
            vm.toString(h.calls(k)));
        console.log(c);
        string memory e = "refusals";
        for (uint256 i; i < h.errsLength(); ++i) {
            bytes4 x = h.errs(i);
            e = string.concat(e, " ", vm.toString(abi.encodePacked(x)), "x", vm.toString(h.errCount(x)));
        }
        console.log(e);
    }
}

abstract contract RegInvPublic is RegInvBase {
    function _which() internal pure virtual returns (uint256);

    /// I5 a credit to a frozen `carol`; I10 the relayed transfer of the frozen `alice`, refused by the pre row.
    function _script() internal override {
        _force(0, 1);
        RegPublicHandler p = RegPublicHandler(address(h));
        p.pubTransfer(1, 2, 10);
        p.pubRelayed(0, 1, 10, 1, 3);
        _end();
    }

    /// Every check but I8 and I9 (no shielded state, no legs).
    function _reached() internal pure override returns (uint256) {
        return 0x34FE; // I1-I7, I10, I12, I13
    }

    function setUp() public {
        RegPublicHandler p = new RegPublicHandler(_which());
        p.init();
        _target(address(p));
    }

    function _sel() internal pure override returns (bytes4[] memory s) {
        s = new bytes4[](20);
        _core(s);
        (s[18], s[19]) = (RegCore.forceTransfer.selector, RegCore.recordOrder.selector);
        (s[12], s[13], s[14]) = (RegPublicHandler.pubTransfer.selector, RegPublicHandler.pubRelayed.selector,
            RegPublicHandler.pubPay.selector);
        (s[15], s[16], s[17]) = (RegPublicHandler.pubMint.selector, RegPublicHandler.pubBurn.selector,
            RegPublicHandler.pubOpenRelayed.selector);
    }
}

/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 128
contract RegInv8Test is RegInvPublic {
    function _which() internal pure override returns (uint256) { return 0; }
}

/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 128
contract RegInv9Test is RegInvPublic {
    function _which() internal pure override returns (uint256) { return 1; }
}

/// Zether ≠ PQZ: the Zether suites prove with the test prover (fewer runs, as `ZetherInvariant.t.sol`).
abstract contract RegInvZether is RegInvBase {
    /// I9 `bob` to `carol` (a frozen `alice` aside); I10 the frozen `alice`'s transfer refused before the proof; I5 a public
    /// credit; roll-over.
    function _script() internal override {
        _force(0, 1);
        RegZetherHandler z = RegZetherHandler(address(h));
        z.zTransfer(1, 2, 5);
        z.zTransfer(0, 1, 5);
        z.zRoll(2);
        z.pubTransfer(0, 2, 10);
        _end();
    }

    function _reached() internal pure override returns (uint256) {
        return 0x37FE; // I1-I10, I12, I13
    }

    function _sel() internal pure override returns (bytes4[] memory s) {
        s = new bytes4[](21);
        _core(s);
        (s[12], s[13], s[14]) = (RegZetherHandler.zShield.selector, RegZetherHandler.zWrapShield.selector,
            RegZetherHandler.zRoll.selector);
        (s[15], s[16], s[17]) = (RegZetherHandler.zTransfer.selector, RegZetherHandler.zMulti.selector,
            RegZetherHandler.zUnshield.selector);
        (s[18], s[19]) = (RegZetherHandler.zUnshieldUnwrap.selector, RegZetherHandler.pubTransfer.selector);
        (s[20]) = (RegZetherHandler.zRoll.selector);
    }
}

/// forge-config: default.invariant.runs = 16
/// forge-config: default.invariant.depth = 48
contract RegInv10Test is RegInvZether {
    function setUp() public {
        RegZetherHandler10 z = new RegZetherHandler10();
        z.init();
        _target(address(z));
    }
}

/// forge-config: default.invariant.runs = 16
/// forge-config: default.invariant.depth = 48
contract RegInv11Test is RegInvZether {
    function setUp() public {
        RegZetherHandler11 z = new RegZetherHandler11();
        z.init();
        _target(address(z));
    }
}

abstract contract RegInvPqz is RegInvBase {
    /// The record names `bob` (alice stays the sender): I9 a single to the frozen `bob` and a shield to him; then `alice`
    /// frozen, her transfer refused before the proof (I10); prepare and roll-over; I5 a public credit.
    function _script() internal override {
        _force(1, 2);
        RegPqzHandler q = RegPqzHandler(address(h));
        q.pqTransfer(2, 0, 0, 0);
        q.pqShield(1, 5);
        RegCore(address(h)).freeze(0, 0, false);
        q.pqTransfer(0, 0, 0, 0);
        q.pqRoll(2);
        q.pubTransfer(0, 3, 10);
        _end();
    }

    function _reached() internal pure override returns (uint256) {
        return 0x37FE; // I1-I10, I12, I13
    }

    function _sel() internal pure override returns (bytes4[] memory s) {
        s = new bytes4[](21);
        _core(s);
        (s[12], s[13], s[14]) = (RegPqzHandler.pqShield.selector, RegPqzHandler.pqWrapShield.selector,
            RegPqzHandler.pqTransfer.selector);
        (s[15], s[16], s[17]) = (RegPqzHandler.pqUnshield.selector, RegPqzHandler.pqRefresh.selector,
            RegPqzHandler.pqUnshieldUnwrap.selector);
        (s[18], s[19], s[20]) = (RegPqzHandler.pqRoll.selector, RegPqzHandler.pubTransfer.selector,
            RegPqzHandler.pqTransfer.selector);
    }
}

/// forge-config: default.invariant.runs = 32
/// forge-config: default.invariant.depth = 64
contract RegInv12Test is RegInvPqz {
    function setUp() public {
        RegPqzHandler12 q = new RegPqzHandler12();
        q.init();
        _target(address(q));
    }
}

/// forge-config: default.invariant.runs = 32
/// forge-config: default.invariant.depth = 64
contract RegInv13Test is RegInvPqz {
    function setUp() public {
        RegPqzHandler13 q = new RegPqzHandler13();
        q.init();
        _target(address(q));
    }
}
