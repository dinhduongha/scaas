// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {SdkGasRows} from "./SdkGasOps.sol";

/// The gas of one inner call: `gasleft()` around a `CALL` to `t` with `d` (in memory before the first read), no return data
/// copied; a revert is passed on.
contract SdkGasMeter {
    function measure(address t, bytes calldata d) external returns (uint256 used) {
        bytes memory m = d;
        bool ok;
        uint256 g0 = gasleft();
        assembly ("memory-safe") { ok := call(gas(), t, 0, add(m, 32), mload(m), 0, 0) }
        used = g0 - gasleft();
        if (!ok) {
            assembly ("memory-safe") {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }
}

/// A row whose transaction sits on EIP-7976's calldata floor (a small call with a long struct: an order's cancel) hides its
/// execution gas in the transaction's total; such a row is measured inside the transaction instead: the call by
/// `SdkGasMeter`, itself the isolated top-level call (so every account and slot the call touches is cold, as on chain), less
/// `SG_METER_CALL`, what the meter's `CALL` adds over the call being the transaction's own (a cold callee, 3,000, against a
/// warm `to`, and the meter's own opcodes between its two `gasleft` reads); the meter's figure holds the call's state gas
/// (EIP-8037's charge comes out of `gasleft`). `SG_METER_CALL` is held by `_meterControl`: a row
/// off the floor measured both ways gives the same figure.
abstract contract SdkGasMetered is SdkGasRows {
    uint256 internal constant SG_METER_CALL = 3_038;
    SdkGasMeter internal sgMeter;

    /// The call `cd` to `c`, measured by the meter: the meter's figure less `SG_METER_CALL` (regular and state gas), its
    /// state part the transaction's, pinned as `_measure` pins them.
    function _measureMetered(string memory key, address c, bytes memory cd) internal returns (uint256 g) {
        if (address(sgMeter) == address(0)) sgMeter = new SdkGasMeter();
        vm.prank(SG_RELAYER);
        uint256 used = sgMeter.measure(c, cd);
        Vm.Gas memory u = vm.lastFrameGas();
        uint256 state = uint256(int256(u.gasStateUsed));
        g = used - SG_METER_CALL;
        _pin(string.concat(key, "_regular"), g - state);
        _pin(string.concat(key, "_state"), state);
        _pin(key, g);
    }

    /// `SG_METER_CALL` held: the call `cd` to `c`, off the floor, measured as the transaction (`_measure`) and by the meter
    /// give the same figure (`key` pinned by the first; nothing else pinned).
    function _meterControl(address c, bytes memory cd) internal {
        if (address(sgMeter) == address(0)) sgMeter = new SdkGasMeter();
        uint256 s = vm.snapshotState();
        vm.prank(SG_RELAYER);
        (bool ok,) = c.call(cd);
        assertTrue(ok, "the control call");
        Vm.Gas memory a = vm.lastFrameGas();
        uint256 tx_ = a.gasTotalUsed - 15_000 - _cdGas(cd) + uint256(int256(a.gasStateUsed));
        vm.revertToState(s);
        vm.prank(SG_RELAYER);
        uint256 used = sgMeter.measure(c, cd);
        Vm.Gas memory b = vm.lastFrameGas();
        vm.revertToState(s);
        assertEq(b.gasStateUsed, a.gasStateUsed, "the same state gas");
        assertEq(used - SG_METER_CALL, tx_, "SG_METER_CALL");
    }
}
