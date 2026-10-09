// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Exposes `_chargeFee` of the base (no override).
contract ChargeFeeHarness is MtxRegistryMock {
    constructor(bytes32 uid) MtxRegistryMock("SCaaS TestRegistry", uid) {}

    function exposedChargeFee(MetaTxLib.MetaTransaction calldata m) external returns (uint256) {
        return _chargeFee(m.from, 0, m);
    }
}

/// What a token does in P1b: overrides `_chargeFee` and reports `0xF3`. Records the basis it was given.
contract FeeProbe is MtxRegistryMock {
    error FeeFailed();

    uint256 public lastBasis;
    uint256 public calls;
    uint256 public lastCount; // count[from] seen inside the hook: proves the call already ran
    uint256[] public bases;

    function f(address, uint256) external nonReentrant {}
    function g() external nonReentrant {}

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.f.selector) return MtxRule(FEE_CLASS_AMOUNT, 1, 0);
        if (sel == this.g.selector) return MtxRule(3, 0, 0);
        return super._mtxRule(sel);
    }

    constructor(bytes32 uid) MtxRegistryMock("SCaaS TestRegistry", uid) {}

    function supportedModes() public pure override returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    function _chargeFee(address from, uint256 basis, MetaTxLib.MetaTransaction memory m)
        internal override returns (uint256)
    {
        if (m.fee == 99) revert FeeFailed();
        lastBasis = basis;
        lastCount = count[from];
        bases.push(basis);
        calls += 1;
        return m.fee;
    }
}

/// CTR-MTX-20, CTR-MTX-22: fee classes; a contract without a fee override accepts fee mode NONE only.
contract MetaTxBaseFeeTest is MtxFixture {
    function _modeRun(MetaTxLib.MetaTransaction memory m, uint32 mode, bytes memory err) internal {
        m.mode = mode;
        m.fee = 1;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        if (err.length != 0) vm.expectRevert(err);
        reg.mtxExecute(m, sig);
    }

    function test_supportedModes_flagsOnly() public view {
        assertEq(reg.supportedModes(), 0x03);
    }

    function test_feeModes_refusedWithoutOverride() public {
        bytes4 setNameSel = MtxRegistryMock.setName.selector;
        // ABSOLUTE refuses PERCENT by class
        _modeRun(_m(alice, _setName("a"), 1, 0), MetaTxLib.MODE_FEE_PERCENT,
            abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, setNameSel, MetaTxLib.MODE_FEE_PERCENT));
        // ABSOLUTE admits FIXED by class; supportedModes() = 0x03 refuses it
        _modeRun(_m(alice, _setName("a"), 1, 0), MetaTxLib.MODE_FEE_FIXED,
            abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        // AMOUNT admits PERCENT by class; supportedModes() refuses it
        _modeRun(_m(alice, abi.encodeCall(MtxRegistryMock.bump, (1)), 1, 0), MetaTxLib.MODE_FEE_PERCENT,
            abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_PERCENT));
        // NONE with both flags passes
        MetaTxLib.MetaTransaction memory ok = _m(alice, _setName("a"), 1, 0);
        ok.relayer = relayer;
        ok.feeRecipient = address(0xFEE);
        _modeRun(ok, MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, "");
        assertEq(reg.nameOf(alice), "a");
    }

    function test_chargeFee_refusesAllButNone() public {
        ChargeFeeHarness h = new ChargeFeeHarness(UID);
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        assertEq(h.exposedChargeFee(m), 0);
        m.mode = MetaTxLib.MODE_FEE_PERCENT;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_PERCENT));
        h.exposedChargeFee(m);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        h.exposedChargeFee(m);
    }

    /// The hook contract P1b relies on: fee after the call, basis = argument i for AMOUNT(i), 0 for ABSOLUTE.
    function test_feeHook_basisAndEvent() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (7)), 1, 0);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 3;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(p));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, p.mtxDigest(m), relayer, 3);
        vm.prank(relayer);
        p.mtxExecute(m, sig);
        assertEq(p.lastBasis(), 7);

        MetaTxLib.MetaTransaction memory a = _m(alice, _setName("a"), 1, 1);
        a.mode = MetaTxLib.MODE_FEE_FIXED;
        bytes memory sigA = _sign(ALICE_PK, a);
        vm.prank(relayer);
        p.mtxExecute(a, sigA);
        assertEq(p.lastBasis(), 0);
        assertEq(p.calls(), 2);

        a.nonce = 2;
        a.mode = MetaTxLib.MODE_FEE_PERCENT;
        sigA = _sign(ALICE_PK, a);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, MtxRegistryMock.setName.selector,
            MetaTxLib.MODE_FEE_PERCENT));
        p.mtxExecute(a, sigA);
    }

    /// Step 6 runs after the call: a failing fee reverts the call's effects and the nonce (all or nothing).
    function test_feeFailure_revertsTheCall() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("paid"), 1, 0);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 99;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        vm.expectRevert(FeeProbe.FeeFailed.selector);
        p.mtxExecute(m, sig);
        assertEq(p.nameOf(alice), "");
        assertEq(p.mtxNonce(alice, 1), 0);
    }

    function test_amountArg1_basisAndShortData() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(FeeProbe.f, (bob, 42)), 1, 0);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        p.mtxExecute(m, sig);
        assertEq(p.lastBasis(), 42);

        bytes memory shortData = abi.encodePacked(FeeProbe.f.selector, bytes32(uint256(uint160(bob))));
        MetaTxLib.MetaTransaction memory s = _m(alice, shortData, 1, 1);
        s.mode = MetaTxLib.MODE_FEE_FIXED;
        sig = _sign(ALICE_PK, s);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, FeeProbe.f.selector));
        p.mtxExecute(s, sig);
    }

    function test_feeRunsAfterCall() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (5)), 1, 0);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        p.mtxExecute(m, sig);
        assertEq(p.lastCount(), 5);
    }

    function test_batch_chargesPerItem() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        uint256[2] memory by = [uint256(7), 9];
        for (uint256 i; i < 2; ++i) {
            ms[i] = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (by[i])), 1, i);
            ms[i].mode = MetaTxLib.MODE_FEE_FIXED;
            ms[i].fee = 3 + i;
            sigs[i] = _sign(ALICE_PK, ms[i]);
        }
        for (uint256 i; i < 2; ++i) {
            vm.expectEmit(true, true, true, true, address(p));
            emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, i, p.mtxDigest(ms[i]), relayer, 3 + i);
        }
        vm.prank(relayer);
        p.mtxBatch(ms, sigs);
        assertEq(p.calls(), 2);
        assertEq(p.bases(0), 7);
        assertEq(p.bases(1), 9);
        assertEq(p.lastCount(), 16);
    }

    function test_feeClassAboveAmount_refused() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(FeeProbe.g, ()), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, FeeProbe.g.selector));
        p.mtxExecute(m, sig);
    }
}
