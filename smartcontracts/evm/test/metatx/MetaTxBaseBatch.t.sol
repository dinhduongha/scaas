// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// CTR-MTX-11: `mtxBatch` is atomic, runs items in order, a fresh ticket per item.
contract MetaTxBaseBatchTest is MtxFixture {
    function _batch(MetaTxLib.MetaTransaction[] memory ms, bytes[] memory sigs) internal {
        vm.prank(relayer);
        reg.mtxBatch(ms, sigs);
    }

    function test_batch_runsEachItemAsItsSigner() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](3);
        bytes[] memory sigs = new bytes[](3);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = _m(bob, _setName("bob"), 1, 0);
        ms[2] = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (2)), 1, 1);
        ms[2].mode = MetaTxLib.MODE_RESTRICT_RELAYER;   // bound to the submitting relayer: still fine in a batch
        ms[2].relayer = relayer;
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = _sign(BOB_PK, ms[1]);
        sigs[2] = _sign(ALICE_PK, ms[2]);
        _batch(ms, sigs);
        assertEq(reg.nameOf(alice), "alice");
        assertEq(reg.nameOf(bob), "bob");
        assertEq(reg.count(alice), 2);
        assertEq(reg.mtxNonce(alice, 1), 2);
        assertEq(reg.mtxNonce(bob, 1), 1);
    }

    function test_batch_isAllOrNothing() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (0)), 1, 1);
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = _sign(ALICE_PK, ms[1]);
        vm.expectRevert(MtxRegistryMock.ZeroBump.selector);
        _batch(ms, sigs);
        assertEq(reg.nameOf(alice), "");
        assertEq(reg.mtxNonce(alice, 1), 0);
    }

    function test_batch_empty() public {
        vm.expectRevert(IMetaTx.MtxBatchEmpty.selector);
        _batch(new MetaTxLib.MetaTransaction[](0), new bytes[](0));
    }

    function test_batch_lengthMismatch() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](1);
        ms[0] = _m(alice, _setName("a"), 1, 0);
        vm.expectRevert(IMetaTx.MtxBatchLengthMismatch.selector);
        _batch(ms, new bytes[](0));
    }

    function test_batch_isNotAllowlisted() public {
        MetaTxLib.MetaTransaction[] memory inner = new MetaTxLib.MetaTransaction[](1);
        inner[0] = _m(alice, _setName("a"), 2, 0);
        bytes memory data = abi.encodeCall(IMetaTx.mtxBatch, (inner, new bytes[](1)));
        MetaTxLib.MetaTransaction memory m = _m(alice, data, 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, IMetaTx.mtxBatch.selector));
        reg.mtxExecute(m, sig);
    }

    function test_batch_replayOfSameItemReverts() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = ms[0];
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = sigs[0];
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _batch(ms, sigs);
        assertEq(reg.mtxNonce(alice, 1), 0);
        assertEq(reg.nameOf(alice), "");
    }

    function test_batch_badSignatureRollsBackEarlierItem() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = _m(bob, _setName("bob"), 1, 0);
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = _sign(ALICE_PK, ms[1]);   // signed by the wrong key
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _batch(ms, sigs);
        assertEq(reg.nameOf(alice), "");
        assertEq(reg.mtxNonce(alice, 1), 0);
        assertEq(reg.mtxNonce(bob, 1), 0);
    }

    function test_batch_wrongRelayerRollsBackEarlierItem() public {
        address other = address(0xCAFE);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = _m(bob, _setName("bob"), 1, 0);
        ms[1].mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        ms[1].relayer = other;              // bound to another relayer than the submitter
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = _sign(BOB_PK, ms[1]);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, other, relayer));
        _batch(ms, sigs);
        assertEq(reg.nameOf(alice), "");
        assertEq(reg.mtxNonce(alice, 1), 0);
        assertEq(reg.mtxNonce(bob, 1), 0);
    }
}
