// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Test-only: a second signed "struct" (stands for P1b's `MetaTransfer`) sharing the lane space (CTR-MTX-15),
/// and an allowlisted function that is NOT `nonReentrant` (CTR-MTX-18 fail-closed).
contract LaneHarness is MetaTxBase {
    constructor() MetaTxBase("SCaaS Lane", bytes32(uint256(1))) {}

    function consume(address from, uint256 batch, uint256 nonce) external {
        _checkEnvelope(from, batch, nonce, block.timestamp + 1, MetaTxLib.MODE_OPEN, address(0));
        _useNonce(from, batch);
    }

    function unguarded() external {}

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.unguarded.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        return super._mtxRule(sel);
    }
}

contract MetaTxBaseLaneTest is MtxFixture {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    function test_sharedLane_oneNonceSequence() public {
        LaneHarness h = new LaneHarness();
        h.consume(alice, 1, 0);
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(IMetaTx.cancelNonce, (9)), 1, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, h.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        h.mtxExecute(m, abi.encodePacked(r, s, v));
        m.nonce = 1;
        (v, r, s) = vm.sign(ALICE_PK, h.mtxDigest(m));
        h.mtxExecute(m, abi.encodePacked(r, s, v));
        assertEq(h.mtxNonce(alice, 1), 2);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 2, 1));
        h.consume(alice, 1, 1);
    }

    function test_unguardedAllowlistedTarget_failsClosed() public {
        LaneHarness h = new LaneHarness();
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(LaneHarness.unguarded, ()), 1, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, h.mtxDigest(m));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        h.mtxExecute(m, abi.encodePacked(r, s, v));
        assertEq(h.mtxNonce(alice, 1), 0);
    }
}
