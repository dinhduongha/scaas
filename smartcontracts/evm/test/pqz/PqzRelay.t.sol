// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";

/// Relaying (CTR-PQZ-15 / -21, P6g plan D4): the address path binds the envelope into the statement (header word 17), the
/// UA path with an `mldsa65` fee UA likewise with its own tag, PQZ selectors are never batched, `PERCENT` is refused.
contract PqzRelayTest is PqzFixture {
    uint256 internal constant KEY = 0xA11CE;
    address internal signer;
    address internal relayer = address(0xBEEF);

    function setUp() public {
        _stack();
        tok = _newToken("pqz");
        signer = vm.addr(KEY);
    }

    function _m(bytes memory data, uint256 nonce, uint256 fee) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m.from = signer;
        m.data = data;
        m.nonce = nonce;
        m.validUntil = block.timestamp + 1 hours;
        m.mode = fee == 0 ? 0 : MetaTxLib.MODE_FEE_FIXED;
        m.fee = fee;
    }

    function _sig(MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, tok.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function test_v1BindingAndFee() public {
        _public(tok, signer, 10 * SCALE + 7);
        // pqzShield from the signer's public balance, relayed with a fixed fee
        MetaTxLib.MetaTransaction memory m = _m(abi.encodeCall(PqzLayer.pqzShield, (alice, 10)), 0, 7);
        bytes memory sg = _sig(m);
        vm.prank(relayer);
        tok.mtxExecute(m, sg);
        assertEq((tok.pqzPending(alice, 0) >> 96) & type(uint64).max, 10, "a TRIVIAL entry");
        assertEq(tok.balanceOf(relayer), 7, "outer fee after the op");
        assertEq(tok.balanceOf(signer), 0);

        // a transfer inside an envelope: the statement carries envelopeBinding(m)
        bytes memory out = _out(1, true);
        bytes memory pl = _payload(1, 0, alice, bob, bytes32(0), out, "");
        bytes memory data = abi.encodeCall(PqzLayer.pqzTransferSingle, (pl, bytes(""), hex"c0de", _mlAuth()));
        m = _m(data, 1, 0);
        bytes32 b = tok.envelopeBinding(m);
        assertTrue(b != 0);
        assertEq(b, keccak256(abi.encode(keccak256("SCAAS-PQZ-ENVELOPE-V1"), block.chainid, tok.chainUid(), address(tok),
            signer, uint256(0), uint256(1), m.validUntil, uint32(0), address(0), uint256(0), address(0))));
        bytes memory st = tok.transferSingleStatement(pl, b);
        assertEq(bytes32(_cut(st, 544, 32)), _relayed(b, ZetherTypes.TransferMode.BUNDLE), "D15: the mode folded in");
        // the proof of the bound statement is valid only there: the mocked precompile accepts exactly that input
        _mockOp(1, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(83_072), st, hex"c0de"), abi.encode(uint256(1)));
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransferSingle(pl, "", hex"c0de", _mlAuth()); // stripped out of its envelope: the direct binding
        MetaTxLib.MetaTransaction memory other = _m(data, 2, 0); // another nonce: another binding
        sg = _sig(other);
        vm.expectRevert(); // MetaTxBadNonce first; with nonce 1 used elsewhere the binding would differ
        tok.mtxExecute(other, sg);
        sg = _sig(m);
        uint256 g = gasleft();
        tok.mtxExecute(m, sg);
        console2.log("pqzTransfer in a v1 envelope (mocked proof) gas", g - gasleft());
        assertEq(tok.pqzAccount(alice).sendCounter, 1);
    }

    function test_percentAndBatchRefused() public {
        _public(tok, signer, 10 * SCALE);
        MetaTxLib.MetaTransaction memory m = _m(abi.encodeCall(PqzLayer.pqzShield, (alice, 1)), 0, 0);
        m.mode = MetaTxLib.MODE_FEE_PERCENT;
        m.fee = 100;
        bytes memory sg = _sig(m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, PqzLayer.pqzShield.selector, m.mode));
        tok.mtxExecute(m, sg);
        m = _m(abi.encodeCall(PqzLayer.pqzShield, (alice, 1)), 0, 0);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](1);
        ms[0] = m;
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sig(m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxNotBatchable.selector, PqzLayer.pqzShield.selector));
        tok.mtxBatch(ms, sigs);
        // a non-PQZ selector still batches
        m = _m(abi.encodeWithSignature("burn(uint256)", 1), 0, 0);
        ms[0] = m;
        sigs[0] = _sig(m);
        tok.mtxBatch(ms, sigs);
    }

    function test_v3FeeUA() public {
        bytes32 fee = _mldsaUA(9);
        NoUnderlyingPqzToken(address(tok)).mintToUA(fee, 20 * SCALE + 5);
        minted += 20 * SCALE + 5;
        MetaTxLib.UAMetaTransaction memory m;
        m.from = fee;
        m.data = abi.encodeCall(PqzLayer.pqzShield, (alice, 20));
        m.validUntil = block.timestamp + 1 hours;
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 5;
        vm.prank(relayer);
        tok.uaExecute(m, _mlAuth());
        assertEq(tok.balanceOfUA(fee), 0, "the UA's public units shielded, the fee paid");
        assertEq(tok.balanceOf(relayer), 5);
        assertEq((tok.pqzPending(alice, 0) >> 96) & type(uint64).max, 20, "a TRIVIAL entry");
        _assertConservation(tok);

        // a v3 transfer: the UA binding (its own tag) in the statement; `shieldIn` 2 from the fee UA's own balance
        NoUnderlyingPqzToken(address(tok)).mintToUA(fee, 2 * SCALE);
        minted += 2 * SCALE;
        bytes memory pl = _payload(1, 2, alice, bob, bytes32(0), _out(2, false), "");
        m.data = abi.encodeCall(PqzLayer.pqzTransferSingle, (pl, bytes(""), hex"c0de", _mlAuth()));
        m.nonce = 1;
        m.mode = 0;
        m.fee = 0;
        bytes32 b = tok.uaEnvelopeBinding(m);
        assertEq(b, keccak256(abi.encode(keccak256("SCAAS-PQZ-UA-ENVELOPE-V1"), block.chainid, tok.chainUid(), address(tok),
            fee, uint256(0), uint256(1), m.validUntil, uint32(0), address(0), uint256(0), address(0))));
        bytes memory st = tok.transferSingleStatement(pl, b);
        _mockOp(1, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(66_560), st, hex"c0de"), abi.encode(uint256(1)));
        uint256 g = gasleft();
        tok.uaExecute(m, _mlAuth());
        console2.log("pqzTransfer in a v3 envelope (mldsa65 fee UA, mocked proof) gas", g - gasleft());
        assertEq(tok.pqzAccount(alice).sendCounter, 1);
        assertEq(tok.balanceOfUA(fee), 0, "shieldIn moved from the signing UA's ledger balance to the pool");
        assertEq(tok.totalShielded(), 22);
        _assertConservation(tok);
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](1);
        ms[0] = m;
        bytes[] memory auths = new bytes[](1);
        auths[0] = _mlAuth();
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxNotBatchable.selector, PqzLayer.pqzTransferSingle.selector));
        tok.uaBatch(ms, auths);
        // UA-6: a holder is a signing UA, so alice (registered with her PQZ key in one call) signs an envelope herself;
        // the same envelope under a signature the `mldsa65` precompile rejects is refused (no `authRef`, no foreign signer)
        NoUnderlyingPqzToken(address(tok)).mintToUA(alice, 3 * SCALE);
        minted += 3 * SCALE;
        MetaTxLib.UAMetaTransaction memory h;
        h.from = alice;
        h.data = abi.encodeCall(PqzLayer.pqzShield, (bob, 3));
        h.validUntil = block.timestamp + 1 hours;
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(0))); // every ML-DSA verification now fails
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, alice));
        tok.uaExecute(h, _mlAuth());
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(1)));
        tok.uaExecute(h, _mlAuth());
        assertEq(tok.balanceOfUA(alice), 0, "alice's own signature shielded her units");
        assertEq((tok.pqzPending(bob, 1) >> 96) & type(uint64).max, 3, "after alice's credit");
        _assertConservation(tok);
        assertEq(UAKinds.PQZ_MLWE, 0x0142);
    }
}
