// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";

/// @notice Plan 5h Task 3b, UA-5c (a)(b) on `NONE_ZETHER` (CTR-ZTH-51): the proof-carrying ops through the UA envelope
///         (`uaExecute`, binding tag `SCAAS-ZETHER-UA-ENVELOPE-V1`, the outer fee from the signer's UA balance), a
///         proof lifted between the address and the UA envelope fails both ways, the unshield to a `bytes32` UA
///         recipient (the statement's recipient word, credited on the UA ledger), and the empty `auth` / `accHint`
///         of the shared signature (D20).
contract ZetherUA5cTest is ZetherFixture {
    uint256 constant PAYER_PK = 0x9A7E5;
    address payer = vm.addr(PAYER_PK);
    uint32 constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;

    function setUp() public {
        _deploy(true);
        _public(tok, payer, 1000);
        _fund(tok, alice, 500);
        tok.mtxRollOver(_id(alice), 1);
        _public(tok, address(this), 10);
        tok.transferToUA(_id(bob), 10); // bob's UA balance pays the outer fee of his envelopes
    }

    function _id(User memory u) internal pure returns (bytes32) {
        return ZetherTypes.UA.unwrap(u.ua);
    }

    function _word(bytes memory a, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") { w := mload(add(add(a, 32), off)) }
    }

    function _pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// A UA envelope signed by `u` (the Zether UA is SIGNING, U8), fixed outer fee 3, restricted to the relayer.
    function _uam(User memory u, bytes memory data) internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        m = MetaTxLib.UAMetaTransaction({
            from: _id(u), data: data, batch: 1, nonce: tok.uaNonce(_id(u), 1), validUntil: block.timestamp + 300,
            mode: RR | FIX, relayer: relayer, fee: 3, feeRecipient: address(0)
        });
    }

    function _uaAuth(User memory u, MetaTxLib.UAMetaTransaction memory m) internal view returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.schnorr(u.x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_METATX, tok.uaDigest(m)), bls));
    }

    function _mt(bytes memory data) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = MetaTxLib.MetaTransaction({
            from: payer, data: data, batch: 1, nonce: tok.mtxNonce(payer, 1), validUntil: block.timestamp + 300,
            mode: RR | FIX, relayer: relayer, fee: 3, feeRecipient: address(0)
        });
    }

    function _sign(MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, tok.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _single(Tx memory t) internal pure returns (bytes memory) {
        return abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (t.payload, t.proof, bytes(""), bytes32(0), bytes("")));
    }

    // ------------------------------------------------------------------ (a) the UA envelope

    /// The binding formula of CTR-ZTH-51, distinct from the address envelope's for the same fields.
    function test_uaEnvelopeBinding_formula() public view {
        MetaTxLib.UAMetaTransaction memory m = _uam(bob, "");
        assertEq(tok.uaEnvelopeBinding(m), keccak256(abi.encode(keccak256("SCAAS-ZETHER-UA-ENVELOPE-V1"), block.chainid,
            ZUID, address(tok), _id(bob), uint256(1), uint256(0), m.validUntil, RR | FIX, relayer, uint256(3), address(0))));
        MetaTxLib.MetaTransaction memory a = _mt("");
        assertTrue(tok.uaEnvelopeBinding(m) != tok.envelopeBinding(a));
    }

    /// A transfer proved for its UA envelope runs through `uaExecute`; the outer fee comes from the signer's UA
    /// balance; the statement carries `ZTX_V1_RELAYED` and the UA binding.
    function test_uaEnvelope_transferSingle() public {
        MetaTxLib.UAMetaTransaction memory m = _uam(bob, "");
        bytes32 b = tok.uaEnvelopeBinding(m);
        Tx memory t = _proveTransfer(tok, alice, carol, 100, 500, _none(), b);
        bytes memory st = stm.transferStatementSingle(address(tok), t.payload, _none(), b);
        assertEq(_word(st, 160), keccak256("ZTX_V1_RELAYED"));
        assertEq(_word(st, 192), b);
        m.data = _single(t);
        bytes memory au = _uaAuth(bob, m);
        vm.prank(relayer);
        tok.uaExecute(m, au);
        assertEq(tok.balanceOf(relayer), 3, "outer fee to the relayer");
        assertEq(tok.balanceOfUA(_id(bob)), 7, "from the signer's UA balance");
        assertTrue(_holds(tok, carol, 100, false));
        assertTrue(_holds(tok, alice, 400, true));
    }

    /// A proof bound to a UA envelope fails inside an address envelope with the same data, and as a direct call.
    function test_uaEnvelopeProof_liftedToTheAddressEnvelope_fails() public {
        MetaTxLib.UAMetaTransaction memory u = _uam(bob, "");
        Tx memory t = _proveTransfer(tok, alice, carol, 100, 500, _none(), tok.uaEnvelopeBinding(u));
        MetaTxLib.MetaTransaction memory m = _mt(_single(t));
        bytes memory sig = _sign(m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxExecute(m, sig);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(t.payload, t.proof, "", bytes32(0), "");
        u.data = _single(t);
        bytes memory au = _uaAuth(bob, u);
        vm.prank(relayer);
        tok.uaExecute(u, au); // where it belongs
    }

    /// A proof bound to an address envelope fails inside a UA envelope with the same data.
    function test_addressEnvelopeProof_liftedToTheUAEnvelope_fails() public {
        MetaTxLib.MetaTransaction memory m = _mt("");
        Tx memory t = _proveTransfer(tok, alice, carol, 100, 500, _none(), tok.envelopeBinding(m));
        MetaTxLib.UAMetaTransaction memory u = _uam(bob, _single(t));
        bytes memory auth = _uaAuth(bob, u);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.uaExecute(u, auth);
        m.data = _single(t);
        bytes memory sig = _sign(m);
        vm.prank(relayer);
        tok.mtxExecute(m, sig); // where it belongs
        assertTrue(_holds(tok, carol, 100, false));
    }

    /// A direct proof (binding 0) put into a UA envelope: the statement is RELAYED there (the UA binding) ⇒ refused.
    function test_directProof_insideTheUAEnvelope_fails() public {
        Tx memory t = _proveTransfer(tok, alice, carol, 100, 500, _none(), 0);
        MetaTxLib.UAMetaTransaction memory u = _uam(bob, _single(t));
        bytes memory au = _uaAuth(bob, u);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.uaExecute(u, au);
        tok.mtxConfidentialTransferSingle(t.payload, t.proof, "", bytes32(0), ""); // the same proof as a direct call
    }

    /// The multi-recipient forms and the unshield join the UA allowlist too (CTR-ZTH-51); the unshield here pays a
    /// derived UA (b).
    function test_uaEnvelope_multiAndUnshieldToUA() public {
        MetaTxLib.UAMetaTransaction memory m = _uam(bob, "");
        User[] memory to = new User[](2);
        (to[0], to[1]) = (carol, bob);
        uint256[] memory vs = new uint256[](2);
        vs[0] = 50;
        Tx memory t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE, tok.uaEnvelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.mtxConfidentialTransfer, (t.payload, t.proof, bytes(""), bytes32(0), bytes("")));
        bytes memory au = _uaAuth(bob, m);
        vm.prank(relayer);
        tok.uaExecute(m, au);
        assertTrue(_holds(tok, carol, 50, false));
        m = _uam(bob, "");
        (bytes memory pl, bytes memory pr) = _proveUnshieldTo(tok, alice, 60, 450, _id(bob), _none(), tok.uaEnvelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.mtxUnshield, (pl, pr, bytes(""), bytes32(0), bytes(""), 60, _id(bob)));
        uint256 pool = tok.balanceOf(SHIELD_POOL_);
        au = _uaAuth(bob, m);
        vm.prank(relayer);
        tok.uaExecute(m, au);
        assertEq(tok.balanceOfUA(_id(bob)), 10 - 6 + 60 * SCALE, "two outer fees out, the unshield in");
        assertEq(tok.balanceOf(SHIELD_POOL_), pool - 60 * SCALE);
        assertTrue(_holds(tok, alice, 390, true));
        _assertConservation(tok, 1100);
    }

    // ------------------------------------------------------------------ (b) unshield to a UA

    /// The recipient word carries the UA id (a padded address unchanged); the units land on the UA ledger.
    function test_unshieldToDerivedUA() public {
        (bytes memory pl, bytes memory pr) = _proveUnshieldTo(tok, alice, 60, 500, _id(carol), _none(), 0);
        bytes memory st = stm.unshieldStatement(address(tok), pl, 60, _id(carol), _none(), 0);
        assertEq(_word(st, 384), _id(carol), "header word 12: the recipient id");
        bytes memory nat = stm.unshieldStatement(address(tok), pl, 60, _pad(address(0xD00D)), _none(), 0);
        assertEq(_word(nat, 384), bytes32(abi.encode(address(0xD00D))), "a native word = abi.encode(address)");
        uint256 supply = tok.totalSupply();
        vm.expectRevert(IZetherToken.ProofRejected.selector); // the proof binds exactly one recipient id
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 60, _id(bob));
        vm.expectEmit(true, true, false, true, address(tok));
        emit IConfidentialToken.Unshielded(_id(alice), 60, _id(carol), address(0));
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 60, _id(carol));
        assertEq(tok.balanceOfUA(_id(carol)), 60 * SCALE);
        assertEq(tok.balanceOf(SHIELD_POOL_), 440 * SCALE);
        assertEq(tok.totalSupply(), supply, "a move, nothing minted");
        assertTrue(_holds(tok, alice, 440, true));
        _assertConservation(tok, 1100);
    }

    /// An unregistered derived id and the pools are refused as recipient, before the proof.
    function test_unshieldRecipient_refused() public {
        bytes32 ghost = bytes32(uint256(1) << 200);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, ghost));
        tok.mtxUnshield("", "", "", bytes32(0), "", 1, ghost);
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        tok.mtxUnshield("", "", "", bytes32(0), "", 1, _pad(MetaTxLib.SHIELD_POOL));
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.mtxUnshield("", "", "", bytes32(0), "", 1, _pad(MetaTxLib.UA_POOL));
        vm.expectRevert(IZetherToken.ZeroRecipient.selector);
        tok.mtxUnshield(new bytes(64 + 128), "", "", bytes32(0), "", 1, bytes32(0));
    }

    // ------------------------------------------------------------------ D20: the shared signature on Zether

    /// `auth` and `accHint` are PQZ's arguments: non-empty on Zether ⇒ named errors, before anything else.
    function test_authAndAccHint_mustBeEmpty() public {
        bytes4[4] memory sels = [ZetherLayer.mtxConfidentialTransfer.selector, ZetherLayer.mtxConfidentialTransferCompact.selector,
            ZetherLayer.mtxConfidentialTransferNoBundle.selector, ZetherLayer.mtxConfidentialTransferSingle.selector];
        for (uint256 i; i < 4; ++i) {
            (bool ok, bytes memory r) = address(tok).call(abi.encodeWithSelector(sels[i], bytes(""), bytes(""), hex"01", bytes32(0), bytes("")));
            assertFalse(ok);
            assertEq(r, abi.encodeWithSelector(IZetherToken.AuthNotEmpty.selector));
            (ok, r) = address(tok).call(abi.encodeWithSelector(sels[i], bytes(""), bytes(""), bytes(""), bytes32(0), hex"01"));
            assertFalse(ok);
            assertEq(r, abi.encodeWithSelector(IZetherToken.AccHintNotEmpty.selector));
        }
        vm.expectRevert(IZetherToken.AuthNotEmpty.selector);
        tok.mtxUnshield("", "", hex"01", bytes32(0), "", 1, _pad(address(0xD00D)));
        vm.expectRevert(IZetherToken.AccHintNotEmpty.selector);
        tok.mtxUnshield("", "", "", bytes32(0), hex"01", 1, _pad(address(0xD00D)));
    }

    /// `mtxRollOver(ua, n)`: any `n ≥ 1` rolls the one aggregated pending; `n = 0` is refused.
    function test_rollOver_n() public {
        _fund(tok, alice, 5);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverRange.selector, 0));
        tok.mtxRollOver(_id(alice), 0);
        uint64 s = tok.accountState(alice.ua).accSeq;
        vm.expectEmit(true, false, false, true, address(tok));
        emit IConfidentialToken.RolledOver(_id(alice), s + 1, 0, 0);
        tok.mtxRollOver(_id(alice), 7);
        assertTrue(_holds(tok, alice, 505, true));
    }

    /// The UA allowlist of `NONE_ZETHER`: the six Zether ops and `burn`; the rollovers are not on it (CTR-ZTH-34).
    function test_uaAllowlist_rolloversOff() public {
        bytes[3] memory off = [
            abi.encodeCall(ZetherLayer.mtxRollOver, (_id(bob), 1)),
            abi.encodeCall(ZetherLayer.mtxRollOverSigned, (bob.ua, 1, 1, bytes(""))),
            abi.encodeCall(ZetherLayer.mtxSetRollOverMode, (bob.ua, ZetherTypes.RollOverMode.PUBLIC, 1, bytes("")))
        ];
        for (uint256 i; i < off.length; ++i) {
            MetaTxLib.UAMetaTransaction memory m = _uam(bob, off[i]);
            bytes memory auth = _uaAuth(bob, m);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(off[i])));
            tok.uaExecute(m, auth);
        }
    }
}
