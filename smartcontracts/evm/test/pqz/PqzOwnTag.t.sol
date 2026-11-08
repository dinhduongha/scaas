// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {UACall} from "../ua/UACall.sol";

/// Group 3h, T59 (spec 2026-11-06-pqz-proof-path §3, §11.1; CTR-PQZ-34 draft): every own debit's blob ends `… ‖ P(v_f) ‖ ownTag ‖
/// kv(8·n) ‖ u8(n)` (C5, R2), `rOf` the one reader of the tail, `memoHash = keccak256(memo ‖ ownTag)` (C3). The PQZ precompile is
/// mocked (`PqzFixture`). UNAUDITED.
contract PqzOwnTagTest is PqzFixture {
    using stdJson for string;

    bytes internal constant PROOF = hex"c0de";
    bytes32 internal constant D00D = bytes32(uint256(uint160(address(0xD00D))));
    bytes32 internal constant TAG = keccak256("PQZ/owntag/v1 test tag");

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        tok = _newToken("owntag");
    }

    // ----- fixtures -----

    function _shield(bytes32 ua, uint256 amount) internal {
        _public(tok, address(this), amount * SCALE);
        tok.mtxShield(ua, amount);
    }

    function _rotate(bytes32 ua, uint64 v, bytes memory pk) internal {
        reg.setPqzKey(ua, v, pk, keccak256(abi.encodePacked("pqzver", ua, v)), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(ua, v, abi.encodePacked("pqzver", ua, v));
    }

    function _op1(bytes32 from, bytes32 to, uint64 p, bool aud, bytes32 tag, uint256 seed)
        internal view returns (IPqzToken.PqzTransferArgs memory t)
    {
        t = _ts(_payload(p, 0, from, to, bytes32(0), _out(seed, aud), ""));
        t.ownTag = tag;
    }

    function _op7(bytes32 from, bytes32[] memory legs, uint64 p, bool aud, bytes32 tag, uint256 seed)
        internal view returns (IPqzToken.PqzMultiArgs memory t)
    {
        t = _ms(_mpayload(p, 0, from, bytes32(0), legs, _blob(seed, _outLen(legs.length, aud)), ""));
        t.ownTag = tag;
    }

    function _burnArgs(bytes32 from, uint64 p, bytes32 tag, uint256 seed) internal view returns (IPqzToken.PqzBurnArgs memory b) {
        b = _bs(bytes.concat(abi.encode(uint256(p), block.number + 50, uint256(0), from, bytes32(0)), _blob(seed, PqzCt.CT)));
        b.ownTag = tag;
    }

    function _two(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (a, b);
    }

    /// The tail of a blob's data: `(ownTag, kv)` read from its last byte, and the bytes before `P(v_f)` (`R`).
    function _tail(bytes memory b) internal pure returns (bytes32 tag, uint64[] memory kv, bytes memory r) {
        uint256 n = uint8(b[b.length - 1]);
        kv = new uint64[](n);
        for (uint256 i; i < n; ++i) kv[i] = uint64(bytes8(_cut(b, b.length - 1 - 8 * n + 8 * i, 8)));
        tag = bytes32(_cut(b, b.length - 33 - 8 * n, 32));
        r = _cut(b, 0, b.length - 33 - 8 * n - PqzCt.VP);
    }

    function _accBlob(bytes32 ua, uint64 v) internal view returns (bytes memory) {
        return SSTORE2.read(tok.pqzAccount(ua, v).accBlob);
    }

    function _kv1(uint64 a) internal pure returns (uint64[] memory k) {
        k = new uint64[](1);
        k[0] = a;
    }

    function _kv2(uint64 a, uint64 b) internal pure returns (uint64[] memory k) {
        k = new uint64[](2);
        (k[0], k[1]) = (a, b);
    }

    // ----- ownTag in the blob (PP-3, C5) -----

    function test_ownTag_inBlob_op1() public {
        _shield(alice, 10);
        IPqzToken.PqzTransferArgs memory t = _op1(alice, bob, 1, false, TAG, 5);
        bytes32 ref = tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", noVerdict());
        bytes memory b = tok.pqzEntryBlob(ref);
        (bytes32 tag, uint64[] memory kv, bytes memory r) = _tail(b);
        assertEq(tag, TAG, "ownTag");
        assertEq(abi.encode(kv), abi.encode(_kv1(0)), "kv: bob's version 0");
        assertEq(r, _rOf(_out(5, false), bob), "R before v_f");
        assertEq(_cut(b, r.length, PqzCt.VP), _packed(t.vFrom), "P(v_f) before the tail");
        assertEq(b, _accBlob(alice, 0), "the entry's blob is the account's");
    }

    function test_ownTag_inBlob_op7() public {
        _shield(alice, 10);
        IPqzToken.PqzMultiArgs memory t = _op7(alice, _two(bob, carol), 1, false, TAG, 6);
        bytes32 ref = tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "", noVerdict());
        (bytes32 tag, uint64[] memory kv,) = _tail(tok.pqzEntryBlob(ref));
        assertEq(tag, TAG);
        assertEq(abi.encode(kv), abi.encode(_kv2(0, 0)), "kv: the legs' versions in leg order");
    }

    function test_ownTag_inBlob_burn() public {
        _shield(alice, 10);
        tok.mtxUnshield(_burnArgs(alice, 1, TAG, 7), 4, D00D, PROOF, _pqAuth(), "", noVerdict());
        bytes memory b = _accBlob(alice, 0);
        assertEq(b.length, PqzCt.CTP + 33, "u' || v_f || ownTag || n");
        (bytes32 tag, uint64[] memory kv, bytes memory r) = _tail(b);
        assertEq(tag, TAG);
        assertEq(kv.length, 0, "a burn credits no key");
        assertEq(r.length, PqzCt.PKP, "R = P(u')");
    }

    function test_ownTag_inBlob_refresh() public {
        _shield(alice, 10);
        tok.mtxUnshield(_burnArgs(alice, 1, TAG, 8), 0, bytes32(0), PROOF, _pqAuth(), "", noVerdict());
        (bytes32 tag, uint64[] memory kv,) = _tail(_accBlob(alice, 0));
        assertEq(tag, TAG);
        assertEq(kv.length, 0);
    }

    // ----- the key versions the call read (R2) -----

    function test_kv_op1() public {
        _shield(alice, 10);
        _rotate(bob, 1, _pk(31));
        bytes32 ref = tok.mtxConfidentialTransferSingle(_op1(alice, bob, 1, false, TAG, 5), PROOF, _pqAuth(), "", noVerdict());
        (, uint64[] memory kv,) = _tail(tok.pqzEntryBlob(ref));
        assertEq(abi.encode(kv), abi.encode(_kv1(1)), "the receiver's current version, read in the call");
    }

    function test_kv_op1Auditor() public {
        _shield(alice, 10);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_op1(alice, bob, 1, true, TAG, 5), PROOF, _pqAuth(), "", noVerdict());
        (, uint64[] memory kv, bytes memory r) = _tail(tok.pqzEntryBlob(ref));
        assertEq(abi.encode(kv), abi.encode(_kv2(0, 0)), "pk_t, then pk_a");
        assertEq(r, _rOf(_out(5, true), bob), "R with the auditor copy");
    }

    function test_kv_op7() public {
        _shield(alice, 10);
        bytes32 ref = tok.mtxConfidentialTransfer(_op7(alice, _two(bob, carol), 1, true, TAG, 6), PROOF, _pqAuth(), "", noVerdict());
        (, uint64[] memory kv,) = _tail(tok.pqzEntryBlob(ref));
        uint64[] memory want = new uint64[](3);
        assertEq(abi.encode(kv), abi.encode(want), "every leg, then the auditor");
    }

    /// A leg rotated before the debit: its current version, in leg order, not in key-pointer order (M22).
    function test_kv_op7Rotated() public {
        _shield(alice, 10);
        _rotate(carol, 1, _pk(32));
        _rotate(carol, 2, _pk(33));
        _rotate(bob, 1, _pk(31));
        bytes32 ref = tok.mtxConfidentialTransfer(_op7(alice, _two(carol, bob), 1, false, TAG, 6), PROOF, _pqAuth(), "", noVerdict());
        (, uint64[] memory kv,) = _tail(tok.pqzEntryBlob(ref));
        assertEq(abi.encode(kv), abi.encode(_kv2(2, 1)), "carol 2, bob 1, as the legs");
    }

    /// The auditor rotated between two debits: each blob names the version read in its own call.
    function test_kv_auditorRotated() public {
        _shield(alice, 10);
        bytes32 r0 = tok.mtxConfidentialTransferSingle(_op1(alice, bob, 1, true, TAG, 5), PROOF, _pqAuth(), "", noVerdict());
        _rotate(aud, 1, _pk(36));
        _shield(alice, 3);
        bytes32 r1 = tok.mtxConfidentialTransferSingle(_op1(alice, bob, 2, true, TAG, 6), PROOF, _pqAuth(), "", noVerdict());
        (, uint64[] memory k0,) = _tail(tok.pqzEntryBlob(r0));
        (, uint64[] memory k1,) = _tail(tok.pqzEntryBlob(r1));
        assertEq(abi.encode(k0), abi.encode(_kv2(0, 0)), "before the rotation");
        assertEq(abi.encode(k1), abi.encode(_kv2(0, 1)), "after it");
    }

    // ----- rOf, the one reader of the tail -----

    function test_rOf_op1() public {
        _shield(alice, 10);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_op1(alice, bob, 1, true, TAG, 5), PROOF, _pqAuth(), "", noVerdict());
        address p = tok.pqzAccount(alice, 0).accBlob;
        assertEq(PqzCore.rOf(p), _rOf(_out(5, true), bob));
        assertEq(tok.transferEntry(ref), _rOf(_out(5, true), bob), "transferEntry = R");
        assertEq(tok.pqzAcc(alice, 0), bytes.concat(_cut(_out(5, true), 0, PqzCt.PK), _cut(_out(5, true), PqzCt.CT, PqzCt.V)),
            "acc = (u, v_f) at the offsets the tail leaves");
    }

    function test_rOf_op7() public {
        _shield(alice, 10);
        IPqzToken.PqzMultiArgs memory t = _op7(alice, _two(bob, carol), 1, true, TAG, 6);
        bytes32 ref = tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "", noVerdict());
        bytes memory b = tok.pqzEntryBlob(ref);
        bytes memory r = PqzCore.rOf(tok.pqzAccount(alice, 0).accBlob);
        assertEq(r.length, b.length - 33 - 8 * 3 - PqzCt.VP, "R ends before v_f, whatever n");
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));
        assertEq(_cut(tok.pqzAcc(alice, 0), PqzCt.PK, PqzCt.V), t.vFrom, "v_f at vOff");
    }

    function test_rOf_burn() public {
        _shield(alice, 10);
        IPqzToken.PqzBurnArgs memory x = _burnArgs(alice, 1, TAG, 7);
        tok.mtxUnshield(x, 4, D00D, PROOF, _pqAuth(), "", noVerdict());
        assertEq(PqzCore.rOf(tok.pqzAccount(alice, 0).accBlob), _packed(x.u), "R = P(u')");
        assertEq(tok.pqzAcc(alice, 0), bytes.concat(x.u, x.vFrom), "acc = (u', v_f)");
    }

    // ----- memoHash (C3) -----

    function test_memoHash_hash() public {
        _shield(alice, 10);
        IPqzToken.PqzTransferArgs memory t = _ts(_payload(1, 0, alice, bob, bytes32(0), _out(5, false), _memo()));
        t.ownTag = TAG;
        bytes memory st = tok.transferSingleStatement(t, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(bytes.concat(_memo(), TAG)), "keccak256(salt || sealedMemo || ownTag)");
    }

    function test_memoHash_bundle() public {
        _shield(alice, 10);
        bytes memory st = tok.transferSingleStatement(_op1(alice, bob, 1, false, TAG, 5), 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(abi.encodePacked(TAG)), "keccak256(ownTag)");
        bytes memory st7 = tok.transferStatement(_op7(alice, _two(bob, carol), 1, false, TAG, 6), 0);
        assertEq(bytes32(_cut(st7, 608, 32)), keccak256(abi.encodePacked(TAG)), "op 7 BUNDLE");
    }

    function test_memoHash_burn() public {
        _shield(alice, 10);
        bytes memory st = tok.burnStatement(_burnArgs(alice, 1, TAG, 7), 4, D00D, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(abi.encodePacked(TAG)));
        st = tok.burnStatement(_burnArgs(alice, 1, TAG, 7), 0, 0, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(abi.encodePacked(TAG)), "refresh");
    }

    /// `memoHash` is a header word the proof binds: a tag swapped after the proof is `ProofRejected`; the proven one lands.
    function test_ownTag_swapped_refused() public {
        _shield(alice, 10);
        IPqzToken.PqzTransferArgs memory t = _op1(alice, bob, 1, false, TAG, 5);
        bytes memory st = tok.transferSingleStatement(t, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1)), abi.encode(uint256(0)));
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, PROOF), abi.encode(uint256(1)));
        IPqzToken.PqzTransferArgs memory swapped = _op1(alice, bob, 1, false, keccak256("another tag"), 5);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(swapped, PROOF, _pqAuth(), "", noVerdict());
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", noVerdict());
    }

    // ----- what the tail leaves unchanged -----

    /// `transferEntry` and `transferCiphertextHash` keep their values: `R`, `keccak256(R)` (CTR-PQZ-23's sender recovery), on both
    /// storage forms; a commit-reveal entry `keccak256(R) ‖ memo`.
    function test_transferEntry_unchanged() public {
        _shield(alice, 10);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_op1(alice, bob, 1, false, TAG, 5), PROOF, _pqAuth(), "", noVerdict());
        bytes memory r = _rOf(_out(5, false), bob);
        assertEq(tok.transferEntry(ref), r);
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));
        IPqzToken.PqzTransferArgs memory h = _ts(_payload(1, 0, bob, carol, bytes32(0), _out(9, false), _memo()));
        h.ownTag = TAG;
        bytes32 ref2 = tok.mtxConfidentialTransferSingleCompact(h, PROOF, _pqAuth(), "", noVerdict());
        bytes memory r2 = _rOf(_out(9, false), carol);
        assertEq(tok.transferEntry(ref2), bytes.concat(keccak256(r2), _memo()), "commit-reveal: keccak256(R) || memo");
    }

    /// Disclosure reads `u` and every leg at the offsets of `R`: the receiver's and the auditor's openings of an op 7 leg
    /// carry the leg's `u ‖ v` and `u ‖ v_a` exactly.
    function test_disclosure_offsetsUnchanged() public {
        _shield(alice, 10);
        IPqzToken.PqzMultiArgs memory t = _op7(alice, _two(bob, carol), 1, true, TAG, 6);
        bytes32 ref = tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "", noVerdict());
        bytes memory dr = tok.disclosureStatement(ref, 1, 5, 1, 0);
        assertEq(_cut(dr, 288 + PqzCt.PK, PqzCt.PK), t.u[0], "u of leg 1's group");
        assertEq(_cut(dr, 288 + 2 * PqzCt.PK, PqzCt.V), t.legs[1].v, "v of leg 1");
        bytes memory da = tok.disclosureStatement(ref, 1, 5, 2, 0);
        assertEq(_cut(da, 288 + 2 * PqzCt.PK, PqzCt.V), t.legs[1].vAuditor, "the auditor copy of leg 1");
    }

    // ----- the client's memoHash (clientkeys, pq_kat.json) against the statement views -----

    /// `smartcontracts/vectors/ua/pq_kat.json` `memoHash` rows (clientkeys `memoHash`): each row's word is the statement view's for
    /// the same salt, sealed memo and tag (op 1 HASH and BUNDLE, a burn).
    function test_memoHash_equalsClientkeys() public {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/ua/pq_kat.json"));
        _shield(alice, 10);
        for (uint256 i; i < 3; ++i) {
            string memory k = string.concat(".memoHash[", vm.toString(i), "]");
            string memory form = j.readString(string.concat(k, ".form"));
            bytes32 tag = j.readBytes32(string.concat(k, ".ownTag"));
            bytes32 want = j.readBytes32(string.concat(k, ".memoHash"));
            bytes memory st;
            if (keccak256(bytes(form)) == keccak256("burn")) {
                st = tok.burnStatement(_burnArgs(alice, 1, tag, 7), 4, D00D, 0);
            } else {
                bytes memory memo = j.readBytes(string.concat(k, ".memo"));
                IPqzToken.PqzTransferArgs memory t = _ts(_payload(1, 0, alice, bob, bytes32(0), _out(5, false), ""));
                if (memo.length != 0) {
                    t.salt = bytes16(_cut(memo, 0, 16));
                    t.sealedMemo = _cut(memo, 16, memo.length - 16);
                }
                t.ownTag = tag;
                st = tok.transferSingleStatement(t, 0);
            }
            assertEq(bytes32(_cut(st, 608, 32)), want, form);
        }
    }
}
