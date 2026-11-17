// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";

import {Vm} from "forge-std/Vm.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";

/// Group 3h, T60 (spec 2026-11-06-pqz-proof-path §4, §11.1; CTR-PQZ-35 draft): `proofStore` `NONE` (calldata only) or `LOG` (a
/// `PqzDebitProof` event per debit: the verified header, the calldata proof), stored at slot 0 byte 23, recorded per debit in the
/// record's `proofStore`; a non-PQZ kind refuses a set one. The PQZ precompile is mocked (`PqzFixture`). UNAUDITED.
contract PqzProofStoreTest is PqzOffchainBase {
    bytes internal constant PROOF = hex"c0ffee";
    bytes32 internal constant D00D = bytes32(uint256(uint160(address(0xD00D))));
    bytes32 internal constant EV = keccak256("PqzDebitProof(address,bytes32,uint64,bytes,bytes)");

    NormalPqzToken internal logT;

    function setUp() public {
        _offStack();
        tok = _newToken("none");
        pStore = PqzCore.LOG;
        logT = _newToken("log");
        pStore = 0;
    }

    function _shieldT(NormalPqzToken t, bytes32 ua, uint256 amount) internal {
        _public(t, address(this), amount * SCALE);
        t.mtxShield(ua, amount);
    }

    function _two(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (a, b);
    }

    /// The `PqzDebitProof` events of the last call: `(blob, ua, sendCounter, header, proof)` each.
    function _logs(address t) internal returns (Vm.Log[] memory out, uint256 n) {
        Vm.Log[] memory all = vm.getRecordedLogs();
        out = new Vm.Log[](all.length);
        for (uint256 i; i < all.length; ++i) if (all[i].emitter == t && all[i].topics[0] == EV) out[n++] = all[i];
    }

    /// Under `LOG` exactly one event, its header the statement's first 640 bytes (the one the proof was checked over), its
    /// proof the calldata proof, `blob` the debit's op blob; the record says `LOG`. Under `NONE` no event, the record `NONE`.
    function _check(NormalPqzToken t, bytes32 from, uint64 k, bytes memory st, uint8 mode) internal {
        (Vm.Log[] memory ls, uint256 n) = _logs(address(t));
        assertEq(t.pqzDebitRecord(from, k).proofStore, mode, "the record's mode");
        if (mode == PqzCore.NONE) {
            assertEq(n, 0, "NONE: no event");
            return;
        }
        assertEq(n, 1, "LOG: exactly one event");
        assertEq(ls[0].topics[1], bytes32(uint256(uint160(t.pqzAccount(from, 0).accBlob))), "blob");
        assertEq(ls[0].topics[2], from, "ua");
        assertEq(uint256(ls[0].topics[3]), k, "sendCounter");
        (bytes memory header, bytes memory proof) = abi.decode(ls[0].data, (bytes, bytes));
        assertEq(header, _slice(st, 0, 640), "the verified header");
        assertEq(proof, PROOF, "the calldata proof");
    }

    function _op1(NormalPqzToken t, bool log) internal {
        _shieldT(t, alice, 10);
        IPqzToken.PqzTransferArgs memory a = _ts(_payload(1, 0, alice, bob, bytes32(0), _out(5, false), ""));
        bytes memory st = t.transferSingleStatement(a, 0);
        vm.recordLogs();
        t.mtxConfidentialTransferSingle(a, PROOF, _pqAuth(), "", noVerdict());
        _check(t, alice, 0, st, log ? PqzCore.LOG : PqzCore.NONE);
    }

    function _op7(NormalPqzToken t, bool log) internal {
        _shieldT(t, alice, 10);
        IPqzToken.PqzMultiArgs memory m = _ms(_mpayload(1, 0, alice, bytes32(0), _two(bob, carol), _blob(6, _outLen(2, true)), ""));
        bytes memory st = t.transferStatement(m, 0);
        vm.recordLogs();
        t.mtxConfidentialTransfer(m, PROOF, _pqAuth(), "", noVerdict());
        _check(t, alice, 0, st, log ? PqzCore.LOG : PqzCore.NONE);
    }

    function _burn(NormalPqzToken t, bool log) internal {
        _shieldT(t, alice, 10);
        IPqzToken.PqzBurnArgs memory b = _bs(bytes.concat(abi.encode(uint256(1), block.number + 50, uint256(0), alice, bytes32(0)),
            _blob(7, PqzCt.CT)));
        bytes memory st = t.burnStatement(b, 4, D00D, 0);
        vm.recordLogs();
        t.mtxUnshield(b, 4, D00D, PROOF, _pqAuth(), "", noVerdict());
        _check(t, alice, 0, st, log ? PqzCore.LOG : PqzCore.NONE);
    }

    function test_proofStore_none_op1() public { _op1(tok, false); }
    function test_proofStore_log_op1() public { _op1(logT, true); }
    function test_proofStore_none_op7() public { _op7(tok, false); }
    function test_proofStore_log_op7() public { _op7(logT, true); }
    function test_proofStore_none_burn() public { _burn(tok, false); }
    function test_proofStore_log_burn() public { _burn(logT, true); }

    function test_proofStore_view() public view {
        assertEq(abi.encode(tok.proofStore(), logT.proofStore()), abi.encode(PqzCore.NONE, PqzCore.LOG));
        // slot 0 byte 23, beside 3f's `pqzVerifyMode` at byte 22 (a debit reads no new slot)
        assertEq(uint8(uint256(vm.load(address(logT), PqzCore._STORAGE)) >> (8 * 23)), PqzCore.LOG);
    }

    /// `OFFCHAIN` (3f): the verdict replaces the precompile, the event is the same (the header as verified, the calldata proof).
    function test_proofStore_offchain() public {
        pStore = PqzCore.LOG;
        NormalPqzToken off = _offToken("off-log", vA, false);
        pStore = 0;
        _shieldOn(off, alice, 10);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(off, alice, bob, 5, false);
        vm.recordLogs();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, st));
        (Vm.Log[] memory ls, uint256 n) = _logs(address(off));
        assertEq(n, 1, "one event in OFFCHAIN mode");
        (bytes memory header, bytes memory proof) = abi.decode(ls[0].data, (bytes, bytes));
        assertEq(header, _slice(st, 0, 640));
        assertEq(proof, VPROOF);
        assertEq(off.pqzDebitRecord(alice, 0).proofStore, PqzCore.LOG);
    }

    /// Codex C3: `NONE`, `LOG`, `NONE` with credits between (slot 0 byte 23 written here; the bit-24 setter is T61's): each
    /// record keeps the mode it was written with, each debit logs exactly by its own.
    function test_proofStore_noneLogNone_creditsBetween() public {
        _shieldT(tok, alice, 10);
        uint8[3] memory modes = [PqzCore.NONE, PqzCore.LOG, PqzCore.NONE];
        for (uint64 k; k < 3; ++k) {
            _setByte23(tok, modes[k]);
            tok.mtxConfidentialTransferSingle(_ts(_payload(0, 0, bob, alice, bytes32(0), _out(20 + k, false), "")), PROOF,
                _pqAuth(), "", noVerdict()); // a credit to alice between her debits
            uint64 p = tok.pqzAccount(alice, 0).pendingCount;
            IPqzToken.PqzTransferArgs memory a = _ts(_payload(p, 0, alice, carol, bytes32(0), _out(30 + k, false), ""));
            bytes memory st = tok.transferSingleStatement(a, 0);
            vm.recordLogs();
            tok.mtxConfidentialTransferSingle(a, PROOF, _pqAuth(), "", noVerdict());
            _check(tok, alice, k, st, modes[k]);
        }
        assertEq(abi.encode(tok.pqzDebitRecord(alice, 0).proofStore, tok.pqzDebitRecord(alice, 1).proofStore,
            tok.pqzDebitRecord(alice, 2).proofStore), abi.encode(PqzCore.NONE, PqzCore.LOG, PqzCore.NONE), "each record its own");
    }

    function _setByte23(NormalPqzToken t, uint8 m) internal {
        uint256 w = uint256(vm.load(address(t), PqzCore._STORAGE));
        w = (w & ~(uint256(0xff) << 184)) | (uint256(m) << 184);
        vm.store(address(t), PqzCore._STORAGE, bytes32(w));
        assertEq(t.proofStore(), m);
    }

    /// 2 and above: `ProofStoreInvalid`.
    function test_proofStore_invalid() public {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        for (uint256 i; i < 2; ++i) {
            c.conf.proofStore = i == 0 ? 2 : 255;
            vm.expectRevert(abi.encodeWithSelector(IPqzToken.ProofStoreInvalid.selector, c.conf.proofStore));
            factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), bytes32(i + 100));
        }
    }

}

/// T60 (C8): a Zether kind refuses a set `proofStore` with the other kind's field error, in the check 3f's fields have (Zether ≠
/// PQZ; no Zether body moves); `NONE` creates as before.
contract PqzProofStoreZetherTest is ZetherFixture {
    function setUp() public {
        _stack();
    }

    function test_proofStore_zether_refused() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.conf.proofStore = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z-log");
        c.conf.proofStore = 0;
        assertTrue(factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z-none") != address(0));
    }
}
