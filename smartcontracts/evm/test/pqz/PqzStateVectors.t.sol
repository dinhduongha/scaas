// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {UACall} from "../ua/UACall.sol";
import {PqzSlots} from "./PqzState.t.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// @notice ua-rs-sign T15e (spec no-decryption-oracle §4.4, §5): the PQZ state vectors of the build's set. A token in several
///         account states (`acc` never debited, a reference to the last debit's blob, materialised by a rollover; TRIVIAL and
///         credit entries; op 1 and op 7 entries, with and without the auditor copies, BUNDLE and HASH), then per account the
///         raw words a reading layer reads (the account struct's slots, the pending slots of `[rolled, p)`, the `acc` slots,
///         every SSTORE2 code, the registry's key record) with the contract's own `T` at the facade's `p` (CTR-PQZ-06), from its
///         burn statement view, and per entry leg its `u ‖ v` (and the auditor copy) from the disclosure statement view, and the
///         op 1 / op 7 / burn `memoHash` words of the statement views. Proofs mocked (no proof is in a row). `STATE_VECTORS=1`
///         writes `smartcontracts/vectors/pqz/[<set>/]state.json` (the commit in `CONTRACT_COMMIT`); ua-rs reproduces every
///         `T` and ciphertext from the words (`tests/facade_pqz_state.rs`). Group 3h T62 (pqz-proof-path spec §9.3, C-PP-1;
///         `"release": "3h"`): every debit's record words with the view's answer (narrow, wide by `shieldIn`, one under `LOG`),
///         every op blob's tail `ownTag ‖ kv ‖ u8(n)` (op 1 with and without the auditor, op 7, a leg at key version 1, a
///         burn) and the logged P of the `LOG` debit as emitted. T62a (owner 2026-11-09, for ua-rs-sign T20d): `noneHeaders`,
///         one `NONE` debit per form and path (op 1, op 7, burn, refresh, unwrap; direct and relayed through its named UA
///         entry): the call's named fields, the token's words, the envelope and `envelopeBinding`, the binding word and the
///         640 header bytes the precompile was called with; `test_noneHeaderRows` reads them back. UNAUDITED.
contract PqzStateVectorsTest is PqzSlots {
    bytes32 internal dave;
    bytes32 internal erin;
    string internal path;

    struct Ent {
        string name;
        bytes32 ref;
        bytes32 from;
        uint64 counter;
    }

    Ent[] internal ents;

    // group 3h T62: the tails of op blobs that are no entry row (a rotated leg, the burn's acc blob), the expected `kv` of the
    // rotated op 7 (its leg at version 1), and the one `LOG` debit's event
    struct Tail {
        string name;
        address blob;
        uint64[] kv;
    }

    Tail[] internal extra;
    bytes32 internal fay;
    Vm.Log internal proofLog;
    bytes32 internal constant EV_PROOF = keccak256("PqzDebitProof(address,bytes32,uint64,bytes,bytes)");

    function setUp() public {
        _stack();
        tok = _newToken("state-vectors");
        dave = _pqzUA(_pk(9), 5);
        erin = _pqzUA(_pk(11), 6);
        _mockOp(7, 1);
    }

    // ------------------------------------------------------------------ the state

    function _single(string memory name, bytes32 from, bytes32 to, uint256 seed, bool aud, bool hash) internal {
        uint64 c = tok.pqzAccount(from, 0).sendCounter;
        bytes memory pl = _payload(tok.pqzAccount(from, 0).pendingCount, 0, from, to, bytes32(0), _out(seed, aud), hash ? _memo() : bytes(""));
        bytes32 ref = hash
            ? tok.mtxConfidentialTransferSingleCompact(_ts(pl), hex"c0de", _pqAuth(), "", noVerdict())
            : tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "", noVerdict());
        ents.push(Ent(name, ref, from, c));
    }

    function _mpl(bytes32 from, bytes32[] memory rec, uint256 seed, bool aud, bool hash) internal view returns (bytes memory) {
        bytes memory memo = hash ? bytes.concat(salt, _slice(_blob(seed + 1, 2 + 40 * rec.length + 32), 0, 2 + 40 * rec.length)) : bytes("");
        return _mpayload(tok.pqzAccount(from, 0).pendingCount, 0, from, bytes32(0), rec, _blob(seed, _outLen(rec.length, aud)), memo);
    }

    function _multi(string memory name, bytes32 from, bytes32[] memory rec, uint256 seed, bool aud, bool hash) internal {
        uint64 c = tok.pqzAccount(from, 0).sendCounter;
        IPqzToken.PqzMultiArgs memory t = _ms(_mpl(from, rec, seed, aud, hash));
        bytes32 ref = hash
            ? tok.mtxConfidentialTransferCompact(t, hex"c0de", _pqAuth(), "", noVerdict())
            : tok.mtxConfidentialTransfer(t, hex"c0de", _pqAuth(), "", noVerdict());
        ents.push(Ent(name, ref, from, c));
    }

    function _legs(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](2);
        (r[0], r[1]) = (a, b);
    }

    function _legs(bytes32 a, bytes32 b, bytes32 c, bytes32 d) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](4);
        (r[0], r[1], r[2], r[3]) = (a, b, c, d);
    }

    /// A shield (a TRIVIAL entry, merged into a same-block TRIVIAL tail) without the fixture's client mirror.
    function _shield(bytes32 ua, uint256 amount) internal {
        _public(tok, address(this), amount * SCALE);
        tok.mtxShield(ua, amount);
    }

    function _build() internal {
        _shield(alice, 7);
        vm.roll(vm.getBlockNumber() + 1);
        _shield(alice, 3);
        _single("op1 carol->alice audited", carol, alice, 11, true, false);
        _multi("op7 M=2 audited carol->[alice,bob]", carol, _legs(alice, bob), 21, true, false);
        _prepare(tok, alice);
        vm.roll(vm.getBlockNumber() + ROLL_AGE);
        tok.mtxRollOver(alice, 0, 3); // alice: acc materialised, entry 3 still pending
        _single("op1 carol->alice", carol, alice, 12, false, false);
        _shield(alice, 5);
        _single("op1 carol->bob", carol, bob, 13, false, false);
        _single("op1 bob->carol audited (bob's debit)", bob, carol, 14, true, false); // bob: acc = his debit's blob
        _multi("op7 M=4 carol->[bob,alice,dave,erin]", carol, _legs(bob, alice, dave, erin), 22, false, false);
        _multi("op7 M=4 audited carol->[dave,bob,erin,alice]", carol, _legs(dave, bob, erin, alice), 23, true, false);
        _shield(bob, 2);
        _single("op1 HASH carol->dave", carol, dave, 15, false, true);
        _multi("op7 M=2 HASH carol->[alice,erin]", carol, _legs(alice, erin), 24, false, true);
        _proofPath();
        _shield(carol, 9); // carol: acc = her last debit's blob, one TRIVIAL entry pending
    }

    /// Group 3h T62: carol's debits of the proof-path rows, each with its own non-zero `ownTag`: op 1 with `shieldIn` 4 (a wide
    /// record), op 1 under `LOG` (slot 0 byte 23 written here; its event kept), op 7 to alice and fay with fay's key rotated to
    /// version 1, and a burn of 1 (its acc blob's tail holds no version).
    function _proofPath() internal {
        _public(tok, address(this), 4 * SCALE);
        IPqzToken.PqzTransferArgs memory a = _ts(_payload(tok.pqzAccount(carol, 0).pendingCount, 4, carol, alice, bytes32(0),
            _out(16, false), ""));
        a.ownTag = keccak256("T62 own tag wide");
        uint64 c = tok.pqzAccount(carol, 0).sendCounter;
        ents.push(Ent("op1 carol->alice shieldIn 4 (a wide record)", tok.mtxConfidentialTransferSingle(a, hex"c0de", _pqAuth(), "",
            noVerdict()), carol, c));
        _mode(PqzCore.LOG);
        a = _ts(_payload(tok.pqzAccount(carol, 0).pendingCount, 0, carol, bob, bytes32(0), _out(17, true), ""));
        a.ownTag = keccak256("T62 own tag log");
        c = tok.pqzAccount(carol, 0).sendCounter;
        vm.recordLogs();
        ents.push(Ent("op1 carol->bob audited, under LOG", tok.mtxConfidentialTransferSingle(a, hex"c0ffee", _pqAuth(), "",
            noVerdict()), carol, c));
        Vm.Log[] memory ls = vm.getRecordedLogs();
        for (uint256 i; i < ls.length; ++i) if (ls[i].emitter == address(tok) && ls[i].topics[0] == EV_PROOF) proofLog = ls[i];
        assertEq(proofLog.topics.length, 4, "the LOG debit's PqzDebitProof");
        _mode(PqzCore.NONE);
        fay = _pqzUA(_pk(13), 7);
        reg.setPqzKey(fay, 1, _pk(14), keccak256("pqzver fay 1"), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(fay, 1, "pqzver fay 1");
        IPqzToken.PqzMultiArgs memory m = _ms(_mpl(carol, _legs(alice, fay), 25, true, false));
        m.ownTag = keccak256("T62 own tag op7");
        bytes32 ref = tok.mtxConfidentialTransfer(m, hex"c0de", _pqAuth(), "", noVerdict());
        uint64[] memory kv = new uint64[](3);
        kv[1] = 1; // alice 0, fay 1, the auditor 0
        extra.push(Tail("op7 M=2 audited carol->[alice,fay at key version 1]", _ptr(ref), kv));
        IPqzToken.PqzBurnArgs memory b = _bs(bytes.concat(abi.encode(uint256(tok.pqzAccount(carol, 0).pendingCount), block.number + 5,
            uint256(0), carol, bytes32(0)), _blob(79, PqzCt.CT)));
        b.ownTag = keccak256("T62 own tag burn");
        tok.mtxUnshield(b, 1, bytes32(uint256(0xD00D)), hex"c0de", _pqAuth(), "", noVerdict());
        extra.push(Tail("burn 1 carol (her acc blob)", tok.pqzAccount(carol, 0).accBlob, new uint64[](0)));
    }

    function _mode(uint8 m) internal {
        uint256 w = uint256(vm.load(address(tok), bytes32(BASE)));
        vm.store(address(tok), bytes32(BASE), bytes32((w & ~(uint256(0xff) << 184)) | (uint256(m) << 184)));
        assertEq(tok.proofStore(), m);
    }

    function _ptr(bytes32 ref) internal view returns (address) {
        return address(uint160(uint256(vm.load(address(tok), keccak256(abi.encode(ref, BASE + 9))))));
    }

    // ------------------------------------------------------------------ the rows

    function _w(string memory s) internal {
        vm.writeLine(path, s);
    }

    function _q(string memory s) internal pure returns (string memory) {
        return string.concat("\"", s, "\"");
    }

    function _hx(bytes memory b) internal pure returns (string memory) {
        return _q(vm.toString(b));
    }

    function _hx32(bytes32 w) internal pure returns (string memory) {
        return _q(vm.toString(w));
    }

    function _hxa(address a) internal pure returns (string memory) {
        return _q(vm.toString(abi.encodePacked(a)));
    }

    function _load(address a, uint256 slot) internal view returns (bytes32) {
        return vm.load(a, bytes32(slot));
    }

    /// The registry's `pqzKey[ua][0]` word (`UAStore.Layout` slot 2, per version since group 3g: the fixtures hold version
    /// 0) and its pointer, checked against `pqzKeyOf`.
    function _keyRecord(bytes32 ua) internal view returns (bytes32 w, address ptr) {
        w = _load(address(reg), uint256(keccak256(abi.encode(uint64(0), keccak256(abi.encode(ua, uint256(2)))))));
        (, ptr,,) = reg.pqzKeyOf(ua);
        assertEq(address(uint160(uint256(w))), ptr, "keyRecord: the pointer");
        assertEq(uint8(uint256(w) >> 160), 1, "keyRecord: proven");
    }

    function _blobRow(address a, bool first) internal {
        _w(string.concat(first ? "" : ",", "{\"address\": ", _hxa(a), ", \"code\": ", _hx(a.code), "}"));
    }

    /// The facade's `p` (CTR-PQZ-06): `pendingCount` or the largest `p` the inline window and `K_MAX` allow.
    function _p(IPqzToken.AccountState memory a) internal pure returns (uint64 p) {
        p = a.pendingCount;
        uint256 lim = a.rolled + PqzCore.INLINE_MAX;
        if (a.rolled + PqzCore.K_MAX - 1 - a.accUnits < lim) lim = a.rolled + PqzCore.K_MAX - 1 - a.accUnits;
        if (lim < p) p = uint64(lim);
    }

    /// `T` of `ua` at `p` with `shieldIn`, from the token's burn (refresh) statement: `header ‖ pk_f ‖ T ‖ u' ‖ v_f`.
    function _tOf(bytes32 ua, uint64 p, uint256 shieldIn) internal view returns (bytes memory) {
        bytes memory pl = bytes.concat(abi.encode(uint256(p), block.number + 5, shieldIn, ua, bytes32(0)), _blob(77, PqzCt.CT));
        return _slice(tok.burnStatement(_bs(pl), 0, bytes32(0), 0), 640 + PqzCt.PK, PqzCt.CT);
    }

    function _account(string memory name, bytes32 ua, uint256 shieldIn, bool last) internal {
        IPqzToken.AccountState memory a = tok.pqzAccount(ua, 0);
        uint64 p = _p(a);
        (bytes32 kr, address kp) = _keyRecord(ua);
        _w(string.concat("{\"name\": ", _q(name), ", \"ua\": ", _hx32(ua), ", \"block\": ", vm.toString(block.number),
            ", \"keyRecord\": ", _hx32(kr), ", \"shieldIn\": ", vm.toString(shieldIn), ", \"p\": ", vm.toString(uint256(p)),
            ", \"sendCounter\": ", vm.toString(uint256(a.sendCounter)), ","));
        _words(ua, a, p);
        _w("], \"blobs\": [");
        _blobRow(kp, true);
        if (a.flags & 1 == 0 && a.accBlob != address(0)) _blobRow(a.accBlob, false);
        for (uint64 i = a.rolled; i < p; ++i) {
            uint256 e = tok.pqzPending(ua, 0, i);
            if (uint16(e >> 64) != 0) _blobRow(address(uint160(e >> 96)), false);
        }
        _w(string.concat("], \"T\": ", _hx(_tOf(ua, p, shieldIn)), "}", last ? "" : ","));
    }

    /// The account struct's slots 0..3 of `(ua, version 0)` (group 3g T52: `sendCounter` left the struct, `sendCounter[ua]` is
    /// its own field, the row's `sendCounter`; group 3h T58: slot 2 `lastDebit`, slot 3 `accHash`), the pending slots of
    /// `[rolled, p)`, the `acc` slots (materialised only).
    function _words(bytes32 ua, IPqzToken.AccountState memory a, uint64 p) internal {
        uint256 base = _acctSlot(ua);
        _w(string.concat("\"account\": [", _hx32(_load(address(tok), base)), ", ", _hx32(_load(address(tok), base + 1)), ", ",
            _hx32(_load(address(tok), base + 2)), ", ", _hx32(_load(address(tok), base + 3)), "],"));
        _w("\"pending\": [");
        for (uint64 i = a.rolled; i < p; ++i) {
            bytes32 e = vm.load(address(tok), _pendingSlot(ua, i));
            _w(string.concat(i == a.rolled ? "" : ",", "{\"index\": ", vm.toString(uint256(i)), ", \"word\": ", _hx32(e), "}"));
        }
        _w("], \"accWords\": [");
        for (uint256 i; a.flags & 1 != 0 && i < PqzCt.ACC_WORDS; ++i) {
            _w(string.concat(i == 0 ? "" : ",", _hx32(_load(address(tok), base + 5 + i))));
        }
    }

    function _entry(Ent memory x, bool last) internal {
        address ptr = address(uint160(uint256(vm.load(address(tok), keccak256(abi.encode(x.ref, BASE + 9))))));
        assertEq(keccak256(_slice(ptr.code, 1, ptr.code.length - 1)), keccak256(tok.pqzEntryBlob(x.ref)), "entryPtr: the entry's blob");
        bytes memory te = tok.transferEntry(x.ref); // R, or keccak256(R) ‖ memo (commit-reveal)
        bytes memory memo = keccak256(te) == keccak256(PqzCore.rOf(ptr)) ? bytes("") : _slice(te, 32, te.length - 32);
        _w(string.concat("{\"name\": ", _q(x.name), ", \"entryRef\": ", _hx32(x.ref), ", \"fromUA\": ", _hx32(x.from),
            ", \"sendCounter\": ", vm.toString(uint256(x.counter)), ", \"entryPtr\": ", _hx32(bytes32(uint256(uint160(ptr)))), ","));
        _w(string.concat("\"memo\": ", _hx(memo), ", \"blob\": "));
        _blobRow(ptr, true);
        _w(", \"legs\": [");
        for (uint256 j; j < 8; ++j) {
            try tok.disclosureStatement(x.ref, j, 0, 1, 0) returns (bytes memory rx) {
                bytes32 owner = _ownerOf(ptr, j);
                (bytes32 kr, address kp) = _keyRecord(owner);
                string memory au = "\"\"";
                try tok.disclosureStatement(x.ref, j, 0, 2, 0) returns (bytes memory ax) {
                    au = _hx(_slice(ax, 288 + PqzCt.PK, PqzCt.CT));
                } catch {}
                _w(string.concat(j == 0 ? "" : ",", "{\"leg\": ", vm.toString(j), ", \"ua\": ", _hx32(owner), ", \"keyRecord\": ",
                    _hx32(kr), ", \"key\": "));
                _blobRow(kp, true);
                _w(string.concat(", \"ct\": ", _hx(_slice(rx, 288 + PqzCt.PK, PqzCt.CT)), ", \"auditorCt\": ", au, "}"));
            } catch {
                break;
            }
        }
        _w(string.concat("]}", last ? "" : ","));
    }

    /// The owner of leg `j` the token names in its receiver disclosure statement: the key there is `pqzKeyOf(UA_j)`.
    function _ownerOf(address ptr, uint256 j) internal view returns (bytes32 o) {
        bytes memory r = PqzCore.rOf(ptr);
        (uint256 g, uint256 m, uint256 a) = PqzCore._bundleShape(r.length);
        assertLt(j, m);
        uint256 ls = 32 + PqzCt.VP * (1 + a);
        uint256 end = 16 + PqzCt.PKP * g + ls * (j + 1);
        assembly ("memory-safe") { o := mload(add(add(r, 32), sub(end, 32))) }
    }

    /// The statements' `memoHash` word (header word 19): group 3h T59 (C3) `keccak256(memo ‖ ownTag)`, `memo` = `salt ‖ sealedMemo`
    /// on op 1 and op 7 HASH, empty on BUNDLE and a burn; each row names its `ownTag` (0 here, the payloads').
    function _memoHashes() internal {
        bytes memory memo = _memo();
        bytes memory pl = _payload(tok.pqzAccount(carol, 0).pendingCount, 0, carol, dave, bytes32(0), _out(31, false), memo);
        bytes memory st = tok.transferSingleStatement(_ts(pl), 0);
        _w(string.concat("{\"op\": 1, \"mode\": \"HASH\", \"salt\": ", _hx(abi.encodePacked(salt)), ", \"sealedMemo\": ",
            _hx(_slice(memo, 16, PqzCore.SEALED)), ", \"ownTag\": ", _hx32(bytes32(0)), ", \"memoHash\": ", _hx32(_word(st, 608)), "},"));
        pl = _payload(tok.pqzAccount(carol, 0).pendingCount, 0, carol, dave, bytes32(0), _out(31, false), "");
        _w(string.concat("{\"op\": 1, \"mode\": \"BUNDLE\", \"ownTag\": ", _hx32(bytes32(0)), ", \"memoHash\": ", _hx32(_word(tok.transferSingleStatement(_ts(pl), 0), 608)), "},"));
        IPqzToken.PqzMultiArgs memory t = _ms(_mpl(carol, _legs(alice, erin), 32, false, true));
        _w(string.concat("{\"op\": 7, \"mode\": \"HASH\", \"salt\": ", _hx(abi.encodePacked(t.salt)), ", \"sealedMemo\": ",
            _hx(t.sealedMemo), ", \"ownTag\": ", _hx32(t.ownTag), ", \"memoHash\": ", _hx32(_word(tok.transferStatement(t, 0), 608)), "},"));
        bytes memory bl = bytes.concat(abi.encode(uint256(tok.pqzAccount(carol, 0).pendingCount), block.number + 5, uint256(0), carol,
            bytes32(0)), _blob(78, PqzCt.CT));
        _w(string.concat("{\"op\": 2, \"mode\": \"\", \"ownTag\": ", _hx32(bytes32(0)), ", \"memoHash\": ", _hx32(_word(tok.burnStatement(_bs(bl), 1, bytes32(uint256(5)), 0), 608)), "}"));
    }

    /// `debitRec[ua][k]` (PqzStorage slot 19): the two words as stored and the view's answer, every debit of `ua`.
    function _records(bytes32 ua, bool last) internal {
        uint64 n = tok.pqzAccount(ua, 0).sendCounter;
        for (uint64 k; k < n; ++k) {
            uint256 s0 = uint256(keccak256(abi.encode(uint256(k), keccak256(abi.encode(ua, BASE + 19)))));
            (bytes32 w0, bytes32 w1) = (_load(address(tok), s0), _load(address(tok), s0 + 1));
            assertTrue(w0 != 0 && uint8(uint256(w0)) & 1 == 1, "a record, RECORD set");
            _w(string.concat("{\"ua\": ", _hx32(ua), ", \"counter\": ", vm.toString(uint256(k)), ", \"w0\": ", _hx32(w0), ", \"w1\": ",
                _hx32(w1), ", \"view\": ", _view(tok.pqzDebitRecord(ua, k)), "}", last && k + 1 == n ? "" : ","));
        }
    }

    function _view(IPqzToken.DebitRecordView memory v) internal pure returns (string memory) {
        string memory a = string.concat("{\"prevBlob\": ", _hxa(v.prevBlob), ", \"p\": ", vm.toString(uint256(v.p)), ", \"deltaP\": ",
            vm.toString(uint256(v.deltaP)), ", \"proofStore\": ", vm.toString(uint256(v.proofStore)));
        return string.concat(a, ", \"shieldIn\": ", vm.toString(uint256(v.shieldIn)), ", \"keyVersion\": ", vm.toString(uint256(v.keyVersion)),
            ", \"prevCounter\": ", vm.toString(uint256(v.prevCounter)), ", \"hasPrev\": ", v.hasPrev ? "true" : "false", "}");
    }

    /// An op blob's tail `ownTag ‖ be64 kv ‖ u8(n)` (spec §3.2), read here from its code and held to what the statement used
    /// (`kv`), with `rOf`'s length.
    function _tail(string memory name, address ptr, uint64[] memory kv, bool last) internal {
        bytes memory c = ptr.code;
        uint256 n = uint8(c[c.length - 1]);
        assertEq(n, kv.length, string.concat(name, ": n"));
        uint256 t = c.length - 1 - (33 + 8 * n); // the tail's start in the data (c = STOP ‖ data)
        string memory ks;
        for (uint256 i; i < n; ++i) {
            uint64 v = uint64(bytes8(_slice(c, 1 + t + 32 + 8 * i, 8)));
            assertEq(v, kv[i], string.concat(name, ": kv"));
            ks = string.concat(ks, i == 0 ? "" : ", ", vm.toString(uint256(v)));
        }
        _w(string.concat("{\"name\": ", _q(name), ", \"blob\": ", _hxa(ptr), ", \"code\": ", _hx(c), ", \"ownTag\": ",
            _hx32(bytes32(_slice(c, 1 + t, 32))), ","));
        _w(string.concat("\"kv\": [", ks, "], \"n\": ", vm.toString(n), ", \"rLen\": ", vm.toString(PqzCore.rOf(ptr).length),
            ", \"vp\": ", vm.toString(PqzCt.VP), "}", last ? "" : ","));
    }

    /// The `kv` an entry's statement used: every receiver and the auditor at version 0, but fay at 1 (none in `ents`).
    function _kvOf(address ptr) internal view returns (uint64[] memory kv) {
        kv = new uint64[](uint8(ptr.code[ptr.code.length - 1]));
    }

    function _proofLogRow() internal {
        (bytes memory h, bytes memory pr) = abi.decode(proofLog.data, (bytes, bytes));
        _w(string.concat("{\"name\": \"op1 carol->bob audited, under LOG\", \"emitter\": ", _hxa(proofLog.emitter), ", \"topics\": [",
            _hx32(proofLog.topics[0]), ", ", _hx32(proofLog.topics[1]), ", ", _hx32(proofLog.topics[2]), ", ", _hx32(proofLog.topics[3]),
            "], \"data\": ", _hx(proofLog.data), ","));
        _w(string.concat("\"blob\": ", _hxa(address(uint160(uint256(proofLog.topics[1])))), ", \"ua\": ", _hx32(proofLog.topics[2]),
            ", \"sendCounter\": ", vm.toString(uint256(proofLog.topics[3])), ", \"header\": ", _hx(h), ", \"proof\": ", _hx(pr), "}"));
    }

    function _uints(uint256[] memory v) internal pure returns (string memory r) {
        for (uint256 i; i < v.length; ++i) r = string.concat(r, i == 0 ? "" : ", ", vm.toString(v[i]));
        r = string.concat("[", r, "]");
    }

    /// T19c's pin of `scaas.pqz` (`test/v2/layout/namespaces.json`), copied into the rows when this commit has it, so ua-rs
    /// compares its parser's table with the pin of the same contract commit.
    function _layout() internal {
        string memory ns = vm.readFile(string.concat(vm.projectRoot(), "/test/v2/layout/namespaces.json"));
        if (!vm.keyExistsJson(ns, ".pqz")) return;
        string[] memory labels = vm.parseJsonStringArray(ns, ".pqz.labels");
        string memory l;
        for (uint256 i; i < labels.length; ++i) l = string.concat(l, i == 0 ? "" : ", ", _q(labels[i]));
        _w(string.concat("\"layout\": {\"id\": ", _q(vm.parseJsonString(ns, ".pqz.id")), ", \"root\": ",
            _hx32(vm.parseJsonBytes32(ns, ".pqz.root")), ", \"labels\": [", l, "],"));
        _w(string.concat("\"slots\": ", _uints(vm.parseJsonUintArray(ns, ".pqz.slots")), ", \"inner\": ",
            _uints(vm.parseJsonUintArray(ns, ".pqz.inner")), ", \"bytes\": ", _uints(vm.parseJsonUintArray(ns, ".pqz.bytes")),
            ", \"widths\": ", _uints(vm.parseJsonUintArray(ns, ".pqz.widths")), "},"));
    }

    /// Builds the state; with `STATE_VECTORS=1` writes the rows (two runs give the same file).
    function test_stateVectors() public {
        _build();
        // the account kinds the rows must cover
        assertEq(tok.pqzAccount(alice, 0).flags & 1, 1, "alice: materialised");
        assertTrue(tok.pqzAccount(bob, 0).accBlob != address(0) && tok.pqzAccount(bob, 0).flags & 1 == 0, "bob: a reference");
        assertEq(tok.pqzAccount(dave, 0).accBlob, address(0), "dave: never debited");
        if (!vm.envOr("STATE_VECTORS", false)) return;
        path = string.concat(_vecDir(), "state.json");
        vm.writeFile(path, "");
        _w(string.concat("{\"_comment\": ", _q(string.concat("smartcontracts/evm/test/pqz/PqzStateVectors.t.sol at contract commit ",
            vm.envString("CONTRACT_COMMIT"), " (STATE_VECTORS=1); proofs mocked; UNAUDITED")), ","));
        _w(string.concat("\"file\": \"state.json\", \"release\": \"3h\", \"set\": ", _q(PqzSet.NAME), ", \"contractCommit\": ", _q(vm.envString("CONTRACT_COMMIT")), ", \"chainId\": ",
            vm.toString(block.chainid), ", \"chainUid\": ", _hx32(tok.chainUid()), ", \"token\": ", _hxa(address(tok)), ", \"registry\": ",
            _hxa(address(reg)), ","));
        _w(string.concat("\"psid\": ", _hx32(_load(address(tok), BASE + 2)), ", \"auditorMode\": ",
            _hx32(_load(address(tok), BASE)), ", \"auditorUA\": ", _hx32(_load(address(tok), BASE + 7)), ","));
        (bytes32 akr, address akp) = _keyRecord(aud);
        _w(string.concat("\"auditorKeyRecord\": ", _hx32(akr), ", \"auditorKey\": "));
        _blobRow(akp, true);
        _w(",");
        _layout();
        _w("\"accounts\": [");
        _account("alice: materialised acc, pending", alice, 0, false);
        _account("bob: acc a debit's blob, pending credits and a TRIVIAL entry", bob, 0, false);
        _account("carol: acc her last debit's blob, a TRIVIAL entry, shieldIn 5", carol, 5, false);
        _account("dave: never debited, op 1 and op 7 credits", dave, 0, false);
        _account("erin: never debited, op 7 credits", erin, 0, true);
        _w("], \"entries\": [");
        for (uint256 i; i < ents.length; ++i) _entry(ents[i], i + 1 == ents.length);
        _w("], \"memoHash\": [");
        _memoHashes();
        _w("], \"records\": [");
        _records(bob, false);
        _records(carol, true);
        _w("], \"tails\": [");
        for (uint256 i; i < ents.length; ++i) {
            address ptr = _ptr(ents[i].ref);
            _tail(ents[i].name, ptr, _kvOf(ptr), false);
        }
        for (uint256 i; i < extra.length; ++i) _tail(extra[i].name, extra[i].blob, extra[i].kv, i + 1 == extra.length);
        _w("], \"proofLogs\": [");
        _proofLogRow();
        _w("], \"noneHeaders\": [");
        _none();
        for (uint256 i; i < noneRows.length; ++i) _w(string.concat(noneRows[i], i + 1 == noneRows.length ? "" : ","));
        _w("]}");
    }

    // ------------------------------------------------------------------ T62a: NONE headers and relayed bindings

    address internal constant RELAYER = address(0xBEEF);
    bytes internal constant PROOF = hex"c0de";
    string[] internal noneRows;
    bytes[] internal noneHdrs;
    WrappedPqzToken internal wt;

    /// T62a: carol's debits under `NONE` after the rows above (they keep their bytes), one per form and path. A relayed call
    /// goes through the form's named UA entry, carol signing the envelope; the envelopes vary `mode`, `batch` and `fee`, with
    /// non-zero unbound relayer or fee recipient (a client must count them as 0). Unwrap on a `WRAPPED_PQZ` token of its own.
    function _none() internal {
        assertEq(tok.proofStore(), PqzCore.NONE);
        MetaTxLib.UAEnvelope memory d; // direct: no envelope, the views' binding 0
        _public(tok, address(this), 2 * SCALE);
        IPqzToken.PqzTransferArgs memory a = _ts(_payload(_pc(tok), 2, carol, alice, bytes32(0), _out(41, false), ""));
        a.ownTag = keccak256("T62a op1 direct");
        _n1(a, d, "op1 BUNDLE direct carol->alice, shieldIn 2");
        a = _ts(_payload(_pc(tok), 0, carol, dave, bob, _out(42, true), _memo()));
        a.ownTag = keccak256("T62a op1 relayed");
        _n1(a, _uEnv(tok, 0, MetaTxLib.MODE_RESTRICT_RELAYER, RELAYER, 0, address(0xFEE1)),
            "op1 HASH relayed audited carol->dave, beneficiary bob; relayer bound, fee recipient unbound");
        IPqzToken.PqzMultiArgs memory m = _ms(_mpl(carol, _legs(alice, erin), 43, true, true));
        m.ownTag = keccak256("T62a op7 direct");
        _n7(m, d, "op7 M=2 HASH direct audited carol->[alice,erin]");
        decoy = 2;
        m = _ms(_mpl(carol, _legs(bob, alice, dave, erin), 44, false, false));
        (m.beneficiaryUA, m.ownTag) = (fay, keccak256("T62a op7 relayed"));
        decoy = 0;
        _n7(m, _uEnv(tok, 7, MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, address(0xBEE2), 5, address(0xFEE2)),
            "op7 M=4 BUNDLE relayed carol->[bob,alice,dave,erin], beneficiary fay, decoyFee 2; fee recipient bound, relayer unbound, fee 5 under fee mode none");
        bytes32 rcp = bytes32(uint256(0xD00D));
        _nb(_burnArgs(tok, bytes32(0), 81, "T62a burn direct"), 1, rcp, d, "burn 1 direct carol to 0xd00d");
        _nb(_burnArgs(tok, bob, 82, "T62a burn relayed"), 2, rcp, _uEnv(tok, 0, 3, RELAYER, 0, address(0xFEE3)),
            "burn 2 relayed carol to 0xd00d, beneficiary bob; relayer and fee recipient bound");
        _nb(_burnArgs(tok, bytes32(0), 83, "T62a refresh direct"), 0, 0, d, "refresh direct carol");
        _nb(_burnArgs(tok, bytes32(0), 84, "T62a refresh relayed"), 0, 0, _uEnv(tok, 9, 0, address(0xBEE4), 0, address(0xFEE4)),
            "refresh relayed carol; relayer and fee recipient unbound, both non-zero");
        _releaseWrapped();
        wt = _newWrapped("t62a");
        MockERC20 usd = MockERC20(wt.underlyings()[0]);
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(wt), 100 * SCALE);
        wt.mtxWrapShield(address(usd), 100 * SCALE, carol);
        PqzLayer w = PqzLayer(address(wt));
        _nu(_burnArgs(w, bytes32(0), 85, "T62a unwrap direct"), IConfidentialWrappedToken.Unwrap(address(usd), rcp, 10, 10 * SCALE), d,
            "unwrap 10 direct carol to 0xd00d (a WRAPPED_PQZ token)");
        _nu(_burnArgs(w, bob, 86, "T62a unwrap relayed"), IConfidentialWrappedToken.Unwrap(address(usd), rcp, 5, 4 * SCALE),
            _uEnv(w, 0, MetaTxLib.MODE_RESTRICT_RELAYER, RELAYER, 0, address(0xFEE5)),
            "unwrap 5 relayed carol to 0xd00d, minOut below the quote, beneficiary bob (a WRAPPED_PQZ token); relayer bound");
    }

    function _pc(PqzLayer t) internal view returns (uint256) {
        return t.pqzAccount(carol, 0).pendingCount;
    }

    function _uEnv(PqzLayer t, uint256 batch, uint32 mode, address relayer, uint256 fee, address feeRecipient)
        internal view returns (MetaTxLib.UAEnvelope memory)
    {
        return MetaTxLib.UAEnvelope(carol, batch, t.mtxNonce(carol, batch), block.timestamp + 300, mode, relayer, fee, feeRecipient);
    }

    /// The statement views' `binding`: 0 direct, the token's `envelopeBinding` of the envelope relayed (`data` is not bound).
    function _eb(PqzLayer t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return u.from == 0 ? bytes32(0) : t.envelopeBinding(MetaTxLib.UAMetaTransaction(u.from, "", u.batch, u.nonce, u.validUntil,
            u.mode, u.relayer, u.fee, u.feeRecipient));
    }

    function _burnArgs(PqzLayer t, bytes32 ben, uint256 seed, string memory tag) internal view returns (IPqzToken.PqzBurnArgs memory b) {
        b = _bs(bytes.concat(abi.encode(_pc(t), block.number + 100, uint256(0), carol, ben), _blob(seed, PqzCt.CT)));
        b.ownTag = keccak256(bytes(tag));
    }

    function _n1(IPqzToken.PqzTransferArgs memory a, MetaTxLib.UAEnvelope memory u, string memory name) internal {
        bytes32 eb = _eb(tok, u);
        bytes memory st = tok.transferSingleStatement(a, eb);
        _row(tok, name, "op1", u, eb, st, _f1(a));
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, PROOF));
        bool hash = a.sealedMemo.length != 0;
        if (u.from == 0) {
            if (hash) tok.mtxConfidentialTransferSingleCompact(a, PROOF, _pqAuth(), "", noVerdict());
            else tok.mtxConfidentialTransferSingle(a, PROOF, _pqAuth(), "", noVerdict());
        } else {
            vm.prank(RELAYER);
            if (hash) tok.mtxConfidentialTransferSingleCompact(u, a, PROOF, _pqAuth(), "", UACall.auth(carol, _mlAuth()), noVerdict());
            else tok.mtxConfidentialTransferSingle(u, a, PROOF, _pqAuth(), "", UACall.auth(carol, _mlAuth()), noVerdict());
        }
        _sealed(tok);
    }

    function _n7(IPqzToken.PqzMultiArgs memory m, MetaTxLib.UAEnvelope memory u, string memory name) internal {
        bytes32 eb = _eb(tok, u);
        bytes memory st = tok.transferStatement(m, eb);
        _row(tok, name, "op7", u, eb, st, _f7(m));
        vm.expectCall(PQZ, abi.encodePacked(uint8(7), uint32(st.length), st, PROOF));
        bool hash = m.sealedMemo.length != 0;
        if (u.from == 0) {
            if (hash) tok.mtxConfidentialTransferCompact(m, PROOF, _pqAuth(), "", noVerdict());
            else tok.mtxConfidentialTransfer(m, PROOF, _pqAuth(), "", noVerdict());
        } else {
            vm.prank(RELAYER);
            if (hash) tok.mtxConfidentialTransferCompact(u, m, PROOF, _pqAuth(), "", UACall.auth(carol, _mlAuth()), noVerdict());
            else tok.mtxConfidentialTransfer(u, m, PROOF, _pqAuth(), "", UACall.auth(carol, _mlAuth()), noVerdict());
        }
        _sealed(tok);
    }

    function _nb(IPqzToken.PqzBurnArgs memory b, uint256 amount, bytes32 rcp, MetaTxLib.UAEnvelope memory u, string memory name) internal {
        bytes32 eb = _eb(tok, u);
        bytes memory st = tok.burnStatement(b, amount, rcp, eb);
        _row(tok, name, amount == 0 ? "refresh" : "burn", u, eb, st, _burnFields(b, amount, rcp));
        vm.expectCall(PQZ, abi.encodePacked(uint8(2), uint32(st.length), st, PROOF));
        if (u.from == 0) {
            tok.mtxUnshield(b, amount, rcp, PROOF, _pqAuth(), "", noVerdict());
        } else {
            vm.prank(RELAYER);
            tok.mtxUnshield(u, b, IPqzToken.Payout(amount, rcp), PROOF, _pqAuth(), "", UACall.auth(carol, _mlAuth()), noVerdict());
        }
        _sealed(tok);
    }

    function _nu(IPqzToken.PqzBurnArgs memory b, IConfidentialWrappedToken.Unwrap memory x, MetaTxLib.UAEnvelope memory u,
        string memory name) internal
    {
        PqzLayer t = PqzLayer(address(wt));
        bytes32 eb = _eb(t, u);
        bytes memory st = wt.unshieldUnwrapStatement(b, x, eb);
        _row(t, name, "unwrap", u, eb, st, _fu(b, x));
        vm.expectCall(PQZ, abi.encodePacked(uint8(2), uint32(st.length), st, PROOF));
        if (u.from == 0) {
            wt.mtxUnshieldUnwrap(b, x, PROOF, _pqAuth(), "", noVerdict());
        } else {
            vm.prank(RELAYER);
            wt.mtxUnshieldUnwrap(u, b, x, PROOF, _pqAuth(), "", UACall.auth(carol, _mlAuth()), noVerdict());
        }
        _sealed(t);
    }

    function _f1(IPqzToken.PqzTransferArgs memory a) internal pure returns (string memory) {
        string memory f = string.concat("\"fromUA\": ", _hx32(a.fromUA), ", \"toUA\": ", _hx32(a.toUA), ", \"beneficiaryUA\": ",
            _hx32(a.beneficiaryUA), ", \"p\": ", vm.toString(uint256(a.p)), ", \"validUntilBlock\": ", vm.toString(a.validUntilBlock));
        return string.concat(f, ", \"shieldIn\": ", vm.toString(a.shieldIn), _memoFields(a.vAuditor.length != 0, a.salt, a.sealedMemo,
            a.ownTag));
    }

    function _f7(IPqzToken.PqzMultiArgs memory m) internal pure returns (string memory) {
        string memory l;
        for (uint256 j; j < m.legs.length; ++j) l = string.concat(l, j == 0 ? "" : ", ", _hx32(m.legs[j].ua));
        string memory f = string.concat("\"fromUA\": ", _hx32(m.fromUA), ", \"legs\": [", l, "], \"beneficiaryUA\": ",
            _hx32(m.beneficiaryUA), ", \"p\": ", vm.toString(uint256(m.p)), ", \"validUntilBlock\": ", vm.toString(m.validUntilBlock));
        f = string.concat(f, ", \"shieldIn\": ", vm.toString(m.shieldIn), ", \"decoyFee\": ", vm.toString(m.decoyFee));
        return string.concat(f, _memoFields(m.legs[0].vAuditor.length != 0, m.salt, m.sealedMemo, m.ownTag));
    }

    function _fu(IPqzToken.PqzBurnArgs memory b, IConfidentialWrappedToken.Unwrap memory x) internal view returns (string memory) {
        return string.concat(_burnFields(b, x.amount, x.recipient), ", \"underlying\": ", _hxa(x.underlying), ", \"minOut\": ",
            vm.toString(x.minOut), ", \"unwrapBinding\": ", _hx32(wt.unwrapBinding(x.underlying, x.minOut)));
    }

    function _memoFields(bool aud, bytes16 s, bytes memory memo, bytes32 tag) internal pure returns (string memory) {
        return string.concat(", \"auditorOn\": ", aud ? "true" : "false", ", \"salt\": ", _hx(abi.encodePacked(s)), ", \"sealedMemo\": ",
            _hx(memo), ", \"ownTag\": ", _hx32(tag), ", \"transferMode\": ", memo.length != 0 ? "0" : "1");
    }

    function _burnFields(IPqzToken.PqzBurnArgs memory b, uint256 amount, bytes32 rcp) internal pure returns (string memory) {
        string memory s = string.concat("\"fromUA\": ", _hx32(b.fromUA), ", \"beneficiaryUA\": ", _hx32(b.beneficiaryUA), ", \"p\": ",
            vm.toString(uint256(b.p)), ", \"validUntilBlock\": ", vm.toString(b.validUntilBlock), ", \"shieldIn\": ", vm.toString(b.shieldIn));
        return string.concat(s, ", \"ownTag\": ", _hx32(b.ownTag), ", \"amount\": ", vm.toString(amount), ", \"recipient\": ", _hx32(rcp));
    }

    /// A row: the token's words, the sender's `sendCounter` before the call, the form's fields, the envelope (relayed), the
    /// views' `binding` as `envelopeBinding`, header word 17 and the 640 header bytes of the statement the view built.
    function _row(PqzLayer t, string memory name, string memory form, MetaTxLib.UAEnvelope memory u, bytes32 eb, bytes memory st,
        string memory fields) internal
    {
        string memory c = string.concat("{\"name\": ", _q(name), ", \"form\": ", _q(form), ", \"path\": ", _q(u.from == 0 ? "direct" : "relayed"),
            ", \"token\": ", _hxa(address(t)), ", \"chainId\": ", vm.toString(block.chainid), ", \"psid\": ", _hx32(t.proofSystemId()));
        c = string.concat(c, ", \"registry\": ", _hxa(t.registry()), ", \"chainUid\": ", _hx32(t.chainUid()), ", \"confidentialFee\": ",
            vm.toString(t.confidentialFee()), ", \"sendCounter\": ", vm.toString(uint256(t.pqzAccount(carol, 0).sendCounter)), ",\n", fields);
        if (u.from != 0) c = string.concat(c, ",\n", _envJson(u));
        noneRows.push(string.concat(c, ", \"envelopeBinding\": ", _hx32(eb), ", \"binding\": ", _hx32(_word(st, 544)), ",\n\"header\": ",
            _hx(_slice(st, 0, 640)), "}"));
        noneHdrs.push(_slice(st, 0, 640));
    }

    function _envJson(MetaTxLib.UAEnvelope memory u) internal pure returns (string memory) {
        string memory s = string.concat("\"envelope\": {\"from\": ", _hx32(u.from), ", \"batch\": ", vm.toString(u.batch), ", \"nonce\": ",
            vm.toString(u.nonce), ", \"validUntil\": ", vm.toString(u.validUntil), ", \"mode\": ", vm.toString(uint256(u.mode)));
        return string.concat(s, ", \"relayer\": ", _hxa(u.relayer), ", \"fee\": ", vm.toString(u.fee), ", \"feeRecipient\": ",
            _hxa(u.feeRecipient), "}");
    }

    /// The debit just made is recorded under `NONE` (its P is the call's calldata, spec §9.5).
    function _sealed(PqzLayer t) internal view {
        assertEq(t.pqzDebitRecord(carol, t.pqzAccount(carol, 0).sendCounter - 1).proofStore, PqzCore.NONE, "a NONE debit");
    }

    // ------------------------------------------------------------------ T62a: the reader

    /// The 20 header words (pq-zero-knowledge.md §7.7) a client lays out from a row.
    struct Hdr {
        bytes32 opTag;
        bytes32 psid;
        uint256 chainId;
        address token;
        address registry;
        bytes32 from;
        bytes32 to;
        bytes32 ben;
        uint256 fee;
        uint256 amount;
        bytes32 recipient;
        uint256 sendCounter;
        uint256 p;
        uint256 validUntil;
        uint256 auditorOn;
        uint256 shieldIn;
        bytes32 chainUid;
        bytes32 binding;
        uint256 salt;
        bytes32 memoHash;
    }

    /// T62a's reader: the `noneHeaders` rows of the set's `state.json`, each equal to the header this commit's contract built
    /// for the same debit, and rebuilt from the row's named fields alone (the envelope's binding with an unbound relayer or
    /// fee recipient as 0, the binding word by form and path, the 20 words); a set without state vectors is skipped.
    function test_noneHeaderRows() public {
        _build();
        _none();
        string memory f = string.concat(_vecDir(), "state.json");
        if (!vm.exists(f)) vm.skip(true, string.concat(PqzSet.NAME, ": no state.json at this set"));
        string[] memory parts = vm.split(vm.readFile(f), "\"noneHeaders\": ");
        assertEq(parts.length, 2, "state.json: the noneHeaders rows (T62a)");
        string memory j = string.concat("{\"noneHeaders\": ", parts[1]);
        assertFalse(vm.keyExistsJson(j, string.concat(".noneHeaders[", vm.toString(noneHdrs.length), "]")), "no row beyond the debits");
        for (uint256 i; i < noneHdrs.length; ++i) {
            string memory k = string.concat(".noneHeaders[", vm.toString(i), "]");
            bytes memory h = vm.parseJsonBytes(j, string.concat(k, ".header"));
            assertEq(h, noneHdrs[i], string.concat(k, ": the header the contract built"));
            assertEq(_rebuild(j, k), h, string.concat(k, ": the header from the row's named fields"));
        }
    }

    function _rebuild(string memory j, string memory k) internal view returns (bytes memory) {
        Hdr memory h;
        (h.psid, h.chainId, h.token, h.registry) = (_jw(j, k, "psid"), _ju(j, k, "chainId"), _ja(j, k, "token"), _ja(j, k, "registry"));
        (h.from, h.ben, h.sendCounter, h.p) = (_jw(j, k, "fromUA"), _jw(j, k, "beneficiaryUA"), _ju(j, k, "sendCounter"), _ju(j, k, "p"));
        (h.validUntil, h.shieldIn, h.chainUid) = (_ju(j, k, "validUntilBlock"), _ju(j, k, "shieldIn"), _jw(j, k, "chainUid"));
        h.fee = h.ben == 0 ? 0 : _ju(j, k, "confidentialFee");
        bytes32 eb = _envelopeBindingOf(j, k, h);
        bytes32 form = keccak256(bytes(vm.parseJsonString(j, string.concat(k, ".form"))));
        if (form == keccak256("op1") || form == keccak256("op7")) _transferWords(j, k, h, eb, form == keccak256("op7"));
        else _burnWords(j, k, h, eb, form == keccak256("unwrap"));
        assertEq(h.binding, _jw(j, k, "binding"), string.concat(k, ": the binding word"));
        return bytes.concat(abi.encode(h.opTag, h.psid, h.chainId, h.token, h.registry, h.from, h.to, h.ben, h.fee, h.amount),
            abi.encode(h.recipient, h.sendCounter, h.p, h.validUntil, h.auditorOn, h.shieldIn, h.chainUid, h.binding, h.salt, h.memoHash));
    }

    /// `envelopeBinding` of a relayed row from its envelope (CTR-PQZ-21, R36: `SCAAS-PQZ-UA-ENVELOPE-V1`, every field but `data`,
    /// an unbound relayer or fee recipient as 0); a direct row's is 0.
    function _envelopeBindingOf(string memory j, string memory k, Hdr memory h) internal view returns (bytes32 eb) {
        eb = _jw(j, k, "envelopeBinding");
        string memory e = string.concat(k, ".envelope");
        if (!vm.keyExistsJson(j, e)) {
            assertEq(eb, 0, string.concat(k, ": a direct call, envelopeBinding 0"));
            return eb;
        }
        uint256 mode = _ju(j, e, "mode");
        address r = mode & 1 != 0 ? _ja(j, e, "relayer") : address(0);
        address fr = mode & 2 != 0 ? _ja(j, e, "feeRecipient") : address(0);
        bytes32 x = keccak256(bytes.concat(abi.encode(keccak256("SCAAS-PQZ-UA-ENVELOPE-V1"), h.chainId, h.chainUid, h.token,
            _jw(j, e, "from"), _ju(j, e, "batch")), abi.encode(_ju(j, e, "nonce"), _ju(j, e, "validUntil"), mode, r, _ju(j, e, "fee"), fr)));
        assertEq(x, eb, string.concat(k, ": envelopeBinding from the envelope's fields"));
    }

    /// Op 1 / op 7: the mode folded into the binding (`SCAAS-PQZ-DIRECT-MODE-V1` direct, the envelope's relayed; HASH 0 with a
    /// sealed memo, BUNDLE 1), `memoHash = keccak256(memo ‖ ownTag)`, op 7's `recipientsHash`, `M` and `fee + M · decoyFee`.
    function _transferWords(string memory j, string memory k, Hdr memory h, bytes32 eb, bool multi) internal pure {
        uint8 mode = uint8(_ju(j, k, "transferMode"));
        bytes memory salt = vm.parseJsonBytes(j, string.concat(k, ".salt"));
        h.salt = uint128(bytes16(salt));
        h.auditorOn = vm.parseJsonBool(j, string.concat(k, ".auditorOn")) ? 1 : 0;
        bytes memory memo = mode == 0 ? bytes.concat(salt, vm.parseJsonBytes(j, string.concat(k, ".sealedMemo"))) : bytes("");
        h.memoHash = keccak256(bytes.concat(memo, _jw(j, k, "ownTag")));
        h.binding = keccak256(abi.encode(eb == 0 ? keccak256("SCAAS-PQZ-DIRECT-MODE-V1") : eb, mode));
        if (!multi) {
            (h.opTag, h.to) = (PqzCore.OP_TRANSFER, _jw(j, k, "toUA"));
            return;
        }
        bytes32[] memory legs = vm.parseJsonBytes32Array(j, string.concat(k, ".legs"));
        (h.opTag, h.to, h.recipient) = (PqzCore.OP_TRANSFER_MULTI, keccak256(abi.encodePacked(legs)), bytes32(legs.length));
        h.fee += legs.length * _ju(j, k, "decoyFee");
    }

    /// Burn, refresh (amount 0), unwrap: `memoHash = keccak256(ownTag)`; the binding 0 / the envelope's, an unwrap's
    /// `unwrapBinding(underlying, minOut)` direct and `keccak256(abi.encode(envelopeBinding, unwrapBinding))` relayed.
    function _burnWords(string memory j, string memory k, Hdr memory h, bytes32 eb, bool unwrap) internal pure {
        (h.amount, h.recipient) = (_ju(j, k, "amount"), _jw(j, k, "recipient"));
        h.opTag = h.amount == 0 ? PqzCore.OP_REFRESH : PqzCore.OP_BURN;
        h.memoHash = keccak256(abi.encodePacked(_jw(j, k, "ownTag")));
        h.binding = eb;
        if (!unwrap) return;
        bytes32 w = keccak256(abi.encode(keccak256("SCAAS-PQZ-UNWRAP-V1"), _ja(j, k, "underlying"), _ju(j, k, "minOut")));
        assertEq(w, _jw(j, k, "unwrapBinding"), string.concat(k, ": unwrapBinding(underlying, minOut)"));
        h.binding = eb == 0 ? w : keccak256(abi.encode(eb, w));
    }

    function _jw(string memory j, string memory k, string memory f) internal pure returns (bytes32) {
        return vm.parseJsonBytes32(j, string.concat(k, ".", f));
    }

    function _ju(string memory j, string memory k, string memory f) internal pure returns (uint256) {
        return vm.parseJsonUint(j, string.concat(k, ".", f));
    }

    function _ja(string memory j, string memory k, string memory f) internal pure returns (address) {
        return vm.parseJsonAddress(j, string.concat(k, ".", f));
    }
}
