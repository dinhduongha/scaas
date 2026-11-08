// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzSlots} from "./PqzState.t.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";

/// @notice ua-rs-sign T15e (spec no-decryption-oracle §4.4, §5): the PQZ state vectors of the build's set. A token in several
///         account states (`acc` never debited, a reference to the last debit's blob, materialised by a rollover; TRIVIAL and
///         credit entries; op 1 and op 7 entries, with and without the auditor copies, BUNDLE and HASH), then per account the
///         raw words a reading layer reads (the account struct's slots, the pending slots of `[rolled, p)`, the `acc` slots,
///         every SSTORE2 code, the registry's key record) with the contract's own `T` at the facade's `p` (CTR-PQZ-06), from its
///         burn statement view, and per entry leg its `u ‖ v` (and the auditor copy) from the disclosure statement view, and the
///         op 1 / op 7 / burn `memoHash` words of the statement views. Proofs mocked (no proof is in a row). `STATE_VECTORS=1`
///         writes `smartcontracts/vectors/pqz/[<set>/]state.json` (the commit in `CONTRACT_COMMIT`); ua-rs reproduces every
///         `T` and ciphertext from the words (`tests/facade_pqz_state.rs`). UNAUDITED.
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
        _shield(carol, 9); // carol: acc = her last debit's blob, one TRIVIAL entry pending
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

    /// The statements' `memoHash` word (header word 19): op 1 and op 7 HASH over `salt ‖ sealedMemo`, BUNDLE and a burn 0.
    function _memoHashes() internal {
        bytes memory memo = _memo();
        bytes memory pl = _payload(tok.pqzAccount(carol, 0).pendingCount, 0, carol, dave, bytes32(0), _out(31, false), memo);
        bytes memory st = tok.transferSingleStatement(_ts(pl), 0);
        _w(string.concat("{\"op\": 1, \"mode\": \"HASH\", \"salt\": ", _hx(abi.encodePacked(salt)), ", \"sealedMemo\": ",
            _hx(_slice(memo, 16, PqzCore.SEALED)), ", \"memoHash\": ", _hx32(_word(st, 608)), "},"));
        pl = _payload(tok.pqzAccount(carol, 0).pendingCount, 0, carol, dave, bytes32(0), _out(31, false), "");
        _w(string.concat("{\"op\": 1, \"mode\": \"BUNDLE\", \"memoHash\": ", _hx32(_word(tok.transferSingleStatement(_ts(pl), 0), 608)), "},"));
        IPqzToken.PqzMultiArgs memory t = _ms(_mpl(carol, _legs(alice, erin), 32, false, true));
        _w(string.concat("{\"op\": 7, \"mode\": \"HASH\", \"salt\": ", _hx(abi.encodePacked(t.salt)), ", \"sealedMemo\": ",
            _hx(t.sealedMemo), ", \"memoHash\": ", _hx32(_word(tok.transferStatement(t, 0), 608)), "},"));
        bytes memory bl = bytes.concat(abi.encode(uint256(tok.pqzAccount(carol, 0).pendingCount), block.number + 5, uint256(0), carol,
            bytes32(0)), _blob(78, PqzCt.CT));
        _w(string.concat("{\"op\": 2, \"mode\": \"\", \"memoHash\": ", _hx32(_word(tok.burnStatement(_bs(bl), 1, bytes32(uint256(5)), 0), 608)), "}"));
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
        _w(string.concat("\"file\": \"state.json\", \"set\": ", _q(PqzSet.NAME), ", \"contractCommit\": ", _q(vm.envString("CONTRACT_COMMIT")), ", \"chainId\": ",
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
        _w("]}");
    }
}
