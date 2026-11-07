// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";

/// @notice ua-rs-sign T14b (spec no-decryption-oracle §4.7, §5): the Zether state vectors. A token with an auditor key
///         (OPTIONAL, BUNDLE disclosure) in several account states (`acc` debited three times, `acc` and `pending` both set,
///         `pending` only, never touched) and three entries (the single format inline, multi-recipient BUNDLE inline with the
///         auditor copies, multi-recipient HASH by SSTORE2 with the memo, the auditor left out); real proofs (the fixture's
///         test prover). The holders' and the auditor's keys are zether-prover's `r33_keys.json` (`m/12381/60/0/7`, `/1/7`,
///         `/0/8`, `/1/8`), so `ua-rs` handles derive them. Per account the raw words a reading layer reads (the account
///         struct's six slots, the data slots of its `bytes` points) with the contract's own `accountState` view and the
///         plaintexts; per entry the words of `entries`, `entryPtrs`, `memos` and the SSTORE2 code with the contract's own
///         `transferEntry` / `transferMemo` / `transferCiphertext` views; the token's words (`psid`, slot 0 with the modes,
///         `auditorKey`), the factory's index record `_rec[token]` (three words from slot 8's mapping; factory index spec §2.1,
///         plan T67: it replaced the one-word `_info[token]`) and T19c's `scaas.zether` pin. `STATE_VECTORS=1` writes
///         `smartcontracts/vectors/zether/state.json` (the commit in `CONTRACT_COMMIT`); ua-rs reproduces every ciphertext from
///         the words (`tests/facade_zether_state.rs`). UNAUDITED.
contract ZetherStateVectorsTest is ZetherFixture {
    // zether-prover vectors/r33_keys.json, bls12381
    uint256 internal constant XA = 0x67c93b3838eb86a76ead85bd6be7ca97ad82758b4ccd30ec58bff013a3392074; // m/12381/60/0/7
    uint256 internal constant XAUD = 0x25f771eaad146dd5c0a479073adf0bdcef837123e5e61770d13bd5f8a9e3e1d9; // m/12381/60/0/8
    uint256 internal constant XB = 0x63a37d32de25c85eafe97a566343e5cae9bf7b957229c247f3ab2c8dc20b1c5a; // m/12381/60/1/7
    uint256 internal constant XD = 0x2592aae4a72ff35d24196d8aa5fbf03bb270d3a83056fa7a6b31fb8700bb882e; // m/12381/60/1/8
    uint256 internal constant ROOT = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
    /// `OpenFactory._rec` (no namespace: slot 8, where `_info` was)
    uint256 internal constant REC = 8;

    User internal dave;
    string internal path;

    struct Ent {
        string name;
        bytes32 ref;
        User from;
        uint64 counter;
        uint256[] amounts;
        bytes32[] to;
    }

    Ent[] internal ents;
    uint256 internal aliceBal;

    function setUp() public {
        _stack();
        alice = _user(XA, address(0xA1));
        bob = _user(XB, address(0xB2));
        carol = _user(0xCA201, address(0xC3));
        dave = _user(XD, address(0xD4));
        IFactoryToken.TokenConfig memory c = _cfg(true, uint256(1) << 40);
        c.conf.auditorKey = ZetherKeys.pub(XAUD, bls);
        tok = ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "zether-state"));
    }

    // ------------------------------------------------------------------ the state

    function _two(User memory a, User memory b) internal pure returns (User[] memory r) {
        r = new User[](2);
        (r[0], r[1]) = (a, b);
    }

    function _vs(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        (r[0], r[1]) = (a, b);
    }

    function _push(string memory name, bytes32 ref, uint64 c, User[] memory to, uint256[] memory vs) internal {
        Ent storage e = ents.push();
        (e.name, e.ref, e.from, e.counter, e.amounts) = (name, ref, alice, c, vs);
        for (uint256 j; j < to.length; ++j) e.to.push(ZetherTypes.UA.unwrap(to[j].ua));
    }

    function _multi(string memory name, User[] memory to, uint256[] memory vs, ZetherTypes.TransferMode mode) internal {
        uint64 c = uint64(tok.sendCounter(alice.ua));
        Tx memory t = _proveMulti(tok, alice, to, vs, aliceBal, _none(), mode);
        bytes32 ref = mode == ZetherTypes.TransferMode.HASH
            ? tok.mtxConfidentialTransferCompact(_zMulti(t.payload, _none()), t.proof)
            : tok.mtxConfidentialTransfer(_zMulti(t.payload, _none()), t.proof);
        aliceBal -= vs[0] + vs[1];
        _push(name, ref, c, to, vs);
    }

    function _build() internal {
        _fund(tok, alice, 1000);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        aliceBal = 1000;
        // the single format, audited, the inner fee to carol
        Tx memory t = _proveTransfer(tok, alice, bob, 100, aliceBal, carol.ua, bytes32(0));
        bytes32 ref = _direct(tok, t, carol.ua);
        aliceBal -= 100 + FEE;
        User[] memory one = new User[](1);
        one[0] = bob;
        uint256[] memory v1 = new uint256[](1);
        v1[0] = 100;
        _push("single alice->bob 100 audited (fee 2 to carol)", ref, 0, one, v1);
        _multi("multi BUNDLE alice->[bob 30, carol 0] audited", _two(bob, carol), _vs(30, 0), ZetherTypes.TransferMode.BUNDLE);
        audOut = true;
        _multi("multi HASH alice->[carol 20, bob 5] auditor left out", _two(carol, bob), _vs(20, 5), ZetherTypes.TransferMode.HASH);
        audOut = false;
        tok.mtxRollOver(ZetherTypes.UA.unwrap(bob.ua), 1); // bob: acc 135
        _fund(tok, bob, 7); // bob: pending 7
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

    function _load(uint256 slot) internal view returns (bytes32) {
        return vm.load(address(tok), bytes32(slot));
    }

    /// `[{slot, word}]` of the `bytes` at `slot`: the length slot (when `withLen`), then its data slots (long form).
    function _bytesWords(uint256 slot, bool withLen) internal view returns (string memory r) {
        uint256 lw = uint256(_load(slot));
        if (withLen) r = string.concat("{\"slot\": ", _hx32(bytes32(slot)), ", \"word\": ", _hx32(bytes32(lw)), "}");
        if (lw == 0) return r;
        assertEq(lw & 1, 1, "a long-form bytes");
        uint256 n = ((lw - 1) / 2 + 31) / 32;
        uint256 d = uint256(keccak256(abi.encode(slot)));
        for (uint256 i; i < n; ++i) {
            r = string.concat(r, bytes(r).length == 0 ? "" : ", ", "{\"slot\": ", _hx32(bytes32(d + i)), ", \"word\": ",
                _hx32(_load(d + i)), "}");
        }
    }

    function _account(string memory name, User memory u, bool last) internal {
        IZetherToken.AccountState memory a = tok.accountState(u.ua);
        uint256 base = uint256(keccak256(abi.encode(u.ua, ROOT + 8)));
        string memory words;
        string memory data;
        for (uint256 i; i < 6; ++i) words = string.concat(words, i == 0 ? "" : ", ", _hx32(_load(base + i)));
        for (uint256 i; i < 4; ++i) {
            string memory d = _bytesWords(base + i, false);
            if (bytes(d).length != 0) data = string.concat(data, bytes(data).length == 0 ? "" : ", ", d);
        }
        (uint256 acc, uint256 pend) = _balances(tok, u, 2000);
        _w(string.concat("{\"name\": ", _q(name), ", \"ua\": ", _hx32(ZetherTypes.UA.unwrap(u.ua)), ", \"Y\": ", _hx(u.y),
            ", \"account\": [", words, "], \"accountData\": [", data, "],"));
        _w(string.concat("\"view\": {\"accC\": ", _hx(a.accC), ", \"accD\": ", _hx(a.accD), ", \"pendingC\": ", _hx(a.pendingC),
            ", \"pendingD\": ", _hx(a.pendingD), ", \"accSeq\": ", vm.toString(uint256(a.accSeq)), ", \"pendingSeq\": ",
            vm.toString(uint256(a.pendingSeq)), ", \"sendCounter\": ", vm.toString(uint256(a.sendCounter)), "},"));
        _w(string.concat("\"balance\": ", vm.toString(acc), ", \"pending\": ", vm.toString(pend), "}", last ? "" : ","));
    }

    function _uints(uint256[] memory v) internal pure returns (string memory r) {
        for (uint256 i; i < v.length; ++i) r = string.concat(r, i == 0 ? "" : ", ", vm.toString(v[i]));
        r = string.concat("[", r, "]");
    }

    function _entry(Ent storage x, bool last) internal {
        uint256 es = uint256(keccak256(abi.encode(x.ref, ROOT + 9)));
        bytes32 ptrWord = _load(uint256(keccak256(abi.encode(x.ref, ROOT + 10))));
        address ptr = address(uint160(uint256(ptrWord)));
        uint256 ms = uint256(keccak256(abi.encode(x.ref, ROOT + 11)));
        bytes memory r = tok.transferEntry(x.ref);
        assertEq(x.ref, _ref(tok, x.from, x.counter), "entryRef");
        _w(string.concat("{\"name\": ", _q(x.name), ", \"entryRef\": ", _hx32(x.ref), ", \"fromUA\": ",
            _hx32(ZetherTypes.UA.unwrap(x.from.ua)), ", \"sendCounter\": ", vm.toString(uint256(x.counter)), ","));
        _w(string.concat("\"entryWords\": [", _bytesWords(es, true), "], \"entryPtr\": ", _hx32(ptrWord), ","));
        if (ptr != address(0)) {
            _w(string.concat("\"blob\": {\"address\": ", _q(vm.toString(abi.encodePacked(ptr))), ", \"code\": ", _hx(ptr.code), "},"));
            _w(string.concat("\"memoWords\": [", _bytesWords(ms, true), "],"));
        }
        _w(string.concat("\"view\": {\"transferEntry\": ", _hx(r), ", \"transferMemo\": ", _hx(tok.transferMemo(x.ref)), ", \"legs\": ["));
        for (uint256 j; j < x.to.length; ++j) {
            (bytes memory ct, bytes memory yt) = dis.transferCiphertext(address(tok), x.ref, j);
            _w(string.concat(j == 0 ? "" : ",", "{\"ciphertext\": ", _hx(ct), ", \"Yt\": ", _hx(yt), "}"));
        }
        bytes32[] memory to = x.to;
        string memory uas;
        for (uint256 j; j < to.length; ++j) uas = string.concat(uas, j == 0 ? "" : ", ", _hx32(to[j]));
        _w(string.concat("]}, \"to\": [", uas, "], \"amounts\": ", _uints(x.amounts), "}", last ? "" : ","));
    }

    /// T19c's pin of `scaas.zether` (`test/v2/layout/namespaces.json`), copied into the rows, so ua-rs compares its
    /// parser's table with the pin of the same contract commit.
    function _layout() internal {
        string memory ns = vm.readFile(string.concat(vm.projectRoot(), "/test/v2/layout/namespaces.json"));
        string[] memory labels = vm.parseJsonStringArray(ns, ".zether.labels");
        string[] memory enc = vm.parseJsonStringArray(ns, ".zether.encodings");
        string memory l;
        string memory e;
        for (uint256 i; i < labels.length; ++i) {
            l = string.concat(l, i == 0 ? "" : ", ", _q(labels[i]));
            e = string.concat(e, i == 0 ? "" : ", ", _q(enc[i]));
        }
        _w(string.concat("\"layout\": {\"id\": ", _q(vm.parseJsonString(ns, ".zether.id")), ", \"root\": ",
            _hx32(vm.parseJsonBytes32(ns, ".zether.root")), ", \"labels\": [", l, "], \"encodings\": [", e, "],"));
        _w(string.concat("\"slots\": ", _uints(vm.parseJsonUintArray(ns, ".zether.slots")), ", \"inner\": ",
            _uints(vm.parseJsonUintArray(ns, ".zether.inner")), ", \"bytes\": ", _uints(vm.parseJsonUintArray(ns, ".zether.bytes")),
            ", \"widths\": ", _uints(vm.parseJsonUintArray(ns, ".zether.widths")), "},"));
    }

    /// Builds the state; with `STATE_VECTORS=1` writes the rows (two runs give the same file).
    function test_stateVectors() public {
        _build();
        assertEq(bytes32(ROOT), vm.parseJsonBytes32(vm.readFile(string.concat(vm.projectRoot(), "/test/v2/layout/namespaces.json")),
            ".zether.root"), "the namespace root");
        uint256 base = uint256(keccak256(abi.encode(address(tok), REC)));
        (bytes32 r0, bytes32 r1, bytes32 r2) = (vm.load(address(factory), bytes32(base)),
            vm.load(address(factory), bytes32(base + 1)), vm.load(address(factory), bytes32(base + 2)));
        assertEq(r0, bytes32(uint256(uint160(address(this)))), "_rec[token].creatorId (slot 8)");
        assertEq(r1, bytes32(0), "_rec[token].ownerUA (no owner)");
        assertEq(uint16(uint256(r2)), 1, "_rec[token].contractClass (TOKEN)");
        assertEq(uint16(uint256(r2) >> 16), uint16(uint8(IOpenFactory.TokenKind.NORMAL_ZETHER)), "_rec[token].kind");
        assertEq(uint64(uint256(r2) >> 32), 1, "_rec[token].version");
        assertTrue(_holds(tok, alice, aliceBal, true), "alice's acc");
        if (!vm.envOr("STATE_VECTORS", false)) return;
        path = string.concat(vm.projectRoot(), "/../vectors/zether/state.json");
        vm.writeFile(path, "");
        _w(string.concat("{\"_comment\": ", _q(string.concat("smartcontracts/evm/test/zether/ZetherStateVectors.t.sol at contract commit ",
            vm.envString("CONTRACT_COMMIT"), " (STATE_VECTORS=1); real proofs (the fixture's test prover); UNAUDITED")), ","));
        _w(string.concat("\"file\": \"state.json\", \"contractCommit\": ", _q(vm.envString("CONTRACT_COMMIT")), ", \"family\": \"evm\", \"chainId\": ",
            vm.toString(block.chainid), ", \"chainUid\": ", _hx32(tok.chainUid()), ", \"token\": ", _q(vm.toString(abi.encodePacked(address(tok)))),
            ", \"block\": ", vm.toString(block.number), ","));
        _w(string.concat("\"factory\": ", _q(vm.toString(abi.encodePacked(address(factory)))), ", \"record\": [", _hx32(r0), ", ", _hx32(r1), ", ", _hx32(r2), "], \"psid\": ",
            _hx32(_load(ROOT + 6)), ", \"modes\": ", _hx32(_load(ROOT)), ", \"p\": ", _hx32(_load(ROOT + 7)), ", \"auditorKeyWords\": [",
            _bytesWords(ROOT + 5, true), "], \"auditorY\": ", _hx(tok.auditorKey()), ", \"confidentialFee\": ", vm.toString(FEE), ","));
        _layout();
        _w("\"accounts\": [");
        _account("alice: acc after three debits, pending rolled", alice, false);
        _account("bob: acc rolled over, pending a shield", bob, false);
        _account("carol: pending only (a credit and a decoy)", carol, false);
        _account("dave: never touched", dave, true);
        _w("], \"entries\": [");
        for (uint256 i; i < ents.length; ++i) _entry(ents[i], i + 1 == ents.length);
        _w("]}");
    }
}
