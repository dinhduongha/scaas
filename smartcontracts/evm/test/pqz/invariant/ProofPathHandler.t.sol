// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {noVerdict} from "../helpers/PqzVerdicts.sol";
import {PqzFixture} from "../helpers/PqzFixture.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UACall} from "../../ua/UACall.sol";

/// Group 3h, T64 (spec 2026-11-06-pqz-proof-path §11.2): the handler of the proof-path invariants P1-P7 and P1′. Actors: four
/// `mldsa65` UAs holding proven PQZ keys. Actions: shields (same-block merges into the tail entry), rollovers, every debit form of
/// a `NORMAL_PQZ` token (op 1 with and without the auditor, op 7 to two legs with it, a burn of 1, a refresh, the 3g migration)
/// at a `p` up to 16 below or above `rolled` (un-rolls), 3g rotations, `setProofStore` and `disableFeature(24)` (the handler holds
/// bit 24 and is the owner). Ghosts per debit `(ua, k)`: the `T` its statement carried, the mode it ran under, its record words,
/// its version and the account's `lastDebit` before it; and the counts of what a rule refused that happened anyway (`badTail`,
/// `badLog`, `badMode`) and of pending entries that changed below a past `max(floor, rolled)` (`changedBelow`). The PQZ
/// precompile and the ML-DSA-65 consent are mocked to accept (`PqzFixture`): the token's state machine is under test, not the
/// proofs. No action reverts (a refused call is caught). UNAUDITED.
contract ProofPathHandler is PqzFixture {
    bytes internal constant PROOF = hex"c0ffee";
    bytes32 internal constant EV = keccak256("PqzDebitProof(address,bytes32,uint64,bytes,bytes)");
    bytes32[] public uas;
    uint256 internal nonce = 1;

    mapping(bytes32 => mapping(uint64 => bytes32)) public tHash; // P2
    mapping(bytes32 => mapping(uint64 => uint8)) public modeAt; // P5
    mapping(bytes32 => mapping(uint64 => bytes32)) public recHash; // P3: keccak256(w0, w1) as written
    mapping(bytes32 => mapping(uint64 => uint64)) public verOf; // P3: the debit's key version
    mapping(bytes32 => mapping(uint64 => uint64)) public lastBefore; // P3: `lastDebit` of that version before the debit
    mapping(bytes32 => uint64) public debits; // ghost sendCounter
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => uint256))) internal frozen; // P1′
    mapping(bytes32 => mapping(uint64 => uint64)) internal frozenTo;
    uint256 public badTail; // P4
    uint256 public badLog; // P5
    uint256 public badMode; // a mode change that landed after bit 24 was disabled
    uint256 public changedBelow; // P1′
    uint256 public shielded; // P6: ghost totalShielded
    uint256 public landed; // debits that landed (the positive control's count)
    uint256 public logged; // LOG debits that landed
    uint256 public rolls; // rollovers that landed
    bool public disabled;

    constructor(UARegistry r, bytes32[] memory u) {
        (reg, uas) = (r, u);
    }

    /// Once, by the test's `setUp` (a later call, the fuzzer's, does nothing).
    function setToken(PqzLayer t) external {
        if (address(tok) == address(0)) tok = t;
    }

    function uaCount() external view returns (uint256) {
        return uas.length;
    }

    function _cur(bytes32 ua) internal view returns (uint64 v) {
        (v,,,) = reg.pqzKeyOf(ua);
    }

    // ------------------------------------------------------------------ after every action: P1′

    function _settle() internal {
        for (uint256 i; i < uas.length; ++i) {
            bytes32 u = uas[i];
            for (uint64 v; v <= reg.pqzKeyLatest(u); ++v) {
                IPqzToken.AccountState memory a = tok.pqzAccount(u, v);
                uint64 lim = a.floor > a.rolled ? a.floor : a.rolled;
                uint64 to = frozenTo[u][v];
                for (uint64 j; j < to; ++j) if (tok.pqzPending(u, v, j) != frozen[u][v][j]) ++changedBelow;
                for (uint64 j = to; j < lim; ++j) frozen[u][v][j] = tok.pqzPending(u, v, j);
                if (lim > to) frozenTo[u][v] = lim;
            }
        }
    }

    // ------------------------------------------------------------------ credits and rollovers

    function shield(uint256 to, uint256 a, bool sameBlock) external {
        bytes32 u = uas[to % uas.length];
        a = bound(a, 1, 100);
        if (tok.balanceOf(address(this)) < a * SCALE) return;
        if (!sameBlock) vm.roll(block.number + 1);
        tok.mtxShield(u, a);
        shielded += a;
        _settle();
    }

    function rollOver(uint256 i, uint256 n) external {
        bytes32 u = uas[i % uas.length];
        uint64 v = _cur(u);
        IPqzToken.AccountState memory a = tok.pqzAccount(u, v);
        if (a.pendingCount <= a.rolled && v == _cur(u) && tok.balanceOf(address(this)) >= SCALE) {
            vm.roll(block.number + 1); // an entry to roll: a shield of 1 in a block of its own
            tok.mtxShield(u, 1);
            ++shielded;
            a = tok.pqzAccount(u, v);
        }
        if (a.pendingCount <= a.rolled) return;
        n = bound(n, 1, a.pendingCount - a.rolled < PqzCore.ROLL_MAX ? a.pendingCount - a.rolled : PqzCore.ROLL_MAX);
        try tok.mtxPrepareAcc(u, v, 0) {} catch {}
        try tok.mtxPrepareAcc(u, v, 1) {} catch {}
        vm.roll(block.number + ROLL_AGE);
        try tok.mtxRollOver(u, v, n) {
            ++rolls;
        } catch {}
        _settle();
    }

    /// More than `INLINE_MAX` entries rolled at once (17-24 shields of 1, a block each, then every pending entry in chunks of
    /// `ROLL_MAX`): the rollover moves `cleared` (`rolled − INLINE_MAX`), where the deletion it no longer makes would sit.
    function bulk(uint256 i, uint256 n) external {
        bytes32 u = uas[i % uas.length];
        uint64 v = _cur(u);
        n = bound(n, PqzCore.INLINE_MAX + 1, PqzCore.INLINE_MAX + 8);
        if (tok.balanceOf(address(this)) < n * SCALE) return;
        for (uint256 j; j < n; ++j) {
            vm.roll(block.number + 1);
            tok.mtxShield(u, 1);
        }
        shielded += n;
        try tok.mtxPrepareAcc(u, v, 0) {} catch {}
        try tok.mtxPrepareAcc(u, v, 1) {} catch {}
        vm.roll(block.number + ROLL_AGE);
        IPqzToken.AccountState memory a = tok.pqzAccount(u, v);
        while (a.pendingCount > a.rolled) {
            uint256 k = a.pendingCount - a.rolled < PqzCore.ROLL_MAX ? a.pendingCount - a.rolled : PqzCore.ROLL_MAX;
            try tok.mtxRollOver(u, v, k) {
                ++rolls;
            } catch {
                break;
            }
            a = tok.pqzAccount(u, v);
        }
        _settle();
    }

    function rotate(uint256 i) external {
        bytes32 u = uas[i % uas.length];
        uint64 v = reg.pqzKeyLatest(u) + 1;
        bytes memory k = new bytes(PqzCt.PK);
        uint256 x = ++nonce;
        assembly ("memory-safe") { mstore(add(k, 40), shl(64, x)) }
        bytes memory pop = abi.encodePacked("proof-path-inv", u, v);
        try reg.setPqzKey(u, v, k, keccak256(pop), UACall.sig(new bytes(ML65_SIG))) {
            try reg.storePqzPop(u, v, pop) {} catch {}
        } catch {}
        _settle();
    }

    // ------------------------------------------------------------------ bit 24

    function setMode(uint256 m) external {
        uint8 next = uint8(m % 2);
        try tok.setProofStore(next) {
            if (disabled || tok.proofStore() != next) ++badMode; // lands only while the bit is set, and sets what it says
        } catch {
            if (!disabled) ++badMode;
        }
        _settle();
    }

    function disable24(uint256 coin) external {
        if (disabled || coin % 8 != 0) return;
        IGovernance(address(tok)).disableFeature(24);
        disabled = true;
    }

    // ------------------------------------------------------------------ debits

    struct D {
        uint256 fi; // the sender's index
        bytes32 from;
        uint64 v;
        uint64 k;
        uint64 p;
        uint256 sIn; // shieldIn, from the handler's public balance (a wide record)
        uint8 mode;
        bytes32 tag;
        bytes st;
        uint256 tAt;
        uint64[] kv;
    }

    /// `form` 0 op 1, 1 op 1 with the auditor, 2 op 7 to two legs with the auditor, 3 a burn of 1, 4 a refresh, 5 the migration
    /// (op 1 to itself from a stale version; a refresh there too when it has none); `pSel` picks `p` in `[max(floor, rolled - 16),
    /// min(rolled + 16, pendingCount)]`.
    function debit(uint256 i, uint256 j, uint256 form, uint256 pSel, bool stale) external {
        form %= 6;
        D memory d;
        (d.fi, d.from) = (i % uas.length, uas[i % uas.length]);
        uint64 cur = _cur(d.from);
        d.v = (form == 5 || (stale && form == 4)) && cur > 0 ? uint64(pSel % cur) : cur;
        if (form == 5 && d.v == cur) form = 4;
        IPqzToken.AccountState memory a = tok.pqzAccount(d.from, d.v);
        uint256 lo = a.rolled > 16 && a.rolled - 16 > a.floor ? a.rolled - 16 : a.floor;
        uint256 hi = a.rolled + 16 < a.pendingCount ? a.rolled + 16 : a.pendingCount;
        d.p = uint64(lo + (pSel >> 8) % (hi - lo + 1));
        d.sIn = form == 5 || d.v != cur ? 0 : (pSel >> 4) % 3; // 0, 1 or 2 units shielded in by the debit itself
        (d.k, d.mode, d.tag) = (tok.pqzAccount(d.from, 0).sendCounter, tok.proofStore(), keccak256(abi.encode("tag", ++nonce)));
        uint64 last = a.lastDebit;
        vm.recordLogs();
        address blob = form <= 2 || form == 5 ? _transfer(d, j, form) : _burn(d, form == 3);
        if (blob == address(0)) {
            vm.getRecordedLogs();
            return;
        }
        _landed(d, blob, last);
        _settle();
    }

    function _transfer(D memory d, uint256 j, uint256 form) internal returns (address) {
        if (form == 2) return _multi(d);
        bytes32 to = form == 5 ? d.from : uas[(d.fi + 1 + j % (uas.length - 1)) % uas.length];
        bool aud = form == 1;
        IPqzToken.PqzTransferArgs memory t = _ts(_payload(d.p, d.sIn, d.from, to, bytes32(0), _out(++nonce, aud), ""));
        (t.keyVersion, t.ownTag) = (d.v, d.tag);
        d.kv = new uint64[](aud ? 2 : 1);
        d.kv[0] = _cur(to);
        if (aud) d.kv[1] = _cur(tok.auditorUA());
        try tok.transferSingleStatement(t, 0) returns (bytes memory st) {
            (d.st, d.tAt) = (st, 640 + (aud ? 3 : 2) * PqzCt.PK); // pk_f ‖ pk_t ‖ [pk_a] ‖ T
        } catch {
            return address(0);
        }
        try tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", noVerdict()) returns (bytes32 ref) {
            shielded += d.sIn;
            return _ptr(ref);
        } catch {
            return address(0);
        }
    }

    function _multi(D memory d) internal returns (address) {
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (uas[(d.fi + 1) % uas.length], uas[(d.fi + 2) % uas.length]);
        IPqzToken.PqzMultiArgs memory m = _ms(_mpayload(d.p, 0, d.from, bytes32(0), legs, _blob(++nonce, _outLen(2, true)), ""));
        (m.keyVersion, m.ownTag) = (d.v, d.tag);
        d.kv = new uint64[](3);
        (d.kv[0], d.kv[1], d.kv[2]) = (_cur(legs[0]), _cur(legs[1]), _cur(tok.auditorUA()));
        try tok.transferStatement(m, 0) returns (bytes memory st) {
            (d.st, d.tAt) = (st, 640 + 4 * PqzCt.PK); // pk_f ‖ pk_0 ‖ pk_1 ‖ pk_a ‖ T
        } catch {
            return address(0);
        }
        try tok.mtxConfidentialTransfer(m, PROOF, _pqAuth(), "", noVerdict()) returns (bytes32 ref) {
            return _ptr(ref);
        } catch {
            return address(0);
        }
    }

    function _burn(D memory d, bool pay) internal returns (address) {
        uint256 amount = pay && shielded > 0 ? 1 : 0;
        bytes32 rcpt = amount == 0 ? bytes32(0) : bytes32(uint256(0xD00D));
        IPqzToken.PqzBurnArgs memory b =
            _bs(bytes.concat(abi.encode(uint256(d.p), block.number + 50, d.sIn, d.from, bytes32(0)), _blob(++nonce, PqzCt.CT)));
        (b.keyVersion, b.ownTag) = (d.v, d.tag);
        d.kv = new uint64[](0);
        try tok.burnStatement(b, amount, rcpt, 0) returns (bytes memory st) {
            (d.st, d.tAt) = (st, 640 + PqzCt.PK);
        } catch {
            return address(0);
        }
        try tok.mtxUnshield(b, amount, rcpt, PROOF, _pqAuth(), "", noVerdict()) {
            shielded = shielded + d.sIn - amount;
            return tok.pqzAccount(d.from, d.v).accBlob;
        } catch {
            return address(0);
        }
    }

    function _ptr(bytes32 ref) internal view returns (address) {
        return address(uint160(uint256(vm.load(address(tok), keccak256(abi.encode(ref, uint256(PqzCore._STORAGE) + 9))))));
    }

    /// The landed debit: ghosts, its blob's tail and `memoHash` (P4), its event (P5).
    function _landed(D memory d, address blob, uint64 last) internal {
        ++landed;
        ++debits[d.from];
        tHash[d.from][d.k] = keccak256(_slice(d.st, d.tAt, PqzCt.CT));
        modeAt[d.from][d.k] = d.mode;
        (verOf[d.from][d.k], lastBefore[d.from][d.k]) = (d.v, last);
        uint256 s0 = uint256(keccak256(abi.encode(uint256(d.k), keccak256(abi.encode(d.from, uint256(PqzCore._STORAGE) + 19)))));
        recHash[d.from][d.k] = keccak256(abi.encode(vm.load(address(tok), bytes32(s0)), vm.load(address(tok), bytes32(s0 + 1))));
        _tail(d, blob);
        uint256 n;
        Vm.Log[] memory ls = vm.getRecordedLogs();
        for (uint256 i; i < ls.length; ++i) {
            if (ls[i].emitter != address(tok) || ls[i].topics[0] != EV) continue;
            ++n;
            (bytes memory h, bytes memory pr) = abi.decode(ls[i].data, (bytes, bytes));
            if (ls[i].topics[1] != bytes32(uint256(uint160(blob))) || ls[i].topics[2] != d.from || uint256(ls[i].topics[3]) != d.k
                || keccak256(h) != keccak256(_slice(d.st, 0, 640)) || keccak256(pr) != keccak256(PROOF)) ++badLog;
        }
        if (n != (d.mode == PqzCore.LOG ? 1 : 0)) ++badLog;
        if (d.mode == PqzCore.LOG) ++logged;
    }

    /// P4: the blob ends with `ownTag ‖ kv ‖ u8(n)` of this debit, and its statement's `memoHash` is `keccak256(ownTag)` (BUNDLE).
    function _tail(D memory d, address blob) internal {
        bytes memory c = blob.code;
        uint256 n = uint8(c[c.length - 1]);
        if (n != d.kv.length) {
            ++badTail;
            return;
        }
        uint256 at = c.length - 1 - 8 * n - 32;
        if (bytes32(_slice(c, at, 32)) != d.tag) ++badTail;
        for (uint256 i; i < n; ++i) if (uint64(bytes8(_slice(c, at + 32 + 8 * i, 8))) != d.kv[i]) ++badTail;
        if (_word(d.st, 608) != keccak256(abi.encodePacked(d.tag))) ++badTail;
    }
}
