// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "../helpers/PqzFixture.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UACall} from "../../ua/UACall.sol";

/// Group 3g, T56 (spec 2026-11-06-pqz-key-versions §13): the handler of the key-version invariants. Actors: four `mldsa65` UAs
/// holding a proven version 0. Actions: shields, op 1 (a third party, or the sender itself: the migration from a stale version),
/// op 7 with two legs, refreshes and unshields, each at the current or a stale version; rotations (a version added and
/// proven), a version stored without its proof (pending), a late proof. The PQZ precompile and the ML-DSA-65 consent are
/// mocked to accept (`PqzFixture`): what is under test is the token's and the registry's state machine, not the proofs. Ghosts:
/// every credit's landing (each version's `pendingCount` before and after: only the receiver's current one, read before the call,
/// may move; a TRIVIAL shield may join the tail entry), the debits per UA, the shielded total, and every call the rules refuse
/// that landed anyway (`bad`). No action reverts (a refused call is caught and checked). UNAUDITED.
contract PqzVerHandler is PqzFixture {
    bytes internal constant PROOF = hex"c0de";
    bytes32[] public uas;
    uint256 public misplaced; // J1 / J5: a credit that changed a version other than the receiver's current (as read before)
    uint256 public credited; // credits that landed (each in its receiver's current version)
    mapping(bytes32 => uint64) public debits; // ghost sendCounter per UA
    mapping(bytes32 => uint64) public provenMax; // the highest version with its proof stored (current, J3)
    mapping(bytes32 => uint64) public currentSeen; // current at the last action (J3: never down)
    uint256 public shielded; // ghost totalShielded
    uint256 public bad; // J10, KV-8 / KV-9: a call the rules refuse that landed
    uint256 public downs; // J3: current went down
    uint256 internal nonce = 1;

    constructor(PqzLayer t, UARegistry r, bytes32[] memory u) {
        (tok, reg, uas) = (t, r, u);
    }

    function uaCount() external view returns (uint256) {
        return uas.length;
    }

    function _cur(bytes32 ua) internal view returns (uint64 v) {
        (v,,,) = reg.pqzKeyOf(ua);
    }

    /// Every action ends here: current never goes down (J3).
    function _seen() internal {
        for (uint256 i; i < uas.length; ++i) {
            uint64 c = _cur(uas[i]);
            if (c < currentSeen[uas[i]]) ++downs;
            currentSeen[uas[i]] = c;
        }
    }

    /// A fresh PQZ key of this set's length: never equal to another (KV-1 refuses a repeat, not the subject here).
    function _freshKey() internal returns (bytes memory k) {
        k = new bytes(PqzCt.PK);
        uint256 n = ++nonce;
        assembly ("memory-safe") { mstore(add(k, 40), shl(64, n)) }
    }

    /// `pendingCount` of every stored version of `u`.
    function _snap(bytes32 u) internal view returns (uint64[] memory c) {
        c = new uint64[](uint256(reg.pqzKeyLatest(u)) + 1);
        for (uint256 v; v < c.length; ++v) c[v] = tok.pqzAccount(u, uint64(v)).pendingCount;
    }

    /// J1 / J5: after a credit to `u`, only version `cur` (read before the call) may have moved, and never down.
    function _landed(bytes32 u, uint64[] memory before, uint64 cur) internal {
        uint64[] memory a = _snap(u);
        for (uint256 v; v < before.length; ++v) {
            if (v == cur ? a[v] < before[v] : a[v] != before[v]) ++misplaced;
        }
        for (uint256 v = before.length; v < a.length; ++v) if (a[v] != 0) ++misplaced;
        ++credited;
    }

    function _proofOf(bytes32 ua, uint64 v) internal pure returns (bytes memory) {
        return abi.encodePacked("pqzver-inv", ua, v);
    }

    /// The debited version: current, or (`stale`) a version below it when there is one.
    function _kv(bytes32 ua, uint256 stale) internal view returns (uint64 cur, uint64 kv) {
        cur = _cur(ua);
        kv = stale % 3 == 0 && cur > 0 ? uint64(stale % cur) : cur;
    }

    // ----- credits -----

    function shield(uint256 to, uint256 a) external {
        bytes32 u = uas[to % uas.length];
        a = bound(a, 1, 1000);
        if (tok.balanceOf(address(this)) < a * SCALE) return;
        (uint64 c, uint64[] memory b) = (_cur(u), _snap(u));
        tok.mtxShield(u, a);
        _landed(u, b, c);
        shielded += a;
        _seen();
    }

    // ----- debits -----

    /// op 1: `to` another UA (allowed at the current version only) or `from` itself (the migration: allowed from a stale version
    /// only, `SelfTransfer` at the current one).
    function transfer(uint256 i, uint256 j, uint256 stale) external {
        (bytes32 from, bytes32 to) = (uas[i % uas.length], uas[j % uas.length]);
        (uint64 cur, uint64 kv) = _kv(from, stale);
        bool ok = from == to ? kv < cur : kv == cur;
        (uint64 toCur, uint64[] memory b) = (_cur(to), _snap(to));
        uint64 p = tok.pqzAccount(from, kv).rolled;
        IPqzToken.PqzTransferArgs memory t = _ts(_payload(p, 0, from, to, bytes32(0), _out(nonce++, false), ""));
        t.keyVersion = kv;
        try tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "") {
            if (!ok) ++bad;
            _landed(to, b, toCur);
            ++debits[from];
        } catch {}
        _seen();
    }

    /// op 7 to two other UAs: allowed at the current version only (never a migration).
    function multi(uint256 i, uint256 stale) external {
        i %= uas.length;
        bytes32 from = uas[i];
        (bytes32 a, bytes32 b) = (uas[(i + 1) % uas.length], uas[(i + 2) % uas.length]);
        (uint64 cur, uint64 kv) = _kv(from, stale);
        (uint64 ca, uint64 cb) = (_cur(a), _cur(b));
        (uint64[] memory sa, uint64[] memory sb) = (_snap(a), _snap(b));
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (a, b);
        uint64 p = tok.pqzAccount(from, kv).rolled;
        IPqzToken.PqzMultiArgs memory t = _ms(_mpayload(p, 0, from, bytes32(0), legs, _blob(nonce++, _outLen(2, false)), ""));
        t.keyVersion = kv;
        try tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "") {
            if (kv != cur) ++bad;
            _landed(a, sa, ca);
            _landed(b, sb, cb);
            ++debits[from];
        } catch {}
        _seen();
    }

    /// A burn: a refresh (amount 0, no recipient) at any version; an unshield (amount > 0) at the current version only.
    function burn(uint256 i, uint256 stale, uint256 amount) external {
        bytes32 from = uas[i % uas.length];
        (uint64 cur, uint64 kv) = _kv(from, stale);
        amount = shielded == 0 ? 0 : bound(amount, 0, shielded);
        bytes32 rcpt = amount == 0 ? bytes32(0) : bytes32(uint256(0xD00D));
        uint64 p = tok.pqzAccount(from, kv).rolled;
        IPqzToken.PqzBurnArgs memory b =
            _bs(bytes.concat(abi.encode(uint256(p), block.number + 50, uint256(0), from, bytes32(0)), _blob(nonce++, PqzCt.CT)));
        b.keyVersion = kv;
        try tok.mtxUnshield(b, amount, rcpt, PROOF, _pqAuth(), "") {
            if (kv != cur && amount != 0) ++bad;
            shielded -= amount;
            ++debits[from];
        } catch {}
        _seen();
    }

    // ----- rotations -----

    /// Version `latest + 1` added and proven: it becomes current.
    function rotate(uint256 i) external {
        bytes32 u = uas[i % uas.length];
        uint64 v = reg.pqzKeyLatest(u) + 1;
        if (!_add(u, v)) return;
        try reg.storePqzPop(u, v, _proofOf(u, v)) {
            if (v > provenMax[u]) provenMax[u] = v;
        } catch {}
        _seen();
    }

    /// Version `latest + 1` stored without its proof: pending, current unchanged.
    function addPending(uint256 i) external {
        _add(uas[i % uas.length], reg.pqzKeyLatest(uas[i % uas.length]) + 1);
        _seen();
    }

    /// The proof of a stored, unproven version below or at latest: current moves to it only if it is the highest proven.
    function proveLate(uint256 i, uint256 which) external {
        bytes32 u = uas[i % uas.length];
        uint64 l = reg.pqzKeyLatest(u);
        uint64 v = uint64(which % (uint256(l) + 1));
        (,, bool proven) = reg.pqzKeyAt(u, v);
        if (proven) return;
        try reg.storePqzPop(u, v, _proofOf(u, v)) {
            if (v > provenMax[u]) provenMax[u] = v;
        } catch {}
        _seen();
    }

    function _add(bytes32 u, uint64 v) internal returns (bool) {
        try reg.setPqzKey(u, v, _freshKey(), keccak256(_proofOf(u, v)), UACall.sig(new bytes(ML65_SIG))) {
            return true;
        } catch {
            return false;
        }
    }
}
