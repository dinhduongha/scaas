// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {VerifyOnlyStandIn} from "./UARegistryLine.t.sol";
import {UACall} from "./UACall.sol";

/// The PQZ home over N generations (spec 2026-11-19-registry-verify-only-kinds §11.2, owner P7, P8, M5; plan Task 8): a record's
/// PQZ attachment lives in the oldest generation from its holder to the reader that enables `0x0142`. Three generations, one
/// single-key kind each (`fndsa512` in gen 1, `mldsa44` in gen 2, `mldsa65` in gen 3: each group new on the line), the `0x0142`
/// verifier an accept-all stand-in (any stored proof proves). UNAUDITED.
contract UARegistryPqzHomeTest is UARegistryBase {
    uint16 internal constant FN = UAKinds.FNDSA512;
    uint16 internal constant ML44 = UAKinds.MLDSA44;
    uint16 internal constant ML65 = UAKinds.MLDSA65;
    uint16 internal constant PQZ = UAKinds.PQZ_MLWE;
    bytes32 internal constant POP_HASH = keccak256(hex"01");

    UARegistry internal g1;
    UARegistry internal g2;
    UARegistry internal g3;
    address internal all;
    mapping(bytes32 => bytes) internal keyOf_;
    mapping(bytes32 => uint16) internal kindOf_;
    uint256 internal salt;

    function setUp() public override {
        super.setUp();
        all = address(new VerifyOnlyStandIn(address(0), 0, 1));
    }

    function _k(uint16 kind, address v, uint64 cap) internal pure returns (UARegistry.KindConfig memory) {
        return UARegistry.KindConfig(kind, v, cap, false, 0);
    }

    /// Gen 1 (`fndsa512`), gen 2 (`mldsa44`), gen 3 (`mldsa65`); `w<i>`: generation i enables `0x0142`.
    function _line(bool w1, bool w2, bool w3) internal {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](w1 ? 2 : 1);
        k[0] = _k(FN, address(mock), 400_000);
        if (w1) k[1] = _k(PQZ, all, 1_000_000);
        g1 = _deploy(address(0x6f01), chainUidA, address(0), false, BUDGET, address(0), true, k);
        k = new UARegistry.KindConfig[](w2 ? 2 : 1);
        k[0] = _k(ML44, address(mock), 400_000);
        if (w2) k[1] = _k(PQZ, all, 1_000_000);
        g2 = _deploy(address(0x6f02), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        k = new UARegistry.KindConfig[](w3 ? 2 : 1);
        k[0] = _k(ML65, address(mock), 400_000);
        if (w3) k[1] = _k(PQZ, all, 1_000_000);
        g3 = _deploy(address(0x6f03), chainUidA, address(g2), false, BUDGET, address(0), true, k);
    }

    /// A fresh record of `kind` on `g`.
    function _rec(UARegistry g, uint16 kind) internal returns (bytes32 ua) {
        bytes memory pk = new bytes(kind == FN ? 897 : kind == ML44 ? 1312 : 1952);
        (pk[0], pk[3]) = (bytes1(kind == FN ? 0x09 : 0x01), bytes1(uint8(++salt)));
        ua = _register(g, kind, pk);
        (keyOf_[ua], kindOf_[ua]) = (pk, kind);
    }

    function _pqzKey(uint256 s) internal pure returns (bytes memory k) {
        k = new bytes(PqzSet.PK);
        (k[0], k[1]) = (bytes1(uint8(s)), bytes1(uint8(s >> 8)));
    }

    /// `ua`'s version-0 key `key` set on `at`, signed by the record's key (its holder checks it, W1).
    function _setCall(UARegistry, bytes32 ua, bytes memory key) internal view returns (bytes memory) {
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, UAKinds.keyHashOf(PQZ, key), POP_HASH);
        bytes memory sig = _sig(keyOf_[ua], UAKinds.uaMessage(kindOf_[ua], UAKinds.PURPOSE_PQZ_KEY, rd));
        return abi.encodeCall(IUARegistry.setPqzKey, (ua, 0, key, POP_HASH, UACall.sig(sig)));
    }

    function _set(UARegistry at, bytes32 ua, bytes memory key) internal {
        (bool ok, bytes memory ret) = address(at).call(_setCall(at, ua, key));
        assertTrue(ok, vm.toString(ret));
    }

    /// `_set`, then its proof stored there: proven by the accept-all `0x0142` verifier.
    function _prove(UARegistry at, bytes32 ua, bytes memory key) internal {
        _set(at, ua, key);
        at.storePqzPop(ua, 0, hex"01");
    }

    function _refused(UARegistry at, bytes memory data, bytes memory err) internal {
        (bool ok, bytes memory ret) = address(at).call(data);
        assertFalse(ok, "refused");
        assertEq(ret, err);
    }

    function _homeIsWalk(UARegistry at, bytes32 ua, address home) internal view {
        (,, address w) = at.holderOf(ua);
        assertEq(at.pqzHomeOf(ua), home, "the home");
        assertEq(w, home, "M4: pqzHomeOf is holderOf's third word");
    }

    // ----- (a) gen 1 with 0x0142, gen 2 without (built directly, the owner's M9 override), gen 3 with -----

    function test_pqzHome_a_gen1With_gen2Without_gen3With() public {
        _line(true, false, true);
        (bytes32 a1, bytes32 a2, bytes32 a3) = (_rec(g1, FN), _rec(g2, ML44), _rec(g3, ML65));
        _homeIsWalk(g3, a1, address(g1));
        _homeIsWalk(g3, a2, address(g3));
        _homeIsWalk(g3, a3, address(g3));
        _homeIsWalk(g2, a2, address(0));
        // a gen-1 record's attachment stays in gen 1 and reads through gen 3 forward there
        _prove(g1, a1, _pqzKey(1));
        (uint64 v, address p, bytes32 ph, bool proven) = g3.pqzKeyOf(a1);
        (uint64 v1, address p1, bytes32 ph1, bool proven1) = g1.pqzKeyOf(a1);
        assertEq(abi.encode(v, p, ph, proven), abi.encode(v1, p1, ph1, proven1));
        assertTrue(proven);
        // gen 2 refuses a PQZ key for its own record (A5-I1 (3)); gen 3, its home, takes it, and its own record's
        _refused(g2, _setCall(g2, a2, _pqzKey(2)), abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, PQZ));
        _prove(g3, a2, _pqzKey(2));
        _prove(g3, a3, _pqzKey(3));
        (,,, proven) = g3.pqzKeyOf(a2);
        assertTrue(proven, "a2's key proven at its home");
        // gen 3 refuses a key hash proven in gen 1 (the `pqz-mlwe` group walks the line, A5-I1 (2))
        bytes32 a2b = _rec(g2, ML44);
        _set(g3, a2b, _pqzKey(1));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, UAKinds.keyHashOf(PQZ, _pqzKey(1)), a1));
        g3.storePqzPop(a2b, 0, hex"01");
    }

    /// M5: one `0x0142` list per enabling generation; gen 1's positions do not move when gen 3 adds entries.
    function test_0142List_perGeneration_stablePositions() public {
        _line(true, false, true);
        bytes32 a1 = _rec(g1, FN);
        _prove(g1, a1, _pqzKey(1));
        assertEq(g1.uaCount(PQZ), 1);
        assertEq(g1.uaAt(PQZ, 0), a1);
        (bytes32 a2, bytes32 a3) = (_rec(g2, ML44), _rec(g3, ML65));
        _prove(g3, a2, _pqzKey(2));
        _prove(g3, a3, _pqzKey(3));
        assertEq(g1.uaCount(PQZ), 1, "gen 1's list unchanged");
        assertEq(g1.uaAt(PQZ, 0), a1);
        assertEq(g3.uaCount(PQZ), 2, "gen 3's own list only, never a concatenation");
        assertEq(g3.uaAt(PQZ, 0), a2);
        assertEq(g3.uaAt(PQZ, 1), a3);
    }

    // ----- (b) gen 1 without, gen 2 with, gen 3 with -----

    function test_pqzHome_b_gen1Without_gen2With_gen3With() public {
        _line(false, true, true);
        (bytes32 a1, bytes32 a3) = (_rec(g1, FN), _rec(g3, ML65));
        _homeIsWalk(g3, a1, address(g2));
        _homeIsWalk(g2, a1, address(g2));
        _homeIsWalk(g1, a1, address(0));
        _homeIsWalk(g3, a3, address(g3));
        _prove(g2, a1, _pqzKey(1));
        (uint64 v, address p, bytes32 ph, bool proven) = g3.pqzKeyOf(a1);
        (uint64 v2, address p2, bytes32 ph2, bool proven2) = g2.pqzKeyOf(a1);
        assertEq(abi.encode(v, p, ph, proven), abi.encode(v2, p2, ph2, proven2));
        assertTrue(proven);
        assertEq(g3.pqzKeyLatest(a1), g2.pqzKeyLatest(a1));
        assertEq(g3.pqzPopOf(a1, 0), hex"01");
        (, address rk) = g3.recordOf(a1);
        assertEq(rk, p2, "recordOf's key from the home");
        _prove(g3, a3, _pqzKey(3));
    }

    /// §11.2 "Writes": the PQZ writes are accepted only at the record's home (`UAUnauthorized` elsewhere).
    function test_pqzWrites_onlyAtHome() public {
        _line(false, true, true);
        bytes32 a1 = _rec(g1, FN);
        _refused(g3, _setCall(g3, a1, _pqzKey(1)), abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, a1));
        _set(g2, a1, _pqzKey(1)); // the control: its home
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, a1));
        g3.storePqzPop(a1, 0, hex"01");
    }

    // ----- (c) the residual (owner P8) -----

    /// A hash proven first in gen 3 is then proven for another UA in gen 1, whose walk does not reach gen 3: two owners on the line,
    /// each proven (documented, pinned).
    function test_pqzHome_c_residualPinned() public {
        _line(true, false, true);
        (bytes32 a1, bytes32 a3) = (_rec(g1, FN), _rec(g3, ML65));
        _prove(g3, a3, _pqzKey(7));
        _prove(g1, a1, _pqzKey(7));
        (,,, bool p1) = g3.pqzKeyOf(a1);
        (,,, bool p3) = g3.pqzKeyOf(a3);
        assertTrue(p1 && p3, "both proven");
        bytes32 h = UAKinds.keyHashOf(PQZ, _pqzKey(7));
        assertEq(g1.keyOwner(h), a1);
        assertEq(g3.keyOwner(h), a3, "each reader sees the nearest owner (local first)");
    }

    // ----- (d) the scoped lists and `pqzKeyLatest` -----

    function _kem() internal pure returns (IUARegistry.KemKey memory k) {
        (k.scheme, k.mlkemEk, k.x25519) = (1, new bytes(1568), bytes32(uint256(7)));
        k.mlkemEk[0] = 0x01;
    }

    function _scoped(UARegistry at, bytes32 ua, bytes memory key) internal {
        bytes32 rd = UAKinds.pqzScopedKeyRecordDigest(
            ua,
            2,
            chainUidA,
            address(0),
            0,
            UAKinds.keyHashOf(PQZ, key),
            POP_HASH,
            keccak256(UAKinds.kemPk(_kem())),
            type(uint64).max
        );
        bytes memory sig = _sig(keyOf_[ua], UAKinds.uaMessage(kindOf_[ua], UAKinds.PURPOSE_PQZ_SCOPED_KEY, rd));
        at.setPqzScopedKey(ua, address(0), 0, key, POP_HASH, _kem(), type(uint64).max, UACall.sig(sig));
        at.storePqzScopedPop(ua, address(0), 0, hex"01"); // proven: listed
    }

    /// (b)'s line: a scope's holder list is the line's, oldest first; a gen-1 record's scoped reads through gen 3 forward to its
    /// home; `pqzKeyLatest` likewise.
    function test_pqzHome_d_scopedListsAndLatest() public {
        _line(false, true, true);
        (bytes32 a1, bytes32 a3) = (_rec(g1, FN), _rec(g3, ML65));
        _scoped(g2, a1, _pqzKey(1));
        _scoped(g3, a3, _pqzKey(3));
        assertEq(g3.pqzScopedCount(address(0)), 2);
        assertEq(g3.pqzScopedAt(address(0), 0), a1, "the older generation's list first");
        assertEq(g3.pqzScopedAt(address(0), 1), a3);
        assertEq(g2.pqzScopedCount(address(0)), 1);
        assertEq(g3.pqzScopedKeyLatest(a1, address(0)), g2.pqzScopedKeyLatest(a1, address(0)));
        (, address p,,) = g3.pqzScopedKeyOf(a1, address(0));
        (, address p2,,) = g2.pqzScopedKeyOf(a1, address(0));
        assertEq(p, p2);
        assertTrue(p != address(0));
        _set(g2, a1, _pqzKey(9));
        assertEq(g3.pqzKeyLatest(a1), 0);
        assertTrue(g3.pqzKeyUsed(a1, UAKinds.keyHashOf(PQZ, _pqzKey(9))), "pqzKeyUsed from the home");
    }

    // ----- (h) M1 in a PQZ home -----

    /// §7 (e): a gen-1 single key whose kind gen 2 carries verify-only with an accept-all verifier, gen 2 its PQZ home: a
    /// `setPqzKey` with a bad signature stays refused (its holder checks it), the good one passes.
    /// (Task 21 review P3-2: the mutant `uint160(cfg) == 0` for `!_registrable(cfg)` in `_single` is equivalent here: every entry
    /// appends `_cfg(0)` = 0 for a record held elsewhere, so both tests agree on every reachable input; the guard stays.)
    function test_m1_pqzHome_singleKey_setPqzKey() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = _k(FN, address(mock), 400_000);
        g1 = _deploy(address(0x6f11), chainUidA, address(0), false, BUDGET, address(0), true, k);
        k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(FN, address(new VerifyOnlyStandIn(address(0x5caa0013), 0, 1)), 250_000, true, 0);
        k[1] = _k(PQZ, all, 1_000_000);
        g2 = _deploy(address(0x6f12), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        bytes32 a1 = _rec(g1, FN);
        assertEq(g2.pqzHomeOf(a1), address(g2));
        bytes memory key = _pqzKey(4);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(a1, UAKinds.keyHashOf(PQZ, key), POP_HASH);
        bytes memory bad = _sig(keyOf_[a1], UAKinds.uaMessage(FN, UAKinds.PURPOSE_PQZ_KEY, rd));
        bad[0] = bytes1(uint8(bad[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, a1));
        g2.setPqzKey(a1, 0, key, POP_HASH, UACall.sig(bad));
        _set(g2, a1, key); // the control
    }
}
