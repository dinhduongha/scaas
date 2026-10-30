// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUAKindVerifier, IUAPopVerifier} from "../../src/ua/IUAVerifier.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {console2} from "forge-std/Test.sol";
import {MockVerifier, UARegistryBase} from "./UARegistryBase.sol";
import {BurnAll, GasProbe} from "./UAGas.t.sol";

/// P6c: the PQ kinds in registry generation 1 (accounts.md CTR-UA-17, CTR-UA-23, §1.8, §1.9; pq-zero-knowledge.md CTR-PQZ-12,
/// CTR-PQZ-13). Mock verifiers for the slots, the stored keys and the cache refusals; the
/// real verifiers on smartcontracts/vectors/ua/pq_signatures.json (context A) for T-REG-1/2, T-AUTH-1, the expanded-key
/// cache and T-GAS. Gas is logged (`-vv`).
contract UARegistryPqTest is UARegistryBase {
    uint64 internal constant CAP_MLDSA44 = 4_250_000;
    uint64 internal constant CAP_MLDSA65 = 5_950_000;
    uint64 internal constant CAP_FNDSA = 2_500_000;
    uint64 internal constant CAP_SLHDSA = 1_400_000;
    uint256 internal constant TX_CAP = 16_777_216; // EIP-7825

    /// Read per test into memory (a storage copy of the 0.5 MB file would cost millions of gas per access).
    function _pj() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_signatures.json");
    }

    // ----- configuration -----

    function _realPq() internal returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](5);
        c[0] = UARegistry.KindConfig(0x0101, address(new P256Verifier()), 400_000);
        c[1] = UARegistry.KindConfig(0x0130, address(new UAMldsaVerifier(0x0130, address(0), "", "")), CAP_MLDSA44);
        c[2] = UARegistry.KindConfig(0x0131, address(new UAMldsaVerifier(0x0131, address(0), "", "")), CAP_MLDSA65);
        c[3] = UARegistry.KindConfig(0x0132, address(new UAFndsaVerifier()), CAP_FNDSA);
        c[4] = UARegistry.KindConfig(0x0133, address(new UASlhdsaVerifier()), CAP_SLHDSA);
    }

    /// Mock verifiers for 0x0101, the four PQ kinds and the PQZ key verifier 0x0142, PQ caps `pqCap`.
    function _mockPq(address v, uint64 pqCap) internal pure returns (UARegistry.KindConfig[] memory c) {
        uint16[6] memory ks = [uint16(0x0101), 0x0130, 0x0131, 0x0132, 0x0133, 0x0142];
        c = new UARegistry.KindConfig[](6);
        for (uint256 i; i < 6; ++i) c[i] = UARegistry.KindConfig(ks[i], v, i == 0 ? 400_000 : pqCap);
    }

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == 0x0130 ? 1312 : kind == 0x0131 ? 1952 : kind == 0x0132 ? 897 : kind == 0x0133 ? 32 : 16384;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == 0x0132) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0; // every h_i = 0 < q
        }
    }

    /// Slots: every PQ kind and the PQZ key verifier (0x0142) configurable, with its cap; the neighbours are not in the
    /// table.
    function test_pqSlots() public {
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(address(mock), 1_000_000));
        uint16[5] memory on = [uint16(0x0130), 0x0131, 0x0132, 0x0133, 0x0142];
        for (uint256 i; i < 5; ++i) {
            assertTrue(r.kindEnabled(on[i]));
            assertEq(r.verifyCap(on[i]), 1_000_000);
        }
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[4] memory refused = [uint16(0x012f), 0x0134, 0x0143, 0x0150];
        for (uint256 i; i < 4; ++i) {
            c[0] = UARegistry.KindConfig(refused[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, refused[i]));
            new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        }
    }

    /// CTR-UA-17: PQ keys are stored (`keyPtr` = SSTORE2(pk), `keyOf`); `auth` carries the signature only.
    function test_pqStored() public {
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(address(mock), 1_000_000));
        uint16[4] memory ks = [uint16(0x0130), 0x0131, 0x0132, 0x0133];
        for (uint256 i; i < 4; ++i) {
            bytes memory pk = _pk(ks[i], 1);
            bytes32 ua = _register(r, ks[i], pk);
            (IUARegistry.Record memory rec,) = r.recordOf(ua);
            assertEq(rec.kind, ks[i]);
            assertEq(rec.keyPtr.code, bytes.concat(hex"00", pk), "SSTORE2(pk)");
            assertEq(r.keyOf(ua), pk);
            bytes memory sig = _sig(pk, r.uaMessage(ks[i], UAKinds.PURPOSE_METATX, DIGEST));
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(bytes(""), sig));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(pk, sig)); // key data in auth: refused
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, ks[i]));
            r.register(ks[i], bytes.concat(pk, hex"00"), _none(), "", "");
        }
    }

    /// The cache's refusals: other kinds, a disabled kind, a part past the last, a verifier with a precompile; a wrong
    /// key length.
    function test_cacheRefusals() public {
        UARegistry.KindConfig[] memory c = _realPq();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        bytes memory pk44 = _pk(0x0130, 1);
        uint16[3] memory others = [uint16(0x0132), 0x0133, 0x0101];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, others[i]));
            r.cacheExpandedKey(others[i], pk44, 0);
        }
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        r.cacheExpandedKey(0x0130, pk44, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0131)));
        r.cacheExpandedKey(0x0131, _pk(0x0131, 1), 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, uint16(0x0130)));
        r.cacheExpandedKey(0x0130, _pk(0x0131, 1), 0);
        // a registry without ML-DSA
        UARegistry none = _deploy(address(0x5ca3), chainUidA, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        none.cacheExpandedKey(0x0130, pk44, 0);
    }

    /// Where the ML-DSA verifier answers through a probed precompile the cache is refused: a cached Solidity path
    /// would exceed the precompile's cap and lock the UA.
    function test_cacheRefusedWithPrecompile() public {
        UARegistry.KindConfig[] memory c = _realPq();
        PrecompileStub stub = new PrecompileStub();
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes memory valid = vm.parseJsonBytes(kat, ".kinds.mldsa44.eip8355_probe_valid");
        stub.set(keccak256(valid));
        c[1].verifier = address(
            new UAMldsaVerifier(0x0130, address(stub), valid, vm.parseJsonBytes(kat, ".kinds.mldsa44.eip8355_probe_invalid"))
        );
        assertEq(UAMldsaVerifier(c[1].verifier).PRECOMPILE(), address(stub));
        c[1].cap = 50_000;
        UARegistry pre = _deploy(address(0x5ca4), chainUidA, address(0), false, BUDGET, address(0), true, c);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        pre.cacheExpandedKey(0x0130, _pk(0x0130, 1), 0);
    }

    // ----- the vectors (real verifiers, context A) -----

    function _row(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".kinds[", vm.toString(i), "].", f);
    }

    /// Stores every part of an ML-DSA key's expanded key, one call each (logged); every part fits one EIP-7825
    /// transaction with its calldata at the EIP-7623 floor (F185: the REGULAR gas of the call as its own transaction, with
    /// the intrinsic and the calldata or the EIP-7976 floor, below 2^24; the EIP-8037 state gas of the stored code is
    /// logged apart: 30.4 M to 40.4 M in all, a 2^24 limit would not hold it).
    function _cache(UARegistry r, uint16 kind, bytes memory pk, string memory name) internal {
        bytes32 ua = r.uaOf(kind, pk);
        for (uint256 p; p < (kind == 0x0130 ? 1 : 2); ++p) {
            vm.expectEmit(true, true, false, false, address(r));
            emit IUARegistry.UAKeyCached(ua, kind, p, address(0));
            assertEq(r.cacheExpandedKey(kind, pk, p), ua);
            Vm.Gas memory vg = vm.lastCallGas();
            uint256 g = vg.gasTotalUsed;
            emit log_named_uint(string.concat("cacheExpandedKey ", name, " part ", vm.toString(p)), g);
            emit log_named_uint("  state gas (EIP-8037)", uint256(int256(vg.gasStateUsed)));
            assertLt(g, TX_CAP, "regular gas in one transaction");
            assertTrue(r.expandedKeyOf(ua)[p] != address(0));
        }
        // a second call stores nothing new (front-running gives the same bytes)
        address first = r.expandedKeyOf(ua)[0];
        r.cacheExpandedKey(kind, pk, 0);
        assertEq(r.expandedKeyOf(ua)[0], first);
    }

    /// T-REG-1/2, T-AUTH-1 on pq_signatures.json: PoPs for another chain uid / registry refused; ML-DSA refused
    /// before its cache is complete (the FIPS 204 key exceeds the cap), registered after; every signature passes with
    /// an empty `keyData`; every verify-side negative is `UAUnauthorized`.
    function test_vectors_pq() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        uint256 rows;
        uint256 sigs;
        uint256 negs;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".kinds[", vm.toString(i), "]")); ++i) {
            bytes32 ua = _pqRegister(r, pj, i);
            sigs += _pqSigs(r, pj, i, ua);
            negs += _pqNegatives(r, pj, i, ua);
            ++rows;
        }
        assertEq(rows, 4, "PQ kinds");
        assertEq(sigs, 8, "PQ sigs");
        assertEq(negs, 33, "PQ negatives");
    }

    /// PoP-side refusals, the ML-DSA cache (refused before it is complete), then `register` (logged).
    function _pqRegister(UARegistry r, string memory pj, uint256 i) internal returns (bytes32 ua) {
        uint16 kind = uint16(vm.parseJsonUint(pj, _row(i, "kind")));
        string memory name = vm.parseJsonString(pj, _row(i, "name"));
        bytes memory pk = vm.parseJsonBytes(pj, _row(i, "keyData"));
        ua = vm.parseJsonBytes32(pj, _row(i, "ua"));
        assertEq(r.portablePopDigest(ua, 0, 0), vm.parseJsonBytes32(pj, _row(i, "pop.popDigest")));
        bytes memory pop = vm.parseJsonBytes(pj, _row(i, "pop.sig"));
        if (kind == 0x0130 || kind == 0x0131) {
            _popRefused(r, kind, pk, pop); // no cache yet: the FIPS 204 key exceeds the cap
            _cache(r, kind, pk, name);
        }
        assertEq(vm.parseJsonBytes(pj, _row(i, "popOther.sig")), pop, "UA-8: the PoP is the same in every context");
        for (uint256 n; vm.keyExistsJson(pj, _row(i, string.concat("negatives[", vm.toString(n), "]"))); ++n) {
            string memory ng = _row(i, string.concat("negatives[", vm.toString(n), "]."));
            if (vm.parseJsonBool(pj, string.concat(ng, "verifyPop")) && !_isPqzRow(vm.parseJsonString(pj, string.concat(ng, "name")))) {
                _popRefused(r, kind, pk, vm.parseJsonBytes(pj, string.concat(ng, "sig")));
            }
        }
        uint256 g = gasleft();
        assertEq(r.register(kind, pk, _none(), pop, ""), ua);
        g -= gasleft();
        emit log_named_uint(string.concat("register ", name), g);
        assertEq(r.keyOf(ua), pk);
    }

    /// `c` plus a stand-in `0x0142` R_REG verifier (accepts; it runs after the PoP, which stays real).
    function _withPqz(UARegistry.KindConfig[] memory b) internal returns (UARegistry.KindConfig[] memory c) {
        address rreg = makeAddr("rreg");
        vm.etch(rreg, hex"00");
        vm.mockCall(rreg, abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector), abi.encode(uint256(1)));
        c = new UARegistry.KindConfig[](b.length + 1);
        for (uint256 i; i < b.length; ++i) c[i] = b[i];
        c[b.length] = UARegistry.KindConfig(0x0142, rreg, 1_000_000);
    }

    /// The negative that is refused only when registering WITH the PQZ key (a plain-digest PoP offered with a key).
    function _isPqzRow(string memory name) internal pure returns (bool) {
        return keccak256(bytes(name)) == keccak256("pop-without-pqz-key");
    }

    /// UA-6 U2, UA-8 P1: the holders' portable PoP over the registration digest with the PQZ key `h` and its proof hash
    /// `pqzPopHash`: the vector's `popPqz.sig` registers (real signer verifier); pq_signatures.json carries the proof's
    /// hash only, so the key is stored unproven (UA8-D8: no `keyOwner`); a PoP over the plain digest offered with the
    /// key is `UAPoP` (the converse, a keyed PoP offered without the key, runs in `test_vectors_pq`).
    function test_vectors_pqzPop() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _withPqz(_realPq()));
        uint256 n;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".kinds[", vm.toString(i), "]")); ++i) {
            if (!vm.keyExistsJson(pj, _row(i, "popPqz"))) continue;
            uint256 snap = vm.snapshotState(); // the vectors share one PQZ key: one holder per state
            _pqzPopRow(r, pj, i);
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 3, "holder kinds");
    }

    function _pqzPopRow(UARegistry r, string memory pj, uint256 i) internal {
        uint16 kind = uint16(vm.parseJsonUint(pj, _row(i, "kind")));
        bytes memory pk = vm.parseJsonBytes(pj, _row(i, "keyData"));
        bytes32 ua = vm.parseJsonBytes32(pj, _row(i, "ua"));
        IUARegistry.UAAttrs memory a = IUARegistry.UAAttrs(
            vm.parseJsonBytes(pj, _row(i, "pqzKey")), vm.parseJsonBytes32(pj, _row(i, "popPqz.pqzPopHash")), 0, ""
        );
        bytes32 h = vm.parseJsonBytes32(pj, _row(i, "popPqz.pqzKeyHash"));
        if (kind == 0x0130 || kind == 0x0131) _cache(r, kind, pk, vm.parseJsonString(pj, _row(i, "name")));
        assertEq(UAKinds.keyHashOf(UAKinds.PQZ_MLWE, a.pqzKey), h);
        assertEq(r.portablePopDigest(ua, h, 0), vm.parseJsonBytes32(pj, _row(i, "popPqz.popDigest")));
        assertEq(r.registrationDigest(r.portablePopDigest(ua, h, 0), a.pqzPopHash),
            vm.parseJsonBytes32(pj, _row(i, "popPqz.registrationDigest")));
        _pqzNegatives(r, pj, i, kind, pk, a);
        bytes memory pop = vm.parseJsonBytes(pj, _row(i, "popPqz.sig"));
        assertEq(r.register(kind, pk, a, pop, ""), ua);
        _assertUnproven(r, ua, a, h);
    }

    function _assertUnproven(UARegistry r, bytes32 ua, IUARegistry.UAAttrs memory a, bytes32 h) internal view {
        (address ptr, bytes32 ph, bool proven) = r.pqzKeyOf(ua);
        assertEq(ptr.code, bytes.concat(hex"00", a.pqzKey));
        assertEq(ph, a.pqzPopHash);
        assertFalse(proven);
        assertEq(r.keyOwner(h), bytes32(0));
    }

    function _pqzNegatives(UARegistry r, string memory pj, uint256 i, uint16 kind, bytes memory pk,
        IUARegistry.UAAttrs memory a) internal
    {
        for (uint256 k; vm.keyExistsJson(pj, _row(i, string.concat("negatives[", vm.toString(k), "]"))); ++k) {
            string memory ng = _row(i, string.concat("negatives[", vm.toString(k), "]."));
            if (!_isPqzRow(vm.parseJsonString(pj, string.concat(ng, "name")))) continue;
            bytes memory sig = vm.parseJsonBytes(pj, string.concat(ng, "sig"));
            vm.expectRevert(IUARegistry.UAPoP.selector);
            r.register(kind, pk, a, sig, "");
        }
    }

    /// The `metatx` and `member` signatures pass with an empty `keyData` (logged).
    function _pqSigs(UARegistry r, string memory pj, uint256 i, bytes32 ua) internal view returns (uint256 n) {
        bytes32 digest = vm.parseJsonBytes32(pj, ".digest");
        for (; n < 2; ++n) {
            string memory sr = _row(i, string.concat("sigs[", vm.toString(n), "]."));
            bytes32 p = keccak256(bytes(string.concat("scaas.ua.purpose.", vm.parseJsonString(pj, string.concat(sr, "purpose")), ".v1")));
            bytes memory auth = abi.encode(bytes(""), vm.parseJsonBytes(pj, string.concat(sr, "sig")));
            uint256 g = gasleft();
            r.requireAuthorized(ua, p, digest, auth);
            g -= gasleft();
            if (n == 0) console2.log(string.concat("requireAuthorized ", vm.parseJsonString(pj, _row(i, "name"))), g);
        }
    }

    /// Every verify-side negative: `UAUnauthorized` for exactly the message the row names.
    function _pqNegatives(UARegistry r, string memory pj, uint256 i, bytes32 ua) internal returns (uint256 n) {
        bytes32 digest = vm.parseJsonBytes32(pj, ".digest");
        uint16 kind = uint16(vm.parseJsonUint(pj, _row(i, "kind")));
        for (; vm.keyExistsJson(pj, _row(i, string.concat("negatives[", vm.toString(n), "]"))); ++n) {
            string memory ng = _row(i, string.concat("negatives[", vm.toString(n), "]."));
            if (vm.parseJsonBool(pj, string.concat(ng, "verifyPop"))) continue;
            bytes32 m = vm.parseJsonBytes32(pj, string.concat(ng, "message"));
            bytes32 p = m == UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, digest)
                ? UAKinds.PURPOSE_MEMBER
                : UAKinds.PURPOSE_METATX;
            assertEq(m, UAKinds.uaMessage(kind, p, digest), "a message the registry asks");
            bytes memory auth = abi.encode(bytes(""), vm.parseJsonBytes(pj, string.concat(ng, "sig")));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            r.requireAuthorized(ua, p, digest, auth);
        }
    }

    function _popRefused(UARegistry r, uint16 kind, bytes memory pk, bytes memory sig) internal {
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(kind, pk, _none(), sig, "");
    }

    /// Registers the three `mldsa65` keys (cache + PoP) and signatures.json's `p256` key on `r`.
    function _members(UARegistry r, string memory pj) internal {
        bytes memory pk = vm.parseJsonBytes(pj, _row(1, "keyData"));
        _cache(r, 0x0131, pk, "mldsa65 #0");
        r.register(0x0131, pk, _none(), vm.parseJsonBytes(pj, _row(1, "pop.sig")), "");
        for (uint256 i; i < 2; ++i) {
            string memory x = string.concat(".extraKeys[", vm.toString(i), "].");
            bytes memory k = vm.parseJsonBytes(pj, string.concat(x, "keyData"));
            _cache(r, 0x0131, k, string.concat("mldsa65 #", vm.toString(i + 1)));
            r.register(0x0131, k, _none(), vm.parseJsonBytes(pj, string.concat(x, "pop.sig")), "");
        }
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        assertEq(vm.parseJsonString(sj, ".derived[1].name"), "p256");
        r.register(0x0101, vm.parseJsonBytes(sj, ".derived[1].keyData"), _none(), vm.parseJsonBytes(sj, ".derived[1].pop.sig"), "");
    }

    /// T-GAS (accounts.md §1.16): on a precompile-less registry the hybrid {mldsa65, p256} t=2 registers and
    /// authorizes within `verifyBudget`; the treasury {mldsa65 ×3} t=2 is refused (2 × 5.95 M + the hold > 12 M).
    function test_T_GAS_pqHybrid() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _withPqz(_realPq()));
        _members(r, pj);
        bytes32 hua = _registerMsig(r, pj, ".msig.hybrid");
        assertEq(hua, vm.parseJsonBytes32(pj, ".msig.hybrid.ua"));
        _sets(r, pj, ".msig.hybrid", hua, 1);
        bytes memory tk = vm.parseJsonBytes(pj, ".msig.treasury.keyData");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        r.register(UAKinds.MSIG, tk, _none(), "", "");
    }

    /// T-GAS: at the largest `mldsa65` cap the structure bound admits for the treasury (5,911,000) the `msig` itself
    /// registers (step 4) but not as a PQZ holder (review2 C0-5): 2 x 5.911 M + the cheapest PQZL debit is over 2^24.
    /// The vector's treasury PoP binds a PQZ key, so its signing sets are not run here with the real verifiers
    /// (`test_T_GAS_pqHybrid` does for the hybrid; `UARegistryPq.t.sol:382` `test_T_GAS_msigPqHold` for the treasury's bound).
    function test_T_GAS_pqTreasury() public {
        string memory pj = _pj();
        UARegistry.KindConfig[] memory c = _realPq();
        c[2].cap = 5_911_000;
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _withPqz(c));
        _members(r, pj);
        bytes32 tua = r.uaOf(UAKinds.MSIG, vm.parseJsonBytes(pj, ".msig.treasury.keyData"));
        assertEq(tua, vm.parseJsonBytes32(pj, ".msig.treasury.ua"));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, tua));
        _registerMsig(r, pj, ".msig.treasury");
    }

    /// UA-6 U5: a PQ-eligible `msig` registers with its m-of-n PoP (members 0 and 1, weight 1 each, t = 2): the
    /// vector's real member signatures `msig.*.popPqz.pop` over the registration digest with the PQZ key and its proof
    /// hash (no proof bytes: unproven, UA8-D8).
    function _registerMsig(UARegistry r, string memory pj, string memory m) internal returns (bytes32) {
        IUARegistry.UAAttrs memory a = IUARegistry.UAAttrs(vm.parseJsonBytes(pj, string.concat(m, ".popPqz.pqzKey")),
            vm.parseJsonBytes32(pj, string.concat(m, ".popPqz.pqzPopHash")), 0, "");
        return r.register(UAKinds.MSIG, vm.parseJsonBytes(pj, string.concat(m, ".keyData")), a,
            vm.parseJsonBytes(pj, string.concat(m, ".popPqz.pop")), "");
    }

    /// Each valid set authorizes with exactly `verifyBudget` gas; the below-threshold set fails.
    function _sets(UARegistry r, string memory pj, string memory m, bytes32 ua, uint256 valid) internal {
        bytes32 digest = vm.parseJsonBytes32(pj, ".digest");
        uint256 n;
        for (uint256 s; vm.keyExistsJson(pj, string.concat(m, ".sets[", vm.toString(s), "]")); ++s) {
            string memory sr = string.concat(m, ".sets[", vm.toString(s), "].");
            bytes memory auth = vm.parseJsonBytes(pj, string.concat(sr, "auth"));
            if (vm.parseJsonBool(pj, string.concat(sr, "valid"))) {
                uint256 g = gasleft();
                r.requireAuthorized{gas: BUDGET}(ua, UAKinds.PURPOSE_METATX, digest, auth);
                g -= gasleft();
                emit log_named_uint(string.concat("requireAuthorized ", m, " ", vm.parseJsonString(pj, string.concat(sr, "name"))), g);
                ++n;
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
                r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, digest, auth);
            }
        }
        assertEq(n, valid);
    }

    /// The msig bound with PQ caps (register step 4, P6c): members burning their whole cap authorize within
    /// `verifyBudget` at the largest cap the bound admits; one more thousand gas of cap and the structure is refused.
    function test_T_GAS_msigPqHold() public {
        MockVerifier burner = new MockVerifier(0, 5_901_000);
        (UARegistry r, bytes memory d) = _burnMembers(REG_A, address(burner), 5_911_000);
        bytes32 id = r.uaOf(UAKinds.MSIG, d);
        bytes32 ua = r.register(UAKinds.MSIG, d, _none(), _burnSigs(r, d, id, UAKinds.PURPOSE_POP_V2, _regDigest(id, _none())), "");
        r.requireAuthorized{gas: BUDGET}(
            ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(d, _burnSigs(r, d, ua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        (UARegistry r2,) = _burnMembers(address(0x5ca6), address(burner), 5_912_000);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        r2.register(UAKinds.MSIG, d, _none(), "", "");
    }

    /// Three `mldsa65` UAs on mock verifiers with cap `cap` at `where`, and the treasury {×3, w1} t=2 over them.
    function _burnMembers(address where, address burner, uint64 cap) internal returns (UARegistry r, bytes memory d) {
        r = _deploy(where, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(burner, cap));
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) m[i] = Member(0x0131, _register(r, 0x0131, _pk(0x0131, i)), 1);
        d = _msigKey(2, m);
    }

    /// Members 0 and 1 sign `(purpose, digest)` (mock signatures, stored kind: no key data): `abi.encode(MemberSig[])`.
    function _burnSigs(UARegistry r, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        UARegistry.MemberSig[] memory sigs = new UARegistry.MemberSig[](2);
        for (uint256 i; i < 2; ++i) {
            bytes memory pk = _pk(0x0131, _saltOf(r, d, i));
            sigs[i] = UARegistry.MemberSig(uint16(i), "", _sig(pk, r.uaMessage(0x0131, UAKinds.PURPOSE_MEMBER, md)));
        }
        return abi.encode(sigs);
    }

    /// The salt of the `_pk(0x0131, salt)` key that sits at member index `i` of `d` (members are sorted by id).
    function _saltOf(UARegistry r, bytes memory d, uint256 i) internal pure returns (uint256) {
        for (uint256 s; s < 3; ++s) if (_indexOf(d, r.uaOf(0x0131, _pk(0x0131, s))) == i) return s;
        revert("member");
    }

    // ----- fix round 1: gen 2 hand-off (C6-8, CTR-UA-23) -----

    /// A gen-2 `msig` {native SmartKeyAccount clone, `mldsa65` handed to gen 1} t=2, every capped call burning its whole
    /// cap, a real-size (3,309 B) signature: registered at exactly its bound (one gas less is refused), it authorizes
    /// with exactly the bound as the `requireAuthorized` frame's gas (gen 2 holds for the handed member too).
    function test_T_GAS_pqHandedAtBudget() public {
        (UARegistry home, address impl, bytes32 mlId) = _handedHome();
        address a = address(0x5d10);
        vm.etch(a, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0131, mlId, 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(a), 1);
        bytes memory d = _msigKey(2, m);
        uint256 held = CAP_MLDSA65 + CAP_MLDSA65 / 63 + 5_000; // gen 1's hold inside gen 2's 63/64
        uint256 bound = 445_000 + 45_000 + held + (held - 400_000) / 63;
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry tight = _deploy(address(0x5d20), chainUidA, address(home), false, uint64(bound - 1), impl, true, none);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.register(UAKinds.MSIG, d, _none(), "", "");
        UARegistry r = _deploy(address(0x5d21), chainUidA, address(home), false, uint64(bound), impl, true, none);
        // U5: PQ-eligible (native weight 1 < t = 2), so an m-of-n PoP; BurnAll accepts any signature
        UARegistry.MemberSig[] memory pop = new UARegistry.MemberSig[](2);
        for (uint16 i; i < 2; ++i) pop[i] = UARegistry.MemberSig(i, "", new bytes(i == _indexOf(d, mlId) ? 3309 : 65));
        bytes32 ua = r.register(UAKinds.MSIG, d, _none(), abi.encode(pop), "");
        uint256 least = _handedLeast(r, d, ua, mlId, bound);
        emit log_named_uint("gen-2 handed mldsa65 bound", bound);
        emit log_named_uint("  least requireAuthorized frame gas", least);
    }

    function _handedHome() internal returns (UARegistry home, address impl, bytes32 mlId) {
        impl = address(new BurnAll());
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0131, address(new BurnAll()), CAP_MLDSA65);
        home = _deploy(address(0x5d00), chainUidA, address(0), false, BUDGET, impl, true, c);
        mlId = home.register(0x0131, _pk(0x0131, 1), _none(), "", "");
    }

    /// Asserts `requireAuthorized` succeeds with `bound` gas (3,309 B ML-DSA-65 signature); returns the least frame gas.
    function _handedLeast(UARegistry r, bytes memory d, bytes32 ua, bytes32 mlId, uint256 bound)
        internal
        returns (uint256 hi)
    {
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        for (uint16 i; i < 2; ++i) s[i] = UARegistry.MemberSig(i, "", new bytes(i == _indexOf(d, mlId) ? 3309 : 65));
        bytes memory call = abi.encodeCall(r.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s)));
        GasProbe p = new GasProbe();
        assertTrue(p.probe(address(r), call, bound), "authorizes with its bound");
        uint256 lo;
        for (hi = bound; hi - lo > 1;) {
            uint256 mid = (lo + hi) / 2;
            if (p.probe(address(r), call, mid)) hi = mid;
            else lo = mid;
        }
    }

    /// Half of an `mldsa65` expanded key (part 0 of 2) does not satisfy the registry: the PoP is refused.
    function test_halfCacheRefusesPop() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        bytes memory pk = vm.parseJsonBytes(pj, _row(1, "keyData"));
        r.cacheExpandedKey(0x0131, pk, 0);
        _popRefused(r, 0x0131, pk, vm.parseJsonBytes(pj, _row(1, "pop.sig")));
    }

    /// Gen 2 hands PQ records to gen 1: it authorizes with gen 1's cache; it has no cache of its own.
    function test_gen2PqHandoff() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry g2 = _deploy(address(0x5d30), chainUidA, address(r), false, BUDGET, address(0), true, none);
        bytes memory pk = vm.parseJsonBytes(pj, _row(0, "keyData"));
        assertEq(uint16(vm.parseJsonUint(pj, _row(0, "kind"))), 0x0130);
        _cache(r, 0x0130, pk, "mldsa44");
        bytes32 ua = r.register(0x0130, pk, _none(), vm.parseJsonBytes(pj, _row(0, "pop.sig")), "");
        _pqSigs(g2, pj, 0, ua);
        address[2] memory z = g2.expandedKeyOf(ua);
        assertEq(z[0], address(0));
        assertEq(z[1], address(0));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        g2.cacheExpandedKey(0x0130, pk, 0);
    }

    // The `pqz-mlwe` `authRef` cases (CTR-PQZ-12 before UA-6) are in legacy/ua6/test/ua/UARegistryPq.t.sol; the PQZ key
    // attribute is tested in `UARegistryUA6.t.sol`.
}

/// A precompile stand-in for the probe: the word 1 for the one input whose hash is set, else the word 0.
contract PrecompileStub {
    bytes32 public good;

    function set(bytes32 h) external {
        good = h;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encode(keccak256(input) == good ? uint256(1) : uint256(0));
    }
}
