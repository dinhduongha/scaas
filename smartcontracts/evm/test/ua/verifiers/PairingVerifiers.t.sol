// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {
    UASafeVerifier,
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../../src/ua/verifiers/PairingVerifiers.sol";
import {G1Bn254, G1Bls12381} from "../../../src/zether/ZetherCurves.sol";

/// The pairing-curve UA verifiers (accounts.md §1.9) against smartcontracts/vectors/ua/signatures.json (valid PoPs and
/// signatures, the generator's negatives) and kinds.json (every invalid key data of the four kinds, reused as malformed
/// keys and malformed signature points). Gas per verifier is printed and checked against the §1.15 caps.
contract PairingVerifiersTest is Test {
    string internal constant SIGS = "../vectors/ua/signatures.json";
    string internal constant KINDS = "../vectors/ua/kinds.json";
    string internal constant STRUCTURES = "../vectors/ua/structures.json";

    mapping(uint16 => UASafeVerifier) internal verifier;
    uint16[4] internal kinds =
        [UAKinds.SCHNORR_BN254, UAKinds.SCHNORR_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.BLS_BN254_MINSIG];

    struct Row {
        uint16 kind;
        bytes keyData;
        bytes32 ua;
        bytes32 popMsg;
        bytes popSig;
        bytes32 popOtherMsg;
        bytes popOtherSig;
        bytes32 metaMsg;
        bytes metaSig;
        bytes32 memberMsg;
        bytes memberSig;
        string pfx; // ".derived[i]"
    }

    function setUp() public {
        verifier[UAKinds.SCHNORR_BN254] = new SchnorrBn254Verifier();
        verifier[UAKinds.SCHNORR_BLS12381] = new SchnorrBls12381Verifier();
        verifier[UAKinds.BLS12381_MINSIG] = new BlsMinSigBls12381Verifier();
        verifier[UAKinds.BLS_BN254_MINSIG] = new BlsMinSigBn254Verifier();
    }

    // ----- vector access -----

    function _isOurs(uint16 k) internal pure returns (bool) {
        return k >= UAKinds.SCHNORR_BN254 && k <= UAKinds.BLS_BN254_MINSIG;
    }

    function _rows() internal view returns (Row[] memory rows) {
        string memory j = vm.readFile(SIGS);
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(".derived[", vm.toString(n), "]"))) ++n;
        rows = new Row[](4);
        uint256 got;
        for (uint256 i; i < n; ++i) {
            string memory pfx = string.concat(".derived[", vm.toString(i), "]");
            uint16 k = uint16(vm.parseJsonUint(j, string.concat(pfx, ".kind")));
            if (!_isOurs(k)) continue;
            Row memory r = rows[k - UAKinds.SCHNORR_BN254]; // indexed by kind, whatever the file order
            ++got;
            r.kind = k;
            r.pfx = pfx;
            r.keyData = vm.parseJsonBytes(j, string.concat(pfx, ".keyData"));
            r.ua = vm.parseJsonBytes32(j, string.concat(pfx, ".ua"));
            r.popMsg = vm.parseJsonBytes32(j, string.concat(pfx, ".pop.message"));
            r.popSig = vm.parseJsonBytes(j, string.concat(pfx, ".pop.sig"));
            r.popOtherMsg = vm.parseJsonBytes32(j, string.concat(pfx, ".popOther.message"));
            r.popOtherSig = vm.parseJsonBytes(j, string.concat(pfx, ".popOther.sig"));
            for (uint256 s; vm.keyExistsJson(j, string.concat(pfx, ".sigs[", vm.toString(s), "]")); ++s) {
                string memory sa = string.concat(pfx, ".sigs[", vm.toString(s), "]");
                bytes32 purpose = keccak256(bytes(vm.parseJsonString(j, string.concat(sa, ".purpose"))));
                bytes32 m = vm.parseJsonBytes32(j, string.concat(sa, ".message"));
                bytes memory sig = vm.parseJsonBytes(j, string.concat(sa, ".sig"));
                if (purpose == keccak256("metatx")) (r.metaMsg, r.metaSig) = (m, sig);
                else if (purpose == keccak256("member")) (r.memberMsg, r.memberSig) = (m, sig);
            }
        }
        assertEq(got, 4, "signatures.json: the four pairing-curve kinds");
    }

    function _ctxPopDigest(string memory c, bytes32 ua) internal view returns (bytes32) {
        string memory s = vm.readFile(STRUCTURES);
        string memory pfx = string.concat(".contexts.", c);
        return UAKinds.popDigest(
            UAKinds.chainKeyHash(vm.parseJsonUint(s, string.concat(pfx, ".chainId"))),
            vm.parseJsonBytes32(s, string.concat(pfx, ".chainUid")),
            vm.parseJsonAddress(s, string.concat(pfx, ".registry")),
            ua,
            bytes32(0)
        );
    }

    function _bls(uint16 k) internal pure returns (bool) {
        return k == UAKinds.BLS12381_MINSIG || k == UAKinds.BLS_BN254_MINSIG;
    }

    /// The invalid key data rows of kinds.json for `k`.
    function _invalidKeys(uint16 k) internal view returns (bytes[] memory out, string[] memory why) {
        string memory j = vm.readFile(KINDS);
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(".invalid[", vm.toString(n), "]"))) ++n;
        out = new bytes[](n);
        why = new string[](n);
        uint256 got;
        for (uint256 i; i < n; ++i) {
            string memory pfx = string.concat(".invalid[", vm.toString(i), "]");
            if (vm.parseJsonUint(j, string.concat(pfx, ".kind")) != k) continue;
            why[got] = vm.parseJsonString(j, string.concat(pfx, ".reason"));
            out[got++] = vm.parseJsonBytes(j, string.concat(pfx, ".keyData"));
        }
        assembly ("memory-safe") {
            mstore(out, got)
            mstore(why, got)
        }
    }

    function _both(UASafeVerifier v, bytes memory key, bytes32 m, bytes memory sig) internal view returns (bool) {
        return v.verify(key, m, sig) || v.verifyPop(key, m, sig);
    }

    // ----- valid -----

    function test_vectorsBindIdsAndMessages() public view {
        Row[] memory rows = _rows();
        string memory j = vm.readFile(SIGS);
        bytes32 digest = vm.parseJsonBytes32(j, ".digest");
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            assertEq(UAKinds.uaOf(r.kind, r.keyData), r.ua, "ua");
            assertEq(r.popMsg, UAKinds.uaMessage(r.kind, UAKinds.PURPOSE_POP, _ctxPopDigest("A", r.ua)), "pop A");
            assertEq(r.popOtherMsg, UAKinds.uaMessage(r.kind, UAKinds.PURPOSE_POP, _ctxPopDigest("B", r.ua)), "pop B");
            assertEq(r.metaMsg, UAKinds.uaMessage(r.kind, UAKinds.PURPOSE_METATX, digest), "metatx");
            UAKinds.validateKeyData(r.kind, r.keyData, false);
        }
    }

    function test_validPopsAndSignatures() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            assertTrue(v.verifyPop(r.keyData, r.popMsg, r.popSig), "pop A");
            assertTrue(v.verifyPop(r.keyData, r.popOtherMsg, r.popOtherSig), "pop B");
            assertTrue(v.verify(r.keyData, r.metaMsg, r.metaSig), "metatx");
            assertTrue(v.verify(r.keyData, r.memberMsg, r.memberSig), "member");
            // Schnorr: verifyPop == verify; BLS: the PoP domain is separate (CTR-UA-07).
            assertEq(v.verify(r.keyData, r.popMsg, r.popSig), !_bls(r.kind), "pop via verify");
            assertEq(v.verifyPop(r.keyData, r.metaMsg, r.metaSig), !_bls(r.kind), "metatx via verifyPop");
            // PoP of context A does not verify for context B's message.
            assertFalse(v.verifyPop(r.keyData, r.popOtherMsg, r.popSig), "pop A on B");
        }
    }

    // ----- generator negatives (wrong purpose, wrong kind tag, other chain uid, mutated, cross DST) -----

    function test_negatives() public view {
        string memory j = vm.readFile(SIGS);
        Row[] memory rows = _rows();
        uint256 seen;
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            bool sigAsPop;
            bool popAsSig;
            for (uint256 n; vm.keyExistsJson(j, string.concat(r.pfx, ".negatives[", vm.toString(n), "]")); ++n) {
                string memory pfx = string.concat(r.pfx, ".negatives[", vm.toString(n), "]");
                string memory nm = vm.parseJsonString(j, string.concat(pfx, ".name"));
                bool pop = vm.parseJsonBool(j, string.concat(pfx, ".verifyPop"));
                bytes32 m = vm.parseJsonBytes32(j, string.concat(pfx, ".message"));
                bytes memory sig = vm.parseJsonBytes(j, string.concat(pfx, ".sig"));
                bool got = pop ? v.verifyPop(r.keyData, m, sig) : v.verify(r.keyData, m, sig);
                assertFalse(got, string.concat(UAKinds.name(r.kind), " ", nm));
                if (keccak256(bytes(nm)) == keccak256("sig-dst-as-pop")) sigAsPop = true;
                if (keccak256(bytes(nm)) == keccak256("pop-dst-as-sig")) popAsSig = true;
                ++seen;
            }
            if (_bls(r.kind)) assertTrue(sigAsPop && popAsSig, "BLS cross-DST negatives present");
        }
        assertGt(seen, 16);
    }

    // ----- malformed keys: every kinds.json invalid row, plus the other curve's key -----

    function test_malformedKeys() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            (bytes[] memory bad, string[] memory why) = _invalidKeys(r.kind);
            assertGt(bad.length, 5);
            for (uint256 b; b < bad.length; ++b) {
                assertFalse(_both(verifier[r.kind], bad[b], r.metaMsg, r.metaSig), why[b]);
                assertFalse(_both(verifier[r.kind], bad[b], r.popMsg, r.popSig), why[b]);
            }
        }
        // Each Schnorr verifier is bound to its curve: the other curve's valid key + signature fails.
        (Row memory sn, Row memory sb) = (rows[0], rows[1]);
        assertFalse(_both(verifier[sn.kind], sb.keyData, sb.metaMsg, sb.metaSig), "bls schnorr via bn254 verifier");
        assertFalse(_both(verifier[sb.kind], sn.keyData, sn.metaMsg, sn.metaSig), "bn254 schnorr via bls verifier");
    }

    // ----- malformed signatures -----

    function test_malformedSignatureLengths() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            assertFalse(_both(v, r.keyData, r.metaMsg, ""), "empty");
            assertFalse(_both(v, r.keyData, r.metaMsg, _cut(r.metaSig, 1)), "short");
            assertFalse(_both(v, r.keyData, r.metaMsg, bytes.concat(r.metaSig, hex"00")), "long");
            assertFalse(_both(v, r.keyData, r.metaMsg, new bytes(r.metaSig.length)), "all zero");
            assertFalse(_both(v, "", r.metaMsg, r.metaSig), "empty key");
            assertFalse(_both(v, bytes.concat(r.keyData, hex"00"), r.metaMsg, r.metaSig), "long key");
        }
    }

    /// Schnorr: z ≥ r, R = O, R malformed (every invalid G1 encoding of the curve from kinds.json).
    function test_malformedSchnorr() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < 2; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            uint256 p = r.keyData.length;
            uint256 order = p == 64 ? G1Bn254.R : G1Bls12381.R;
            bytes memory rPt = _cut(r.metaSig, 32);
            uint256 z = uint256(bytes32(_tail(r.metaSig, 32)));
            assertTrue(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(z))));
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(z + order))), "z + r");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(order))), "z = r");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(type(uint256).max))), "z = 2^256-1");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(new bytes(p), bytes32(z))), "R = O");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(0))), "z = 0");
            (bytes[] memory bad, string[] memory why) = _invalidKeys(r.kind);
            for (uint256 b; b < bad.length; ++b) {
                if (bad[b].length != p) continue;
                assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(bad[b], bytes32(z))), why[b]);
            }
        }
    }

    /// BLS: the G1 signature replaced by every invalid G1 encoding of its curve (kinds.json rows of the same-curve
    /// Schnorr kind: identity, non-zero padding, x = p, non-canonical, off the curve, outside the subgroup).
    function test_malformedBlsSignatures() public view {
        Row[] memory rows = _rows();
        for (uint256 i = 2; i < 4; ++i) {
            Row memory r = rows[i];
            uint16 g1Kind = r.kind == UAKinds.BLS12381_MINSIG ? UAKinds.SCHNORR_BLS12381 : UAKinds.SCHNORR_BN254;
            (bytes[] memory bad, string[] memory why) = _invalidKeys(g1Kind);
            uint256 n;
            for (uint256 b; b < bad.length; ++b) {
                if (bad[b].length != r.metaSig.length) continue;
                assertFalse(_both(verifier[r.kind], r.keyData, r.metaMsg, bad[b]), why[b]);
                assertFalse(_both(verifier[r.kind], r.keyData, r.popMsg, bad[b]), why[b]);
                ++n;
            }
            assertGt(n, 3);
            // −sig is a valid point and a wrong signature.
            bytes memory negSig =
                r.kind == UAKinds.BLS12381_MINSIG ? G1Bls12381.neg(r.metaSig) : G1Bn254.neg(r.metaSig);
            assertFalse(_both(verifier[r.kind], r.keyData, r.metaMsg, negSig), "-sig");
        }
    }

    /// EIP-2537 in this EVM: G1ADD accepts an on-curve point outside the subgroup, PAIRING_CHECK refuses it — the
    /// BLS12-381 verifier relies on the pairing for the subgroup check of the signature.
    function test_bls12381SubgroupCheckIsInThePairing() public view {
        bytes memory off = _offSubgroupBlsG1();
        (bool ok, bytes memory out) = address(0x0b).staticcall{gas: 50_000}(bytes.concat(off, new bytes(128)));
        assertTrue(ok && out.length == 128, "G1ADD accepts it (on curve only)");
        Row[] memory rows = _rows();
        (ok,) = address(0x0f).staticcall{gas: 200_000}(bytes.concat(off, rows[2].keyData));
        assertFalse(ok, "PAIRING_CHECK refuses it");
    }

    /// `check` reverts on a malformed BLS12-381 point (bn254 G1 points are checked in Solidity: false, no revert);
    /// `verify` / `verifyPop` turn the revert into false.
    function test_checkRevertsVerifyAnswersFalse() public {
        Row[] memory rows = _rows();
        Row memory r = rows[1];
        bytes memory offSubgroupR = bytes.concat(_offSubgroupBlsG1(), _tail(r.metaSig, 32));
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        verifier[r.kind].check{gas: 100_000}(r.keyData, r.metaMsg, offSubgroupR, false);
        assertFalse(verifier[r.kind].verify(r.keyData, r.metaMsg, offSubgroupR));
        Row memory b = rows[0];
        bytes memory offCurveR = bytes.concat(bytes32(uint256(1)), bytes32(uint256(3)), _tail(b.metaSig, 32));
        assertFalse(verifier[b.kind].check(b.keyData, b.metaMsg, offCurveR, false));
    }

    /// Starved calls never pass: below `CHECK_GAS` + 1/64 they revert `UAVerifyGas`; with enough gas they pass.
    function test_starvedVerifyNeverTrue() public {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            uint256 need = v.CHECK_GAS() + v.CHECK_GAS() / 63 + 5_000;
            for (uint256 g = 3_000; g < need; g += need / 7) {
                try v.verify{gas: g}(r.keyData, r.metaMsg, r.metaSig) returns (bool ok) {
                    assertFalse(ok, "starved verify passed");
                } catch {}
            }
            vm.expectRevert(UAKinds.UAVerifyGas.selector);
            v.verify{gas: need - 1_000}(r.keyData, r.metaMsg, r.metaSig);
            assertTrue(v.verify{gas: need + 10_000}(r.keyData, r.metaMsg, r.metaSig), "enough gas");
        }
    }

    /// bn254 `mapToG1` is try-and-increment: gas per extra iteration, and how many iterations `CHECK_GAS` allows
    /// (an honest message needs more than k with probability ~2^-k).
    function test_bn254MapToG1Iterations() public view {
        (uint256 minIt, uint256 minGas, uint256 maxIt, uint256 maxGas) = (type(uint256).max, 0, 0, 0);
        for (uint256 i; i < 64; ++i) {
            bytes memory prefix = abi.encodePacked("SCAAS-UA-BLS-BN254-SIG-V1", keccak256(abi.encode(i)));
            uint256 g = gasleft();
            G1Bn254.mapToG1(prefix);
            g -= gasleft();
            uint256 it = _iterations(prefix);
            if (it < minIt) (minIt, minGas) = (it, g);
            if (it > maxIt) (maxIt, maxGas) = (it, g);
        }
        uint256 per = (maxGas - minGas) / (maxIt - minIt);
        console.log("bn254 mapToG1: iterations min/max", minIt, maxIt);
        console.log("  gas at min / per extra iteration", minGas, per);
        Row[] memory rows = _rows();
        Row memory r = rows[3];
        uint256 valid = _gas(verifier[r.kind], false, r.keyData, r.memberMsg, r.memberSig);
        console.log("  CHECK_GAS headroom in iterations ", (verifier[r.kind].CHECK_GAS() + 3_000 - valid) / per);
    }

    function _iterations(bytes memory prefix) internal view returns (uint256 n) {
        uint256 p = G1Bn254.P;
        for (uint32 ctr;; ++ctr) {
            uint256 x = uint256(keccak256(abi.encodePacked(prefix, ctr))) % p;
            uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
            (, bytes memory y) = address(0x05).staticcall(abi.encode(32, 32, 32, rhs, (p + 1) / 4, p));
            uint256 yy = abi.decode(y, (uint256));
            if (mulmod(yy, yy, p) == rhs) return ctr + 1;
        }
    }

    // ----- gas (accounts.md §1.15 caps: schnorr-bn254 50 k, bls12381-minsig 200 k; the other two have none yet) -----

    function test_gas() public view {
        Row[] memory rows = _rows();
        uint256[4] memory caps = [uint256(50_000), 0, 200_000, 0];
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            uint256 gv = _gas(v, false, r.keyData, r.metaMsg, r.metaSig);
            uint256 gp = _gas(v, true, r.keyData, r.popMsg, r.popSig);
            uint256 gm = _gas(v, false, r.keyData, r.memberMsg, r.memberSig);
            // Rejecting worst case: a well-formed signature for another message runs the full check.
            uint256 gw = _gas(v, false, r.keyData, r.memberMsg, r.metaSig);
            // Rejecting malformed early: all-zero signature.
            uint256 gz = _gas(v, false, r.keyData, r.metaMsg, new bytes(r.metaSig.length));
            // Rejecting a malformed point (a failing precompile burns what it is given): bounded by CHECK_GAS.
            bytes memory offCurve = r.metaSig.length == 64 || r.metaSig.length == 96
                ? bytes.concat(bytes32(uint256(1)), bytes32(uint256(3)), _tail(r.metaSig, r.metaSig.length - 64))
                : bytes.concat(_cut(r.metaSig, r.metaSig.length - 64), bytes32(0), bytes32(uint256(5)), _tail(r.metaSig, r.metaSig.length - 128));
            uint256 gb = _gas(v, false, r.keyData, r.metaMsg, offCurve);
            console.log(UAKinds.name(r.kind));
            console.log("  verify metatx(cold) / member", gv, gm);
            console.log("  verifyPop                   ", gp);
            console.log("  reject wrong msg / zero sig ", gw, gz);
            console.log("  reject off-curve point      ", gb, v.CHECK_GAS());
            assertLe(gb, v.CHECK_GAS() + 10_000, "malformed point bounded by CHECK_GAS");
            uint256 worst = _max(_max(_max(gv, gp), _max(gm, gw)), gb);
            console.log("  worst                       ", worst);
            uint256 gc = gasleft();
            v.check(r.keyData, r.memberMsg, r.memberSig, false);
            console.log("  wrapper overhead (try + self-call)", gm - (gc - gasleft()));
            if (caps[i] != 0) assertLe(worst, caps[i], "over the 1.15 cap");
        }
    }

    /// Proposed `verifyCap` starting values (§1.15 has 50 k and 200 k; schnorr-bls12381 / bls-bn254-minsig: none). A cap
    /// must be at least `CHECK_GAS + CHECK_GAS / 63 + 5 000` plus the call itself, or `verify` reverts `UAVerifyGas`.
    function test_proposedCapsSuffice() public view {
        Row[] memory rows = _rows();
        uint256[4] memory caps = [uint256(50_000), 70_000, 200_000, 345_000];
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            assertGe(caps[i], v.CHECK_GAS() + v.CHECK_GAS() / 63 + 5_000, "cap below the CHECK_GAS floor");
            assertTrue(v.verify{gas: caps[i]}(r.keyData, r.metaMsg, r.metaSig), "metatx at cap");
            assertTrue(v.verifyPop{gas: caps[i]}(r.keyData, r.popMsg, r.popSig), "pop at cap");
        }
    }

    function _gas(UASafeVerifier v, bool pop, bytes memory k, bytes32 m, bytes memory s)
        internal view returns (uint256 used)
    {
        uint256 g = gasleft();
        pop ? v.verifyPop(k, m, s) : v.verify(k, m, s);
        used = g - gasleft();
    }

    function _offSubgroupBlsG1() internal view returns (bytes memory off) {
        (bytes[] memory bad, string[] memory why) = _invalidKeys(UAKinds.SCHNORR_BLS12381);
        for (uint256 b; b < bad.length; ++b) {
            if (keccak256(bytes(why[b])) == keccak256("outside the subgroup")) off = bad[b];
        }
        assertEq(off.length, 128);
    }

    // ----- bytes helpers -----

    function _max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function _cut(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(b.length - n);
        for (uint256 i; i < c.length; ++i) c[i] = b[i];
    }

    function _tail(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) c[i] = b[b.length - n + i];
    }
}
