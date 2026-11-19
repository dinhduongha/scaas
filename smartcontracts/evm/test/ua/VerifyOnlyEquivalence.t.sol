// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {MldsaVerifyOnly, MldsaVerifyOnly44, MldsaVerifyOnly65, MldsaVerifyOnly87} from "../../src/ua/MlDsaVerifyOnly.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {PqVectors} from "./PqVectors.sol";
import {Eip8355Emulator, Eip8355Emulator87, eip8355, eip8355_87} from "./MlDsa.t.sol";

/// An EIP-8355 stand-in lax on one input (`lax`: answered 1), else the emulator's verdict: one per edge row (§7 (d)).
contract LaxOn {
    bytes32 public lax;
    bool public is87;

    function set(bytes32 h, bool k87) external {
        (lax, is87) = (h, k87);
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        bool ok = is87 ? eip8355_87(input) : eip8355(input); // first: `Shake.reserve()` wants the frame's first allocation
        return abi.encode(ok || keccak256(input) == lax ? 1 : 0);
    }
}

/// An EIP-8051 stand-in for key form 1: one word 1 exactly for the input `expected` (the holder's cached key ‖ sig ‖ pq_msg),
/// else 0 (P1: the cache layout equals the precompile's input byte for byte).
contract Eip8051Exact {
    bytes32 public expected;

    function set(bytes32 h) external {
        expected = h;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encode(keccak256(input) == expected ? 1 : 0);
    }
}

/// Equivalence (spec 2026-11-19-registry-verify-only-kinds §7, CTR-UA-62; owner R5, P1; plan Task 10): the verify-only verifier
/// against the holder's `MldsaVerifier` (pure Solidity) on every row of `pq_kat.json` per level, the verifier-level differential
/// (bytes flipped, lengths ± 1, trailing bytes), one lax stand-in per invalid row, and the form-1 cache layout. On forge the
/// precompile is a stand-in backed by the holder's own code (`eip8355`), so these rows test the verify-only verifier's framing
/// (lengths, `pq_msg`, the three states), never a real precompile: that run is Task 13's, on a local chain whose client has it.
/// The ACVP / Wycheproof sets of `pq_external.json` carry their own message framing (no `ua_msg`); through this stand-in they
/// would compare the holder's code with itself, so they run in that local probe. The registry-level differential of §7 (c)
/// needs a registered record of a KAT key, whose PoP the vectors do not carry: the registry's routing on each entry is
/// `UARegistryVerifyOnly.t.sol`'s (Tasks 5, 6). A difference in either direction stops the kind (R5). UNAUDITED.
contract VerifyOnlyEquivalenceTest is PqVectors {
    uint256 internal constant CALL_GAS = 60_000_000; // the stand-in runs a Solidity verify (gas metering paused)
    address internal constant PC = address(0x5caa0014);

    function _name(uint16 kind) internal pure returns (string memory) {
        return kind == PqUA.MLDSA44 ? "mldsa44" : kind == PqUA.MLDSA65 ? "mldsa65" : "mldsa87";
    }

    function _vo(string memory kat, uint16 kind, address pc, uint8 form) internal returns (MldsaVerifyOnly v) {
        address[] memory c = new address[](1);
        c[0] = pc;
        bytes[] memory inv = new bytes[](1);
        inv[0] = _k(kat, _name(kind), "eip8355_probe_invalid");
        bytes memory valid = _k(kat, _name(kind), "eip8355_probe_valid");
        if (kind == PqUA.MLDSA44) v = new MldsaVerifyOnly44(c, valid, inv, form, CALL_GAS);
        else if (kind == PqUA.MLDSA65) v = new MldsaVerifyOnly65(c, valid, inv, form, CALL_GAS);
        else v = new MldsaVerifyOnly87(c, valid, inv, form, CALL_GAS);
    }

    function _pair(string memory kat, uint16 kind) internal returns (MldsaVerifier h, MldsaVerifyOnly v) {
        vm.etch(PC, kind == PqUA.MLDSA87 ? address(new Eip8355Emulator87()).code : address(new Eip8355Emulator()).code);
        h = new MldsaVerifier(kind, address(0), "", "");
        v = _vo(kat, kind, PC, 0);
        assertEq(v.PRECOMPILE(), PC, "probe");
    }

    function _same(MldsaVerifier h, MldsaVerifyOnly v, bytes memory pk, bytes32 m, bytes memory sig, string memory what)
        internal
        view
        returns (bool verdict)
    {
        verdict = h.verify(pk, m, sig);
        assertEq(v.verify(pk, m, sig), verdict, what);
        assertEq(v.verifyPop(pk, m, sig), verdict, what);
    }

    function _mu(string memory kat, string memory name, uint256 i) internal pure returns (string memory) {
        return string.concat(".kinds.", name, ".mutations[", vm.toString(i), "]");
    }

    /// (a): the UA row and every mutation of `pq_kat.json`, with the vectors' own verdict too.
    function _kat(uint16 kind) internal {
        vm.pauseGasMetering();
        string memory kat = _kat();
        string memory name = _name(kind);
        (MldsaVerifier h, MldsaVerifyOnly v) = _pair(kat, kind);
        assertTrue(_same(h, v, _k(kat, name, "pk"), bytes32(_k(kat, name, "ua_msg")), _k(kat, name, "sig"), "UA row"));
        uint256 n;
        for (; vm.keyExistsJson(kat, _mu(kat, name, n)); ++n) {
            string memory mu = _mu(kat, name, n);
            bool got = _same(
                h,
                v,
                _b(kat, string.concat(mu, ".pk")),
                bytes32(_b(kat, string.concat(mu, ".ua_msg"))),
                _b(kat, string.concat(mu, ".sig")),
                vm.parseJsonString(kat, string.concat(mu, ".what"))
            );
            assertEq(got, vm.parseJsonBool(kat, string.concat(mu, ".valid")), "the vectors' verdict");
        }
        assertGt(n, 0);
    }

    function test_equivalence_a_kat_mldsa44() public {
        _kat(PqUA.MLDSA44);
    }

    function test_equivalence_a_kat_mldsa65() public {
        _kat(PqUA.MLDSA65);
    }

    function test_equivalence_a_kat_mldsa87() public {
        _kat(PqUA.MLDSA87);
    }

    /// (b): the verifier-level differential on `mldsa65`'s UA row: a byte of the signature (sampled every 211 bytes and its ends),
    /// of the key (every 97) and the message flipped; lengths ± 1; trailing bytes. Every row the same verdict on both (refused).
    function test_equivalence_b_differential() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        (MldsaVerifier h, MldsaVerifyOnly v) = _pair(kat, PqUA.MLDSA65);
        bytes memory pk = _k(kat, "mldsa65", "pk");
        bytes memory sig = _k(kat, "mldsa65", "sig");
        bytes32 m = bytes32(_k(kat, "mldsa65", "ua_msg"));
        for (uint256 i; i < sig.length + 211; i += 211) {
            bytes memory s = bytes.concat(sig);
            s[i < sig.length ? i : sig.length - 1] ^= 0x01; // the last byte last
            assertFalse(_same(h, v, pk, m, s, "sig byte"));
        }
        for (uint256 i; i < pk.length; i += 97) {
            bytes memory k = bytes.concat(pk);
            k[i] ^= 0x01;
            assertFalse(_same(h, v, k, m, sig, "pk byte"));
        }
        assertFalse(_same(h, v, pk, m ^ bytes32(uint256(1)), sig, "message"));
        assertFalse(_same(h, v, pk, m, bytes.concat(sig, hex"00"), "sig + 1 / trailing"));
        assertFalse(_same(h, v, pk, m, _cut(sig, sig.length - 1), "sig - 1"));
        assertFalse(_same(h, v, bytes.concat(pk, hex"00"), m, sig, "pk + 1 / trailing"));
        assertFalse(_same(h, v, _cut(pk, pk.length - 1), m, sig, "pk - 1"));
    }

    /// (d): for each invalid mutation row, a precompile lax on exactly that row is caught by the differential (the verify-only
    /// verdict differs from the holder's): the probe of the deploy and this suite stop such a kind (R5).
    function test_equivalence_d_laxPerRow_caught() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        MldsaVerifier h = new MldsaVerifier(PqUA.MLDSA65, address(0), "", "");
        LaxOn lax = new LaxOn();
        bytes32 tag = PqUA.tag(PqUA.MLDSA65);
        uint256 caught;
        for (uint256 n; vm.keyExistsJson(kat, _mu(kat, "mldsa65", n)); ++n) {
            string memory mu = _mu(kat, "mldsa65", n);
            if (vm.parseJsonBool(kat, string.concat(mu, ".valid"))) continue;
            (bytes memory pk, bytes memory sig) = (_b(kat, string.concat(mu, ".pk")), _b(kat, string.concat(mu, ".sig")));
            bytes32 m = bytes32(_b(kat, string.concat(mu, ".ua_msg")));
            lax.set(keccak256(abi.encodePacked(pk, sig, PqUA.pqMessage(tag, m))), false);
            // a length mutation never reaches the precompile (lengths first, `test_malformed_answersZero`)
            if (pk.length != 1952 || sig.length != 3309) continue;
            MldsaVerifyOnly v = _vo(kat, PqUA.MLDSA65, address(lax), 0);
            if (v.PRECOMPILE() == address(0)) {
                ++caught; // the row is the probe's own negative row: the probe refuses the lax precompile first
                continue;
            }
            assertTrue(v.verify(pk, m, sig) != h.verify(pk, m, sig), vm.parseJsonString(kat, string.concat(mu, ".what")));
            ++caught;
        }
        assertGt(caught, 0);
    }

    /// Form 1 (P1): the holder's parts of every KAT key, concatenated, are the precompile's expected key bytes: a stand-in that
    /// answers 1 only for `expandedKey(pk) ‖ sig ‖ pq_msg` accepts `verifyCached` on the parts, and refuses one part changed.
    function test_cacheLayout_equalsPrecompileInput() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        _layout(kat, PqUA.MLDSA44, 0);
        _layout(kat, PqUA.MLDSA65, 1);
        _layout(kat, PqUA.MLDSA87, 2);
    }

    function _layout(string memory kat, uint16 kind, uint256 i) internal {
        string memory name = _name(kind);
        MldsaVerifier h = new MldsaVerifier(kind, address(0), "", "");
        bytes memory pk = _k(kat, name, "pk");
        bytes memory sig = _k(kat, name, "sig");
        bytes32 m = bytes32(_k(kat, name, "ua_msg"));
        bytes32 pq = PqUA.pqMessage(PqUA.tag(kind), m);
        MldsaVerifyOnly v = _form1(kind, h, pk, sig, pq);
        bytes memory chunks;
        for (uint256 p; p < h.expandedKeyParts(); ++p) {
            address ptr = address(uint160(0xca000 + 16 * i + p));
            vm.etch(ptr, bytes.concat(hex"00", h.expandedKeyPart(pk, p)));
            chunks = bytes.concat(chunks, bytes20(ptr));
        }
        assertTrue(v.verifyCached(chunks, m, sig), name);
        address last = address(uint160(0xca000 + 16 * i + h.expandedKeyParts() - 1));
        bytes memory code = last.code;
        code[code.length - 1] ^= 0x01; // one byte of the transform's output flipped
        vm.etch(last, code);
        assertFalse(v.verifyCached(chunks, m, sig), "a changed part");
    }

    /// Form 1: a part missing (or a pointer list of the wrong length) answers 0 without a precompile call (lengths first).
    function test_cacheLayout_missingPart_noCall() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        MldsaVerifier h = new MldsaVerifier(PqUA.MLDSA65, address(0), "", "");
        bytes memory pk = _k(kat, "mldsa65", "pk");
        bytes memory sig = _k(kat, "mldsa65", "sig");
        bytes32 m = bytes32(_k(kat, "mldsa65", "ua_msg"));
        MldsaVerifyOnly v = _form1(PqUA.MLDSA65, h, pk, sig, PqUA.pqMessage(PqUA.tag(PqUA.MLDSA65), m));
        address ptr = address(uint160(0xcb000));
        vm.etch(ptr, bytes.concat(hex"00", h.expandedKeyPart(pk, 0)));
        vm.expectCall(v.PRECOMPILE(), "", 0);
        assertFalse(v.verifyCached(abi.encodePacked(ptr), m, sig), "one part of two");
    }

    /// A form-1 verifier over a stand-in that answers 1 only to `expandedKey(pk) ‖ sig ‖ pq` (the probe rows in that layout).
    function _form1(uint16 kind, MldsaVerifier h, bytes memory pk, bytes memory sig, bytes32 pq)
        internal
        returns (MldsaVerifyOnly v)
    {
        Eip8051Exact x = new Eip8051Exact();
        bytes memory valid = abi.encodePacked(h.expandedKey(pk), sig, pq);
        x.set(keccak256(valid));
        address[] memory c = new address[](1);
        c[0] = address(x);
        bytes[] memory inv = new bytes[](1);
        inv[0] = abi.encodePacked(h.expandedKey(pk), sig, ~pq);
        if (kind == PqUA.MLDSA44) v = new MldsaVerifyOnly44(c, valid, inv, 1, CALL_GAS);
        else if (kind == PqUA.MLDSA65) v = new MldsaVerifyOnly65(c, valid, inv, 1, CALL_GAS);
        else v = new MldsaVerifyOnly87(c, valid, inv, 1, CALL_GAS);
        assertEq(v.PRECOMPILE(), address(x));
    }

    function _cut(bytes memory b, uint256 n) internal pure returns (bytes memory r) {
        r = new bytes(n);
        for (uint256 i; i < n; ++i) {
            r[i] = b[i];
        }
    }
}
