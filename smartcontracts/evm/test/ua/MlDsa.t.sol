// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqVectors} from "./PqVectors.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {Shake} from "../../src/ua/Shake.sol";
import {MlDsa, MldsaVerifier} from "../../src/ua/MlDsa.sol";

/// FIPS 204 Table 1, ML-DSA-87, written out here (the test's own copy of `MlDsa.params87()`).
function p87() pure returns (MlDsa.Params memory) {
    return MlDsa.Params(8, 7, 60, 120, 1 << 19, (MlDsa.Q - 1) / 32, 75, 64, 20, 4, 2592, 4627);
}

contract MlHarness {
    function verify(uint256 level, bytes calldata pk, bytes calldata mprime, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        Shake.reserve();
        return MlDsa.verify(level == 44 ? MlDsa.params44() : level == 65 ? MlDsa.params65() : p87(), pk, mprime, sig);
    }

    function verifyExpanded(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        Shake.reserve();
        return MlDsa.verifyExpanded(level == 44 ? MlDsa.params44() : MlDsa.params65(), ek, mprime, sig);
    }

    function shake256(bytes calldata input, uint256 outLen) external pure returns (bytes memory out) {
        Shake.reserve();
        bytes memory inp = input;
        out = new bytes(outLen + 200); // whole blocks are written
        uint256 p;
        uint256 o;
        assembly {
            p := add(inp, 32)
            o := add(out, 32)
        }
        Shake.hash(Shake.SHAKE256, p, input.length, o, outLen);
        assembly {
            mstore(out, outLen)
        }
    }
}

/// The cached path on a formatted message `mprime` of the caller's (ACVP's): the parts read by `MlDsa.readParts`, the same library
/// function `MldsaVerifier.verifyCached` reads them with (no copy, F-9), then the level's core on the expanded key.
contract CachedM {
    function verify(uint256 level, bytes calldata chunks, bytes calldata mprime, bytes calldata sig)
        external
        view
        returns (bool)
    {
        MlDsa.Params memory P = level == 44 ? MlDsa.params44() : level == 65 ? MlDsa.params65() : p87();
        (bytes memory ek, bool ok) = MlDsa.readParts(P, chunks, level == 44 ? 1 : level == 65 ? 2 : 3);
        return ok && this.verifyExpanded(level, ek, mprime, sig);
    }

    function verifyExpanded(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        Shake.reserve();
        return
            MlDsa.verifyExpanded(
                level == 44 ? MlDsa.params44() : level == 65 ? MlDsa.params65() : p87(), ek, mprime, sig
            );
    }
}

/// EIP-8355 `VERIFY_MLDSA44` / `VERIFY_MLDSA65` by input length: `pk ‖ sig ‖ msg`.
function eip8355(bytes calldata input) pure returns (bool ok) {
    Shake.reserve();
    if (input.length >= 3732 && input.length < 5261) {
        ok = MlDsa.verify(MlDsa.params44(), input[0:1312], abi.encodePacked(bytes2(0), input[3732:]), input[1312:3732]);
    } else if (input.length >= 5261) {
        ok = MlDsa.verify(MlDsa.params65(), input[0:1952], abi.encodePacked(bytes2(0), input[5261:]), input[1952:5261]);
    }
}

/// `VERIFY_MLDSA87` in the EIP-8355 layout (`pk ‖ sig ‖ msg`): the stand-in for `0x14` / the SCaaS testnet's `0x…5caa0014`.
function eip8355_87(bytes calldata input) pure returns (bool ok) {
    Shake.reserve();
    if (input.length >= 7219) {
        ok = MlDsa.verify(p87(), input[0:2592], abi.encodePacked(bytes2(0), input[7219:]), input[2592:7219]);
    }
}

contract Eip8355Emulator87 {
    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encode(eip8355_87(input) ? 1 : 0);
    }
}

/// An EIP-8355 precompile stand-in: `pk ‖ sig ‖ msg` ⇒ the 32-byte word 0 or 1, ML-DSA-44 or -65 by length.
contract Eip8355Emulator {
    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encode(eip8355(input) ? 1 : 0);
    }
}

/// Answers a valid input with the word 1 and reverts (with a 32-byte zero word) on an invalid one.
contract RevertsOnInvalid {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (!eip8355(input)) {
            assembly {
                mstore(0, 0)
                revert(0, 32)
            }
        }
        return abi.encode(uint256(1));
    }
}

contract AlwaysOne {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

/// `mldsa44` / `mldsa65` (CTR-UA-23): ACVP ML-DSA sigVer (pure and internal), the EIP-8051 NIST KATs, the EIP-8355
/// cases, the EIP-8051 expanded key, the precompile probe, the SCaaS UA vectors, malformed encodings.
contract MlDsaTest is PqVectors {
    function test_zetaTable_mldsa() public pure {
        _zetas(MlDsa.ZETAS, 4, 256, 8380417, 1753);
    }

    function test_kat_mldsa44() public {
        _uaVector("mldsa44", address(new MldsaVerifier(PqUA.MLDSA44, address(0), "", "")), PqUA.MLDSA44);
    }

    function test_kat_mldsa65() public {
        _uaVector("mldsa65", address(new MldsaVerifier(PqUA.MLDSA65, address(0), "", "")), PqUA.MLDSA65);
    }

    /// The EIP-8051 expanded key: Solidity and clientkeys produce the same bytes, and it verifies the same signature.
    function test_expandedKey() public {
        string memory kat = _kat();
        MlHarness h = new MlHarness();
        string[2] memory names = ["mldsa44", "mldsa65"];
        uint16[2] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65];
        for (uint256 i; i < 2; ++i) {
            uint256 level = i == 0 ? 44 : 65;
            bytes memory ek = new MldsaVerifier(kinds[i], address(0), "", "").expandedKey(_k(kat, names[i], "pk"));
            assertEq(ek, _k(kat, names[i], "expanded_key"), names[i]);
            bytes memory mprime = abi.encodePacked(bytes2(0), _k(kat, names[i], "signed_message"));
            bytes memory sig = _k(kat, names[i], "sig");
            assertTrue(h.verifyExpanded(level, ek, mprime, sig));
            sig[5] ^= 0x01;
            assertFalse(h.verifyExpanded(level, ek, mprime, sig));
            sig[5] ^= 0x01;
            assertFalse(h.verifyExpanded(i == 0 ? 65 : 44, ek, mprime, sig), "expanded key of the other level");
            _setU32(ek, 0, _u32(ek, 0) + MlDsa.Q); // first Â coefficient + q (< 2^32): refused, not reduced
            assertFalse(h.verifyExpanded(level, ek, mprime, sig));
        }
    }

    /// P6c: the parts the UA registry stores concatenate to the expanded key, each fits EIP-170 with its STOP byte;
    /// `verifyCached` reads them by EXTCODECOPY and agrees with `verify`; a wrong count, order or byte fails; a part
    /// past the last reverts; `verifyPop` is `verify`.
    function test_expandedKeyParts_verifyCached() public {
        string memory kat = _kat();
        string[2] memory names = ["mldsa44", "mldsa65"];
        uint16[2] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65];
        for (uint256 i; i < 2; ++i) {
            MldsaVerifier v = new MldsaVerifier(kinds[i], address(0), "", "");
            bytes memory pk = _k(kat, names[i], "pk");
            uint256 parts = v.expandedKeyParts();
            assertEq(parts, i + 1, "parts");
            bytes memory chunks;
            bytes memory all;
            for (uint256 p; p < parts; ++p) {
                bytes memory part = v.expandedKeyPart(pk, p);
                assertLt(part.length, 24_576, "EIP-170 with the STOP byte");
                address ptr = address(uint160(0xc0de00 + 16 * i + p));
                vm.etch(ptr, bytes.concat(hex"00", part));
                chunks = bytes.concat(chunks, bytes20(ptr));
                all = bytes.concat(all, part);
            }
            assertEq(all, _k(kat, names[i], "expanded_key"), names[i]);
            vm.expectRevert(abi.encodeWithSelector(MldsaVerifier.UAMldsaPart.selector, parts));
            v.expandedKeyPart(pk, parts);
            bytes32 m = bytes32(_k(kat, names[i], "ua_msg"));
            bytes memory sig = _k(kat, names[i], "sig");
            assertTrue(v.verifyCached(chunks, m, sig), "cached");
            assertTrue(v.verifyExpanded(all, m, sig), "expanded");
            assertTrue(v.verifyPop(pk, m, sig), "verifyPop = verify");
            assertFalse(v.verifyCached(chunks, ~m, sig), "other message");
            assertFalse(v.verifyCached(bytes.concat(chunks, bytes20(address(0xc0de00))), m, sig), "extra pointer");
            assertFalse(
                v.verifyCached(bytes.concat(bytes20(address(0xbad)), _slice(chunks, 20, chunks.length - 20)), m, sig),
                "a pointer without code"
            );
            if (parts == 2) {
                bytes memory swapped = bytes.concat(_slice(chunks, 20, 20), _slice(chunks, 0, 20));
                assertFalse(v.verifyCached(swapped, m, sig), "parts out of order");
            }
            address last = address(bytes20(_slice(chunks, chunks.length - 20, 20)));
            bytes memory code = last.code;
            code[code.length - 1] ^= 0x01; // one t̂1 coefficient's low byte
            vm.etch(last, code);
            assertFalse(v.verifyCached(chunks, m, sig), "one flipped byte");
        }
    }

    function test_acvp_mldsa() public {
        vm.pauseGasMetering(); // 90 full verifications: correctness only
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        uint256 n = _cases(ext, "acvp_mldsa");
        assertEq(n, 90); // 30 per level; ML-DSA-87 since CTR-UA-39 (tgId 5 pure, tgId 12 internal)
        for (uint256 i; i < n; ++i) {
            string memory c = _case("acvp_mldsa", i);
            bytes32 set = keccak256(bytes(vm.parseJsonString(ext, string.concat(c, ".set"))));
            uint256 level = set == keccak256("ML-DSA-44") ? 44 : set == keccak256("ML-DSA-65") ? 65 : 87;
            bool got = h.verify(
                level,
                _b(ext, string.concat(c, ".pk")),
                _b(ext, string.concat(c, ".mprime")),
                _b(ext, string.concat(c, ".sig"))
            );
            assertEq(
                got,
                vm.parseJsonBool(ext, string.concat(c, ".valid")),
                vm.parseJsonString(ext, string.concat(c, ".reason"))
            );
        }
    }

    function test_eip8051_nistKat() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        assertEq(_cases(ext, "eip8051_nist_kat"), 10);
        for (uint256 i; i < 10; ++i) {
            string memory c = _case("eip8051_nist_kat", i);
            assertTrue(
                h.verify(
                    44,
                    _b(ext, string.concat(c, ".pk")),
                    _b(ext, string.concat(c, ".mprime")),
                    _b(ext, string.concat(c, ".sig"))
                )
            );
        }
    }

    function test_eip8355_cases() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        for (uint256 i; i < 2; ++i) {
            // cases 1 and 2; case 3 (too short to parse) runs in the probe test
            string memory c = _case("eip8355", i);
            bool got = h.verify(
                44,
                _b(ext, string.concat(c, ".pk")),
                _b(ext, string.concat(c, ".mprime")),
                _b(ext, string.concat(c, ".sig"))
            );
            assertEq(got, vm.parseJsonBool(ext, string.concat(c, ".valid")));
        }
    }

    /// The precompile is used only on an exact EIP-8355 answer (valid ⇒ word 1, flipped ⇒ word 0), for both levels.
    function test_probe_usesOnlyAnExactEip8355Answer() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        string[2] memory names = ["mldsa44", "mldsa65"];
        uint16[2] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65];
        address pc = address(0x12);
        for (uint256 i; i < 2; ++i) {
            bytes memory valid = _k(kat, names[i], "eip8355_probe_valid");
            bytes memory invalid = _k(kat, names[i], "eip8355_probe_invalid");
            vm.etch(pc, ""); // no code: probe fails, pure Solidity
            assertEq(new MldsaVerifier(kinds[i], pc, valid, invalid).PRECOMPILE(), address(0));
            vm.etch(pc, address(new AlwaysOne()).code); // answers 1 to everything: refused
            assertEq(new MldsaVerifier(kinds[i], pc, valid, invalid).PRECOMPILE(), address(0));
            vm.etch(pc, address(new Eip8355Emulator()).code);
            MldsaVerifier v = new MldsaVerifier(kinds[i], pc, valid, invalid);
            assertEq(v.PRECOMPILE(), pc);
            bytes32 uaMsg = bytes32(_k(kat, names[i], "ua_msg"));
            assertTrue(v.verify(_k(kat, names[i], "pk"), uaMsg, _k(kat, names[i], "sig")));
            assertFalse(v.verify(_k(kat, names[i], "pk"), uaMsg ^ bytes32(uint256(1)), _k(kat, names[i], "sig")));
        }
        (bool ok, bytes memory ret) = pc.staticcall(_b(_ext(), ".eip8355.cases[2].input")); // EIP-8355 case 3
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), 0);
    }

    function test_refusesOtherKinds() public {
        vm.expectRevert(abi.encodeWithSelector(MldsaVerifier.UAMldsaKind.selector, PqUA.FNDSA512));
        new MldsaVerifier(PqUA.FNDSA512, address(0), "", "");
    }

    function test_malformed_mldsa() public {
        string memory kat = _kat();
        MldsaVerifier v = new MldsaVerifier(PqUA.MLDSA44, address(0), "", "");
        bytes memory pk = _k(kat, "mldsa44", "pk");
        bytes memory sig = _k(kat, "mldsa44", "sig");
        bytes32 m = bytes32(_k(kat, "mldsa44", "ua_msg"));
        assertFalse(v.verify(_k(kat, "mldsa65", "pk"), m, sig)); // a 65 key on the 44 verifier
        assertFalse(new MldsaVerifier(PqUA.MLDSA65, address(0), "", "").verify(pk, m, sig)); // 44 on the 65 verifier
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
        sig[2420 - 4] = 0x51; // hint count of row 0 above ω = 80
        assertFalse(v.verify(pk, m, sig));
    }

    /// HintBitUnpack's encoding checks on the vectors' signatures: each mutant keeps the hint masks, so it verifies iff
    /// the check is missing (non-zero padding; a repeated index with the count raised by one).
    function test_malformed_hints() public {
        string memory kat = _kat();
        MlHarness h = new MlHarness();
        string[2] memory names = ["mldsa44", "mldsa65"];
        for (uint256 i; i < 2; ++i) {
            MlDsa.Params memory P = i == 0 ? MlDsa.params44() : MlDsa.params65();
            uint256 level = i == 0 ? 44 : 65;
            bytes memory pk = _k(kat, names[i], "pk");
            bytes memory sig = _k(kat, names[i], "sig");
            bytes memory mprime = abi.encodePacked(bytes2(0), _k(kat, names[i], "signed_message"));
            assertTrue(h.verify(level, pk, mprime, sig));
            uint256 y = P.sigLen - P.omega - P.k; // the hint encoding: ω indices, then k running counts
            uint256 used = uint8(sig[P.sigLen - 1]);
            assertLt(used, P.omega); // there is padding
            assertGt(used, uint8(sig[P.sigLen - 2])); // the last row has a hint
            bytes memory bad = bytes.concat(sig);
            bad[y + P.omega - 1] = 0x01;
            assertFalse(h.verify(level, pk, mprime, bad), "non-zero hint padding");
            bad = bytes.concat(sig);
            bad[y + used] = bad[y + used - 1];
            bad[P.sigLen - 1] = bytes1(uint8(used + 1));
            assertFalse(h.verify(level, pk, mprime, bad), "repeated hint index");
        }
    }

    /// The z bound (`‖z‖∞ < γ1 − β`, both signs) on the degenerate expanded key (`_degenerateKey`): z_0 = ±(γ1 − β − 1)
    /// is accepted, ±(γ1 − β) refused, nothing else differs.
    function test_malformed_zBound() public {
        vm.pauseGasMetering();
        MlHarness h = new MlHarness();
        bytes memory mprime = abi.encodePacked(bytes2(0), keccak256("any message"));
        for (uint256 i; i < 2; ++i) {
            (MlDsa.Params memory P, bytes memory ek, bytes memory tr) = _degenerateKey(i);
            uint256 level = i == 0 ? 44 : 65;
            bytes memory sig = _degenerate(h, P, tr, mprime, new bytes(P.omega + P.k)); // no hints, z = 0
            assertTrue(h.verifyExpanded(level, ek, mprime, sig));
            _setZ0(P, sig, P.beta + 1); // z_0 = γ1 − v
            assertTrue(h.verifyExpanded(level, ek, mprime, sig));
            _setZ0(P, sig, 2 * P.gamma1 - P.beta - 1);
            assertTrue(h.verifyExpanded(level, ek, mprime, sig));
            _setZ0(P, sig, P.beta);
            assertFalse(h.verifyExpanded(level, ek, mprime, sig), "z_0 = gamma1 - beta");
            _setZ0(P, sig, 2 * P.gamma1 - P.beta);
            assertFalse(h.verifyExpanded(level, ek, mprime, sig), "z_0 = -(gamma1 - beta)");
        }
    }

    /// The hint count `≤ ω` on the degenerate expanded key: rows 0 .. k−2 end at x, the last row holds ω − x indices
    /// (accepted) or ω + 1 (refused; its last index is read from the first count byte, x).
    function test_malformed_hintCount() public {
        vm.pauseGasMetering();
        MlHarness h = new MlHarness();
        bytes memory mprime = abi.encodePacked(bytes2(0), keccak256("any message"));
        for (uint256 i; i < 2; ++i) {
            (MlDsa.Params memory P, bytes memory ek, bytes memory tr) = _degenerateKey(i);
            bytes memory sig = _degenerate(h, P, tr, mprime, _hintsUpTo(P, P.omega));
            assertTrue(h.verifyExpanded(i == 0 ? 44 : 65, ek, mprime, sig));
            sig = _degenerate(h, P, tr, mprime, _hintsUpTo(P, P.omega + 1));
            assertFalse(h.verifyExpanded(i == 0 ? 44 : 65, ek, mprime, sig), "hint count > omega");
        }
    }

    /// CTR-UA-39: `mldsa87` through an EIP-8355 precompile (the emulator at the SCaaS testnet's address): the pq_kat.json row
    /// and each mutation with noble's verdict (the c~ second-word flip among them), and the library's own parameters.
    function test_kat_mldsa87() public {
        vm.pauseGasMetering(); // each emulated precompile call is a full Solidity verify
        string memory kat = _kat();
        address pc = 0x000000000000000000000000000000005caA0014; // the SCaaS testnet's MLDSA87
        vm.etch(pc, address(new Eip8355Emulator87()).code);
        MldsaVerifier v = new MldsaVerifier(
            PqUA.MLDSA87, pc, _k(kat, "mldsa87", "eip8355_probe_valid"), _k(kat, "mldsa87", "eip8355_probe_invalid")
        );
        assertEq(v.PRECOMPILE(), pc);
        _uaVector("mldsa87", address(v), PqUA.MLDSA87);
        assertEq(abi.encode(MlDsa.params87()), abi.encode(p87()));
    }

    /// CTR-UA-39 Q1 as rewritten by the owner 2026-11-15: `mldsa87` has a verifier without a precompile too (none, an empty
    /// account, one that says 1 to everything, a probe of another level: pure Solidity, `PRECOMPILE` 0) and the two-part cache;
    /// with an answering precompile it uses it. The UA row and its mutations through `verifyCached` on the parts.
    function test_mldsa87_withoutPrecompile() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        bytes memory valid = _k(kat, "mldsa87", "eip8355_probe_valid");
        bytes memory invalid = _k(kat, "mldsa87", "eip8355_probe_invalid");
        address pc = address(0x14);
        assertEq(new MldsaVerifier(PqUA.MLDSA87, address(0), "", "").PRECOMPILE(), address(0), "none");
        assertEq(new MldsaVerifier(PqUA.MLDSA87, pc, valid, invalid).PRECOMPILE(), address(0), "empty account");
        vm.etch(pc, address(new AlwaysOne()).code);
        assertEq(
            new MldsaVerifier(PqUA.MLDSA87, pc, valid, invalid).PRECOMPILE(), address(0), "answers 1 to everything"
        );
        vm.etch(pc, address(new Eip8355Emulator()).code); // 44 / 65 only
        assertEq(
            new MldsaVerifier(
                    PqUA.MLDSA87,
                    pc,
                    _k(kat, "mldsa65", "eip8355_probe_valid"),
                    _k(kat, "mldsa65", "eip8355_probe_invalid")
                )
                .PRECOMPILE(),
            address(0),
            "a probe of another level"
        );
        vm.etch(pc, address(new Eip8355Emulator87()).code);
        assertEq(new MldsaVerifier(PqUA.MLDSA87, pc, valid, invalid).PRECOMPILE(), pc, "the precompile when it answers");
        MldsaVerifier v = new MldsaVerifier(PqUA.MLDSA87, address(0), "", "");
        _uaVector("mldsa87", address(v), PqUA.MLDSA87); // pure Solidity on the FIPS 204 key
        (bytes memory chunks, bytes memory all) = _parts(v, _k(kat, "mldsa87", "pk"), 0xc0de87);
        assertEq(all, v.expandedKey(_k(kat, "mldsa87", "pk")), "parts concatenate to expandedKey(pk)");
        _cached87(v, kat, chunks);
    }

    /// The `mldsa87` UA row and its mutations of the same key through `verifyCached` on `chunks` (its parts).
    function _cached87(MldsaVerifier v, string memory kat, bytes memory chunks) internal view {
        bytes32 m = bytes32(_k(kat, "mldsa87", "ua_msg"));
        bytes memory sig = _k(kat, "mldsa87", "sig");
        assertTrue(v.verifyCached(chunks, m, sig), "cached");
        assertFalse(v.verifyCached(chunks, ~m, sig), "other message");
        assertEq(chunks.length, 60, "three pointers");
        assertFalse(v.verifyCached(_slice(chunks, 0, 40), m, sig), "parts 0 + 1 only");
        assertFalse(
            v.verifyCached(bytes.concat(_slice(chunks, 0, 20), _slice(chunks, 40, 20)), m, sig), "parts 0 + 2 only"
        );
        assertFalse(
            v.verifyCached(bytes.concat(_slice(chunks, 20, 20), _slice(chunks, 0, 20), _slice(chunks, 40, 20)), m, sig),
            "parts out of order"
        );
        uint256 n;
        uint256 same;
        for (; vm.keyExistsJson(kat, string.concat(".kinds.mldsa87.mutations[", vm.toString(n), "]")); ++n) {
            string memory mu = string.concat(".kinds.mldsa87.mutations[", vm.toString(n), "]");
            if (keccak256(_b(kat, string.concat(mu, ".pk"))) != keccak256(_k(kat, "mldsa87", "pk"))) continue; // another key
            bool got = v.verifyCached(
                chunks, bytes32(_b(kat, string.concat(mu, ".ua_msg"))), _b(kat, string.concat(mu, ".sig"))
            );
            assertEq(
                got,
                vm.parseJsonBool(kat, string.concat(mu, ".valid")),
                vm.parseJsonString(kat, string.concat(mu, ".what"))
            );
            ++same;
        }
        assertEq(n, 9, "mutations");
        assertGt(same, 6, "most mutations keep the key");
    }

    /// The registry's parts of `pk` on `v`, each at its own pointer (`0x00 ‖ part`, as SSTORE2), and their concatenation.
    function _parts(MldsaVerifier v, bytes memory pk, uint256 at)
        internal
        returns (bytes memory chunks, bytes memory all)
    {
        for (uint256 p; p < v.expandedKeyParts(); ++p) {
            bytes memory part = v.expandedKeyPart(pk, p);
            address ptr = address(uint160(at * 16 + p));
            vm.etch(ptr, bytes.concat(hex"00", part));
            chunks = bytes.concat(chunks, bytes20(ptr));
            all = bytes.concat(all, part);
        }
    }

    /// Owner 2026-11-15 (CTR-UA-39 Q1, MD-4): the `mldsa87` parts are `Â` rows 0-2, 3-5 and 6-7 ‖ tr ‖ t̂1 (21,504 / 21,504 / 22,592 B),
    /// each under EIP-170 with its STOP byte, 65,600 B in all; `mldsa65` keeps rows 0-2 | 3-5 ‖ tail (15,360 / 21,568 B), `mldsa44`
    /// one part (20,544 B); `expandedKeyParts` is `PqUA.mldsaParts` (the one count). Each multi-part kind concatenates to
    /// `expandedKey(pk)` byte for byte (the split; the expansion itself against an independent reference in
    /// `test_expandedKey_nobleReference`); past the last part reverts `UAMldsaPart`.
    function test_expandedKeyParts_split() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        string[3] memory names = ["mldsa44", "mldsa65", "mldsa87"];
        uint16[3] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65, PqUA.MLDSA87];
        uint256[3][3] memory len =
            [[uint256(20_544), 0, 0], [uint256(15_360), 21_568, 0], [uint256(21_504), 21_504, 22_592]];
        for (uint256 i; i < 3; ++i) {
            MldsaVerifier v = new MldsaVerifier(kinds[i], address(0), "", "");
            bytes memory pk = _k(kat, names[i], "pk");
            uint256 parts = v.expandedKeyParts();
            assertEq(parts, i + 1, "parts");
            assertEq(parts, PqUA.mldsaParts(kinds[i]), "the one count");
            bytes memory all;
            for (uint256 p; p < parts; ++p) {
                bytes memory part = v.expandedKeyPart(pk, p);
                assertEq(part.length, len[i][p], string.concat(names[i], " part ", vm.toString(p), " length"));
                assertLt(part.length + 1, 24_577, "EIP-170 with the STOP byte");
                all = bytes.concat(all, part);
            }
            assertEq(all, v.expandedKey(pk), string.concat(names[i], ": parts = expandedKey(pk)"));
            assertEq(all.length, MlDsa.expandedLen(i == 0 ? MlDsa.params44() : i == 1 ? MlDsa.params65() : p87()));
            vm.expectRevert(abi.encodeWithSelector(MldsaVerifier.UAMldsaPart.selector, parts));
            v.expandedKeyPart(pk, parts);
        }
        assertEq(PqUA.mldsaParts(PqUA.FNDSA512), 0, "no cache for another kind");
        assertEq(PqUA.mldsaParts(PqUA.FNDSA1024), 0);
    }

    /// F-9 (owner 2026-11-15): the expansion against an independent reference, `mldsa_cache.json` (gen_mldsa_cache.mjs, built from noble's
    /// post-quantum 0.7.1, its own XOF128 and NTT, not from this code; for 44 / 65 equal to clientkeys' `pq_kat.json` key):
    /// 12 keys per level, the whole expanded key and every part by SHA-256 and length.
    function test_expandedKey_nobleReference() public {
        vm.pauseGasMetering();
        string memory j = vm.readFile("../vectors/ua/mldsa_cache.json");
        string[3] memory names = ["mldsa44", "mldsa65", "mldsa87"];
        uint16[3] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65, PqUA.MLDSA87];
        uint256 n;
        for (uint256 i; i < 3; ++i) {
            MldsaVerifier v = new MldsaVerifier(kinds[i], address(0), "", "");
            for (
                uint256 r;
                vm.keyExistsJson(j, string.concat(".levels.", names[i], ".keys[", vm.toString(r), "]"));
                ++r
            ) {
                string memory row = string.concat(".levels.", names[i], ".keys[", vm.toString(r), "].");
                bytes memory pk = vm.parseJsonBytes(j, string.concat(row, "pk"));
                assertEq(
                    sha256(v.expandedKey(pk)), vm.parseJsonBytes32(j, string.concat(row, "ek_sha256")), "expanded key"
                );
                bytes32[] memory ps = vm.parseJsonBytes32Array(j, string.concat(row, "parts_sha256"));
                assertEq(ps.length, v.expandedKeyParts(), "parts");
                for (uint256 p; p < ps.length; ++p) {
                    assertEq(sha256(v.expandedKeyPart(pk, p)), ps[p], "part");
                }
                ++n;
            }
        }
        assertEq(n, 36, "12 keys per level");
    }

    /// F-9: NIST ACVP ML-DSA sigVer (`pq_external.json`, 30 cases per level, tgId 5 pure and tgId 12 internal) through both paths
    /// with ACVP's verdict: the FIPS-key core and the cached path (each key's parts at pointers as SSTORE2 writes them, read by
    /// `MlDsa.readParts` as `verifyCached` reads them, `CachedM`). `verifyCached` itself formats the UA's 32-byte message, so it
    /// cannot take ACVP's M'; the UA rows and their mutations run through it (`test_mldsa87_withoutPrecompile`,
    /// `test_mutations_bothPaths`).
    function test_acvp_mldsa_cachedDifferential() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        CachedM c = new CachedM();
        MldsaVerifier[3] memory v = [
            new MldsaVerifier(PqUA.MLDSA44, address(0), "", ""),
            new MldsaVerifier(PqUA.MLDSA65, address(0), "", ""),
            new MldsaVerifier(PqUA.MLDSA87, address(0), "", "")
        ];
        uint256[3] memory per;
        for (uint256 i; i < _cases(ext, "acvp_mldsa"); ++i) {
            ++per[_acvpBoth(ext, i, h, c, v)];
        }
        assertEq(per[0], 30);
        assertEq(per[1], 30);
        assertEq(per[2], 30, "ML-DSA-87 cases");
    }

    /// One ACVP case through both paths (`test_acvp_mldsa_cachedDifferential`); returns its level index.
    function _acvpBoth(string memory ext, uint256 i, MlHarness h, CachedM c, MldsaVerifier[3] memory v)
        internal
        returns (uint256 li)
    {
        string memory cs = _case("acvp_mldsa", i);
        bytes32 set = keccak256(bytes(vm.parseJsonString(ext, string.concat(cs, ".set"))));
        li = set == keccak256("ML-DSA-44") ? 0 : set == keccak256("ML-DSA-65") ? 1 : 2;
        uint256 level = li == 0 ? 44 : li == 1 ? 65 : 87;
        bytes memory pk = _b(ext, string.concat(cs, ".pk"));
        bytes memory mp = _b(ext, string.concat(cs, ".mprime"));
        bytes memory sig = _b(ext, string.concat(cs, ".sig"));
        bool want = vm.parseJsonBool(ext, string.concat(cs, ".valid"));
        assertEq(h.verify(level, pk, mp, sig), want, "FIPS-key path");
        (bytes memory chunks,) = _parts(v[li], pk, 0xacc000 + i);
        assertEq(c.verify(level, chunks, mp, sig), want, "cached path (ACVP verdict)");
    }

    /// F-9: every `pq_kat.json` mutation of the three levels, and the UA row, through `verify` (FIPS key) and `verifyCached` (the
    /// real function on the parts of its own key): the same verdict.
    function test_mutations_bothPaths() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        string[3] memory names = ["mldsa44", "mldsa65", "mldsa87"];
        uint16[3] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65, PqUA.MLDSA87];
        uint256 n;
        for (uint256 i; i < 3; ++i) {
            MldsaVerifier v = new MldsaVerifier(kinds[i], address(0), "", "");
            for (
                uint256 m;
                vm.keyExistsJson(kat, string.concat(".kinds.", names[i], ".mutations[", vm.toString(m), "]"));
                ++m
            ) {
                if (_mutationBoth(
                        kat,
                        v,
                        string.concat(".kinds.", names[i], ".mutations[", vm.toString(m), "]"),
                        0xbee000 + 64 * i + m
                    )) ++n;
            }
        }
        assertGt(n, 18, "mutations through both paths");
    }

    /// One mutation `mu` through `verify` and `verifyCached` on its own key's parts; false for a key of another length (no parts).
    function _mutationBoth(string memory kat, MldsaVerifier v, string memory mu, uint256 at) internal returns (bool) {
        bytes memory pk = _b(kat, string.concat(mu, ".pk"));
        if (pk.length != (v.KIND() == PqUA.MLDSA44 ? 1312 : v.KIND() == PqUA.MLDSA65 ? 1952 : 2592)) return false;
        bytes32 msg_ = bytes32(_b(kat, string.concat(mu, ".ua_msg")));
        bytes memory sig = _b(kat, string.concat(mu, ".sig"));
        bool want = vm.parseJsonBool(kat, string.concat(mu, ".valid"));
        (bytes memory chunks,) = _parts(v, pk, at);
        assertEq(v.verify(pk, msg_, sig), want, "FIPS-key path");
        assertEq(v.verifyCached(chunks, msg_, sig), want, vm.parseJsonString(kat, string.concat(mu, ".what")));
        return true;
    }

    /// The precompile path checks the lengths before calling; the probe needs this level's exact split and a non-reverting
    /// answer.
    function test_probe_lengthsAndReverts() public {
        vm.pauseGasMetering();
        string memory kat = _kat();
        address pc = address(0x12);
        bytes memory valid44 = _k(kat, "mldsa44", "eip8355_probe_valid");
        bytes memory invalid44 = _k(kat, "mldsa44", "eip8355_probe_invalid");
        vm.etch(pc, address(new Eip8355Emulator()).code); // answers both levels
        MldsaVerifier v = new MldsaVerifier(PqUA.MLDSA44, pc, valid44, invalid44);
        assertEq(v.PRECOMPILE(), pc);
        assertEq(
            new MldsaVerifier(
                    PqUA.MLDSA44,
                    pc,
                    _k(kat, "mldsa65", "eip8355_probe_valid"),
                    _k(kat, "mldsa65", "eip8355_probe_invalid")
                )
                .PRECOMPILE(),
            address(0),
            "65 probe on the 44 verifier"
        );
        vm.etch(pc, address(new AlwaysOne()).code); // now any call would answer 1
        bytes memory pk = _k(kat, "mldsa44", "pk");
        bytes memory sig = _k(kat, "mldsa44", "sig");
        bytes32 m = bytes32(_k(kat, "mldsa44", "ua_msg"));
        assertFalse(v.verify(bytes.concat(pk, hex"00"), m, sig), "pk length");
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")), "sig length");
        vm.etch(pc, address(new RevertsOnInvalid()).code);
        assertEq(new MldsaVerifier(PqUA.MLDSA44, pc, valid44, invalid44).PRECOMPILE(), address(0), "reverts on invalid");
    }

    /// The degenerate expanded key `Â = 0`, `t̂1 = 0` with the vector's `tr` (level 44 for i = 0, else 65): it accepts
    /// any z for a c~ built from the hints alone, which is why an expanded key is never taken from a caller.
    function _degenerateKey(uint256 i) internal view returns (MlDsa.Params memory P, bytes memory ek, bytes memory tr) {
        P = i == 0 ? MlDsa.params44() : MlDsa.params65();
        uint256 o = P.k * P.l * 1024;
        ek = new bytes(MlDsa.expandedLen(P));
        tr = _slice(_k(_kat(), i == 0 ? "mldsa44" : "mldsa65", "expanded_key"), o, 64);
        for (uint256 b; b < 64; ++b) {
            ek[o + b] = tr[b];
        }
    }

    /// Hint encoding: rows 0 .. k−2 hold indices 0 .. x−1 (x = ⌈ω/2⌉), the last row 2x − ω … x − 1 and ends at `end`.
    function _hintsUpTo(MlDsa.Params memory P, uint256 end) internal pure returns (bytes memory y) {
        uint256 x = (P.omega + 1) / 2;
        y = new bytes(P.omega + P.k);
        for (uint256 j; j < x; ++j) {
            y[j] = bytes1(uint8(j));
        }
        for (uint256 j = x; j < P.omega; ++j) {
            y[j] = bytes1(uint8(j + x - P.omega));
        }
        for (uint256 r; r + 1 < P.k; ++r) {
            y[P.omega + r] = bytes1(uint8(x));
        }
        y[P.omega + P.k - 1] = bytes1(uint8(end));
    }

    /// A signature for the degenerate expanded key (`Â = 0`, `t̂1 = 0`): w' = 0, so UseHint gives m − 1 at each hint
    /// position of `y` and 0 elsewhere; c~ = H(H(tr ‖ M') ‖ w1Encode(w1)), z = 0 (v = γ1 everywhere), hints `y`.
    function _degenerate(MlHarness h, MlDsa.Params memory P, bytes memory tr, bytes memory mprime, bytes memory y)
        internal
        pure
        returns (bytes memory sig)
    {
        uint256 m1 = (MlDsa.Q - 1) / (2 * P.gamma2) - 1;
        bytes memory w1 = new bytes(P.k * 32 * P.w1Bits);
        uint256 idx;
        for (uint256 r; r < P.k; ++r) {
            for (; idx < uint8(y[P.omega + r]); ++idx) {
                _putLe(w1, (r * 256 + uint8(y[idx])) * P.w1Bits, P.w1Bits, m1);
            }
        }
        bytes memory ct = h.shake256(bytes.concat(h.shake256(bytes.concat(tr, mprime), 64), w1), P.ctLen);
        bytes memory z = new bytes(P.l * 32 * P.zBits);
        for (uint256 c; c < P.l * 256; ++c) {
            _putLe(z, c * P.zBits, P.zBits, P.gamma1);
        }
        sig = bytes.concat(ct, z, y);
    }

    /// Re-encodes the first z coefficient as `v` (z_0 = γ1 − v).
    function _setZ0(MlDsa.Params memory P, bytes memory sig, uint256 v) internal pure {
        bytes memory z = _slice(sig, P.ctLen, 3);
        _putLe(z, 0, P.zBits, v);
        for (uint256 b; b < 3; ++b) {
            sig[P.ctLen + b] = z[b];
        }
    }

    /// Writes the `n`-bit value `v` at bit position `p`, least significant bit first.
    function _putLe(bytes memory b, uint256 p, uint256 n, uint256 v) internal pure {
        for (uint256 i; i < n; ++i) {
            uint256 bit = p + i;
            uint8 mask = uint8(2 ** (bit % 8));
            uint8 cur = uint8(b[bit / 8]) & ~mask;
            b[bit / 8] = bytes1((v >> i) & 1 == 1 ? cur | mask : cur);
        }
    }

    function _u32(bytes memory b, uint256 o) internal pure returns (uint256) {
        return
            uint256(uint8(b[o])) << 24 | uint256(uint8(b[o + 1])) << 16 | uint256(uint8(b[o + 2])) << 8
                | uint8(b[o + 3]);
    }

    function _setU32(bytes memory b, uint256 o, uint256 v) internal pure {
        for (uint256 i; i < 4; ++i) {
            b[o + i] = bytes1(uint8(v >> (24 - 8 * i)));
        }
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory s) {
        s = new bytes(len);
        for (uint256 i; i < len; ++i) {
            s[i] = b[off + i];
        }
    }
}
