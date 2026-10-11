// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqVectors} from "./PqVectors.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {Shake} from "../../src/ua/Shake.sol";
import {MlDsa, UAMldsaVerifier} from "../../src/ua/MlDsa.sol";

contract MlHarness {
    function verify(uint256 level, bytes calldata pk, bytes calldata mprime, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return MlDsa.verify(level == 44 ? MlDsa.params44() : MlDsa.params65(), pk, mprime, sig);
    }

    function verifyExpanded(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig)
        external pure returns (bool)
    {
        Shake.reserve();
        return MlDsa.verifyExpanded(level == 44 ? MlDsa.params44() : MlDsa.params65(), ek, mprime, sig);
    }
}

/// An EIP-8355 precompile stand-in: `pk ‖ sig ‖ msg` ⇒ the 32-byte word 0 or 1, ML-DSA-44 or -65 by length.
contract Eip8355Emulator {
    fallback(bytes calldata input) external returns (bytes memory) {
        Shake.reserve();
        bool ok;
        if (input.length >= 3732 && input.length < 5261) {
            ok = MlDsa.verify(MlDsa.params44(), input[0:1312], abi.encodePacked(bytes2(0), input[3732:]), input[1312:3732]);
        } else if (input.length >= 5261) {
            ok = MlDsa.verify(MlDsa.params65(), input[0:1952], abi.encodePacked(bytes2(0), input[5261:]), input[1952:5261]);
        }
        return abi.encode(ok ? 1 : 0);
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
        _uaVector("mldsa44", address(new UAMldsaVerifier(PqUA.MLDSA44, address(0), "", "")), PqUA.MLDSA44);
    }

    function test_kat_mldsa65() public {
        _uaVector("mldsa65", address(new UAMldsaVerifier(PqUA.MLDSA65, address(0), "", "")), PqUA.MLDSA65);
    }

    /// The EIP-8051 expanded key: Solidity and clientkeys produce the same bytes, and it verifies the same signature.
    function test_expandedKey() public {
        string memory kat = _kat();
        MlHarness h = new MlHarness();
        string[2] memory names = ["mldsa44", "mldsa65"];
        uint16[2] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65];
        for (uint256 i; i < 2; ++i) {
            uint256 level = i == 0 ? 44 : 65;
            bytes memory ek = new UAMldsaVerifier(kinds[i], address(0), "", "").expandedKey(_k(kat, names[i], "pk"));
            assertEq(ek, _k(kat, names[i], "expanded_key"), names[i]);
            bytes memory mprime = abi.encodePacked(bytes2(0), _k(kat, names[i], "signed_message"));
            bytes memory sig = _k(kat, names[i], "sig");
            assertTrue(h.verifyExpanded(level, ek, mprime, sig));
            sig[5] ^= 0x01;
            assertFalse(h.verifyExpanded(level, ek, mprime, sig));
            sig[5] ^= 0x01;
            ek[3] = 0xff; // first Â coefficient ≥ q: refused, not reduced
            assertFalse(h.verifyExpanded(level, ek, mprime, sig));
        }
    }

    function test_acvp_mldsa() public {
        vm.pauseGasMetering(); // 60 full verifications: correctness only
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        uint256 n = _cases(ext, "acvp_mldsa");
        assertEq(n, 60);
        for (uint256 i; i < n; ++i) {
            string memory c = _case("acvp_mldsa", i);
            uint256 level = keccak256(bytes(vm.parseJsonString(ext, string.concat(c, ".set")))) == keccak256("ML-DSA-44") ? 44 : 65;
            bool got = h.verify(level, _b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")),
                _b(ext, string.concat(c, ".sig")));
            assertEq(got, vm.parseJsonBool(ext, string.concat(c, ".valid")), vm.parseJsonString(ext, string.concat(c, ".reason")));
        }
    }

    function test_eip8051_nistKat() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        assertEq(_cases(ext, "eip8051_nist_kat"), 10);
        for (uint256 i; i < 10; ++i) {
            string memory c = _case("eip8051_nist_kat", i);
            assertTrue(h.verify(44, _b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")), _b(ext, string.concat(c, ".sig"))));
        }
    }

    function test_eip8355_cases() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        MlHarness h = new MlHarness();
        for (uint256 i; i < 2; ++i) { // cases 1 and 2; case 3 (too short to parse) runs in the probe test
            string memory c = _case("eip8355", i);
            bool got = h.verify(44, _b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")), _b(ext, string.concat(c, ".sig")));
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
            assertEq(new UAMldsaVerifier(kinds[i], pc, valid, invalid).PRECOMPILE(), address(0));
            vm.etch(pc, address(new AlwaysOne()).code); // answers 1 to everything: refused
            assertEq(new UAMldsaVerifier(kinds[i], pc, valid, invalid).PRECOMPILE(), address(0));
            vm.etch(pc, address(new Eip8355Emulator()).code);
            UAMldsaVerifier v = new UAMldsaVerifier(kinds[i], pc, valid, invalid);
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
        vm.expectRevert(abi.encodeWithSelector(UAMldsaVerifier.UAMldsaKind.selector, PqUA.FNDSA512));
        new UAMldsaVerifier(PqUA.FNDSA512, address(0), "", "");
    }

    function test_malformed_mldsa() public {
        string memory kat = _kat();
        UAMldsaVerifier v = new UAMldsaVerifier(PqUA.MLDSA44, address(0), "", "");
        bytes memory pk = _k(kat, "mldsa44", "pk");
        bytes memory sig = _k(kat, "mldsa44", "sig");
        bytes32 m = bytes32(_k(kat, "mldsa44", "ua_msg"));
        assertFalse(v.verify(_k(kat, "mldsa65", "pk"), m, sig)); // a 65 key on the 44 verifier
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
        sig[2420 - 4] = 0x51; // hint count of row 0 above ω = 80
        assertFalse(v.verify(pk, m, sig));
    }
}
