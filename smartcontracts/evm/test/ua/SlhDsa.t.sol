// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqVectors} from "./PqVectors.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {SlhDsaSha2128s, UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";

contract SlhHarness {
    function verify(bytes calldata pk, bytes calldata mprime, bytes calldata sig) external view returns (bool) {
        return SlhDsaSha2128s.verify(pk, mprime, sig);
    }
}

/// `slhdsa128s` (CTR-UA-23): ACVP SLH-DSA-SHA2-128s sigVer (pure and internal interfaces) and the SCaaS UA vector.
contract SlhDsaTest is PqVectors {
    function test_kat_slhdsa128s() public {
        _uaVector("slhdsa128s", address(new UASlhdsaVerifier()), PqUA.SLHDSA128S);
    }

    function test_acvp_slhdsa() public {
        vm.pauseGasMetering(); // 28 full verifications: correctness only (gas is PqGasTest's)
        string memory ext = _ext();
        SlhHarness h = new SlhHarness();
        uint256 n = _cases(ext, "acvp_slhdsa");
        assertEq(n, 28);
        for (uint256 i; i < n; ++i) {
            string memory c = _case("acvp_slhdsa", i);
            bool got = h.verify(_b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")), _b(ext, string.concat(c, ".sig")));
            assertEq(got, vm.parseJsonBool(ext, string.concat(c, ".valid")), vm.parseJsonString(ext, string.concat(c, ".reason")));
        }
    }

    function test_malformed_slhdsa() public {
        string memory kat = _kat();
        UASlhdsaVerifier v = new UASlhdsaVerifier();
        bytes memory pk = _k(kat, "slhdsa128s", "pk");
        bytes memory sig = _k(kat, "slhdsa128s", "sig");
        bytes32 m = bytes32(_k(kat, "slhdsa128s", "ua_msg"));
        assertTrue(v.verify(pk, m, sig));
        assertFalse(v.verify(bytes.concat(pk, hex"00"), m, sig));
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
        assertFalse(v.verify(pk, m, ""));
    }
}
