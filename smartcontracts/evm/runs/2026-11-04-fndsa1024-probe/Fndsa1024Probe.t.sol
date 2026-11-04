// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// Falcon-1024 probe (2026-11-04, research; spec docs/superpowers/specs/2026-11-04-fndsa1024.md, note
// docs/research/fndsa1024-evm-gas.md). The built Falcon-512 code paths at Falcon-1024 (`Falcon1024.sol`), checked against
// NIST round-3 Falcon-1024 KATs rebuilt as padded signatures (kat1024.json, extract.py) and one UA-shaped row
// (ua1024.json, noble1024.mjs), with the gas of: verify on the round-3 key, verify on the cached NTT key, the least working
// gas of each, the KAT messages, and the built `fndsa512` verifier in the same run for comparison.
//   cd smartcontracts/evm && FOUNDRY_CONFIG=runs/2026-11-04-fndsa1024-probe/foundry.toml forge test -vv
import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {PqVectors} from "../../test/ua/PqVectors.sol";
import {Falcon1024, Fndsa1024Probe} from "./Falcon1024.sol";

contract NttCache {
    function store(bytes calldata hHat) external returns (address) {
        return SSTORE2.write(hHat);
    }
}

contract Fndsa1024ProbeTest is PqVectors {
    string constant DIR = "runs/2026-11-04-fndsa1024-probe/";
    uint256 constant BUDGET = 12_000_000; // UA_VERIFY_BUDGET on EIP-7825 chains
    uint256 constant BUDGET_HEDERA = 10_500_000;

    Fndsa1024Probe v;

    function setUp() public {
        v = new Fndsa1024Probe();
    }

    function _gas(bytes memory call) internal view returns (uint256 used, bool verdict) {
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(v).staticcall(call);
        used = g - gasleft();
        require(ok, "call failed");
        verdict = abi.decode(ret, (bool));
    }

    /// Least call gas at which `call` still returns true, +-1000 (as the ML-DSA-87 probe's `_leastCap`).
    function _least(bytes memory call, uint256 used) internal view returns (uint256 hi) {
        uint256 lo = used / 2;
        hi = 2 * used;
        while (hi - lo > 1000) {
            uint256 mid = (lo + hi) / 2;
            (bool ok, bytes memory ret) = address(v).staticcall{gas: mid}(call);
            if (ok && abi.decode(ret, (bool))) hi = mid;
            else lo = mid;
        }
    }

    function test_zetaTable_falcon1024() public pure {
        _zetas(Falcon1024.ZETAS, 2, 1024, 12289, 1945);
    }

    /// Every kept NIST KAT verifies on both key forms; a set padding bit, the NIST (unpadded) header 0x2A, the Falcon-512
    /// header 0x39, a 1,281-byte signature and a pk with header 0x09 are refused.
    function test_kat1024() public {
        string memory j = vm.readFile(string.concat(DIR, "kat1024.json"));
        for (uint256 i; i < 10; ++i) {
            string memory c = string.concat(".cases[", vm.toString(i), "].");
            bytes memory pk = vm.parseJsonBytes(j, string.concat(c, "pk"));
            bytes memory m = vm.parseJsonBytes(j, string.concat(c, "msg"));
            bytes memory sig = vm.parseJsonBytes(j, string.concat(c, "sig"));
            uint256 count = vm.parseJsonUint(j, string.concat(c, "count"));
            bytes memory hHat = v.nttKey(pk);
            (uint256 raw, bool r1) = _gas(abi.encodeCall(v.verifyMsg, (pk, m, sig)));
            (uint256 ntt, bool r2) = _gas(abi.encodeCall(v.verifyNttMsg, (hHat, m, sig)));
            assertTrue(r1 && r2, string.concat("KAT count ", vm.toString(count)));
            console2.log(string.concat("KAT count ", vm.toString(count), " |msg| ", vm.toString(m.length), " raw ",
                vm.toString(raw), " ntt-key ", vm.toString(ntt)));
            bytes memory bad = bytes.concat(sig);
            bad[1279] = 0x01; // non-zero padding
            assertFalse(v.verifyMsg(pk, m, bad), "padding");
            bad = bytes.concat(sig);
            bad[0] = 0x2a;
            assertFalse(v.verifyMsg(pk, m, bad), "NIST header");
            bad[0] = 0x39;
            assertFalse(v.verifyMsg(pk, m, bad), "Falcon-512 header");
            assertFalse(v.verifyMsg(pk, m, bytes.concat(sig, hex"00")), "1,281 bytes");
            bad = bytes.concat(pk);
            bad[0] = 0x09;
            assertFalse(v.verifyMsg(bad, m, sig), "pk header 0x09");
            m[0] = m[0] ^ bytes1(0x01);
            assertFalse(v.verifyMsg(pk, m, sig), "message flip");
        }
    }

    function test_ua1024() public {
        string memory j = vm.readFile(string.concat(DIR, "ua1024.json"));
        bytes memory pk = vm.parseJsonBytes(j, ".pk");
        bytes32 m = bytes32(vm.parseJsonBytes(j, ".ua_msg"));
        bytes memory sig = vm.parseJsonBytes(j, ".sig");
        assertEq(bytes32(vm.parseJsonBytes(j, ".tag_hash")), keccak256("scaas.ua.fndsa1024.v1"));
        assertEq(keccak256(abi.encodePacked(keccak256("scaas.ua.fndsa1024.v1"), pk)), bytes32(vm.parseJsonBytes(j, ".ua")));

        bytes memory callRaw = abi.encodeCall(v.verify, (pk, m, sig));
        (uint256 raw, bool ok) = _gas(callRaw);
        assertTrue(ok, "raw");
        bytes memory hHat = v.nttKey(pk);
        assertEq(hHat.length, 2048);
        bytes memory callNtt = abi.encodeCall(v.verifyNtt, (hHat, m, sig));
        (uint256 ntt, bool ok2) = _gas(callNtt);
        assertTrue(ok2, "ntt key");
        console2.log("fndsa1024 verify (valid, round-3 key)", raw);
        console2.log("fndsa1024 verify least working gas (round-3 key, +-1000)", _least(callRaw, raw));
        console2.log("fndsa1024 verify (valid, NTT key in calldata)", ntt);
        console2.log("fndsa1024 verify least working gas (NTT key, +-1000)", _least(callNtt, ntt));
        _mutations(j, hHat);
        _cacheAndReference(hHat);
    }

    function _mutations(string memory j, bytes memory hHat) internal view {
        for (uint256 i; i < 6; ++i) {
            string memory c = string.concat(".mutations[", vm.toString(i), "].");
            bytes memory bad = vm.parseJsonBytes(j, string.concat(c, "sig"));
            bytes32 mm = bytes32(vm.parseJsonBytes(j, string.concat(c, "ua_msg")));
            bool want = vm.parseJsonBool(j, string.concat(c, "valid"));
            assertEq(v.verify(vm.parseJsonBytes(j, string.concat(c, "pk")), mm, bad), want, "mutation, round-3 key");
            if (i != 4) assertEq(v.verifyNtt(hHat, mm, bad), want, "mutation, NTT key");
        }
    }

    function _cacheAndReference(bytes memory hHat) internal {
        NttCache cache = new NttCache();
        cache.store(hHat);
        Vm.Gas memory vg = vm.lastCallGas();
        console2.log("NTT key SSTORE2 write (2,048 B) gasTotalUsed", vg.gasTotalUsed);
        console2.log("NTT key SSTORE2 write state gas (EIP-8037)", uint256(int256(vg.gasStateUsed)));

        string memory kat = _kat();
        UAFndsaVerifier f512 = new UAFndsaVerifier();
        bytes memory call512 = abi.encodeCall(f512.verify, (_k(kat, "fndsa512", "pk"), bytes32(_k(kat, "fndsa512", "ua_msg")),
            _k(kat, "fndsa512", "sig")));
        uint256 g = gasleft();
        (bool ok3, bytes memory ret) = address(f512).staticcall(call512);
        g -= gasleft();
        assertTrue(ok3 && abi.decode(ret, (bool)), "fndsa512 reference");
        console2.log("reference: fndsa512 verify (valid, built UAFndsaVerifier), same run", g);
        console2.log("66 % of 12,000,000 / of 10,500,000", BUDGET * 66 / 100, BUDGET_HEDERA * 66 / 100);
    }

    /// `|s2_i| ≤ 2047`: 2047 decodes, 2048 does not (1,024 coefficients in 1,239 bytes).
    function test_decode_s2Bound1024() public view {
        assertTrue(v.decompress(_comp(2047)));
        assertFalse(v.decompress(_comp(2048)));
    }

    function _comp(uint256 v0) internal pure returns (bytes memory c) {
        c = new bytes(1239);
        uint256 p;
        for (uint256 i; i < 1024; ++i) {
            uint256 x = i == 0 ? v0 : 0;
            _set(c, p, 8, x & 127);
            p += 8 + (x >> 7);
            _set(c, p, 1, 1);
            ++p;
        }
    }

    function _set(bytes memory b, uint256 p, uint256 n, uint256 x) internal pure {
        for (uint256 i; i < n; ++i) {
            uint256 bit = p + i;
            uint8 mask = uint8(128 / 2 ** (bit % 8));
            uint8 cur = uint8(b[bit / 8]) & ~mask;
            b[bit / 8] = bytes1((x >> (n - 1 - i)) & 1 == 1 ? cur | mask : cur);
        }
    }
}
