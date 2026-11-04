// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// ML-DSA-87 probe (2026-11-04, research; spec docs/superpowers/specs/2026-11-04-mldsa87.md, note
// docs/research/mldsa87-evm-gas.md). The built ML-DSA code paths at ML-DSA-87 (`MlDsa87.sol`), checked against the 30
// NIST ACVP ML-DSA-87 sigVer cases (acvp87.json, extract.py) and one UA-shaped row (ua87.json, noble87.mjs), with the gas
// of: verify on the FIPS 204 key, verify on the expanded key, each expanded-key part as the registry's
// `cacheExpandedKey` stores it (regular and EIP-8037 state gas), `verifyCached` and its least working cap. The same cache
// harness runs at ML-DSA-65 (pq_kat.json) to compare with the registry's own figures.
//   cd smartcontracts/evm && FOUNDRY_CONFIG=runs/2026-11-04-mldsa87-probe/foundry.toml forge test -vv
import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {Mldsa87Probe} from "./MlDsa87.sol";

interface IParts {
    function expandedKeyPart(bytes calldata pk, uint256 part) external view returns (bytes memory);
}

/// The registry's `cacheExpandedKey` minus its kind / config checks (UARegistryLib): the id, the stored-part check, the
/// verifier's `expandedKeyPart`, SSTORE2, the pointer slot, the event.
contract CacheHarness {
    mapping(bytes32 => address[3]) public ekPtr;

    event UAKeyCached(bytes32 indexed ua, uint16 indexed kind, uint256 part, address ptr);

    function cache(address v, uint16 kind, bytes32 tag, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        ua = keccak256(abi.encodePacked(tag, pk));
        if (ekPtr[ua][part] != address(0)) return ua;
        address ptr = SSTORE2.write(IParts(v).expandedKeyPart(pk, part));
        ekPtr[ua][part] = ptr;
        emit UAKeyCached(ua, kind, part, ptr);
    }
}

contract Mldsa87ProbeTest is Test {
    string constant DIR = "runs/2026-11-04-mldsa87-probe/";
    uint256 constant BUDGET = 12_000_000; // UA_VERIFY_BUDGET on EIP-7825 chains (Hedera 10,500,000)
    uint256 constant TX_CAP = 1 << 24; // EIP-7825

    Mldsa87Probe v;

    function setUp() public {
        v = new Mldsa87Probe();
    }

    function _gas(address to, bytes memory call) internal view returns (uint256 used, bool verdict) {
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = to.staticcall(call);
        used = g - gasleft();
        require(ok, "call failed");
        verdict = abi.decode(ret, (bool));
    }

    /// Every ACVP case on both key forms gives ACVP's verdict; the gas of the valid ones (long messages: μ's SHAKE256
    /// absorbs |M'| bytes, ~one permutation per 136 B, so these are above the UA row's 34-byte M').
    function test_acvp87() public {
        string memory j = vm.readFile(string.concat(DIR, "acvp87.json"));
        for (uint256 i; i < 30; ++i) {
            string memory c = string.concat(".cases[", vm.toString(i), "].");
            bytes memory pk = vm.parseJsonBytes(j, string.concat(c, "pk"));
            bytes memory mp = vm.parseJsonBytes(j, string.concat(c, "mprime"));
            bytes memory sig = vm.parseJsonBytes(j, string.concat(c, "sig"));
            bool valid = vm.parseJsonBool(j, string.concat(c, "valid"));
            uint256 tc = vm.parseJsonUint(j, string.concat(c, "tc"));
            (uint256 raw, bool r1) = _gas(address(v), abi.encodeCall(v.verifyMPrime, (pk, mp, sig)));
            bytes memory ek = v.expandedKey(pk);
            (uint256 exp, bool r2) = _gas(address(v), abi.encodeCall(v.verifyExpandedMPrime, (ek, mp, sig)));
            assertEq(r1, valid, string.concat("FIPS 204 key, tc ", vm.toString(tc)));
            assertEq(r2, valid, string.concat("expanded key, tc ", vm.toString(tc)));
            console2.log(string.concat("tc ", vm.toString(tc), valid ? " valid" : " invalid", " |M'| ", vm.toString(mp.length),
                " raw ", vm.toString(raw), " expanded ", vm.toString(exp)));
        }
    }

    function test_ua87() public {
        string memory j = vm.readFile(string.concat(DIR, "ua87.json"));
        bytes memory pk = vm.parseJsonBytes(j, ".pk");
        bytes32 m = bytes32(vm.parseJsonBytes(j, ".ua_msg"));
        bytes memory sig = vm.parseJsonBytes(j, ".sig");
        assertEq(bytes32(vm.parseJsonBytes(j, ".tag_hash")), v.KIND_TAG());
        assertEq(keccak256(abi.encodePacked(v.KIND_TAG(), m)), bytes32(vm.parseJsonBytes(j, ".signed_message")));

        (uint256 raw, bool ok) = _gas(address(v), abi.encodeCall(v.verify, (pk, m, sig)));
        assertTrue(ok, "raw");
        bytes memory ek = v.expandedKey(pk);
        assertEq(ek.length, 65_600, "expanded key = (k*l + k) * 1024 + 64");
        (uint256 exp, bool ok2) = _gas(address(v), abi.encodeCall(v.verifyExpanded, (ek, m, sig)));
        assertTrue(ok2, "expanded");
        console2.log("mldsa87 verify (valid, FIPS 204 key)", raw);
        console2.log("mldsa87 verify (valid, expanded key in calldata)", exp);
        for (uint256 i; i < 3; ++i) {
            string memory c = string.concat(".mutations[", vm.toString(i), "].");
            bytes memory bad = vm.parseJsonBytes(j, string.concat(c, "sig"));
            assertEq(v.verify(pk, m, bad), vm.parseJsonBool(j, string.concat(c, "valid")), "mutation raw");
            assertEq(v.verifyExpanded(ek, m, bad), vm.parseJsonBool(j, string.concat(c, "valid")), "mutation expanded");
        }

        bytes memory chunks = _cacheParts(pk, ek);
        (uint256 cached, bool ok3) = _gas(address(v), abi.encodeCall(v.verifyCached, (chunks, m, sig)));
        assertTrue(ok3, "cached");
        console2.log("mldsa87 verifyCached (valid)", cached);
        console2.log("mldsa87 verifyCached least working gas (cold pointers, +-1000)", _leastCap(chunks, m, sig, cached));
        console2.log("  budget 12,000,000; 66 % bound", BUDGET * 66 / 100);
    }

    /// The cache: one isolated transaction per part; returns the parts' pointers in order.
    function _cacheParts(bytes memory pk, bytes memory ek) internal returns (bytes memory chunks) {
        CacheHarness h = new CacheHarness();
        bytes32 ua = keccak256(abi.encodePacked(v.KIND_TAG(), pk));
        bytes memory joined;
        for (uint256 p; p < 3; ++p) {
            uint256 g = gasleft();
            bytes memory part = v.expandedKeyPart(pk, p);
            g -= gasleft();
            joined = bytes.concat(joined, part);
            h.cache(address(v), 0x0134, v.KIND_TAG(), pk, p);
            Vm.Gas memory vg = vm.lastCallGas();
            string memory n = string.concat("mldsa87 part ", vm.toString(p));
            console2.log(string.concat(n, " bytes"), part.length);
            console2.log(string.concat(n, " expandedKeyPart gas"), g);
            console2.log(string.concat(n, " cache tx gasTotalUsed"), vg.gasTotalUsed);
            console2.log(string.concat(n, " cache tx state gas (EIP-8037)"), uint256(int256(vg.gasStateUsed)));
            assertLt(part.length + 1, 24_577, "under EIP-170");
            chunks = bytes.concat(chunks, bytes20(h.ekPtr(ua, p)));
        }
        assertEq(keccak256(joined), keccak256(ek), "parts concatenate to the expanded key");
    }

    /// Least gas at which verifyCached still verifies, cold pointers (as PqGas.t.sol), +-1000.
    function _leastCap(bytes memory chunks, bytes32 m, bytes memory sig, uint256 cached) internal returns (uint256 hi) {
        uint256 lo = cached / 2;
        hi = 2 * cached;
        while (hi - lo > 1000) {
            uint256 mid = (lo + hi) / 2;
            for (uint256 q; q < 3; ++q) {
                vm.cool(address(this.slice20(chunks, q)));
            }
            try v.verifyCached{gas: mid}(chunks, m, sig) returns (bool r) {
                if (r) hi = mid;
                else lo = mid;
            } catch {
                lo = mid;
            }
        }
    }

    function slice20(bytes calldata b, uint256 i) external pure returns (bytes20) {
        return bytes20(b[20 * i:20 * i + 20]);
    }

    /// Calibration: the same harness at ML-DSA-65 with the built verifier (two parts), beside the registry's figures.
    function test_calibrate65() public {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes memory pk = vm.parseJsonBytes(kat, ".kinds.mldsa65.pk");
        UAMldsaVerifier v65 = new UAMldsaVerifier(PqUA.MLDSA65, address(0), "", "");
        CacheHarness h = new CacheHarness();
        for (uint256 p; p < 2; ++p) {
            h.cache(address(v65), PqUA.MLDSA65, PqUA.tag(PqUA.MLDSA65), pk, p);
            Vm.Gas memory vg = vm.lastCallGas();
            console2.log(string.concat("mldsa65 part ", vm.toString(p), " cache tx gasTotalUsed"), vg.gasTotalUsed);
            console2.log(string.concat("mldsa65 part ", vm.toString(p), " cache tx state gas (EIP-8037)"), uint256(int256(vg.gasStateUsed)));
        }
        bytes32 m = bytes32(vm.parseJsonBytes(kat, ".kinds.mldsa65.ua_msg"));
        bytes memory sig = vm.parseJsonBytes(kat, ".kinds.mldsa65.sig");
        (uint256 raw, bool ok) = _gas(address(v65), abi.encodeCall(v65.verify, (pk, m, sig)));
        assertTrue(ok);
        console2.log("mldsa65 verify (valid, FIPS 204 key), same toolchain", raw);
    }
}
