// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SlhDsaSha2128s, SlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {Shake} from "../../src/ua/Shake.sol";
import {FndsaVerifier} from "../../src/ua/FnDsa.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {MlDsa, MldsaVerifier} from "../../src/ua/MlDsa.sol";

/// SLH-DSA with every hypertree layer's WOTS+ message forced to 0: 510 chain steps per layer, the most work any input
/// can force (a valid signature reaching it needs seven 2^-128 events). Same code as `verify` otherwise.
contract SlhWorstCase {
    function run(bytes calldata pk, bytes calldata mprime, bytes calldata sig) external view returns (uint256 node) {
        bytes32 seed = bytes32(pk[0:16]);
        bytes32 inner = sha256(abi.encodePacked(bytes16(sig[0:16]), bytes16(seed), bytes16(pk[16:32]), mprime));
        uint256 dg = uint256(sha256(abi.encodePacked(bytes16(sig[0:16]), bytes16(seed), inner, uint32(0))));
        uint256 idxTree = (dg >> 32) & ((1 << 54) - 1);
        uint256 idxLeaf = (dg >> 16) & 0x1ff;
        uint256 b = SlhDsaSha2128s.buf(seed, 160);
        uint256 t = SlhDsaSha2128s.buf(seed, 704);
        node = SlhDsaSha2128s.forsPk(sig, dg >> 88, idxTree, idxLeaf, b, t);
        for (uint256 j; j < 7; ++j) {
            if (j != 0) {
                idxLeaf = idxTree & 0x1ff;
                idxTree >>= 9;
            }
            node = SlhDsaSha2128s.xmssPk(
                sig, SlhDsaSha2128s.HT_OFF + j * SlhDsaSha2128s.XMSS_LEN, 0, j, idxTree, idxLeaf, b, t
            );
        }
    }
}

contract Permuter {
    function run(uint256 n) external pure {
        Shake.reserve();
        for (uint256 i; i < n; ++i) {
            Shake.permute();
        }
    }
}

contract MlDsaExpanded {
    function verify(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        Shake.reserve();
        return MlDsa.verifyExpanded(level == 44 ? MlDsa.params44() : MlDsa.params65(), ek, mprime, sig);
    }
}

/// T-GAS for the PQ kinds (accounts.md CTR-UA-23): execution gas of one `verify` call (the registry's capped
/// `staticcall`), valid signature; SLH-DSA also at its worst case. `forge test --match-contract PqGasTest -vv` prints the
/// numbers. Budget on EIP-7825 chains: `UA_VERIFY_BUDGET` = 12,000,000; a PQ kind is enabled where its cap is ≤ 75 % =
/// 9,000,000 (owner 2026-11-15; 66 % by the ruling of 2026-10-31, ~50 % before). The bounds are the values measured on 2026-10-12 (solc 0.8.37, osaka) plus ~10 %.
contract PqGasTest is Test {
    function _kat() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_kat.json");
    }

    /// Gas of `verifier.verify(pk, ua_msg, sig)` for the vector of kind `name` (must be valid).
    function _one(string memory kat, string memory name, address verifier) internal view returns (uint256 used) {
        string memory k = string.concat(".kinds.", name);
        bytes memory call = abi.encodeWithSignature(
            "verify(bytes,bytes32,bytes)",
            vm.parseJsonBytes(kat, string.concat(k, ".pk")),
            bytes32(vm.parseJsonBytes(kat, string.concat(k, ".ua_msg"))),
            vm.parseJsonBytes(kat, string.concat(k, ".sig"))
        );
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = verifier.staticcall(call);
        used = g - gasleft();
        require(ok && abi.decode(ret, (bool)), "not valid");
    }

    function test_gas_slhdsa() public {
        string memory kat = _kat();
        uint256 valid = _one(kat, "slhdsa128s", address(new SlhdsaVerifier()));
        SlhWorstCase w = new SlhWorstCase();
        bytes memory pk = vm.parseJsonBytes(kat, ".kinds.slhdsa128s.pk");
        bytes memory sig = vm.parseJsonBytes(kat, ".kinds.slhdsa128s.sig");
        bytes memory mprime = abi.encodePacked(bytes2(0), vm.parseJsonBytes(kat, ".kinds.slhdsa128s.signed_message"));
        uint256 g = gasleft();
        w.run(pk, mprime, sig);
        uint256 worst = g - gasleft();
        console2.log("slhdsa128s verify (valid)", valid);
        console2.log("slhdsa128s worst case (510 steps x 7 layers)", worst);
        assertLt(valid, worst);
        assertLt(worst, 1_460_000, "SLH-DSA gas gate: the worst case stays far inside 6,000,000");
    }

    function test_gas_fndsa() public {
        Permuter p = new Permuter();
        uint256 g0 = gasleft();
        p.run(1);
        uint256 g1 = gasleft();
        p.run(11);
        uint256 perm = ((g1 - gasleft()) - (g0 - g1)) / 10;
        uint256 fn = _one(_kat(), "fndsa512", address(new FndsaVerifier(PqUA.FNDSA512)));
        uint256 fn1024 = _one(_kat(), "fndsa1024", address(new FndsaVerifier(PqUA.FNDSA1024)));
        console2.log("keccak-f[1600] permutation", perm);
        console2.log("fndsa512 verify (valid)", fn);
        console2.log("fndsa1024 verify (valid)", fn1024);
        assertLt(perm, 73_000);
        assertLt(fn, 2_500_000);
        assertLt(fn1024, 5_250_000, "fndsa1024 under its provisional cap (CTR-UA-40)");
    }

    function _expanded(string memory kat, string memory name, uint256 level) internal returns (uint256 used) {
        MlDsaExpanded e = new MlDsaExpanded();
        string memory k = string.concat(".kinds.", name);
        bytes memory ek = vm.parseJsonBytes(kat, string.concat(k, ".expanded_key"));
        bytes memory mprime = abi.encodePacked(bytes2(0), vm.parseJsonBytes(kat, string.concat(k, ".signed_message")));
        bytes memory sig = vm.parseJsonBytes(kat, string.concat(k, ".sig"));
        uint256 g = gasleft();
        bool ok = e.verify(level, ek, mprime, sig);
        used = g - gasleft();
        require(ok, "expanded");
    }

    struct Cand {
        bytes chunks;
        bytes32 m;
        bytes sig;
        string what;
    }

    uint256 internal nextPtr = 0xcace000;

    /// The parts of `pk` on `v` at fresh pointers (`0x00 ‖ part`, as SSTORE2 writes them), packed as `verifyCached` takes them.
    function _cacheAt(MldsaVerifier v, bytes memory pk) internal returns (bytes memory chunks) {
        for (uint256 p; p < v.expandedKeyParts(); ++p) {
            bytes memory part = v.expandedKeyPart(pk, p);
            address ptr = address(uint160(++nextPtr));
            vm.etch(ptr, bytes.concat(hex"00", part));
            chunks = bytes.concat(chunks, bytes20(ptr));
        }
    }

    /// The accepting inputs of one level (F-2, owner 2026-11-15): the `pq_kat.json` row, the `pq_signatures.json` PoP and two
    /// signatures, the `mldsa_cache.json` batch (16 UA-shaped signatures, noble) and its `omega_row` (an accepting signature with
    /// exactly ω hints, or the most-hinted one padded to ω, rejected only at the last check: an upper bound).
    function _cands(MldsaVerifier v, string memory name) internal returns (Cand[] memory c, uint256 n) {
        string memory kat = _kat();
        string memory pj = vm.readFile("../vectors/ua/pq_signatures.json");
        string memory mc = vm.readFile("../vectors/ua/mldsa_cache.json");
        c = new Cand[](21);
        string memory k = string.concat(".kinds.", name);
        bytes memory ch = _cacheAt(v, vm.parseJsonBytes(kat, string.concat(k, ".pk")));
        c[n++] = Cand(
            ch,
            bytes32(vm.parseJsonBytes(kat, string.concat(k, ".ua_msg"))),
            vm.parseJsonBytes(kat, string.concat(k, ".sig")),
            "pq_kat row"
        );
        uint256 row;
        while (
            keccak256(bytes(vm.parseJsonString(pj, string.concat(".kinds[", vm.toString(row), "].name"))))
                != keccak256(bytes(name))
        ) ++row;
        string memory r = string.concat(".kinds[", vm.toString(row), "].");
        ch = _cacheAt(v, vm.parseJsonBytes(pj, string.concat(r, "keyData")));
        c[n++] = Cand(
            ch,
            vm.parseJsonBytes32(pj, string.concat(r, "pop.message")),
            vm.parseJsonBytes(pj, string.concat(r, "pop.sig")),
            "pq_signatures pop"
        );
        for (uint256 i; i < 2; ++i) {
            string memory sr = string.concat(r, "sigs[", vm.toString(i), "].");
            c[n++] = Cand(
                ch,
                vm.parseJsonBytes32(pj, string.concat(sr, "message")),
                vm.parseJsonBytes(pj, string.concat(sr, "sig")),
                "pq_signatures sig"
            );
        }
        string memory lv = string.concat(".levels.", name, ".");
        ch = _cacheAt(v, vm.parseJsonBytes(mc, string.concat(lv, "keys[0].pk")));
        for (uint256 i; i < 16; ++i) {
            string memory br = string.concat(lv, "batch[", vm.toString(i), "].");
            c[n++] = Cand(
                ch,
                vm.parseJsonBytes32(mc, string.concat(br, "ua_msg")),
                vm.parseJsonBytes(mc, string.concat(br, "sig")),
                "batch"
            );
        }
        c[n++] = Cand(
            ch,
            vm.parseJsonBytes32(mc, string.concat(lv, "omega_row.ua_msg")),
            vm.parseJsonBytes(mc, string.concat(lv, "omega_row.sig")),
            "omega row"
        );
        require(
            vm.parseJsonBool(mc, string.concat(lv, "omega_row.valid")), "the omega row is an accepting signature here"
        );
    }

    /// The least gas limit at which `verifyCached` still answers true, cold pointers (`verifyCached`'s self-call to
    /// `verifyExpanded` loses 1/64), bisected to 1,000.
    function _least(MldsaVerifier v, Cand memory x, uint256 hi) internal returns (uint256) {
        vm.resumeGasMetering(); // a call's gas limit binds only while metering runs
        uint256 lo = hi / 2;
        while (hi - lo > 1000) {
            uint256 mid = (lo + hi) / 2;
            for (uint256 q; q < x.chunks.length / 20; ++q) {
                vm.cool(address(bytes20(_at20(x.chunks, q))));
            }
            try v.verifyCached{gas: mid}(x.chunks, x.m, x.sig) returns (bool ok) {
                if (ok) hi = mid;
                else lo = mid;
            } catch {
                lo = mid;
            }
        }
        vm.pauseGasMetering();
        return hi;
    }

    function _at20(bytes memory b, uint256 i) internal pure returns (bytes20 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), mul(i, 20)))
        }
    }

    /// P6c / F-2 (accounts.md CTR-UA-23; `mldsa87` owner 2026-11-15): the registry's expanded-key cache. Gas of each
    /// `expandedKeyPart` (each part transaction's regular gas against 2^24 is `UARegistryPq.t.sol`'s) and of `verifyCached` over
    /// the worst accepting input of the level (`_cands`): the least working gas, cold pointers, of the most expensive inputs, plus
    /// 30,000 is at most the kind's cap without a precompile (`DeployBase`'s `CAP_MLDSA44` / `65` / `87`; ≤ 75 % of 12 M).
    function test_gas_mldsaCache() public {
        vm.pauseGasMetering();
        string[3] memory names = ["mldsa44", "mldsa65", "mldsa87"];
        uint16[3] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65, PqUA.MLDSA87];
        uint256[3] memory bound = [uint256(4_250_000), 5_950_000, 8_850_000];
        for (uint256 i; i < 3; ++i) {
            MldsaVerifier v = new MldsaVerifier(kinds[i], address(0), "", "");
            bytes memory pk = vm.parseJsonBytes(_kat(), string.concat(".kinds.", names[i], ".pk"));
            for (uint256 p; p < v.expandedKeyParts(); ++p) {
                vm.resumeGasMetering();
                uint256 g = gasleft();
                bytes memory part = v.expandedKeyPart(pk, p);
                g -= gasleft();
                vm.pauseGasMetering();
                console2.log(string.concat(names[i], " expandedKeyPart ", vm.toString(p), " bytes"), part.length);
                console2.log(string.concat(names[i], " expandedKeyPart ", vm.toString(p), " gas"), g);
            }
            (Cand[] memory c, uint256 n) = _cands(v, names[i]);
            uint256[] memory used = new uint256[](n);
            for (uint256 j; j < n; ++j) {
                vm.resumeGasMetering();
                uint256 g = gasleft();
                bool ok = v.verifyCached(c[j].chunks, c[j].m, c[j].sig);
                g -= gasleft();
                vm.pauseGasMetering();
                assertTrue(ok, string.concat(names[i], " accepts: ", c[j].what));
                used[j] = g;
            }
            uint256 worst;
            uint256 at;
            for (uint256 t; t < 3; ++t) {
                // the three most expensive inputs, bisected
                uint256 top;
                for (uint256 j; j < n; ++j) {
                    if (used[j] > used[top]) top = j;
                }
                uint256 least = _least(v, c[top], 2 * used[top]);
                console2.log(string.concat(names[i], " least working cap, cold, ", c[top].what), least);
                if (least > worst) (worst, at) = (least, top);
                used[top] = 0;
            }
            console2.log(
                string.concat(names[i], " worst accepting input, least working cap (cold, +-1000): ", c[at].what), worst
            );
            console2.log(string.concat(names[i], " cap"), bound[i]);
            assertLe(worst + 30_000, bound[i], "F-2: the worst accepting input's least working gas + 30,000 <= the cap");
        }
    }

    function test_gas_mldsa() public {
        string memory kat = _kat();
        uint256 c44 = _one(kat, "mldsa44", address(new MldsaVerifier(PqUA.MLDSA44, address(0), "", "")));
        uint256 c65 = _one(kat, "mldsa65", address(new MldsaVerifier(PqUA.MLDSA65, address(0), "", "")));
        uint256 e44 = _expanded(kat, "mldsa44", 44);
        uint256 e65 = _expanded(kat, "mldsa65", 65);
        console2.log("mldsa44 verify (valid, FIPS 204 key)", c44);
        console2.log("mldsa65 verify (valid, FIPS 204 key)", c65);
        console2.log("mldsa44 verify (valid, EIP-8051 expanded key)", e44);
        console2.log("mldsa65 verify (valid, expanded key)", e65);
        assertGt(c44, 6_000_000, "FIPS-key ML-DSA-44 over the public-chain bound: if this fails, revisit ruling P10");
        assertLt(c44, 12_600_000);
        assertLt(c65, 20_800_000);
        assertLt(e44, 4_500_000);
        assertLt(e65, 6_400_000);
    }
}
