// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SlhDsaSha2128s, UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {Shake} from "../../src/ua/Shake.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {MlDsa, UAMldsaVerifier} from "../../src/ua/MlDsa.sol";

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
            node = SlhDsaSha2128s.xmssPk(sig, SlhDsaSha2128s.HT_OFF + j * SlhDsaSha2128s.XMSS_LEN, 0, j, idxTree, idxLeaf, b, t);
        }
    }
}

contract Permuter {
    function run(uint256 n) external pure {
        Shake.reserve();
        for (uint256 i; i < n; ++i) Shake.permute();
    }
}

contract MlDsaExpanded {
    function verify(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return MlDsa.verifyExpanded(level == 44 ? MlDsa.params44() : MlDsa.params65(), ek, mprime, sig);
    }
}

/// T-GAS for the PQ kinds (accounts.md CTR-UA-23): execution gas of one `verify` call (the registry's capped
/// `staticcall`), valid signature; SLH-DSA also at its worst case. `forge test --match-contract PqGasTest -vv` prints the
/// numbers. Budget on EIP-7825 chains: `UA_VERIFY_BUDGET` = 12,000,000; an enabled kind on a public chain ≤ ~50 % =
/// 6,000,000. The bounds are the values measured on 2026-10-12 (solc 0.8.37, osaka) plus ~10 %.
contract PqGasTest is Test {
    function _kat() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_kat.json");
    }

    /// Gas of `verifier.verify(pk, ua_msg, sig)` for the vector of kind `name` (must be valid).
    function _one(string memory kat, string memory name, address verifier) internal view returns (uint256 used) {
        string memory k = string.concat(".kinds.", name);
        bytes memory call = abi.encodeWithSignature("verify(bytes,bytes32,bytes)", vm.parseJsonBytes(kat, string.concat(k, ".pk")),
            bytes32(vm.parseJsonBytes(kat, string.concat(k, ".ua_msg"))), vm.parseJsonBytes(kat, string.concat(k, ".sig")));
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = verifier.staticcall(call);
        used = g - gasleft();
        require(ok && abi.decode(ret, (bool)), "not valid");
    }

    function test_gas_slhdsa() public {
        string memory kat = _kat();
        uint256 valid = _one(kat, "slhdsa128s", address(new UASlhdsaVerifier()));
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
        uint256 fn = _one(_kat(), "fndsa512", address(new UAFndsaVerifier()));
        console2.log("keccak-f[1600] permutation", perm);
        console2.log("fndsa512 verify (valid)", fn);
        assertLt(perm, 73_000);
        assertLt(fn, 2_500_000);
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

    function test_gas_mldsa() public {
        string memory kat = _kat();
        uint256 c44 = _one(kat, "mldsa44", address(new UAMldsaVerifier(PqUA.MLDSA44, address(0), "", "")));
        uint256 c65 = _one(kat, "mldsa65", address(new UAMldsaVerifier(PqUA.MLDSA65, address(0), "", "")));
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
