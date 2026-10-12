// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PqUA} from "../../src/ua/PqUA.sol";

interface IVerify {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}

/// Shared reader of the PQ vectors: `pq_kat.json` (SCaaS: keys from clientkeys `src/pq.js`, UA messages, a mutation set
/// with noble's verdicts) and `pq_external.json` (ACVP FIPS 204 / 205 sigVer, the EIP-8051 / EIP-8052 KATs, the EIP-8355
/// cases), both under `smartcontracts/vectors/ua/`. The files are read per test (a storage copy would not fit a block).
abstract contract PqVectors is Test {
    function _kat() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_kat.json");
    }

    function _ext() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_external.json");
    }

    function _b(string memory json, string memory key) internal pure returns (bytes memory) {
        return vm.parseJsonBytes(json, key);
    }

    function _k(string memory kat, string memory name, string memory field) internal pure returns (bytes memory) {
        return _b(kat, string.concat(".kinds.", name, ".", field));
    }

    function _case(string memory section, uint256 i) internal pure returns (string memory) {
        return string.concat(".", section, ".cases[", vm.toString(i), "]");
    }

    function _cases(string memory ext, string memory section) internal view returns (uint256 n) {
        while (vm.keyExistsJson(ext, _case(section, n))) ++n;
    }

    /// The UA-level vector of one kind through its verifier: TAG, UA id, ua_msg, the signed message, the signature,
    /// and every mutation with noble's verdict.
    function _uaVector(string memory name, address verifier, uint16 kind) internal view {
        string memory kat = _kat();
        bytes memory pk = _k(kat, name, "pk");
        bytes32 tag = PqUA.tag(kind);
        assertEq(tag, bytes32(_k(kat, name, "tag_hash")), "TAG(kind)");
        assertEq(keccak256(abi.encodePacked(tag, pk)), bytes32(_k(kat, name, "ua")), "UA id");
        bytes32 uaMsg = PqUA.uaMessage(tag, bytes32(_b(kat, ".purpose_tag")), bytes32(_b(kat, ".digest")));
        assertEq(uaMsg, bytes32(_k(kat, name, "ua_msg")), "ua_msg");
        bytes32 signed = kind == PqUA.FNDSA512 ? uaMsg : PqUA.pqMessage(tag, uaMsg);
        assertEq(signed, bytes32(_k(kat, name, "signed_message")), "signed message");
        assertTrue(IVerify(verifier).verify(pk, uaMsg, _k(kat, name, "sig")), "valid signature");
        assertTrue(IVerify(verifier).verifyPop(pk, uaMsg, _k(kat, name, "sig")), "verifyPop = verify (P6c)");
        assertFalse(IVerify(verifier).verifyPop(pk, ~uaMsg, _k(kat, name, "sig")), "verifyPop, other message");
        uint256 n;
        for (; vm.keyExistsJson(kat, string.concat(".kinds.", name, ".mutations[", vm.toString(n), "]")); ++n) {
            string memory m = string.concat(".kinds.", name, ".mutations[", vm.toString(n), "]");
            bool got = IVerify(verifier).verify(_b(kat, string.concat(m, ".pk")),
                bytes32(_b(kat, string.concat(m, ".ua_msg"))), _b(kat, string.concat(m, ".sig")));
            assertEq(got, vm.parseJsonBool(kat, string.concat(m, ".valid")), vm.parseJsonString(kat, string.concat(m, ".what")));
        }
        assertEq(n, kind == PqUA.FNDSA512 ? 6 : 8, "mutations"); // + 2 non-empty-context signatures for ML-DSA, SLH-DSA
    }

    /// `t` (n entries of `width` bytes, big-endian) is `root^brv(k) mod q`, and root^n = −1 (a primitive 2n-th root).
    function _zetas(bytes memory t, uint256 width, uint256 n, uint256 q, uint256 root) internal pure {
        assertEq(t.length, n * width);
        uint256 bits;
        // forge-lint: disable-next-line(incorrect-shift)
        while ((1 << bits) < n) ++bits;
        uint256 pw = 1;
        for (uint256 i; i < n; ++i) {
            uint256 r;
            for (uint256 b; b < bits; ++b) r = (r << 1) | ((i >> b) & 1);
            uint256 v;
            for (uint256 j; j < width; ++j) v = (v << 8) | uint8(t[r * width + j]);
            assertEq(v, pw);
            pw = mulmod(pw, root, q);
        }
        assertEq(pw, q - 1);
    }
}
