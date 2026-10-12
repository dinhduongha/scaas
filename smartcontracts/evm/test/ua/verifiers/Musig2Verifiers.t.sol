// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {
    Musig2Secp256k1Verifier,
    KEYAGG_LIST_TAG,
    KEYAGG_COEF_TAG
} from "../../../src/ua/verifiers/Musig2Secp256k1Verifier.sol";
import {Musig2Bn254Verifier} from "../../../src/ua/verifiers/Musig2Bn254Verifier.sol";
import {Bip340} from "../../../src/ua/verifiers/Bip340.sol";
import {G1Bn254} from "../../../src/zether/ZetherCurves.sol";
import {GroupFixtures} from "../GroupFixtures.sol";

/// UA-2c MuSig2 verifiers (accounts.md §1.6.1, §1.9) on groups.json (BIP-327 signer in Rust; n = 2, 3, 8, 16): KeyAgg
/// with hints (secp256k1) and with ECMUL/ECADD (bn254), the group signature against the stored `Q`, every groups.json
/// negative, and the negatives the file does not carry — the second-key rule, `x(P_i) ≥ N`, flipped hints, malformed
/// lengths (false, never a revert). Gas logged with -vv.
contract Musig2VerifiersTest is GroupFixtures {
    Musig2Secp256k1Verifier internal secp;
    Musig2Bn254Verifier internal bn;
    bytes32 internal constant M = keccak256("scaas.ua.test.musig2");
    /// 02 ‖ N: a valid secp256k1 point (N³ + 7 is a square mod p) with x ≥ N, which the ecrecover trick cannot take.
    bytes internal constant KEY_X_N = hex"02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    function setUp() public {
        secp = new Musig2Secp256k1Verifier();
        bn = new Musig2Bn254Verifier();
    }

    function test_tags() public pure {
        assertEq(sha256("KeyAgg list"), KEYAGG_LIST_TAG);
        assertEq(sha256("KeyAgg coefficient"), KEYAGG_COEF_TAG);
        assertEq(sha256("BIP0340/challenge"), Bip340.CHALLENGE_TAG);
    }

    // ------------------------------------------------------------------ groups.json

    function test_groups() public {
        uint256[4] memory ns = [uint256(2), 3, 8, 16];
        for (uint256 i; i < ns.length; ++i) {
            _groupRow(_group(MS, ns[i], ns[i]), address(secp), "musig2-secp256k1", 64);
            _groupRow(_group(MB, ns[i], ns[i]), address(bn), "musig2-bn254", 96);
        }
    }

    function _groupRow(Group memory g, address v, string memory name, uint256 sigLen) internal {
        string memory label = string.concat(name, " n=", vm.toString(g.n));
        (bool ok, uint256 used) = _metered(v, abi.encodeCall(secp.verifyPop, (g.keyData, g.popMessage, g.pop)));
        assertTrue(ok, label);
        emit log_named_uint(string.concat(label, " verifyPop"), used);
        bytes memory sig = _head(g.pop, sigLen);
        (ok, used) = _metered(v, abi.encodeCall(secp.verify, (g.vk, g.popMessage, sig)));
        assertTrue(ok, label);
        emit log_named_uint(string.concat(label, " verify"), used);
        (ok,) = _metered(v, abi.encodeCall(secp.verifyPop, (g.keyData, ~g.popMessage, g.pop)));
        assertFalse(ok, "pop over another message");
        bytes memory own = _gsign(g.kind, g.secret, g.vk, M);
        (ok,) = _metered(v, abi.encodeCall(secp.verify, (g.vk, M, own)));
        assertTrue(ok, "a signature by the group secret");
    }

    /// The main groups' `sigs` rows (metatx, member) verify against `vk`.
    function test_mainSigs() public view {
        string memory j = _gj();
        Group[2] memory gs = [_main(MS), _main(MB)];
        for (uint256 k; k < 2; ++k) {
            for (uint256 i; i < 2; ++i) {
                string memory r = string.concat(gs[k].row, ".sigs[", vm.toString(i), "]");
                bytes32 m = vm.parseJsonBytes32(j, string.concat(r, ".message"));
                bytes memory sig = vm.parseJsonBytes(j, string.concat(r, ".sig"));
                assertTrue(k == 0 ? secp.verify(gs[k].vk, m, sig) : bn.verify(gs[k].vk, m, sig));
            }
        }
    }

    /// Every groups.json negative of the MuSig2 kinds: `register` rows fail `verifyPop` (incl. those the registry
    /// already refuses as UAKeyData), `verify` rows fail `verify`; a `sigValid` row's signature alone verifies.
    function test_vectorNegatives() public view {
        string memory j = _gj();
        uint16[2] memory kinds = [MS, MB];
        uint256 seen;
        for (uint256 k; k < 2; ++k) {
            string memory row = _main(kinds[k]).row;
            for (uint256 i; vm.keyExistsJson(j, string.concat(row, ".negatives[", vm.toString(i), "]")); ++i) {
                _vectorNegative(j, kinds[k], string.concat(row, ".negatives[", vm.toString(i), "]"));
                ++seen;
            }
        }
        assertEq(seen, 27); // 15 + 12
    }

    function _vectorNegative(string memory j, uint16 kind, string memory r) internal view {
        (uint256 vkLen, uint256 sigLen) = kind == MS ? (33, 64) : (64, 96);
        string memory name = vm.parseJsonString(j, string.concat(r, ".name"));
        bytes32 m = vm.parseJsonBytes32(j, string.concat(r, ".message"));
        if (keccak256(bytes(vm.parseJsonString(j, string.concat(r, ".entry")))) == keccak256("verify")) {
            bytes memory vk = vm.parseJsonBytes(j, string.concat(r, ".vk"));
            bytes memory s = vm.parseJsonBytes(j, string.concat(r, ".sig"));
            assertFalse(kind == MS ? secp.verify(vk, m, s) : bn.verify(vk, m, s), name);
            return;
        }
        bytes memory d = vm.parseJsonBytes(j, string.concat(r, ".keyData"));
        bytes memory pop = vm.parseJsonBytes(j, string.concat(r, ".pop"));
        assertFalse(kind == MS ? secp.verifyPop(d, m, pop) : bn.verifyPop(d, m, pop), name);
        if (vm.parseJsonBool(j, string.concat(r, ".sigValid"))) {
            bytes memory s = _head(pop, sigLen);
            assertTrue(kind == MS ? secp.verify(_head(d, vkLen), m, s) : bn.verify(_head(d, vkLen), m, s), name);
        }
    }

    // ------------------------------------------------------------------ own negatives (secp256k1)

    /// BIP-327's `a = 1` for the second key: the same list aggregated with a hashed `a_2` is a consistent group (Q',
    /// hints, d') that a verifier hashing every coefficient would accept. The test's coefficient formula is first pinned
    /// against groups.json `coefficients[0]`.
    function test_secpSecondKeyRule() public {
        (bytes memory kd, bytes memory hints, uint256 d) = _secpWithoutSecondKeyRule(_main(MS));
        bytes memory sig = _bip340Sign(d, M);
        assertTrue(secp.verify(_head(kd, 33), M, sig), "its signature is fine");
        assertFalse(secp.verifyPop(kd, M, bytes.concat(sig, hints)));
    }

    /// The main group's key data, hints and secret with `a_2` hashed like every other coefficient.
    function _secpWithoutSecondKeyRule(Group memory g)
        internal
        returns (bytes memory kd, bytes memory hints, uint256 d)
    {
        (uint256 a2, uint256 sk2) = _hashedA2(g);
        d = addmod(g.secret, mulmod(a2 - 1, sk2, N_K1), N_K1);
        Vm.Wallet memory q = vm.createWallet(d);
        kd = bytes.concat(bytes1(uint8(2 + (q.publicKeyY & 1))), bytes32(q.publicKeyX), _slice(g.keyData, 33, 101));
        Vm.Wallet memory h2 = vm.createWallet(mulmod(a2, sk2, N_K1));
        hints =
            bytes.concat(_head(g.hints, 64), abi.encodePacked(h2.publicKeyX, h2.publicKeyY), _slice(g.hints, 128, 64));
    }

    /// `hash_{KeyAgg coefficient}(L ‖ pk_2) mod N` and `sk_2`; the formula pinned on `coefficients[0]` first.
    function _hashedA2(Group memory g) internal view returns (uint256, uint256) {
        string memory j = _gj();
        bytes[] memory pks = vm.parseJsonBytesArray(j, string.concat(g.row, ".members"));
        uint256[] memory a = vm.parseJsonUintArray(j, string.concat(g.row, ".coefficients"));
        bytes32 l = vm.parseJsonBytes32(j, string.concat(g.row, ".L"));
        assertEq(a[1], 1, "a_2 = 1");
        assertEq(_coef(l, pks[0]), a[0], "coefficient formula");
        return (_coef(l, pks[1]), vm.parseJsonUintArray(j, string.concat(g.row, ".secrets"))[1]);
    }

    function _coef(bytes32 l, bytes memory pk) internal pure returns (uint256) {
        return uint256(sha256(abi.encodePacked(KEYAGG_COEF_TAG, KEYAGG_COEF_TAG, l, pk))) % N_K1;
    }

    /// `x(P_i) ≥ N` (accounts.md §1.6.1: required `< N`); the registry test shows the point passes key validation.
    function test_secpKeyXAtLeastN() public {
        Group memory g = _group(MS, 2, 2);
        bytes memory other = _slice(g.keyData, 35, 33);
        bytes memory d = other[0] == bytes1(0x03)
            ? bytes.concat(g.vk, hex"0002", KEY_X_N, other)
            : bytes.concat(g.vk, hex"0002", other, KEY_X_N);
        assertFalse(secp.verifyPop(d, M, bytes.concat(_bip340Sign(g.secret, M), g.hints)));
    }

    function test_secpWrongHint() public view {
        Group memory g = _main(MS);
        bytes memory sig = _head(g.pop, 64);
        assertTrue(secp.verifyPop(g.keyData, g.popMessage, g.pop));
        for (uint256 i; i < 3; ++i) {
            assertFalse(secp.verifyPop(g.keyData, g.popMessage, bytes.concat(sig, _flip(g.hints, 64 * i + 63))), "y");
            assertFalse(secp.verifyPop(g.keyData, g.popMessage, bytes.concat(sig, _flip(g.hints, 64 * i + 5))), "x");
        }
        assertFalse(secp.verifyPop(g.keyData, g.popMessage, bytes.concat(sig, _swap(g.hints, 0, 128, 64))), "swapped");
    }

    function test_secpMalformed() public view {
        Group memory g = _main(MS);
        (bytes memory kd, bytes memory pop, bytes32 m) = (g.keyData, g.pop, g.popMessage);
        assertFalse(secp.verifyPop(_head(kd, kd.length - 1), m, pop), "key data - 1");
        assertFalse(secp.verifyPop(bytes.concat(kd, hex"00"), m, pop), "key data + 1");
        assertFalse(secp.verifyPop("", m, pop), "empty key data");
        assertFalse(secp.verifyPop(kd, m, ""), "empty pop");
        assertFalse(secp.verifyPop(kd, m, bytes.concat(pop, hex"00")), "pop + 1");
        bytes memory d = bytes.concat(kd);
        d[34] = 0x02; // n = 2 with three keys
        assertFalse(secp.verifyPop(d, m, pop), "n mismatch");
        d = bytes.concat(kd);
        d[35] = 0x04; // prefix of key 0
        assertFalse(secp.verifyPop(d, m, pop), "member prefix 04");
        d = bytes.concat(kd);
        for (uint256 b = 1; b < 33; ++b) {
            d[b] = 0;
        }
        d[32] = 0x05; // x(Q) = 5: off the curve
        assertFalse(secp.verifyPop(d, m, pop), "Q off curve");
        bytes memory sig = _head(pop, 64);
        assertFalse(secp.verify(_slice(g.vk, 1, 32), m, sig), "x-only vk");
        bytes memory q4 = bytes.concat(g.vk);
        q4[0] = 0x04;
        assertFalse(secp.verify(q4, m, sig), "vk prefix 04");
        assertFalse(secp.verify(g.vk, m, bytes.concat(sig, hex"00")), "sig 65");
    }

    // ------------------------------------------------------------------ own negatives (bn254)

    /// The bn254 port's second-key rule (a_2 = 1), as for secp256k1, with the widened coefficient hash.
    function test_bnSecondKeyRule() public view {
        Group memory g = _main(MB);
        string memory j = _gj();
        bytes[] memory pks = vm.parseJsonBytesArray(j, string.concat(g.row, ".members"));
        uint256[] memory sks = vm.parseJsonUintArray(j, string.concat(g.row, ".secrets"));
        uint256[] memory a = vm.parseJsonUintArray(j, string.concat(g.row, ".coefficients"));
        bytes32 l = vm.parseJsonBytes32(j, string.concat(g.row, ".L"));
        assertEq(a[1], 1, "a_2 = 1");
        assertEq(_wide(l, pks[0]), a[0], "coefficient formula");
        uint256 d = addmod(g.secret, mulmod(_wide(l, pks[1]) - 1, sks[1], G1Bn254.R), G1Bn254.R);
        bytes memory q = G1Bn254.mulBase(d);
        bytes memory kd = bytes.concat(q, _slice(g.keyData, 64, g.keyData.length - 64));
        bytes memory sig = _bnSign(d, q, M);
        assertTrue(bn.verify(q, M, sig), "its signature is fine");
        assertFalse(bn.verifyPop(kd, M, sig));
    }

    function _wide(bytes32 l, bytes memory pk) internal pure returns (uint256) {
        uint256 hi = uint256(sha256(abi.encodePacked(KEYAGG_COEF_TAG, KEYAGG_COEF_TAG, l, pk, uint8(0))));
        uint256 lo = uint256(sha256(abi.encodePacked(KEYAGG_COEF_TAG, KEYAGG_COEF_TAG, l, pk, uint8(1))));
        return addmod(mulmod(hi, (type(uint256).max % G1Bn254.R) + 1, G1Bn254.R), lo, G1Bn254.R);
    }

    /// Invalid points make the precompile fail inside the bounded self-call: false, never a revert.
    function test_bnMalformed() public view {
        Group memory g = _main(MB);
        (bytes memory kd, bytes memory sig, bytes32 m) = (g.keyData, g.pop, g.popMessage);
        assertTrue(bn.verifyPop(kd, m, sig));
        assertFalse(bn.verifyPop(_flip(kd, 66 + 64 + 63), m, sig), "member off curve");
        assertFalse(bn.verifyPop(_flip(kd, 63), m, sig), "Q off curve");
        assertFalse(bn.verifyPop(_head(kd, kd.length - 1), m, sig), "key data - 1");
        bytes memory d = bytes.concat(kd);
        d[65] = 0x02;
        assertFalse(bn.verifyPop(d, m, sig), "n mismatch");
        assertFalse(bn.verifyPop("", m, sig), "empty");
        assertFalse(bn.verify(kd, m, sig), "verify takes Q only");
    }

    /// verifyPop's worst case (n = 16) fits `POP_GAS` inside `check`.
    function test_bnPopGas() public {
        Group memory g = _group(MB, 16, 16);
        (bool ok, uint256 used) =
            _metered(address(bn), abi.encodeCall(bn.check, (g.keyData, g.popMessage, g.pop, true)));
        assertTrue(ok);
        emit log_named_uint("musig2-bn254 check(pop) n=16", used);
        assertLt(used, bn.POP_GAS());
    }
}
