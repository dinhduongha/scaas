// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {HashToCurve} from "../../src/common/HashToCurve.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {FrostSecp256k1, UAFrostSecp256k1Verifier} from "../../src/ua/verifiers/UAFrostSecp256k1Verifier.sol";
import {FrostBn254Verifier} from "../../src/ua/verifiers/FrostBn254Verifier.sol";

/// RFC 9591 verify over an arbitrary-length message (the RFC vectors sign "test", the UA kinds sign 32 bytes).
contract FrostHarness {
    function verifyBytes(bytes memory y, bytes memory m, bytes memory sig) external view returns (bool) {
        return FrostSecp256k1.verify(y, m, sig);
    }
}

contract KindsHarness {
    function validate(uint16 kind, bytes memory d) external view {
        UAKinds.validateKeyData(kind, d, false);
    }
}

/// `UAFrostSecp256k1Verifier` and `FrostBn254Verifier` (accounts.md §1.6.1, §1.9) on smartcontracts/vectors/ua/groups.json:
/// every FROST group (PoP via `verifyPop`, stored-key `verify`), the DKG rows' `H_dkg` preimages and challenges, `zfDkg`,
/// RFC 9591 Appendix E.5, T-FROST (`tFrost[]`), the main groups' sigs and negatives; plus RFC 9380 K.1, extra DKG
/// negatives, malformed input never reverts, gas (`-vv`).
contract UAFrostTest is Test {
    string internal gj;
    string internal sj;
    UAFrostSecp256k1Verifier internal fs;
    FrostBn254Verifier internal fb;
    Bip340Verifier internal bip;
    FrostHarness internal h;
    KindsHarness internal kh;
    uint256[] internal frostGroups; // indexes into groups[] of kinds 0x0111 / 0x0113
    uint256 internal sMain;
    uint256 internal bMain;

    uint16 internal constant FROST_SECP = 0x0111;
    uint16 internal constant FROST_BN = 0x0113;
    uint256 internal constant SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant BN_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant BN_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// ZF frost-secp256k1 3.0.0 `tests/helpers/vectors.json`: E.5 key and message, other nonce randomness than the RFC text.
    bytes internal constant E5_SIG_ZF =
        hex"024c1ad4e031872661fa6ebd05dfc7fb30db08b38d79f0edbc82051ae931381bc6a46881e25c7989d3816eae32074f1ab0d49ee908a59713ed5284c6bade7cfb02";
    /// `zfDkg` has no PoP: an RFC 9591 signature over ZF_MSG = keccak256("ua2c frost fixture message") by
    /// `s = Σ signing_key` of `vectors_dkg.json` (Σ s_i·G = its verifying_key), made once with a Python RFC 9591 signer.
    bytes32 internal constant ZF_MSG = 0xe1352934f280ed376861f0a7e09acc380153101c3871257792f04d8fc208abbe;
    bytes internal constant ZF_SIG =
        hex"03f580a2e6d16da374db56831869718cd069d2ca1e84006b901cb370de1927cd08916c42b72a61c11b026fc5e0f5714a9d53a30170a15321c6f5e9ae10ad30961a";

    function setUp() public {
        gj = vm.readFile("../vectors/ua/groups.json");
        sj = vm.readFile("../vectors/ua/signatures.json");
        fs = new UAFrostSecp256k1Verifier();
        fb = new FrostBn254Verifier();
        bip = new Bip340Verifier();
        h = new FrostHarness();
        kh = new KindsHarness();
        for (uint256 i; vm.keyExistsJson(gj, string.concat(".groups[", vm.toString(i), "]")); ++i) {
            uint256 kind = vm.parseJsonUint(gj, _g(i, "kind"));
            if (kind != FROST_SECP && kind != FROST_BN) continue;
            frostGroups.push(i);
            if (keccak256(bytes(vm.parseJsonString(gj, _g(i, "role")))) == keccak256("main")) {
                if (kind == FROST_SECP) sMain = i;
                else bMain = i;
            }
        }
    }

    function _g(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".groups[", vm.toString(i), "].", f);
    }

    function _gb(uint256 i, string memory f) internal view returns (bytes memory) {
        return vm.parseJsonBytes(gj, _g(i, f));
    }

    function _secp(uint256 i) internal view returns (bool) {
        return vm.parseJsonUint(gj, _g(i, "kind")) == FROST_SECP;
    }

    // ---- RFC 9380 expand_message_xmd (SHA-256), Appendix K.1, through the library the FROST hashes use

    function test_xmd_rfc9380_k1() public pure {
        bytes memory dst = "QUUX-V01-CS02-with-expander-SHA256-128";
        assertEq(HashToCurve.expandMessageXmd("", dst, 0x20), hex"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
        assertEq(HashToCurve.expandMessageXmd("abc", dst, 0x20), hex"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615");
        assertEq(
            HashToCurve.expandMessageXmd("abcdef0123456789", dst, 0x20),
            hex"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"
        );
        assertEq(
            HashToCurve.expandMessageXmd("", dst, 0x80),
            hex"af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4"
            hex"cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472"
            hex"c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
        );
        assertEq(
            HashToCurve.expandMessageXmd("abc", dst, 0x80),
            hex"abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b"
            hex"664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425"
            hex"cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
        );
    }

    // ---- RFC 9591 Appendix E.5 FROST(secp256k1, SHA-256)

    function test_rfc9591_e5() public view {
        bytes memory y = vm.parseJsonBytes(gj, ".rfc9591E5.groupPublicKey");
        bytes memory m = vm.parseJsonBytes(gj, ".rfc9591E5.message");
        bytes memory sig = vm.parseJsonBytes(gj, ".rfc9591E5.sig");
        assertEq(y, hex"02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
        assertEq(m, "test");
        assertEq(sig, hex"0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324");
        assertTrue(h.verifyBytes(y, m, sig), "RFC text sig");
        assertTrue(h.verifyBytes(y, m, E5_SIG_ZF), "ZF vectors.json sig");
        assertFalse(h.verifyBytes(y, "tesu", sig), "other message");
        assertFalse(h.verifyBytes(hex"03f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f", m, sig), "-Y");
        for (uint256 k; k < 65; k += 8) {
            bytes memory bad = bytes.concat(sig);
            bad[k] ^= 0x01;
            assertFalse(h.verifyBytes(y, m, bad), "mutated sig");
        }
        assertFalse(h.verifyBytes(y, m, bytes.concat(_slice(sig, 0, 33), bytes32(SECP_N))), "z = N");
        assertFalse(h.verifyBytes(y, m, _slice(sig, 0, 64)), "short sig");
    }

    // ---- T-FROST: RFC 9591 signatures are not BIP-340 signatures and vice versa

    /// `tFrost[]`: 10 rows. The BIP-340 re-encoding of E.5 signs the 4-byte "test", which `Bip340Verifier` (32-byte
    /// `ua_msg` only) cannot take: that one row is skipped and counted.
    function test_tFrost() public view {
        uint256 used;
        uint256 skipped;
        for (uint256 i; vm.keyExistsJson(gj, string.concat(".tFrost[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(".tFrost[", vm.toString(i), "].");
            bytes memory key = vm.parseJsonBytes(gj, string.concat(p, "key"));
            bytes memory m = vm.parseJsonBytes(gj, string.concat(p, "message"));
            bytes memory sig = vm.parseJsonBytes(gj, string.concat(p, "sig"));
            bool valid = vm.parseJsonBool(gj, string.concat(p, "valid"));
            bool got;
            if (keccak256(bytes(vm.parseJsonString(gj, string.concat(p, "verifier")))) == keccak256("frost-secp256k1")) {
                got = m.length == 32 ? fs.verify(key, bytes32(m), sig) : h.verifyBytes(key, m, sig);
            } else {
                if (m.length != 32) {
                    assertFalse(valid);
                    ++skipped;
                    continue;
                }
                got = bip.verify(key, bytes32(m), sig);
            }
            assertEq(got, valid, vm.parseJsonString(gj, string.concat(p, "name")));
            ++used;
        }
        assertEq(used, 9);
        assertEq(skipped, 1);
    }

    function test_tfrost_bip340Official() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".bip340Official[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(".bip340Official[", vm.toString(i), "]");
            if (!vm.parseJsonBool(sj, string.concat(p, ".valid"))) continue;
            bytes memory m = vm.parseJsonBytes(sj, string.concat(p, ".message"));
            if (m.length != 32) continue;
            bytes memory pk = vm.parseJsonBytes(sj, string.concat(p, ".publicKey"));
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(p, ".sig"));
            assertTrue(bip.verify(pk, bytes32(m), sig));
            assertFalse(fs.verify(bytes.concat(hex"02", pk), bytes32(m), bytes.concat(hex"02", sig)));
            ++n;
        }
        assertGe(n, 3, "official BIP-340 rows used");
    }

    // ---- groups.json FROST groups: PoP (verifyPop), stored key (verify), sigs, DKG rows, zfDkg

    function test_groups() public view {
        assertEq(frostGroups.length, 12);
        uint256[2][6] memory tn = [[uint256(2), 3], [uint256(2), 2], [uint256(2), 8], [uint256(8), 8], [uint256(2), 16], [uint256(16), 16]];
        for (uint256 j; j < 12; ++j) {
            uint256 i = frostGroups[j];
            bool secp = _secp(i);
            assertEq(secp, j < 6);
            assertEq(vm.parseJsonUint(gj, _g(i, "t")), tn[j % 6][0]);
            assertEq(vm.parseJsonUint(gj, _g(i, "n")), tn[j % 6][1]);
            bytes memory kd = _gb(i, "keyData");
            bytes memory vk = _gb(i, "vk");
            bytes32 m = vm.parseJsonBytes32(gj, _g(i, "pop.message"));
            bytes memory blob = _gb(i, "pop.blob");
            assertEq(vk, _slice(kd, 0, secp ? 33 : 64));
            assertEq(blob, _gb(i, "pop.sig"));
            assertTrue(_pop(secp, kd, m, blob), vm.parseJsonString(gj, _g(i, "name")));
            assertTrue(_verify(secp, vk, m, blob));
            assertFalse(_pop(secp, kd, bytes32(uint256(m) ^ 1), blob), "other message");
        }
        assertEq(sMain, frostGroups[0]);
        assertEq(bMain, frostGroups[6]);
    }

    function test_mainSigs() public view {
        uint256[2] memory mains = [sMain, bMain];
        uint256 n;
        for (uint256 k; k < 2; ++k) {
            uint256 i = mains[k];
            bytes memory vk = _gb(i, "vk");
            for (uint256 s; vm.keyExistsJson(gj, _g(i, string.concat("sigs[", vm.toString(s), "]"))); ++s) {
                string memory p = string.concat("sigs[", vm.toString(s), "].");
                bytes32 m = vm.parseJsonBytes32(gj, _g(i, string.concat(p, "message")));
                assertTrue(_verify(k == 0, vk, m, _gb(i, string.concat(p, "sig"))));
                ++n;
            }
        }
        assertEq(n, 4);
    }

    /// A `dkg[]` row as `vm.parseJson` decodes it (fields in alphabetical order; 32-byte hex strings become bytes32).
    struct DkgRow {
        bytes R;
        bytes32 challenge;
        bytes[] commitments;
        uint256 id;
        bytes32 mu;
        bytes preimage;
    }

    /// Each `dkg[]` row: `preimage == id (32 BE) ‖ C_i0 ‖ R_i`, `challenge == H_dkg(preimage)` (secp256k1 through the
    /// verifier's library; bn254 recomputed here per the ciphersuite table), and the row equals its key-data slice.
    function test_dkgRows() public view {
        uint256 rows;
        for (uint256 j; j < 12; ++j) rows += this.dkgGroup(frostGroups[j]);
        assertEq(rows, 106);
    }

    /// One group per external frame (memory of the parsed JSON is released between groups).
    function dkgGroup(uint256 i) external view returns (uint256) {
        string memory json = vm.readFile("../vectors/ua/groups.json");
        bool secp = vm.parseJsonUint(json, _g(i, "kind")) == FROST_SECP;
        bytes memory kd = vm.parseJsonBytes(json, _g(i, "keyData"));
        DkgRow[] memory rows = abi.decode(vm.parseJson(json, _g(i, "dkg")), (DkgRow[]));
        (uint256 size, uint256 t, uint256 per, uint256 base) = _layout(kd, secp);
        for (uint256 p; p < rows.length; ++p) {
            DkgRow memory r = rows[p];
            uint256 o = base + p * per;
            assertEq(r.id, p + 1);
            assertEq(r.commitments.length, t);
            for (uint256 k; k < t; ++k) assertEq(r.commitments[k], _slice(kd, o + k * size, size));
            assertEq(r.R, _slice(kd, o + t * size, size));
            assertEq(r.mu, bytes32(_word(kd, o + (t + 1) * size)));
            assertEq(r.preimage, abi.encodePacked(p + 1, r.commitments[0], r.R));
            uint256 c = secp ? FrostSecp256k1.hashToScalar(r.preimage, FrostSecp256k1.DST_DKG) : _hdkgBn(r.preimage);
            assertEq(bytes32(c), r.challenge);
        }
        return rows.length;
    }

    function _hdkgBn(bytes memory m) internal pure returns (uint256) {
        bytes memory pre = bytes.concat("FROST-BN254-KECCAK256-SCAAS-v1", "dkg", m);
        uint256 hi = uint256(keccak256(bytes.concat(pre, hex"00")));
        uint256 lo = uint256(keccak256(bytes.concat(pre, hex"01")));
        return addmod(mulmod(hi, (type(uint256).max % BN_R) + 1, BN_R), lo, BN_R);
    }

    /// The ZF-authored DKG transcript passes the on-chain DKG check (with the inline group signature).
    function test_zfDkg() public view {
        bytes memory kd = vm.parseJsonBytes(gj, ".zfDkg.keyData");
        assertTrue(fs.verifyPop(kd, ZF_MSG, ZF_SIG));
        (, uint256 t,, uint256 base) = _layout(kd, true);
        bytes memory bad = bytes.concat(kd);
        _put(bad, base + (t + 1) * 33, _word(kd, base + (t + 1) * 33) ^ 1);
        assertFalse(fs.verifyPop(bad, ZF_MSG, ZF_SIG), "mu_1 mutated");
    }

    /// Main groups' `negatives[]`: `register` rows — `verifyPop` false; `UAKeyData` rows are refused by
    /// `UAKinds.validateKeyData`, `UAPoP` rows pass it; `sigValid` ⇒ the signature alone verifies against keyData's Y
    /// (only the group check refuses). `verify` rows — false.
    function test_negatives() public view {
        uint256[2] memory mains = [sMain, bMain];
        uint256[2] memory counts;
        for (uint256 k; k < 2; ++k) {
            uint256 i = mains[k];
            bool secp = k == 0;
            uint16 kind = secp ? FROST_SECP : FROST_BN;
            for (uint256 s; vm.keyExistsJson(gj, _g(i, string.concat("negatives[", vm.toString(s), "]"))); ++s) {
                string memory p = string.concat("negatives[", vm.toString(s), "].");
                string memory name = vm.parseJsonString(gj, _g(i, string.concat(p, "name")));
                bytes32 err = keccak256(bytes(vm.parseJsonString(gj, _g(i, string.concat(p, "error")))));
                bytes32 m = vm.parseJsonBytes32(gj, _g(i, string.concat(p, "message")));
                if (keccak256(bytes(vm.parseJsonString(gj, _g(i, string.concat(p, "entry"))))) == keccak256("verify")) {
                    assertEq(err, keccak256("false"));
                    assertFalse(_verify(secp, _gb(i, string.concat(p, "vk")), m, _gb(i, string.concat(p, "sig"))), name);
                } else {
                    bytes memory kd = _gb(i, string.concat(p, "keyData"));
                    bytes memory pop = _gb(i, string.concat(p, "pop"));
                    assertFalse(_pop(secp, kd, m, pop), name);
                    if (err == keccak256("UAKeyData")) {
                        try kh.validate(kind, kd) {
                            revert(string.concat(name, ": validateKeyData accepted"));
                        } catch (bytes memory e) {
                            assertEq(e, abi.encodeWithSelector(UAKinds.UAKeyData.selector, kind), name);
                        }
                    } else {
                        assertEq(err, keccak256("UAPoP"), name);
                        kh.validate(kind, kd);
                    }
                    if (vm.parseJsonBool(gj, _g(i, string.concat(p, "sigValid")))) {
                        assertTrue(_verify(secp, _slice(kd, 0, secp ? 33 : 64), m, pop), string.concat(name, " sigValid"));
                    }
                }
                ++counts[k];
            }
        }
        assertEq(counts[0], 16);
        assertEq(counts[1], 14);
    }

    // ---- DKG negatives not in groups.json (main groups)

    /// μ_i = order (non-canonical) and R_1 replaced by R_2, per curve.
    function test_badPoK_extra() public view {
        for (uint256 k; k < 2; ++k) {
            (bool secp, bytes memory kd, bytes32 m, bytes memory sig) = _main(k == 0);
            (uint256 size, uint256 t, uint256 per, uint256 base) = _layout(kd, secp);
            for (uint256 i; i < 3; ++i) {
                bytes memory bad = bytes.concat(kd);
                _put(bad, base + i * per + (t + 1) * size, secp ? SECP_N : BN_R);
                assertFalse(_pop(secp, bad, m, sig), "mu = order");
            }
            bytes memory swapR = bytes.concat(kd);
            _copy(swapR, base + t * size, kd, base + per + t * size, size);
            assertFalse(_pop(secp, swapR, m, sig), "R_1 := R_2");
            assertTrue(_pop(secp, kd, m, sig));
        }
    }

    /// Non-canonical / off-curve Y, C_i0, R_i.
    function test_badPoints_secp() public view {
        (, bytes memory kd, bytes32 m, bytes memory sig) = _main(true);
        (, uint256 t, uint256 per, uint256 base) = _layout(kd, true);
        uint256[3] memory offs = [uint256(0), base + per, base + per + t * 33]; // Y, C_20, R_2
        for (uint256 k; k < 3; ++k) {
            uint256 o = offs[k];
            bytes memory bad = bytes.concat(kd);
            bad[o] = 0x04;
            assertFalse(fs.verifyPop(bad, m, sig), "prefix 04");
            bad[o] = 0x00;
            assertFalse(fs.verifyPop(bad, m, sig), "prefix 00");
            bad = bytes.concat(kd);
            _put(bad, o + 1, SECP_P + 1); // x >= p (x = p + 1 ≡ 1, a valid x mod p)
            assertFalse(fs.verifyPop(bad, m, sig), "x >= p");
            _put(bad, o + 1, 5); // x³ + 7 is a non-residue
            assertFalse(fs.verifyPop(bad, m, sig), "off curve");
        }
    }

    function test_badPoints_bn() public view {
        (, bytes memory kd, bytes32 m, bytes memory sig) = _main(false);
        (, uint256 t, uint256 per, uint256 base) = _layout(kd, false);
        uint256[3] memory boffs = [uint256(0), base + per, base + per + t * 64];
        for (uint256 k; k < 3; ++k) {
            uint256 o = boffs[k];
            bytes memory bad = bytes.concat(kd);
            _put(bad, o + 32, _word(kd, o + 32) + BN_P); // y + p: non-canonical
            assertFalse(fb.verifyPop(bad, m, sig), "bn y + p");
            bad = bytes.concat(kd);
            _put(bad, o + 32, addmod(_word(kd, o + 32), 1, BN_P));
            assertFalse(fb.verifyPop(bad, m, sig), "bn off curve");
            bad = bytes.concat(kd);
            _put(bad, o, 0);
            _put(bad, o + 32, 0);
            assertFalse(fb.verifyPop(bad, m, sig), "bn identity");
        }
    }

    /// n / t bounds and truncation; `verifyPop` refuses before touching a point.
    function test_bounds() public view {
        (, bytes memory kd, bytes32 m, bytes memory sig) = _main(true);
        assertFalse(fs.verifyPop(_setU16(kd, 35, 17), m, sig), "n = 17");
        assertFalse(fs.verifyPop(_setU16(kd, 35, 1), m, sig), "t > n");
        assertFalse(fs.verifyPop(_setU16(kd, 35, 0), m, sig), "n = 0");
        assertFalse(fs.verifyPop(_setU16(kd, 33, 0), m, sig), "t = 0");
        assertFalse(fs.verifyPop(_slice(kd, 0, kd.length - 1), m, sig), "truncated");
        assertFalse(fs.verifyPop(bytes.concat(kd, hex"00"), m, sig), "trailing byte");
        assertFalse(fs.verifyPop(_slice(kd, 0, 36), m, sig), "short header");
        assertFalse(fs.verifyPop("", m, sig), "empty");
        assertFalse(fs.verify(_slice(kd, 0, 32), m, sig), "vk 32 bytes");
        assertFalse(fs.verify(kd, m, sig), "vk = key data");
        uint256 big = frostGroups[5]; // t = n = 16: right length for 16, header says 17
        assertFalse(fs.verifyPop(_setU16(_setU16(_gb(big, "keyData"), 33, 17), 35, 17), m, _gb(big, "pop.blob")), "t = n = 17");
        (, kd, m, sig) = _main(false);
        assertFalse(fb.verifyPop(_setU16(kd, 66, 17), m, sig), "bn n = 17");
        assertFalse(fb.verifyPop(_setU16(kd, 64, 0), m, sig), "bn t = 0");
        assertFalse(fb.verifyPop(_setU16(kd, 66, 1), m, sig), "bn t > n");
        assertFalse(fb.verifyPop(_slice(kd, 0, kd.length - 1), m, sig), "bn truncated");
        assertFalse(fb.verifyPop(_slice(kd, 0, 67), m, sig), "bn short header");
        assertFalse(fb.verifyPop("", m, sig), "bn empty");
        assertFalse(fb.verify(_slice(kd, 0, 63), m, sig), "bn vk 63 bytes");
        assertFalse(fb.verify(kd, m, sig), "bn vk = key data");
    }

    // ---- malformed input never reverts (a revert fails the test); mutations outside C_ik (k ≥ 1) answer false

    function testFuzz_randomNeverReverts(bytes calldata a, bytes calldata b, bytes32 m) public view {
        fs.verify(a, m, b);
        fs.verifyPop(a, m, b);
        fb.verify(a, m, b);
        fb.verifyPop(a, m, b);
    }

    function testFuzz_mutatedSecp(uint256 pos, uint8 delta) public view {
        _mutate(true, pos, delta);
    }

    function testFuzz_mutatedBn(uint256 pos, uint8 delta) public view {
        _mutate(false, pos, delta);
    }

    function _mutate(bool secp_, uint256 pos, uint8 delta) internal view {
        (bool secp, bytes memory kd, bytes32 m, bytes memory sig) = _main(secp_);
        delta = uint8(bound(delta, 1, 255));
        pos = bound(pos, 0, kd.length + sig.length - 1);
        (uint256 size, uint256 t, uint256 per, uint256 base) = _layout(kd, secp);
        bool higher;
        if (pos < kd.length) {
            kd[pos] = bytes1(uint8(kd[pos]) ^ delta);
            if (pos >= base) {
                uint256 inPart = (pos - base) % per;
                higher = inPart >= size && inPart < t * size; // C_ik, k ≥ 1: not an input of any equation
            }
        } else {
            sig[pos - kd.length] = bytes1(uint8(sig[pos - kd.length]) ^ delta);
        }
        bool ok = _pop(secp, kd, m, sig);
        if (!higher) assertFalse(ok);
    }

    // ---- gas (T-GAS input): verify on the stored key and verifyPop, every groups.json FROST group, warm verifiers

    function test_gas() public view {
        fs.verify("", 0, "");
        fb.verify("", 0, "");
        uint256[6] memory capPop = [uint256(100_000), 80_000, 200_000, 220_000, 380_000, 420_000];
        for (uint256 j; j < 12; ++j) {
            uint256 i = frostGroups[j];
            bool secp = _secp(i);
            bytes memory vk = _gb(i, "vk");
            bytes memory kd = _gb(i, "keyData");
            bytes32 m = vm.parseJsonBytes32(gj, _g(i, "pop.message"));
            bytes memory sig = _gb(i, "pop.blob");
            uint256 g = gasleft();
            bool ok = _verify(secp, vk, m, sig);
            uint256 gv = g - gasleft();
            assertTrue(ok);
            g = gasleft();
            ok = _pop(secp, kd, m, sig);
            uint256 gp = g - gasleft();
            assertTrue(ok);
            console.log(vm.parseJsonString(gj, _g(i, "kindName")), vm.parseJsonString(gj, _g(i, "name")));
            console.log("  verify / verifyPop", gv, gp);
            assertLt(gv, secp ? 21_000 : 32_000);
            assertLt(gp, capPop[j % 6]);
        }
    }

    // ---- helpers

    function _main(bool secp) internal view returns (bool, bytes memory kd, bytes32 m, bytes memory sig) {
        uint256 i = secp ? sMain : bMain;
        return (secp, _gb(i, "keyData"), vm.parseJsonBytes32(gj, _g(i, "pop.message")), _gb(i, "pop.blob"));
    }

    function _pop(bool secp, bytes memory kd, bytes32 m, bytes memory sig) internal view returns (bool) {
        return secp ? fs.verifyPop(kd, m, sig) : fb.verifyPop(kd, m, sig);
    }

    function _verify(bool secp, bytes memory vk, bytes32 m, bytes memory sig) internal view returns (bool) {
        return secp ? fs.verify(vk, m, sig) : fb.verify(vk, m, sig);
    }

    function _layout(bytes memory kd, bool secp) internal pure returns (uint256 size, uint256 t, uint256 per, uint256 base) {
        size = secp ? 33 : 64;
        t = (uint256(uint8(kd[size])) << 8) | uint8(kd[size + 1]);
        per = (t + 1) * size + 32;
        base = size + 4;
    }

    function _slice(bytes memory b, uint256 o, uint256 len) internal pure returns (bytes memory s) {
        s = new bytes(len);
        for (uint256 i; i < len; ++i) s[i] = b[o + i];
    }

    function _copy(bytes memory dst, uint256 dOff, bytes memory src, uint256 sOff, uint256 len) internal pure {
        for (uint256 i; i < len; ++i) dst[dOff + i] = src[sOff + i];
    }

    function _word(bytes memory b, uint256 o) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(add(b, 32), o))
        }
    }

    function _put(bytes memory b, uint256 o, uint256 w) internal pure {
        assembly {
            mstore(add(add(b, 32), o), w)
        }
    }

    function _setU16(bytes memory b, uint256 o, uint256 v) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[o] = bytes1(uint8(v >> 8));
        c[o + 1] = bytes1(uint8(v));
    }
}
