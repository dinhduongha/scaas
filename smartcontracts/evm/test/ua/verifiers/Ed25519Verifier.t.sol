// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Sha512} from "../../../src/common/Sha512.sol";
import {Ed25519} from "../../../src/common/Ed25519.sol";
import {Ed25519Verifier} from "../../../src/ua/verifiers/Ed25519Verifier.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";

/// UA-2b `ed25519` (0x0102, accounts.md §1.9): SHA-512 known answers (FIPS 180-4 examples, padding boundaries, long
/// input); RFC 8032 §7.1 and the strict-rule cases of signatures.json `ed25519Rfc8032` (any message length, via
/// `verifyRaw`); the derived row `ed25519`; T-FUZZ parity with ed25519_fuzz.json (`valid` = ed25519-dalek
/// `verify_strict`); malformed inputs (false, never a revert); forge fuzz; gas against the registry cap.
contract Ed25519VerifierTest is Test {
    uint256 internal constant P = Ed25519.P;
    uint256 internal constant L = Ed25519.L;
    /// The registry cap (UARegistryBase `_cap(0x0102)`): the measured worst + ~23 %.
    uint256 internal constant CAP = 210_000;

    /// A valid signature whose `S` and `k` have no zero 4-bit window below bit 252 (every Straus addition runs) and
    /// whose `A` takes the √−1 branch of decompression: the most expensive accepted input (noble, ground from a seed).
    bytes internal constant WORST_PK = hex"e3d99115142bc70561544c8d38361c63e65f9edd1b9f5d9a0654d4b397563bb0";
    bytes32 internal constant WORST_MSG = 0xd31914fd312462c05580de6faa34902e29bc9bea23cf9bdbe9aa7782b474ee38;
    bytes internal constant WORST_SIG =
        hex"6df5f8952c2953fd66ed2e2fca68b3e5ce989a965408052c6a330edfab577a5e55b2456ed2289bb6971134389c1ff3d562addadb3749185ca834ebb98956490c";

    Ed25519Verifier internal v;
    string internal sj;

    struct FuzzCase {
        string class; // ed25519_fuzz.json keys, alphabetical (vm.parseJson decodes in that order); 32-byte hex = bytes32
        bytes32 msg;
        bool noble;
        bytes32 pk;
        bytes sig;
        bool valid;
    }

    function setUp() public {
        v = new Ed25519Verifier();
        sj = vm.readFile("../vectors/ua/signatures.json");
    }

    // ------------------------------------------------------------------ SHA-512

    function _sha(bytes memory m) internal pure returns (bytes memory) {
        (bytes32 hi, bytes32 lo) = Sha512.hash(m);
        return abi.encodePacked(hi, lo);
    }

    /// byte i = 31·i + 7 (mod 256)
    function _pattern(uint256 n) internal pure returns (bytes memory m) {
        m = new bytes(n);
        for (uint256 i; i < n; ++i) {
            m[i] = bytes1(uint8(i * 31 + 7));
        }
    }

    function test_sha512_fips() public pure {
        assertEq(
            _sha(""),
            hex"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assertEq(
            _sha("abc"),
            hex"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // FIPS 180-4 example, 896 bits: two blocks
        assertEq(
            _sha(
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            hex"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    /// Padding boundaries (111 = the longest one-block message, 112 = the shortest two-block one, 128/239/240 the next
    /// edges), all-0xff words (every 64-bit addition carries), long inputs. Digests: node `crypto` SHA-512.
    function test_sha512_boundaries() public pure {
        uint16[19] memory n = [0, 1, 55, 56, 63, 64, 111, 112, 113, 127, 128, 129, 239, 240, 241, 255, 256, 1000, 1023];
        bytes[19] memory d = [
            bytes(
                hex"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ),
            hex"365d11a1dfe610b60efa996136d37ab8afd2715b8c6bc2850dc5e6005b702bb9f59b0f306ecb2c43ee44c429967d45843524eb2f7c16aab9bde142ee268b51c6",
            hex"330eb5e81b4d722cae1e0efbf883efb180c3e346d2b3b797dafc90409583ed35af65dc2d7974a353f0c21663e196b60d3ee5a2c70c50b7b3bccdb93a5dbce6bf",
            hex"1b5b63bfd5420b2dc480abce3dbdb3e19e5f9d4fabffba7764883937eaae878a55362c938c141712c44c3076c3fabb2c60814c2994c311c33049a8d6de2a8898",
            hex"b16f76c30db64b5ee1ef166d2d37e13ff6cee9fd88bae9ba283cd58e0a2133b220a76db56279406461f84ce2cffd1d116d38fd9f38fc5df18770a987ff695499",
            hex"4c7aba3659929c4fd87604c532a3b5f174d0626b2d661dbbbfac76c97a49a5a7789d2c68324c754f66bf629fa72054f334feaad8b1cf4c885ae03a1e634afc18",
            hex"da780d8338a8a920ceb6892cb4ecbb0cc0c66956269aadd5dd0f48790a00857bd975890f3b2955a317738cc7a770820c29f922ffbc22020f1909d594cc987d1b",
            hex"053182f7fa4e59f8636e415a77ed4fdc650f0a43834c9d35adf899599c3ab9c4153f02ff50bd01888060cd36a6fa12d9db242fc35164c80135613514186d5843",
            hex"766fea2f90094ecec1166ea4d6e9ddc6ae6fbe4a060e049300ecbe631a7d6547409b6ac39865409e6dd5dada112955fddf32698feb98806c1910f446ac5af7e3",
            hex"a7a75593826fd37d4e60f6101eabb9f8ab1cf4d5319ebc805266d5da8deb5097de1a235fc5d9d3d73c50ac100ffc75089fb454674ab61232091bd19cbdc67396",
            hex"df007a08f3aaae47e0c92ef840ecd43645ae6098c819f2a4a66174ef1cd49e5c6dfccf0616895e570b7564af641de5863dff9f89c752913d30cf0ecf678e1635",
            hex"a10ea769b79831bca33e9efb29fc501ded6e9c88885d079acb76eecaa8ac58d68bdc7e00103053e1519352c0d064c87accc3d553a6039decc2c4f1e7667eef79",
            hex"38980139aa28f1ccec548e21fd73d927488c4aa749a4b304fe0c5f7797fb80a03bc0557584ef42f47e0d3ff4eee0011084ac8421cf08dd2cea6a132bcd075c90",
            hex"eb5690f4b1753298de6626f031576ca2b93cec042d597a7a1f9e47534af610f409acb608d88fdaeade8b36fd09a6cd81f2ff8ec10962e79cd791eebc26d569f5",
            hex"251de04cf5e385bd219874e1d5b9bd8922411704029606ac7b99915032fa4bc7fb8435b84995f14a8707ff154c9c3d13332a1e4c2233ccbfa3494b91558bfd5f",
            hex"ac1ecd53106f3dfba66b7b3fcac37652aad2aad2a291c354eaca03928e74853d53c0e8c7f2fa05025efdb262fd4b51103747d3dafd53e1feefc590bf2617b30a",
            hex"7629794792236644c8c5792257d9a64320b887aae34806f9bc3713c494ea7f17602e0a9a9009b1e69b31d189d89a4f599dd30891fa04a1668ff31e30d0719df4",
            hex"b41d42e106eca6bf57123566b7ed1550c37d33af23afbfa8e302dfd44c988b3003a26b4140ef42f535e66ea424e7c4a31616307269e6d520a6508f726da23d0a",
            hex"a2fb44a07ac535e5f2c666ceaa06e17f02d542f05b20b58690e6ff1072eeb7b3aee5c3e32248976728173e82cc030059ce84c8760c77af16dcdd43aa510a4765"
        ];
        for (uint256 i; i < n.length; ++i) {
            assertEq(_sha(_pattern(n[i])), d[i], vm.toString(n[i]));
        }
        bytes memory ff = new bytes(128);
        for (uint256 i; i < 128; ++i) {
            ff[i] = 0xff;
        }
        assertEq(
            _sha(ff),
            hex"5acaf06f5dd1d107b81b9b7516d454e304cf5699d01ffe66a01ad554cfb0db896bbc16e08bd4fbcab36364909edf50ecb6c8042722a4c59456d9048244cd57f0"
        );
        assembly ("memory-safe") {
            mstore(ff, 111)
        }
        assertEq(
            _sha(ff),
            hex"ab0843dec43271ce45b21ac736670d67878bf765f08f8285f3c3de8215e45c3075edcb7fc648e5670bf8ae3450af222fdff789212f6b0000d0309ce4db088432"
        );
    }

    /// FIPS 180-4 long-message example: one million "a" (7,813 blocks).
    function test_sha512_millionA() public pure {
        bytes memory m = new bytes(1_000_000);
        assembly ("memory-safe") {
            for { let p := add(m, 32) } lt(p, add(m, 1000032)) { p := add(p, 32) } {
                mstore(p, 0x6161616161616161616161616161616161616161616161616161616161616161)
            }
        }
        assertEq(
            _sha(m),
            hex"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );
    }

    /// Dirty scratch memory past the free memory pointer does not leak into the padding.
    function test_sha512_dirtyMemory() public pure {
        assembly ("memory-safe") {
            let m := mload(0x40)
            for { let p := m } lt(p, add(m, 0x2000)) { p := add(p, 32) } { mstore(p, not(0)) }
        }
        assertEq(
            _sha("abc"),
            hex"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    function test_sha512_gas() public {
        bytes memory m = new bytes(96); // R ‖ A ‖ ua_msg
        uint256 g = gasleft();
        Sha512.hash(m);
        emit log_named_uint("sha512 96 bytes (1 block)", g - gasleft());
        m = new bytes(239);
        g = gasleft();
        Sha512.hash(m);
        emit log_named_uint("sha512 239 bytes (2 blocks)", g - gasleft());
    }

    // ------------------------------------------------------------------ vectors

    /// RFC 8032 §7.1 TEST 1/2/3/1024/SHA(abc) and the strict-rule rows (small-order, non-canonical, mixed-order A).
    function test_rfc8032() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(sj, _rfc(i, "")); ++i) {
            bool ok = v.verifyRaw(
                vm.parseJsonBytes(sj, _rfc(i, ".publicKey")),
                vm.parseJsonBytes(sj, _rfc(i, ".message")),
                vm.parseJsonBytes(sj, _rfc(i, ".sig"))
            );
            assertEq(ok, vm.parseJsonBool(sj, _rfc(i, ".valid")), vm.parseJsonString(sj, _rfc(i, ".name")));
            ++n;
        }
        assertEq(n, 11, "ed25519Rfc8032 rows");
    }

    function _rfc(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".ed25519Rfc8032[", vm.toString(i), "]", f);
    }

    /// signatures.json derived row `ed25519`: PoPs and signatures accept, every negative refuses (verify and
    /// verifyPop: the same check).
    function test_derivedRow() public {
        string memory d = ".derived[7]";
        assertEq(vm.parseJsonString(sj, string.concat(d, ".name")), "ed25519");
        assertEq(vm.parseJsonUint(sj, string.concat(d, ".kind")), 0x0102);
        bytes memory k = vm.parseJsonBytes(sj, string.concat(d, ".keyData"));
        string[2] memory pops = [".pop", ".popOther"];
        for (uint256 i; i < 2; ++i) {
            string memory p = string.concat(d, pops[i]);
            bytes32 m = vm.parseJsonBytes32(sj, string.concat(p, ".message"));
            // UA-8: the portable PoP message, the same in both contexts
            bytes32 ua = vm.parseJsonBytes32(sj, string.concat(d, ".ua"));
            assertEq(m, UAKinds.uaMessage(0x0102, UAKinds.PURPOSE_POP_V2, UAKinds.registrationDigest(ua, 0x0102, 0, UAKinds.kemRecordHash(ua, 0, ""), 0)));
            assertTrue(v.verifyPop(k, m, vm.parseJsonBytes(sj, string.concat(p, ".sig"))), pops[i]);
        }
        uint256 n;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(d, ".sigs[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(d, ".sigs[", vm.toString(i), "]");
            bytes32 m = vm.parseJsonBytes32(sj, string.concat(p, ".message"));
            bytes memory s = vm.parseJsonBytes(sj, string.concat(p, ".sig"));
            uint256 g = gasleft();
            assertTrue(v.verify(k, m, s));
            if (i == 0) emit log_named_uint("verify ed25519 (derived metatx)", g - gasleft());
            ++n;
        }
        assertEq(n, 2, "sigs");
        n = 0;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(d, ".negatives[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(d, ".negatives[", vm.toString(i), "]");
            bytes32 m = vm.parseJsonBytes32(sj, string.concat(p, ".message"));
            bytes memory s = vm.parseJsonBytes(sj, string.concat(p, ".sig"));
            string memory name = vm.parseJsonString(sj, string.concat(p, ".name"));
            assertFalse(v.verify(k, m, s), name);
            assertFalse(v.verifyPop(k, m, s), name);
            ++n;
        }
        assertEq(n, 14, "negatives");
    }

    /// T-FUZZ (accounts.md §1.16): accept/reject parity with ed25519-dalek `verify_strict` on every case.
    function test_fuzzParity() public view {
        string memory j = vm.readFile("../vectors/ua/ed25519_fuzz.json");
        FuzzCase[] memory c = abi.decode(vm.parseJson(j, ".cases"), (FuzzCase[]));
        assertEq(c.length, 2144, "cases");
        uint256 accepted;
        for (uint256 i; i < c.length; ++i) {
            bool ok = v.verify(abi.encodePacked(c[i].pk), c[i].msg, c[i].sig);
            if (ok != c[i].valid) revert(string.concat("case ", vm.toString(i), " ", c[i].class));
            if (ok) ++accepted;
        }
        assertEq(accepted, 192 + 99, "accepted: class valid + a-mixed-order k = 0 mod 8");
    }

    // ------------------------------------------------------------------ malformed input

    function _le(uint256 x) internal pure returns (bytes32 r) {
        for (uint256 i; i < 32; ++i) {
            r |= bytes32(uint256(uint8(x >> (8 * i))) << (8 * (31 - i)));
        }
    }

    function _valid() internal view returns (bytes memory k, bytes32 m, bytes memory s) {
        string memory d = ".derived[7]";
        k = vm.parseJsonBytes(sj, string.concat(d, ".keyData"));
        m = vm.parseJsonBytes32(sj, string.concat(d, ".sigs[0].message"));
        s = vm.parseJsonBytes(sj, string.concat(d, ".sigs[0].sig"));
    }

    function test_malformed() public view {
        (bytes memory k, bytes32 m, bytes memory s) = _valid();
        assertTrue(v.verify(k, m, s));
        // lengths
        assertFalse(v.verify("", m, s));
        assertFalse(v.verify(abi.encodePacked(k, uint8(0)), m, s));
        assertFalse(v.verify(_slice(k, 31), m, s));
        assertFalse(v.verify(k, m, ""));
        assertFalse(v.verify(k, m, _slice(s, 63)));
        assertFalse(v.verify(k, m, abi.encodePacked(s, uint8(0))));
        bytes32 r = bytes32(_slice(s, 32));
        // S = L, S = 2^256 − 1, S + L (same point mod L)
        uint256 sv = uint256(_le(uint256(bytes32(_at(s, 32)))));
        assertFalse(v.verify(k, m, abi.encodePacked(r, _le(L))));
        assertFalse(v.verify(k, m, abi.encodePacked(r, bytes32(type(uint256).max))));
        assertFalse(v.verify(k, m, abi.encodePacked(r, _le(sv + L))));
        // R or A: y = p + i (non-canonical, i ≤ 18), with and without the sign bit; x = 0 with the sign bit
        for (uint256 i; i < 19; ++i) {
            for (uint256 sign; sign < 2; ++sign) {
                bytes32 e = _le(P + i | sign << 255);
                assertFalse(v.verify(k, m, abi.encodePacked(e, _at(s, 32))));
                assertFalse(v.verify(abi.encodePacked(e), m, s));
            }
        }
        bytes32[2] memory x0 = [_le(1 | 1 << 255), _le(P - 1 | 1 << 255)];
        for (uint256 i; i < 2; ++i) {
            assertFalse(v.verify(k, m, abi.encodePacked(x0[i], _at(s, 32))));
            assertFalse(v.verify(abi.encodePacked(x0[i]), m, s));
        }
        // small-order A and R: the 8 torsion points
        bytes32[8] memory so = _smallOrder();
        for (uint256 i; i < 8; ++i) {
            assertFalse(v.verify(abi.encodePacked(so[i]), m, s));
            assertFalse(v.verify(k, m, abi.encodePacked(so[i], _at(s, 32))));
            assertTrue(Ed25519.smallOrderY(uint256(_le(uint256(so[i]))) & ((1 << 255) - 1)));
        }
        // off-curve A (y = 2: (y² − 1)/(d·y² + 1) is not a square), all zero, all 0xff
        assertFalse(v.verify(abi.encodePacked(_le(2)), m, s));
        assertFalse(v.verify(new bytes(32), m, new bytes(64)));
        assertFalse(v.verify(abi.encodePacked(bytes32(type(uint256).max)), m, abi.encodePacked(r, r)));
    }

    /// The canonical encodings of the 8 small-order points (UAKinds `_edSmallOrder`).
    function _smallOrder() internal pure returns (bytes32[8] memory) {
        return [
            bytes32(0x0100000000000000000000000000000000000000000000000000000000000000),
            0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0000000000000000000000000000000000000000000000000000000000000080,
            0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05,
            0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85,
            0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a,
            0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
        ];
    }

    function _slice(bytes memory b, uint256 n) internal pure returns (bytes memory r) {
        r = new bytes(n);
        for (uint256 i; i < n; ++i) {
            r[i] = b[i];
        }
    }

    function _at(bytes memory b, uint256 o) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), o))
        }
    }

    // ------------------------------------------------------------------ forge fuzz

    /// Random key, message and signature (any lengths): never reverts, never verifies.
    function testFuzz_randomNeverVerifies(bytes calldata k, bytes32 m, bytes calldata s) public view {
        assertFalse(v.verify(k, m, s));
    }

    function testFuzz_random64NeverVerifies(bytes32 k, bytes32 m, bytes32 r, bytes32 s) public view {
        assertFalse(v.verify(abi.encodePacked(k), m, abi.encodePacked(r, s)));
    }

    /// One flipped bit anywhere in (A, M, R ‖ S) of a valid signature: refused. A flip in A may give another valid
    /// key, a flip in S's top bits a value ≥ L: refused either way.
    function testFuzz_bitFlipRefused(uint256 bit) public view {
        (bytes memory k, bytes32 m, bytes memory s) = _valid();
        bit = bound(bit, 0, 128 * 8 - 1);
        if (bit < 256) k[bit / 8] ^= bytes1(uint8(1 << (bit % 8)));
        else if (bit < 512) m ^= bytes32(uint256(1) << (bit - 256));
        else s[(bit - 512) / 8] ^= bytes1(uint8(1 << (bit % 8)));
        assertFalse(v.verify(k, m, s));
    }

    // ------------------------------------------------------------------ gas

    function test_gas() public {
        (bytes memory k, bytes32 m, bytes memory s) = _valid();
        v.verify(k, m, s); // the verifier account warm: the registry pays its cold access outside the capped frame
        uint256 g = gasleft();
        assertTrue(v.verify(k, m, s));
        uint256 valid = g - gasleft();
        g = gasleft();
        assertFalse(v.verify(k, m ^ bytes32(uint256(1)), s));
        uint256 invalid = g - gasleft();
        g = gasleft();
        assertTrue(v.verify(WORST_PK, WORST_MSG, WORST_SIG));
        uint256 worst = g - gasleft();
        bytes memory sL = abi.encodePacked(bytes32(_slice(s, 32)), _le(L));
        g = gasleft();
        assertFalse(v.verify(k, m, sL));
        uint256 early = g - gasleft();
        emit log_named_uint("verify valid", valid);
        emit log_named_uint("verify invalid (other message)", invalid);
        emit log_named_uint("verify worst (all windows, sqrt(-1) branch)", worst);
        emit log_named_uint("verify early reject (S = L)", early);
        assertLe(valid, worst);
        assertLe(invalid, worst);
        assertLe(worst * 6 / 5, CAP + 5_000, "cap >= 1.2 x measured worst");
        assertLe(worst, CAP, "worst over the cap");
    }
}
