// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm, console} from "forge-std/Test.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {IUAPopVerifier} from "../../../src/ua/IUAVerifier.sol";
import {P256Verifier} from "../../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../../src/ua/verifiers/Bip340Verifier.sol";

/// UA-2a ECC verifiers (accounts.md §1.9): `p256`, `webauthn-p256`, `bip340`. Positives and negatives from
/// `vectors/ua/signatures.json`, own fixtures (vm.signP256, a BIP-340 signer on vm.createWallet), the official
/// BIP-340 vectors with 32-byte messages, malformed inputs (false, never a revert), the Solidity path (P256VERIFY
/// probe failed) and gas against the §1.15 caps.
contract EccVerifiersTest is Test {
    uint256 internal constant N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    bytes32 internal constant RP_ID_HASH = keccak256("rp.example"); // any 32 bytes
    string internal constant ORIGIN = "https://wallet.example";
    // §1.15 starting caps.
    uint256 internal constant CAP_P256 = 400_000;
    uint256 internal constant CAP_WEBAUTHN = 400_000;
    uint256 internal constant CAP_BIP340 = 50_000;

    P256Verifier internal p256;
    WebAuthnP256Verifier internal webauthn;
    Bip340Verifier internal bip340;

    function setUp() public {
        p256 = new P256Verifier();
        webauthn = new WebAuthnP256Verifier();
        bip340 = new Bip340Verifier();
    }

    // ------------------------------------------------------------------ helpers

    function _msg(uint16 kind, bytes32 digest) internal pure returns (bytes32) {
        return UAKinds.uaMessage(kind, UAKinds.PURPOSE_METATX, digest);
    }

    function _p256Key(uint256 pk) internal pure returns (bytes memory) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        return abi.encodePacked(x, y);
    }

    /// Low-s ECDSA-P256 over `h`.
    function _p256Sign(uint256 pk, bytes32 h) internal pure returns (bytes32 r, bytes32 s) {
        (r, s) = vm.signP256(pk, h);
        if (uint256(s) > N_P256 / 2) s = bytes32(N_P256 - uint256(s));
    }

    function _p256Sig(uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = _p256Sign(pk, sha256(abi.encodePacked(message)));
        return abi.encodePacked(r, s);
    }

    function _authData(bytes32 rpIdHash, uint8 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(rpIdHash, flags, uint32(7));
    }

    function _clientData(bytes32 challenge, string memory tail) internal pure returns (bytes memory) {
        return abi.encodePacked(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"',
            ORIGIN,
            '"',
            tail
        );
    }

    function _waSig(uint256 pk, bytes memory authData, bytes memory clientData) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = _p256Sign(pk, sha256(abi.encodePacked(authData, sha256(clientData))));
        return abi.encode(authData, string(clientData), uint256(r), uint256(s));
    }

    function _waKey(uint256 pk) internal pure returns (bytes memory) {
        return abi.encodePacked(_p256Key(pk), RP_ID_HASH);
    }

    /// BIP-340 signing on vm.createWallet: returns the x-only key and `r ‖ s` over `m` with nonce `k`.
    function _bipSign(uint256 d, uint256 k, bytes32 m) internal returns (bytes memory key, bytes memory sig) {
        Vm.Wallet memory w = vm.createWallet(d);
        if (w.publicKeyY & 1 == 1) d = N_K1 - d;
        Vm.Wallet memory wr = vm.createWallet(k);
        if (wr.publicKeyY & 1 == 1) k = N_K1 - k;
        bytes32 t = sha256("BIP0340/challenge");
        uint256 e = uint256(sha256(abi.encodePacked(t, t, wr.publicKeyX, w.publicKeyX, m))) % N_K1;
        key = abi.encodePacked(w.publicKeyX);
        sig = abi.encodePacked(wr.publicKeyX, addmod(k, mulmod(e, d, N_K1), N_K1));
    }

    function _flip(bytes memory b, uint256 i) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[i] = c[i] ^ 0x01;
    }

    function _both(IUAPopVerifier v, bytes memory key, bytes32 m, bytes memory sig) internal view returns (bool) {
        bool a = v.verify(key, m, sig);
        assertEq(a, v.verifyPop(key, m, sig), "verifyPop == verify");
        return a;
    }

    function _gas(IUAPopVerifier v, bool pop, bytes memory key, bytes32 m, bytes memory sig)
        internal
        view
        returns (uint256 used, bool ok)
    {
        uint256 g = gasleft();
        ok = pop ? v.verifyPop(key, m, sig) : v.verify(key, m, sig);
        used = g - gasleft();
    }

    // ------------------------------------------------------------------ vectors/ua/signatures.json

    function _verifierFor(string memory name) internal view returns (IUAPopVerifier) {
        bytes32 h = keccak256(bytes(name));
        if (h == keccak256("p256")) return p256;
        if (h == keccak256("webauthn-p256")) return webauthn;
        if (h == keccak256("bip340")) return bip340;
        return IUAPopVerifier(address(0));
    }

    function test_SignatureVectors() public view {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/ua/signatures.json"));
        uint256 seen;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            string memory e = string.concat(".derived[", vm.toString(i), "]");
            IUAPopVerifier v = _verifierFor(vm.parseJsonString(j, string.concat(e, ".name")));
            if (address(v) == address(0)) continue;
            ++seen;
            _vectorEntry(j, e, v);
        }
        assertEq(seen, 3, "p256, webauthn-p256, bip340");
    }

    function _vectorEntry(string memory j, string memory e, IUAPopVerifier v) internal view {
        uint16 kind = uint16(vm.parseJsonUint(j, string.concat(e, ".kind")));
        bytes memory key = vm.parseJsonBytes(j, string.concat(e, ".keyData"));
        bytes32 ua = vm.parseJsonBytes32(j, string.concat(e, ".ua"));
        assertEq(ua, UAKinds.uaOf(kind, key), "ua");
        _pop(j, string.concat(e, ".pop"), v, kind, key, ua);
        _pop(j, string.concat(e, ".popOther"), v, kind, key, ua);
        for (uint256 k; vm.keyExistsJson(j, string.concat(e, ".sigs[", vm.toString(k), "]")); ++k) {
            string memory s = string.concat(e, ".sigs[", vm.toString(k), "]");
            bytes32 m = vm.parseJsonBytes32(j, string.concat(s, ".message"));
            assertEq(
                m,
                UAKinds.uaMessage(
                    kind,
                    vm.parseJsonBytes32(j, string.concat(s, ".purposeTag")),
                    vm.parseJsonBytes32(j, string.concat(s, ".digest"))
                ),
                s
            );
            assertTrue(v.verify(key, m, vm.parseJsonBytes(j, string.concat(s, ".sig"))), s);
        }
        for (uint256 k; vm.keyExistsJson(j, string.concat(e, ".negatives[", vm.toString(k), "]")); ++k) {
            string memory n = string.concat(e, ".negatives[", vm.toString(k), "]");
            bytes32 m = vm.parseJsonBytes32(j, string.concat(n, ".message"));
            bytes memory sig = vm.parseJsonBytes(j, string.concat(n, ".sig"));
            bool ok =
                vm.parseJsonBool(j, string.concat(n, ".verifyPop")) ? v.verifyPop(key, m, sig) : v.verify(key, m, sig);
            assertFalse(ok, vm.parseJsonString(j, string.concat(n, ".name")));
        }
    }

    function _pop(string memory j, string memory p, IUAPopVerifier v, uint16 kind, bytes memory key, bytes32 ua)
        internal
        view
    {
        string memory c = string.concat(".contexts.", vm.parseJsonString(j, string.concat(p, ".context")));
        bytes32 popDigest = UAKinds.popDigest(
            UAKinds.chainKeyHash(vm.parseJsonUint(j, string.concat(c, ".chainId"))),
            vm.parseJsonBytes32(j, string.concat(c, ".chainUid")),
            vm.parseJsonAddress(j, string.concat(c, ".registry")),
            ua,
            bytes32(0)
        );
        assertEq(popDigest, vm.parseJsonBytes32(j, string.concat(p, ".popDigest")), p);
        bytes32 m = vm.parseJsonBytes32(j, string.concat(p, ".message"));
        assertEq(m, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP, popDigest), p);
        assertTrue(v.verifyPop(key, m, vm.parseJsonBytes(j, string.concat(p, ".sig"))), p);
    }

    // ------------------------------------------------------------------ p256

    function testFuzz_P256Valid(uint256 pk, bytes32 digest) public view {
        pk = bound(pk, 1, N_P256 - 1);
        bytes32 m = _msg(UAKinds.P256, digest);
        assertTrue(_both(p256, _p256Key(pk), m, _p256Sig(pk, m)));
    }

    function test_P256Negatives() public view {
        uint256 pk = 0xA11CE;
        bytes memory key = _p256Key(pk);
        bytes32 m = _msg(UAKinds.P256, keccak256("d"));
        bytes memory sig = _p256Sig(pk, m);
        assertTrue(_both(p256, key, m, sig));
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        assertFalse(_both(p256, key, m, abi.encodePacked(r, N_P256 - uint256(s))), "high-s");
        assertFalse(_both(p256, key, m, _flip(sig, 5)), "mutated r");
        assertFalse(_both(p256, key, m, _flip(sig, 40)), "mutated s");
        assertFalse(_both(p256, key, UAKinds.uaMessage(UAKinds.P256, UAKinds.PURPOSE_MEMBER, keccak256("d")), sig));
        assertFalse(
            _both(p256, key, UAKinds.uaMessage(UAKinds.WEBAUTHN_P256, UAKinds.PURPOSE_METATX, keccak256("d")), sig)
        );
        assertFalse(_both(p256, _p256Key(pk + 1), m, sig), "other key");
        assertFalse(_both(p256, _flip(key, 63), m, sig), "off-curve key");
        assertFalse(_both(p256, abi.encodePacked(key, bytes1(0)), m, sig), "key 65");
        assertFalse(_both(p256, _slice(key, 63), m, sig), "key 63");
        assertFalse(_both(p256, key, m, abi.encodePacked(sig, bytes1(0))), "sig 65");
        assertFalse(_both(p256, key, m, _slice(sig, 63)), "sig 63");
        assertFalse(_both(p256, key, m, ""), "sig empty");
        assertFalse(_both(p256, key, m, abi.encodePacked(uint256(0), s)), "r = 0");
        assertFalse(_both(p256, key, m, abi.encodePacked(r, uint256(0))), "s = 0");
        assertFalse(_both(p256, key, m, abi.encodePacked(N_P256, s)), "r = n");
        assertFalse(_both(p256, new bytes(64), m, sig), "zero key");
        assertFalse(_both(p256, abi.encodePacked(type(uint256).max, type(uint256).max), m, sig), "key >= p");
    }

    function _slice(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) {
            c[i] = b[i];
        }
    }

    /// The probe vector of `P256Precompile` (key = G) is valid by the OZ Solidity verifier; `PRECOMPILE` iff 0x100
    /// accepts it.
    function test_P256Probe() public view {
        bytes32 h = sha256("scaas.ua.p256.probe");
        bytes32 r = 0xb73892af0c08dbba796b57346b43b924c690fa3c5e70a70904ce3285b2f4ca89;
        bytes32 s = 0x6da50c09d4911f559acd8c1bfbdb1e82b16a9ed0f53ed7f9ed3e56e1d793bef1;
        assertEq(h, 0x8708b9c1b15ea4b9eceaf938fc2b0ac2f8643b92d02c9c9d202a540a97c0f1e9);
        assertTrue(P256.verifySolidity(h, r, s, bytes32(P256.GX), bytes32(P256.GY)));
        (bool ok, bytes memory out) = address(0x100).staticcall(abi.encode(h, r, s, P256.GX, P256.GY));
        bool present = ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
        assertEq(p256.PRECOMPILE(), present);
        assertEq(webauthn.PRECOMPILE(), present);
    }

    /// Probe fails ⇒ the Solidity path. `vm.mockCall` before the deploy makes 0x100 answer as an empty account
    /// (success, no returndata) or as a liar (1 to everything); forge 1.3.5 has no `vm.setEvmVersion`, and
    /// `FOUNDRY_EVM_VERSION=prague` runs the whole suite without any 0x100.
    function test_P256ProbeFailsSolidityPath() public {
        _solidityPath(bytes(""), "empty 0x100");
    }

    function test_P256ProbeRejectsLiar() public {
        _solidityPath(abi.encode(uint256(1)), "0x100 answers 1");
    }

    function _solidityPath(bytes memory answer, string memory label) internal {
        vm.mockCall(address(0x100), bytes(""), answer);
        P256Verifier v = new P256Verifier();
        WebAuthnP256Verifier w = new WebAuthnP256Verifier();
        assertFalse(v.PRECOMPILE(), label);
        assertFalse(w.PRECOMPILE(), label);
        console.log(label);
        _solidityP256(v, label);
        _solidityWebAuthn(w, label);
    }

    function _solidityP256(P256Verifier v, string memory label) internal view {
        uint256 pk = 0xB0B;
        bytes32 m = _msg(UAKinds.P256, keccak256("fallback"));
        bytes memory key = _p256Key(pk);
        bytes memory sig = _p256Sig(pk, m);
        assertTrue(_both(v, key, m, sig), label);
        assertFalse(_both(v, key, m, _flip(sig, 40)), label);
        (uint256 gv,) = _gas(v, false, key, m, sig);
        (uint256 gw,) = _gas(v, false, key, m, _flip(sig, 40));
        console.log("  p256 Solidity path verify (valid / invalid):", gv, gw);
        assertLt(gv, CAP_P256);
        assertLt(gw, CAP_P256);
    }

    function _solidityWebAuthn(WebAuthnP256Verifier w, string memory label) internal view {
        uint256 pk = 0xB0B;
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("fallback"));
        bytes memory wsig = _waSig(pk, _authData(RP_ID_HASH, 0x05), _clientData(m, "}"));
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(wsig, (bytes, string, uint256, uint256));
        bytes memory bad = abi.encode(ad, c, r ^ 1, s);
        assertTrue(_both(w, _waKey(pk), m, wsig), label);
        assertFalse(_both(w, _waKey(pk), m, bad), label);
        (uint256 gv,) = _gas(w, false, _waKey(pk), m, wsig);
        (uint256 gw,) = _gas(w, false, _waKey(pk), m, bad);
        console.log("  webauthn Solidity path verify (valid / invalid):", gv, gw);
        assertLt(gv, CAP_WEBAUTHN);
        assertLt(gw, CAP_WEBAUTHN);
    }

    function _word(bytes memory b, uint256 o) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), o))
        }
    }

    // ------------------------------------------------------------------ webauthn-p256

    function testFuzz_WebAuthnValid(uint256 pk, bytes32 digest) public view {
        pk = bound(pk, 1, N_P256 - 1);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, digest);
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        assertTrue(_both(webauthn, _waKey(pk), m, _waSig(pk, a, _clientData(m, "}"))), "safari");
        assertTrue(_both(webauthn, _waKey(pk), m, _waSig(pk, a, _clientData(m, ',"crossOrigin":false}'))), "chrome");
    }

    function test_WebAuthnGrammar() public view {
        uint256 pk = 0xC0FFEE;
        bytes memory key = _waKey(pk);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("d"));
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        bytes memory l3 = _clientData(m, ',"crossOrigin":false,"other":1}');
        assertTrue(_both(webauthn, key, m, _waSig(pk, a, l3)), "L3 tail");
        bytes memory flags = _authData(RP_ID_HASH, 0x1d);
        assertTrue(_both(webauthn, key, m, _waSig(pk, flags, _clientData(m, "}"))), "UP|UV|BE|BS");
        assertTrue(
            _both(webauthn, key, m, _waSig(pk, abi.encodePacked(a, hex"a1b2c3"), _clientData(m, "}"))), "authData > 37"
        );
        bytes memory other = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(m)), '","origin":""}'
        );
        assertTrue(_both(webauthn, key, m, _waSig(pk, a, other)), "any origin, even empty");

        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ',"crossOrigin":true}'))), "crossOrigin true");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ', "crossOrigin":false}'))), "whitespace");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ',"x":1}'))), "member before crossOrigin");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, "} "))), "trailing");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ""))), "unterminated");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(keccak256("x"), "}"))), "other challenge");
        bytes memory create = abi.encodePacked(
            '{"type":"webauthn.create","challenge":"', Base64.encodeURL(abi.encodePacked(m)), '","origin":"o"}'
        );
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, create)), "webauthn.create");
    }

    function test_WebAuthnNegatives() public view {
        uint256 pk = 0xC0FFEE;
        bytes memory key = _waKey(pk);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("d"));
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        bytes memory cd = _clientData(m, "}");
        bytes memory sig = _waSig(pk, a, cd);
        assertTrue(_both(webauthn, key, m, sig));

        assertFalse(_both(webauthn, key, m, _waSig(pk, _authData(keccak256("other rp"), 0x05), cd)), "rpIdHash");
        assertFalse(_both(webauthn, key, m, _waSig(pk, _authData(RP_ID_HASH, 0x04), cd)), "no UP");
        assertFalse(_both(webauthn, key, m, _waSig(pk, _authData(RP_ID_HASH, 0x01), cd)), "no UV");
        assertFalse(_both(webauthn, key, m, _waSig(pk, _slice(a, 36), cd)), "authData 36");
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(sig, (bytes, string, uint256, uint256));
        assertFalse(_both(webauthn, key, m, abi.encode(ad, c, r, N_P256 - s)), "high-s");
        assertFalse(_both(webauthn, key, m, abi.encode(ad, c, r ^ 1, s)), "mutated r");
        assertFalse(_both(webauthn, key, m, abi.encode(abi.encodePacked(ad, hex"00"), c, r, s)), "authData changed");
        assertFalse(_both(webauthn, key, UAKinds.uaMessage(UAKinds.P256, UAKinds.PURPOSE_METATX, keccak256("d")), sig));
        assertFalse(_both(webauthn, _waKey(pk + 1), m, sig), "other key");
        assertFalse(_both(webauthn, _p256Key(pk), m, sig), "key 64");
        assertFalse(_both(webauthn, abi.encodePacked(key, bytes1(0)), m, sig), "key 97");
        assertFalse(_both(webauthn, abi.encodePacked(_flip(_p256Key(pk), 63), RP_ID_HASH), m, sig), "off-curve key");
        // the p256 kind's raw signature offered as a WebAuthn assertion
        assertFalse(_both(webauthn, key, m, _p256Sig(pk, m)), "raw r||s");
    }

    /// Malformed ABI blobs return false, never revert.
    function test_WebAuthnMalformedAbi() public view {
        uint256 pk = 0xC0FFEE;
        bytes memory key = _waKey(pk);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("d"));
        bytes memory sig = _waSig(pk, _authData(RP_ID_HASH, 0x05), _clientData(m, "}"));
        assertFalse(_both(webauthn, key, m, ""), "empty");
        assertFalse(_both(webauthn, key, m, new bytes(127)), "127 bytes");
        assertFalse(_both(webauthn, key, m, new bytes(128)), "zero head");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 0, type(uint256).max)), "offset max");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 0, 1 << 255)), "offset 2^255");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 32, sig.length)), "offset = length");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 32, sig.length - 31)), "offset leaves < 32");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 128, type(uint256).max)), "authData length max");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 128, sig.length)), "authData length past end");
        uint256 cdOff = _word(sig, 32);
        assertFalse(_both(webauthn, key, m, _setWord(sig, cdOff, type(uint256).max - 31)), "clientData length wraps");
        uint256 cdEnd = cdOff + 32 + _word(sig, cdOff);
        assertFalse(_both(webauthn, key, m, _slice(sig, cdEnd - 1)), "truncated clientData");
        assertFalse(
            _both(webauthn, key, m, abi.encodePacked(keccak256("a"), keccak256("b"), keccak256("c"), keccak256("d"))),
            "junk"
        );
    }

    function _setWord(bytes memory b, uint256 o, uint256 w) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        assembly ("memory-safe") {
            mstore(add(add(c, 32), o), w)
        }
    }

    // ------------------------------------------------------------------ bip340

    function test_Bip340ChallengeTag() public pure {
        assertEq(
            sha256("BIP0340/challenge"), bytes32(0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c)
        );
        assertEq((P_K1 + 1) / 4, 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c);
    }

    struct Bip {
        bytes32 key;
        bytes32 message;
        bytes sig;
        bool ok;
    }

    /// bitcoin/bips bip-0340/test-vectors.csv, rows 0–14 (the 32-byte messages; 15–18 have other lengths).
    function _bipVectors() internal pure returns (Bip[15] memory v) {
        v[0] = Bip(
            hex"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            hex"0000000000000000000000000000000000000000000000000000000000000000",
            hex"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
            true
        ); // valid
        v[1] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
            true
        ); // valid
        v[2] = Bip(
            hex"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            hex"7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
            hex"5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
            true
        ); // valid
        v[3] = Bip(
            hex"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
            hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            hex"7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
            true
        ); // test fails if msg is reduced modulo p or n
        v[4] = Bip(
            hex"d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
            hex"4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
            hex"00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
            true
        ); // valid
        v[5] = Bip(
            hex"eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // public key not on the curve
        v[6] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
            false
        ); // has_even_y(R) is false
        v[7] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
            false
        ); // negated message
        v[8] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
            false
        ); // negated s value
        v[9] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
            false
        ); // sG - eP is infinite (fails if has_even_y(inf) is defined as true and x(inf) as 0)
        v[10] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
            false
        ); // sG - eP is infinite (fails if has_even_y(inf) is defined as true and x(inf) as 1)
        v[11] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // sig[0:32] is not an X coordinate on the curve
        v[12] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // sig[0:32] is equal to field size
        v[13] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            false
        ); // sig[32:64] is equal to curve order
        v[14] = Bip(
            hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // public key is not a valid X coordinate because it exceeds the field size
    }

    function test_Bip340OfficialVectors() public view {
        Bip[15] memory v = _bipVectors();
        for (uint256 i; i < v.length; ++i) {
            assertEq(_both(bip340, abi.encodePacked(v[i].key), v[i].message, v[i].sig), v[i].ok, vm.toString(i));
        }
    }

    function testFuzz_Bip340Valid(uint256 d, uint256 k, bytes32 digest) public {
        d = bound(d, 1, N_K1 - 1);
        k = bound(k, 1, N_K1 - 1);
        bytes32 m = _msg(UAKinds.BIP340, digest);
        (bytes memory key, bytes memory sig) = _bipSign(d, k, m);
        assertTrue(_both(bip340, key, m, sig));
        assertFalse(_both(bip340, key, m, _flip(sig, 63)), "mutated s");
        assertFalse(_both(bip340, key, _msg(UAKinds.BIP340, ~digest), sig), "other message");
    }

    function test_Bip340Negatives() public {
        bytes32 m = _msg(UAKinds.BIP340, keccak256("d"));
        (bytes memory key, bytes memory sig) = _bipSign(0xD00D, 0x1234, m);
        assertTrue(_both(bip340, key, m, sig));
        (uint256 r, uint256 s) = abi.decode(sig, (uint256, uint256));
        assertFalse(_both(bip340, key, m, abi.encodePacked(r, N_K1)), "s = n");
        assertFalse(_both(bip340, key, m, abi.encodePacked(r, N_K1 - s)), "negated s");
        assertFalse(_both(bip340, key, m, abi.encodePacked(P_K1, s)), "r = p");
        assertFalse(_both(bip340, abi.encodePacked(P_K1), m, sig), "key = p");
        assertFalse(_both(bip340, abi.encodePacked(uint256(5)), m, sig), "key off curve (x = 5)");
        assertFalse(_both(bip340, new bytes(32), m, sig), "key 0");
        assertFalse(_both(bip340, abi.encodePacked(key, bytes1(0)), m, sig), "key 33");
        assertFalse(_both(bip340, abi.encodePacked(bytes1(0x02), key), m, sig), "compressed key");
        assertFalse(_both(bip340, key, m, abi.encodePacked(sig, bytes1(0))), "sig 65");
        assertFalse(_both(bip340, key, m, _slice(sig, 63)), "sig 63");
        assertFalse(_both(bip340, key, m, ""), "sig empty");
        assertFalse(_both(bip340, key, m, new bytes(64)), "sig 0");
        assertFalse(_both(bip340, key, UAKinds.uaMessage(UAKinds.BIP340, UAKinds.PURPOSE_POP, keccak256("d")), sig));
    }

    // ------------------------------------------------------------------ gas

    function test_Gas() public {
        bytes32 d = keccak256("gas");
        uint256 pk = 0xA11CE;
        bytes32 m = _msg(UAKinds.P256, d);
        bytes memory key = _p256Key(pk);
        bytes memory sig = _p256Sig(pk, m);
        _report("p256", p256, key, m, sig, _flip(sig, 40), CAP_P256);

        m = _msg(UAKinds.WEBAUTHN_P256, d);
        key = _waKey(pk);
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        sig = _waSig(pk, a, _clientData(m, ',"crossOrigin":false}'));
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(sig, (bytes, string, uint256, uint256));
        _report("webauthn-p256", webauthn, key, m, sig, abi.encode(ad, c, r ^ 1, s), CAP_WEBAUTHN);

        m = _msg(UAKinds.BIP340, d);
        (key, sig) = _bipSign(0xD00D, 0x1234, m);
        _report("bip340", bip340, key, m, sig, _flip(sig, 63), CAP_BIP340);
    }

    function _report(
        string memory name,
        IUAPopVerifier v,
        bytes memory key,
        bytes32 m,
        bytes memory sig,
        bytes memory bad,
        uint256 cap
    ) internal view {
        v.verify(key, m, sig); // warm the verifier account: the numbers below exclude the 2,500 cold-access surcharge
        (uint256 gv, bool okv) = _gas(v, false, key, m, sig);
        (uint256 gp, bool okp) = _gas(v, true, key, m, sig);
        (uint256 gb, bool okb) = _gas(v, false, key, m, bad);
        assertTrue(okv && okp && !okb, name);
        console.log(name);
        console.log("  verify / verifyPop (valid), verify (invalid sig):", gv, gp, gb);
        assertLt(gv, cap, name);
        assertLt(gp, cap, name);
        assertLt(gb, cap, name);
    }

    /// With the probed precompile an invalid P-256 signature costs one precompile call, not the Solidity verifier.
    function test_P256InvalidCheapWithPrecompile() public {
        vm.skip(!p256.PRECOMPILE());
        uint256 pk = 0xA11CE;
        bytes32 m = _msg(UAKinds.P256, keccak256("gas"));
        bytes memory key = _p256Key(pk);
        p256.verify(key, m, ""); // warm
        (uint256 g, bool ok) = _gas(p256, false, key, m, _flip(_p256Sig(pk, m), 40));
        assertFalse(ok);
        assertLt(g, 20_000, "p256 invalid");
        m = _msg(UAKinds.WEBAUTHN_P256, keccak256("gas"));
        bytes memory wsig = _waSig(pk, _authData(RP_ID_HASH, 0x05), _clientData(m, "}"));
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(wsig, (bytes, string, uint256, uint256));
        webauthn.verify(_waKey(pk), m, ""); // warm
        (g, ok) = _gas(webauthn, false, _waKey(pk), m, abi.encode(ad, c, r ^ 1, s));
        assertFalse(ok);
        assertLt(g, 40_000, "webauthn invalid");
    }
}
