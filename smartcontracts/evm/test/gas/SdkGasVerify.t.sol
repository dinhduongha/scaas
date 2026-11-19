// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {Sha512} from "../../src/common/Sha512.sol";
import {Ed25519} from "../../src/common/Ed25519.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier,
    ZetherSchnorrBls12381Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {FndsaVerifier} from "../../src/ua/FnDsa.sol";
import {SlhdsaVerifier, SlhDsaSha2128s} from "../../src/ua/SlhDsa.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {GasBurner} from "../pqz/PqzStateGas.t.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {UACall} from "../ua/UACall.sol";
import {Vm} from "forge-std/Test.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {SdkGasRows} from "./SdkGasOps.sol";
import {BlsMultiKit} from "../ua/BlsMultiKit.sol";

/// The copy-cost forwarder (owner 2026-11-19, "OK"): what a token does with a signature, nothing else: the token's own
/// `MtxPipelineLib._authorize` (a native id: the pool and key-data guards, then `SigCheck.isValid`; a derived one: the
/// registry's `requireAuthorized`, the `UASig` copied from calldata into the call). Owner 2026-11-19 (the sampled check):
/// a bare `SigCheck.isValid` as the native reference was 938 gas cheaper than the token's native path and its derived
/// side 231 cheaper, so every verify delta stood about 707 above the token's.
contract SdkGasForwarder {
    address internal immutable REG;
    bytes32 internal immutable SKA;

    constructor(IUARegistry reg_) {
        (REG, SKA) = (address(reg_), UARegistry(address(reg_)).smartKeyCloneHash());
    }

    function check(bytes32 from, bytes32 purpose, bytes32 digest, IUARegistry.UASig calldata auth) external view {
        MtxPipelineLib.Ctx memory c;
        (c.registry, c.skaCloneCodehash) = (REG, SKA);
        MtxPipelineLib._authorize(c, from, purpose, digest, auth);
    }
}

/// A5 (owner 2026-11-19): SLH-DSA-128s's verify path as `SlhDsaSha2128s.verify` runs it, each hypertree layer's WOTS+
/// message the real one (`worst` false) or forced to 0 (`worst` true: 510 chain steps a layer, the most work any input can
/// force; `PqGas.t.sol`'s `SlhWorstCase`). The difference of the two runs is what the worst case adds over the vector.
contract SdkGasSlh {
    function run(bytes calldata pk, bytes calldata mprime, bytes calldata sig, bool worst)
        external
        view
        returns (uint256 node)
    {
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
                sig, SlhDsaSha2128s.HT_OFF + j * SlhDsaSha2128s.XMSS_LEN, worst ? 0 : node, j, idxTree, idxLeaf, b, t
            );
        }
    }
}

/// Meters a call: the gas `target` used, its frame's own.
contract SdkGasMeter {
    function run(address target, bytes calldata cd) external returns (uint256 g) {
        g = gasleft();
        (bool ok, bytes memory ret) = target.call(cd);
        g -= gasleft();
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// The verify rows of the classical kinds (owner 2026-11-19, part 3b): the execution gas of the forwarder's `check` for a
/// signer kind, its calldata subtracted, minus the native key's (the reference signer, whose path makes no registry call);
/// the generator stores the difference (both metered by `SdkGasMeter`). Real verifiers on the gen-1 caps (`UARegistryVectors.t.sol`'s registry), each UA
/// registered with its vector PoP and checked with its vector signature under `metatx`
/// (`smartcontracts/vectors/ua/signatures.json`, `derived[]`); P-256 on the 0x100 precompile. Keys `verify_<kind>`
/// (4 hex digits) and `verify_native`, the difference `verify_<kind>_delta`.
contract SdkGasVerifyTest is SdkGasRows, UARegistryBase {
    string internal sj;
    SdkGasForwarder internal fwd;
    SdkGasMeter internal meter;

    function setUp() public override {
        super.setUp();
        sj = vm.readFile("../vectors/ua/signatures.json");
        address[8] memory v = [
            address(new WebAuthnP256Verifier()),
            address(new P256Verifier()),
            address(new Ed25519Verifier()),
            address(new Bip340Verifier()),
            address(new SchnorrBn254Verifier()),
            address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()),
            address(new BlsMinSigBn254Verifier())
        ];
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](10);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
        c[8] = UARegistry.KindConfig(0x0108, address(new Secp256k1Verifier()), 50_000);
        // the Zether UA kind (owner 2026-11-19, P1): Schnorr under the Zether tag, `UALedgerBase`'s cap
        c[9] = UARegistry.KindConfig(0x0141, address(new ZetherSchnorrBls12381Verifier()), 70_000);
        // G4: the registry as a deploy configures it (`SdkGasDeploy`), these verifiers kept (the PQ precompile stand-ins);
        // the forwarder reads its `SmartKeyAccount` clone hash, as the token's pipeline does
        _sgSkaSetup(chainUidA);
        _sgDeployRegistry(REG_A, chainUidA, _withPq(c));
        reg = UARegistry(REG_A);
        fwd = new SdkGasForwarder(reg);
        meter = new SdkGasMeter();
    }

    /// The PQ kinds on the paths the registry executes (owner 2026-11-19, item 6): ML-DSA-44 / -65 / -87 on their
    /// precompiles at the SCaaS testnet's addresses, each a `GasBurner` at the calibrated price (59,000 / 100,000 / 135,000
    /// + 6 for the one message word, less 2,900: the stand-in is a cold account, a precompile a warm one), the verifier's
    /// probe answered by mocks first; SLH-DSA-128s and FN-DSA-512 / -1024 on their pure-Solidity verifiers (no precompile
    /// for them exists). Caps: `DeployBase`'s (the precompile path 250,000).
    function _withPq(UARegistry.KindConfig[] memory b) internal returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](b.length + 6);
        for (uint256 i; i < b.length; ++i) {
            c[i] = b[i];
        }
        uint16[3] memory ml = [uint16(0x0130), 0x0131, 0x0134];
        uint256[3] memory len = [uint256(1312 + 2420), 1952 + 3309, 2592 + 4627];
        uint256[3] memory price = [uint256(59_000), 100_000, 135_000];
        for (uint256 i; i < 3; ++i) {
            address at = address(uint160(0x5caa0012 + i));
            (bytes memory valid, bytes memory invalid) = (new bytes(len[i] + 32), new bytes(len[i] + 32));
            valid[0] = 0x01;
            vm.mockCall(at, bytes(""), abi.encode(uint256(1)));
            vm.mockCall(at, invalid, abi.encode(uint256(0)));
            MldsaVerifier v = new MldsaVerifier(ml[i], at, valid, invalid);
            assertEq(v.PRECOMPILE(), at, "the precompile path");
            c[b.length + i] = UARegistry.KindConfig(ml[i], address(v), 250_000);
        }
        vm.clearMockedCalls();
        for (uint256 i; i < 3; ++i) {
            vm.etch(address(uint160(0x5caa0012 + i)), address(new GasBurner(price[i] + 6 - 2_900)).code);
        }
        c[b.length + 3] = UARegistry.KindConfig(0x0133, address(new SlhdsaVerifier()), 1_400_000);
        c[b.length + 4] = UARegistry.KindConfig(0x0132, address(new FndsaVerifier(0x0132)), 2_500_000);
        c[b.length + 5] = UARegistry.KindConfig(0x0135, address(new FndsaVerifier(0x0135)), 5_250_000);
    }

    function _d(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".derived[", vm.toString(i), "].", f);
    }

    function _hex4(uint16 k) internal pure returns (string memory s) {
        bytes memory h = "0123456789abcdef";
        s = string(abi.encodePacked("0x", h[k >> 12], h[(k >> 8) & 15], h[(k >> 4) & 15], h[k & 15]));
    }

    /// The gas of `fwd`'s `check` inside the meter's call: the native key's `check` is too small for its own transaction to
    /// clear EIP-7976's calldata floor (its total sat on it), so both sides of the difference are metered alike; the
    /// meter's call overhead cancels, its copy of a longer signature counts against the kind (an upper bound).
    function _metered(string memory key, bytes memory cd) internal returns (uint256 g) {
        vm.prank(SG_RELAYER);
        g = meter.run(address(fwd), cd);
        Vm.Gas memory used = vm.lastFrameGas();
        assertEq(used.gasStateUsed, 0, "a check writes nothing");
        _pin(key, g);
    }

    /// The native key's check (the reference) and its signature's calldata (ruling 2: `verify_native_sig_bytes`).
    function _native() internal returns (uint256 n) {
        bytes32 dg = keccak256("sdk-gas-verify");
        uint256 pk = 0xA11CE;
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(pk, dg);
        bytes32 native = bytes32(uint256(uint160(vm.addr(pk))));
        n = _metered("verify_native", _cd(native, dg, a));
        _sigBytes("verify_native", native, dg, a);
    }

    function _cd(bytes32 ua, bytes32 dg, IUARegistry.UASig memory a) internal pure returns (bytes memory) {
        return abi.encodeCall(SdkGasForwarder.check, (ua, UAKinds.PURPOSE_METATX, dg, a));
    }

    /// Ruling 2 (owner 2026-11-19): the signature's length in calldata, `<key>_sig_bytes`: the call with the signer's
    /// `UASig` less the call with an empty one (the operation the SDK quotes, built with an empty signature).
    function _sigBytes(string memory key, bytes32 ua, bytes32 dg, IUARegistry.UASig memory a) internal {
        IUARegistry.UASig memory none;
        _pin(string.concat(key, "_sig_bytes"), _cd(ua, dg, a).length - _cd(ua, dg, none).length);
    }

    /// `j`'s longest `metatx` signature row in `sigs[]` of row prefix `r` (owner 2026-11-19, A5: a variable-length signature
    /// at its longest, WebAuthn's clientDataJSON; of equal lengths the first).
    function _metatxRow(string memory j, string memory r) internal view returns (string memory best) {
        uint256 n;
        for (uint256 s; vm.keyExistsJson(j, string.concat(r, "sigs[", vm.toString(s), "]")); ++s) {
            string memory p = string.concat(r, "sigs[", vm.toString(s), "].");
            if (keccak256(bytes(vm.parseJsonString(j, string.concat(p, "purpose")))) != keccak256("metatx")) continue;
            uint256 len = vm.parseJsonBytes(j, string.concat(p, "sig")).length;
            if (len > n) (n, best) = (len, p);
        }
        require(n != 0, "a metatx signature");
    }

    /// One derived kind's row: its check of the vector signature, the difference to the native key's plus `worst` (what
    /// the kind's worst case adds over the vector, A5), its sig bytes.
    function _row(uint16 kind, bytes32 ua, bytes32 dg, IUARegistry.UASig memory u, uint256 n, uint256 worst) internal {
        string memory key = string.concat("verify_", _hex4(kind));
        _pin(string.concat(key, "_delta"), _metered(key, _cd(ua, dg, u)) - n + worst); // the verify row's figure
        _sigBytes(key, ua, dg, u);
    }

    /// A5 (owner 2026-11-19): what SLH-DSA-128s's forced worst case adds over the vector `sig` of key `pk` on `uaMsg`, both
    /// paths metered alike (`SdkGasSlh`), pinned as `verify_0x0133_worst_extra`.
    function _slhWorst(bytes memory pk, bytes32 uaMsg, bytes memory sig) internal returns (uint256 extra) {
        SdkGasSlh slh = new SdkGasSlh();
        bytes memory mp = PqUA.emptyContext(PqUA.pqMessage(keccak256("scaas.ua.slhdsa128s.v1"), uaMsg));
        uint256 same = meter.run(address(slh), abi.encodeCall(SdkGasSlh.run, (pk, mp, sig, false)));
        uint256 worst = meter.run(address(slh), abi.encodeCall(SdkGasSlh.run, (pk, mp, sig, true)));
        assertGt(worst, same, "the forced case does more work");
        extra = worst - same;
        _pin("verify_0x0133_worst_extra", extra);
    }

    function _rev(uint256 v) internal pure returns (uint256 r) {
        for (uint256 i; i < 32; ++i) {
            r = (r << 8) | ((v >> (8 * i)) & 0xff);
        }
    }

    /// Owner 2026-11-19 (ruling 2 of the sampled check, case (a)): ed25519's verify gas depends on the data only through
    /// `Ed25519._straus`, which adds a point for every nonzero 4-bit window of `S` and of `k = SHA-512(R ‖ A ‖ M) mod L`
    /// (MODEXP and SHA-512 cost the same for every 32-byte message). The most work: every window 0-62 of both nonzero (a
    /// window 63 cannot be nonzero without zeroing windows 31-62, as both are below L < 2^253). Forced here: `S` with every
    /// window 1, and `R` ground until `k` has every window nonzero; the call returns false only at the final compare, after
    /// the full work. The key's own branches (the square root of -1, the parity flip) are the worst of eight keys. Pinned as
    /// `verify_0x0102_worst_extra`: the forced run less the vector's, both metered alike.
    function _edWorst(bytes memory pk, bytes32 m, bytes memory sig) internal returns (uint256 extra) {
        address v = address(new Ed25519Verifier());
        uint256 sv;
        for (uint256 i; i < 63; ++i) {
            sv |= 1 << (4 * i);
        }
        uint256 same = meter.run(v, abi.encodeCall(Ed25519Verifier.verify, (pk, m, sig)));
        uint256 worst;
        for (uint256 key; key < 8; ++key) {
            bytes memory a = key == 0 ? pk : abi.encodePacked(vm.publicKeyEd25519(keccak256(abi.encode("sg-ed", key))));
            bytes memory forced = abi.encodePacked(_edR(a, m, key), bytes32(_rev(sv)));
            uint256 g = meter.run(v, abi.encodeCall(Ed25519Verifier.verify, (a, m, forced)));
            if (g > worst) worst = g;
        }
        assertGt(worst, same, "the forced case does more work");
        extra = worst - same;
        _pin("verify_0x0102_worst_extra", extra);
    }

    /// An `R` for key `a` and message `m` whose `k = SHA-512(R ‖ A ‖ M) mod L` has every window 0-62 nonzero.
    function _edR(bytes memory a, bytes32 m, uint256 key) internal pure returns (bytes32 r) {
        uint256 r256 = (type(uint256).max % Ed25519.L + 1) % Ed25519.L; // 2^256 mod L
        for (uint256 j;; ++j) {
            r = keccak256(abi.encode("sg-ed-r", key, j));
            if (_fullWindows(_edK(r, a, m, r256))) return r;
        }
    }

    function _edK(bytes32 r, bytes memory a, bytes32 m, uint256 r256) internal pure returns (uint256) {
        (bytes32 hi, bytes32 lo) = Sha512.hash(abi.encodePacked(r, a, m));
        return addmod(mulmod(_rev(uint256(lo)), r256, Ed25519.L), _rev(uint256(hi)), Ed25519.L);
    }

    function _fullWindows(uint256 k) internal pure returns (bool) {
        for (uint256 i; i < 63; ++i) {
            if ((k >> (4 * i)) & 15 == 0) return false;
        }
        return true;
    }

    /// Owner 2026-11-19 (ruling 2 of the sampled check, case (b)): FN-DSA's verify gas depends on the data without a bound:
    /// `HashToPoint` rejection-samples SHAKE256 output (one more Keccak-f block when a salt's draws are rejected more often;
    /// no number of blocks is impossible), and the compressed `s2` decodes in a data-dependent loop. Measured as the most
    /// expensive of 64 signatures: the vector's with its 40-byte salt replaced by `keccak256("sg-fn", kind, j)` (40 bytes),
    /// each run to the final norm check (full work, false at the end), less the vector's own; pinned as
    /// `verify_<kind>_varied_extra`. The row's `margin` (the input list) is added on top.
    function _fnVaried(uint16 kind, bytes memory pk, bytes32 m, bytes memory sig) internal returns (uint256 extra) {
        address v = address(new FndsaVerifier(kind));
        uint256 same = meter.run(v, abi.encodeCall(FndsaVerifier.verify, (pk, m, sig)));
        uint256 worst = _fnMost(v, kind, pk, m, sig, "sg-fn");
        extra = worst > same ? worst - same : 0;
        _pin(string.concat("verify_", _hex4(kind), "_varied_extra"), extra);
        // the safety check (owner 2026-11-19, "approved, as proposed"): 64 further salts, never above the row with its margin
        // (`scaas-sdk` holds `verify_<kind>_safety_extra` to it)
        worst = _fnMost(v, kind, pk, m, sig, "sg-fn-safety");
        _pin(string.concat("verify_", _hex4(kind), "_safety_extra"), worst > same ? worst - same : 0);
    }

    /// The most expensive of 64 runs of the vector `sig` with its salt replaced by `keccak256(seed, kind, j)` (40 bytes).
    function _fnMost(address v, uint16 kind, bytes memory pk, bytes32 m, bytes memory sig, string memory seed)
        internal
        returns (uint256 worst)
    {
        for (uint256 j; j < 64; ++j) {
            bytes memory s = bytes.concat(sig);
            bytes memory salt = abi.encodePacked(keccak256(abi.encode(seed, kind, j)), bytes8(keccak256(abi.encode(j))));
            for (uint256 i; i < 40; ++i) {
                s[1 + i] = salt[i];
            }
            uint256 g = meter.run(v, abi.encodeCall(FndsaVerifier.verify, (pk, m, s)));
            if (g > worst) worst = g;
        }
    }

    /// What a PQ kind's worst case adds over its vector: SLH-DSA forced (A5), FN-DSA the most of 64 salts (ruling 2 (b)).
    function _pqWorst(uint16 kind, bytes memory pk, bytes32 m, bytes memory sig) internal returns (uint256) {
        if (kind == 0x0133) return _slhWorst(pk, m, sig);
        if (kind == 0x0132 || kind == 0x0135) return _fnVaried(kind, pk, m, sig);
        return 0;
    }

    /// ua-rs's cap on a WebAuthn assertion (`WEBAUTHN_MAX_ASSERTION`, owner 2026-11-19, G3): authenticatorData and
    /// clientDataJSON together at most 1,024 bytes; the chains take any length.
    uint256 internal constant SG_WA_CAP = 1_024;

    /// Q2 (owner 2026-11-19, "approved"): `0x0100`'s verify gas grows with clientDataJSON, so its row is measured at the cap.
    /// The worst case there (`WebAuthnClientData.parse`): the origin, scanned byte by byte up to its closing quote, as long as
    /// the cap leaves (`prefix ‖ origin ‖ "}`, the L2 form); the vector key's own authenticatorData (37 bytes), signed by its
    /// vector secret over `message` (the challenge), low-s. Beside it, pinned for the record and not in the row, ua-rs's
    /// cap vector's shape (`smartcontracts/vectors/ua/sign.json` `webauthn.accepted`, the row at the cap: a 21-byte origin,
    /// `crossOrigin` false, then a filler member): `verify_0x0100_cap_row` and `verify_0x0100_origin_extra`, what the long
    /// origin adds over it; and `verify_0x0100_vector`, the longest vector's check.
    function _waCap(uint256 sk, bytes32 message, bytes memory vsig, bytes memory k)
        internal
        returns (bytes memory sig)
    {
        (bytes memory ad,,,) = abi.decode(vsig, (bytes, bytes, bytes32, bytes32));
        sig = _waSign(sk, ad, _waClientData(message, ad.length, ""));
        bytes memory rowShape = _waSign(sk, ad, _waClientData(message, ad.length, "https://scaas.example"));
        address v = address(new WebAuthnP256Verifier());
        uint256 shape = _waMeter(v, k, message, rowShape);
        _pin("verify_0x0100_cap_row", shape);
        _pin("verify_0x0100_origin_extra", _waMeter(v, k, message, sig) - shape);
        _pin("verify_0x0100_vector", _waMeter(v, k, message, vsig));
    }

    /// A clientDataJSON for challenge `m` filling the cap beside `adLen` bytes of authenticatorData: with `origin` empty, an
    /// origin of `x` as long as the cap leaves (`prefix ‖ origin ‖ "}`); else that origin, `crossOrigin` false and a filler
    /// member of `x` (the cap vector's shape).
    function _waClientData(bytes32 m, uint256 adLen, bytes memory origin) internal pure returns (bytes memory cd) {
        cd = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(m)), '","origin":"', origin
        );
        if (origin.length != 0) cd = abi.encodePacked(cd, '","crossOrigin":false,"other_keys_can_be_added_here":"');
        uint256 fill = SG_WA_CAP - adLen - cd.length - 2;
        bytes memory x = new bytes(fill);
        for (uint256 i; i < fill; ++i) {
            x[i] = "x";
        }
        cd = abi.encodePacked(cd, x, '"}');
    }

    /// The verifier's `verify` of `sig`, metered (it must accept).
    function _waMeter(address v, bytes memory k, bytes32 m, bytes memory sig) internal returns (uint256 g) {
        assertTrue(WebAuthnP256Verifier(v).verify(k, m, sig), "an accepted assertion");
        g = meter.run(v, abi.encodeCall(WebAuthnP256Verifier.verify, (k, m, sig)));
    }

    /// The canonical WebAuthn assertion `abi.encode(authData, clientDataJSON, r, s)` by P-256 secret `sk`, low-s.
    function _waSign(uint256 sk, bytes memory ad, bytes memory cd) internal pure returns (bytes memory) {
        assertEq(ad.length + cd.length, SG_WA_CAP, "at the cap");
        (bytes32 r, bytes32 s_) = vm.signP256(sk, sha256(abi.encodePacked(ad, sha256(cd))));
        uint256 n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551; // the P-256 group order
        if (uint256(s_) > n / 2) s_ = bytes32(n - uint256(s_));
        return abi.encode(ad, cd, r, s_);
    }

    function test_sdkGas_verify() public {
        uint256 n = _native();
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            uint16 kind = uint16(vm.parseJsonUint(sj, _d(i, "kind")));
            // 0x0141 (owner 2026-11-19, P1): a Zether UA signs its own operations (e.g. the multi-recipient proof's UA
            // signature); its cost is the BLS12-381 G1MSM of three points and fixed-size hashes: no data dependence
            if (kind > 0x0108 && kind != 0x0141) continue;
            bytes memory k = vm.parseJsonBytes(sj, _d(i, "keyData"));
            bytes32 ua = vm.parseJsonBytes32(sj, _d(i, "ua"));
            UACall.register(reg, kind, k, _none(), vm.parseJsonBytes(sj, _d(i, "pop.sig")), "");
            string memory row = _metatxRow(sj, string.concat(".derived[", vm.toString(i), "]."));
            // a stored kind (the Zether one) signs with empty key data, as `scaas-ua` sends it
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(row, "sig"));
            // Q2 (owner 2026-11-19): WebAuthn at ua-rs's cap, its worst case (`_waCap`), instead of the longest vector
            if (kind == 0x0100) {
                sig = _waCap(
                    vm.parseJsonUint(sj, _d(i, "secret")),
                    vm.parseJsonBytes32(sj, string.concat(row, "message")),
                    sig,
                    k
                );
            }
            IUARegistry.UASig memory u = UACall.auth(ua, abi.encode(kind == 0x0141 ? bytes("") : k, sig));
            uint256 worst = kind == 0x0102
                ? _edWorst(
                    k,
                    vm.parseJsonBytes32(sj, string.concat(row, "message")),
                    vm.parseJsonBytes(sj, string.concat(row, "sig"))
                )
                : 0;
            _row(kind, ua, vm.parseJsonBytes32(sj, string.concat(row, "digest")), u, n, worst);
            ++rows;
        }
        assertEq(rows, 10, "0x0100 - 0x0108, 0x0141");
    }

    /// The PQ kinds 0x0130-0x0135 (item 6) on `smartcontracts/vectors/ua/pq_signatures.json` (context A): each registered
    /// with its vector PoP, its `metatx` signature checked with an empty `keyData` (a stored kind's `UASig`, as `scaas-ua`
    /// sends it).
    function test_sdkGas_verifyPq() public {
        string memory pj = vm.readFile("../vectors/ua/pq_signatures.json");
        uint256 n = _native();
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".kinds[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".kinds[", vm.toString(i), "].");
            uint16 kind = uint16(vm.parseJsonUint(pj, string.concat(r, "kind")));
            bytes32 ua = vm.parseJsonBytes32(pj, string.concat(r, "ua"));
            bytes memory pk = vm.parseJsonBytes(pj, string.concat(r, "keyData"));
            assertEq(
                UACall.register(reg, kind, pk, _none(), vm.parseJsonBytes(pj, string.concat(r, "pop.sig")), ""), ua
            );
            string memory row = _metatxRow(pj, r);
            IUARegistry.UASig memory u;
            u.signature = vm.parseJsonBytes(pj, string.concat(row, "sig"));
            uint256 worst = _pqWorst(kind, pk, vm.parseJsonBytes32(pj, string.concat(row, "message")), u.signature);
            _row(kind, ua, vm.parseJsonBytes32(pj, string.concat(row, "digest")), u, n, worst);
            ++rows;
        }
        assertEq(rows, 6, "0x0130 - 0x0135");
    }

    // --- bls12381-multi (0x0121), plan Task 16 (spec 2026-11-19-bls12381-multi §8.4, owner ruling R2-Q2 / I1) ---

    uint256[4] internal SG_BLS_N = [uint256(2), 16, 32, 64];

    /// A group of `n` members (unit weights, `sk` from `seed`) at threshold `t`.
    function _blsGroup(uint256 n, uint16 t, uint256 seed) internal view returns (BlsMultiKit.Group memory) {
        uint256[] memory sks = new uint256[](n);
        uint16[] memory w = new uint16[](n);
        for (uint256 i; i < n; ++i) {
            sks[i] = uint256(keccak256(abi.encode("sg-bls", seed, i)))
                % 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
            w[i] = 1;
        }
        return BlsMultiKit.group(sks, w, t);
    }

    /// `registerBlsMulti(key, none, pop, "")` of group `g`, its PoP made here (all members).
    function _blsRegisterCd(BlsMultiKit.Group memory g) internal view returns (bytes memory) {
        IUARegistry.BlsMultiKey memory key;
        (bytes[] memory keys, uint16[] memory weights) = BlsMultiKit.members(g);
        key.aggKey = BlsMultiKit._cut(g.d, 0, 256);
        key.threshold = uint16(bytes2(BlsMultiKit._cut(g.d, 256, 2)));
        key.members = new IUARegistry.BlsMultiMember[](keys.length);
        for (uint256 i; i < keys.length; ++i) {
            key.members[i] = IUARegistry.BlsMultiMember(keys[i], weights[i]);
        }
        return abi.encodeCall(
            IUARegistry.registerBlsMulti, (key, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), bytes(""))
        );
    }

    /// Owner ruling 2026-11-19 (plan Task 16, "approved"; was a plan choice): the line of a counted row from its n = 2 and
    /// n = 64 points, `per_item = ⌈(g(64) − g(2)) / 62⌉` (the worst over `g`'s rows), `gas = g(2) − 2·per_item`, checked
    /// at or above all four points. Controller call (owner auto-run 2026-11-19): where a point lies above that line (the
    /// verify row at n = 16, by 304 gas), the row's gas is raised to the largest `g(n) − per_item·n`, the slope kept; the
    /// line then stays within 1,000 gas of the n = 64 point (asserted).
    function _blsFit(uint256[4][] memory g) internal view returns (uint256 s, uint256[] memory b) {
        for (uint256 r; r < g.length; ++r) {
            uint256 c = (g[r][3] - g[r][0] + 61) / 62;
            if (c > s) s = c;
        }
        b = new uint256[](g.length);
        for (uint256 r; r < g.length; ++r) {
            b[r] = g[r][0] - 2 * s;
            for (uint256 i; i < 4; ++i) {
                if (g[r][i] - s * SG_BLS_N[i] > b[r]) b[r] = g[r][i] - s * SG_BLS_N[i];
            }
            for (uint256 i; i < 4; ++i) {
                assertGe(b[r] + s * SG_BLS_N[i], g[r][i], "the per-item line at or above every point");
            }
            assertLt(b[r] + s * 64 - g[r][3], 1_000, "the line within 1,000 of the n = 64 point");
        }
    }

    /// The `0x0121` verify row (`"item": "members"`): the forwarder's check of a hot-path signature (`verify`, as a minimal
    /// set is accepted there too) less the native key's, at n = 2, 16, 32, 64, each at the worst k of the two sides of the
    /// pinned `apk(S)` boundary (k = ⌊(n + 1)/2⌋ adds, k + 1 subtracts with the negation; unit weights, t = k); pinned
    /// `verify_0x0121_n<n>_k<k>` (metered) and `verify_0x0121_n<n>` (the worst, less the native key's); the line by
    /// `_blsFit` into `verify_0x0121_delta` (its gas at a count of 0) and `verify_0x0121_per_item` (its slope).
    function test_sdkGas_verifyBlsMulti() public {
        uint256 nat = _native();
        uint256[4][] memory g = new uint256[4][](1);
        bytes32 dg = keccak256("sdk-gas-verify-bls-multi");
        IUARegistry.UASig memory u;
        bytes32 ua;
        for (uint256 i; i < 4; ++i) {
            uint256 n = SG_BLS_N[i];
            for (uint256 k = (n + 1) / 2; k <= (n + 1) / 2 + 1 && k <= n; ++k) {
                BlsMultiKit.Group memory grp = _blsGroup(n, uint16(k), 100 * n + k);
                (bool ok,) = address(reg).call(_blsRegisterCd(grp));
                assertTrue(ok, "registerBlsMulti");
                u.signature = BlsMultiKit.sign(
                    grp, (uint256(1) << k) - 1, UAKinds.uaMessage(UAKinds.BLS12381_MULTI, UAKinds.PURPOSE_METATX, dg)
                );
                string memory key = string.concat("verify_0x0121_n", vm.toString(n), "_k", vm.toString(k));
                uint256 m = _metered(key, _cd(grp.ua, dg, u));
                if (m - nat > g[0][i]) g[0][i] = m - nat;
                ua = grp.ua;
            }
            _pin(string.concat("verify_0x0121_n", vm.toString(n)), g[0][i]);
        }
        (uint256 s, uint256[] memory b) = _blsFit(g);
        _pin("verify_0x0121_per_item", s);
        _pin("verify_0x0121_delta", b[0]);
        _sigBytes("verify_0x0121", ua, dg, u);
    }

    /// The `registerBlsMulti` base row (kind `account`, variant `registry`, `"item": "members"`): the registration of a group
    /// of n members (unit weights, t = n / 2; its PoP and calldata as `scaas-ua` builds them) by the relayer, execution gas
    /// with its state gas (`SdkGasRows._measure`), at n = 2, 16, 32, 64 (keys `account_registerBlsMulti_n<n>_<lane>_registry`):
    /// `fresh` the registry's first `0x0121` registration (the kind's list count slot new: what the SDK quotes, it reads no
    /// list), `used` one after another group's. The line by `_blsFit` over both into `account_registerBlsMulti_<fresh|used>_registry`
    /// (the gas at a count of 0) and `account_registerBlsMulti_per_item_registry`.
    function test_sdkGas_registerBlsMulti() public {
        uint256[4][] memory g = new uint256[4][](2);
        bytes memory other = _blsRegisterCd(_blsGroup(2, 1, 7));
        for (uint256 i; i < 4; ++i) {
            uint256 n = SG_BLS_N[i];
            sgCountTag = string.concat("n", vm.toString(n), "_");
            bytes memory cd = _blsRegisterCd(_blsGroup(n, uint16(n / 2), 1_000 + n));
            uint256 snap = vm.snapshotState();
            g[0][i] = _measure(_k("account", "registerBlsMulti", "fresh", "registry"), address(reg), cd);
            vm.revertToState(snap);
            (bool ok,) = address(reg).call(other);
            assertTrue(ok, "another group first");
            g[1][i] = _measure(_k("account", "registerBlsMulti", "used", "registry"), address(reg), cd);
            vm.revertToState(snap);
        }
        sgCountTag = "";
        (uint256 s, uint256[] memory b) = _blsFit(g);
        _pin("account_registerBlsMulti_per_item_registry", s);
        _pin("account_registerBlsMulti_fresh_registry", b[0]);
        _pin("account_registerBlsMulti_used_registry", b[1]);
    }
}
