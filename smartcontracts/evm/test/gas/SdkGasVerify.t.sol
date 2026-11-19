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
    BlsMinSigBn254Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {FndsaVerifier} from "../../src/ua/FnDsa.sol";
import {SlhdsaVerifier, SlhDsaSha2128s} from "../../src/ua/SlhDsa.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {GasBurner} from "../pqz/PqzStateGas.t.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {UACall} from "../ua/UACall.sol";
import {Vm} from "forge-std/Test.sol";
import {SdkGasRows} from "./SdkGasOps.sol";

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
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](9);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
        c[8] = UARegistry.KindConfig(0x0108, address(new Secp256k1Verifier()), 50_000);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _withPq(c));
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
        uint256 worst;
        for (uint256 j; j < 64; ++j) {
            bytes memory s = bytes.concat(sig);
            bytes memory salt =
                abi.encodePacked(keccak256(abi.encode("sg-fn", kind, j)), bytes8(keccak256(abi.encode(j))));
            for (uint256 i; i < 40; ++i) {
                s[1 + i] = salt[i];
            }
            uint256 g = meter.run(v, abi.encodeCall(FndsaVerifier.verify, (pk, m, s)));
            if (g > worst) worst = g;
        }
        extra = worst > same ? worst - same : 0;
        _pin(string.concat("verify_", _hex4(kind), "_varied_extra"), extra);
    }

    /// What a PQ kind's worst case adds over its vector: SLH-DSA forced (A5), FN-DSA the most of 64 salts (ruling 2 (b)).
    function _pqWorst(uint16 kind, bytes memory pk, bytes32 m, bytes memory sig) internal returns (uint256) {
        if (kind == 0x0133) return _slhWorst(pk, m, sig);
        if (kind == 0x0132 || kind == 0x0135) return _fnVaried(kind, pk, m, sig);
        return 0;
    }

    function test_sdkGas_verify() public {
        uint256 n = _native();
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            uint16 kind = uint16(vm.parseJsonUint(sj, _d(i, "kind")));
            if (kind > 0x0108) continue; // the stored Zether kind signs no SCaaS op
            bytes memory k = vm.parseJsonBytes(sj, _d(i, "keyData"));
            bytes32 ua = vm.parseJsonBytes32(sj, _d(i, "ua"));
            UACall.register(reg, kind, k, _none(), vm.parseJsonBytes(sj, _d(i, "pop.sig")), "");
            string memory row = _metatxRow(sj, string.concat(".derived[", vm.toString(i), "]."));
            IUARegistry.UASig memory u =
                UACall.auth(ua, abi.encode(k, vm.parseJsonBytes(sj, string.concat(row, "sig"))));
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
        assertEq(rows, 9, "0x0100 - 0x0108");
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
}
