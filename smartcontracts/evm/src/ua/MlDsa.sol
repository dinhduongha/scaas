// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUAKindVerifier, PqUA} from "./PqUA.sol";
import {Shake} from "./Shake.sol";
import {PqNtt} from "./PqNtt.sol";

/// @title ML-DSA-44 / ML-DSA-65 verification (FIPS 204 Algorithm 8 `ML-DSA.Verify_internal`).
/// @notice Two key forms, one core: the FIPS 204 public key `ρ ‖ t1` (EIP-8355's encoding; `Â = ExpandA(ρ)`,
///         `tr = H(pk, 64)` and `NTT(t1·2^d)` computed per call) and the EIP-8051 expanded key
///         `Â ‖ tr ‖ NTT(t1·2^d)` (coefficients u32 big-endian, `Â` row-major, the FIPS 64-byte `tr`: the layout of
///         EIP-8051's reference implementation; its text says a 32-byte `tr`, 20,512 B). `mPrime` is the formatted
///         message `M'` (pure interface: `0 ‖ |ctx| ‖ ctx ‖ M`). Requires `Shake.reserve()` first. **UNAUDITED.**
library MlDsa {
    uint256 internal constant Q = 8380417;
    uint256 internal constant N = 256;
    /// FIPS 204 `zetas[k] = 1753^brv8(k) mod q`, k = 0..255, u32 big-endian (ζ = 1753, a primitive 512-th root of unity).
    bytes internal constant ZETAS = hex"0000000100495e020039756700396569004f062b0053df73004fe033004f066b0076b1ae00360dd50028edb000207fe4003972830070894a00088192006d3dc8004c72940041e0b40028a3d20066528a004a18a700794034000a52ee006b7d81004e9f1d001a2877002571df001649ee007611bd00492bb7002af6970022d8d50036f72a0030911e0029d13f004926730050685f002010a2003887f70011b2c3000603a4000e2bed0010b72c004a5f35001f9d1500428cd4003177f40020e61200341c1d001ad873007366810049553f003952f60062564a0065ad0500439a1c0053aa5f0030b62200087f38003b0e6d002c83da001c496e00330e2b001c5b70002ee3f100137eb90057a930003ac6ef003fd54c004eb2ea00503ee1007bb175002648b4001ef256001d90a20045a6d4002ae59b0052589c006ef1f5003f72880017510200075d59001187ba0052aca900773e9e000296d8002592ec004cff1200404ce8004aa582001e54e6004f16c1001a7e790003978f004e48170031b859005884cc001b4827005b63d0005d787a0035225e00400c7e006c09d1005bd532006bc4d300258ecb002e534c00097a6c003b8820006d285c002ca4f800337caa0014b2a0005585360028f1860055795d004af67000234a860075e8260078de660005528c007adf59000f6e17005bf3da00459b7e00628b34005dbecb001a9e7b000006d9006257c500574b3c0069a8ef002898380064b5fe007ef8f5002a4e7800120a23000154a80009b7ff00435e8700437ff8005cd5b4004dc04e004728af007f735d000c8d0d000f66d5005a6d800061ab9800185d9600437f310046829800662960004bd5790028de0600465d8d0049b0e30009b434007c0db3005a68b000409ba90064d3d50021762a0065859100246e390048c39b007bc759004f585900392db2002309230012eb6700454df20030c31c002854240013232e007faf80002dbfcb00022a0b007e832c0026587a006b337500095b76006be1cc005e061e0078e00d00628c37003da604004ae53c001f1d68006330bb007361b8005ea06c00671ac700201fc6005ba4ff0060d7720008f201006de02400080e6d0056038e00695688001e6d3e002603bd006a9dfa0007c017006dbfd40074d0bd0063e1e300519573007ab60d002867ba002decd40058018c003f4cf5000b700900427e23003cbd370027333300673957001a4b5d00196926001ef2060011c14e004c76c8003cf42f007fb19a006af66c002e1669003352d6000347600008526000741e78002f6316006f0a110007c0f100776d0b000d1ff000345824000223d40068c559005e8885002faa320023fc65005e69420051e0ed0065adb3002ca5e60079e1fe007b40640035e1dd00433aac00464ade001cfe140073f1ce0010170e0074b6d7";

    struct Params {
        uint256 k;
        uint256 l;
        uint256 tau;
        uint256 beta;
        uint256 gamma1;
        uint256 gamma2;
        uint256 omega;
        uint256 ctLen; // λ/4: length of c~
        uint256 zBits; // 1 + log2 γ1
        uint256 w1Bits; // bitlen((q − 1)/(2γ2) − 1)
        uint256 pkLen;
        uint256 sigLen;
    }

    function params44() internal pure returns (Params memory) {
        return Params(4, 4, 39, 78, 1 << 17, (Q - 1) / 88, 80, 32, 18, 6, 1312, 2420);
    }

    function params65() internal pure returns (Params memory) {
        return Params(6, 5, 49, 196, 1 << 19, (Q - 1) / 32, 55, 48, 20, 4, 1952, 3309);
    }

    /// Length of the EIP-8051-style expanded key: `Â` (k·l polynomials) ‖ tr (64) ‖ NTT(t1·2^d) (k polynomials).
    function expandedLen(Params memory P) internal pure returns (uint256) {
        return (P.k * P.l + P.k) * 1024 + 64;
    }

    /// Verify against the FIPS 204 public key.
    function verify(Params memory P, bytes calldata pk, bytes memory mPrime, bytes calldata sig)
        internal pure returns (bool)
    {
        if (pk.length != P.pkLen) return false;
        return _verify(P, pk, false, mPrime, sig);
    }

    /// Verify against the expanded key (every coefficient must be `< q`).
    /// @dev Trust: only an expanded key the caller derived itself with `expandKey(pk)` from an authenticated `pk`. The
    ///      layout holds no ρ and nothing ties `Â`, `tr`, `t̂1` together, so a caller-supplied key allows universal
    ///      forgery: `Â = 0, t̂1 = 0` (any `tr`) accepts `z = 0, h = 0` for any message, and the victim's own `tr`, `t̂1`
    ///      with `Â[i][0] = t̂1_i`, `Â[i][j>0] = 0` accepts `z = (c, 0, …)` for any message.
    function verifyExpanded(Params memory P, bytes calldata ek, bytes memory mPrime, bytes calldata sig)
        internal pure returns (bool)
    {
        if (ek.length != expandedLen(P)) return false;
        return _verify(P, ek, true, mPrime, sig);
    }

    /// The expanded key of a FIPS 204 public key (what EIP-8051's precompile and a stored-key verifier take).
    /// @dev The only trustworthy source of an expanded key: never accept one from a caller (see `verifyExpanded`).
    function expandKey(Params memory P, bytes calldata pk) internal pure returns (bytes memory ek) {
        require(pk.length == P.pkLen, "MlDsa: pk length");
        ek = new bytes(expandedLen(P));
        uint256 dst;
        assembly ("memory-safe") {
            dst := add(ek, 32)
        }
        uint256 z = PqNtt.table(ZETAS, 4);
        uint256 a = PqNtt.alloc(N);
        uint256 buf = PqNtt.alloc(6);
        for (uint256 i; i < P.k; ++i) {
            for (uint256 j; j < P.l; ++j) {
                _expandA(bytes32(pk[0:32]), j, i, a, buf);
                dst = _put(a, dst);
            }
        }
        // tr: `hash` writes a whole block (160 bytes) for these 64; the overrun lands in the t̂1 region, which the loop
        // below overwrites afterwards (correct only because of this write order).
        Shake.hash(Shake.SHAKE256, _copy(pk), pk.length, dst, 64);
        dst += 64;
        for (uint256 i; i < P.k; ++i) {
            _t1Hat(pk, i, a, z);
            PqNtt.reduce(a, N, Q);
            dst = _put(a, dst);
        }
    }

    // ------------------------------------------------------------------ core

    /// Working buffers of one verification (memory pointers; keeps the stack shallow).
    struct Work {
        uint256 zetas;
        uint256 c; // NTT(c)
        uint256 acc;
        uint256 a;
        uint256 buf;
        uint256 w; // μ ‖ w1Encode(w'_1)
        uint256[] zh; // NTT(z_j)
        uint256[] h; // hint masks
    }

    function _verify(Params memory P, bytes calldata key, bool expanded, bytes memory mPrime, bytes calldata sig)
        private pure returns (bool)
    {
        if (sig.length != P.sigLen) return false;
        Work memory W;
        bool ok;
        (ok, W.h) = _hints(P, sig[P.ctLen + P.l * 32 * P.zBits:]);
        if (!ok) return false;
        W.zetas = PqNtt.table(ZETAS, 4);
        W.zh = new uint256[](P.l);
        for (uint256 j; j < P.l; ++j) {
            W.zh[j] = PqNtt.alloc(N);
            if (!_decodeZ(P, sig[P.ctLen + j * 32 * P.zBits:], W.zh[j])) return false; // ‖z‖∞ ≥ γ1 − β
            PqNtt.ntt(W.zh[j], N, Q, W.zetas);
        }
        W.w = PqNtt.alloc(3 + P.k * P.w1Bits);
        _mu(P, key, expanded, mPrime, W.w); // μ in the first 64 bytes of w
        W.c = _sampleInBall(P, sig[0:P.ctLen]);
        PqNtt.ntt(W.c, N, Q, W.zetas);
        W.acc = PqNtt.alloc(N);
        W.a = PqNtt.alloc(N);
        W.buf = PqNtt.alloc(6);
        for (uint256 i; i < P.k; ++i) {
            if (!_row(P, key, expanded, W, i)) return false;
        }
        Shake.hash(Shake.SHAKE256, W.w, 64 + P.k * 32 * P.w1Bits, W.buf, P.ctLen);
        return _sameCt(W.buf, sig[0:P.ctLen]);
    }

    /// μ = H(tr ‖ M', 64) written at `out` (`tr` from the expanded key, or H(pk, 64)).
    function _mu(Params memory P, bytes calldata key, bool expanded, bytes memory mPrime, uint256 out) private pure {
        uint256 trm = PqNtt.alloc(3 + (mPrime.length + 31) / 32);
        if (expanded) {
            uint256 o = P.k * P.l * 1024;
            assembly ("memory-safe") {
                calldatacopy(trm, add(key.offset, o), 64)
            }
        } else {
            uint256 tmp = PqNtt.alloc(6);
            Shake.hash(Shake.SHAKE256, _copy(key), key.length, tmp, 64);
            assembly ("memory-safe") {
                mcopy(trm, tmp, 64)
            }
        }
        assembly ("memory-safe") {
            mcopy(add(trm, 64), add(mPrime, 32), mload(mPrime))
        }
        uint256 tmp2 = PqNtt.alloc(6);
        Shake.hash(Shake.SHAKE256, trm, 64 + mPrime.length, tmp2, 64);
        assembly ("memory-safe") {
            mcopy(out, tmp2, 64)
        }
    }

    /// Row i: w'_i = INTT(Σ_j Â[i][j]∘ẑ_j − ĉ∘NTT(t1_i·2^d)), then UseHint and w1Encode into `W.w`.
    function _row(Params memory P, bytes calldata key, bool expanded, Work memory W, uint256 i)
        private pure returns (bool)
    {
        uint256 acc = W.acc;
        uint256 a = W.a;
        assembly ("memory-safe") {
            calldatacopy(acc, calldatasize(), 8192) // zero
        }
        for (uint256 j; j < P.l; ++j) {
            if (expanded) {
                if (!_get(key, (i * P.l + j) * 1024, a)) return false;
            } else {
                _expandA(bytes32(key[0:32]), j, i, a, W.buf);
            }
            _mulAcc(acc, a, W.zh[j]);
        }
        if (expanded) {
            if (!_get(key, P.k * P.l * 1024 + 64 + i * 1024, a)) return false;
        } else {
            _t1Hat(key, i, a, W.zetas);
        }
        PqNtt.mulPoint(a, W.c, N, Q); // c·t1·2^d in the NTT domain
        _sub(acc, a);
        PqNtt.intt(acc, N, Q, W.zetas);
        _useHintEncode(P, acc, W.h[i], W.w + 64 + i * 32 * P.w1Bits);
        return true;
    }

    /// The first `ct.length` (32 or 48) bytes at `buf` equal `ct`.
    function _sameCt(uint256 buf, bytes calldata ct) private pure returns (bool same) {
        assembly ("memory-safe") {
            same := eq(mload(buf), calldataload(ct.offset))
            if eq(ct.length, 48) {
                let hi := not(sub(shl(128, 1), 1))
                same := and(same, eq(and(mload(add(buf, 32)), hi), and(calldataload(add(ct.offset, 32)), hi)))
            }
        }
    }

    // ------------------------------------------------------------------ pieces

    /// RejNTTPoly(ρ ‖ s ‖ r) (Algorithms 30, 32) into `a`.
    function _expandA(bytes32 rho, uint256 s, uint256 r, uint256 a, uint256 buf) private pure {
        uint256 seed = PqNtt.alloc(2);
        assembly ("memory-safe") {
            mstore(seed, rho)
            mstore8(add(seed, 32), s)
            mstore8(add(seed, 33), r)
        }
        Shake.absorb(Shake.SHAKE128, seed, 34);
        uint256 i;
        while (i < N) {
            Shake.squeeze(Shake.SHAKE128, buf);
            assembly ("memory-safe") {
                for { let o := 0 } and(lt(o, 168), lt(i, N)) { o := add(o, 3) } {
                    let x := shr(232, mload(add(buf, o))) // b0 ‖ b1 ‖ b2
                    let v := or(or(shl(16, and(x, 0x7f)), and(x, 0xff00)), shr(16, x))
                    if lt(v, Q) {
                        mstore(add(a, shl(5, i)), v)
                        i := add(i, 1)
                    }
                }
            }
        }
    }

    /// NTT(t1_i · 2^13) from the public key (10-bit little-endian coefficients after ρ).
    function _t1Hat(bytes calldata pk, uint256 i, uint256 a, uint256 z) private pure {
        uint256 base;
        assembly ("memory-safe") {
            base := add(pk.offset, add(32, mul(i, 320)))
        }
        assembly ("memory-safe") {
            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
                let bit := mul(c, 10)
                let v := and(shr(and(bit, 7), _le4(calldataload(add(base, shr(3, bit))))), 0x3ff)
                mstore(add(a, shl(5, c)), mulmod(v, 8192, Q))
            }
            function _le4(w) -> x {
                x := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
            }
        }
        PqNtt.ntt(a, N, Q, z);
    }

    /// z_j from the signature: γ1 − (zBits-bit little-endian value), stored mod q; false iff ‖z_j‖∞ ≥ γ1 − β.
    function _decodeZ(Params memory P, bytes calldata enc, uint256 out) private pure returns (bool ok) {
        uint256 g1 = P.gamma1;
        uint256 bound = P.gamma1 - P.beta;
        uint256 bits = P.zBits;
        // forge-lint: disable-next-line(incorrect-shift)
        uint256 mask = (1 << bits) - 1;
        ok = true;
        assembly ("memory-safe") {
            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
                let bit := mul(c, bits)
                let w := calldataload(add(enc.offset, shr(3, bit)))
                let x := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                let v := and(shr(and(bit, 7), x), mask) // z = γ1 − v ∈ (−γ1, γ1]
                let zz
                switch gt(v, g1)
                case 0 {
                    zz := sub(g1, v)
                    if iszero(lt(zz, bound)) { ok := 0 }
                }
                default {
                    let m := sub(v, g1) // |z|
                    if iszero(lt(m, bound)) { ok := 0 }
                    zz := sub(Q, m)
                }
                mstore(add(out, shl(5, c)), zz)
            }
        }
    }

    /// HintBitUnpack (Algorithm 21): one 256-bit mask per row; false on a malformed hint.
    function _hints(Params memory P, bytes calldata y) private pure returns (bool ok, uint256[] memory h) {
        h = new uint256[](P.k);
        uint256 omega = P.omega;
        uint256 idx;
        for (uint256 i; i < P.k; ++i) {
            uint256 end = uint8(y[omega + i]);
            if (end < idx || end > omega) return (false, h);
            uint256 first = idx;
            uint256 mask;
            while (idx < end) {
                uint256 pos = uint8(y[idx]);
                if (idx > first && uint8(y[idx - 1]) >= pos) return (false, h);
                // forge-lint: disable-next-line(incorrect-shift)
                mask |= 1 << pos;
                ++idx;
            }
            h[i] = mask;
        }
        for (; idx < omega; ++idx) if (y[idx] != 0) return (false, h);
        return (true, h);
    }

    /// SampleInBall(c~) (Algorithm 29) with SHAKE256 over the whole c~.
    function _sampleInBall(Params memory P, bytes calldata ct) private pure returns (uint256 c) {
        c = PqNtt.alloc(N);
        uint256 seed = PqNtt.alloc(2);
        assembly ("memory-safe") {
            calldatacopy(seed, ct.offset, ct.length)
        }
        Shake.absorb(Shake.SHAKE256, seed, ct.length);
        uint256 buf = PqNtt.alloc(6);
        Shake.squeeze(Shake.SHAKE256, buf);
        uint256 signs;
        assembly ("memory-safe") {
            let s := shr(192, mload(buf)) // 8 bytes, little-endian bit order
            signs := or(or(or(byte(24, s), shl(8, byte(25, s))), or(shl(16, byte(26, s)), shl(24, byte(27, s)))),
                or(or(shl(32, byte(28, s)), shl(40, byte(29, s))), or(shl(48, byte(30, s)), shl(56, byte(31, s)))))
        }
        uint256 pos = 8;
        uint256 tau = P.tau;
        for (uint256 i = N - tau; i < N; ++i) {
            uint256 j;
            while (true) {
                if (pos == 136) {
                    Shake.squeeze(Shake.SHAKE256, buf);
                    pos = 0;
                }
                assembly ("memory-safe") {
                    j := byte(0, mload(add(buf, pos)))
                }
                ++pos;
                if (j <= i) break;
            }
            assembly ("memory-safe") {
                let pj := add(c, shl(5, j))
                mstore(add(c, shl(5, i)), mload(pj))
                switch and(shr(sub(add(i, tau), N), signs), 1)
                case 0 { mstore(pj, 1) }
                default { mstore(pj, sub(Q, 1)) }
            }
        }
    }

    /// acc += a ∘ b (pointwise mod q).
    function _mulAcc(uint256 acc, uint256 a, uint256 b) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 8192) { i := add(i, 32) } {
                let p := add(acc, i)
                mstore(p, addmod(mload(p), mulmod(mload(add(a, i)), mload(add(b, i)), Q), Q))
            }
        }
    }

    /// acc −= a (mod q).
    function _sub(uint256 acc, uint256 a) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 8192) { i := add(i, 32) } {
                let p := add(acc, i)
                mstore(p, addmod(mload(p), sub(Q, mload(add(a, i))), Q))
            }
        }
    }

    /// UseHint (Algorithms 36, 40) on row `r` with hint mask `hm`, then SimpleBitPack(w1Bits) little-endian at `out`.
    function _useHintEncode(Params memory P, uint256 r, uint256 hm, uint256 out) private pure {
        uint256 g2 = P.gamma2;
        uint256 m = (Q - 1) / (2 * g2);
        uint256 bits = P.w1Bits;
        assembly ("memory-safe") {
            let twoG2 := shl(1, g2)
            let accBits := 0
            let accN := 0
            let o := out
            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
                let x := mload(add(r, shl(5, c)))
                let r0p := mod(x, twoG2)
                let diff := sub(x, r0p)
                if gt(r0p, g2) { diff := add(diff, twoG2) }
                let r1 := div(diff, twoG2)
                if eq(diff, sub(Q, 1)) { r1 := 0 }
                if and(shr(c, hm), 1) {
                    switch and(gt(r0p, 0), iszero(gt(r0p, g2)))
                    case 1 { r1 := mod(add(r1, 1), m) }
                    default { r1 := mod(add(r1, sub(m, 1)), m) }
                }
                accBits := or(accBits, shl(accN, r1))
                accN := add(accN, bits)
                for {} iszero(lt(accN, 8)) {} {
                    mstore8(o, and(accBits, 0xff))
                    o := add(o, 1)
                    accBits := shr(8, accBits)
                    accN := sub(accN, 8)
                }
            }
        }
    }

    /// Reads polynomial `off` (bytes) of the expanded key: 256 × u32 big-endian, each `< q`.
    function _get(bytes calldata ek, uint256 off, uint256 a) private pure returns (bool ok) {
        ok = true;
        assembly ("memory-safe") {
            let s := add(ek.offset, off)
            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
                let v := shr(224, calldataload(add(s, shl(2, c))))
                if iszero(lt(v, Q)) { ok := 0 }
                mstore(add(a, shl(5, c)), v)
            }
        }
    }

    /// Writes polynomial `a` as 256 × u32 big-endian at `dst`; returns the next write position.
    function _put(uint256 a, uint256 dst) private pure returns (uint256) {
        assembly ("memory-safe") {
            for { let c := 0 } lt(c, N) { c := add(c, 8) } {
                let w := 0
                for { let t := 0 } lt(t, 8) { t := add(t, 1) } {
                    w := or(shl(32, w), mload(add(a, shl(5, add(c, t)))))
                }
                mstore(add(dst, shl(2, c)), w)
            }
        }
        return dst + 1024;
    }

    function _copy(bytes calldata b) private pure returns (uint256 p) {
        p = PqNtt.alloc((b.length + 31) / 32);
        assembly ("memory-safe") {
            calldatacopy(p, b.offset, b.length)
        }
    }
}

/// @title `mldsa44` / `mldsa65` UA verifier (accounts.md CTR-UA-23, kinds 0x0130 / 0x0131): FIPS 204 ML-DSA over
///        `pq_msg` with the empty context, on the FIPS 204 public key (`keyData`). An EIP-8355 precompile is used when
///        the constructor's probe of `candidate` passes (`pk ‖ sig ‖ pq_msg` ⇒ exactly the word 1, a flipped
///        signature ⇒ exactly 0), else pure Solidity. **UNAUDITED.**
contract UAMldsaVerifier is IUAKindVerifier {
    uint16 public immutable KIND;
    bytes32 public immutable KIND_TAG;
    address public immutable PRECOMPILE; // 0 = pure Solidity

    error UAMldsaKind(uint16 kind);

    /// @param probeValid an input `pk ‖ sig ‖ msg` in the EIP-8355 layout that verifies; `probeInvalid` one that does not.
    ///        Both must be exactly `pkLen + sigLen + 32` bytes of this level (the split `verify` sends), else pure Solidity.
    constructor(uint16 kind_, address candidate, bytes memory probeValid, bytes memory probeInvalid) {
        if (kind_ != PqUA.MLDSA44 && kind_ != PqUA.MLDSA65) revert UAMldsaKind(kind_);
        KIND = kind_;
        KIND_TAG = PqUA.tag(kind_);
        MlDsa.Params memory P = kind_ == PqUA.MLDSA44 ? MlDsa.params44() : MlDsa.params65();
        uint256 len = P.pkLen + P.sigLen + 32;
        bool exact = probeValid.length == len && probeInvalid.length == len;
        PRECOMPILE = exact && PqUA.probe(candidate, probeValid, probeInvalid) ? candidate : address(0);
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        Shake.reserve(); // first allocation of the frame
        MlDsa.Params memory P = KIND == PqUA.MLDSA44 ? MlDsa.params44() : MlDsa.params65();
        if (keyData.length != P.pkLen || sig.length != P.sigLen) return false; // fixed split for the precompile too
        bytes32 pq = PqUA.pqMessage(KIND_TAG, message);
        if (PRECOMPILE != address(0)) return PqUA.callBool(PRECOMPILE, abi.encodePacked(keyData, sig, pq));
        return MlDsa.verify(P, keyData, PqUA.emptyContext(pq), sig);
    }

    /// EIP-8051 expanded key of `pk` (FIPS 64-byte `tr`); see `MlDsa.verifyExpanded` on trusting one.
    function expandedKey(bytes calldata pk) external view returns (bytes memory) {
        Shake.reserve();
        return MlDsa.expandKey(KIND == PqUA.MLDSA44 ? MlDsa.params44() : MlDsa.params65(), pk);
    }
}
