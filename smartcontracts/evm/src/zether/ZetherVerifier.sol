// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {
    IZetherVerifierCommon, IZetherVerifier, IZetherBurnVerifier, IZetherInnerProductVerifier
} from "./IZetherVerifier.sol";
import {ZetherTranscript as T} from "./ZetherTranscript.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {G1Bls12381} from "./ZetherCurves.sol";

/// @title The curve layer every Zether verifier contract shares: the curve hooks, the proof system ids, the NUMS
///        generator blob (§3, read from an SSTORE2 data contract) and the arithmetic helpers.
abstract contract ZetherCurve is IZetherVerifierCommon {
    uint256 internal constant NGEN = 130; // h, U, G_0..63, H_0..63
    /// @dev Fold slots (zether.md §9.1): `G`, then the blob in its order; the caller's points from `SLOT_EXT`.
    uint256 internal constant SLOT_G = 0;
    uint256 internal constant SLOT_HB = 1;
    uint256 internal constant SLOT_U = 2;
    uint256 internal constant SLOT_GI = 3;
    uint256 internal constant SLOT_HI = 67;
    uint256 internal constant SLOT_EXT = 131;

    // ------------------------------------------------------------------ móc theo đường cong

    /// @dev Nhãn proof system của đường cong; id = keccak của nhãn, transfer nhiều người nhận thêm "/multi".
    function _psidLabel() internal pure virtual returns (string memory);
    function _pointBytes() internal pure virtual returns (uint256);
    function _order() internal pure virtual returns (uint256);
    function _gen(string memory label, uint32 index) internal view virtual returns (bytes memory);
    function _base() internal pure virtual returns (bytes memory);
    function _msm(bytes memory pts, uint256[] memory sc) internal view virtual returns (bytes memory);
    function _add(bytes memory a, bytes memory b) internal view virtual returns (bytes memory);
    function _neg(bytes memory a) internal pure virtual returns (bytes memory);
    function _valid(bytes memory a) internal view virtual returns (bool);

    /// @dev The SSTORE2 data contract of the generator blob (`0x00 ‖ blob`).
    function _store() internal view virtual returns (address);

    // ------------------------------------------------------------------ views

    function proofSystemId() public pure returns (bytes32) { return keccak256(bytes(_psidLabel())); }
    function proofSystemIdMulti() public pure returns (bytes32) { return keccak256(abi.encodePacked(_psidLabel(), "/multi")); }

    function groupOrder() external pure returns (uint256) { return _order(); }
    function g1EncodedBytes() external pure returns (uint256) { return _pointBytes(); }

    /// @notice Blob generator NUMS `h ‖ U ‖ G_0..G_63 ‖ H_0..H_63` (§3).
    function generators() public view returns (bytes memory blob) {
        uint256 len = NGEN * _pointBytes();
        address store = _store();
        blob = new bytes(len);
        assembly ("memory-safe") { extcodecopy(store, add(blob, 32), 1, len) }
    }

    // ------------------------------------------------------------------ tiện ích

    /// @dev `ρ` of the merged check (§9.1): a fork of the transcript state `st` that absorbs the whole `proof`. The running
    ///      transcript absorbs no `z_*`, `a` or `b`, so a weight read off it would let the prover choose those after it.
    function _rho(bytes32 st, bytes memory proof) internal pure returns (uint256 rho) {
        (, rho) = T.challenge(T.absorb(st, "fold.proof", proof), "fold.rho", _order());
    }

    /// @dev `f[slot] += w·s` mod `r`, the one place a term enters the fold.
    function _term(uint256[] memory f, uint256 slot, uint256 w, uint256 s, uint256 r) internal pure {
        f[slot] = addmod(f[slot], mulmod(w, s, r), r);
    }

    function _negS(uint256 a, uint256 r) internal pure returns (uint256) {
        return a == 0 ? 0 : r - a;
    }

    function _isZero(bytes memory a) internal pure returns (bool z) {
        z = true;
        for (uint256 i; i < a.length; i += 32) {
            if (_word(a, i) != 0) return false;
        }
    }

    function _log2(uint256 v) internal pure returns (uint256 l) {
        while (v > 1) {
            v >>= 1;
            ++l;
        }
    }

    /// @dev C0-19: a failed MODEXP precompile reverts with its address (diagnostics), not with empty data.
    error PrecompileFailed(uint256 at);

    function _inv(uint256 a, uint256 r) internal view returns (uint256 out) {
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 32), 32)
            mstore(add(m, 64), 32)
            mstore(add(m, 96), a)
            mstore(add(m, 128), sub(r, 2))
            mstore(add(m, 160), r)
            ok := staticcall(gas(), 0x05, m, 192, m, 32)
            ok := and(ok, eq(returndatasize(), 32)) // W-I: no 0x05 ⇒ empty
            out := mload(m)
        }
        if (!ok) revert PrecompileFailed(0x05);
    }

    function _word(bytes memory a, uint256 off) internal pure returns (uint256 w) {
        assembly ("memory-safe") { w := mload(add(add(a, 32), off)) }
    }

    function _slice(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        _copy(out, 0, a, off, len);
    }

    /// @dev Chép `len` byte (bội của 32) từ `src[srcOff..]` sang `dst[dstOff..]`.
    function _copy(bytes memory dst, uint256 dstOff, bytes memory src, uint256 srcOff, uint256 len) internal pure {
        assembly ("memory-safe") {
            let d := add(add(dst, 32), dstOff)
            let s := add(add(src, 32), srcOff)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(d, i), mload(add(s, i))) }
        }
    }

    function _put(bytes memory blob, uint256 idx, bytes memory pt, uint256 p) internal pure {
        _copy(blob, idx * p, pt, 0, p);
    }

    /// @dev Nhãn generator §3: `u8(len(label)) ‖ label ‖ be4(index)`.
    function _genMsg(string memory label, uint32 index) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(bytes(label).length), label, index);
    }
}

/// @title Verifier Σ-Bullets cho Zether: the inner-product side (§8.2), shared by the transfer and burn verifiers of a
///        curve (owner 2026-10-19, CTR-ZTH-20, candidate (2): no duplicated Bulletproof code).
/// @notice **UNAUDITED.** Generator NUMS tính trong constructor theo §3 rồi ghi vào một data
///         contract (SSTORE2): ai cũng tính lại được, không có hằng số nào để tin. Trên BLS12-381 MSM đi qua 0x0c nên mọi
///         điểm đầu vào được kiểm subgroup ngầm. Runs the one MSM of the merged check (§9.1, CTR-ZTH-53).
abstract contract ZetherInnerProductBase is ZetherCurve, IZetherInnerProductVerifier {
    address public immutable generatorStore;

    error GeneratorStoreFailed();

    constructor() {
        uint256 p = _pointBytes();
        bytes memory blob = new bytes(NGEN * p);
        _put(blob, 0, _gen("h", 0), p);
        _put(blob, 1, _gen("U", 0), p);
        for (uint32 i = 0; i < 64; ++i) {
            _put(blob, 2 + i, _gen("G", i), p);
            _put(blob, 66 + i, _gen("H", i), p);
        }
        // SSTORE2: runtime = 0x00 (STOP) ‖ blob, để không ai "gọi" được data contract.
        bytes memory init = abi.encodePacked(
            hex"61", uint16(blob.length + 1), hex"80600c6000396000f3", hex"00", blob
        );
        address store;
        assembly ("memory-safe") { store := create(0, add(init, 32), mload(init)) }
        if (store == address(0)) revert GeneratorStoreFailed();
        generatorStore = store;
    }

    function _store() internal view override returns (address) { return generatorStore; }

    /// @notice One Bulletproof range proof of `n = 64` bits (§9) on the caller's transcript `st`, its two equations folded
    ///         alone under a `ρ` that hashes `proof`: `V` the committed point, `proof` the `16P + 160` bytes
    ///         `A S T1 T2 (L_j R_j)_j τ_x μ t̂ a b`. Returns the new state. A pure function of its inputs (whoever calls it
    ///         learns nothing it could not compute). Precondition: `V` is not absorbed here; `st` must already bind `V`,
    ///         else a standalone use is a weak-Fiat-Shamir forgery target.
    function verifyRange(bytes32 st, bytes calldata V, bytes calldata proof) external view returns (bool, bytes32) {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = SLOT_EXT;
        if (V.length != _pointBytes()) return (false, st);
        return _fold(st, SigmaFold(_rho(st, bytes.concat(V, proof)), 1, V, new uint256[](SLOT_EXT + 1), commitments), proof);
    }

    /// @inheritdoc IZetherInnerProductVerifier
    function verifyFold(bytes32 st, SigmaFold calldata sigma, bytes calldata rangeProofs) external view returns (bool ok) {
        (ok,) = _fold(st, sigma, rangeProofs);
    }

    /// @dev `pts` = `G ‖ blob ‖ points ‖ (A S T1 T2 (L_j R_j)_j)_k`, one MSM whatever the number of proofs (§9.1). Every
    ///      point stays in `pts` with its scalar, 0 too: G1MSM's subgroup check is what admits it.
    ///      ponytail: the auditor-off `O` points keep their slots (3 points, `1 + 4M` on multi), a few gas-priced no-ops for one
    ///      layout; drop them only by their proven `O`, never by a zero scalar.
    function _fold(bytes32 st, SigmaFold memory sigma, bytes memory rangeProofs) private view returns (bool ok, bytes32) {
        BP memory b;
        b.p = _pointBytes();
        b.r = _order();
        b.n = 64;
        b.k = 6;
        b.sOff = (4 + 2 * b.k) * b.p;
        b.rho = sigma.rho % b.r;
        b.wt = sigma.weight % b.r;
        b.at = sigma.scalars.length;
        uint256 len = b.sOff + 160;
        uint256 m = sigma.commitments.length;
        if (b.rho == 0 || b.wt == 0 || rangeProofs.length != m * len || sigma.points.length + SLOT_EXT * b.p != b.at * b.p) {
            return (false, st);
        }
        bytes memory pts = _foldStart(b, sigma, m);
        for (uint256 k; k < m; ++k) {
            b.pr = _slice(rangeProofs, k * len, len);
            (ok, st) = _bpTranscript(st, b);
            if (!ok) return (false, st);
            _copy(pts, b.at * b.p, b.pr, 0, 16 * b.p);
            _bp1(b, sigma.commitments[k]);
            _bp2(b);
            b.at += 16;
        }
        return (_isZero(_msm(pts, b.f)), st);
    }

    /// @dev `b.f` = the caller's scalars, room for `m` proofs; returns `pts` up to the caller's points.
    function _foldStart(BP memory b, SigmaFold memory sigma, uint256 m) private view returns (bytes memory pts) {
        uint256 ext = sigma.scalars.length;
        b.f = new uint256[](ext + 16 * m);
        for (uint256 i; i < ext; ++i) b.f[i] = sigma.scalars[i];
        pts = new bytes(b.f.length * b.p);
        _put(pts, SLOT_G, _base(), b.p);
        _copy(pts, SLOT_HB * b.p, generators(), 0, NGEN * b.p);
        _copy(pts, SLOT_EXT * b.p, sigma.points, 0, sigma.points.length);
    }

    struct BP {
        uint256 p;
        uint256 r;
        uint256 n;
        uint256 k;
        uint256 sOff;
        uint256 rho;
        uint256 wt;     // the weight of the next equation
        uint256 at;     // the slot of this proof's `A`
        uint256[] f;    // the fold, one scalar per slot
        bytes pr;       // this proof
        uint256[5] sc;  // τ_x μ t̂ a b
        uint256 y;
        uint256 z;
        uint256 x;
        uint256 w;
        uint256[] u;
        uint256[] uInv;
    }

    /// @dev Reads the scalars of `b.pr` and draws its challenges (§9): every scalar `< r`, every challenge `≠ 0`.
    function _bpTranscript(bytes32 st, BP memory b) private pure returns (bool, bytes32) {
        bytes memory pr = b.pr;
        for (uint256 i; i < 5; ++i) {
            b.sc[i] = _word(pr, b.sOff + 32 * i); // τ_x μ t̂ a b
            if (b.sc[i] >= b.r) return (false, st);
        }
        st = T.absorb(st, "bp.AS", abi.encodePacked(uint32(b.n), _slice(pr, 0, 2 * b.p)));
        (st, b.y) = T.challenge(st, "bp.y", b.r);
        (st, b.z) = T.challenge(st, "bp.z", b.r);
        st = T.absorb(st, "bp.T", _slice(pr, 2 * b.p, 2 * b.p));
        (st, b.x) = T.challenge(st, "bp.x", b.r);
        st = T.absorb(st, "bp.t", _slice(pr, b.sOff, 96));
        (st, b.w) = T.challenge(st, "bp.w", b.r);
        if (b.y == 0 || b.z == 0 || b.x == 0 || b.w == 0) return (false, st);
        b.u = new uint256[](b.k);
        for (uint256 j; j < b.k; ++j) {
            st = T.absorb(st, "ipa.LR", _slice(pr, (4 + 2 * j) * b.p, 2 * b.p));
            (st, b.u[j]) = T.challenge(st, "ipa.u", b.r);
            if (b.u[j] == 0) return (false, st);
        }
        return (true, st);
    }

    /// @dev BP-1 into the fold: [t̂ − δ]G + [τ_x]Hb − [z²]V − [x]T1 − [x²]T2. `v` the slot of `V`.
    function _bp1(BP memory b, uint256 v) private pure {
        uint256 r = b.r;
        uint256 w = b.wt;
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 sumY;
        uint256 yi = 1;
        for (uint256 i; i < b.n; ++i) {
            sumY = addmod(sumY, yi, r);
            yi = mulmod(yi, b.y, r);
        }
        // δ = (z − z²)·Σy^i − z³·(2^n − 1)
        uint256 delta = addmod(
            mulmod(addmod(b.z, r - z2, r), sumY, r),
            r - mulmod(mulmod(z2, b.z, r), ((1 << b.n) - 1) % r, r),
            r
        );
        _term(b.f, SLOT_G, w, addmod(b.sc[2], r - delta, r), r);
        _term(b.f, SLOT_HB, w, b.sc[0], r);
        _term(b.f, v, w, _negS(z2, r), r);
        _term(b.f, b.at + 2, w, _negS(b.x, r), r);
        _term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);
        b.wt = mulmod(w, b.rho, r);
    }

    /// @dev BP-2 into the fold (§9): A + [x]S + Σ[−z − a·s_i]G_i + Σ[z + y^{-i}(z²2^i − b·s_i⁻¹)]H_i − [μ]Hb
    ///        + [w(t̂ − ab)]U + Σ[u_j²]L_j + Σ[u_j⁻²]R_j
    function _bp2(BP memory b) private view {
        uint256 r = b.r;
        uint256 w = b.wt;
        uint256 a = b.at;
        _term(b.f, a, w, 1, r);
        _term(b.f, a + 1, w, b.x, r);
        _bpVectorScalars(b);
        _term(b.f, SLOT_HB, w, _negS(b.sc[1], r), r);
        _term(b.f, SLOT_U, w, mulmod(b.w, addmod(b.sc[2], r - mulmod(b.sc[3], b.sc[4], r), r), r), r);
        for (uint256 j; j < b.k; ++j) {
            _term(b.f, a + 4 + 2 * j, w, mulmod(b.u[j], b.u[j], r), r);
            _term(b.f, a + 5 + 2 * j, w, mulmod(b.uInv[j], b.uInv[j], r), r);
        }
        b.wt = mulmod(w, b.rho, r);
    }

    /// @dev The `G_i` and `H_i` terms of BP-2, on the slots every range proof shares.
    function _bpVectorScalars(BP memory b) private view {
        uint256 r = b.r;
        uint256 n = b.n;
        uint256[] memory s = _sVector(b);
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 yInv = _inv(b.y, r);
        uint256 yInvI = 1;
        uint256 twoI = 1;
        for (uint256 i; i < n; ++i) {
            uint256 t = addmod(b.z, mulmod(b.sc[3], s[i], r), r);
            _term(b.f, SLOT_GI + i, b.wt, _negS(t, r), r);
            // s_i⁻¹ = s_{n−1−i}: phần bù bit đảo dấu mọi số mũ
            t = addmod(mulmod(z2, twoI, r), r - mulmod(b.sc[4], s[n - 1 - i], r), r);
            t = addmod(b.z, mulmod(yInvI, t, r), r);
            _term(b.f, SLOT_HI + i, b.wt, t, r);
            yInvI = mulmod(yInvI, yInv, r);
            twoI = addmod(twoI, twoI, r);
        }
    }

    /// @dev s_0 = Π u_j⁻¹, s_i = s_{i − 2^lg} · u_{k−1−lg}² (lg = bit cao nhất của i). Ghi `b.uInv`.
    function _sVector(BP memory b) private view returns (uint256[] memory s) {
        uint256 r = b.r;
        s = new uint256[](b.n);
        b.uInv = new uint256[](b.k);
        s[0] = 1;
        for (uint256 j; j < b.k; ++j) {
            b.uInv[j] = _inv(b.u[j], r);
            s[0] = mulmod(s[0], b.uInv[j], r);
        }
        for (uint256 i = 1; i < b.n; ++i) {
            uint256 lg = _log2(i);
            uint256 uj = b.u[b.k - 1 - lg];
            s[i] = mulmod(s[i - (1 << lg)], mulmod(uj, uj, r), r);
        }
    }
}

/// @title Verifier Σ-Bullets cho Zether, độc lập đường cong (đặc tả §6–§9): the Σ-protocol side.
/// @notice **UNAUDITED.** Một Σ-protocol (R1 khoá, R2–R4 ciphertext cùng `s`, R5 số dư, R9
///         auditor: `s` ở định dạng một người nhận, `t_j` riêng mỗi leg ở định dạng nhiều người nhận, liên kết Σ-Bullets) và các Bulletproof (`n_v = n_b = 64`, ruling RS-NV64-1) trên **một**
///         transcript; every equation is folded into **one** MSM that must equal `O`, each weighted by a power of `ρ`
///         (§9.1, CTR-ZTH-53). Split (owner 2026-10-19, CTR-ZTH-20): a transfer verifier and a burn verifier per curve
///         share this base (the checks are the internal `_verify*`; the compiler keeps in each only the code its entry
///         points reach): it folds the Σ-protocol, and the curve's inner-product verifier, fixed in the constructor, adds
///         the range proofs and runs the MSM. Same statements and proofs as the per-equation verifier in
///         `legacy/zether-msm/`; same verdicts up to the bound of §9.1.
abstract contract ZetherVerifierBase is ZetherCurve {
    bytes32 internal constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 internal constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    // Multi-recipient transfer: the storage mode is part of opTag (spec 2026-10-08-zether-multi-recipient §4).
    bytes32 internal constant OP_MULTI_HASH = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH");
    bytes32 internal constant OP_MULTI_BUNDLE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    uint256 internal constant MAX_RECIPIENTS = 16;
    uint256 internal constant NV = 64; // limits D1 (RS-NV64-1)
    uint256 internal constant NB = 64;
    /// @dev Statement header (zether.md §7, `…/v3`): 16 words, `chainUid` the 4th (CTR-ZTH-36), the salt the 14th
    ///      (CTR-ZTH-30), `memoHash` the 15th (CTR-ZTH-50), `validUntilBlock` the 16th (review C0-9: the token checks it, the
    ///      proof binds it); `fee` and `amount` are read here, mod `r` with no range check: E5 is a congruence, and the
    ///      token bounds `fee < 2^64`, `0 < amount ≤ maxShielded ≤ 2^54` before it builds the header (zether.md §8.1, §8.2).
    uint256 internal constant HEADER = 512;
    uint256 internal constant FEE_AT = 288;
    uint256 internal constant AMOUNT_AT = 352;

    /// @notice The curve's inner-product verifier (the range proofs, the generators), a constructor argument fixed at
    ///         deployment (CTR-ZTH-20).
    IZetherInnerProductVerifier public immutable innerProduct;
    address public immutable generatorStore;

    error InnerProductMismatch(address innerProduct);

    constructor(IZetherInnerProductVerifier innerProduct_) {
        if (!SigCheck.isContract(address(innerProduct_)) || innerProduct_.proofSystemId() != proofSystemId()) {
            revert InnerProductMismatch(address(innerProduct_));
        }
        innerProduct = innerProduct_;
        generatorStore = innerProduct_.generatorStore();
    }

    function _store() internal view override returns (address) { return generatorStore; }

    // ------------------------------------------------------------------ verify

    function _verifyTransfer(bytes calldata statement, bytes calldata proof) internal view returns (bool) {
        uint256 p = _pointBytes();
        // Σ 10P + 192 ‖ BP(64) 16P + 160 ‖ BP(64) 16P + 160
        if (statement.length != HEADER + 9 * p || proof.length != 42 * p + 512) return false;
        if (bytes32(statement[0:32]) != OP_TRANSFER || bytes32(statement[32:64]) != proofSystemId()) return false;
        Ctx memory x = _ctx(statement, proof, 10 * p, bytes.concat(proof[0:10 * p], statement[HEADER:]));
        if (x.c == 0 || !_sigmaTransfer(x)) return false;
        uint256[] memory v = new uint256[](2);
        (v[0], v[1]) = (SLOT_EXT, SLOT_EXT + 1); // V_v, V_b
        return _fold(x, v, 10 * p + 192);
    }

    /// @notice Transfer tới `M` người nhận, một proof: Σ (E1–E8, E3/E6/E6′/E7 theo từng người) + BP(v_j) cho từng
    ///         người + BP(b'). Statement `Y_f Y_a C_acc D_acc D_out C_deb be32(M) (Y_tj C_out_j C_aud_j D_aud_j)_j`: every
    ///         auditor copy under its own randomness `t_j` (review C0-1, owner ruling 2026-10-27 (ii)).
    function _verifyTransferMulti(bytes calldata statement, bytes calldata proof) internal view returns (bool) {
        uint256 m = _multiLegs(statement, proof);
        if (m == 0) return false;
        uint256 p = _pointBytes();
        uint256 mAt = HEADER + 6 * p; // be32(M), not a point: left out of the slots
        uint256 sigma = (6 + 5 * m) * p;
        bytes memory pts = bytes.concat(proof[0:sigma], statement[HEADER:mAt], statement[mAt + 32:]);
        Ctx memory x = _ctx(statement, proof, sigma, pts);
        if (x.c == 0 || !_sigmaTransferMulti(x, m)) return false;
        uint256[] memory v = new uint256[](m + 1);
        for (uint256 j; j < m; ++j) v[j] = _lpf(j, 0); // V_vj
        v[m] = SLOT_EXT; // V_b
        return _fold(x, v, sigma + (4 + 3 * m) * 32);
    }

    /// @dev `M` of a well-formed multi-recipient statement and proof, else 0.
    function _multiLegs(bytes calldata statement, bytes calldata proof) private pure returns (uint256 m) {
        uint256 p = _pointBytes();
        uint256 mAt = HEADER + 6 * p;
        if (statement.length < mAt + 32) return 0;
        m = uint256(bytes32(statement[mAt:mAt + 32]));
        if (m == 0 || m > MAX_RECIPIENTS || statement.length != mAt + 32 + 4 * p * m) return 0;
        bytes32 op = bytes32(statement[0:32]);
        if (op != OP_MULTI_HASH && op != OP_MULTI_BUNDLE) return 0;
        if (bytes32(statement[32:64]) != proofSystemIdMulti()) return 0;
        // Σ (6 + 5M)P + (4 + 3M)·32 ‖ BP(v_1) … BP(v_M) ‖ BP(b'), mỗi BP 16P + 160
        if (proof.length != (6 + 5 * m) * p + (4 + 3 * m) * 32 + (m + 1) * (16 * p + 160)) return 0;
    }

    function _verifyBurn(bytes calldata statement, bytes calldata proof) internal view returns (bool) {
        uint256 p = _pointBytes();
        if (statement.length != HEADER + 3 * p || proof.length != 20 * p + 256) return false;
        if (bytes32(statement[0:32]) != OP_BURN || bytes32(statement[32:64]) != proofSystemId()) return false;
        Ctx memory x = _ctx(statement, proof, 4 * p, bytes.concat(proof[0:4 * p], statement[HEADER:]));
        if (x.c == 0 || !_sigmaBurn(x)) return false;
        uint256[] memory v = new uint256[](1);
        v[0] = SLOT_EXT; // V_b
        return _fold(x, v, 4 * p + 96);
    }

    /// @dev The verdict: the range proofs from `off` on the running transcript, added to the Σ fold, one MSM (§9.1). `v` the
    ///      slot of each proof's commitment, already absorbed by `_ctx`.
    function _fold(Ctx memory x, uint256[] memory v, uint256 off) private view returns (bool) {
        return innerProduct.verifyFold(
            x.st, IZetherInnerProductVerifier.SigmaFold(x.rho, x.w, x.pts, x.f, v), _slice(x.pr, off, x.pr.length - off)
        );
    }

    struct Ctx {
        uint256 p;
        uint256 r;
        uint256 c;
        bytes32 st;
        bytes s;      // statement
        bytes pr;     // proof
        uint256 rho;  // the fold challenge (§9.1)
        uint256 w;    // the weight of the next equation
        uint256 sAt;  // the slot of the statement's first point
        bytes pts;    // the proof's Σ points ‖ the statement's points, slots from `SLOT_EXT`
        uint256[] f;  // the fold, one scalar per slot
    }

    /// @dev Hấp thụ statement và `sigmaLen` byte đầu của proof, rút challenge `c` (§7), rồi `ρ` (§9.1). `pts`: see `Ctx`.
    function _ctx(bytes calldata statement, bytes calldata proof, uint256 sigmaLen, bytes memory pts)
        private pure returns (Ctx memory x)
    {
        x.p = _pointBytes();
        x.r = _order();
        x.s = statement;
        x.pr = proof;
        x.st = T.absorb(T.init(), "statement", x.s);
        x.st = T.absorb(x.st, "sigma.commit", proof[0:sigmaLen]);
        (x.st, x.c) = T.challenge(x.st, "sigma.c", x.r);
        x.rho = _rho(x.st, x.pr);
        x.w = 1;
        x.sAt = SLOT_EXT + sigmaLen / x.p;
        x.pts = pts;
        x.f = new uint256[](SLOT_EXT + pts.length / x.p);
    }

    /// @dev One equation, `Σ [s_i] at_i`, into the fold under the next power of `ρ`.
    function _e3(Ctx memory x, uint256[3] memory slots, uint256[3] memory s) private pure {
        for (uint256 i; i < 3; ++i) _term(x.f, slots[i], x.w, s[i], x.r);
        x.w = mulmod(x.w, x.rho, x.r);
    }

    function _e4(Ctx memory x, uint256[4] memory slots, uint256[4] memory s) private pure {
        for (uint256 i; i < 4; ++i) _term(x.f, slots[i], x.w, s[i], x.r);
        x.w = mulmod(x.w, x.rho, x.r);
    }

    /// @dev E5, the one six-term equation: [z_b + c·fee]G + [z_x]D_acc − [z_x]D_out − [c]C_acc + [c]C_deb − A_bal, `slots` those
    ///      of `D_acc D_out C_acc C_deb A_bal`.
    function _e5(Ctx memory x, uint256 zb, uint256 zx, uint256[5] memory slots) private pure {
        uint256 r = x.r;
        _term(x.f, SLOT_G, x.w, addmod(zb, mulmod(x.c, _word(x.s, FEE_AT), r), r), r);
        _term(x.f, slots[0], x.w, zx, r);
        _term(x.f, slots[1], x.w, _negS(zx, r), r);
        _term(x.f, slots[2], x.w, r - x.c, r);
        _term(x.f, slots[3], x.w, x.c, r);
        _term(x.f, slots[4], x.w, r - 1, r);
        x.w = mulmod(x.w, x.rho, r);
    }

    /// @dev Điểm thứ `i` của phần điểm statement (sau header 480 byte).
    function _sp(Ctx memory x, uint256 i) private pure returns (bytes memory) {
        return _slice(x.s, HEADER + i * x.p, x.p);
    }

    /// @dev Điểm thứ `i` của proof.
    function _pf(Ctx memory x, uint256 i) private pure returns (bytes memory) {
        return _slice(x.pr, i * x.p, x.p);
    }

    /// @dev Scalar thứ `i` sau `nPts` điểm đầu của proof; `>= r` ⇒ proof không chính tắc.
    function _ps(Ctx memory x, uint256 nPts, uint256 i) private pure returns (uint256 v, bool ok) {
        v = _word(x.pr, nPts * x.p + 32 * i);
        ok = v < x.r;
    }

    /// @dev E1–E8 (§8.1) into the fold. Statement: Y_f Y_t Y_a C_acc D_acc C_out D_out C_deb C_aud.
    ///      Proof: V_v V_b A_y A_D A_out A_deb A_bal A_aud A_Vv A_Vb z_x z_v z_s z_b z_gv z_gb.
    function _sigmaTransfer(Ctx memory x) private pure returns (bool) {
        uint256[6] memory z;
        for (uint256 i; i < 6; ++i) {
            bool ok;
            (z[i], ok) = _ps(x, 10, i);
            if (!ok) return false;
        }
        if (_isZero(_sp(x, 6)) || _isZero(_sp(x, 0)) || _isZero(_sp(x, 1))
            || keccak256(_sp(x, 0)) == keccak256(_sp(x, 1))) return false;
        uint256 r = x.r;
        uint256 nc = r - x.c;
        uint256 s = x.sAt;
        uint256 a = SLOT_EXT;
        // E1  [z_x]G − [c]Y_f − A_y
        _e3(x, [SLOT_G, s, a + 2], [z[0], nc, r - 1]);
        // E2  [z_s]G − [c]D_out − A_D
        _e3(x, [SLOT_G, s + 6, a + 3], [z[2], nc, r - 1]);
        // E3  [z_v]G + [z_s]Y_t − [c]C_out − A_out
        _e4(x, [SLOT_G, s + 1, s + 5, a + 4], [z[1], z[2], nc, r - 1]);
        // E4  [z_v]G + [z_s]Y_f − [c]C_deb − A_deb
        _e4(x, [SLOT_G, s, s + 7, a + 5], [z[1], z[2], nc, r - 1]);
        _e5(x, z[3], z[0], [s + 4, s + 6, s + 3, s + 7, a + 6]);
        // E6  auditor bật ⇒ [z_v]G + [z_s]Y_a − [c]C_aud − A_aud; tắt ⇒ C_aud = A_aud = O
        if (_isZero(_sp(x, 2))) {
            if (!_isZero(_sp(x, 8)) || !_isZero(_pf(x, 7))) return false;
        } else {
            _e4(x, [SLOT_G, s + 2, s + 8, a + 7], [z[1], z[2], nc, r - 1]);
        }
        // E7  [z_v]G + [z_gv]Hb − [c]V_v − A_Vv
        _e4(x, [SLOT_G, SLOT_HB, a, a + 8], [z[1], z[4], nc, r - 1]);
        // E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
        _e4(x, [SLOT_G, SLOT_HB, a + 1, a + 9], [z[3], z[5], nc, r - 1]);
        return true;
    }

    /// @dev Statement: Y_f Y_a C_acc D_acc D_out C_deb, rồi các leg. Proof: V_b A_y A_D A_deb A_bal A_Vb
    ///      (V_vj A_out_j A_aud_j A_Daud_j A_Vvj)_j z_x z_s z_b z_gb (z_vj z_gvj z_tj)_j.
    function _sigmaTransferMulti(Ctx memory x, uint256 m) private pure returns (bool) {
        uint256[] memory z = new uint256[](4 + 3 * m);
        for (uint256 i; i < z.length; ++i) {
            bool ok;
            (z[i], ok) = _ps(x, 6 + 5 * m, i);
            if (!ok) return false;
        }
        if (_isZero(_sp(x, 0)) || _isZero(_sp(x, 4))) return false;
        uint256 r = x.r;
        uint256 nc = r - x.c;
        uint256 s = x.sAt;
        uint256 a = SLOT_EXT;
        // E1  [z_x]G − [c]Y_f − A_y
        _e3(x, [SLOT_G, s, a + 1], [z[0], nc, r - 1]);
        // E2  [z_s]G − [c]D_out − A_D
        _e3(x, [SLOT_G, s + 4, a + 2], [z[1], nc, r - 1]);
        if (!_sigmaLegs(x, m, z)) return false;
        // E4  [Σz_vj]G + [z_s]Y_f − [c]C_deb − A_deb
        uint256 zv;
        for (uint256 j; j < m; ++j) zv = addmod(zv, z[4 + 3 * j], r);
        _e4(x, [SLOT_G, s, s + 5, a + 3], [zv, z[1], nc, r - 1]);
        _e5(x, z[2], z[0], [s + 3, s + 4, s + 2, s + 5, a + 4]);
        // E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
        _e4(x, [SLOT_G, SLOT_HB, a, a + 5], [z[2], z[3], nc, r - 1]);
        return true;
    }

    /// @dev Những gì mọi leg dùng chung (gom vào memory cho khỏi tràn stack).
    struct Legs {
        bool aud;
        bytes32 yf;
        uint256 nc; // r − c
        uint256 zs;
        uint256[] z;
    }

    /// @dev E3_j, E6_j, E6′_j, E7_j của từng người nhận; Y_tj ≠ O, ≠ Y_f.
    function _sigmaLegs(Ctx memory x, uint256 m, uint256[] memory z) private pure returns (bool) {
        Legs memory l;
        l.aud = !_isZero(_sp(x, 1));
        l.yf = keccak256(_sp(x, 0));
        l.nc = x.r - x.c;
        l.zs = z[1];
        l.z = z;
        if (l.aud && !_distinctAud(x, m)) return false;
        for (uint256 j; j < m; ++j) {
            if (!_sigmaLeg(x, l, j)) return false;
        }
        return true;
    }

    /// @dev With the auditor on, no two legs share `C_aud` or `D_aud` (review C0-1): a reused `t_j` would make
    ///      `C_aud_j − C_aud_k = [v_j − v_k]G` public again, so such a statement is refused, not only never built.
    function _distinctAud(Ctx memory x, uint256 m) private pure returns (bool) {
        bytes32[] memory h = new bytes32[](2 * m);
        for (uint256 j; j < m; ++j) {
            (h[2 * j], h[2 * j + 1]) = (keccak256(_lp(x, j, 2)), keccak256(_lp(x, j, 3)));
            for (uint256 k; k < j; ++k) {
                if (h[2 * k] == h[2 * j] || h[2 * k + 1] == h[2 * j + 1]) return false;
            }
        }
        return true;
    }

    /// @dev The slot of proof point `k` of leg `j`: V_vj A_out_j A_aud_j A_Daud_j A_Vvj at `6 + 5j + k`.
    function _lpf(uint256 j, uint256 k) private pure returns (uint256) {
        return SLOT_EXT + 6 + 5 * j + k;
    }

    /// @dev The slot of statement point `k` (Y_t, C_out, C_aud, D_aud) of leg `j`.
    function _lps(Ctx memory x, uint256 j, uint256 k) private pure returns (uint256) {
        return x.sAt + 6 + 4 * j + k;
    }

    function _sigmaLeg(Ctx memory x, Legs memory l, uint256 j) private pure returns (bool) {
        uint256 r1 = x.r - 1;
        uint256 zv = l.z[4 + 3 * j];
        bytes memory yt = _lp(x, j, 0);
        if (_isZero(yt) || keccak256(yt) == l.yf) return false;
        // E3_j  [z_vj]G + [z_s]Y_tj − [c]C_out_j − A_out_j
        _e4(x, [SLOT_G, _lps(x, j, 0), _lps(x, j, 1), _lpf(j, 1)], [zv, l.zs, l.nc, r1]);
        if (!_sigmaAud(x, l, j)) return false;
        // E7_j  [z_vj]G + [z_gvj]Hb − [c]V_vj − A_Vvj
        _e4(x, [SLOT_G, SLOT_HB, _lpf(j, 0), _lpf(j, 4)], [zv, l.z[5 + 3 * j], l.nc, r1]);
        return true;
    }

    /// @dev Leg `j`'s auditor copy (review C0-1, owner ruling 2026-10-27 (ii)): auditor bật ⇒ `D_aud_j ≠ O`,
    ///      E6_j  [z_vj]G + [z_tj]Y_a − [c]C_aud_j − A_aud_j, E6′_j  [z_tj]G − [c]D_aud_j − A_Daud_j;
    ///      tắt ⇒ C_aud_j = D_aud_j = A_aud_j = A_Daud_j = O và z_tj = 0.
    function _sigmaAud(Ctx memory x, Legs memory l, uint256 j) private pure returns (bool) {
        uint256 zt = l.z[6 + 3 * j];
        if (!l.aud) {
            return zt == 0 && _isZero(_lp(x, j, 2)) && _isZero(_lp(x, j, 3)) && _isZero(_pf(x, 6 + 5 * j + 2))
                && _isZero(_pf(x, 6 + 5 * j + 3));
        }
        if (_isZero(_lp(x, j, 3))) return false;
        _e4(x, [SLOT_G, x.sAt + 1, _lps(x, j, 2), _lpf(j, 2)], [l.z[4 + 3 * j], zt, l.nc, x.r - 1]);
        _e3(x, [SLOT_G, _lps(x, j, 3), _lpf(j, 3)], [zt, l.nc, x.r - 1]);
        return true;
    }

    /// @dev Điểm thứ `k` (Y_t, C_out, C_aud, D_aud) của người nhận `j`.
    function _lp(Ctx memory x, uint256 j, uint256 k) private pure returns (bytes memory) {
        return _slice(x.s, HEADER + 6 * x.p + 32 + (4 * j + k) * x.p, x.p);
    }

    /// @dev §8.2. Statement: Y_f C_acc D_acc. Proof: V_b A_y A_bal A_Vb z_x z_b z_gb.
    function _sigmaBurn(Ctx memory x) private pure returns (bool) {
        uint256[3] memory z;
        for (uint256 i; i < 3; ++i) {
            bool ok;
            (z[i], ok) = _ps(x, 4, i);
            if (!ok) return false;
        }
        if (_isZero(_sp(x, 0))) return false;
        uint256 r = x.r;
        uint256 nc = r - x.c;
        uint256 s = x.sAt;
        uint256 a = SLOT_EXT;
        // E1  [z_x]G − [c]Y_f − A_y
        _e3(x, [SLOT_G, s, a + 1], [z[0], nc, r - 1]);
        // E5  [z_b + c·(amount + fee)]G + [z_x]D_acc − [c]C_acc − A_bal
        uint256 debit = addmod(_word(x.s, AMOUNT_AT), _word(x.s, FEE_AT), r);
        _e4(x, [SLOT_G, s + 2, s + 1, a + 2], [addmod(z[1], mulmod(x.c, debit, r), r), z[0], nc, r - 1]);
        // E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
        _e4(x, [SLOT_G, SLOT_HB, a, a + 3], [z[1], z[2], nc, r - 1]);
        return true;
    }

}

/// @title The transfer verifier of a curve: `verifyTransfer`, `verifyTransferMulti`, and the group operations of
///        `IZetherVerifier` (the token's homomorphic updates, `ZetherDisclosure`, the client tests).
abstract contract ZetherTransferVerifierBase is ZetherVerifierBase, IZetherVerifier {
    function verifyTransfer(bytes calldata statement, bytes calldata proof) external view returns (bool) {
        return _verifyTransfer(statement, proof);
    }

    function verifyTransferMulti(bytes calldata statement, bytes calldata proof) external view returns (bool) {
        return _verifyTransferMulti(statement, proof);
    }

    function ringSize() external pure returns (uint256) { return 2; }
    function identity() external pure returns (bytes memory) { return new bytes(_pointBytes()); }
    function isValidPoint(bytes calldata a) external view returns (bool) { return _valid(a); }
    function g1Add(bytes calldata a, bytes calldata b) external view returns (bytes memory) { return _add(a, b); }
    function g1Sub(bytes calldata a, bytes calldata b) external view returns (bytes memory) {
        return _add(a, _neg(b));
    }
    function g1Mul(bytes calldata a, uint256 k) external view returns (bytes memory) {
        uint256[] memory sc = new uint256[](1);
        sc[0] = k;
        return _msm(a, sc);
    }
    function g1MulBase(uint256 k) external view returns (bytes memory) {
        uint256[] memory sc = new uint256[](1);
        sc[0] = k;
        return _msm(_base(), sc);
    }
    function g1Msm(bytes calldata pts, uint256[] calldata scalars) external view returns (bytes memory) {
        return _msm(pts, scalars);
    }
}

/// @title The burn verifier of a curve: `verifyBurn` (unshield, unshield-unwrap) only.
abstract contract ZetherBurnVerifierBase is ZetherVerifierBase, IZetherBurnVerifier {
    function verifyBurn(bytes calldata statement, bytes calldata proof) external view returns (bool) {
        return _verifyBurn(statement, proof);
    }
}

/// @title Verifier Zether trên BLS12-381 (EIP-2537, cần Prague).
/// @notice **UNAUDITED.** 117–126 bit; điểm 128 byte; subgroup check nằm
///         trong mọi G1MSM.
abstract contract ZetherBls12381Curve is ZetherCurve {
    bytes internal constant GEN_DST = "SCAAS-ZETHER-GEN-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    uint256 internal constant PROBE_GAS = 100_000; // EIP-2537 prices these calls at 12,000 and 21,312

    function _psidLabel() internal pure override returns (string memory) {
        return "scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"; // v3: review C0-1 (per-leg t_j), C0-9 (validUntilBlock)
    }

    function curveName() external pure returns (string memory) { return "bls12-381"; }

    /// @dev Probe cả G1ADD và G1MSM: G + G == [2]G. Precompile vắng mặt trả 0 byte ⇒ false. Then the check the fold rests on
    ///      (zether.md §9.1): G1MSM must refuse the order-3 point `(0, 2)`, alone and at scalar 0 beside a good term. Both
    ///      calls fail on every compliant chain and a failed precompile burns all it is sent, so each is capped at
    ///      `PROBE_GAS`: the exception to CTR-ZTH-15, and `ZetherLib.init` reads an out-of-gas probe as an unsupported chain.
    function isSupportedOnThisChain() external view returns (bool) {
        bytes memory g = G1Bls12381.generator();
        (bool ok, bytes memory sum) = address(0x0b).staticcall(bytes.concat(g, g));
        if (!ok || sum.length != 128) return false;
        (bool ok2, bytes memory dbl) = address(0x0c).staticcall(abi.encodePacked(g, uint256(2)));
        if (!ok2 || dbl.length != 128 || keccak256(sum) != keccak256(dbl) || G1Bls12381.isIdentity(sum)) return false;
        bytes memory t = abi.encodePacked(uint256(0), uint256(0), uint256(0), uint256(2));
        (bool taken,) = address(0x0c).staticcall{gas: PROBE_GAS}(abi.encodePacked(t, uint256(1)));
        if (taken) return false;
        (taken,) = address(0x0c).staticcall{gas: PROBE_GAS}(abi.encodePacked(g, uint256(1), t, uint256(0)));
        return !taken;
    }

    function _pointBytes() internal pure override returns (uint256) { return 128; }
    function _order() internal pure override returns (uint256) { return G1Bls12381.R; }
    function _base() internal pure override returns (bytes memory) { return G1Bls12381.generator(); }

    function _gen(string memory label, uint32 index) internal view override returns (bytes memory) {
        return G1Bls12381.hashToG1(_genMsg(label, index), GEN_DST);
    }

    function _msm(bytes memory pts, uint256[] memory sc) internal view virtual override returns (bytes memory) {
        return G1Bls12381.msm(pts, sc);
    }

    function _add(bytes memory a, bytes memory b) internal view override returns (bytes memory) {
        return G1Bls12381.add(a, b);
    }

    function _neg(bytes memory a) internal pure override returns (bytes memory) { return G1Bls12381.neg(a); }
    function _valid(bytes memory a) internal view override returns (bool) { return G1Bls12381.isValid(a); }
}

/// @title The BLS12-381 inner-product (Bulletproof) verifier (CTR-ZTH-20).
contract ZetherInnerProductVerifierBls12381 is ZetherInnerProductBase, ZetherBls12381Curve {}

/// @title The BLS12-381 transfer verifier (CTR-ZTH-20).
contract ZetherTransferVerifierBls12381 is ZetherTransferVerifierBase, ZetherBls12381Curve {
    constructor(IZetherInnerProductVerifier ip) ZetherVerifierBase(ip) {}
}

/// @title The BLS12-381 burn verifier (CTR-ZTH-20).
contract ZetherBurnVerifierBls12381 is ZetherBurnVerifierBase, ZetherBls12381Curve {
    constructor(IZetherInnerProductVerifier ip) ZetherVerifierBase(ip) {}
}

