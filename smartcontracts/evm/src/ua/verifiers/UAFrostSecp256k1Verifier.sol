// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {HashToCurve} from "../../common/HashToCurve.sol";

/// @title RFC 9591 FROST(secp256k1, SHA-256) verification and the frost-core DKG proof of knowledge (accounts.md §1.6.1).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Elements are SEC1 compressed (33), scalars 32-byte big-endian.
///         `H(m, label) = int(expand_message_xmd_SHA256(m, "FROST-secp256k1-SHA256-v1" ‖ label, 48)) mod N`
///         (RFC 9591 §6.5 `hash_to_field`; labels `chal` for H2, `dkg` for the ZF frost-core `HDKG`).
///         Every `z·G − c·Q == R` check is one `ecrecover(−z·x(Q), v(Q), x(Q), −c·x(Q))`, which returns
///         `address(x(Q)⁻¹·(−c·x(Q)·Q + z·x(Q)·G))`, compared with `address(R)` (R decompressed with one MODEXP).
///         Fails closed, never reverts: a point with prefix ∉ {02, 03}, `x ≥ p` or off the curve, `z ≥ N`, a failed
///         MODEXP (out of gas) ⇒ false. Not covered (probability ~2⁻¹²⁸ each, fail closed): `x(Q) ≥ N` (ecrecover
///         refuses r ≥ N) and `c == 0`.
library FrostSecp256k1 {
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes internal constant DST_CHAL = "FROST-secp256k1-SHA256-v1chal";
    bytes internal constant DST_DKG = "FROST-secp256k1-SHA256-v1dkg";

    /// RFC 9591 `hash_to_field` to a scalar: 48 bytes of `expand_message_xmd` (SHA-256) mod N.
    function hashToScalar(bytes memory m, bytes memory dst) internal pure returns (uint256 s) {
        bytes memory u = HashToCurve.expandMessageXmd(m, dst, 48);
        uint256 hi;
        uint256 lo;
        assembly ("memory-safe") {
            hi := mload(add(u, 32))
            lo := shr(128, mload(add(u, 64)))
        }
        s = addmod(mulmod(hi, 1 << 128, N), lo, N);
    }

    /// RFC 9591 verify: `sig = R (33) ‖ z (32)`, `c = H2(R ‖ Y ‖ msg)`, accept iff `z < N` and `z·G == R + c·Y`.
    function verify(bytes memory y, bytes memory message, bytes memory sig) internal view returns (bool) {
        if (y.length != 33 || sig.length != 65) return false;
        (bool ok, uint256 rx, uint256 ry) = decompress(sig, 0);
        uint256 z = _word(sig, 33);
        if (!ok || z >= N) return false;
        uint256 c = hashToScalar(bytes.concat(_slice33(sig), y, message), DST_CHAL);
        return isLinear(y, 0, z, c, rx, ry);
    }

    /// `z·G − c·Q == (rx, ry)` with `Q` the compressed point at `q[o:o+33]` (lifted by ecrecover from its prefix).
    function isLinear(bytes memory q, uint256 o, uint256 z, uint256 c, uint256 rx, uint256 ry)
        internal pure returns (bool)
    {
        uint256 prefix = uint8(q[o]);
        uint256 qx = _word(q, o + 1);
        if (prefix != 2 && prefix != 3) return false;
        address got = ecrecover(bytes32(mulmod(N - z, qx, N)), uint8(prefix + 25), bytes32(qx), bytes32(mulmod(N - c, qx, N)));
        return got != address(0) && got == address(uint160(uint256(keccak256(abi.encodePacked(rx, ry)))));
    }

    /// SEC1 compressed point at `b[o:o+33]` → affine `(x, y)`; false on prefix ∉ {02, 03}, `x ≥ p`, off the curve.
    function decompress(bytes memory b, uint256 o) internal view returns (bool ok, uint256 x, uint256 y) {
        uint256 prefix = uint8(b[o]);
        x = _word(b, o + 1);
        if ((prefix != 2 && prefix != 3) || x >= P) return (false, 0, 0);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 0x20), 32)
            mstore(add(m, 0x40), 32)
            mstore(add(m, 0x60), rhs)
            mstore(add(m, 0x80), 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c) // (p + 1) / 4
            mstore(add(m, 0xa0), P)
            let success := staticcall(gas(), 0x05, m, 0xc0, m, 0x20)
            ok := and(success, eq(returndatasize(), 0x20)) // Yul evaluates arguments right to left
            y := mload(m)
        }
        if (!ok || mulmod(y, y, P) != rhs) return (false, 0, 0);
        if (y & 1 != prefix - 2) y = P - y;
    }

    function _word(bytes memory b, uint256 o) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), o))
        }
    }

    function _slice33(bytes memory b) private pure returns (bytes memory s) {
        s = new bytes(33);
        assembly ("memory-safe") {
            mstore(add(s, 32), mload(add(b, 32)))
            mstore8(add(s, 64), byte(0, mload(add(b, 64))))
        }
    }
}

/// @title UA verifier for `frost-secp256k1` (0x0111, accounts.md §1.6.1, §1.9) — RFC 9591, **not** BIP-340.
/// @notice `verify(Y, ua_msg, R ‖ z)`: RFC 9591 FROST(secp256k1, SHA-256) over the 32-byte `ua_msg`, `Y` (33) the stored
///         group key. `verifyPop(keyData, msg, sig)`: key data = `Y (33) ‖ u16 t ‖ u16 n ‖ n × (t × C_ik (33) ‖ R_i (33)
///         ‖ μ_i (32))`, 2 ≤ t ≤ n ≤ 16, participant `i = 1..n` (RFC 9591 scalar identifiers); for each `i`:
///         `μ_i < N`, `R_i == μ_i·G − c_i·C_i0` with `c_i = H(i (32 BE) ‖ C_i0 ‖ R_i, "dkg")` (ZF frost-core
///         `keys::dkg` `challenge` / `verify_proof_of_knowledge`); `Y == Σ C_i0`; then `verify(Y, msg, sig)`.
///         `C_ik` for k ≥ 1 enter no equation on chain (Feldman share checks are each participant's duty, §1.6.1
///         attestation-only): their encoding is checked by `UAKinds.validateKeyData` at registration, not here.
///         Malformed input returns false, never reverts.
contract UAFrostSecp256k1Verifier is IUAPopVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        return FrostSecp256k1.verify(keyData, abi.encodePacked(message), sig);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        (bool ok, uint256[3] memory a) = _sumOfProven(keyData);
        if (!ok) return false;
        bytes memory y = keyData[0:33];
        (bool okY, uint256 yx, uint256 yy) = FrostSecp256k1.decompress(y, 0);
        uint256 p = FrostSecp256k1.P;
        uint256 z2 = mulmod(a[2], a[2], p);
        if (!okY || a[0] != mulmod(yx, z2, p) || a[1] != mulmod(yy, mulmod(z2, a[2], p), p)) return false;
        return FrostSecp256k1.verify(y, abi.encodePacked(message), sig);
    }

    /// Header and length checks, every PoK, and `Σ C_i0` in Jacobian coordinates (X, Y, Z) = affine (X/Z², Y/Z³).
    function _sumOfProven(bytes calldata keyData) private view returns (bool, uint256[3] memory a) {
        if (keyData.length < 37) return (false, a);
        uint256 t = uint16(bytes2(keyData[33:35]));
        uint256 n = uint16(bytes2(keyData[35:37]));
        if (t < 2 || t > n || n > 16) return (false, a);
        uint256 per = (t + 1) * 33 + 32;
        if (keyData.length != 37 + n * per) return (false, a);
        for (uint256 i; i < n; ++i) {
            (bool ok, uint256 cx, uint256 cy) = _pok(i + 1, keyData[37 + i * per:37 + (i + 1) * per], t);
            if (!ok) return (false, a);
            if (i == 0) (a[0], a[1], a[2]) = (cx, cy, 1);
            else if (!_addMixed(a, cx, cy)) return (false, a);
        }
        return (true, a);
    }

    /// Participant `id`'s record `part = t × C_ik ‖ R_i ‖ μ_i`: `μ_i < N`, `R_i == μ_i·G − c_i·C_i0`; returns affine `C_i0`.
    function _pok(uint256 id, bytes calldata part, uint256 t) private view returns (bool ok, uint256, uint256) {
        bytes memory c0 = part[0:33];
        bytes memory r = part[t * 33:t * 33 + 33];
        uint256 mu = uint256(bytes32(part[t * 33 + 33:]));
        uint256 rx;
        uint256 ry;
        (ok, rx, ry) = FrostSecp256k1.decompress(r, 0);
        if (!ok || mu >= FrostSecp256k1.N) return (false, 0, 0);
        uint256 ch = FrostSecp256k1.hashToScalar(abi.encodePacked(id, c0, r), FrostSecp256k1.DST_DKG);
        if (!FrostSecp256k1.isLinear(c0, 0, mu, ch, rx, ry)) return (false, 0, 0);
        return FrostSecp256k1.decompress(c0, 0);
    }

    /// `a += (x2, y2)`: Jacobian + affine addition (add-2007-bl, a = 0). False when the inputs share an x coordinate
    /// (doubling or a sum at infinity). ponytail: such a transcript is refused (an honest DKG hits it with probability
    /// ~2⁻²⁵⁶); add doubling only if a legitimate use for repeated or cancelling C_i0 appears.
    function _addMixed(uint256[3] memory a, uint256 x2, uint256 y2) private pure returns (bool) {
        uint256 p = FrostSecp256k1.P;
        (uint256 x1, uint256 y1, uint256 z1) = (a[0], a[1], a[2]);
        uint256 zz = mulmod(z1, z1, p);
        uint256 h = addmod(mulmod(x2, zz, p), p - x1, p);
        if (h == 0) return false;
        uint256 r = addmod(mulmod(y2, mulmod(zz, z1, p), p), p - y1, p);
        uint256 hh = mulmod(h, h, p);
        uint256 hhh = mulmod(hh, h, p);
        uint256 v = mulmod(x1, hh, p);
        uint256 x3 = addmod(addmod(mulmod(r, r, p), p - hhh, p), p - addmod(v, v, p), p);
        a[1] = addmod(mulmod(r, addmod(v, p - x3, p), p), p - mulmod(y1, hhh, p), p);
        a[0] = x3;
        a[2] = mulmod(z1, h, p);
        return true;
    }
}
