// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {Bip340} from "./Bip340.sol";

// sha256("KeyAgg list") and sha256("KeyAgg coefficient"): the BIP-327 KeyAgg tags (pinned by the tests).
bytes32 constant KEYAGG_LIST_TAG = 0x481c971c3c0b46d7f0b275ae598d4e2c7ed7319c594a5c6ec79ea0d4990294f0;
bytes32 constant KEYAGG_COEF_TAG = 0xbfc904034d1c88e8c80e22e53d24566d64824ed6427281c09100f94dcd52c981;

/// @title UA verifier for `musig2-secp256k1` (0x0110, accounts.md §1.6.1, §1.9).
/// @notice `verify(vk, m, sig)`: `vk = Q` (33, SEC1 compressed, from the registry's `keyPtr`), BIP-340 verify of the
///         32-byte `ua_msg` by `x(Q)` (BIP-327 output is BIP-340-valid; Q's parity plays no role here).
///         `verifyPop(keyData, m, pop)`: `keyData = Q (33) ‖ u16 n ‖ n × pk_i (33)`, `pop = sig (64) ‖ n × H_i (64)`.
///         Recomputes BIP-327 KeyAgg: `L = hash_{KeyAgg list}(pk_1 ‖ … ‖ pk_n)`, `a_i = hash_{KeyAgg coefficient}(L ‖
///         pk_i) mod N`, `a_i = 1` for the second distinct key (keys are strictly increasing, so it is `pk_2`); each hint
///         is checked as `address(H_i) == ecrecover(0, 25 + prefix_i, x(P_i), a_i·x(P_i) mod N)` (= `address(a_i·P_i)`,
///         `x(P_i) < N` required); the hints are summed in Jacobian coordinates (no inversion: `Q` is lifted with one
///         MODEXP and compared projectively, x and parity); then BIP-340 by `x(Q)` over `m`. A degenerate partial sum
///         (`S == ±H_i`, never met by an honest group) gives `Z = 0` and fails closed. Malformed input returns false,
///         never reverts. **UNAUDITED.**
contract Musig2Secp256k1Verifier is IUAPopVerifier {
    uint256 private constant _P = Bip340.P;
    uint256 private constant _N = Bip340.N;

    function verify(bytes calldata vk, bytes32 message, bytes calldata sig) public view returns (bool) {
        return vk.length == 33 && (vk[0] == 0x02 || vk[0] == 0x03)
            && Bip340.verify(uint256(bytes32(vk[1:33])), message, sig);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata pop) external view returns (bool) {
        if (keyData.length < 35) return false;
        uint256 n = uint16(bytes2(keyData[33:35]));
        if (n < 2 || n > 16 || keyData.length != 35 + 33 * n || pop.length != 64 + 64 * n) return false;
        return keyAgg(keyData, n, pop[64:]) && verify(keyData[0:33], message, pop[0:64]);
    }

    /// `Q` (keyData[0:33]) == Σ a_i·P_i with the hints `h = n × (x ‖ y)`; lengths checked by the caller.
    function keyAgg(bytes calldata keyData, uint256 n, bytes calldata h) internal view returns (bool) {
        bytes32 l = sha256(abi.encodePacked(KEYAGG_LIST_TAG, KEYAGG_LIST_TAG, keyData[35:]));
        (uint256 x1, uint256 y1, uint256 z1) = (0, 0, 0);
        for (uint256 i; i < n; ++i) {
            (bool ok, uint256 hx, uint256 hy) = _hint(keyData, h, l, i);
            if (!ok) return false;
            if (i == 0) (x1, y1, z1) = (hx, hy, 1);
            else (x1, y1, z1) = _addMixed(x1, y1, z1, hx, hy);
        }
        // Q from its compressed form: x(Q) < p, on the curve, y of the stated parity; compare X == x·Z², Y == y·Z³
        uint256 qx = uint256(bytes32(keyData[1:33]));
        if (qx >= _P || z1 == 0) return false;
        (bool ok, uint256 qy) = Bip340.liftX(qx);
        if (!ok) return false;
        if (keyData[0] == 0x03) qy = _P - qy;
        uint256 zz = mulmod(z1, z1, _P);
        return x1 == mulmod(qx, zz, _P) && y1 == mulmod(qy, mulmod(zz, z1, _P), _P);
    }

    /// Key `i`: SEC1 prefix, `x(P_i) < N`, strictly above key `i − 1` (KeySort), and the hint `H_i == a_i·P_i` by the
    /// `ecrecover` trick; returns `H_i`.
    function _hint(bytes calldata keyData, bytes calldata h, bytes32 l, uint256 i)
        private
        view
        returns (bool, uint256 hx, uint256 hy)
    {
        uint256 o = 35 + 33 * i;
        uint8 prefix = uint8(keyData[o]);
        uint256 x = uint256(bytes32(keyData[o + 1:o + 33]));
        if ((prefix != 2 && prefix != 3) || x >= _N) return (false, 0, 0);
        if (i > 0) {
            uint8 pp = uint8(keyData[o - 33]);
            if (pp > prefix || (pp == prefix && uint256(bytes32(keyData[o - 32:o])) >= x)) return (false, 0, 0);
        }
        // a_i = 1 for the second distinct key (BIP-327 GetSecondKey; keys are distinct and sorted, so it is pk_2)
        uint256 a = i == 1 ? 1 : _coef(l, keyData[o:o + 33]);
        (hx, hy) = (uint256(bytes32(h[64 * i:64 * i + 32])), uint256(bytes32(h[64 * i + 32:64 * i + 64])));
        if (hx >= _P || hy >= _P) return (false, 0, 0);
        address got = ecrecover(0, 25 + prefix, bytes32(x), bytes32(mulmod(a, x, _N)));
        return (got != address(0) && got == address(uint160(uint256(keccak256(abi.encodePacked(hx, hy))))), hx, hy);
    }

    /// `a_i = hash_{KeyAgg coefficient}(L ‖ pk_i) mod N`.
    function _coef(bytes32 l, bytes calldata pk) private view returns (uint256) {
        return uint256(sha256(abi.encodePacked(KEYAGG_COEF_TAG, KEYAGG_COEF_TAG, l, pk))) % _N;
    }

    /// Jacobian (x1, y1, z1) + affine (x2, y2) on y² = x³ + 7 (textbook mixed addition). `H == 0` (doubling or
    /// P + (−P)) yields z3 = 0, which every later step keeps at 0: the caller then refuses.
    function _addMixed(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2)
        private
        pure
        returns (uint256 x3, uint256 y3, uint256 z3)
    {
        uint256 zz = mulmod(z1, z1, _P);
        uint256 hh = addmod(mulmod(x2, zz, _P), _P - x1, _P); // U2 − X1
        uint256 r = addmod(mulmod(y2, mulmod(zz, z1, _P), _P), _P - y1, _P); // S2 − Y1
        uint256 h2 = mulmod(hh, hh, _P);
        uint256 h3 = mulmod(h2, hh, _P);
        uint256 v = mulmod(x1, h2, _P);
        x3 = addmod(addmod(mulmod(r, r, _P), _P - h3, _P), _P - addmod(v, v, _P), _P);
        y3 = addmod(mulmod(r, addmod(v, _P - x3, _P), _P), _P - mulmod(y1, h3, _P), _P);
        z3 = mulmod(z1, hh, _P);
    }
}
