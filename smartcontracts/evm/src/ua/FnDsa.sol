// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAKindVerifier} from "./IUAVerifier.sol";
import {Shake} from "./Shake.sol";
import {PqNtt} from "./PqNtt.sol";

/// @title Falcon-512 verification (round-3 specification v1.2 Algorithm 16; EIP-8052 `FALCON_HASH_TO_POINT_SHAKE256`
///        + `FALCON_CORE`): `c = HashToPoint(salt ‖ msg)` by SHAKE256, `s1 = c − s2·h`, accept iff
///        `‖s1‖² + ‖s2‖² ≤ ⌊β²⌋ = 34,034,726` (the reference code's bound; EIP-8052's text says `<`).
/// @notice pk (897 B) = `0x09 ‖ h` (512 × 14-bit big-endian, each `< q`); sig (666 B) = the round-3 padded format
///         `0x39 ‖ salt (40) ‖ compressed s2`, zero-padded (EIP-8052's 666-byte "padded signature"). The decoder is
///         the reference `comp_decode`: sign bit, 7 low bits, unary high part, `|v| ≤ 2047`, no "−0", every bit after
///         the last coefficient zero. **UNAUDITED.**
library Falcon512 {
    uint256 internal constant N = 512;
    uint256 internal constant Q = 12289;
    uint256 internal constant PK_LEN = 897;
    uint256 internal constant SIG_LEN = 666;
    uint256 internal constant BOUND = 34034726;
    /// `zetas[k] = 10302^brv9(k) mod q`, k = 0..511, u16 big-endian (10302 = 11^12: a primitive 1024-th root of unity).
    bytes internal constant ZETAS = hex"000105c72036141a102619992d2f051916e40c7b04bc29930e25261022510dd61c8f2aba23011691139f193d166011ef0bbe2549023324620a412c4c12d50a4f2f75073d02d612032b68109f0ad006630b931ce1093e241623ee2fb02c191f21222012c52bdb08f6254612ee23c22181243b0c811c232ad3049226f203bb2ceb20942321095c11641b030b1500821eff2c480ea4197a2cc613cb276c2f8b26551f4b068914d31c842a9c26241051220101e024e703fe2ff8169f2de1265d2eae2f701a5b21cc0d830aab20a518ea1ce729220e7b2193143b0d360163108709f423582d280cd92824232d24c013e427d819861218112404ec014e097a059429610d48095f144723c1243900f30bb8029f0dcb2e250f911cd8277f29f91a4a2e5d23520a7e0b990f8a224b1b2d24d009422031273824bd2b800c72151f27b3065e0cc72028296822dd113e0b1f278311142525144b1ce22a3527001c4f0fd525ac2f901337087620b62f6123b41eac000305921dd32910067f21cd134a0a9014ab149d04902b4a2351085f2bd82e6d122510002e141544094d2a9f077810f12e4e137029ba2c96213d2c1713931f4513e0267c21c32456187b09761797088b0a062a61214e2407001b1c2506601cec03f9102f1d972f0f2a0021890a761c662de00ef90ec22e7b030513ed2bd626a001ba24a119bf01621d04139409b1041524d6283e295b22142d731bab159923822fc918081354019006c0191b17f81ada0e3b2ab2153b04e62c3428100f9e287f20da2e2d206d2e83013c1b26154617cd0e7e1e8e12b51d7415a10ecd009315501ea02be71e4915450f14258604a6211717e6172503fa2247041107b515c62b0309280feb14c310e4133427882df71c2a234318892c8c1c7007a42c160dcc2f102fc704512f731631226c22930b1c03cf107421ef17b401a520110e100cbf1df117bd12ae1903242c15da1f8c2e09025d2703155c03f2031322671479249923ca1fb813c11da70d751d5508011cd12ad800c001af29d609c917122f6a27b2208c24ea190f02a5185a0d082fcd239b052b0ace0c4e0527203302c51f71220f2cbe1850039a2e482012042207a61f1f27e32ba9004021b92d562666196b061e0b84263a18e21eb00efa1489292e23ce2413156e057c2ebc047a2c4d0e902030189b048717d3012716862d75214f0b67205120140d011f37257d00a829c707aa13f218b814b1181a0f7405502b511bc12606181724bf070d07a2080317fe098f0f7b2dc12297223824a500da26c828ce242b101314d5281216f408e9009c253220800f9701c518ed2e5f214512a61acc1281050d27f814f9237f1e74015e05e828ea1afa05d109c4062f18cb2b122fd018e605cb0bc1069d02d300ae0ab219150a5f199a284a0ead24942ea61d6f28bf01aa0cf3";

    /// Verifies `sig` over `msg` (32 bytes on the UA path; any length here). Requires `Shake.reserve()` first.
    function verify(bytes calldata pk, bytes memory message, bytes calldata sig) internal pure returns (bool) {
        if (pk.length != PK_LEN || sig.length != SIG_LEN || pk[0] != 0x09 || sig[0] != 0x39) return false;
        (bool ok, uint256 s2) = _decompress(sig[41:]);
        if (!ok) return false;
        uint256 h = PqNtt.alloc(N);
        if (!_decodePk(pk[1:], h)) return false;
        return _short(s2, h, _hashToPoint(sig[1:41], message));
    }

    /// ‖c − s2·h‖² + ‖s2‖² ≤ ⌊β²⌋, with `s1` centred in (−q/2, q/2].
    function _short(uint256 s2, uint256 h, uint256 c) private pure returns (bool) {
        uint256 z = PqNtt.table(ZETAS, 2);
        uint256 t = PqNtt.alloc(N); // s2 mod q
        uint256 norm;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, shl(5, N)) { i := add(i, 32) } {
                let v := mload(add(s2, i)) // signed, |v| ≤ 2047
                norm := add(norm, mul(v, v))
                mstore(add(t, i), mod(add(v, Q), Q)) // wraps a negative v into [0, q)
            }
        }
        PqNtt.ntt(t, N, Q, z);
        PqNtt.ntt(h, N, Q, z);
        PqNtt.mulPoint(t, h, N, Q);
        PqNtt.intt(t, N, Q, z); // t = s2·h
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, shl(5, N)) { i := add(i, 32) } {
                let v := addmod(mload(add(c, i)), sub(Q, mload(add(t, i))), Q) // s1 = c − s2·h
                if gt(v, 6144) { v := sub(Q, v) }
                norm := add(norm, mul(v, v))
            }
        }
        return norm <= BOUND;
    }

    /// SHAKE256(salt ‖ msg): 16-bit big-endian draws, keep `t < 61445 = 5q`, `c_i = t mod q`.
    function _hashToPoint(bytes calldata salt, bytes memory message) private pure returns (uint256 c) {
        bytes memory input = abi.encodePacked(salt, message);
        uint256 inPtr;
        assembly ("memory-safe") {
            inPtr := add(input, 32)
        }
        Shake.absorb(Shake.SHAKE256, inPtr, input.length);
        c = PqNtt.alloc(N);
        uint256 buf = PqNtt.alloc(6); // one 136-byte block + slack
        uint256 i;
        while (i < N) {
            Shake.squeeze(Shake.SHAKE256, buf);
            assembly ("memory-safe") {
                for { let o := 0 } and(lt(o, 136), lt(i, N)) { o := add(o, 2) } {
                    let t := shr(240, mload(add(buf, o)))
                    if lt(t, 61445) {
                        mstore(add(c, shl(5, i)), mod(t, Q))
                        i := add(i, 1)
                    }
                }
            }
        }
    }

    /// 512 × 14-bit big-endian coefficients, each `< q`.
    function _decodePk(bytes calldata enc, uint256 h) private pure returns (bool ok) {
        ok = true;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let bit := mul(i, 14)
                let v := and(shr(sub(242, and(bit, 7)), calldataload(add(enc.offset, shr(3, bit)))), 0x3fff)
                if iszero(lt(v, Q)) { ok := 0 }
                mstore(add(h, shl(5, i)), v)
            }
        }
    }

    /// Reference `comp_decode` over the 625 bytes after the salt; s2 as signed words (two's complement). Internal for the
    /// decoder test (`|s2_i| ≤ 2047` is not observable through `verify`).
    function _decompress(bytes calldata comp) internal pure returns (bool ok, uint256 s2) {
        s2 = PqNtt.alloc(N);
        ok = true;
        uint256 src;
        uint256 pos;
        assembly ("memory-safe") {
            src := comp.offset
            // n bits (n ≤ 8) at bit position p, most significant bit first
            function rd(from, p, n) -> v {
                v := and(shr(sub(256, add(and(p, 7), n)), calldataload(add(from, shr(3, p)))), sub(shl(n, 1), 1))
            }
            let limit := shl(3, comp.length)
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                if gt(add(pos, 8), limit) { ok := 0 break }
                let b := rd(src, pos, 8)
                pos := add(pos, 8)
                let m := and(b, 0x7f)
                for {} 1 {} {
                    if iszero(lt(pos, limit)) { ok := 0 break }
                    let bit := rd(src, pos, 1)
                    pos := add(pos, 1)
                    if bit { break }
                    m := add(m, 128)
                    if gt(m, 2047) { ok := 0 break }
                }
                if iszero(ok) { break }
                b := shr(7, b) // sign
                if and(b, iszero(m)) { ok := 0 break } // "−0"
                if b { m := sub(0, m) }
                mstore(add(s2, shl(5, i)), m)
            }
        }
        if (ok) ok = _zeroTail(comp, pos);
    }

    /// Every bit of `comp` from bit `pos` on is zero (the unused bits of the last byte, then the padding).
    function _zeroTail(bytes calldata comp, uint256 pos) private pure returns (bool ok) {
        ok = true;
        assembly ("memory-safe") {
            if and(pos, 7) {
                let cur := byte(0, calldataload(add(comp.offset, shr(3, pos))))
                if and(cur, sub(shl(sub(8, and(pos, 7)), 1), 1)) { ok := 0 }
                pos := and(add(pos, 7), not(7))
            }
            for { let o := shr(3, pos) } lt(o, comp.length) { o := add(o, 32) } {
                let w := calldataload(add(comp.offset, o))
                let left := sub(comp.length, o)
                if lt(left, 32) { w := shr(shl(3, sub(32, left)), w) }
                if w { ok := 0 }
            }
        }
    }
}

/// @title `fndsa512` UA verifier (accounts.md CTR-UA-23, kind 0x0132): Falcon-512 over the 32-byte `ua_msg`, the message
///        size of EIP-8052 (Falcon has no context string; `ua_msg` already carries `TAG(kind)`). Pure Solidity: EIP-8052
///        has no addresses yet. **UNAUDITED.**
contract UAFndsaVerifier is IUAKindVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return Falcon512.verify(keyData, abi.encodePacked(message), sig);
    }
}
