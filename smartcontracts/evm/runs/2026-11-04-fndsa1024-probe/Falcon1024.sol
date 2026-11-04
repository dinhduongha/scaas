// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Shake} from "../../src/ua/Shake.sol";
import {PqNtt} from "../../src/ua/PqNtt.sol";

/// @title Falcon-1024 probe (2026-11-04, research, not `src/`): a copy of `src/ua/FnDsa.sol`'s `Falcon512` at main
///        4c72332d with the Falcon-1024 parameters (specification v1.2, NIST round 3, Table 3.3 and the reference
///        `common.c` `l2bound`), marked PROBE, and one addition: `verifyNtt`, the same check on a key already in the NTT
///        domain (`ĥ = NTT(h)`, the cached form; FIPS 206's provisional public-key encoding is also the NTT form).
///        Same SHAKE, NTT, decoder and norm code as the built Falcon-512 verifier. **UNAUDITED.**
/// @notice pk (1,793 B) = `0x0A ‖ h` (1024 × 14-bit big-endian, each `< q`); sig (1,280 B) = the round-3 padded format
///         `0x3A ‖ salt (40) ‖ compressed s2 (1,239 B)`, zero-padded (the reference `falcon.h` FALCON_SIG_PADDED_SIZE(10)).
///         Accept iff `‖c − s2·h‖² + ‖s2‖² ≤ ⌊β²⌋ = 70,265,242` (`l2bound[10]`).
library Falcon1024 {
    uint256 internal constant N = 1024; // PROBE (512)
    uint256 internal constant Q = 12289;
    uint256 internal constant PK_LEN = 1793; // PROBE (897)
    uint256 internal constant SIG_LEN = 1280; // PROBE (666)
    uint256 internal constant BOUND = 70265242; // PROBE (34,034,726)
    bytes1 internal constant PK_HEAD = 0x0a; // PROBE (0x09): 0x00 + logn
    bytes1 internal constant SIG_HEAD = 0x3a; // PROBE (0x39): 0x30 + logn, compressed / padded
    /// `zetas[k] = 1945^brv10(k) mod q`, k = 0..1023, u16 big-endian (1945 = 11^6: a primitive 2048-th root of unity;
    /// 1945^2 = 10302, Falcon-512's root). PROBE (512 entries, root 10302).
    bytes internal constant ZETAS = hex"000105c72036141a102619992d2f051916e40c7b04bc29930e25261022510dd61c8f2aba23011691139f193d166011ef0bbe2549023324620a412c4c12d50a4f2f75073d02d612032b68109f0ad006630b931ce1093e241623ee2fb02c191f21222012c52bdb08f6254612ee23c22181243b0c811c232ad3049226f203bb2ceb20942321095c11641b030b1500821eff2c480ea4197a2cc613cb276c2f8b26551f4b068914d31c842a9c26241051220101e024e703fe2ff8169f2de1265d2eae2f701a5b21cc0d830aab20a518ea1ce729220e7b2193143b0d360163108709f423582d280cd92824232d24c013e427d819861218112404ec014e097a059429610d48095f144723c1243900f30bb8029f0dcb2e250f911cd8277f29f91a4a2e5d23520a7e0b990f8a224b1b2d24d009422031273824bd2b800c72151f27b3065e0cc72028296822dd113e0b1f278311142525144b1ce22a3527001c4f0fd525ac2f901337087620b62f6123b41eac000305921dd32910067f21cd134a0a9014ab149d04902b4a2351085f2bd82e6d122510002e141544094d2a9f077810f12e4e137029ba2c96213d2c1713931f4513e0267c21c32456187b09761797088b0a062a61214e2407001b1c2506601cec03f9102f1d972f0f2a0021890a761c662de00ef90ec22e7b030513ed2bd626a001ba24a119bf01621d04139409b1041524d6283e295b22142d731bab159923822fc918081354019006c0191b17f81ada0e3b2ab2153b04e62c3428100f9e287f20da2e2d206d2e83013c1b26154617cd0e7e1e8e12b51d7415a10ecd009315501ea02be71e4915450f14258604a6211717e6172503fa2247041107b515c62b0309280feb14c310e4133427882df71c2a234318892c8c1c7007a42c160dcc2f102fc704512f731631226c22930b1c03cf107421ef17b401a520110e100cbf1df117bd12ae1903242c15da1f8c2e09025d2703155c03f2031322671479249923ca1fb813c11da70d751d5508011cd12ad800c001af29d609c917122f6a27b2208c24ea190f02a5185a0d082fcd239b052b0ace0c4e0527203302c51f71220f2cbe1850039a2e482012042207a61f1f27e32ba9004021b92d562666196b061e0b84263a18e21eb00efa1489292e23ce2413156e057c2ebc047a2c4d0e902030189b048717d3012716862d75214f0b67205120140d011f37257d00a829c707aa13f218b814b1181a0f7405502b511bc12606181724bf070d07a2080317fe098f0f7b2dc12297223824a500da26c828ce242b101314d5281216f408e9009c253220800f9701c518ed2e5f214512a61acc1281050d27f814f9237f1e74015e05e828ea1afa05d109c4062f18cb2b122fd018e605cb0bc1069d02d300ae0ab219150a5f199a284a0ead24942ea61d6f28bf01aa0cf307990405052d165c0e28076422f11a2316a5208a279d174704e0098a13fb1cb605f208670d0f10172fed1c771bd61e0124b321bb052206d0163a266a01522096286b0d502b7425f2224a1566049a25292e0704e716980570258f08a422f70ccc1fba17c52bf3039b0af02f40274a17cc2e881e1f0177065408892e79072c2e582f4d102a0a811e04158500cc1b9e2a80080609b30be205402e320d4f0f8d05bc2be025d923d01261147e117b04d424382e950938242d1ba11a732b371283109b026e2938119316280b83207315e9027c1cd02239108b21100d2f08f31f120d4102001dc31aa9132a0b5400ef2c1f11ca070c057b17ce1445296a2e6b00921b6d05ee214c1c3a1fb11f561615271e099d29251fd0223320880da71e2d0811193f046b05a52b9c1d05166604981a7d04fb0f3102431a25189e0c2a253018b32f2d21ea2ad2209b1b911d541cc52c0b2e41003c0a9d0c8005ff08d42fbd16cc11d6058919d527301199207a1cee23f216cb21611363241109e0192c1a2d2e6513ee099229582e612cd30874152802cc083e0d782eaa1e47288d2b491d8a145b074a1add1f901898233313c504c22e4b0dbb0e052d340ba62aa41007268406b9060004441459237c0d1f10a90e5e28792e3122882b912185235b249328df1e78239e1f732d9d0d281083107e05f62f842de5056d0814015a1ecd0c5b204112e8181218b01dd82490178a01d204062114069120fb06250ed117af0a2a076d2e0b1c032ba109e716b000150b3924f6267f03172c97270419ef00aa2f6b2d7910c1090300082e3811ab10cd212e0cc4197128c8271d03d625e02c921126107a22830eae247405c9280324850cf509e422fd2f762def0a421198030a2207125906a5227704ff2ca00a701bcf0c2c00bd291e27602abb193906c6211a296305fa0f1d1eba2b7912d41e5b0c1625571523074c2734290a13d61c9311d509ae0b1824361f9f149b29031adf2b1e181428a7041007f31239151e0bcc16290e551b5a2c5112a20a5304471695241c04d9111a228620030f0007321ff02fb924f51f0112e225691aac247f1e630a4d2c902e94287a03f72c7909b513af15ab2b012d9b055b00180636113b2b3a26e329ee28f71c12289e09221255270c01a117fa22741ea60d5a0a3e1af712352e0301c207982dbf14f80e5621211c8626bc1bf22fc2124c22e12a8b23ef2cc71c4e22531964067a1a0f118319ba05e20bf9038e18f51d9202ef295720a80c9d1d8705020df40b10281c17c6160e23d118280f650ea914fa0dd003011a6b003200d8212402ff275c1fc821762cb428712ffa1c4323af232c1ef914e524800a492a8312f70eb9236101251ffe20991a1d1a6704f10bbf278622690b7d2dca14a919e310b10c950a230efd13da1e1302aa03d41baf2cb51457202f";

    /// Verifies `sig` over `message` (any length). Requires `Shake.reserve()` first.
    function verify(bytes calldata pk, bytes memory message, bytes calldata sig) internal pure returns (bool) {
        if (pk.length != PK_LEN || pk[0] != PK_HEAD) return false;
        uint256 h = PqNtt.alloc(N);
        if (!_decodePk(pk[1:], h)) return false;
        return _check(h, false, message, sig);
    }

    /// PROBE: the same check with `hHat` = NTT(h), 1024 × u16 big-endian, each `< q` (the cached form; the registry would
    /// derive it from the authenticated pk once, as the ML-DSA expanded key).
    function verifyNtt(bytes calldata hHat, bytes memory message, bytes calldata sig) internal pure returns (bool) {
        if (hHat.length != 2 * N) return false;
        uint256 h = PqNtt.alloc(N);
        bool ok = true;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let v := shr(240, calldataload(add(hHat.offset, shl(1, i))))
                if iszero(lt(v, Q)) { ok := 0 }
                mstore(add(h, shl(5, i)), v)
            }
        }
        if (!ok) return false;
        return _check(h, true, message, sig);
    }

    /// PROBE: ĥ = NTT(h) as `verifyNtt` reads it (what a registry cache would store).
    function nttKey(bytes calldata pk) internal pure returns (bytes memory out) {
        require(pk.length == PK_LEN && pk[0] == PK_HEAD, "pk");
        uint256 h = PqNtt.alloc(N);
        require(_decodePk(pk[1:], h), "pk range");
        PqNtt.ntt(h, N, Q, PqNtt.table(ZETAS, 2));
        out = new bytes(2 * N);
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let v := mod(mload(add(h, shl(5, i))), Q)
                mstore8(add(add(out, 32), shl(1, i)), shr(8, v))
                mstore8(add(add(out, 33), shl(1, i)), and(v, 0xff))
            }
        }
    }

    function _check(uint256 h, bool hInNtt, bytes memory message, bytes calldata sig) private pure returns (bool) {
        if (sig.length != SIG_LEN || sig[0] != SIG_HEAD) return false;
        (bool ok, uint256 s2) = _decompress(sig[41:]);
        if (!ok) return false;
        return _short(s2, h, hInNtt, _hashToPoint(sig[1:41], message));
    }

    /// ‖c − s2·h‖² + ‖s2‖² ≤ ⌊β²⌋, with `s1` centred in (−q/2, q/2].
    function _short(uint256 s2, uint256 h, bool hInNtt, uint256 c) private pure returns (bool) {
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
        if (!hInNtt) PqNtt.ntt(h, N, Q, z);
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

    /// 1024 × 14-bit big-endian coefficients, each `< q`.
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

    /// Reference `comp_decode` over the 1,239 bytes after the salt; s2 as signed words (two's complement).
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

/// The entries a `UAFndsaVerifier`-shaped verifier at Falcon-1024 would have (`verify` over the 32-byte `ua_msg`), plus
/// the probe's: any-length messages (the NIST KATs) and the cached NTT key form.
contract Fndsa1024Probe {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return Falcon1024.verify(keyData, abi.encodePacked(message), sig);
    }

    function verifyMsg(bytes calldata keyData, bytes calldata message, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return Falcon1024.verify(keyData, message, sig);
    }

    function verifyNtt(bytes calldata hHat, bytes32 message, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return Falcon1024.verifyNtt(hHat, abi.encodePacked(message), sig);
    }

    function verifyNttMsg(bytes calldata hHat, bytes calldata message, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return Falcon1024.verifyNtt(hHat, message, sig);
    }

    function nttKey(bytes calldata pk) external pure returns (bytes memory) {
        return Falcon1024.nttKey(pk);
    }

    function decompress(bytes calldata comp) external pure returns (bool ok) {
        (ok,) = Falcon1024._decompress(comp);
    }
}
