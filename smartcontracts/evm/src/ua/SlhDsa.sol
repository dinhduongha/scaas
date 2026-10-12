// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "./IUAVerifier.sol";
import {PqUA} from "./PqUA.sol";

/// @title SLH-DSA-SHA2-128s verification (FIPS 205, Algorithms 8, 11, 13, 17, 20; SHA2 category 1, §11.2.1).
/// @notice n = 16, h = 63, d = 7, h' = 9, a = 12, k = 14, lg w = 4, len = 35, m = 30; pk = PK.seed ‖ PK.root (32 B),
///         sig = R ‖ SIG_FORS ‖ SIG_HT (7,856 B). Every tweakable hash is `Trunc16(SHA-256(PK.seed ‖ 0^48 ‖ ADRSc ‖ M))`
///         on the SHA-256 precompile 0x02, with one memory buffer per input shape: `PK.seed ‖ 0^48` (64 B), then the
///         22-byte compressed address `ADRSc`, then the message. **UNAUDITED.**
/// @dev Gas is linear in the WOTS+ chain steps an input forces: at most 510 per layer (checksum included), 3,570 in all,
///      plus 182 FORS hashes; the measured worst case is in `test/ua/PqGas.t.sol`.
library SlhDsaSha2128s {
    uint256 internal constant SIG_LEN = 7856;
    uint256 private constant HI16 = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
    // ADRS types (FIPS 205 §4.2)
    uint256 private constant WOTS_HASH = 0;
    uint256 private constant WOTS_PK = 1;
    uint256 private constant TREE = 2;
    uint256 private constant FORS_TREE = 3;
    uint256 private constant FORS_ROOTS = 4;
    // signature layout: R (16) ‖ FORS 14 × (sk 16 ‖ auth 12 × 16) ‖ HT 7 × (WOTS 35 × 16 ‖ auth 9 × 16)
    uint256 private constant FORS_OFF = 16;
    uint256 internal constant HT_OFF = 16 + 14 * 13 * 16; // 2928
    uint256 internal constant XMSS_LEN = (35 + 9) * 16; // 704

    /// `slh_verify_internal(M', SIG, PK)`. `mPrime` is the formatted message (pure interface: `0 ‖ |ctx| ‖ ctx ‖ M`).
    function verify(bytes calldata pk, bytes memory mPrime, bytes calldata sig) internal view returns (bool) {
        if (pk.length != 32 || sig.length != SIG_LEN) return false;
        bytes32 seed = bytes32(pk[0:16]);
        bytes32 root = bytes32(pk[16:32]);
        bytes16 r = bytes16(sig[0:16]);
        // H_msg = MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M'), 30)
        bytes32 inner = sha256(abi.encodePacked(r, bytes16(seed), bytes16(root), mPrime));
        uint256 dg = uint256(sha256(abi.encodePacked(r, bytes16(seed), inner, uint32(0))));
        uint256 md = dg >> 88; // 21 bytes = 14 × 12-bit FORS indices
        uint256 idxTree = (dg >> 32) & ((1 << 54) - 1); // bytes 21..27 mod 2^54
        uint256 idxLeaf = (dg >> 16) & 0x1ff; // bytes 28..29 mod 2^9

        uint256 b = buf(seed, 160); // tweakable hashes F and H: 64 + 22 + 32
        uint256 t = buf(seed, 704); // T_k (FORS roots) and T_len (WOTS+ public keys): 64 + 22 + 35 × 16
        uint256 node = forsPk(sig, md, idxTree, idxLeaf, b, t);
        for (uint256 j; j < 7; ++j) {
            if (j != 0) {
                idxLeaf = idxTree & 0x1ff;
                idxTree >>= 9;
            }
            node = xmssPk(sig, HT_OFF + j * XMSS_LEN, node, j, idxTree, idxLeaf, b, t);
        }
        return bytes32(node) == root;
    }

    /// A buffer starting with `PK.seed ‖ 0^48`.
    function buf(bytes32 seed, uint256 len) internal pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := mload(0x40)
            mstore(0x40, add(p, len))
            mstore(p, seed)
            mstore(add(p, 0x20), 0)
        }
    }

    /// ADRSc = layer (1) ‖ tree (8) ‖ type (1) ‖ word1 (4) ‖ word2 (4) ‖ word3 (4), right-aligned in a word, so
    /// `mstore(buf + 54, adrs)` writes it at buf + 64 and re-zeroes the last 10 padding bytes.
    function _adrs(uint256 layer, uint256 tree, uint256 typ, uint256 w1) private pure returns (uint256) {
        return (layer << 168) | (tree << 104) | (typ << 96) | (w1 << 64);
    }

    /// Algorithm 17 `fors_pkFromSig` then `T_k` (internal: the gas test composes the worst case from it).
    function forsPk(bytes calldata sig, uint256 md, uint256 tree, uint256 leaf, uint256 b, uint256 t)
        internal view returns (uint256 pk)
    {
        uint256 base = _adrs(0, tree, FORS_TREE, leaf);
        assembly ("memory-safe") {
            let s := add(sig.offset, FORS_OFF)
            for { let i := 0 } lt(i, 14) { i := add(i, 1) } {
                let idx := and(shr(sub(156, mul(i, 12)), md), 0xfff)
                let ti := add(shl(12, i), idx)
                let o := add(s, mul(i, 208))
                // leaf: F(PK.seed, ADRS(height 0, index ti), sk)
                mstore(add(b, 54), or(base, ti))
                calldatacopy(add(b, 86), o, 16)
                if iszero(staticcall(gas(), 2, b, 102, 0, 0x20)) { revert(0, 0) }
                let nd := and(mload(0), HI16)
                for { let j := 0 } lt(j, 12) { j := add(j, 1) } {
                    let au := and(calldataload(add(o, mul(add(j, 1), 16))), HI16)
                    let odd := and(shr(j, idx), 1)
                    ti := shr(1, ti) // (ti - odd) / 2 == ti >> 1
                    mstore(add(b, 54), or(or(base, shl(32, add(j, 1))), ti))
                    switch odd
                    case 0 { mstore(add(b, 86), nd) mstore(add(b, 102), au) }
                    default { mstore(add(b, 86), au) mstore(add(b, 102), nd) }
                    if iszero(staticcall(gas(), 2, b, 118, 0, 0x20)) { revert(0, 0) }
                    nd := and(mload(0), HI16)
                }
                mstore(add(t, add(86, shl(4, i))), nd)
            }
        }
        uint256 rootsAdrs = _adrs(0, tree, FORS_ROOTS, leaf);
        assembly ("memory-safe") {
            mstore(add(t, 54), rootsAdrs)
            if iszero(staticcall(gas(), 2, t, 310, 0, 0x20)) { revert(0, 0) } // 64 + 22 + 14 × 16
            pk := and(mload(0), HI16)
        }
    }

    /// Algorithm 11 `xmss_pkFromSig` (with Algorithm 8 `wots_pkFromSig` inline) at hypertree layer `layer`; the work
    /// is largest for `m = 0` (510 chain steps).
    function xmssPk(bytes calldata sig, uint256 off, uint256 m, uint256 layer, uint256 tree, uint256 leaf,
        uint256 b, uint256 t) internal view returns (uint256 node)
    {
        uint256 chainBase = _adrs(layer, tree, WOTS_HASH, leaf);
        uint256 pkAdrs = _adrs(layer, tree, WOTS_PK, leaf);
        uint256 treeBase = _adrs(layer, tree, TREE, 0);
        assembly ("memory-safe") {
            let s := add(sig.offset, off)
            // message nibbles (high nibble first) and the checksum Σ(15 − m_i), 3 nibbles
            let csum := 0
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                csum := add(csum, sub(15, and(shr(sub(252, shl(2, i)), m), 15)))
            }
            for { let i := 0 } lt(i, 35) { i := add(i, 1) } {
                let v
                switch lt(i, 32)
                case 1 { v := and(shr(sub(252, shl(2, i)), m), 15) }
                default { v := and(shr(shl(2, sub(34, i)), csum), 15) }
                calldatacopy(add(b, 86), add(s, shl(4, i)), 16)
                let a := or(chainBase, shl(32, i))
                for { let j := v } lt(j, 15) { j := add(j, 1) } {
                    mstore(add(b, 54), or(a, j))
                    if iszero(staticcall(gas(), 2, b, 102, add(b, 86), 0x20)) { revert(0, 0) }
                }
                mstore(add(t, add(86, shl(4, i))), and(mload(add(b, 86)), HI16))
            }
            mstore(add(t, 54), pkAdrs)
            if iszero(staticcall(gas(), 2, t, 646, 0, 0x20)) { revert(0, 0) } // 64 + 22 + 35 × 16
            node := and(mload(0), HI16)
            // authentication path, h' = 9
            let au0 := add(s, 560)
            let ti := leaf
            for { let k := 0 } lt(k, 9) { k := add(k, 1) } {
                let au := and(calldataload(add(au0, shl(4, k))), HI16)
                let odd := and(shr(k, leaf), 1)
                ti := shr(1, ti)
                mstore(add(b, 54), or(or(treeBase, shl(32, add(k, 1))), ti))
                switch odd
                case 0 { mstore(add(b, 86), node) mstore(add(b, 102), au) }
                default { mstore(add(b, 86), au) mstore(add(b, 102), node) }
                if iszero(staticcall(gas(), 2, b, 118, 0, 0x20)) { revert(0, 0) }
                node := and(mload(0), HI16)
            }
        }
    }
}

/// @title `slhdsa128s` UA verifier (accounts.md CTR-UA-23, kind 0x0133): SLH-DSA-SHA2-128s over `pq_msg` with the empty
///        context, pure Solidity on SHA-256 `0x02` (no EIP proposes an SLH-DSA precompile). **UNAUDITED.**
contract UASlhdsaVerifier is IUAPopVerifier {
    bytes32 public constant TAG = keccak256("scaas.ua.slhdsa128s.v1");

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        return SlhDsaSha2128s.verify(keyData, PqUA.emptyContext(PqUA.pqMessage(TAG, message)), sig);
    }

    /// The PoP is an ordinary signature over the PoP `ua_msg` (accounts.md §1.8 step 6).
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}
