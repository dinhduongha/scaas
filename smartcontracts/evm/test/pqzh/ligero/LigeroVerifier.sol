// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// PQZH-Ligero verifier (test-only, never deployed): a full Solidity/Yul port of pqz-core/pqzh/ligero/src/ligero.rs
/// verify + cs.rs comb for R_REG (op 3), R_TX and R_TX0 (op 1; R_TX0, the transfer without the auditor, by the
/// 66,560-byte statement length, plan R6), docs/research/pqzh-ligero.md §4, §11 and §14.
///
/// F_q, q = 2^42 - 215; F_q^4 = F_q[Y]/(Y^4 - 3) packed in one word, lane s (coefficient of Y^s) at bits 64s..64s+63,
/// every lane canonical. Lazy sums of F_q^4 x F_q products use two words of two 128-bit lanes: (lane 0, lane 2) and
/// (lane 1, lane 3), each product < 2^84, so up to 2^44 terms fit a lane.
///
/// The matrix A (32 x 32 polynomials of 64 coefficients, canonical, 6 bytes big-endian, order (i, j, coefficient))
/// lives in data contracts of 24,576 B (EIP-170) and is copied to memory once per verify.
contract LigeroVerifier {
    uint256 internal constant Q = 4398046510889;
    uint256 internal constant M42 = 0x3ffffffffff;
    uint256 internal constant M64 = 0xffffffffffffffff;
    uint256 internal constant M128 = 0xffffffffffffffffffffffffffffffff;
    uint256 internal constant M02 = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
    uint256 internal constant DELTA = 67108863;
    uint256 internal constant ACHUNK = 24_576;
    uint256 internal constant ABYTES = 393_216;
    uint8 internal constant OP_TRANSFER = 1;
    uint8 internal constant OP_REGISTER = 3;
    uint256 internal constant TX_STMT = 83_072;
    uint256 internal constant TX0_STMT = 66_560;
    uint256 internal constant REG_STMT = 16_480;
    /// proofSystemId, statement bytes 32..63 (plan D3): keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")
    bytes32 internal constant PQZH_ID = 0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4;
    /// opTags keccak256("SCAAS-PQZ-OP-<NAME>-V1"), statement bytes 0..31
    bytes32 internal constant TAG_TRANSFER = 0xef22f3d1c1fc2edc565522eb73ca8cb782e8780eaf9b1f677965dd0cd5275414;
    bytes32 internal constant TAG_REGISTER = 0x69562a9cd615eb3d906cb1934ad56c788c30228d2faf7c517e33d65b4a03c088;
    // R_TX small items (Layout::small indices) and the slack base
    uint256 internal constant E2 = 0;
    uint256 internal constant DD = 1;
    uint256 internal constant DP = 2;
    uint256 internal constant MM = 3;
    uint256 internal constant CC = 4;
    uint256 internal constant ET = 5;
    uint256 internal constant SIG = 6;

    address[] internal aData;

    constructor(address[] memory a) {
        aData = a;
    }

    struct Params {
        uint256 n;
        uint256 k;
        uint256 ell;
        uint256 t;
        uint256 powBits;
    }

    struct V {
        uint256 op;
        uint256 legs; // op 1: ciphertext legs (R_TX 3: t, f, a; R_TX0 2: t, f)
        uint256 n;
        uint256 k;
        uint256 ell;
        uint256 t;
        uint256 m;
        uint256 d2;
        // layout
        uint256 nr;
        uint256[] bBase;
        uint256[] bBits;
        uint256[] bOff;
        uint256[] bB2;
        uint256[] sCount;
        uint256[] sBits;
        uint256[] sOff;
        uint256[] sV0;
        uint256[] sB0;
        uint256 sv;
        uint256 ss;
        uint256 sb;
        uint256 nsv;
        uint256 nsb;
        uint256[] tri; // x | y << 32 | z << 64
        // transcript
        bytes32 st;
        uint256 ctr;
        uint256 hbuf;
        uint256 hpos;
        uint256[] ca;
        uint256[] cb;
        uint256[] rq;
        uint256 cl;
        uint256 cq;
        uint256 rho;
        // proof (calldata offsets)
        uint256 pOff;
        uint256 wOff;
        uint256 qOff;
        uint256 hOff;
        uint256 colOff;
        uint256 cw;
        uint256[] idx;
        // statement (calldata offset)
        uint256 sOffs;
        // comb
        uint256[] ownIdx; // row -> own slot + 1 (0: none)
        uint256[] own; // nOwn x l packed F_q^4
        uint256[] ownLen;
        uint256[] ownRow;
        uint256[] beta;
        uint256[] ones;
        uint256 rhs;
        uint256 cur;
        uint256 rhoL;
        uint256[] rp; // rho^0..rho^64
        uint256[] amat; // A in memory (bytes as words)
    }

    // ---------------------------------------------------------------- field
    /// lane-wise reduction of a packed word whose lanes are < 2q
    function lred(uint256 s) internal pure returns (uint256 c) {
        assembly {
            let l0 := and(s, M64)
            let l1 := and(shr(64, s), M64)
            let l2 := and(shr(128, s), M64)
            let l3 := shr(192, s)
            c := or(or(sub(l0, mul(Q, iszero(lt(l0, Q)))), shl(64, sub(l1, mul(Q, iszero(lt(l1, Q)))))),
                or(shl(128, sub(l2, mul(Q, iszero(lt(l2, Q))))), shl(192, sub(l3, mul(Q, iszero(lt(l3, Q)))))))
        }
    }

    uint256 internal constant QP = 0x000003ffffffff29000003ffffffff29000003ffffffff29000003ffffffff29; // q in every lane

    function ea(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return lred(a + b);
        }
    }

    function es(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return lred(a + (QP - b));
        }
    }

    function eb(uint256 a, uint256 x) internal pure returns (uint256 c) {
        assembly {
            c := or(or(mulmod(and(a, M64), x, Q), shl(64, mulmod(and(shr(64, a), M64), x, Q))),
                or(shl(128, mulmod(and(shr(128, a), M64), x, Q)), shl(192, mulmod(shr(192, a), x, Q))))
        }
    }

    function em(uint256 a, uint256 b) internal pure returns (uint256 c) {
        assembly {
            let a0 := and(a, M64)
            let a1 := and(shr(64, a), M64)
            let a2 := and(shr(128, a), M64)
            let a3 := shr(192, a)
            let b0 := and(b, M64)
            let b1 := and(shr(64, b), M64)
            let b2 := and(shr(128, b), M64)
            let b3 := shr(192, b)
            c := mod(add(mul(a0, b0), mul(3, add(add(mul(a1, b3), mul(a2, b2)), mul(a3, b1)))), Q)
            c := or(c, shl(64, mod(add(add(mul(a0, b1), mul(a1, b0)), mul(3, add(mul(a2, b3), mul(a3, b2)))), Q)))
            c := or(c, shl(128, mod(add(add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0)), mul(3, mul(a3, b3))), Q)))
            c := or(c, shl(192, mod(add(add(add(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0)), Q)))
        }
    }

    /// rho f - c b - a63 in one reduction (cs.rs ring recurrence)
    function step(uint256 rho, uint256 f, uint256 c, uint256 b, uint256 a63) internal pure returns (uint256 r) {
        r = es(es(em(rho, f), em(c, b)), a63);
    }

    function epow(uint256 a, uint256 e) internal pure returns (uint256 r) {
        r = 1;
        while (e > 0) {
            if (e & 1 == 1) r = em(r, a);
            a = em(a, a);
            e >>= 1;
        }
    }

    function fpow(uint256 a, uint256 e) internal pure returns (uint256 r) {
        assembly {
            r := 1
            for {} gt(e, 0) { e := shr(1, e) } {
                if and(e, 1) { r := mulmod(r, a, Q) }
                a := mulmod(a, a, Q)
            }
        }
    }

    function red2(uint256 x02, uint256 x13) internal pure returns (uint256 c) {
        assembly {
            c := or(or(mod(and(x02, M128), Q), shl(64, mod(and(x13, M128), Q))),
                or(shl(128, mod(shr(128, x02), Q)), shl(192, mod(shr(128, x13), Q))))
        }
    }

    // ---------------------------------------------------------------- transcript (transcript.rs)
    function absorb(V memory v, bytes memory data) internal pure {
        v.st = keccak256(abi.encodePacked(v.st, data));
        v.ctr = 0;
        v.hpos = 4;
    }

    function absorbCd(V memory v, bytes calldata data) internal pure {
        v.st = keccak256(abi.encodePacked(v.st, data));
        v.ctr = 0;
        v.hpos = 4;
    }

    function word(V memory v) internal pure returns (uint256 w) {
        if (v.hpos == 4) {
            v.hbuf = uint256(keccak256(abi.encodePacked(v.st, uint8(0xff), uint64(v.ctr))));
            v.ctr++;
            v.hpos = 0;
        }
        w = (v.hbuf >> (192 - 64 * v.hpos)) & M64;
        v.hpos++;
    }

    function fq(V memory v) internal pure returns (uint256 x) {
        do {
            x = word(v) & M42;
        } while (x >= Q);
    }

    /// four successive base elements, lane 0 first (sequential: operand order is not specified in Solidity)
    function f4(V memory v) internal pure returns (uint256 x) {
        x = fq(v);
        x |= fq(v) << 64;
        x |= fq(v) << 128;
        x |= fq(v) << 192;
    }

    // ---------------------------------------------------------------- layout (cs.rs Layout::new)
    function mkLayout(V memory v) internal pure {
        uint256 ell = v.ell;
        uint256 nb = v.op == OP_REGISTER ? 2 : 4;
        uint256 ns = v.op == OP_REGISTER ? 2 : 10 + v.legs;
        v.bBase = new uint256[](nb);
        v.bBits = new uint256[](nb);
        v.bOff = new uint256[](nb);
        v.bB2 = new uint256[](nb);
        v.nr = (2048 + ell - 1) / ell;
        uint256 cur;
        for (uint256 g; g < nb; ++g) {
            bool sv = g % 2 == 0;
            v.bBits[g] = sv ? 7 : 9;
            v.bOff[g] = sv ? 64 : 256;
            v.bB2[g] = sv ? 1296 : 26896;
            v.bBase[g] = cur;
            cur += v.nr * (2 + v.bBits[g]);
        }
        v.sCount = new uint256[](ns);
        v.sBits = new uint256[](ns);
        v.sOff = new uint256[](ns);
        v.sV0 = new uint256[](ns);
        v.sB0 = new uint256[](ns);
        if (v.op == OP_REGISTER) {
            (v.sCount[0], v.sBits[0], v.sCount[1], v.sBits[1]) = (1, 11, 1, 15);
        } else {
            uint88[13] memory spec = [
                uint88(48 << 64 | 8 << 32 | 128),
                16 << 64 | 4 << 32,
                16 << 64 | 4 << 32,
                16 << 64 | 14 << 32,
                16 << 64 | 11 << 32 | 64,
                16 << 64 | 25 << 32 | (1 << 24),
                1 << 64 | 11 << 32,
                1 << 64 | 15 << 32,
                1 << 64 | 11 << 32,
                1 << 64 | 15 << 32,
                1 << 64 | 13 << 32,
                1 << 64 | 13 << 32,
                1 << 64 | 13 << 32
            ];
            for (uint256 i; i < ns; ++i) {
                v.sCount[i] = uint256(spec[i] >> 64);
                v.sBits[i] = uint256(spec[i] >> 32) & 0xffffffff;
                v.sOff[i] = uint256(spec[i]) & 0xffffffff;
            }
            v.sCount[0] = 16 * v.legs; // e2 of each leg
        }
        (uint256 v0, uint256 b0) = (0, 0);
        for (uint256 i; i < ns; ++i) {
            (v.sV0[i], v.sB0[i]) = (v0, b0);
            v0 += v.sCount[i];
            b0 += v.sCount[i] * v.sBits[i];
        }
        v.nsv = (v0 + ell - 1) / ell;
        v.nsb = (b0 + ell - 1) / ell;
        (v.sv, v.ss, v.sb) = (cur, cur + v.nsv, cur + 2 * v.nsv);
        v.m = v.sb + v.nsb;
        uint256 ntri;
        for (uint256 g; g < nb; ++g) ntri += v.nr * (1 + v.bBits[g]);
        ntri += v.nsv + v.nsb;
        v.tri = new uint256[](ntri);
        uint256 p;
        for (uint256 g; g < nb; ++g) {
            for (uint256 r; r < v.nr; ++r) {
                uint256 vr = v.bBase[g] + r;
                v.tri[p++] = vr | vr << 32 | (vr + v.nr) << 64;
                for (uint256 j; j < v.bBits[g]; ++j) {
                    uint256 br = v.bBase[g] + (2 + j) * v.nr + r;
                    v.tri[p++] = br | br << 32 | br << 64;
                }
            }
        }
        for (uint256 r; r < v.nsv; ++r) v.tri[p++] = (v.sv + r) | (v.sv + r) << 32 | (v.ss + r) << 64;
        for (uint256 r; r < v.nsb; ++r) v.tri[p++] = (v.sb + r) | (v.sb + r) << 32 | (v.sb + r) << 64;
    }

    // ---------------------------------------------------------------- entry points
    function verify(uint8 op, bytes calldata stmt, bytes calldata proof, Params calldata p) external view returns (bool ok) {
        (ok,) = _verify(op, stmt, proof, p);
    }

    /// ok and the gas of each stage: [statement + seed, layout + transcript + PoW + indices, columns + Merkle,
    /// A copy, comb (statement matrix work), comb (rest) + sum check, per-column checks, total, distinct columns]
    function verifyProfiled(uint8 op, bytes calldata stmt, bytes calldata proof, Params calldata p)
        external
        view
        returns (bool ok, uint256[9] memory g)
    {
        return _verify(op, stmt, proof, p);
    }

    /// ligero.rs max_len_exact: t distinct columns and the largest pruned multiproof, sum_(0<l<d) min(t, ceil(n / 2^l))
    /// + 2 - t digests
    function maxLen(V memory v, uint256 polyBytes, uint256 depth) internal pure returns (uint256) {
        uint256 mid;
        for (uint256 l = 1; l < depth; ++l) {
            uint256 a = (v.n + (1 << l) - 1) >> l;
            mid += a < v.t ? a : v.t;
        }
        return 32 + polyBytes + 8 + v.t * v.cw + (mid + 2 - v.t) * 32;
    }

    /// the verifier's length bound for (op, statement length, p) (tests)
    function maxProofLen(uint8 op, uint256 stmtLen, Params calldata p) external pure returns (uint256) {
        V memory v;
        (v.op, v.n, v.k, v.ell, v.t) = (op, p.n, p.k, p.ell, p.t);
        v.legs = stmtLen == TX0_STMT ? 2 : 3;
        v.d2 = 2 * p.k - 1;
        mkLayout(v);
        v.cw = 32 + (v.m + 12) * 6;
        uint256 depth;
        while ((1 << depth) < v.n) ++depth;
        return maxLen(v, (2 * v.d2 + v.d2 - v.ell) * 24, depth);
    }

    function _verify(uint8 op, bytes calldata stmt, bytes calldata proof, Params calldata p)
        internal
        view
        returns (bool, uint256[9] memory g)
    {
        uint256 g0 = gasleft();
        uint256 gl = g0;
        V memory v;
        (v.op, v.n, v.k, v.ell, v.t) = (op, p.n, p.k, p.ell, p.t);
        v.legs = stmt.length == TX0_STMT ? 2 : 3; // op 1: the form by length (R6), as cs.rs form_of
        v.d2 = 2 * p.k - 1;
        // the length gate first, before the statement or the proof is parsed (ligero.rs proof_len_ok)
        if (op != OP_REGISTER && op != OP_TRANSFER) return (false, g);
        mkLayout(v);
        uint256 polyBytes = (2 * v.d2 + v.d2 - v.ell) * 24;
        v.cw = 32 + (v.m + 12) * 6;
        uint256 depth;
        while ((1 << depth) < v.n) ++depth;
        if (proof.length > maxLen(v, polyBytes, depth) || proof.length < 32 + polyBytes + 8) return (false, g);
        if (!stmtOk(v, stmt)) return (false, g);
        v.st = keccak256(abi.encodePacked("SCAAS-PQZH-LIGERO-V1", op, uint32(stmt.length), stmt));
        v.hpos = 4;
        (g[0], gl) = (gl - gasleft(), gasleft());

        v.pOff = pOffOf(proof);
        v.wOff = v.pOff + 32;
        v.qOff = v.wOff + v.d2 * 24;
        v.hOff = v.qOff + v.d2 * 24;
        if (!drawAll(v, proof, polyBytes, p.powBits)) return (false, g);
        (g[1], gl) = (gl - gasleft(), gasleft());

        v.colOff = v.pOff + 40 + polyBytes;
        if (!columns(v, proof.length, depth, bytes32(proof[0:32]))) return (false, g);
        (g[2], gl) = (gl - gasleft(), gasleft());

        loadA(v);
        (g[3], gl) = (gl - gasleft(), gasleft());

        combRing(v);
        (g[4], gl) = (gl - gasleft(), gasleft());

        combRest(v);
        // linear test sum over H_k: k (q_0 + q_k) = rhs
        if (eb(ea(ld4(v.qOff), ld4(v.qOff + 24 * v.k)), v.k) != v.rhs) return (false, g);
        (g[5], gl) = (gl - gasleft(), gasleft());

        bool ok = columnChecks(v);
        (g[6], g[7]) = (gl - gasleft(), g0 - gasleft());
        g[8] = v.idx.length;
        return (ok, g);
    }

    /// challenges, PoW, query indices (ligero.rs verify_inner, same order as the prover)
    function drawAll(V memory v, bytes calldata proof, uint256 polyBytes, uint256 powBits) internal pure returns (bool) {
        absorbCd(v, proof[0:32]);
        v.ca = new uint256[](v.m);
        v.cb = new uint256[](v.m);
        for (uint256 i; i < v.m; ++i) v.ca[i] = f4(v);
        for (uint256 i; i < v.m; ++i) v.cb[i] = f4(v);
        v.cl = f4(v);
        v.cq = f4(v);
        v.rho = f4(v);
        v.rq = new uint256[](v.tri.length);
        for (uint256 i; i < v.tri.length; ++i) v.rq[i] = f4(v);
        absorbCd(v, proof[32:32 + polyBytes]);
        bytes8 nonce = bytes8(proof[32 + polyBytes:40 + polyBytes]);
        if (uint256(keccak256(abi.encodePacked(v.st, "PoW", nonce))) >> (256 - powBits) != 0) return false;
        absorb(v, abi.encodePacked(nonce));
        v.idx = drawIndices(v);
        return polysCanonical(v.wOff, 3 * v.d2 - v.ell);
    }

    function pOffOf(bytes calldata b) internal pure returns (uint256 o) {
        assembly {
            o := b.offset
        }
    }

    /// F_q^4 element at calldata offset o (4 x 6 bytes big-endian)
    function ld4(uint256 o) internal pure returns (uint256 x) {
        assembly {
            let w := calldataload(o)
            x := or(or(shr(208, w), shl(64, and(shr(160, w), 0xffffffffffff))),
                or(shl(128, and(shr(112, w), 0xffffffffffff)), shl(192, and(shr(64, w), 0xffffffffffff))))
        }
    }

    function polysCanonical(uint256 o, uint256 nel) internal pure returns (bool ok) {
        assembly {
            ok := 1
            let e := add(o, mul(nel, 24))
            for {} lt(o, e) { o := add(o, 6) } {
                if iszero(lt(shr(208, calldataload(o)), Q)) { ok := 0 }
            }
        }
    }

    // ---------------------------------------------------------------- statement (cs.rs parse)
    function stmtOk(V memory v, bytes calldata s) internal pure returns (bool ok) {
        uint256 o;
        uint256 nco;
        // id (D3) and opTag, in depth as cs.rs parse
        if (s.length < 64 || bytes32(s[32:64]) != PQZH_ID) return false;
        if (bytes32(s[0:32]) != (v.op == OP_REGISTER ? TAG_REGISTER : TAG_TRANSFER)) return false;
        if (v.op == OP_REGISTER) {
            if (s.length != REG_STMT) return false;
            (o, nco) = (96, 2048);
        } else if (v.op == OP_TRANSFER) {
            if (s.length != (v.legs == 3 ? TX_STMT : TX0_STMT)) return false;
            if (uint256(bytes32(s[448:480])) != v.legs - 2) return false; // auditorOn = 1 (R_TX) / 0 (R_TX0), R6
            if (uint256(bytes32(s[256:288])) >> 64 != 0) return false;
            // D15 as pqz-stmt: a transfer's amount and recipient words are 0, the salt word is 16 zero bytes || salt
            if (uint256(bytes32(s[288:320])) != 0 || uint256(bytes32(s[320:352])) != 0) return false;
            if (bytes16(s[576:592]) != 0) return false;
            // (legs + 1) x 2048 + 16 + 2048 + legs x 16 coefficients, contiguous (R_TX 10,304, R_TX0 8,240)
            (o, nco) = (640, (v.legs + 2) * 2048 + 16 + 16 * v.legs);
        } else {
            return false;
        }
        v.sOffs = pOffOf(s);
        assembly {
            ok := 1
            let p := add(s.offset, o)
            let e := add(p, mul(nco, 8))
            for {} lt(p, e) { p := add(p, 8) } {
                if iszero(lt(shr(192, calldataload(p)), Q)) { ok := 0 }
            }
        }
    }

    function sc(V memory v, uint256 byteOff) internal pure returns (uint256 x) {
        uint256 o = v.sOffs + byteOff;
        assembly {
            x := shr(192, calldataload(o))
        }
    }

    // ---------------------------------------------------------------- queries, columns, Merkle
    function drawIndices(V memory v) internal pure returns (uint256[] memory idx) {
        uint256 mask = 1;
        while (mask < v.n) mask <<= 1;
        mask -= 1;
        uint256[] memory raw = new uint256[](v.t);
        for (uint256 i; i < v.t; ++i) {
            uint256 x;
            do {
                x = word(v) & mask;
            } while (x >= v.n);
            // insertion sort
            uint256 j = i;
            while (j > 0 && raw[j - 1] > x) {
                raw[j] = raw[j - 1];
                --j;
            }
            raw[j] = x;
        }
        uint256 d;
        for (uint256 i; i < v.t; ++i) if (i == 0 || raw[i] != raw[i - 1]) raw[d++] = raw[i];
        assembly {
            mstore(raw, d)
        }
        return raw;
    }

    function columns(V memory v, uint256 plen, uint256 depth, bytes32 root) internal pure returns (bool) {
        uint256 d = v.idx.length;
        uint256 mpOff = v.colOff + d * v.cw;
        if (mpOff > v.pOff + plen) return false;
        uint256[] memory h = new uint256[](d);
        if (!leaves(v.colOff, v.cw, h)) return false;
        uint256[] memory ix = new uint256[](d);
        for (uint256 i; i < d; ++i) ix[i] = v.idx[i];
        return merkleRoot(ix, h, depth, mpOff, v.pOff + plen) == root;
    }

    /// leaf = keccak256(salt || column) for each opened column; every value canonical
    function leaves(uint256 co, uint256 cw, uint256[] memory h) internal pure returns (bool ok) {
        assembly {
            ok := 1
            let buf := mload(0x40)
            let d := mload(h)
            for { let i := 0 } lt(i, d) { i := add(i, 1) } {
                let c := add(co, mul(i, cw))
                for { let p := add(c, 32) } lt(p, add(c, cw)) { p := add(p, 6) } {
                    if iszero(lt(shr(208, calldataload(p)), Q)) { ok := 0 }
                }
                calldatacopy(buf, c, cw)
                mstore(add(add(h, 32), mul(i, 32)), keccak256(buf, cw))
            }
        }
    }

    /// root_from (merkle.rs): level by level, a sibling read from calldata only when not computable; every sibling
    /// byte must be consumed (returns 0 on a malformed multiproof)
    function merkleRoot(uint256[] memory ix, uint256[] memory h, uint256 depth, uint256 sp, uint256 end)
        internal
        pure
        returns (bytes32)
    {
        uint256 d = ix.length;
        for (uint256 l; l < depth; ++l) {
            uint256 o;
            uint256 i;
            while (i < d) {
                uint256 x = ix[i];
                if (x % 2 == 0 && i + 1 < d && ix[i + 1] == x + 1) {
                    h[o] = uint256(keccak256(abi.encodePacked(h[i], h[i + 1])));
                    i += 2;
                } else {
                    if (sp + 32 > end) return 0;
                    uint256 sib;
                    assembly {
                        sib := calldataload(sp)
                    }
                    sp += 32;
                    h[o] = x % 2 == 0 ? uint256(keccak256(abi.encodePacked(h[i], sib))) : uint256(keccak256(abi.encodePacked(sib, h[i])));
                    i += 1;
                }
                ix[o] = x / 2;
                ++o;
            }
            d = o;
        }
        if (d != 1 || ix[0] != 0 || sp != end) return 0;
        return bytes32(h[0]);
    }

    // ---------------------------------------------------------------- comb (cs.rs comb)
    function loadA(V memory v) internal view {
        if (v.op == OP_REGISTER || v.op == OP_TRANSFER) {
            uint256[] memory a = new uint256[](ABYTES / 32 + 1);
            address[] memory ad = aData;
            assembly {
                let dst := add(a, 32)
                for { let c := 0 } lt(c, mload(ad)) { c := add(c, 1) } {
                    extcodecopy(mload(add(add(ad, 32), mul(c, 32))), add(dst, mul(c, ACHUNK)), 0, ACHUNK)
                }
            }
            v.amat = a;
        }
    }

    function take(V memory v, uint256 size) internal pure returns (uint256 w) {
        w = v.cur;
        if (size == 1) v.cur = em(v.cur, v.rho);
        else if (size == v.ell) v.cur = em(v.cur, v.rhoL);
        else if (size <= 64) v.cur = em(v.cur, v.rp[size]);
        else v.cur = em(v.cur, epow(v.rho, size));
    }

    function addOwn(V memory v, uint256 row, uint256 slot, uint256 w) internal pure {
        uint256 o = v.ownIdx[row] - 1;
        uint256 i = o * v.ell + slot;
        v.own[i] = ea(v.own[i], w);
    }

    function bpos(V memory v, uint256 g, uint256 x) internal pure returns (uint256, uint256) {
        return (v.bBase[g] + x / v.ell, x % v.ell);
    }

    function spos(V memory v, uint256 it, uint256 x) internal pure returns (uint256, uint256) {
        uint256 y = v.sV0[it] + x;
        return (v.sv + y / v.ell, y % v.ell);
    }

    function sqpos(V memory v, uint256 it, uint256 x) internal pure returns (uint256, uint256) {
        uint256 y = v.sV0[it] + x;
        return (v.ss + y / v.ell, y % v.ell);
    }

    function bitpos(V memory v, uint256 it, uint256 x, uint256 j) internal pure returns (uint256, uint256) {
        uint256 b = v.sB0[it] + x * v.sBits[it] + j;
        return (v.sb + b / v.ell, b % v.ell);
    }

    function addS(V memory v, uint256 it, uint256 x, uint256 w) internal pure {
        (uint256 r, uint256 s) = spos(v, it, x);
        addOwn(v, r, s, w);
    }

    /// own-vector rows: big value rows and all small rows
    function initComb(V memory v) internal pure {
        uint256 m = v.m;
        v.ownIdx = new uint256[](m);
        uint256 nOwn;
        for (uint256 g; g < v.bBase.length; ++g) for (uint256 r; r < v.nr; ++r) v.ownIdx[v.bBase[g] + r] = ++nOwn;
        for (uint256 r = v.sv; r < m; ++r) v.ownIdx[r] = ++nOwn;
        v.own = new uint256[](nOwn * v.ell);
        v.ownRow = new uint256[](nOwn);
        for (uint256 r; r < m; ++r) if (v.ownIdx[r] != 0) v.ownRow[v.ownIdx[r] - 1] = r;
        v.beta = new uint256[](m);
        v.ones = new uint256[](m);
        v.rp = new uint256[](65);
        v.rp[0] = 1;
        for (uint256 i = 1; i <= 64; ++i) v.rp[i] = em(v.rp[i - 1], v.rho);
        v.rhoL = epow(v.rho, v.ell);
        v.cur = v.rho; // weights start at rho^1
    }

    /// sum_k rho^k p_k (k < kk), p at statement byte offset o (be8 coefficients)
    function rsum(V memory v, uint256 o, uint256 kk) internal pure returns (uint256 r) {
        uint256 x02;
        uint256 x13;
        uint256[] memory rp = v.rp;
        uint256 so = v.sOffs + o;
        assembly {
            for { let k := 0 } lt(k, kk) { k := add(k, 1) } {
                let c := shr(192, calldataload(add(so, mul(k, 8))))
                let w := mload(add(add(rp, 32), mul(k, 32)))
                x02 := add(x02, mul(and(w, M02), c))
                x13 := add(x13, mul(and(shr(64, w), M02), c))
            }
        }
        r = red2(x02, x13);
    }

    /// a_j[idx] = sum_i gam_i M_ij[idx] for the 32 x 32 blocks of A (tr = 1: M_ij = A_ji)
    function aPass(uint256[] memory am, uint256[] memory gam, uint256 j, bool tr, uint256[] memory a) internal pure {
        assembly {
            let base := add(am, 32)
            let g := add(gam, 32)
            for { let idx := 0 } lt(idx, 64) { idx := add(idx, 1) } {
                let x02 := 0
                let x13 := 0
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    let blk := add(mul(i, 32), j)
                    if tr { blk := add(mul(j, 32), i) }
                    let c := shr(208, mload(add(base, mul(6, add(mul(blk, 64), idx)))))
                    let w := mload(add(g, mul(i, 32)))
                    x02 := add(x02, mul(and(w, M02), c))
                    x13 := add(x13, mul(and(shr(64, w), M02), c))
                }
                mstore(add(add(a, 32), mul(idx, 32)), or(or(mod(and(x02, M128), Q), shl(64, mod(and(x13, M128), Q))),
                    or(shl(128, mod(shr(128, x02), Q)), shl(192, mod(shr(128, x13), Q)))))
            }
        }
    }

    /// ring block (cs.rs Bld::ring): kind 0 A, 1 A^T, 2 one statement polyvec at byte offset `so`; x = big group g.
    /// Big-group own vectors are contiguous: value x of group g is own[g nr l + x].
    function ring(V memory v, uint256 kind, uint256 so, uint256 kk, uint256 g) internal pure returns (uint256[] memory gam) {
        uint256 nout = kind == 2 ? 1 : 32;
        uint256 w0 = take(v, nout * kk);
        gam = new uint256[](nout);
        gam[0] = w0;
        for (uint256 i = 1; i < nout; ++i) gam[i] = em(gam[i - 1], v.rp[kk]);
        uint256[] memory a = new uint256[](64);
        for (uint256 j; j < 32; ++j) {
            if (kind == 2) {
                for (uint256 idx; idx < 64; ++idx) a[idx] = eb(w0, sc(v, so + 512 * j + 8 * idx));
            } else {
                aPass(v.amat, gam, j, kind == 1, a);
            }
            ringJ(v, a, kk, g * v.nr * v.ell + 64 * j);
        }
    }

    /// own[p + m] += f_m(a), m < 64 (recurrence f_{m+1} = rho f_m - rho^K (X^m a)_{K-1} - (X^m a)_63)
    function ringJ(V memory v, uint256[] memory a, uint256 kk, uint256 p) internal pure {
        uint256 f;
        for (uint256 k; k < kk; ++k) f = ea(f, em(v.rp[k], a[k]));
        uint256[] memory own = v.own;
        for (uint256 m; m < 64; ++m) {
            own[p + m] = ea(own[p + m], f);
            if (m < 63) {
                uint256 bk = kk - 1 >= m ? a[kk - 1 - m] : es(0, a[kk - 1 + 64 - m]);
                f = step(v.rho, f, v.rp[kk], bk, a[63 - m]);
            }
        }
    }

    /// the ring blocks (statement-matrix work)
    function combRing(V memory v) internal pure {
        initComb(v);
        if (v.op == OP_REGISTER) {
            uint256[] memory gam = ring(v, 0, 0, 64, 0);
            eTerms(v, gam, 1, 96);
        } else {
            uint256[] memory gam = ring(v, 0, 0, 64, 0);
            eTerms(v, gam, 1, 640);
            // header 640 || pk_f || pk_t || [pk_a] || u_T || v_T || u || v_t || v_f || [v_a]
            uint256 uT = 640 + 16384 * v.legs;
            uint256 uo = uT + 16512;
            gam = ring(v, 1, 0, 64, 2);
            eTerms(v, gam, 3, uo);
            for (uint256 x; x < v.legs; ++x) {
                // rows 3-5 (R_TX0: 3, 4): pk_t, pk_f, pk_a at 640 + 16384 (1, 0, 2)
                uint256 pko = 640 + 16384 * (x == 0 ? 1 : (x == 1 ? 0 : 2));
                gam = ring(v, 2, pko, 16, 2);
                for (uint256 k; k < 16; ++k) {
                    uint256 w = em(gam[0], v.rp[k]);
                    addS(v, E2, 16 * x + k, w);
                    addS(v, x == 1 ? DP : DD, k, eb(w, DELTA));
                }
                v.rhs = ea(v.rhs, em(gam[0], rsum(v, uo + 16384 + 128 * x, 16)));
            }
            // row 6: u_T^T s_f + Delta M + e_T = v_T
            gam = ring(v, 2, uT, 16, 0);
            for (uint256 k; k < 16; ++k) {
                uint256 w = em(gam[0], v.rp[k]);
                addS(v, MM, k, eb(w, DELTA));
                addS(v, ET, k, w);
            }
            v.rhs = ea(v.rhs, em(gam[0], rsum(v, uT + 16384, 16)));
        }
    }

    /// e-terms of a 32 x 64 ring block: coefficient gam_i rho^k on value 64 i + k of group eg; rhs from the polyvec at so
    function eTerms(V memory v, uint256[] memory gam, uint256 eg, uint256 so) internal pure {
        uint256[] memory own = v.own;
        uint256 ob = eg * v.nr * v.ell;
        for (uint256 i; i < 32; ++i) {
            uint256 w = gam[i];
            for (uint256 k; k < 64; ++k) {
                own[ob + 64 * i + k] = ea(own[ob + 64 * i + k], w);
                w = em(w, v.rho);
            }
            v.rhs = ea(v.rhs, em(gam[i], rsum(v, so + 512 * i, 64)));
        }
    }

    function combRest(V memory v) internal pure {
        if (v.op == OP_TRANSFER) {
            uint256 fee = uint256(sc(v, 280));
            uint256 w0 = take(v, 16);
            for (uint256 k; k < 16; ++k) {
                uint256 w = em(w0, v.rp[k]);
                uint256 nw = es(0, w);
                addS(v, MM, k, w);
                if (k > 0) addS(v, CC, k - 1, w);
                addS(v, DP, k, nw);
                addS(v, DD, k, nw);
                addS(v, CC, k, eb(nw, 16));
                v.rhs = ea(v.rhs, eb(w, (fee >> (4 * k)) & 15));
            }
            addS(v, CC, 15, take(v, 1));
            for (uint256 x; x < v.legs; ++x) {
                uint256 w = take(v, 1);
                for (uint256 k; k < 16; ++k) {
                    (uint256 r, uint256 s) = sqpos(v, E2, 16 * x + k);
                    addOwn(v, r, s, w);
                }
                addS(v, SIG + 4 + x, 0, w);
                v.rhs = ea(v.rhs, eb(w, 4096));
            }
        }
        // big groups: bit decompositions (shared beta) and norms (shared ones)
        uint256 sumBeta;
        {
            uint256 pw = 1;
            for (uint256 c; c < v.ell; ++c) {
                sumBeta = ea(sumBeta, pw);
                pw = em(pw, v.rho);
            }
        }
        uint256 sig0 = v.op == OP_REGISTER ? 0 : SIG;
        for (uint256 g; g < v.bBase.length; ++g) {
            for (uint256 r; r < v.nr; ++r) {
                uint256 l = take(v, v.ell);
                uint256 vr = v.bBase[g] + r;
                v.beta[vr] = ea(v.beta[vr], l);
                for (uint256 j; j < v.bBits[g]; ++j) {
                    uint256 br = v.bBase[g] + (2 + j) * v.nr + r;
                    v.beta[br] = es(v.beta[br], eb(l, 1 << j));
                }
                v.rhs = es(v.rhs, eb(em(l, sumBeta), v.bOff[g]));
            }
            uint256 w = take(v, 1);
            for (uint256 r; r < v.nr; ++r) {
                uint256 sr = v.bBase[g] + v.nr + r;
                v.ones[sr] = ea(v.ones[sr], w);
            }
            addS(v, sig0 + g, 0, w);
            v.rhs = ea(v.rhs, eb(w, v.bB2[g]));
        }
        // small values: x - sum_j 2^j bit_j = -off
        for (uint256 it; it < v.sCount.length; ++it) {
            for (uint256 i; i < v.sCount[it]; ++i) {
                uint256 w = take(v, 1);
                addS(v, it, i, w);
                for (uint256 j; j < v.sBits[it]; ++j) {
                    (uint256 r, uint256 s) = bitpos(v, it, i, j);
                    addOwn(v, r, s, es(0, eb(w, 1 << j)));
                }
                if (v.sOff[it] != 0) v.rhs = es(v.rhs, eb(w, v.sOff[it]));
            }
        }
        // trim every own vector to its last nonzero slot
        uint256 nOwn = v.ownRow.length;
        v.ownLen = new uint256[](nOwn);
        for (uint256 o; o < nOwn; ++o) {
            uint256 len = v.ell;
            while (len > 0 && v.own[o * v.ell + len - 1] == 0) --len;
            v.ownLen[o] = len;
        }
    }

    // ---------------------------------------------------------------- per-column checks
    struct ColCtx {
        uint256 wn;
        uint256 kinv;
        uint256[] om; // omega_k^c
        uint256[] bt; // rho^c
        uint256[] xp; // eta^i
        uint256[] lc; // Lagrange basis at eta
        uint256[] tmp;
    }

    function columnChecks(V memory v) internal pure returns (bool) {
        uint256 ell = v.ell;
        ColCtx memory c;
        c.wn = fpow(3, (Q - 1) / v.n);
        c.kinv = fpow(v.k, Q - 2);
        uint256 wk = fpow(3, (Q - 1) / v.k);
        c.om = new uint256[](ell);
        c.bt = new uint256[](ell);
        c.om[0] = 1;
        c.bt[0] = 1;
        for (uint256 i = 1; i < ell; ++i) {
            c.om[i] = mulmod(c.om[i - 1], wk, Q);
            c.bt[i] = em(c.bt[i - 1], v.rho);
        }
        c.xp = new uint256[](v.d2);
        c.lc = new uint256[](ell);
        c.tmp = new uint256[](ell);
        for (uint256 d; d < v.idx.length; ++d) if (!oneColumn(v, c, d)) return false;
        return true;
    }

    /// Lagrange basis of H_k at eta into c.lc; s = (eta^k - 1)/k; returns Z_zeta(eta)
    function lagr(ColCtx memory c, uint256 eta, uint256 k) internal pure returns (uint256) {
        return lagrange(c.lc, c.tmp, c.om, eta, mulmod(addmod(c.xp[k], Q - 1, Q), c.kinv, Q));
    }

    function oneColumn(V memory v, ColCtx memory c, uint256 d) internal pure returns (bool) {
        uint256 eta = mulmod(3, fpow(c.wn, v.idx[d]), Q);
        uint256 u = v.colOff + d * v.cw + 32; // column values, 6 bytes each
        uint256 m = v.m;
        powers(c.xp, eta);
        // proximity
        {
            uint256 lhs = ea(dotU(v.ca, u, m), eb(dotU(v.cb, u, m), c.xp[v.k - 1]));
            lhs = ea(lhs, ea(em(v.cl, blind(u, m, 1)), em(v.cq, blind(u, m, 2))));
            if (evalP(v.wOff, v.d2, c.xp) != ea(lhs, blind(u, m, 0))) return false;
        }
        // Lagrange basis of H_k at eta, Z_zeta(eta)
        uint256 zeta = lagr(c, eta, v.k);
        // linear
        {
            uint256 acc = ownEval(v, c.lc, u);
            acc = ea(acc, em(dotL(c.bt, c.lc, v.ell), dotU(v.beta, u, m)));
            uint256 lsum;
            for (uint256 i; i < v.ell; ++i) lsum = addmod(lsum, c.lc[i], Q);
            acc = ea(acc, eb(dotU(v.ones, u, m), lsum));
            if (evalP(v.qOff, v.d2, c.xp) != ea(acc, blind(u, m, 1))) return false;
        }
        // quadratic
        return eb(evalP(v.hOff, v.d2 - v.ell, c.xp), zeta) == ea(quad(v, u), blind(u, m, 2));
    }

    function powers(uint256[] memory xp, uint256 eta) internal pure {
        assembly {
            let n := mload(xp)
            let p := add(xp, 32)
            let x := 1
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(p, mul(i, 32)), x)
                x := mulmod(x, eta, Q)
            }
        }
    }

    /// blinding row b (0: u_0, 1: u_lin, 2: u_quad) of the column at u
    function blind(uint256 u, uint256 m, uint256 b) internal pure returns (uint256 x) {
        uint256 o = u + 6 * (m + 4 * b);
        assembly {
            x := or(or(shr(208, calldataload(o)), shl(64, shr(208, calldataload(add(o, 6))))),
                or(shl(128, shr(208, calldataload(add(o, 12)))), shl(192, shr(208, calldataload(add(o, 18))))))
        }
    }

    /// sum_i c_i U_i over the m witness rows of the column at u
    function dotU(uint256[] memory c, uint256 u, uint256 m) internal pure returns (uint256) {
        uint256 x02;
        uint256 x13;
        assembly {
            let p := add(c, 32)
            for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                let x := shr(208, calldataload(add(u, mul(i, 6))))
                let w := mload(add(p, mul(i, 32)))
                x02 := add(x02, mul(and(w, M02), x))
                x13 := add(x13, mul(and(shr(64, w), M02), x))
            }
        }
        return red2(x02, x13);
    }

    /// sum_c a_c l_c (a packed F_q^4, l base)
    function dotL(uint256[] memory a, uint256[] memory l, uint256 n) internal pure returns (uint256) {
        uint256 x02;
        uint256 x13;
        assembly {
            let p := add(a, 32)
            let q := add(l, 32)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let x := mload(add(q, mul(i, 32)))
                let w := mload(add(p, mul(i, 32)))
                x02 := add(x02, mul(and(w, M02), x))
                x13 := add(x13, mul(and(shr(64, w), M02), x))
            }
        }
        return red2(x02, x13);
    }

    /// polynomial with n F_q^4 coefficients at calldata o, at the point whose powers are xp
    function evalP(uint256 o, uint256 n, uint256[] memory xp) internal pure returns (uint256) {
        uint256 x02;
        uint256 x13;
        assembly {
            let q := add(xp, 32)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let x := mload(add(q, mul(i, 32)))
                let w := calldataload(add(o, mul(i, 24)))
                let l0 := shr(208, w)
                let l1 := and(shr(160, w), 0xffffffffffff)
                let l2 := and(shr(112, w), 0xffffffffffff)
                let l3 := and(shr(64, w), 0xffffffffffff)
                x02 := add(x02, mul(or(l0, shl(128, l2)), x))
                x13 := add(x13, mul(or(l1, shl(128, l3)), x))
            }
        }
        return red2(x02, x13);
    }

    /// lc_c = omega^c s / (eta - omega^c) for c < l (batch inversion); returns prod (eta - omega^c) = Z_zeta(eta)
    function lagrange(uint256[] memory lc, uint256[] memory pre, uint256[] memory om, uint256 eta, uint256 s)
        internal
        pure
        returns (uint256 zeta)
    {
        assembly {
            let n := mload(lc)
            let acc := 1
            for { let c := 0 } lt(c, n) { c := add(c, 1) } {
                mstore(add(add(pre, 32), mul(c, 32)), acc)
                acc := mulmod(acc, addmod(eta, sub(Q, mload(add(add(om, 32), mul(c, 32)))), Q), Q)
            }
            zeta := acc
        }
        uint256 inv = fpow(zeta, Q - 2);
        assembly {
            for { let c := mload(lc) } gt(c, 0) {} {
                c := sub(c, 1)
                let oc := mload(add(add(om, 32), mul(c, 32)))
                mstore(add(add(lc, 32), mul(c, 32)), mulmod(mulmod(mulmod(inv, mload(add(add(pre, 32), mul(c, 32))), Q), oc, Q), s, Q))
                inv := mulmod(inv, addmod(eta, sub(Q, oc), Q), Q)
            }
        }
    }

    function ownEval(V memory v, uint256[] memory lc, uint256 u) internal pure returns (uint256 acc) {
        uint256 nOwn = v.ownRow.length;
        for (uint256 o; o < nOwn; ++o) {
            uint256 len = v.ownLen[o];
            if (len == 0) continue;
            uint256 uo = u + 6 * v.ownRow[o];
            uint256 uv;
            assembly {
                uv := shr(208, calldataload(uo))
            }
            acc = ea(acc, eb(rowEval(v.own, o * v.ell, lc, len), uv));
        }
    }

    /// sum_{c < len} own[off + c] lc_c
    function rowEval(uint256[] memory own, uint256 off, uint256[] memory lc, uint256 len) internal pure returns (uint256) {
        uint256 x02;
        uint256 x13;
        assembly {
            let p := add(add(own, 32), mul(off, 32))
            let q := add(lc, 32)
            for { let c := 0 } lt(c, len) { c := add(c, 1) } {
                let x := mload(add(q, mul(c, 32)))
                let w := mload(add(p, mul(c, 32)))
                x02 := add(x02, mul(and(w, M02), x))
                x13 := add(x13, mul(and(shr(64, w), M02), x))
            }
        }
        return red2(x02, x13);
    }

    function quad(V memory v, uint256 u) internal pure returns (uint256) {
        uint256 x02;
        uint256 x13;
        uint256[] memory tri = v.tri;
        uint256[] memory rq = v.rq;
        assembly {
            let n := mload(tri)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let t := mload(add(add(tri, 32), mul(i, 32)))
                let ux := shr(208, calldataload(add(u, mul(6, and(t, 0xffffffff)))))
                let uy := shr(208, calldataload(add(u, mul(6, and(shr(32, t), 0xffffffff)))))
                let uz := shr(208, calldataload(add(u, mul(6, shr(64, t)))))
                let x := addmod(mulmod(ux, uy, Q), sub(Q, uz), Q)
                let w := mload(add(add(rq, 32), mul(i, 32)))
                x02 := add(x02, mul(and(w, M02), x))
                x13 := add(x13, mul(and(shr(64, w), M02), x))
            }
        }
        return red2(x02, x13);
    }
}
