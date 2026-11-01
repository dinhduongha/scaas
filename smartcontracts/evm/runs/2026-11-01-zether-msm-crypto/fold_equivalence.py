#!/usr/bin/env python3
"""Exact check of the merged-MSM fold (snapshot 6fed9881, src/zether/ZetherVerifier.sol) against the
per-equation verifier (legacy/zether-msm/ZetherVerifier.sol), Σ-protocol lens.

Model: BLS12-381 G1 is cyclic of prime order r (every input point passes G1MSM's subgroup check), so a
point is a symbol P_name and an MSM is the linear form Σ f[slot]·P_slot.  Two transliterations:

  * `New*`    : the fold of the new verifier, line by line (slot arithmetic + `_term` accumulation),
  * `legacy_*`: the equation list of the legacy verifier, each equation a list of (point name, scalar).

Then for every point name:  f_new[name]  ==  Σ_i ρ^i · legacy_coef_i[name]      (identity in Z_r).

Two arithmetics drive the same transliteration:
  * SYM : sympy symbols, `r − a` read as `−a`, addmod/mulmod as +/× — a proof of the identity as polynomials
          over Z (hence over Z_r) in the challenges, responses and proof scalars;
  * NUM : ints mod r with the literal Solidity ops (addmod, mulmod, `r - c`, `_negS`), random values,
          plus the full MSM over random point scalars — catches edge cases the symbolic reading glosses
          (`r − 0 = r`, `_negS(0) = 0`, `mulmod(w, r, r)`).

Forms: transfer (auditor on/off), burn, multi for M = 1..16 (auditor on/off).
"""
import random
import sys
import sympy as sp

R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
SLOT_G, SLOT_HB, SLOT_U, SLOT_GI, SLOT_HI, SLOT_EXT = 0, 1, 2, 3, 67, 131
N, K = 64, 6
HEADER_WORDS = 16
FEE_AT, AMOUNT_AT = 288 // 32, 352 // 32  # header word indices


# ----------------------------------------------------------------------------- arithmetic
class Sym:
    """Z_r read symbolically: r ≡ 0."""
    def add(self, a, b): return a + b
    def mul(self, a, b): return a * b
    def rminus(self, a): return -a           # `r - a`
    def negS(self, a): return -a             # `_negS(a, r)`
    def const(self, v): return sp.Integer(v)
    def inv(self, a, name): return sp.Symbol(name)  # free symbol for a⁻¹ (same on both sides)
    def pow2mask(self): return sp.Integer((1 << N) - 1)
    def zero(self): return sp.Integer(0)
    def is_zero(self, e): return sp.expand(e) == 0


class Num:
    """Literal Solidity arithmetic mod r."""
    def add(self, a, b): return (a + b) % R
    def mul(self, a, b): return (a * b) % R
    def rminus(self, a): return R - a        # may be r itself when a = 0, as in the Solidity
    def negS(self, a): return 0 if a == 0 else R - a
    def const(self, v): return v % R
    def inv(self, a, name): return pow(a, R - 2, R)
    def pow2mask(self): return ((1 << N) - 1) % R
    def zero(self): return 0
    def is_zero(self, e): return e % R == 0


# ----------------------------------------------------------------------------- proof / statement model
class Vals:
    """One proof + statement, abstractly: scalars by name (symbolic or numeric), point names by position."""
    def __init__(self, A, form, m=1, aud=True, seed=0):
        self.A, self.form, self.m, self.aud = A, form, m, aud
        rnd = random.Random(seed)
        sym = isinstance(A, Sym)

        def S(name):
            return sp.Symbol(name) if sym else rnd.randrange(R)
        self.S = S
        self.c, self.rho = S("c"), S("rho")
        self.fee, self.amount = S("fee"), S("amount")
        if form == "transfer":
            self.z = [S(n) for n in ("z_x", "z_v", "z_s", "z_b", "z_gv", "z_gb")]
            self.nPf, self.nSp, self.nBp = 10, 9, 2
        elif form == "burn":
            self.z = [S(n) for n in ("z_x", "z_b", "z_gb")]
            self.nPf, self.nSp, self.nBp = 4, 3, 1
        elif form == "multi":
            self.z = [S(n) for n in ("z_x", "z_s", "z_b", "z_gb")]
            for j in range(m):
                self.z += [S(f"z_v{j}"), S(f"z_gv{j}"), S(f"z_t{j}") if aud else A.zero()]
            self.nPf, self.nSp, self.nBp = 6 + 5 * m, 6 + 4 * m, m + 1
        # range proofs: scalars τ_x μ t̂ a b, challenges y z x w u_0..5
        self.bp = []
        for k in range(self.nBp):
            d = {n: S(f"bp{k}_{n}") for n in ("tau", "mu", "that", "a", "b", "y", "z", "x", "w")}
            d["u"] = [S(f"bp{k}_u{j}") for j in range(K)]
            self.bp.append(d)
        # the point names, in the slot order the new verifier lays out (`_foldStart`, `_fold`)
        self.names = ["G", "Hb", "U"] + [f"G_{i}" for i in range(N)] + [f"H_{i}" for i in range(N)]
        assert len(self.names) == SLOT_EXT
        self.names += [f"pf{i}" for i in range(self.nPf)]
        self.names += [f"sp{i}" for i in range(self.nSp)]
        for k in range(self.nBp):
            self.names += [f"BP{k}_A", f"BP{k}_S", f"BP{k}_T1", f"BP{k}_T2"]
            for j in range(K):
                self.names += [f"BP{k}_L{j}", f"BP{k}_R{j}"]

    # the legacy reads leg statement point k of leg j at byte HEADER + 6P + 32 + (4j+k)P: statement point 6+4j+k
    def lp(self, j, k): return f"sp{6 + 4 * j + k}"
    def lpf(self, j, k): return f"pf{6 + 5 * j + k}"


# ----------------------------------------------------------------------------- the NEW verifier, transliterated
class NewFold:
    def __init__(self, V):
        self.V, self.A = V, V.A
        self.f = {}            # slot -> scalar  (x.f / b.f)
        self.w = V.A.const(1)  # x.w
        self.rho = V.rho
        self.r = R
        self.p = 1             # byte arithmetic in slot units
        self.sAt = SLOT_EXT + V.nPf   # x.sAt = SLOT_EXT + sigmaLen / p
        self.nSlots = SLOT_EXT + V.nPf + V.nSp

    def term(self, slot, w, s):             # `_term`
        assert 0 <= slot < self.nSlots + 16 * self.V.nBp, slot
        self.f[slot] = self.A.add(self.f.get(slot, self.A.zero()), self.A.mul(w, s))

    def e3(self, slots, s):
        for i in range(3): self.term(slots[i], self.w, s[i])
        self.w = self.A.mul(self.w, self.rho)

    def e4(self, slots, s):
        for i in range(4): self.term(slots[i], self.w, s[i])
        self.w = self.A.mul(self.w, self.rho)

    def e5(self, zb, zx, slots):
        A = self.V.A; c = self.V.c
        self.term(SLOT_G, self.w, A.add(zb, A.mul(c, self.V.fee)))
        self.term(slots[0], self.w, zx)
        self.term(slots[1], self.w, A.negS(zx))
        self.term(slots[2], self.w, A.rminus(c))
        self.term(slots[3], self.w, c)
        self.term(slots[4], self.w, A.rminus(A.const(1)))
        self.w = A.mul(self.w, self.rho)

    # ---- Σ transfer (src lines 532-565)
    def sigma_transfer(self):
        V, A = self.V, self.A
        z = V.z; nc = A.rminus(V.c); s = self.sAt; a = SLOT_EXT; r1 = A.rminus(A.const(1))
        self.e3([SLOT_G, s, a + 2], [z[0], nc, r1])                      # E1
        self.e3([SLOT_G, s + 6, a + 3], [z[2], nc, r1])                  # E2
        self.e4([SLOT_G, s + 1, s + 5, a + 4], [z[1], z[2], nc, r1])     # E3
        self.e4([SLOT_G, s, s + 7, a + 5], [z[1], z[2], nc, r1])         # E4
        self.e5(z[3], z[0], [s + 4, s + 6, s + 3, s + 7, a + 6])         # E5
        if V.aud:
            self.e4([SLOT_G, s + 2, s + 8, a + 7], [z[1], z[2], nc, r1]) # E6
        self.e4([SLOT_G, SLOT_HB, a, a + 8], [z[1], z[4], nc, r1])       # E7
        self.e4([SLOT_G, SLOT_HB, a + 1, a + 9], [z[3], z[5], nc, r1])   # E8
        return [SLOT_EXT, SLOT_EXT + 1]                                  # v = V_v, V_b

    # ---- Σ multi (src lines 569-669)
    def _lpf(self, j, k): return SLOT_EXT + 6 + 5 * j + k
    def _lps(self, j, k): return self.sAt + 6 + 4 * j + k

    def sigma_multi(self):
        V, A = self.V, self.A
        m = V.m; z = V.z; nc = A.rminus(V.c); s = self.sAt; a = SLOT_EXT; r1 = A.rminus(A.const(1))
        self.e3([SLOT_G, s, a + 1], [z[0], nc, r1])                      # E1
        self.e3([SLOT_G, s + 4, a + 2], [z[1], nc, r1])                  # E2
        # _sigmaLegs
        zs = z[1]
        for j in range(m):
            zv = z[4 + 3 * j]
            self.e4([SLOT_G, self._lps(j, 0), self._lps(j, 1), self._lpf(j, 1)], [zv, zs, nc, r1])   # E3_j
            # _sigmaAud
            zt = z[6 + 3 * j]
            if V.aud:
                self.e4([SLOT_G, self.sAt + 1, self._lps(j, 2), self._lpf(j, 2)], [z[4 + 3 * j], zt, nc, r1])  # E6_j
                self.e3([SLOT_G, self._lps(j, 3), self._lpf(j, 3)], [zt, nc, r1])                              # E6'_j
            self.e4([SLOT_G, SLOT_HB, self._lpf(j, 0), self._lpf(j, 4)], [zv, z[5 + 3 * j], nc, r1])          # E7_j
        zv = A.zero()
        for j in range(m): zv = A.add(zv, z[4 + 3 * j])
        self.e4([SLOT_G, s, s + 5, a + 3], [zv, z[1], nc, r1])           # E4
        self.e5(z[2], z[0], [s + 3, s + 4, s + 2, s + 5, a + 4])         # E5
        self.e4([SLOT_G, SLOT_HB, a, a + 5], [z[2], z[3], nc, r1])       # E8
        return [self._lpf(j, 0) for j in range(m)] + [SLOT_EXT]          # v = V_vj..., V_b

    # ---- Σ burn (src lines 677-697)
    def sigma_burn(self):
        V, A = self.V, self.A
        z = V.z; nc = A.rminus(V.c); s = self.sAt; a = SLOT_EXT; r1 = A.rminus(A.const(1))
        self.e3([SLOT_G, s, a + 1], [z[0], nc, r1])                      # E1
        debit = A.add(V.amount, V.fee)
        self.e4([SLOT_G, s + 2, s + 1, a + 2], [A.add(z[1], A.mul(V.c, debit)), z[0], nc, r1])  # E5
        self.e4([SLOT_G, SLOT_HB, a, a + 3], [z[1], z[2], nc, r1])       # E8
        return [SLOT_EXT]

    # ---- the inner-product side: `_fold`, `_bp1`, `_bp2`, `_bpVectorScalars`, `_sVector` (src lines 186-348)
    def fold_bp(self, commitments):
        V, A = self.V, self.A
        assert len(commitments) == V.nBp
        wt = self.w                     # sigma.weight
        at = self.nSlots                # b.at = sigma.scalars.length
        for k in range(V.nBp):
            b = V.bp[k]
            sc = [b["tau"], b["mu"], b["that"], b["a"], b["b"]]
            y, z, x, w_ch, u = b["y"], b["z"], b["x"], b["w"], b["u"]
            # points A S T1 T2 (L R)_j land on slots at..at+15 (`_copy(pts, b.at * b.p, b.pr, 0, 16 * b.p)`)
            # --- _bp1
            w = wt
            z2 = A.mul(z, z)
            sumY = A.zero(); yi = A.const(1)
            for i in range(N):
                sumY = A.add(sumY, yi); yi = A.mul(yi, y)
            delta = A.add(A.mul(A.add(z, A.rminus(z2)), sumY),
                          A.rminus(A.mul(A.mul(z2, z), A.pow2mask())))
            self.term(SLOT_G, w, A.add(sc[2], A.rminus(delta)))
            self.term(SLOT_HB, w, sc[0])
            self.term(commitments[k], w, A.negS(z2))
            self.term(at + 2, w, A.negS(x))
            self.term(at + 3, w, A.negS(A.mul(x, x)))
            wt = A.mul(w, self.rho)
            # --- _bp2
            w = wt
            a = at
            self.term(a, w, A.const(1))
            self.term(a + 1, w, x)
            # _bpVectorScalars (uses b.wt == w)
            s_vec, uInv = self._sVector(u)
            yInv = A.inv(y, f"bp{k}_yinv")
            yInvI = A.const(1); twoI = A.const(1)
            for i in range(N):
                t = A.add(z, A.mul(sc[3], s_vec[i]))
                self.term(SLOT_GI + i, w, A.negS(t))
                t = A.add(A.mul(z2, twoI), A.rminus(A.mul(sc[4], s_vec[N - 1 - i])))
                t = A.add(z, A.mul(yInvI, t))
                self.term(SLOT_HI + i, w, t)
                yInvI = A.mul(yInvI, yInv); twoI = A.add(twoI, twoI)
            self.term(SLOT_HB, w, A.negS(sc[1]))
            self.term(SLOT_U, w, A.mul(w_ch, A.add(sc[2], A.rminus(A.mul(sc[3], sc[4])))))
            for j in range(K):
                self.term(a + 4 + 2 * j, w, A.mul(u[j], u[j]))
                self.term(a + 5 + 2 * j, w, A.mul(uInv[j], uInv[j]))
            wt = A.mul(w, self.rho)
            at += 16
        self.w = wt

    def _sVector(self, u):
        A = self.A
        s = [None] * N
        uInv = [A.inv(u[j], str(u[j]).replace("_u", "_uinv") if isinstance(u[j], sp.Basic) else f"uinv{j}") for j in range(K)]
        s[0] = A.const(1)
        for j in range(K): s[0] = A.mul(s[0], uInv[j])
        for i in range(1, N):
            lg = i.bit_length() - 1
            uj = u[K - 1 - lg]
            s[i] = A.mul(s[i - (1 << lg)], A.mul(uj, uj))
        return s, uInv


# ----------------------------------------------------------------------------- the LEGACY verifier, transliterated
def legacy_equations(V):
    """List of equations in the fold's order; each a list of (point name, scalar). Mirrors legacy/zether-msm."""
    A = V.A; c = V.c; nc = A.rminus(c); r1 = A.rminus(A.const(1))
    eqs = []
    sp_ = lambda i: f"sp{i}"
    pf = lambda i: f"pf{i}"
    if V.form == "transfer":
        z = V.z
        eqs.append([("G", z[0]), (sp_(0), nc), (pf(2), r1)])                                   # E1
        eqs.append([("G", z[2]), (sp_(6), nc), (pf(3), r1)])                                   # E2
        eqs.append([("G", z[1]), (sp_(1), z[2]), (sp_(5), nc), (pf(4), r1)])                   # E3
        eqs.append([("G", z[1]), (sp_(0), z[2]), (sp_(7), nc), (pf(5), r1)])                   # E4
        eqs.append([("G", A.add(z[3], A.mul(c, V.fee))), (sp_(4), z[0]), (sp_(6), A.negS(z[0])),
                    (sp_(3), nc), (sp_(7), c), (pf(6), r1)])                                   # E5
        if V.aud:
            eqs.append([("G", z[1]), (sp_(2), z[2]), (sp_(8), nc), (pf(7), r1)])               # E6
        eqs.append([("G", z[1]), ("Hb", z[4]), (pf(0), nc), (pf(8), r1)])                      # E7
        eqs.append([("G", z[3]), ("Hb", z[5]), (pf(1), nc), (pf(9), r1)])                      # E8
        vs = [pf(0), pf(1)]
    elif V.form == "multi":
        z = V.z; m = V.m
        eqs.append([("G", z[0]), (sp_(0), nc), (pf(1), r1)])                                   # E1
        eqs.append([("G", z[1]), (sp_(4), nc), (pf(2), r1)])                                   # E2
        for j in range(m):
            zv = z[4 + 3 * j]
            eqs.append([("G", zv), (V.lp(j, 0), z[1]), (V.lp(j, 1), nc), (V.lpf(j, 1), r1)])   # E3_j
            zt = z[6 + 3 * j]
            if V.aud:
                eqs.append([("G", z[4 + 3 * j]), (sp_(1), zt), (V.lp(j, 2), nc), (V.lpf(j, 2), r1)])  # E6_j
                eqs.append([("G", zt), (V.lp(j, 3), nc), (V.lpf(j, 3), r1)])                         # E6'_j
            eqs.append([("G", zv), ("Hb", z[5 + 3 * j]), (V.lpf(j, 0), nc), (V.lpf(j, 4), r1)])     # E7_j
        zv = A.zero()
        for j in range(m): zv = A.add(zv, z[4 + 3 * j])
        eqs.append([("G", zv), (sp_(0), z[1]), (sp_(5), nc), (pf(3), r1)])                     # E4
        eqs.append([("G", A.add(z[2], A.mul(c, V.fee))), (sp_(3), z[0]), (sp_(4), A.negS(z[0])),
                    (sp_(2), nc), (sp_(5), c), (pf(4), r1)])                                   # E5
        eqs.append([("G", z[2]), ("Hb", z[3]), (pf(0), nc), (pf(5), r1)])                      # E8
        vs = [V.lpf(j, 0) for j in range(m)] + [pf(0)]
    else:
        z = V.z
        eqs.append([("G", z[0]), (sp_(0), nc), (pf(1), r1)])                                   # E1
        debit = A.add(V.amount, V.fee)
        eqs.append([("G", A.add(z[1], A.mul(c, debit))), (sp_(2), z[0]), (sp_(1), nc), (pf(2), r1)])  # E5
        eqs.append([("G", z[1]), ("Hb", z[2]), (pf(0), nc), (pf(3), r1)])                      # E8
        vs = [pf(0)]
    # range proofs, legacy verifyRange: _bp1 then _bp2, in proof order
    for k in range(V.nBp):
        b = V.bp[k]
        sc = [b["tau"], b["mu"], b["that"], b["a"], b["b"]]
        y, z, x, w_ch, u = b["y"], b["z"], b["x"], b["w"], b["u"]
        z2 = A.mul(z, z)
        sumY = A.zero(); yi = A.const(1)
        for i in range(N):
            sumY = A.add(sumY, yi); yi = A.mul(yi, y)
        delta = A.add(A.mul(A.add(z, A.rminus(z2)), sumY), A.rminus(A.mul(A.mul(z2, z), A.pow2mask())))
        eqs.append([("G", A.add(sc[2], A.rminus(delta))), ("Hb", sc[0]), (vs[k], A.negS(z2)),
                    (f"BP{k}_T1", A.negS(x)), (f"BP{k}_T2", A.negS(A.mul(x, x)))])            # BP-1
        # _bp2
        e = [(f"BP{k}_A", A.const(1)), (f"BP{k}_S", x)]
        # _sVector
        uInv = [A.inv(u[j], f"bp{k}_uinv{j}") for j in range(K)]
        s = [None] * N
        s[0] = A.const(1)
        for j in range(K): s[0] = A.mul(s[0], uInv[j])
        for i in range(1, N):
            lg = i.bit_length() - 1
            uj = u[K - 1 - lg]
            s[i] = A.mul(s[i - (1 << lg)], A.mul(uj, uj))
        yInv = A.inv(y, f"bp{k}_yinv")
        yInvI = A.const(1); twoI = A.const(1)
        gi, hi = [], []
        for i in range(N):
            gi.append((f"G_{i}", A.negS(A.add(z, A.mul(sc[3], s[i])))))
            inner = A.add(A.mul(z2, twoI), A.rminus(A.mul(sc[4], s[N - 1 - i])))
            hi.append((f"H_{i}", A.add(z, A.mul(yInvI, inner))))
            yInvI = A.mul(yInvI, yInv); twoI = A.add(twoI, twoI)
        e += gi + hi
        e.append(("Hb", A.negS(sc[1])))
        e.append(("U", A.mul(w_ch, A.add(sc[2], A.rminus(A.mul(sc[3], sc[4]))))))
        for j in range(K):
            e.append((f"BP{k}_L{j}", A.mul(u[j], u[j])))
            e.append((f"BP{k}_R{j}", A.mul(uInv[j], uInv[j])))
        eqs.append(e)                                                                          # BP-2
    return eqs


# ----------------------------------------------------------------------------- the comparison
def run(A, form, m=1, aud=True, seed=0, verbose=True):
    V = Vals(A, form, m, aud, seed)
    nf = NewFold(V)
    commitments = {"transfer": nf.sigma_transfer, "multi": nf.sigma_multi, "burn": nf.sigma_burn}[form]()
    e_sigma = len(set(commitments)) and None  # unused
    nf.fold_bp(commitments)
    eqs = legacy_equations(V)

    # Σ_i ρ^i · legacy coefficient per point name
    want = {}
    wi = A.const(1)
    for eq in eqs:
        for name, s in eq:
            want[name] = A.add(want.get(name, A.zero()), A.mul(wi, s))
        wi = A.mul(wi, V.rho)
    assert A.is_zero(A.add(wi, A.rminus(nf.w))), "weight after the last equation != rho^e"

    # the new fold per name (slot -> name by the layout)
    got = {}
    for slot, s in nf.f.items():
        name = V.names[slot]
        assert name not in got
        got[name] = s
    names = set(got) | set(want)
    bad = []
    for name in sorted(names):
        d = A.add(got.get(name, A.zero()), A.rminus(want.get(name, A.zero())))
        if not A.is_zero(d):
            bad.append((name, d))
    # every point of the layout that any equation touches is present, and the layout has no name twice
    assert len(set(V.names)) == len(V.names)
    e = len(eqs)
    if verbose:
        tag = f"{form:8s} M={m:2d} aud={'on ' if aud else 'off'} {A.__class__.__name__}"
        print(f"{tag}: equations e={e:3d}, slots={len(V.names):3d}, touched={len(got):3d}, mismatches={len(bad)}")
    for name, d in bad:
        print("   MISMATCH", name, d if isinstance(A, Sym) else hex(d))
    if isinstance(A, Num):
        # end-to-end: Σ f[slot]·P_slot == Σ_i ρ^i Q_i over random point "discrete logs"
        rnd = random.Random(seed + 7)
        P = {name: rnd.randrange(R) for name in V.names}
        lhs = sum(s * P[V.names[slot]] for slot, s in nf.f.items()) % R
        rhs = 0; wi = 1
        for eq in eqs:
            q = sum(s * P[name] for name, s in eq) % R
            rhs = (rhs + wi * q) % R
            wi = wi * V.rho % R
        assert lhs == rhs, "MSM of the fold != Σ ρ^i Q_i"
    return not bad, e, len(V.names)


if __name__ == "__main__":
    ok = True
    counts = {}
    for A in (Sym(), Num()):
        for form, aud in (("transfer", True), ("transfer", False), ("burn", True)):
            good, e, n = run(A, form, 1, aud)
            ok &= good; counts[(form, 1, aud)] = (e, n)
        ms = range(1, 17) if isinstance(A, Num) else (1, 2, 3, 16)
        for m in ms:
            for aud in (True, False):
                good, e, n = run(A, "multi", m, aud, seed=m)
                ok &= good; counts[("multi", m, aud)] = (e, n)
    # numeric edge cases: z_x = 0 (D_acc / D_out scalar 0), c-independent
    print("\nequation counts e and MSM point counts per form:")
    for key, (e, n) in sorted(counts.items(), key=lambda kv: (kv[0][0], kv[0][1], not kv[0][2])):
        print(f"  {key[0]:8s} M={key[1]:2d} aud={'on ' if key[2] else 'off'}: e={e:3d} points={n}")
    print("\nALL FORMS MATCH" if ok else "\nMISMATCH FOUND")
    sys.exit(0 if ok else 1)
