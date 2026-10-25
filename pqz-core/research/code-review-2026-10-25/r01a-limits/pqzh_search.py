"""Preset search (radices of the set, proven regime, query soundness >= the preset's) for the smallest PQZH bound of audited
R_TXM M = 4 with G = 2. python3 -I pqzh_search.py"""
import sys, math, functools
exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "pqzh_bound.py")).read().split("SAUD =")[0])
SAUD = {"n2048-kmax1024": 2, "n2304-kmax4096": 3}
def ro_g(g):
    def ro(p_, rel, ell):
        se, sl = [p_.s_bits, p_.e_bits], [(1, p_.sl_s), (1, p_.sl_e)]
        _, m_, aud_ = rel
        legs = m_ + 1 + aud_ * m_
        pairs = 1 + g
        v = [(16 * legs, p_.e2_bits)] + [(16 * m_, 4)]
        v += [(16, 4), (16, p_.m_bits), (16, p_.c_bits), (16, p_.et_bits)] + sl * pairs + [(1, p_.sl_2)] * legs
        nr = -(-p_.N // ell)
        small = 2 * -(-sum(c for c, _ in v) // ell) + -(-sum(c * b for c, b in v) // ell)
        return sum(nr * (2 + b) for b in se * pairs) + small, len(se * pairs) * nr + small
    return ro
for name, s in SAUD.items():
    c, _ = L.set_consts(name)
    p = L.Lay(c); q = c['Q']; mp = c['MAX_PROOF_PQZH']; mi = c['MAX_INPUT']
    f = L.factor(q - 1)
    rad = c['RADICES']
    extra = sorted({r for r in f if r not in rad and r <= 431})
    mult = {r: f.count(r) for r in set(f)}
    smooth_of = lambda rs: sorted(x for x in functools.reduce(lambda a, r: {y * r**e for y in a for e in range(mult[r] + (2 if r == 2 else 0) + 1) if y * r**e <= 2**21}, rs, {1}) if (q - 1) % x == 0 and x <= L.NMAX)
    L.rows_own_set = ro_g(2)
    n0, k0, t0 = c['PRESET_N'], c['PRESET_K'], c['PRESET_T']
    snd0 = t0 * -math.log2(L.factor_proven(n0, k0)) + L.POW
    print(f"{name}: preset n {n0} k {k0} t {t0} query bits {snd0:.2f}; extra radices {extra}")
    for rs in [rad] + ([sorted(rad + extra)] if extra else []):
        sm = smooth_of(rs)
        res = []
        for nn in sm:
            for kk in sm:
                if 4 * kk > nn or kk < 64: continue
                fac = L.factor_proven(nn, kk)
                tt = L.t_of(fac)
                # keep at least the preset's query soundness
                while tt * -math.log2(fac) + L.POW < snd0: tt += 1
                if kk - tt - 1 < 16: continue
                if 2 * kk - 1 > sm[-1]: continue
                res.append((L.bound_set(p, ('txm', 4, 1), nn, kk, tt), nn, kk, tt))
        res.sort()
        print("  radices", rs, "best:", [(b, nn, kk, tt) for b, nn, kk, tt in res[:5]])
