"""PQZH (Ligero) proof bound and precompile input per R_TXM shape with G = ceil(M / s_aud) (auditor on): ligero_params.py's
layout model (= the crate's exact bound on every built shape) with the group count changed. python3 -I pqzh_bound.py"""
import sys, math
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "..", "..", "..", "pqzh", "ligero"))
import ligero_params as L
_rr = L.read_rs
def rr(path):
    import re
    out = {}
    for name, v in re.findall(r'pub\(crate\) const (\w+): [^=]+= ([^;]+);', open(path).read()):
        v = v.strip()
        if v in ('true', 'false'): out[name] = v == 'true'
        elif v.startswith('"'): out[name] = v.strip('"')
        elif v.startswith('&[') or v.startswith('['):
            try: out[name] = [int(x.replace('_', ''), 0) for x in v.strip('&[]').split(',') if x.strip()]
            except ValueError: pass
        else: out[name] = int(v.replace('_', ''))
    return out
L.read_rs = rr
SAUD = {"n2048-kmax1024": 2, "n2304-kmax4096": 3, "n2560-kmax16384": 4}
for name, s in SAUD.items():
    c, _ = L.set_consts(name)
    p = L.Lay(c)
    n, k, t = c['PRESET_N'], c['PRESET_K'], c['PRESET_T']
    mp, mi = c['MAX_PROOF_PQZH'], c['MAX_INPUT']
    orig = L.rows_own_set
    for m in (1, 2, 4):
        for aud in (1, 0):
            g = -(-m // (s if aud else 4))
            def ro(p_, rel, ell, g=g):
                se, sl = [p_.s_bits, p_.e_bits], [(1, p_.sl_s), (1, p_.sl_e)]
                _, m_, aud_ = rel
                legs = m_ + 1 + aud_ * m_
                pairs = 1 + g
                v = [(16 * legs, p_.e2_bits)] + [(16 * m_, 4)]
                v += [(16, 4), (16, p_.m_bits), (16, p_.c_bits), (16, p_.et_bits)] + sl * pairs + [(1, p_.sl_2)] * legs
                bigs, smalls = se * pairs, v
                nr = -(-p_.N // ell)
                small = 2 * -(-sum(c for c, _ in smalls) // ell) + -(-sum(c * b for c, b in smalls) // ell)
                return sum(nr * (2 + b) for b in bigs) + small, len(bigs) * nr + small
            L.rows_own_set = ro
            b = L.bound_set(p, ('txm', m, aud), n, k, t)
            L.rows_own_set = orig
            b0 = L.bound_set(p, ('txm', m, aud), n, k, t)
            pk, v, h = 8 * p.N, 128, 640
            st = h + (1 + m + aud) * pk + (pk + v) + g * pk + v * (m + 1) + aud * v * m
            print(f"{name} M={m} aud={aud} G={g}: bound {b:,} (today {b0:,}) <= {mp:,}: {b <= mp}; input {5 + st + b:,} <= {mi:,}: {5 + st + b <= mi}")
