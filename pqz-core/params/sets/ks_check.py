# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The knowledge-soundness side conditions of LNP22 theorem 6.4.3 on the committed codegen headers (review R0-C5, Codex
3w u5-4; three-key round), the same inequalities lnp-tbox-codegen.sage asserts since that fix:

  Barp = 2 sqrt(Bz3sqr) / sqrt(26)      (the verifier's z3 bound, lnp-tbox.c: l2(z3)^2 <= Bz3sqr, T = 1.64)
  q >= 41 nex d Barp                    (lemma 3.2.5)
  q >  Barp^2 + Barp sqrt(nbin d)       (binary coefficients of Ps1 s1 + Pm m + f)
  q >  Barp^2 + Barp sqrt(Z d)          (the Z upsilon terms of the one accumulated equation)
  q >  3 B_i^2 + Barp^2                 (every exact l2 proof i < Z)

Reads q, Bz3sqr, nbin, Z, nex and l2Bsq_i of every pqz_<rel>_params.h of every set; prints each relation's smallest
margin q / rhs and the overall smallest. Exit 1 if any condition fails. Stdlib only:
  python3 -B -I pqz-core/params/sets/ks_check.py [set ...]
"""
import glob
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
D = 64


def limbs(h, name):
    m = re.search(r"%s_limbs\[\] = \{([^}]*)\}" % re.escape(name), h)
    return sum(int(x.strip().rstrip("UL")) << (64 * i) for i, x in enumerate(m[1].split(",")))


def margins(path):
    """{condition: q / rhs} of one header"""
    h = open(path).read()
    r = re.search(r"static const lnp_tbox_params_t (\w+) = \{\{ \w+, \w+, (\d+), \w+, (\d+), (\d+), (\d+),", h)
    name, nbin, _nprime, z, nex = r[1], *map(int, r.groups()[1:])
    q, bz3sqr = limbs(h, f"{name}_q"), limbs(h, f"{name}_Bz3sqr")
    bsq = [limbs(h, f"{name}_l2Bsq{i}") for i in range(z)]
    barp = 2 * math.sqrt(bz3sqr) / math.sqrt(26)
    out = {"41 nex d Barp": q / (41 * nex * D * barp), "Barp^2 + Barp sqrt(nbin d)": q / (barp**2 + barp * math.sqrt(nbin * D)),
           "Barp^2 + Barp sqrt(Z d)": q / (barp**2 + barp * math.sqrt(z * D))}
    out |= {f"3 B_{i}^2 + Barp^2": q / (3 * b + barp**2) for i, b in enumerate(bsq)}
    return out


def main(argv):
    sets = argv or sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob(os.path.join(HERE, "*", "set.toml")))
    worst, n, bad = (math.inf, ""), 0, []
    for s in sets:
        for p in sorted(glob.glob(os.path.join(HERE, s, "pqz_*_params.h"))):
            m = margins(p)
            n += 1
            k = min(m, key=m.get)
            rel = os.path.basename(p)[4:-9]
            print(f"{s} {rel:7s} smallest margin {m[k]:8.2f}x  ({k})")
            bad += [f"{s} {rel}: {c} fails ({v:.3f}x)" for c, v in m.items() if not v > 1]
            if m[k] < worst[0]:
                worst = (m[k], f"{s} {rel} ({k})")
    print(f"ks_check: {n} headers, smallest margin {worst[0]:.2f}x at {worst[1]}" + ("" if not bad else ": FAIL"))
    for b in bad:
        print("FAIL", b)
    return 1 if bad or not n else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
