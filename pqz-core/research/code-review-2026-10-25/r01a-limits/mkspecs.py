"""R0-1 fix part a, limit check: the changed PQZL specs (s_aud groups with the auditor on, Bprime 8 for reg / dr)
from gen_set.py's spec text, without changing gen_set.py. python3 -I mkspecs.py"""
import os, sys, types
G = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'), "params", "sets", "gen_set.py")
src = open(G).read()
src = src.replace('[k, k], [bs, be], 0, 0, 1, "s[0], in [-1, 1]")', '[k, k], [bs, be], 0, 0, 8, "s[0]")')
src = src.replace('16 * eb, 1, "s[0], in [-1, 1]")', '16 * eb, 8, "s[0]")')
old = """    for M in (2, 4, 8, 16):
        G = (M + 3) // 4
        bits = tx_bits - 64 + 64 * M
        ks, Bs = debit(G)
        for aud in (1, 0):
"""
new = """    for M in (2, 4, 8, 16):
        bits = tx_bits - 64 + 64 * M
        for aud in (1, 0):
            G = -(-M // (SAUD[name] if aud else 4))
            ks, Bs = debit(G)
"""
assert old in src
src = src.replace(old, new)
src = src.replace('if __name__ == "__main__":', 'if False:')
m = types.ModuleType("gs"); m.__file__ = G
m.SAUD = {"n2048-kmax1024": 2, "n2304-kmax4096": 3, "n2560-kmax16384": 4, "n2816-kmax65536": 4}
exec(compile(src, G, "exec"), m.__dict__)
for name in ("n2048-kmax1024", "n2304-kmax4096"):
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "specs", name); os.makedirs(d, exist_ok=True)
    sp = m.specs(name)
    for r in ("reg", "dr", "txm4", "txm8"):
        open(os.path.join(d, f"{r}_params.sage"), "w").write(sp[r])
        print(name, r, [l for l in sp[r].splitlines() if l.startswith(("m1 =", "Bprime", "n =", "# R_TXM"))])
