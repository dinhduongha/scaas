# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# elfcmp.py <before.so> <after.so>: section-by-section equality of two ELF64 files; differing bytes of a data section
# explained as panic Location {file: &str (vaddr u64, len u64), line u32, col u32} fields
import sys, struct


def secs(b):
    (shoff,) = struct.unpack_from("<Q", b, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x3A)
    hs = [struct.unpack_from("<IIQQQQIIQQ", b, shoff + i * shentsize) for i in range(shnum)]
    st = hs[shstrndx]
    strtab = b[st[4] : st[4] + st[5]]
    out = []
    for h in hs:
        name = strtab[h[0] : strtab.index(b"\0", h[0])].decode()
        data = b[h[4] : h[4] + h[5]] if h[1] != 8 else b""  # SHT_NOBITS
        out.append((name, h[3], data))  # name, vaddr, bytes
    return out


A, B = (open(p, "rb").read() for p in sys.argv[1:3])
sa, sb = secs(A), secs(B)
assert [(n, a, len(d)) for n, a, d in sa] == [(n, a, len(d)) for n, a, d in sb], "section layout differs"
mem = {}
for n, a, d in sa:
    if a:
        for k, v in enumerate(d):
            mem[a + k] = v


def rd(a, n):
    return bytes(mem.get(a + k, 0) for k in range(n))


res, rc = [], 0
for (n, a, x), (_, _, y) in zip(sa, sb):
    if x == y:
        res.append(f"{n or '(null)'} identical")
        continue
    diffs = [a + k for k in range(len(x)) if x[k] != y[k]]
    if not a:
        res.append(f"{n} DIFFERS ({len(diffs)} bytes, not loaded)")
        rc = 1
        continue
    fields, files, bad = set(), set(), []
    for d in diffs:
        ok = False
        for f in range(d - (d % 4), d - 24, -4):
            for r in (f - 16, f - 20):
                p, ln = struct.unpack("<QQ", rd(r, 16))
                if 0 < ln < 300 and p in mem and rd(p, ln).endswith(b".rs"):
                    fields.add((r, "line" if f == r + 16 else "col"))
                    files.add(rd(p, ln).decode())
                    ok = True
                    break
            if ok:
                break
        if not ok:
            bad.append(d)
    if bad:
        rc = 1
    lines = sum(1 for _, k in fields if k == "line")
    res.append(
        f"{n}: {len(diffs)} bytes differ in {len({r for r, _ in fields})} panic Location records ({lines} line, "
        f"{len(fields) - lines} column fields; files: {', '.join(sorted(files))}); unexplained bytes: {len(bad)}"
    )
print("; ".join(res))
sys.exit(rc)
