# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# sbfproof.py <before.so> <after.so> <old src root> <new src root>: every differing byte of two SBF builds explained.
# .text: a differing instruction must be `stw [r10+off], imm` (op 0x62) with only imm changed, storing the `line` of a
#   {file: &str, line: u32} built on the stack: an `lddw` of a ".rs" path within 16 instructions before, its pointer
#   stored at off-16 and its length (stdw imm) at off-8; the old line imm_before and the new line imm_after hold the
#   same code once whitespace is dropped (one may be a prefix of the other: rustfmt wraps).
# data: a differing byte must be a line or column field of a panic Location {file ptr u64, len u64, line u32, col u32}
#   whose ptr (SBF keeps the vaddr in the high word) names a ".rs" path; the same line check for the line fields.
import os, re, sys, struct

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "elfcmp.py")).read().split("A, B =")[0])  # secs()
A, B = (open(p, "rb").read() for p in sys.argv[1:3])
OLD, NEW = sys.argv[3:5]
sa, sb = secs(A), secs(B)
assert [(n, a, len(d)) for n, a, d in sa] == [(n, a, len(d)) for n, a, d in sb]
mem = {a + k: v for n, a, d in sa if a for k, v in enumerate(d)}
rd = lambda a, n: bytes(mem.get(a + k, 0) for k in range(n))


def path(p, ln):
    for q in (p, p >> 32):
        if 0 < ln < 300 and q in mem and rd(q, ln).endswith(b".rs"):
            return rd(q, ln).decode()


def tail(root, rel, line, col):
    t = open(f"{root}/programs/{rel}").read().splitlines()
    rest = (t[line - 1][col - 1 :] if col else t[line - 1]) + "".join(t[line : line + 12])
    return (
        re.sub(r",([)\]}])", r"\1", "".join(rest.split())).replace("{", "").replace("}", "")[:60]
    )  # rustfmt's trailing commas and block braces do not count


def same_line(f, lo, ln, co=None, cn=None):
    """the code from (line, column) on, whitespace dropped, is the same in the old and the new source: rustfmt moves
    tokens, never changes them; without a column the whole line from its first token"""
    if "programs/" not in f:
        return None  # a dependency's path: not formatted here, must not move
    rel = f.split("programs/", 1)[1]
    return tail(OLD, rel, lo, co) == tail(NEW, rel, ln, cn)


bad, rep = [], {}
for (n, a, x), (_, _, y) in zip(sa, sb):
    if x == y:
        rep[n] = "identical"
        continue
    if n == ".text":
        ins = sorted({k // 8 for k in range(len(x)) if x[k] != y[k]})
        files = set()
        for i in ins:
            bx, by = x[i * 8 : i * 8 + 8], y[i * 8 : i * 8 + 8]
            off = struct.unpack("<h", bx[2:4])[0]
            lo, ln = struct.unpack("<i", bx[4:8])[0], struct.unpack("<i", by[4:8])[0]
            ok = bx[0] == 0x62 and bx[1] == 0x0A and bx[:4] == by[:4]
            if ok:
                f = None
                for j in range(i - 1, i - 17, -1):
                    c = x[j * 8 : j * 8 + 8]
                    if c[0] == 0x18:
                        p = struct.unpack("<I", c[4:8])[0] | struct.unpack("<I", x[j * 8 + 12 : j * 8 + 16])[0] << 32
                        raw = rd(p, 300)
                        if raw.startswith(b"programs/") and b".rs" in raw:
                            f = raw[: raw.index(b".rs") + 3].decode()
                        if f:
                            break
                ok = bool(f) and same_line(f, lo, ln) is True
                if ok:
                    files.add(f)
            if not ok:
                bad.append((n, hex(a + i * 8), lo, ln))
        rep[n] = f"{len(ins)} stw line immediates ({', '.join(sorted(files))})"
        continue
    diffs = [a + k for k in range(len(x)) if x[k] != y[k]]
    recs, files = set(), set()
    ymem = dict(mem)
    ymem.update({a + k: v for k, v in enumerate(y)})
    for d in diffs:
        hit = None
        for r in range(d - (d % 4) - 16, d - (d % 4) - 24, -4):
            p, ln = struct.unpack("<QQ", rd(r, 16))
            f = path(p, ln)
            if f and r + 16 <= d < r + 24:
                hit = (r, f)
                break
        if hit:
            r, f = hit
            lo, co = struct.unpack("<II", rd(r + 16, 8))
            ln, cn = struct.unpack("<II", bytes(ymem[r + 16 + k] for k in range(8)))
            if same_line(f, lo, ln, co, cn) is not True:
                hit = None
        if hit:
            recs.add(hit[0])
            files.add(hit[1])
        else:
            bad.append((n, hex(d)))
    rep[n] = f"{len(diffs)} bytes in {len(recs)} panic Location line/column fields ({', '.join(sorted(files))})"
print("; ".join(f"{k}: {v}" for k, v in rep.items()))
print("unexplained:", len(bad), [b for b in bad if b[0] != ".text"][:6], bad[:4])
sys.exit(1 if bad else 0)
