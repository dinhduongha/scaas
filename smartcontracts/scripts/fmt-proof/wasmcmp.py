# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# wasmcmp.py <before.wasm> <after.wasm> <old family root> <new family root>: per section equality; every differing data
# byte is a line or column field of a panic Location {file ptr u32, len u32, line u32, col u32} naming a ".rs" path, and the
# code at (line, column) of that file, whitespace and trailing commas dropped, is the same in the old and the new source
import os, re, sys, struct

OLD, NEW = sys.argv[3:5]


def tail(root, rel, line, col):
    if rel.startswith("/") or not os.path.exists(f"{root}/{rel}"):
        return None  # not a file of the family: must not move
    t = open(f"{root}/{rel}").read().splitlines()
    if line > len(t):
        return None
    rest = t[line - 1][col - 1 :] + "".join(t[line : line + 12])
    return re.sub(r",([)\]}])", r"\1", "".join(rest.split())).replace("{", "").replace("}", "")[:60]


def leb(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def sections(b):
    i, out = 8, []
    while i < len(b):
        sid = b[i]
        n, j = leb(b, i + 1)
        body = b[j : j + n]
        name = None
        if sid == 0:
            ln, k = leb(body, 0)
            name = body[k : k + ln].decode()
        out.append((sid, name, body))
        i = j + n
    return out


def data_segments(body):
    n, i = leb(body, 0)
    segs = []
    for _ in range(n):
        flag, i = leb(body, i)
        assert flag == 0, flag
        assert body[i] == 0x41
        off, i = leb(body, i + 1)  # i32.const (small positive)
        assert body[i] == 0x0B
        i += 1
        ln, i = leb(body, i)
        segs.append((off, body[i : i + ln]))
        i += ln
    return segs


A, B = (open(p, "rb").read() for p in sys.argv[1:3])
sa, sb = sections(A), sections(B)
assert [(s, n) for s, n, _ in sa] == [(s, n) for s, n, _ in sb], "section lists differ"
NAMES = {
    1: "type",
    2: "import",
    3: "function",
    5: "memory",
    6: "global",
    7: "export",
    10: "code",
    11: "data",
    12: "datacount",
}
res = []
for (sid, name, x), (_, _, y) in zip(sa, sb):
    label = name or NAMES.get(sid, str(sid))
    if x == y:
        res.append(f"{label} identical")
        continue
    if sid != 11:
        res.append(f"{label} DIFFERS")
        continue
    da, db = data_segments(x), data_segments(y)
    assert [(o, len(d)) for o, d in da] == [(o, len(d)) for o, d in db], "data layout differs"
    mem = {}
    for o, d in da:
        for k, v in enumerate(d):
            mem[o + k] = v

    def u32(a):
        return struct.unpack("<I", bytes(mem.get(a + k, 0) for k in range(4)))[0]

    diffs = [o + k for (o, d), (_, e) in zip(da, db) for k in range(len(d)) if d[k] != e[k]]
    fields, bad, files = set(), [], set()
    for a in diffs:
        ok = False
        for f in range(a - (a % 4), a - 16, -4):  # candidate field start (line at r+8, col at r+12)
            for r in (f - 8, f - 12):
                p, n = u32(r), u32(r + 4)
                if 0 < n < 300 and p in mem:
                    s = bytes(mem.get(p + k, 0) for k in range(n))
                    if s.endswith(b".rs"):
                        e = {o + k: v for (o, d) in db for k, v in enumerate(d)}
                        lo, co = u32(r + 8), u32(r + 12)
                        ln, cn = (struct.unpack("<I", bytes(e.get(r + q + k, 0) for k in range(4)))[0] for q in (8, 12))
                        if tail(OLD, s.decode(), lo, co) is None or tail(OLD, s.decode(), lo, co) != tail(
                            NEW, s.decode(), ln, cn
                        ):
                            print(
                                "  source differs at",
                                s.decode(),
                                (lo, co),
                                "->",
                                (ln, cn),
                                tail(OLD, s.decode(), lo, co),
                                "|",
                                tail(NEW, s.decode(), ln, cn),
                            )
                            break
                        fields.add((r, "line" if f == r + 8 else "col"))
                        files.add(s.decode())
                        ok = True
                        break
            if ok:
                break
        if not ok:
            bad.append(a)
    lines = sum(1 for _, k in fields if k == "line")
    cols = len(fields) - lines
    res.append(
        f"data: {len(diffs)} bytes differ in {len({r for r, _ in fields})} panic Location records "
        f"({lines} line, {cols} column fields; files: {', '.join(sorted(files))}); unexplained bytes: {len(bad)}"
    )
print("; ".join(res))
sys.exit(1 if any("DIFFERS" in r for r in res) or bad else 0)
