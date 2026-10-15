#!/usr/bin/env python3
"""PQZH op 7 R_TXM statements and witnesses vs pqz_kat.py (P6-ANON Track H, H1). pqz-core has no op 7 until Track L
merges, so pqz_kat.py is the byte oracle: every txm*_stmt.bin dumped by the Ligero crate (`dump_setup`) must parse
under pqz_kat.py's op 7 rules with PQZH's id only, be rebuilt byte for byte by build_multi from the parsed fields, carry
recipientsHash = recipients_hash(UA_0..UA_{M-1}) (UA_j = 0x1000 + j) and the M / auditorOn words of its file name; and
its witness (s_f || e_f || (r_g || e1_g)_g || e2 vectors || d_j || d', plan §4 prover API) must reproduce the
statement's pk_f, every u_g, v_j, v_f, v_{a,j} with pqz_kat.py's own A, products and encryption (legs in group j // 4),
meet every norm, and satisfy the debit: Dec(s_f, T) = b' + sum_j a_j + fee with every digit < 16.
  python3 -I kat_multi.py DIR      (DIR holds txm<M>[_0][_fee0|_two]_{stmt,wit}.bin); exit 1 on any difference
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../smartcontracts/vectors/pqz"))
import pqz_kat as K  # noqa: E402

N = 2048


def i8(b):
    return [x - 256 if x > 127 else x for x in b]


def i16(b):
    return [int.from_bytes(b[i:i + 2], "little", signed=True) for i in range(0, len(b), 2)]


def value(d):
    return sum(x * 16**i for i, x in enumerate(d))


def check(st, wit, m, aud):
    bad = []
    d = K.parse(7, st, ids=(K.PQZH_ID,))
    try:
        K.parse(7, st, ids=(K.PQZL_ID,))
        bad.append("parsed as PQZL")
    except ValueError:
        pass
    if (d["legs"], d["auditor"]) != (m, aud):
        bad.append(f"shape {d['legs']}, {d['auditor']}")
    f = {k: d[k] for k in K.MULTI_HEADER if k not in ("opTag", "M", "auditorOn")} | {"salt": d["salt"][16:]}
    if K.build_multi(f, d["pk_f"], d["pks"], d["T"], d["us"], d["vs"], d["v_f"], pk_a=d.get("pk_a"),
                     v_as=d.get("v_as")) != st:
        bad.append("rebuild")
    if d["recipientsHash"] != K.recipients_hash([0x1000 + j for j in range(m)]):
        bad.append("recipientsHash")
    # witness
    g = K.groups(m)
    nv = m + 1 + aud * m
    if len(wit) != 6144 * (1 + g) + 32 * nv + 16 * (m + 1):
        return bad + [f"witness length {len(wit)}"]
    s_f, e_f = i8(wit[:N]), i16(wit[N:3 * N])
    rs = [i8(wit[6144 * (1 + i):6144 * (1 + i) + N]) for i in range(g)]
    e1s = [i16(wit[6144 * (1 + i) + N:6144 * (2 + i)]) for i in range(g)]
    p = 6144 * (1 + g)
    e2 = [i16(wit[p + 32 * x:p + 32 * x + 32]) for x in range(nv)]
    p += 32 * nv
    ds = [list(wit[p + 16 * j:p + 16 * j + 16]) for j in range(m)]
    dp = list(wit[p + 16 * m:p + 16 * m + 16])
    if K.sq(s_f) > K.B_S**2 or K.sq(e_f) > K.B_E**2 or any(K.sq(r) > K.B_S**2 for r in rs) or \
            any(K.sq(e) > K.B_E**2 for e in e1s) or any(K.sq(e) > K.B_2**2 for e in e2):
        bad.append("norms")
    if any(x > 15 for x in sum(ds, dp)):
        bad.append("digit >= 16")
    t = K.mul_A(K.polys(s_f))
    if K.enc_vec([[(t[i][k] + e_f[K.D * i + k]) % K.Q for k in range(K.D)] for i in range(K.K)]) != d["pk_f"]:
        bad.append("pk_f != A s_f + e_f")
    # vectors in witness order: legs (d_j), f (d'), auditor copies (d_j); group of leg j: j // 4, v_f: 0
    vecs = [(d["pks"][j], ds[j], j // K.LEGS_PER_GROUP, d["vs"][j]) for j in range(m)]
    vecs.append((d["pk_f"], dp, 0, d["v_f"]))
    if aud:
        vecs += [(d["pk_a"], ds[j], j // K.LEGS_PER_GROUP, d["v_as"][j]) for j in range(m)]
    for gi in range(g):
        xs = [x for x in range(nv) if vecs[x][2] == gi]
        u, vs = K.encrypt([vecs[x][0] for x in xs], [vecs[x][1] for x in xs], rs[gi], e1s[gi], [e2[x] for x in xs])
        if u != d["us"][gi]:
            bad.append(f"u_{gi}")
        bad += [f"v vector {x}" for x, v in zip(xs, vs) if v != vecs[x][3]]
    _, noise, bal = K.dec(s_f, d["T"])
    fee = int.from_bytes(d["fee"], "big")
    amounts = [value(x) for x in ds]
    if bal != value(dp) + sum(amounts) + fee:
        bad.append(f"debit: {bal} != {value(dp)} + {sum(amounts)} + {fee}")
    return bad, amounts, fee, bal


def main(dirname):
    nbad = 0
    files = sorted(glob.glob(os.path.join(dirname, "txm*_stmt.bin")))
    for fn in files:
        tag = os.path.basename(fn)[:-len("_stmt.bin")]
        mt = re.fullmatch(r"txm(\d+)(_0)?(_fee0|_two)?", tag)
        m, aud = int(mt.group(1)), 0 if mt.group(2) else 1
        st = open(fn, "rb").read()
        wit = open(os.path.join(dirname, tag + "_wit.bin"), "rb").read()
        try:
            r = check(st, wit, m, aud)
            bad, info = (r, "") if isinstance(r, list) else (r[0], f"legs {r[1]} fee {r[2]} balance {r[3]}")
        except Exception as x:  # a malformed dump must fail, not crash the run
            bad, info = [f"raised {type(x).__name__}: {x}"], ""
        nbad += bool(bad)
        print(f"{tag}_stmt {len(st)} B wit {len(wit)} B M={m} auditorOn={aud} {info} "
              f"{'ok' if not bad else 'FAIL ' + '; '.join(bad)}")
    if not files:
        print("no txm*_stmt.bin")
        nbad = 1
    print(f"kat_multi: {len(files)} statements,", "FAIL" if nbad else "ok")
    return 1 if nbad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
