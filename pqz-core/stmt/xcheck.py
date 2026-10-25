#!/usr/bin/env python3
"""pqz-stmt cross-check inputs (P6e Task 5), written by the independent Python codec pqz_kat.py:

  xcheck.py <C dump dir> <out.txt> [n]

1. The C core's statements (pqz-core/pqzh/xcheck/dump_setup DIR pqzh: pqz_bench.c setup(), all six forms, with the
   real opTag and the PQZH id in bytes 0..63; the bench's header words are canonical since P6e stmt3):
   pqz_kat.py must accept each and rebuild it byte for byte from the parsed fields with its own builders.
2. n random statements per form (both ids, random header words, coefficients < q) built by pqz_kat.py, each written
   with its fields ("ok" lines), and every D15 / R6 mutation of some of them with pqz_kat.py's reason ("bad" lines).
3. Op 7 R_TXM (P6-ANON S2): one random statement per built (id, M, auditorOn), fee 0 on every other one, and the
   op 7 rules' mutations (M word, auditorOn, length, amount = 0, ...); pqz-stmt reads them with parse_multi.
pqz-stmt's tests/xcheck.rs reads the dump dir and out.txt (PQZ_STMT_XCHECK=<dir>): it must parse the same bytes into
the same fields, build the same bytes from the fields, and reject each "bad" line for the same reason.
Line format: ok <op> <form> <stmt hex> <field>=<hex>...  |  bad <op> <reason> <stmt hex>  |  c <name> <form> ok.
"""
import importlib.util
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "pqz_kat", os.path.join(HERE, "..", "..", "smartcontracts", "vectors", "pqz", "pqz_kat.py"))
kat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kat)

PK, V, CT, HB = kat.PK_BYTES, kat.V_BYTES, kat.CT_BYTES, kat.HEADER_BYTES
C_FORMS = {"reg": "REGISTER", "tx": "TRANSFER", "burn": "BURN", "ds": "DISCLOSE-SENDER", "dr": "DISCLOSE-RECEIVER",
           "tx0": "TRANSFER0"}


def op_of(form):
    return kat.OP_BYTE[form.rstrip("0")]


def fields_of(form, st):
    """The statement split into the named objects pqz-stmt exposes."""
    if form == "REGISTER":
        return {"words": st[:96], "pk": st[96:]}
    if form.startswith("DISCLOSE"):
        return {"words": st[:288], "pk": st[288:288 + PK], "u": st[288 + PK:288 + 2 * PK], "v": st[288 + 2 * PK:]}
    tr, aud = form.startswith("TRANSFER"), form == "TRANSFER"
    f, o, b = {"hdr": st[:HB]}, 0, st[HB:]
    for k, n, on in (("pk_f", PK, True), ("pk_t", PK, tr), ("pk_a", PK, aud), ("t", CT, True), ("u", PK, True),
                     ("v_t", V, tr), ("v_f", V, True), ("v_a", V, aud)):
        if on:
            f[k], o = b[o:o + n], o + n
    assert o == len(b)
    return f


def rebuild(form, st):
    """pqz_kat.py's own builders from its parse of st."""
    p = kat.parse(op_of(form), st)
    op = form.rstrip("0")
    assert p["op"] == op
    if op == "REGISTER":
        return kat.build_register(p["message"], p["pk"], psid=st[32:64])
    if op.startswith("DISCLOSE"):
        f = {k: p[k] for k in kat.DISC if k != "opTag"}
        return kat.build_disclose(op, f, p["pk"], p["u"], p["v"])
    f = {k: p[k] for k in kat.HEADER if k != "opTag"}
    f["salt"] = f["salt"][16:]  # 16 zero bytes || salt (parse enforces it)
    out = p["u"] + b"".join(p[k] for k in ("v_t", "v_f", "v_a") if k in p)
    return kat.build_debit(op, f, p["pk_f"], p["T"], out, pk_t=p.get("pk_t"), pk_a=p.get("pk_a"))


def main(argv):
    cdir, out_path = argv[1], argv[2]
    n = int(argv[3]) if len(argv) > 3 else 4
    rng = random.Random(0x5717)
    lines = []
    for name, form in C_FORMS.items():
        st = open(os.path.join(cdir, f"{name}_stmt.bin"), "rb").read()
        assert len(st) == kat.STMT_BYTES[form], name
        assert rebuild(form, st) == st, f"pqz_kat.py rebuild of the C {name} statement differs"
        lines.append(f"c {name} {form} ok")

    def coeffs(k):
        return b"".join(rng.randrange(kat.Q).to_bytes(8, "big") for _ in range(k))

    valid = []
    for _ in range(n):
        for form in ("TRANSFER", "TRANSFER0", "BURN", "REFRESH", "REGISTER", "DISCLOSE-SENDER", "DISCLOSE-RECEIVER",
                     "DISCLOSE-AUDITOR"):
            psid = rng.choice([kat.PQZL_ID, kat.PQZH_ID])
            op = form.rstrip("0")
            if op == "REGISTER":
                st = kat.build_register(rng.randbytes(32), coeffs(kat.N), psid=psid)
            elif op.startswith("DISCLOSE"):
                f = {k: rng.randbytes(32) for k in kat.DISC[2:]}
                f.update(proofSystemId=psid, amount=rng.getrandbits(64), kind=rng.randrange(3))
                st = kat.build_disclose(op, f, coeffs(kat.N), coeffs(kat.N), coeffs(16))
            else:
                f = {k: rng.randbytes(32) for k in kat.HEADER[2:]}
                f.update(proofSystemId=psid, fee=rng.getrandbits(64), amount=rng.getrandbits(64),
                         salt=rng.randbytes(16))
                f.pop("auditorOn")
                for k in kat.ZERO_WORDS[op]:
                    f[k] = 0
                tr, aud = op == "TRANSFER", form == "TRANSFER"
                out = coeffs(kat.N + 16 * (2 + aud if tr else 1))
                st = kat.build_debit(op, f, coeffs(kat.N), coeffs(kat.N + 16), out, pk_t=coeffs(kat.N) if tr else None,
                                     pk_a=coeffs(kat.N) if aud else None)
            assert len(st) == kat.STMT_BYTES[form] and rebuild(form, st) == st
            kat.parse(op_of(form), st)
            valid.append((form, st))
            fl = " ".join(f"{k}={v.hex()}" for k, v in fields_of(form, st).items())
            lines.append(f"ok {op_of(form)} {form} {st.hex()} {fl}")

    multi = []
    i = 0
    for psid in (kat.PQZL_ID, kat.PQZH_ID):
        for aud in (1, 0):
            for m in kat.BUILT_LEGS[psid]:
                f = {k: rng.randbytes(32) for k in kat.MULTI_HEADER[2:] if k not in ("M", "auditorOn")}
                f.update(proofSystemId=psid, fee=0 if i % 2 == 0 else rng.getrandbits(64), amount=0,
                         salt=rng.randbytes(16))
                i += 1
                st = kat.build_multi(f, coeffs(kat.N), [coeffs(kat.N) for _ in range(m)], coeffs(kat.N + 16),
                                     [coeffs(kat.N) for _ in range(kat.groups(m, aud))], [coeffs(16) for _ in range(m)],
                                     coeffs(16), pk_a=coeffs(kat.N) if aud else None,
                                     v_as=[coeffs(16) for _ in range(m)] if aud else None)
                p = kat.parse(7, st)
                back = kat.build_multi({k: p[k] for k in kat.MULTI_HEADER if k not in ("opTag", "M", "auditorOn")} |
                                       {"salt": p["salt"][16:]}, p["pk_f"], p["pks"], p["T"], p["us"], p["vs"],
                                       p["v_f"], pk_a=p.get("pk_a"), v_as=p.get("v_as"))
                assert len(st) == kat.multi_len(m, aud) and back == st and p["legs"] == m
                multi.append(st)
                fl = {"hdr": st[:HB], "pk_f": p["pk_f"], "pks": b"".join(p["pks"])}
                if aud:
                    fl["pk_a"] = p["pk_a"]
                fl.update(t=p["T"], us=b"".join(p["us"]), vs=b"".join(p["vs"]), v_f=p["v_f"])
                if aud:
                    fl["v_as"] = b"".join(p["v_as"])
                lines.append(f"ok 7 TRANSFER-MULTI {st.hex()} " + " ".join(f"{k}={v.hex()}" for k, v in fl.items()))

    def bad(op, st, what):
        try:
            kat.parse(op, st)
        except ValueError as x:
            lines.append(f"bad {op} {str(x).replace(' ', '_')} {st.hex()}")
            return
        raise AssertionError(f"pqz_kat.py accepted: {what}")

    L = kat.Q.bit_length()
    for form, st in valid[:16]:
        op = op_of(form)
        body0 = {"REGISTER": 96}.get(form, 288 if form.startswith("DISCLOSE") else HB)
        c = body0 + 8 * rng.randrange((len(st) - body0) // 8)
        for v in (kat.Q, 2**L, 2**64 - 1, kat.Q + rng.randrange(2**L - kat.Q)):  # L = ceil(log2 q)
            bad(op, st[:c] + v.to_bytes(8, "big") + st[c + 8:], "coefficient")
        bad(op, st[:-1], "length - 1")
        bad(op, st + b"\0", "length + 1")
        bad(op, rng.choice([kat.OP_TAG[m] for m in kat.OP_NAMES if kat.OP_BYTE[m] != op]) + st[32:], "opTag")
        bad(op % 5 + 1, st, "other op")
        bad(op, st[:32] + rng.randbytes(32) + st[64:], "id")
        if form.startswith("DISCLOSE"):
            i = 224 + rng.randrange(24)
            bad(op, st[:i] + bytes([st[i] | (1 + rng.randrange(255))]) + st[i + 1:], "amount")
            # the kind word = OpeningKind + 256 w (R0-1): w = 0 but for AUDITOR, w < S_AUD there; < 2^16
            k = int.from_bytes(st[256:288], "big") & 255
            wmax = kat.S_AUD if form == "DISCLOSE-AUDITOR" else 1
            for v, what in ((k + 256 * wmax, "kind window"), (k + 2**16, "kind word >= 2^16")):
                bad(op, st[:256] + kat.word(v) + st[288:], what)
        elif form != "REGISTER":
            for k in kat.ZERO_WORDS[form.rstrip("0")]:
                i = 32 * kat.HEADER.index(k) + 16 + rng.randrange(16)  # the low half: the salt form still holds
                bad(op, st[:i] + bytes([st[i] ^ (1 + rng.randrange(255))]) + st[i + 1:], k)
            for w, what in ((256, "fee"), (288, "amount"), (576, "salt")):
                if what == "salt":
                    i = w + rng.randrange(16)
                    bad(op, st[:i] + bytes([st[i] | (1 + rng.randrange(255))]) + st[i + 1:], what)
                    continue
                i = w + rng.randrange(24)
                bad(op, st[:i] + bytes([st[i] | (1 + rng.randrange(255))]) + st[i + 1:], what)
            if op == 1:
                a = int.from_bytes(st[448:480], "big")
                for v in (1 - a, 2, 2**64 + a):
                    bad(op, st[:448] + v.to_bytes(32, "big") + st[480:], "auditorOn")
    w = kat.word
    for st in sorted(multi, key=len)[:6] + [max(multi, key=len)]:
        c = HB + 8 * rng.randrange((len(st) - HB) // 8)
        for v in (kat.Q, 2**63 + 5):
            bad(7, st[:c] + v.to_bytes(8, "big") + st[c + 8:], "coefficient")
        bad(7, st[:-1], "length - 1")
        bad(7, st + b"\0", "length + 1")
        bad(7, st[:639], "header cut")
        bad(7, rng.choice([kat.OP_TAG[m] for m in kat.OP_NAMES if m != "TRANSFER-MULTI"]) + st[32:], "opTag")
        bad(1, st, "op 7 statement under op 1")
        bad(7, st[:32] + rng.randbytes(32) + st[64:], "id")
        bad(7, st[:256] + w(2**64 + rng.getrandbits(64)) + st[288:], "fee")
        bad(7, st[:288] + w(2**64) + st[320:], "amount >= 2^64")
        bad(7, st[:288] + w(1 + rng.getrandbits(63)) + st[320:], "amount = 0")
        bad(7, st[:579] + bytes([st[579] | 1]) + st[580:], "salt")
        for mm in (0, 3, 5, 16, 2**64 + 1):
            bad(7, st[:320] + w(mm) + st[352:], "M word")
        a = int.from_bytes(st[448:480], "big")
        for v in (2, 2**64 + a):
            bad(7, st[:448] + w(v) + st[480:], "auditorOn")
        bad(7, st[:448] + w(1 - a) + st[480:], "auditorOn flipped")
        m = int.from_bytes(st[320:352], "big")
        other = [x for x in (1, 2, 4) if x != m][0]
        bad(7, st[:320] + w(other) + st[352:], "another built M")
    t1 = next(st for form, st in valid if form == "TRANSFER")
    bad(7, t1, "op 1 statement under op 7")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"xcheck.py: {len(C_FORMS)} C statements rebuilt by pqz_kat.py, {len(valid)} random statements, "
          f"{len(multi)} op 7 statements, "
          f"{sum(1 for l in lines if l.startswith('bad'))} rejections -> {os.path.basename(out_path)}")


if __name__ == "__main__":
    main(sys.argv)
