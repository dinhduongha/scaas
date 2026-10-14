#!/usr/bin/env python3
"""PQZH statements vs pqz_kat.py (P6e Task 9): every statement dumped by ligero.sh (the Ligero crate's, equal to the
patched pqz_bench.c ones) must parse under pqz_kat.py's D15 / R6 rules with PQZH's proofSystemId only (D3), fail to
parse as PQZL's, and be rebuilt byte for byte by pqz_kat.py's builders from the parsed fields.
  python3 -I kat_stmt.py DIR      (DIR holds <rel>_stmt.bin); exit 1 on any difference
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../smartcontracts/vectors/pqz"))
import pqz_kat as K  # noqa: E402


def rebuild(d):
    op = d["op"]
    if op == "REGISTER":
        return K.build_register(d["message"], d["pk"], psid=K.PQZH_ID)
    if op.startswith("DISCLOSE"):
        f = {k: int.from_bytes(d[k], "big") for k in K.DISC if k not in ("opTag", "proofSystemId")}
        return K.build_disclose(op, dict(f, proofSystemId=K.PQZH_ID), d["pk"], d["u"], d["v"])
    f = {k: int.from_bytes(d[k], "big") for k in K.HEADER if k not in ("opTag", "proofSystemId")}  # auditorOn: build_debit sets it for TRANSFER (R6)
    f["proofSystemId"] = K.PQZH_ID
    if op == "TRANSFER":
        out = d["u"] + d["v_t"] + d["v_f"] + d.get("v_a", b"")
        return K.build_debit(op, f, d["pk_f"], d["T"], out, d["pk_t"], d.get("pk_a"))
    return K.build_debit(op, f, d["pk_f"], d["T"], d["u"] + d["v_f"])


def main(dirname):
    bad = 0
    for rel, op in (("reg", 3), ("tx", 1), ("burn", 2), ("ds", 4), ("dr", 5), ("tx0", 1)):
        st = open(os.path.join(dirname, rel + "_stmt.bin"), "rb").read()
        d = K.parse(op, st, ids=(K.PQZH_ID,))
        try:
            K.parse(op, st, ids=(K.PQZL_ID,))
            pqzl = "PARSED"
        except ValueError:
            pqzl = "rejected"
        same = rebuild(d) == st
        ok = same and pqzl == "rejected" and st[32:64] == K.PQZH_ID
        bad += not ok
        print(f"{rel}_stmt {len(st)} B {d['op']} id={st[32:64].hex()[:8]} as-PQZL={pqzl} "
              f"rebuilt={'equal' if same else 'DIFFERENT'} {'ok' if ok else 'FAIL'}")
    print("kat_stmt:", "FAIL" if bad else "ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
