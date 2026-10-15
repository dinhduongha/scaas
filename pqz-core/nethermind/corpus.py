#!/usr/bin/env python3
"""P6f: one flat corpus of PQZ precompile inputs from smartcontracts/vectors/pqz (P6e Task 11), for every consumer
(the C# tests, the harness, the calibration, probe.sh, e2e.py). Run with python3 -I.

    corpus.py <out.jsonl>

One JSON object per line: kind (honest | flip | negative | fee0 | selftest), name, id (pqzl | pqzh | -), form, op,
stmt_len, input (hex), expect ("1", "0", "revert", or the 32-byte self-test hash in hex). The honest inputs are the
proof_<id>.json rows; flip = the honest input with negative.json's "proof middle byte bit 3 flipped" edit (decodes,
fails in the verifier); negative = every negative.json row through pqz_kat.apply_edits; fee0 = fee0.json's statements
under each id; selftest = selftest.json's input and hash. Nothing here is computed afresh: the edits and expectations
are the vectors' own."""
import json
import os
import sys

VEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../smartcontracts/vectors/pqz")
sys.path.insert(0, VEC)
import pqz_kat as K  # noqa: E402  (the vectors' own checker: apply_edits, statement_rows, with_id, IDS)


def main(out):
    stmts = {f: bytes.fromhex(r["stmt"]) for f, r in K.statement_rows(VEC).items()}
    proofs = {(r["form"], n): bytes.fromhex(r["proof"]) for n in K.IDS for r in K.load(VEC, f"proof_{n}.json")["rows"]}
    neg = K.load(VEC, "negative.json")["rows"]
    rows = []

    def add(kind, name, idn, form, inp, expect):
        rows.append({"kind": kind, "name": name, "id": idn, "form": form, "op": inp[0] if inp else -1,
                     "stmt_len": int.from_bytes(inp[1:5], "big") if len(inp) >= 5 else -1,
                     "input": inp.hex(), "expect": expect})

    for (form, idn), p in sorted(proofs.items()):
        op = K.OP_BYTE[form.rstrip("0")]
        add("honest", f"{form} {idn}", idn, form, K.precompile_input(op, K.with_id(stmts[form], K.IDS[idn]), p), "1")
    for r in neg:
        e = {"0": "0", "revert": "revert"}[r["expect"]]
        kind = "flip" if r["name"].endswith("proof middle byte bit 3 flipped") else "negative"
        add(kind, r["name"], r["id"], r["form"], K.apply_edits(r, stmts, proofs), e)
    for r in K.load(VEC, "fee0.json")["rows"]:
        s = bytes.fromhex(r["stmt"])
        for idn in K.IDS:
            p = bytes.fromhex(r[idn]["proof"])
            op = int(r["op"])
            add("fee0", f"fee0 {r['form']} {idn}", idn, r["form"], K.precompile_input(op, K.with_id(s, K.IDS[idn]), p), "1")
    st = K.load(VEC, "selftest.json")
    add("selftest", "OP_SELFTEST", "-", "SELFTEST", bytes.fromhex(st["input"]), st["hash"])
    with open(out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    kinds = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"corpus {out}: {len(rows)} inputs {kinds}")


if __name__ == "__main__":
    main(sys.argv[1])
