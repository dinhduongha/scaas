#!/usr/bin/env python3
"""Replay smartcontracts/vectors/pqz/proof_pqzh.json through the crate (plan 5h Task 8c, v3 byte identity): for every
row, prove the row's statement (its statement file's PQZL-id bytes with bytes 32..63 set to the PQZH id) and witness
with its rnd32, compare keccak(proof) with the row's proof_keccak, and verify the stored proof. Stdlib only.

  python3 -I pqz-core/pqzh/ligero/runs/replay_vectors.py <ligero_kat binary> > runs/<tag>-replay.txt
"""
import json
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..")
VEC = os.path.join(ROOT, "smartcontracts", "vectors", "pqz")


def main():
    binary = sys.argv[1]
    d = json.load(open(os.path.join(VEC, "proof_pqzh.json")))
    psid = bytes.fromhex(d["proof_system_id"])
    cache, lines = {}, []
    for r in d["rows"]:
        ref = r["statement"]
        if ref["file"] not in cache:
            cache[ref["file"]] = json.load(open(os.path.join(VEC, ref["file"])))["rows"]
        key = "case" if "case" in ref else "form"
        st = next(x for x in cache[ref["file"]] if x.get(key) == ref[key] and (key == "case" or "case" not in x))
        stmt = bytearray.fromhex(st["stmt"])
        stmt[32:64] = psid
        lines.append(f"{r['op']} {stmt.hex()} {r['wit']} {r['rnd32']} {r['proof']}")
    out = subprocess.run([binary, "replay"], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    got = [json.loads(x) for x in out.stdout.splitlines()]
    bad = 0
    for r, g in zip(d["rows"], got, strict=True):
        ok = g["keccak"] == r["proof_keccak"] and g["proof_bytes"] == r["proof_bytes"] and g["verify_stored"]
        bad += not ok
        print(f"{r['form']:<18} {r.get('case', ''):<16} bytes {g['proof_bytes']:>7} keccak {'same' if ok else 'DIFF'} "
              f"verify_stored {g['verify_stored']}")
    print(f"rows {len(got)}, byte-identical and stored proof verified: {len(got) - bad}, failures: {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
