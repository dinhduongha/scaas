"""Fuzz inputs from the frozen vectors (smartcontracts/vectors/pqz/, P6e D9), rebuilt at run time by run.sh (light):

    python3 -I pqz-core/fuzz/seeds.py <out dir>

<out>/honest.bin: the honest precompile inputs as be32(len) || input records: proof_pqzl.json's 8 forms (pqz-stmt
FORMS order), proof_pqzh.json's 8, then fee0.json's 4 forms under PQZL and PQZH (24; src/lib.rs relies on the first
16 being PQZL then PQZH in FORMS order). <out>/seeds/precompile/: those inputs, the self-test input and every row
of negative.json (input rebuilt by pqz_kat.py's apply_edits); seeds/mutate/, seeds/codec/: one empty edit script per
honest input and mode / codec and selector.
"""
import os
import shutil
import sys

V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../smartcontracts/vectors/pqz")
sys.path.insert(0, V)
import pqz_kat as k  # noqa: E402

out = sys.argv[1]
stmts = {f: bytes.fromhex(r["stmt"]) for f, r in k.statement_rows(V).items()}
proofs = {(r["form"], n): bytes.fromhex(r["proof"]) for n in k.IDS for r in k.load(V, f"proof_{n}.json")["rows"]}
honest = [k.precompile_input(r["op"], k.with_id(stmts[r["form"]], k.IDS[n]), proofs[r["form"], n])
          for n in ("pqzl", "pqzh") for r in k.load(V, f"proof_{n}.json")["rows"]]
honest += [k.precompile_input(r["op"], k.with_id(bytes.fromhex(r["stmt"]), k.IDS[n]), bytes.fromhex(r[n]["proof"]))
           for n in ("pqzl", "pqzh") for r in k.load(V, "fee0.json")["rows"]]
with open(os.path.join(out, "honest.bin"), "wb") as f:
    for b in honest:
        f.write(len(b).to_bytes(4, "big") + b)
shutil.rmtree(os.path.join(out, "seeds"), ignore_errors=True)  # stale seeds could hold valid proofs the oracle does not know
neg = [k.apply_edits(r, stmts, proofs) for r in k.load(V, "negative.json")["rows"]]
d = os.path.join(out, "seeds", "precompile")
os.makedirs(d, exist_ok=True)
for i, b in enumerate(honest + [bytes([6, 0, 0, 0, 0])] + neg):
    with open(os.path.join(d, f"vec-{i:03}"), "wb") as f:
        f.write(b)
for t, seeds in (("mutate", [bytes([c, m]) for c in range(len(honest)) for m in range(4)]),
                 ("codec", [bytes([c, x]) for c in range(5) for x in range(16)])):
    os.makedirs(os.path.join(out, "seeds", t), exist_ok=True)
    for i, b in enumerate(seeds):
        with open(os.path.join(out, "seeds", t, f"seed-{i:03}"), "wb") as f:
            f.write(b)
print(f"seeds.py: {len(honest)} honest inputs -> honest.bin; {len(honest) + 1 + len(neg)} precompile seeds "
      f"({len(neg)} negative.json rows)")
