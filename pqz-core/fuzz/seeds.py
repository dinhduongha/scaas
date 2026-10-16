"""Fuzz inputs from the frozen vectors (smartcontracts/vectors/pqz/, P6e D9, P6-ANON S4), rebuilt at run time by run.sh
(light):

    python3 -I pqz-core/fuzz/seeds.py <out dir>

<out>/honest.bin: the honest precompile inputs as be32(len) || input records: proof_pqzl.json's 8 forms (pqz-stmt
FORMS order), proof_pqzh.json's 8, fee0.json's 4 forms under PQZL and PQZH (the first 24, P6e; src/lib.rs relies on
the first 16 being PQZL then PQZH in FORMS order), then the op 7 R_TXM rows (P6-ANON S5): proof_pqzl.json's 11 and
proof_pqzh.json's 8 (every built (id, M, auditorOn), statements from statement_transfer_multi.json), then the files of
regress/valid/ (valid inputs from outside the vectors, see README.md). <out>/seeds/precompile/: those inputs, the
self-test input and every row of negative.json (input rebuilt by pqz_kat.py's apply_edits); seeds/mutate/,
seeds/codec/: one empty edit script per honest input and mode / codec and selector.
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V = os.path.join(HERE, "../../smartcontracts/vectors/pqz")
sys.path.insert(0, V)
import pqz_kat as k  # noqa: E402

out = sys.argv[1]
stmts = {f: bytes.fromhex(r["stmt"]) for f, r in k.statement_rows(V).items()}
stmts |= {c: bytes.fromhex(r["stmt"]) for c, r in k.multi_rows(V).items()}  # op 7: keyed by case
rows = {n: k.load(V, f"proof_{n}.json")["rows"] for n in k.IDS}
proofs = {(r.get("case", r["form"]), n): bytes.fromhex(r["proof"]) for n in k.IDS for r in rows[n]}


def inputs(n, multi):
    return [k.precompile_input(r["op"], k.with_id(stmts[r.get("case", r["form"])], k.IDS[n]), proofs[r.get("case", r["form"]), n])
            for r in rows[n] if (r["op"] == 7) == multi]


honest = inputs("pqzl", False) + inputs("pqzh", False)
honest += [k.precompile_input(r["op"], k.with_id(bytes.fromhex(r["stmt"]), k.IDS[n]), bytes.fromhex(r[n]["proof"]))
           for n in ("pqzl", "pqzh") for r in k.load(V, "fee0.json")["rows"]]
n_p6e = len(honest)
honest += inputs("pqzl", True) + inputs("pqzh", True)
n_multi = len(honest) - n_p6e
rv = os.path.join(HERE, "regress", "valid")
extra = [open(os.path.join(rv, f), "rb").read() for f in sorted(os.listdir(rv))] if os.path.isdir(rv) else []
honest += extra
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
# codec: byte 0 = codec + 5 x (honest index >> 4), byte 1 bits 0..3 = honest index & 15 (src/lib.rs pqz_fuzz_codec)
for t, seeds in (("mutate", [bytes([c, m]) for c in range(len(honest)) for m in range(4)]),
                 ("codec", [bytes([x + 5 * (c >> 4), c & 15]) for x in range(5) for c in range(len(honest))])):
    os.makedirs(os.path.join(out, "seeds", t), exist_ok=True)
    for i, b in enumerate(seeds):
        with open(os.path.join(out, "seeds", t, f"seed-{i:03}"), "wb") as f:
            f.write(b)
print(f"seeds.py: {len(honest)} honest inputs -> honest.bin ({n_p6e} P6e, {n_multi} op 7, {len(extra)} regress/valid); "
      f"{len(honest) + 1 + len(neg)} precompile seeds ({len(neg)} negative.json rows, "
      f"{sum(r['form'] == 'TRANSFER-MULTI' for r in k.load(V, 'negative.json')['rows'])} of them op 7)")
