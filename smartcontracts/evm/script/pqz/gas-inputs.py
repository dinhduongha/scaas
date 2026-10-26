#!/usr/bin/env python3
"""Plan 5h Task 8d part 2b: the inputs of the gas table (`PqzStatePinGasTest.test_gasTable_*`) per parameter set, written
to `test/vectors/pqz-gas/<set>.json` (forge cannot read the multi-MB vector files under its memory gas):

  per proof system and form: `proof` = the bytes the table sends (PQZL: the set's vector proof, the larger of the form's
  rows; PQZH: the crate's proof bound `max_proof_len`, the worst case a client can be handed, with the vector proof as
  `honest`), `input` = the precompile input 5 + statement + proof, and `row` = the provisional testnet price of that
  (op, id, stmtLen[, legs, auditorOn]) in `pqz-core/nethermind/chain/engine-pqz-provisional-<n>.json` (Task 9 replaces
  them; the precompile charges row + 3 * ceil(input / 32), CTR-PQZ-11).

  python3 -I smartcontracts/evm/script/pqz/gas-inputs.py [--check]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
SETS = os.path.join(REPO, "pqz-core", "params", "sets")
OUT = os.path.join(REPO, "smartcontracts", "evm", "test", "vectors", "pqz-gas")
OP = {"TRANSFER": 1, "TRANSFER0": 1, "BURN": 2, "REFRESH": 2, "REGISTER": 3, "DISCLOSE-SENDER": 4,
      "DISCLOSE-RECEIVER": 5, "DISCLOSE-AUDITOR": 5}


def table(name):
    sj = json.load(open(os.path.join(SETS, name, "set.json")))
    vec = os.path.join(REPO, "smartcontracts", "vectors", "pqz", "" if name == "n2048-kmax1024" else name)
    eng = json.load(open(os.path.join(REPO, "pqz-core", "nethermind", "chain",
                                      f"engine-pqz-provisional-{name.split('-')[0]}.json")))["schedules"][-1]["pqz"]
    out = {"set": name, "source": "smartcontracts/evm/script/pqz/gas-inputs.py: the set's vectors (proof_pqz*.json), "
           f"chain/engine-pqz-provisional-{name.split('-')[0]}.json (provisional rows, testnet only until Task 9)"}
    for sys_ in ("pqzl", "pqzh") if sj["pqzh"] else ("pqzl",):
        pid = "0x" + sj[f"{sys_}_id"]
        rows = {}
        for r in json.load(open(os.path.join(vec, f"proof_{sys_}.json")))["rows"]:
            st = r["statement"]
            if "disclosure" in st:  # op 7 legs' disclosures: the same op 5 statement and row as the op 1 one
                continue
            key = st["case"].replace("-boundary", "") if r["op"] == 7 else r["form"]
            if key in ("M2-off-two-real", "M4-off-decoys"):
                continue
            if r["op"] == 7:
                m, aud = int(key[1]), key.endswith("-on")
                e = [x for x in eng if x["op"] == 7 and x["id"] == pid and x["legs"] == m and x["auditorOn"] == aud]
            else:
                stmt = sj["lengths"]["stmt"][r["form"]]
                e = [x for x in eng if x["op"] == OP[key] and x["id"] == pid and x["stmtLen"] == stmt]
            assert len(e) == 1, f"{name} {sys_} {key}: {len(e)} schedule rows"
            proof = r["max_proof_len"] if sys_ == "pqzh" else r["proof_bytes"]
            row = {"proof": proof, "input": 5 + e[0]["stmtLen"] + proof, "row": e[0]["gas"]}
            if sys_ == "pqzh":
                row["honest"] = r["proof_bytes"]
            if key not in rows or rows[key]["proof"] < proof:
                rows[key] = row
        out[sys_] = rows
    return json.dumps(out, indent=1, sort_keys=True) + "\n"


def main(argv):
    names = sorted(d for d in os.listdir(SETS) if os.path.exists(os.path.join(SETS, d, "set.json")))
    os.makedirs(OUT, exist_ok=True)
    bad = 0
    for n in names:
        p, t = os.path.join(OUT, f"{n}.json"), table(n)
        if "--check" in argv:
            if not os.path.exists(p) or open(p).read() != t:
                print(f"gas-inputs.py --check: {p} differs")
                bad = 1
        else:
            open(p, "w").write(t)
    print(f"gas-inputs.py{' --check' if '--check' in argv else ''}: {len(names)} sets")
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
