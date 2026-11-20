# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The keystore and vault rows of smartcontracts/vectors/keystore/keystore.json as tab-separated lines, for the UniFFI bindings'
# smoke tests in languages without a JSON parser of their own (C++, Java, Kotlin; plan T20b-T20h). Text fields are hex (UTF-8):
#   pass     <passphrase>
#   valid    <row id> <container text> <seed count>      then one `seed` line per seed, in order:
#   seed     <id> <label> <words> <backup> <account ids, comma-separated, possibly empty>
#   refused  <row id> <error code> <container text>
# Usage: python3 -I rows.py <keystore.json> <out.tsv>
import json
import sys


def h(s):
    return s.encode().hex()


def main(src, out):
    with open(src, encoding="utf-8") as f:
        d = json.load(f)
    lines = [f"pass\t{h(d['passphrase'])}"]
    for r in d["valid"]:
        seeds = json.loads(r["text"])["seeds"]
        lines.append(f"valid\t{h(r['id'])}\t{h(r['text'])}\t{len(seeds)}")
        for s in seeds:
            accounts = ",".join(a["id"] for a in s["accounts"])
            lines.append(f"seed\t{s['id']}\t{h(s['label'])}\t{s['words']}\t{s['backup']}\t{accounts}")
    for r in d["refused"]:
        lines.append(f"refused\t{h(r['id'])}\t{r['error']}\t{h(r['text'])}")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
