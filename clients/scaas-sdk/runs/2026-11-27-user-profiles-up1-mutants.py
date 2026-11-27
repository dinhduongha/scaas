# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP1 mutants (clientkeys src/profile.js): python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up1-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [":!clients/scaas-sdk/runs/*-mutants.txt", ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt"]

P = "clients/clientkeys/src/profile.js"
CK = "cd clients/clientkeys && ../../scripts/capped node --test test/profile.test.js"
MUTANTS = [
    ("the HMAC file name over the item name only (no part)",
     [(P, "kName, concatBytes(lp(part), lp(name))))", "kName, lp(name)))")], CK),
    ("the last-chunk flag ignored at import (either flag accepted)",
     [(P, "      out.push(openChunk(kx, header, prefix, i, i === n - 1, body.subarray(i * step, (i + 1) * step)));\n",
       "      const c = body.subarray(i * step, (i + 1) * step);\n"
       "      try {\n        out.push(openChunk(kx, header, prefix, i, true, c));\n"
       "      } catch {\n        out.push(openChunk(kx, header, prefix, i, false, c));\n      }\n")], CK),
    ("rev left out of the item AD",
     [(P, "lp(part), lp(name), be(rev, 8));", "lp(part), lp(name));")], CK),
    ("name inside the wrap's public JSON",
     [(P, "state: e.state, gen: e.gen, kdf: kdfJson(e.kdf) });", "state: e.state, gen: e.gen, name: e.name, kdf: kdfJson(e.kdf) });")], CK),
    ("anchorCompare: any difference is rollback (ahead not followed)",
     [(P, 'if (s.rev > a.rev) return "follow";', 'if (s.rev > a.rev) return "rollback";'),
      (P, '    stored.gen > anchor.gen ? "follow"', '    stored.gen > anchor.gen ? "rollback"'),
      (P, '      .map(() => "follow"),', '      .map(() => "rollback"),')], CK),
]

if __name__ == "__main__":
    mutants_lib.main("up1", MUTANTS)
