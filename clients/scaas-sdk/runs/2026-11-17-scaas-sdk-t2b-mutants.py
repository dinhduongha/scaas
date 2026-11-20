# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T2b mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t2b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

K = "clients/clientkeys/src/keystore.js"
T = "cd clients/clientkeys && ../../scripts/capped node --test test/keystore.test.js"
MUTANTS = [
    ("drop the duplicate-label check", [(K, "for (const k of [\"id\", \"label\"])", "for (const k of [\"id\"])")], T),
    ("accept words: 13", [(K, "const WORDS = [12, 15, 18, 21, 24];", "const WORDS = [12, 13, 15, 18, 21, 24];")], T),
    ("skip the inner-label comparison", [(K, "if (!isObj(inner) || inner.label !== k)", "if (!isObj(inner))")], T),
    ("accept a missing indexMac", [(K, "  \"indexMac\",\n", "  \"indexMac?\",\n"),
                                   (K, "if (!isStr(s.indexMac) || !/^[0-9a-f]{64}$/.test(s.indexMac))",
                                    "if (Object.hasOwn(s, 'indexMac') && (!isStr(s.indexMac) || !/^[0-9a-f]{64}$/.test(s.indexMac)))")], T),
]

if __name__ == "__main__":
    main("t2b", MUTANTS)
