# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""P6h (3) mutants, clientkeys side (CLI-SGN-55: sealPqKey / openPqKey in src/pq.js), each killed by test/pqz-leaf.test.js:
python3 runs/2026-11-22-p6h-sealpq-js-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/clientkeys/src/pq.js"
T = "cd clients/clientkeys && node --test test/pqz-leaf.test.js"
MUTANTS = [
    ("the label check skipped", [(P, "    if (vault?.label !== pqzLeafLabel({ account, index, version })) throw new Error();", "")], T, "another account"),
    ("the 32-byte check skipped", [(P, "    if (leaf.length !== 32) throw new Error();", "")], T, "31-byte payload"),
    ("the label names no key version", [(P, "`pqz:registry:${account}:${index}:${BigInt(version)}`", "`pqz:registry:${account}:${index}`")], T, "pqzLeafLabel"),
    ("refusals keep their own class", [(P, "  } catch {\n    wipe(leaf);", "  } catch (e) {\n    if (e?.code) throw e;\n    wipe(leaf);")], T, "VaultOpen"),
    ("sealPqKey seals version 0 always", [(P, "  const leaf = pqzKeySeed(seed, account, index, version);", "  const leaf = pqzKeySeed(seed, account, index);")], T, "gives the 32 bytes back"),
    ("sealPqKey drops the seed vault's id", [(P, "pin, prf, id });", "pin, prf });")], T, "gives the 32 bytes back"),
    ("sealPqKey takes an index past 2^31", [(P, '  hardened(index, "index");\n', "")], T, "hardened range"),
]

if __name__ == "__main__":
    main("js", MUTANTS, prefix="2026-11-22-p6h-sealpq")
