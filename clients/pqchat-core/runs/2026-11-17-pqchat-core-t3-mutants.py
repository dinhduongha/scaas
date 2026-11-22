# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T3's mutants (the vectors through the SDK): python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t3-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

M = "clients/pqchat-core/src/matrix.rs"
O = "clients/pqchat-core/src/order.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --features vectors --test vectors "
NP = "base64::engine::general_purpose::STANDARD_NO_PAD"
MUTANTS = [
    ("the Matrix event written unpadded",
     [(M, 'json!({ "v": 1, "hint": STANDARD.encode(hint), "env": STANDARD.encode(env) })',
       f'json!({{ "v": 1, "hint": {NP}.encode(hint), "env": {NP}.encode(env) }})')],
     T + "matrix_event_row"),
    ("the parents passed unsorted to S5",
     [(O, "    v.sort();\n", "")], T + "parents_sorted_into_s5"),
]

if __name__ == "__main__":
    main("t3", MUTANTS)
