# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T2's mutants (the storage interface, the errors): python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t2-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

S = "clients/pqchat-core/src/store.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 "
MUTANTS = [
    ("drop the revision check",
     [(S, "        if revision != expected {\n            return Ok(false);\n        }\n", "")],
     T + "--test store revisions_per_item"),
    ("one revision for all items",
     [(S, "        let revision = items.get(key).map_or(0, |i| i.revision);",
       "        let revision = items.values().map(|i| i.revision).max().unwrap_or(0);")],
     T + "--test store revisions_per_item"),
    ("let an error carry its input",
     [(S, "        match self.0.load(key).map_err(io)? {",
       "        match self.0.load(key).map_err(|e| {\n            tracing::debug!(item = key, \"load\");\n            io(e)\n        })? {")],
     T + "--test errors no_error_or_log_line_holds_an_input"),
]

if __name__ == "__main__":
    main("t2", MUTANTS)
