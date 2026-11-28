# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""CLI-PQV-19 / CLI-PQV-20 in pqvault-core (branch pqvault-files): a mutant of each new check of PqVault's `file` items on
Arweave, the scaas-sdk plan's `mutants_lib` with this crate's record: python3
clients/pqvault-core/runs/2026-11-28-pqvault-files-mutants.py check | run [name...]. Each test command goes through
scripts/capped, foreground (mutant_guard's deadline and restore)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/pqvault-core/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-28-pqvault-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-22-pqvault-core-summary.txt"]

F = "clients/pqvault-core/src/file.rs"
K = "clients/pqvault-core/src/keys.rs"
C = "clients/pqvault-core/src/content.rs"
CD = "cd clients/pqvault-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
DEV = CD + "--test devices a_file_item_is_signed_only_after_its_object_was_read"
VEC = CD + "--features vectors --test vectors "

MUTANTS = [
    (
        "confirm_file signs without the read",
        [(F, "        if !p.read {\n            return Err(Error::FileNotRead);\n        }\n", "")],
        DEV,
    ),
    (
        "a failed read counts as read",
        [(F, "        files.fetch_file(&u.url, u.size, u.ct_sha256).await?;",
          "        let _ = files.fetch_file(&u.url, u.size, u.ct_sha256).await;")],
        DEV,
    ),
    (
        "the file key opened as a Data key",
        [(K, "    core.open_key(kf, wire.to_vec(), U::File, x.ctx())",
          "    core.open_key(kf, wire.to_vec(), U::Data, x.ctx())")],
        DEV,
    ),
    (
        "an edit keeps the base version's wrap",
        [(F, "        let Some(wire) = (value.ty == \"file\")", "        let Some(wire) = (value.ty == \"none\")")],
        DEV,
    ),
    (
        "a file read under the author's epoch at version 1",
        [(F, "            version.version,\n            version.author,", "            1,\n            version.author,")],
        DEV,
    ),
    (
        "any url accepted",
        [(C, "                && url_ok\n", "                && (url_ok || true)\n")],
        VEC + "a_file_items_bounds",
    ),
    (
        "an ar:// id of any length",
        [(C, "                    id.len() == 43\n", "                    id.len() >= 42\n")],
        VEC + "a_file_items_bounds",
    ),
    (
        "ctSha256 of any length",
        [(C, '                && hex_of("ctSha256", 32)\n', "")],
        VEC + "a_file_items_bounds",
    ),
    (
        "keyWrap of any length",
        [(C, '                && hex_of("keyWrap", 60)\n', "")],
        VEC + "a_file_items_bounds",
    ),
    (
        "a size 0",
        [(C, "(1..=SAFE).contains(&n))\n                && hex_of", "(0..=SAFE).contains(&n))\n                && hex_of")],
        VEC + "a_file_items_bounds",
    ),
]

if __name__ == "__main__":
    L.main("files", MUTANTS)
