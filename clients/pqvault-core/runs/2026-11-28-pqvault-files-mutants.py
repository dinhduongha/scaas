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
V = "clients/pqvault-core/src/vault.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
CD = "cd clients/pqvault-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
DEV = CD + "--test devices a_file_item_is_signed_only_after_its_object_was_read"
VEC = CD + "--features vectors --test vectors "
E2E = ('cd clients/pqvault-core && PATH="$HOME/.foundry/bin:$PATH" CARGO_INCREMENTAL=0 ../../scripts/capped cargo test '
       "--locked --offline -j2 --test e2e -- --ignored --exact file_item_on_arweave")
SDK = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
       "--features app-core,arweave --test arweave ")

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
        [(F, '        if value.ty != "file" {\n            return Ok(value.clone());', '        if value.ty != "none" {\n            return Ok(value.clone());')],
        DEV,
    ),
    (
        "a file opened under version 1's kFile",
        [(F, "            version.version,\n            version.author,", "            1,\n            version.author,")],
        DEV,
    ),
    # review fixes
    (
        "create_item writes a file item (E-1)",
        [(V, '        if value.ty == "file" {\n            return Err(Error::Shape);\n        }\n        let nonce', "        let nonce")],
        DEV,
    ),
    (
        "an edit names another object (E-2)",
        [(F, "        if FIXED.iter().any(|k| was.plain(k) != value.plain(k)) {", "        if false {")],
        DEV,
    ),
    (
        "an edit after a rekey sealed under the base's epoch (F-4)",
        [(F, "        let new = v.at(epoch, base.item_id, version, v.state.me);\n        let kv_new = v.keys.get(&epoch)",
          "        let new = v.at(base.epoch_id, base.item_id, version, v.state.me);\n        let kv_new = v.keys.get(&base.epoch_id)")],
        E2E,
    ),
    (
        "resolve re-seals from the latest version always (E-3)",
        [(V, '                    merged.ty == "file" && i.ty == "file" && wrap(i) == wrap(merged)', "                    false")],
        E2E,
    ),
    (
        "file_info names an https url (E-7)",
        [(F, "    let url = s(\"url\").filter(|u| crate::content::ar_url_ok(u))?;", "    let url = s(\"url\")?;")],
        VEC + "item_versions_and_refusals",
    ),
    (
        "any url accepted",
        [(C, "                && url_ok\n", "                && (url_ok || true)\n")],
        VEC + "a_file_items_bounds",
    ),
    (
        "an ar:// id of any length",
        [(C, "        id.len() == 43\n", "        id.len() >= 42\n")],
        VEC + "a_file_items_bounds",
    ),
    (
        "a non-canonical ar:// id (F-6)",
        [(C, '            && id.bytes().last().is_some_and(|b| b"AEIMQUYcgkosw048".contains(&b))\n', "")],
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
    (
        "a file above what open_file returns is sealed (F-1)",
        [(AC, "    if file.len() > scaas_ua::wallet::SECRET_MAX {", "    if file.len() > scaas_ua::wallet::SECRET_MAX * 2 {")],
        SDK + "a_file_above_what_open_file_returns_is_refused",
    ),
]

if __name__ == "__main__":
    L.main("files-r2", MUTANTS)
