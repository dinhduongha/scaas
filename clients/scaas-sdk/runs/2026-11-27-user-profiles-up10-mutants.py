# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP10 mutants: settings, export and import at the store's crate clients/scaas-profile (spec §7.7, §10.1):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up10-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

S = "clients/scaas-profile/src/settings.rs"
X = "clients/scaas-profile/src/export.rs"
P = "clients/scaas-profile/src/profile.rs"


def t(binary, name):
    return ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
            f"--features test-hooks --test {binary} -- --exact {name}")


MUTANTS = [
    ("the passphrase check of set_settings removed",
     [(S, "        if self.core.protected() && weakens(&old, s) {\n",
       "        if self.core.protected() && false {\n")],
     t("settings", "set_settings_needs_the_passphrase_to_weaken")),
    # a chunk that does not verify is skipped and the payload parsed: the label is refused before the tag
    ("parse before verify",
     [(X, "            .open_chunk(&prefix, k, i + 1 == n, header, c)\n            .map_err(|_| no(\"tag\"))?;\n",
       "            .open_chunk(&prefix, k, i + 1 == n, header, c)\n            .unwrap_or_default();\n")],
     t("export", "hooks::verify_before_parse")),
    ("settings imported whole",
     [(X, "        let settings = settings::filter(&review.settings, confirmed).json()?;\n",
       "        let settings = review.settings.json()?;\n")],
     t("export", "hooks::preview_then_import")),
    ("a filter that forgets credential references",
     [(S, "        credentials: Vec::new(),\n",
       "        credentials: s.credentials.clone(),\n")],
     t("settings", "import_filter")),
    ("start removing a temporary directory whose build.lock is held",
     [(P, "                if try_lock_file(&path.join(BUILD_LOCK))?.is_some() {\n",
       "                if try_lock_file(&path.join(BUILD_LOCK))?.is_some() || true {\n")],
     t("export", "hooks::import_temporary_directory")),
    ("a preview written to disk in plain form",
     [(X, "        let pl = open_file(&self.heavy, self.kdf_max_kib, file, pass)?;\n        parse_payload(&pl)\n",
       "        let pl = open_file(&self.heavy, self.kdf_max_kib, file, pass)?;\n"
       "        let _ = std::fs::write(self.p.join(\".preview\"), &pl[..]);\n        parse_payload(&pl)\n")],
     t("export", "hooks::preview_then_import")),
]

if __name__ == "__main__":
    mutants_lib.main("up10", MUTANTS)
