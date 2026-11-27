# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP9 mutants: delete, start and the migration at the store's crate clients/scaas-profile (spec §10, §12):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up9-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

P = "clients/scaas-profile/src/profile.rs"
M = "clients/scaas-profile/src/migrate.rs"
L = "clients/scaas-profile/src/lifecycle.rs"
T = ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features test-hooks --test lifecycle -- --exact ")
MUTANTS = [
    ("the clean-up removing a directory without an envelope",
     [(P, "        for (_, env) in &scan {\n"
          "            if env.is_none() {\n"
          "                self.event(ProfileEvent::ProfileDamaged);\n"
          "            }\n",
       "        for (id, env) in &scan {\n"
       "            if env.is_none() {\n"
       "                self.event(ProfileEvent::ProfileDamaged);\n"
       "                remove_dir(&self.p.join(id))?;\n"
       "            }\n")],
     T + "damaged_directory_reported_never_removed"),
    # the migration after the root lock's release: a start beside it runs its first run and makes a second "default"
    ("no root lock at migration",
     [(P, "            let _root = pr.root_lock()?;\n"
          "            let first_run = pr.start()?;\n",
       "            let first_run = {\n"
       "                let _root = pr.root_lock()?;\n"
       "                pr.start()?\n"
       "            };\n")],
     T + "hooks::concurrent_starts_make_one_default"),
    ("migration ignoring migration: pending on resume",
     [(M, "            e.filter(|e| e.state == State::Unprotected && e.migration.is_some())\n",
       "            e.filter(|e| e.state == State::Unprotected)\n")],
     T + "legacy_beside_profiles_reported"),
    ("delete without the name check",
     [(L, "        confirm(&info.name, confirm_name)?;\n        let instance = open.release()",
       "        let _ = confirm(&info.name, confirm_name);\n        let instance = open.release()")],
     T + "delete_open_profile"),
]

if __name__ == "__main__":
    mutants_lib.main("up9", MUTANTS)
