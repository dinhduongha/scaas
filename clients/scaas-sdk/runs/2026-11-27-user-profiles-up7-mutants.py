# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP7 mutants: the re-seal and its open-time rules at the store's crate clients/scaas-profile (spec §7.3):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up7-mutants.py check | run [name]"""
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
R = "clients/scaas-profile/src/reseal.rs"
S = "clients/scaas-profile/src/store.rs"
T = ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features test-hooks --test reseal -- --exact ")
MUTANTS = [
    ("the journal ignored at open",
     [(P, "        if std::fs::symlink_metadata(dir.join(reseal::NEXT)).is_ok() {\n",
       "        if false && std::fs::symlink_metadata(dir.join(reseal::NEXT)).is_ok() {\n")],
     T + "g4_crash_at_each_step"),
    ("the envelope renamed before the generation is complete",
     [(R, "            file::write(&dir, &dir.join(NEXT), &bytes)?;\n",
       "            file::write(&dir, &dir.join(NEXT), &bytes)?;\n"
       "            std::fs::rename(dir.join(NEXT), dir.join(envelope::FILE)).map_err(|_| Error::VaultIo)?;\n")],
     T + "g4_crash_at_each_step"),
    # a higher generation taken as one to remove once the wrap opens: only the open without the anchor gets that far
    ("removing every generation other than gen",
     [(P, "                Some(k) if k > gen => higher = true,\n",
       "                Some(k) if k > gen => lower.push(e.path()),\n")],
     T + "generations_older_envelope_kept"),
    ("removing a lower generation before the wrap opens",
     [(P, "        let lower = self.generations(&dir, id, env.gen)?;\n",
       "        let lower = self.generations(&dir, id, env.gen)?;\n"
       "        for g in &lower {\n            remove_dir(g)?;\n        }\n")],
     T + "generations_older_envelope_kept"),
    # the current arena reused as the new generation's (so not wiped at the commit): the old envelope opens what follows
    ("DEK_p kept at a passphrase change",
     [(R, "        let keys = Arc::new(ProfileKeys::new());\n        keys.create_dek().map_err(kdf_code)?;\n",
       "        let keys = match core.keys() {\n            Some(k) => k,\n            None => {\n"
       "                let k = Arc::new(ProfileKeys::new());\n                k.create_dek().map_err(kdf_code)?;\n"
       "                k\n            }\n        };\n"),
      (S, "        if let Some(k) = old.keys {\n            k.lock();\n        }\n",
       "        if let Some(k) = old\n            .keys\n"
       "            .filter(|k| !self.cur().keys.as_ref().is_some_and(|n| Arc::ptr_eq(k, n)))\n        {\n"
       "            k.lock();\n        }\n")],
     T + "g5_old_envelope_opens_nothing_after_change"),
    ("tombstones carried into the new generation",
     [(S, "                        rev: at.checked_add(1).ok_or(Error::Argument)?,\n                        ..Manifest::default()\n",
       "                        rev: at.checked_add(1).ok_or(Error::Argument)?,\n"
       "                        tombstones: m.tombstones.clone(),\n                        ..Manifest::default()\n")],
     T + "tombstones_dropped_at_reseal"),
    ("the store write lock not held during the re-seal",
     [(R, "        let w = core.write_lock()?;\n", "        let w = core.live()?;\n")],
     T + "writer_through_change_waits_and_lands"),
]

if __name__ == "__main__":
    mutants_lib.main("up7", MUTANTS)
