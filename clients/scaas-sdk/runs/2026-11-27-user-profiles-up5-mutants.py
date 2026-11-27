# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP5 mutants (the sealed store core: names, manifests, tombstones, anchor, generation files, write lock):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up5-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

S = "clients/scaas-sdk/src/user_profile/store.rs"
A = "clients/scaas-sdk/src/user_profile/anchor.rs"
T = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features user-profile,test-hooks --test user_profile -- --exact ")
MUTANTS = [
    ("the HMAC name replaced by the item name",
     [(S, "        Ok(self.gdir.join(keys.item_file(part, name).map_err(ua)?))\n",
       "        Ok(self.gdir.join(name))\n")],
     T + "g1_no_name_on_disk"),
    ("the manifest's rev not compared",
     [(S, "        let below = m.items.get(name).is_some_and(|l| rev < *l);\n",
       "        let below = false;\n")],
     T + "g5_old_item_put_back"),
    ("no tombstone at delete",
     [(S, "                    m.tombstones.insert(name.to_string(), last);\n",
       "                    let _ = last;\n")],
     T + "g5_deleted_item_put_back"),
    ("the manifest written without put_if",
     [(S, "            match put_file_if(&self.gdir, &p, at, &bytes) {\n",
       "            match FileStore::write(&self.gdir, &p, &bytes, false).map_err(io) {\n")],
     T + "g5_two_writers_both_land"),
    ("\"differs from the anchor\" as the rule",
     [(A, "                Some(s) if s.rev > a.rev => Verdict::Follow,\n",
       "                Some(s) if s.rev > a.rev => Verdict::Rollback,\n"),
      (A, "            std::cmp::Ordering::Greater => Verdict::Follow,\n",
       "            std::cmp::Ordering::Greater => Verdict::Rollback,\n")],
     T + "anchor_rows"),
    ("the .lock / .tmp.* pattern refused",
     [(S, "        \".lock\" => Some(Kind::Lock),\n", "        \".lock\" => None,\n"),
      (S, "            (digits(pid) && digits(n)).then_some(Kind::Temp)\n",
       "            (digits(pid) && digits(n) && false).then_some(Kind::Temp)\n")],
     T + "store_files_temporaries_locks_others"),
    ("no clean-up at open",
     [(S, "                std::fs::remove_file(e.path()).map_err(|_| SdkError::VaultIo)?\n",
       "                drop(e.path())\n")],
     T + "store_files_temporaries_locks_others"),
    ("a waiting writer answered StoreConflict",
     [(S, "            .wait_timeout_while(held, wait, |h| *h)\n",
       "            .wait_timeout_while(held, Duration::ZERO, |h| *h)\n"),
      (S, "            return Err(SdkError::ProfileBusy);\n", "            return Err(SdkError::StoreConflict);\n")],
     T + "writer_waits_then_busy"),
]

if __name__ == "__main__":
    mutants_lib.main("up5", MUTANTS)
