# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP6 mutants: part a (the profile root, the index, the envelope, start, open and lock at the store's crate
clients/scaas-profile) and part b (the SDK's: `close` not called at lock, the closed flag not checked):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up6-mutants.py check | run [name]"""
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
E = "clients/scaas-profile/src/envelope.rs"
T = ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features test-hooks --test ")
LOCK = T + "lock -- --exact "
PROF = T + "profiles -- --exact "
U = "clients/scaas-sdk/src/user_profile/mod.rs"
L = "clients/scaas-sdk/src/lib.rs"
SDK = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
       "--features user-profile,test-hooks --test user_profile -- --exact ")
MUTANTS = [
    ("the instance lock dropped",
     [(P, "        let instance = try_lock_file(&dir.join(INSTANCE_LOCK))?.ok_or(Error::ProfileInUse)?;\n",
       "        let instance = File::open(&dir).map_err(|_| Error::VaultIo)?;\n")],
     LOCK + "second_open_in_another_process"),
    ("start taking every profile's lock",
     [(P, "        let scan = self.scan()?;\n        for (_, env) in &scan {\n",
       "        let scan = self.scan()?;\n        for (id, _) in &scan {\n"
       "            if let Some(f) = try_lock_file(&self.p.join(id).join(INSTANCE_LOCK))? {\n"
       "                std::mem::forget(f);\n            }\n        }\n        for (_, env) in &scan {\n")],
     LOCK + "start_takes_no_live_lock"),
    ("the state check removed",
     [(E, "        let state_ok = match e.state {\n", "        let state_ok = true || match e.state {\n")],
     PROF + "g3_state_flipped_and_marker"),
    ("a missing index treated as a first run",
     [(P, "        if scan.is_empty() {\n            return Ok(true);\n",
       "        if scan.is_empty() || !self.root.join(index::FILE).exists() {\n            return Ok(true);\n"),
      (P, "        if parsed.is_none() && scan.is_empty() {\n            return Ok((Index::new(Vec::new()), at));\n",
       "        if parsed.is_none() {\n            return Ok((Index::new(Vec::new()), at));\n")],
     PROF + "g10_rebuild_lists_every_visible"),
    ("a rebuild listing only unprotected profiles",
     [(P, "                    name: env?.name?,\n",
       "                    name: env.filter(|e| e.state == State::Unprotected)?.name?,\n")],
     PROF + "g10_rebuild_lists_every_visible"),
    ("the root's mode not tightened",
     [(P, "            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))\n",
       "            std::fs::set_permissions(root, m.permissions())\n")],
     PROF + "g12_root_modes_and_symlink"),
    ("a symlinked root accepted",
     [(P, "    if m.file_type().is_symlink() || !m.is_dir() {\n",
       "    if !std::fs::metadata(root).is_ok_and(|m| m.is_dir()) {\n")],
     PROF + "g12_root_modes_and_symlink"),
    ("the per-device maximum not checked",
     [(E, "        if a.m_kib > max_kib {\n", "        if false && a.m_kib > max_kib {\n")],
     PROF + "g8_bounds_before_any_kdf"),
    ("a KDF under the root lock",
     [(P, "        let _heavy = self.heavy.acquire();\n",
       "        let _heavy = (self.heavy.acquire(), self.root_lock()?);\n")],
     PROF + "g8_start_during_held_kdf"),
    # part b: without the close, the old `Sdk`'s chain call still reaches the chain after lock
    ("close not called at lock",
     [(U, "            out = s.close().await;\n", "            let _ = &out;\n")],
     SDK + "g11_no_request_after_lock"),
    # part b: without the flag, the closed `Sdk`'s chain call is `ChainUnknown` (its chains dropped), not `ProfileLocked`: only
    # the exact code tells
    ("the closed flag not checked",
     [(L, "        Some(_) => Ok(()),\n        None => Err(SdkError::ProfileLocked),\n", "        _ => Ok(()),\n")],
     SDK + "g11_no_request_after_lock"),
]

if __name__ == "__main__":
    mutants_lib.main("up6", MUTANTS)
