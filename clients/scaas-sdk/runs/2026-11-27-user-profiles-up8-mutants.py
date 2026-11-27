# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP8 mutants: hidden profiles at the store's crate clients/scaas-profile (spec §8, §6, §7.1):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up8-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

H = "clients/scaas-profile/src/hidden.rs"
E = "clients/scaas-profile/src/envelope.rs"
T = ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features test-hooks --test hidden -- --exact ")
MUTANTS = [
    # the search stops at its first match: the dummy fill counts candidates, so fewer runs than max(candidates, 4)
    ("an early stop at the match",
     [(H, "            Ok(Some(keys)) => found.push(Found {\n"
          "                id: id.clone(),\n"
          "                bytes: env.as_ref().map(|(_, b)| b.clone()).unwrap_or_default(),\n"
          "                keys,\n"
          "            }),\n",
       "            Ok(Some(keys)) => {\n"
       "                found.push(Found {\n"
       "                    id: id.clone(),\n"
       "                    bytes: env.as_ref().map(|(_, b)| b.clone()).unwrap_or_default(),\n"
       "                    keys,\n"
       "                });\n"
       "                break;\n"
       "            }\n")],
     T + "g7_runs_counted"),
    ("a corrupt candidate ending the search",
     [(H, "            Ok(None) => {}\n",
       "            Ok(None) if env.is_none() => break,\n            Ok(None) => {}\n")],
     T + "g7_runs_counted"),
    ("candidates read from the index",
     [(H, "        .filter(|(_, e)| e.as_ref().is_none_or(|(e, _)| e.name.is_none()))\n",
       "        .filter(|(id, _)| {\n"
       "            std::fs::read_to_string(p.with_file_name(\"profiles.json\"))\n"
       "                .unwrap_or_default()\n"
       "                .contains(id.as_str())\n"
       "        })\n")],
     T + "g7_runs_counted"),
    ("hide() without the duplicate check",
     [(H, "        taken(found, &info.id)?;\n", "        drop(found);\n")],
     T + "g7_duplicates"),
    ("last written on a hidden open",
     [(H, "        self.open_found(&f).inspect_err(|_| f.keys.lock())\n",
       "        {\n"
       "            let _r = self.root_lock()?;\n"
       "            let (mut ix, at) = self.index_locked()?;\n"
       "            ix.last = Some(f.id.clone());\n"
       "            self.write_index(&mut ix, at)?;\n"
       "        }\n"
       "        self.open_found(&f).inspect_err(|_| f.keys.lock())\n")],
     T + "g7_runs_counted"),
    # the hint bound into the wraps: a rename, hide() or show() then fails the wrap at the next open
    ("name in the wraps' AD",
     [(E, "    gen: u64,\n    kdf: &'a Kdf,\n}\n", "    gen: u64,\n    kdf: &'a Kdf,\n    name: &'a Option<String>,\n}\n"),
      (E, "            gen: self.gen,\n            kdf,\n", "            gen: self.gen,\n            kdf,\n            name: &self.name,\n")],
     T + "name_hint"),
    ("the lock taken before the search reads",
     [(H, "    for (id, env) in &candidates {\n",
       "    for (id, env) in &candidates {\n"
       "        let _l = try_lock_file(&p.join(id).join(INSTANCE_LOCK))?.ok_or(Error::ProfileInUse)?;\n")],
     T + "search_locks_only_the_match"),
]

if __name__ == "__main__":
    mutants_lib.main("up8", MUTANTS)
