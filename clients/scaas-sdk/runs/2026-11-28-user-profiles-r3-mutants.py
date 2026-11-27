# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles wave-1 code review, task R3 mutants: the SDK seam (review STATUS rows C-1, C-4, C-5, C-6, C-7, C-8, E-5) and
the guards C-7 found without a mutant (the secrets gate, `PartStore::gate`, the store's `imported` marking read by the SDK, the
unbacked-delete check):
python3 clients/scaas-sdk/runs/2026-11-28-user-profiles-r3-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-28-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

L = "clients/scaas-sdk/src/lib.rs"
U = "clients/scaas-sdk/src/user_profile/mod.rs"
V = "clients/scaas-sdk/src/vault/unlock.rs"
S = "clients/scaas-sdk/src/vault/seeds.rs"
X = "clients/scaas-profile/src/export.rs"
TS = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
      "--features user-profile,test-hooks --test user_profile -- --exact ")
FLAG_THEN_SEEDS = ("        let tasks = self\n            .tasks\n            .lock()\n            .unwrap_or_else(PoisonError::into_inner)\n"
                   "            .take();\n        tasks.into_iter().flatten().for_each(|t| t.abort());\n"
                   "        #[cfg(feature = \"test-hooks\")]\n        self.hook(\"close\");\n"
                   "        let out = self.lock_every().await;\n")
SEEDS_THEN_FLAG = ("        let out = self.lock_every().await;\n"
                   "        #[cfg(feature = \"test-hooks\")]\n        self.hook(\"close\");\n"
                   "        let tasks = self\n            .tasks\n            .lock()\n            .unwrap_or_else(PoisonError::into_inner)\n"
                   "            .take();\n        tasks.into_iter().flatten().for_each(|t| t.abort());\n")
MUTANTS = [
    # C-1: the closed flag before the seeds' lock, and read under the map's lock by the unlock and the hidden open
    ("C-1 close locks the seeds before its flag (the order of UP6 back)",
     [(L, FLAG_THEN_SEEDS, SEEDS_THEN_FLAG)],
     TS + "c1_unlock_racing_lock_keeps_nothing"),
    ("C-1 the unlock keeps its wallet after the close",
     [(V, "                    let first = sdk.live().map(|()| !open.contains_key(&id));\n",
       "                    let first: Result<bool, SdkError> = Ok(!open.contains_key(&id));\n")],
     TS + "c1_unlock_racing_lock_keeps_nothing"),
    ("C-1 the hidden open keeps its wallet after the close",
     [(V, "                    sdk.live()\n                        .map(|()| hidden.insert(id.clone(), (seed, set.clone())))\n",
       "                    Ok::<_, SdkError>(hidden.insert(id.clone(), (seed, set.clone())))\n")],
     TS + "c1_unlock_racing_lock_keeps_nothing"),
    # C-4: the `Sdk` holds the open profile
    ("C-4 the Sdk does not hold the open profile",
     [(U, "        let _ = s.profile.set(self.open.clone());\n", "        let _ = &s.profile;\n")],
     TS + "c4_sdk_keeps_the_profile_open"),
    # C-5: the preview reads `sdk.state` with the SDK's parser; the store's marking read back through the SDK
    ("C-5 the preview skips the SDK's parse of sdk.state",
     [(U, "            crate::op::state::check(b).map_err(|_| SdkError::ProfileImportOpen)?;\n", "            let _ = b;\n")],
     TS + "c5_preview_reads_state_with_the_sdk_parser"),
    ("C-7 the store's imported marking skipped (read back through the SDK)",
     [(X, "            *b = mark_imported(b)?;\n", "")],
     TS + "g9_export_import_through_sdk"),
    # C-6
    ("C-6 part_store hands out the part sdk",
     [(U, "        if part == ProfilePart::Sdk {\n            return Err(SdkError::Argument);\n        }\n", "")],
     TS + "c6_part_store_refuses_the_sdk_part"),
    # C-7: the close abort, the secrets gate, PartStore::gate, the unbacked-delete check
    ("C-7 close aborts no task",
     [(L, "        tasks.into_iter().flatten().for_each(|t| t.abort());\n", "        drop(tasks);\n")],
     TS + "c7_call_across_lock_aborted"),
    ("C-7 the secrets gate removed from generate",
     [(S, "    pub async fn generate(&self, req: Generate) -> Result<NewSeed, SdkError> {\n        self.sdk.secrets_allowed()?;\n",
       "    pub async fn generate(&self, req: Generate) -> Result<NewSeed, SdkError> {\n")],
     TS + "passphrase_required_before_any_work"),
    ("C-7 PartStore::gate passes a migrated default",
     [(U, "        let migrated = self.core.migration_pending() && !self.core.protected();\n",
       "        let migrated = false;\n")],
     TS + "migrated_default_refused_until_sealed"),
    ("C-7 the unbacked-delete check removed",
     [(U, "        if self.delete_preview().await?.unbacked > 0 && unbacked.is_none() {\n",
       "        if false && unbacked.is_none() {\n")],
     TS + "delete_through_sdk"),
    # C-8 (c)
    ("C-8 a cancelled join on a plain Sdk is ProfileLocked",
     [(L, "            Err(e) if e.is_cancelled() && self.live().is_err() => Err(SdkError::ProfileLocked),\n",
       "            Err(e) if e.is_cancelled() => Err(SdkError::ProfileLocked),\n")],
     TS + "c8_cancelled_plain_sdk_call_is_internal"),
    # E-5's SDK half
    ("E-5 the SDK's write_last not passed to the store",
     [(U, "        c.write_last = config.write_last;\n", "")],
     TS + "e5_write_last_through_sdk"),
]

if __name__ == "__main__":
    mutants_lib.main("r3", MUTANTS)
