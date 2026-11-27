# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles wave-1 code review, task R1 mutants: the scaas-profile fixes (review STATUS rows of R1):
python3 clients/scaas-sdk/runs/2026-11-28-user-profiles-r1-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-28-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

P = "clients/scaas-profile/src/profile.rs"
M = "clients/scaas-profile/src/migrate.rs"
H = "clients/scaas-profile/src/hidden.rs"
R = "clients/scaas-profile/src/reseal.rs"
X = "clients/scaas-profile/src/export.rs"
F = "clients/scaas-profile/src/file.rs"
S = "clients/scaas-profile/src/store.rs"
E = "clients/scaas-profile/src/envelope.rs"
I = "clients/scaas-profile/src/index.rs"
G = "clients/scaas-profile/src/settings.rs"
T = ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features test-hooks --test review -- --exact ")
U = "clients/scaas-sdk/src/user_profile/mod.rs"
L = "clients/scaas-profile/src/lifecycle.rs"
C = "clients/scaas-profile/Cargo.toml"
TL = ("cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
      "--lib -- --exact ")
TS = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
      "--features user-profile,test-hooks --test user_profile -- --exact ")
MUTANTS = [
    # R1a: start and journal
    ("G-1 a tombstone beside a live profile takes its keychain items",
     [(P, "                    Some(_held) if std::fs::symlink_metadata(self.p.join(id)).is_ok() => {\n",
       "                    Some(_held) if false => {\n")],
     T + "g1_tombstone_beside_live_profile"),
    ("A-1 a journal beside an older envelope removes the live generation",
     [(P, "            if self.anchor_gen(dir, id)? > gen {\n"
          "                self.event(ProfileEvent::ProfileRollback);\n"
          "                return Err(Error::ProfileRollback);\n"
          "            }\n", "")],
     T + "a1_journal_beside_an_older_envelope"),
    ("A-5 the tombstone removed before its keychain items",
     [(P, "                    Some(_held) => self.remove_keychain(id).and_then(|()| remove_dir(&path)),\n",
       "                    Some(_held) => remove_dir(&path).and_then(|()| self.remove_keychain(id)),\n")],
     T + "a5_tombstone_kept_until_its_keychain_items_go"),
    ("A-6 a clean-up failure fatal at start",
     [(P, "            if cleaned.is_err() {\n"
          "                self.event(ProfileEvent::ProfileDamaged);\n"
          "            }\n", "            cleaned?;\n")],
     T + "a5_tombstone_kept_until_its_keychain_items_go"),
    ("A-6 a legacy item that cannot move fatal",
     [(M, "            if self.move_item(src, name, &to).is_err() {\n"
          "                self.event(ProfileEvent::ProfileDamaged);\n"
          "            }\n", "            self.move_item(src, name, &to)?;\n")],
     T + "a6_legacy_item_unmovable_reported"),
    ("A-16 a build directory without its build.lock removed",
     [(P, "                match lock.is_file() {\n", "                match true {\n")],
     T + "a16_tmp_without_build_lock_left"),
    ("G-11 a missing protected generation created empty",
     [(P, "        if gen > 0 && !dir.join(format!(\"g{gen}\")).is_dir() {\n", "        if false {\n")],
     T + "g11_missing_generation_damaged"),
    # R1b: the hidden flag from the label, the hidden search
    ("G-2 a rename takes hidden from the hint on disk",
     [(H, "        let hidden = info.hidden;\n",
       "        let hidden = read_envelope(core.dir(), &info.id)?\n"
       "            .ok_or(Error::ProfileFormat)?\n"
       "            .0\n"
       "            .name\n"
       "            .is_none();\n")],
     T + "g2_hidden_flag_from_the_label"),
    ("G-2 a passphrase change keeps the hint on disk",
     [(R, "            name: (!info.hidden).then(|| info.name.clone()),\n", "")],
     T + "g2_hidden_flag_from_the_label"),
    ("G-2 an export takes hidden from the hint on disk",
     [(X, "        let label = label_json(&info.name, info.hidden)?;\n",
       "        let label = label_json(&info.name, env.name.is_none())?;\n")],
     T + "g2_hidden_flag_from_the_label"),
    ("A-12 an open profile never says hidden",
     [(P, "                protected: keys.is_some(),\n                hidden,\n",
       "                protected: keys.is_some(),\n                hidden: false,\n")],
     T + "g2_hidden_flag_from_the_label"),
    ("A-8 a stripped hint left as it is",
     [(H, "        if !label.hidden {\n            self.rewrite_hint(&opened, env, &label.name)?;\n",
       "        if false {\n            self.rewrite_hint(&opened, env, &label.name)?;\n")],
     T + "a8_stripped_hint_rewritten_from_the_label"),
    ("F-1 an unusable passphrase skips the candidates' runs",
     [(H, "        let e = env.as_ref().map(|(e, _)| e).filter(|_| usable);\n",
       "        let e = env.as_ref().map(|(e, _)| e);\n")],
     T + "f1_invalid_passphrase_costs_every_run"),
    ("F-5 hide's search under the store write lock",
     [(H, "        // the wrap check and the duplicate search before the store write lock (review F-5)\n",
       "        let _held = core.write_lock()?;\n")],
     T + "f5_search_before_the_store_write_lock"),
    # R1c: bounds
    ("G-4 files read whole",
     [(F, "    match read_bounded(p, SEALED_MAX)? {\n"
          "        None => Ok(None),\n"
          "        Some(None) => Err(Error::VaultFormat),\n"
          "        Some(Some(bytes)) => Ok(Some((rev_of(&bytes), bytes))),\n"
          "    }\n",
       "    match std::fs::read(p) {\n"
       "        Ok(bytes) => Ok(Some((rev_of(&bytes), bytes))),\n"
       "        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),\n"
       "        Err(_) => Err(Error::VaultIo),\n"
       "    }\n")],
     T + "g4_files_read_bounded"),
    ("G-4 the anchor read at the item bound",
     [(S, "        let in_file = file::read_bounded(&self.dir.join(ANCHOR_FILE), crate::anchor::MAX)?\n"
          "            .map(Option::unwrap_or_default);\n",
       "        let in_file = file::read(&self.dir.join(ANCHOR_FILE))?.map(|(_, b)| b);\n")],
     T + "g4_files_read_bounded"),
    ("G-9 an envelope rev above 2^53 accepted",
     [(E, " || e.rev > crate::file::REV_MAX {\n", " {\n")],
     T + "g9_revs_above_2_pow_53_refused"),
    ("G-9 an index rev above 2^53 accepted",
     [(I, "            && ix.rev <= crate::file::REV_MAX\n", "")],
     T + "g9_revs_above_2_pow_53_refused"),
    ("A-4 caps of any text",
     [(G, "                (1..=78).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit())\n", "                true\n")],
     T + "a4_g6_settings_strings_bounded"),
    ("G-6 userinfo in an endpoint URL",
     [(G, "                    && !auth.contains('@')\n", "")],
     T + "a4_g6_settings_strings_bounded"),
    ("G-6 a backslash in an endpoint URL",
     [(G, " && b != b'\\\\')\n", ")\n")],
     T + "a4_g6_settings_strings_bounded"),
    ("G-6 any scheme",
     [(G, "            let rest = u\n                .strip_prefix(\"https://\")\n                .or_else(|| u.strip_prefix(\"http://\"));\n",
       "            let rest = Some(u.split_once(\"://\").map_or(u, |(_, r)| r));\n")],
     T + "a4_g6_settings_strings_bounded"),
    ("E-4 set_settings writes what parse refuses",
     [(G, "        ProfileSettings::parse(&bytes).map_err(|_| Error::Argument)?;\n", "")],
     T + "e4_settings_written_only_when_readable"),
    ("E-4 set_passphrase keeps settings that do not parse",
     [(R, " || ProfileSettings::parse(b).is_err() {\n", " {\n")],
     T + "e4_settings_written_only_when_readable"),
    ("A-17 an item without rev reaches the KDF",
     [(X, "        if review.items.iter().any(|(_, b)| rev_of(b) == u64::MAX) {\n", "        if false {\n")],
     T + "a17_item_without_rev_refused_before_the_kdf"),
    # R1d: re-seal and create after the commit's rename
    ("A-2 a failure after the re-seal's rename reported",
     [(R, "        let _ = core.commit(gen, keys, Head::of(next.rev, &bytes));\n",
       "        core.commit(gen, keys, Head::of(next.rev, &bytes))?;\n")],
     T + "a2_reseal_committed_reports_success"),
    ("A-3 a failure after the create's rename reported",
     [(P, "                self.write_index(&mut ix, at).is_ok()\n", "                self.write_index(&mut ix, at).map(|_| true)?\n")],
     T + "a3_create_committed_reports_success"),
    # R1e: item rollback readable until accepted, unfinished deletes, the index reconciled
    ("C-3 a rolled-back item unreadable",
     [(S, "        if rolled {\n            self.event(ProfileEvent::ProfileRollback);\n        }\n",
       "        if rolled {\n            return Err(Error::ProfileRollback);\n        }\n")],
     T + "c3_item_rollback_readable_until_accepted"),
    ("C-3 a rolled-back item written",
     [(S, "        if cur.as_ref().is_some_and(|(_, _, rolled)| *rolled) {\n", "        if false {\n")],
     T + "c3_item_rollback_readable_until_accepted"),
    ("C-3 accept_rollback does nothing",
     [(S, "        let Some((rev, _, true)) = self.item(&g, keys, part, name, &m)? else {\n",
       "        let Some((rev, _, false)) = self.item(&g, keys, part, name, &m)? else {\n")],
     T + "c3_item_rollback_readable_until_accepted"),
    ("C-3 no rollback event",
     [(S, "            self.event(ProfileEvent::ProfileRollback);\n", "")],
     T + "c3_item_rollback_readable_until_accepted"),
    ("C-3 the core's events never reach the profiles'",
     [(P, "        core.events = self.events.clone();\n", "")],
     T + "c3_item_rollback_readable_until_accepted"),
    ("C-3 no damaged event",
     [(S, "                    self.event(ProfileEvent::ProfileDamaged);\n                    Err(Error::ProfileDamaged)\n",
       "                    Err(Error::ProfileDamaged)\n")],
     T + "c3_listed_item_missing_damaged"),
    ("C-3 the SDK's accept_rollback does nothing",
     [(U, "        run(move || core.accept_rollback(part, &name)).await\n",
       "        run(move || {\n            let _ = (core, part, name);\n            Ok(())\n        })\n        .await\n")],
     TS + "c3_accept_rollback_through_sdk"),
    ("A-9 an unfinished delete left at open",
     [(S, "        core.finish_deletes()?;\n", "")],
     T + "a9_unfinished_delete_finished_at_open"),
    ("G-10 a parsable index trusted",
     [(P, "                if held == rows.iter().map(key).collect::<Vec<_>>() {\n", "                if true {\n")],
     T + "g10_index_reconciled_with_the_envelopes"),
    ("G-10 twins in the index not reported",
     [(P, "        if twins {\n            self.event(ProfileEvent::ProfileIndexMismatch);\n        }\n", "")],
     T + "g10_index_reconciled_with_the_envelopes"),
    # R1f: E-3, E-5, A-11, B-3, Q5
    ("E-3 a keystore deleted without the unbacked confirm",
     [(L, "        if unbacked.is_none() && !matches!(keystore, Ok(None)) {\n", "        if false {\n")],
     T + "e3_delete_of_a_keystore_needs_the_unbacked_confirm"),
    ("E-3 the SDK passes no unbacked confirm",
     [(U, "                .with(|n| p.delete(&open, n, Some(ConfirmDeleteUnbacked {})))\n",
       "                .with(|n| p.delete(&open, n, None))\n")],
     TS + "delete_through_sdk"),
    ("E-3 the preview leaves operations unmarked",
     [(X, "            *b = mark_imported(b)?;\n", "")],
     T + "e3_import_marks_open_operations"),
    ("E-5 every open writes last",
     [(P, "            let mut changed = self.write_last && ix.last.as_deref() != Some(id);\n",
       "            let mut changed = ix.last.as_deref() != Some(id);\n")],
     T + "e5_cli_never_writes_last"),
    ("A-11 the name kept at lock",
     [(P, "                .name,\n        );\n        drop(Zeroizing::new(name));\n",
       "                .name\n                .clone(),\n        );\n        drop(Zeroizing::new(name));\n")],
     T + "a11_name_cleared_at_lock"),
    ("B-3 no mlock by default",
     [(C, "default = [\"mlock\"]\n", "default = []\n")],
     T + "b3_profile_arena_locked"),
    ("Q5 another owner accepted",
     [(P, "    match root == process {\n", "    match true {\n")],
     TL + "profile::tests::q5_root_owner_compared"),
]

if __name__ == "__main__":
    mutants_lib.main("r1", MUTANTS)
