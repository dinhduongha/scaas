# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles review fix round, task R6 mutants: the owner's rulings of 2026-11-28 (F-2 label rev, G-1 tombstone
markers, G-3 migrated seeds' confirm, G-5 reverse of a strengthening, hidden twins, StoreError's two codes, the uid shortcut)
and two R4 findings (the SDK's seed-wide loops skip key-locked vaults; sdk.state's key order at the preview):
python3 clients/scaas-sdk/runs/2026-11-28-user-profiles-r6-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-28-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

CK = "clients/clientkeys/src/profile.js"
UA = "clients/ua-rs/src/wallet/profile.rs"
P = "clients/scaas-profile/src/profile.rs"
H = "clients/scaas-profile/src/hidden.rs"
R = "clients/scaas-profile/src/reseal.rs"
L = "clients/scaas-profile/src/lifecycle.rs"
G = "clients/scaas-profile/src/settings.rs"
X = "clients/scaas-profile/src/export.rs"
U = "clients/scaas-sdk/src/user_profile/mod.rs"
V = "clients/scaas-sdk/src/vault/mod.rs"
VU = "clients/scaas-sdk/src/vault/unlock.rs"
VP = "clients/scaas-sdk/src/vault/prf.rs"
CAP = "CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
T = "cd clients/scaas-profile && " + CAP + "--features test-hooks --test review -- --exact "
TP = "cd clients/scaas-profile && " + CAP + "--features test-hooks --test profiles -- --exact "
TR = "cd clients/scaas-profile && " + CAP + "--features test-hooks --test lifecycle -- --exact "
TG = "cd clients/scaas-profile && " + CAP + "--test settings -- --exact "
TL = "cd clients/scaas-profile && " + CAP + "--lib -- --exact "
TS = "cd clients/scaas-sdk && " + CAP + "--features user-profile,test-hooks --test user_profile -- --exact "
TSL = "cd clients/scaas-sdk && " + CAP + "--features user-profile,test-hooks --lib -- --exact "
TV = "cd clients/scaas-sdk && " + CAP + "--lib -- --exact "
MUTANTS = [
    # (a) F-2: the label's AD binds the envelope's rev
    ("F-2 clientkeys' label AD without the rev",
     [(CK, "lp(id), be(rev, 8));\n", "lp(id));\n")],
     'cd clients/clientkeys && ../../scripts/capped node --test --test-name-pattern="labels" test/profile.test.js',
     "labels"),
    ("F-2 ua-rs' label AD without the rev",
     [(UA, "        lp(id.as_bytes())?,\n        rev.to_be_bytes().to_vec(),\n", "        lp(id.as_bytes())?,\n")],
     "cd clients/ua-rs && " + CAP + "--features app-core,user-profile,test-hooks,vectors --test profile -- --exact label_rows"),
    ("F-2 a label that fails at its rev is ProfileFormat again",
     [(P, "            scaas_ua::wallet::Error::Aead => Error::ProfileRollback,\n",
       "            scaas_ua::wallet::Error::Aead => Error::ProfileFormat,\n")],
     T + "f2_older_envelope_with_raised_rev_is_rollback"),
    ("F-2 the open's label rollback raises no event",
     [(P, "                if *e == Error::ProfileRollback {\n                    self.event(ProfileEvent::ProfileRollback);\n",
       "                if *e == Error::ProfileRollback {\n")],
     T + "f2_older_envelope_with_raised_rev_is_rollback"),
    ("F-2 hide, show and rename keep the old label (not re-sealed at the new rev)",
     [(H, "        env.label = Some(seal_label(&keys, &env.id, env.rev, name, hidden)?);\n",
       "        env.label = Some(seal_label(&keys, &env.id, env.rev - 1, name, hidden)?);\n")],
     T + "f2_older_envelope_with_raised_rev_is_rollback"),
    ("F-2 the hint repair keeps the old label",
     [(P, "                &keys, &env.id, env.rev, name, false,\n", "                &keys, &env.id, env.rev - 1, name, false,\n")],
     TP + "envelope_files_open"),
    ("F-2 the re-seal seals the label at the old rev",
     [(R, "            next.rev,\n", "            env.rev,\n")],
     T + "a1_journal_beside_an_older_envelope"),
    # (b) G-1 two-step: tombstone markers
    ("G-1 a delete writes no marker",
     [(L, "            self.mark(id)?;\n", "")],
     T + "g1_two_step_old_copy_after_a_tombstone_refused"),
    ("G-1 start finishes a tombstone without a marker",
     [(P, "                        .mark(id)\n                        .and_then(|()| self.remove_keychain(id))\n",
       "                        .remove_keychain(id)\n")],
     T + "g1_two_step_old_copy_after_a_tombstone_refused"),
    ("G-1 a marked directory is scanned (listed, searched)",
     [(P, "is_dir() || marked(p, &id) {\n", "is_dir() {\n")],
     T + "g1_two_step_old_copy_after_a_tombstone_refused"),
    ("G-1 open takes a marked directory",
     [(P, "        if marked(&self.p, id) {\n", "        if false {\n")],
     T + "g1_two_step_old_copy_after_a_tombstone_refused"),
    ("G-1 purge_tombstones keeps the markers",
     [(L, "        remove_dir(&self.p.join(MARKS))?;\n", "")],
     T + "g1_two_step_old_copy_after_a_tombstone_refused"),
    # (c) G-3: a migrated default's seeds confirmed
    ("G-3 the crate seals a migrated keystore without the confirm",
     [(R, "        if migrated.is_none() && self.core.migration_pending() && !matches!(keystore, Ok(None)) {\n",
       "        if false && !matches!(keystore, Ok(None)) {\n")],
     TR + "hooks::migrated_default_sealed_after_commit"),
    ("G-3 the SDK takes any count",
     [(U, "            Some(m) if migrated.is_some_and(|c| c.seeds == m.seeds) => {\n",
       "            Some(m) if migrated.is_some_and(|c| c.seeds <= m.seeds) => {\n")],
     TS + "migrated_default_refused_until_sealed"),
    # (d) G-5 / A-15: the reverse of a strengthening
    ("G-5 strict_majority off is no weakening",
     [(G, "            (o.strict_majority && !n.strict_majority) || caps_raised(&o.caps, &n.caps)\n",
       "            caps_raised(&o.caps, &n.caps)\n")],
     TG + "reverse_of_a_strengthening_weakens"),
    ("G-5 a raised global cap is no weakening",
     [(G, "    let reversed = caps_raised(&old.caps, &new.caps)\n", "    let reversed = false\n")],
     TG + "reverse_of_a_strengthening_weakens"),
    ("G-5 caps compared as text",
     [(G, "            (Some(a), Some(b)) => (b.len(), b) > (a.len(), a),\n", "            (Some(a), Some(b)) => b > a,\n")],
     TG + "reverse_of_a_strengthening_weakens"),
    ("G-5 leading zeros count",
     [(G, "            .then(|| v.trim_start_matches('0').to_string())\n", "            .then(|| v.to_string())\n")],
     TG + "reverse_of_a_strengthening_weakens"),
    # (2) hidden twins
    ("twins: open_hidden picks the first",
     [(H, "                    _ => Error::ProfileHiddenAmbiguous,\n", "                    _ => Error::ProfileOpen,\n")],
     T + "hidden_duplicates_listed_never_picked"),
    ("twins: a choice matched by place only",
     [(H, "        let chosen = found.get(at).map(|f| choice_of(at, f)) == Some(Ok(choice));\n",
       "        let chosen = found.get(at).is_some();\n")],
     T + "hidden_duplicates_listed_never_picked"),
    # (3) StoreError's two codes
    ("StoreError ProfileBusy reaches the SDK as VaultIo",
     [(V, "        StoreError::ProfileBusy => SdkError::ProfileBusy,\n", "        StoreError::ProfileBusy => SdkError::VaultIo,\n")],
     TV + "vault::tests::store_codes_map_by_name"),
    ("StoreError the face's ProfilePartFull is Unavailable",
     [(U, "        Error::ProfilePartFull => StoreError::ProfilePartFull,\n",
       "        Error::ProfilePartFull => StoreError::Unavailable,\n")],
     TSL + "user_profile::tests::store_codes_by_name"),
    # (5) the root's owner: the /proc/self shortcut
    ("uid: the injected uid ignored (the probe always)",
     [(P, "        Some(uid) => Ok(uid),\n", "        Some(_) => probe_uid(root),\n")],
     TL + "profile::tests::q5_proc_self_shortcut"),
    ("uid: process_uid without the shortcut",
     [(P, "    uid_of(proc_uid(), root)\n", "    uid_of(None, root)\n")],
     TL + "profile::tests::q5_proc_self_shortcut"),
    ("uid: another process's /proc entry",
     [(P, '    std::fs::metadata("/proc/self").ok().map(|m| m.uid())\n', '    std::fs::metadata("/proc/1").ok().map(|m| m.uid())\n')],
     TL + "profile::tests::q5_proc_self_shortcut"),
    # (i) the SDK's seed-wide loops skip a key-locked vault
    ("key lock: the unlock opens the key-locked vault with the seed's passphrase",
     [(VU, '                .filter(|l| l.as_str() != "seed" && !l.starts_with(super::KEY_LOCKED))\n',
       '                .filter(|l| l.as_str() != "seed")\n')],
     TV + "vault::tests::key_locked_vault_skipped_by_seed_wide_loops"),
    ("key lock: the re-wrap and the PRF enable map the key-locked vault",
     [(VP, "        .map(|(k, t)| match k.starts_with(super::KEY_LOCKED) {\n", "        .map(|(k, t)| match k.is_empty() {\n")],
     TV + "vault::tests::key_locked_vault_skipped_by_seed_wide_loops"),
    # (ii) sdk.state's key order at the preview
    ("order: the preview's marking sorts the keys",
     [(X, "                    v.push(e);\n                }\n                Ok(Ordered::Object(v))\n",
       "                    v.push(e);\n                }\n                v.sort_by(|a: &(String, Ordered), b| a.0.cmp(&b.0));\n"
       "                Ok(Ordered::Object(v))\n")],
     T + "import_marking_keeps_the_key_order"),
]

if __name__ == "__main__":
    mutants_lib.main("r6", MUTANTS)
