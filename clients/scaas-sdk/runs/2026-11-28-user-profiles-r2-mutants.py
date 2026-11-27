# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles wave-1 code review, task R2 mutants: the ua-rs fixes (review STATUS rows B-1, B-4, B-5, B-6) and the up2
bindings no record showed (B-6: the wrap domain, the label AD's id, the export nonce's `last` byte and AD index, the
all-zero platform secret, the `t` / `p` / salt bounds):
python3 clients/scaas-sdk/runs/2026-11-28-user-profiles-r2-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-28-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

P = "clients/ua-rs/src/wallet/profile.rs"
MF = "clients/ua-rs/src/wallet/manifest.rs"
ST = "clients/ua-rs/src/wallet/store.rs"
NM = "clients/ua-rs/runs/2026-11-27-key-handles-nm.py"
UA = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
      "--features user-profile,test-hooks,vectors --test profile -- --exact ")
VAULT = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
         "--test wallet_vault -- --exact ")
MUTANTS = [
    # B-1, B-4: the key lock at every open path; the mark kept against an older manifest
    ("B-1 a plain install of a key-locked import",
     [(MF, "            if !locked && m.key_locked.contains(&e) {\n", "            if false {\n")],
     VAULT + "key_lock_refuses_the_old_plain_vault"),
    ("B-4 an older manifest drops a held import's key-lock mark",
     [(ST, "            .all(|e| new.key_locked.contains(e));\n", "            .all(|_| true);\n")],
     VAULT + "key_lock_mark_kept_against_an_older_manifest"),
    # B-5: the nm gate's allow-list (its control line fails when the allow-list reads nothing)
    ("B-5 the wallet allow-list admits every module",
     [(NM, 'WALLET = re.compile(r"scaas_ua::wallet::(\\w+)")\n', 'WALLET = re.compile("(?!)")\n')],
     "python3 " + NM),
    # B-6: the check_pass branch, the drop wipe measured per thread
    ("B-6 check_pass accepts a wrap of another DEK_p",
     [(P, "            false => Err(Error::Aead),\n", "            false => Ok(()),\n")],
     UA + "check_pass_another_dek"),
    ("B-6 a dropped ProfileKeys leaks its arena",
     [(P, "        let store = SecretStore::empty_open();\n        ProfileKeys {\n",
       "        let store = SecretStore::empty_open();\n        std::mem::forget(store.clone());\n        ProfileKeys {\n")],
     UA + "lock_wipes_the_arena"),
    # B-6: the up2 bindings
    ("B-6 the pass wrap under the platform's domain",
     [(P, 'const WRAP_PASS: &[u8] = b"scaas.profile.wrap";\n', 'const WRAP_PASS: &[u8] = b"scaas.profile.platform";\n')],
     UA + "pass_rows"),
    ("B-6 the label AD without the profile id",
     [(P, "    Ok([lp(LABEL)?, 1u16.to_be_bytes().to_vec(), lp(id.as_bytes())?].concat())\n",
       "    Ok([lp(LABEL)?, 1u16.to_be_bytes().to_vec()].concat())\n")],
     UA + "label_rows"),
    ("B-6 the export nonce's last byte always 0",
     [(P, "        let n = [&prefix[..], &i.to_be_bytes(), &[u8::from(last)]]\n",
       "        let n = [&prefix[..], &i.to_be_bytes(), &[0u8]]\n")],
     UA + "export_file_rows"),
    ("B-6 the export AD without the chunk index",
     [(P, "            header,\n            &i.to_be_bytes(),\n", "            header,\n")],
     UA + "export_file_rows"),
    ("B-6 an all-zero platform secret accepted",
     [(P, "        if secret.iter().fold(0u8, |a, b| a | b) == 0 {\n", "        if secret.is_empty() {\n")],
     UA + "platform_rows"),
    ("B-6 the t lower bound not checked",
     [(P, "        let ok = (65_536..=1_048_576).contains(&kdf.m_kib) && (3..=10).contains(&kdf.t);\n",
       "        let ok = (65_536..=1_048_576).contains(&kdf.m_kib) && (..=10).contains(&kdf.t);\n")],
     UA + "kdf_bound_rows"),
    ("B-6 p not checked",
     [(P, "        if !ok || kdf.p != 4 || salt.len() != 16 {\n", "        if !ok || salt.len() != 16 {\n")],
     UA + "kdf_bound_rows"),
    ("B-6 the salt length not checked",
     [(P, "        if !ok || kdf.p != 4 || salt.len() != 16 {\n", "        if !ok || kdf.p != 4 {\n")],
     UA + "kdf_bound_rows"),
]

if __name__ == "__main__":
    mutants_lib.main("r2", MUTANTS)
