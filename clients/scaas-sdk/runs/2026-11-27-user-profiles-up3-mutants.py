# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP3 key-lock mutants: python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up3-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

V = "clients/ua-rs/src/wallet/vault.rs"
M = "clients/ua-rs/src/wallet/manifest.rs"
UA = "cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 --test wallet_vault "
MUTANTS = [
    ("the reader does not refuse a prf envelope on a key-locked label",
     [(V, "            .filter(|x| is_vault_id(&x.id) && !(x.prf.is_some() && key_locked(&x.label)))\n",
       "            .filter(|x| is_vault_id(&x.id))\n")],
     UA + "key_lock_label_form"),
    ("reseal_label_vault does not skip a key-locked label",
     [(M, "    pub fn reseal_label_vault(&self, label: &str) -> Result<Vault> {\n        if key_locked(label) {\n",
       "    pub fn reseal_label_vault(&self, label: &str) -> Result<Vault> {\n        if key_locked(label) && false {\n")],
     UA + "key_lock_skipped_by_reseal_and_retained_open"),
    ("the backup payload keeps the key-locked key",
     [(M, "            let secrets = held(m)\n                .filter(|h| !matches!(h, Held::Locked(_)))\n",
       "            let secrets = held(m)\n")],
     UA + "key_lock_left_out_of_backup_and_link"),
]

if __name__ == "__main__":
    mutants_lib.main("up3", MUTANTS)
