# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T4 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t4-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/vault/seeds.rs"
U = "clients/scaas-sdk/src/vault/unlock.rs"
V = "clients/ua-rs/src/wallet/vault.rs"
ST = "clients/ua-rs/src/wallet/store.rs"
UAK = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features vectors --test retained_key "
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test vault "
MUTANTS = [
    ("drop short_seed for 21 words", [(S, "let warnings = if words < 24 {", "let warnings = if words < 21 {")],
     T + "import_accepts_12_to_24"),
    ("a hidden set emits an event", [(U, "                Ok(SessionSet { id })", "                sdk.emit(Event::KeystoreChanged { rev: 0 });\n                Ok(SessionSet { id })")],
     T + "hidden_set_writes_and_emits_nothing"),
    ("skip the MAC check", [(U, "if !mac_ok(&w, e)? {", "if false {")], T + "mac_mismatch_keeps_the_seed_locked"),
    ("mark a locked row verified", [(S, "        verified,\n    }\n}", "        verified: true,\n    }\n}")], T + "locked_rows_are_unverified"),
    ("accept a 7-character passphrase", [(V, "if p.chars().count() < 8 || !other {", "if p.chars().count() < 7 || !other {")],
     T + "vault_passphrase_rule"),
    ("import_key without the passphrase check", [(S, "    let check = Wallet::open_vault(seed_vault,", "    return Ok(());\n    #[allow(unreachable_code)]\n    let check = Wallet::open_vault(seed_vault,")],
     T + "import_key_refusals"),
    ("import_key without the imported_key mark", [(S, "e.warnings.push(\"imported_key\".into());", "")],
     T + "import_key_seals_a_leaf_and_marks_it"),
    ("heavy work without the limit", [("clients/scaas-sdk/src/lib.rs", "let _permit = self.heavy.acquire().await.map_err(|_| SdkError::Internal)?;", "")],
     T + "heavy_work_one_at_a_time"),
    # owner 2026-11-18 (b): "skip zeroize on lock" (the arena's pages, where the retained key lives, released unwiped)
    ("skip zeroize on lock", [(ST, "        self.page.0.zeroize();\n        #[cfg(feature = \"vectors\")]", "        #[cfg(feature = \"vectors\")]")],
     UAK + "lock_zeroizes_the_retained_key"),
    # owner 2026-11-18 (i): the passphrase is never retained
    ("retain the passphrase", [(U, "let r = sdk.heavy(move || open_entry(&e, &key, None)).await;",
                                "if let Key::Pass(p) = &key {\n                    Box::leak(Box::new(p.clone()));\n                }\n                let r = sdk.heavy(move || open_entry(&e, &key, None)).await;")],
     T + "passphrase_not_retained_after_unlock"),
    ("open no label vault at a passphrase unlock", [(U, "for label in e.vaults.keys().filter(|l| l.as_str() != \"seed\") {", "for label in e.vaults.keys().filter(|l| l.as_str() == \"manifest\") {")],
     "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib passphrase_unlock_opens_every_vault"),
]

if __name__ == "__main__":
    main("t4", MUTANTS)
