# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T13b mutants of ruling 3, vault v2 (owner 2026-11-19): clientkeys, ua-rs and the SDK together:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13f-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
C = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features vectors --test wallet_vault "
CK = "cd clients/clientkeys && ../../scripts/capped node --test "
MUTANTS = [
    ("ua-rs: the AAD without the id", [("clients/ua-rs/src/wallet/vault.rs", 'format!("{id}|{label}|{part}").into_bytes()',
                                       'format!("{}|{label}|{part}", &id[..0]).into_bytes()')], UA + "vault_json"),
    ("ua-rs: a v 1 vault read", [("clients/ua-rs/src/wallet/vault.rs", '!= Some(2) || v.get("moved").is_some()',
                                 '== Some(9) || v.get("moved").is_some()')], UA + "vault_json_refusals"),
    ("ua-rs: a label vault of another seed opened", [("clients/ua-rs/src/wallet/manifest.rs",
      "if *self.vault_id.get_or_init(|| vault.id().to_owned()) != vault.id() {", "if false {")], UA + "a_label_vault_of_another_seed_is_refused"),
    ("SDK: a vault of another seed's id parsed", [("clients/scaas-sdk/src/vault/keystore.rs",
      '&& v.get("id").and_then(Value::as_str) == Some(seed_id)', '&& !seed_id.is_empty()')], C + "--test keystore_vectors"),
    ("SDK: a vault rewrite leaves the MAC", [("clients/scaas-sdk/src/vault/prf.rs", "                e.index_mac = index_mac.clone();\n", "")],
     C + "--test passkey enable_then_unlock_by_passkey"),
    ("SDK: a child leaves its parent's MAC", [("clients/scaas-sdk/src/vault/seeds.rs", "                        p.index_mac = mac(&parent.wallet, p)?;\n", "")],
     C + "--test children remove_then_derive_never_reuses"),
    ("clientkeys: the AAD without the id", [("clients/clientkeys/src/vault.js", "const aad = (vault, part) => `${vault.id}|${vault.label}|${part}`;",
                                           "const aad = (vault, part) => `${vault.label}|${part}`;")], CK + "test/vault.test.js"),
    ("clientkeys: the MAC without the vault texts", [("clients/clientkeys/src/keystore-mac.js", "'backup', 'accounts', 'vaults']);", "'backup', 'accounts']);")],
     CK + "test/keystore.test.js"),
    ("clientkeys: a vault of another seed's id parsed", [("clients/clientkeys/src/keystore.js",
      "if (inner.v !== 2 || inner.id !== s.id)", "if (inner.v !== 2)")], CK + "test/keystore.test.js"),
]

if __name__ == "__main__":
    main("t13f", MUTANTS)
