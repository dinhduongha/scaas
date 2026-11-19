# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T13a mutants (closing review P2-1, the nested-secret hang class):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13a-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

SEC = "clients/ua-rs/src/wallet/secret.rs"
PRF = "clients/scaas-sdk/src/vault/prf.rs"
ROOTS = "clients/scaas-sdk/src/vault/roots.rs"
UNLOCK = "clients/scaas-sdk/src/vault/unlock.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --lib "
MUTANTS = [
    ("with2 locks one secret twice", [(SEC, "if Arc::ptr_eq(&self.cell, &other.cell) {", "if false {")],
     UA + "with2_one_secret_twice_and_both_orders"),
    ("with2 locks in call order, not id order", [(SEC, "if self.id < other.id {", "if true {")],
     UA + "with2_one_secret_twice_and_both_orders"),
    ("secret_dispose holds the registry over the secret's lock",
     [(SEC, "    let removed = registry().remove(&id);\n    match removed {", "    match registry().remove(&id) {")],
     UA + "dispose_of_a_secret_in_use_does_not_hold_the_registry"),
    ("change_passphrase nests the two passphrases",
     [(PRF, "passphrases(&old, &n2, |o, n| Ok(v.rewrap_pin(o, n)?))",
       "passphrase(&old, |o| passphrase(&n2, |n| Ok(v.rewrap_pin(o, n)?)))")],
     T + "--test passkey change_passphrase_one_secret_for_both"),
    ("root (d) nests the key and the passphrase",
     [(ROOTS, "key.with2(&dp, |k, p| {", "key.with(|k| dp.with(|p| {"),
      (ROOTS, "Ok(Wallet::from_private_key(k, p, index)?)\n                        })",
       "Ok(Wallet::from_private_key(k, p, index)?)\n                        }))")],
     T + "--test roots one_secret_for_two_parameters_does_not_hang"),
    ("root (c) nests the two signatures", [(ROOTS, "s1.with2(&s2, derive)", "s1.with(|a| s2.with(|b| derive(a, b)))")],
     T + "--test roots one_secret_for_two_parameters_does_not_hang"),
]

if __name__ == "__main__":
    main("t13a", MUTANTS)
