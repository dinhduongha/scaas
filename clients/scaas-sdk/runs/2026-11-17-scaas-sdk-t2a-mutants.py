# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T2a mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t2a-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/mod.rs"
V = "clients/ua-rs/src/wallet/vault.rs"
S = "clients/ua-rs/src/wallet/store.rs"
X = "clients/ua-rs/src/wallet/secret.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 "
MUTANTS = [
    ("MAC over fields in another order",
     [(M, '"{{\\"id\\":{},\\"label\\":{},', '"{{\\"label\\":{},\\"id\\":{},'),
      (M, "        s(f.id),\n        s(f.label),\n", "        s(f.label),\n        s(f.id),\n")],
     UA + "--test index_mac index_mac_rows"),
    ("re-seal with a new DEK",
     [(V, 'Ok(Vault { data: gcm_seal(dek, secret, &aad(&self.label, "data"))?, ..self.clone() })',
          'let _ = dek; Ok(Vault { data: gcm_seal(&random::<32>()?, secret, &aad(&self.label, "data"))?, ..self.clone() })')],
     UA + "--test reseal reseal_keeps_the_prf_envelope"),
    ("keep the DEK after lock",
     [(S, "        g.arena = None;\n        g.generation += 1;", "        g.arena = g.arena.take().filter(|a| !a.deks.is_empty());\n        g.generation += 1;")],
     UA + "--test reseal dek_wiped_at_lock"),
    ("skip the zeroing on dispose",
     [(X, "        self.mem.iter_mut().for_each(|b| b.0.zeroize());\n", "")],
     UA + "--lib secret_bytes_zeroed_on_dispose"),
]

if __name__ == "__main__":
    main("t2a", MUTANTS)
