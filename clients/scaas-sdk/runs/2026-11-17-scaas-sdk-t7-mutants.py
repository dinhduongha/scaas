# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T7 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t7-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-sdk/src/vault/prf.rs"
S = "clients/scaas-sdk/src/vault/seeds.rs"
U = "clients/scaas-sdk/src/vault/unlock.rs"
L = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test passkey "
MUTANTS = [
    ("accept an answer without PRF", [(P, "            if !a.prf {\n                return Err(SdkError::AuthenticatorRefused);\n            }\n        } else {",
                                       "            let _ = a;\n        } else {")], T + "no_prf_is_refused"),
    ("one salt per vault instead of per seed", [(P, "            let env = PrfEnvelope {\n                output,\n                credential_id: &credential,\n                salt: &salt,\n",
                                                 "            let fresh = random32()?;\n            let env = PrfEnvelope {\n                output,\n                credential_id: &credential,\n                salt: &fresh,\n")],
     T + "enable_then_unlock_by_passkey"),
    ("the open wallet keeps the old envelopes (no refresh)", [(P, "let Ok(open) = self.open_seed(seed) else {", "let Ok(open) = self.open_seed(\"\") else {")],
     T + "manifest_reseal_keeps_prf"),
    # the plan's third mutant, restored with import_key (owner 2026-11-18)
    ("drop the PRF envelope on a new import", [(S, "let prf = match seed_vault.prf_params() {", "let prf = match None::<(String, Vec<u8>)> {")],
     T + "new_import_in_a_passkey_session_carries_the_prf_envelope"),
    # owner 2026-11-18 (b)
    ("open all at unlock", [(U, "if prf && label.as_str() != \"manifest\" {", "if false {")], L + "imports_open_on_first_use"),
]

if __name__ == "__main__":
    main("t7", MUTANTS)
