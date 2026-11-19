# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Owner rulings C3, C4 of 2026-11-19 (plan T15's report): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-c3c4-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/ua-rs/src/wallet/policy.rs"
R = "clients/scaas-sdk/src/confidential/read.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential "
MUTANTS = [
    ("C3: the owner statements under metatx (the old mapping)",
     [(P, '        "ZetherRollOver" | "ZetherSetRollOverMode" => "zether-owner",\n', "")],
     U + "owner_statements_sign_under_their_contract_purpose"),
    ("C3 class: PqzRollOver under metatx", [(P, '        "PqzRollOver" => "zether-auth",\n', "")],
     U + "owner_statements_sign_under_their_contract_purpose"),
    ("C3 class: AuditorConsent under metatx", [(P, '        "AuditorConsent" => "auditor-consent",\n', "")],
     U + "owner_statements_sign_under_their_contract_purpose"),
    ("C4: an uncatalogued token is Argument",
     [(R, "    if class != CLASS_TOKEN || !ZETHER_KINDS.contains(&kind) {\n        return Err(SdkError::TokenUncatalogued);",
       "    if class != CLASS_TOKEN || !ZETHER_KINDS.contains(&kind) {\n        return Err(SdkError::Argument);")],
     T + "uncatalogued_token_refused"),
    ("C4: the clone check dropped (R6 refuses it under its own code)",
     [(R, "let (_, env) = scaas_ua::factory::clone_env(&r.code).ok_or(SdkError::TokenUncatalogued)?;",
       "let Some((_, env)) = scaas_ua::factory::clone_env(&r.code) else { return Err(SdkError::LegKeyMismatch) };")],
     T + "code_hash_checked"),
    ("C4: a leg of another key is Argument", [(R, "        _ => Err(SdkError::LegKeyMismatch),", "        _ => Err(SdkError::Argument),")],
     T + "leg_of_another_key_refused"),
]

if __name__ == "__main__":
    main("c3c4", MUTANTS)
