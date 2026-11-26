# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T16 part 1 (the PQZ reading layer, the set check, the balance) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t16a-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-sdk/src/confidential/pqz.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential_pqz "
MUTANTS = [
    ("the account words read for a token of another set", [(P, "(psid == pqzl || Some(psid) == pqzh, env)", "(true, env)")],
     T + "set_mismatch_before_parse"),
    ("no set check", [(P, "    if r.psid != pqzl && Some(r.psid) != pqzh {\n        return Err",
                       "    if false {\n        return Err")],
     T + "set_mismatch_before_parse"),
    ("proofStore not checked (T16-b)", [(P, "if field(&x.slot0, \"proofStore\") > 1 {", "if false {")],
     T + "pqz_token_checks"),
    ("a token of a Zether kind taken (R5)", [(P, "!PQZ_KINDS.contains(&kind)", "kind == 0")],
     T + "pqz_token_checks"),
    # re-anchored 2026-11-23 (T26 A2-4: an OFFCHAIN token's key counts unproven, `!(proven || offchain)`): the same mutation
    ("an unproven key record taken (R6)", [(P, "if !(proven || offchain)\n        || ptr", "if ptr")],
     T + "pqz_leg_of_another_key_refused"),
    ("the registry's key not compared with the handle's (R6)", [(P, "code.and_then(|c| c.split_first()) != Some((&0, pk))", "code.is_none()")],
     T + "pqz_leg_of_another_key_refused"),
    ("a facade refusal reads again (R7)", [(P, "                decrypt(&sdk, key, w).await\n",
                                            "                match decrypt(&sdk, key, w).await { Ok(o) => Ok(o), Err(_) => { read(&sdk, &r.chain, &r.token, ua, r.key_version, &pk, false, &[]).await?; Err(SdkError::Argument) } }\n")],
     T + "pqz_word_failure_never_fails_over"),
]

if __name__ == "__main__":
    main("t16a", MUTANTS)
