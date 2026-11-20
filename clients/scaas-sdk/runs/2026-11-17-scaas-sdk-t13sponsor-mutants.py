# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13b (sponsored registration, spec §7.1, R16) mutants, and T13's split:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13sponsor-mutants.py check | run
(Named `t13sponsor`: the files `…-t13b-mutants.*` beside this one belong to an earlier review round's numbering.)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/account/sponsor.rs"
R = "clients/scaas-sdk/src/account/register.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test account_ops "
L = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
MUTANTS = [
    # the plan's four
    ("drop the UA check", [(S, "                if !b.ua.eq_ignore_ascii_case(&expected_ua) {", "                if false {")],
     T + "sponsored_registration_checks"),
    ("drop the local PoP check", [(S, "                check_registration(kind, &key_data, &attrs, &pop, &pqz_pop, &|_| None)\n"
                                      "                    .map_err(|_| SdkError::RegistrationPopInvalid)?;", "")],
     T + "sponsored_registration_checks"),
    ("prepare the payment before the registration lands (no receiver check)",
     [("clients/scaas-sdk/src/wallet/ops.rs",
       "                crate::account::receiver_registered(&sdk, &req.chain, &id32(&req.to)?).await?;\n", "")],
     T + "pay_to_unregistered_derived_ua"),
    ("skip the setKemKey when kemPkHash is set", [(R, "    if let Some(fill) = kem_fill {", "    if let Some(fill) = kem_fill.filter(|_| false) {")],
     T + "sponsored_registration_checks"),
    # T13's: no split for a PQ registration
    ("no split for a PQ registration", [(R, "        let split = pqz_pop != \"0x\"", "        let split = false\n            && pqz_pop != \"0x\"")],
     L + "pq_registration_split"),
    # each check of the task
    ("the kind not read", [(S, "if out.len() != 32 || U256::from_be_slice(&out) != U256::from(1) {", "if out.len() != 32 {")],
     T + "sponsored_registration_checks"),
    ("the UA not recomputed from the key data", [(S, "                    || scaas_ua::derive_ua(kind, &key_data, false)", "                    || false && scaas_ua::derive_ua(kind, &key_data, false)")],
     T + "sponsored_registration_checks"),
    ("a committed KEM key not compared", [(S, "                            || scaas_ua::keccak256(&kem_pk) != attrs.kem_pk_hash\n", "")],
     T + "sponsored_registration_checks"),
    # the depth bound is not observable by outcome (every deeper blob also fails its field types); the size bound is
    # removed 2026-11-20 (review T5): "no 64 KiB bound": the sponsor's own bound gave way to RegistrationBlob::from_json's 768 KiB bound in 3d0110340 (t13rulings "R1: no size bound")
]

if __name__ == "__main__":
    main("t13sponsor", MUTANTS)
