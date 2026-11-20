# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13 (account operations: registration, records) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13-mutants.py check | run
(The files `…-t13a…t13f-mutants.*` beside this one belong to an earlier review round's numbering.)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/account/register.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test account_ops "
MUTANTS = [
    # the plan's: role Authorization for a PoP
    ("a PoP signed under another purpose", [(R, "&scaas_ua::ua_portable::pop_v2_tag(),",
                                             "&scaas_ua::purpose_tag(\"metatx\").map_err(|_| SdkError::Internal)?,")],
     T + "registration_args_equal_portable_json"),
    # each check of the task
    ("landed by the receipt, not the record", [(R, "Landed::Registered => match (out.len(), word(out, 0)?) {",
                                                "Landed::Registered => match (out.len(), U256::ZERO) {")],
     T + "registry_write_landed_by_record"),
    ("a registered UA written again", [(R, "    if !registered {\n        // an ML-DSA key", "    if true {\n        // an ML-DSA key")],
     T + "registry_write_landed_by_record"),
    ("a write submitted twice", [(R, "t.remove(&w.id);", "t.get(&w.id);")],
     T + "registry_write_landed_by_record"),
    ("the KEM repair ignores a stored key", [(R, "                let stored = if read_record(&pool, registry, Landed::Kem(0), &ua).await? {",
                                              "                let stored = if false {")],
     T + "kem_repair_after_commit_form"),
]

if __name__ == "__main__":
    main("t13", MUTANTS)
