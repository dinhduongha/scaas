# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T16 part 3, the controller calls P-T16-3 and P-T16-5 of 2026-11-19: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t16d-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

V = "clients/scaas-sdk/src/confidential/verdict.rs"
Q = "clients/scaas-sdk/src/confidential/pqz.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential_pqz "
MUTANTS = [
    ("P-T16-3: a native verifier's code not checked", [(V, "            || !x.native_code.is_empty()\n", "")],
     T + "verdict_native_verifier"),
    ("P-T16-3: any native signature accepted",
     [(V, "scaas_ua::verify::native_ecdsa(\n                    &addr,\n                    &scaas_ua::ua_auth_digest(&d, &x.verifier, &purpose, &digest),\n                    &sig,\n                )",
       "{\n                    let _ = (&d, &addr);\n                    true\n                }")],
     T + "verdict_native_verifier"),
    ("P-T16-5: the last version left out", [(Q, "        for v in 1..=latest {", "        for v in 1..latest {")],
     T + "pqz_balance_all_versions"),
]

if __name__ == "__main__":
    main("t16d", MUTANTS)
