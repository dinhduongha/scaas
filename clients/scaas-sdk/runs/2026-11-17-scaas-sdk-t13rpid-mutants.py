# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13, owner 2026-11-19 T4: the passkey RP ID from the SDK's configuration mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13rpid-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "clients/scaas-sdk/src/account/mod.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
L = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib -- --exact "
MUTANTS = [
    ("a passkey created with no RP ID configured",
     [(A, "                let rp_id = sdk.rp_id.clone().ok_or(SdkError::AuthenticatorRefused)?;",
          "                let rp_id = sdk.rp_id.clone().unwrap_or_default();")],
     L + "op::tests::passkey_rp_id_from_config"),
]

if __name__ == "__main__":
    main("t13rpid", MUTANTS)
