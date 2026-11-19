# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13: passkey and secure-element signing (owner 2026-11-19, S1, P1) mutants, the plan's two:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13external-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

X = "clients/scaas-sdk/src/op/external.rs"
S = "clients/ua-rs/src/wallet/signer.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib -- "
MUTANTS = [
    ("ua-rs: skip the external answer's verification",
     [(S, "    if ok {\n        Ok(sig)", "    if ok || !ok {\n        Ok(sig)")],
     T + "se_key_message_mode"),
    ("digest-mode SE call (the SDK hashes ua_msg first)",
     [(X, "                .p256_sign(handle, ua_msg.to_vec(),", "                .p256_sign(handle, scaas_ua::sha256(&ua_msg).to_vec(),")],
     T + "se_key_message_mode"),
]

if __name__ == "__main__":
    main("t13external", MUTANTS)
