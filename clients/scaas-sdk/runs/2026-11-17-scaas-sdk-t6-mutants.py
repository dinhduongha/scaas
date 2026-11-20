# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T6 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t6-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/ua-rs/src/wallet/roots.rs"
SR = "clients/scaas-sdk/src/vault/roots.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features roots --test roots "
SDK = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features classical-roots --test roots "
MUTANTS = [
    ("skip the double-signature comparison", [(R, "if sig1.len() != 65 || sig1 != sig2 {", "if sig1.len() != 65 {")],
     UA + "root_c_rows_and_refusals"),
    ("hash r || s || v", [(R, "hkdf_sha256(&ikm[..],", "hkdf_sha256(&[&ikm[..], &[27 + bit]].concat(),")],
     UA + "root_c_rows_and_refusals"),
    ("passphrase floor 10 -> 9", [(R, "pub const ROOT_PASSPHRASE_MIN: usize = 10;", "pub const ROOT_PASSPHRASE_MIN: usize = 9;")],
     UA + "passphrase_floor"),
    ("a failed signature check passed through as ExternalSignature", [(SR, "scaas_ua::wallet::Error::ExternalSignature => SdkError::OriginSignature,", "")],
     SDK + "root_c_refusals_each_with_its_control"),
]

if __name__ == "__main__":
    main("t6", MUTANTS)
