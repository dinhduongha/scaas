# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T13's msig follow-ups M1-M5 (owner 2026-11-19): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13m-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/scaas-sdk/src/account/msig.rs"
R = "clients/scaas-sdk/src/account/register.rs"
U = "clients/ua-rs/src/wallet/uasig.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
L = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test wallet_uasig "
MUTANTS = [
    ("M1: msig_combine keeps the caller's order", [(U, "    members.sort_by_key(|m| m.index);\n", "")],
     UA + "msig_updated_rows_through_the_builder"),
    ("M1: a Signed slot under another index", [(M, "                if m.index != *index {", "                if false && m.index != *index {")],
     L + "msig_members_apart"),
    ("M5: the device asked over another member digest",
     [(M, "scaas_ua::member_digest(\n            ua,", "scaas_ua::member_digest(\n            &[0; 32],")],
     L + "msig_members_apart"),
    ("M2: an inactive slot is Argument",
     [(M, "        if !v.active(s.index()) {\n            return Err(SdkError::MsigSlotInactive);",
       "        if !v.active(s.index()) {\n            return Err(SdkError::Argument);")],
     L + "msig_minimal_sets"),
    ("M3: an update landed by its version alone",
     [(R, "super::msig::decode_structure(out).map(|kd| scaas_ua::keccak256(&kd) == h)", "{ let _ = (out, h); Some(true) }")],
     L + "update_msig_current"),
    ("M4: holds_pqz_key never read",
     [(M, "holds_pqz_key: word(&key, 0).ok_or(SdkError::Argument)? != U256::ZERO,", "holds_pqz_key: word(&key, 0).ok_or(SdkError::Argument)?.is_zero() && false,")],
     L + "update_msig_current"),
]

if __name__ == "__main__":
    main("t13m", MUTANTS)
