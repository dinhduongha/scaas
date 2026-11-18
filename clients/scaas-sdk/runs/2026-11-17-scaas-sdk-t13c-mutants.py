# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T13c mutants (owner 2026-11-19 rulings C, D, F; closing review P2-11):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13c-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/ua-rs/src/wallet/policy.rs"
O = "clients/scaas-sdk/src/wallet/ops.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
W = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test wallet_ops "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
CHECK = '|| !same(get(&m, "entryRef"), &[0u8; 32]) || uint(get(&m, "batch"))? != lane {'
MUTANTS = [
    ("C: Expect::Execute keeps the message's data", [(P, '            m.insert("data".into(), to_hex(&data).into());\n', "")],
     UA + "execute_signs_only_the_decoded_call"),
    ("D: Expect::Transfer accepts a payment's entryRef",
     [(P, CHECK, '|| uint(get(&m, "batch"))? != lane {'), (P, '    msg.insert("entryRef".into(), to_hex(&[0u8; 32]).into());\n', "")],
     UA + "transfer_is_entry_ref_zero_on_the_named_lane"),
    ("D: Expect::Transfer accepts another lane",
     [(P, CHECK, '|| !same(get(&m, "entryRef"), &[0u8; 32]) {'), (P, '    msg.insert("batch".into(), dec(&lane));\n', "")],
     UA + "transfer_is_entry_ref_zero_on_the_named_lane"),
    ("D: the transfer on ids keeps a payment's entryRef",
     [(O, 'm.insert("entryRef".into(), json!(hex(&[0u8; 32])));', 'm.insert("entryRef".into(), json!(hex(&scaas_ua::keccak256(b"x"))));')],
     W + "transfer_on_ids_is_its_vector_and_posts_ua_metatx"),
    ("D: a pay's salt left out is random",
     [(O, "None => derived_salt(m, context),", "None => { let _ = context; let mut b = [0u8; 32]; getrandom::getrandom(&mut b).map_err(|_| SdkError::Internal)?; b }")],
     W + "pay_salt_derived_from_the_request"),
    ("D: the derived salt ignores the request",
     [(O, "for part in context.iter().copied().chain([fields.as_str()]) {", "for part in [fields.as_str()] {")],
     W + "pay_salt_derived_from_the_request"),
    ("F: a relay fee's job without its call", [(S, "        b.op = Some(relay_fee_op(&b, &call)?);\n", "        let _ = call;\n")],
     W + "relay_fee_job_carries_its_call"),
]

if __name__ == "__main__":
    main("t13c", MUTANTS)
