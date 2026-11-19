# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T16 part 3 (the controller calls P-T16-1..5 of 2026-11-19): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t16c-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/ua-rs/src/wallet/policy.rs"
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
D = "clients/scaas-sdk/src/confidential/pqz_debit.rs"
Q = "clients/scaas-sdk/src/confidential/pqz.rs"
O = "clients/scaas-sdk/src/op/quote.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential_pqz "
MUTANTS = [
    ("P-T16-1: PqzAuth under metatx (the old mapping)",
     [(P, '        "PqzRollOver" | "PqzAuth" => "zether-auth",\n', '        "PqzRollOver" => "zether-auth",\n')],
     U + "owner_statements_sign_under_their_contract_purpose"),
    ("PqzAuth's op word always op 1",
     [(D, "let auth = pqz_auth_message(op, &stmt)?;", "let auth = pqz_auth_message(1, &stmt)?;")],
     T + "pqz_transfer_multi_pairs"),
    ("an OFFCHAIN debit attaches no verdict",
     [(D, "let verdict = if offchain {", "let verdict = if false {")],
     T + "pqz_auth_attached_by_the_facade"),
    ("the transfer's envelope word without the form's mode",
     [(D, '("proveTransfer", 1u8, bind_mode(&binding, mode, verification))', '("proveTransfer", 1u8, binding)')],
     T + "pqz_auth_attached_by_the_facade"),
    ("vTo and vFrom swapped",
     [(D, 'args.insert("vTo".into(), json!(part(&stmt, off + pkl, v)?));', 'args.insert("vTo".into(), json!(part(&stmt, off + pkl + v, v)?));')],
     T + "pqz_auth_attached_by_the_facade"),
    ("a Compact entry in the token's default form",
     [(D, 'let hash = d.name.ends_with("Compact") || sfield', 'let hash = sfield')],
     T + "pqz_transfer_single_pairs"),
    ("the proof on the async worker",
     [(Q, "    let out = sdk\n        .heavy(move || {\n            let (_seed, k) = key;\n            Ok(k.call(cmd, &body)?)\n        })\n        .await?;",
       "    let out = (move || -> Result<String, SdkError> {\n            let (_seed, k) = key;\n            Ok(k.call(cmd, &body)?)\n        })()?;")],
     T + "proof_runs_off_the_async_workers"),
    ("a PQZ debit through the gateway",
     [(O, ' && !(p.t.kind == "pqz" && PQZ_DEBITS.contains(&p.t.name))', "")],
     T + "pqz_unshield_pairs"),
    ("P-T16-4: an opening token is a set mismatch",
     [(Q, "    if r.psid == PQZL_SPLIT_ID {", "    if false && r.psid == PQZL_SPLIT_ID {")],
     T + "opening_token_refused"),
    ("a recipient key the token would refuse",
     [(Q, "let ok = (record[11] == 1 || offchain) && code.len()", "let ok = true || (record[11] == 1 || offchain) && code.len()")],
     T + "pqz_transfer_single_pairs"),
]

if __name__ == "__main__":
    main("t16c", MUTANTS)
