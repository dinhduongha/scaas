# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T12 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t12-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

O = "clients/scaas-sdk/src/wallet/ops.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
E = "clients/ua-rs/src/wallet/entries/token.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test wallet_ops "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
PAYEE = ("                    Ok(Expect::PayeeFee {\n                        payee,\n                        chain_id,\n                        chain_uid,\n"
         "                        amount: amount.clone(),\n                        decimals: 0,\n                        entry_ref,\n"
         "                        expected_token: token,\n                        max_fee: fee.clone(),\n                        fee_recipient,\n"
         "                        now,\n                        max_window,\n                    })")
AS_PAYMENT = ("                    Ok(Expect::Payment {\n                        account: payee,\n                        chain_id,\n                        chain_uid,\n"
              "                        amount: amount.clone(),\n                        decimals: 0,\n                        payee,\n                        entry_ref,\n"
              "                        expected_token: token,\n                        max_fee: fee.clone(),\n                        fee_recipient: Some(fee_recipient),\n"
              "                        relayer: None,\n                        now,\n                        max_window,\n                    })")
SAVE = ("        field(\n            \"save\",\n            &m.save.to_string(),\n            &m.save.to_string(),\n            Source::Signed,\n        ),\n")
MUTANTS = [
    # the plan's three
    ("drop save from the review", [(O, SAVE, "")], T + "pay_with_paymeta_v3"),
    ("sign UAPayeeFee with the payment's Expect", [(O, PAYEE, AS_PAYMENT)], T + "every_wallet_pair_is_its_vector"),
    ("accept an undecoded UAExecute", [(O, "                        if allow.is_none() {\n                            return Err(SdkError::OpaqueCallRefused);",
                                         "                        if false {\n                            return Err(SdkError::OpaqueCallRefused);")],
     T + "ua_execute_decoded_only"),
    # each check of the task
    ("the domain's salt not compared", [(O, "|| hex(word(&b, 5)?) != profile.chain_uid.to_ascii_lowercase()", "|| false")],
     T + "domain_kind_from_the_contract"),
    ("the transfer on ids posted to /v1/op (ruling 6)", [(S, 'let outcome = if row.entry == "mtxExecuteTransfer" {', "let outcome = if false {")],
     T + "transfer_on_ids_is_its_vector_and_posts_ua_metatx"),
    ("the transfer on ids signs bytes (ruling 6)", [(E, '"bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,E", "$ @");',
                                                     '"bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,E", "$ @bytes");')],
     UA + "entries_transfer_on_ids"),
    ("an id not padded: the address as from", [(O, "            if t == \"address\" {\n                hex(&a)", "            if true {\n                hex(&a)")],
     T + "unbound_relayer_is_zero"),
]

if __name__ == "__main__":
    main("t12", MUTANTS)
