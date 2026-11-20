#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 17 mutants (scaas-sdk signer kind 0x0121; ua-rs sign_scaas_bls_multi). From the worktree root:
python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

SDK = "clients/scaas-sdk"
B = SDK + "/src/op/bls_multi.rs"
Q = SDK + "/src/op/quote.rs"
G = SDK + "/src/op/gas.rs"
TS = ["../../scripts/capped", "cargo", "test", "--locked", "--lib", "bls_multi"]
TG = ["../../scripts/capped", "cargo", "test", "--locked", "--lib", "gas_attached_unknown"]
UA = "clients/ua-rs"
P = UA + "/src/wallet/policy.rs"
TU = ["../../scripts/capped", "cargo", "test", "--locked", "--features", "wallet", "--test", "sign_scaas", "bls_multi"]
M = [
    ("job op keeps the 160-byte UASig", B, "                *v = named.clone();\n                return 1;", "                return 1;",
     TS, SDK, "bls_multi_sign_collect_aggregate_submit"),
    ("aggregate always surplus", B, "bls_multi::aggregate(&d, &ua_msg, &parts, surplus)", "bls_multi::aggregate(&d, &ua_msg, &parts, true)",
     TS, SDK, "bls_multi_stored_path_minimal"),
    ("quote reads no members", Q, '("members", Some(n)) => Some(n),', '("members", Some(_)) => None,', TS, SDK,
     "bls_multi_stored_path_minimal"),
    ("member of another group accepted", B, "    if key_data(member)? != d {\n        return Err(SdkError::Argument);\n    }\n", "",
     TS, SDK, "bls_multi_sign_collect_aggregate_submit"),
    ("registration keeps the quote's gas", B, "let gas = quote.gas_limit.max(super::gas::with_margin(est));",
     "let gas = quote.gas_limit.max(est - est);", TS, SDK, "bls_multi_register_sends_the_pop"),
    ("registration quote without per_item", G, "&& n <= COUNT_MAX => p.gas.saturating_mul(n),", "&& n <= COUNT_MAX => 0,",
     TS, SDK, "bls_multi_register_quote_by_n"),
    ("unknown attached kind: members unread", G, 'items(p, &|i| (i == "members").then_some(BLS_MULTI_MAX))',
     "items(p, &|_| None)", TG, SDK, "gas_attached_unknown_counts_members_at_the_cap"),
    ("member signs without the check", P, "    if check(td, &expect)? != td.digest()? {\n        return Err(Error::PolicyRefused);\n    }\n    key.sign_request",
     "    key.sign_request", TU, UA, "bls_multi_member_signs_under_the_check"),
    ("member signs under another purpose", P, "        message: scaas_bls_multi_message(td)?,",
     "        message: crate::ua_message(crate::bls_multi::KIND, &crate::purpose_tag(\"trade\")?, &td.digest()?).map_err(|_| Error::Argument)?,",
     TU, UA, "bls_multi_member_signs_under_the_check"),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
