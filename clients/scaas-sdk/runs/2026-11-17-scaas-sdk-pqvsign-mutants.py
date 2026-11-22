# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault's dedicated signing path (owner 2026-11-22, CLI-PQV-13): each refusal of `ua-rs`'s `wallet::pqvault`, the generic
app signing's refusals of PqVault's records, and the SDK's routing of its two calls:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-pqvsign-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

PV = "clients/ua-rs/src/wallet/pqvault.rs"
US = "clients/ua-rs/src/wallet/uasig.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test app_core "
S = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features app-core --test app_core_vault_records "
MUTANTS = [
    (
        "a PqVault name with another encodeType accepted",
        [(PV, ".any(|(n, s)| *n == t && typed.encode_type() == *s)", ".any(|(n, _s)| *n == t)")],
        U + "pqvault_sign_refusals",
    ),
    (
        "a struct outside PqVault's records accepted",
        [(PV, "    if !RECORDS\n", "    if false && !RECORDS\n")],
        U + "pqvault_sign_refusals",
    ),
    (
        "the domain's path not checked",
        [(PV, "    if path_of(typed).as_ref() != Some(path) {", "    if path_of(typed).is_none() {")],
        U + "pqvault_sign_refusals",
    ),
    (
        "another domain name accepted",
        [(PV, "d.get(\"name\")?.as_str()? != DOMAIN_NAME || ", "")],
        U + "pqvault_sign_refusals",
    ),
    (
        "another domain version accepted",
        [(PV, " || d.get(\"version\")?.as_str()? != DOMAIN_VERSION", "")],
        U + "pqvault_sign_refusals",
    ),
    (
        "DS_V's separator not checked (another salt)",
        [(PV, "(typed.domain_separator().ok()? == ds_v())", "true")],
        U + "pqvault_sign_refusals",
    ),
    (
        "the chain-bound path under the app id, not P_V",
        [(PV, "Some(AppPath::ChainBound { purpose: purpose() })", "Some(AppPath::ChainBound { purpose: app_id() })")],
        U + "pqvault_records_reproduce_the_vectors",
    ),
    (
        "the generic portable path accepting a SCaaS app id",
        [(US, "            if is_scaas_purpose(&app_purpose(app_id)?) {", "            if false {")],
        U + "pqvault_sign_refusals",
    ),
    (
        "P_V not a SCaaS purpose",
        [(US, "            .any(|(_, s)| app_purpose(&keccak256(s.as_bytes())).ok() == Some(*purpose))", "            .any(|_| false)")],
        U + "pqvault_sign_refusals",
    ),
    (
        "the SDK's PqVault signing on the generic digest",
        [(AC, "            scaas_ua::wallet::pqvault::digest,", "            scaas_ua::wallet::app_record_digest,")],
        S + "typed_digests_in_both_domains",
    ),
    (
        "the SDK's PqVault signing by the generic signer",
        [(AC, "            scaas_ua::wallet::pqvault::sign,", "            scaas_ua::wallet::sign_app_record,")],
        S + "signing_paths_by_the_pqv_account",
    ),
    (
        "the SDK's PqVault verification by the generic one",
        [(AC, "            scaas_ua::wallet::pqvault::verify,", "            scaas_ua::wallet::verify_app_record,")],
        S + "verify_app_record_on_the_committed_rows",
    ),
    (
        "the SDK's generic signing on PqVault's path",
        [
            (
                AC,
                "            scaas_ua::wallet::app_record_digest,\n            scaas_ua::wallet::sign_app_record,",
                "            scaas_ua::wallet::pqvault::digest,\n            scaas_ua::wallet::pqvault::sign,",
            )
        ],
        S + "pqvault_path_refusals",
    ),
    (
        "the SDK's generic verification on PqVault's path",
        [(AC, "            scaas_ua::wallet::verify_app_record,\n", "            scaas_ua::wallet::pqvault::verify,\n")],
        S + "pqvault_path_refusals",
    ),
]

if __name__ == "__main__":
    main("pqvsign", MUTANTS)
