# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan V9 on the SDK's generic surface: each check of the passphrase's bytes (RFC 8265 OpaqueString, then NFC)
before Argon2id (part 1); the records' typed digests in both domains, the signing and verifying paths and an msig's native
seat (part 2, records.json): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-v9-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

AK = "clients/ua-rs/src/wallet/appkey.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test app_core_vault_rows "
AC = "clients/scaas-sdk/src/app_core.rs"
E7 = "clients/ua-rs/src/wallet/eip712.rs"
US = "clients/ua-rs/src/wallet/uasig.rs"
UP = "clients/ua-rs/src/ua_portable.rs"
R = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features app-core --test app_core_vault_records "
MUTANTS = [
    ("the passphrase without NFC", [(AK, "    out.extend(mapped.nfc());", "    out.extend(mapped.chars());")], T + "passphrase_rows"),
    (
        "the passphrase's non-ASCII spaces kept",
        [(AK, "s.chars().map(|c| if ZS.contains(&c) { ' ' } else { c })", "s.chars()")],
        T + "passphrase_rows",
    ),
    (
        "a control character accepted",
        [(AK, "    if out.is_empty() || out.chars().any(char::is_control) {", "    if out.is_empty() {")],
        T + "passphrase_rows",
    ),
    (
        "an empty passphrase accepted",
        [(AK, "    if out.is_empty() || out.chars().any(char::is_control) {", "    if out.chars().any(char::is_control) {")],
        T + "passphrase_rows",
    ),
    (
        "bytes that are not UTF-8 accepted",
        [
            (
                AK,
                "    let s = std::str::from_utf8(passphrase).map_err(|_| Error::Argument)?;",
                "    let lossy = String::from_utf8_lossy(passphrase);\n    let s: &str = &lossy;",
            )
        ],
        T + "passphrase_rows",
    ),
    (
        "a struct's referenced types left out of its type hash",
        [(E7, ".chain(deps.iter().map(String::as_str))", ".chain(deps.iter().map(String::as_str).take(0))")],
        R + "typed_digests_in_both_domains",
    ),
    (
        "the domain separator over its first two fields only",
        [
            (
                E7,
                "        for (n, ty) in &fields {\n            enc.extend_from_slice(&encode_atom(ty, self.domain.get(n))?);",
                "        for (n, ty) in fields.iter().take(2) {\n            enc.extend_from_slice(&encode_atom(ty, self.domain.get(n))?);",
            )
        ],
        R + "typed_digests_in_both_domains",
    ),
    (
        "the chain-bound signature under the app id, not its purpose",
        [
            (
                AC,
                "            None => {\n                scaas_ua::ua_portable::app_purpose(&app_id).map_err(|e| SdkError::Ua(e.into()))?\n            }",
                "            None => app_id,",
            )
        ],
        R + "signing_paths_by_the_pqv_account",
    ),
    (
        "the chain-bound verification under the app id, not its purpose",
        [
            (
                AC,
                "                        None => scaas_ua::ua_portable::app_purpose(\n"
                "                            &self.app_id.ok_or(SdkError::Argument)?,\n"
                "                        )\n"
                "                        .map_err(|e| SdkError::Ua(e.into()))?,",
                "                        None => self.app_id.ok_or(SdkError::Argument)?,",
            )
        ],
        R + "verify_app_record_on_the_committed_rows",
    ),
    (
        "a stored kind's key taken from the signature, not the record",
        [(US, "        (true, true) => key_data,", "        (true, true) => sig.key_data.clone(),")],
        R + "verify_app_record_on_the_committed_rows",
    ),
    (
        "an msig seat counted without its accepted bit",
        [
            (
                AC,
                "let accepted = |x: [u8; 32], i: u16| recs.get(&x).is_some_and(|r| bit(&r.active, i));",
                "let accepted = |x: [u8; 32], _i: u16| recs.contains_key(&x);",
            )
        ],
        R + "native_member_in_an_msig",
    ),
    (
        "a native seat's signature over the member digest, not the typed digest",
        [
            (
                UP,
                'crate::verify::native_ecdsa(m.id[12..].try_into().expect("20 bytes"), digest, sig)',
                'crate::verify::native_ecdsa(m.id[12..].try_into().expect("20 bytes"), md, sig)',
            )
        ],
        R + "native_member_in_an_msig",
    ),
]

if __name__ == "__main__":
    main("v9", MUTANTS)
