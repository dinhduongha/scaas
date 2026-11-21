# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan V9 on the SDK's generic surface: each check of the passphrase's bytes (RFC 8265 OpaqueString, then NFC)
before Argon2id: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-v9-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

AK = "clients/ua-rs/src/wallet/appkey.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test app_core_vault_rows "
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
]

if __name__ == "__main__":
    main("v9", MUTANTS)
