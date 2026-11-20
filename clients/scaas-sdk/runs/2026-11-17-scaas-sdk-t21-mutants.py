# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T21, the app-core surface: ua-rs's key handles (the usage check, the key-wrap constant, the scope, the public MAC's
origin, the arena's limit, the KEM wrap's info) and clientkeys' twins:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t21-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

AK = "clients/ua-rs/src/wallet/appkey.rs"
ST = "clients/ua-rs/src/wallet/store.rs"
CK = "clients/clientkeys/src/appcore.js"
UT = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test app_core "
CT = "cd clients/clientkeys && ../../scripts/capped node --test --test-reporter=tap test/appcore.test.js"
MUTANTS = [
    (
        "drop the usage check",
        [
            (
                AK,
                "        if h.usage != usage {\n            return Err(Error::AppKeyUsage);",
                "        if false {\n            return Err(Error::AppKeyUsage);",
            )
        ],
        UT + "seal_rows_and_usage_refusals",
    ),
    (
        "seal accepts an aad starting with the key-wrap constant",
        [(AK, "    if aad.starts_with(KEYWRAP) {", "    if false {")],
        UT + "seal_rows_and_usage_refusals",
    ),
    (
        "drop the key-wrap constant from seal_key's AAD",
        [(AK, "    [KEYWRAP, &[usage as u8], aad].concat()", "    [&[usage as u8][..], aad].concat()")],
        UT + "seal_key_rows",
    ),
    (
        "drop the usage byte from seal_key's AAD",
        [(AK, "    [KEYWRAP, &[usage as u8], aad].concat()", "    [KEYWRAP, aad].concat()")],
        UT + "seal_key_rows",
    ),
    (
        "mix the usage into derive's info",
        [
            (
                AK,
                "        let okm = hkdf_sha256(&ikm, salt, info, if nonce { 44 } else { 32 })?;",
                "        let info = [info, &[usage as u8]].concat();\n"
                "        let okm = hkdf_sha256(&ikm, salt, &info, if nonce { 44 } else { 32 })?;",
            )
        ],
        UT + "derive_and_mac_rows",
    ),
    (
        "accept a foreign handle",
        [(AK, "        if h.scope != self.scope || !h.h.same_store(&self.store) {", "        if false {")],
        UT + "scope_arena_and_lock",
    ),
    (
        "the public MAC on a derived key",
        [(AK, "        if key.origin == Origin::Derived {", "        if false {")],
        UT + "derive_and_mac_rows",
    ),
    (
        "no arena limit",
        [(ST, "        if a.app_live >= max {", "        if false {")],
        UT + "scope_arena_and_lock",
    ),
    (
        "a destroyed handle's slot not freed",
        [
            (
                ST,
                "                a.app_live = a.app_live.saturating_sub(1);",
                "                a.app_live = a.app_live;",
            )
        ],
        UT + "scope_arena_and_lock",
    ),
    (
        "the KEM wrap's info without keccak256(kemPk)",
        [
            (
                AK,
                "    let info = [label, aad, &[1u8], &crate::keccak256(kem_pk)].concat();",
                "    let info = [label, aad, &[1u8]].concat();",
            )
        ],
        UT + "argon2_kem_and_root_rows",
    ),
    (
        "clientkeys: seal accepts the key-wrap prefix",
        [
            (
                CK,
                '  if (startsWith(bytes(aad), KEYWRAP)) throw new AppCoreError("AppKeyUsage");\n  return gcmsiv(bytes(key), bytes(nonce), bytes(aad)).encrypt',
                "  return gcmsiv(bytes(key), bytes(nonce), bytes(aad)).encrypt",
            )
        ],
        CT,
        "seal and open rows; an aad starting with the key-wrap constant refused",
    ),
]

if __name__ == "__main__":
    main("t21", MUTANTS)
