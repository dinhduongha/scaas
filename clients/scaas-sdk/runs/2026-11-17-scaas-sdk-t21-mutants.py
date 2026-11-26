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
US = "clients/ua-rs/src/wallet/uasig.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
UP = "clients/ua-rs/src/ua_portable.rs"
PR = "clients/scaas-sdk/src/pqchat_records.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records"
ST_ = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test app_core "
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
        [(AK, "        if !matches!(key.origin, Origin::Drawn | Origin::Unwrapped) {", "        if false {")],
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
    (
        "drop the purpose-list check",
        [(US, "            if is_scaas_purpose(purpose) {", "            if false {")],
        UT + "app_record_paths_and_refusals",
    ),
    (
        "the seal purpose not refused",
        [(US, "        || *purpose == crate::seal_purpose_tag()\n", "")],
        UT + "app_record_paths_and_refusals",
    ),
    (
        "drop the domain-name check",
        [(US, "    if super::app_refusals::SCAAS_DOMAIN_NAMES.contains(&name) {", "    if false {")],
        UT + "app_record_paths_and_refusals",
    ),
    (
        "accept any portable field set",
        [(US, '            if keys != ["name", "salt", "version"] {', "            if false {")],
        UT + "app_record_paths_and_refusals",
    ),
    (
        "accept any salt",
        [
            (
                US,
                "            if !salt.is_some_and(|s| s.eq_ignore_ascii_case(&eip712::to_hex(app_id))) {",
                "            if false {",
            )
        ],
        UT + "app_record_paths_and_refusals",
    ),
    (
        "drop the chain-bound domain's contract check",
        [
            (
                US,
                '            if !(d.contains_key("chainId") && d.contains_key("verifyingContract")) {',
                "            if false {",
            )
        ],
        UT + "app_record_paths_and_refusals",
    ),
    (
        "the generated purpose list loses a constant",
        [
            (
                "clients/ua-rs/src/wallet/app_refusals.rs",
                '    ("PURPOSE_KEM", "scaas.ua.purpose.kem.v1"),\n',
                "",
            )
        ],
        UT + "refusal_lists_match_the_contracts",
    ),
    (
        "sdk: accept any label",
        [(AC, "        ok.then_some(()).ok_or(SdkError::AppLabelRefused)", "        Ok(())")],
        ST_ + "labels_scope_and_handles",
    ),
    (
        "sdk: allow an overlapping prefix",
        [(AC, "        if own || other {", "        if false {")],
        ST_ + "labels_scope_and_handles",
    ),
    (
        "sdk: accept a foreign handle",
        [(AC, "        (k.core == self.id)", "        (k.core == k.core)")],
        ST_ + "labels_scope_and_handles",
    ),
    (
        "sdk: a chain step may rebuild a labelled key",
        [
            (
                AC,
                "            .any(|p| data.starts_with(p.as_bytes()))",
                "            .any(|p| p.is_empty() && data.starts_with(p.as_bytes()))",
            )
        ],
        ST_ + "labels_scope_and_handles",
    ),
    (
        "sdk: drop the chainId check",
        [(AC, "        if id.as_deref() != Some(&chain_id.to_string()) {", "        if false {")],
        ST_ + "app_records_both_paths",
    ),
    (
        "sdk: drop the verifyingContract check",
        [(AC, "        if listed {", "        if false {")],
        ST_ + "app_records_both_paths",
    ),
    (
        "sdk: kem_wrap reads as a plain read",
        [
            (
                AC,
                "            Purpose::FeedsDecryption,\n            |pool, at, line| async move {\n                let to = line.holder(",
                "            Purpose::Plain,\n            |pool, at, line| async move {\n                let to = line.holder(",
            )
        ],
        ST_ + "kem_wrap_to_a_ua_reads_its_key_at_the_final_block",
    ),
    (
        "sdk: kem_wrap accepts any scheme",
        [(AC, "    if scheme != 1 {", "    if false {")],
        ST_ + "kem_wrap_to_a_ua_reads_its_key_at_the_final_block",
    ),
    (
        "sdk: drop the factory-class check",
        [(AC, "        if class != 0 && Some(class) != self.class.map(usize::from) {", "        if false {")],
        ST_ + "factory_instance_of_another_class_refused",
    ),
    (
        "sdk: prepare_app_call without the contract check",
        [
            (
                AC,
                "        self.refuse_contract(&profile, &pool, &contract).await?;",
                "        let _ = (&profile, &pool);",
            )
        ],
        ST_ + "prepare_app_call_builds_named_calldata",
    ),
    (
        "sdk: verify reads no domain",
        [(AC, "        let domain = needs_domain\n            .then(", "        let domain = false\n            .then(")],
        ST_ + "verify_app_record_reads_the_registry",
    ),
    (
        "sdk: verify ignores the enabled bits",
        [
            (
                AC,
                "                *b = enabled.get(i).copied().unwrap_or(0) & accepted.get(i).copied().unwrap_or(0);",
                "                *b = accepted.get(i).copied().unwrap_or(0);",
            )
        ],
        ST_ + "verify_app_record_reads_the_registry",
    ),
    (
        "ua-rs: a portable msig signature need not be minimal",
        [
            (
                UP,
                "    pop: bool,\n    cx: &Cx,\n    bits: &Bits,\n) -> Result<bool> {\n    if !msig_slots_minimal(d, &slots.iter().map(|s| s.index).collect::<Vec<_>>())? {",
                "    pop: bool,\n    cx: &Cx,\n    bits: &Bits,\n) -> Result<bool> {\n    if false {",
            )
        ],
        UT + "verify_app_record_signers",
    ),
    (
        "ua-rs: a portable msig slot need not be accepted",
        [(UP, "        if !(pop || bits.record(ua, s.index))", "        if !(pop || true)")],
        UT + "verify_app_record_signers",
    ),
    (
        "ua-rs: a single key's key data not checked against the id",
        [
            (
                US,
                "    if derive_ua(kind, &key, false).ok() != Some(*ua) || !sig.members.is_empty() {",
                "    if !sig.members.is_empty() {",
            )
        ],
        UT + "verify_app_record_signers",
    ),
    (
        "sdk: an entry taking wrapHashes from the caller",
        [(PR, "            Ok(hex(&pqchat::wrap_hash(v)?))", "            Ok(w.member.clone())")],
        ST_.replace("--test app_core", "--test pqchat_records") + "entries_reproduce_the_vectors",
    ),
]

if __name__ == "__main__":
    main("t21", MUTANTS)
