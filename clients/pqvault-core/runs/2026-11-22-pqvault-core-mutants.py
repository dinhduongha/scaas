# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan V10 / V10e: a mutant of each refusal and check of pqvault-core, the scaas-sdk plan's `mutants_lib` with this
crate's record: python3 clients/pqvault-core/runs/2026-11-22-pqvault-core-mutants.py check | run [name…]. The e2e mutants
run one anvil test each (capped, foreground, the anvil stopped with the test)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/pqvault-core/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-22-pqvault-core-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-22-pqvault-core-summary.txt"]

C = "clients/pqvault-core/src/content.rs"
K = "clients/pqvault-core/src/keys.rs"
RC = "clients/pqvault-core/src/records.rs"
V = "clients/pqvault-core/src/vault.rs"
LB = "clients/pqvault-core/src/lib.rs"
CD = "cd clients/pqvault-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
VEC = CD + "--features vectors --test vectors "
CORE = CD + "--test core "
LIB = CD + "--lib "
E2E = CD + "--test e2e -- --ignored --exact "

MUTANTS = [
    # refusals before any work (P1, VC18) and the item's bounds
    (
        "P1 without the word count and its warning",
        [
            (
                LB,
                """                && s.class == "full"
                && s.words == 24
                && !s.warnings.iter().any(|w| w == "below-24-words")""",
                '''                && s.class == "full"''',
            )
        ],
        CORE + "p1_refusals_before_any_call",
    ),
    (
        "P1 taking a classical kind",
        [(LB, "        if !is_pq_kind(*kind) {", "        if false {")],
        CORE + "p1_refusals_before_any_call",
    ),
    (
        "a pending vault unlocked",
        [(V, "        if s.pending {\n", "        if false {\n")],
        CORE + "pending_and_unverified_never_unlock",
    ),
    (
        "a short passphrase taken",
        [
            (
                V,
                "            if n.map_err(|_| Error::PassphraseInvalid)? < 16 {",
                "            if n.map_err(|_| Error::PassphraseInvalid)? < 15 {",
            )
        ],
        CORE + "passphrase_length",
    ),
    # bounded and canonical decoders
    (
        "the padding not compared on read",
        [(C, "        Ok(q) if q == p => Ok(c.to_vec()),", "        Ok(_) => Ok(c.to_vec()),")],
        LIB + "content::tests::pad_buckets_and_unpad_refusals",
    ),
    (
        "canonical JSON not compared on read",
        [(C, "        Ok(s) if s.as_bytes() == b => Ok(v),", "        Ok(_) => Ok(v),")],
        LIB + "content::tests::parse_canonical_refuses_other_spellings",
    ),
    (
        "an unsafe integer written",
        [(C, "                .map(|x| x <= SAFE)", "                .map(|_| true)")],
        LIB + "content::tests::canonical_sorts_by_utf16_and_refuses_unsafe_numbers",
    ),
    (
        "a title past 256 B written",
        [(C, """len_in(o.get("title"), 1, 256)""", """len_in(o.get("title"), 1, 257)""")],
        LIB + "content::tests::item_bounds",
    ),
    # the key schedule and the bytes (vectors)
    (
        "the item AAD without its author",
        [
            (
                RC,
                "        version,\n        alloy::primitives::B256::from(author.0),",
                "        version,\n        alloy::primitives::B256::ZERO,",
            )
        ],
        VEC + "item_versions_and_refusals",
    ),
    (
        "the vault id without its mode",
        [(RC, "        alloy::primitives::U256::from(mode),", "        alloy::primitives::U256::ZERO,")],
        VEC + "records_ids_scopes_and_digests",
    ),
    (
        "the item key of another usage (KeyWrap)",
        [
            (
                K,
                '        lbl("item"),\n        ctx,\n        U::Data,',
                '        lbl("item"),\n        ctx,\n        U::KeyWrap,',
            )
        ],
        VEC + "item_versions_and_refusals",
    ),
    (
        "an unknown passKdf taken",
        [(K, "    if pass_kdf != 1 {\n        return Err(Error::PassKdfUnknown);\n    }\n", "")],
        VEC + "passphrase_keys",
    ),
    (
        "K_v without the passKdf in its info",
        [
            (
                K,
                "    let ctx = [&vault.0[..], &epoch.0, &pass_kdf.to_be_bytes()].concat();",
                "    let ctx = [&vault.0[..], &epoch.0].concat();",
            )
        ],
        VEC + "key_schedule",
    ),
    (
        "a tombstone migrated",
        [
            (
                V,
                '== Some("deleted") => {\n                        skipped += 1\n                    }',
                '== Some("never") => {}',
            )
        ],
        CORE + "migration_plan_and_warning",
    ),
    # V10e's decryption checks, on anvil
    (
        "the wrap-hash check skipped",
        [
            (
                V,
                "                if e.wrap_hashes.get(j) != Some(&wrap_hash(w))\n                    || w.member != s.me",
                "                if w.member != s.me",
            )
        ],
        E2E + "shared_vault_both_modes",
    ),
    (
        "the signature chain not checked",
        [(V, "                    || !self.verify_sig(&s, e.author, &rec, &e.sig).await?\n", "")],
        E2E + "shared_vault_both_modes",
    ),
    (
        "the replica's versions not compared",
        [
            (
                V,
                "            let Ok(h) = self.version_at(&home.at, item, n).await else {\n                return Ok(false);\n            };",
                "            let Ok(h) = self.version_at(&home.at, item, n).await else {\n                continue;\n            };",
            )
        ],
        E2E + "shared_vault_both_modes",
    ),
    (
        "the sealedInfo tag not checked (a wrong passphrase taken)",
        [
            (
                V,
                "            None => Ok(Some(false)),",
                "            None => {\n                u.keys.insert(e.id, kv);\n                Ok(Some(true))\n            }",
            )
        ],
        E2E + "personal_vault_recovery_conflict_passphrase",
    ),
    (
        "a version opened under another epoch's K_v",
        [
            (
                V,
                "        let kv = v.keys.get(&epoch).ok_or(Error::Unreadable)?;\n        keys::decrypt_item(",
                "        let kv = v.keys.values().next_back().ok_or(Error::Unreadable)?;\n        keys::decrypt_item(",
            )
        ],
        E2E + "personal_vault_recovery_conflict_passphrase",
    ),
    (
        "a lower version count taken (rollback)",
        [
            (
                V,
                "let prev = seen.items.entry(id).or_insert(n);\n        if n < *prev {",
                "let prev = seen.items.entry(id).or_insert(n);\n        if false {",
            )
        ],
        E2E + "shared_vault_both_modes",
    ),
    (
        "the prev key not checked against its epoch",
        [(V, "            match (back, pinfo) {", "            match (back, pinfo.or(Some(Value::Null))) {")],
        E2E + "personal_vault_recovery_conflict_passphrase",
    ),
]

if __name__ == "__main__":
    L.main("v10", MUTANTS)
