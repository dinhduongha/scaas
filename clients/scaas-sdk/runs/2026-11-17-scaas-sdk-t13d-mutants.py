# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T13d mutants (closing review P2-2, P2-4, P2-7, P2-8, P2-10, the P3s; owner 2026-11-19 ruling E):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13d-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

V = "clients/scaas-sdk/src/vault"
OP = "clients/scaas-sdk/src/op"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
C = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
L = C + "--lib "
P = "clients/ua-rs/src/wallet/policy.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
MUTANTS = [
    ("P2-2: the rollback verdict not emitted", [(f"{V}/unlock.rs", "        if l.rollback {", "        if false {")],
     C + "--test vault rollback_is_shown"),
    ("E: a new label takes format characters", [(f"{V}/keystore.rs", "label_ok(label) && !label.chars().any(crate::text::hidden)", "label_ok(label)")],
     C + "--test vault seed_labels_refuse_format_characters"),
    ("P2-7: the import's write unchecked against the stored seed",
     [(f"{V}/seeds.rs", "if e.vaults.contains_key(&label)\n                                || e.vaults.get(\"manifest\") != manifest_read.as_ref()\n", "if false\n")],
     C + "--test vault import_key_two_sdks_one_store"),
    ("P2-7: a failed import leaves the seed open", [(f"{V}/seeds.rs", "if taken.load(std::sync::atomic::Ordering::SeqCst) {", "if false {")],
     L + "import_key_failed_write_leaves_no_ghost_import"),
    ("P2-8: the policy dropped at enable", [(f"{V}/prf.rs", "                    Some(policy),\n", "                    None,\n")],
     C + "--test passkey platform_secret_unlock"),
    ("P2-4: the check capped at the rate", [(f"{OP}/prepared.rs", "scaas_ua::wallet::fee_due(d.name, &canonical)?", "env.get(\"fee\").map(dec).transpose()?.unwrap_or_default().to_string()")],
     C + "--test wallet_ops percent_fee_is_reviewed_as_its_amount"),
    ("P2-4: fee_due returns the rate", [(P, "    Ok(u256_to_dec(&fee_of(&env, basis.as_ref())?))\n}", "    let _ = basis;\n    Ok(u256_to_dec(&uint(get(&env, \"fee\"))?))\n}")],
     UA + "fee_due_is_the_amount_the_check_charges"),
    ("P3: an unbounded ABI offset", [("clients/scaas-sdk/src/wallet/tokens.rs", "let start = off.checked_add(32).ok_or(SdkError::Argument)?;", "let start = off + 32;")],
     L + "abi_string_offset_overflow_is_refused"),
    ("P3: a registry answer by its last byte", [("clients/scaas-sdk/src/account/restore.rs",
      "let registered = out.len() == 32\n                                && out.get(..31).is_some_and(|h| h.iter().all(|b| *b == 0))\n                                && out.last() == Some(&1);",
      "let registered = out.last() == Some(&1);")],
     C + "--test account restore_reads_a_whole_bool_word"),
    ("P3: the prepared table never pruned", [(f"{OP}/prepared.rs", "        table.retain(|_, q| q.expires_at > now);\n", "")],
     L + "the_prepared_table_drops_expired_entries"),
    ("P3: no nonce floor of the session's own sends", [(f"{OP}/quote.rs", ".await?.max(floor);", ".await?.max(0 * floor);")],
     L + "a_second_self_relay_takes_the_next_nonce"),
    ("P3: a native send signs with the quote's payer",
     [("clients/scaas-sdk/src/wallet/native_evm.rs", "if !signs_with_key || format!", "if format!")],
     C + "--test wallet native_send_signs_with_the_reviewed_key_only"),
    ("P3: a discovered first endpoint is decisive",
     [(f"{OP}/follow.rs", "let decisive =\n                        strict || (a.members == [0] && pool.pool().class(0) != Class::Discovered);", "let decisive =\n                        strict || a.members == [0];")],
     L + "a_non_decisive_read_is_never_terminal"),
    ("P3: resend ignores a bound relayer", [(f"{OP}/submit.rs", "                        if row.relayer_bound {", "                        if false {")],
     L + "resend_with_a_bound_relayer_is_refused"),
    ("P2-10: a spike call exported again",
     [("clients/scaas-sdk/ffi/src/api/mod.rs", "pub fn api_version() -> u32 {", "pub fn spike_any() {}\n\npub fn api_version() -> u32 {")],
     "cd clients/scaas-sdk/bindings/dart && ../../../../scripts/capped dart test --reporter expanded --no-color --name 'no spike call'"),
]

if __name__ == "__main__":
    main("t13d", MUTANTS)
