# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The fixes of the two Fable reviews of T13-T20 (2026-11-20: F1, F14, F19, F22; T3, T9, T10, T12, T15):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-r1120-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

MSIG = "clients/scaas-sdk/src/account/msig.rs"
REG = "clients/scaas-sdk/src/account/register.rs"
READ = "clients/scaas-sdk/src/confidential/read.rs"
VERDICT = "clients/scaas-sdk/src/confidential/verdict.rs"
NODE = "clients/scaas-rpc/src/node.rs"
DEX = "clients/scaas-sdk/src/dex.rs"
POLICY = "clients/ua-rs/src/wallet/policy.rs"
EXT = "clients/scaas-sdk/src/op/external.rs"
PQZ = "clients/scaas-sdk/src/confidential/pqz.rs"
WDART = "clients/scaas-sdk/bindings/dart/lib/src/rust/third_party/scaas_sdk/wallet.dart"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F}"
APART = f"{SDK} --lib account::msig::tests::msig_members_apart"
SAMPLE = f"{SDK} --lib confidential::read::tests::decoy_sample_reads_want_words"
SPLIT = f"{SDK} --test account_ops split_second_part_prepared_again_after_the_first_landed"
VERD = f"{SDK} --test confidential_pqz verdict_checked_before_attach"
MAJ = ("cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test node "
       "verifier_strict_majority_compares_the_verdict")
CONSENT = f"{SDK} --lib admin::tests::pqz_auditor_consent_of_a_derived_ua"
NOTLISTED = f"{SDK} --test dex"
DER = f"{SDK} --lib op::external::tests::der_signature_bounds"
DEXT = f"{SDK} --test dex "
MUTANTS = [
    ("F1: a slot signed elsewhere combined over another operation",
     [(MSIG, "                bound_to(member, ua, purpose, digest)?;\n", "")], APART),
    ("F1: the binding's digest not compared",
     [(MSIG, '|| got("digest")? != *digest', '|| got("digest").is_err()')], APART),
    ("T10: the member JSON's 64 KiB bound dropped",
     [(MSIG, "if s.len() > 64 << 10 {", "if s.len() > 128 << 10 {")], APART),
    ("T10: the 256 inner signatures bound dropped",
     [(MSIG, "if inner.len() > 256 {", "if inner.len() > 512 {")], APART),
    ("F14: strict_majority compares validUntil",
     [(NODE, '        o.remove("validUntil");\n', "")], MAJ),
    ("M3: the group's earliest answer decides (one replica's clock)",
     [(NODE, "                if let Some(v) = group.get(k / 2) {", "                if let Some(v) = group.first() {")], MAJ),
    ("M3: the group's latest answer decides",
     [(NODE, "                if let Some(v) = group.get(k / 2) {", "                if let Some(v) = group.last() {")], MAJ),
    ("F19: a long list read whole",
     [(READ, "if n <= want.saturating_mul(2) {", "if n <= u64::MAX {")], SAMPLE),
    ("F19: a short sample accepted",
     [(READ, "(out.len() as u64 == want).then_some(out)", "Some(out)")], SAMPLE),
    ("F22: a landed first part's storePqzPop never prepared again",
     [(REG, '    if registered && pqz_pop != "0x" {', '    if false && registered && pqz_pop != "0x" {')],
     SPLIT),
    # removed after the first run (survived, equivalent): "T3: the verdict's token not compared": ua-rs pqz_verdict_typed_data refuses a verdict whose token differs from its argument, and the digest is the SDK's token's
    # removed after the first run (survived, equivalent): "T3: the verdict's chainId not compared": ua-rs pqz_verdict_typed_data refuses a verdict whose chainId differs from its argument, and the digest is the SDK's chain's
    ("T3: the verdict's proofSystemId not compared",
     [(VERDICT, '        ("proofSystemId", hex(&x.psid)),\n', "")], VERD),
    ("T3: the verdict's statementHash not compared",
     [(VERDICT, '        ("statementHash", hex(&scaas_ua::keccak256(stmt))),\n', "")], VERD),
    ("T3: the verdict's proofHash not compared",
     [(VERDICT, '        ("proofHash", hex(&scaas_ua::keccak256(proof))),\n', "")], VERD),
    ("T3: a derived verifier's signature with members accepted",
     [(VERDICT, ".is_none_or(|m| !m.is_empty())", ".is_none_or(|_| false)")], VERD),
    ("T3, M6: the signer's key not the verifier's UA",
     [(VERDICT, "if scaas_ua::derive_ua(kind, &key_data, false).ok()? != x.verifier {",
       "if scaas_ua::derive_ua(kind, &key_data, false).ok()? == [1; 32] {")], VERD),
    ("T9: a derived auditor's consent under metatx",
     [(POLICY, '"AuditorConsent" => "auditor-consent",', '"AuditorConsent" => "metatx",')], CONSENT),
    ("T12: cancel_all on an unlisted DEX",
     [(DEX, "                listed(&sdk, &req.chain, &dex)?;\n                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;\n                let (_, chain_id, pool)",
       "                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;\n                let (_, chain_id, pool)")],
     NOTLISTED),
    ("T12: a cancel order on an unlisted DEX",
     [(DEX, "                if !ua {\n                    listed(&sdk, &req.chain, &dex)?;\n                }\n", "")], NOTLISTED),
    ("T15: DER outer length not compared",
     [(EXT, "    if usize::from(n) != body.len() {", "    if usize::from(n) > body.len() + 1 {")], DER),
    ("T15: DER trailing bytes accepted",
     [(EXT, "(a + b == body.len()).then_some((r, s))", "Some((r, s))")], DER),
    ("T15: DER a high integer without its zero accepted",
     [(EXT, "[x, ..] if *x < 0x80 => v,", "[_, ..] => v,")], DER),
    ("T15: a PQZ token cloned for another chain read",
     [(PQZ, "    if env.chain_uid != *chain_uid {\n        return Err(SdkError::ProfileMismatch);",
       "    if false {\n        return Err(SdkError::ProfileMismatch);")],
     f"{SDK} --test confidential_pqz pqz_token_checks"),
    # the generated file is restored byte for byte by the runner
    ("the raw marker as a callable item of the generated Dart",
     [(WDART, "class NativeKeyRef {\n", "class AllowRawNative {}\n\nclass NativeKeyRef {\n")],
     f"{SDK},native-networks,raw-native --lib wallet::raw::tests::raw_absent_from_the_generated_dart"),
    ("M5, F1: the binding's ua not compared",
     [(MSIG, 'if got("ua")? != *ua || ', 'if ')], APART),
    ("M5, F1: the binding's purpose not compared",
     [(MSIG, '|| got("purpose")? != *purpose ', '')], APART),
    ("M5, F7: a member told native by its key reference, not its opened key",
     [(MSIG, "        .any(|k| matches!(k, Key::Native(..))))\n}", "        .any(|_| matches!(slot, MsigSlot::Member { key: KeyRef::Native { .. }, .. })))\n}")],
     f"{SDK} --lib account::msig::tests::imported_evm_key_is_a_native_member"),
    ("M5, F24: a bytes record's offsets added unchecked",
     [(REG, "let end = off.checked_add(32)?.checked_add(len)?;", "let end = off + 32 + len;")],
     f"{SDK} --lib account::register::tests::record_offsets_added_checked"),
    ("M5, F24: a KEM record's offset added unchecked",
     [(REG, "Some(!out.get(off..off.checked_add(32)?)?.iter().all(|b| *b == 0))", "Some(!out.get(off..off + 32)?.iter().all(|b| *b == 0))")],
     f"{SDK} --lib account::register::tests::record_offsets_added_checked"),
    ("M5, F24: a record word's index multiplied unchecked",
     [(REG, "    let at = i.checked_mul(32)?;", "    let at = i * 32;")],
     f"{SDK} --lib account::register::tests::record_offsets_added_checked"),
    ("M5, F3: a second block read",
     [(PQZ, "    let (raws, within) = a.value;", "    let _ = pool.read_at_block(choice, PURPOSE, |at| fetch(pool, at, plan)).await?;\n    let (raws, within) = a.value;")],
     f"{SDK} --test confidential_pqz pqz_balance_all_versions"),
    ("M13, T12: a liquidity order on an unlisted DEX",
     [(DEX, "                let entry = listed(&sdk, &req.chain, &dex)?;",
       "                let entry = listed(&sdk, &req.chain, &dex).unwrap_or(crate::ListedDex {\n"
       "                    address: req.dex.clone(),\n                    liquidity: true,\n"
       "                    position_readers: vec![],\n                });")],
     DEXT + "dex_not_on_profile_list_is_refused"),
    ("M13, T9: an order's signature not the signer's over its digest",
     [(DEX, '        json!({"keyData": hex(&s.key_data), "signature": hex(&s.signature), "members": []})',
       '        json!({"keyData": hex(&s.key_data), "signature": hex(&[&s.signature[..], &[0][..]].concat()), "members": []})')],
     DEXT + "liquidity_order_signs_under_its_check"),
    ("M13, F19: a long list read whole (through the fake)",
     [(READ, "if n <= want.saturating_mul(2) {", "if n <= u64::MAX {")],
     f"{SDK} --test confidential zether_decoy_list_sampled"),
]

if __name__ == "__main__":
    main("r1120", MUTANTS)
