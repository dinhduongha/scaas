# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T41.soroban (with T27.soroban, T29.soroban, T30.soroban) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t41sor-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

CJ = "clients/clientkeys/src/fam/soroban.js"
UF = "clients/ua-rs/src/families/soroban.rs"
UT = "clients/ua-rs/src/wallet/soroban_tx.rs"
RS = "clients/scaas-rpc/src/soroban.rs"
SO = "clients/scaas-sdk/src/wallet/families/soroban_ops.rs"
CK = "cd clients/clientkeys && node --test --test-reporter=tap test/fam-soroban.test.js"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test families_soroban "
RPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features soroban --test soroban_send "
SDK = ("cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --no-default-features "
       "--features vault,account,wallet,file-store,soroban --test soroban_ops ")
MUTANTS = [
    # T27: the envelope
    ("clientkeys: a field left out of the envelope", [(CJ, "    args: spec.map(([n, type]) => ({ type, value: fields[n] })),",
                                                       "    args: spec.slice(1).map(([n, type]) => ({ type, value: fields[n] })),")],
     CK, "each op row"),
    ("ua-rs: a field left out of the envelope", [(UF, "            u32be(out, 5);\n            out.extend_from_slice(&v.to_be_bytes());",
                                                   "            let _ = v;")],
     UA + "op_rows_byte_for_byte_and_signed_by_the_subject_only"),
    ("ua-rs: the wrong preimage type", [(UF, "const ENVELOPE_TYPE_SOROBAN_AUTHORIZATION: u32 = 9;",
                                         "const ENVELOPE_TYPE_SOROBAN_AUTHORIZATION: u32 = 8;")],
     UA + "op_rows_byte_for_byte_and_signed_by_the_subject_only"),
    ("ua-rs: the network id unchecked", [(UF, "    if t.network_id != network_id(&s.passphrase) {", "    if false {")],
     UA + "refused_op_rows_each_refused_beside_their_control"),
    ("ua-rs: another key signs the op", [(UT, "        if self.network != Network::Stellar || self.public_key != op.subject_key() {",
                                          "        if self.network != Network::Stellar {")],
     UA + "op_rows_byte_for_byte_and_signed_by_the_subject_only"),
    # the packed form: the credential's map keys swapped
    ("ua-rs: the credential map's keys swapped", [(UT, '(&b"public_key"[..], &pk[..]), (&b"signature"[..], &sig[..])',
                                                   '(&b"signature"[..], &sig[..]), (&b"public_key"[..], &pk[..])')],
     UA + "native_rows_byte_for_byte_and_signed_by_the_source_only"),
    ("ua-rs: the wrong transaction prefix", [(UT, "const ENVELOPE_TYPE_TX: u32 = 2;", "const ENVELOPE_TYPE_TX: u32 = 1;")],
     UA + "native_rows_byte_for_byte_and_signed_by_the_source_only"),
    # T30: the broadcast and the readers
    ("rpc: another id accepted", [(RS, "                        (_, Some(h)) if !h.eq_ignore_ascii_case(&want) => SendOutcome::Refused {",
                                   "                        (_, Some(h)) if h.is_empty() && !h.eq_ignore_ascii_case(&want) => SendOutcome::Refused {")],
     RPC + "send_merges_per_cli_rpc_08"),
    ("rpc: already known as refused", [(RS, '(Some("PENDING" | "DUPLICATE"), Some(_)) => SendOutcome::Accepted,',
                                        '(Some("PENDING"), Some(_)) => SendOutcome::Accepted,')],
     RPC + "send_merges_per_cli_rpc_08"),
    ("rpc: the depth bound dropped", [(RS, "    fn sc_val(&mut self, depth: u32) -> Option<()> {\n        let depth = depth.checked_sub(1)?;",
                                       "    fn sc_val(&mut self, depth: u32) -> Option<()> {\n        let depth = depth.saturating_sub(1);")],
     RPC + "a_too_deep_or_oversized_transaction_data_is_refused_beside_its_control"),
    # T41: the SDK
    ("sdk: the payee check dropped", [(SO, "                    if !expect.payee.iter().any(|p| p == t) {",
                                       "                    if expect.payee.is_empty() && !expect.payee.iter().any(|p| p == t) {")],
     SDK + "a_handed_off_pay_imports_with_each_check_and_lands"),
    ("sdk: the consumed check dropped", [(SO, "                if spent(sor, &op).await? {\n                    return Err(SdkError::ImportConsumed);",
                                          "                if false && spent(sor, &op).await? {\n                    return Err(SdkError::ImportConsumed);")],
     SDK + "a_handed_off_pay_imports_with_each_check_and_lands"),
    ("sdk: the expiry check dropped", [(SO, "                if u64::from(blob.op.expiry) < ledger.saturating_add(IMPORT_MARGIN_SECS)",
                                        "                if false && u64::from(blob.op.expiry) < ledger.saturating_add(IMPORT_MARGIN_SECS)")],
     SDK + "a_handed_off_pay_imports_with_each_check_and_lands"),
    ("sdk: a blob's unknown field taken (a footprint from the blob)", [(SO, "#[serde(deny_unknown_fields)]\npub struct SignedOpBlob {",
                                                                       "pub struct SignedOpBlob {")],
     SDK + "a_handed_off_pay_imports_with_each_check_and_lands"),
    ("sdk: the resource fee left out of the cost", [(SO, "    let total = resource\n        .checked_add(inclusion)",
                                                     "    let total = 0u64\n        .checked_add(inclusion)")],
     SDK + "an_own_op_self_relays_under_the_cap"),
    ("sdk: the quote signs the op", [(SO, "                let sig = signature(&p)?;\n                let env = invoke(&pk, 0, seq, max_time, &op, sig, None)",
                                      "                let sig = match p.subject.as_ref() { Some(k) => Some(stellar(&sdk, k)?.1.sign_soroban_auth(&op)?), None => signature(&p)? };\n                let env = invoke(&pk, 0, seq, max_time, &op, sig, None)")],
     SDK + "an_own_op_self_relays_under_the_cap"),
    ("sdk: resend gives the op to sign again", [(SO, '                    signature: s("signature"),\n                    relayer_bound: false,\n                    op: Some(op),',
                                                  '                    signature: None,\n                    relayer_bound: false,\n                    op: Some(op),')],
     SDK + "resend_wraps_the_same_signed_op_in_a_new_transaction"),
    ("sdk: the sequence not advanced", [(SO, "                let seq = seq.checked_add(1).ok_or(SdkError::Argument)?;\n                let inclusion",
                                         "                let seq = seq.checked_add(0).ok_or(SdkError::Argument)?;\n                let inclusion")],
     SDK + "an_own_op_self_relays_under_the_cap"),
    ("sdk: the native send's sequence not advanced", [(SO, "                    seq: seq.checked_add(1).ok_or(SdkError::Argument)?.to_string(),",
                                                       "                    seq: seq.to_string(),")],
     SDK + "a_native_xlm_send"),
    ("sdk: following ends without the chain fact", [(SO, "                        _ if gone && r.tx_id.is_none() => end(&mut r, \"landed\", \"spent\"),",
                                                     "                        _ if r.tx_id.is_none() => end(&mut r, \"landed\", \"spent\"),")],
     SDK + "a_pay_through_the_gateways_is_the_vectors_signed_op"),
    ("sdk: the review field not the signed one", [(SO, "fn rebuilt(p: &SorobanPrepared, passphrase: &str) -> Result<Checked, SdkError> {\n    checked(p, passphrase, p.expiry, 0)",
                                                   "fn rebuilt(p: &SorobanPrepared, passphrase: &str) -> Result<Checked, SdkError> {\n    let mut p = p.clone();\n    p.expiry += 1;\n    checked(&p, passphrase, p.expiry, 0)")],
     SDK + "a_pay_through_the_gateways_is_the_vectors_signed_op"),
    ("sdk: a payer's consumed op counted landed", [(SO, "                        _ if gone => end(&mut r, \"consumed\", \"spent by another transaction\"),",
                                                    "                        _ if gone => end(&mut r, \"landed\", \"spent by another transaction\"),")],
     SDK + "a_pay_landed_by_another_first_is_consumed_for_the_payee"),
]

if __name__ == "__main__":
    main("t41sor", MUTANTS)
