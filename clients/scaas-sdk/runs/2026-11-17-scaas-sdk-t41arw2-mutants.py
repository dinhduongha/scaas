# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T41.arweave's scaas-rpc and SDK parts (chains-arweave plan T19 and T20) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t41arw2-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

RA = "clients/scaas-rpc/src/arweave.rs"
RH = "clients/scaas-rpc/src/http.rs"
SA = "clients/scaas-sdk/src/arweave.rs"
RPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features arweave,node-client --test arweave "
# the SDK set with `arweave` and without `evm`
SDK = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --no-default-features --features vault,account,wallet,file-store,mlock,near,algorand,cosmos,aptos,solana,soroban,sui,ton,native-networks,raw-native,arweave --test arweave "
MUTANTS = [
    # CA-T19, the plan's list
    ("failover stopping at a refused body",
     [(RA, "                        .map_err(ReadError::Failure)", "                        .map_err(|e| ReadError::Revert { data: vec![], reason: e.text().into() })")],
     RPC + "failover_moves_past_a_body_that_fails_the_check"),
    ("the receipt's id comparison skipped", [(RA, '            Ok(v) if v["id"].as_str() == Some(id) =>', '            Ok(v) if !v.is_null() =>')],
     RPC + "an_upload_posts_the_same_bytes"),
    ("x-paid-by sent to every bundler", [(RA, "                .filter(|(b, _)| *b == i)\n", "")], RPC + "http_402_is_payment_required"),
    ("the announced length not checked", [(RH, "        if r.content_length().is_some_and(|n| n != len as u64) {",
       "        if r.content_length().is_some_and(|n| n > len as u64 + 1) {")], RPC + "an_announced_length_other_than_len"),
    ("settled on one gateway", [(RA, "        if group.len() < 2 || ops.len() < 2 {", "        if group.is_empty() {")],
     RPC + "settled_needs_two_operators"),
    ("the depth check dropped", [(RA, "        if group.iter().any(|s| s.tip < block.saturating_add(depth)) {", "        if false {")],
     RPC + "settled_needs_two_operators"),
    ("the bytes not read back for settled", [(RA, "        Ok(self.data(id, len, Purpose::Plain, &check).await.is_ok())", "        Ok(true)")],
     RPC + "settled_needs_two_operators"),
    ("a discovered gateway read for a decryption", [(RA, "                .failover(self, purpose, |i| async move {", "                .failover(self, Purpose::Plain, |i| async move {")],
     RPC + "the_decryption_mark"),
    # CA-T20, the plan's list where it applies (no key is held by ArweaveFiles: "a re-post that signs again" cannot be written;
    # the spy test stays)
    ("a re-post of other bytes", [(SA, "        let _ = self.post(&it, b).await;", "        let _ = self.upload_file([kept.item.clone(), vec![0]].concat()).await;")],
     SDK + "kept_until_settled"),
    ("the re-post schedule without an end", [(SA, "REPOST_AFTER.get(kept.reposts as usize)", "REPOST_AFTER.get((kept.reposts as usize).min(2))")],
     SDK + "kept_until_settled"),
    ("the check skipped before open_file", [(SA, "        let check = move |b: &[u8]| check_object(b, size, &ct_sha256, CAP).is_ok();",
       "        let check = move |_: &[u8]| { let _ = (size, ct_sha256); true };")], SDK + "bytes_that_fail_ct_sha256"),
    ("a larger bucket posted without a payer", [(SA, "            PayerPath::None => return Err(SdkError::PayerUnavailable),",
       "            PayerPath::None => (self.send(it, None).await?, Paid::FreeTier),")], SDK + "a_larger_bucket_without_a_payer"),
    ("the self-pay notice dropped", [(SA, "(paid == Paid::SelfPay).then_some(SELF_PAY_NOTICE)", "None::<&'static str>")],
     SDK + "self_pay_signs_nothing_more"),
    ("a kept item not reloaded by the verifying parser", [(SA, "        let it = DataItem::parse_c9(bytes).map_err(|_| SdkError::ArweaveItem)?;",
       "        let it = DataItem::parse(bytes).map_err(|_| SdkError::ArweaveItem)?;")], SDK + "only_an_item_ua_rs_built"),
]

if __name__ == "__main__":
    main("t41arw2", MUTANTS)
