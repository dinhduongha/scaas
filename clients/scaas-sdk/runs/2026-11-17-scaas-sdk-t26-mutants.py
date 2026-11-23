# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T26, the review's fixes (areas B and C, 2026-11-23) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t26-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

PRF = "clients/scaas-sdk/src/vault/prf.rs"
SOR = "clients/scaas-sdk/src/wallet/families/soroban_ops.rs"
FFI = "clients/scaas-sdk/ffi/src/api/mod.rs"
SUB = "clients/scaas-sdk/src/op/submit.rs"
QUO = "clients/scaas-sdk/src/op/quote.rs"
FOL = "clients/scaas-sdk/src/op/follow.rs"
APT = "clients/scaas-rpc/src/aptos.rs"
COS = "clients/scaas-rpc/src/cosmos.rs"
CPP = "clients/scaas-sdk/bindings/cpp/same_blocks.py"
CS = "clients/scaas-sdk/bindings/cs/CopyCall.cs"
SW = "clients/scaas-sdk/bindings/swift/CopyCall.swift"
TOOLS = '"$(git rev-parse --git-common-dir)/../scratchpad/tools'
F = (
    "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records,near,algorand,"
    "cosmos,aptos,solana,soroban,sui,ton,substrate,arweave"
)
STATUS = """    let status = match &w.tx {
        Some(h) => {
            let (s, win) = sor
                .transaction_window_at(i, h)
                .await
                .map_err(|e| failed(i, e))?;
            if win.latest < spent_at {
                return Err(malformed(i, "a status behind its entries"));
            }
            Some((s, win))
        }
        None => None,
    };"""
R = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F
MUTANTS = [
    (
        "C-1: an all-zero output taken as written",
        [(PRF, "b.len() == 32 && b.iter().fold(0u8, |a, x| a | x) != 0", "b.len() == 32")],
        T + " --test passkey an_output_never_written_is_refused",
    ),
    (
        "C-1: the unlock's output not checked",
        [(PRF, "        written(&out)?;\n        Ok(Key::Prf(out))", "        Ok(Key::Prf(out))")],
        T + " --test passkey an_output_never_written_is_refused",
    ),
    (
        "C-1: the enable's output not checked",
        [(PRF, "    written(&out)?;\n    let p2 = pass.clone();", "    let p2 = pass.clone();")],
        T + " --test passkey an_output_never_written_is_refused",
    ),
    (
        "B-1: a transfer bound by valid_until on the clock",
        [(SOR, 'pay_until: (r.entry == "pay").then_some(r.valid_until),', "pay_until: Some(r.valid_until),")],
        T + " --test soroban_ops a_transfer_ends_on_its_expiry_ledger_not_on_the_clock",
    ),
    (
        "B-2: a discovered endpoint 0 decisive",
        [(SOR, "let decisive = strict || (i == 0 && pool.class(0) != Class::Discovered);", "let decisive = strict || i == 0;")],
        T + " --test soroban_ops a_discovered_endpoint_decides_nothing",
    ),
    (
        "B-2: a native not-found expired beyond the endpoint's history",
        [(SOR, "if win.close_time > w.max_time && win.oldest <= w.sent_at =>", "if win.close_time > w.max_time =>")],
        T + " --test soroban_ops a_native_send_expires_on_the_chains_time_within_its_history",
    ),
    (
        "B-2: a native send expired by any not-found",
        [(SOR, "if win.close_time > w.max_time && win.oldest <= w.sent_at =>", "if win.oldest <= w.sent_at =>")],
        T + " --test soroban_ops a_native_send_expires_on_the_chains_time_within_its_history",
    ),
    (
        "B-2: a pay's valid_until never against the chain's time",
        [(SOR, "Some(v) if !gone => {", "Some(v) if false => {")],
        T + " --test soroban_ops a_pay_expires_on_the_chains_time",
    ),
    (
        "B-3: the status read before the spent entries",
        [
            (
                SOR,
                "    let (spent_at, gone) = if w.native {\n        (0, false)",
                "    let early = match &w.tx {\n        Some(h) => Some(sor.transaction_window_at(i, h).await.map_err(|e| failed(i, e))?),"
                "\n        None => None,\n    };\n    let (spent_at, gone) = if w.native {\n        (0, false)",
            ),
            (SOR, STATUS, "    let status = early;"),
        ],
        T + " --test soroban_ops an_own_landing_between_the_reads_is_never_consumed",
    ),
    (
        "C-2: the FRB opening without the load check",
        [(FFI, "    scaas_sdk::load_check(expect_api, need_features)?;\n", "    let _ = (expect_api, need_features);\n")],
        "cd clients/scaas-sdk/ffi && ../../../scripts/capped cargo test --locked --offline -j2 the_opening_runs_the_load_check",
    ),
    (
        "B-4: submit signs a handed-back op unchecked",
        [(SOR, "                if p.signature.is_none() {\n                    own_terms(&sdk, c, sor, &p, passphrase).await?;\n                }\n", "")],
        T + " --test soroban_ops submit_and_hand_off_check_a_handed_back_op_again",
    ),
    (
        "B-4: the hand-off signs a handed-back op unchecked",
        [(SOR, "                own_terms(&sdk, c, sor, &p, passphrase).await?;\n                let op = rebuilt(&p, passphrase)?;\n                let k =",
          "                let op = rebuilt(&p, passphrase)?;\n                let k =")],
        T + " --test soroban_ops submit_and_hand_off_check_a_handed_back_op_again",
    ),
    (
        "B-4: the expiry ledger not held to the window",
        [(SOR, "    checked(p, passphrase, ledger, window).map(|_| ())", "    checked(p, passphrase, p.expiry, 0).map(|_| ())")],
        T + " --test soroban_ops submit_and_hand_off_check_a_handed_back_op_again",
    ),
    (
        "B-5: the stored transaction decides the path",
        [(SUB, "if let (Some(raw), false) = (&row.raw, row.path == \"gateway\") {", "if let (Some(raw), false) = (&row.raw, false) {")],
        T + " --lib op::tests::resend_of_a_self_relay_to_the_gateways_posts_to_them",
    ),
    (
        "B-6: a failed send marked sent",
        [(SUB, "send_once(sdk, &row).await.unwrap_or(InFlight::Signed);", "send_once(sdk, &row).await.unwrap_or(InFlight::GivenUpByEveryNode);")],
        T + " --lib op::tests::a_simulation_down_in_transport_is_sent_at_the_next_resume",
    ),
    (
        "B-6: a transport failure of the simulation as SimRefused",
        [(SUB, "                Err(e) => return Err(super::sim(e)),", "                Err(_) => return Ok(InFlight::SimRefused),")],
        T + " --lib op::tests::a_simulation_down_in_transport_is_sent_at_the_next_resume",
    ),
    (
        "B-6: every gateway unreachable is given up",
        [(SUB, "                .any(|(_, o)| matches!(o, scaas_rpc::node::NodeOutcome::Unreachable(_))) =>", "                .any(|(_, o)| matches!(o, scaas_rpc::node::NodeOutcome::Refused(_))) =>")],
        T + " --lib op::tests::a_post_no_gateway_took_stays_signed",
    ),
    (
        "B-7: one unreadable gateway refuses every quote",
        [(QUO, "            Err(e) => last = Some(e),", "            Err(e) => return Err(e.into()),")],
        T + " --lib op::tests::a_gateway_down_or_of_another_chain_is_left_out",
    ),
    (
        "B-7: the send posts to every listed gateway",
        [(SUB, "    let node = kept_gateways(sdk, &row.chain).await?;", "    let _ = kept_gateways(sdk, &row.chain).await?;\n    let node = scaas_rpc::node::NodeClient::new(\n        sdk.chains.iter().find(|c| c.profile.key == row.chain).and_then(|c| c.gateways.clone()).ok_or(SdkError::SubmitPathNone)?,\n    )?;")],
        T + " --lib op::tests::a_gateway_down_or_of_another_chain_is_left_out",
    ),
    (
        "B-8: resume sends another family's row",
        [(SUB, "                        && evm(&sdk, &row.chain).is_ok()\n", "")],
        T + " --lib op::tests::resume_leaves_another_familys_row",
    ),
    (
        "B-11: no finalized re-read under strict_majority",
        [(FOL, "if strict && choice != BlockChoice::Finalized", "if false && strict && choice != BlockChoice::Finalized")],
        T + " --lib op::tests::strict_majority_ends_a_failed_operation_at_the_finalized_block",
    ),
    (
        "B-9: the indexer's network not compared",
        [(APT, "Some(c) if c == u64::from(self.chain_id) =>", "Some(_) =>")],
        R + " --test aptos an_indexer_of_another_network_answers_nothing",
    ),
    (
        "B-10: a CometBFT answer without result as null",
        [(COS, 'match v.get("result").filter(|r| !r.is_null()) {', 'match Some(v.get("result").cloned().unwrap_or_default()).as_ref() {')],
        R + " --test cosmos the_cometbft_and_rest_reads",
    ),
    (
        "C-4: the drift check sorts single lines",
        [(CPP, "    return blocks(a) == blocks(b)", '    return sorted(a.split("\\n")) == sorted(b.split("\\n"))')],
        "cd clients/scaas-sdk/bindings/cpp && python3 -I test_same_blocks.py",
        "test_lines_in_another_order_inside_a_block",
    ),
    (
        "C-5: C#'s read leaves its buffer",
        [(CS, "        var r = n < 0 ? null : out_[..(int)n];\n        CryptographicOperations.ZeroMemory(out_);\n", "        var r = n < 0 ? null : out_[..(int)n];\n")],
        "cd clients/scaas-sdk/bindings/cs && bash ../lib.sh uniffi && ../../../../scripts/capped dotnet test; rc=$?; dotnet build-server shutdown >/dev/null 2>&1; exit $rc",
        "CopyCallsRevealDispose",
    ),
    (
        "C-5: Swift's read leaves its buffer",
        [(SW, "        out.withUnsafeMutableBytes { if let p = $0.baseAddress { _ = memset(p, 0, $0.count) } }\n        return r", "        return r")],
        "cd clients/scaas-sdk/bindings/swift && SWIFTC=" + TOOLS + '/swift-6.4.2/usr/bin/swiftc" bash run.sh',
        "the copy call zeroes its read buffer",
    ),
]

if __name__ == "__main__":
    main("t26", MUTANTS)
