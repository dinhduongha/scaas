# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T26, the review's fixes (areas A, B and C, 2026-11-23) mutants:
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
SEEDS = "clients/scaas-sdk/src/vault/seeds.rs"
UNL = "clients/scaas-sdk/src/vault/unlock.rs"
FAM = "clients/scaas-sdk/src/wallet/families/mod.rs"
SEC = "clients/ua-rs/src/wallet/secret.rs"
APK = "clients/ua-rs/src/wallet/appkey.rs"
JSR = "clients/scaas-sdk/src/wasm/js.rs"
EVT = "clients/scaas-sdk/src/events.rs"
WAS = "clients/scaas-sdk/src/wasm.rs"
CFG = "clients/scaas-sdk/src/config.rs"
STO = "clients/scaas-sdk/src/vault/store.rs"
SYN = "clients/scaas-sdk/src/sync_cpp.rs"
SW = "clients/scaas-sdk/bindings/swift/CopyCall.swift"
LINE = "clients/scaas-sdk/src/line.rs"
VLT = "clients/scaas-sdk/src/vault/mod.rs"
ROOTS = "clients/scaas-sdk/src/vault/roots.rs"
POL = "clients/ua-rs/src/wallet/policy.rs"
PQC = "clients/ua-rs/src/wallet/pqchat.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
PQR = "clients/scaas-sdk/src/pqchat_records.rs"
PQK = "clients/ua-rs/src/wallet/pqchat_keys.rs"
USEAL = "clients/ua-rs/src/wallet/seal.rs"
JSEAL = "clients/clientkeys/src/seal.js"
OPS = "clients/scaas-sdk/src/wallet/ops.rs"
CPQ = "clients/scaas-sdk/src/confidential/pqz.rs"
FPQ = "clients/ua-rs/src/facade/pqz.rs"
DLY = "clients/scaas-sdk/src/admin/delay.rs"
HOF = "clients/scaas-sdk/src/op/handoff.rs"
REG = "clients/scaas-sdk/src/account/register.rs"
MSG = "clients/scaas-sdk/src/account/msig.rs"
MAN = "clients/ua-rs/src/wallet/manifest.rs"
OPM = "clients/scaas-sdk/src/op/mod.rs"
REVM = "clients/scaas-rpc/src/evm.rs"
GAS = "clients/scaas-sdk/src/op/gas.rs"
PQD = "clients/scaas-sdk/src/confidential/pqz_debit.rs"
BLS = "clients/scaas-sdk/src/op/bls_multi.rs"
HIS = "clients/scaas-sdk/src/wallet/history.rs"
REVM = "clients/scaas-rpc/src/evm.rs"
NAP = "scaas-node/src/adapters/aptos.rs"
TON = "clients/scaas-sdk/src/wallet/families/ton.rs"
LIB = "clients/scaas-sdk/src/lib.rs"
ALG = "clients/scaas-sdk/src/wallet/families/algorand.rs"
BTC = "clients/scaas-rpc/src/bitcoin.rs"
DEX = "clients/scaas-sdk/src/dex.rs"
OPS = "clients/scaas-sdk/src/wallet/ops.rs"
TOK = "clients/scaas-sdk/src/wallet/tokens.rs"
ARW = "clients/scaas-rpc/src/arweave.rs"
HOF = "clients/scaas-sdk/src/op/handoff.rs"
HTP = "clients/scaas-rpc/src/http.rs"
PQV = "clients/pqvault-core/src/vault.rs"
PV = "cd clients/pqvault-core && ../../scripts/capped cargo test --locked --offline -j2"
N = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j2 --lib"
TOOLS = '"$(git rev-parse --git-common-dir)/../scratchpad/tools'
JS = "cd clients/scaas-sdk/bindings/js && WASM_BINDGEN=" + TOOLS + '/wasm-bindgen/bin/wasm-bindgen" bash run.sh'
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
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors"
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
        [(FAM, "            Err(e) => last = Some(e),", "            Err(e) => return Err(e.into()),")],
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
    (
        "A-1: a write signs a stored entry unchecked",
        [(SEEDS, "            stored_ok(&open.wallet, &e)?;\n            f(&mut e)?;", "            f(&mut e)?;")],
        T + " --test vault an_entry_changed_after_unlock_is_never_trusted_nor_signed_again",
    ),
    (
        "A-1: a writer's mismatch leaves the seed open",
        [(SEEDS, "        sdk.lock_seed(seed).await;\n    }\n    r\n}", "    }\n    r\n}")],
        T + " --test vault an_entry_changed_after_unlock_is_never_trusted_nor_signed_again",
    ),
    (
        "A-2: rows verified by the unlock alone",
        [(SEEDS, "    let ok = mac_ok(&open.wallet, e).unwrap_or(false);", "    let ok = true;")],
        T + " --test vault an_entry_changed_after_unlock_is_never_trusted_nor_signed_again",
    ),
    (
        "A-4: a second unlock replaces the session",
        [(UNL, "                if sdk.open_seed(&seed).is_ok() {\n                    return Ok(());\n                }\n", ""),
         (UNL, "                    if open.contains_key(&id) {", "                    if false && open.contains_key(&id) {")],
        T + " --lib vault::tests::unlock_of_an_open_seed_keeps_its_session",
    ),
    (
        "Soroban gateway: the family not compared",
        [(FAM, 'x.get("family").and_then(|f| f.as_str()) == Some(family.as_str())', "true")],
        T + " --test soroban_ops a_gateway_of_another_chain_takes_no_op",
    ),
    (
        "Soroban gateway: the chain_uid not compared",
        [(FAM, "            .is_some_and(|u| u.eq_ignore_ascii_case(&c.profile.chain_uid))\n    };", "            .is_some()\n    };")],
        T + " --test soroban_ops a_gateway_of_another_chain_takes_no_op",
    ),
    (
        "C-11: a sealed secret takes the copy write",
        [(SEC, "        .filter(|b| !b.sealed)\n", "")],
        U + " --lib a_sealed_secret_refuses_the_copy_write",
    ),
    (
        "A-3: seal_key seals a rooted key",
        [(APK, "        self.check(key)?;\n        if key.rooted {\n            return Err(Error::AppKeyRooted);\n        }", "        self.check(key)?;")],
        U + " --test app_core the_app_root_and_its_derivations_are_never_sealed_out",
    ),
    (
        "A-3: a derivation loses the root's mark",
        [(APK, "        let rooted = keys.iter().any(|k| k.rooted);", "        let rooted = false;")],
        U + " --test app_core the_app_root_and_its_derivations_are_never_sealed_out",
    ),
    (
        "A-3: mac_derive loses the root's mark",
        [(APK, "        h.rooted = key.rooted;", "        h.rooted = false;")],
        U + " --test app_core the_app_root_and_its_derivations_are_never_sealed_out",
    ),
    (
        "C-6: a JS value lifted without its depth bound",
        [(JSR, "    if !shallow(&v, JS_DEPTH) {", "    if !shallow(&v, usize::MAX) {")],
        JS,
        "nested beyond 128 levels",
    ),
    (
        "C-12: the opaque code by the error's text",
        [(JSR, "    out.map_err(|_| match refused {", "    out.map_err(|e| match refused || e.to_string().contains(\"OpaqueCallRefused\") {")],
        JS,
        "store, authenticator, PRF",
    ),
    (
        "C-7: an async release dropped where no runtime runs",
        [(STO, "            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()", "            if let Ok(rt) = tokio::runtime::Handle::try_current().map_err(|_| ()).and(Err::<tokio::runtime::Runtime, ()>(()))")],
        T + ",uniffi --lib binding::tests::a_lock_is_released_wherever_it_is_dropped",
    ),
    (
        "C-7: a sync release dropped where no runtime runs",
        [(SYN, "            .spawn(move || store.unlock(token));", "            .spawn(move || {\n                if tokio::runtime::Handle::try_current().is_ok() {\n                    store.unlock(token)\n                }\n            });")],
        T + ",sync-api --lib sync_cpp::tests::a_lock_is_released_wherever_it_is_dropped",
    ),
    (
        "A-3 (b): a KEM wrap of a rooted key",
        [(APK, "        if key.rooted {\n            return Err(Error::AppKeyRooted);\n        }\n        let (mlkem_ct, x25519_eph, ss)", "        let (mlkem_ct, x25519_eph, ss)")],
        U + " --test app_core the_app_root_and_its_derivations_are_never_kem_wrapped",
    ),
    (
        "A-3 (b): the SDK's kem_wrap_to_key of a rooted key",
        [(APK, "        if key.rooted {\n            return Err(Error::AppKeyRooted);\n        }\n        let (mlkem_ct, x25519_eph, ss)", "        let (mlkem_ct, x25519_eph, ss)")],
        T + " --test app_core the_app_root_never_leaves_by_a_kem_wrap",
    ),
    (
        "C-3: the JS configuration's keys not compared",
        [(JSR, "        if !keys_known(&config, &to_js(&c)?, JS_DEPTH) {", "        if false {")],
        JS,
        "an EVM profile opens",
    ),
    (
        "B-14: every end said to rest on one endpoint",
        [(EVT, "    pub(crate) fn of(strict: bool) -> Basis {\n        if strict {", "    pub(crate) fn of(strict: bool) -> Basis {\n        if !strict && strict {")],
        T + " --lib op::tests::strict_majority_ends_a_failed_operation_at_the_finalized_block",
    ),
    (
        "F2 / A-7: a holder off the line taken",
        [(LINE, "        if !on(r.holder) || (r.pqzHome != Address::ZERO && !on(r.pqzHome)) {", "        if false {")],
        T + " --lib account::",
    ),
    (
        "F2: a line not checked consecutive",
        [(LINE, "            if g != U256::from(top - gens.len()) {", "            if false {")],
        T + " --lib account::",
    ),
    (
        "F2: a native member signs in the bound registry's domain",
        [(LINE, "        let at = holder\n            .filter(|h| self.generation(*h).is_some())\n            .unwrap_or(self.bound());", "        let at = self.bound();")],
        T + " --lib account::msig::tests::msig_on_a_two_generation_line",
    ),
    (
        "F2: every domain at generation 1",
        [(LINE, "            generation: self.generation(at).unwrap_or(1),", "            generation: 1,")],
        T + " --lib account::msig::tests::msig_on_a_two_generation_line",
    ),
    (
        "A-7: a write target falls back on a failed read",
        [(LINE, "            Ok(line().await?.map_or(registry, |(h, _, _)| h))", "            Ok(line().await.unwrap_or(None).map_or(registry, |(h, _, _)| h))")],
        T + " --lib account::register::tests::write_targets_follow_the_line",
    ),
    (
        "A-6: a write over a rollback",
        [(VLT, "        if rolled_back(&item, &ks, self.get(HEAD).await?)? {", "        if false {")],
        T + " --lib vault::tests::rollback_blocks_writes_until_accepted",
    ),
    (
        "A-6: accept_rollback writes nothing",
        [(VLT, "        self.put(HEAD, prev, anchor(ks.rev, &item.bytes)?).await\n    }", "        let _ = (prev, ks);\n        Ok(())\n    }")],
        T + " --lib vault::tests::rollback_blocks_writes_until_accepted",
    ),
    (
        "A2-5: one handle for both signatures",
        [(ROOTS, " || Arc::ptr_eq(&s1, &s2) {", " {")],
        T + " --test roots one_secret_for_two_parameters_does_not_hang",
    ),
    (
        "A2-8: sign_scaas takes an ERC-7739 nest",
        [(POL, "    if matches!(expect, Expect::Any(_) | Expect::Erc7739 { .. }) {\n        return Err(Error::Argument);\n    }\n    if let super", "    if matches!(expect, Expect::Any(_)) {\n        return Err(Error::Argument);\n    }\n    if let super")],
        "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features vectors --test wallet_typed erc7739_kat_and_expect",
    ),
    (
        "A-8: a PqChat record by its name alone",
        [(PQC, "            .is_some_and(|t| t.encode_type() == td.encode_type())", "            .is_some_and(|_| true)")],
        U + " --test app_core pqchat_sign_records_only",
    ),
    (
        "A-5: a prepared record shows no review",
        [(AC, "                Ok(AppPrepared {\n                    review: Self::review(&path, &typed),\n                    digest: hex(&d),", "                Ok(AppPrepared {\n                    review: vec![],\n                    digest: hex(&d),")],
        T + " --test app_core app_record_reviewed_before_signed",
    ),
    (
        "A-9: a PqChat record signed in any scope",
        [(PQR, "        self.label(scaas_ua::wallet::pqchat_keys::PREFIX.as_bytes())?;\n        let td = pqchat::typed(name, message)?;", "        let td = pqchat::typed(name, message)?;")],
        T + ",vectors --test pqchat_records entries_reproduce_the_vectors",
    ),
    (
        "A-10: the factory class read at the head",
        [(AC, "            .read_at_block(final_block(profile), Purpose::Plain, |at| {\n                let d = data.clone();\n                async move { pool.call_at(&at, f, d).await.map(|b| b.to_vec()) }", "            .read_at_block(scaas_rpc::pool::BlockChoice::Latest, Purpose::Plain, |at| {\n                let d = data.clone();\n                async move { pool.call_at(&at, f, d).await.map(|b| b.to_vec()) }")],
        T + " --test app_core",
    ),
    (
        "A-11: decode_inner copies past its input",
        [(PQK, "    let v = a.bytes(at, (*left).min(PT_MAX))?;", "    let v = a.bytes(at, PT_MAX)?;")],
        U + " --lib decode_budget",
    ),
    (
        "B-17: read_app a plain read",
        [(AC, "        self.read_app_as(chain, contract, entry, args, Purpose::FeedsDecryption)", "        self.read_app_as(chain, contract, entry, args, Purpose::Plain)")],
        T + " --test app_core read_app_feeds_decryption_by_default",
    ),
    (
        "B2-9: a transfer skips the receiver check",
        [(OPS, "                crate::line::receiver_registered(&sdk, &req.chain, &id32(&req.to)?).await?;\n                let kind = kind_of(&sdk, &req.chain, \"UAMetaTransfer\", token).await?;\n                let mut m", "                let kind = kind_of(&sdk, &req.chain, \"UAMetaTransfer\", token).await?;\n                let mut m")],
        T + " --test account_ops pay_to_unregistered_derived_ua",
    ),
    (
        "A2-4: the SDK requires a proven holder key on an OFFCHAIN token",
        [(CPQ, "    if !(proven || offchain)\n", "    if !proven\n")],
        T + " --test confidential_pqz offchain_holder_key_need_not_be_proven",
    ),
    (
        "A2-4: the facade requires a proven holder key on an OFFCHAIN token",
        [(FPQ, "    if !(proven == 1 || proven == 0 && offchain) || added > 1 {", "    if proven != 1 || added > 1 {")],
        T + " --test confidential_pqz offchain_holder_key_need_not_be_proven",
    ),
    (
        "A2-3: governance_delay takes a token of another factory",
        [(DLY, "                if word(f, 0)?.get(12..) != Some(&factory[..])\n                    || small", "                if word(f, 0)?.get(12..).is_none()\n                    || small")],
        T + " --test governance_delay the_token_is_the_profile_factorys",
    ),
    (
        "A2-3: governance_delay takes another class",
        [(DLY, "? != CLASS_TOKEN\n", "? > CLASS_TOKEN + 1\n")],
        T + " --test governance_delay the_token_is_the_profile_factorys",
    ),
    (
        "A2-1: ua-rs judges an msig sender on its first structure",
        [(USEAL, "    let d = &current(*id).map_or_else(|| d.to_vec(), |c| c.0);\n", "    let d = &d.to_vec();\n")],
        U + " --test wallet_seal seal_json_acceptance",
    ),
    (
        "A2-1: ua-rs counts a disabled slot",
        [(USEAL, "accepted(x, i) && current(x).is_none_or(|c| slot_enabled(&c.1, i))", "accepted(x, i)")],
        U + " --test wallet_seal seal_json_acceptance",
    ),
    (
        "A2-1: ua-rs judges an inner msig member on its first structure",
        [(USEAL, "members(x).map(|(_, k)| current(x).map_or(k, |c| c.0))", "members(x).map(|(_, k)| k)")],
        U + " --test wallet_seal seal_json_acceptance",
    ),
    (
        "A2-1: clientkeys judges an msig sender on its first structure",
        [(JSEAL, "  const d = nowOf(cur, hex(id), first);\n", "  const d = first;\n")],
        "cd clients/clientkeys && node --test test/seal.test.js",
    ),
    (
        "A2-1: clientkeys counts a disabled slot",
        [(JSEAL, "accepted(x, i) === true && enabledAt(cur, x, i)", "accepted(x, i) === true")],
        "cd clients/clientkeys && node --test test/seal.test.js",
    ),
    (
        "A-5b: a PqChat record's key opened at prepare",
        [(PQR, "        Ok(PqChatPrepared {\n            record: name.into(),", "        let crate::op::Key::Ua(..) = crate::op::key(&self.sdk, &account)? else {\n            return Err(SdkError::Argument);\n        };\n        Ok(PqChatPrepared {\n            record: name.into(),")],
        T + ",vectors --test pqchat_records entries_reproduce_the_vectors",
    ),
    (
        "Sticky: no retry of a moved head",
        [(REVM, "        for _ in 0..STICKY_TRIES {", "        for _ in 0..1 {")],
        R + " --test evm_profiles a_sticky_read_stays_on_one_endpoint_and_retries_a_moved_head",
    ),
    (
        "Sticky: the head not read again",
        [(REVM, "                    Ok((head().await? == (number, hash)).then_some((v, number, hash)))", "                    Ok(Some((v, number, hash)))")],
        R + " --test evm_profiles a_sticky_read_stays_on_one_endpoint_and_retries_a_moved_head",
    ),
    (
        "Sticky: a request named by a made-up pin",
        [(REVM, "        if self.pinned_reads {\n            pinned(at)\n        } else {\n            alloy::eips::BlockId::latest()\n        }", "        pinned(at)")],
        R + " --test evm_profiles a_sticky_read_stays_on_one_endpoint_and_retries_a_moved_head",
    ),
    (
        "Sticky: a read feeding a decryption served",
        [(REVM, "        if purpose == Purpose::FeedsDecryption\n            || self.pool.policy()", "        if self.pool.policy()")],
        R + " --test evm_profiles a_sticky_read_stays_on_one_endpoint_and_retries_a_moved_head",
    ),
    (
        "Sticky: strict majority served",
        [(REVM, "            || self.pool.policy() == crate::Policy::StrictMajority\n", "            || false\n")],
        R + " --test evm_profiles a_sticky_read_stays_on_one_endpoint_and_retries_a_moved_head",
    ),
    (
        "Sticky: read_line pinned on every chain",
        [(LINE, "    Ok(if pool.pinned_reads() || choice != BlockChoice::Latest {", "    Ok(if true {")],
        T + " --lib account::msig::tests::msig_on_a_two_generation_line",
    ),
    (
        "(161): a simulated revert loses its reason",
        [(OPM, "        SimError::Revert(reason) => SdkError::Rpc(scaas_rpc::RpcError::Revert {\n            endpoint: 0,\n            data: vec![],\n            reason,", "        SimError::Revert(_) => SdkError::Rpc(scaas_rpc::RpcError::Revert {\n            endpoint: 0,\n            data: vec![],\n            reason: String::new(),")],
        T + " --lib line::tests::a_simulated_revert_keeps_its_reason",
    ),
    (
        "A2-6: the generation raised before the keys are checked",
        [(MAN, "        recipients.iter().try_for_each(Recipient::check)?;\n", "")],
        "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test wallet_custody a_refused_backup_raises_no_generation",
    ),
    (
        "A2-7: no bounds on a blob built as a struct",
        [(HOF, "                SignedOpBlob::from_json(&blob.to_json()?)?;\n", "")],
        T + " --test handoff blob_bounds_and_the_cap",
    ),
    (
        "A2-7: the blob's signer not its from",
        [(HOF, "                if unhex(&blob.signer)? != from {", "                if false {")],
        T + " --test handoff import_refusals_in_order",
    ),
    (
        "A2-7: the kind on the blob's word",
        [(HOF, "                if kind != blob.signer_kind {", "                if false {")],
        T + " --test handoff import_refusals_in_order",
    ),
    (
        "A2-9: the write table never pruned",
        [(REG, "    t.retain(|_, x| x.strong_count() > 0);\n", "")],
        T + " --lib account::register::tests::dropped_registry_writes_are_pruned",
    ),
    (
        "A2-11: a Signed slot's inner leaves unchecked",
        [(MSG, "            MsigSlot::Signed { member, .. } => {\n                let m = member_of(member)?;\n                if m.members.is_empty() {", "            MsigSlot::Signed { member, .. } => {\n                let m = member_of(member)?;\n                if true {")],
        T + " --lib account::msig::tests::msig_minimal_sets",
    ),
    (
        "B2-1: a plain transfer at 21,000",
        [(QUO, "    } else {\n        // the estimate with the value sent (T13b ruling 5)", "    } else if data.is_empty() {\n        Figure::whole(21_000, GasSources::both(GasFrom::Estimate))\n    } else {\n        // the estimate with the value sent (T13b ruling 5)")],
        T + " --test wallet",
    ),
    (
        "B2-1: no transaction row still quoted",
        [(GAS, "    let Some(tx) = tx_gas(chain, opt_in, tables) else {\n        return Ok(None);\n    };\n    let r = lookup_in", "    let tx = tx_gas(chain, opt_in, tables).unwrap_or(TxGas { intrinsic: 21_000, per_byte: 64, from: GasFrom::Chain });\n    let r = lookup_in")],
        T + " --lib op::tests::no_transaction_row_no_figure",
    ),
    (
        "B2-1: the L1 component not added",
        [(QUO, "            q.gas_limit = own.saturating_add(super::gas::with_margin(l1));", "            q.gas_limit = own.max(l1 & 0);")],
        T + " --lib op::tests::in_estimate_adds_the_l1_component",
    ),
    (
        "B2-1: Linea's fees not taken",
        [(QUO, "        Some(crate::L1Fee::Linea) => {", "        Some(crate::L1Fee::Linea) if false => {")],
        T + " --test l1_fee linea_fees_are_linea_estimate_gas",
    ),
    (
        "B2-1: an estimated send gets the L1 component again",
        [(QUO, "        Some(crate::L1Fee::InEstimate) if !estimated => {", "        Some(crate::L1Fee::InEstimate) if estimated || !estimated => {")],
        T + " --test l1_fee in_estimate_native_send_is_its_estimate",
    ),
    (
        "B2-2: an op 7's decoys not drawn",
        [(PQD, "    if decoys > 0 {\n        let (registry, pool)", "    if decoys > u32::MAX - 1 {\n        let (registry, pool)")],
        T + " --test confidential_pqz pqz_op7_draws_its_decoys_from_the_line",
    ),
    (
        "B2-3: no half-block share",
        [(BLS, "    if profile.tx_gas_cap.is_none() && gas > block / 2 {", "    if profile.tx_gas_cap.is_none() && gas > block {")],
        T + " --lib op::tests::",
    ),
    (
        "B2-13: the verify row's margin dropped",
        [(GAS, "            .map(|v| v.gas.saturating_add(v.margin))\n    })\n    .unwrap_or((app, GasFrom::App))", "            .map(|v| v.gas)\n    })\n    .unwrap_or((app, GasFrom::App))")],
        T + " --lib op::gas::tests::verify_or_counts_the_margin",
    ),
    (
        "B2-4: a log outside the filter taken",
        [(REVM, "    match logs.iter().all(fits) {", "    match logs.iter().all(fits) || true {")],
        T + " --test history history_refuses_logs_outside_the_filter",
    ),
    (
        "B2-4: a log outside the range taken",
        [(REVM, "        l.block_number.is_none_or(|b| (from..=to).contains(&b)) && filter.matches(&l.inner)", "        filter.matches(&l.inner)")],
        T + " --test history history_refuses_logs_outside_the_filter",
    ),
    (
        "B2-5: the operations by the id's text",
        [(HIS, "r.chain == chain && id_word(&r.from).is_ok_and(|(w, _)| w == word)", "r.chain == chain && r.from.eq_ignore_ascii_case(&account)")],
        T + " --test history operations_in_history",
    ),
    (
        "B2-11: a disabled pqz read and proved first",
        [(PQD, "                crate::op::kind_enabled(&evm(&sdk, &d.chain)?.0, \"pqz\")?;\n", "")],
        T + " --test confidential_pqz a_disabled_pqz_refuses_before_any_read",
    ),
    (
        "B2-12: a produced slot outside the range taken",
        [("clients/scaas-rpc/src/solana.rs", "        if slots.iter().any(|s| !range.contains(s)) {", "        if slots.iter().any(|s| !range.contains(s) && false) {")],
        R + " --test solana a_produced_slot_outside_the_range_is_refused",
    ),
    (
        "B-16: submit takes the caller's data unchecked",
        [("clients/scaas-sdk/src/wallet/native_evm.rs", "                let data = unhex(&q.data)?;\n                native_args(chain_id, &data)?;\n", "                let data = unhex(&q.data)?;\n")],
        T + " --test wallet",
    ),
    (
        "8b-4: the node reads a missing list as empty",
        [(NAP, "            let Some(rows) = d[\"user_transactions\"].as_array().cloned() else {\n                bail!(\"indexer: AnswerMalformed: no user_transactions list\")\n            };", "            let rows = d[\"user_transactions\"].as_array().cloned().unwrap_or_default();")],
        N + " adapters::aptos::tests::an_indexer_answer_without_its_list_is_malformed",
    ),

    (
        "B2-15: a frozen jetton wallet the endpoint's failure",
        [(TON, '        "frozen" => return Ok((String::new(), Some("frozen".into()))),\n', "")],
        T + " --test ton",
    ),
    (
        "B-22: Depth(0) opens on a real profile",
        [(LIB, "            if p.finality == Finality::Depth(0)\n", "            if false && p.finality == Finality::Depth(0)\n")],
        T + " --test config",
    ),
    (
        "B2-6: any box 404 is a zero balance",
        [(ALG, '            }) if message == "box not found" => {', "            }) if !message.is_empty() || message.is_empty() => {")],
        T + " --test algorand",
    ),
    (
        "B2-6: the majority read needs the first's round",
        [(ALG, "want.is_none_or(|w| r >= w)", "want.is_none_or(|w| r == w)")],
        T + " --test algorand",
    ),
    (
        "B2-12: a mempool output taken as confirmed",
        [(BTC, "                    || (u.height.is_some() && o.confirmations == 0) =>", "                    || (u.height.is_some() && o.confirmations == u64::MAX) =>")],
        R + " --test bitcoin",
    ),
    (
        "B2-12: a repeated outpoint taken",
        [(BTC, "        if !out.iter().all(|u| seen.insert((u.txid.as_str(), u.vout))) {", "        if out.iter().all(|u| !seen.insert((u.txid.as_str(), u.vout))) {")],
        R + " --test bitcoin",
    ),
    (
        "B2-12: a caller's address the endpoint's failure",
        [(BTC, '        Err(FamilyError::Argument("an address out of form"))', '        Err(malformed(0, "an address out of form"))')],
        R + " --test bitcoin",
    ),
    (
        "B2-8: the DEX's prepares sign a disabled kind",
        [(DEX, "    if let KeyRef::Ua { kind, .. } = signer {\n        let (profile, _, _) = evm(sdk, chain)?;", "    if let (true, KeyRef::Ua { kind, .. }) = (false, signer) {\n        let (profile, _, _) = evm(sdk, chain)?;")],
        T + " --test dex",
    ),
    (
        "B2-8: sign_order on the prepare's clock",
        [(DEX, "                    *now = at;", "                    let _ = (now, at);")],
        T + " --test dex",
    ),
    (
        "B2-10: the salt from the terms as typed",
        [(OPS, "                        &canon_id(&req.to)?,\n                        &canon_amount(&req.value)?,\n                    ],", "                        &req.to,\n                        &req.value,\n                    ],")],
        T + " --test wallet_ops",
    ),
    (
        "B2-14: an unreadable index token ends the list",
        [(TOK, "                        Err(e) if n >= listed && !matches!(e, SdkError::ProfileMismatch) => out", "                        Err(e) if false && n >= listed && !matches!(e, SdkError::ProfileMismatch) => out")],
        T + " --test wallet",
    ),
    (
        "B-13: every poll scans from the row's start",
        [(FOL, "                            .insert(row.op.clone(), at.saturating_add(1));", "                            .insert(row.op.clone(), 0);")],
        T + " --lib op::tests::a_poll_scans_only_the_blocks_after_the_last",
    ),
    (
        "B-21: every gateway read before the vote",
        [(ARW, "            if groups.iter().any(wins) {\n                break;\n            }", "            if groups.iter().any(wins) && false {\n                break;\n            }")],
        R + " --test arweave",
    ),
    (
        "B-15: a native signer's blob kind trusted",
        [(HOF, "                if native != (blob.signer_kind == super::gas::NATIVE_EVM) {", "                if native && !native {")],
        T + " --test handoff",
    ),
    (
        "B-20: the body read whole before the cap",
        [(HTP, "        if buf.len() + c.len() > cap {\n            return Ok(None);\n        }\n        each(c);\n        buf.extend_from_slice(c);\n    }\n    Ok(Some(buf))", "        each(c);\n        buf.extend_from_slice(c);\n    }\n    Ok((buf.len() <= cap).then_some(buf))")],
        R + " --lib http::read_tests::the_read_stops_at_the_first_chunk_past_the_cap",
    ),
    # TODO 8b-8 follow-ups of pqchat-sigs (2026-11-23), each beside its red-first test
    (
        "8b-8 (1): a vault of groupMode 1 verified",
        [(PQV, "            || c.group_mode.0 != 0\n", "")],
        PV + " --test core a_vault_of_group_mode_1_is_refused_before_any_call",
    ),
    (
        "8b-8 (2): a member's keys deduplicated by UA",
        [(PQV, "    m.dedup_by_key(|k| (k.ua, k.key_id.0));", "    m.dedup_by_key(|k| k.ua);")],
        PV + " --test devices each_own_key_is_kept_and_its_wrap_opens",
    ),
    (
        "8b-8 (2): members sorted by UA only",
        [(PQV, "    m.sort_by_key(|k| (k.ua, k.key_id.0));", "    m.sort_by_key(|k| k.ua);")],
        PV + " --test devices each_own_key_is_kept_and_its_wrap_opens",
    ),
    (
        "8b-8 (2): a ninth key of one UA taken",
        [(PQV, "    if m.windows(KEYS_PER_UA_MAX + 1)", "    if false && m.windows(KEYS_PER_UA_MAX + 1)")],
        PV + " --test devices at_most_eight_keys_per_ua",
    ),
]


if __name__ == "__main__":
    main("t26", MUTANTS)
