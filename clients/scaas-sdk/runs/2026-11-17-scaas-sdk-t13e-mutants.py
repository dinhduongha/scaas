# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T13b mutants (owner 2026-11-19, T13b rulings 1, 2, 5, 6, 7; ruling 3's are t13f):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13e-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

OP = "clients/scaas-sdk/src/op"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
C = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
L = C + "--lib "
RPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_fakes "
WIN = "if expires_at <= wall || expires_at > wall.saturating_add(sdk.window(&d.chain)) {"
MUTANTS = [
    ("1: a past validUntil passes", [(f"{OP}/prepared.rs", WIN, "if expires_at > wall.saturating_add(sdk.window(&d.chain)) {")],
     L + "valid_until_is_held_to_the_sdk_clock"),
    ("1: no window on the SDK's clock", [(f"{OP}/prepared.rs", WIN, "if expires_at <= wall {")], L + "valid_until_is_held_to_the_sdk_clock"),
    ("1: the window is the limits' only", [("clients/scaas-sdk/src/lib.rs", ".and_then(|c| c.profile.max_valid_secs)", ".and_then(|_| None)")],
     L + "valid_until_is_held_to_the_sdk_clock"),
    ("2: terminal rows never pruned", [(f"{OP}/state.rs", "!r.terminal() || r.ended_at.is_none_or(|e| e.saturating_add(keep) > now)", "true || keep > now")],
     L + "terminal_rows_pruned_after_retention"),
    ("2: a non-terminal row pruned too", [(f"{OP}/state.rs", "!r.terminal() || r.ended_at.is_none_or(|e| e.saturating_add(keep) > now)",
                                         "r.ended_at.unwrap_or(r.valid_until.min(now)).saturating_add(keep) > now")],
     L + "terminal_rows_pruned_after_retention"),
    ("5: the native estimate without its value", [(f"{OP}/quote.rs", ".simulate_value(from, to, value, data.clone())", ".simulate_value(from, to, U256::ZERO, data.clone())")],
     C + "--test wallet native_send_estimate_carries_the_value"),
    ("5: simulate_value drops the value", [("clients/scaas-rpc/src/evm.rs", "            .with_value(value)\n", "")],
     RPC + "simulate_value_carries_the_value"),
    ("6: the passphrase's bytes kept in a new secret",
     [("clients/scaas-sdk/src/vault/unlock.rs", "let r = sdk.heavy(move || open_entry(&e, &key, None)).await;",
       "if let Key::Pass(p) = &key {\n                    let c = p.with(|b| zeroize::Zeroizing::new(b.to_vec()));\n"
       "                    Box::leak(Box::new(SecretBytes::from_zeroizing(c)));\n                }\n"
       "                let r = sdk.heavy(move || open_entry(&e, &key, None)).await;")],
     C + "--test vault passphrase_not_retained_after_unlock"),
    ("7: a retry signs before the earlier op is Expired",
     [(f"{OP}/submit.rs", "if let Some(op) = earlier_on_lane(&sdk, &prepared).await? {", "if let Some(op) = None::<String> {")],
     L + "retry_on_a_lane_waits_for_expired"),
    ("7: a retry is the earlier op even once Expired",
     [(f"{OP}/submit.rs", "if op.state(row.op.clone()).await? != OpState::Expired {", "if op.state(row.op.clone()).await.is_ok() {")],
     L + "retry_on_a_lane_waits_for_expired"),
]

if __name__ == "__main__":
    main("t13e", MUTANTS)
