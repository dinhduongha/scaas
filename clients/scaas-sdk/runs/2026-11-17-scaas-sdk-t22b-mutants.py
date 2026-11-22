# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T22's gaps (the CLI's confirm per command; the session's objects; JSON text flags):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t22b-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/scaas-cli/src/main.rs"
F = "clients/scaas-cli/src/flex.rs"
K = "clients/scaas-cli/src/calls.rs"
D = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --features dev-profiles --test cli -- --exact "
MUTANTS = [
    # the brief's mutant: one signing command's confirm removed
    (
        "admin sign-rescue-vault signs without asking",
        [(K, '(r: RescueVault) @sign => { cx.confirm(json!({"sign": r}))?; js(', "(r: RescueVault) @sign => { js(")],
        D + "every_signing_command_asks_first",
    ),
    (
        "dex place listed without its confirm",
        [(K, '"dex place" "Dex::place" {order: H<Arc<PreparedOrder>>} @sign => {', '"dex place" "Dex::place" {order: H<Arc<PreparedOrder>>} => {')],
        D + "every_command_declares_its_confirm_class",
    ),
    (
        "registry writes submitted without asking",
        [(M, '                cx.confirm(json!({"review": review(&w.review()), "quote": quote, "write": w.id(), "chain": w.chain(), "entry": w.entry(), "ua": w.ua()}))?;\n', "")],
        D + "every_signing_command_asks_first",
    ),
    (
        "a session's prepared operation kept as a type no call names",
        [(M, "            keep(&n, Arc::new(p));\n", "            keep(&n, p);\n")],
        D + "every_signing_command_asks_first",
    ),
    (
        "a text flag given JSON refused",
        [(F, "            o @ (Value::Object(_) | Value::Array(_)) => v.visit_string(o.to_string()),\n", "")],
        D + "every_signing_command_asks_first",
    ),
]

if __name__ == "__main__":
    main("t22b", MUTANTS)
