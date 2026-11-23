# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T26, the review's fixes (areas B and C, 2026-11-23) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t26-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

PRF = "clients/scaas-sdk/src/vault/prf.rs"
SOR = "clients/scaas-sdk/src/wallet/families/soroban_ops.rs"
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
]

if __name__ == "__main__":
    main("t26", MUTANTS)
