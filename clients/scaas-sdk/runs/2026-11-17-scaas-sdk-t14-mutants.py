# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T14 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t14-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

H = "clients/scaas-sdk/src/wallet/history.rs"
W = "clients/scaas-sdk/src/watch.rs"
L = "clients/scaas-sdk/src/lib.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test history "
MUTANTS = [
    # the plan's three
    ("one unbounded range", [(H, "let from = top.saturating_sub(LOG_RANGE_MAX - 1);", "let from = 0;")],
     T + "history_pages_with_logs_range"),
    ("block the producer on a full queue",
     [(L, "        let _ = self.events.send(e);",
       "        while self.events.len() >= self.limits.event_queue as usize {\n            std::thread::yield_now();\n        }\n"
       "        let _ = self.events.send(e);")],
     T + "lagged_subscriber"),
    ("write a hidden set's cursor", [(W, ".any(|r| rows_id(r).eq_ignore_ascii_case(&account))", ".any(|_| true)")],
     T + "no_hidden_set_cursor"),
    # each check of the task
    ("resume from the final block, not the cursor",
     [(W, "scan(&pool, &[token], B256::from(word), cur + 1, to)", "scan(&pool, &[token], B256::from(word), fin, to)")],
     T + "cursor_resumes_after_restart"),
    ("the SDK's own write is a StateChanged",
     [(W, "        let _ = self\n            .state_seen\n            .compare_exchange(prev.unwrap_or(0), new, SeqCst, SeqCst);",
       "        let _ = (prev, new);")],
     T + "state_changed_from_another_process"),
    ("no cap per poll", [(W, "let take = n.min(self.limits.max_watch as usize);", "let take = n;")], T + "watch_cap"),
    ("a first read is a BalanceChanged", [(W, ".is_some_and(|v| v != a.value)", ".is_none_or(|v| v != a.value)")],
     T + "history_added_and_balance_changed_events"),
    ("history older than the cursor not dropped",
     [(H, "items.retain(|i| before.is_none_or(|c| (i.block, i.log_index) < (c.block, c.log_index)));", "")],
     T + "history_pages_with_logs_range"),
]

if __name__ == "__main__":
    main("t14", MUTANTS)
