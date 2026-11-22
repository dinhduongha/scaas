# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T6's mutants (messages: chain positions, content, envelope, order), each killed by its own named test
through a fixture that reaches its check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t6-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

MS = "clients/pqchat-core/src/message.rs"
OR = "clients/pqchat-core/src/order.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test message "
MUTANTS = [
    ("counter persisted after the send",
     [(MS, "        let counter = self.take_counter(&ep.epoch.id, &device)?;",
       "        let counter = self.next_counter(&ep.epoch.id, &device)?;"),
      (MS, "            }\n        };\n        if sealed.record.sender.to_ascii_lowercase() != ua {",
       "            }\n        };\n        self.take_counter(&ep.epoch.id, &sealed.record.device)?;\n"
       "        if sealed.record.sender.to_ascii_lowercase() != ua {")],
     T + "counter_taken_before_the_seal"),
    ("a walk before the signature check",
     [(MS, "        let ok = self\n            .app\n            .verify_pqchat_record(",
       "        let _ = self.position(ep, &r.sender.to_ascii_lowercase(), &r.device.to_ascii_lowercase(), r.counter);\n"
       "        let ok = self\n            .app\n            .verify_pqchat_record(")],
     T + "walk_only_after_signature_and_membership"),
    ("the walk bound off by a factor",
     [(MS, "pub const WALK_MAX: u64 = 1 << 20;", "pub const WALK_MAX: u64 = 1 << 19;")],
     T + "long_chain_fresh_store"),
    ("positions unbounded",
     [(MS, "        while q.len() > POSITIONS_MAX {", "        while q.len() > usize::MAX {")],
     T + "five_hundred_devices_keep_positions_bounded"),
    ("parents unsorted",
     [(OR, "    v.sort();\n    v.dedup();", "    v.dedup();")],
     T + "parents_at_most_eight_sorted"),
    ("an edit accepted from any UA",
     [(OR, "                .filter(|t| t.sender == a.sender)", "                .filter(|_| true)")],
     T + "edit_and_redact_from_another_ua_ignored"),
    ("the unknown-epoch buffer unbounded",
     [(MS, "            while v.len() > PENDING_MAX {\n                v.remove(0);\n            }\n", "")],
     T + "unknown_epoch_buffered_then_shown"),
]

if __name__ == "__main__":
    main("t6", MUTANTS)
