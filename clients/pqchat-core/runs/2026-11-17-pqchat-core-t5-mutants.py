# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T5's mutants (sessions, epochs, wraps, removal, leave, msig expansion), each killed by its own named test
through a fixture that reaches its check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t5-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

SE = "clients/pqchat-core/src/session.rs"
RD = "clients/pqchat-core/src/reads.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test session "
MUTANTS = [
    ("epoch = parent (no + 1)",
     [(SE, "        let number = p.epoch + 1;", "        let number = p.epoch;")],
     T + "plain_rekey_is_the_parents_number_plus_one"),
    ("K reused from the parent",
     [(SE, "            .pqchat_epoch_id(s.session_id.clone(), ua.clone(), r.nonce)?;\n        let k = self.app.pqchat_epoch_key(seed)?;",
       "            .pqchat_epoch_id(s.session_id.clone(), ua.clone(), r.nonce)?;\n        let _ = seed;\n        let k = parent.k.clone();")],
     T + "rekey_draws_a_fresh_k"),
    ("the creator absent from admins",
     [(SE, "        let admins = sorted(&r.admins, Some(&me))?;", "        let admins = sorted(&r.admins, None)?;")],
     T + "two_members_one_write"),
    ("a removed member kept",
     [(SE, "        let members: Vec<String> = sorted(&r.members, None)?\n            .into_iter()\n            .filter(|u| !out(u))\n            .collect();",
       "        let members: Vec<String> = sorted(&r.members, None)?;")],
     T + "removed_member_dropped_and_authors_nothing"),
    ("the highest KEM version replaced by the first seen",
     [(RD, "            Ok(version)\n        })?;\n        Ok((kept, raised))", "            Ok(high.unwrap_or(version))\n        })?;\n        Ok((kept, raised))")],
     T + "wraps_at_the_highest_version"),
    ("via not set",
     [(SE, "            seated.extend(leaves.into_iter().map(|l| (l, ua.clone())));",
       "            seated.extend(leaves.into_iter().map(|l| (l, ZERO32.to_string())));")],
     T + "msig_seat_expanded"),
    ("a rekey started automatically on a raised version",
     [(SE, "                    out.push(m.ua.clone());\n",
       "                    out.push(m.ua.clone());\n                    let p = KeyRef::Native { seed: String::new(), network: \"evm\".into(), index: 0 };\n"
       "                    let _ = self.net.prepare(&s.chain, &s.home, \"IPqChat.rekey\", json!({}), &p).await;\n")],
     T + "raised_version_starts_no_rekey"),
    ("a send under a child before its finality",
     [(SE, "            Some(_) => Err(PqChatError::EpochNotFinal),", "            Some(c) => Ok(c),")],
     T + "sends_held_until_the_child_is_final"),
]

if __name__ == "__main__":
    main("t5", MUTANTS)
