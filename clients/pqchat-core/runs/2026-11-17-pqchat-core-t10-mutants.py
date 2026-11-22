# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T10's mutants (public topics), each killed by its own named test through a fixture that reaches its
check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t10-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

TO = "clients/pqchat-core/src/topics.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test topics "
MUTANTS = [
    ("skip the factory listing of the ref's instance",
     [(TO, "        if !self\n            .listed(&on.chain, &on.instance)\n            .await\n            .map_err(|_| RefFault::Unreadable)?\n        {\n            return Err(RefFault::Unlisted);\n        }\n", "")],
     T + "ref_verified_only_when_listed"),
    ("skip the home check",
     [(TO, "        if t.home_chain != uid || t.home_chat_contract != on.instance {\n            return Err(RefFault::OtherHome);\n        }\n", "")],
     T + "ref_refused_at_another_home"),
    ("accept a seq jump (vote)",
     [(TO, "self.vote_of(on, &eid, &voter).await?.1 + 1;", "self.vote_of(on, &eid, &voter).await?.1 + 2;")],
     T + "seq_is_stored_plus_one"),
    ("accept a seq jump (writer)",
     [(TO, "let seq = model::num(at(&v, \"seq\"))? + 1;", "let seq = model::num(at(&v, \"seq\"))? + 2;")],
     T + "seq_is_stored_plus_one"),
    ("accept a seq jump (topic update)",
     [(TO, "self.topic(on, topic_id).await?.seq + 1;", "self.topic(on, topic_id).await?.seq + 2;")],
     T + "seq_is_stored_plus_one"),
]

if __name__ == "__main__":
    main("t10", MUTANTS)
