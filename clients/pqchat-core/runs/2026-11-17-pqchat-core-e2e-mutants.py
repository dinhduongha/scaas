# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T11's mutants (the real-crypto e2e, local): each removes one check, reached by its own fixture in
`tests/e2e.rs::e2e_run` with no other check in front of it, and is killed by that fixture's assertion (the record's failure
line names it: `mutant <n>: <reason>`). The plan's numbering; the mutants this round does not run are listed in T11's
decisions Change with their reason.
python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-e2e-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

MS = "clients/pqchat-core/src/message.rs"
RD = "clients/pqchat-core/src/reads.rs"
MX = "clients/pqchat-core/src/matrix.rs"
T = ("cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test e2e -- --ignored "
     "--test-threads 1 e2e_run")
MUTANTS = [
    ("6 the counter check dropped",
     [(MS, "        if seen.contains(&r.counter)\n            || (seen.len() >= SEEN_MAX && seen.first().is_some_and(|m| r.counter <= *m))\n        {\n            return Err(DropReason::Counter);\n        }\n", "")],
     T, "e2e_run"),
    ("7 the messageId dedupe dropped",
     [(MS, "        if self.chains().seen_id(sid, &id) {\n            return Err(DropReason::Duplicate);\n        }\n", "")],
     T, "e2e_run"),
    ("8 the replica equality skipped",
     [(RD, "            Self::replica(&home, &r)?;\n", "            let _ = &r;\n")],
     T, "e2e_run"),
    ("9 the factory listing skipped",
     [(RD, "        if !self\n            .listed(&s.chain, contract)\n            .await\n            .map_err(|_| DropReason::Unlisted)?\n        {\n            return Err(DropReason::Unlisted);\n        }\n", "")],
     T, "e2e_run"),
    ("10 the wrap-hash check skipped",
     [(RD, "        check::wrap_hash(&read, signed)?;\n", "        let _ = (&read, signed);\n")],
     T, "e2e_run"),
    ("14 the pending gate removed (join)",
     [(MX, "    pub async fn join_room(&self, ep: &OpenEpoch) -> Result<RoomUse, PqChatError> {\n        self.require_accepted(&ep.epoch.session_id)?;\n", "    pub async fn join_room(&self, ep: &OpenEpoch) -> Result<RoomUse, PqChatError> {\n")],
     T, "e2e_run"),
]

if __name__ == "__main__":
    main("e2e", MUTANTS)
