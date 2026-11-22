# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T8's mutants (the Matrix transport, binding, conformance), each killed by its own named test through a
fixture that reaches its check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t8-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

MX = "clients/pqchat-core/src/matrix.rs"
SE = "clients/pqchat-core/src/session.rs"
FAKE = "clients/pqchat-core/tests/common/matrix.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test "
MUTANTS = [
    ("process events of any room",
     [(MX, "        let Some(sid) = self.room_session(room)? else {",
       "        let Some(sid) = self.room_session(room)?.or_else(|| self.timelines.lock().ok()?.keys().next().cloned()) else {")],
     T + "matrix_fake events_of_an_unbound_room_ignored"),
    ("use a room joined before",
     [(MX, "            if !members.iter().all(|m| *m == me || known.contains(&m)) {\n                return refuse(RoomRefusal::JoinedBefore);\n            }\n", "")],
     T + "matrix_fake room_joined_before_not_used"),
    ("invite an unbound id",
     [(MX, "        Ok(claimed.filter(|c| held.contains(c)).cloned())", "        Ok(claimed.cloned())")],
     T + "matrix_fake invites_only_bound_ids_once_complete"),
    ("trust a power level for a removal",
     [(MX, "            let admin = p.epoch.admins.contains(&ua);",
       "            let admin = self.room_bind(room)?.is_some_and(|b| b.created);")],
     T + "matrix_fake removal_by_a_parent_admin_only"),
    ("send a Matrix read receipt in a bound room",
     [(FAKE, "        // no receipt, read marker, typing or presence (CLI-PQC-05)\n",
       "        r.ephemeral.push((self.user.clone(), \"m.receipt\".into()));\n")],
     T + "matrix_conformance fake_conforms"),
    ("carry the room id in a chain write",
     [(SE, "\"wrapHashes\": signed.wrap_hashes, \"sealedInfo\": model::hex(&sealed)});",
       "\"wrapHashes\": signed.wrap_hashes, \"sealedInfo\": model::hex(serde_json::to_string(&r.info).unwrap_or_default().as_bytes())});")],
     T + "matrix_fake room_id_in_no_chain_write"),
]

if __name__ == "__main__":
    main("t8", MUTANTS)
