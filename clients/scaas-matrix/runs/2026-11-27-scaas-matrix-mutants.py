# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-matrix's mutants (plan T9, then the Fable review's fixes as record `r1`; CLI-MTX-02 to CLI-MTX-09): the privacy defaults, the room-kind filter and refusals, the
per-profile lock, the store key never on disk and the URL rule, each killed by its own named test, one at a time, through the
scaas-sdk plan's runner (clients/scaas-sdk/runs/mutants_lib.py, which runs every command under scripts/mutant_guard.py):
python3 clients/scaas-matrix/runs/2026-11-27-scaas-matrix-mutants.py check | run [name…]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/scaas-matrix/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-27-scaas-matrix-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-27-scaas-matrix-summary.txt"]

P = "clients/scaas-matrix/src/policy.rs"
LIB = "clients/scaas-matrix/src/lib.rs"
TR = "clients/scaas-matrix/src/transport.rs"
PQ_CONSENT = "clients/pqchat-core/src/consent.rs"
PQ_MATRIX = "clients/pqchat-core/src/matrix.rs"
PQC = "cd clients/pqchat-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
C = "cd clients/scaas-matrix && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
UNIT = C + "--lib policy::tests::"
PROF = C + "--features testing --test profile "
E2E = C + "--test e2e -- --ignored scaas_matrix_against_synapse"

# "records unbounded on read" (the sealed length check in `unseal`) is left out: it is equivalent at the error level, since the
# plaintext bound of `policy::decode` refuses the same record after decryption (r1: survived); the check bounds the work, not
# the outcome.
MUTANTS = [
    ("public receipts by default",
     [(P, "    } else {\n        Receipt::Private\n    })", "    } else {\n        Receipt::Public\n    })")],
     UNIT + "defaults_are_private"),
    ("typing on by default",
     [(P, "    Ok(s.typing)\n", "    Ok(true)\n")],
     UNIT + "defaults_are_private"),
    ("presence online on sync",
     [(LIB, ".set_presence(PresenceState::Offline)", ".set_presence(PresenceState::Online)")],
     PROF + "every_sync_says_presence_offline"),
    ("a PqChat room in the Matrix list",
     [(P, "RoomFilter::Matrix => self.kind(room) == RoomKind::Matrix,", "RoomFilter::Matrix => true,")],
     UNIT + "kinds_never_mix"),
    ("a held invite not marked PqChat",
     [(P, "        self.held.push(room.to_string());\n        Ok(())\n", "        Ok(())\n")],
     UNIT + "kinds_never_mix"),
    ("a held invite takes a joined Matrix room",
     [(P, "        if joined_matrix {\n            // a room joined meanwhile", "        if false {\n            // a room joined meanwhile")],
     UNIT + "a_held_invite_cannot_take_a_joined_matrix_room"),
    ("any string marked",
     [(P, "    room.len() <= ROOM_ID_MAX\n        && room.bytes().all(|b| (0x21..=0x7e).contains(&b))\n        && RoomId::parse(room).is_ok()",
       "    !room.is_empty()")],
     UNIT + "a_held_invite_cannot_take_a_joined_matrix_room"),
    ("Matrix actions allowed in a PqChat room",
     [(P, "        RoomKind::PqChat => Err(MatrixError::MatrixRoomKind),", "        RoomKind::PqChat => Ok(()),")],
     UNIT + "nothing_ephemeral_in_a_pqchat_room_whatever_the_settings"),
    ("marks unbounded",
     [(P, "&& self.pqchat.len() >= MARKS_MAX", "&& self.pqchat.len() > MARKS_MAX + 1")],
     UNIT + "marks_are_bounded"),
    ("http to any host",
     [(P, "        \"http\" if loopback => Ok(u),", "        \"http\" => Ok(u),")],
     UNIT + "homeserver_https_or_loopback_ip"),
    ("http to any host, at login",
     [(P, "        \"http\" if loopback => Ok(u),", "        \"http\" => Ok(u),")],
     PROF + "login_refuses_plain_http_off_loopback"),
    ("a pusher over http",
     [(P, "        Ok(u) if u.scheme() == \"https\" => Ok(()),", "        Ok(_) => Ok(()),")],
     UNIT + "own_records_bounded_before_decoding"),
    ("no profile lock",
     [(LIB, "    f.try_lock().map_err(|e| match e {",
       "    let _ = f.try_lock();\n    Ok::<(), std::fs::TryLockError>(()).map_err(|e| match e {")],
     PROF + "one_client_per_profile_directory"),
    ("close keeps the client for the transport",
     [(LIB, "        let client = lk(&self.inner.client).take();", "        let client = lk(&self.inner.client).clone();")],
     PROF + "one_client_per_profile_directory"),
    ("the store key written beside the store",
     [(LIB, "    if let Some(k) = key {\n        b = b.sqlite_store_with_config_and_cache_path(",
       "    if let Some(k) = key {\n        let _ = std::fs::write(dir.join(\"key\"), &k.0[..]);\n"
       "        b = b.sqlite_store_with_config_and_cache_path(")],
     PROF + "no_secret_on_any_file"),
    ("records stored in the clear",
     [(LIB, "        let b = seal(&self.cipher, name, v, max)?;\n",
       "        let b = serde_json::to_vec(v).map_err(|_| MatrixError::Internal)?;\n")],
     PROF + "no_secret_on_any_file"),
    ("settings not persisted",
     [(LIB, "        self.inner\n            .put(SETTINGS_KEY, &s, policy::SETTINGS_MAX)\n            .await?;\n", "")],
     PROF + "settings_persist_with_private_defaults"),
    ("a login over an existing store",
     [(LIB, "        if store_dir(dir).exists() {\n            return Err(MatrixError::MatrixSession);\n        }\n", "")],
     PROF + "a_login_over_a_store_is_refused_and_wipe_clears_it"),
    ("bound rooms not marked",
     [(TR, "    async fn bound(&self, room: &str) -> Result<(), TransportError> {\n        self.mark(room).await\n",
       "    async fn bound(&self, room: &str) -> Result<(), TransportError> {\n        let _ = room;\n        Ok(())\n")],
     PROF + "marks_persist_and_refuse_a_non_room"),
    ("cleartext in an encrypted room shown as ordinary",
     [(LIB, "        None if encrypted_room && !came_encrypted => Trust::Unencrypted,\n", "")],
     C + "--lib tests::items_by_kind"),
    ("a commitment mismatch read as a cancel",
     [(LIB, "Some(\"m.mismatched_sas\" | \"m.key_mismatch\" | \"m.mismatched_commitment\")",
       "Some(\"m.mismatched_sas\" | \"m.key_mismatch\")")],
     C + "--lib tests::verification_endings"),
    ("a PqChat event above the bound forwarded",
     [(TR, "    if m.ty != EVENT_TYPE || c.len() > EVENT_MAX {", "    if m.ty != EVENT_TYPE {")],
     C + "--lib transport::tests::pqchat_events_only_and_bounded"),
    ("held invites unbounded",
     [(P, "        if self.held.len() >= HELD_MAX {\n            self.held.remove(0);\n        }\n", "")],
     UNIT + "strangers_fill_only_the_held_set"),
    ("a release keeps the held room PqChat",
     [(P, "        if !hold {\n            self.held.retain(|h| h != room);\n", "        if !hold {\n")],
     UNIT + "kinds_never_mix"),
    ("the record cipher replaced under another key",
     [(LIB, "            StoreCipher::import_with_key(&key.0[..], &b).map_err(|_| MatrixError::MatrixStore)\n        }",
       "            StoreCipher::import_with_key(&key.0[..], &b)\n                .or_else(|_| StoreCipher::new())\n                .map_err(|_| MatrixError::MatrixStore)\n        }")],
     C + "--lib tests::the_record_cipher_opens_only_under_its_store_key"),
    ("a closed handle's logout wipes",
     [(LIB, "        let c = self.inner.client()?;\n        let at_server = matches!(",
       "        let c = match self.inner.client() {\n            Ok(c) => c,\n            Err(_) => {\n                let _ = std::fs::remove_dir_all(store_dir(&self.dir));\n                return Err(MatrixError::MatrixSession);\n            }\n        };\n        let at_server = matches!(")],
     PROF + "one_client_per_profile_directory"),
    ("joined read from the local view",
     [(LIB, "            self.client()?\n                .send(joined_rooms::v3::Request::new())\n                .await\n                .map_err(|_| MatrixError::MatrixRoom)?\n                .joined_rooms\n                .iter()\n                .any(|r| r.as_str() == room)",
       "            let _ = joined_rooms::v3::Request::new();\n            self.client()?\n                .get_room(&RoomId::parse(room).map_err(|_| MatrixError::MatrixArgument)?)\n                .is_some_and(|r| r.state() == RoomState::Joined)")],
     E2E),
    ("no answer taken as not joined",
     [(LIB, "                .await\n                .map_err(|_| MatrixError::MatrixRoom)?\n                .joined_rooms\n                .iter()\n                .any(|r| r.as_str() == room)",
       "                .await\n                .map(|x| x.joined_rooms.iter().any(|r| r.as_str() == room))\n                .unwrap_or(false)")],
     PROF + "marks_persist_and_refuse_a_non_room"),
    ("a held room kept after the account joins it",
     [(P, "            // a room joined meanwhile (from another client) is the user's Matrix room again: its hold dropped (J-1)\n            self.held.retain(|h| h != room);\n", "")],
     UNIT + "a_held_invite_cannot_take_a_joined_matrix_room"),
    ("the sync keeps a joined held room PqChat",
     [(LIB, "    for r in held_joined {\n", "    for r in held_joined.into_iter().take(0) {\n")],
     E2E),
    ("preview holds a room already joined",
     [(PQ_CONSENT, "            if !t.joined(room).await? {", "            if true {")],
     PQC + "--test recovery preview_fails_closed_when_the_hold_is_refused"),
    ("preview not failing closed",
     [(PQ_CONSENT, "            t.hold_invite(room, true).await?;", "            let _ = t.hold_invite(room, true).await;")],
     PQC + "--test recovery preview_fails_closed_when_the_hold_is_refused"),
    ("a bound room not told on its second use",
     [(PQ_MATRIX, "            }) if s == sid => return self.told_bound(room).await,", "            }) if s == sid => return Ok(RoomUse::Bound),")],
     PQC + "--test matrix_fake a_bound_room_is_told_to_the_transport"),
    ("bound rooms not listed for a new login",
     [(PQ_MATRIX, "            if !v.iter().any(|r| r == room) {\n                v.push(room.to_string());\n            }\n", "")],
     PQC + "--test matrix_fake a_bound_room_is_told_to_the_transport"),
    ("a transport room left unmarked",
     [(TR, "        let id = send!(self, r)?.room_id;\n        self.mark(id.as_str()).await?;\n",
       "        let id = send!(self, r)?.room_id;\n")],
     E2E),
    ("an unverified device's refusal unnamed",
     [(LIB, "            MatrixError::MatrixDeviceUnverified\n        }\n        _ => MatrixError::MatrixSend,",
       "            MatrixError::MatrixSend\n        }\n        _ => MatrixError::MatrixSend,")],
     E2E),
    ("auto-join on invite",
     [(LIB, "    let mut changed = !res.rooms.invited.is_empty() || !res.rooms.left.is_empty();\n",
       "    let mut changed = !res.rooms.invited.is_empty() || !res.rooms.left.is_empty();\n"
       "    for r in res.rooms.invited.keys() {\n        if let Some(x) = c.get_room(r) {\n            let _ = x.join().await;\n        }\n    }\n")],
     E2E),
]

if __name__ == "__main__":
    L.main("r1", MUTANTS)
