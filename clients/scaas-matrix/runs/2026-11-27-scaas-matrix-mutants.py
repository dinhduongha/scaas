# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-matrix's mutants (plan T9; CLI-MTX-02 to CLI-MTX-06): the privacy defaults, the room-kind filter and refusals, the
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
C = "cd clients/scaas-matrix && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
UNIT = C + "--lib policy::tests::"
PROF = C + "--test profile "
E2E = C + "--test e2e -- --ignored scaas_matrix_against_synapse"

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
     [(P, "        self.mark(room)?;\n        if hold {", "        if hold {")],
     UNIT + "kinds_never_mix"),
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
    ("no profile lock",
     [(LIB, "    f.try_lock().map_err(|e| match e {",
       "    let _ = f.try_lock();\n    Ok::<(), std::fs::TryLockError>(()).map_err(|e| match e {")],
     PROF + "one_client_per_profile_directory"),
    ("the store key written beside the store",
     [(LIB, "    if let Some(k) = key {\n        b = b.sqlite_store_with_config_and_cache_path(",
       "    if let Some(k) = key {\n        let _ = std::fs::write(dir.join(\"key\"), &k.0[..]);\n"
       "        b = b.sqlite_store_with_config_and_cache_path(")],
     PROF + "store_key_on_no_file"),
    ("settings not persisted",
     [(LIB, "            *s\n        };\n        self.inner.put(SETTINGS_KEY, &s).await",
       "            *s\n        };\n        let _ = s;\n        Ok(())")],
     PROF + "settings_persist_with_private_defaults"),
    ("a transport room left unmarked",
     [(TR, "        let id = send!(self, r)?.room_id.to_string();\n        self.0.mark(&id, None).await.map_err(|_| E)?;\n",
       "        let id = send!(self, r)?.room_id.to_string();\n")],
     E2E),
]

if __name__ == "__main__":
    L.main("t9", MUTANTS)
