# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T11's mutants (the real-crypto e2e, local): each removes one check, reached by its own fixture in
`tests/e2e.rs::e2e_run` with no other check in front of it, and is killed by that fixture's assertion (the record's failure
line names it: `mutant <n>: <reason>`). The plan's numbering, all 15; where a check lives in the SDK or ua-rs the mutant is
applied there and killed through the e2e (T11's decisions Change names each form).
python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-e2e-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

MS = "clients/pqchat-core/src/message.rs"
RD = "clients/pqchat-core/src/reads.rs"
MX = "clients/pqchat-core/src/matrix.rs"
SE = "clients/pqchat-core/src/session.rs"
SK = "clients/scaas-sdk/src/pqchat_keys.rs"
SA = "clients/scaas-sdk/src/app_core.rs"
SO = "clients/scaas-sdk/src/op/mod.rs"
UK = "clients/ua-rs/src/wallet/pqchat_keys.rs"
T = ("cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --features vectors --test e2e -- "
     "--ignored --test-threads 1 e2e_run")
MUTANTS = [
    ("1 K2 unwrap with another KEM version's key",
     [(SK, "            .and_then(|k| k.kem_key(wrap.key_id))", "            .and_then(|k| k.kem_key(wrap.key_id.saturating_sub(1)))")],
     T, "e2e_run"),
    ("2 the envelope check skipped",
     [(MS, '                if e.code() == "Aead" {', "                if false {")],
     T, "e2e_run"),
    ("3 V1 skipped",
     [(MS, "        if !ok {\n            return Err(DropReason::Signature);\n        }\n", "        let _ = ok;\n")],
     T, "e2e_run"),
    ("4 membership read from the replica",
     [(RD, "        let home = self.checked_at(s, &s.home, epoch_id).await?;",
       "        let home = self.checked_at(s, replica.unwrap_or(&s.home), epoch_id).await?;"),
      (RD, "            .open_own_wrap(&s.chain, &s.home, &home, account, me)",
       "            .open_own_wrap(&s.chain, replica.unwrap_or(&s.home), &home, account, me)")],
     T, "e2e_run"),
    ("5 the home slot ignored",
     [(SE, "        if let Some(c) = self.child_of(s, &epoch).await? {",
       "        if let Some(c) = {\n            let _ = s;\n            None::<String>\n        } {")],
     T, "e2e_run"),
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
    ("11 the sealedInfo open's check skipped",
     [(UK, "            sealed.get(12..).ok_or(Error::Aead)?,\n        )?;\n        canonical_content(&pt)",
       "            sealed.get(12..).ok_or(Error::Aead)?,\n        )?;\n        unpad(&pt)")],
     T, "e2e_run"),
    ("12 unpad accepting a non-zero fill",
     [(UK, "    if *again != pt {", "    if again.len() != pt.len() {")],
     T, "e2e_run"),
    ("13 finality ignored",
     [(SO, "        crate::Finality::Depth(n) => BlockChoice::Depth(n),", "        crate::Finality::Depth(_) => BlockChoice::Depth(0),")],
     T, "e2e_run"),
    ("15 a discovered endpoint allowed for the KEM key",
     [(SA, "                Purpose::FeedsDecryption,\n                |at| async move {\n                    call_at(pool, &at, registry, \"kemKeyAt(bytes32,uint64)\"",
       "                Purpose::Plain,\n                |at| async move {\n                    call_at(pool, &at, registry, \"kemKeyAt(bytes32,uint64)\"")],
     T, "e2e_run"),
]

if __name__ == "__main__":
    main("e2e", MUTANTS)
