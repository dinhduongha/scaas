# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T4's mutants (record checks, trusted reads, replicas, instances), each killed by its own reason through a
fixture that reaches its check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t4-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

MS = "clients/pqchat-core/src/message.rs"
RD = "clients/pqchat-core/src/reads.rs"
NT = "clients/pqchat-core/src/net.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 "
C = T + "--test check "
MUTANTS = [
    ("skip the envelope check",
     [(MS, '                if e.code() == "Aead" {\n                    DropReason::Envelope', '                if false {\n                    DropReason::Envelope')],
     C + "envelope_a_flipped_byte"),
    ("skip V1",
     [(MS, "        if !ok {\n            return Err(DropReason::Signature);\n        }\n", "        let _ = ok;\n")],
     C + "signature_of_another_key"),
    ("skip the membership check",
     [(MS, "        if !ep.epoch.has_member(&sender) {\n            return Err(DropReason::Member);\n        }\n", "")],
     C + "member_a_sender_outside_the_epoch"),
    ("read membership from the replica",
     [(RD, "        let (home, home_kept) = self.checked_at(s, &s.home, epoch_id, true).await?;",
       "        let (mut home, home_kept) = self.checked_at(s, &s.home, epoch_id, true).await?;"),
      (RD, "            Self::replica_kept(\n                &home,\n                home_kept.as_ref().map(|k| &k.sig),\n                &r,\n                rep_kept.as_ref().map(|k| &k.sig),\n            )?;\n", "            let _ = (&rep_kept, &home_kept);\n            home = r;\n")],
     C + "member_read_at_home_not_at_the_replica"),
    ("drop the counter check",
     [(MS, "        if seen.contains(&r.counter)\n            || (seen.len() >= SEEN_MAX && seen.first().is_some_and(|m| r.counter <= *m))\n        {",
       "        if false {")],
     C + "counter_two_records_one_counter"),
    ("drop the messageId dedupe",
     [(MS, "        if self.chains().seen_id(sid, &id) {", "        if false {")], C + "duplicate_one_record_twice"),
    ("skip the replica equality",
     [(RD, "            Self::replica_kept(\n                &home,\n                home_kept.as_ref().map(|k| &k.sig),\n                &r,\n                rep_kept.as_ref().map(|k| &k.sig),\n            )?;\n", "            let _ = (&r, &rep_kept, &home_kept);\n")], C + "replica_differs_from_home"),
    ("skip the factory listing",
     [(RD, "        if !self\n            .listed(&s.chain, contract)\n            .await\n            .map_err(|_| DropReason::Unlisted)?\n        {",
       "        if false {")],
     C + "unlisted_instance"),
    ("skip the wrap-hash check",
     [(RD, "        check::wrap_hash(&read, signed)?;", "        let _ = (&read, signed);")],
     C + "wrap_hash_before_any_decapsulation"),
    ("mark kemKeyOf as an ordinary read",
     [(NT, '    ("IUARegistry.kemKeyOf", Trusted),', '    ("IUARegistry.kemKeyOf", Plain),')],
     T + "--test reads kem_key_of_is_trusted"),
    ("drop the highest-version check",
     [(RD, "            if high.is_some_and(|h| version < h) {", "            if false {")],
     T + "--test reads kem_version_lowered"),
]

if __name__ == "__main__":
    main("t4", MUTANTS)
