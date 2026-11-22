# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T9's mutants (recovery, consent, locked seed, device binding), each killed by its own named test through
a fixture that reaches its check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t9-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

RE = "clients/pqchat-core/src/recovery.rs"
MX = "clients/pqchat-core/src/matrix.rs"
DV = "clients/pqchat-core/src/device.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test recovery "
MUTANTS = [
    ("read an unlisted instance",
     [(RE, "                    && num(at(i, \"version\"))? != 0\n", "")],
     T + "finds_every_session_once"),
    ("skip de-duplication",
     [(RE, "                        if !seen.insert(sid.clone()) {\n                            continue;\n                        }\n",
       "                        seen.insert(sid.clone());\n")],
     T + "finds_every_session_once"),
    ("show a session whose home is not listed",
     [(RE, "        if !self.listed(&home_chain, &home).await? {\n            return Ok(None);\n        }\n", "")],
     T + "shown_only_with_a_listed_equal_home"),
    ("open a pending wrap without the user's look",
     [(RE, "        let name = if consent == Consent::Accepted {", "        let name = if true {")],
     T + "pending_session_reaches_nothing"),
    ("join the room before acceptance",
     [(MX, "        self.require_accepted(&ep.epoch.session_id)?;\n", "")],
     T + "pending_session_reaches_nothing"),
    ("drop an event that arrives while locked",
     [(MX, "            } else {\n                k.overflow = true;\n            }", "            }")],
     T + "locked_events_kept_and_read_at_unlock"),
    ("keep the old device id on an anchor mismatch",
     [(DV, "Some(d) if d.anchor.is_some() && d.anchor.as_deref() == anchor => Ok(d),",
       "Some(d) if d.anchor.is_some() => Ok(d),")],
     T + "device_bound_to_its_anchor"),
    ("count a leave as acceptance",
     [(RE, "            self.set_consent(&s, Consent::Declined, true)?", "            self.set_consent(&s, Consent::Accepted, true)?")],
     T + "left_session_declined"),
]

if __name__ == "__main__":
    main("t9", MUTANTS)
