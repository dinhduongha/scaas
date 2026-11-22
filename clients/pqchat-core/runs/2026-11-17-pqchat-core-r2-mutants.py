# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core round 2's mutants (the contact card, UA-7 §14 O7; a room joined before, CLI-PQC-05), each killed by its own
named test through a fixture that reaches its check:
python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-r2-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

CK = "clients/clientkeys/src/pqchat.js"
UA = "clients/ua-rs/src/wallet/pqchat.rs"
MX = "clients/pqchat-core/src/matrix.rs"
TCK = "cd clients/clientkeys && node --test --test-reporter=tap --test-name-pattern 'contact cards' test/pqchat.test.js"
TUA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test pqchat_keys "
TPQ = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test matrix_fake "
MUTANTS = [
    ("clientkeys: card signature not checked",
     [(CK, "  return verifyUA(name, bytes(publicKey), PURPOSE_PQCHAT, typed(\"PqChatCard\", card), bytes(sig.signature));",
       "  return true;")],
     TCK, "contact cards"),
    ("clientkeys: card UA not compared",
     [(CK, "  if (String(card.ua).toLowerCase() !== String(ua).toLowerCase()) return false;\n", "")],
     TCK, "contact cards"),
    ("ua-rs: card signature not checked",
     [(UA, "c.ua == *ua && card_typed(c).is_ok_and(|td| verify_typed(ua, &td, sig, state))",
       "c.ua == *ua && card_typed(c).is_ok()")],
     TUA + "cards_reproduce_the_rows"),
    ("ua-rs: card UA not compared",
     [(UA, "c.ua == *ua && card_typed(c).is_ok_and(|td| verify_typed(ua, &td, sig, state))",
       "card_typed(c).is_ok_and(|td| verify_typed(&c.ua, &td, sig, state))")],
     TUA + "cards_reproduce_the_rows"),
    ("crate: a card's refusal ignored",
     [(MX, "        if !ok {\n            return Err(PqChatError::CardRefused);\n        }\n", "        let _ = ok;\n")],
     TPQ + "card_binds_its_matrix_id"),
    ("crate: the claimed Matrix id not matched to the bound ones",
     [(MX, "Ok(claimed.filter(|c| held.contains(c)).cloned())", "Ok(claimed.filter(|_| !held.is_empty()).cloned())")],
     TPQ + "card_binds_only_its_own_matrix_id"),
    ("crate: a room joined before used without its members' check",
     [(MX, "            if !members.iter().all(|m| *m == me || known.contains(&m)) {",
       "            if false && !members.iter().all(|m| *m == me || known.contains(&m)) {")],
     TPQ + "room_joined_before_used_when_its_members_check"),
]

if __name__ == "__main__":
    main("r2", MUTANTS)
