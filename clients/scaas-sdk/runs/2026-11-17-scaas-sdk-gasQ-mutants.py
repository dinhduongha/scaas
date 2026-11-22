# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutants of the owner's rulings Q3, Q4, Q5 of 2026-11-19 ("approved all 5 as proposed") and K1 ("approved both as
proposed"): the WebAuthn cap in every UASig builder (Q3: ua-rs, clientkeys), on SmartKeyAccount and NEAR / Algorand passkeys
(Q4: clientkeys), a self-relay resend's gas from the stored signed calldata (Q5), a PQZ rollover's count held to ROLL_MAX
(K1): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasQ-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

W = "clients/ua-rs/src/wallet/webauthn.rs"
A = "clients/ua-rs/src/wallet/uasig.rs"
SE = "clients/ua-rs/src/wallet/seal.rs"
K = "clients/clientkeys/src/uakey.js"
WJ = "clients/clientkeys/src/webauthn.js"
MO = "clients/clientkeys/src/metaop.js"
G = "clients/scaas-sdk/src/op/gas.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features vectors --test wallet_webauthn a_signer_cannot_bypass_the_cap"
CK3 = "cd clients/clientkeys && ../../scripts/capped node --test test/ua-wallet.test.js"
CK4 = "cd clients/clientkeys && ../../scripts/capped node --test test/webauthn.test.js"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib --features pqz,pqz-set-n2304-kmax4096 "
Q5 = U + "resend_as_self_relay_recomputes_the_signed_gas"
CAP = "        capped(a.len(), c.len())?;\n    }\n    Ok(sig)\n"
MUTANTS = [
    # Q3, ua-rs
    ("Q3 ua-rs: the answer's cap removed", [(W, CAP, "    }\n    Ok(sig)\n")], UA),
    ("Q3 ua-rs: a non-canonical answer passed",
     [(W, "        let (a, c) = crate::verify::webauthn_fields(&sig).ok_or(Error::WebAuthnAssertion)?;\n" + CAP,
       "        if let Some((a, c)) = crate::verify::webauthn_fields(&sig) {\n            capped(a.len(), c.len())?;\n        }\n    }\n    Ok(sig)\n")],
     UA),
    ("Q3 ua-rs: ua_sig bypasses it",
     [(A, "super::webauthn::answer(key, &ua_request(kind, purpose, digest)?)?", "key.sign_request(&ua_request(kind, purpose, digest)?)?")], UA),
    ("Q3 ua-rs: ua_sig_app bypasses it",
     [(A, "super::webauthn::answer(key, &app_request(kind, app_id, digest)?)?", "key.sign_request(&app_request(kind, app_id, digest)?)?")], UA),
    ("Q3 ua-rs: an msig member slot bypasses it",
     [(A, "        super::webauthn::answer(key, &req)\n", "        key.sign_request(&req)\n")], UA),
    ("Q3 ua-rs: a container's sender bypasses it",
     [(SE, "super::webauthn::answer(*k, &seal_request(kind, digest)?)?", "k.sign_request(&seal_request(kind, digest)?)?")], UA),
    # Q3, clientkeys
    ("Q3 clientkeys: a member's answer uncapped", [(K, "    if (m.kind === 0x0100) webauthnCapped(sig);\n", "")], CK3),
    ("Q3 clientkeys: a non-canonical answer passed",
     [(K, '?? fail("WebAuthnAssertion", "not the canonical encoding");', "?? [[], []];")], CK3),
    ("Q3 clientkeys: the cap off by one",
     [(K, "  if (f[0].length + f[1].length > WEBAUTHN_MAX_ASSERTION)\n", "  if (f[0].length + f[1].length >= WEBAUTHN_MAX_ASSERTION)\n")], CK3),
    # Q4, clientkeys
    ("Q4: encodeAssertion uncapped", [(WJ, "  const [a, c] = assertionCapped(authenticatorData, clientDataJSON);\n  const { r, s }", "  const [a, c] = [bytesOf(authenticatorData), bytesOf(clientDataJSON)];\n  const { r, s }")], CK4),
    ("Q4: passkeyAssertion uncapped", [(MO, "= assertionCapped(a.authenticatorData, a.clientDataJSON);", "= [a.authenticatorData, a.clientDataJSON];")], CK4),
    ("Q4: the cap off by one",
     [(WJ, "  if (a.length + c.length > WEBAUTHN_MAX_ASSERTION)",
       "  if (a.length + c.length >= WEBAUTHN_MAX_ASSERTION)")], CK4),
    ("Q4: refused without its code", [(WJ, "throw coded(\"WebAuthnTooLong\", `authenticatorData", "throw new Error(`authenticatorData")], CK4),
    # Q5
    ("Q5: resend not recomputed",
     [(S, "                        let quote = signed_quote(\n                            &sdk,\n                            &row.chain,",
       "                        let _recomputed = signed_quote(\n                            &sdk,\n                            &row.chain,")], Q5),
    ("Q5: the signer's kind not kept", [(S, "                    signer_kind: Some(signer),\n", "                    signer_kind: Some(0),\n")], Q5),
    ("Q5: the unsigned length not kept",
     [(S, "                    unsigned_len: Some(unsigned_len as u64),\n", "                    unsigned_len: Some(0),\n")], Q5),
    ("Q5: the stored signed calldata not read",
     [(S, "                            &unhex(&row.calldata)?,\n                            own,\n", "                            &vec![0u8; unsigned_len],\n                            own,\n")], Q5),
    # K1
    ("K1: no clamp", [(G, "            let n = roll_max().map_or(n, |m| n.min(alloy::primitives::U256::from(m)));\n", "")],
     U + "a_huge_rollover_is_quoted_at_roll_max"),
    ("K1: every count clamped",
     [(G, "    u64::try_from(n).ok()\n}\n\n/// The kind of the second signature",
       "    u64::try_from(n).ok().map(|n| n.min(roll_max().unwrap_or(n)))\n}\n\n/// The kind of the second signature")],
     U + "item_count_reads_the_operations_counts"),
    ("K1: a set's figure wrong", [(G, "const ROLL_MAX: [u64; 4] = [80, 64, 48, 32];", "const ROLL_MAX: [u64; 4] = [80, 80, 48, 32];")],
     U + "roll_max_is_the_sets_own"),
    ("K1: another set's figure picked",
     [(G, "        .find(|(on, _)| **on)\n", "        .find(|(on, _)| !**on)\n")], U + "roll_max_is_the_sets_own"),
]

if __name__ == "__main__":
    main("gasQ", MUTANTS)
