# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T41.evm (the hand-off; spec §27.5 (c)) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t41evm-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

H = "clients/scaas-sdk/src/op/handoff.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
E = "clients/ua-rs/src/wallet/eip712.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test handoff "
W = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test wallet_ops "
MUTANTS = [
    # plan T41's common mutants
    ("the payee check dropped", [(H, "                    if !expect.payee.iter().any(|p| p.eq_ignore_ascii_case(to)) {\n                        return Err(SdkError::ImportNotPayee);\n                    }\n", "                    let _ = to;\n")],
     T + "import_refusals_in_order"),
    ("the relayer check dropped", [(H, "                    if bound != Some(payer) {\n                        return Err(SdkError::ImportRelayerBound);\n                    }\n", "                    let _ = bound;\n")],
     T + "a_bound_relayer_must_be_the_payer"),
    ("the consumed check dropped", [(H, "                if lane_nonce(&pool, Address::from(contract), \"token\", &from, batch).await? > nonce {", "                if lane_nonce(&pool, Address::from(contract), \"token\", &from, batch).await? > nonce && false {")],
     T + "import_refusals_in_order"),
    ("the quote signing", [(Q, "                let unsigned = super::submit::unsigned(&prepared)?;\n", "                let _ = super::submit::sign(&sdk, &prepared).await?;\n                let unsigned = super::submit::unsigned(&prepared)?;\n")],
     W + "every_wallet_pair_is_its_vector"),
    ("an imported operation signed again", [(S, "    if let Some((sig, _)) = &p.t.signed {\n        return Ok((sig.clone(), p.t.extra.clone()));\n    }\n", "")],
     T + "hand_off_import_quote_submit"),
    ("the payer's nonce not advanced", [(S, "        *e = (*e).max(nonce.saturating_add(1));", "        *e = (*e).max(nonce);")],
     T + "payers_and_their_nonces"),
    ("the canonical zeroing of an unbound feeRecipient skipped", [(E, "                if mode & 2 == 0 {\n                    m.insert(\"feeRecipient\".into(), ZERO_ADDRESS.into());\n                }\n", "")],
     T + "an_unbound_fee_recipient_in_the_blob_is_zeroed"),
    # T41.evm's own checks
    ("a fee imported", [(H, "                if !fee.is_zero() || fee_of(row.name, &blob.message)? != \"0\" {", "                if fee.is_zero() && fee_of(row.name, &blob.message)? == \"never\" {")], T + "import_refusals_in_order"),
    ("no margin before validUntil", [(H, "const IMPORT_MARGIN_SECS: u64 = 120;", "const IMPORT_MARGIN_SECS: u64 = 0;")], T + "import_refusals_in_order"),
    ("a confidential kind imported", [(H, "                    .filter(|_| blob.kind == \"token\")\n", "")], T + "import_refusals_in_order"),
    ("the import's simulation dropped", [(H, "                    Ok(g) => g,\n", "                    Ok(g) => g,\n                    Err(_) if true => 0,\n")],
     T + "import_refusals_in_order"),
    ("a hand-off with a fee", [(H, "                if fee_of(p.t.name, &p.t.message)? != \"0\"\n                    || p.t.relay_call", "                if p.t.relay_call")], T + "hand_off_refusals"),
    ("Hedera's ECDSA payer refused", [(Q, "    if network != \"evm\" && network != \"hedera_ecdsa\" {", "    if network != \"evm\" {")], T + "payers_and_their_nonces"),
]

if __name__ == "__main__":
    main("t41evm", MUTANTS)
