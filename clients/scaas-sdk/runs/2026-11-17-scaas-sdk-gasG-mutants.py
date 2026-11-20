# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's rulings G1 and G3 of 2026-11-19 ("approved all 6 as proposed"): `ua_extra` when
either party the entry debits is a derived UA (G1); the calldata part recomputed from the signed calldata, never below the
quote, refused above `max_gas` (G3): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasG-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
W = "clients/ua-rs/src/wallet/webauthn.rs"
X = "clients/ua-rs/src/wallet/signer.rs"
K = "clients/clientkeys/src/uakey.js"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features vectors "
CK = "cd clients/clientkeys && ../../scripts/capped node --test test/ua-wallet.test.js"
T = "signed_gas_is_recomputed_from_the_signature"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
G1 = "        if signer != NATIVE_EVM || op.attached.is_some_and(|k| k != Some(NATIVE_EVM)) {\n"
MUTANTS = [
    # G1: either party debited
    ("G1: the attached owner ignored (signer only, as before)", [(G, " || op.attached.is_some_and(|k| k != Some(NATIVE_EVM))", "")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("G1: an attached signature of unknown kind read as native",
     [(G, "op.attached.is_some_and(|k| k != Some(NATIVE_EVM))", "op.attached.is_some_and(|k| k.is_some_and(|k| k != NATIVE_EVM))")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("G1: a native attached owner counted", [(G, "op.attached.is_some_and(|k| k != Some(NATIVE_EVM))", "op.attached.is_some()")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("G1: added twice when both are derived",
     [(G, "            g = g.saturating_add(b.ua_extra.unwrap_or(0));\n",
       "            g = g.saturating_add(b.ua_extra.unwrap_or(0));\n"
       "            if signer != NATIVE_EVM && op.attached.is_some() {\n"
       "                g = g.saturating_add(b.ua_extra.unwrap_or(0));\n"
       "            }\n")],
     U + "gas_ua_extra_for_a_derived_signer"),
    # G3, the SDK: the gas recomputed from the signed calldata
    ("G3: nothing recomputed", [(G, "        0 => quoted,\n        more =>", "        _ => quoted,\n        more if false =>")],
     U + T),
    ("G3: lowered when the signature is shorter than counted",
     [(G, "        0 => quoted,\n",
       "        0 => quoted.saturating_sub(with_margin(counted.saturating_sub(signed).saturating_mul(PER_BYTE))),\n")],
     U + "signed_gas_counts_the_real_signature"),
    ("G3: the verify row's sig_bytes not counted", [(G, "                    .map(|v| v.sig_bytes)\n", "                    .map(|_| 0)\n")],
     U + T),
    ("G3: an app's figure read as counting sig_bytes",
     [(G, "        Some(GasFrom::Chain | GasFrom::Module(_) | GasFrom::Reference) => {", "        Some(_) => {")],
     U + "signed_gas_counts_the_real_signature"),
    ("G3: the transaction signed with the old quote",
     [(S, "                let quote = match &quote.path {\n                    SubmitPath::SelfRelay { .. } => {\n",
       "                let _signed = match &quote.path {\n                    SubmitPath::SelfRelay { .. } => {\n"),
      (S, "                    _ => quote,\n", "                    _ => quote.clone(),\n")],
     U + T),
    ("G3: max_gas not checked by name",
     [(Q, "    if gas > sdk.limits.max_gas {\n        return Err(SdkError::SignedGasAboveCap);\n    }\n", "")], U + T),
    ("G3: max_gas off by one", [(Q, "    if gas > sdk.limits.max_gas {\n", "    if gas >= sdk.limits.max_gas {\n")], U + T),
    ("G3: not put back on refusal",
     [(S, "                            Err(e) => {\n                                put_back(&sdk, &prepared);\n                                return Err(e);\n                            }\n                        }\n                    }\n                    _ => quote,",
       "                            Err(e) => {\n                                return Err(e);\n                            }\n                        }\n                    }\n                    _ => quote,")],
     U + T),
    # G3, ua-rs: the WebAuthn cap
    ("G3 ua-rs: the builder's cap removed", [(W, "    capped(auth_data.len(), client_data_json.len())?;\n", "")],
     UA + "--test wallet_webauthn sign_json_refusals"),
    ("G3 ua-rs: the cap off by one", [(W, "        Some(n) if n <= WEBAUTHN_MAX_ASSERTION => Ok(()),", "        Some(n) if n < WEBAUTHN_MAX_ASSERTION => Ok(()),")],
     UA + "--test wallet_webauthn sign_json_accepted_rows"),
    ("G3 ua-rs: refused without its name", [(W, "        _ => Err(Error::WebAuthnTooLong),", "        _ => Err(Error::WebAuthnAssertion),")],
     UA + "--test wallet_webauthn sign_json_refusals"),
    ("G3 ua-rs: an external device's assertion uncapped",
     [(X, "                super::webauthn::capped(a.len(), c.len())?;\n", "")],
     UA + "--test wallet_external an_external_assertion_above_the_cap_is_refused"),
    # G3, clientkeys: the same cap
    ("G3 clientkeys: the cap removed",
     [(K, "  if (authData.length + clientDataJSON.length > WEBAUTHN_MAX_ASSERTION)\n", "  if (false)\n")], CK),
]

if __name__ == "__main__":
    main("gasG", MUTANTS)
