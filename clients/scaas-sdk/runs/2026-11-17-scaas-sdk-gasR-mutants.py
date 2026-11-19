# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutants of the PR A review's six findings (Claude review of 2026-11-19; controller call under the owner's auto-run of
2026-11-19): (1) a gas table's unknown key refused, GasFieldUnknown; (2) a gateway row's self-relay resend takes the larger of
the row's own figure and the payer's quote; (3) the signed re-quote held to the block gas limit; (4) a third party's derived
holder adds ua_extra; (5) clientkeys' WebAuthn caps read an ArrayBuffer by its bytes. (6) is a doc fix, no mutant:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasR-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

C = "clients/scaas-sdk/src/config.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
K = "clients/clientkeys/src/uakey.js"
WJ = "clients/clientkeys/src/webauthn.js"
MO = "clients/clientkeys/src/metaop.js"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib --features pqz,pqz-set-n2304-kmax4096 "
F1 = U + "gas_table_unknown_key_refused"
F2 = U + "resend_as_self_relay_takes_the_rows_own_figure"
F3 = U + "signed_gas_is_held_to_the_block_limit"
F4 = U + "holder"
F4Q = U + "operator_transfer_quote_counts_a_derived_holder"
CK3 = "cd clients/clientkeys && ../../scripts/capped node --test test/ua-wallet.test.js"
CK4 = "cd clients/clientkeys && ../../scripts/capped node --test test/webauthn.test.js"
MUTANTS = [
    # 1
    ("F1: unknown keys not refused",
     [(C, "            named = Some(crate::SdkError::GasFieldUnknown);\n", "")], F1),
    ("F1: the top level not checked", [(C, "        if unknown_key(&v, GAS_TOP_KEYS)\n", "        if false\n")], F1),
    ("F1: verify rows not checked",
     [(C, "            || verify.iter().any(|r| unknown_key(r, GAS_VERIFY_KEYS))\n", "")], F1),
    ("F1: a row's parts not checked",
     [(C, "                || GAS_PART_KEYS\n                    .iter()\n                    .any(|(p, pk)| p == k && unknown_key(v, pk))\n",
       "                || false\n")], F1),
    ("F1: a generator key not allowed (control)",
     [(C, '            "second_party",\n            "unmeasured",\n', '            "unmeasured",\n')], F1),
    # 2
    ("F2: resend ignores the row's own figure",
     [(S, "                            unhex(&row.calldata)?.len(),\n                            own,\n",
       "                            unhex(&row.calldata)?.len(),\n                            {\n                                let _ = own;\n                                None\n                            },\n")],
     F2),
    ("F2: the row's figure replaces a higher quote",
     [(Q, "        Some((g, from)) if g > q.gas_limit => (g, Some(from)),\n", "        Some((g, from)) => (g, Some(from)),\n")], F2),
    ("F2: the row's lane state misread",
     [(S, '(&row.entry, &row.kind, signer, row.nonce == "0")', '(&row.entry, &row.kind, signer, row.nonce != "0")')], F2),
    # 3
    ("F3: the block limit not checked after signing",
     [(Q, "    if c.profile.tx_gas_cap.is_some_and(|cap| gas > cap) || gas > block.limit {\n",
       "    if c.profile.tx_gas_cap.is_some_and(|cap| gas > cap) {\n")], F3),
    ("F3: the block limit off by one",
     [(Q, "    if c.profile.tx_gas_cap.is_some_and(|cap| gas > cap) || gas > block.limit {\n",
       "    if c.profile.tx_gas_cap.is_some_and(|cap| gas > cap) || gas >= block.limit {\n")], F3),
    # 4
    ("F4: a derived holder adds nothing",
     [(G, " || op.attached.is_some_and(|k| k != Some(NATIVE_EVM)) || op.holder {",
       " || op.attached.is_some_and(|k| k != Some(NATIVE_EVM)) {")], F4),
    ("F4: an operator transfer's account read inverted",
     [(G, "            id.is_none_or(|id| !scaas_ua::in_native_space(&id))\n",
       "            id.is_none_or(|id| scaas_ua::in_native_space(&id))\n")], F4),
    ("F4: an unreadable account counted native",
     [(G, "            id.is_none_or(|id| !scaas_ua::in_native_space(&id))\n",
       "            id.is_some_and(|id| !scaas_ua::in_native_space(&id))\n")], F4),
    ("F4: a force transfer's record holder counted native",
     [(G, '        "mtxForceTransfer" => true,\n', '        "mtxForceTransfer" => false,\n')], F4),
    ("F4: the quote does not read the holder",
     [(Q, "        holder: super::gas::holder_derived(key.0, message),\n", "        holder: false,\n")], F4Q),
    # 5
    ("F5: the cap reads .length of the raw inputs",
     [(WJ, "  if (a.length + c.length > WEBAUTHN_MAX_ASSERTION)\n",
       "  if (authenticatorData.length + clientDataJSON.length > WEBAUTHN_MAX_ASSERTION)\n")], CK4),
    ("F5: an ArrayBuffer not read as bytes",
     [(WJ, "  if (b instanceof ArrayBuffer) return new Uint8Array(b);\n", "")], CK4),
    ("F5: not-bytes not refused by name",
     [(WJ, '  if (!a || !c) throw coded("WebAuthnAssertion", "authenticatorData and clientDataJSON must be bytes");\n', "")],
     CK4),
    ("F5: passkeyAssertion returns the raw authenticatorData",
     [(MO, "  return { authenticatorData, clientDataJSON: cdj, signature: concatBytes(r, s) };",
       "  return { authenticatorData: a.authenticatorData, clientDataJSON: cdj, signature: concatBytes(r, s) };")], CK4),
    ("F5 uakey: the cap reads .length of the raw inputs",
     [(K, "  if (authData.length + clientDataJSON.length > WEBAUTHN_MAX_ASSERTION)\n",
       "  if ((ad?.length ?? 0) + (cd?.length ?? 0) > WEBAUTHN_MAX_ASSERTION)\n")], CK3),
    ("F5 uakey: not-bytes not refused by name",
     [(K, '  if (!authData || !clientDataJSON) no("authData and clientDataJSON must be bytes");\n', "")], CK3),
]

if __name__ == "__main__":
    main("gasR", MUTANTS)
