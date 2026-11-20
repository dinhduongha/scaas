# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's rulings A1-A6 of 2026-11-19 ("approved"): a derived signer's `ua_extra` (A1),
the attached signature's verify gas without its bytes (A3), the refusal of a verify row without `sig_bytes` (A4), the
longest / worst-case verify rows (A5), the wrap-in fee rows (A6) and the sampled end-to-end check: python3
clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasA-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
R = "clients/scaas-sdk/gas/reference.json"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
UA_ADD = "            g = g.saturating_add(b.ua_extra.unwrap_or(0));\n"
MUTANTS = [
    # A1: ua_extra
    ("ua_extra not added", [(G, UA_ADD, "")], U + "gas_ua_extra_for_a_derived_signer"),
    ("ua_extra added for the native key too", [(G, "if signer != NATIVE_EVM || op.attached.is_some_and(|k| k != Some(NATIVE_EVM)) || op.holder {", "if true {")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("parse: ua_extra dropped", [(C, 'ua_extra: match r.get("ua_extra") {', "ua_extra: match None::<&serde_json::Value> {")],
     U + "gas_table_extra_fields_parse"),
    # A3: the attached signature's verify gas only
    ("the attached signature's bytes added again",
     [(G, "tables, k, false, &attached)", "tables, k, true, &attached)")],
     U + "gas_second_signature"),
    ("an unknown attached signature's bytes added again",
     [(G, "tables, *k, false, &capped)", "tables, *k, true, &capped)")],
     U + "gas_second_signature"),
    ("the attached signature's verify gas dropped",
     [(G, "Some(Some(k)) => verify_part(chain, opt_in, tables, k, false, &attached).map(|v| v.0),", "Some(Some(_)) => Some(0),")],
     U + "gas_second_signature"),
    ("the signer's own sig_bytes dropped too",
     [(G, "verify_part(chain, opt_in, tables, signer, true, &own)", "verify_part(chain, opt_in, tables, signer, false, &own)")],
     U + "gas_save_fee_and_sig_bytes"),
    # A4: a verify row without sig_bytes refused by name
    ("A4: a missing sig_bytes read as 0, accepted",
     [(C, "named.get_or_insert(crate::SdkError::GasSigBytesMissing);\n                        0", "0")],
     U + "gas_verify_row_without_sig_bytes_is_refused"),
    ("A4: refused as Argument, not by name",
     [(C, "named.get_or_insert(crate::SdkError::GasSigBytesMissing);", "named.get_or_insert(crate::SdkError::Argument);")],
     U + "gas_verify_row_without_sig_bytes_is_refused"),
    ("A4: the flag never set", [(C, "                        named.get_or_insert(crate::SdkError::GasSigBytesMissing);\n", "")],
     U + "gas_verify_row_without_sig_bytes_is_refused"),
    ("A4: the reference table's native row without sig_bytes",
     [(R, '      "source": "the reference signer (0 by definition)",\n      "sig_bytes": 96\n',
       '      "source": "the reference signer (0 by definition)"\n')],
     U + "reference_file_parses"),
    # A5: the longest / worst-case verify rows held to their measurement
    ("A5: WebAuthn sig_bytes back at the first vector", [(R, "\"sig_bytes\": 1344", "\"sig_bytes\": 480")],
     U + "reference_rows_hold_their_sources"),
    ("A5: SLH-DSA's verify row at the valid vector",
     [(R, "\"signer\": 307,\n      \"gas\": 1339000,\n      \"measured\": 1338105,", "\"signer\": 307,\n      \"gas\": 815000,\n      \"measured\": 814427,")],
     U + "reference_rows_hold_their_sources"),
    # A6: the wrap-in fee rows held to their source (the fee against the signer holding units)
    ("A6: a wrap-in fee_extra against the fresh row",
     [(R, "_fresh_wrapped_reg\",\n      \"fee_extra\": {\n        \"gas\": 126000,\n        \"measured\": 125105,\n        \"source\": \"smartcontracts/evm/test/vectors/sdk_gas.json#token_mtxWrap_fee_wrapped-token_mtxWrap_held_wrapped,",
       "_fresh_wrapped_reg\",\n      \"fee_extra\": {\n        \"gas\": 126000,\n        \"measured\": 125105,\n        \"source\": \"smartcontracts/evm/test/vectors/sdk_gas.json#token_mtxWrap_fee_wrapped-token_mtxWrap_fresh_wrapped,")],
     U + "reference_rows_hold_their_sources"),
    # the ua_extra source held: first key less the others
    ("ua_extra source: the verify delta not subtracted",
     [(G, "                        ks.fold(a, |g, k| g - key(k))\n", "                        a - key(ks.next().unwrap())\n")],
     U + "reference_rows_hold_their_sources"),
]

if __name__ == "__main__":
    main("gasA", MUTANTS)
