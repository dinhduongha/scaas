# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T24.cosmos, Cosmos's balance reads (spec §8.7):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24cosmos-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

C = "clients/scaas-sdk/src/wallet/families/cosmos.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
G = "clients/scaas-sdk/src/config.rs"
R = "clients/scaas-rpc/src/cosmos.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features cosmos --test cosmos -- --exact "
TR = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features cosmos --test cosmos -- --exact "
MUTANTS = [
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "cosmos_two_endpoints_one_down"),
    ("the SDK's reads not pinned to the height",
     [(C, ".get_at_height(i, path, h)", ".get(i, path)")],
     T + "cosmos_strict_majority_agrees_at_one_height"),
    ("scaas-rpc sends no height header",
     [(R, "let header = Some((HEIGHT, h.as_str()));", "let header = Some((HEIGHT, h.as_str())).filter(|_| false);")],
     TR + "a_rest_read_at_a_height_sends_the_height_header"),
    ("strict majority: the others read at their own head",
     [(C, "|j, h| async move { set_at(cos, j, h, id, denom, tokens).await },",
       "|j, _h| async move { let h = cos.rest.head(j, None).await.map_err(ReadError::Failure)?; set_at(cos, j, h, id, denom, tokens).await },")],
     T + "cosmos_strict_majority_agrees_at_one_height"),
    ("a balance string read without the amount rule",
     [(C, "Some(s) => amount(i, s),", "Some(s) => Ok(s.to_string()),")],
     T + "cosmos_malformed_answers_are_refused"),
    ("the bech32 checksum not checked",
     [(C, "pad_ok && chk == 1", "pad_ok")],
     T + "cosmos_holder_and_token_forms"),
    ("the padding bits not checked",
     [(C, "58 => v.get(51).is_some_and(|g| g & 0x0f == 0),", "58 => true,")],
     T + "cosmos_holder_and_token_forms"),
    ("params of another family accepted",
     [(G, "family == Family::Cosmos\n                    && (1..=50)", "(1..=50)")],
     T + "cosmos_holder_and_token_forms"),
    ("a denom's first byte not checked",
     [(G, "&& d.first().is_some_and(u8::is_ascii_alphabetic)\n", "")],
     T + "cosmos_holder_and_token_forms"),
]

if __name__ == "__main__":
    main("t24cosmos", MUTANTS)
