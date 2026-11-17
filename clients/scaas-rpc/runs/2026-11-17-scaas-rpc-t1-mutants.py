# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T1 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t1-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

E = "clients/scaas-rpc/src/endpoint.rs"
RPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --lib "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --no-default-features --features json --test json "
DEBUG_IMPL = '''impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint").field("class", &self.class).field("label", &self.label)
            .field("auth", &self.auth.as_ref().map(|_| "<secret>")).finish()
    }
}
'''
MUTANTS = [
    ("drop the scheme check", [(E, 'if !matches!(url.scheme(), "http" | "https") {', "if false {")],
     RPC + "a_scheme_other_than_http_is_refused"),
    ("compare URLs as strings", [(E, "endpoints[..i].iter().any(|b| b.identity() == a.identity())",
                                  "endpoints[..i].iter().any(|b| b.url.as_str() == a.url.as_str())")],
     RPC + "equal_parsed_urls_are_refused"),
    ("accept one endpoint under strict_majority", [(E, "if policy == Policy::StrictMajority && endpoints.len() < 2 {",
                                                    "if policy == Policy::StrictMajority && endpoints.len() < 1 {")],
     RPC + "strict_majority_with_one_endpoint_is_refused"),
    ("a Debug derive on the URL", [(E, "#[derive(Clone)]\npub struct Endpoint {", "#[derive(Clone, Debug)]\npub struct Endpoint {"),
                                   (E, DEBUG_IMPL, "")],
     RPC + "debug_and_display_carry_no_url_or_secret"),
    ("a list-wide credential accepted", [(E, "if self.api_key_env.is_some() || self.api_key_file.is_some() || self.api_key_header.is_some() || self.auth.is_some() {",
                                          "if false {")],
     RPC + "a_list_wide_credential_is_refused"),
    ("depth_within returning Deep for Unbalanced", [("clients/ua-rs/src/json.rs", ".ok_or(DepthError::Unbalanced)?", ".ok_or(DepthError::Deep)?")],
     UA + "depth_within_matches_bounded"),
]

if __name__ == "__main__":
    main("t1", MUTANTS)
