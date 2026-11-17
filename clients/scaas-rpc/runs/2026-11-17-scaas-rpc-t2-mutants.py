# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T2 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t2-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

H = "clients/scaas-rpc/src/http.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test http "
MUTANTS = [
    ("skip the Content-Length check", [(H, "if r.content_length().is_some_and(|n| n > cap as u64) {", "if false {")],
     T + "an_announced_length_above_the_cap_is_refused_unread"),
    ("> to >= at the chunk cap", [(H, "if buf.len() + c.len() > cap {", "if buf.len() + c.len() >= cap {")],
     T + "a_body_at_the_cap_is_read"),
    ("depth 64 to 128", [(H, "pub const DEPTH_MAX: usize = 64;", "pub const DEPTH_MAX: usize = 128;")],
     T + "a_depth_of_65_is_too_deep_and_64_read"),
    ("drop the timeout", [(H, "let mut req = self.client.request(method, url).timeout(timeout);",
                           "let mut req = self.client.request(method, url); let _ = timeout;")],
     T + "a_hung_endpoint_times_out"),
    ("the default redirect policy", [(H, "reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()",
                                      "reqwest::Client::builder().build()")],
     T + "a_redirect_is_not_followed"),
    ("send the credential to every endpoint", [(H, "match e.auth() {", "match list.endpoints().iter().find_map(|x| x.auth()) {")],
     T + "the_credential_goes_to_its_endpoint_only"),
]

if __name__ == "__main__":
    main("t2", MUTANTS)
