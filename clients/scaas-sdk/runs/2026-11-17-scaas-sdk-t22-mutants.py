# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T22, the CLI `scaas` (CLI-SDK-17): each check of `clients/scaas-cli` beside the test that holds it:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t22-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/scaas-cli/src/main.rs"
C = "clients/scaas-cli/src/config.rs"
F = "clients/scaas-cli/src/flex.rs"
K = "clients/scaas-cli/src/calls.rs"
T = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --test cli -- --exact "
D = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --features dev-profiles --test cli -- --exact "
U = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --bin scaas -- --exact "
MUTANTS = [
    # the plan's mutant: a passphrase read from an environment variable
    (
        "a secret read from the environment",
        [(M, "        let fd = self\n", "        if let Ok(v) = std::env::var(format!(\"SCAAS_{}\", name.to_uppercase().replace('-', \"_\"))) {\n            return Ok(Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(v.into_bytes())).map_err(|e| Fail::Sdk(SdkError::Ua(e)))?));\n        }\n        let fd = self\n")],
        T + "secret_never_from_environment",
    ),
    (
        "unknown flags ignored (a secret given as a value is not refused)",
        [(K, "        #[derive(serde::Deserialize)]\n        #[serde(deny_unknown_fields)]\n        struct A", "        #[derive(serde::Deserialize)]\n        struct A")],
        T + "no_secret_flag_exists",
    ),
    (
        "-fd flags not kept apart",
        [(F, 'if let Some(base) = name.strip_suffix("-fd") {', 'if let Some(base) = name.strip_suffix("-fd").filter(|_| false) {')],
        T + "no_secret_flag_exists",
    ),
    ("any answer confirms", [(M, 'if a == "y" || a == "yes" {', "if !a.is_empty() || a.is_empty() {")], D + "review_and_quote_before_submit"),
    (
        "the review not shown before the confirm",
        [(M, 'self.confirm(json!({"review": review(&p.review()), "quote": quote,', 'self.confirm(json!({"quote": quote,')],
        D + "review_and_quote_before_submit",
    ),
    ("the process ends before the send is reported", [(M, "const SEND_WAIT_MS: u64 = 30_000;", "const SEND_WAIT_MS: u64 = 0;")], D + "review_and_quote_before_submit"),
    ("the reveal not typed", [(M, '.is_ok_and(|a| a == "reveal")', ".is_ok_and(|_| true)")], T + "generate_reveals_once"),
    ("remove without asking", [(K, 'cx.confirm(json!({"remove": seed, "unbacked": unbacked}))?;', "")], T + "remove_asks_first"),
    ("--profiles in a release build", [(C, 'Some(f) if cfg!(feature = "dev-profiles") => read_bounded(f)?,', "Some(f) => read_bounded(f)?,")], T + "profiles_pinned"),
    (
        "no development banner",
        [(C, 'eprintln!("DEVELOPMENT BUILD (dev-profiles): profiles from a file, sha256 {d}")', "let _ = d;")],
        D + "profiles_pinned",
    ),
    ("an overlay may raise a decimal cap", [(C, "(Ok(b), Ok(x)) if x <= b => Ok(Some(a.clone())),", "(Ok(_), Ok(_)) => Ok(Some(a.clone())),")], U + "config::tests::overlay_lowers_caps_and_adds_credentials_only"),
    ("an overlay may raise max_gas", [(C, "if g > build.max_gas {", "if g > u64::MAX - 1 {")], U + "config::tests::overlay_lowers_caps_and_adds_credentials_only"),
    (
        "an overlay's unknown fields ignored (a chain_uid, a contract, an endpoint list)",
        [(C, "#[derive(Deserialize, Default)]\n#[serde(deny_unknown_fields)]\nstruct Overlay {", "#[derive(Deserialize, Default)]\nstruct Overlay {")],
        U + "config::tests::overlay_lowers_caps_and_adds_credentials_only",
    ),
    ("a credential file readable by others", [(C, "if m.permissions().mode() & 0o077 != 0 {", "if m.permissions().mode() & 0o007 != 0 {")], U + "config::tests::credential_file_readable_by_others_refused"),
    ("output unbounded", [(M, "if text.len() > OUTPUT_MAX {", "if text.len() > usize::MAX - 1 {")], U + "tests::output_bounded"),
    ("a secret line unbounded", [(M, "if n == 0 || n > SECRET_MAX {", "if n == 0 {")], U + "tests::secret_line_bounded"),
    ("the table draws outside text raw", [(M, "if c == ' ' || c.is_ascii_graphic() {", "if c == ' ' || !c.is_control() || true {")], U + "tests::table_escapes_what_a_terminal_acts_on"),
]

if __name__ == "__main__":
    main("t22", MUTANTS)
