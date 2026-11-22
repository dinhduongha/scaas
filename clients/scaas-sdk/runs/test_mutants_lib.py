# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The mutant runner's kill rule (merged-tree review M12): python3 -I clients/scaas-sdk/runs/test_mutants_lib.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import COMPILE_ERRORS, failure_line, intended, killed_by, ran_nothing

CARGO = "cd x && ../../scripts/capped cargo test --locked --features F --lib account::msig::tests::msig_members_apart"
assert intended(CARGO) == "account::msig::tests::msig_members_apart"
assert intended("cd x && cargo test --test dex") is None, "a whole binary: any failing test"
assert intended("cd g && python3 -I test_generate.py") is None
assert intended("forge test --match-test 'test_sdkGas_pqzConfRoll$'") == "test_sdkGas_pqzConfRoll"
assert intended(CARGO, "verdict_checked") == "verdict_checked"
red = "test account::msig::tests::msig_members_apart ... FAILED\npanicked at src/a.rs:1:2:\nassertion failed\n"
assert killed_by(red, intended(CARGO))
assert not killed_by(red.replace("msig_members_apart", "other_test"), intended(CARGO)), "another test's failure"
assert not killed_by("error: could not find something\n", None), "no failing test"
assert killed_by("[FAIL: measured at the bound: 64 != 80] test_sdkGas_pqzConfRoll() (gas: 1)\n", "test_sdkGas_pqzConfRoll")
assert failure_line("all good\n") == "-"
# plan T39: forge's failure line is a kill's line; a forge filter as a signature regex names its test; a run of no test
assert failure_line("x\n[FAIL: pinned: false != true] test_a() (gas: 1)\n").startswith("[FAIL: pinned")
assert intended("forge test --match-test '^test_sdkGas_verify\\('") == "test_sdkGas_verify"
assert intended("forge test --match-test 'test_sdkGas_pqzConfRoll\\('") == "test_sdkGas_pqzConfRoll"
# node's spec reporter marks a failing test with ✖ (no `not ok` line): its line is the failure line
assert failure_line("✔ a (1ms)\n✖ finding 5: capped by their bytes (0.6ms)\n  AssertionError [ERR_ASSERTION]: x\n").startswith("✖ finding 5")
assert killed_by("✖ Q4: capped at 1,024 bytes (0.4ms)\n  Error: WebAuthnTooLong: above 1024 bytes\n", None), "a test that throws"
assert not killed_by("✔ Q4: capped at 1,024 bytes (0.4ms)\n", None), "control: a passing test"
assert ran_nothing("Warning: no tests match the provided pattern:\n")
assert ran_nothing("test result: ok. 0 passed; 0 failed; 0 ignored\ntest result: ok. 0 passed; 0 failed; 3 ignored\n")
assert not ran_nothing("test result: ok. 0 passed; 0 failed; 0 ignored\ntest result: ok. 1 passed; 0 failed; 0 ignored\n")
assert not ran_nothing("ℹ pass 3\n"), "control: another runner's output"
dart = "00:00 +0 -1: test/binding_test.dart: load_check: this library passes [E]\n  Expected: throws\n"
assert killed_by(dart, None) and failure_line(dart) != "-", "a dart test's failure"
assert not killed_by("00:00 +3: test/binding_test.dart: load_check: this library passes\n", None), "a dart pass"
gen = "[gen] ok: Go\n[gen] FAIL a generated file differs from the committed one\n"
assert killed_by(gen, None) and failure_line(gen).startswith("[gen] FAIL"), "the generator's drift check"
assert not killed_by("[gen] ok: no drift\n", None)
assert any(e in "Error (2314): Compiler run failed" for e in COMPILE_ERRORS), "solc"
print("mutants_lib kill rule ok")
