# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The mutant runner's kill rule (merged-tree review M12): python3 -I clients/scaas-sdk/runs/test_mutants_lib.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import COMPILE_ERRORS, failure_line, intended, killed_by

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
dart = "00:00 +0 -1: test/binding_test.dart: load_check: this library passes [E]\n  Expected: throws\n"
assert killed_by(dart, None) and failure_line(dart) != "-", "a dart test's failure"
assert not killed_by("00:00 +3: test/binding_test.dart: load_check: this library passes\n", None), "a dart pass"
gen = "[gen] ok: Go\n[gen] FAIL a generated file differs from the committed one\n"
assert killed_by(gen, None) and failure_line(gen).startswith("[gen] FAIL"), "the generator's drift check"
assert not killed_by("[gen] ok: no drift\n", None)
assert any(e in "Error (2314): Compiler run failed" for e in COMPILE_ERRORS), "solc"
print("mutants_lib kill rule ok")
