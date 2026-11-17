#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T13 C4 mutants (ua-py and ua-dart-frb refuse an integer outside its C / Rust type before the call); runner and
modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root, after a release ua-c build (the ua-py gate's):
python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

PY, DF = "clients/ua-py", "clients/ua-dart-frb"
WAL, RS = PY + "/scaas_ua/wallet.py", DF + "/rust/src/api/wallet.rs"
TPY = ["python3", "-m", "unittest", "tests.test_wallet.Native"]
TDF = [os.path.abspath("scripts/capped"), "sh", "-c",
       "cargo build --locked --offline -j2 --manifest-path rust/Cargo.toml > /dev/null 2>&1 && dart test -r expanded test/wallet_test.dart -N 'not wrapped'"]
M = [
    ("py: the range check removed", WAL, "            if b and isinstance(v, int) and not 0 <= v < 1 << b:", "            if False:", TPY, PY),
    ("py: no lower bound (-1 wraps)", WAL, "not 0 <= v < 1 << b:", "not v < 1 << b:", TPY, PY),
    ("dart-frb: ss58 prefix cast", RS, "ss58_address(int(prefix)?)", "ss58_address(prefix as u16)", TDF, DF),
    ("dart-frb: bitcoin change cast", RS, "int(change)?, int(index)?)?)))", "change as u32, int(index)?)?)))", TDF, DF),
    ("dart-frb: ua kind cast", RS, "self.0.ua_key(int(kind)?, int(account)?, int(index)?)", "self.0.ua_key(kind as u16, int(account)?, int(index)?)", TDF, DF),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
