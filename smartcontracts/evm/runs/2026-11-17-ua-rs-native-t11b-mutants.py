#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T11b mutants (ua-qt: the witnessProgram and ss58Address invokables). QML has no raw signing (asserted by
test_no_decaps_no_raw_export_no_handle), no network list of its own and no feature-bit check (Rust-linked), so those mutants of
the other bindings do not apply. Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root, after a
ua-qt gate run (build/ configured), QT the Qt 6 prefix: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

QTD = "clients/ua-qt"
RS = QTD + "/src/ua_wallet.rs"
QT = os.environ.get("QT", os.path.expanduser("~/usr/Qt/6.12.0/gcc_64"))
T = [os.path.abspath("scripts/capped"), "sh", "-c",
     f"export QMAKE={QT}/bin/qmake6 LD_LIBRARY_PATH={QT}/lib QT_QPA_PLATFORM=offscreen; cmake --build build -j2 > /dev/null && "
     "t=$(mktemp); cd build && ctest -V --output-on-failure > $t 2>&1; r=$?; grep -E 'FAIL!|Totals' $t; rm -f $t; exit $r"]
M = [(n, f, a, b, T, QTD) for n, f, a, b in [
    ("witnessProgram without its version byte", RS, ".witness_program().map(|(v, p)| [&[v][..], &p].concat())", ".witness_program().map(|(_v, p)| p)"),
    ("ss58Address ignores its prefix", RS, "?.ss58_address(u16::try_from(prefix).map_err(|_| ARG.to_string())?)))", "?.ss58_address(0)))"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
