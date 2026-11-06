#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13d: the ua-py binding's tests (clients/ua-py tests/test_wallet.py over scaas_ua/wallet.py and libscaas_ua_c) catch a
change in what they test. One mutant per run on a clean tree (one or more replacements), its test classes run, every file restored
byte for byte after it. A mutant whose module does not import is NOT-LOADED (it kills nothing); a mutant whose tests pass SURVIVED:
both are findings (exit 1). Needs clients/ua-c/target/release/libscaas_ua_c.so (cargo build --release in clients/ua-c).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13d-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13d-mutants.py check           (every replacement found once, no run)"""
import re
import subprocess
import sys

PY = "clients/ua-py/"
WP = PY + "scaas_ua/wallet.py"


def t(*names):
    return ["python3", "-m", "unittest"] + [f"tests.test_wallet.{n}" for n in names]


M = [
    # the plan's T13 list
    ("the load check skipped", [(WP, "        check_build(abi, lib.scaas_ua_features())\n", "")],
     t("Load.test_load_refuses_wrong_abi_or_features")),
    ("a secret buffer not wiped (every call)", [(WP, "        for b in self.bufs:\n            _wipe(b)", "        for b in self.bufs:\n            pass")],
     t("Secrets.test_secret_buffer_wiped_after_call")),
    ("a handle freed twice (close does not clear the pointer)", [(WP, "            p, self._p = self._p, None", "            p = self._p")],
     t("Handles.test_handle_freed_exactly_once")),
    # the controller's
    ("the feature check skipped (ABI only)", [(WP, "    if (features & need != need or features >> len(FEATURES) or sets & (sets - 1)",
        "    if False and (features & need != need or features >> len(FEATURES) or sets & (sets - 1)")],
     t("Load.test_load_refuses_wrong_abi_or_features")),
    ("a refused library kept", [(WP, "        abi = lib.scaas_ua_abi_version()\n", "        _lib = lib\n        abi = lib.scaas_ua_abi_version()\n")],
     t("Load.test_load_refuses_wrong_abi_or_features")),
    ("the PQZ leaf in an unwiped buffer", [(WP, "            out = s.buf(32)\n            _ok(_c('export_pqz_leaf_raw')",
        "            out = C.create_string_buffer(32)\n            _ok(_c('export_pqz_leaf_raw')")],
     t("Secrets.test_secret_buffer_wiped_after_call")),
    ("the KEM shared secret in an unwiped buffer", [(WP, "            ss = s.buf(32)\n            _ok(_c('kem_decaps')",
        "            ss = C.create_string_buffer(32)\n            _ok(_c('kem_decaps')")],
     t("Secrets.test_secret_buffer_wiped_after_call")),
    ("a passphrase passed without a wiped copy", [(WP, "            return _str(_c('wallet_seal_vault'), w, s.bytes_in(passphrase, True))",
        "            return _str(_c('wallet_seal_vault'), w, bytes(passphrase) + b'\\0')")],
     t("Secrets.test_secret_buffer_wiped_after_call")),
    ("a secret output as bytes (cannot be wiped)", [(WP, "            C.memmove((C.c_char * n).from_buffer(o), b, n)\n        return o",
        "            C.memmove((C.c_char * n).from_buffer(o), b, n)\n        return bytes(o)")],
     t("Secrets.test_secret_buffer_wiped_after_call")),
    ("a str secret accepted", [(WP, "            raise TypeError('a secret is bytes-like (a bytearray, wiped after use): a str cannot be wiped')",
        "            v = v.encode()")], t("Secrets.test_a_str_secret_is_refused")),
    ("a fixed-size input not checked (an over-read)", [(WP, "    if v is None or len(v) != n:\n        _refuse(f'{what}: {n} bytes')",
        "    if v is None:\n        _refuse(f'{what}: {n} bytes')")], t("Secrets.test_a_str_secret_is_refused")),
    ("close does not wait for a call in flight", [(WP, "            while self._busy:\n                self._cv.wait()\n", "")],
     t("Handles.test_close_waits_for_a_call_in_flight")),
    ("a call on a closed handle reaches the library", [(WP, "            if self._p is None:\n                raise ValueError(f'{type(self).__name__} is closed')\n", "")],
     t("Handles.test_use_after_close_never_reaches_the_library")),
    ("restore ignores `installed` (an equal generation installs)", [(WP,
        "        return Wallet(out.value) if installed.value else None", "        return Wallet(out.value)")],
     t("Seal.test_seal_json_replay_backup_rows")),
    ("restore_backup_rollback calls restore_backup", [(WP, "        return Wallet._restore('wallet_restore_backup_rollback',",
        "        return Wallet._restore('wallet_restore_backup',")], t("Seal.test_seal_json_replay_backup_rows")),
    ("native_key ignores coin_type", [(WP, "_network(network), index, COIN_DEFAULT if coin_type is None else coin_type)",
        "_network(network), index, COIN_DEFAULT)")], t("Keys.test_keys_json_native_rows")),
    ("a backup recipient's ephemeral flag dropped", [(WP, "_Recipient(r.kind, kd, len(kd), r.version, pk, len(pk), r.ephemeral)",
        "_Recipient(r.kind, kd, len(kd), r.version, pk, len(pk), False)")], t("Seal.test_backup_seal_restores_a_wallet")),
    ("uasig keys reversed", [(WP, "        arr = (P * max(len(ps), 1))(*ps)", "        arr = (P * max(len(ps), 1))(*reversed(ps))")],
     t("Sign.test_sign_json_msig_rows_through_uasig")),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)

bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, suite) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        lrc = subprocess.run(["python3", "-c", "import scaas_ua.wallet"], cwd=PY, capture_output=True).returncode
        try:  # a hang is a kill too (its own verdict line says so)
            r = subprocess.run(suite, cwd=PY, capture_output=True, text=True, timeout=600) if lrc == 0 else None
            rc, out = (r.returncode, r.stdout + r.stderr) if r else (lrc, "")
        except subprocess.TimeoutExpired:
            rc, out = "timeout", "FAIL: timeout (600 s)"
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)))
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
