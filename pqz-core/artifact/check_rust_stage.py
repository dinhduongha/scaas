#!/usr/bin/env python3
"""Pins results.py's "Rust = C" checks (Task 12 review): on scratch copies of a passing quick run, each tamper must
turn RESULT into FAIL, the untouched copy must stay PASS.
  python3 -I artifact/check_rust_stage.py [run dir]     (default artifact/runs/fs3-t6-docker-quick); exit 1 on a miss
"""
import os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "runs", "fs3-t6-docker-quick")


def crash(d):  # the wasm32 bench panics: no JSON lines, rc 101
    open(os.path.join(d, "rust-fnv-wasm.jsonl"), "w").write("thread 'main' panicked at src/bin/bench.rs\nrc=101\n")


def early_stop(d):  # the op 7 bench stops before R_TXM8: its lines are gone, rc still 0
    p = os.path.join(d, "rust-fnv-txm.jsonl")
    keep = [l for l in open(p) if not re.search(r'"(rel|timing)": ?"R_TXM8[ "]', l)]
    open(p, "w").writelines(keep)


def missing(d):  # the stage did not run at all
    os.remove(os.path.join(d, "rust-fnv-native.jsonl"))


def rc_only(d):  # complete lines, but the process exited non-zero
    p = os.path.join(d, "rust-fnv-native.jsonl")
    t = open(p).read().replace("rc=0", "rc=134")
    open(p, "w").write(t)


def verify_only(d):  # the Rust backend (no C core in the build) left an M = 8 row verify-only in the wasm32 replay
    p = os.path.join(d, "vectors-wasm.jsonl")
    t = open(p).read().replace('"form":"TRANSFER-MULTI M8-on","proof_bytes":80290,"wasm_equal_native":true',
                               '"form":"TRANSFER-MULTI M8-on","proof_bytes":80290,"wasm_equal_native":"native proof (verify only)"')
    open(p, "w").write(t)


def no_rust_expected(d):  # expected-results.json without its rust section (as an old freeze wrote it)
    import json
    e = json.load(open(os.path.join(HERE, "expected-results.json")))
    e.pop("rust")
    json.dump(e, open(os.path.join(d, "expected-no-rust.json"), "w"))


def run(d):
    e = os.path.join(d, "expected-no-rust.json")
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "results.py"), "check", d] + ([e] if os.path.exists(e) else []),
                       capture_output=True, text=True)
    fails = [l for l in r.stdout.splitlines() if l.startswith("| FAIL")]
    return r.returncode, "RESULT: PASS" in r.stdout, fails


bad = 0
for name, tamper in [("untouched", None), ("crash", crash), ("early_stop", early_stop), ("missing", missing),
                     ("rc_only", rc_only), ("verify_only", verify_only),
                     ("no_rust_expected", no_rust_expected)]:
    with tempfile.TemporaryDirectory() as t:
        d = os.path.join(t, "run")
        shutil.copytree(RUN, d)
        if tamper:
            tamper(d)
        rc, ok, fails = run(d)
        want_pass = tamper is None
        good = ok == want_pass and (rc == 0) == want_pass
        bad += not good
        print(f"{name}: {'PASS' if ok else 'FAIL'} (rc {rc}), expected {'PASS' if want_pass else 'FAIL'}: "
              f"{'ok' if good else 'MISS'}" + "".join(f"\n    {f}" for f in fails))
print("check_rust_stage:", "ok" if not bad else f"{bad} MISS")
sys.exit(1 if bad else 0)
