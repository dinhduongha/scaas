#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The size ratchet of ua-rs-sign MD-12 (step `ua-sizes`): stripped release `libscaas_ua_c` per target and feature cell, the
bindings' own artifacts, the wasm32 modules beside them. Sizes, not timing.

  python3 clients/ua-c/sizes.py measure <out.json> [target | row prefix ...]   build (scripts/capped cargo, -j2, --locked), record
  python3 clients/ua-c/sizes.py check <measured.json> [baseline]  exit 1 on growth past the tolerance or an unknown cell
  python3 clients/ua-c/sizes.py selftest                          the check's positive control (exit 1 if it cannot fail)

`measure` resumes: it writes <out.json> after every row and skips a row it already holds, so a run may go one row at a time; a
new run takes a new file. A failed build is a failure of `check`; a row without its environment (ua-qt: QMAKE) or a target this
host cannot build is reported, not failed.

Targets: x86_64-unknown-linux-gnu, aarch64-linux-android (ANDROID_NDK_HOME), aarch64-apple-ios (macOS, xcrun),
wasm32-unknown-unknown; default: the ones this host builds. Strip: `LLVM_STRIP` (default `llvm-strip`) `--strip-all` on a
copy of the cdylib / wasm, `--strip-debug` on a copy of the staticlib. `pqzh`: the bytes of `pqzh_ligero` symbols in the
unstripped x86-64 cdylib (`LLVM_NM`, inlined code not counted), recorded, not checked.

A cell may grow only by editing size-baseline.json with its old -> new figure and a reason in the commit (MD-12); a cell
that shrank past the tolerance is reported so the baseline is lowered. The tolerance (1 %) absorbs another host's C compiler
and checkout path lengths (panic locations), not growth: growth inside it is printed, and the baseline only moves by hand, so
it cannot accumulate. UNAUDITED."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = Path(__file__).resolve().parent / "size-baseline.json"
TOL = 0.01
X86, ANDROID, IOS, WASM = "x86_64-unknown-linux-gnu", "aarch64-linux-android", "aarch64-apple-ios", "wasm32-unknown-unknown"
FACADES = "mlock,zether,pqz,pqz-set-"
# ua-c's MD-12 cells: the wallet alone (ua-c always has it), the default (both facades, n2304-kmax4096), each other PQZ set
UA_C_CELLS = {
    "no-default": ["--no-default-features"],
    "default": [],
    **{s: ["--no-default-features", "--features", FACADES + s] for s in ("n2048-kmax1024", "n2560-kmax16384", "n2816-kmax65536")},
}
# (key, crate directory, targets, cargo args, artifacts by kind, env it needs)
ROWS = [("ua-c/" + c, "clients/ua-c", (X86, ANDROID, IOS, WASM), a, "scaas_ua_c", None) for c, a in UA_C_CELLS.items()]
ROWS += [
    # the bindings with a Rust artifact of their own (their one feature set); ua-py, ua-go, ua-cs load libscaas_ua_c
    ("ua-cxx", "clients/ua-cxx", (X86,), [], "scaas_ua_cxx", None),
    ("ua-dart-frb", "clients/ua-dart-frb/rust", (X86,), [], "scaas_ua_frb", None),
    ("ua-qt", "clients/ua-qt", (X86,), [], "scaas_ua_qt", "QMAKE"),
    # the wasm32 modules that exist today (the wasm-bindgen ua-rs binding is the next round, Q4)
    ("zether-prover", "clients/zether-prover", (WASM,), [], "zether_prover", None),
]
ROWS += [(f"pqz-ffi-wasm/{s}", "pqz-core/ffi/wasm", (WASM,), ["--no-default-features", "--features", f"pqzl-rust,set-{s}"],
          "pqz_ffi_wasm", None) for s in ("n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536")]


def files(target, stem):
    """The artifacts of a crate's lib target: kind -> file name."""
    if target == WASM:
        return {"cdylib": f"{stem}.wasm"}
    dylib = ".dylib" if target == IOS else ".so"
    return {"cdylib": f"lib{stem}{dylib}", "staticlib": f"lib{stem}.a"}


def host_targets():
    t = [X86, WASM]
    if os.environ.get("ANDROID_NDK_HOME"):
        t.append(ANDROID)
    if shutil.which("xcrun"):
        t.append(IOS)
    return t


def target_env(target):
    env = dict(os.environ)
    if target == ANDROID:
        b = Path(os.environ["ANDROID_NDK_HOME"]) / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        cc = str(b / "aarch64-linux-android24-clang")
        env.update({"CC_aarch64_linux_android": cc, "AR_aarch64_linux_android": str(b / "llvm-ar"),
                    "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER": cc})
    return env


def measure(out, targets, prefixes=()):
    strip, nm = os.environ.get("LLVM_STRIP", "llvm-strip"), os.environ.get("LLVM_NM", "llvm-nm")
    path = Path(out)
    got = json.loads(path.read_text()) if path.exists() else {"sizes": {}, "pqzh_symbol_bytes": {}, "skipped": {}}
    sizes, pqzh, skipped = got["sizes"], got["pqzh_symbol_bytes"], got["skipped"]
    tmp = Path(tempfile.mkdtemp(prefix="ua-sizes-"))
    for key, crate, row_targets, args, stem, need in ROWS:
        if prefixes and not key.startswith(tuple(prefixes)):
            continue
        for t in (t for t in row_targets if t in targets):
            names = files(t, stem)
            if any(k.startswith(f"{t}/{key}/") for k in sizes):
                continue
            if need and not os.environ.get(need):
                skipped[f"{t}/{key}"] = f"{need} not set"
                continue
            cmd = [str(ROOT / "scripts/capped"), "cargo", "build", "--release", "--locked", "-j2", "--lib", "--target", t, *args]
            print("+", " ".join(cmd[1:]), f"({crate})", flush=True)
            if subprocess.run(cmd, cwd=ROOT / crate, env=target_env(t), check=False).returncode:
                skipped[f"{t}/{key}"] = "build failed"
            else:
                skipped.pop(f"{t}/{key}", None)
                for kind, name in names.items():
                    f = ROOT / crate / "target" / t / "release" / name
                    if not f.exists():  # ua-cxx, ua-qt: no cdylib
                        continue
                    c = tmp / name
                    shutil.copy(f, c)
                    subprocess.run([strip, "--strip-all" if kind == "cdylib" else "--strip-debug", str(c)], check=True)
                    sizes[f"{t}/{key}/{kind}"] = c.stat().st_size
                    if t == X86 and kind == "cdylib" and key.startswith("ua-c/"):
                        syms = subprocess.run([nm, "-S", "--size-sort", str(f)], check=True, capture_output=True, text=True).stdout
                        pqzh[key] = sum(int(l.split()[1], 16) for l in syms.splitlines() if "pqzh_ligero" in l)
            path.write_text(json.dumps(got, indent=1, sort_keys=True) + "\n")
    shutil.rmtree(tmp)
    print(f"{len(sizes)} sizes -> {out}; skipped: {skipped or 'none'}")


def compare(measured, base, tol=TOL):
    """(failures, notes) of `measured` against `base` (both cell -> bytes)."""
    fails, notes = [], []
    for k, v in sorted(measured.items()):
        if k not in base:
            fails.append(f"{k}: {v} B, not in the baseline (add it with a reason)")
        elif v > base[k] * (1 + tol):
            fails.append(f"{k}: grew {base[k]} -> {v} B (+{(v / base[k] - 1) * 100:.2f} %): baseline old -> new and a reason")
        elif v > base[k]:
            notes.append(f"{k}: grew {base[k]} -> {v} B (+{(v / base[k] - 1) * 100:.2f} %), inside the tolerance")
        elif v < base[k] * (1 - tol):
            notes.append(f"{k}: shrank {base[k]} -> {v} B: lower the baseline")
    notes += [f"{k}: not measured on this host" for k in sorted(set(base) - set(measured))]
    return fails, notes


def check(measured_path, baseline_path=BASELINE):
    measured = json.loads(measured_path.read_text())
    fails, notes = compare(measured["sizes"], json.loads(baseline_path.read_text())["sizes"])
    fails += [f"{k}: build failed" for k, why in measured.get("skipped", {}).items() if why == "build failed"]
    fails += ["nothing measured"] if not measured["sizes"] else []
    for n in notes:
        print("note:", n)
    for f in fails:
        print("FAIL:", f)
    print(f"ua-sizes: {len(fails)} failure(s)")
    return 1 if fails else 0


def selftest():
    """A check that cannot fail proves nothing: one change at a time, through the exit code, on a synthetic and the real baseline."""
    real = json.loads(BASELINE.read_text())["sizes"]
    k = min(real)
    syn = {"a": 1000, "b": 1000}
    cases = [("equal", syn, syn, 0), ("+1.0 %, the tolerance", {"a": 1010, "b": 1000}, syn, 0), ("+1.1 %", {"a": 1011, "b": 1000}, syn, 1),
             ("unknown cell", {"a": 1000, "c": 1}, syn, 1), ("shrunk", {"a": 900, "b": 1000}, syn, 0), ("cell not measured", {"a": 1000}, syn, 0),
             ("the real baseline", real, real, 0), (f"the real baseline, {k} +2 %", {**real, k: int(real[k] * 1.02)}, real, 1),
             ("a failed build", syn, syn, 1, {"x/ua-c/default": "build failed"}), ("nothing measured", {}, syn, 1),
             ("a row without its env", syn, syn, 0, {"x/ua-qt": "QMAKE not set"})]
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        m, b = Path(d) / "measured.json", Path(d) / "baseline.json"
        for name, measured, base, want, *skipped in cases:
            m.write_text(json.dumps({"sizes": measured, "skipped": skipped[0] if skipped else {}}))
            b.write_text(json.dumps({"sizes": base}))
            got = check(m, b)
            bad += got != want
            print(f"{'ok ' if got == want else 'BAD'} {name}: rc {got}, want {want}")
    print(f"selftest: {len(cases)} cases, {bad} wrong")
    return 1 if bad else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["measure"] and len(a) >= 2:
        picked = [t for t in a[2:] if t in (X86, ANDROID, IOS, WASM)]
        measure(a[1], picked or host_targets(), [r for r in a[2:] if r not in picked])
    elif a[:1] == ["check"] and len(a) in (2, 3):
        sys.exit(check(*map(Path, a[1:])))
    elif a == ["selftest"]:
        sys.exit(selftest())
    else:
        sys.exit(__doc__)
