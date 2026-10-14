#!/usr/bin/env python3
"""Tables and checks for the pqz-core reproducibility run (README.md).

  results.py check <out dir> [expected-results.json]
      reads the run files reproduce.sh wrote into <out dir>, writes <out dir>/results.json and results.md,
      compares against the expected results; exit 1 on a failed check (correctness, proofs_fnv, sizes).
  results.py freeze <label> <out dir>
      builds expected-results.json (stdout) from a reproduce.sh --full run; prints the Markdown table to stderr.
  results.py freeze <label> <rel3 run prefix> <sv run prefix>
      the same from a direct run: rel3/relfix.sh (rel3/runs/<x>-*) and sv/rel3.sh (sv/runs/<x>-*).

proofs_fnv is a hash over the proofs of seeds 0..n-1, so it is keyed by n (the number of proves); native and wasm
proofs are byte-identical, so one table serves both.
"""
import json, os, platform, re, subprocess, sys

RELS = ["R_REG", "R_TX", "R_BURN", "R_DS", "R_DR"]
TOL = {"proof_bytes_rel": 0.005, "wasm_prove_peak_rel": 0.01, "ratio_rel": 0.5}
# run file name in <out dir> -> (backend, verifier) for the per-relation table
BENCH = {
    "native-generic.jsonl": ("native", "generic"), "wasm-generic.jsonl": ("wasm", "generic"),
    "native-fast.jsonl": ("native", "fast"), "x86v3-fast.jsonl": ("x86v3", "fast"), "wasm-fast.jsonl": ("wasm", "fast"),
    "wasm-both.jsonl": ("wasm", "both"), "fnv-native.jsonl": ("native", "fnv"), "fnv-wasm.jsonl": ("wasm", "fnv"),
    "alone-wasm-nosv.jsonl": ("wasm-nosv", "alone"),
}
CHECKS = ["kat.txt", "tbox-fixes.txt", "sv-fixes.txt", "diff-portable.jsonl", "diff-x86v3.jsonl"]


def jsonl(path, backend=None):
    """JSON lines of a run file; non-JSON lines (stderr, rc notes) are skipped. backend: keep only those lines."""
    out = []
    for line in open(path, errors="replace"):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if isinstance(o, dict) and (backend is None or o.get("backend") == backend):
            out.append(o)
    return out


def bench(path, backend=None):
    """{rel: {np, fnv, bytes_max, arena_peak, prove, valid, adv}}, fails, mismatches."""
    rels, fails, mism = {}, 0, 0
    for o in jsonl(path, backend):
        if "timing" in o:
            rel, what = o["timing"].split(" ", 1)
            r = rels.setdefault(rel, {})
            r[{"prove": "prove", "verify valid": "valid", "verify adversarial": "adv"}.get(what, what)] = o
            if what == "prove":
                r["np"] = o["n"]
        elif "proofs_fnv" in o:
            r = rels.setdefault(o["rel"], {})
            r.update(fnv=o["proofs_fnv"], bytes_max=o["proof_bytes_max"], arena_peak=o["arena_peak"])
        if "fails" in o:
            fails += o["fails"]
        mism += o.get("mismatches", 0) if "fails" in o else 0
        if "prove_rc" in o or "verify_honest" in o or "error" in o:
            fails += 1
    return rels, fails, mism


def diff(path):
    cases = mism = other = prg = 0
    for o in jsonl(path):
        if "cases" in o and "seed" in o:
            cases += o["cases"]; mism += o["mismatches"]; other += o.get("other_fails", 0)
        prg += o.get("prg_mismatches", 0)
    return {"cases": cases, "mismatches": mism, "other_fails": other, "prg_mismatches": prg}


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return None


def machine():
    cpu = flags = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name") and not cpu:
                cpu = line.split(":", 1)[1].strip()
            if line.startswith("flags") and not flags:
                have = set(line.split(":", 1)[1].split())
                flags = " ".join(f for f in ["aes", "vaes", "avx2", "avx512f", "avx512ifma"] if f in have)
    except OSError:
        pass
    osr = sh(". /etc/os-release && echo \"$PRETTY_NAME\"")
    return {"cpu": cpu, "flags": flags, "threads": os.cpu_count(), "os": osr, "kernel": platform.release(),
            "cc": sh("${CC:-clang} --version"), "wasm_ld": sh("${WASM_LD:-wasm-ld-18} --version"),
            "node": sh("node --version"), "python": platform.python_version(), "docker": os.path.exists("/.dockerenv")}


def p99(r):
    """p99 verify: honest or adversarial, the larger (as in STATUS.md)."""
    v = [r[k]["p99_ms"] for k in ("valid", "adv") if k in r]
    return max(v) if v else None


def summarize(files):
    """files: {standard name: path}. Returns the results dict (no comparison)."""
    res = {"relations": {rel: {"fnv": {}} for rel in RELS}, "checks": {}, "runs": {}}
    R = res["relations"]
    for name, path in files.items():
        if name not in BENCH or not os.path.exists(path):
            continue
        be, ver = BENCH[name]
        rels, fails, mism = bench(path, "wasm-nosv" if ver == "alone" else None)
        res["runs"][name] = {"fails": fails, "mismatches": mism, "file": path}
        for rel, r in rels.items():
            if rel not in R:
                continue
            x = R[rel]
            if "fnv" in r:
                x["fnv_seen"] = x.get("fnv_seen", []) + [[name, r["np"], r["fnv"]]]
                x["fnv"].setdefault(str(r["np"]), r["fnv"])
                x["proof_bytes_max"] = max(x.get("proof_bytes_max", 0), r["bytes_max"])
            if ver == "alone":
                x["wasm_prove_peak_bytes"] = r.get("arena_peak")
            if ver == "generic" and "prove" in r:
                x[f"prove_p50_ms_{be}"] = r["prove"]["p50_ms"]
                x[f"generic_verify_p50_ms_{be}"] = r.get("valid", {}).get("p50_ms")
            if ver == "fast" and "valid" in r:
                x[f"sv_p50_ms_{be}"] = r["valid"]["p50_ms"]
                x[f"sv_p99_ms_{be}"] = p99(r)
    for rel in RELS:
        x = R[rel]
        g, f = x.get("generic_verify_p50_ms_native"), x.get("sv_p50_ms_native")
        pn, pw = x.get("prove_p50_ms_native"), x.get("prove_p50_ms_wasm")
        x["ratios"] = {"sv_speedup": round(g / f, 1) if g and f else None,
                       "wasm_over_native_prove": round(pw / pn, 2) if pw and pn else None}
    C = res["checks"]
    for name, key, ok in (("kat.txt", "kat", "19/19 cases equal"), ("tbox-fixes.txt", "tbox_fixes", "check_tbox_fixes: ok"),
                          ("sv-fixes.txt", "sv_fixes", "check_sv_fixes: ok")):
        p = files.get(name)
        if p and os.path.exists(p):
            C[key] = "ok" if ok in open(p, errors="replace").read() else "FAIL"
    for name in ("diff-portable.jsonl", "diff-x86v3.jsonl"):
        p = files.get(name)
        if p and os.path.exists(p):
            C[name[:-6]] = diff(p)
    return res


def compare(res, exp):
    """Adds res["compare"]: a list of [status, what, detail]; status ok / FAIL / warn / info."""
    t = exp.get("tolerance", TOL)
    out = []
    add = lambda s, w, d: out.append([s, w, d])
    C = res["checks"]
    for k in ("kat", "tbox_fixes", "sv_fixes"):
        add("ok" if C.get(k) == "ok" else "FAIL", k, C.get(k, "not run"))
    for k in ("diff-portable", "diff-x86v3"):
        if k in C:
            d = C[k]
            good = d["cases"] > 0 and d["mismatches"] == 0 and d["other_fails"] == 0 and d["prg_mismatches"] == 0
            add("ok" if good else "FAIL", k, f'{d["cases"]} cases, {d["mismatches"]} mismatches, '
                f'{d["other_fails"]} other fails, PRG {d["prg_mismatches"]}')
    for name, r in res["runs"].items():
        add("ok" if r["fails"] == 0 and r["mismatches"] == 0 else "FAIL", f"{name} fails",
            f'fails {r["fails"]}, verifier disagreements {r["mismatches"]}')
    for rel in RELS:
        x, e = res["relations"][rel], exp["relations"][rel]
        for name, np_, fnv in x.get("fnv_seen", []):
            want = e["fnv"].get(str(np_))
            add("info" if want is None else "ok" if want == fnv else "FAIL", f"{rel} proofs_fnv {name} n={np_}",
                f"{fnv} (no frozen value for n={np_})" if want is None else f"{fnv}, expected {want}")
        for k, tk in (("proof_bytes_max", "proof_bytes_rel"), ("wasm_prove_peak_bytes", "wasm_prove_peak_rel")):
            if x.get(k) is not None:
                dev = abs(x[k] - e[k]) / e[k]
                add("ok" if dev <= t[tk] else "FAIL", f"{rel} {k}", f"{x[k]}, frozen {e[k]} ({dev:.2%}, tol {t[tk]:.1%})")
        for k, v in x["ratios"].items():
            if v is not None and e["ratios"].get(k):
                dev = abs(v - e["ratios"][k]) / e["ratios"][k]
                add("ok" if dev <= t["ratio_rel"] else "warn", f"{rel} ratio {k}",
                    f'{v}, frozen {e["ratios"][k]} ({dev:.0%}, tol {t["ratio_rel"]:.0%}; machine-dependent)')
    res["compare"] = out
    return not any(s == "FAIL" for s, _, _ in out)


def fmt(v, nd=1):
    return "–" if v is None else f"{v:,.{nd}f}" if isinstance(v, float) else f"{v:,}"


def table(res):
    L = ["| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm"
         " | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |", "|---|---|---|---|---|---|---|"]
    for rel in RELS:
        x = res["relations"][rel]
        g = lambda k, nd=1: fmt(x.get(k), nd)
        pk = x.get("wasm_prove_peak_bytes")
        L.append(f"| `{rel}` | {g('proof_bytes_max')} | {g('prove_p50_ms_native', 0)} / {g('prove_p50_ms_wasm', 0)} ms"
                 f" | {g('generic_verify_p50_ms_native', 0)} / {g('generic_verify_p50_ms_wasm', 0)} ms"
                 f" | {g('sv_p50_ms_native', 2)} / {g('sv_p50_ms_x86v3', 2)} / {g('sv_p50_ms_wasm', 1)} ms"
                 f" | {g('sv_p99_ms_native', 1)} / {g('sv_p99_ms_x86v3', 1)} / {g('sv_p99_ms_wasm', 1)} ms"
                 f" | {fmt(pk / 2**20 if pk else None)} MiB |")
    return "\n".join(L)


def markdown(res):
    m = res["machine"]
    L = [f"# pqz-core reproducibility run ({res.get('mode', '?')})", "",
         f"Machine: {m['cpu']} ({m['threads']} threads; flags {m['flags']}), {m['os']}, kernel {m['kernel']}, "
         f"{m['cc']}, {m['wasm_ld']}, node {m['node']}, Python {m['python']}, in Docker: {m['docker']}.", "",
         "Times are informational (they depend on the machine); `proofs_fnv`, the checks and the sizes are compared.", "",
         table(res), ""]
    if "compare" in res:
        n = {s: sum(1 for c in res["compare"] if c[0] == s) for s in ("ok", "FAIL", "warn", "info")}
        L += [f"## Against expected-results.json: {n['ok']} ok, {n['FAIL']} FAIL, {n['warn']} warn, {n['info']} info", "",
              "| status | check | detail |", "|---|---|---|"]
        L += [f"| {s} | {w} | {d} |" for s, w, d in res["compare"]]
    return "\n".join(L) + "\n"


def main(a):
    here = os.path.dirname(os.path.abspath(__file__))
    if len(a) >= 2 and a[0] == "check":
        d = a[1]
        exp = json.load(open(a[2] if len(a) > 2 else os.path.join(here, "expected-results.json")))
        res = summarize({n: os.path.join(d, n) for n in list(BENCH) + CHECKS})
        res["mode"] = open(os.path.join(d, "mode.txt")).read().strip() if os.path.exists(os.path.join(d, "mode.txt")) else "?"
        res["machine"] = machine()
        ok = compare(res, exp)
        json.dump(res, open(os.path.join(d, "results.json"), "w"), indent=1)
        open(os.path.join(d, "results.md"), "w").write(markdown(res))
        print(markdown(res))
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if len(a) in (3, 4) and a[0] == "freeze":
        label, r3, sv = a[1], a[2], a[3] if len(a) == 4 else None
        files = {n: os.path.join(r3, n) for n in list(BENCH) + CHECKS} if sv is None else {"native-generic.jsonl": f"{r3}-native.jsonl", "wasm-generic.jsonl": f"{r3}-wasm.jsonl",
                 "fnv-native.jsonl": f"{r3}-fnv-native.jsonl", "fnv-wasm.jsonl": f"{r3}-fnv-wasm.jsonl",
                 "native-fast.jsonl": f"{sv}-native-fast.jsonl", "x86v3-fast.jsonl": f"{sv}-x86v3-fast.jsonl",
                 "wasm-fast.jsonl": f"{sv}-wasm-fast.jsonl", "wasm-both.jsonl": f"{sv}-wasm-both.jsonl",
                 "alone-wasm-nosv.jsonl": f"{sv}-alone.jsonl", "kat.txt": f"{r3}-kat.txt",
                 "tbox-fixes.txt": f"{r3}-tbox-fixes.txt", "sv-fixes.txt": f"{sv}-sv-fixes.txt",
                 "diff-portable.jsonl": f"{sv}-diff-portable.jsonl", "diff-x86v3.jsonl": f"{sv}-diff-x86v3.jsonl"}
        res = summarize(files)
        # every n with a frozen hash: the rel3 per-op runs (n = 1, native) too
        for rel, r in (bench(f"{r3}-alone.jsonl", "native")[0] if sv else {}).items():
            if rel in RELS:  # the package's five relations (R_TX0, P6e Task 2, is not in its runs)
                res["relations"][rel]["fnv"].setdefault(str(r["np"]), r["fnv"])
        res["machine"] = machine()
        res["mode"] = f"frozen run {label}"
        ok = compare(res, {"relations": {k: {**v, "ratios": {}} for k, v in res["relations"].items()}})
        exp = {"frozen": label, "source_runs": sorted(files.values()), "machine": res["machine"], "tolerance": TOL,
               "relations": {rel: {k: x.get(k) for k in ("fnv", "proof_bytes_max", "wasm_prove_peak_bytes", "ratios")}
                             | {"times_ms_informational": {k: v for k, v in x.items() if k.endswith("_ms_native")
                                                           or k.endswith("_ms_wasm") or k.endswith("_ms_x86v3")}}
                             for rel, x in res["relations"].items()}}
        json.dump(exp, sys.stdout, indent=1)
        print()
        sys.stderr.write(markdown(res) + ("" if ok else "\nFROZEN RUN HAS FAILED CHECKS\n"))
        return 0 if ok else 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
