#!/usr/bin/env python3
"""Tables and checks for the pqz-core reproducibility run (README.md), both proof systems and pqz-ffi.

  results.py check <out dir> [expected-results.json]
      reads the run files reproduce.sh wrote into <out dir>, writes <out dir>/results.json and results.md,
      compares against the expected results; exit 1 on a failed check (correctness, proof hashes, sizes).
  results.py freeze <label> <out dir>
      builds expected-results.json (stdout) from a reproduce.sh --full run; prints the Markdown tables to stderr.
  results.py freeze <label> <rel3 run prefix> <sv run prefix> [<ligero run prefix> <ffi run prefix>]
      the same from direct runs: rel3/relfix.sh (rel3/runs/<x>-*), sv/rel3.sh (sv/runs/<x>-*), and for PQZH
      pqzh/ligero/runs/tx0.sh (<x>.jsonl native, <x>-wasm.jsonl wasm32) and for pqz-ffi ffi/run.sh (<x>-*).

PQZL: proofs_fnv is a hash over the proofs of seeds 0..n-1, so it is keyed by n (the number of proves); native and
wasm proofs are byte-identical, so one table serves both. PQZH: one FNV-1a hash and length per proof, keyed by its
seed (ligero_bench fnv_by_seed; run_wasm.mjs's fnv_last = seed n-1), native = wasm32. pqz-ffi: the digest lines
(statement, witness and proof hashes of every form of both systems, the self-test), native = wasm32.
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
FORMS = ["R_REG", "R_TX", "R_BURN", "R_DS", "R_DR", "R_TX0"]  # PQZH, ligero_bench / run_wasm.mjs order
PQZH_RUNS = {"pqzh-native.jsonl": "native", "pqzh-wasm.jsonl": "wasm"}
# text run files: they pass with a last line rc=0, no "rc=<non-zero>" (stmt/xcheck.sh reports cargo's rc that way)
# and every listed marker ("!marker": must not appear; check_symbols.sh prints "symbols ok" even when nm finds no file)
TEXT = {"pqzh-test.txt": ["mutated inputs rejected, 0 verifier panics caught"], "pqzh-nobench.txt": [],
        "pqzh-xcheck.txt": ["kat_stmt: ok"], "stmt-xcheck.txt": ["xcheck: C 6 / 6 forms equal"],
        "ffi-test.txt": ["selftest hash", "0 disagreements"],
        "ffi-native.txt": ["c_abi: ok (0 failures)", "(must be 0): 0", "symbols ok", "!No such file"],
        "ffi-wasm-build.txt": [], "vectors-build.txt": [], "vectors-check.txt": [": ok", "!DIFF", "!EXTRA"],
        "vectors-pqz-kat.txt": ["pqz_kat: ok"], "vectors-tamper.txt": ["caught: ok"]}
FFI = ["ffi-digests-native.jsonl", "ffi-digests-wasm.jsonl", "ffi-bench.jsonl"]
VECTORS = "vectors-wasm.jsonl"  # replay_wasm.mjs: one line per proof, then {"cases", "fails"}


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
            "node": sh("node --version"), "python": platform.python_version(), "docker": os.path.exists("/.dockerenv"),
            "rustc": sh(f"cd '{os.path.dirname(os.path.abspath(__file__))}/../pqzh' && rustc --version")}


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


def text_check(path, markers):
    t = open(path, errors="replace").read()
    rc = re.findall(r"^rc=(\d+)$", t, re.M)
    bad = rc[-1:] != ["0"] or re.search(r"\brc=[1-9]", t) or any((m[1:] in t) if m[0] == "!" else (m not in t) for m in markers)
    return "FAIL" if bad else "ok"


def pqzh_bench(path):
    """{form: {...}}, fails: one ligero_bench / run_wasm.mjs run file (native or wasm32 by its line shapes)."""
    forms, fails = {}, 0
    for o in jsonl(path):
        rel = o.get("rel")
        if rel is None:
            fails += o.get("fails", 0)
            continue
        x = forms.setdefault(rel, {"fnv": {}, "proof_bytes": {}})
        if "fnv_by_seed" in o:  # native: every seed's hash, the last proof's length
            x["fnv"].update({str(i): h for i, h in enumerate(o["fnv_by_seed"])})
            x["proof_bytes"][str(len(o["fnv_by_seed"]) - 1)] = o["proof_bytes"]
            x.update(max_len_exact=o["max_len_exact"], max_len_verifier=o["max_len_verifier"],
                     proof_bytes_max=o["proof_bytes_max"])
        elif "fnv_last" in o:  # wasm32: the last of n proofs, seed n-1
            x["fnv"][str(o["stats"]["n"] - 1)] = o["fnv_last"]
            x["proof_bytes"][str(o["stats"]["n"] - 1)] = o["proof_bytes"]
        if o.get("timing") in ("prove", "verify_honest", "verify_adversarial"):
            x[o["timing"]] = o["stats"]
            if o["timing"] == "prove":
                x["memory_mib"] = o.get("peak_heap_mb", o.get("memory_mib"))  # native prove heap peak / wasm32 linear memory
                if "within_256mib" in o:
                    x["within_256mib"] = o["within_256mib"]
        if "kind" in o:
            x["mutations"] = x.get("mutations", 0) + o["cases"]
            fails += o["accepted"] + o["panics"]
    t = open(path, errors="replace").read()
    rc = re.findall(r"^rc=(\d+)$", t, re.M)
    return forms, fails + (rc[-1:] != ["0"] if rc else 0)


def pqzh_summary(files):
    """files: {name: path}. {"forms": {form: {...}}, "runs": {...}}"""
    out = {"forms": {f: {"fnv_seen": [], "bytes_seen": []} for f in FORMS}, "runs": {}}
    for name, be in PQZH_RUNS.items():
        p = files.get(name)
        if not p or not os.path.exists(p):
            continue
        forms, fails = pqzh_bench(p)
        out["runs"][name] = {"fails": fails, "forms": sorted(forms), "file": p}
        for rel, r in forms.items():
            if rel not in out["forms"]:
                continue
            x = out["forms"][rel]
            x["fnv_seen"] += [[name, s, h] for s, h in sorted(r["fnv"].items())]
            x["bytes_seen"] += [[name, s, n] for s, n in sorted(r["proof_bytes"].items())]
            for k in ("max_len_exact", "max_len_verifier", "proof_bytes_max", "within_256mib"):
                if k in r:
                    x[k] = r[k]
            if "prove" in r:
                x[f"prove_p50_ms_{be}"] = r["prove"]["p50_ms"]
                x[f"prove_memory_mib_{be}"] = r.get("memory_mib")
            if "verify_honest" in r:
                x[f"verify_p50_ms_{be}"] = r["verify_honest"]["p50_ms"]
                x[f"verify_p99_ms_{be}"] = r["verify_honest"]["p99_ms"]
                x[f"verify_n_{be}"] = r["verify_honest"]["n"]
            if "mutations" in r:
                x["mutations_native"] = r["mutations"]
    for x in out["forms"].values():
        g = lambda a, b: round(x[a] / x[b], 2) if x.get(a) and x.get(b) else None
        x["ratios"] = {"wasm_over_native_prove": g("prove_p50_ms_wasm", "prove_p50_ms_native"),
                       "wasm_over_native_verify": g("verify_p50_ms_wasm", "verify_p50_ms_native")}
    return out


def ffi_summary(files):
    out = {}
    p = files.get("ffi-test.txt")
    if p and os.path.exists(p):
        m = re.search(r"selftest hash ([0-9a-f]{64})", open(p, errors="replace").read())
        out["selftest"] = m and m.group(1)
    for name, key in (("ffi-digests-native.jsonl", "digests_native"), ("ffi-digests-wasm.jsonl", "digests_wasm")):
        p = files.get(name)
        if p and os.path.exists(p):
            out[key] = jsonl(p)
    p = files.get("ffi-bench.jsonl")
    if p and os.path.exists(p):
        out["bench"] = [o for o in jsonl(p) if "sys" in o]
    return out


def compare_pqzh(res, exp):
    """PQZH and pqz-ffi checks, appended to res["compare"]."""
    out = res["compare"]
    add = lambda s, w, d: out.append([s, w, d])
    t = exp.get("tolerance", TOL)
    for name, st in res["text_checks"].items():
        add(st, name, "rc 0 and its markers" if st == "ok" else "see the file")
    P, E = res["pqzh"], exp.get("pqzh", {}).get("forms", {})
    for name, r in P["runs"].items():
        good = r["fails"] == 0 and r["forms"] == sorted(FORMS)
        add("ok" if good else "FAIL", f"PQZH {name}", f'fails {r["fails"]}, forms {len(r["forms"])} / {len(FORMS)}')
    for rel in FORMS:
        x, e = P["forms"][rel], E.get(rel, {})
        for what, seen, want in (("fnv", x["fnv_seen"], e.get("fnv", {})), ("proof bytes", x["bytes_seen"], e.get("proof_bytes", {}))):
            for name, seed, v in seen:
                w = want.get(seed)
                add("info" if w is None else "ok" if w == v else "FAIL", f"PQZH {rel} {what} seed {seed} {name}",
                    f"{v} (no frozen value for seed {seed})" if w is None else f"{v}, expected {w}")
        by = {}
        for name, seed, v in x["fnv_seen"]:
            by.setdefault(seed, set()).add(v)
        for seed, v in sorted(by.items()):
            if len([1 for n, s, _ in x["fnv_seen"] if s == seed]) > 1:
                add("ok" if len(v) == 1 else "FAIL", f"PQZH {rel} native = wasm32 seed {seed}", " / ".join(sorted(v)))
        if "max_len_exact" in x:
            if e.get("max_len_exact") is not None:
                add("ok" if x["max_len_exact"] == e["max_len_exact"] else "FAIL", f"PQZH {rel} max_len_exact",
                    f'{x["max_len_exact"]}, expected {e["max_len_exact"]}')
            good = x["proof_bytes_max"] <= x["max_len_exact"] == x["max_len_verifier"]
            add("ok" if good else "FAIL", f"PQZH {rel} proofs within the bound",
                f'max {x["proof_bytes_max"]} <= max_len_exact {x["max_len_exact"]} = verifier bound {x["max_len_verifier"]}')
        if "within_256mib" in x:
            add("ok" if x["within_256mib"] else "FAIL", f"PQZH {rel} wasm32 memory <= 256 MiB", f'{x.get("prove_memory_mib_wasm")} MiB')
        for k, v in x["ratios"].items():
            if v is not None and e.get("ratios", {}).get(k):
                dev = abs(v - e["ratios"][k]) / e["ratios"][k]
                add("ok" if dev <= t["ratio_rel"] else "warn", f"PQZH {rel} ratio {k}",
                    f'{v}, frozen {e["ratios"][k]} ({dev:.0%}, tol {t["ratio_rel"]:.0%}; machine-dependent)')
    F, EF = res["ffi"], exp.get("ffi", {})
    if "selftest" in F:
        w = EF.get("selftest")
        add("info" if not w else "ok" if F["selftest"] == w else "FAIL", "pqz-ffi selftest hash", f'{F["selftest"]}, expected {w}')
    if "digests_native" in F:
        n, wl = F["digests_native"], F.get("digests_wasm")
        add("ok" if n and n == wl else "FAIL", "pqz-ffi digest lines native = wasm32", f"{len(n)} / {len(wl or [])} lines")
        w = EF.get("digest_lines")
        add("info" if w is None else "ok" if n == w else "FAIL", "pqz-ffi digest lines = frozen",
            f"{len(n)} lines" + ("" if w is None else f", {sum(a != b for a, b in zip(n, w)) + abs(len(n) - len(w))} differ"))
    if "vectors" in res:
        v = res["vectors"]
        good = v["cases"] > 0 and v["fails"] == 0 and v["rows"] == v["cases"] and v["equal_valid"] == v["rows"]
        add("ok" if good else "FAIL", "vectors wasm32 replay",
            f'{v["rows"]} proofs, {v["equal_valid"]} byte-equal and valid, fails {v["fails"]}')


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
    if "pqzh" in res:
        compare_pqzh(res, exp)
    return not any(s == "FAIL" for s, _, _ in res["compare"])


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


def pqzh_table(res):
    L = ["| | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32"
         " | prove memory native heap / wasm32 linear | verifies native / wasm32 |", "|---|---|---|---|---|---|---|---|"]
    for rel in FORMS:
        x = res["pqzh"]["forms"][rel]
        g = lambda k, nd=1: fmt(x.get(k), nd)
        L.append(f"| `{rel}` | {g('proof_bytes_max')} | {g('max_len_exact')} | {g('prove_p50_ms_native', 0)} / "
                 f"{g('prove_p50_ms_wasm', 0)} ms | {g('verify_p50_ms_native', 2)} / {g('verify_p99_ms_native', 2)} ms"
                 f" | {g('verify_p50_ms_wasm', 2)} / {g('verify_p99_ms_wasm', 2)} ms"
                 f" | {g('prove_memory_mib_native')} / {g('prove_memory_mib_wasm')} MiB"
                 f" | {g('verify_n_native')} / {g('verify_n_wasm')} |")
    return "\n".join(L)


def ffi_table(res):
    b = res["ffi"].get("bench", [])
    if not b:
        return "(no ffi_bench run)"
    L = ["| system | form | proof bytes | verify p50 / p99 through the C ABI | adversarial p50 |", "|---|---|---|---|---|"]
    for o in b:
        L.append(f"| {o['sys']} | {o['form']} | {fmt(o.get('proof_bytes'))} | {fmt(o['c_abi']['p50_ms'], 2)} / "
                 f"{fmt(o['c_abi']['p99_ms'], 2)} ms | {fmt(o.get('adversarial', {}).get('p50_ms'), 2)} ms |")
    return "\n".join(L)


def markdown(res):
    m = res["machine"]
    L = [f"# pqz-core reproducibility run ({res.get('mode', '?')})", "",
         f"Machine: {m['cpu']} ({m['threads']} threads; flags {m['flags']}), {m['os']}, kernel {m['kernel']}, "
         f"{m['cc']}, {m['wasm_ld']}, node {m['node']}, Python {m['python']}, {m.get('rustc')}, in Docker: {m['docker']}.", "",
         "Times are informational (they depend on the machine); the proof hashes, the checks and the sizes are compared.", "",
         "## PQZL (the LaZer fork, C)", "", table(res), ""]
    if "pqzh" in res:
        L += ["## PQZH (Ligero, Rust; the proven preset)", "", pqzh_table(res), "",
              f"## pqz-ffi (one precompile, both systems)", "", f"Self-test hash: `{res['ffi'].get('selftest')}`.", "",
              ffi_table(res), ""]
    if "compare" in res:
        n = {s: sum(1 for c in res["compare"] if c[0] == s) for s in ("ok", "FAIL", "warn", "info")}
        L += [f"## Against expected-results.json: {n['ok']} ok, {n['FAIL']} FAIL, {n['warn']} warn, {n['info']} info", "",
              "| status | check | detail |", "|---|---|---|"]
        L += [f"| {s} | {w} | {d} |" for s, w, d in res["compare"]]
    return "\n".join(L) + "\n"


def add_pqzh(res, files):
    res["pqzh"] = pqzh_summary(files)
    res["ffi"] = ffi_summary(files)
    res["text_checks"] = {n: text_check(files[n], TEXT[n]) for n in TEXT if files.get(n) and os.path.exists(files[n])}
    p = files.get(VECTORS)
    if p and os.path.exists(p):
        rows = [o for o in jsonl(p) if "form" in o]
        end = ([o for o in jsonl(p) if "cases" in o] or [{"cases": 0, "fails": 1}])[-1]
        res["vectors"] = {"rows": len(rows), "cases": end["cases"], "fails": end["fails"],
                          "equal_valid": sum(1 for o in rows if o.get("wasm_equal_native") is True and o.get("wasm_precompile") == 1)}


def main(a):
    here = os.path.dirname(os.path.abspath(__file__))
    if len(a) >= 2 and a[0] == "check":
        d = a[1]
        exp = json.load(open(a[2] if len(a) > 2 else os.path.join(here, "expected-results.json")))
        files = {n: os.path.join(d, n) for n in list(BENCH) + CHECKS + list(PQZH_RUNS) + list(TEXT) + FFI + [VECTORS]}
        res = summarize(files)
        add_pqzh(res, files)
        res["mode"] = open(os.path.join(d, "mode.txt")).read().strip() if os.path.exists(os.path.join(d, "mode.txt")) else "?"
        res["machine"] = machine()
        ok = compare(res, exp)
        json.dump(res, open(os.path.join(d, "results.json"), "w"), indent=1)
        open(os.path.join(d, "results.md"), "w").write(markdown(res))
        print(markdown(res))
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if len(a) in (3, 4, 6) and a[0] == "freeze":
        label, r3, sv = a[1], a[2], a[3] if len(a) >= 4 else None
        files = {n: os.path.join(r3, n) for n in list(BENCH) + CHECKS + list(PQZH_RUNS) + list(TEXT) + FFI} if sv is None else {"native-generic.jsonl": f"{r3}-native.jsonl", "wasm-generic.jsonl": f"{r3}-wasm.jsonl",
                 "fnv-native.jsonl": f"{r3}-fnv-native.jsonl", "fnv-wasm.jsonl": f"{r3}-fnv-wasm.jsonl",
                 "native-fast.jsonl": f"{sv}-native-fast.jsonl", "x86v3-fast.jsonl": f"{sv}-x86v3-fast.jsonl",
                 "wasm-fast.jsonl": f"{sv}-wasm-fast.jsonl", "wasm-both.jsonl": f"{sv}-wasm-both.jsonl",
                 "alone-wasm-nosv.jsonl": f"{sv}-alone.jsonl", "kat.txt": f"{r3}-kat.txt",
                 "tbox-fixes.txt": f"{r3}-tbox-fixes.txt", "sv-fixes.txt": f"{sv}-sv-fixes.txt",
                 "diff-portable.jsonl": f"{sv}-diff-portable.jsonl", "diff-x86v3.jsonl": f"{sv}-diff-x86v3.jsonl"}
        if len(a) == 6:
            lg, ff = a[4], a[5]
            files.update({"pqzh-native.jsonl": f"{lg}.jsonl", "pqzh-wasm.jsonl": f"{lg}-wasm.jsonl",
                          "ffi-test.txt": f"{ff}-test.txt", "ffi-digests-native.jsonl": f"{ff}-digests-native.jsonl",
                          "ffi-digests-wasm.jsonl": f"{ff}-digests-wasm.jsonl", "ffi-bench.jsonl": f"{ff}-bench.jsonl"})
        res = summarize(files)
        if sv is None or len(a) == 6:
            add_pqzh(res, files)
            res["text_checks"] = {k: v for k, v in res["text_checks"].items() if sv is None}  # a direct run's text files differ
        # every n with a frozen hash: the rel3 per-op runs (n = 1, native) too
        for rel, r in (bench(f"{r3}-alone.jsonl", "native")[0] if sv else {}).items():
            if rel in RELS:  # the package's five relations (R_TX0, P6e Task 2, is not in its runs)
                res["relations"][rel]["fnv"].setdefault(str(r["np"]), r["fnv"])
        res["machine"] = machine()
        res["mode"] = f"frozen run {label}"
        ok = compare(res, {"relations": {k: {**v, "ratios": {}} for k, v in res["relations"].items()}})
        pq = {}
        if "pqzh" in res:
            pq["pqzh"] = {"preset": "proven (Params::preset, --regime proven --r431 1)", "forms": {
                rel: {"fnv": {s: h for _, s, h in x["fnv_seen"]}, "proof_bytes": {s: n for _, s, n in x["bytes_seen"]},
                      "max_len_exact": x.get("max_len_exact"), "ratios": x["ratios"],
                      "informational": {k: v for k, v in x.items() if k.startswith(("prove_", "verify_"))}}
                for rel, x in res["pqzh"]["forms"].items()}}
            pq["ffi"] = {"selftest": res["ffi"].get("selftest"), "digest_lines": res["ffi"].get("digests_native")}
        exp = {"frozen": label, "source_runs": sorted(files.values()), "machine": res["machine"], "tolerance": TOL,
               "relations": {rel: {k: x.get(k) for k in ("fnv", "proof_bytes_max", "wasm_prove_peak_bytes", "ratios")}
                             | {"times_ms_informational": {k: v for k, v in x.items() if k.endswith("_ms_native")
                                                           or k.endswith("_ms_wasm") or k.endswith("_ms_x86v3")}}
                             for rel, x in res["relations"].items()}} | pq
        json.dump(exp, sys.stdout, indent=1)
        print()
        sys.stderr.write(markdown(res) + ("" if ok else "\nFROZEN RUN HAS FAILED CHECKS\n"))
        return 0 if ok else 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
