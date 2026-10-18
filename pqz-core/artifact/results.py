#!/usr/bin/env python3
"""Tables and checks for the pqz-core reproducibility run (README.md), both proof systems and pqz-ffi.

  results.py check <out dir> [expected-results.json]
      reads the run files reproduce.sh wrote into <out dir>, writes <out dir>/results.json and results.md,
      compares against the expected results; exit 1 on a failed check (correctness, proof hashes, sizes).
  results.py freeze <label> <out dir>
      builds expected-results.json (stdout) from a reproduce.sh --full run; prints the Markdown tables to stderr.
  results.py freeze <label> <pqzl-measure run prefix> <sv run prefix> [<ligero run prefix> <ffi run prefix>]
      the same from direct runs: research/pqzl-measure/relfix.sh (research/pqzl-measure/runs/<x>-*), pqzl/sv/rel3.sh (pqzl/sv/runs/<x>-*), and for PQZH
      pqzh/ligero/runs/tx0.sh (<x>.jsonl native, <x>-wasm.jsonl wasm32) and for pqz-ffi ffi/run.sh (<x>-*).
  results.py freeze-txm <label> <out dir> [expected-results.json]
      P6-ANON S6: the current expected results (stdout) with only what op 7 changes taken from a quick / full run:
      "txm" (the op 7 vector replay) and ffi.digest_lines (pqz-ffi's op 7 lines; refused unless the old lines are
      kept, in order); every other value stays. Exit 1 if the run then fails a check.
  results.py multi <out dir>
      the op 7 R_TXM measurement table of a reproduce.sh --multi-bench run: results-multi.md / .json; exit 1 if a
      bench failed (mutation accepted, panic, rc != 0) or a built shape is missing. Times are informational.
  results.py d6 <run dir>
      port plan D6 / Task 12: the Rust core against the C core, both measured in one session by pqzl/rust/d6.sh:
      results-d6.md / .json (prove / verify / verify_fast p50 / p99 native and wasm32, prove peak memory, proofs_fnv
      per relation and core; the wasm32 op 7 M = 8 criterion); exit 1 if a bench failed.

The Rust core (pqzl/rust/, port plan Task 12) adds rows next to the C core's when its run files are present (the
"Rust = C" stage's rust-*.jsonl in check, rust-txm-*.jsonl in multi); without them every table is as before.

PQZL: proofs_fnv is a hash over the proofs of seeds 0..n-1, so it is keyed by n (the number of proves); native and
wasm proofs are byte-identical, so one table serves both. PQZH: one FNV-1a hash and length per proof, keyed by its
seed (ligero_bench fnv_by_seed; run_wasm.mjs's fnv_last = seed n-1), native = wasm32. pqz-ffi: the digest lines
(statement, witness and proof hashes of every form of both systems, the self-test), native = wasm32.
"""
import hashlib, json, os, platform, re, subprocess, sys

RELS = ["R_REG", "R_TX", "R_BURN", "R_DS", "R_DR", "R_TX0"]  # pqz_bench / run_wasm.mjs mask 63
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
        "vectors-pqz-kat.txt": ["pqz_kat: ok"], "vectors-tamper.txt": ["caught: ok"],
        "rust-build.txt": [], "rust-keys-pqz-kat.txt": ["pqz_kat: ok"]}
FFI = ["ffi-digests-native.jsonl", "ffi-digests-wasm.jsonl", "ffi-bench.jsonl"]
VECTORS = "vectors-wasm.jsonl"  # replay_wasm.mjs: one line per proof, then {"cases", "verify_only", "fails"}
# op 7 R_TXM (P6-ANON S6, D14): the built leg counts per id (= pqz-stmt built_legs, plan D3 / S3), both auditorOn;
# wasm32 proves PQZL op 7 up to M = 4 only on the C backend (pqzl::WASM_PQZL_MAX_LEGS, one 512 MiB arena, S3), so its
# replay verifies the native PQZL M = 8 proofs there (S4); the Rust backend (default) proves M = 8 too (port plan
# Task 12), and those rows are byte-equal, valid rows like the others
TXM_BUILT = {"pqzl": (1, 2, 4, 8), "pqzh": (1, 2, 4)}
WASM_PQZL_MAX_LEGS = 4
VERIFY_ONLY = "native proof (verify only)"
NEGATIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "smartcontracts", "vectors", "pqz",
                        "negative.json")
# The Rust core (pqzl/rust/), "Rust = C" stage: run file -> (backend, verifier) as BENCH. The Rust bench / wasm runner
# print the C bench's JSON lines without arena_peak; the wasm runner adds wasm_memory_bytes (linear memory after the
# relation's proves). The op 7 runs are checked against expected rust.txm_fnv, the keys KAT against rust.keys_kat.
RUST_BENCH = {"rust-fnv-native.jsonl": ("native", "generic"), "rust-fnv-wasm.jsonl": ("wasm", "generic"),
              "rust-fast-native.jsonl": ("native", "fast"), "rust-fast-wasm.jsonl": ("wasm", "fast")}
RUST_TXM = ["rust-fnv-txm.jsonl", "rust-fast-txm.jsonl"]
RUST_KEYS = "rust-keys-kat.jsonl"


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
            r.update(fnv=o["proofs_fnv"], bytes_max=o["proof_bytes_max"], arena_peak=o.get("arena_peak"),
                     wasm_memory=o.get("wasm_memory_bytes"))
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


def summarize(files, runs=BENCH):
    """files: {standard name: path}; runs: the bench files to read (BENCH, or RUST_BENCH). Returns the results dict
    (no comparison)."""
    res = {"relations": {rel: {"fnv": {}} for rel in RELS}, "checks": {}, "runs": {}}
    R = res["relations"]
    for name, path in files.items():
        if name not in runs or not os.path.exists(path):
            continue
        be, ver = runs[name]
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
        good = v["cases"] > 0 and v["fails"] == 0 and v["rows"] == v["cases"] and v["equal_valid"] + v["verify_only"] == v["rows"]
        add("ok" if good else "FAIL", "vectors wasm32 replay",
            f'{v["rows"]} proofs, {v["equal_valid"]} byte-equal and valid, {v["verify_only"]} native PQZL op 7 M > '
            f'{WASM_PQZL_MAX_LEGS} proofs valid (verify only), fails {v["fails"]}')
    if "txm" in res:
        compare_txm(res, exp)


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
    if "rust" in res:
        compare_rust(res, exp)
    return not any(s == "FAIL" for s, _, _ in res["compare"])


def add_rust(res, files):
    """res["rust"] from the "Rust = C" stage's run files; nothing when there are none."""
    have = lambda n: files.get(n) and os.path.exists(files[n])
    if not any(have(n) for n in list(RUST_BENCH) + RUST_TXM + [RUST_KEYS]):
        return
    r = summarize(files, RUST_BENCH)
    rust = {"relations": r["relations"], "runs": r["runs"], "txm_fnv_seen": []}
    for n in filter(have, RUST_TXM):
        rels, fails, mism = bench(files[n])
        rust["runs"][n] = {"fails": fails, "mismatches": mism, "file": files[n]}
        rust["txm_fnv_seen"] += [[rel, n, x["np"], x["fnv"]] for rel, x in rels.items() if "fnv" in x]
    if have(RUST_KEYS):
        rust["keys_kat_sha256"] = hashlib.sha256(open(files[RUST_KEYS], "rb").read()).hexdigest()
    res["rust"] = rust


def compare_rust(res, exp):
    """Rust = C: the Rust prover's proofs_fnv = the C core's frozen hashes (the six relations: exp relations, keyed by n;
    op 7: exp rust.txm_fnv), every Rust bench fails 0, and the keys KAT = the C core's output. The self-test, digests and
    vectors on the Rust core are the pqz-ffi / vectors stages' checks (pqz-ffi's default backend is pqzl-rust)."""
    R, E = res["rust"], exp.get("rust", {})
    add = lambda s, w, d: res["compare"].append([s, w, d])
    for name, r in R["runs"].items():
        add("ok" if r["fails"] == 0 and r["mismatches"] == 0 else "FAIL", f"Rust {name} fails",
            f'fails {r["fails"]}, verifier disagreements {r["mismatches"]}')
    seen = [[rel, n, np_, h] for rel in RELS for n, np_, h in R["relations"][rel].get("fnv_seen", [])] + R["txm_fnv_seen"]
    for rel, name, np_, h in seen:
        want = (exp["relations"][rel]["fnv"] if rel in RELS else E.get("txm_fnv", {}).get(rel, {})).get(str(np_))
        add("info" if want is None else "ok" if want == h else "FAIL", f"Rust {rel} proofs_fnv {name} n={np_}",
            f"{h} (no C hash for n={np_})" if want is None else f"{h}, C core {want}")
    if "keys_kat_sha256" in R:
        w = E.get("keys_kat", {}).get("sha256")
        add("info" if not w else "ok" if R["keys_kat_sha256"] == w else "FAIL", "Rust keys KAT = C",
            f'sha256 {R["keys_kat_sha256"]}, expected {w}')


def fmt(v, nd=1):
    return "–" if v is None else f"{v:,.{nd}f}" if isinstance(v, float) else f"{v:,}"


def table(res):
    L = ["| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm"
         " | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |", "|---|---|---|---|---|---|---|"]
    for rel in RELS:
        for name, x in [(f"`{rel}`", res["relations"][rel])] + ([(f"`{rel}` Rust", res["rust"]["relations"][rel])]
                                                               if "rust" in res else []):
            g = lambda k, nd=1: fmt(x.get(k), nd)
            pk = x.get("wasm_prove_peak_bytes")
            L.append(f"| {name} | {g('proof_bytes_max')} | {g('prove_p50_ms_native', 0)} / {g('prove_p50_ms_wasm', 0)} ms"
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
    if "rust" in res:
        L += ["\"Rust\" rows: the Rust core (`pqzl/rust/`) in this run's \"Rust = C\" stage (bench 5 5 63 native, 3 1 63 "
              "wasm32; --full also verify_fast), on the same machine as the C rows but with other sample sizes.", ""]
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
        vo = [o for o in rows if verify_only_ok(o)]
        res["vectors"] = {"rows": len(rows), "cases": end["cases"], "fails": end["fails"], "verify_only": len(vo),
                          "equal_valid": sum(1 for o in rows if o.get("wasm_equal_native") is True and o.get("wasm_precompile") == 1)}
    if files.get("vectors-check.txt") and os.path.exists(files["vectors-check.txt"]):
        res["txm"] = txm_summary(files)


def txm_shape(case):
    """'M8-on-boundary' -> (8, True); None if not an op 7 case name."""
    m = re.match(r"M(\d+)-(on|off)\b", case)
    return m and (int(m.group(1)), m.group(2) == "on")


def verify_only_ok(o):
    """A wasm32 replay row that may be verify-only: PQZL op 7 with M > WASM_PQZL_MAX_LEGS, verified through the wasm32
    precompile."""
    f = o.get("form", "").split()
    s = len(f) == 2 and f[0] == "TRANSFER-MULTI" and txm_shape(f[1])
    return bool(s) and o.get("id") == "pqzl" and s[0] > WASM_PQZL_MAX_LEGS and o.get("wasm_equal_native") == VERIFY_ONLY \
        and o.get("wasm_precompile") == 1


def txm_summary(files):
    """Op 7 R_TXM in the vector stages. native: pqz-vectors --check's "<id> <case> proof <n> B" lines (each proof made
    again, deterministic, ...01 through pqz_precompile, the files byte-equal); wasm: replay_wasm.mjs's TRANSFER-MULTI
    rows; negatives: negative.json's op 7 rows per id (--check replayed each through the precompile and asserted
    0 / revert, and found the file byte-equal: "same negative.json")."""
    t = open(files["vectors-check.txt"], errors="replace").read()
    out = {"native": {f"{i} {c}": int(n) for i, c, n in re.findall(r"^(pqzl|pqzh) (M\d+-\S+)\s+proof\s+(\d+) B", t, re.M)},
           "wasm": {}, "negatives": {}, "negative_rejected": {}, "negative_same": "same negative.json" in t}
    p = files.get(VECTORS)
    for o in (jsonl(p) if p and os.path.exists(p) else []):
        f = o.get("form", "").split()
        if len(f) == 2 and f[0] == "TRANSFER-MULTI":
            out["wasm"][f'{o["id"]} {f[1]}'] = {k: o.get(k) for k in ("proof_bytes", "wasm_equal_native", "wasm_precompile")}
    if os.path.exists(NEGATIVE):
        for r in json.load(open(NEGATIVE))["rows"]:
            if r.get("form") == "TRANSFER-MULTI":
                out["negatives"][r["id"]] = out["negatives"].get(r["id"], 0) + 1
                out["negative_rejected"][r["id"]] = out["negative_rejected"].get(r["id"], 0) + (r["expect"] in ("0", "revert"))
    return out


def txm_expected(res):
    """The "txm" section of expected-results.json from a run's txm summary."""
    x = res["txm"]
    return {"built_legs": {k: list(v) for k, v in TXM_BUILT.items()}, "proof_bytes": x["native"],
            "wasm_verify_only": sorted(k for k, o in x["wasm"].items() if o["wasm_equal_native"] == VERIFY_ONLY),
            "negatives": x["negatives"]}


def compare_txm(res, exp):
    """Every built (id, M, auditorOn) and every op 7 vector row: native and wasm32; the op 7 negatives."""
    x, e = res["txm"], exp.get("txm", {})
    add = lambda s, w, d: res["compare"].append([s, w, d])
    ep = e.get("proof_bytes", {})
    keys = {f"{i} M{m}-{a}" for i, ms in TXM_BUILT.items() for m in ms for a in ("on", "off")} | set(x["native"]) | set(ep)
    for k in sorted(keys, key=lambda k: (k.split()[0], txm_shape(k.split()[1]) or (0, 0), k)):
        n, w = x["native"].get(k), ep.get(k)
        add("FAIL" if n is None else "info" if w is None else "ok" if n == w else "FAIL", f"op 7 {k} native",
            "not in pqz-vectors --check" if n is None else f"proof {n} B, ...01 through pqz_precompile"
            + (" (no frozen value)" if w is None else f", expected {w} B"))
        o = x["wasm"].get(k)
        vo = o is not None and verify_only_ok({"id": k.split()[0], "form": "TRANSFER-MULTI " + k.split()[1], **o})
        good = o is not None and o["wasm_precompile"] == 1 and (o["wasm_equal_native"] is True or vo) \
            and (not vo or k in e.get("wasm_verify_only", [k]))
        add("ok" if good else "FAIL", f"op 7 {k} wasm32", "not replayed" if o is None else
            f'{o["proof_bytes"]} B, {"native proof verified (wasm32 proves PQZL M <= 4)" if vo else "proved again, byte-equal"}'
            f', precompile {o["wasm_precompile"]}')
    for i in TXM_BUILT:
        n, r, w = x["negatives"].get(i, 0), x["negative_rejected"].get(i, 0), e.get("negatives", {}).get(i)
        good = n > 0 and r == n and x["negative_same"] and (w is None or n == w)
        add(("ok" if w is not None else "info") if good else "FAIL", f"op 7 {i} negatives",
            f"{n} rows of negative.json, {r} expect 0 / revert, replayed by pqz-vectors --check"
            + (" (same negative.json)" if x["negative_same"] else " (NO 'same negative.json')")
            + ("" if w is None else f", expected {w} rows"))


# --multi-bench run files: PQZL research/pqzl-measure/txm-bench.sh (moved to pqzl-txm-*), PQZH ligero_bench / run_wasm.mjs txm
TXM_PQZL = ["native-generic", "native-fast", "x86v3-fast", "wasm-fast", "wasm-generic", "wasm-nosv"]
TXM_PQZH = ["native", "oversize", "wasm", "oversize-wasm"]  # the built runs first: an oversize run fills only what is missing
TXM_TEXT = ["pqzl-txm.txt", "pqzh-txm-build.txt", "pqzh-txm-oversize-build.txt", "pqzh-txm-wasm-build.txt",
            "pqzh-txm-oversize-wasm-build.txt"]


TXM_RUST = ["native-generic", "native-fast", "wasm-generic", "wasm-fast"]  # rust-txm-<run>.jsonl, one process per shape


def txm_rel(rel):
    """'R_TXM8_0' -> (8, False)."""
    m = re.fullmatch(r"R_TXM(\d+)(_0)?", rel or "")
    return m and (int(m.group(1)), not m.group(2))


def txm_fill(out, f, rels):
    """One op 7 bench file's relations into out {"M,on|off": {...}}; f = its run (native-generic, wasm-fast, ...).
    wasm32 prove peak: the C arena peak of the prover build without SV (wasm-nosv), or the Rust wasm runner's linear
    memory after the proves (wasm-generic; one shape per process)."""
    for rel, r in rels.items():
        s = txm_rel(rel)
        if not s:
            continue
        x = out.setdefault(f"{s[0]},{'on' if s[1] else 'off'}", {"m": s[0], "aud": s[1]})
        if f == "wasm-nosv":
            x["wasm_prove_peak_bytes"] = r.get("arena_peak")
        elif f.endswith("generic"):
            be = f.split("-")[0]
            if "bytes_max" in r:
                x[f"proof_bytes_max_{be}"] = r["bytes_max"]
            if r.get("wasm_memory"):
                x["wasm_prove_peak_bytes"] = r["wasm_memory"]
            if "prove" in r:
                x[f"prove_p50_ms_{be}"] = r["prove"]["p50_ms"]
            if "valid" in r:
                x[f"verify_p50_ms_{be}"], x[f"verify_p99_ms_{be}"] = r["valid"]["p50_ms"], p99(r)
        elif "valid" in r:
            x[f"sv_p99_ms_{f.split('-')[0]}"] = p99(r)


def multi(d):
    """The op 7 table of a --multi-bench run: {"pqzl": {"M,on": {...}}, "pqzh": {...}, "checks": [...]}."""
    res = {"pqzl": {}, "pqzh": {}, "checks": [], "machine": machine()}
    add = lambda s, w, x: res["checks"].append([s, w, x])
    for n in TXM_TEXT:
        p = os.path.join(d, n)
        st = text_check(p, []) if os.path.exists(p) else "FAIL"
        add(st, n, "rc 0" if st == "ok" else "see the file" if os.path.exists(p) else "missing")
    for f in TXM_PQZL:
        p = os.path.join(d, f"pqzl-txm-{f}.jsonl")
        if not os.path.exists(p):
            add("FAIL", f"pqzl-txm-{f}.jsonl", "missing")
            continue
        rels, fails, mism = bench(p)
        add("ok" if fails == 0 and mism == 0 else "FAIL", f"pqzl-txm-{f}.jsonl", f"fails {fails}, verifier disagreements {mism}")
        txm_fill(res["pqzl"], f, rels)
    # the Rust core (reproduce.sh --multi-bench's Rust step), if run: rows next to PQZL's
    for f in TXM_RUST:
        p = os.path.join(d, f"rust-txm-{f}.jsonl")
        if os.path.exists(p):
            rels, fails, mism = bench(p)
            add("ok" if fails == 0 and mism == 0 else "FAIL", f"rust-txm-{f}.jsonl", f"fails {fails}, verifier disagreements {mism}")
            txm_fill(res.setdefault("rust", {}), f, rels)
    for n in ("rust-txm-build.txt", "rust-txm.txt"):
        p = os.path.join(d, n)
        if os.path.exists(p):
            st = text_check(p, [])
            add(st, n, "rc 0" if st == "ok" else "see the file")
    for f in TXM_PQZH:
        p = os.path.join(d, f"pqzh-txm-{f}.jsonl")
        if not os.path.exists(p):
            add("FAIL", f"pqzh-txm-{f}.jsonl", "missing")
            continue
        forms, fails = pqzh_bench(p)
        add("ok" if fails == 0 else "FAIL", f"pqzh-txm-{f}.jsonl", f"fails {fails} (mutations accepted, panics, rc)")
        be = "wasm" if f.endswith("wasm") else "native"
        for rel, r in forms.items():
            s = txm_rel(rel)
            if not s:
                continue
            x = res["pqzh"].setdefault(f"{s[0]},{'on' if s[1] else 'off'}", {"m": s[0], "aud": s[1]})
            if f"src_{be}" in x:
                continue  # measured by the built run already
            x[f"src_{be}"] = f
            for k in ("max_len_exact", "proof_bytes_max"):
                if k in r:
                    x[k] = r[k]
            if "prove" in r:
                x[f"prove_p50_ms_{be}"], x[f"prove_memory_mib_{be}"] = r["prove"]["p50_ms"], r.get("memory_mib")
            if "verify_honest" in r:
                x[f"verify_p50_ms_{be}"], x[f"verify_p99_ms_{be}"] = r["verify_honest"]["p50_ms"], r["verify_honest"]["p99_ms"]
    for i in ("pqzl", "pqzh"):
        for m in TXM_BUILT[i]:
            for a in ("on", "off"):
                add("ok" if f"{m},{a}" in res[i] else "FAIL", f"{i} R_TXM ({m}, {a}) measured", "built shape")
    return res


def multi_markdown(res):
    k = lambda x: (not x["aud"], x["m"])
    built = lambda i, x: "yes" if x["m"] in TXM_BUILT[i] else "no (oversize, bench build only)"
    L = ["# Op 7 R_TXM measurements (reproduce.sh --multi-bench)", "",
         "Machine: {cpu} ({threads} threads; flags {flags}), in Docker: {docker}. Times are informational.".format(**res["machine"]), "",
         "## PQZL (research/pqzl-measure/txm-bench.sh, the L3 method)", "",
         "| M | auditor | built | proof bytes (max) | prove p50 native / wasm32 | generic verify p50 / p99 native"
         " | SV p99 portable / x86-64-v3 / wasm32 | wasm32 prove peak (no SV) |", "|---|---|---|---|---|---|---|---|"]
    rust = res.get("rust", {})
    for c in sorted(res["pqzl"].values(), key=k):
        rs = rust.get(f"{c['m']},{'on' if c['aud'] else 'off'}")
        for core, x in [("", c)] + ([(" Rust", rs)] if rs else []):
            g = lambda key, nd=1: fmt(x.get(key), nd)
            pk = x.get("wasm_prove_peak_bytes")
            L.append(f"| {x['m']}{core} | {'on' if x['aud'] else 'off'} | {built('pqzl', x)} | {g('proof_bytes_max_native')}"
                     f" | {g('prove_p50_ms_native', 0)} / {g('prove_p50_ms_wasm', 0)} ms"
                     f" | {g('verify_p50_ms_native', 0)} / {g('verify_p99_ms_native', 0)} ms"
                     f" | {g('sv_p99_ms_native', 1)} / {g('sv_p99_ms_x86v3', 1)} / {g('sv_p99_ms_wasm', 1)} ms"
                     f" | {fmt(pk / 2**20 if pk else None)} MiB |")
    if rust:
        L += ["", "\"Rust\" rows: the Rust core (`pqzl/rust/`, its bench and wasm/run_wasm.mjs, the counts of the PQZL "
              "rows; wasm32 with the op 7 limit lifted, feature wasm-m8). Its wasm32 prove peak is the module's linear "
              "memory after the proves (one shape per process), the C one the arena peak; no x86-64-v3 build."]
    L += ["", "## PQZH (Ligero, the proven preset; the H2 method of pqzh/ligero/runs/txm.sh)", "",
          "| M | auditor | built | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native"
          " | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear |", "|---|---|---|---|---|---|---|---|---|"]
    for x in sorted(res["pqzh"].values(), key=k):
        g = lambda key, nd=1: fmt(x.get(key), nd)
        L.append(f"| {x['m']} | {'on' if x['aud'] else 'off'} | {built('pqzh', x)} | {g('proof_bytes_max')}"
                 f" | {g('max_len_exact')} | {g('prove_p50_ms_native', 0)} / {g('prove_p50_ms_wasm', 0)} ms"
                 f" | {g('verify_p50_ms_native', 2)} / {g('verify_p99_ms_native', 2)} ms"
                 f" | {g('verify_p50_ms_wasm', 2)} / {g('verify_p99_ms_wasm', 2)} ms"
                 f" | {g('prove_memory_mib_native')} / {g('prove_memory_mib_wasm')} MiB |")
    n = {s: sum(1 for c in res["checks"] if c[0] == s) for s in ("ok", "FAIL")}
    L += ["", f"## Checks: {n['ok']} ok, {n['FAIL']} FAIL", "", "| status | check | detail |", "|---|---|---|"]
    L += [f"| {s} | {w} | {x} |" for s, w, x in res["checks"]]
    return "\n".join(L) + "\n"


# D6 (port plan Task 12): pqzl/rust/d6.sh writes <core>-<run>.jsonl (one process per relation, core and backend) and
# rust-memory.txt (tests/memory.rs peak_per_op), rust-m8-{native,wasm}-vectors.jsonl (the wasm32 op 7 M = 8 question)
D6_RUNS = ["native-generic", "native-fast", "wasm-generic", "wasm-fast", "wasm-nosv"]  # wasm-nosv: C only
D6_RELS = RELS + [f"R_TXM{m}{a}" for a in ("", "_0") for m in TXM_BUILT["pqzl"]]
VEC_REL = {"REGISTER": "R_REG", "TRANSFER": "R_TX", "BURN": "R_BURN", "DISCLOSE-SENDER": "R_DS",
           "DISCLOSE-RECEIVER": "R_DR", "TRANSFER0": "R_TX0"}
# Task 12's criterion for raising the wasm32 op 7 prove limit to M = 8 (Rust backend): the M = 8 wasm32 peak within the
# C core's wasm32 M = 4 peak (R_TXM4, auditor on: 268,012,304 B = 255.6 MiB, artifact/runs/s6-docker-multi), and
# native = wasm32 on the M = 8 vector proofs
WASM_M8_BUDGET = 268012304


def vec_rel(name):
    """tests/memory.rs row name -> relation: 'TRANSFER' -> 'R_TX', 'M8-off' -> 'R_TXM8_0'."""
    s = txm_shape(name)
    return VEC_REL.get(name) or (s and f"R_TXM{s[0]}{'' if s[1] else '_0'}")


def d6(d, rerun=None):
    """rerun: a d6.sh D6_T re-run of some loop steps (its own run dir); its relations' rows replace the first pass's."""
    res = {"rels": {}, "checks": [], "machine": machine()}
    add = lambda s, w, x: res["checks"].append([s, w, x])
    fresh = set()  # (rel, core) taken from the re-run
    for core, src, f in [(c, s, f) for s in [d] + ([rerun] if rerun else []) for c in ("c", "rust") for f in D6_RUNS]:
        p = os.path.join(src, f"{core}-{f}.jsonl")
        if not os.path.exists(p):
            continue
        rels, fails, mism = bench(p)
        name = os.path.relpath(p, d)
        add("ok" if fails == 0 and mism == 0 else "FAIL", name, f"fails {fails}, verifier disagreements {mism}")
        be, ver = f.split("-")
        for rel, r in rels.items():
            if src == rerun and (rel, core) not in fresh:
                fresh.add((rel, core))
                res["rels"].setdefault(rel, {})[core] = {}
                rr = res.setdefault("rerun", {"dir": os.path.relpath(rerun, d), "rels": []})["rels"]
                rr += [] if rel in rr else [rel]
            x = res["rels"].setdefault(rel, {}).setdefault(core, {})
            if ver == "nosv":
                x["wasm_peak"] = r.get("arena_peak")
                continue
            if "fnv" in r and ver == "generic":
                x[f"fnv_{be}"] = [r["fnv"], r["np"]]
                x["native_peak" if be == "native" else "wasm_peak"] = r.get("arena_peak" if be == "native" else "wasm_memory")
            if "prove" in r and ver == "generic":
                x[f"prove_{be}"] = [r["prove"]["p50_ms"], r["prove"]["p99_ms"]]
            if "valid" in r:
                x[f"{'verify' if ver == 'generic' else 'fast'}_{be}"] = [r["valid"]["p50_ms"], p99(r)]
    for core in ("c", "rust"):  # ffi_bench on each pqz-ffi backend
        p = os.path.join(d, f"{core}-ffi-bench.jsonl")
        if os.path.exists(p):
            res[f"ffi_{core}"] = [o for o in jsonl(p) if "sys" in o]
    p = os.path.join(d, "rust-memory.txt")
    for line in open(p, errors="replace") if os.path.exists(p) else []:
        m = re.match(r"(\S+)\s+(\d+)(?:\s+\d+){6}$", line.strip())
        if m and vec_rel(m.group(1)):
            res["rels"].setdefault(vec_rel(m.group(1)), {}).setdefault("rust", {})["native_peak"] = int(m.group(2))
    for rel, x in res["rels"].items():
        c, r = x.get("c", {}), x.get("rust", {})
        for be in ("native", "wasm"):
            (hc, nc), (hr, nr) = c.get(f"fnv_{be}", [None, 0]), r.get(f"fnv_{be}", [None, 0])
            if hc and hr:  # the same proofs only for the same n (d6.sh runs both cores with the same counts)
                add("info" if nc != nr else "ok" if hc == hr else "FAIL", f"{rel} proofs_fnv {be} Rust = C",
                    f"Rust {hr} (n={nr}), C {hc} (n={nc})")
    n, w = (os.path.join(d, f"rust-m8-{s}-vectors.jsonl") for s in ("native", "wasm"))
    if os.path.exists(n) and os.path.exists(w):
        m8 = [l for l in open(w) if l.startswith('{"row": "M8-')]  # proved in wasm32: a "prove" digest, not a refusal
        eq = open(n).read() == open(w).read() and bool(m8) and all('"prove"' in l for l in m8)
        peaks = {rel: res["rels"].get(rel, {}).get("rust", {}).get("wasm_peak") for rel in ("R_TXM8", "R_TXM8_0")}
        fit = all(v and v <= WASM_M8_BUDGET for v in peaks.values())
        res["wasm_m8"] = {"native_eq_wasm": eq, "peaks": peaks, "budget": WASM_M8_BUDGET, "enough": eq and fit}
        add("info", "wasm32 op 7 M = 8 (Task 12)", f"{'enough' if eq and fit else 'not enough'}: native = wasm32 on the "
            f"vector proofs {eq}; Rust wasm32 M = 8 peaks {peaks} B, budget {WASM_M8_BUDGET:,} B (the C M = 4 peak)")
    return res


def d6_markdown(res):
    ms = lambda v: "–" if not v else f"{fmt(v[0], 1)} / {fmt(v[1], 1)}"
    mib = lambda v: "–" if not v else f"{v / 2**20:,.1f}"
    fnv = lambda v: "–" if not v else f"{v[0]} (n={v[1]})"
    L = ["# D6: the Rust core against the C core (pqzl/rust/d6.sh)", "",
         "Machine: {cpu} ({threads} threads; flags {flags}), {os}, {cc}, node {node}, {rustc}.".format(**res["machine"]),
         "One session, one machine; one process per relation, core and backend. Times p50 / p99 in ms (verify p99: the "
         "larger of honest and adversarial). Prove peak native: C arena peak / Rust heap peak (counting allocator, cold "
         "Ctx, tests/memory.rs); wasm32: C arena peak (prover build without SV) / Rust linear memory of the "
         "one-relation process.", ""] + ([f"Rows of {', '.join(f'`{r}`' for r in res['rerun']['rels'])}: the re-run in "
         f"`{res['rerun']['dir']}/` (d6.sh D6_T), which replaces the first pass's rows of those relations (kept in the raw "
         "files of this directory).", ""] if "rerun" in res else []) + [
         "| relation | core | prove native | prove wasm32 | verify native | verify wasm32 | verify_fast native "
         "| verify_fast wasm32 | prove peak native (MiB) | prove peak wasm32 (MiB) | proofs_fnv native / wasm32 |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for rel in D6_RELS + sorted(set(res["rels"]) - set(D6_RELS)):
        for core in ("c", "rust"):
            x = res["rels"].get(rel, {}).get(core)
            if x is None:
                continue
            L.append(f"| `{rel}` | {'C' if core == 'c' else 'Rust'} | {ms(x.get('prove_native'))} | {ms(x.get('prove_wasm'))}"
                     f" | {ms(x.get('verify_native'))} | {ms(x.get('verify_wasm'))} | {ms(x.get('fast_native'))}"
                     f" | {ms(x.get('fast_wasm'))} | {mib(x.get('native_peak'))} | {mib(x.get('wasm_peak'))}"
                     f" | {fnv(x.get('fnv_native'))} / {fnv(x.get('fnv_wasm'))} |")
    for core in ("c", "rust"):
        if f"ffi_{core}" in res:
            L += ["", f"## pqz-ffi path, {'C' if core == 'c' else 'Rust (pqzl-rust)'} backend (ffi_bench 200)", "",
                  ffi_table({"ffi": {"bench": res[f"ffi_{core}"]}})]
    n = {s: sum(1 for c in res["checks"] if c[0] == s) for s in ("ok", "FAIL")}
    L += ["", f"## Checks: {n['ok']} ok, {n['FAIL']} FAIL", "", "| status | check | detail |", "|---|---|---|"]
    L += [f"| {s} | {w} | {x} |" for s, w, x in res["checks"]]
    return "\n".join(L) + "\n"


def main(a):
    here = os.path.dirname(os.path.abspath(__file__))
    if len(a) >= 2 and a[0] == "check":
        d = a[1]
        exp = json.load(open(a[2] if len(a) > 2 else os.path.join(here, "expected-results.json")))
        files = {n: os.path.join(d, n) for n in list(BENCH) + CHECKS + list(PQZH_RUNS) + list(TEXT) + FFI + [VECTORS]}
        files.update({n: os.path.join(d, n) for n in list(RUST_BENCH) + RUST_TXM + [RUST_KEYS]})
        res = summarize(files)
        add_pqzh(res, files)
        add_rust(res, files)
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
        files = {n: os.path.join(r3, n) for n in list(BENCH) + CHECKS + list(PQZH_RUNS) + list(TEXT) + FFI + [VECTORS]} if sv is None else {"native-generic.jsonl": f"{r3}-native.jsonl", "wasm-generic.jsonl": f"{r3}-wasm.jsonl",
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
        # every n with a frozen hash: the pqzl-measure per-op runs (n = 1, native) too
        for rel, r in (bench(f"{r3}-alone.jsonl", "native")[0] if sv else {}).items():
            if rel in RELS:
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
        if "txm" in res:
            pq["txm"] = txm_expected(res)
        exp = {"frozen": label, "source_runs": sorted(files.values()), "machine": res["machine"], "tolerance": TOL,
               "relations": {rel: {k: x.get(k) for k in ("fnv", "proof_bytes_max", "wasm_prove_peak_bytes", "ratios")}
                             | {"times_ms_informational": {k: v for k, v in x.items() if k.endswith("_ms_native")
                                                           or k.endswith("_ms_wasm") or k.endswith("_ms_x86v3")}}
                             for rel, x in res["relations"].items()}} | pq
        json.dump(exp, sys.stdout, indent=1)
        print()
        sys.stderr.write(markdown(res) + ("" if ok else "\nFROZEN RUN HAS FAILED CHECKS\n"))
        return 0 if ok else 1
    if len(a) in (3, 4) and a[0] == "freeze-txm":
        label, d = a[1], a[2]
        exp = json.load(open(a[3] if len(a) > 3 else os.path.join(here, "expected-results.json")))
        files = {n: os.path.join(d, n) for n in list(BENCH) + CHECKS + list(PQZH_RUNS) + list(TEXT) + FFI + [VECTORS]}
        res = summarize(files)
        add_pqzh(res, files)
        if "txm" not in res or not res["ffi"].get("digests_native"):
            sys.stderr.write(f"freeze-txm: {d} has no vectors-check.txt or ffi-digests-native.jsonl\n")
            return 1
        old, new = exp["ffi"]["digest_lines"], res["ffi"]["digests_native"]
        it = iter(new)
        if not all(any(o == n for n in it) for o in old):  # old lines kept, in order: only op 7 lines added
            sys.stderr.write("freeze-txm: the run changes existing pqz-ffi digest lines; not an op 7-only change\n")
            return 1
        added = [f'{n["sys"]} {n["form"]}' for n in new if n not in old]
        exp["ffi"]["digest_lines"] = new
        exp["txm"] = txm_expected(res)
        exp.setdefault("changes", []).append(
            f"{label}: + txm (op 7 R_TXM vector replay, run {os.path.normpath(d)}); ffi.digest_lines {len(old)} -> "
            f"{len(new)} (added {', '.join(added)}); every other value unchanged")
        res["mode"] = open(os.path.join(d, "mode.txt")).read().strip() if os.path.exists(os.path.join(d, "mode.txt")) else "?"
        res["machine"] = machine()
        ok = compare(res, exp)
        json.dump(exp, sys.stdout, indent=1)
        print()
        sys.stderr.write(markdown(res) + ("" if ok else "\nRUN FAILS A CHECK AGAINST THE NEW EXPECTED RESULTS\n"))
        return 0 if ok else 1
    if len(a) == 2 and a[0] == "multi":
        res = multi(a[1])
        json.dump(res, open(os.path.join(a[1], "results-multi.json"), "w"), indent=1)
        md = multi_markdown(res)
        open(os.path.join(a[1], "results-multi.md"), "w").write(md)
        print(md)
        ok = not any(st == "FAIL" for st, _, _ in res["checks"])
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if len(a) in (2, 3) and a[0] == "d6":
        res = d6(a[1], a[2] if len(a) == 3 else None)
        json.dump(res, open(os.path.join(a[1], "results-d6.json"), "w"), indent=1)
        md = d6_markdown(res)
        open(os.path.join(a[1], "results-d6.md"), "w").write(md)
        print(md)
        ok = not any(st == "FAIL" for st, _, _ in res["checks"])
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
