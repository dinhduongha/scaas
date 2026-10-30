#!/usr/bin/env python3
"""fs3 Task 6 (2026-10-30): the refresh of expected-results.json for the PQZL v3 transcript + D-2/D-3 at
n2304-kmax4096, from the committed files of this run directory (the Docker quick run of 04:48; it failed only
against the stale 2026-10-18 expected file, and the PASS run ../fs3-t6-docker-quick/ reproduces every hash,
proof size and digest line; times, ratios and memory peaks are within tolerance).

  python3 -I refreeze.py <base expected-results.json>   > expected-results.json

The base is the 2026-10-18 file (git show e328ef4d:pqz-core/artifact/expected-results.json). The run's own
results.json was written by the image's older results.py, so the run files are summarised again here with today's
results.py. Inputs: the run files of this directory, c-fnv-n5.jsonl / c-fnv-n10.jsonl (the C core's pqz_bench 5 / 10
in the same image). The output equals the committed expected-results.json (fs3 Task 6 fix 1: diff empty).
"""
import importlib.util, json, os, sys

RUN = os.path.dirname(os.path.abspath(__file__))
A = os.path.normpath(os.path.join(RUN, "..", ".."))
spec = importlib.util.spec_from_file_location("results", os.path.join(A, "results.py"))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

REL_RUN = "pqz-core/artifact/runs/fs3-t6-docker-quick-fail-0448"
PASS_RUN = "pqz-core/artifact/runs/fs3-t6-docker-quick"
CHANGE = (
    "2026-10-30 (fs3 Task 6): v3 transcript + D-2/D-3 at n2304-kmax4096 (reproduce.sh now PQZ_SET=n2304-kmax4096; the "
    "KAT check reads the set's own golden). Every value is taken from the Docker quick run " + REL_RUN + " (04:48; it "
    "failed only against the stale 2026-10-18 file) by its refreeze.py; the PASS run " + PASS_RUN + " gives the "
    "same hashes, proof sizes and digest lines (times, ratios and memory peaks within tolerance): relations.*.fnv n = 1/2/3 from that run's C benches, n = 5/10 from the C core's pqz_bench there "
    "(c-fnv-n5/n10.jsonl; the Rust core gives the same hashes for n = 1/3/5/10), proof_bytes_max, "
    "wasm_prove_peak_bytes, ratios, times, pqzh figures of seeds 0/1 only (seeds 2-4 need a --full refreeze), "
    "ffi.selftest + digest_lines, txm, rust.txm_fnv, rust.keys_kat; machine block unchanged")


def bench_fnv(name):
    out = {}
    for line in open(os.path.join(RUN, name)):
        if line.startswith("{"):
            j = json.loads(line)
            if "proofs_fnv" in j:
                out[j["rel"]] = j["proofs_fnv"]
    return out


def main(base):
    e = json.load(open(base))
    files = {n: os.path.join(RUN, n) for n in list(R.BENCH) + R.CHECKS + list(R.PQZH_RUNS) + list(R.TEXT) + R.FFI + [R.VECTORS]}
    files.update({n: os.path.join(RUN, n) for n in list(R.RUST_BENCH) + R.RUST_TXM + [R.RUST_KEYS]})
    r = R.summarize(files)
    R.add_pqzh(r, files)
    R.add_rust(r, files)
    bench = {n: bench_fnv(f"c-fnv-n{n}.jsonl") for n in (5, 10)}
    for rel, x in r["relations"].items():
        o = e["relations"][rel]
        o["fnv"] = {**x["fnv"], **{str(n): bench[n][rel] for n in bench}}
        o["proof_bytes_max"] = x["proof_bytes_max"]
        o["wasm_prove_peak_bytes"] = x["wasm_prove_peak_bytes"]
        o["ratios"] = x["ratios"]
        o["times_ms_informational"] = {k: v for k, v in x.items() if k.endswith(("_ms_native", "_ms_wasm", "_ms_x86v3"))}
    for rel, x in r["pqzh"]["forms"].items():
        o = e["pqzh"]["forms"][rel]
        o["fnv"] = {s: h for _, s, h in x["fnv_seen"]}
        o["proof_bytes"] = {s: n for _, s, n in x["bytes_seen"]}
        o["max_len_exact"] = x["max_len_exact"]
        o["ratios"] = x["ratios"]
        o["informational"] = {k: v for k, v in x.items() if k.startswith(("prove_", "verify_"))}
    e["ffi"] = {"selftest": r["ffi"]["selftest"], "digest_lines": r["ffi"]["digests_native"]}
    e["txm"] = R.txm_expected(r)
    e["rust"]["txm_fnv"] = {rel: {str(n): h} for rel, _, n, h in r["rust"]["txm_fnv_seen"]}
    e["rust"]["txm_fnv_source"] = (REL_RUN + " (Rust core, bench 2 per shape; the PASS run " + PASS_RUN + " gives the "
                                   "same hashes; the C core gives the same proofs at this set: gate fin-fnv-c.txt)")
    e["rust"]["keys_kat"]["sha256"] = r["rust"]["keys_kat_sha256"]
    e["rust"]["keys_kat"]["source"] = ("SHA-256 of the Rust keys KAT (pqz keys_kat 100) at n2304-kmax4096, run " + REL_RUN
                                       + " (the PASS run " + PASS_RUN + " gives the same file; pqz_kat.py --c-keys: = C)")
    e["changes"].append(CHANGE)
    names = {os.path.basename(p) for p in files.values() if os.path.exists(p)}
    names |= {"c-fnv-n5.jsonl", "c-fnv-n10.jsonl", "rust-host-bench-n1.jsonl", "rust-host-bench-n10.jsonl"}
    refresh = sorted(f"{REL_RUN.removeprefix('pqz-core/')}/{n}" for n in names)  # as source_runs: relative to pqz-core
    out = {}
    for k, v in e.items():  # the 2026-10-17 freeze keys stay as history; the refresh keys follow them
        out[k] = v
        if k == "source_runs":
            out["refreshed"] = "2026-10-30 fs3 Task 6 (PQZL v3 transcript + D-2/D-3, n2304-kmax4096), see changes"
            out["refresh_runs"] = refresh
    sys.stdout.write(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
