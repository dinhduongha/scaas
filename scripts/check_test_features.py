#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""No test feature in a production artifact (ARCH-POS-13; spec no-decryption-oracle §4.8, Codex C1 and C7; ua-rs-sign T15c2).

Cargo unifies features: any crate that turns on `vectors` or `hazmat` of `scaas-ua`, `zether-prover` or `pqz-ffi` hands every
build beside it the raw decrypt commands; `scaas-ct`'s `vectors` records every ladder's secret scalar (T15l, Fable P3-4). Two checks, each with its positive control (a check that cannot fail proves
nothing), exit 1 on any finding:

1. manifests: no tracked `Cargo.toml` (outside `legacy/`) enables one of those features outside `[dev-dependencies]` or a
   test-only crate (TEST_ONLY): not in a dependency's `features`, not forwarded by a feature that is not itself a test
   feature, and no crate's `default` reaches a test feature through its own feature table.
2. graphs: `cargo tree -e features,normal,build -i <crate>` of each production artifact (ARTIFACTS: the resolved feature
   graph without dev edges, every feature with what enabled it, transitive defaults included) shows none of them.

  python3 scripts/check_test_features.py        (from the repository root; cargo honours CARGO_NET_OFFLINE)
UNAUDITED."""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARDED = ("scaas-ua", "zether-prover", "pqz-ffi", "scaas-ct")
TEST = ("vectors", "hazmat")
# test-only crates: the fuzz harness of ua-rs (its targets reach the facades through `vectors`)
TEST_ONLY = {"clients/ua-rs/fuzz/Cargo.toml"}
# the production artifacts: (directory, extra cargo tree arguments); the bindings' cores and zether-read-balance
ARTIFACTS = [
    ("clients/ua-c", []),
    ("clients/ua-cxx", []),
    ("clients/ua-qt", []),
    ("clients/ua-dart-frb/rust", []),
    ("clients/zether-prover", []),  # zether-read-balance, zether-cli and the wasm library: the package's features
    ("scaas-node", []),  # the node (scaas-ua for the UA formats; T15l, Fable P3-4)
    ("pqz-core/ffi/wasm", []),  # pqz-ffi's wasm32 library (T15l, Fable P3-4)
]
DEP_TABLES = ("dependencies", "build-dependencies")


def dep_tables(m):
    """The non-dev dependency tables of a parsed manifest: top level and per target."""
    for t in DEP_TABLES:
        yield t, m.get(t, {})
    for cfg, tm in m.get("target", {}).items():
        for t in DEP_TABLES:
            yield f"target.{cfg}.{t}", tm.get(t, {})


def check_manifest(rel, text):
    """The findings of one manifest (`rel`, its text)."""
    if rel in TEST_ONLY:
        return []
    m, out = tomllib.loads(text), []
    names = {}  # dependency key -> package name, non-dev tables only
    for where, deps in dep_tables(m):
        for key, d in deps.items():
            pkg = d.get("package", key) if isinstance(d, dict) else key
            names[key] = pkg
            feats = d.get("features", []) if isinstance(d, dict) else []
            out += [f"{rel}: [{where}] {key} enables {pkg}/{f}" for f in feats if pkg in GUARDED and f in TEST]
    features = m.get("features", {})
    for f, enables in features.items():
        for e in enables:
            dep, _, feat = e.partition("/")
            dep = dep.rstrip("?")
            if feat in TEST and names.get(dep, dep) in GUARDED and f not in TEST:
                out.append(f"{rel}: [features] {f} = {e} (only a test feature may forward to one)")
    seen, todo = set(), ["default"]
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        todo += [e for e in features.get(f, []) if "/" not in e and ":" not in e]
    out += [f"{rel}: [features] default reaches the test feature {f}" for f in sorted(seen & set(TEST))]
    return out


def check_manifests():
    files = subprocess.run(["git", "ls-files", "*Cargo.toml"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    files = [f for f in files if "/legacy/" not in f and not f.startswith("legacy/")]
    out = [x for f in files for x in check_manifest(f, (ROOT / f).read_text(encoding="utf-8"))]
    return len(files), out


LINE = re.compile(r"^(\d+)(.*?)(?: \(\*\))?$")
FEATURE = re.compile(r'^(\S+) feature "([^"]+)"')


def tree(cwd, pkg, extra):
    """`cargo tree -i pkg` of the artifact in `cwd` as (depth, node) lines, or None if `pkg` is not in its graph."""
    cmd = ["cargo", "tree", "--locked", "-e", "features,normal,build", "-f", "{p}", "--prefix", "depth", "-i", pkg, *extra]
    r = subprocess.run(cmd, cwd=ROOT / cwd, capture_output=True, text=True)
    if r.returncode != 0:
        if "did not match any packages" in r.stderr:
            return None
        raise SystemExit(f"{cwd}: {' '.join(cmd)} failed:\n{r.stderr}")
    return [(int(m.group(1)), m.group(2)) for m in map(LINE.match, r.stdout.splitlines()) if m]


def check_graph(cwd, extra):
    """The guarded crates' test features in the artifact's resolved graph, each with the chain that enabled it."""
    out = []
    for pkg in GUARDED:
        lines = tree(cwd, pkg, extra)
        for i, (depth, node) in enumerate(lines or []):
            f = FEATURE.match(node)
            if depth == 1 and f and f.group(1) == pkg and f.group(2) in TEST:
                chain, d = [node], depth  # the enablers below it, down to the root's feature
                for dd, n in lines[i + 1:]:
                    if dd <= depth:
                        break
                    if dd == d + 1:
                        chain.append(n)
                        d = dd
                out.append(f"{cwd}{' ' + ' '.join(extra) if extra else ''}: {' <- '.join(chain)}")
    return out


def main():
    bad = []
    n, found = check_manifests()
    print(f"manifests: {n} Cargo.toml checked, {len(found)} findings")
    bad += found
    # positive control 1: `vectors` in [dependencies] and a `hazmat` forwarded from `default` are found, [dev-dependencies] not
    dep = 'scaas-ua = { path = "x", features = ["vectors"] }\n'
    head = '[package]\nname = "scratch"\n'
    fwd = head + '[dependencies]\nzether-prover = { path = "x" }\n[features]\ndefault = ["x"]\nx = ["zether-prover/hazmat"]\n'
    ok = (check_manifest("scratch", head + "[dependencies]\n" + dep) != [] and check_manifest("scratch", fwd) != []
          and check_manifest("scratch", head + "[dev-dependencies]\n" + dep) == [])
    ok = ok and check_manifest("scratch", head + '[dependencies]\nscaas-ct = { path = "x", features = ["vectors"] }\n') != []
    print(f"positive control (manifests): vectors in [dependencies] (scaas-ua, scaas-ct) and a forwarded hazmat found, "
          f"[dev-dependencies] not: {ok}")
    bad += [] if ok else ["positive control (manifests) failed"]
    for cwd, extra in ARTIFACTS:
        found = check_graph(cwd, extra)
        print(f"graph {cwd}: {len(found)} findings")
        bad += found
    # positive control 2: the same graph with `vectors` forced is found (and, through it, zether-prover's `hazmat`)
    forced = check_graph("clients/ua-c", ["--features", "scaas-ua/vectors"])
    ok = any("scaas-ua feature \"vectors\"" in x for x in forced) and any("zether-prover feature \"hazmat\"" in x for x in forced)
    print(f"positive control (graph): ua-c with scaas-ua/vectors forced: {len(forced)} findings, both crates found: {ok}")
    bad += [] if ok else ["positive control (graph) failed"]
    # T15l (Fable P3-4): the new rows are seen too: scaas-ct's `vectors` forced into zether-prover's graph (its dev-dependency
    # enables it for the tests only) is found; the node's graph holds scaas-ua and the wasm library's pqz-ffi, so neither row is
    # vacuous, and both are rows of ARTIFACTS (forcing scaas-ua/vectors in the node does not resolve: its serde_json pin; pqz-ffi has no test feature of its
    # own yet, pqz-core `hazmat` is T15h)
    ct = check_graph("clients/zether-prover", ["--features", "scaas-ct/vectors"])
    rows = [r[0] for r in ARTIFACTS]
    node = "scaas-node" in rows and tree("scaas-node", "scaas-ua", []) is not None
    wasm = "pqz-core/ffi/wasm" in rows and tree("pqz-core/ffi/wasm", "pqz-ffi", []) is not None
    ok = any('scaas-ct feature "vectors"' in x for x in ct) and node and wasm
    print(f"positive control (graph): scaas-ct/vectors forced in zether-prover: {len(ct)} findings; scaas-ua in scaas-node's "
          f"graph {node}, pqz-ffi in pqz-core/ffi/wasm's {wasm}: {ok}")
    bad += [] if ok else ["positive control (graph, T15l rows) failed"]
    for b in bad:
        print(f"FINDING: {b}")
    print(f"check_test_features: {'FAIL' if bad else 'ok'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
