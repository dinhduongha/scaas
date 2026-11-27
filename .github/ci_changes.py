# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Which CI jobs a run needs: one output per job, "true" when a changed path starts with one of its prefixes.

A push (to main), a change to .github/, or a failed diff runs every job. Prefixes are the job's own directory plus every
directory its tests read (vectors, contracts, ua-rs for the wrappers); when in doubt a prefix is wider, never narrower.
`docs` runs on every pull request: it reads ids in code comments too.
A path no component test reads starts no component job, only `docs`: Markdown anywhere, and everything under a `runs/`
directory (evidence logs, one-off scripts, probe data: the owner's machine runs them, CI does not). A `runs/` file a test
does read is named in RUNS_READ with the jobs that read it.

A group is forced on, whatever the paths, by a pull-request label `ci-full-<group>` / `ci-full` (env LABELS, a JSON list)
or by a manual run (workflow_dispatch, env FULL = the chosen `ci-full-<group>` / `ci-full`); a manual run has no diff,
so it runs only that group plus `docs`.
"""

import json
import os
import subprocess

# Each on-chain family: its own directory, the shared build/test scripts and the cross-language vectors.
SC = ["smartcontracts/scripts/", "smartcontracts/vectors/"]
# the root rust-toolchain.toml: the one Rust toolchain of every crate (ARCH-POS-12)
RT = ["rust-toolchain.toml"]
# ua-rs and every crate it builds (ua-rs-sign T18): scaas-ct, zether-prover (the Zether facade), pqz-ffi, pqzl, pqz-stmt, Ligero
# and the parameter sets (the PQZ facade, MD-5); a job over ua-rs reads them all; vendor/ (the third-party sources it builds:
# PQClean Falcon natively, falcon-rs 0.3.1 on wasm32, CLI-UAL-66) and scripts/vendor.sh, which installs and checks it (ARCH-POS-24)
VENDOR = ["vendor/", "scripts/vendor.sh"]
UARS = (
    [
        "clients/ua-rs/",
        "clients/scaas-ct/",
        "clients/zether-prover/",
        "pqz-core/ffi/",
        "pqz-core/pqzl/",
        "pqz-core/stmt/",
        "pqz-core/pqzh/",
        "pqz-core/params/",
    ]
    + VENDOR
    + RT
)
# the profile store (owner 2026-11-27): its own crate, a dependency of the SDK (feature `user-profile`); every job over the SDK
# reads it
PROFILE = ["clients/scaas-profile/"]
JOBS = {
    "contract-evm": ["smartcontracts/evm/"]
    + SC
    + ["pqz-core/params/", "scripts/size_gate.py", "scripts/evm_libs.sh"]
    + VENDOR,
    "contract-soroban": ["smartcontracts/soroban/"] + SC + RT,
    "contract-solana": ["smartcontracts/solana/"] + SC + RT,
    "contract-near": ["smartcontracts/near/"] + SC + RT,
    "contract-algorand": ["smartcontracts/algorand/"] + SC,
    # smartcontracts/move/ holds only aptos/ and sui/, nothing shared; a shared file there gets its prefix in both
    "contract-aptos": ["smartcontracts/move/aptos/"] + SC,
    "contract-sui": ["smartcontracts/move/sui/"] + SC,
    "contract-cosmos": ["smartcontracts/cosmos/"] + SC + RT,
    "contract-ton": ["smartcontracts/ton/"] + SC,
    "node": ["scaas-node/", "clients/ua-rs/", "clients/scaas-rpc/", "smartcontracts/"] + VENDOR + RT,
    # the network crate and the depth scan it takes from ua-rs (json)
    "scaas-rpc": ["clients/scaas-rpc/", "clients/ua-rs/"] + VENDOR + RT,
    "docs": [""],
    "clientkeys": ["clients/clientkeys/", "smartcontracts/", "scaas-node/src/"] + VENDOR,
    # the directories the pqz job builds and tests (pqzl, ffi, stmt, pqzh/ligero, params, fuzz); pqz-core/nethermind/ (chain
    # scripts, the C# plugin), artifact/, glic/, research/, runs/ and the top-level gate scripts are run on the owner's machine
    "pqz": [
        "pqz-core/pqzl/",
        "pqz-core/ffi/",
        "pqz-core/stmt/",
        "pqz-core/pqzh/",
        "pqz-core/params/",
        "pqz-core/fuzz/",
        "pqz-core/gate-controls.sh",
        "smartcontracts/vectors/pqz/",
    ]
    + VENDOR
    + RT,
    "zether-prover": ["clients/zether-prover/", "clients/scaas-ct/", "smartcontracts/evm/", "smartcontracts/vectors/"]
    + VENDOR
    + RT,
    # secret_mul's own tests (ua-rs-sign T3c; T15o closes the gap T20 found: ua-rs and zether-prover only build the crate)
    "scaas-ct": ["clients/scaas-ct/"] + RT,
    # the user-profile cell's no-signing gate (CLI-UPR-30) reads scaas-profile's graph too
    "ua-rs": UARS + ["smartcontracts/"] + PROFILE,
    # the Falcon gate in wasm32 (CLI-UAL-66, Fable audit FR-4): tests/fndsa/wasm over ua-rs and the vectors it compiles in
    "ua-rs-fndsa-wasm": UARS + ["smartcontracts/vectors/"],
    "ua-cxx": ["clients/ua-cxx/", "smartcontracts/vectors/"] + UARS,
    "ua-c": ["clients/ua-c/", "smartcontracts/vectors/"] + UARS,
    "ua-qt": ["clients/ua-qt/", "smartcontracts/vectors/", "smartcontracts/near/", "smartcontracts/algorand/"] + UARS,
    # ua-py, ua-go, ua-cs load libscaas_ua_c (the wallet surface, MD-3): the job builds clients/ua-c first
    "ua-py": ["clients/ua-py/", "clients/ua-c/", "smartcontracts/vectors/"] + UARS,
    "ua-go": ["clients/ua-go/", "clients/ua-c/", "smartcontracts/vectors/", "smartcontracts/evm/"] + UARS,
    "ua-cs": ["clients/ua-cs/", "clients/ua-c/", "smartcontracts/vectors/"] + UARS,
    "ua-dart-frb": ["clients/ua-dart-frb/", "smartcontracts/vectors/"] + UARS,
    # every lockfile over ua-rs (cargo tree --locked); cargo deny and cargo audit of ua-rs, ua-c, zether-prover (clients/ua-rs/deny.toml)
    "ua-deps": [
        "clients/",
        "pqz-core/ffi/",
        "pqz-core/pqzl/",
        "pqz-core/stmt/",
        "pqz-core/pqzh/",
        "scaas-node/Cargo.toml",
        "scaas-node/Cargo.lock",
    ]
    + VENDOR
    + RT,
    "ua-dart": ["clients/ua-dart/", "smartcontracts/vectors/", "smartcontracts/evm/"],
    # the profile store over ua-rs (owner 2026-11-27): its own crate and the vectors it reads (profile/items.json)
    "scaas-profile": PROFILE + ["smartcontracts/vectors/"] + UARS,
    # the SDK (plan T20) and what it builds: ua-rs, scaas-rpc, zether-prover, pqz-core's crates, the vectors and gas tables it reads
    "scaas-sdk": [
        "clients/scaas-sdk/",
        "clients/scaas-rpc/",
        "clients/zether-prover/",
        "clients/scaas-ct/",
        "smartcontracts/vectors/",
    ]
    + PROFILE
    + UARS,
    "scaas-sdk-wasm": ["clients/scaas-sdk/", "clients/scaas-rpc/"] + PROFILE + UARS,
    # the CLI `scaas` (plan T22) over the SDK: what the SDK builds, and its own crate
    "scaas-cli": [
        "clients/scaas-cli/",
        "clients/scaas-sdk/",
        "clients/scaas-rpc/",
        "clients/zether-prover/",
        "clients/scaas-ct/",
        "smartcontracts/vectors/",
    ]
    + PROFILE
    + UARS,
    # PqVault's app core (plan V10) over the SDK: what the SDK builds, and its own crate
    "pqvault-core": [
        "clients/pqvault-core/",
        "clients/scaas-sdk/",
        "clients/scaas-rpc/",
        "clients/zether-prover/",
        "clients/scaas-ct/",
        "smartcontracts/vectors/",
    ]
    + PROFILE
    + UARS,
    # PqChat's app core (pqchat-core plan T2, CLI-PQC-01) over the SDK: the same inputs as pqvault-core's, and its own crate
    "pqchat-core": [
        "clients/pqchat-core/",
        "clients/scaas-sdk/",
        "clients/scaas-rpc/",
        "clients/zether-prover/",
        "clients/scaas-ct/",
        "smartcontracts/vectors/",
    ]
    + PROFILE
    + UARS,
    "keystore-vectors": ["clients/scaas-sdk/", "clients/clientkeys/", "smartcontracts/vectors/keystore/"]
    + PROFILE
    + UARS,
    # ARCH-POS-13 (ua-rs-sign T15c2): no test feature in a production artifact; every manifest that can reach scaas-ua,
    # zether-prover or pqz-ffi
    "test-features": ["clients/", "pqz-core/ffi/", "scaas-node/Cargo.toml", "scripts/check_test_features.py"]
    + VENDOR
    + RT,
}
# ci-full-<group>: the jobs a label or a manual run forces on; ci-full: every job.
GROUPS = {
    "ci-full-contracts": [j for j in JOBS if j.startswith("contract-")],
    "ci-full-node": ["node", "scaas-rpc"],
    "ci-full-clients": [
        "clientkeys",
        "zether-prover",
        "scaas-ct",
        "test-features",
        "keystore-vectors",
        "scaas-cli",
        "pqvault-core",
        "pqchat-core",
        "scaas-profile",
    ]
    + [j for j in JOBS if j.startswith("scaas-sdk")]
    + [j for j in JOBS if j.startswith("ua-")],
    "ci-full-pqz": ["pqz"],
    "ci-full": list(JOBS),
}


def changed():
    """The pull request's paths, or None: run everything."""
    if os.environ.get("EVENT") != "pull_request" or not os.environ.get("BASE"):
        return None
    r = subprocess.run(["git", "diff", "--name-only", os.environ["BASE"], "HEAD"], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    paths = [p for p in r.stdout.splitlines() if p]
    return None if any(p.startswith(".github/") for p in paths) else paths


# the runs/ files a CI test reads (found by grep of the tests for reads of runs/ paths, 2026-11-04), with the jobs reading them
RUNS_READ = {
    "smartcontracts/evm/runs/2026-10-27-metatx-split-node-floor.txt": [
        "node"
    ],  # guard.rs erc1271_floor_covers_forge_minimum
    # CLI-UPR-30: the ua-rs job's user-profile cell runs it (no signing symbol in the user-profile rlib)
    "clients/ua-rs/runs/2026-11-27-key-handles-nm.py": ["ua-rs"],
}


def read_by_tests(p):
    """False for a path no component test reads: Markdown, or anything under a `runs/` directory not in RUNS_READ."""
    if p.endswith(".md"):
        return False
    return not ("/runs/" in f"/{p}")


def needed(paths, forced=()):
    """paths None: every job. forced: group names (labels or the manual choice) ORed in. `docs` (prefix '') sees every
    path; the other jobs only the paths a test reads."""
    on = {j for g in forced for j in GROUPS.get(g, ())}
    code = None if paths is None else [p for p in paths if read_by_tests(p)]
    read = set() if paths is None else {j for p in paths for j in RUNS_READ.get(p, ())}
    return {
        job: paths is None
        or job in on
        or job in read
        or any(p.startswith(x) for p in (paths if job == "docs" else code) for x in prefixes)
        for job, prefixes in JOBS.items()
    }


# the bindings (plan T20, T20b-T20h): one matrix cell per language enabled in clients/scaas-sdk/bindings/langs (owner
# 2026-11-22, decisions CLI-SDK-33 (102)). A change under bindings/<lang>/ needs that language's cell only; a change to what
# every cell builds or reads (the SDK, ffi, lib.sh, the shared rows, the list itself, scaas-rpc, the vectors, ua-rs and its
# crates) and the generator under runs/ need every enabled cell; a language left out has no cell.
BINDINGS = "clients/scaas-sdk/bindings/"
BIND_SHARED = ["clients/scaas-sdk/", "clients/scaas-rpc/", "smartcontracts/vectors/"] + PROFILE + UARS
BIND_RUNS = ["clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh"]


def _langs_module():
    import importlib.util

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("langs", os.path.join(root, BINDINGS, "langs.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LANGS = _langs_module()


def bind_cells(paths, forced=(), langs=None):
    """The enabled languages (the list's order) whose cell the paths need; paths None or a ci-full / ci-full-clients group:
    every enabled one."""
    langs = LANGS.enabled(LANGS.FILE.read_text()) if langs is None else langs
    if paths is None or any(g in ("ci-full", "ci-full-clients") for g in forced):
        return list(langs)
    on = set()
    for p in paths:
        own = p[len(BINDINGS) :].split("/", 1) if p.startswith(BINDINGS) else []
        if p in BIND_RUNS:
            on |= set(langs)
        elif not read_by_tests(p):
            continue
        elif len(own) == 2 and own[0] in LANGS.KNOWN:  # a language's own directory
            on |= {own[0]} & set(langs)
        elif any(p.startswith(x) for x in BIND_SHARED):
            on |= set(langs)
    return [lang for lang in langs if lang in on]


def main():
    if os.environ.get("EVENT") == "workflow_dispatch":
        paths, forced = [""], [os.environ.get("FULL", "")]  # no diff: only `docs` (prefix '') and the chosen group
    else:
        paths, forced = changed(), json.loads(os.environ.get("LABELS") or "null") or []
    out = needed(paths, forced)
    cells = bind_cells(paths, forced)
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/stdout"), "a") as f:
        for job, run in out.items():
            f.write(f"{job.replace('-', '_')}={'true' if run else 'false'}\n")
        f.write(f"scaas_sdk_bind_langs={json.dumps(cells, separators=(',', ':'))}\n")
    print(" ".join(j for j, r in out.items() if r) or "no job", "| bindings:", " ".join(cells) or "none")


if __name__ == "__main__":
    assert all(needed(None).values())
    assert needed(["pqz-core/fuzz/run.sh"]) == {j: j in ("pqz", "docs") for j in JOBS}
    for p in (
        "pqz-core/ffi/src/x.rs",
        "pqz-core/stmt/src/x.rs",
        "pqz-core/pqzh/ligero/src/x.rs",
        "pqz-core/fuzz/run.sh",
    ):
        assert needed([p])["pqz"], p
    for p in (
        "pqz-core/nethermind/chain/patch-chainspec.py",
        "pqz-core/nethermind/Nethermind.Pqz/X.cs",
        "pqz-core/gate.sh",
        "pqz-core/artifact/results.py",
        "pqz-core/glic/absence.sh",
    ):
        assert not needed([p])["pqz"], p  # chain scripts, plugin, local gates: not read by the pqz job
    assert needed(["clients/ua-rs/src/lib.rs"])["ua-c"] and not needed(["clients/ua-py/x.py"])["pqz"]
    assert (
        needed(["smartcontracts/vectors/ua/nested.json"])["ua-py"] and needed(["smartcontracts/vectors/pqz/a"])["pqz"]
    )
    # each family: its own directory runs its job and no other family's; shared scripts and vectors run them all
    for fam, d in [
        ("evm", "evm"),
        ("soroban", "soroban"),
        ("solana", "solana"),
        ("near", "near"),
        ("algorand", "algorand"),
        ("aptos", "move/aptos"),
        ("sui", "move/sui"),
        ("cosmos", "cosmos"),
        ("ton", "ton"),
    ]:
        r = needed([f"smartcontracts/{d}/x"])
        assert [j for j in r if j.startswith("contract-") and r[j]] == [f"contract-{fam}"], fam
    assert all(needed(["pqz-core/params/sets/a"])[j] for j in ("contract-evm", "pqz"))
    for p in ("smartcontracts/scripts/test.sh", "smartcontracts/vectors/metatx/legacy/ua-mtx-merge/paymeta.json"):
        assert all(needed([p])[j] for j in GROUPS["ci-full-contracts"]), p
    # groups: a label on a docs-only pull request runs `docs` and that group, nothing else
    for g, js in GROUPS.items():
        assert needed(["docs/x.md"], [g]) == {j: j == "docs" or j in js for j in JOBS}, g
    assert set(GROUPS["ci-full-contracts"]) == {
        f"contract-{f}" for f in "evm soroban solana near algorand aptos sui cosmos ton".split()
    }
    assert set(GROUPS["ci-full-clients"]) == {
        "clientkeys",
        "zether-prover",
        "scaas-ct",
        "ua-rs",
        "ua-rs-fndsa-wasm",
        "ua-cxx",
        "ua-c",
        "ua-qt",
        "ua-py",
        "ua-go",
        "ua-cs",
        "ua-dart-frb",
        "ua-dart",
        "test-features",
        "ua-deps",
        "scaas-sdk",
        "scaas-sdk-wasm",
        "keystore-vectors",
        "scaas-cli",
        "pqvault-core",
        "pqchat-core",
        "scaas-profile",
    }
    # plan T20: the SDK's jobs; its generator under runs/ starts the bindings' drift check, other runs/ files nothing
    sdk = {j for j, r in needed(["clients/scaas-sdk/src/lib.rs"]).items() if r}
    assert sdk >= {
        "scaas-sdk",
        "scaas-sdk-wasm",
        "keystore-vectors",
        "scaas-cli",
        "pqvault-core",
        "pqchat-core",
    }, sdk
    assert not needed(["clients/scaas-sdk/runs/2026-11-17-scaas-sdk-summary.txt"])["scaas-sdk"]
    # owner 2026-11-27: the profile store starts its own job and every job over the SDK; the SDK alone does not start its job
    prof = {j for j, r in needed(["clients/scaas-profile/src/store.rs"]).items() if r}
    assert prof >= {"scaas-profile"} | sdk and not needed(["clients/scaas-sdk/src/lib.rs"])["scaas-profile"], prof
    assert bind_cells(["clients/scaas-profile/src/store.rs"]) == bind_cells(["clients/scaas-sdk/src/lib.rs"])
    assert needed(["smartcontracts/vectors/keystore/keystore.json"])["keystore-vectors"]
    assert all(needed(["docs/x.md"], ["ci-full"]).values())
    assert needed(["docs/x.md"], ["bug", "ci-full-node"]) == needed(
        ["docs/x.md"], ["ci-full-node"]
    )  # other labels ignored
    assert needed([""], ["ci-full-pqz"]) == {j: j in ("pqz", "docs") for j in JOBS}  # manual run
    # Markdown and everything under runs/ start only `docs`; code beside them still counts
    only_docs = {j: j == "docs" for j in JOBS}
    for p in (
        "scaas-node/runs/2026-11-01-x.txt",
        "smartcontracts/evm/runs/a/b.log",
        "pqz-core/sv/runs/g.jsonl",
        "pqz-core/README.md",
        "smartcontracts/evm/src/README.md",
        "runs/top.txt",
    ):
        assert needed([p]) == only_docs, p
    for p in (
        "smartcontracts/evm/runs/2026-11-04-gov-smoke-7622.sh",
        "pqz-core/ffi/vectors/runs/probe/kat.json",
        "pqz-core/nethermind/runs/2026-11-04-mldsa87-probe.py",
        "smartcontracts/evm/runs/x/Probe.t.sol",
    ):
        assert needed([p]) == only_docs, p  # one-off scripts and probe data under runs/
    for p, js in RUNS_READ.items():  # a runs/ file a test reads starts exactly its readers (and docs)
        assert needed([p]) == {j: j == "docs" or j in js for j in JOBS}, p
    assert {j for j, r in needed(["rust-toolchain.toml"]).items() if r} == {
        "docs",
        "contract-soroban",
        "contract-solana",
        "contract-near",
        "contract-cosmos",
        "node",
        "pqz",
        "zether-prover",
        "scaas-ct",
        "ua-rs",
        "ua-rs-fndsa-wasm",
        "ua-cxx",
        "ua-c",
        "ua-qt",
        "ua-dart-frb",
        "test-features",
        "ua-py",
        "ua-go",
        "ua-cs",
        "ua-deps",
        "scaas-rpc",
        "scaas-sdk",
        "scaas-sdk-wasm",
        "keystore-vectors",
        "scaas-cli",
        "pqvault-core",
        "pqchat-core",
        "scaas-profile",
    }
    # the network crate: its own job and the node's (the node builds it); ua-rs (its depth scan) runs it too
    assert {j for j, r in needed(["clients/scaas-rpc/src/evm.rs"]).items() if r} >= {"scaas-rpc", "node"}
    assert needed(["clients/ua-rs/src/json.rs"])["scaas-rpc"] and not needed(["scaas-node/src/chain.rs"])["scaas-rpc"]
    # ua-rs-sign T18: every job over ua-rs reads the crates ua-rs builds; the bindings over libscaas_ua_c read ua-c and ua-rs
    over = ["ua-rs", "ua-c", "ua-cxx", "ua-qt", "ua-dart-frb", "ua-py", "ua-go", "ua-cs"]
    for p in (
        "pqz-core/ffi/src/lib.rs",
        "pqz-core/pqzl/rust/src/lib.rs",
        "pqz-core/pqzl/x.c",
        "pqz-core/stmt/src/lib.rs",
        "pqz-core/pqzh/ligero/src/x.rs",
        "pqz-core/params/sets/a",
        "clients/zether-prover/src/api.rs",
        "clients/scaas-ct/src/lib.rs",
    ):
        assert all(needed([p])[j] for j in over), p
    for p in ("clients/ua-rs/src/lib.rs", "clients/ua-c/src/lib.rs"):
        assert all(needed([p])[j] for j in ("ua-py", "ua-go", "ua-cs", "ua-deps")), p
    assert not any(needed(["pqz-core/fuzz/run.sh"])[j] for j in over)  # a directory only the pqz job reads
    assert needed(["clients/scaas-ct/src/lib.rs"])["zether-prover"] and needed(["scaas-node/Cargo.lock"])["ua-deps"]
    assert {j for j, r in needed(["clients/scaas-ct/src/lib.rs"]).items() if r} >= {
        "scaas-ct",
        "ua-rs",
        "zether-prover",
    }
    assert not needed(["clients/ua-rs/src/lib.rs"])["scaas-ct"]  # its own directory only
    # FR-4: the wasm32 Falcon gate runs on ua-rs, vendor/ and the vectors, not on another family's contracts
    for p in (
        "clients/ua-rs/src/falcon/soft.rs",
        "vendor/falcon-rs-0.3.1/src/sign.rs",
        "smartcontracts/vectors/ua/pq_kat.json",
    ):
        assert needed([p])["ua-rs-fndsa-wasm"], p
    assert not needed(["smartcontracts/evm/src/x.sol"])["ua-rs-fndsa-wasm"]
    # ARCH-POS-24, TODO 8b-9 (4b): a pin change in vendor.sh reaches the jobs that build over the forge libraries and the
    # pqz job, which installs and checks the kat and research groups
    assert all(needed(["scripts/vendor.sh"])[j] for j in ("contract-evm", "zether-prover", "clientkeys", "pqz", "node"))
    assert not needed(["scaas-node/src/main.rs"])["ua-deps"] and not needed(["clients/ua-py/x.py"])["ua-c"]
    assert needed(["smartcontracts/evm/foundry.txt"])["contract-evm"]  # a .txt outside runs/ counts
    assert needed(["scaas-node/runs/a.txt", "scaas-node/src/x.rs"])["node"]
    assert needed(["smartcontracts/evm/runs/a.txt"], ["ci-full-contracts"])["contract-evm"]  # a label still forces
    # the bindings' cells (decisions CLI-SDK-33 (102)): the committed list enables all nine; a language's own directory needs
    # its cell only, what every cell builds needs them all, a left-out language none; an unknown or repeated name is refused
    nine = ["cpp", "cs", "python", "kotlin", "swift", "java", "go", "dart", "js"]
    assert LANGS.enabled(LANGS.FILE.read_text()) == nine and list(LANGS.KNOWN) == nine
    assert bind_cells(None) == nine and bind_cells(["docs/x.md"], ["ci-full-clients"]) == nine
    assert bind_cells(["clients/scaas-sdk/bindings/go/smoke/smoke_test.go"]) == ["go"]
    assert bind_cells(["clients/scaas-sdk/bindings/js/test/smoke.test.mjs", "clients/scaas-sdk/bindings/cs/X.cs"]) == [
        "cs",
        "js",
    ]
    for p in (
        "clients/scaas-sdk/src/lib.rs",
        "clients/scaas-sdk/ffi/src/lib.rs",
        "clients/scaas-sdk/bindings/lib.sh",
        "clients/scaas-sdk/bindings/rows.py",
        "clients/scaas-sdk/bindings/langs",
        "clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh",
        "clients/ua-rs/src/lib.rs",
        "smartcontracts/vectors/keystore/keystore.json",
    ):
        assert bind_cells([p]) == nine, p
    for p in ("clients/scaas-sdk/runs/2026-11-17-scaas-sdk-summary.txt", "docs/x.md", "scaas-node/src/main.rs"):
        assert bind_cells([p]) == [], p
    some = ["cpp", "python", "js"]
    assert bind_cells(["clients/scaas-sdk/bindings/go/x.go"], langs=some) == [], "a left-out language has no cell"
    assert bind_cells(["clients/scaas-sdk/src/lib.rs"], langs=some) == some
    assert bind_cells([""], ["ci-full-pqz"]) == []  # a manual run of another group
    for bad in ("cpp\nrust\n", "go\ngo\n"):
        try:
            LANGS.enabled(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    assert LANGS.enabled("# all off\n") == [] and LANGS.enabled("cpp # the C++ one\njs\n") == ["cpp", "js"]
    main()
