# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Fable review fixes C-1..C-6 (ua-mtx-fix-verifier): one mutant at a time on a clean tree, applied to its file, the test
suite run through scripts/capped, the file restored in the same run, then `git diff --exit-code`. Every new check has a
mutant that must be killed: the locally built digest, the registry pin, the chainUid pin, the chain id at start, the probe's
mode and verifier, the proposal probe's gate and its constant statement; then C-2's blob tail, C-3's failover, C-4's body-before-slot, C-5's bound, and one mutant through the
opt-in anvil run (PATH must hold anvil and forge). Writes `mutant | tests that went red | rc` to the -mutants.txt beside
this file; full outputs to git-ignored .log files. Run from scaas-pqz-verifier/:
python3 runs/2026-11-11-ua-mtx-fix-verifier-mutants.py"""
import os
import re
import subprocess
import sys

OUT = "runs/2026-11-11-ua-mtx-fix-verifier-mutants.txt"
CAPPED = ["../scripts/capped", "cargo", "test", "--offline", "--locked", "-j2"]
ALL = CAPPED
ANVIL = CAPPED + ["--test", "anvil", "--", "--ignored"]
RPC_DIGEST = """let auth = {
            alloy::sol! { function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32); }
            let c = uaAuthDigestCall { ua: self.ua, purposeTag: purpose_pqz_verdict(), digest: verdict_digest(&v, self.chain_uid) };
            self.read(At { node: 0, block: 0 }, self.registry, c).await?
        };"""
MUTANTS = [
    ("C-1 local digest: sign the registry's uaAuthDigest answer", "src/lib.rs",
     "let auth = verdict_auth_digest(&self.registry_domain, self.ua, verdict_digest(&v, self.chain_uid));", RPC_DIGEST, ALL),
    ("C-1 local digest: another registry generation in the domain", "src/lib.rs",
     "registry_domain: registry_domain(cfg.registry_generation,", "registry_domain: registry_domain(cfg.registry_generation + 1,", ALL),
    ("C-1 registry pin skipped", "src/lib.rs", "if registry != self.registry {", "if false && registry != self.registry {", ALL),
    ("C-1 chainUid pin skipped", "src/lib.rs", "if chain_uid != self.chain_uid {", "if false && chain_uid != self.chain_uid {", ALL),
    ("C-6 chain id at start not compared", "src/chain.rs", "anyhow::ensure!(id == chain_id,", "anyhow::ensure!(id == id,", ALL),
    ("C-1 probe: the mode unchecked (verdict keeps it)", "src/lib.rs",
     "            let cfg = self.offchain(at, &t).await?;\n            if !proposal",
     "            let cfg = self.read(at, t.at, IPqzToken::pqzVerifyConfigCall {}).await?;\n            if !proposal", ALL),
    ("probe: the proposal gate ignored (any verifier without proposal)", "src/lib.rs",
     "if !proposal && cfg.verifier != self.ua {", "if false && !proposal && cfg.verifier != self.ua {", ALL),
    ("probe: the probe statement as long as a statement header", "src/lib.rs",
     'pub const PROBE_STATEMENT: &[u8] = b"SCAAS-PQZ-VERIFIER-PROBE-V1";', "pub const PROBE_STATEMENT: &[u8] = &[0u8; 640];", ALL),
    ("C-1 served: OFFCHAIN mode unchecked", "src/lib.rs", "if cfg.pqzVerifyMode != OFFCHAIN {",
     "if false && cfg.pqzVerifyMode != OFFCHAIN {", ALL),
    ("C-1 served: this verifier unchecked", "src/lib.rs", "if cfg.verifier != self.ua {", "if false && cfg.verifier != self.ua {", ALL),
    ("C-2 blob tail not stripped", "src/lib.rs", "checked_sub(tail + vp)", "checked_sub(vp + 0 * tail)", ALL),
    ("C-3 no failover (node 0 only)", "src/lib.rs", "for node in 0..self.chain.nodes() {", "for node in 0..1 {", ALL),
    ("C-4 queue place before the body", "src/http.rs",
     "    let req = decode(b).await?;\n    let _slot = app.slot()?;\n    Ok(Json(app.svc.probe(req).await?))",
     "    let _slot = app.slot()?;\n    let req = decode(b).await?;\n    Ok(Json(app.svc.probe(req).await?))", ALL),
    ("C-5 ownership record unbounded", "src/lib.rs", "&& self.owner.len() >= OWNER_MAX {", "&& self.owner.len() >= usize::MAX {", ALL),
    ("C-1 on anvil: another registry generation in the domain", "src/lib.rs",
     "registry_domain: registry_domain(cfg.registry_generation,", "registry_domain: registry_domain(cfg.registry_generation + 1,",
     ANVIL),
]


def main():
    if subprocess.run(["git", "diff", "--quiet", "--exit-code", "--", "src", "tests"]).returncode:
        sys.exit("the crate is not clean")
    only = set(sys.argv[1:])
    rows = []
    for i, (name, path, old, new, cmd) in enumerate(MUTANTS, 1):
        if only and str(i) not in only:
            continue
        orig = open(path).read()
        assert orig.count(old) == 1, name
        log = f"runs/2026-11-11-ua-mtx-fix-verifier-mutant-{i}.log"
        print(f"mutant {i}/{len(MUTANTS)}: {name}: start", flush=True)
        try:
            open(path, "w").write(orig.replace(old, new))
            with open(log, "w") as f:
                rc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env={**os.environ, "CAPPED_SLOTS": "3"}).returncode
        finally:
            open(path, "w").write(orig)
        assert subprocess.run(["git", "diff", "--exit-code", "--", "src", "tests"]).returncode == 0, f"{name}: not restored"
        text = open(log).read()
        red = re.findall(r"^test (\S+) \.\.\. FAILED$", text, re.M)
        built = "error[" not in text and "could not compile" not in text
        verdict = ", ".join(red) if red else ("NONE (survivor)" if built else "DID NOT COMPILE")
        rows.append(f"{name} | {verdict} | {rc}")
        print(rows[-1], flush=True)
    with open(OUT, "w") as f:
        f.write("mutant | tests that went red | rc\n" + "\n".join(rows) + "\n")


main()
