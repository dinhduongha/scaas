# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan V8: the node's PqVault rows and rules, each mutant one literal replacement (exactly one match) in scaas-node/src,
then `cargo test --lib` filtered to the PqVault and PqChat tests (through scripts/capped), the file restored; killed when the run
fails. One line per mutant; logs in runs/2026-11-21-pqvault/node-mutants/<name>.log (git-ignored). From the repository root:
  python3 smartcontracts/evm/runs/2026-11-21-pqvault/node_mutants.py [name ...]
"""
import os
import subprocess
import sys

G = "scaas-node/src/guard.rs"
T = "scaas-node/src/typed.rs"
M = [
    ("rule-pqvault-class-3", G, '"pqvault" => Rule::FactoryClass(CLASS_PQVAULT),', '"pqvault" => Rule::FactoryClass(CLASS_PQCHAT),'),
    ("relay-inner-pqchat-only", G, 'const FACTORY_KINDS: [(&str, &str); 2] = [("pqchat", "PqChat"), ("pqvault", "PqVault")];',
     'const FACTORY_KINDS: [(&str, &str); 2] = [("pqchat", "PqChat"), ("pqchat", "PqVault")];'),
    ("unsigned-pqvault-open", G, '"pqvault" => Some((self.relay_unsigned_pqvault, "relay_unsigned_pqvault")),',
     '"pqvault" => Some((true, "relay_unsigned_pqvault")),'),
    ("unsigned-pqvault-pqchat-param", G, '"pqvault" => Some((self.relay_unsigned_pqvault, "relay_unsigned_pqvault")),',
     '"pqvault" => Some((self.relay_unsigned_pqchat, "relay_unsigned_pqvault")),'),
    ("hex-args-pqchat-only", T, 'if contract == "pqchat" || contract == "pqvault" {', 'if contract == "pqchat" {'),
    ("config-class-4-unknown", T, "(3, 0) | (4, 0) => {", "(3, 0) => {"),
    ("row-createItems-dropped", T, '    ("createItems", PV, "PqVaultBatch b,UASig sig"),\n', ""),
]


def run(name, path, old, new):
    src = open(path).read()
    if src.count(old) != 1:
        return f"{name} | {path} | NOT APPLIED ({src.count(old)} matches)"
    os.makedirs("smartcontracts/evm/runs/2026-11-21-pqvault/node-mutants", exist_ok=True)
    log = f"smartcontracts/evm/runs/2026-11-21-pqvault/node-mutants/{name}.log"
    try:
        open(path, "w").write(src.replace(old, new))
        with open(log, "w") as f:
            r = subprocess.run(["../scripts/capped", "cargo", "test", "-j", "2", "--lib", "--", "pqvault", "pqchat",
                                "instance_rows", "a_pqvault"], cwd="scaas-node", stdout=f, stderr=subprocess.STDOUT)
    finally:
        open(path, "w").write(src)
    t = open(log, errors="replace").read()
    fails = sorted({l.split()[1] for l in t.splitlines() if l.startswith("test ") and l.endswith("FAILED")})
    if r.returncode != 0 and not fails:
        fails = ["(build)"]
    return f"{name} | {path} | {'KILLED' if r.returncode != 0 else 'SURVIVED'} | {', '.join(fails[:6])}"


if __name__ == "__main__":
    want = sys.argv[1:]
    for m in M:
        if not want or m[0] in want:
            print(run(*m), flush=True)
