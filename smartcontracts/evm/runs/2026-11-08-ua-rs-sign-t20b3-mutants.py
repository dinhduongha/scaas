#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20b (owner 2026-11-08): the reference readers check `--registry` against the token's `ChainEnv`. Each mutant undoes
one rule (the clone's layout in `ua-rs` `factory::clone_env` and in `zether-read-balance`'s `clone_registry`, the refusal of a
non-clone, the registry comparison) and names the test that must catch it. One mutant per run on a clean tree, its command,
every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that
does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1). The reading-layer tests
run against a local anvil (`ANVIL`, default ~/.foundry/bin/anvil; killed by the tests).
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b3-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b3-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b3-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, ZP = "clients/ua-rs/", "clients/zether-prover/"
B, F, ZB = R + "src/bin/pqz-read.rs", R + "src/factory.rs", ZP + "src/bin/zether-read-balance.rs"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL,
       "PATH": os.path.dirname(ANVIL) + os.pathsep + os.environ.get("PATH", "")}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
PR = (R, CT + ["--test", "pqz_read", "--", "--include-ignored"])
RB = (ZP, CT + ["--test", "read_balance", "--", "--include-ignored"])
FT = (R, CT + ["--test", "factory", "chain_env_kat_rows"])
ZK = (ZP, CT + ["--bin", "zether-read-balance", "clone_registry_is_the_kat_layout"])

M = [
    # pqz-read
    ("pqz-read: --registry not compared with the env's", [(B, "    if env.registry != a.registry {", "    if false {")], PR),
    ("pqz-read: a token without an env accepted", [(B, """    let Some((_, env)) = scaas_ua::factory::clone_env(&r.code(&a.token)?) else {
        return Err("R5: the token is not a clone of a chain-neutral release".into());
    };
    if env.registry != a.registry {""", """    let env = scaas_ua::factory::clone_env(&r.code(&a.token)?).map(|e| e.1);
    if env.is_some_and(|env| env.registry != a.registry) {""")], PR),
    # ua-rs factory::clone_env
    ("clone_env: the proxy head unchecked", [(F, "    (take(&mut at, 10)? == PROXY_HEAD).then_some(())?;", "    take(&mut at, 10)?;")], FT),
    ("clone_env: bytes after the env accepted", [(F, "    (at == runtime.len()).then_some(())?;\n", "")], FT),
    ("clone_env: hedera any byte", [(F, "        [1] => true,\n        _ => return None,", "        _ => true,")], FT),
    ("clone_env: more than 4 deps", [(F, "    (n_deps <= MAX_DEPS).then_some(())?;\n", "")], FT),
    # zether-read-balance
    ("zether-read-balance: --registry not compared with the env's", [(ZB, "        if unhex(reg)? != env_registry {", "        if false {")], RB),
    ("zether-read-balance: a token without an env accepted",
     [(ZB, 'let env_registry = clone_registry(&r.code(&t)?).ok_or("R5: the token is not a clone of a chain-neutral release")?;',
       "let env_registry = clone_registry(&r.code(&t)?).unwrap_or_default();")], RB),
    ("clone_registry: bytes after the env accepted", [(ZB, "code.len() == at + 1 + 32 * params", "code.len() >= at + 1 + 32 * params")], ZK),
    ("clone_registry: the proxy tail unchecked", [(ZB, "code.get(..10)? == HEAD && code.get(30..45)? == TAIL && ", "code.get(..10)? == HEAD && ")], ZK),
]

if sys.argv[1:] == ["count"]:
    print(len(M))
    raise SystemExit(0)
if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, f, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)

NOT_BUILT = re.compile(r"^error(\[E\d+\])?: could not compile", re.M)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, (cwd, cmd)) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env={**os.environ, **ENV})
        rc, out = r.returncode, r.stdout + r.stderr
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M) + re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)
                        + re.findall(r"^✖ (.+?) \(", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
