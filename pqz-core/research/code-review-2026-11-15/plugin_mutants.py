#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plugin fault-boundary mutants (review 3w-delta U3h-2 + the exit watchdog): each applied alone, the ML-DSA tests run
# through run-tests.sh (PQZ_TEST_FILTER), the source restored.
# usage (from the repo root, under scripts/capped): python3 -I <this> pqz-core/nethermind <log>
import os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
log = pathlib.Path(sys.argv[2])
P, M = "Nethermind.Pqz/PqzPrecompile.cs", "Nethermind.Pqz/MlDsaPrecompile.cs"
OLD_FAULT_BODY = """        string cause = e is null ? $"status={status}" : $"{where}{e.GetType().Name}: {e.Message}";
        string msg = $"PQZ-NODE-FAULT {cause} keccak={Keccak.Compute(input)} len={input.Length}: a fault of this node, not of the input; exit 120";
        Console.Error.WriteLine(msg);
        Console.Error.Flush();
        if (Log.IsError) Log.Error(msg);
        Terminate();
    }

    /// <summary>The exit watchdog's bound"""
MUT = [
 ("W1 watchdog thread not started", P, "            w.Start();", "            _ = w;"),
 ("F1 NodeFault without its boundary (the pre-fix order: diagnostic, then exit)", P,
  None, None),
 ("C1 the zero word's warning unguarded", M,
  """        try
        {
            if (PqzPrecompile.Log.IsWarn) PqzPrecompile.Log.Warn($"MLDSA-CRYPTO-EXCEPTION {alg.Name} len={len}: {e.Message}: …00");
        }
        catch
        {
            // the word is the zero word regardless
        }""",
  """        if (PqzPrecompile.Log.IsWarn) PqzPrecompile.Log.Warn($"MLDSA-CRYPTO-EXCEPTION {alg.Name} len={len}: {e.Message}: …00");"""),
]
out = []
env = dict(os.environ, PQZ_TEST_FILTER="FullyQualifiedName~MlDsaTests")
for name, f, a, b in MUT:
    p = root / f
    src = p.read_text()
    if a is None:  # F1: replace Fault's body from its try to the watchdog's summary
        i, j = src.index("        try\n        {\n            string cause"), src.index("    /// <summary>The exit watchdog's bound")
        mut = src[:i] + OLD_FAULT_BODY + src[j + len("    /// <summary>The exit watchdog's bound"):]
    else:
        assert src.count(a) == 1, name
        mut = src.replace(a, b)
    p.write_text(mut)
    try:
        r = subprocess.run(["sh", str(root / "run-tests.sh")], env=env, capture_output=True, text=True)
    finally:
        p.write_text(src)
        subprocess.run(["dotnet", "build-server", "shutdown"], capture_output=True)
    txt = r.stdout + r.stderr
    with log.open("a") as fh:
        fh.write(f"===== {name}\n{txt}\n")
    failed = [l.strip() for l in txt.splitlines() if l.strip().startswith(("Failed:", "Passed:", "Total tests"))]
    red = r.returncode != 0 or any(l.startswith("Failed:") and l.split()[1] != "0" for l in failed)
    print(f"{name}: {'RED' if red else 'GREEN (mutant survived)'}; {failed}", flush=True)
    out.append(red)
print(f"mutants red: {sum(out)}/{len(out)}")
sys.exit(0 if all(out) else 1)
