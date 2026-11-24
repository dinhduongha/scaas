#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plugin fault-boundary mutants (review 3w-delta U3h-2 + the exit watchdog): each applied alone, the ML-DSA tests and
# the PQZ-seam children run
# through run-tests.sh (PQZ_TEST_FILTER), the source restored.
# usage (from the repo root, under scripts/capped): python3 -I <this> pqz-core/nethermind <log>
# A hung run (owner 2026-11-24, scripts/mutant_guard.py): past 3 x its unmutated baseline (at least 10 min, or `--timeout N`)
# its process group is killed and it reads `killed (timeout N s)`; the source is restored on every exit (SIGINT / SIGTERM
# too); a target file that differs from HEAD refuses the run.
import os, pathlib, subprocess, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
import mutant_guard as guard  # noqa: E402

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

    /// <summary>The exit watchdog's default bound (ms)."""
MUT = [
    ("W1 watchdog thread not started", P, "            w.Start();", "            _ = w;"),
    ("F1 NodeFault without its boundary (the pre-fix order: diagnostic, then exit)", P, None, None),
    (
        "C1 the zero word's warning unguarded",
        M,
        """        try
        {
            if (PqzPrecompile.Log.IsWarn) PqzPrecompile.Log.Warn($"MLDSA-CRYPTO-EXCEPTION {alg.Name} len={len}: {e.Message}: …00");
        }
        catch
        {
            // the word is the zero word regardless
        }""",
        """        if (PqzPrecompile.Log.IsWarn) PqzPrecompile.Log.Warn($"MLDSA-CRYPTO-EXCEPTION {alg.Name} len={len}: {e.Message}: …00");""",
    ),
    (
        "P1 PqzPrecompile.Run without its catch",
        P,
        """        try
        {
            return RunUnguarded(input, s, call);
        }
        catch (Exception e) when (e is not DllNotFoundException)
        {
            NodeFault("", e, input); // the cause is built inside the fault boundary (review 3w-delta U3h-2)
            throw; // not reached (NodeFault exits)
        }""",
        """        return RunUnguarded(input, s, call);""",
    ),
    (
        "F1b the watchdog started after the diagnostic (F-1)",
        P,
        [
            """    {
        StartWatchdog();
        try
        {
            string cause""",
            """        finally
        {
            ExitNow();""",
        ],
        [
            """    {
        try
        {
            string cause""",
            """        finally
        {
            StartWatchdog();
            ExitNow();""",
        ],
    ),
    (
        "F6 the input-panic warning unguarded (F-6)",
        P,
        [
            """        try
        {
            if (Log.IsWarn) Log.Warn($"PQZ-INPUT-PANIC""",
            """        catch
        {
            // the word is …00 regardless
        }""",
        ],
        [
            """        {
            if (Log.IsWarn) Log.Warn($"PQZ-INPUT-PANIC""",
            "",
        ],
    ),
]
out = []
env = dict(
    os.environ,
    PQZ_TEST_FILTER="FullyQualifiedName~MlDsaTests|FullyQualifiedName~A_failing_diagnostic_on_the_pqz_path|FullyQualifiedName~An_input_panic_with",
)
sel = sys.argv[3].split(",") if len(sys.argv) > 3 else None
guard.refuse_dirty([root / m[1] for m in MUT], root)
for name, f, a, b in MUT:
    if sel and name.split()[0] not in sel:
        continue
    p = root / f
    src = p.read_text()
    if a is None:  # F1: replace Fault's body from its try to the watchdog's summary
        i, j = (
            src.index("        try\n        {\n            string cause"),
            src.index("    /// <summary>The exit watchdog's default bound (ms)."),
        )
        mut = src[:i] + OLD_FAULT_BODY + src[j + len("    /// <summary>The exit watchdog's default bound (ms).") :]
    else:
        mut = src
        for x, y in zip(a, b) if isinstance(a, list) else [(a, b)]:
            assert mut.count(x) == 1, name
            mut = mut.replace(x, y)
    cmd = ["sh", str(root / "run-tests.sh")]
    lim, saved = guard.limit(cmd, env=env), {p: p.read_bytes()}
    try:
        p.write_text(mut)
        r = guard.run(cmd, lim, env=env, capture_output=True, text=True)
    finally:
        guard.restore(saved)
        subprocess.run(["dotnet", "build-server", "shutdown"], capture_output=True)
    txt = r.stdout + r.stderr
    with log.open("a") as fh:
        fh.write(f"===== {name}\n{txt}\n")
    failed = [l.strip() for l in txt.splitlines() if l.strip().startswith(("Failed:", "Passed:", "Total tests"))]
    built = any(l.startswith("Total tests") for l in failed)
    red = (
        bool(r.timeout)
        or built
        and (r.returncode != 0 or any(l.startswith("Failed:") and l.split()[1] != "0" for l in failed))
    )
    print(
        f"{name}: {guard.outcome(r, 'RED') if red else 'GREEN (mutant survived)' if built else 'INVALID (no test ran: build failed?)'}; {failed}",
        flush=True,
    )
    out.append(red)
print(f"mutants red: {sum(out)}/{len(out)}")
sys.exit(0 if all(out) else 1)
