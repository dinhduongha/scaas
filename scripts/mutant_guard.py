# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The mutant runners' guard (owner 2026-11-24): a hung mutant blocks nothing and corrupts nothing. The shared runners
(clients/scaas-sdk/runs/mutants_lib.py, clients/scaas-rpc/runs/mutants_lib.py, runs/mutants_lib.py, the ua-rs-native and
bls-multi `mutants-run.py`, smartcontracts/evm/script/wraplimit/mutants.py) and the standalone ones still run use it:
  refuse_dirty(files, root)  before the first mutant: a target file that differs from HEAD is a leftover mutation of a run
                             that died; the run refuses to start (rc 2) and names the file
  run(cmd, deadline, **kw)   subprocess.run's call, the command in its own session (process group); at the deadline, or on
                             any exception (SIGINT, SIGTERM and SIGHUP raise), the whole group is killed (capped, cargo and
                             node children too), and any child left after a normal exit; the result carries `seconds` and
                             `timeout` (the deadline in s when it passed, else None)
  deadline(base)             the per-mutant deadline in s: `--timeout N` from the command line, else 3 x the measured
                             baseline `base`, at least 10 min
  limit(cmd, **kw)           a runner without its own baseline: `cmd` run once on the unmutated tree per (cmd, cwd, env),
                             required green (else rc 2), and its deadline; call it before the mutation is written
  restore(saved)             every mutated file written back with the signals held off, then checked byte for byte; a file
                             that does not come back stops the whole run loudly (rc 3)
  outcome(r, text), counted  a hang's outcome is `killed (timeout N s)`: the test did not pass, so it counts as killed
Importing it takes `--timeout N` out of sys.argv and makes SIGTERM and SIGHUP raise SystemExit (SIGINT already raises), so a
runner's `finally` restores on every way out. A shell runner uses the command line:
  python3 -I scripts/mutant_guard.py time -- CMD...         the baseline: CMD once (output dropped), its seconds on stdout,
                                                            CMD's rc
  python3 -I scripts/mutant_guard.py exec SECONDS -- CMD... CMD under the deadline of a SECONDS baseline, its rc; at the
                                                            deadline rc 124 and `killed (timeout N s)` on stderr
Self-check: python3 -I scripts/mutant_guard.py --self-test"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

FACTOR, FLOOR = 3, 600
SIGS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def _pop_timeout(argv):
    if "--timeout" not in argv:
        return None
    i = argv.index("--timeout")
    if i + 1 >= len(argv) or not argv[i + 1].isdigit() or int(argv[i + 1]) <= 0:
        raise SystemExit("[mutants] --timeout takes whole seconds > 0")
    v = int(argv[i + 1])
    del argv[i : i + 2]
    return v


TIMEOUT = _pop_timeout(sys.argv)


def _raise(signum, _frame):
    raise SystemExit(128 + signum)


for _s in (signal.SIGTERM, signal.SIGHUP):
    # an ignored signal (nohup) stays ignored
    if signal.getsignal(_s) is signal.SIG_DFL:
        signal.signal(_s, _raise)


def deadline(base):
    if TIMEOUT:
        return TIMEOUT
    return None if base is None else max(FLOOR, int(FACTOR * base + 0.999))


_BASE = {}


def limit(cmd, **kw):
    env = kw.get("env") or {}
    key = (repr(cmd), str(kw.get("cwd")), tuple(sorted((k, v) for k, v in env.items() if os.environ.get(k) != v)))
    if key not in _BASE:
        print(f"[mutants] baseline (unmutated): {cmd}", flush=True)
        b = run(cmd, TIMEOUT, **{**kw, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL})
        if b.returncode != 0:
            print(f"[mutants] refused: the baseline is red (rc={b.returncode}): {cmd}", flush=True)
            raise SystemExit(2)
        _BASE[key] = b.seconds
    return deadline(_BASE[key])


def refuse_dirty(files, root):
    bad = [
        f
        for f in dict.fromkeys(str(f) for f in files)
        if subprocess.run(["git", "-C", str(root), "diff", "--quiet", "HEAD", "--", f]).returncode != 0
    ]
    for f in bad:
        print(f"[mutants] refused: {f} differs from HEAD (a leftover mutation: a run died); restore it, then run again")
    if bad:
        raise SystemExit(2)


def _killpg(pid, sig):
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _kill(p):
    # a second Ctrl-C does not cut the kill short; a pending signal raises after it
    old = signal.pthread_sigmask(signal.SIG_BLOCK, SIGS)
    try:
        _killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            pass
        _killpg(p.pid, signal.SIGKILL)
        p.wait()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def run(cmd, deadline=None, **kw):
    if kw.pop("capture_output", False):
        kw["stdout"] = kw["stderr"] = subprocess.PIPE
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, start_new_session=True, **kw)
    hit = None
    try:
        out, err = p.communicate(timeout=deadline)
    except subprocess.TimeoutExpired:
        hit = deadline
        _kill(p)
        try:
            out, err = p.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # a child that left the group holds the pipe: give up its output
            out = err = "" if kw.get("text") else b""
    except BaseException:
        _kill(p)
        raise
    # a child the test left behind (an anvil, a cargo job) goes with its group
    _killpg(p.pid, signal.SIGKILL)
    r = subprocess.CompletedProcess(cmd, p.returncode, out, err)
    r.seconds, r.timeout, r.pid = time.monotonic() - t0, hit, p.pid
    return r


def restore(saved):
    old = signal.pthread_sigmask(signal.SIG_BLOCK, SIGS)
    try:
        for f, b in saved.items():
            Path(f).write_bytes(b)
    finally:
        bad = [f for f, b in saved.items() if not Path(f).is_file() or Path(f).read_bytes() != b]
        if bad:
            print(
                f"[mutants] FATAL: not restored: {', '.join(map(str, bad))}; the run stops", file=sys.stderr, flush=True
            )
            raise SystemExit(3)
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def outcome(r, text):
    return f"killed (timeout {r.timeout} s)" if r.timeout else text


def counted(text):
    """The summary's bucket of a row's outcome: a timeout counts inside `killed`."""
    return "killed" if text.startswith("killed (") else text


def _scenario(name, d):
    """One case of the self-test, in its own process: the test command writes its group's id to `pid`."""
    f = Path(d) / "a.txt"
    saved = {f: f.read_bytes()}
    f.write_bytes(b"mutated\n")
    try:
        r = run(
            f"echo $$ > {d}/pid; sleep 1000 & sleep 1000; wait", shell=True, deadline=2 if name == "timeout" else None
        )
    finally:
        restore(saved)
    print(outcome(r, "survived"), flush=True)


def _self_test():
    import contextlib
    import io
    import shutil
    import tempfile

    assert deadline(17) == 600 and deadline(300) == 900 and deadline(None) is None
    assert counted("killed (timeout 600 s)") == "killed" and counted("survived") == "survived"
    assert _pop_timeout(["x", "--timeout", "5", "run"]) == 5 and _pop_timeout(["x", "run"]) is None
    with contextlib.redirect_stdout(io.StringIO()):
        assert limit("true", shell=True) == FLOOR
        try:
            limit("false", shell=True)
            raise AssertionError("a red baseline taken")
        except SystemExit as e:
            assert e.code == 2
    ok = True

    def line(good, text):
        nonlocal ok
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {text}", flush=True)

    def alive(pid, kill):
        try:
            kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    for name in ("timeout", "sigterm"):
        d = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q", d], check=True)
        (Path(d) / "a.txt").write_text("original\n")
        subprocess.run(["git", "-C", d, "add", "a.txt"], check=True)
        subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "t"], check=True)
        args = [sys.executable, "-I", __file__, "--scenario", name, d]
        p = subprocess.Popen(args, stdout=subprocess.PIPE, text=True, start_new_session=True)
        t0 = time.monotonic()
        if name == "sigterm":
            while not (Path(d) / "pid").exists() and time.monotonic() - t0 < 10:
                time.sleep(0.1)
            time.sleep(0.5)
            p.send_signal(signal.SIGTERM)
        try:
            out, _ = p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            out = "(no end in 20 s)"
        took = time.monotonic() - t0
        restored = (Path(d) / "a.txt").read_text() == "original\n"
        pid = int((Path(d) / "pid").read_text())
        left = alive(pid, os.kill) or alive(pid, os.killpg)
        # the self-test leaves nothing either: the runner's group, then the test's
        _killpg(p.pid, signal.SIGKILL)
        _killpg(pid, signal.SIGKILL)
        p.wait()
        shutil.rmtree(d)
        if name == "timeout":
            line(
                out.strip() == "killed (timeout 2 s)" and took < 15, f"timeout: outcome {out.strip()!r} in {took:.1f} s"
            )
        else:
            line(p.returncode == 128 + signal.SIGTERM, f"sigterm: the runner stopped, rc {p.returncode}")
        line(restored, f"{name}: the file restored")
        line(not left, f"{name}: no child process left")
    d = tempfile.mkdtemp()
    subprocess.run(["git", "init", "-q", d], check=True)
    (Path(d) / "a.txt").write_text("original\n")
    subprocess.run(["git", "-C", d, "add", "a.txt"], check=True)
    subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "t"], check=True)
    (Path(d) / "a.txt").write_text("leftover\n")
    buf, rc = io.StringIO(), None
    try:
        with contextlib.redirect_stdout(buf):
            refuse_dirty(["a.txt"], d)
    except SystemExit as e:
        rc = e.code
    line(
        rc == 2 and "a.txt differs from HEAD" in buf.getvalue(),
        f"dirty: refused with rc {rc}: {buf.getvalue().strip()}",
    )
    shutil.rmtree(d)
    print("mutant_guard self-test " + ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def _cli(argv):
    if argv[0] == "time" and argv[1:2] == ["--"]:
        r = run(argv[2:], TIMEOUT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{r.seconds:.0f}")
        return r.returncode
    if argv[0] == "exec" and argv[2:3] == ["--"]:
        r = run(argv[3:], deadline(float(argv[1])))
        if r.timeout:
            print(outcome(r, ""), file=sys.stderr)
            return 124
        return r.returncode
    raise SystemExit("usage: mutant_guard.py time -- CMD... | exec SECONDS -- CMD... | --self-test")


if __name__ == "__main__":
    if sys.argv[1:2] in (["time"], ["exec"]):
        sys.exit(_cli(sys.argv[1:]))
    elif sys.argv[1:2] == ["--scenario"]:
        _scenario(sys.argv[2], sys.argv[3])
    elif sys.argv[1:] == ["--self-test"]:
        sys.exit(_self_test())
    else:
        print("python3 -I scripts/mutant_guard.py --self-test")
        sys.exit(2)
