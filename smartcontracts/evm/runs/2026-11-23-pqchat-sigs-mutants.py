#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-signatures S1 (CTR-CHAT-23): each new check of `PqChat`'s signature-storage setting is caught by its
test. One mutant per run on a clean tree, `forge test` over test/pqchat, every file restored byte for byte after it; a mutant that
does not compile kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-sigs-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-sigs-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

E = "smartcontracts/evm/"
P = E + "src/pqchat/PqChat.sol"
CAPPED = os.path.abspath("scripts/capped")
FORGE = ([CAPPED, "forge", "test", "--match-path", "test/pqchat/*.t.sol"], E)
M = [
    ("initialize takes any setting", [(P, "        if (sigStore_ != SIG_NONE && sigStore_ != SIG_SSTORE2) revert PqChatSigStore(sigStore_);\n", "")]),
    ("initialize takes log (1)", [(P, "sigStore_ != SIG_NONE && sigStore_ != SIG_SSTORE2", "sigStore_ > SIG_SSTORE2")]),
    ("every instance keeps signatures", [(P, "        return _s().sigStore == SIG_SSTORE2;", "        return true;")]),
    ("no instance keeps signatures", [(P, "        return _s().sigStore == SIG_SSTORE2;", "        return false;")]),
    ("a none instance answers the signature views", [(P, "        if (!_keep()) revert PqChatSigNotStored();", "        _keep();")]),
    ("a none instance keeps leave records", [(P, "        if (_keep()) _s().leaves[l.epochId].push(", "        if (true) _s().leaves[l.epochId].push(")]),
    ("an sstore2 instance keeps no leave record", [(P, "        if (_keep()) _s().leaves[l.epochId].push(", "        if (false) _s().leaves[l.epochId].push(")]),
    ("the kept blob's signature offset wrong", [(P, "            if keep { mstore(add(o, 64), add(head, r)) }", "            if keep { mstore(add(o, 64), head) }")]),
    ("the kept blob without the signature tail", [(P, "            if keep { mcopy(add(add(o, head), r), add(es, 64), e) }\n", "")]),
    ("leaveSig reads the dynamic records' offset word", [(P, "_returnSig(_get(_s().leaves[epochId][index]), 5);", "_returnSig(_get(_s().leaves[epochId][index]), 2);")]),
    ("the author read at the none blob's offset", [(P, "        return _word(ep.record, uint256(_word(ep.record, 0)) + 32);", "        return _word(ep.record, 96);")]),
    ("the one-blob bound without the kept signature", [(P, "        bytes memory blob = _blob(abi.encode(m), sig);\n        if (blob.length + 2 > _codeCap(limit))", "        bytes memory blob = _blob(abi.encode(m), sig);\n        if (abi.encode(m, bytes32(0)).length + 2 > _codeCap(limit))")]),
    ("sessionSig answers an epoch id", [(P, "        _kept();\n        Epoch storage ep = _known(sessionId);\n        if (ep.sessionId != sessionId) revert PqChatUnknown(sessionId);", "        _kept();\n        Epoch storage ep = _known(sessionId);")]),
    ("epochSig answers a session id", [(P, "        _kept();\n        Epoch storage ep = _known(epochId);\n        if (ep.sessionId == epochId) revert PqChatUnknown(epochId);", "        _kept();\n        Epoch storage ep = _known(epochId);")]),
]

if sys.argv[1:] == ["check"]:
    for name, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    suite, cwd = FORGE
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(suite, capture_output=True, text=True, cwd=cwd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    loaded = "Compiler run failed" not in out
    failed = sorted(set(re.findall(r"^\[FAIL[^\]]*\] (\w+)\(", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    print(f"{verdict} | M{n} {name} | {P} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
