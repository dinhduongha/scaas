#!/usr/bin/env python3
"""typed-signing R2 mutants: each patches one moved rule, runs test/ua/UARegistrySplit.t.sol, restores the file and checks the
restore with `cmp` against a copy taken first. A mutant is caught when a named test fails. Foreground, one forge at a time.
  python3 -I runs/2026-11-01-typed-signing-r2-mutations.py [name ...] > runs/2026-11-01-typed-signing-r2-mutations.txt"""
import os, re, shutil, subprocess, sys, tempfile

LIB, REG, STORE = "src/ua/UARegistryLib.sol", "src/ua/UARegistry.sol", "src/ua/UAStore.sol"
M = [
    ("record-keyOwner", LIB, "library write: step 8 does not claim the keyHash",
     "        if (kh != 0) s.keyOwner[kh] = ua; // msig: none\n", ""),
    ("empty-proof-hash", LIB, "library rule: the empty proof's hash accepted",
     "if (pqz != (attrs.pqzPopHash != 0) || attrs.pqzPopHash == EMPTY_PROOF_HASH) revert",
     "if (pqz != (attrs.pqzPopHash != 0)) revert"),
    ("kem-commit-hash", LIB, "library rule: version 0 takes any key",
     "            if (keccak256(kemPk) != committed) revert IUARegistry.UAKemKeyHash(ua);\n", ""),
    ("native-member-digest", LIB, "library rule: a native member over member_digest, not the typed digest",
     "return UAStore.byCode(address(uint160(uint256(id))), typed, s.sig, _cloneHash());",
     "return UAStore.byCode(address(uint160(uint256(id))), md, s.sig, _cloneHash());"),
    ("event-pop-hash", LIB, "library event: no pop hash in `UARegistered`",
     "emit IUARegistry.UARegistered(ua, kind, d, attrs, keccak256(pop), pqzPop,",
     "emit IUARegistry.UARegistered(ua, kind, d, attrs, bytes32(0), pqzPop,"),
    ("words-swapped", REG, "the words: kind and 0x0142 swapped in `_lib`",
     "(uint256 a, uint256 b, bytes32 c) = (_cfg(kind), _CFG18, _SMART_KEY_CLONE_CODEHASH);",
     "(uint256 a, uint256 b, bytes32 c) = (_CFG18, _cfg(kind), _SMART_KEY_CLONE_CODEHASH);"),
    ("word-clone-zero", REG, "the words: the clone codehash not passed",
     "(uint256 a, uint256 b, bytes32 c) = (_cfg(kind), _CFG18, _SMART_KEY_CLONE_CODEHASH);",
     "(uint256 a, uint256 b, bytes32 c) = (_cfg(kind), _CFG18, bytes32(0));"),
    ("kind-word-record", REG, "the words: `setKemKey` with the wrong kind's word",
     "_lib(UARegistryLib.setKemKey.selector, _s.records[ua].kind);", "_lib(UARegistryLib.setKemKey.selector, 0);"),
    ("layout-swap", STORE, "storage: two fields swapped in `UAStore.Layout`",
     "        mapping(bytes32 ua => bytes32) keyOwner_; // never", ""),  # replaced below
    ("no-abi-error", REG, "ABI: SSTORE2WriteFailed not declared",
     "    error SSTORE2WriteFailed();\n", ""),
    ("no-lib-check", REG, "constructor: a missing library accepted",
     "        if (address(UARegistryLib).code.length == 0) revert UAConfig(0);\n", ""),
]


def layout_swap(s):
    a = "        mapping(bytes32 ua => uint64) kemMax; // 11: the highest stored KEM version (0: none, or the register key only)\n"
    b = "        mapping(bytes32 ua => KemCommit) kemCommit; // 12\n"
    assert a + b in s
    return s.replace(a + b, b + a)


def run():
    p = subprocess.run(["../../scripts/capped", "forge", "test", "--match-path", "test/ua/UARegistrySplit.t.sol"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


names = sys.argv[1:]
bad = 0
for name, path, what, old, new in M:
    if names and name not in names:
        continue
    keep = tempfile.mktemp()
    shutil.copy(path, keep)
    src = open(path).read()
    if name == "layout-swap":
        mut = layout_swap(src)
    else:
        assert src.count(old) == 1, name
        mut = src.replace(old, new)
    open(path, "w").write(mut)
    try:
        rc, out = run()
    finally:
        shutil.copy(keep, path)
    same = subprocess.run(["cmp", keep, path]).returncode == 0
    os.unlink(keep)
    fails = sorted({l[:150] for l in out.splitlines() if l.startswith("[FAIL")})
    compiled = "Compiler run failed" not in out
    caught = rc != 0 and compiled and bool(fails)
    bad += not (caught and same)
    print(f"## {name}: {what}\nfile {path}, restored by cmp: {'same' if same else 'DIFFERENT'}\n"
          f"{'CAUGHT' if caught else 'NOT CAUGHT'} rc={rc} compiled={compiled}")
    for f in fails:
        print("  " + f)
    sys.stdout.flush()
print(f"mutants not caught or not restored: {bad}")
sys.exit(1 if bad else 0)
