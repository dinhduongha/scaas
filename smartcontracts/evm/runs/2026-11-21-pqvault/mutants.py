# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan V3-V6 (spec §11 "Negative tests that can fail"): each mutant replaces one literal line (exactly one match) in a
source file, runs the PqVault suites (test/pqvault, the default set, -j 1, through scripts/capped) and restores the file; a
mutant is killed when the run fails. One line per mutant on stdout and in runs/2026-11-21-pqvault/mutants/<name>.log
(git-ignored). Usage, from smartcontracts/evm:
  python3 runs/2026-11-21-pqvault/mutants.py [name ...]      (no name: every mutant)
"""
import os
import subprocess
import sys

V = "src/pqvault/PqVault.sol"
T = "src/pqvault/PqVaultTypes.sol"
B = "src/pqgroup/PqGroupBase.sol"

M = [
    # V3: the group part
    ("rekey-admin-to-member", V, "|| !_has(pa, e.author)) revert PqVaultNotAdmin(e.author);",
     "|| _memberAt(pm, e.author) == type(uint256).max) revert PqVaultNotAdmin(e.author);"),
    ("rekey-removed-admin", V, "if ((pe.removed != 0 && pe.removedOf[e.author]) || !_has(pa, e.author))", "if (!_has(pa, e.author))"),
    ("create-min-member-0", V, "_checkLists(reg, admins, members, v.wrapHashes.length, 1);", "_checkLists(reg, admins, members, v.wrapHashes.length, 0);"),
    ("rekey-min-member-0", V, "_checkLists(reg, e.admins, members, e.wrapHashes.length, 1);", "_checkLists(reg, e.admins, members, e.wrapHashes.length, 0);"),
    ("create-pass-shape-kdf-only", V, "|| (v.passKdf == 0) != (v.passSalt == 0)", "|| (v.passKdf == 0) != (v.passKdf == 0)"),
    ("rekey-pass-shape-kdf-only", V, "if ((e.passKdf == 0) != (e.passSalt == 0)) revert PqVaultShape();", "if ((e.passKdf == 0) != (e.passKdf == 0)) revert PqVaultShape();"),
    ("mode-never-read", V, "        if (mode == 0) {\n            reg.requirePortableApp", "        if (true) {\n            reg.requirePortableApp"),
    ("mode-always-1", V, "        if (mode == 0) {\n            reg.requirePortableApp", "        if (false) {\n            reg.requirePortableApp"),
    ("mode-gt-1-allowed", V, "|| v.mode > 1 ||", "||"),
    ("mode1-home-check", V, "|| (v.mode == 1 && !home)", ""),
    ("dsb-no-verifying-contract", T, "NAME_HASH, VERSION_HASH, block.chainid, c));", "NAME_HASH, VERSION_HASH, block.chainid, address(0)));"),
    ("dsv-no-salt", T, "DOMAIN_V_TYPEHASH, NAME_HASH, VERSION_HASH, APP_ID));", "DOMAIN_V_TYPEHASH, NAME_HASH, VERSION_HASH, bytes32(0)));"),
    ("vaultid-no-mode", T, "abi.encode(TAG_VAULT, creator, nonce, mode, homeChain, homeVaultContract)",
     "abi.encode(TAG_VAULT, creator, nonce, uint8(0), homeChain, homeVaultContract)"),
    ("vaultid-no-home", T, "abi.encode(TAG_VAULT, creator, nonce, mode, homeChain, homeVaultContract)",
     "abi.encode(TAG_VAULT, creator, nonce, mode, bytes32(0), address(0))"),
    ("purpose-pqchat-mode1", T, "bytes32 internal constant P_V = keccak256(abi.encode(UAKinds.APP_PURPOSE_NS, APP_ID));",
     "bytes32 internal constant P_V = UAKinds.PURPOSE_PQCHAT;"),
    ("appid-other-mode0", V, "reg.requirePortableApp(signer, PqVaultTypes.APP_ID,", "reg.requirePortableApp(signer, keccak256(\"scaas.pqchat\"),"),
    ("rekey-vault-equality", B, "if (pe.sessionId != sessionId) _fail(F_UNKNOWN, uint256(parentEpochId), 0);", ""),
    ("leave-vault-equality", V, "if (ep.sessionId != l.vaultId) revert PqVaultUnknown(l.epochId);", ""),
    ("remove-vault-equality", V, "if (ep.sessionId != r.vaultId) revert PqVaultUnknown(r.epochId);", ""),
    ("home-slot-check", B, "if (c != 0) _fail(F_EPOCH_TAKEN, uint256(parentEpochId), uint256(c));", "c;"),
    ("wrap-hash-check", B, "if (PqChatTypes.hashWrap(w) != hashes[i]) _fail(F_WRAP_HASH, uint256(epochId), i);", ""),
    ("nonce-mark", B, "b[nonce >> 8] = word | bit;", ""),
    # V4: items, versions, batches
    ("edit-version-check", V, "if (d.version != next) revert PqVaultVersion(next, d.version);", ""),
    ("item-member-check", V, "if (_memberAt(m, author) == type(uint256).max || ep.left[author] || ep.removedOf[author]) {",
     "if (ep.left[author] || ep.removedOf[author]) {"),
    ("item-left-check", V, "if (_memberAt(m, author) == type(uint256).max || ep.left[author] || ep.removedOf[author]) {",
     "if (_memberAt(m, author) == type(uint256).max || ep.removedOf[author]) {"),
    ("item-removed-check", V, "if (_memberAt(m, author) == type(uint256).max || ep.left[author] || ep.removedOf[author]) {",
     "if (_memberAt(m, author) == type(uint256).max || ep.left[author]) {"),
    ("item-epoch-taken", V, "if (child != 0) revert PqVaultEpochTaken(epochId, child);", "child;"),
    ("item-incomplete", V, "if (ep.landed != ep.wraps) revert PqVaultIncomplete(epochId);", ""),
    ("create-item-vault-equality", V, "_itemRights(it.epochId, it.vaultId, it.author);",
     "_itemRights(it.epochId, _v().epochs[it.epochId].sessionId, it.author);"),
    ("create-items-vault-equality", V, "_itemRights(b.epochId, b.vaultId, b.author);",
     "_itemRights(b.epochId, _v().epochs[b.epochId].sessionId, b.author);"),
    ("edit-epoch-in-item-vault", V, "_itemRights(d.epochId, vid, d.author);",
     "_itemRights(d.epochId, _v().epochs[d.epochId].sessionId, d.author);"),
    ("batch-field-vault", V, "if (it.vaultId != b.vaultId || it.epochId != b.epochId || it.author != b.author) revert PqVaultShape();",
     "if (it.epochId != b.epochId || it.author != b.author) revert PqVaultShape();"),
    ("batch-field-epoch", V, "if (it.vaultId != b.vaultId || it.epochId != b.epochId || it.author != b.author) revert PqVaultShape();",
     "if (it.vaultId != b.vaultId || it.author != b.author) revert PqVaultShape();"),
    ("batch-field-author", V, "if (it.vaultId != b.vaultId || it.epochId != b.epochId || it.author != b.author) revert PqVaultShape();",
     "if (it.vaultId != b.vaultId || it.epochId != b.epochId) revert PqVaultShape();"),
    ("batch-empty", V, "if (n == 0) revert PqVaultShape();", ""),
    ("batch-item-nonce-mark", V, "            _useNonce(scope, it.nonce);\n", ""),
    ("batch-nonce-mark", V, "        _useNonce(scope, b.nonce);\n", ""),
    ("create-item-nonce", V, "_useNonce(PqVaultTypes.scopeItem(it.vaultId, it.author), it.nonce);", ""),
    ("edit-nonce", V, "_useNonce(PqVaultTypes.scopeItem(vid, d.author), d.nonce);", ""),
    ("ct-min", V, "if (c.length < CT_MIN || c.length > CT_MAX) revert PqVaultShape();", "if (c.length > CT_MAX) revert PqVaultShape();"),
    ("ct-max", V, "if (c.length < CT_MIN || c.length > CT_MAX) revert PqVaultShape();", "if (c.length < CT_MIN) revert PqVaultShape();"),
    # V5: recovery views
    ("latest-range-clamp", V, "_page(_v().items[vid], offset, limit, LATEST_RANGE_MAX);", "_page(_v().items[vid], offset, limit, 1000);"),
    ("items-range-clamp", V, "_page(_v().items[vid], offset, limit, ITEMS_RANGE_MAX);", "_page(_v().items[vid], offset, limit, 1000);"),
    ("latest-not-latest", V, "VersionView memory w = versionAt(iids[i], c);", "VersionView memory w = versionAt(iids[i], 1);"),
    ("page-end", V, "uint256 end = n - offset > limit ? offset + limit : n;\n        page = new bytes32[](end - offset);\n        for (uint256 i; i < page.length; ++i) {\n            page[i] = l[offset + i];",
     "uint256 end = offset + limit;\n        page = new bytes32[](end - offset);\n        for (uint256 i; i < page.length; ++i) {\n            page[i] = l[offset + i];"),
]


def run(name, path, old, new):
    src = open(path).read()
    if src.count(old) != 1:
        return f"{name} | {path} | NOT APPLIED ({src.count(old)} matches)"
    os.makedirs("runs/2026-11-21-pqvault/mutants", exist_ok=True)
    log = f"runs/2026-11-21-pqvault/mutants/{name}.log"
    try:
        open(path, "w").write(src.replace(old, new))
        env = dict(os.environ, FOUNDRY_TEST="test/pqvault", FOUNDRY_OUT="out/pv-mut", FOUNDRY_CACHE_PATH="cache/pv-mut")
        with open(log, "w") as f:
            r = subprocess.run(["../../scripts/capped", "forge", "test", "-j", "1"], env=env, stdout=f, stderr=subprocess.STDOUT)
    finally:
        open(path, "w").write(src)
    t = open(log, errors="replace").read()
    fails = sorted({l.split("] ")[1].split("(")[0] for l in t.splitlines() if l.startswith("[FAIL") and "] " in l})
    if r.returncode != 0 and not fails:
        fails = ["(build)"]
    return f"{name} | {path} | {'KILLED' if r.returncode != 0 else 'SURVIVED'} | {', '.join(fails[:6])}"


if __name__ == "__main__":
    want = sys.argv[1:]
    for m in M:
        if not want or m[0] in want:
            print(run(*m), flush=True)
