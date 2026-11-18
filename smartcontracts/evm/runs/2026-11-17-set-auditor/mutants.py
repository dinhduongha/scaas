# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The setAuditor plan's mutants (spec 2026-11-17-set-auditor.md §13), one per check: the source edit applied, the test
directory compiled into its own out/ and cache/ through `scripts/capped`, the named test file run, the file restored byte-equal in
the same process (finally). Killed = forge fails (rc != 0) with a test red.

Usage (from smartcontracts/evm): python3 runs/2026-11-17-set-auditor/mutants.py <task> list | run <id> ... | all
Full output: runs/2026-11-17-set-auditor/<task>/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` on stdout and
appended to runs/2026-11-17-set-auditor/<task>/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")

GB = "src/governance/GovernanceBits.sol"
GL = "src/governance/GovernanceLib.sol"
RB = "src/regulated/RegulatedBase.sol"
ZL = "src/zether/ZetherLib.sol"
PS = "src/pqz/PqzStateLib.sol"
ZY = "src/zether/ZetherLayer.sol"
AR = "src/confidential/AuditorRules.sol"
MB = "src/metatx/MetaTokenBase.sol"
ZA = ("test/zether", "ZetherAuditor.t.sol")
ZPS = "../../clients/zether-prover/src/state.rs"
ZPR = "../../clients/zether-prover/src/schnorr.rs"
ZP = ("@clients/zether-prover", "--test state --test auditor_pop")
PL = "src/pqz/PqzLayer.sol"
PC = "src/pqz/PqzCore.sol"
PA = ("test/pqz", "PqzAuditor.t.sol")
UAP = "../../clients/ua-rs/src/facade/pqz.rs"
UT = ("@clients/ua-rs", "--features vectors --test facade_pqz_state")

GR = "src/governance/GovernanceRouter.sol"
GRA = ("test/governance", "GovRouterAuditor.t.sol")

NG = "../../scaas-node/src/guard.rs"
NS = ("@scaas-node", "--lib auditor_verdicts")

# task -> id -> (file, old, new, test dir, match-path glob)
MUTANTS = {
    "a8": {
        "requeue-dropped": (NG, '    if reason.starts_with("AuditorNotReady") {\n', '    if reason.starts_with("AuditorNotReady-") {\n', *NS),
    },
    "a6": {
        "key-struct-word": (GR, "abi.encode(keccak256(newKey), epoch, chainUid)", "abi.encode(keccak256(pop), epoch, chainUid)", *GRA),
        "ua-struct-word": (GR, "abi.encode(newAuditor, epoch, chainUid)", "abi.encode(bytes32(0), epoch, chainUid)", *GRA),
        "key-epoch-forwarded": (GR, "(IZetherToken.setAuditorKey, (newKey, epoch, pop, chainUid))",
                                "(IZetherToken.setAuditorKey, (newKey, epoch + 1, pop, chainUid))", *GRA),
        "pop-not-forwarded": (GR, "(IZetherToken.setAuditorKey, (newKey, epoch, pop, chainUid))",
                              "(IZetherToken.setAuditorKey, (newKey, epoch, newKey, chainUid))", *GRA),
        "consent-not-forwarded": (GR, "(IPqzToken.setAuditorUA, (newAuditor, epoch, consent, chainUid))",
                                  "(IPqzToken.setAuditorUA, (newAuditor, epoch, auth, chainUid))", *GRA),
        "ua-op-key-typehash": (GR, "_uaCall(T.UA_SET_AUDITOR_UA, e,", "_uaCall(T.UA_SET_AUDITOR_KEY, e,", *GRA),
        "typehash-string": ("src/governance/GovernanceRouterBase.sol", "bytes newKey,uint32 epoch", "bytes key,uint32 epoch",
                            "test/governance", "GovRouterTypehash.t.sol"),
    },
    "a1": {
        "delayed-relax-32": (RB, "            | GovernanceBits.NOT_DISABLEABLE) | (uint256(1) << GovernanceBits.KYC);",
                             "            | GovernanceBits.NOT_DISABLEABLE) | (uint256(1) << GovernanceBits.KYC) | GovernanceBits.AUDITOR_BITS;",
                             "test/governance", "GovAuditorBit.t.sol"),
        "regulated-roles-32": (GB, "        (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << RECORD) | (1 << MODERATE);",
                               "        (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << RECORD) | (1 << MODERATE) | (uint256(1) << 32);",
                               "test/governance", "GovAuditorBit.t.sol"),
        "zether-none-check-dropped": (ZL, "        if (auditorMode == uint8(ZetherTypes.AuditorMode.NONE)) revert IZetherToken.BadAuditorMode(auditorMode);\n", "",
                                      "test/governance", "GovAuditorBit.t.sol"),
        "pqz-none-check-dropped": (PS, "                if (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE)) revert IPqzToken.BadAuditorMode(c.auditorMode);\n", "",
                                   "test/governance", "GovAuditorBit.t.sol"),
        "zether-admin0-dropped": (ZL, "        if (g.admin == 0) revert IGovernance.FeatureNeedsAdmin(GovernanceBits.AUDITOR);\n", "",
                                  "test/governance", "GovAuditorBit.t.sol"),
        "pqz-admin0-dropped": (PS, "                if (g.admin == 0) revert IGovernance.FeatureNeedsAdmin(GovernanceBits.AUDITOR);\n", "",
                               "test/governance", "GovAuditorBit.t.sol"),
        "delegable-accepted": (GL, "        if (bit == GovernanceBits.AUDITOR && t.delegable) revert IGovernance.DelegableRefused(bit);\n", "",
                               "test/governance", "GovAuditorBit.t.sol"),
        "enableable-32": (GB, "    uint256 internal constant ENABLEABLE = (1 << ALLOWLIST) | (1 << DENYLIST) | (1 << KYC);",
                          "    uint256 internal constant ENABLEABLE = (1 << ALLOWLIST) | (1 << DENYLIST) | (1 << KYC) | (uint256(1) << 32);",
                          "test/governance", "GovAuditorBit.t.sol"),
    },
    "a2": {
        "drop-use32": (ZY, "        GovernanceUse.use(GovernanceBits.AUDITOR, c, 0);\n", "", *ZA),
        "drop-chain-word": (ZY, "bytes32 c = _holderOnChain(GovernanceBits.AUDITOR, chainUid_);", "bytes32 c = _govSubject();", *ZA),
        "drop-epoch-check": (ZL, "        AuditorRules.requireNext(s.auditorEpoch, epoch);\n", "", *ZA),
        "confirm-before-eta": (ZL, "                if (block.timestamp < s.auditorEta) revert IConfidentialToken.AuditorNotReady(s.auditorEta);\n", "", *ZA),
        "drop-window-end": (AR, "        if (block.timestamp <= uint256(eta) + AUDITOR_CONFIRM_WINDOW) return CONFIRMABLE;\n        return EXPIRED;",
                            "        return CONFIRMABLE;", *ZA),
        "window-zero-notice": (AR, "AUDITOR_CONFIRM_WINDOW = 7 days;", "AUDITOR_CONFIRM_WINDOW = 0;", *ZA),
        "window-by-delay": (AR, "AUDITOR_CONFIRM_WINDOW = 7 days;", "AUDITOR_CONFIRM_WINDOW = 2 days;", *ZA),
        "refuse-over-expired": (ZL, "        if (AuditorRules.live(s.auditorEta, s.auditorProposerRoleEpoch, s.auditorProposer)) {",
                                "        if (s.auditorEta != 0) {", *ZA),
        "accept-over-live": (ZL, "                revert IConfidentialToken.AuditorPending();\n", "", *ZA),
        "drop-cancel": (ZL, "            } else if (h == current) {", "            } else if (false) {", *ZA),
        "drop-proposer-confirm": (ZL, "                AuditorRules.requireProposer(caller, s.auditorProposer);\n                if (block.timestamp",
                                  "                if (block.timestamp", *ZA),
        "drop-proposer-cancel": (ZL, "                AuditorRules.requireProposer(caller, s.auditorProposer);\n                _clearAuditorProposal(s);",
                                 "                _clearAuditorProposal(s);", *ZA),
        "drop-role-epoch": (AR, " || g.epoch[GovernanceBits.AUDITOR][proposer] != roleEpoch", "", *ZA),
        "notice-alone": (MB, "        if (g > d) d = g;\n", "", *ZA),
        "grantdelay-alone": (MB, "        d = IOpenFactory(FACTORY).noticePeriod();", "        d = 0;", *ZA),
        "delay0-not-at-once": (ZL, "        if (delay == 0) {", "        if (false) {", *ZA),
        "skip-checks-proposal": (ZL, "        if (h == current) revert IConfidentialToken.AuditorSame();\n        _auditorChecks(s.p, newKey, epoch, pop, e);\n",
                                 "        if (h == current) revert IConfidentialToken.AuditorSame();\n", *ZA),
        "skip-checks-apply": (ZL, "                _auditorChecks(s.p, newKey, epoch, pop, e);\n                _applyAuditor", "                _applyAuditor", *ZA),
        "pop-d-unbound": (ZL, '"SCAAS-ZETHER-AUDITOR-POP-V1", d, g, y, r', '"SCAAS-ZETHER-AUDITOR-POP-V1", g, y, r', *ZA),
        "pop-drop-c-nonzero": (ZL, "        if (c == 0) return false;\n", "", *ZA),
        "pop-drop-z-range": (ZL, "        if (z >= n || !v.isValidPoint(r)) return false;", "        if (!v.isValidPoint(r)) return false;", *ZA),
        "pop-drop-r-valid": (ZL, "        if (z >= n || !v.isValidPoint(r)) return false;", "        if (z >= n) return false;", *ZA),
        "skip-entry-single": (ZL, "        _auditorEntry(s, entryRef, abi.encode(t.cAud));\n", "", *ZA),
        "skip-entry-multi": (ZL, "        _auditorEntry(s, entryRef, abi.encode(t.legs[0].cAud));\n", "", *ZA),
        "write-at-epoch0": (ZL, "        if (e != 0 && !_isO(cAud)) s.entryAuditorEpoch[entryRef] = e;", "        if (!_isO(cAud)) s.entryAuditorEpoch[entryRef] = e;", *ZA),
        "write-on-optout": (ZL, "        if (e != 0 && !_isO(cAud)) s.entryAuditorEpoch[entryRef] = e;", "        if (e != 0) s.entryAuditorEpoch[entryRef] = e;", *ZA),
        "history-overwritten": (ZL, "        s.auditorKeys[epoch - 1] = previous;", "        s.auditorKeys[0] = previous;", *ZA),
        "keyof-current": (ZY, "        return e == s.auditorEpoch ? s.auditorKey : s.auditorKeys[e];", "        return s.auditorKey;", *ZA),
        "epoch-moves-pinned": (ZL, "        ZetherTypes.DisclosureMode disclosureMode;\n        ZetherTypes.AuditorMode auditorMode;\n"
                               "        /// @dev Bit 32 (set-auditor spec §6, CTR-ZTH-95): the replacements of the auditor key so far, slot 0 byte 22 (read\n"
                               "        ///      with `auditorMode` by every transfer, no extra storage read).\n        uint32 auditorEpoch;\n",
                               "        uint32 auditorEpoch;\n        ZetherTypes.DisclosureMode disclosureMode;\n        ZetherTypes.AuditorMode auditorMode;\n",
                               "test/v2", "Layout.t.sol"),
    },
    "a3": {
        "disclosure-current-key": ("src/zether/ZetherDisclosure.sol", "IZetherToken(token).auditorKeyOf(entryRef);",
                                   "IZetherToken(token).auditorKey();", *ZA),
        "recovery-current-key": (ZPS, "            if cmd == \"recoverTransfer\" {\n                p.y_aud = entry_auditor_key(v)?;",
                                 "            if cmd == \"recoverTransfer\" {\n                p.y_aud = point(&bytes_list(&ns(\"auditorKey\")?, &slot_words(v, \"auditorKeyWords\")?)?)?;",
                                 *ZP),
        "reader-current-auditor": (ZPS, "                        p.y_aud = entry_auditor_key(v)?;\n                        if field_u64",
                                   "                        p.y_aud = point(&bytes_list(&ns(\"auditorKey\")?, &slot_words(v, \"auditorKeyWords\")?)?)?;\n                        if field_u64",
                                   *ZP),
        "reader-secret-before-epoch": (ZPS, "== 0 || p.y_aud != *y || leg[3]", "== 0 || leg[3]", *ZP),
        "pop-challenge-drops-y": (ZPR, "    b.extend(encode_point::<C>(&generator::<C>()));\n    b.extend(encode_point::<C>(y));\n",
                                  "    b.extend(encode_point::<C>(&generator::<C>()));\n", *ZP),
        "pop-challenge-drops-d": (ZPR, "    let mut b = b\"SCAAS-ZETHER-AUDITOR-POP-V1\".to_vec();\n    b.extend_from_slice(d);\n",
                                  "    let mut b = b\"SCAAS-ZETHER-AUDITOR-POP-V1\".to_vec();\n", *ZP),
        "ua-rs-reader-current-auditor": (ZPS, "                        p.y_aud = entry_auditor_key(v)?;\n                        if field_u64",
                                         "                        p.y_aud = point(&bytes_list(&ns(\"auditorKey\")?, &slot_words(v, \"auditorKeyWords\")?)?)?;\n                        if field_u64",
                                         "@clients/ua-rs", "--features zether,wallet,mlock --no-default-features --test facade_zether_state"),
    },
    "a4": {
        "drop-use32": (PL, "        GovernanceUse.use(GovernanceBits.AUDITOR, c, 0);\n", "", *PA),
        "drop-chain-word": (PL, "bytes32 c = _holderOnChain(GovernanceBits.AUDITOR, chainUid_);", "bytes32 c = _govSubject();", *PA),
        "read-pqz-notice": (PL, "consent, c, _auditorDelay(), e.registry", "consent, c, PqzCore.$().noticePeriod, e.registry", *PA),
        "drop-epoch-check": (PS, "        AuditorRules.requireNext(s.auditorEpoch, epoch);\n", "", *PA),
        "confirm-before-eta": (PS, "                if (block.timestamp < s.auditorEta) revert IConfidentialToken.AuditorNotReady(s.auditorEta);\n", "", *PA),
        "refuse-over-expired": (PS, "        if (AuditorRules.live(s.auditorEta, s.auditorProposerRoleEpoch, s.auditorProposer)) {",
                                "        if (s.auditorEta != 0) {", *PA),
        "accept-over-live": (PS, "                revert IConfidentialToken.AuditorPending();\n", "", *PA),
        "drop-cancel": (PS, "            } else if (newAuditor == s.auditorUA) {", "            } else if (false) {", *PA),
        "drop-proposer-confirm": (PS, "                AuditorRules.requireProposer(caller, s.auditorProposer);\n                if (block.timestamp",
                                  "                if (block.timestamp", *PA),
        "drop-proposer-cancel": (PS, "                AuditorRules.requireProposer(caller, s.auditorProposer);\n                _clearAuditorProposal(s);",
                                 "                _clearAuditorProposal(s);", *PA),
        "delay0-not-at-once": (PS, "        if (delay == 0) {\n            _applyAuditor(s, newAuditor, epoch);", "        if (false) {\n            _applyAuditor(s, newAuditor, epoch);", *PA),
        "skip-checks-proposal": (PS, "        if (newAuditor == s.auditorUA) revert IConfidentialToken.AuditorSame();\n        _auditorChecks(",
                                 "        if (newAuditor == s.auditorUA) revert IConfidentialToken.AuditorSame();\n        if (false) _auditorChecks(", *PA),
        "skip-checks-apply": (PS, "                _auditorChecks(newAuditor, epoch, consent, registry, domainSeparator, chainUid);\n                _applyAuditor",
                              "                _applyAuditor", *PA),
        "consent-zether-purpose": (PS, "UAKinds.PURPOSE_AUDITOR_CONSENT,", "UAKinds.PURPOSE_ZETHER_AUTH,", *PA),
        "drop-opening-kem": (PS, "        if (s.pqzOpening\n", "        if (false && s.pqzOpening\n", *PA),
        "proven-everywhere": (PS, "(!proven && IUARegistry(registry).kindEnabled(UAKinds.PQZ_MLWE))", "!proven", *PA),
        "proven-never": (PS, "(!proven && IUARegistry(registry).kindEnabled(UAKinds.PQZ_MLWE))", "false", *PA),
        "skip-entry-write": (PC, "        if (o.auditorOn == 1) {\n            uint32 e = s.auditorEpoch;", "        if (false) {\n            uint32 e = s.auditorEpoch;", *PA),
        "write-at-epoch0": (PC, "            if (e != 0) s.entryAuditorEpoch[ref] = e;", "            s.entryAuditorEpoch[ref] = e;", *PA),
        "write-on-optout": (PC, "        if (o.auditorOn == 1) {\n            uint32 e = s.auditorEpoch;", "        if (true) {\n            uint32 e = s.auditorEpoch;", *PA),
        "legof-current": (PC, "        if (kind == 2) owner = auditorUAOf(ref);", "        if (kind == 2) owner = $().auditorUA;", *PA),
        "uaof-current": (PC, "        return e == s.auditorEpoch ? s.auditorUA : s.auditorUAs[e];", "        return s.auditorUA;", *PA),
        "history-overwritten": (PS, "        s.auditorUAs[epoch - 1] = previous;", "        s.auditorUAs[0] = previous;", *PA),
        "epoch-moves-pinned": (PC, "        bool pqzOwnKey;\n        bool pqzOpening;\n", "        uint32 auditorEpochX;\n        bool pqzOwnKey;\n        bool pqzOpening;\n",
                               "test/v2", "Layout.t.sol"),
        "reader-current-auditor": (UAP, "    let slot = if at == current {\n        slot_add(&PQZ_ROOT, 7)\n    } else {",
                                   "    let slot = if true {\n        slot_add(&PQZ_ROOT, 7)\n    } else {", *UT),
        "reader-secret-before-epoch": (UAP, "            if holder != f.word(\"ua\")? {", "            if holder != holder {", *UT),
    },
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)
    cargo = re.findall(r"^test (\S+) \.\.\. FAILED", log, re.M)
    return sorted(set(forge + cargo))


def run(task, mid):
    path, old, new, tdir, match = MUTANTS[task][mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    out = os.path.join(HERE, task)
    os.makedirs(out, exist_ok=True)
    logp = os.path.join(out, f"mut-{mid}.log")
    name = tdir.replace("/", "-")
    try:
        open(full, "w").write(src.replace(old, new))
        if tdir.startswith("@"):  # a Rust crate (repository-relative), `match` its cargo test arguments
            cwd, env = os.path.join(EVM, "..", "..", tdir[1:]), dict(os.environ)
            cmd = [CAPPED, "cargo", "test", "-j", "2", "--locked", *match.split()]
        else:
            cwd = EVM
            env = {**os.environ, "FOUNDRY_TEST": tdir, "FOUNDRY_SCRIPT": tdir, "FOUNDRY_OUT": f"out/mut-sa-{name}",
                   "FOUNDRY_CACHE_PATH": f"cache/mut-sa-{name}"}
            cmd = [CAPPED, FORGE, "test", "-j", "2", "--match-path", f"{tdir}/{match}"]
        with open(logp, "w") as log:
            rc = subprocess.call(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if open(full).read() != src:
        raise SystemExit(f"{mid}: {path} not restored")
    t = open(logp).read()
    red = red_tests(t)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in t else "none")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(out, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in MUTANTS:
        raise SystemExit(__doc__)
    task, verb = sys.argv[1], sys.argv[2]
    if verb == "list":
        print("\n".join(MUTANTS[task]))
    elif verb == "run":
        for m in sys.argv[3:]:
            run(task, m)
    elif verb == "all":
        txt = os.path.join(HERE, task, "mutants.txt")
        done = {l.split(" | ")[0] for l in open(txt) if " | " in l} if os.path.exists(txt) else set()
        for m in MUTANTS[task]:
            if m not in done:
                run(task, m)
    else:
        raise SystemExit(__doc__)
