#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""No chain: mldsa_on.py's set selection (each refusal by name beside its control, one field changed) and its envelope
canonicalisation (`MetaTxLib.canon`: a non-zero unbound relayer / fee recipient is signed as zero), each test run against a
mutant of what it guards, which it must catch.  python3 -I script/onchain/test_mldsa_on.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mldsa_on as M  # noqa: E402

HDR = {"key": "local-31337-testnet", "name": "local", "chainId": 31337, "chainUid": "0x" + "11" * 32, "network": "testnet"}
FAILS = []


def refused(f, name):
    try:
        f()
    except M.Stop as e:
        return str(e).startswith(name)
    return False


def t_sets(se):
    """True iff `se` (set_entries) passes every row."""
    flat_off = dict(HDR, ua_registry="0xa", mldsa_precompile="off")
    two = dict(HDR, ua_registry="0xa", mldsa_precompile="off",
               sets={"mldsa-off": {"ua_registry": "0xa", "mldsa_precompile": "off"},
                     "mldsa-on": {"ua_registry": "0xb", "mldsa_precompile": "on"}})
    rows = [
        se(flat_off, "mldsa-off")["ua_registry"] == "0xa",                              # control of the two below
        refused(lambda: se(flat_off, "mldsa-on"), "DEPLOY_SET_MISMATCH"),               # a flat book of the other mode
        refused(lambda: se(flat_off, "mldsa-of"), "DEPLOY_SET_UNKNOWN"),                # one letter changed
        se(two, "mldsa-on")["ua_registry"] == "0xb",                                     # the set's own entries, not the top
        se(two, "mldsa-off")["ua_registry"] == "0xa",
        refused(lambda: se(dict(two, sets={"mldsa-off": two["sets"]["mldsa-off"]}), "mldsa-on"), "DEPLOY_SET_MISSING"),
        refused(lambda: se(dict(two, sets=dict(two["sets"], **{"mldsa-on": {"mldsa_precompile": "off"}})), "mldsa-on"),
                "DEPLOY_SET_MISMATCH"),                                                  # a set entry whose mode is not its label's
    ]
    return all(rows)


def t_canon(ce):
    z = b"\0" * 20
    r, f = "0x" + "aa" * 20, "0x" + "bb" * 20
    env = [z, 0, 1, 9, 0, r, 5, f]
    rows = [
        ce(env)[5] == 0 and ce(env)[7] == 0,                     # open mode: a non-zero unbound relayer and recipient signed as 0
        ce(env[:4] + [1] + env[5:])[5] == r and ce(env[:4] + [1] + env[5:])[7] == 0,  # relayer bound
        ce(env[:4] + [2] + env[5:])[7] == f and ce(env[:4] + [2] + env[5:])[5] == 0,  # recipient bound
        ce(env[:4] + [0x22] + env[5:])[7] == f,                  # FIXED fee + recipient bound (Tokens' FIXED_FEE)
        ce(env)[6] == 5 and env[5] == r,                         # the fee kept; the caller's list untouched
    ]
    return all(rows)


def check(ok, what):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILS.append(what)


def mutant_ignores_mode(book, label):
    if label not in M.SETS:
        raise M.Stop("DEPLOY_SET_UNKNOWN")
    return dict(book["sets"][label]) if "sets" in book and label in book["sets"] else dict(book)


def mutant_top_level(book, label):
    if label not in M.SETS:
        raise M.Stop("DEPLOY_SET_UNKNOWN")
    if book.get("mldsa_precompile") != M.SETS[label] and "sets" not in book:
        raise M.Stop("DEPLOY_SET_MISMATCH")
    return dict(book)


def mutant_keeps_relayer(env):
    e = list(env)
    if not e[4] & 0x2:
        e[7] = 0
    return e


def mutant_mask_swapped(env):
    e = list(env)
    if not e[4] & 0x2:
        e[5] = 0
    if not e[4] & 0x1:
        e[7] = 0
    return e


if __name__ == "__main__":
    check(t_sets(M.set_entries), "set_entries: every row")
    check(not t_sets(mutant_ignores_mode), "mutant: set_entries without the mode check is caught")
    check(not t_sets(mutant_top_level), "mutant: set_entries reading the book's top level is caught")
    check(t_canon(M.canon_env), "canon_env: every row")
    check(not t_canon(mutant_keeps_relayer), "mutant: canon_env keeping an unbound relayer is caught")
    check(not t_canon(mutant_mask_swapped), "mutant: canon_env with the two bits swapped is caught")
    print(f"test_mldsa_on: {len(FAILS)} failure(s)")
    sys.exit(1 if FAILS else 0)
