#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""No chain: mldsa_on.py's set selection (each refusal by name beside its control, one field changed) and its envelope
canonicalisation (`MetaTxLib.canon`: a non-zero unbound relayer / fee recipient is signed as zero), and mldsa_on_pqz.py's
roll wait (bounded, `ROLL_WAIT`; `evm_mine` on anvil) and forge's filler bytes; each test run against a mutant of what it guards, which
it must catch.  python3 -I script/onchain/test_mldsa_on.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mldsa_on as M  # noqa: E402
import mldsa_on_pqz as Q  # noqa: E402

Q.M = M
Q._bind()

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


class Chain:
    """A fake RPC for `wait_roll`: the head moves `step` blocks per poll (0: stuck); anvil mines on `evm_mine`."""

    def __init__(self, chain, head, step):
        self.chain, self.head, self.step, self.mined, self.t = chain, head, step, 0, 0.0

    def rpc(self, method, params=()):
        if method == "eth_chainId":
            return hex(self.chain)
        if method == "evm_mine":
            self.mined += 1
            self.head += 1
            return "0x0"
        h = self.head
        self.head += self.step
        return hex(h)

    def sleep(self, s):
        self.t += s
        if self.t > 10_000:
            raise RuntimeError("HUNG")  # a wait without its bound

    def clock(self):
        return self.t


def t_wait(w):
    """True iff `w` (wait_roll) passes every row."""
    def run(chain, step, head=100):
        c = Chain(chain, head, step)
        try:
            return w(100, rpc=c.rpc, sleep=c.sleep, clock=c.clock), c
        except M.Stop as e:
            return str(e).split(":")[0], c
        except RuntimeError as e:
            return str(e), c
    moving, c1 = run(1337, 1)
    stuck, c2 = run(1337, 0)
    anvil, c3 = run(31337, 0)
    rows = [
        moving == 100 + Q.E.ROLL_AGE + 1 and c1.mined == 0,  # control: a live chain reaches b0 + 6, nothing mined
        stuck == "ROLL_WAIT" and 300 < c2.t <= 302,          # a stuck head: the named stop at the bound, not a hang
        anvil == 106 and c3.mined == 6,                      # anvil: the six blocks mined, then reached
        run(1337, 0, head=106)[0] == 106,                    # already there: no wait
    ]
    return all(rows)


def mutant_unbounded(b0, n=None, limit=300, rpc=None, sleep=None, clock=None):
    want = b0 + Q.E.ROLL_AGE + 1
    if int(rpc("eth_chainId"), 16) == 31337:
        for _ in range(want - int(rpc("eth_blockNumber"), 16)):
            rpc("evm_mine")
    while (h := int(rpc("eth_blockNumber"), 16)) < want:
        sleep(1)
    return h


def mutant_no_mine(b0, n=None, limit=300, rpc=None, sleep=None, clock=None):
    t0, want = clock(), b0 + Q.E.ROLL_AGE + 1
    while (h := int(rpc("eth_blockNumber"), 16)) < want:
        if clock() - t0 > limit:
            raise M.Stop("ROLL_WAIT")
        sleep(1)
    return h


def t_blob(b):
    x, y = b(0x7C01, 18_432), b(0x7C02, 18_432)
    lanes = [int.from_bytes(x[i:i + 8], "big") for i in range(0, len(x), 8)]
    return len(x) == 18_432 and len(b(1, 48)) == 48 and all(v < 1 << 40 for v in lanes) and any(v >> 32 for v in lanes) and x != y


if __name__ == "__main__":
    check(t_sets(M.set_entries), "set_entries: every row")
    check(not t_sets(mutant_ignores_mode), "mutant: set_entries without the mode check is caught")
    check(not t_sets(mutant_top_level), "mutant: set_entries reading the book's top level is caught")
    check(t_canon(M.canon_env), "canon_env: every row")
    check(not t_canon(mutant_keeps_relayer), "mutant: canon_env keeping an unbound relayer is caught")
    check(not t_canon(mutant_mask_swapped), "mutant: canon_env with the two bits swapped is caught")
    check(t_wait(Q.wait_roll), "wait_roll: every row")
    check(not t_wait(mutant_unbounded), "mutant: wait_roll without its bound is caught")
    check(not t_wait(mutant_no_mine), "mutant: wait_roll without evm_mine on anvil is caught")
    check(t_blob(Q.blob), "blob: forge's filler, every 64-bit lane < 2^40")
    check(not t_blob(lambda seed, n: b"".join(Q.E.kc(Q.W(seed), Q.W(i)) for i in range(0, n, 32))[:n]),
          "mutant: blob without the lane mask is caught")
    print(f"test_mldsa_on: {len(FAILS)} failure(s)")
    sys.exit(1 if FAILS else 0)
