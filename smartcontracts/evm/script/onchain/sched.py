# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""matrix.sh's parallel plan on a remote target (owner 2026-11-16: "many transactions per block, groups in parallel").
Stdlib only (python3 -I).
  sched.py plan <group> [<group> ...]
      one line per group in run order: `<wave> <group> <keys>`, the groups of a wave run at the same time; <keys> is `none`
      (eth_calls only), `default` (the target's own keys: the RescueVault's admin and rescuer, wraplimits' state; at most
      one such group per wave) or `mnemonic:<i>,<i+1>,<i+2>` (ONCHAIN_K1..K3 from those indexes of the testnet mnemonic
      file, PRIVATE_KEY = K1; a group's indexes fixed by its name, never another group's). A group waits for the groups it
      needs that are in the list (AFTER); `views` reads the other groups' books, so it runs alone after them (wraplimits
      excepted), `verify` after every group. A list
      with a group before one it needs is refused by name (GROUP_ORDER), an unknown group too (GROUP_UNKNOWN).
  FUND_KEY=<hex> sched.py fund <rpc> <amount wei> <address> [<address> ...]
      tops each address up to <amount> from FUND_KEY's account in one batch: consecutive nonces sent at once, then every
      receipt awaited (bounded), status 1 checked, a named stop at the first failure (FUND_FAILED); one line per transfer.
  sched.py self-test
Never a key: indexes and addresses only; FUND_KEY only from the environment."""
import sys

ALL = ("tokens", "gov", "dex", "liquidity", "misc", "zether", "pq", "pqoff", "verifiers", "mldsaalt", "pqchat", "rescue",
       "pqzkeys", "pqzwallet", "views", "wraplimits", "verify")
AFTER = {"pqzwallet": ("pqzkeys",),  # its factory and holders
         "pqoff": ("pq",),  # both write e2e's own book deployments/<key>-pqz.json
         "views": tuple(g for g in ALL if g not in ("views", "wraplimits", "verify")),  # every group's book (wraplimits:
         # its own outputs, after views in the default list)
         "verify": ALL}  # every contract of the chain
NONE = {"verifiers", "views", "verify"}  # eth_calls only
DEFAULT = {"rescue", "wraplimits"}  # the target's own keys (genesis alloc / the state of an earlier call)
BASE = 10  # mnemonic indexes 0-3 are the deployer and the sequential matrix's keys


class Refused(SystemExit):
    """A named refusal: the message starts with its name."""


def keys(g):
    if g in NONE:
        return "none"
    if g in DEFAULT:
        return "default"
    i = BASE + 3 * ALL.index(g)
    return f"mnemonic:{i},{i + 1},{i + 2}"


def plan(groups):
    for g in groups:
        if g not in ALL:
            raise Refused(f"GROUP_UNKNOWN: {g!r} is not a matrix group")
    for i, g in enumerate(groups):
        late = [h for h in groups[i + 1:] if h in AFTER.get(g, ()) and h != g]
        if late:
            raise Refused(f"GROUP_ORDER: {g} needs {', '.join(late)} first (put it after them)")
    done, out, wave = set(), [], 0
    left = list(dict.fromkeys(groups))
    while left:
        wave += 1
        now, used = [], set()
        for g in left:
            need = [h for h in AFTER.get(g, ()) if h in left and h != g]
            if need or (g in ("views", "verify") and now):
                continue
            k = keys(g)
            if k != "none" and k in used:
                continue
            now.append(g)
            used.add(k)
            if g in ("views", "verify"):
                break
        out += [(wave, g, keys(g)) for g in now]
        left = [g for g in left if g not in now]
        done.update(now)
    return out


def self_test():
    bad = []

    def want(c, what):
        if not c:
            bad.append(what)

    def refused(name, groups):
        try:
            plan(groups)
        except Refused as e:
            return str(e).startswith(name + ":")
        return False

    rest = ["pq", "pqoff", "verifiers", "mldsaalt", "pqchat", "rescue", "pqzkeys", "pqzwallet", "views"]
    for gs in (rest, list(ALL), ["rescue", "wraplimits", "tokens", "gov"], ["pqoff"], ["views"]):
        p = plan(gs)
        want(sorted(g for _, g, _ in p) == sorted(set(gs)), f"every group once: {gs}")
        pos = {g: w for w, g, _ in p}
        for g in pos:
            for h in AFTER.get(g, ()):
                if h in pos and h != g:
                    want(pos[h] < pos[g], f"{h} before {g}")
        for w in set(pos.values()):
            ks = [k for x, _, k in p if x == w and k != "none"]
            want(len(ks) == len(set(ks)), f"no two groups of wave {w} share a key set: {ks}")
        idx = [int(i) for _, _, k in p if k.startswith("mnemonic:") for i in k[9:].split(",")]
        want(len(idx) == len(set(idx)) and min(idx or [BASE]) >= BASE, f"no mnemonic index twice, none below {BASE}")
        want(all([x for x, _, _ in p].count(w) == 1 and all(pos[h] < w for h in AFTER["views"] if h in pos)
                 for w, g, _ in p if g == "views"), "views alone, after every group whose book it reads")
    p = {g: w for w, g, _ in plan(rest)}
    want(p["pq"] == p["verifiers"] == p["mldsaalt"] == p["pqchat"] == p["rescue"] == p["pqzkeys"] == 1, "the independent groups at once")
    want(p["pqoff"] == p["pqzwallet"] == 2 and p["views"] == 3, "pqoff and pqzwallet next, views last")
    p = {g: w for w, g, _ in plan(["rescue", "wraplimits"])}
    want(p["rescue"] != p["wraplimits"], "two groups on the target's own keys never at once")
    want(refused("GROUP_ORDER", ["pqzwallet", "pqzkeys"]), "pqzwallet before pqzkeys refused")
    want(refused("GROUP_ORDER", ["views", "tokens"]), "views before another group refused")
    want(refused("GROUP_ORDER", ["pqoff", "pq"]), "pqoff before pq refused")
    want(refused("GROUP_UNKNOWN", ["tokens", "nope"]), "an unknown group refused")
    print("sched self-test: " + ("ok" if not bad else "FAIL " + "; ".join(bad)))
    return 1 if bad else 0


def fund(rpc_url, amount, addrs):
    import os, time
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../pqz"))
    import e2e as E  # noqa: E402  (rpc, legacy_tx, address)
    E.RPC = rpc_url
    key = int(os.environ["FUND_KEY"], 16)
    frm = E.address(key)
    chain = int(E.rpc("eth_chainId"), 16)
    nonce = int(E.rpc("eth_getTransactionCount", [frm, "pending"]), 16)
    base = int(E.rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    need = [(a, amount - int(E.rpc("eth_getBalance", [a, "latest"]), 16)) for a in addrs]
    need = [(a, v) for a, v in need if v > 0]
    have = int(E.rpc("eth_getBalance", [frm, "latest"]), 16)
    if sum(v for _, v in need) + 300_000 * len(need) * (2 * base + 10**9) > have:
        raise Refused(f"FUND_SHORT: {frm} holds {have / 1e18:.3f} ETH, the top-ups need {sum(v for _, v in need) / 1e18:.3f}")
    hs = []
    for a, v in need:  # explicit gas: a new account's state gas (EIP-8037)
        raw = E.legacy_tx(key, nonce, 2 * base + 10**9, 300_000, a, v, b"", chain)
        hs.append((a, v, E.rpc("eth_sendRawTransaction", ["0x" + raw.hex()])))
        nonce += 1
    t0 = time.time()
    for a, v, h in hs:
        while not (r := E.rpc("eth_getTransactionReceipt", [h])):
            if time.time() - t0 > 600:
                raise Refused(f"FUND_FAILED: no receipt for {h} ({a}) in 600 s")
            time.sleep(2)
        if r["status"] != "0x1":
            raise Refused(f"FUND_FAILED: {h} ({a}) status {r['status']}")
        print(f"[fund] {a} +{v / 1e18:.3f} ETH tx {h} block {int(r['blockNumber'], 16)}")
    print(f"[fund] ok {len(hs)} transfers from {frm} ({len(addrs) - len(hs)} already funded)")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["plan"] and len(a) > 1:
        for w, g, k in plan(a[1:]):
            print(w, g, k)
    elif a[:1] == ["fund"] and len(a) >= 4:
        fund(a[1], int(a[2]), a[3:])
    elif a == ["self-test"]:
        sys.exit(self_test())
    else:
        sys.exit(__doc__)
