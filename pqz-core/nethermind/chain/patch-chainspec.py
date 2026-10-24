#!/usr/bin/env python3
"""P6f: patch-chainspec.py <genesis.json> <engine-pqz.json> <timestamp> <out.json> [--testnet-reset]

Writes <out> = <genesis> with engine.Pqz = <engine-pqz.json> whose first schedule's timestamp is <timestamp>
(decimal or 0x hex; later schedules keep theirs and must be later). Refuses if engine.Pqz is already there or a
precompile address has an allocation. Prints the diff: exactly one added key, engine.Pqz.

The first timestamp must lie at least 5 minutes in the future (wall clock, as in add-schedule.py): an activation at a
block already made would change history and split a re-synced node from the chain (review CHAIN-02, 2026-10-19). Only
--testnet-reset activates at genesis, and there the timestamp must equal the genesis timestamp. Without it the first
timestamp must also lie after the genesis timestamp (a fresh chain whose genesis is still in the future: activating
at its genesis needs the reset params; review Minor-7, 2026-10-20).

--testnet-reset (path B: a fresh chain from this genesis, owner 2026-10-15) also sets three params that leave the
genesis block unchanged: eip4895TransitionTimestamp 1 (withdrawals from block 1: without them a follower rejects every
block of a chain with eip4844 at 0), maximumExtraDataSize 0xffff (Clique's 97 B extraData; the default 32 B makes a
follower reject every header) and maxCodeSizeTransition 0 (the 64 KiB code size from block 0, not from block 6432 of the
old history). It also sets the genesis gasLimit to 200,000,000 (0xbebc200, TODO "SCaaS testnet at the next reset",
plan fs3 Task 13): under Amsterdam (EIP-8037) a transaction's gas limit (regular + state) must fit the block gas limit,
and from the old 0x1000000 the 1/1024-per-block ramp took ~2.5 h to reach the 110 M a 64 KiB deploy needs. This changes
the genesis header, so the genesis hash (= chainUid, smartcontracts/evm/chain-uids.json) changes with the reset. A
genesis that already has engine.Pqz (the live chainspec) gets it replaced, on a reset only. --testnet-reset refuses any
chain but the SCaaS testnet (params.chainId 0x1dc6 = 7622; never 22776, the future mainnet). patch-chainspec.py --check
runs the self-check. Run with python3 -I."""
import difflib
import json
import os
import sys
import tempfile
import time

ADDR = ["000000000000000000000000000000005caa0f01", "000000000000000000000000000000005caa0012",
        "000000000000000000000000000000005caa0013"]
RESET = {"eip4895TransitionTimestamp": 1, "maximumExtraDataSize": "0xffff", "maxCodeSizeTransition": 0}
TESTNET = 7622  # the only chain --testnet-reset may touch (owner 2026-10-15; 22776 is the future mainnet)
RESET_GAS_LIMIT = "0xbebc200"  # 200,000,000 = config.json Blocks.TargetBlockGasLimit: no ramp after the reset


def main(src, eng, ts, out, *flags):
    reset = "--testnet-reset" in flags
    g = json.load(open(src))
    e = json.load(open(eng))
    if "Pqz" in g.get("engine", {}) and not reset:
        sys.exit("engine.Pqz already present")
    alloc = {k.lower().removeprefix("0x") for k in g.get("accounts", {})}
    if alloc & set(ADDR):
        sys.exit("a precompile address has an allocation")
    t = int(ts, 0)
    g0 = int(str(g["genesis"]["timestamp"]), 0)
    if reset and int(str(g["params"].get("chainId", "0")), 0) != TESTNET:
        sys.exit(f"--testnet-reset: chainId {g['params'].get('chainId')} is not the SCaaS testnet's {TESTNET} (0x1dc6)")
    if reset and t != g0:
        sys.exit(f"--testnet-reset: timestamp {t} is not the genesis timestamp {g0}")
    if not reset and t < time.time() + 300:
        sys.exit(f"timestamp {t} is not at least 5 minutes in the future (now {int(time.time())}); "
                 f"activation at genesis is --testnet-reset's")
    if not reset and t <= g0:
        sys.exit(f"timestamp {t} is not after the genesis timestamp {g0}; activation at genesis is --testnet-reset's")
    e["schedules"][0]["timestamp"] = hex(t)
    if any(int(str(s["timestamp"]), 0) <= t for s in e["schedules"][1:]):
        sys.exit("later schedules must be after the first")
    g2 = json.loads(json.dumps(g))
    g2["engine"]["Pqz"] = e
    if reset:
        g2["params"].update(RESET)
        g2["genesis"]["gasLimit"] = RESET_GAS_LIMIT
    a, b = json.dumps(g, indent=1, sort_keys=True).splitlines(), json.dumps(g2, indent=1, sort_keys=True).splitlines()
    d = [l for l in difflib.unified_diff(a, b, "genesis", "patched", lineterm="", n=0)]
    removed = [l for l in d if l.startswith("-") and not l.startswith("---")]
    changed = {k for k in set(g["params"]) | set(g2["params"]) if g["params"].get(k) != g2["params"].get(k)}
    header = {k for k in set(g["genesis"]) | set(g2["genesis"]) if g["genesis"].get(k) != g2["genesis"].get(k)}
    others = lambda x: {k: v for k, v in x["engine"].items() if k != "Pqz"}
    if set(g2) != set(g) or others(g2) != others(g) or header - ({"gasLimit"} if reset else set()) \
            or g2["accounts"] != g["accounts"] or changed - set(RESET if reset else {}):
        sys.exit("unexpected diff")
    json.dump(g2, open(out, "w"), indent=1)
    print(f"{out}: engine.Pqz {'replaced' if 'Pqz' in g['engine'] else 'added'} (first timestamp {t} = {hex(t)}, {len(e['schedules'])} schedule(s), "
          f"{len(e['schedules'][0]['pqz'])} rows); diff: {len([l for l in d if l.startswith('+') and not l.startswith('+++')])} added lines, "
          f"{len(removed)} removed; params changed: {', '.join(f'{k} {g['params'].get(k)} -> {g2['params'][k]}' for k in sorted(changed)) or 'none'}"
          f"; genesis header changed: {', '.join(f'{k} {g['genesis'].get(k)} -> {g2['genesis'][k]}' for k in sorted(header)) or 'none'}")


def check():
    """--check (review CHAIN-02): a future first timestamp passes, a past one or genesis without --testnet-reset is
    refused, and so is one at or before a still-future genesis; --testnet-reset takes exactly the genesis timestamp,
    sets the genesis gasLimit to 200 M and replaces an existing engine.Pqz (refused without it). Each refusal must give its expected reason (review Minor-6)."""
    now = int(time.time())
    with tempfile.TemporaryDirectory() as d:
        src, eng, out = (os.path.join(d, f) for f in ("g.json", "e.json", "o.json"))
        src2 = os.path.join(d, "g2.json")  # a fresh chain whose genesis is still an hour ahead
        for f, g0 in ((src, "0x0"), (src2, hex(now + 3600))):
            json.dump({"params": {"networkID": 1, "chainId": "0x1dc6"}, "engine": {"clique": {}}, "genesis": {"timestamp": g0},
                       "accounts": {"0x1": {}}}, open(f, "w"))
        json.dump({"schedules": [{"timestamp": "0x0", "pqz": []}]}, open(eng, "w"))
        main(src, eng, str(now + 900), out)
        main(src, eng, "0", out, "--testnet-reset")
        assert json.load(open(out))["genesis"]["gasLimit"] == RESET_GAS_LIMIT
        # a reset of a chain that already has engine.Pqz (the live chainspec, plan fs3 Task 13) replaces it
        live, out2 = os.path.join(d, "live.json"), os.path.join(d, "o2.json")
        os.replace(out, live)
        json.dump({"schedules": [{"timestamp": "0x0", "pqz": [{"op": 1}]}]}, open(eng, "w"))
        main(live, eng, "0", out2, "--testnet-reset")
        assert json.load(open(out2))["engine"]["Pqz"]["schedules"][0]["pqz"] == [{"op": 1}]
        try:
            main(live, eng, str(now + 900), out2)
            raise AssertionError("engine.Pqz replaced without --testnet-reset")
        except SystemExit as e:
            assert e.code == "engine.Pqz already present", e.code
            print(f"  refused (engine.Pqz present, no --testnet-reset): {e.code}")
        main(src2, eng, str(now + 3600), out, "--testnet-reset")
        other = os.path.join(d, "g22776.json")  # review amsterdam-node L2: a reset of any other chain is refused
        g = json.load(open(src))
        g["params"]["chainId"] = hex(22776)
        json.dump(g, open(other, "w"))
        try:
            main(other, eng, "0", out, "--testnet-reset")
            raise AssertionError("reset of chain 22776")
        except SystemExit as e:
            assert "not the SCaaS testnet's 7622" in str(e.code), e.code
            print(f"  refused (chainId 22776, --testnet-reset): {e.code}")
        main(src2, eng, str(now + 3601), out)
        for g, bad, why in ((src, [str(now - 60)], "5 minutes"), (src, [str(now + 60)], "5 minutes"),
                            (src, ["0"], "5 minutes"), (src, [str(now + 900), "--testnet-reset"], "not the genesis"),
                            (src2, [str(now + 900)], "not after the genesis"),
                            (src2, [str(now + 3600)], "not after the genesis")):
            try:
                main(g, eng, bad[0], out, *bad[1:])
                raise AssertionError(bad)
            except SystemExit as e:
                assert isinstance(e.code, str) and why in e.code, (bad, e.code)
                print(f"  refused ({' '.join(bad)}): {e.code}")
    print("patch-chainspec --check: ok")


if __name__ == "__main__":
    check() if sys.argv[1:] == ["--check"] else main(*sys.argv[1:])
