#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""deploy.sh evm's first step (owner 2026-11-15; the gen-1 kind rule, owner ruling 2026-10-31 option (a)): the verifiers whose
constructors probe the chain's own precompiles, which forge's EVM (Deploy.s.sol's simulation) does not have, deployed on the
real chain BEFORE Deploy.s.sol, with script/pqz/e2e.py's builders and probes (P6g D15), no new format:
  - `PqzKeyVerifier` (`pqz-mlwe` 0x0142) on the `PQZ` precompile, the set's PQZL id and its self-test R_REG vector
    (statement_register.json row 0, proof_pqzl.json row 4: the constructor's probe), when the precompile answers its
    OP_SELFTEST with the set's hash; after the deploy `isSupportedOnThisChain()` must be true;
  - with `MLDSA_PRECOMPILE=on` (the default; owner 2026-11-15, MD-6 / MD-7): `MldsaVerifier(kind, candidate, probe valid, probe
    invalid)` for `mldsa44` 0x0130, `mldsa65` 0x0131 and `mldsa87` 0x0134, each on the first candidate (the chain's own
    0x...5caa0012 / 13 / 14; EIP-8355's Draft 0x12 / 0x13 / 0x14 after them only under the chain's probe_draft_precompiles flag
    with the owner's confirmation in the book, then with the fuller probe: CTR-UA-69, DeployBase._mldsaCandidates) that answers that level's pq_kat.json
    EIP-8355 probe exactly (valid => the word 1, flipped => 0); after the deploy `PRECOMPILE()` must be that candidate, and
    `verify` of the level's pq_kat.json row with gas cap + cap / 63 (DeployBase's precompile-path cap, the registry's hold)
    must answer true, its flipped message false (F-6); `MLDSA_PRECOMPILE=off`: none of them (DeployBase builds the cache path).
Each by CREATE2 through the deterministic deployer with DEPLOY_SALT (e2e.py's Deployer.deploy2 = DeployBase's `new X{salt}`,
NET-EVM-05): the address follows from the init code and the salt; code already there is reused. A precompile that does not
answer: that verifier is skipped by name (a chain without it: anvil), and DeployBase's gate requires nothing of it.
  PRIVATE_KEY=<deployer> [DEPLOY_SALT=…] [FOUNDRY_OUT=out] python3 -I script/pq_verifiers.py <rpc>
stdout: `PQZ_KEY_VERIFIER=<address>` / `MLDSA44_VERIFIER=<address>` / `MLDSA65_VERIFIER=` / `MLDSA87_VERIFIER=` lines for deploy.sh, and `[deploy] pq-verifiers …` progress
lines; e2e.py's own check lines go to stderr. Never a key. Exit 1 on a failed deploy or check."""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "pqz"))
import e2e as E  # noqa: E402

E.log = lambda s: (print(s, file=sys.stderr, flush=True), E.LOG.append(s))  # e2e.py's lines off stdout
E.OUT_DIR = os.environ.get("FOUNDRY_OUT", "out")
# kind, name, candidates (DeployBase._mldsaCandidates), the precompile-path cap (DeployBase.CAP_MLDSA<x>_PRECOMPILE)
MLDSA = ((0x0130, "mldsa44", 200_000), (0x0131, "mldsa65", 200_000), (0x0134, "mldsa87", 250_000))


def candidates(i, draft=False):
    """CTR-UA-69 (owner R9): the chain's own address first (the Final EIP addresses with it: none for ML-DSA today); EIP-8355's
    Draft 0x12 / 0x13 / 0x14 after it, only when `draft_allowed`."""
    own = "0x" + f"{0x5CAA0012 + i:040x}"
    return (own, "0x" + f"{0x12 + i:040x}") if draft else (own,)


def draft_allowed(row, book):
    """The chain row's `probe_draft_precompiles` (chain-uids.json, owner C5) with the owner's confirmation in the chain's book
    (`probe_draft_precompiles_owner`, its reason); the flag without it: DRAFT_PROBE_UNCONFIRMED."""
    if not (row or {}).get("probe_draft_precompiles"):
        return False
    if not (book or {}).get("probe_draft_precompiles_owner"):
        raise SystemExit(
            "[deploy] pq-verifiers FAIL DRAFT_PROBE_UNCONFIRMED: chain-uids.json sets probe_draft_precompiles, the book has "
            "no probe_draft_precompiles_owner (CTR-UA-69)"
        )
    return True


def edge_rows(k, name):
    """The fuller probe's extra rows (CTR-UA-69): each pq_kat.json mutation of level `name` as its EIP-8355 input
    `pk ‖ sig ‖ pq_msg` (pq_msg = keccak256(TAG(kind) ‖ ua_msg), PqUA.pqMessage), each to be answered with the word 0."""
    t = E.keccak256(f"scaas.ua.{name}.v1".encode())
    b = lambda h: bytes.fromhex(h.removeprefix("0x"))  # noqa: E731
    return [b(m["pk"]) + b(m["sig"]) + E.keccak256(t + b(m["ua_msg"])) for m in k["mutations"]]


def say(s):
    print(f"[deploy] pq-verifiers {s}", flush=True)


E_STATE_GAS_PER_BYTE = 1530  # EIP-8037 code deposit, DeployBase.STATE_GAS_PER_BYTE


def gate(D, name, args, src=None):
    """The release gas gate of `name` before its CREATE2 (NET-EVM-06), by the declared `RELEASE_GAS_GATE` as DeployBase's
    `_requireReleaseGas(name, to, data)`: `testnet`, e2e.py's formula; `public`, the declared code limit (`CHAIN_CODE_LIMIT`,
    default 65,536), then the transaction measured: `eth_estimateGas` (regular + state) x 1.05 within the block gas limit,
    and regular x 1.05 < 2^24, regular bounded above by the estimate less the code deposit (runtime x 1,530, EIP-8037),
    which `eth_estimateGas` does not give apart. Code already at the address: nothing is sent, nothing gated."""
    gate = os.environ.get("RELEASE_GAS_GATE", "testnet")
    if gate != "public":
        return E.require_release_gas(name)
    j = json.load(open(os.path.join(E.EVM, E.OUT_DIR, (src or name) + ".sol", name + ".json")))
    runtime = len(j["deployedBytecode"]["object"].removeprefix("0x")) // 2
    limit_code = int(os.environ.get("CHAIN_CODE_LIMIT", "65536"))
    if runtime > limit_code:
        raise SystemExit(
            f"[deploy] pq-verifiers FAIL {name} runtime {runtime:,} B > CHAIN_CODE_LIMIT {limit_code:,} (NET-EVM-06)"
        )
    init = D.linked(name, src)[0] + args
    if E.rpc("eth_getCode", [E.create2_address(E.CREATE2_DEPLOYER, E.DEPLOY_SALT, init), "latest"]) != "0x":
        return
    tx = {"from": D.s.addr, "to": E.CREATE2_DEPLOYER, "data": "0x" + (E.DEPLOY_SALT + init).hex()}
    total = int(E.rpc("eth_estimateGas", [tx]), 16)
    regular = max(total - runtime * E_STATE_GAS_PER_BYTE, 0)
    limit = int(E.rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16)
    if regular * 105 // 100 >= 1 << 24:
        raise SystemExit(
            f"[deploy] pq-verifiers FAIL {name} release: regular gas x 1.05 = {regular * 105 // 100:,} >= 2^24 "
            "(EIP-7825, NET-EVM-06)"
        )
    if limit < total * 105 // 100:
        raise SystemExit(
            f"[deploy] pq-verifiers FAIL block gas limit {limit:,} < {total * 105 // 100:,} asked by the {name} "
            "release (measured regular + state x 1.05, NET-EVM-06)"
        )
    say(f"gate public {name}: runtime {runtime:,} B, estimate {total:,}, regular <= {regular:,}, block {limit:,}")


def main(rpc):
    E.RPC = rpc
    chain = int(E.rpc("eth_chainId"), 16)
    E.CTX[:] = [chain, bytes.fromhex(E.rpc("eth_getBlockByNumber", ["0x0", False])["hash"][2:])]
    sd = E.Sender(int(os.environ["PRIVATE_KEY"], 16))
    D = E.Deployer(sd)
    out = {}
    only_ml = os.environ.get("PQ_VERIFIERS") == "mldsa"  # the matrix's `mldsaalt` group: the ML-DSA verifiers only
    want = json.load(open(os.path.join(E.K.VEC_DIR, "selftest.json")))["hash"]
    try:
        st = E.call(E.PQZ, bytes.fromhex("0600000000"))
    except RuntimeError:
        st = "0x"
    if only_ml:
        pass
    elif st[2:] != want:
        say(f"skip PqzKeyVerifier: no PQZ precompile at {E.PQZ} (OP_SELFTEST {st[:18]}, want {want[:16]}...)")
    else:
        reg_stmt = bytes.fromhex(
            json.load(open(os.path.join(E.K.VEC_DIR, "statement_register.json")))["rows"][0]["stmt"]
        )
        reg_proof = bytes.fromhex(json.load(open(os.path.join(E.K.VEC_DIR, "proof_pqzl.json")))["rows"][4]["proof"])
        args = E.encs(["w", "w", "b", "w", "b"], [E.PQZ, E.PQZL_ID, reg_stmt[96:], reg_stmt[64:96], reg_proof])
        gate(D, "PqzKeyVerifier", args)
        a = D.deploy2("PqzKeyVerifier", args, "pqz_key_verifier")
        ok = E.words(E.call(a, E.cd("isSupportedOnThisChain()", [])))[0][-1] == 1
        E.check(ok, f"PqzKeyVerifier {a}: isSupportedOnThisChain()")
        if not ok:
            raise SystemExit(1)
        out["PQZ_KEY_VERIFIER"] = a
        say(f"PqzKeyVerifier ok {a} (PQZ {E.PQZ}, PQZL {E.PQZL_ID.hex()[:16]}...)")

    def held_call(to, data, gas):
        """`to`'s answer to `data` with `gas` for the call itself, as the registry holds it (F-6), by an eth_call to code
        put at a throwaway address by state override (nothing deployed): STATICCALL(gas, to, calldata) and its success,
        return-data size and first word. The transaction's own gas is not the hold: a chain with the calldata floor
        (EIP-7623 / EIP-7976) refuses an eth_call whose gas is below the floor of its calldata (reset 5, 2026-11-16: the
        ML-DSA-44 KAT verify, 3,812 B of calldata, "gas below floor data cost: have 203174, want 265112"). The word only for
        a good STATICCALL returning 32 bytes, else -1."""
        at = "0x" + E.keccak256(b"scaas.pq_verifiers.held-call")[12:].hex()
        code = (
            "365f5f37"
            + "60205f365f73"
            + to[2:].lower()
            + "63"
            + f"{gas:08x}"
            + "fa"
            + "602052"
            + "3d604052"
            + "60605ff3"
        )
        # the outer call's gas: the block's limit, at most EIP-7825's per-transaction cap (eth_call too on a node with it)
        tx = min(int(E.rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16), 1 << 24)
        w = E.words(
            E.rpc(
                "eth_call",
                [{"to": at, "data": "0x" + data.hex(), "gas": hex(tx)}, "latest", {at: {"code": "0x" + code}}],
            )
        )
        ok, rds, word = (int.from_bytes(x, "big") for x in (w[1], w[2], w[0]))
        return word if ok == 1 and rds == 32 else -1

    mode = os.environ.get("MLDSA_PRECOMPILE", "on")
    if mode not in ("on", "off"):
        raise SystemExit("[deploy] pq-verifiers FAIL MLDSA_PRECOMPILE: on or off")
    kat = json.load(open(os.path.join(E.EVM, "../vectors/ua/pq_kat.json")))["kinds"]
    sys.path.insert(0, HERE)
    import deploybook

    uid = "0x" + E.CTX[1].hex()
    row = next((r for r in deploybook.rows() if r["chainId"] == chain and r["chainUid"].lower() == uid), None)
    bp = os.path.join(deploybook.EVM, "deployments", f"{row['key']}.json") if row else None
    draft = draft_allowed(row, json.load(open(bp)) if bp and os.path.exists(bp) else None)
    for i, (kind, name, cap) in enumerate(MLDSA):
        if mode == "off":
            say(f"skip MldsaVerifier({kind:#06x}): MLDSA_PRECOMPILE=off (the registry's expanded-key cache)")
            continue
        k = kat[name]
        valid, bad = bytes.fromhex(k["eip8355_probe_valid"][2:]), bytes.fromhex(k["eip8355_probe_invalid"][2:])

        def answers(at):
            # a Draft address: the fuller probe, every mutation row too (CTR-UA-69)
            neg = [bad] + (edge_rows(k, name) if int(at, 16) < 0x100 else [])
            try:
                return E.call(at, valid) == "0x" + "00" * 31 + "01" and all(E.call(at, x) == "0x" + "00" * 32 for x in neg)
            except RuntimeError:
                return False

        cs = candidates(i, draft)
        cand = next((c for c in cs if answers(c)), None)
        if cand is None:
            say(f"skip MldsaVerifier({kind:#06x}): no {name} precompile answers the KAT probe at {', '.join(cs)}")
            continue
        args = E.encs(["w", "w", "b", "b"], [kind, cand, valid, bad])
        gate(D, "MldsaVerifier", args, src="MlDsa")
        a = D.deploy2("MldsaVerifier", args, f"{name}_verifier", src="MlDsa")
        got = "0x" + E.words(E.call(a, E.cd("PRECOMPILE()", [])))[0][12:].hex()
        ok = got == cand.lower()
        E.check(ok, f"MldsaVerifier({kind:#06x}) {a}: PRECOMPILE() = {got}")
        # F-6: the precompile path verifies the level's KAT row within the registry's hold of its cap, and refuses it flipped
        msg = bytes.fromhex(k["ua_msg"][2:])
        for m, want in ((msg, 1), (bytes(b ^ 0xFF for b in msg), 0)):
            data = E.cd(
                "verify(bytes,bytes32,bytes)",
                ["b", "w", "b"],
                bytes.fromhex(k["pk"][2:]),
                m,
                bytes.fromhex(k["sig"][2:]),
            )
            try:
                verdict = held_call(a, data, cap + cap // 63)
            except RuntimeError:
                verdict = -1
            good = verdict == want
            ok = ok and good
            E.check(
                good,
                f"MldsaVerifier({kind:#06x}) {a}: verify of the KAT row{' flipped' if not want else ''} within "
                f"{cap + cap // 63:,} gas = {verdict} (want {want})",
            )
        if not ok:
            raise SystemExit(1)
        out[f"MLDSA{name[5:]}_VERIFIER"] = a
        say(f"MldsaVerifier({kind:#06x}) ok {a} (precompile {cand})")
    if E.FAILS:
        raise SystemExit(f"[deploy] pq-verifiers FAIL {E.FAILS[0]}")
    for n, a in out.items():
        print(f"{n}={a}")


# The deploy's differential probe of a later generation (spec 2026-11-19-registry-verify-only-kinds §9, F4, R5; plan Task 13): per
# row, the holder's entry on the kind's home verifier and the verify-only verifier's `verify`, each by `eth_call` through the node
# list under strict majority (ARCH-POS-15). The holder on a precompile: `verify(pk, ua_msg, sig)`; on the cache: each
# `expandedKeyPart(pk, p)`, concatenated, then `verifyExpanded(ek, ua_msg, sig)` (never `verify` on the FIPS key: over 2^24 for
# ML-DSA-65 / -87). Any verdict that differs from the other or from the row's `valid` stops before broadcast, with the rows.
#   python3 -I script/pq_verifiers.py differential <rpc>[,<rpc>…] <kind> <home verifier> <verify-only verifier> <parts>
# (<parts>: the home's `expandedKeyParts()`, 0 on a precompile). UNAUDITED tooling.
SEL_VERIFY, SEL_PART, SEL_EXPANDED = "024ad318", "b733b5e4", "6e2fe976"


class DiffError(Exception):
    pass


def abi_args(*args):
    """ABI encoding of `args`: ("w", 32-byte word | int) or ("b", bytes)."""
    head, tail, n = [], b"", 32 * len(args)
    for t, v in args:
        if t == "w":
            head.append(v if isinstance(v, bytes) else int(v).to_bytes(32, "big"))
        else:
            head.append((n + len(tail)).to_bytes(32, "big"))
            tail += len(v).to_bytes(32, "big") + v + b"\0" * (-len(v) % 32)
    return b"".join(head) + tail


def abi_bytes(ret):
    """The one `bytes` an ABI return holds."""
    o = int.from_bytes(ret[:32], "big")
    n = int.from_bytes(ret[o : o + 32], "big")
    return ret[o + 32 : o + 32 + n]


def majority(nodes, to, data, what):
    """The strict majority's answer of `eth_call(to, data)` over `nodes` (callables -> bytes, None on an error)."""
    answers = [n(to, data) for n in nodes]
    for a in answers:
        if 2 * answers.count(a) > len(answers):
            return a
    raise DiffError(f"GEN_DIFFERENTIAL_NODES: no strict majority on {what}")


def verdict(ret):
    return ret is not None and len(ret) == 32 and int.from_bytes(ret, "big") == 1


def differential(nodes, home, vo, parts, rows):
    """`rows`: (what, pk, ua_msg, sig, valid). Returns [(what, holder, verify-only, valid)]; DiffError on any difference."""
    out, ek = [], {}
    for what, pk, msg, sig, valid in rows:
        if parts == 0:
            h = verdict(majority(nodes, home, bytes.fromhex(SEL_VERIFY) + abi_args(("b", pk), ("w", msg), ("b", sig)), what))
        else:
            if pk not in ek:
                ek[pk] = b"".join(
                    abi_bytes(majority(nodes, home, bytes.fromhex(SEL_PART) + abi_args(("b", pk), ("w", p)), f"part {p}") or b"")
                    for p in range(parts)
                )
            data = bytes.fromhex(SEL_EXPANDED) + abi_args(("b", ek[pk]), ("w", msg), ("b", sig))
            h = verdict(majority(nodes, home, data, what))
        v = verdict(majority(nodes, vo, bytes.fromhex(SEL_VERIFY) + abi_args(("b", pk), ("w", msg), ("b", sig)), what))
        out.append((what, h, v, valid))
    bad = [r for r in out if not r[1] == r[2] == r[3]]
    if bad:
        raise DiffError(f"GEN_DIFFERENTIAL_MISMATCH: rows (what, holder, verify-only, valid) {bad}: to the owner (R5)")
    return out


def kat_rows(name):
    """The level's pq_kat.json rows: the valid one and its mutations."""
    k = json.load(open(os.path.join(E.EVM, "..", "vectors", "ua", "pq_kat.json")))["kinds"][name]
    b = lambda h: bytes.fromhex(h.removeprefix("0x"))  # noqa: E731
    rows = [("valid", b(k["pk"]), b(k["ua_msg"]), b(k["sig"]), True)]
    return rows + [(m["what"], b(m["pk"]), b(m["ua_msg"]), b(m["sig"]), bool(m["valid"])) for m in k["mutations"]]


def rpc_call(url):
    import urllib.request

    def call(to, data):
        body = {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": "0x" + data.hex()}, "latest"]}
        req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            j = json.load(r)
        return None if "error" in j else bytes.fromhex(j["result"].removeprefix("0x"))

    return call


if __name__ == "__main__" and sys.argv[1:2] == ["differential"]:
    urls, kind, home, vo, parts = sys.argv[2].split(","), int(sys.argv[3], 0), sys.argv[4], sys.argv[5], int(sys.argv[6])
    name = {0x0130: "mldsa44", 0x0131: "mldsa65", 0x0134: "mldsa87"}[kind]
    try:
        for r in differential([rpc_call(u) for u in urls], home, vo, parts, kat_rows(name)):
            say(f"differential {name} {r[0]}: holder {r[1]}, verify-only {r[2]}, valid {r[3]}")
    except DiffError as e:
        say(f"FAIL {e}")
        sys.exit(1)
elif __name__ == "__main__":
    main(*sys.argv[1:])
