#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""deploy.sh evm's first step (owner 2026-11-15; the gen-1 kind rule, owner ruling 2026-10-31 option (a)): the verifiers whose
constructors probe the chain's own precompiles, which forge's EVM (Deploy.s.sol's simulation) does not have, deployed on the
real chain BEFORE Deploy.s.sol, with script/pqz/e2e.py's builders and probes (P6g D15), no new format:
  - `PqzKeyVerifier` (`pqz-mlwe` 0x0142) on the `PQZ` precompile, the set's PQZL id and its self-test R_REG vector
    (statement_register.json row 0, proof_pqzl.json row 4: the constructor's probe), when the precompile answers its
    OP_SELFTEST with the set's hash; after the deploy `isSupportedOnThisChain()` must be true;
  - `MldsaVerifier(0x0134, candidate, probe valid, probe invalid)` (`mldsa87`) on the first candidate (0x14, then the SCaaS
    testnet's 0x...5caa0014, DeployBase._mldsa87Precompile's) that answers pq_kat.json's mldsa87 EIP-8355 probe exactly
    (valid => the word 1, flipped => 0); after the deploy `PRECOMPILE()` must be that candidate.
Each by CREATE2 through the deterministic deployer with DEPLOY_SALT (e2e.py's Deployer.deploy2 = DeployBase's `new X{salt}`,
NET-EVM-05): the address follows from the init code and the salt; code already there is reused. A precompile that does not
answer: that verifier is skipped by name (a chain without it: anvil), and DeployBase's gate requires nothing of it.
  PRIVATE_KEY=<deployer> [DEPLOY_SALT=…] [FOUNDRY_OUT=out] python3 -I script/pq_verifiers.py <rpc>
stdout: `PQZ_KEY_VERIFIER=<address>` / `MLDSA87_VERIFIER=<address>` lines for deploy.sh, and `[deploy] pq-verifiers …` progress
lines; e2e.py's own check lines go to stderr. Never a key. Exit 1 on a failed deploy or check."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "pqz"))
import e2e as E  # noqa: E402

E.log = lambda s: (print(s, file=sys.stderr, flush=True), E.LOG.append(s))  # e2e.py's lines off stdout
E.OUT_DIR = os.environ.get("FOUNDRY_OUT", "out")
ML87_CANDIDATES = ("0x0000000000000000000000000000000000000014", "0x000000000000000000000000000000005caa0014")


def say(s):
    print(f"[deploy] pq-verifiers {s}", flush=True)


def main(rpc):
    E.RPC = rpc
    chain = int(E.rpc("eth_chainId"), 16)
    E.CTX[:] = [chain, bytes.fromhex(E.rpc("eth_getBlockByNumber", ["0x0", False])["hash"][2:])]
    sd = E.Sender(int(os.environ["PRIVATE_KEY"], 16))
    D = E.Deployer(sd)
    out = {}
    want = json.load(open(os.path.join(E.K.VEC_DIR, "selftest.json")))["hash"]
    try:
        st = E.call(E.PQZ, bytes.fromhex("0600000000"))
    except RuntimeError:
        st = "0x"
    if st[2:] != want:
        say(f"skip PqzKeyVerifier: no PQZ precompile at {E.PQZ} (OP_SELFTEST {st[:18]}, want {want[:16]}...)")
    else:
        E.require_release_gas("PqzKeyVerifier")
        reg_stmt = bytes.fromhex(json.load(open(os.path.join(E.K.VEC_DIR, "statement_register.json")))["rows"][0]["stmt"])
        reg_proof = bytes.fromhex(json.load(open(os.path.join(E.K.VEC_DIR, "proof_pqzl.json")))["rows"][4]["proof"])
        a = D.deploy2("PqzKeyVerifier", E.encs(["w", "w", "b", "w", "b"],
                                                [E.PQZ, E.PQZL_ID, reg_stmt[96:], reg_stmt[64:96], reg_proof]), "pqz_key_verifier")
        ok = E.words(E.call(a, E.cd("isSupportedOnThisChain()", [])))[0][-1] == 1
        E.check(ok, f"PqzKeyVerifier {a}: isSupportedOnThisChain()")
        if not ok:
            raise SystemExit(1)
        out["PQZ_KEY_VERIFIER"] = a
        say(f"PqzKeyVerifier ok {a} (PQZ {E.PQZ}, PQZL {E.PQZL_ID.hex()[:16]}...)")
    k = json.load(open(os.path.join(E.EVM, "../vectors/ua/pq_kat.json")))["kinds"]["mldsa87"]
    valid, bad = bytes.fromhex(k["eip8355_probe_valid"][2:]), bytes.fromhex(k["eip8355_probe_invalid"][2:])

    def answers(at):
        try:
            return E.call(at, valid) == "0x" + "00" * 31 + "01" and E.call(at, bad) == "0x" + "00" * 32
        except RuntimeError:
            return False

    cand = next((c for c in ML87_CANDIDATES if answers(c)), None)
    if cand is None:
        say(f"skip MldsaVerifier(0x0134): no ML-DSA-87 precompile answers the KAT probe at {', '.join(ML87_CANDIDATES)}")
    else:
        E.require_release_gas("MldsaVerifier")
        a = D.deploy2("MldsaVerifier", E.encs(["w", "w", "b", "b"], [0x0134, cand, valid, bad]), "mldsa87_verifier", src="MlDsa")
        got = "0x" + E.words(E.call(a, E.cd("PRECOMPILE()", [])))[0][12:].hex()
        ok = got == cand.lower()
        E.check(ok, f"MldsaVerifier(0x0134) {a}: PRECOMPILE() = {got}")
        if not ok:
            raise SystemExit(1)
        out["MLDSA87_VERIFIER"] = a
        say(f"MldsaVerifier(0x0134) ok {a} (precompile {cand})")
    if E.FAILS:
        raise SystemExit(f"[deploy] pq-verifiers FAIL {E.FAILS[0]}")
    for n, a in out.items():
        print(f"{n}={a}")


if __name__ == "__main__":
    main(*sys.argv[1:])
