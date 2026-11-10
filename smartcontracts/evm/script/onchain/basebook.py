#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b: the base book deployments/onchain-<net>-base.json (coverage.py) of the target's own deploy: every
contract of its deploy plan (deploy.sh's dry-run file broadcast/Deploy.s.sol/<chainid>/dry-run/run-latest.json, or a runs
note's deploy rows: libraries, verifiers, registry trio, router, factory, releases), its release list (RELEASES_JSON) and
its deployments json (DEPLOY_JSON), each under its groups.json label; a token kind's body module (e.g. NormalTokenP)
under its kind's label, so a traced DELEGATECALL into it counts for the kind.
  DEPLOY_JSON=… RELEASES_JSON=… [PLAN=…] [NOTE=…] python3 -I script/onchain/basebook.py <net>
(the SCaaS testnet: NOTE=runs/2026-11-10-ua-mtx-merge-t66b-step5-7622.txt, the Step 5 deploy rows)"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))


def main():
    net = sys.argv[1]
    labels = {c["label"] for cs in json.load(open(os.path.join(HERE, "groups.json")))["groups"].values() for c in cs}
    kinds = sorted((c["label"] for c in json.load(open(os.path.join(HERE, "groups.json")))["groups"]["tokens"]), key=len,
                   reverse=True)

    def label(name):
        if name in labels:
            return name
        for k in kinds:  # a body module: the kind's label + its letter (P, T, A, W, R, Z, Q, S)
            if re.fullmatch(re.escape(k) + r"(P|T|A|W|R|Z|Q|S)", name):
                return k
        return None

    book = {}
    dj = os.environ.get("DEPLOY_JSON", "deployments/7622.json")
    note = os.environ.get("NOTE")
    if note:
        t = open(os.path.join(EVM, note)).read()
        rows = re.findall(r"^\d+ \| (\w+) -> (0x[0-9a-f]{40}) \|", t, re.M)
        rows += re.findall(r"^(\w+) \| (0x[0-9a-fA-F]{40}) \| \d+ B \| equal", t, re.M)
    else:
        chain = os.path.basename(dj).split(".")[0]
        plan = os.environ.get("PLAN", f"broadcast/Deploy.s.sol/{chain}/dry-run/run-latest.json")
        tx = json.load(open(os.path.join(EVM, plan)))["transactions"]
        rows = [(x["contractName"], x["contractAddress"]) for x in tx if x.get("contractName") and x.get("contractAddress")]
    for name, a in rows:
        if label(name):
            book[a.lower()] = label(name)
    rel = json.load(open(os.path.join(EVM, os.environ.get("RELEASES_JSON", "deployments/7622-t66b-releases.json"))))
    for name, v in rel.items():
        if isinstance(v, dict) and "address" in v and label(name):
            book[v["address"].lower()] = label(name)
    dep = json.load(open(os.path.join(EVM, dj)))
    for key, name in (("ua_registry", "UARegistry"), ("ua_registry_core_lib", "UARegistryCoreLib"),
                      ("ua_registry_aux_lib", "UARegistryAuxLib"), ("governance_router", "GovernanceRouter"),
                      ("token_factory", "OpenFactory"), ("relay_fee_router", "RelayFeeRouter"),
                      ("relay_fee_executor", "RelayFeeExecutor"), ("compliance_registry", "ComplianceRegistry"),
                      ("smart_key_account_factory", "SmartKeyAccountFactory"),
                      ("smart_key_account_implementation", "SmartKeyAccount"), ("zether_disclosure", "ZetherDisclosure"),
                      ("zether_statements", "ZetherStatements"), ("zether_verifier_bls12381", "ZetherTransferVerifierBls12381"),
                      ("zether_burn_verifier_bls12381", "ZetherBurnVerifierBls12381"),
                      ("zether_inner_product_verifier_bls12381", "ZetherInnerProductVerifierBls12381"),
                      ("dex_implementation", "SCaaSDex"), ("demo_token", "NormalToken"), ("demo_token_2", "NormalToken")):
        if key in dep:
            book[dep[key].lower()] = name
    with open(os.path.join(EVM, f"deployments/onchain-{net}-base.json"), "w") as f:
        json.dump(book, f, indent=1)
    print(f"base book: {len(book)} addresses")


if __name__ == "__main__":
    main()
