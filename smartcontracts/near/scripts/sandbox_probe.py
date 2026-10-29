#!/usr/bin/env python3
"""near-sandbox facts behind Task 19's findings (kept per the repo's keep-experiment-code rule).

  devnet.sh up <home> && python3 sandbox_probe.py <rpc-url> <home>; devnet.sh down <home>

1. the protocol config's action fees (vs the node's pinned RuntimeFeesConfig figures);
2. a transfer to an implicit (64-hex) account, new or existing, burns create-account + add-key + transfer fees;
3. send_tx with a stale nonce: wait_until NONE answers success, INCLUDED returns INVALID_TRANSACTION;
4. a call in flight (NEP-519 yield of the target fixture) keeps its transaction INCLUDED_FINAL / Started until resumed.
"""
import base64
import hashlib
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deploy as D  # noqa: E402

TGAS = 10**12


def gas(r):
    return [(o["outcome"]["executor_id"], o["outcome"]["gas_burnt"] / TGAS) for o in [r["transaction_outcome"]] + r["receipts_outcome"]]


def raw(f, rpc, receiver, actions, nonce):
    block = D.b58d(rpc("block", {"finality": "final"})["header"]["hash"])
    tx = D.bstr(f.account) + D.pk_borsh(f.pk) + struct.pack("<Q", nonce) + D.bstr(receiver) + block + D.u32(len(actions)) + b"".join(actions)
    return tx, base64.b64encode(tx + b"\0" + f.sk.sign(hashlib.sha256(tx).digest())).decode()


def main():
    rpc, home = D.Rpc(sys.argv[1]), sys.argv[2]
    pc = rpc("EXPERIMENTAL_protocol_config", {"finality": "final"})
    tc = pc["runtime_config"]["transaction_costs"]
    print("1. protocol", pc["protocol_version"], "action_receipt_creation", tc["action_receipt_creation_config"])
    for k in ["function_call_cost", "function_call_cost_per_byte", "transfer_cost", "create_account_cost", "add_key_cost"]:
        print("  ", k, json.dumps(tc["action_creation_config"][k]))
    k = json.load(open(os.path.join(home, "validator_key.json")))
    f = D.Key.parse(k["account_id"], k["secret_key"])
    for what in ["a new", "an existing"]:
        r = f.send(rpc, "c" * 64, [D.transfer(10**24)], f"2. transfer to {what} implicit account")
        print("  ", gas(r))
    r = f.send(rpc, f.account, [D.transfer(1)], "2. transfer to a named account (itself)")
    print("  ", gas(r))
    for wu in ["NONE", "INCLUDED"]:
        _, b = raw(f, rpc, f.account, [D.transfer(1)], f.nonce)  # the nonce of the last transaction: stale
        try:
            print(f"3. stale nonce, wait_until {wu}:", rpc("send_tx", {"signed_tx_base64": b, "wait_until": wu}))
        except RuntimeError as e:
            print(f"3. stale nonce, wait_until {wu}: error", str(e)[:300])
    code = open(os.path.join(D.NEAR_DIR, "target/near/scaas_near_target_fixture/scaas_near_target_fixture.wasm"), "rb").read()
    f.send(rpc, f"fx.{f.account}", [D.create_account(), D.transfer(5 * 10**24), D.deploy_contract(code)], "4. fixture")
    f.nonce += 1
    tx, b = raw(f, rpc, f"fx.{f.account}", [D.function_call("wait", b"", 30 * TGAS)], f.nonce)
    rpc("send_tx", {"signed_tx_base64": b, "wait_until": "NONE"})
    h = D.b58e(hashlib.sha256(tx).digest())
    for i in range(5):
        time.sleep(1)
        s = rpc("EXPERIMENTAL_tx_status", {"tx_hash": h, "sender_account_id": f.account, "wait_until": "NONE"})
        print(f"4. yielded call after {i + 1} s: final_execution_status {s.get('final_execution_status')}, status {s.get('status')}")
    f.send(rpc, f"fx.{f.account}", [D.function_call("resume", b'{"ok": true}', 30 * TGAS)], "4. resume")
    s = rpc("EXPERIMENTAL_tx_status", {"tx_hash": h, "sender_account_id": f.account, "wait_until": "FINAL"})
    print("4. after resume:", s.get("final_execution_status"), s.get("status"))


if __name__ == "__main__":
    main()
