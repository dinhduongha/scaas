#!/usr/bin/env python3
"""NEAR keyless deploy (near-algorand spec §3.7, §3.9; plan Task 19; README principle 5).

  deploy.py <rpc-url>                  deploy every SCaaS account, initialise it, register every lane on every token
                                       (storage_deposit), delete every access key, then the gate; writes
                                       <deployments>/<genesis-hash>.json only when the gate passes
  deploy.py <rpc-url> gate <account…>  the gate alone: fails unless view_access_key_list is empty for each account

Accounts are sub-accounts of the funding account F: one token per NEAR_TOKENS entry (`<symbol lower>.F`), `dex.F`,
`relayfee.F` (the escrow router), `relayexec.F` (its executor). Each is created with a temporary full-access key, its
code and its balance (code + NEAR_FUND NEAR) in one transaction; the account itself signs `new(…)` and then, after the
lane registrations, the deletion of that key. Nothing else ever holds a key: the code cannot change (no contract issues
DeployContract / AddKey / DeleteKey / DeleteAccount, checked by check_no_authority.sh), and the node re-checks the key
lists at start (halted otherwise).

env:
  NEAR_ACCOUNT_ID, NEAR_PRIVATE_KEY (ed25519:<base58>)  the funding account; or NEAR_KEY_FILE, a JSON with account_id and
                                                         secret_key (near-sandbox validator_key.json, near-cli credentials)
  NEAR_TOKENS       "SYMBOL:Name:decimals[,…]" (default "SCT:SCaaS Test:6")
  NEAR_ADMIN        the tokens' mint admin (default the funding account)
  NEAR_LANES        the relayer lanes (implicit account ids, comma-separated), each registered on each token
  NEAR_FUND         NEAR per contract account above its code's storage (default 2)
  NEAR_DEPLOYMENTS_DIR  default smartcontracts/near/deployments
Wasm: smartcontracts/near/target/near/<crate>/<crate>.wasm (smartcontracts/scripts/build.sh near first).
Needs python3 with `cryptography` (as smartcontracts/vectors/metatx/famvec.py).
"""
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NEAR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TGAS = 10**12
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58e(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58d(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": "deploy", "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, body, {"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            v = json.load(r)
        if v.get("error"):
            raise RuntimeError(f"{method}: {json.dumps(v['error'])}")
        return v["result"]

    def query(self, **q):
        return self("query", dict(finality="final", **q))

    def view(self, account, method, args=b""):
        r = self.query(request_type="call_function", account_id=account, method_name=method,
                       args_base64=base64.b64encode(args).decode())
        return bytes(r["result"])


# ------------------------------------------------------------------ Borsh transaction (nearcore Transaction::V0)

def u32(n):
    return struct.pack("<I", n)


def bstr(s):
    b = s if isinstance(s, bytes) else s.encode()
    return u32(len(b)) + b


def pk_borsh(pk):
    return b"\0" + pk  # KeyType::ED25519


def create_account():
    return b"\0"


def deploy_contract(code):
    return b"\1" + bstr(code)


def function_call(method, args, gas, deposit=0):
    return b"\2" + bstr(method) + bstr(args) + struct.pack("<Q", gas) + deposit.to_bytes(16, "little")


def transfer(amount):
    return b"\3" + amount.to_bytes(16, "little")


def add_full_key(pk):
    return b"\5" + pk_borsh(pk) + struct.pack("<Q", 0) + b"\1"  # AccessKey { nonce 0, FullAccess }


def delete_key(pk):
    return b"\6" + pk_borsh(pk)


class Key:
    def __init__(self, account, sk: ed25519.Ed25519PrivateKey):
        self.account, self.sk = account, sk
        self.pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.nonce = None

    @staticmethod
    def parse(account, secret):
        raw = b58d(secret.split(":", 1)[1])
        return Key(account, ed25519.Ed25519PrivateKey.from_private_bytes(raw[:32]))

    def pk_str(self):
        return "ed25519:" + b58e(self.pk)

    def send(self, rpc, receiver, actions, what):
        if self.nonce is None:
            self.nonce = rpc.query(request_type="view_access_key", account_id=self.account, public_key=self.pk_str())["nonce"]
        self.nonce += 1
        block = b58d(rpc("block", {"finality": "final"})["header"]["hash"])
        tx = (bstr(self.account) + pk_borsh(self.pk) + struct.pack("<Q", self.nonce) + bstr(receiver) + block
              + u32(len(actions)) + b"".join(actions))
        sig = self.sk.sign(hashlib.sha256(tx).digest())
        signed = tx + b"\0" + sig
        r = rpc("send_tx", {"signed_tx_base64": base64.b64encode(signed).decode(), "wait_until": "FINAL"})
        failed = [o for o in [r["transaction_outcome"]] + r["receipts_outcome"] if "Failure" in o["outcome"]["status"]]
        if "Failure" in r["status"] or failed:
            raise RuntimeError(f"{what}: {json.dumps(r['status'])} {[f['outcome']['status'] for f in failed]}")
        burnt = sum(o["outcome"]["gas_burnt"] for o in [r["transaction_outcome"]] + r["receipts_outcome"])
        print(f"  {what}: ok, {burnt / TGAS:.3f} Tgas")
        return r


# ------------------------------------------------------------------ deploy

def wasm(crate):
    p = os.path.join(NEAR_DIR, "target", "near", crate, f"{crate}.wasm")
    if not os.path.exists(p):
        sys.exit(f"{p}: run smartcontracts/scripts/build.sh near first")
    return open(p, "rb").read()


def token_metadata(name, symbol, decimals):
    """FungibleTokenMetadata (NEP-148) Borsh: spec, name, symbol, icon, reference, reference_hash, decimals."""
    return bstr("ft-1.0.0") + bstr(name) + bstr(symbol) + b"\0" + b"\0" + b"\0" + bytes([decimals])


def gate(rpc, accounts):
    """Spec §3.9 / R10: every SCaaS account keyless, else the run fails."""
    bad = []
    for a in accounts:
        keys = rpc.query(request_type="view_access_key_list", account_id=a)["keys"]
        if keys:
            bad.append(f"{a} has {len(keys)} access key(s): {[k['public_key'] for k in keys]}")
    if bad:
        sys.exit("deploy gate FAILED (spec §3.9: every SCaaS NEAR account is keyless):\n  " + "\n  ".join(bad))
    print(f"deploy gate: {len(accounts)} accounts keyless (view_access_key_list empty)")


def funder():
    if os.environ.get("NEAR_KEY_FILE"):
        k = json.load(open(os.environ["NEAR_KEY_FILE"]))
        return Key.parse(k["account_id"], k.get("secret_key") or k["private_key"])
    return Key.parse(os.environ["NEAR_ACCOUNT_ID"], os.environ["NEAR_PRIVATE_KEY"])


def deploy(rpc):
    f = funder()
    status = rpc("status", [])
    genesis = status["genesis_hash"]
    network = b58d(genesis)
    assert len(network) == 32, genesis
    byte_cost = int(rpc("EXPERIMENTAL_protocol_config", {"finality": "final"})["runtime_config"]["storage_amount_per_byte"])
    fund = int(float(os.environ.get("NEAR_FUND", "2")) * 10**24)
    admin = os.environ.get("NEAR_ADMIN", f.account)
    lanes = [x for x in os.environ.get("NEAR_LANES", "").split(",") if x]
    tokens = []
    for t in os.environ.get("NEAR_TOKENS", "SCT:SCaaS Test:6").split(","):
        sym, name, dec = t.split(":")
        tokens.append({"account": f"{sym.lower()}.{f.account}", "symbol": sym, "name": name, "decimals": int(dec)})
    dex, router, executor = (f"{n}.{f.account}" for n in ("dex", "relayfee", "relayexec"))
    plan = [(t["account"], "scaas_near_token", network + bstr(admin) + token_metadata(t["name"], t["symbol"], t["decimals"]))
            for t in tokens]
    plan += [(dex, "scaas_near_dex", b""), (router, "scaas_near_relayfee", bstr(executor)), (executor, "scaas_near_relayexec", bstr(router))]
    print(f"deploy on {status['chain_id']} (genesis {genesis}) from {f.account}: {[p[0] for p in plan]}")
    keys = {}
    for account, crate, init in plan:
        code = wasm(crate)
        tmp = Key(account, ed25519.Ed25519PrivateKey.generate())
        amount = len(code) * byte_cost + fund
        f.send(rpc, account, [create_account(), transfer(amount), add_full_key(tmp.pk), deploy_contract(code)],
               f"create {account} ({crate}, {len(code)} B, {amount / 10**24:.3f} NEAR)")
        tmp.send(rpc, account, [function_call("new", init, 100 * TGAS)], f"{account}.new")
        keys[account] = tmp
    for t in tokens:
        bounds = json.loads(rpc.view(t["account"], "storage_balance_bounds"))
        for lane in lanes:
            args = json.dumps({"account_id": lane, "registration_only": True}).encode()
            f.send(rpc, t["account"], [function_call("storage_deposit", args, 30 * TGAS, int(bounds["min"]))],
                   f"{t['account']}.storage_deposit({lane})")
    for account, k in keys.items():
        k.send(rpc, account, [delete_key(k.pk)], f"{account}: delete its last access key")
    gate(rpc, list(keys))
    out = {
        "network": genesis, "chain_id": status["chain_id"], "funder": f.account, "admin": admin,
        "tokens": [{"account": t["account"], "symbol": t["symbol"], "decimals": t["decimals"]} for t in tokens],
        "dex": dex, "relayfee": router, "relayexec": executor, "lanes": lanes,
        "code_hash": {a: rpc.query(request_type="view_account", account_id=a)["code_hash"] for a in keys},
        "deployed_at": int(time.time()),
    }
    d = os.environ.get("NEAR_DEPLOYMENTS_DIR") or os.path.join(NEAR_DIR, "deployments")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{genesis}.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"wrote {path}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    rpc = Rpc(sys.argv[1])
    if sys.argv[2:3] == ["gate"]:
        gate(rpc, sys.argv[3:] or sys.exit("gate: name the accounts"))
    elif len(sys.argv) == 2:
        deploy(rpc)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
