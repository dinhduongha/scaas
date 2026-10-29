#!/usr/bin/env python3
"""deploy.py's recovery of a create that left algod's pending cache (T20 review I2), offline: a fake algod answers 404
for the pending lookup and has no block history (a default, non-archival node); the funder's created apps decide.
Run: smartcontracts/algorand/.venv/bin/python -I smartcontracts/algorand/scripts/test_deploy.py"""
import base64
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deploy as D  # noqa: E402
from algosdk import account, encoding, transaction  # noqa: E402
from algosdk.error import AlgodHTTPError  # noqa: E402


class Node:
    """Pending cache empty, no blocks: only account info."""

    def __init__(self, apps):
        self.apps = apps

    def pending_transaction_info(self, txid):
        raise AlgodHTTPError("txn does not exist", 404)

    def account_info(self, addr):
        return {"created-apps": self.apps}

    def block_info(self, **kw):
        raise AlgodHTTPError("failed to retrieve information from the ledger", 404)


def b64(b):
    return base64.b64encode(b).decode()


class Recovery(unittest.TestCase):
    def setUp(self):
        sk, addr = account.generate_account()
        self.f = types.SimpleNamespace(sk=sk, addr=addr)
        self.s = D.Spec("Token")
        self.admin = account.generate_account()[1]
        args = [b"Token A".ljust(32, b"\0"), b"TKA".ljust(8, b"\0"), 6, self.admin, 1002]
        sp = transaction.SuggestedParams(1000, 10, 110, b64(b"\1" * 32), "x", flat_fee=True)
        t = transaction.ApplicationCreateTxn(addr, sp, transaction.OnComplete.NoOpOC, self.s.approval, self.s.clear, self.s.schema,
                                             transaction.StateSchema(0, 0), app_args=D.encode_args(self.s, args),
                                             extra_pages=self.s.extra_pages)
        stx = t.sign(sk)
        self.rec = {"txid": stx.get_txid(), "stx": encoding.msgpack_encode(stx), "first": 10, "last": 110, "min_id": 1010}
        self.state = types.SimpleNamespace(apps={"account": 1002}, orphans=[], path="resume.json")

    def app(self, app_id, admin=None, approval=None):
        g = {"name": b"Token A".ljust(32, b"\0"), "symbol": b"TKA".ljust(8, b"\0"), "decimals": 6,
             "admin": encoding.decode_address(admin or self.admin), "account_app": 1002}
        gs = [{"key": b64(k.encode()), "value": {"type": 2, "uint": v} if isinstance(v, int) else {"type": 1, "bytes": b64(v)}}
              for k, v in g.items()]
        return {"id": app_id, "params": {"approval-program": b64(approval or self.s.approval), "global-state": gs}}

    def landed(self, apps):
        return D.landed(Node(apps), self.f, "token:TKA", self.rec, self.state)

    def test_recorded_create_decodes_its_parameters(self):
        args, approval, clear = D.recorded(self.rec)
        self.assertEqual((approval, clear), (self.s.approval, self.s.clear))
        g = D.create_globals(self.s, "token", args)
        self.assertEqual((g["symbol"], g["decimals"], g["admin"], g["account_app"]),
                         (b"TKA".ljust(8, b"\0"), 6, encoding.decode_address(self.admin), 1002))

    def test_found_among_the_funders_created_apps(self):
        other = account.generate_account()[1]
        apps = [self.app(1002), self.app(1009), self.app(1012, admin=other), self.app(1013, approval=b"\x0a\x81\x01\x43"),
                self.app(1014)]
        # 1002 is the state's account app, 1009 below the recorded counter, 1012 another admin, 1013 other code
        self.assertEqual(self.landed(apps), 1014)

    def test_not_on_chain(self):
        self.assertIsNone(self.landed([self.app(1002), self.app(1009)]))

    def test_two_matches_refused(self):
        with self.assertRaises(SystemExit) as e:
            self.landed([self.app(1014), self.app(1016)])
        self.assertIn("all match its recorded create", str(e.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
