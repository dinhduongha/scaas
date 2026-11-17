# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""SCaaS testnet reset 3, step 5: script/pqz/e2e.py unchanged, its transactions' gas limit given explicitly as the matrix's
pq group asks it (script/onchain/pq.py): eth_estimateGas x 1.5 + 300 k, at most 60 M and the block's gas limit. e2e.py's
own limit (estimate x 1.15 + 50 k) left the ML-DSA-65-signed named mtxShield(alice, 7) out of gas in this run's first try
(448,624 asked, status 0 at 437,226 used: e2e-pqz-scaas-testnet-try1.txt), as pq.py's comment records on the local copy; and
section 6c's transfers with the auditor leg on, as pq.py's _rotation (pqUSD is auditor FULL).
  python3 -I runs/2026-11-12-scaas-testnet-reset3/e2e3.py <e2e.py's arguments>"""
import os
import sys

EVM = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
sys.path.insert(0, os.path.join(EVM, "script/pqz"))
import e2e as E  # noqa: E402

_send0 = E.Sender.send


def _send(self, to, data, what, gas=None):
    if gas is None:
        tx = {"from": self.addr, "data": "0x" + data.hex(), **({"to": to} if to else {})}
        try:
            est = int(E.rpc("eth_estimateGas", [tx]), 16)
            lim = int(E.rpc("eth_getBlockByNumber", ["latest", False])["gasLimit"], 16)
            gas = min(lim, 60_000_000, int(est * 1.5) + 300_000)
        except RuntimeError:
            gas = None  # e2e's own path reports the refused estimate
    return _send0(self, to, data, what, gas)


E.Sender.send = _send
_rotation0 = E.rotation


def _rotation(pq, s, reg, C, *a):
    """Section 6c sends its op-1 transfers with the auditor leg off on pqUSD, whose auditor mode is FULL: the token refuses
    them AuditorRequired() (this run's second try, e2e-pqz-scaas-testnet-try2.txt). The leg on, as pq.py's _rotation."""
    t0 = E.transfer
    E.transfer = lambda pq_, s_, C_, frm, to, ben, v, aud_on, *r, **k: t0(pq_, s_, C_, frm, to, ben, v, True, *r, **k)
    try:
        return _rotation0(pq, s, reg, C, *a)
    finally:
        E.transfer = t0


E.rotation = _rotation
sys.argv[0] = "e2e.py"
E.main()
