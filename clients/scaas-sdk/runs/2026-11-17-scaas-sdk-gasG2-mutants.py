# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's rulings G2, Q1 and Q2 of 2026-11-19 ("approved all 6 as proposed", "approved
all 5 as proposed"): `ua_extra` on every variant a derived signer can sign, the generator's fallback for a variant or a kind
without a derived run, none on a native-only entry (G2); the second derived party of `mtxPayWithPayeeFee` (Q1); WebAuthn's
verify row at ua-rs's cap, its worst case (Q2): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasG2-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import ROOT, main

GEN = "clients/scaas-sdk/gas/generate.py"
R = "clients/scaas-sdk/gas/reference.json"
VER = "smartcontracts/evm/test/gas/SdkGasVerify.t.sol"
TG = "python3 clients/scaas-sdk/gas/test_generate.py"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
U = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
FORGE = ("cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/gas/SdkGasVerify.t.sol "
         "--match-test '^test_sdkGas_verify\\('")


def _row_without_ua(text, kind, entry):
    """The fresh row of (`kind`, `entry`) from its key to the end of its `ua_extra`, and the same without the `ua_extra`."""
    i = text.index(f'"entry": "{entry}",\n      "kind": "{kind}",\n      "fresh": true,')
    j = text.index(',\n      "ua_extra": {', i)
    k = text.index("\n      }", j) + len("\n      }")
    return text[i:k], text[i:j]


_REF = (ROOT / R).read_text()
SHIELD, SHIELD_NO_UA = _row_without_ua(_REF, "zether", "mtxShield")
ADDKEY = '"entry": "mtxAddKey",\n      "kind": "account",\n      "fresh": true,'
MUTANTS = [
    # the generator (G2, Q1), on test_generate.py's synthetic measurement
    ("G2: a variant without a derived run not listed",
     [(GEN, '        if fresh - ua:\n            x["unmeasured"]', '        if False:\n            x["unmeasured"]')], TG),
    ("G2: the fallback takes the smallest on another kind",
     [(GEN, '        d = max(donors, key=lambda r: r["ua_extra"]["measured"])',
       '        d = min(donors, key=lambda r: r["ua_extra"]["measured"])')], TG),
    ("G2: a row with no donor left without ua_extra",
     [(GEN, '            raise SystemExit(f"{row[\'kind\']} {row[\'entry\']}: no ua_extra measured for the entry on any kind (G2)")',
       "            continue")], TG),
    ("G2: a native-only entry measured with a derived signer accepted",
     [(GEN, '            raise SystemExit(f"{kind} {entry}: listed native-only (ua_native) but measured with a derived signer")',
       "            pass")], TG),
    ("Q1: the second party's verify delta not taken off",
     [(GEN, "        worst = max(m[a] - m[b] - m[less] for a, b in items)", "        worst = max(m[a] - m[b] for a, b in items)")],
     TG),
    # the table (G2), held by the SDK's test
    ("G2: a measured row's ua_extra dropped", [(R, SHIELD, SHIELD_NO_UA)], U + "reference_ua_extra_covers_every_variant"),
    ("G2: a native-only kind given a ua_extra",
     [(R, ADDKEY, ADDKEY + '\n      "ua_extra": {"gas": 1000, "measured": 1, "source": "x#a-b"},')],
     U + "reference_ua_extra_covers_every_variant"),
    ("G2: a measured row marked unmeasured",
     [(R, SHIELD, SHIELD.replace('"ua_extra": {', '"ua_extra": {\n        "unmeasured": ["normal"],', 1))],
     U + "reference_ua_extra_covers_every_variant"),
    # Q2: the row at the cap's worst case, held by the pins
    ("Q2: WebAuthn back on the longest vector",
     [(VER, "            if (kind == 0x0100) {\n", "            if (kind == 0xFFFF) {\n")], FORGE),
    ("Q2: the cap's worst case replaced by the cap vector's shape",
     [(VER, '        sig = _waSign(sk, ad, _waClientData(message, ad.length, ""));',
       '        sig = _waSign(sk, ad, _waClientData(message, ad.length, "https://scaas.example"));')], FORGE),
]

if __name__ == "__main__":
    main("gasG2", MUTANTS)
