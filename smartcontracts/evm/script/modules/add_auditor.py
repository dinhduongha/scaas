# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""setAuditor plan A2 / A4 (spec 2026-11-17-set-auditor.md §5.5, §8; CTR-GOV-31): bit 32's setter and two views on each
confidential kind in `entries.json` (Zether: the module Z; PQZ: Q, which `gen_faces.py` moves to S on the split kinds), and their
events and errors in each face's ABI-only interface (`face_abi.json`), sorted as the generator writes them. Idempotent.
usage (from smartcontracts/evm): python3 script/modules/add_auditor.py zether|pqz; then gen_faces.py."""

import json
import sys

ZETHER = ("NormalZetherToken", "WrappedZetherToken", "NormalZetherRegulatedToken", "WrappedZetherRegulatedToken")
PQZ = ("NormalPqzToken", "WrappedPqzToken", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken")
UASIG = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])"


def row(sel, sig, name, decl, mut, guard, params, ret, iface, domain, group):
    return {
        "sel": sel,
        "sig": sig,
        "name": name,
        "decl": decl,
        "kept": False,
        "mut": mut,
        "guard": guard,
        "params": params,
        "names": [p.rsplit(" ", 1)[1] for p in params],
        "returns": ret,
        "ifaces": [iface],
        "vis": "external",
        "domain": domain,
        "group": group,
    }


STATE = "uint32 epoch, bytes32 pending, uint64 eta, bytes32 proposer, uint8 status"
ROWS = {
    "zether": [
        row(
            "2328ce6c",
            "setAuditorKey(bytes,uint32,bytes,bytes32)",
            "setAuditorKey",
            "ZetherLayer",
            "nonpayable",
            "nonReentrant",
            ["bytes calldata newKey", "uint32 epoch", "bytes calldata pop", "bytes32 chainUid_"],
            "",
            "IZetherToken",
            "zether",
            "Z",
        ),
        row(
            "24174abc",
            "auditorKeyOf(bytes32)",
            "auditorKeyOf",
            "ZetherLayer",
            "view",
            "",
            ["bytes32 entryRef"],
            "bytes memory _p0",
            "IZetherToken",
            "zether",
            "Z",
        ),
        row(
            "b5e09c0f",
            "auditorState()",
            "auditorState",
            "ZetherLayer",
            "view",
            "",
            [],
            STATE,
            "IZetherToken",
            "zether",
            "Z",
        ),
    ],
    "pqz": [
        row(
            "f6f32d5d",
            f"setAuditorUA(bytes32,uint32,{UASIG},bytes32)",
            "setAuditorUA",
            "PqzLayer",
            "nonpayable",
            "nonReentrant",
            ["bytes32 newAuditor", "uint32 epoch", "IUARegistry.UASig calldata consent", "bytes32 chainUid_"],
            "",
            "IPqzToken",
            "pqz",
            "Q",
        ),
        row(
            "c93622ee",
            "auditorUAOf(bytes32)",
            "auditorUAOf",
            "PqzLayer",
            "view",
            "",
            ["bytes32 entryRef"],
            "bytes32 _p0",
            "IPqzToken",
            "pqz",
            "Q",
        ),
        row("b5e09c0f", "auditorState()", "auditorState", "PqzLayer", "view", "", [], STATE, "IPqzToken", "pqz", "Q"),
    ],
}
B32 = lambda n: {"internalType": "bytes32", "name": n, "type": "bytes32"}  # noqa: E731
U32 = lambda n: {"internalType": "uint32", "name": n, "type": "uint32"}  # noqa: E731
U64 = lambda n: {"internalType": "uint64", "name": n, "type": "uint64"}  # noqa: E731
BYT = lambda n: {"internalType": "bytes", "name": n, "type": "bytes"}  # noqa: E731
U8 = lambda n: {"internalType": "uint8", "name": n, "type": "uint8"}  # noqa: E731


def ev(name, *inputs):
    return {"anonymous": False, "inputs": [dict(i, indexed=False) for i in inputs], "name": name, "type": "event"}


def er(name, *inputs):
    return {"inputs": list(inputs), "name": name, "type": "error"}


COMMON_EVENTS = [ev("AuditorProposalCancelled", U32("epoch"))]
COMMON_ERRORS = [
    er("AuditorNotReady", U64("eta")),
    er("AuditorPending"),
    er("AuditorSame"),
    er("AuditorEpochMismatch", U32("expected"), U32("got")),
    er("FeatureNeedsAdmin", U8("bit")),
    er("DelegableRefused", U8("bit")),
]
EVENTS = {
    "zether": COMMON_EVENTS
    + [
        ev("AuditorKeyProposed", U32("epoch"), BYT("newKey"), B32("proposer"), U64("eta")),
        ev("AuditorKeySet", U32("epoch"), BYT("previousKey"), BYT("newKey")),
    ],
    "pqz": COMMON_EVENTS
    + [
        ev("AuditorUAProposed", U32("epoch"), B32("newAuditor"), B32("proposer"), U64("eta")),
        ev("AuditorUASet", U32("epoch"), B32("previousAuditor"), B32("newAuditor")),
    ],
}
ERRORS = {"zether": COMMON_ERRORS + [er("AuditorKeyInvalid"), er("AuditorConsentInvalid")], "pqz": COMMON_ERRORS}


def put(rows, item, key):
    rows[:] = [r for r in rows if r[key] != item[key]] + [item]
    rows.sort(key=lambda r: r[key])


fam = sys.argv[1] if len(sys.argv) > 1 else ""
if fam not in ROWS:
    raise SystemExit(__doc__)
kinds = ZETHER if fam == "zether" else PQZ
E = json.load(open("script/modules/entries.json"))
for k in kinds:
    for r in ROWS[fam]:
        put(E["kinds"][k], dict(r), "name")
open("script/modules/entries.json", "w").write(json.dumps(E, indent=1))
A = json.load(open("script/modules/face_abi.json"))
for k in kinds:
    for e in EVENTS[fam]:
        put(A["kinds"][k]["event"], dict(e), "name")
    for e in ERRORS[fam]:
        put(A["kinds"][k]["error"], dict(e), "name")
open("script/modules/face_abi.json", "w").write(json.dumps(A, indent=1))
