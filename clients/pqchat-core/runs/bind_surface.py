# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T12 (owner 2026-11-22, "Handle SecretBytes"): decrypted content in the generated Dart surface only as the
SDK's `SecretBytes` handle (`ArcSecretBytes`), read through the SDK's copy calls; run by runs/2026-11-17-pqchat-core-bind.sh
over the generated Dart directory:
  python3 -I clients/pqchat-core/runs/bind_surface.py <dart dir>
Each type holding a decrypted content or `sealedInfo` plaintext has exactly the members named here (a field, or an opaque
type's getter), the content as the handle, and no method; `PqChat`'s calls that hand them out return these types; no generated
function takes a handle or one of these types and returns anything but a number, a flag, a handle or one of these types;
`PqChat`'s `send…` and `seal…` calls are exactly `SENDS` with their parameters, the content only as the handle, and the
crate's `Content` is not in the surface (owner 2026-11-23).
A failure is a TAP `not ok` line; rc 1."""
import re
import sys
from pathlib import Path

H = "ArcSecretBytes"
# type → member → Dart type
HOLDS = {
    "Received": {"messageId": "String", "record": "PqChatMessage", "content": H},
    "Message": {"id": "String", "sender": "String", "ts": "BigInt?", "onBehalfOf": "String?", "supported": "bool",
                "edited": "bool", "content": H, "reactions": "List<Reaction>"},
    "Reaction": {"content": H, "count": "BigInt"},
    "Preview": {"creator": "String", "epoch": "String", "members": "List<String>", "admins": "List<String>", "info": H,
                "chainStores": "BigInt", "matrix": "bool"},
    "SessionSummary": {"s": "SessionRef", "latest": "String", "epochs": "BigInt", "consent": "Consent", "info": H + "?"},
    # a store by its index in the epoch's list (the list itself is `sealedInfo` plaintext)
    "SendReport": {"messageId": "String?", "stores": "List<(int, Delivery)>", "post": "Delivery?"},
}
# PqChat's calls that hand out decrypted content or `sealedInfo` plaintext
RETURNS = {"info": f"Future<{H}>", "timeline": "Future<List<Message>>", "receive": "Future<Received>",
           "posted": "Future<Received>", "preview": "Future<Preview>", "sessions": "Future<List<SessionSummary>>"}
# PqChat's send entries, each with exactly these parameters (owner 2026-11-23): a content is sent only as its JSON in the
# handle; no other `send…` or `seal…` call, none taking a plain string or the crate's `Content`
SENDS = {"send": {"s": "SessionRef", "me": "Me", "content": H, "ts": "BigInt?", "o": "SendOpts"},
         "sendFile": {"s": "SessionRef", "me": "Me", "f": "FileToSend", "ts": "BigInt?", "o": "SendOpts"},
         "sendEpoch": {"s": "SessionRef", "epoch": "String"}}
# what a function over a handle or a holding type may return
SCALAR = {"void", "bool", "int", "BigInt", H, *HOLDS}

bad = []


def body(src, name):
    """The body of class `name` (plain or abstract), braces balanced; None when absent."""
    m = re.search(rf"^(?:abstract )?class {name}\b[^{{]*\{{", src, re.M)
    if not m:
        return None
    i, depth = m.end(), 1
    while depth and i < len(src):
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return src[m.end():i - 1]


def members(b):
    """(fields and getters by name and type, the other members)."""
    got, other = {}, []
    for st in re.sub(r"^\s*///.*$", "", b, flags=re.M).split(";"):
        s = " ".join(st.split())
        if not s or re.match(r"set \w+\(|const \w+\(", s):
            continue
        if s.startswith("@override") and re.search(r"get hashCode|operator ==", s):
            continue
        if m := re.fullmatch(r"final (.+) (\w+)", s) or re.fullmatch(r"(.+) get (\w+)", s):
            got[m[2]] = m[1]
        else:
            other.append(s[:80])
    return got, other


def strip(t):
    t = t.strip()
    return re.sub(r"^Future<(.*)>$", r"\1", t)


def main(d):
    files = [p for p in Path(d).rglob("*.dart") if not p.name.startswith("frb_generated")]
    src = "\n".join(p.read_text() for p in files)
    for name, want in HOLDS.items():
        b = body(src, name)
        if b is None:
            bad.append(f"{name} not in the surface (positive control)")
            continue
        got, other = members(b)
        if got != want:
            bad.append(f"{name}'s members {sorted(got.items())}, not {sorted(want.items())}")
        if other:
            bad.append(f"{name} has a member that is no field: {other}")
    pq = body(src, "PqChat") or ""
    for f, ret in RETURNS.items():
        m = re.search(rf"^\s*(\S.*?) {f}\(", pq, re.M)
        if not m or m[1] != ret:
            bad.append(f"PqChat.{f} returns {m[1] if m else 'nothing'}, not {ret}")
    seen = {}
    for m in re.finditer(r"^\s*[A-Z][^\n;]*? ((?:send|seal)\w*)\((.*?)\);", pq, re.M | re.S):
        ps = [" ".join(x.replace("required ", "").split()) for x in re.sub(r"[{}]", "", m[2]).split(",")]
        seen[m[1]] = dict(reversed(x.rsplit(" ", 1)) for x in ps if x)
    for f, want in SENDS.items():
        if seen.get(f) != want:
            bad.append(f"PqChat.{f}'s parameters {seen.get(f)}, not {want}")
    for f in sorted(set(seen) - set(SENDS)):
        bad.append(f"PqChat.{f} is not a send entry of the surface: {seen[f]}")
    if body(src, "Content") is not None:
        bad.append("the crate's Content in the surface")
    holds = "|".join([H, "SecretBytes", *HOLDS])
    for m in re.finditer(r"^\s*(?:static )?([A-Z][\w<>?, ()]*?) (\w+)\((\{?[^()]*?\}?)\)\s*(?:=>|;)", src, re.M):
        ret, fn, params = m[1], m[2], m[3]
        if re.search(rf"\b(?:{holds})\b", params) and strip(ret) not in SCALAR:
            bad.append(f"{fn}({' '.join(params.split())}) returns {ret}")
    for b in bad:
        print(f"not ok - decrypted content not only as the handle: {b}")
    print(f"[bind] surface: {len(HOLDS)} holding types, {len(RETURNS)} calls, {len(SENDS)} send entries checked; "
          f"{len(bad)} refused")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
