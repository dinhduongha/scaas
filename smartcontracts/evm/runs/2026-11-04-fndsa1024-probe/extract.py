# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Falcon-1024 probe (2026-11-04): extract NIST round-3 Falcon-1024 KATs into kat1024.json beside this file.

Input: the NIST round-3 Falcon submission package (Falcon-Round3.zip, the URL below), read with the stdlib `zipfile`
without extracting. The file is untrusted data: run with `python3 -I`, the path as an argument; a SHA-256 mismatch of the
zip or of KAT/falcon1024-KAT.rsp refuses it before it is parsed.

Each KAT row: pk (1,793 B, 0x0A || h) and sm in the NIST API form `u16 sig_len || nonce (40) || msg || 0x2A || compressed`.
Rebuilt as the round-3 *padded* signature `0x3A || nonce || compressed || zeros` (1,280 B), the form a `fndsa512`-shaped
kind uses (666 B at Falcon-512). A compressed s2 longer than 1,239 B has no padded form: counted, not kept.
    python3 -I runs/2026-11-04-fndsa1024-probe/extract.py <download dir>/Falcon-Round3.zip
"""
import hashlib
import json
import os
import re
import sys
import zipfile

SOURCE = ("https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/"
          "Falcon-Round3.zip")
ZIP_PIN = "fd58f0454f6bfb4713734e60b2d2d75d96fbae62d5180fceeef1039df5362f44"
MEMBER = "Falcon/falcon-round3/KAT/falcon1024-KAT.rsp"
RSP_PIN = "036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d"
PK, SIG, COMP, KEEP = 1793, 1280, 1239, 10


def main(path):
    raw = open(path, "rb").read()
    if hashlib.sha256(raw).hexdigest() != ZIP_PIN:
        sys.exit("zip sha256 mismatch: refused")
    with zipfile.ZipFile(path) as z:
        info = z.getinfo(MEMBER)
        if info.file_size > 4_000_000:
            sys.exit("rsp too large: refused")
        rsp = z.read(MEMBER)
    if hashlib.sha256(rsp).hexdigest() != RSP_PIN:
        sys.exit("rsp sha256 mismatch: refused")
    rows = [dict(re.findall(r"^(\w+) = ([0-9A-Fa-f]*)$", r, re.M)) for r in rsp.decode("ascii").split("count = ")[1:]]
    if len(rows) != 100:
        sys.exit(f"expected 100 KAT rows, got {len(rows)}")
    comp_lens, cases = [], []
    for i, r in enumerate(rows):
        pk, msg, sm = bytes.fromhex(r["pk"]), bytes.fromhex(r["msg"]), bytes.fromhex(r["sm"])
        mlen = int(r["mlen"])
        sig_len = int.from_bytes(sm[:2], "big")
        nonce, body = sm[2:42], sm[42 + mlen:]
        if (len(pk) != PK or pk[0] != 0x0A or len(msg) != mlen or sm[42:42 + mlen] != msg or len(body) != sig_len
                or body[0] != 0x2A or int(r["smlen"]) != len(sm)):
            sys.exit(f"count {i}: unexpected format")
        comp = body[1:]
        comp_lens.append(len(comp))
        if len(comp) > COMP or len(cases) == KEEP:
            continue
        sig = bytes([0x3A]) + nonce + comp + bytes(COMP - len(comp))
        assert len(sig) == SIG
        cases.append({"count": i, "mlen": mlen, "pk": "0x" + pk.hex(), "msg": "0x" + msg.hex(), "sm": "0x" + sm.hex(),
                      "sig": "0x" + sig.hex(), "comp_len": len(comp), "valid": True})
    out = {"source": SOURCE, "sha256_zip": ZIP_PIN, "member": MEMBER, "sha256_rsp": RSP_PIN,
           "note": "NIST round-3 Falcon-1024 KATs (first rows whose compressed s2 fits 1,239 B), rebuilt as padded "
                   "1,280-byte signatures 0x3A || nonce || compressed || zeros; `sm` is the original NIST form",
           "all_rows": len(rows), "comp_len_min": min(comp_lens), "comp_len_max": max(comp_lens),
           "rows_over_1239": [i for i, c in enumerate(comp_lens) if c > COMP], "cases": cases}
    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat1024.json")
    with open(dst, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(len(cases), "cases kept of", len(rows), "| compressed s2", min(comp_lens), "-", max(comp_lens),
          "B | rows over 1239 (count):", out["rows_over_1239"])


if __name__ == "__main__":
    main(sys.argv[1])
