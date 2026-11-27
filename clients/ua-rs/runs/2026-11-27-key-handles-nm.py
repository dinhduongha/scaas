#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Owner 2026-11-27 (user-profiles spec O15): scaas-ua with only the profile-crypto features compiles no signing code.

From the repository root: python3 clients/ua-rs/runs/2026-11-27-key-handles-nm.py
(each cargo build through scripts/capped; CAP='' runs it bare, as CI does). Exit 0 when:
  1. the scaas-ua rlib of `--no-default-features --features user-profile` defines no symbol matching SIGNING
     (signing code, the PQ kinds, the group signers, the C ABI), read with `nm -C --defined-only`; the verify-only
     identity layer (MD-5) stays in every build and is not matched;
  2. the positive control: the rlib of `--no-default-features --features wallet` defines such symbols;
  3. `cargo tree -e features` of clients/scaas-profile enables no scaas-ua feature in FORBIDDEN, and the same read of
     scaas-ua with `wallet` (the control) finds them.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UA = ROOT / "clients/ua-rs"
PROFILE = ROOT / "clients/scaas-profile"
CAP = os.environ.get("CAP", str(ROOT / "scripts/capped")).split()
# signing code: the wallet's signing and seed modules and key types, the group signers, the facades, the PQ kinds (`pq`:
# their verifiers too), a curve crate's signing key or signing call compiled into scaas-ua, the PQ and group signer crates,
# the C ABI. Not matched: the verify-only identity layer every build has (MD-5: src/verify.rs, ua_portable.rs, groups.rs).
SIGNING = re.compile(
    r"scaas_ua::wallet::(sign|signer|pqsign|pairing|uasig|policy|tx|kem|seal|derive|vault|manifest|substrate|webauthn)::"
    r"|scaas_ua::wallet::(Wallet|UaKey|NativeKey)\b|scaas_ua::(frost|musig2|pq|falcon|facade)::"
    r"|SigningKey|sign_prehash|try_sign|ml_dsa::|slh_dsa::|PQCLEAN|falcon_rs::|frost_core::|frost_secp256k1::|schnorrkel::"
    r"|scaas_ua_")
# the signing features and their signing dependencies (an optional dependency shows as a feature of its name)
FORBIDDEN = re.compile(
    r"^(default|wallet|pq|signers|zether|pqz.*|fam-.*|app-core|roots|vectors"
    r"|ml-dsa|slh-dsa|falcon-rs|frost-.*|schnorrkel|bip32|bip39|ml-kem)$")


def rlib(features):
    print(f"[kh-nm] build scaas-ua --features {features}", flush=True)
    # stderr passes through: capped's slot lines (scripts/mutant_guard.py starts a deadline at them), cargo's errors
    out = subprocess.run(
        CAP + ["cargo", "build", "--locked", "--offline", "-j2", "--no-default-features", "--features", features,
               "--message-format=json"],
        cwd=UA, env={**os.environ, "CARGO_INCREMENTAL": "0"}, stdout=subprocess.PIPE, text=True)
    if out.returncode:
        sys.exit(f"FAIL: the build with --features {features} (rc {out.returncode})")
    for line in out.stdout.splitlines():
        m = json.loads(line)
        if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "scaas_ua":
            return next(f for f in m["filenames"] if f.endswith(".rlib"))
    sys.exit("FAIL: no scaas_ua rlib in the build's messages")


def signing(features):
    syms = subprocess.run(["nm", "-C", "--defined-only", rlib(features)], capture_output=True, text=True).stdout
    lines = syms.splitlines()
    hits = [l for l in lines if SIGNING.search(l)]
    print(f"[kh-nm] {features} | {len(lines)} symbols | {len(hits)} signing", flush=True)
    return hits


def ua_features(cwd, *args):
    out = subprocess.run(["cargo", "tree", "--offline", "--locked", "-e", "features", "-i", "scaas-ua", *args],
                         cwd=cwd, capture_output=True, text=True)
    if out.returncode:
        fail(f"cargo tree in {cwd.relative_to(ROOT)}: {out.stderr.strip().splitlines()[0]}")
    return sorted(set(re.findall(r'scaas-ua feature "([^"]+)"', out.stdout)))


failed = []


def fail(why):
    failed.append(why)
    print(f"FAIL: {why}", flush=True)


hits = signing("user-profile")
if hits:
    fail("user-profile compiles signing code: " + "; ".join(h.split(" ", 2)[-1][:160] for h in hits[:5]))
if not signing("wallet"):
    fail("control: the wallet build shows no signing symbol (the pattern reads nothing)")
prof = ua_features(PROFILE)
print(f"[kh-nm] scaas-profile's scaas-ua features: {prof}", flush=True)
if any(FORBIDDEN.match(f) for f in prof):
    fail(f"scaas-profile enables {[f for f in prof if FORBIDDEN.match(f)]}")
if not any(FORBIDDEN.match(f) for f in ua_features(UA, "--no-default-features", "--features", "wallet")):
    fail("control: the tree of a wallet build shows no forbidden feature")
print(f"[kh-nm] {'FAIL' if failed else 'ok'}", flush=True)
sys.exit(1 if failed else 0)
