#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 15 mutants (the bindings over ua-rs: ua-c, ua-cxx, ua-qt, ua-dart-frb; the 0x0121 member partial and PoP
part). Each binding: the partial call forwarded to the PoP part, the PoP part signed as a partial; killed by its
groups.json blsMulti.wallet test. From the worktree root, after the bindings are built once:
python3 -I <this> [first last | check]. The Qt build needs QMAKE and LD_LIBRARY_PATH set as in the CI header."""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CAPPED = os.path.abspath("scripts/capped")
C, CXX, QT, FRB = "clients/ua-c", "clients/ua-cxx", "clients/ua-qt", "clients/ua-dart-frb"
TC = ["sh", "-c", f"{CAPPED} cargo build --locked && python3 -m unittest tests.test_vectors.WalletBlsMulti"]
TX = ["sh", "-c", f"{CAPPED} cmake --build build && build/wallet_test bls_multi_json || {{ echo 'FAIL: bls_multi_json'; exit 1; }}"]
TQ = ["sh", "-c", f"{CAPPED} cmake --build build && QT_QPA_PLATFORM=offscreen build/tst_ua -input tests > build/mut.out 2>&1; rc=$?; "
      "sed -nE 's/^FAIL! +: .*::(test_[a-z_]+)\\(.*/FAIL: \\1/p' build/mut.out; exit $rc"]
TF = ["sh", "-c", f"{CAPPED} cargo build --locked --manifest-path rust/Cargo.toml && "
      f"{CAPPED} dart test -r expanded --no-color test/wallet_test.dart -N bls_multi_json"]
CR, XR, QR, FR = C + "/src/lib.rs", CXX + "/src/wallet.rs", QT + "/src/ua_wallet.rs", FRB + "/rust/src/api/wallet.rs"
M = [
    ("ua-c partial is the PoP part", CR,
     ".sign_bls_multi(bytes(key_data, key_data_len)?, arr(ua_msg32)?)?",
     ".sign_bls_multi_pop(bytes(key_data, key_data_len)?)?", TC, C, "test_parts_match_vectors"),
    ("ua-c PoP part signed as a partial", CR,
     ".sign_bls_multi_pop(bytes(key_data, key_data_len)?)?",
     ".sign_bls_multi(bytes(key_data, key_data_len)?, &[0; 32])?", TC, C, "test_parts_match_vectors"),
    ("ua-cxx partial is the PoP part", XR,
     "sign_bls_multi(key_data, &a(ua_msg)?)?", "sign_bls_multi_pop(key_data)?", TX, CXX, "bls_multi_json"),
    ("ua-cxx PoP part signed as a partial", XR,
     "sign_bls_multi_pop(key_data)?))", "sign_bls_multi(key_data, &[0; 32])?))", TX, CXX, "bls_multi_json"),
    ("ua-qt partial is the PoP part", QR,
     "sign_bls_multi(&bytes(key_data)?, &fixed(ua_msg)?)", "sign_bls_multi_pop(&bytes(key_data)?)", TQ, QT,
     "test_bls_multi_parts"),
    ("ua-qt PoP part signed as a partial", QR,
     "sign_bls_multi_pop(&bytes(key_data)?)", "sign_bls_multi(&bytes(key_data)?, &[0; 32])", TQ, QT, "test_bls_multi_parts"),
    ("ua-dart-frb partial is the PoP part", FR,
     "sign_bls_multi(&key_data, &a(&ua_msg)?)?", "sign_bls_multi_pop(&key_data)?", TF, FRB, "bls_multi_json"),
    ("ua-dart-frb PoP part signed as a partial", FR,
     "sign_bls_multi_pop(&key_data)?)", "sign_bls_multi(&key_data, &[0; 32])?)", TF, FRB, "bls_multi_json"),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
