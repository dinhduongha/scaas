# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T1's mutants (the ua-rs PqChat key entries): python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t1-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

K = "clients/ua-rs/src/wallet/pqchat_keys.rs"
A = "clients/ua-rs/src/wallet/appkey.rs"
T = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors --test pqchat_keys "
MUTANTS = [
    # removed after the first run (survived, equivalent): "K2 without the P14 modulus check": `ml_kem`'s `Ek::new` runs the
    # same FIPS 203 §7.2 modulus check again (kem.rs `encaps`), so the p14 rows stay refused with `KemCheck`; the function
    # itself is tested directly (tests/wallet_kem.rs, `ek_modulus_ok` on the FIPS rows)
    ("K2's info without kemPkHash",
     [(A, "    let info = [label, aad, &[1u8], &crate::keccak256(kem_pk)].concat();",
       "    let info = [label, aad, &[1u8]].concat();")], T + "wraps_and_p14"),
    ("K2's AAD without keyId",
     [(K, "    [&session[..], epoch, member, &be64(key_id)].concat()", "    [&session[..], epoch, member].concat()")],
     T + "wraps_and_p14"),
    ("K3 with a salt",
     [(K, "let ck = hkdf_sha256(&key[..], &[], &[CHAIN, &ctx].concat(), 32)?;",
       "let ck = hkdf_sha256(&key[..], &[1], &[CHAIN, &ctx].concat(), 32)?;")], T + "chains_and_the_far_read"),
    ("advance swapping the 0x01 and 0x02 messages",
     [(K, "ck = key32(&hmac_sha256(&ck[..], &[2]))?;", "ck = key32(&hmac_sha256(&ck[..], &[1]))?;"),
      (K, "let mk = key32(&hmac_sha256(&ck[..], &[1]))?;", "let mk = key32(&hmac_sha256(&ck[..], &[2]))?;")],
     T + "chains_and_the_far_read"),
    ("S5 dropping the AAD",
     [(K, "aead_seal(Alg::Aes256GcmSiv, &mk, &n, &message_aad(h), &pt)?;", "aead_seal(Alg::Aes256GcmSiv, &mk, &n, &[], &pt)?;")],
     T + "message_envelope_payload"),
    ("the canonical check sorting by UTF-8",
     [(K, "keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));", "keys.sort();")], T + "canonical_json_rows"),
    ("unpad accepting a non-zero fill",
     [(K, "    if *again != pt {", "    if again.len() != pt.len() {")], T + "padding_rows_and_unpad_refusals"),
    ("V2 without the members bound",
     [(K, "    let n = a.num(ml, MEMBERS_MAX as u64)?;", "    let n = a.num(ml, u16::MAX as u64)?;")], T + "bounded_decoders"),
    ("the hint call accepting a chain position",
     [(K, "        if !matches!(k.origin, Origin::Drawn | Origin::Unwrapped) {",
       "        if !matches!(k.origin, Origin::Drawn | Origin::Unwrapped | Origin::Chain) {")],
     T + "refusals_one_change_at_a_time"),
    ("the walk bound off by a factor",
     [(K, "        if n > WALK_MAX {\n            return Err(Error::PqChatTooFar);", "        if n > 2 * WALK_MAX {\n            return Err(Error::PqChatTooFar);")],
     T + "the_walk_bound"),
]

if __name__ == "__main__":
    main("t1", MUTANTS)
