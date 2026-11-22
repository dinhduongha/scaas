// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The R32 form of `tests/r33_keys.rs`'s mnemonic test before plan T23 (scaas-sdk; spec §25 Q-K15, owner 2026-11-17: 12 to 24
// words accepted with the short-seed flag). Kept as it was; not built.
#[test]
fn bip39_seed_and_24_word_rule() {
    assert_eq!(
        hex::encode(seed()),
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
    );
    // 12 words: valid BIP-39 but R32 demands 24.
    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(seed_from_mnemonic(twelve, "").is_err());
    // bad checksum
    assert!(seed_from_mnemonic(&ABANDON_ART.replace(" art", " abandon"), "").is_err());
}
