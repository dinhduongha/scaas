// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T4 (R17): `bip39_word_in_list`, a listed word true, an unlisted word and a near miss false.
use scaas_ua::wallet::bip39_word_in_list;

#[test]
fn word_in_list() {
    for w in ["abandon", "zoo", "Bench", " hurt ", "frown"] {
        assert!(bip39_word_in_list(w), "{w}");
    }
    for w in ["abandonn", "bnech", "", "zoo zoo", "hello1", "abando"] {
        assert!(!bip39_word_in_list(w), "{w}");
    }
}

#[test]
fn word_count_of_a_wallet() {
    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let w = scaas_ua::wallet::Wallet::from_mnemonic(twelve, "").unwrap();
    assert_eq!(w.word_count(), Ok(12));
    let (g, _) = scaas_ua::wallet::Wallet::generate().unwrap();
    assert_eq!(g.word_count(), Ok(24));
    w.lock();
    assert_eq!(w.word_count(), Err(scaas_ua::wallet::Error::WalletLocked));
}
