// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T42's size probe (runs/fam-sizes.sh): one binary that reaches every family's entry points a build has, so the
//! release binary's size per `fam-<row>` feature counts their code (an unused rlib function would be dropped at link time).
//! `fam_size <mnemonic> <message hex>`; it prints what each network answers. Not a tool. UNAUDITED.
use scaas_ua::wallet::{AllowRawDigest, EvmTx, Network, Wallet};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (Some(words), Some(msg)) = (a.get(1), a.get(2)) else {
        eprintln!("usage: fam_size <mnemonic> <message>");
        std::process::exit(2);
    };
    let w = Wallet::from_mnemonic(words, "").unwrap();
    let m = msg.as_bytes();
    for n in Network::all() {
        let key = match n {
            Network::Polkadot => w.polkadot_key(msg),
            _ => w.native_key(n, m.len() as u32, None),
        };
        let Ok(k) = key else {
            println!("{n:?}: off");
            continue;
        };
        let sig = match n {
            Network::Near => k.sign_near_transaction(m, AllowRawDigest),
            Network::Sui => k.sign_sui_transaction(m, AllowRawDigest),
            Network::Stellar => k.sign_stellar_transaction(&[m[0]; 32], m, AllowRawDigest),
            Network::HederaEd25519 => k.sign_hedera_transaction(m, AllowRawDigest),
            Network::Polkadot => k.ss58_address(0).map(String::into_bytes),
            _ => k.sign_message(m, AllowRawDigest),
        };
        println!("{n:?}: {:?} {}", k.address(), sig.map_or(0, |s| s.len()));
    }
    println!("evm tx: {:?}", EvmTx::from_json(m).and_then(|t| t.sighash()).is_ok());
    #[cfg(feature = "fam-near")]
    println!("near: {:?}", scaas_ua::near::metaop_digest(m)[0]);
    #[cfg(feature = "fam-algorand")]
    println!("algorand: {:?}", scaas_ua::algorand::address_to_key(msg).is_ok());
    #[cfg(feature = "fam-solana")]
    println!("solana: {:?}", scaas_ua::families::solana::account_of(&[m[0]; 32], &[1; 32]).is_some());
    #[cfg(feature = "fam-sui")]
    println!("sui: {:?}", scaas_ua::families::sui::account_of(&[m[0]; 32], &[1; 32])[0]);
}
