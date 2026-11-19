// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T2a: `SecretBytes` (spec §5): the copy calls by id, `dispose`, the registry. Its zeroing and blocks: the unit tests
//! in src/wallet/secret.rs; not `Clone` / `Debug`: its compile-fail doc tests.
use scaas_ua::wallet::{
    secret_dispose, secret_read, secret_write, secrets_live, Error, SecretBytes,
};
use zeroize::Zeroizing;

#[test]
fn copy_calls_by_id() {
    let s = SecretBytes::new(5).unwrap();
    assert!(s.with(|b| b == [0; 5]));
    secret_write(s.id(), b"hello").unwrap();
    assert!(s.with(|b| b == b"hello"));
    let mut out = [0u8; 8];
    assert_eq!(secret_read(s.id(), &mut out), Ok(5));
    assert_eq!(&out[..5], b"hello");
    // refusals, each beside its accepted form above
    assert_eq!(
        secret_write(s.id(), b"hell"),
        Err(Error::Argument),
        "another length"
    );
    assert_eq!(
        secret_read(s.id(), &mut [0u8; 4]),
        Err(Error::Argument),
        "a short buffer"
    );
    assert_eq!(
        secret_write(u64::MAX, b"hello"),
        Err(Error::Argument),
        "an unknown id"
    );
    s.with_mut(|b| b.copy_from_slice(b"world"));
    assert_eq!(secret_read(s.id(), &mut out), Ok(5));
    assert_eq!(&out[..5], b"world");
}

#[test]
fn secret_bytes_dispose_ends_the_id() {
    let s = SecretBytes::from_zeroizing(Zeroizing::new(b"key".to_vec())).unwrap();
    let id = s.id();
    let live = secrets_live();
    assert!(live >= 1);
    assert!(secret_dispose(id));
    assert!(!secret_dispose(id), "twice");
    assert_eq!((s.len(), s.with(<[u8]>::to_vec)), (0, vec![]));
    assert_eq!(secret_read(id, &mut [0u8; 8]), Err(Error::Argument));
    assert_eq!(secret_write(id, b""), Err(Error::Argument));
    drop(s);
    // a dropped secret leaves the registry too
    let t = SecretBytes::new(1).unwrap();
    let tid = t.id();
    drop(t);
    assert_eq!(secret_read(tid, &mut [0u8; 1]), Err(Error::Argument));
    assert_ne!(id, tid, "ids are not reused");
}
