// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CTR-UA-65 (placeholder; spec 2026-11-19-registry-verify-only-kinds §12 "Clients"): a registration of `kind` goes only to the
//! registry where `kindHome(kind)` is that registry; the caller passes the `kindHome` it read (no RPC here, owner C6).
use scaas_ua::{registration_target_ok, TargetError};

const GEN1: [u8; 20] = [0x11; 20];
const GEN2: [u8; 20] = [0x22; 20];

#[test]
fn target_equal_ok() {
    assert_eq!(registration_target_ok(0x0131, &GEN1, &GEN1), Ok(()));
}

#[test]
fn target_other_verify_only() {
    let e = registration_target_ok(0x0131, &GEN2, &GEN1).unwrap_err();
    assert_eq!(
        e,
        TargetError::VerifyOnly {
            kind: 0x0131,
            kind_home: GEN1
        }
    );
    assert_eq!(e.code(), "UAVerifyOnly");
}

#[test]
fn target_zero_home_not_on_line() {
    let e = registration_target_ok(0x0131, &GEN1, &[0; 20]).unwrap_err();
    assert_eq!(e, TargetError::KindNotOnLine { kind: 0x0131 });
    assert_eq!(e.code(), "UAKindNotOnLine");
    // A zero registry with a zero home is no match either.
    assert_eq!(
        registration_target_ok(0x0131, &[0; 20], &[0; 20]),
        Err(TargetError::KindNotOnLine { kind: 0x0131 })
    );
}
