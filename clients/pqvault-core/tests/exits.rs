// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! B2-3 (fable re-review 2026-11-25; CTR-PQV-06, C9): a removal kept under the head counts when it names the head or an
//! ancestor at most `EXIT_LAG_MAX` = 16 above it, with `nextEpoch` the named number plus one; 17 above, or another
//! `nextEpoch`, is `ChainUnverified`. A verified chain of 18 epochs built here; the seam's signature check accepts every
//! signature, so only the window and the number decide. Each negative beside its positive control, one change at a time.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use pqvault_core::records::*;
use pqvault_core::{Error, Instance, Net, PqVault, VaultState};
use scaas_sdk::app_core::{AppCall, AppKey, AppPath, AppSigned, AppWrap, MsigVersion};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::MemoryStore;
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig, SdkError};
use serde_json::Value;
use std::sync::Arc;

/// A seam whose signature check accepts every signature and that answers nothing else; a signature with slots names its
/// signer's version by its tag (an `msig`'s, for the step 6 rows).
struct Accepting;
#[async_trait::async_trait]
impl Net for Accepting {
    async fn read(&self, _: &str, _: Addr, _: &str, _: Value) -> Result<Value, SdkError> {
        Err(SdkError::Argument)
    }
    async fn sign(
        &self,
        _: &str,
        _: &KeyRef,
        _: AppPath,
        _: String,
    ) -> Result<AppSigned, SdkError> {
        Err(SdkError::Argument)
    }
    async fn verify(
        &self,
        _: &str,
        ua: B32,
        _: AppPath,
        _: String,
        sig: UaSig,
    ) -> Result<Option<Vec<MsigVersion>>, SdkError> {
        // an `msig` signer here: one with slots, its version the tag `signature` names (CTR-UA-74 step 2)
        if sig.members.is_empty() {
            return Ok(Some(vec![]));
        }
        let version = match sig.signature.len() {
            0 => 0,
            _ => u64::from_be_bytes(sig.signature.as_slice().try_into().unwrap()),
        };
        Ok(Some(vec![MsigVersion {
            msig: hex(&ua.0),
            version,
        }]))
    }
    async fn kem_wrap(
        &self,
        _: &str,
        _: B32,
        _: u64,
        _: Arc<AppKey>,
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        Err(SdkError::Argument)
    }
    async fn call(
        &self,
        _: &str,
        _: Addr,
        _: &str,
        _: Value,
        _: KeyRef,
    ) -> Result<AppCall, SdkError> {
        Err(SdkError::Argument)
    }
    async fn quote(
        &self,
        _: &str,
        _: Addr,
        _: &str,
        _: Value,
        _: KeyRef,
        _: KeyRef,
    ) -> Result<scaas_sdk::app_core::AppQuote, SdkError> {
        Err(SdkError::Argument)
    }
}

async fn vault() -> PqVault {
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let core = PqVault::scope(&sdk).unwrap();
    PqVault::with_net(sdk, core, Arc::new(Accepting))
}

const ME: B32 = B32([0x11; 32]);
/// One SDK scope at a time (an app's labels are the process's while its scope lives).
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const BOB: B32 = B32([0x22; 32]);

/// A portable vault of ME (its admin) and BOB, then 17 epochs by ME: `epochs[0..=17]`, ids recomputed, parents chained.
fn chain() -> VaultState {
    let (home_chain, home) = (B32([1; 32]), Addr([0xaa; 20]));
    let vid = vault_id(ME, 1, 0, home_chain, home);
    let create = VaultCreate {
        creator: ME,
        nonce: Num(1),
        mode: Num(0),
        home_chain,
        home_vault_contract: home,
        admins: vec![ME],
        members: vec![],
        wrap_hashes: vec![],
        pass_kdf: Num(0),
        pass_salt: B32::default(),
        sealed_info: Bytes(vec![]),
        group_mode: Num(0),
    };
    let mut epochs: Vec<pqvault_core::EpochState> = vec![];
    for n in 0..=17u64 {
        let (id, parent) = if n == 0 {
            (vid, B32::default())
        } else {
            (epoch_id(vid, ME, 100 + n), epochs[n as usize - 1].id)
        };
        epochs.push(pqvault_core::EpochState {
            id,
            number: n,
            parent,
            author: ME,
            admins: vec![ME],
            members: vec![],
            wrap_hashes: vec![],
            pass_kdf: 0,
            pass_salt: B32::default(),
            sealed_info: vec![],
            nonce: 100 + n,
            sig: UaSig::default(),
            removals: vec![],
            own_wraps: vec![],
        });
    }
    VaultState {
        at: Instance {
            chain: "anvil".into(),
            chain_id: 31337,
            contract: Addr([0xaa; 20]),
        },
        chain_uid: home_chain,
        vault_id: vid,
        create,
        epochs,
        me: ME,
        verified: false,
        pending: false,
    }
}

/// The state with one removal by `admin` of BOB naming epoch `named`, `next` its `nextEpoch`, kept under the head.
fn with_removal(named: usize, next: u64, admin: B32) -> VaultState {
    let mut s = chain();
    let r = VaultRemove {
        vault_id: s.vault_id,
        epoch_id: s.epochs[named].id,
        next_epoch: Num(next),
        members: vec![BOB],
        admin,
        nonce: Num(7),
    };
    s.epochs[17].removals.push(Signed {
        record: r,
        sig: UaSig::default(),
    });
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removal_names_the_head_or_an_ancestor_within_16() {
    let _one = ONE.lock().await;
    let pv = vault().await;
    let ok = |s: VaultState| {
        let pv = &pv;
        async move { pv.verify(s).await.map(|s| s.verified) }
    };
    assert!(ok(chain()).await.unwrap(), "the chain without a removal");
    // the head itself, and 16 above it: verified, the removal counted
    let s = pv.verify(with_removal(17, 18, ME)).await.unwrap();
    assert!(s.epochs[17].removed().contains(&BOB));
    assert!(ok(with_removal(1, 2, ME)).await.unwrap());
    // 17 above the head: refused
    assert!(matches!(
        ok(with_removal(0, 1, ME)).await,
        Err(Error::ChainUnverified)
    ));
    // the named epoch's nextEpoch not its number plus one: the head's plus one, or the named number itself
    assert!(matches!(
        ok(with_removal(1, 18, ME)).await,
        Err(Error::ChainUnverified)
    ));
    assert!(matches!(
        ok(with_removal(1, 1, ME)).await,
        Err(Error::ChainUnverified)
    ));
    // a remover outside the head's admins: refused; its twin, the admin, above
    assert!(matches!(
        ok(with_removal(1, 2, BOB)).await,
        Err(Error::ChainUnverified)
    ));
}

/// An `msig`'s signature at `version` for the seam: one slot, the tag `signature`.
fn at_version(version: u64) -> UaSig {
    UaSig {
        key_data: vec![],
        signature: scaas_ua_tag(version),
        members: vec![MemberSig {
            index: 0,
            members: vec![],
            sig: vec![1],
        }],
    }
}

fn scaas_ua_tag(version: u64) -> Vec<u8> {
    if version == 0 {
        vec![]
    } else {
        version.to_be_bytes().to_vec()
    }
}

/// C-3, R-2 (CTR-UA-74 step 6 along a vault): ME, an `msig` here, signs epoch 5 at version 1; epoch 9 under an empty tag (the
/// old quorum, version 0) is refused, as is the create record at version 1 followed by epoch 1 at 0, and a removal kept under
/// the head at version 0; each twin, at version 1, verifies.
#[tokio::test(flavor = "multi_thread")]
async fn an_msig_version_never_goes_back_along_the_vault() {
    let _one = ONE.lock().await;
    let pv = vault().await;
    let ok = |s: VaultState| {
        let pv = &pv;
        async move { pv.verify(s).await.map(|s| s.verified) }
    };
    let with = |at: &[(usize, u64)]| {
        let mut s = chain();
        for (i, v) in at {
            s.epochs[*i].sig = at_version(*v);
        }
        s
    };
    assert!(ok(with(&[(5, 1), (9, 1)])).await.unwrap(), "twin: 1 then 1");
    assert!(ok(with(&[(5, 0), (9, 1)])).await.unwrap(), "twin: 0 then 1");
    assert!(matches!(
        ok(with(&[(5, 1), (9, 0)])).await,
        Err(Error::ChainUnverified)
    ));
    // the create record's signature is epoch 0's
    assert!(matches!(
        ok(with(&[(0, 1), (1, 0)])).await,
        Err(Error::ChainUnverified)
    ));
    assert!(ok(with(&[(0, 1), (1, 1)])).await.unwrap());
    let mut s = with_removal(17, 18, ME);
    s.epochs[5].sig = at_version(1);
    s.epochs[17].removals[0].sig = at_version(0);
    assert!(matches!(ok(s).await, Err(Error::ChainUnverified)));
    let mut s = with_removal(17, 18, ME);
    s.epochs[5].sig = at_version(1);
    s.epochs[17].removals[0].sig = at_version(1);
    assert!(ok(s).await.unwrap(), "twin: the removal at 1");
}

/// A-1 (CTR-UA-74, CTR-PQV): an epoch an `msig` signed before an `updateMsig` (no tag), copied to a replica with its registry's
/// current tag, agrees with the home's, as does one whose inner `msig` slot carries another tag; a copy that differs in anything
/// but the tags (a single-key slot's signature, an inner leaf's) does not.
#[test]
fn a_replica_epoch_agrees_without_its_tags() {
    let home = {
        let mut e = chain().epochs[3].clone();
        e.sig = UaSig {
            key_data: vec![],
            signature: vec![],
            members: vec![
                MemberSig {
                    index: 0,
                    members: vec![],
                    sig: vec![7; 40],
                },
                MemberSig {
                    index: 1,
                    members: vec![InnerSig {
                        index: 0,
                        sig: vec![8; 40],
                    }],
                    sig: vec![],
                },
            ],
        };
        e
    };
    let copy = |f: fn(&mut UaSig)| {
        let mut e = home.clone();
        f(&mut e.sig);
        e
    };
    assert!(pqvault_core::epoch_agrees(&home, &home.clone()));
    assert!(
        pqvault_core::epoch_agrees(&copy(|s| s.signature = 2u64.to_be_bytes().to_vec()), &home),
        "the outer tag"
    );
    assert!(
        pqvault_core::epoch_agrees(
            &copy(|s| s.members[1].sig = 1u64.to_be_bytes().to_vec()),
            &home
        ),
        "an inner msig slot's tag"
    );
    assert!(
        !pqvault_core::epoch_agrees(&copy(|s| s.members[0].sig[0] ^= 1), &home),
        "a single-key slot's signature"
    );
    assert!(
        !pqvault_core::epoch_agrees(&copy(|s| s.members[1].members[0].sig[0] ^= 1), &home),
        "an inner leaf's signature"
    );
    // a single key's signature is its signature, never a tag
    let single = |sig: Vec<u8>| {
        let mut e = home.clone();
        e.sig = UaSig {
            signature: sig,
            ..UaSig::default()
        };
        e
    };
    assert!(!pqvault_core::epoch_agrees(
        &single(vec![1; 8]),
        &single(vec![2; 8])
    ));
}
