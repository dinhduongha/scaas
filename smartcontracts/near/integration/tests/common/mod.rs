//! Shared sandbox helpers of the token tests (Task 5 `account.rs`, Task 6 `metatx.rs`): SCaaS test signers
//! (ed25519, secp256k1, P-256 passkey), one sandbox + token per test, `*_check` then entry. Needs
//! `smartcontracts/scripts/build.sh near` first.
#![allow(dead_code, unused_imports)]
pub use near_contract_standards::fungible_token::metadata::{FungibleTokenMetadata, FT_METADATA_SPEC};
pub use near_workspaces::network::Sandbox;
pub use near_workspaces::result::ExecutionFinalResult;
pub use near_workspaces::types::{Finality, KeyType, NearToken, SecretKey};
pub use near_workspaces::{Account, AccountId, Contract, Worker};
pub use p256::ecdsa::signature::hazmat::PrehashSigner;
pub use scaas_near_common::hash::nep413_hash;
pub use scaas_near_common::metaop::*;
pub use scaas_near_common::ua::{self, KeyRecord, KIND_ED25519, KIND_MSIG, KIND_NEAR_ACCOUNT};
pub use scaas_near_common::webauthn::b64url;
pub use scaas_near_common::{Auth, Holder};
pub use scaas_near_token::{record_bytes, Check, Subject, KEYOP_FINISH_RECOVERY, KEYOP_SET_POLICY, POLICY_PASSKEY_FOR_VALUE, RECOVERY_DELAY_S};
pub use serde_json::{json, Value};
pub use sha2::{Digest, Sha256};

pub const TOKEN_WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_token/scaas_near_token.wasm");
pub const NETWORK: [u8; 32] = [0x22; 32];
pub const VU: u64 = 4_102_444_800;
pub const RP: &str = "pay.scaas.test";
pub const ORIGIN: &str = "https://pay.scaas.test";

pub fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn b<T: borsh::BorshSerialize>(x: &T) -> Vec<u8> {
    borsh::to_vec(x).unwrap()
}

/// A SCaaS key: ed25519, secp256k1 (near-crypto) or a P-256 passkey of `rp`.
pub enum Signer {
    Ed(near_crypto::SecretKey),
    K1(near_crypto::SecretKey),
    Pk(p256::ecdsa::SigningKey, String),
}

impl Signer {
    pub fn ed(seed: &str) -> Self {
        Signer::Ed(near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, seed))
    }
    pub fn k1(seed: &str) -> Self {
        Signer::K1(near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, seed))
    }
    pub fn pk(seed: u8, rp: &str) -> Self {
        Signer::Pk(p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap(), rp.into())
    }
    pub fn raw(&self) -> Vec<u8> {
        match self {
            Signer::Ed(k) | Signer::K1(k) => b(&k.public_key())[1..].to_vec(),
            Signer::Pk(k, _) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
        }
    }
    pub fn key(&self) -> KeyRecord {
        match self {
            Signer::Ed(_) => KeyRecord { kind: ua::KIND_ED25519, key_data: self.raw() },
            Signer::K1(_) => KeyRecord { kind: ua::KIND_SECP256K1, key_data: self.raw() },
            Signer::Pk(_, rp) => {
                KeyRecord { kind: ua::KIND_WEBAUTHN_P256, key_data: [self.raw(), sha(rp.as_bytes()).to_vec()].concat() }
            }
        }
    }
    pub fn ua(&self) -> Holder {
        Holder::Ua(self.key().id())
    }
    /// The auth for `op` (passkey assertions from `origin`).
    pub fn sign(&self, op: &MetaOp, origin: &str) -> Auth {
        let digest = op.digest();
        match self {
            Signer::Ed(k) => Auth::Ed25519 {
                key: self.raw().try_into().unwrap(),
                sig: b(&k.sign(&nep413_hash(&digest, &op.contract)))[1..].try_into().unwrap(),
            },
            Signer::K1(k) => {
                let s = b(&k.sign(&digest))[1..].to_vec();
                Auth::Secp256k1 { key: self.raw().try_into().unwrap(), sig: s[..64].try_into().unwrap(), v: s[64] }
            }
            Signer::Pk(k, rp) => {
                let ad = [&sha(rp.as_bytes())[..], &[0x05, 0, 0, 0, 0]].concat();
                let cdj = format!(
                    r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
                    b64url(&digest)
                );
                let sig: p256::ecdsa::Signature = k.sign_prehash(&sha(&[&ad[..], &sha(cdj.as_bytes())].concat())).unwrap();
                Auth::Passkey {
                    key: self.raw().try_into().unwrap(),
                    authenticator_data: ad,
                    client_data_json: cdj.into_bytes(),
                    sig: sig.normalize_s().unwrap_or(sig).to_bytes().into(),
                }
            }
        }
    }
}

pub struct T {
    pub w: Worker<Sandbox>,
    pub token: Contract,
    pub relayer: Account,
    pub alice: Account,
    pub bob: Account,
}

pub async fn setup() -> T {
    let w = near_workspaces::sandbox().await.unwrap();
    let token = w.dev_deploy(&std::fs::read(TOKEN_WASM).expect("run build.sh near first")).await.unwrap();
    let meta = FungibleTokenMetadata {
        spec: FT_METADATA_SPEC.into(),
        name: "SCaaS Test".into(),
        symbol: "SCT".into(),
        icon: None,
        reference: None,
        reference_hash: None,
        decimals: 6,
    };
    let args = b(&(NETWORK, token.id().to_string(), meta));
    token.call("new").args(args).transact().await.unwrap().into_result().unwrap();
    let relayer = w.dev_create_account().await.unwrap();
    let alice = w.dev_create_account().await.unwrap();
    let bob = w.dev_create_account().await.unwrap();
    T { w, token, relayer, alice, bob }
}

pub fn tgas(out: &ExecutionFinalResult) -> f64 {
    out.total_gas_burnt.as_gas() as f64 / 1e12
}

impl T {
    pub fn id(&self) -> AccountId {
        self.token.id().clone()
    }

    pub fn near(&self, a: &Account) -> Holder {
        Holder::Near(a.id().as_str().parse().unwrap())
    }

    /// A key op (codes 6–12) of `from` at key nonce `nonce`, `extra = sha256(params)`.
    pub fn op(&self, code: u8, from: &Holder, to: &Holder, nonce: u64, params: &[u8]) -> MetaOp {
        MetaOp {
            network: NETWORK,
            contract: self.id().as_str().parse().unwrap(),
            op: code,
            from: from.clone(),
            to: to.clone(),
            relayer: None,
            amount: 0,
            pay_ref: [0; 32],
            lane: [0; 32],
            nonce,
            valid_until: VU,
            extra: sha(params),
        }
    }

    pub async fn check(&self, caller: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8]) -> Check {
        let args = [b(&caller.id().as_str()), b(op), b(auth), params.to_vec()].concat();
        self.token.view(&format!("{entry}_check")).args(args).await.unwrap().borsh().unwrap()
    }

    pub async fn call(&self, who: &Account, entry: &str, args: Vec<u8>, yocto: u128) -> ExecutionFinalResult {
        let out = who
            .call(self.token.id(), entry)
            .args(args)
            .deposit(NearToken::from_yoctonear(yocto))
            .max_gas()
            .transact()
            .await
            .unwrap();
        println!("{entry} by {}: {:.3} Tgas, ok {}", who.id(), tgas(&out), out.is_success());
        out
    }

    /// `entry_check` (caller = `who`) then the entry with exactly `storage_needed` attached.
    pub async fn exec(&self, who: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8]) -> (Check, ExecutionFinalResult) {
        let c = self.check(who, entry, op, auth, params).await;
        let out = self.call(who, entry, [b(op), b(auth), params.to_vec()].concat(), c.storage_needed.0).await;
        (c, out)
    }

    /// `exec` that must succeed with no error in its check.
    pub async fn ok(&self, who: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8]) -> Check {
        let (c, out) = self.exec(who, entry, op, auth, params).await;
        assert_eq!(c.error, None, "{entry}");
        assert!(out.is_success(), "{entry}: {:?}", out.failures());
        c
    }

    /// The check reports `err` and the entry panics with it.
    pub async fn refused(&self, who: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8], err: &str) {
        let (c, out) = self.exec(who, entry, op, auth, params).await;
        assert!(c.error.as_deref().is_some_and(|e| e.contains(err)), "{entry}: check {:?}, want {err}", c.error);
        assert!(out.is_failure() && format!("{:?}", out.failures()).contains(err), "{entry}: {:?}", out.failures());
    }

    pub async fn subject(&self, h: &Holder) -> Option<Subject> {
        self.token.view("subject").args(b(h)).await.unwrap().borsh().unwrap()
    }

    pub async fn byte_cost(&self) -> u128 {
        let cfg = self.w.protocol_config(Finality::Final.into()).await.unwrap();
        cfg.runtime_config.storage_amount_per_byte.as_yoctonear()
    }

    pub async fn usage(&self) -> u64 {
        self.token.view_account().await.unwrap().storage_usage
    }

    pub async fn now_s(&self) -> u64 {
        self.w.view_block().await.unwrap().timestamp() / 1_000_000_000
    }

    /// `mtx_set_guardian(guardian)` signed by `s` for `from` at `nonce`.
    pub async fn set_guardian(&self, who: &Account, s: &Signer, from: &Holder, nonce: u64, g: Option<Holder>) -> Check {
        let p = b(&g);
        let op = self.op(OP_SET_GUARDIAN, from, from, nonce, &p);
        self.ok(who, "mtx_set_guardian", &op, &s.sign(&op, ORIGIN), &p).await
    }

    /// Admin mint to alice (the token is its own admin in `setup`), then `transfer_to_ua` to a new UA `h`.
    pub async fn fund(&self, h: &Holder, amount: u128) {
        let dep = NearToken::from_millinear(100);
        let first = if self.registered(&self.alice).await { NearToken::from_yoctonear(1) } else { dep };
        let out = self.token.call("mint").args_json(json!({"to": self.alice.id(), "amount": amount.to_string()}))
            .deposit(first).transact().await.unwrap();
        assert!(out.is_success(), "{:?}", out.failures());
        if let Holder::Ua(id) = h {
            let out = self.alice.call(self.token.id(), "transfer_to_ua")
                .args_json(json!({"id": id.to_vec(), "amount": amount.to_string()}))
                .deposit(dep).transact().await.unwrap();
            assert!(out.is_success(), "{:?}", out.failures());
        }
    }

    pub async fn balance(&self, h: &Holder) -> u128 {
        let v: String = match h {
            Holder::Near(a) => self.token.view("ft_balance_of").args_json(json!({"account_id": a})).await.unwrap().json().unwrap(),
            Holder::Ua(id) => self.token.view("ua_balance_of").args_json(json!({"id": id.to_vec()})).await.unwrap().json().unwrap(),
        };
        v.parse().unwrap()
    }

    pub async fn lane_nonce(&self, h: &Holder, lane: [u8; 32]) -> u64 {
        self.token.view("lane_nonce").args(b(&(h.clone(), lane))).await.unwrap().borsh().unwrap()
    }

    pub async fn registered(&self, a: &Account) -> bool {
        let v: Value =
            self.token.view("storage_balance_of").args_json(json!({"account_id": a.id()})).await.unwrap().json().unwrap();
        !v.is_null()
    }
}
