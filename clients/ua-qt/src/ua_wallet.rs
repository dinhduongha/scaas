// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `UaWallet` (ua-rs-sign T13b, spec §9.2): the QML singleton of the wallet. It gets **public data**, **`seal` to a public key**
//! and **sign requests by handle id**, nothing else: no decapsulation, no open, no raw-digest signature, no `Any` typed data, no
//! export, no key handle (spec §6.2: a KEM handle is a decapsulation oracle, never handed to a script layer). The wallet itself
//! is opened on the C++ side of the app (ua-cxx, `scaas_ua.hpp`), which hands a key to QML as an id (`scaas::ua::registerKey`).
//! Every invokable first runs ua-cxx's load check (`scaas::ua::load`: abi_version and features), clears `lastError`, and on
//! failure sets it to the error code (`UAAbiMismatch`, `UAKeyRevoked`, `UAPolicyRefused`, ...) and returns "" (strings), false
//! or -1. Bytes travel as "0x…" hex, JSON as strings. UNAUDITED.
#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
        include!("scaas_ua.hpp");
        /// The load check of ua-cxx: the linked core's abi_version and features against the header's.
        #[namespace = "scaas::ua"]
        fn load() -> Result<()>;
    }

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qml_singleton]
        #[qproperty(QString, last_error, cxx_name = "lastError")]
        type UaWallet = super::UaWalletRust;

        /// A UA key's key data, a native key's public key.
        #[qinvokable] #[cxx_name = "keyData"] fn key_data(self: Pin<&mut Self>, id: i32) -> QString;
        /// A UA key's UA (none for a MuSig2 participant).
        #[qinvokable] fn ua(self: Pin<&mut Self>, id: i32) -> QString;
        /// A native key's address (none for a network without one).
        #[qinvokable] fn address(self: Pin<&mut Self>, id: i32) -> QString;
        /// A native key's network name ("" for a UA key).
        #[qinvokable] fn network(self: Pin<&mut Self>, id: i32) -> QString;
        /// A UA key's kind, 0 for a native key, -1 on failure.
        #[qinvokable] fn kind(self: Pin<&mut Self>, id: i32) -> i32;
        #[qinvokable] #[cxx_name = "isUa"] fn is_ua(self: Pin<&mut Self>, id: i32) -> bool;
        #[qinvokable] #[cxx_name = "signUa"] fn sign_ua(self: Pin<&mut Self>, id: i32, purpose: &QString, digest: &QString) -> QString;
        #[qinvokable] #[cxx_name = "signMember"]
        fn sign_member(self: Pin<&mut Self>, id: i32, structure_ua: &QString, structure_ua_msg: &QString) -> QString;
        /// Typed data through the signing policy: `expect_json` says what the user confirmed (spec §5.4).
        #[qinvokable] #[cxx_name = "signTyped"]
        fn sign_typed(self: Pin<&mut Self>, id: i32, typed_data_json: &QString, expect_json: &QString) -> QString;
        /// The raw transaction.
        #[qinvokable] #[cxx_name = "signTransaction"] fn sign_transaction(self: Pin<&mut Self>, id: i32, tx_json: &QString) -> QString;
        #[qinvokable] #[cxx_name = "signKeyProof"] fn sign_key_proof(self: Pin<&mut Self>, id: i32, challenge: &QString) -> QString;
        /// The UASig builder: `request_json` as ua-c's `scaas_ua_uasig`, its key positions index `ids_json`, a JSON array of ids.
        #[qinvokable] #[cxx_name = "uaSig"] fn ua_sig(self: Pin<&mut Self>, request_json: &QString, ids_json: &QString) -> QString;
        /// A seal to `kem_pk` (authenticates no sender): JSON `{mlkemCt, x25519Eph, ciphertext}`.
        #[qinvokable]
        fn seal(self: Pin<&mut Self>, kem_pk: &QString, purpose: &QString, aad: &QString, pt: &QString) -> QString;
    }
}

use core::pin::Pin;
use cxx_qt_lib::QString;
use scaas_ua::wallet as uw;
use scaas_ua_cxx::wallet::{registered, Key};
use scaas_ua_cxx::UaErr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct UaWalletRust {
    last_error: QString,
}

/// An error code ("UAKeyRevoked"); never an input.
type Res<T> = Result<T, String>;
const ARG: &str = "UAArgument";

fn code(e: UaErr) -> String {
    let s = e.to_string();
    s.split(": ").next().unwrap_or(ARG).to_string()
}
fn wallet<T>(r: uw::Result<T>) -> Res<T> {
    r.map_err(|e| code(e.into()))
}
fn hx(b: &[u8]) -> String {
    b.iter().fold(String::from("0x"), |s, x| s + &format!("{x:02x}"))
}
fn bytes(q: &QString) -> Res<Vec<u8>> {
    let t = String::from(q);
    let h = t.strip_prefix("0x").unwrap_or(&t);
    if !h.len().is_multiple_of(2) || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ARG.into());
    }
    (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|x| u8::from_str_radix(x, 16).ok()).ok_or_else(|| ARG.into())).collect()
}
fn fixed<const N: usize>(q: &QString) -> Res<[u8; N]> {
    bytes(q)?.try_into().map_err(|_| ARG.into())
}
fn key(id: i32) -> Res<Key> {
    u64::try_from(id).ok().and_then(registered).ok_or_else(|| ARG.into())
}
fn ua_key(k: &Key) -> Res<&uw::UaKey> {
    k.ua_key().ok_or_else(|| ARG.into())
}
fn native_key(k: &Key) -> Res<&uw::NativeKey> {
    k.native_key().ok_or_else(|| ARG.into())
}

impl qobject::UaWallet {
    /// The load check, then `f` (panic-guarded), `lastError` cleared first and set on failure.
    fn run<T: Default>(mut self: Pin<&mut Self>, f: impl FnOnce() -> Res<T>) -> T {
        self.as_mut().set_last_error(QString::default());
        let r = catch_unwind(AssertUnwindSafe(|| {
            qobject::load().map_err(|e| e.what().split(": ").next().unwrap_or("UAAbiMismatch").to_string())?;
            f()
        }));
        match r.unwrap_or_else(|_| Err("UAInternal".into())) {
            Ok(v) => v,
            Err(c) => {
                self.set_last_error(QString::from(&c));
                T::default()
            }
        }
    }
    fn text(self: Pin<&mut Self>, f: impl FnOnce() -> Res<String>) -> QString {
        QString::from(&self.run(f))
    }
    fn hex(self: Pin<&mut Self>, f: impl FnOnce() -> Res<Vec<u8>>) -> QString {
        self.text(|| f().map(|b| hx(&b)))
    }

    pub fn key_data(self: Pin<&mut Self>, id: i32) -> QString {
        self.hex(|| {
            let k = key(id)?;
            Ok(k.ua_key().map_or_else(|| k.native_key().map(uw::NativeKey::public_key).unwrap_or_default(), uw::UaKey::key_data))
        })
    }
    pub fn ua(self: Pin<&mut Self>, id: i32) -> QString {
        self.hex(|| ua_key(&key(id)?)?.ua().map(|u| u.to_vec()).ok_or_else(|| ARG.into()))
    }
    pub fn address(self: Pin<&mut Self>, id: i32) -> QString {
        self.text(|| native_key(&key(id)?)?.address().ok_or_else(|| ARG.into()))
    }
    pub fn network(self: Pin<&mut Self>, id: i32) -> QString {
        self.text(|| Ok(key(id)?.native_key().map(|n| n.network().name().to_string()).unwrap_or_default()))
    }
    pub fn kind(self: Pin<&mut Self>, id: i32) -> i32 {
        let v = self.run(|| Ok(Some(key(id)?.ua_key().map_or(0, |u| i32::from(u.kind())))));
        v.unwrap_or(-1)
    }
    pub fn is_ua(self: Pin<&mut Self>, id: i32) -> bool {
        self.run(|| Ok(key(id)?.ua_key().is_some()))
    }
    pub fn sign_ua(self: Pin<&mut Self>, id: i32, purpose: &QString, digest: &QString) -> QString {
        self.hex(|| wallet(ua_key(&key(id)?)?.sign_ua(&fixed(purpose)?, &fixed(digest)?)))
    }
    pub fn sign_member(self: Pin<&mut Self>, id: i32, structure_ua: &QString, structure_ua_msg: &QString) -> QString {
        self.hex(|| wallet(ua_key(&key(id)?)?.sign_member(&fixed(structure_ua)?, &fixed(structure_ua_msg)?)))
    }
    pub fn sign_typed(self: Pin<&mut Self>, id: i32, typed_data_json: &QString, expect_json: &QString) -> QString {
        self.hex(|| {
            let k = key(id)?;
            let td = wallet(uw::TypedData::from_json(String::from(typed_data_json).as_bytes()))?;
            let expect = wallet(uw::Expect::from_json(String::from(expect_json).as_bytes()))?;
            wallet(native_key(&k)?.sign_typed(&td, expect))
        })
    }
    pub fn sign_transaction(self: Pin<&mut Self>, id: i32, tx_json: &QString) -> QString {
        self.hex(|| {
            let k = key(id)?;
            let tx = wallet(uw::EvmTx::from_json(String::from(tx_json).as_bytes()))?;
            Ok(wallet(native_key(&k)?.sign_transaction(&tx))?.raw)
        })
    }
    pub fn sign_key_proof(self: Pin<&mut Self>, id: i32, challenge: &QString) -> QString {
        self.hex(|| wallet(native_key(&key(id)?)?.sign_key_proof(&bytes(challenge)?)))
    }
    pub fn ua_sig(self: Pin<&mut Self>, request_json: &QString, ids_json: &QString) -> QString {
        self.text(|| {
            let ids: Vec<i32> = serde_json::from_str(&String::from(ids_json)).map_err(|_| String::from(ARG))?;
            let keys = ids.into_iter().map(key).collect::<Res<Vec<Key>>>()?;
            let req = wallet(uw::UaSigRequest::from_json(String::from(request_json).as_bytes()))?;
            let signers: Vec<&dyn uw::Signer> = keys.iter().map(Key::signer).collect();
            Ok(scaas_ua::json::uasig_json(&wallet(req.sign(&signers))?))
        })
    }
    pub fn seal(self: Pin<&mut Self>, kem_pk: &QString, purpose: &QString, aad: &QString, pt: &QString) -> QString {
        self.text(|| {
            let pt = Zeroizing::new(bytes(pt)?);
            let s = wallet(uw::seal(&bytes(kem_pk)?, &String::from(purpose), &bytes(aad)?, &pt))?;
            Ok(serde_json::json!({"mlkemCt": hx(&s.mlkem_ct), "x25519Eph": hx(&s.x25519_eph), "ciphertext": hx(&s.ciphertext)}).to_string())
        })
    }
}
