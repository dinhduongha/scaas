// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! One command per SDK call (CLI-SDK-17): `"<group> <call>"`, the SDK call it runs, its flags (one struct's fields, flattened,
//! or one flag per parameter) and what it returns. `tests/cli.rs` holds this table equal to the SDK's public calls both ways,
//! with [`EXCLUDED`] named and reasoned.
use crate::flex::Flex;
use crate::{handle, hexed, js, named, review, Cx, Fail, Out, H};
use scaas_sdk::account::*;
use scaas_sdk::admin::delay::HolderKind;
use scaas_sdk::admin::*;
use scaas_sdk::app_core::*;
use scaas_sdk::confidential::*;
use scaas_sdk::dex::*;
use scaas_sdk::events::Subscription;
use scaas_sdk::op::{
    BlsMultiPart, ImportExpect, KeyRef, OpState, Prepared, SignedOpBlob, SubmitPath, SubmitQuote,
};
use scaas_sdk::pqchat_keys::*;
use scaas_sdk::pqchat_records::*;
use scaas_sdk::vault::{
    keystore, store, ConfirmRemove, ConfirmRemoveUnbacked, DeriveChild, DeriveFromKey,
    DeriveFromSignature, Generate, ImportKey, ImportWords, Keystore, Remove, SeedBackup, Unlock,
};
use scaas_sdk::wallet::*;
use scaas_sdk::{GasTable, Sdk};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// SDK calls without a command of their own, each with its reason.
pub const EXCLUDED: &[(&str, &str)] = &[
    (
        "Sdk::open",
        "every command opens the SDK over the data directory, the profiles and the overlay",
    ),
    (
        "SdkError::code",
        "every refusal the CLI prints is the SDK's code",
    ),
    (
        "SdkError::own_variants",
        "the SDK's own tests of its code names",
    ),
    (
        "lib::features",
        "the same as `Sdk::features` (`sdk features`)",
    ),
    (
        "Sdk::spawn",
        "Rust-only: the executor of the SDK's own calls",
    ),
    (
        "Sdk::authenticator",
        "Rust-only: the CLI configures no authenticator",
    ),
    ("Sdk::vault", "the group `vault`"),
    ("Sdk::account", "the group `account`"),
    ("Sdk::wallet", "the group `wallet`"),
    ("Sdk::confidential", "the group `confidential`"),
    ("Sdk::dex", "the group `dex`"),
    ("Sdk::admin", "the group `admin`"),
    ("Sdk::op", "the group `op`"),
    ("AppCore::new", "the group `app-core`, from `--app <file>`"),
    (
        "StoreLock::new",
        "the store's own lock: the CLI's store is the data directory",
    ),
    (
        "MemoryStore::new",
        "the CLI's store is the data directory (`FileStore`)",
    ),
    ("FileStore::new", "the data directory (`--data-dir`)"),
    (
        "Wallet::native_sign",
        "feature raw-native: off in the CLI (no input that signs undecoded bytes, as CLI-TUI-17)",
    ),
    ("AllowRawNative::new", "feature raw-native: off in the CLI"),
    (
        "AllowOpaqueCall::new",
        "feature opaque-calls: off in the CLI",
    ),
    // T41.arweave (CLI-SDK-21): an Arweave upload is public and permanent (a live one is the owner's, plan T21)
    (
        "ArweaveFiles::new",
        "feature arweave: off in the CLI (a permanent public upload)",
    ),
    (
        "ArweaveFiles::upload_file",
        "feature arweave: off in the CLI (a permanent public upload)",
    ),
    ("ArweaveFiles::keep_up", "feature arweave: off in the CLI"),
    (
        "ArweaveFiles::fetch_file",
        "feature arweave: off in the CLI",
    ),
    (
        "AppCore::seal_for_arweave",
        "feature arweave: off in the CLI",
    ),
];

fn take<T: serde::de::DeserializeOwned>(m: Map<String, Value>) -> Result<T, Fail> {
    Ok(T::deserialize(Flex(Value::Object(m)))?)
}

macro_rules! args {
    ($m:ident, ($r:ident : $t:ty), $body:expr) => {{
        let $r: $t = take($m)?;
        Ok($body)
    }};
    ($m:ident, { $($a:ident : $t:ty),* $(,)? }, $body:expr) => {{
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct A { $($a: $t),* }
        let A { $($a),* } = take($m)?;
        Ok($body)
    }};
}

macro_rules! desc {
    (($r:ident : $t:ty)) => {
        crate::flex::fields::<$t>()
    };
    ({ $($a:ident : $t:ty),* $(,)? }) => {
        vec![$(stringify!($a)),*]
    };
}

/// A command's confirm (`scaas commands`): `op` returns an operation object, which one command submits only after its review
/// and quote are confirmed (`finish`; the body's type must be one, [`crate::IntoOp`]); `sign` asks in its body before it signs
/// or submits; none neither signs nor submits.
macro_rules! class {
    (op) => {
        Some("op")
    };
    (sign) => {
        Some("sign")
    };
    () => {
        None
    };
}

macro_rules! body {
    (op; $body:expr) => {
        crate::IntoOp::into_op($body)
    };
    ($($c:ident)?; $body:expr) => {
        $body
    };
}

macro_rules! calls {
    ($cx:ident; $( $cli:literal $sdk:literal $args:tt $([$($s:literal),*])? $(@$class:ident)? => $body:expr; )*) => {
        /// Every command, the SDK call it runs and its confirm.
        pub const CALLS: &[(&str, &str, Option<&str>)] = &[ $( ($cli, $sdk, class!($($class)?)), )* ];

        /// Runs command `cmd` with flags `m`.
        pub async fn dispatch($cx: &mut Cx, cmd: &str, m: Map<String, Value>) -> Result<Out, Fail> {
            match cmd {
                $( $cli => args!(m, $args, body!($($class)?; $body)), )*
                _ => Err(Fail::cli("UnknownCommand", cmd)),
            }
        }

        /// The flags of command `cmd`.
        pub fn describe(cmd: &str) -> Option<Vec<&'static str>> {
            match cmd { $( $cli => Some(desc!($args)), )* _ => None }
        }

        /// The secrets of command `cmd`, each read from `--<name>-fd` or the terminal.
        pub fn secrets(cmd: &str) -> Vec<&'static str> {
            match cmd { $( $cli => vec![$($($s),*)?], )* _ => vec![] }
        }
    };
}

fn sdk(cx: &Cx) -> Arc<Sdk> {
    cx.sdk.clone()
}

/// `Unlock` by its name (`passphrase` reads the secret `passphrase`).
fn unlock_by(cx: &mut Cx, by: &str) -> Result<Unlock, Fail> {
    match by {
        "passphrase" => Ok(Unlock::Passphrase(cx.secret("passphrase")?)),
        "passkey" => Ok(Unlock::Passkey),
        "platform" => Ok(Unlock::Platform),
        _ => Err(Fail::cli(
            "Argument",
            "--by passphrase | passkey | platform",
        )),
    }
}

/// `AppNonce` by name: `Random`, `FromKey`, or `{"FromHandle": "<key name>"}`.
#[derive(serde::Deserialize)]
enum Nonce {
    Random,
    FromKey,
    FromHandle(H<Arc<AppKey>>),
}

impl Nonce {
    fn sdk(self) -> AppNonce {
        match self {
            Nonce::Random => AppNonce::Random,
            Nonce::FromKey => AppNonce::FromKey,
            Nonce::FromHandle(k) => AppNonce::FromHandle(k.0),
        }
    }
}

/// The SDK's `Result<(), _>` as `{"ok": true}`.
fn ok() -> Out {
    named("ok", true)
}

fn key_shown() -> Value {
    json!({"key": "an app key handle (never readable)"})
}

calls! { cx;
    // ---- Sdk
    "sdk api-version" "Sdk::api_version" {} => named("api_version", Sdk::api_version());
    "sdk features" "Sdk::features" {} => named("features", Sdk::features());
    "sdk limits" "Sdk::limits" {} => js(cx.sdk.limits());
    "sdk heavy-peak" "Sdk::heavy_peak" {} => named("heavy_peak", cx.sdk.heavy_peak());
    "sdk subscribe" "Sdk::subscribe" {} => handle(cx.sdk.subscribe(), json!({"subscription": "open"}));
    "sdk watch" "Sdk::watch" {account: String, chains: Vec<String>} => { cx.sdk.watch(account, chains).await?; ok() };
    "sdk state-rev" "Sdk::state_rev" {} => named("state_rev", cx.sdk.state_rev().await?);
    "sdk poll" "Sdk::poll" {} => { cx.sdk.poll().await?; ok() };
    "subscription next" "Subscription::next" {subscription: H<Arc<Subscription>>, timeout_ms: u64} => named("event", subscription.0.next(timeout_ms).await);
    "op-state is-terminal" "OpState::is_terminal" (s: OpState) => named("is_terminal", s.is_terminal());
    "gas-table parse" "GasTable::parse" {text: String} => js(GasTable::parse(&text)?);

    // ---- vault
    "vault seeds" "Vault::seeds" {} => js(sdk(cx).vault().seeds().await?);
    "vault seed" "Vault::seed" {seed: String} => js(sdk(cx).vault().seed(seed).await?);
    "vault generate" "Vault::generate" {label: String} ["vault-passphrase"] => {
        let vault_passphrase = cx.secret("vault-passphrase")?;
        Out::Seed(sdk(cx).vault().generate(Generate { label, vault_passphrase }).await?)
    };
    "vault derive-child" "Vault::derive_child" {parent: String, label: String} ["vault-passphrase"] => {
        let vault_passphrase = cx.secret("vault-passphrase")?;
        Out::Seed(sdk(cx).vault().derive_child(DeriveChild { parent, label, vault_passphrase }).await?)
    };
    "vault import-words" "Vault::import_words" {label: String} ["words", "vault-passphrase"] => {
        let words = cx.secret("words")?;
        let vault_passphrase = cx.secret("vault-passphrase")?;
        js(sdk(cx).vault().import_words(ImportWords { label, words, vault_passphrase }).await?)
    };
    "vault import-key" "Vault::import_key" {seed: String, network: String} ["secret", "vault-passphrase"] => {
        let secret = cx.secret("secret")?;
        let vault_passphrase = cx.secret("vault-passphrase")?;
        js(sdk(cx).vault().import_key(ImportKey { seed, network, secret, vault_passphrase }).await?)
    };
    "vault word-in-list" "Vault::word_in_list" {} ["word"] => { let w = cx.secret("word")?; named("in_list", sdk(cx).vault().word_in_list(w)) };
    "vault confirm-backup" "Vault::confirm_backup" {seed: String} => { sdk(cx).vault().confirm_backup(seed).await?; ok() };
    "vault rename" "Vault::rename" {seed: String, label: String} => { sdk(cx).vault().rename(seed, label).await?; ok() };
    "vault remove" "Vault::remove" {seed: String, unbacked: bool} @sign => {
        cx.confirm(json!({"remove": seed, "unbacked": unbacked}))?;
        sdk(cx).vault().remove(Remove { seed, confirm: ConfirmRemove {}, unbacked: unbacked.then_some(ConfirmRemoveUnbacked {}) }).await?;
        ok()
    };
    "vault unlock" "Vault::unlock" {seed: String, by: String} ["passphrase"] => { let u = unlock_by(cx, &by)?; sdk(cx).vault().unlock(seed, u).await?; ok() };
    "vault open-hidden" "Vault::open_hidden" {seed: String, by: String} ["passphrase", "bip39-passphrase"] => {
        let u = unlock_by(cx, &by)?;
        let p = cx.secret("bip39-passphrase")?;
        js(sdk(cx).vault().open_hidden(seed, u, p).await?)
    };
    "vault lock" "Vault::lock" {seed: String} => named("locked", sdk(cx).vault().lock(seed).await);
    "vault lock-all" "Vault::lock_all" {} => named("locked", sdk(cx).vault().lock_all().await);
    "vault keystore-rollback" "Vault::keystore_rollback" {} => named("rollback", sdk(cx).vault().keystore_rollback().await?);
    "vault memory-protection" "Vault::memory_protection" {seed: String} => named("memory_protection", format!("{:?}", sdk(cx).vault().memory_protection(seed)?));
    "vault enable-passkey-unlock" "Vault::enable_passkey_unlock" {seed: String} ["vault-passphrase"] => {
        let p = cx.secret("vault-passphrase")?; sdk(cx).vault().enable_passkey_unlock(seed, p).await?; ok()
    };
    "vault enable-platform-unlock" "Vault::enable_platform_unlock" {seed: String, policy: scaas_sdk::platform::KeyPolicy} ["vault-passphrase"] => {
        let p = cx.secret("vault-passphrase")?; sdk(cx).vault().enable_platform_unlock(seed, p, policy).await?; ok()
    };
    "vault disable-prf-unlock" "Vault::disable_prf_unlock" {seed: String} => { sdk(cx).vault().disable_prf_unlock(seed).await?; ok() };
    "vault change-passphrase" "Vault::change_passphrase" {seed: String} ["old", "new"] => {
        let (old, new) = (cx.secret("old")?, cx.secret("new")?); sdk(cx).vault().change_passphrase(seed, old, new).await?; ok()
    };
    "vault key-derivation-typed-data" "Vault::key_derivation_typed_data" {account_hex: String, set: u32} => named("typed_data", sdk(cx).vault().key_derivation_typed_data(account_hex, set)?);
    "vault signature-from-compact" "Vault::signature_from_compact" {} ["sig"] => {
        // the expanded signature is itself secret material of a root (d): it stays in this process
        let s = cx.secret("sig")?; let _ = sdk(cx).vault().signature_from_compact(s)?; named("ok", "the signature is valid; it is not printed")
    };
    "vault derive-from-signature" "Vault::derive_from_signature" {label: String, account: String, set: u32} ["signature1", "signature2", "derivation-passphrase", "vault-passphrase"] => {
        let (signature1, signature2) = (cx.secret("signature1")?, cx.secret("signature2")?);
        let (derivation_passphrase, vault_passphrase) = (cx.secret("derivation-passphrase")?, cx.secret("vault-passphrase")?);
        Out::Seed(sdk(cx).vault().derive_from_signature(DeriveFromSignature { label, account, set, signature1, signature2, derivation_passphrase, vault_passphrase }).await?)
    };
    "vault derive-from-key" "Vault::derive_from_key" {label: String, network: String, index: u32} ["key", "derivation-passphrase", "vault-passphrase"] => {
        let key = cx.secret("key")?;
        let (derivation_passphrase, vault_passphrase) = (cx.secret("derivation-passphrase")?, cx.secret("vault-passphrase")?);
        Out::Seed(sdk(cx).vault().derive_from_key(DeriveFromKey { label, network, key, derivation_passphrase, index, vault_passphrase }).await?)
    };
    "seed-backup reveal" "SeedBackup::reveal" {backup: H<Arc<SeedBackup>>} => {
        if !cx.typed_reveal() {
            return Err(Fail::cli("NotConfirmed", "the words stay hidden"));
        }
        let words = backup.0.reveal()?;
        let text = words.with(|w| String::from_utf8_lossy(w).into_owned());
        named("words", zeroize::Zeroizing::new(text).as_str())
    };
    "seed-backup challenge" "SeedBackup::challenge" {backup: H<Arc<SeedBackup>>} => named("positions", backup.0.challenge()?);
    "seed-backup verify" "SeedBackup::verify" {backup: H<Arc<SeedBackup>>} ["answers"] => { let a = cx.secret("answers")?; named("verified", backup.0.verify(a)?) };
    "keystore parse" "Keystore::parse" {bytes: Vec<u8>} => js(Keystore::parse(&bytes)?);
    "keystore serialize" "Keystore::serialize" (k: Keystore) => named("keystore", k.serialize()?);
    "keystore rev-of" "store::rev_of" {bytes: Vec<u8>} => named("rev", store::rev_of(&bytes));
    "keystore is-uuid4" "keystore::is_uuid4" {s: String} => named("is_uuid4", keystore::is_uuid4(&s));
    "keystore label-ok" "keystore::label_ok" {label: String} => named("label_ok", keystore::label_ok(&label));
    "keystore new-label-ok" "keystore::new_label_ok" {label: String} => named("new_label_ok", keystore::new_label_ok(&label));
    "keystore accounts-json" "keystore::accounts_json" {rows: Vec<scaas_sdk::vault::AccountRow>} => named("accounts", keystore::accounts_json(&rows));

    // ---- account
    "account accounts" "Account::accounts" {seed: String} => js(sdk(cx).account().accounts(seed).await?);
    "account next-account" "Account::next_account" {seed: String} => named("next_account", sdk(cx).account().next_account(seed).await?);
    "account add-ua" "Account::add_ua" (r: scaas_sdk::account::AddUa) => js(sdk(cx).account().add_ua(r).await?);
    "account add-native" "Account::add_native" (r: scaas_sdk::account::AddNative) => js(sdk(cx).account().add_native(r).await?);
    "account create-passkey-key" "Account::create_passkey_key" (r: scaas_sdk::account::CreatePasskeyKey) => js(sdk(cx).account().create_passkey_key(r).await?);
    "account create-se-key" "Account::create_se_key" (r: scaas_sdk::account::CreateSeKey) => js(sdk(cx).account().create_se_key(r).await?);
    "account add-watch" "Account::add_watch" (r: scaas_sdk::account::AddWatch) => js(sdk(cx).account().add_watch(r).await?);
    "account signs" "Account::signs" {seed: String, id: String} => named("signs", sdk(cx).account().signs(seed, id).await?);
    "account msig-state" "Account::msig_state" {chain: String, ua: String} => js(sdk(cx).account().msig_state(chain, ua).await?);
    "account prepare-msig-register" "Account::prepare_msig_register" (r: MsigRegister) @op => sdk(cx).account().prepare_msig_register(r).await?;
    "account prepare-accept-membership" "Account::prepare_accept_membership" (r: AcceptMembership) @op => sdk(cx).account().prepare_accept_membership(r).await?.into_iter().collect::<Vec<_>>();
    "account prepare-update-msig" "Account::prepare_update_msig" (r: UpdateMsig) @op => {
        let plan = sdk(cx).account().prepare_update_msig(r).await?;
        if !plan.warnings.is_empty() { crate::print_warnings(cx, &plan.warnings)?; }
        vec![plan.write]
    };
    "account prepare-register" "Account::prepare_register" (r: Register) @op => sdk(cx).account().prepare_register(r).await?;
    "account quote-registry-write" "Account::quote_registry_write" {write: H<Arc<RegistryWrite>>} => { let q = sdk(cx).account().quote_registry_write(write.0).await?; let v = serde_json::to_value(&q).unwrap_or(Value::Null); handle(q, v) };
    "account submit-registry-write" "Account::submit_registry_write" {write: H<Arc<RegistryWrite>>, quote: H<SubmitQuote>} @sign => {
        cx.confirm(json!({"review": review(&write.0.review()), "quote": quote.0, "write": write.0.id(), "chain": write.0.chain(), "entry": write.0.entry(), "ua": write.0.ua()}))?;
        { let op = sdk(cx).account().submit_registry_write(write.0, quote.0).await?; cx.sent(op).await }
    };
    "account registration-of" "Account::registration_of" {chain: String, ua: String} => js(sdk(cx).account().registration_of(chain, ua).await?);
    "account prepare-kem-repair" "Account::prepare_kem_repair" {key: KeyRef, chain: String, payer: KeyRef} @op => sdk(cx).account().prepare_kem_repair(key, chain, payer).await?.into_iter().collect::<Vec<_>>();
    "account marks" "Account::marks" {seed: String, chain: String} => js(sdk(cx).account().marks(seed, chain).await?);
    "account restore" "Account::restore" (r: Restore) => js(sdk(cx).account().restore(r).await?);
    "account prepare-smart-add-key" "Account::prepare_smart_add_key" {op: SmartOp, key: SubjectKeyArgs} @op => sdk(cx).account().prepare_smart_add_key(op, key).await?;
    "account prepare-smart-remove-key" "Account::prepare_smart_remove_key" {op: SmartOp, index: String} @op => sdk(cx).account().prepare_smart_remove_key(op, index).await?;
    "account prepare-smart-rotate-key" "Account::prepare_smart_rotate_key" {op: SmartOp, index: String, key: SubjectKeyArgs} @op => sdk(cx).account().prepare_smart_rotate_key(op, index, key).await?;
    "account prepare-smart-set-guardian" "Account::prepare_smart_set_guardian" {op: SmartOp, guardian: String} @op => sdk(cx).account().prepare_smart_set_guardian(op, guardian).await?;
    "account prepare-smart-cancel-recovery" "Account::prepare_smart_cancel_recovery" {op: SmartOp} @op => sdk(cx).account().prepare_smart_cancel_recovery(op).await?;
    "account prepare-smart-cancel-nonce" "Account::prepare_smart_cancel_nonce" {op: SmartOp, lane: String} @op => sdk(cx).account().prepare_smart_cancel_nonce(op, lane).await?;
    "account prepare-smart-execute" "Account::prepare_smart_execute" {op: SmartOp, call: SmartCall} @op => sdk(cx).account().prepare_smart_execute(op, call).await?;
    "account prepare-initiate-recovery" "Account::prepare_initiate_recovery" {op: SmartOp, account: String, new_key: SubjectKeyArgs} @op => sdk(cx).account().prepare_initiate_recovery(op, account, new_key).await?;
    "account prepare-smart-deploy" "Account::prepare_smart_deploy" {key: KeyRef, chain: String, factory: String, first_key: SubjectKeyArgs, guardian: String} @op => sdk(cx).account().prepare_smart_deploy(key, chain, factory, first_key, guardian).await?;
    "account prepare-complete-recovery" "Account::prepare_complete_recovery" {key: KeyRef, chain: String, account: String, new_key: SubjectKeyArgs} @op => sdk(cx).account().prepare_complete_recovery(key, chain, account, new_key).await?;
    "account registration-blob" "Account::registration_blob" {key: KeyRef, attrs: RegisterAttrs} => js(sdk(cx).account().registration_blob(key, attrs).await?);
    "account prepare-submit-registration" "Account::prepare_submit_registration" {blob: RegistrationBlob, chain: String, expected_ua: String, payer: KeyRef} @op => sdk(cx).account().prepare_submit_registration(blob, chain, expected_ua, payer).await?;
    "account msig-structure" "msig::msig_structure" {members: Vec<MsigMemberArgs>, threshold: u16} => js(msig_structure(members, threshold)?);
    "account smart-account-address" "smart::smart_account_address" {factory: String, implementation: String, first_key: SubjectKeyArgs, guardian: String} => named("address", smart_account_address(&factory, &implementation, &first_key, &guardian)?);
    "msig-structure ua" "MsigStructureArgs::ua" (m: MsigStructureArgs) => named("ua", m.ua()?);
    "subject-key secp256k1" "SubjectKeyArgs::secp256k1" {address: String} => js(SubjectKeyArgs::secp256k1(&address)?);
    "registration-blob from-json" "RegistrationBlob::from_json" {text: String} => js(RegistrationBlob::from_json(&text)?);
    "registration-blob to-json" "RegistrationBlob::to_json" (b: RegistrationBlob) => named("json", b.to_json()?);
    "registry-write id" "RegistryWrite::id" {write: H<Arc<RegistryWrite>>} => named("id", write.0.id());
    // the registry line of ua-rs-sign (merged 6e7e71142): the bound registry's walk and its targets
    "account ua-line" "Account::ua_line" {chain: String, ua: String} => { let l = sdk(cx).account().ua_line(chain, ua).await?; let v = serde_json::json!({"holder": l.holder, "kind": l.kind, "pqz_home": l.pqz_home}); handle(l, v) };
    "ua-line key-target" "UaLine::key_target" {line: H<scaas_sdk::UaLine>} => named("key_target", line.0.key_target());
    "ua-line pqz-target" "UaLine::pqz_target" {line: H<scaas_sdk::UaLine>} => named("pqz_target", line.0.pqz_target()?);
    "account register-target" "Account::register_target" {chain: String, kind: u16} => named("register_target", sdk(cx).account().register_target(chain, kind).await?);
    "account pqz-decoy-candidates" "Account::pqz_decoy_candidates" {chain: String} => named("pqz_decoy_candidates", sdk(cx).account().pqz_decoy_candidates(chain).await?);
    "registry-write chain" "RegistryWrite::chain" {write: H<Arc<RegistryWrite>>} => named("chain", write.0.chain());
    "registry-write entry" "RegistryWrite::entry" {write: H<Arc<RegistryWrite>>} => named("entry", write.0.entry());
    "registry-write ua" "RegistryWrite::ua" {write: H<Arc<RegistryWrite>>} => named("ua", write.0.ua());
    "registry-write review" "RegistryWrite::review" {write: H<Arc<RegistryWrite>>} => named("review", review(&write.0.review()));
    "registry-write calldata" "RegistryWrite::calldata" {write: H<Arc<RegistryWrite>>} => named("calldata", write.0.calldata());
    "registry-write payer" "RegistryWrite::payer" {write: H<Arc<RegistryWrite>>} => named("payer", write.0.payer());
    "registry-write registration-gas" "RegistryWrite::registration_gas" {write: H<Arc<RegistryWrite>>} => named("registration_gas", write.0.registration_gas());

    // ---- op
    "op state" "Op::state" {op: String} => js(sdk(cx).op().state(op).await?);
    "op quote" "Op::quote" {prepared: H<Arc<Prepared>>, path: SubmitPath} => { let q = sdk(cx).op().quote(prepared.0, path).await?; let v = serde_json::to_value(&q).unwrap_or(Value::Null); handle(q, v) };
    "op quote-with-gas" "Op::quote_with_gas" {prepared: H<Arc<Prepared>>, path: SubmitPath, gas: u64} => { let q = sdk(cx).op().quote_with_gas(prepared.0, path, gas).await?; let v = serde_json::to_value(&q).unwrap_or(Value::Null); handle(q, v) };
    "op submit" "Op::submit" {prepared: H<Arc<Prepared>>, quote: H<SubmitQuote>} @sign => { cx.confirm_op(&prepared.0, &quote.0)?; { let op = sdk(cx).op().submit(prepared.0, quote.0).await?; cx.sent(op).await } };
    "op resume" "Op::resume" {} => named("resumed", sdk(cx).op().resume().await?);
    "op resend" "Op::resend" {op: String, quote: H<SubmitQuote>} @sign => { cx.confirm(json!({"resend": op, "quote": quote.0}))?; sdk(cx).op().resend(op.clone(), quote.0).await?; cx.sent(op).await };
    // T41.evm (spec §27.5 (c)): the signer's hand-off signs once and sends nothing; the payee's import is an operation object,
    // quoted and submitted as any (`op quote`, `op submit`)
    "op hand-off" "Op::hand_off" {prepared: H<Arc<Prepared>>} @sign => {
        cx.confirm(json!({"review": review(&prepared.0.review()), "op": prepared.0.id(), "sign": "a hand-off: signed once, sent by its payee"}))?;
        js(sdk(cx).op().hand_off(prepared.0).await?)
    };
    "op import-signed" "Op::import_signed" {blob: SignedOpBlob, expect: ImportExpect} @op => sdk(cx).op().import_signed(blob, expect).await?;
    "signed-op-blob from-json" "SignedOpBlob::from_json" {text: String} => js(SignedOpBlob::from_json(&text)?);
    "signed-op-blob to-json" "SignedOpBlob::to_json" (b: SignedOpBlob) => named("json", b.to_json()?);
    "op member-sign" "Op::member_sign" {prepared: H<Arc<Prepared>>} @sign => {
        cx.confirm(json!({"review": review(&prepared.0.review()), "op": prepared.0.id(), "sign": "as an msig member"}))?;
        named("signature", sdk(cx).op().member_sign(prepared.0).await?)
    };
    "op bls-multi-part" "Op::bls_multi_part" {prepared: H<Arc<Prepared>>, member: KeyRef} @sign => {
        cx.confirm(json!({"review": review(&prepared.0.review()), "op": prepared.0.id(), "sign": "a BLS multi part"}))?;
        let p = sdk(cx).op().bls_multi_part(prepared.0, member).await?; let v = serde_json::to_value(&p).unwrap_or(Value::Null); handle(p, v)
    };
    "op bls-multi-part-ok" "Op::bls_multi_part_ok" {prepared: H<Arc<Prepared>>, part: BlsMultiPart} => named("ok", sdk(cx).op().bls_multi_part_ok(&prepared.0, &part));
    "op submit-bls-multi" "Op::submit_bls_multi" {prepared: H<Arc<Prepared>>, quote: H<SubmitQuote>, parts: Vec<BlsMultiPart>, surplus: bool} @sign => {
        cx.confirm_op(&prepared.0, &quote.0)?;
        { let op = sdk(cx).op().submit_bls_multi(prepared.0, quote.0, parts, surplus).await?; cx.sent(op).await }
    };
    "op bls-multi-pop-part" "Op::bls_multi_pop_part" {member: KeyRef} @sign => {
        cx.confirm(json!({"sign": "a BLS proof-of-possession part", "member": member}))?;
        js(sdk(cx).op().bls_multi_pop_part(member)?)
    };
    "op bls-multi-pop-part-ok" "Op::bls_multi_pop_part_ok" {key_data: String, part: BlsMultiPart} => named("ok", sdk(cx).op().bls_multi_pop_part_ok(&key_data, &part));
    "op quote-register-bls-multi" "Op::quote_register_bls_multi" {chain: String, key_data: String, payer: KeyRef} => { let q = sdk(cx).op().quote_register_bls_multi(chain, key_data, payer).await?; let v = serde_json::to_value(&q).unwrap_or(Value::Null); handle(q, v) };
    "op register-bls-multi" "Op::register_bls_multi" {chain: String, key_data: String, parts: Vec<BlsMultiPart>, quote: H<SubmitQuote>} @sign => {
        cx.confirm(json!({"register": "a BLS multi key", "chain": chain, "key_data": key_data, "quote": quote.0}))?;
        { let op = sdk(cx).op().register_bls_multi(chain, key_data, parts, quote.0).await?; cx.sent(op).await }
    };
    "prepared id" "Prepared::id" {prepared: H<Arc<Prepared>>} => named("id", prepared.0.id());
    "prepared chain" "Prepared::chain" {prepared: H<Arc<Prepared>>} => named("chain", prepared.0.chain());
    "prepared entry" "Prepared::entry" {prepared: H<Arc<Prepared>>} => named("entry", prepared.0.entry());
    "prepared review" "Prepared::review" {prepared: H<Arc<Prepared>>} => named("review", review(&prepared.0.review()));
    "prepared opaque" "Prepared::opaque" {prepared: H<Arc<Prepared>>} => named("opaque", prepared.0.opaque());
    "prepared signer" "Prepared::signer" {prepared: H<Arc<Prepared>>} => named("signer", prepared.0.signer());
    "prepared expires-at" "Prepared::expires_at" {prepared: H<Arc<Prepared>>} => named("expires_at", prepared.0.expires_at());

    // ---- wallet
    "wallet tokens" "Wallet::tokens" {chain: String, with_index: bool} => js(sdk(cx).wallet().tokens(chain, with_index).await?);
    "wallet balances" "Wallet::balances" {id: String, chain: String} => js(sdk(cx).wallet().balances(id, chain).await?);
    "wallet history" "Wallet::history" {account: String, chain: String, before: Option<Cursor>, limit: u32} => js(sdk(cx).wallet().history(account, chain, before, limit).await?);
    "wallet native-address" "Wallet::native_address" {key: NativeKeyRef, ss58_prefix: Option<u16>} => js(sdk(cx).wallet().native_address(key, ss58_prefix).await?);
    "wallet prepare-native-send" "Wallet::prepare_native_send" (r: NativeSend) @op => sdk(cx).wallet().prepare_native_send(r).await?;
    "wallet submit-native-send" "Wallet::submit_native_send" (q: NativeQuote) @sign => { cx.confirm(json!({"quote": q}))?; named("tx", sdk(cx).wallet().submit_native_send(q).await?) };
    // SDK plan T41.soroban: a G… subject's ops through `/v1/ops` or by self-relay, the hand-off, the native XLM send
    "wallet soroban-prepare" "Wallet::soroban_prepare" (r: SorobanOpRequest) => js(sdk(cx).wallet().soroban_prepare(r).await?);
    "wallet soroban-quote" "Wallet::soroban_quote" {prepared: SorobanPrepared, path: SorobanPath} => js(sdk(cx).wallet().soroban_quote(prepared, path).await?);
    "wallet soroban-submit" "Wallet::soroban_submit" {prepared: SorobanPrepared, quote: SorobanQuote} @sign => { cx.confirm(json!({"prepared": prepared, "quote": quote}))?; named("op", sdk(cx).wallet().soroban_submit(prepared, quote).await?) };
    "wallet soroban-hand-off" "Wallet::soroban_hand_off" (p: SorobanPrepared) @sign => { cx.confirm(json!({"hand_off": p}))?; js(sdk(cx).wallet().soroban_hand_off(p).await?) };
    "wallet soroban-import" "Wallet::soroban_import" {blob: SignedOpBlob, expect: SorobanImportExpect} => js(sdk(cx).wallet().soroban_import(blob, expect).await?);
    "wallet soroban-resend" "Wallet::soroban_resend" {op: String} => js(sdk(cx).wallet().soroban_resend(op).await?);
    "wallet soroban-follow" "Wallet::soroban_follow" {op: String} => named("state", sdk(cx).wallet().soroban_follow(op).await?);
    "wallet soroban-prepare-native-send" "Wallet::soroban_prepare_native_send" (r: SorobanNativeSend) => js(sdk(cx).wallet().soroban_prepare_native_send(r).await?);
    "wallet soroban-submit-native-send" "Wallet::soroban_submit_native_send" (q: SorobanNativeQuote) @sign => { cx.confirm(json!({"quote": q}))?; named("op", sdk(cx).wallet().soroban_submit_native_send(q).await?) };
    "wallet prepare-transfer" "Wallet::prepare_transfer" (r: Transfer) @op => sdk(cx).wallet().prepare_transfer(r).await?;
    "wallet prepare-pay" "Wallet::prepare_pay" (r: Pay) @op => sdk(cx).wallet().prepare_pay(r).await?;
    "wallet prepare-pay-with-tax" "Wallet::prepare_pay_with_tax" (r: PayWithTax) @op => sdk(cx).wallet().prepare_pay_with_tax(r).await?;
    "wallet prepare-payee-fee" "Wallet::prepare_payee_fee" (r: PayeeFee) @op => sdk(cx).wallet().prepare_payee_fee(r).await?;
    "wallet prepare-pay-under-mandate" "Wallet::prepare_pay_under_mandate" (r: PayUnderMandate) @op => sdk(cx).wallet().prepare_pay_under_mandate(r).await?;
    "wallet prepare-relay-fee" "Wallet::prepare_relay_fee" (r: RelayFee) @op => sdk(cx).wallet().prepare_relay_fee(r).await?;
    "wallet prepare-execute" "Wallet::prepare_execute" (r: Execute) @op => sdk(cx).wallet().prepare_execute(r).await?;
    "wallet prepare-cancel-nonce" "Wallet::prepare_cancel_nonce" (r: CancelNonce) @op => sdk(cx).wallet().prepare_cancel_nonce(r).await?;
    "wallet prepare-burn" "Wallet::prepare_burn" (r: Burn) @op => sdk(cx).wallet().prepare_burn(r).await?;
    "wallet prepare-wrap" "Wallet::prepare_wrap" (r: Wrap) @op => sdk(cx).wallet().prepare_wrap(r).await?;
    "wallet prepare-wrap-leg" "Wallet::prepare_wrap_leg" (r: WrapLeg) @op => sdk(cx).wallet().prepare_wrap_leg(r).await?;
    "wallet prepare-unwrap" "Wallet::prepare_unwrap" (r: Unwrap) @op => sdk(cx).wallet().prepare_unwrap(r).await?;
    "wallet prepare-unwrap-leg" "Wallet::prepare_unwrap_leg" (r: UnwrapLeg) @op => sdk(cx).wallet().prepare_unwrap_leg(r).await?;
    "wallet prepare-add-reserve" "Wallet::prepare_add_reserve" (r: AddReserve) @op => sdk(cx).wallet().prepare_add_reserve(r).await?;
    "wallet prepare-wrap-to-ua" "Wallet::prepare_wrap_to_ua" (r: WrapToUa) @op => sdk(cx).wallet().prepare_wrap_to_ua(r).await?;
    "wallet prepare-unwrap-to-ua" "Wallet::prepare_unwrap_to_ua" (r: UnwrapToUa) @op => sdk(cx).wallet().prepare_unwrap_to_ua(r).await?;
    "wallet prepare-set-mandate" "Wallet::prepare_set_mandate" (r: SetMandate) @op => sdk(cx).wallet().prepare_set_mandate(r).await?;
    "wallet prepare-set-payee" "Wallet::prepare_set_payee" (r: SetPayee) @op => sdk(cx).wallet().prepare_set_payee(r).await?;
    "wallet prepare-revoke-mandate" "Wallet::prepare_revoke_mandate" (r: RevokeMandate) @op => sdk(cx).wallet().prepare_revoke_mandate(r).await?;
    "wallet prepare-delegate-revoke" "Wallet::prepare_delegate_revoke" (r: DelegateRevoke) @op => sdk(cx).wallet().prepare_delegate_revoke(r).await?;

    // ---- confidential
    "confidential zether-key" "Confidential::zether_key" {seed: String, account: u32} => js(sdk(cx).confidential().zether_key(seed, account).await?);
    "confidential zether-balance" "Confidential::zether_balance" (r: ZetherBalanceRequest) => js(sdk(cx).confidential().zether_balance(r).await?);
    "confidential pqz-balance" "Confidential::pqz_balance" (r: PqzBalanceRequest) => js(sdk(cx).confidential().pqz_balance(r).await?);
    "confidential pqz-balance-all" "Confidential::pqz_balance_all" (r: PqzBalanceRequest) => js(sdk(cx).confidential().pqz_balance_all(r).await?);
    "confidential request-verdict" "Confidential::request_verdict" (r: PqzVerdictRequest) => js(sdk(cx).confidential().request_verdict(r).await?);
    "confidential prepare-pqz-shield" "Confidential::prepare_pqz_shield" (r: PqzShield) @op => sdk(cx).confidential().prepare_pqz_shield(r).await?;
    "confidential prepare-pqz-wrap-shield" "Confidential::prepare_pqz_wrap_shield" (r: PqzWrapShield) @op => sdk(cx).confidential().prepare_pqz_wrap_shield(r).await?;
    "confidential prepare-pqz-prepare-acc" "Confidential::prepare_pqz_prepare_acc" (r: PqzAccountOp) @op => sdk(cx).confidential().prepare_pqz_prepare_acc(r).await?;
    "confidential prepare-pqz-roll-over" "Confidential::prepare_pqz_roll_over" (r: PqzAccountOp) @op => sdk(cx).confidential().prepare_pqz_roll_over(r).await?;
    "confidential prepare-pqz-transfer" "Confidential::prepare_pqz_transfer" (r: PqzTransfer) @op => sdk(cx).confidential().prepare_pqz_transfer(r).await?;
    "confidential prepare-pqz-transfer-compact" "Confidential::prepare_pqz_transfer_compact" (r: PqzTransfer) @op => sdk(cx).confidential().prepare_pqz_transfer_compact(r).await?;
    "confidential prepare-pqz-transfer-multi" "Confidential::prepare_pqz_transfer_multi" (r: PqzTransferMulti) @op => sdk(cx).confidential().prepare_pqz_transfer_multi(r).await?;
    "confidential prepare-pqz-transfer-multi-compact" "Confidential::prepare_pqz_transfer_multi_compact" (r: PqzTransferMulti) @op => sdk(cx).confidential().prepare_pqz_transfer_multi_compact(r).await?;
    "confidential prepare-pqz-unshield" "Confidential::prepare_pqz_unshield" (r: PqzUnshield) @op => sdk(cx).confidential().prepare_pqz_unshield(r).await?;
    "confidential prepare-pqz-unshield-unwrap" "Confidential::prepare_pqz_unshield_unwrap" (r: PqzUnshieldUnwrap) @op => sdk(cx).confidential().prepare_pqz_unshield_unwrap(r).await?;
    "confidential prepare-zether-shield" "Confidential::prepare_zether_shield" (r: ZetherShield) @op => sdk(cx).confidential().prepare_zether_shield(r).await?;
    "confidential prepare-zether-wrap-shield" "Confidential::prepare_zether_wrap_shield" (r: ZetherWrapShield) @op => sdk(cx).confidential().prepare_zether_wrap_shield(r).await?;
    "confidential prepare-zether-roll-over" "Confidential::prepare_zether_roll_over" (r: ZetherRollOver) @op => sdk(cx).confidential().prepare_zether_roll_over(r).await?;
    "confidential prepare-zether-roll-over-batch" "Confidential::prepare_zether_roll_over_batch" (r: ZetherRollOverBatch) @op => sdk(cx).confidential().prepare_zether_roll_over_batch(r).await?;
    "confidential prepare-zether-transfer" "Confidential::prepare_zether_transfer" (r: ZetherTransfer) @op => sdk(cx).confidential().prepare_zether_transfer(r).await?;
    "confidential prepare-zether-unshield" "Confidential::prepare_zether_unshield" (r: ZetherUnshield) @op => sdk(cx).confidential().prepare_zether_unshield(r).await?;
    "confidential prepare-zether-unshield-unwrap" "Confidential::prepare_zether_unshield_unwrap" (r: ZetherUnshieldUnwrap) @op => sdk(cx).confidential().prepare_zether_unshield_unwrap(r).await?;
    "confidential prepare-zether-transfer-multi" "Confidential::prepare_zether_transfer_multi" (r: ZetherTransferMulti) @op => sdk(cx).confidential().prepare_zether_transfer_multi(r).await?;
    "confidential prepare-zether-transfer-compact" "Confidential::prepare_zether_transfer_compact" (r: ZetherTransferMulti) @op => sdk(cx).confidential().prepare_zether_transfer_compact(r).await?;
    "confidential prepare-zether-owner-roll-over" "Confidential::prepare_zether_owner_roll_over" (r: ZetherOwnerRollOver) @op => sdk(cx).confidential().prepare_zether_owner_roll_over(r).await?;
    "confidential prepare-zether-roll-over-signed" "Confidential::prepare_zether_roll_over_signed" {r: ZetherOwnerRollOver, relay: OwnerRelay} @op => sdk(cx).confidential().prepare_zether_roll_over_signed(r, relay).await?;
    "confidential prepare-zether-owner-set-mode" "Confidential::prepare_zether_owner_set_mode" (r: ZetherOwnerSetMode) @op => sdk(cx).confidential().prepare_zether_owner_set_mode(r).await?;
    "confidential prepare-zether-set-roll-over-mode" "Confidential::prepare_zether_set_roll_over_mode" {r: ZetherOwnerSetMode, relay: OwnerRelay} @op => sdk(cx).confidential().prepare_zether_set_roll_over_mode(r, relay).await?;

    // ---- dex
    "dex markets" "Dex::markets" {chain: String} => named("markets", raw_json(sdk(cx).dex().markets(chain).await?));
    "dex depth" "Dex::depth" {chain: String, market: i64, levels: Option<u32>} => named("depth", raw_json(sdk(cx).dex().depth(chain, market, levels).await?));
    "dex trades" "Dex::trades" {chain: String, market: i64} => named("trades", raw_json(sdk(cx).dex().trades(chain, market).await?));
    "dex ticker" "Dex::ticker" {chain: String, market: i64} => named("ticker", raw_json(sdk(cx).dex().ticker(chain, market).await?));
    "dex orders" "Dex::orders" {chain: String, maker: String} => named("orders", raw_json(sdk(cx).dex().orders(chain, maker).await?));
    "dex prepare-trade-order" "Dex::prepare_trade_order" (r: TradeOrder) @op => sdk(cx).dex().prepare_trade_order(r).await?;
    "dex prepare-liquidity-order" "Dex::prepare_liquidity_order" (r: LiquidityOrder) @op => sdk(cx).dex().prepare_liquidity_order(r).await?;
    "dex sign-order" "Dex::sign_order" {order: H<Arc<PreparedOrder>>} @sign => {
        cx.confirm(json!({"review": review(&order.0.review()), "order": order.0.id(), "chain": order.0.chain()}))?;
        js(sdk(cx).dex().sign_order(order.0).await?)
    };
    "dex place" "Dex::place" {order: H<Arc<PreparedOrder>>} @sign => {
        cx.confirm(json!({"review": review(&order.0.review()), "order": order.0.id(), "chain": order.0.chain()}))?;
        named("placed", raw_json(sdk(cx).dex().place(order.0).await?))
    };
    "dex cancel-all" "Dex::cancel_all" (r: CancelAll) @sign => { cx.confirm(json!({"cancel_all": r}))?; named("cancelled", raw_json(sdk(cx).dex().cancel_all(r).await?)) };
    "dex prepare-cancel-order" "Dex::prepare_cancel_order" (r: CancelOrder) @op => sdk(cx).dex().prepare_cancel_order(r).await?;
    "dex prepare-cancel-wrap-order" "Dex::prepare_cancel_wrap_order" (r: CancelWrapOrder) @op => sdk(cx).dex().prepare_cancel_wrap_order(r).await?;
    "dex prepare-wrap-order" "Dex::prepare_wrap_order" (r: WrapOrder) @op => sdk(cx).dex().prepare_wrap_order(r).await?;
    "prepared-order id" "PreparedOrder::id" {order: H<Arc<PreparedOrder>>} => named("id", order.0.id());
    "prepared-order chain" "PreparedOrder::chain" {order: H<Arc<PreparedOrder>>} => named("chain", order.0.chain());
    "prepared-order review" "PreparedOrder::review" {order: H<Arc<PreparedOrder>>} => named("review", review(&order.0.review()));
    "prepared-order signer" "PreparedOrder::signer" {order: H<Arc<PreparedOrder>>} => named("signer", order.0.signer());

    // ---- admin
    "admin create3-address" "Admin::create3_address" {factory: String, creator_id: String, contract_class: u16, kind: u16, salt: String} => js(sdk(cx).admin().create3_address(factory, creator_id, contract_class, kind, salt)?);
    "admin sign-rescue-vault" "Admin::sign_rescue_vault" (r: RescueVault) @sign => { cx.confirm(json!({"sign": r}))?; js(sdk(cx).admin().sign_rescue_vault(r).await?) };
    "admin sign-pqz-auditor-consent" "Admin::sign_pqz_auditor_consent" (r: AuditorConsent) @sign => { cx.confirm(json!({"sign": r}))?; named("signature", sdk(cx).admin().sign_pqz_auditor_consent(r).await?) };
    "admin sign-zether-auditor-consent" "Admin::sign_zether_auditor_consent" (r: AuditorConsent) @sign => { cx.confirm(json!({"sign": r}))?; named("signature", sdk(cx).admin().sign_zether_auditor_consent(r).await?) };
    "admin governance-delay" "Admin::governance_delay" {chain: String, token: String, bit: u16, holder: Option<HolderKind>} => js(sdk(cx).admin().governance_delay(chain, token, bit, holder).await?);
    "admin ua-grant-role" "Admin::admin_ua_grant_role" (r: UaGrantRole) @op => sdk(cx).admin().admin_ua_grant_role(r).await?;
    "admin ua-revoke-role" "Admin::admin_ua_revoke_role" (r: UaRevokeRole) @op => sdk(cx).admin().admin_ua_revoke_role(r).await?;
    "admin ua-set-grant" "Admin::admin_ua_set_grant" (r: UaSetGrant) @op => sdk(cx).admin().admin_ua_set_grant(r).await?;
    "admin ua-cancel-grant" "Admin::admin_ua_cancel_grant" (r: UaCancelGrant) @op => sdk(cx).admin().admin_ua_cancel_grant(r).await?;
    "admin ua-disable-feature" "Admin::admin_ua_disable_feature" (r: UaDisableFeature) @op => sdk(cx).admin().admin_ua_disable_feature(r).await?;
    "admin ua-transfer-admin" "Admin::admin_ua_transfer_admin" (r: UaTransferAdmin) @op => sdk(cx).admin().admin_ua_transfer_admin(r).await?;
    "admin ua-accept-admin" "Admin::admin_ua_accept_admin" (r: UaAcceptAdmin) @op => sdk(cx).admin().admin_ua_accept_admin(r).await?;
    "admin ua-renounce-admin" "Admin::admin_ua_renounce_admin" (r: UaRenounceAdmin) @op => sdk(cx).admin().admin_ua_renounce_admin(r).await?;
    "admin ua-renounce-role" "Admin::admin_ua_renounce_role" (r: UaRenounceRole) @op => sdk(cx).admin().admin_ua_renounce_role(r).await?;
    "admin ua-mint" "Admin::admin_ua_mint" (r: UaMint) @op => sdk(cx).admin().admin_ua_mint(r).await?;
    "admin ua-mint-to-ua" "Admin::admin_ua_mint_to_ua" (r: UaMintToUA) @op => sdk(cx).admin().admin_ua_mint_to_ua(r).await?;
    "admin ua-disable-wrap" "Admin::admin_ua_disable_wrap" (r: UaDisableWrap) @op => sdk(cx).admin().admin_ua_disable_wrap(r).await?;
    "admin ua-propose-rate" "Admin::admin_ua_propose_rate" (r: UaProposeRate) @op => sdk(cx).admin().admin_ua_propose_rate(r).await?;
    "admin ua-cancel-rate" "Admin::admin_ua_cancel_rate" (r: UaCancelRate) @op => sdk(cx).admin().admin_ua_cancel_rate(r).await?;
    "admin ua-execute-rate" "Admin::admin_ua_execute_rate" (r: UaExecuteRate) @op => sdk(cx).admin().admin_ua_execute_rate(r).await?;
    "admin ua-set-market" "Admin::admin_ua_set_market" (r: UaSetMarket) @op => sdk(cx).admin().admin_ua_set_market(r).await?;
    "admin ua-set-exchange-target" "Admin::admin_ua_set_exchange_target" (r: UaSetExchangeTarget) @op => sdk(cx).admin().admin_ua_set_exchange_target(r).await?;
    "admin ua-set-listed-only" "Admin::admin_ua_set_listed_only" (r: UaSetListedOnly) @op => sdk(cx).admin().admin_ua_set_listed_only(r).await?;
    "admin ua-set-fee-split" "Admin::admin_ua_set_fee_split" (r: UaSetFeeSplit) @op => sdk(cx).admin().admin_ua_set_fee_split(r).await?;
    "admin ua-freeze" "Admin::admin_ua_freeze" (r: UaFreeze) @op => sdk(cx).admin().admin_ua_freeze(r).await?;
    "admin ua-unfreeze" "Admin::admin_ua_unfreeze" (r: UaUnfreeze) @op => sdk(cx).admin().admin_ua_unfreeze(r).await?;
    "admin ua-force-transfer" "Admin::admin_ua_force_transfer" (r: UaForceTransfer) @op => sdk(cx).admin().admin_ua_force_transfer(r).await?;
    "admin ua-pause" "Admin::admin_ua_pause" (r: UaPause) @op => sdk(cx).admin().admin_ua_pause(r).await?;
    "admin ua-unpause" "Admin::admin_ua_unpause" (r: UaUnpause) @op => sdk(cx).admin().admin_ua_unpause(r).await?;
    "admin ua-record-order" "Admin::admin_ua_record_order" (r: UaRecordOrder) @op => sdk(cx).admin().admin_ua_record_order(r).await?;
    "admin ua-revoke-order" "Admin::admin_ua_revoke_order" (r: UaRevokeOrder) @op => sdk(cx).admin().admin_ua_revoke_order(r).await?;
    "admin ua-operator-transfer" "Admin::admin_ua_operator_transfer" (r: UaOperatorTransfer) @op => sdk(cx).admin().admin_ua_operator_transfer(r).await?;
    "admin ua-set-tax-rate" "Admin::admin_ua_set_tax_rate" (r: UaSetTaxRate) @op => sdk(cx).admin().admin_ua_set_tax_rate(r).await?;
    "admin ua-set-tax-recipient" "Admin::admin_ua_set_tax_recipient" (r: UaSetTaxRecipient) @op => sdk(cx).admin().admin_ua_set_tax_recipient(r).await?;
    "admin ua-pqz-set-verifier" "Admin::admin_ua_pqz_set_verifier" (r: UaPqzSetVerifier) @op => sdk(cx).admin().admin_ua_pqz_set_verifier(r).await?;
    "admin ua-pqz-cancel-verifier" "Admin::admin_ua_pqz_cancel_verifier" (r: UaPqzCancelVerifier) @op => sdk(cx).admin().admin_ua_pqz_cancel_verifier(r).await?;
    "admin ua-pqz-revoke-verifier" "Admin::admin_ua_pqz_revoke_verifier" (r: UaPqzRevokeVerifier) @op => sdk(cx).admin().admin_ua_pqz_revoke_verifier(r).await?;
    "admin ua-set-proof-store" "Admin::admin_ua_set_proof_store" (r: UaSetProofStore) @op => sdk(cx).admin().admin_ua_set_proof_store(r).await?;
    "admin ua-set-auditor-key" "Admin::admin_ua_set_auditor_key" (r: UaSetAuditorKey) @op => sdk(cx).admin().admin_ua_set_auditor_key(r).await?;
    "admin ua-set-auditor-ua" "Admin::admin_ua_set_auditor_ua" (r: UaSetAuditorUA) @op => sdk(cx).admin().admin_ua_set_auditor_ua(r).await?;
    "admin ua-set-verifier-fee" "Admin::admin_ua_set_verifier_fee" (r: UaSetVerifierFee) @op => sdk(cx).admin().admin_ua_set_verifier_fee(r).await?;
    "admin ua-set-wrap-limits" "Admin::admin_ua_set_wrap_limits" (r: UaSetWrapLimits) @op => sdk(cx).admin().admin_ua_set_wrap_limits(r).await?;
    "admin ua-set-wrap-member" "Admin::admin_ua_set_wrap_member" (r: UaSetWrapMember) @op => sdk(cx).admin().admin_ua_set_wrap_member(r).await?;
    "admin ua-set-max-supply" "Admin::admin_ua_set_max_supply" (r: UaSetMaxSupply) @op => sdk(cx).admin().admin_ua_set_max_supply(r).await?;
    "admin ua-set-max-wrap-supply" "Admin::admin_ua_set_max_wrap_supply" (r: UaSetMaxWrapSupply) @op => sdk(cx).admin().admin_ua_set_max_wrap_supply(r).await?;
    "admin ua-set-allowed" "Admin::admin_ua_set_allowed" (r: UaSetAllowed) @op => sdk(cx).admin().admin_ua_set_allowed(r).await?;
    "admin ua-set-denied" "Admin::admin_ua_set_denied" (r: UaSetDenied) @op => sdk(cx).admin().admin_ua_set_denied(r).await?;
    "admin ua-enable-feature" "Admin::admin_ua_enable_feature" (r: UaEnableFeature) @op => sdk(cx).admin().admin_ua_enable_feature(r).await?;
    "admin ua-publish-token-env" "Admin::admin_ua_publish_token_env" (r: UaPublishTokenEnv) @op => sdk(cx).admin().admin_ua_publish_token_env(r).await?;
    "admin ua-publish-dex-env" "Admin::admin_ua_publish_dex_env" (r: UaPublishDexEnv) @op => sdk(cx).admin().admin_ua_publish_dex_env(r).await?;
    "admin ua-publish-class-env" "Admin::admin_ua_publish_class_env" (r: UaPublishClassEnv) @op => sdk(cx).admin().admin_ua_publish_class_env(r).await?;
    "admin ua-deprecate-token" "Admin::admin_ua_deprecate_token" (r: UaDeprecateToken) @op => sdk(cx).admin().admin_ua_deprecate_token(r).await?;
    "admin ua-deprecate-dex" "Admin::admin_ua_deprecate_dex" (r: UaDeprecateDex) @op => sdk(cx).admin().admin_ua_deprecate_dex(r).await?;
    "admin ua-deprecate-release" "Admin::admin_ua_deprecate_release" (r: UaDeprecateRelease) @op => sdk(cx).admin().admin_ua_deprecate_release(r).await?;
    "admin ua-set-token-kind-enabled" "Admin::admin_ua_set_token_kind_enabled" (r: UaSetTokenKindEnabled) @op => sdk(cx).admin().admin_ua_set_token_kind_enabled(r).await?;
    "admin ua-set-class-kind-enabled" "Admin::admin_ua_set_class_kind_enabled" (r: UaSetClassKindEnabled) @op => sdk(cx).admin().admin_ua_set_class_kind_enabled(r).await?;
    "admin ua-set-kyc-provider" "Admin::admin_ua_set_kyc_provider" (r: UaSetKycProvider) @op => sdk(cx).admin().admin_ua_set_kyc_provider(r).await?;
    "admin ua-set-compliance" "Admin::admin_ua_set_compliance" (r: UaSetCompliance) @op => sdk(cx).admin().admin_ua_set_compliance(r).await?;
    "admin ua-create-token" "Admin::admin_ua_create_token" (r: UaCreateToken) @op => sdk(cx).admin().admin_ua_create_token(r).await?;
    "admin ua-create-dex" "Admin::admin_ua_create_dex" (r: UaCreateDex) @op => sdk(cx).admin().admin_ua_create_dex(r).await?;
    "admin ua-create-instance" "Admin::admin_ua_create_instance" (r: UaCreateInstance) @op => sdk(cx).admin().admin_ua_create_instance(r).await?;
    "admin ua-set-chain-entries" "Admin::admin_ua_set_chain_entries" (r: UaSetChainEntries) @op => sdk(cx).admin().admin_ua_set_chain_entries(r).await?;
    "admin ua-approve-token-release" "Admin::admin_ua_approve_token_release" (r: UaApproveTokenRelease) @op => sdk(cx).admin().admin_ua_approve_token_release(r).await?;
    "admin ua-approve-dex-release" "Admin::admin_ua_approve_dex_release" (r: UaApproveDexRelease) @op => sdk(cx).admin().admin_ua_approve_dex_release(r).await?;
    "admin ua-approve-release" "Admin::admin_ua_approve_release" (r: UaApproveRelease) @op => sdk(cx).admin().admin_ua_approve_release(r).await?;
    "admin ua-revoke-approval" "Admin::admin_ua_revoke_approval" (r: UaRevokeApproval) @op => sdk(cx).admin().admin_ua_revoke_approval(r).await?;
    "admin ua-cancel-nonce" "Admin::admin_ua_cancel_nonce" (r: UaCancelNonce) @op => sdk(cx).admin().admin_ua_cancel_nonce(r).await?;

    // ---- app-core (spec §12): key handles live in this process, named by `--as` in a session
    "app-core random-bytes" "AppCore::random_bytes" {seed: String, n: u32} => hexed("bytes", &cx.app()?.random_bytes(&seed, n)?);
    "app-core random-key" "AppCore::random_key" {seed: String, usage: AppKeyUsage} => handle(cx.app()?.random_key(&seed, usage)?, key_shown());
    "app-core derive" "AppCore::derive" {keys: Vec<H<Arc<AppKey>>>, salt: Vec<u8>, label: Vec<u8>, context: Vec<u8>, usage: AppKeyUsage, nonce: bool} =>
        handle(cx.app()?.derive(keys.into_iter().map(|k| k.0).collect(), salt, label, context, usage, nonce)?, key_shown());
    "app-core mac-derive" "AppCore::mac_derive" {key: H<Arc<AppKey>>, data: Vec<u8>, usage: AppKeyUsage} => handle(cx.app()?.mac_derive(key.0, data, usage)?, key_shown());
    "app-core mac-public" "AppCore::mac_public" {key: H<Arc<AppKey>>, label_and_data: Vec<u8>, len: u32} => hexed("mac", &cx.app()?.mac_public(key.0, label_and_data, len)?);
    "app-core seal" "AppCore::seal" {key: H<Arc<AppKey>>, nonce: Nonce, aad: Vec<u8>, pt: Vec<u8>} => hexed("sealed", &cx.app()?.seal(key.0, nonce.sdk(), aad, pt)?);
    "app-core open" "AppCore::open" {key: H<Arc<AppKey>>, nonce: Nonce, aad: Vec<u8>, ct: Vec<u8>} => {
        // the plaintext of the caller's own sealed record (`Plaintext` only): to stdout, as the app would show it
        let p = cx.app()?.open(key.0, nonce.sdk(), aad, ct)?;
        p.with(|b| hexed("plaintext", b))
    };
    "app-core seal-file" "AppCore::seal_file" {seed: String, file: Vec<u8>} => {
        let s = cx.app()?.seal_file(&seed, file)?;
        let h = |b: &[u8]| format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
        handle(s.key, json!({"key": "an app key handle (never readable)", "object": h(&s.object), "ct_sha256": h(&s.ct_sha256),
            "sha256": h(&s.sha256), "size": s.size}))
    };
    "app-core open-file" "AppCore::open_file" {key: H<Arc<AppKey>>, object: Vec<u8>, size: u64, sha256: Vec<u8>} => {
        // the plaintext of a file whose key the caller holds (`Plaintext` only), after every check
        let p = cx.app()?.open_file(key.0, object, size, sha256)?;
        p.with(|b| hexed("plaintext", b))
    };
    "app-core seal-key" "AppCore::seal_key" {under: H<Arc<AppKey>>, key: H<Arc<AppKey>>, aad: Vec<u8>} => hexed("wire", &cx.app()?.seal_key(under.0, key.0, aad)?);
    "app-core open-key" "AppCore::open_key" {under: H<Arc<AppKey>>, wire: Vec<u8>, usage: AppKeyUsage, aad: Vec<u8>} => handle(cx.app()?.open_key(under.0, wire, usage, aad)?, key_shown());
    "app-core same-key" "AppCore::same_key" {a: H<Arc<AppKey>>, b: H<Arc<AppKey>>} => named("same", cx.app()?.same_key(a.0, b.0)?);
    "app-core argon2id" "AppCore::argon2id" {seed: String, salt: Vec<u8>, m_kib: u32, t: u32, p: u32} ["password"] => {
        let pw = cx.secret("password")?; handle(cx.app()?.argon2id(seed, pw, salt, m_kib, t, p).await?, key_shown())
    };
    "app-core argon2id-passphrase" "AppCore::argon2id_passphrase" {seed: String, salt: Vec<u8>, m_kib: u32, t: u32, p: u32} ["passphrase"] => {
        let pw = cx.secret("passphrase")?; handle(cx.app()?.argon2id_passphrase(seed, pw, salt, m_kib, t, p).await?, key_shown())
    };
    "app-core kem-wrap-to-key" "AppCore::kem_wrap_to_key" {kem_pk: Vec<u8>, key: H<Arc<AppKey>>, label: Vec<u8>, aad: Vec<u8>} => js(cx.app()?.kem_wrap_to_key(kem_pk, key.0, label, aad)?);
    "app-core kem-unwrap" "AppCore::kem_unwrap" {account: KeyRef, key_version: u64, wrap: AppWrap, label: Vec<u8>, aad: Vec<u8>, usage: AppKeyUsage} => handle(cx.app()?.kem_unwrap(account, key_version, wrap, label, aad, usage)?, key_shown());
    "app-core app-root-key" "AppCore::app_root_key" {account: KeyRef} => handle(cx.app()?.app_root_key(account)?, key_shown());
    "app-core account-ua" "AppCore::account_ua" {account: KeyRef} => hexed("ua", &cx.app()?.account_ua(&account)?);
    "app-core destroy" "AppCore::destroy" {key: H<Arc<AppKey>>} => { cx.app()?.destroy(key.0)?; ok() };
    "app-core sign-app-record" "AppCore::sign_app_record" {account: KeyRef, path: AppPath, typed_json: String} @sign => {
        cx.confirm(json!({"sign": "an app record", "account": account, "path": path, "typed_data": typed_json}))?;
        js(cx.app()?.sign_app_record(account, path, typed_json).await?)
    };
    "app-core kem-wrap" "AppCore::kem_wrap" {chain: String, recipient: String, kem_version: u64, key: H<Arc<AppKey>>, label: Vec<u8>, aad: Vec<u8>} => js(cx.app()?.kem_wrap(chain, recipient, kem_version, key.0, label, aad).await?);
    "app-core verify-app-record" "AppCore::verify_app_record" {chain: String, ua: String, path: AppPath, typed_json: String, sig: AppUaSig} => named("valid", cx.app()?.verify_app_record(chain, ua, path, typed_json, sig).await?);
    "app-core sign-pqvault-record" "AppCore::sign_pqvault_record" {account: KeyRef, path: AppPath, typed_json: String} @sign => {
        cx.confirm(json!({"sign": "a PqVault record", "account": account, "path": path, "typed_data": typed_json}))?;
        js(cx.app()?.sign_pqvault_record(account, path, typed_json).await?)
    };
    "app-core verify-pqvault-record" "AppCore::verify_pqvault_record" {chain: String, ua: String, path: AppPath, typed_json: String, sig: AppUaSig} => named("valid", cx.app()?.verify_pqvault_record(chain, ua, path, typed_json, sig).await?);
    "app-core verify-app-record-key" "AppCore::verify_app_record_key" {kind: u16, key_data: Vec<u8>, path: AppPath, purpose: Option<String>, typed_json: String, signature: Vec<u8>} => named("valid", cx.app()?.verify_app_record_key(kind, key_data, path, purpose, typed_json, signature)?);
    "app-core prepare-app-call" "AppCore::prepare_app_call" {chain: String, contract: String, entry: String, args: String, payer: KeyRef} @sign => {
        let call = cx.app()?.prepare_app_call(chain, contract, entry, args, payer).await?;
        cx.confirm(json!({"review": review(&call.review), "quote": call.quote}))?;
        named("tx", sdk(cx).wallet().submit_native_send(call.quote).await?)
    };
    "app-core read-app" "AppCore::read_app" {chain: String, contract: String, entry: String, args: String, trusted: bool} => named("result", raw_json(cx.app()?.read_app(chain, contract, entry, args, trusted).await?));
    "app-core pqchat-epoch-key" "AppCore::pqchat_epoch_key" {seed: String} => handle(cx.app()?.pqchat_epoch_key(&seed)?, key_shown());
    "app-core pqchat-wrap" "AppCore::pqchat_wrap" {chain: String, k: H<Arc<AppKey>>, session_id: String, epoch_id: String, member: String, key_id: u64} => js(cx.app()?.pqchat_wrap(chain, k.0, session_id, epoch_id, member, key_id).await?);
    "app-core pqchat-unwrap" "AppCore::pqchat_unwrap" {account: KeyRef, session_id: String, epoch_id: String, wrap: PqWrap} => handle(cx.app()?.pqchat_unwrap(account, session_id, epoch_id, wrap)?, key_shown());
    "app-core pqchat-chain" "AppCore::pqchat_chain" {k: H<Arc<AppKey>>, session_id: String, epoch_id: String, sender: String, device: String} => handle(cx.app()?.pqchat_chain(k.0, session_id, epoch_id, sender, device)?, key_shown());
    "app-core pqchat-advance" "AppCore::pqchat_advance" {pos: H<Arc<AppKey>>, n: u64} => handle(cx.app()?.pqchat_advance(pos.0, n)?, key_shown());
    "app-core pqchat-hint" "AppCore::pqchat_hint" {k: H<Arc<AppKey>>} => hexed("hint", &cx.app()?.pqchat_hint(k.0)?);
    "app-core pqchat-open-info" "AppCore::pqchat_open_info" {k: H<Arc<AppKey>>, session_id: String, epoch_id: String, sealed: Vec<u8>} => {
        let p = cx.app()?.pqchat_open_info(k.0, session_id, epoch_id, sealed)?; p.with(|b| hexed("info", b))
    };
    "app-core pqchat-open-envelope" "AppCore::pqchat_open_envelope" {k: H<Arc<AppKey>>, session_id: String, epoch_id: String, env: Vec<u8>} => js(cx.app()?.pqchat_open_envelope(k.0, session_id, epoch_id, env)?);
    "app-core pqchat-open-message" "AppCore::pqchat_open_message" {pos: H<Arc<AppKey>>, record: PqChatMessage} => {
        let p = cx.app()?.pqchat_open_message(pos.0, record)?; p.with(|b| hexed("content", b))
    };
    "app-core pqchat-seal-message" "AppCore::pqchat_seal_message" {account: KeyRef, k: H<Arc<AppKey>>, pos: H<Arc<AppKey>>, header: PqMessageHeader, content_json: String} @sign => {
        cx.confirm(json!({"sign": "a PqChat message", "account": account, "header": header}))?;
        js(cx.app()?.pqchat_seal_message(account, k.0, pos.0, header, content_json).await?)
    };
    "app-core pqchat-sign-session" "AppCore::pqchat_sign_session" {account: KeyRef, k: H<Arc<AppKey>>, r: PqSessionNew} @sign => {
        cx.confirm(json!({"sign": "a PqChat session", "account": account, "record": r}))?; js(cx.app()?.pqchat_sign_session(account, k.0, r).await?)
    };
    "app-core pqchat-sign-epoch" "AppCore::pqchat_sign_epoch" {account: KeyRef, k: H<Arc<AppKey>>, r: PqEpochNew} @sign => {
        cx.confirm(json!({"sign": "a PqChat epoch", "account": account, "record": r}))?; js(cx.app()?.pqchat_sign_epoch(account, k.0, r).await?)
    };
    "app-core verify-pqchat-record" "AppCore::verify_pqchat_record" {chain: String, ua: String, name: String, record_json: String, sig: AppUaSig} => named("valid", cx.app()?.verify_pqchat_record(chain, ua, name, record_json, sig).await?);
    "app-core pqchat-decode-payload" "AppCore::pqchat_decode_payload" {payload: Vec<u8>} => js(cx.app()?.pqchat_decode_payload(payload)?);
    "app-core sign-pqchat-session" "AppCore::sign_pqchat_session" {account: KeyRef, r: PqChatSession} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_session(account, r).await?) };
    "app-core sign-pqchat-epoch" "AppCore::sign_pqchat_epoch" {account: KeyRef, r: PqChatEpoch} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_epoch(account, r).await?) };
    "app-core sign-pqchat-leave" "AppCore::sign_pqchat_leave" {account: KeyRef, r: PqChatLeave} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_leave(account, r).await?) };
    "app-core sign-pqchat-remove" "AppCore::sign_pqchat_remove" {account: KeyRef, r: PqChatRemove} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_remove(account, r).await?) };
    "app-core sign-pqchat-message" "AppCore::sign_pqchat_message" {account: KeyRef, r: PqChatMessage} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_message(account, r).await?) };
    "app-core sign-pqchat-topic" "AppCore::sign_pqchat_topic" {account: KeyRef, r: PqTopic} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_topic(account, r).await?) };
    "app-core sign-pqchat-topic-update" "AppCore::sign_pqchat_topic_update" {account: KeyRef, r: PqTopicUpdate} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_topic_update(account, r).await?) };
    "app-core sign-pqchat-topic-writer" "AppCore::sign_pqchat_topic_writer" {account: KeyRef, r: PqTopicWriter} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_topic_writer(account, r).await?) };
    "app-core sign-pqchat-topic-entry" "AppCore::sign_pqchat_topic_entry" {account: KeyRef, r: PqTopicEntry} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_topic_entry(account, r).await?) };
    "app-core sign-pqchat-topic-edit" "AppCore::sign_pqchat_topic_edit" {account: KeyRef, r: PqTopicEdit} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_topic_edit(account, r).await?) };
    "app-core sign-pqchat-topic-vote" "AppCore::sign_pqchat_topic_vote" {account: KeyRef, r: PqTopicVote} @sign => { cx.confirm(json!({"sign": r}))?; js(cx.app()?.sign_pqchat_topic_vote(account, r).await?) };
}

/// A JSON text the SDK returned (a node's or a contract's answer), as JSON; text that is not JSON stays a string.
fn raw_json(s: String) -> Value {
    serde_json::from_str(&s).unwrap_or(Value::String(s))
}
