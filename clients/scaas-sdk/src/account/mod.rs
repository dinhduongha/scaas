// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `account` (spec §7, CLI-SDK-07; plan T9): the account rows of a seed, their UA ids and the restore scan. Every row names its
//! seed; a UA key is `(seed, kind, account, index)` and its UA is the one `scaas-ua` derives; one account index per wallet (a new
//! wallet takes the next free index, so no two wallets share one); the EIP-2333 kinds at index 0 only (CLI-UAL-15). Every change
//! rewrites the seed's index MAC (the seed unlocked). A watch row holds no key and signs nothing. UNAUDITED.
#[cfg(feature = "evm")]
mod line;
#[cfg(feature = "evm")]
pub mod msig;
#[cfg(feature = "evm")]
mod register;
#[cfg(feature = "evm")]
mod restore;
#[cfg(feature = "evm")]
pub mod smart;
#[cfg(feature = "evm")]
mod sponsor;

#[cfg(feature = "evm")]
pub use msig::{
    msig_structure, AcceptMembership, MsigMemberArgs, MsigRegister, MsigSlotState, MsigState,
    MsigStructureArgs, MsigUpdatePlan, UpdateMsig,
};
#[cfg(feature = "evm")]
pub(crate) use register::{record_call, record_call2, record_holds, record_holds2, Landed};
#[cfg(feature = "evm")]
pub use register::{
    Register, RegisterAttrs, RegistrationGas, RegistrationState, RegistryWrite, StepGas,
};
#[cfg(feature = "evm")]
pub use restore::Restore;
#[cfg(feature = "evm")]
pub use smart::{smart_account_address, SmartCall, SmartOp, SubjectKeyArgs};
#[cfg(feature = "evm")]
pub use sponsor::{
    AttrsArgs, KemArgs, KemRecord, RegisterArgs, RegistrationBlob, WebAuthnArgs, BLOB_MAX,
};

use crate::vault::{change_entry, AccountRow, SeedEntry};
use crate::{Sdk, SdkError};
use std::sync::Arc;

/// The account module.
#[derive(Clone)]
pub struct Account {
    pub(crate) sdk: Arc<Sdk>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// The account module (spec §7).
    pub fn account(self: &Arc<Self>) -> Arc<Account> {
        Arc::new(Account { sdk: self.clone() })
    }
}

/// One account row as the app shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct AccountInfo {
    pub id: String,
    /// The seed the row belongs to (R2).
    pub seed: String,
    pub name: String,
    /// `ua`, `native`, `key` or `watch`.
    pub shape: String,
    pub kind: Option<u16>,
    pub account: Option<u32>,
    pub index: Option<u32>,
    pub network: Option<String>,
    /// A UA row's or a key row's UA, a native row's address, a watch row's id.
    pub id_text: String,
    /// The seed is unlocked and its index MAC verified at unlock (spec §6.2); a locked seed's rows are unverified.
    pub verified: bool,
    /// An EVM row whose code is an EIP-7702 designator (`0xef0100…`), from [`Account::marks`]; the SDK builds no type-4
    /// transaction, so it cannot offer to clear it (CLI-SDK-31).
    pub delegated: bool,
}

/// `add_ua`: the UA key `kind` of wallet `account` at `index`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct AddUa {
    pub seed: String,
    pub kind: u16,
    pub account: u32,
    pub index: u32,
    pub name: String,
}

/// `add_native`: the native key of `network` (a `scaas-ua` network name) at `index`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct AddNative {
    pub seed: String,
    pub network: String,
    pub index: u32,
    pub name: String,
}

/// `add_watch`: an id to watch (a `0x` 32-byte UA or a `0x` 20-byte address); no key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct AddWatch {
    pub seed: String,
    pub watch: String,
    pub name: String,
}

/// `create_passkey_key`: a new passkey of the deployment's RP ID (`SdkConfig::rp_id`), named `name` beside seed `seed`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyKey {
    pub seed: String,
    pub name: String,
}

/// `create_se_key`: a new secure-element P-256 key under `policy`, named `name` beside seed `seed`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct CreateSeKey {
    pub seed: String,
    pub name: String,
    pub policy: crate::platform::KeyPolicy,
}

const NAME_MAX: usize = 64;

fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= NAME_MAX && !n.chars().any(crate::text::hidden)
}

fn info(seed: &str, row: &AccountRow, verified: bool) -> AccountInfo {
    let u32_of = |n: u64| u32::try_from(n).ok();
    let base = |id: &str, name: &str, shape: &str, id_text: &str| AccountInfo {
        id: id.into(),
        seed: seed.into(),
        name: name.into(),
        shape: shape.into(),
        kind: None,
        account: None,
        index: None,
        network: None,
        id_text: id_text.into(),
        verified,
        delegated: false,
    };
    match row {
        AccountRow::Ua {
            id,
            name,
            kind,
            account,
            index,
            ua,
        } => AccountInfo {
            kind: u16::try_from(*kind).ok(),
            account: u32_of(*account),
            index: u32_of(*index),
            ..base(id, name, "ua", ua)
        },
        AccountRow::Native {
            id,
            name,
            network,
            index,
            address,
            ..
        } => AccountInfo {
            network: Some(network.clone()),
            index: u32_of(*index),
            ..base(id, name, "native", address)
        },
        AccountRow::Key {
            id, name, kind, ua, ..
        } => AccountInfo {
            kind: u16::try_from(*kind).ok(),
            ..base(id, name, "key", ua)
        },
        AccountRow::Watch { id, name, watch } => base(id, name, "watch", watch),
    }
}

impl Account {
    /// The rows of seed `seed`, in order.
    pub async fn accounts(&self, seed: String) -> Result<Vec<AccountInfo>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let e = sdk.entry(&seed).await?;
                // review T26 A-2: the rows as read, checked under the open wallet
                let verified = crate::vault::seeds::rows_verified(&sdk, &e);
                Ok(e.accounts
                    .iter()
                    .map(|r| info(&seed, r, verified))
                    .collect())
            })
            .await
    }

    /// The account index a new wallet of seed `seed` takes: one past the highest a UA row uses (0 for none). One index per
    /// wallet, for every attribute it registers (CLI-SDK-07).
    pub async fn next_account(&self, seed: String) -> Result<u32, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move { Ok(next_account(&sdk.entry(&seed).await?)) })
            .await
    }

    /// Adds the UA key `kind` of wallet `account` at `index` to seed `seed` (unlocked: `WalletLocked`), its UA the one
    /// `scaas-ua` derives; the MAC rewritten. `Argument`: an EIP-2333 kind at an index other than 0 (CLI-UAL-15, `scaas-ua`'s
    /// rule), a kind with no UA of its own, a name empty, above 64 bytes or with a control or format (`Cf`, bidi) character;
    /// `AccountExists`: the same key twice.
    pub async fn add_ua(&self, req: AddUa) -> Result<AccountInfo, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if !name_ok(&req.name) {
                    return Err(SdkError::Argument);
                }
                let open = sdk.open_seed(&req.seed)?;
                let ua = match zether_ua(&sdk, &req)? {
                    Some(ua) => ua,
                    None => hex(&open
                        .wallet
                        .ua_key(req.kind, req.account, req.index)?
                        .ua()
                        .ok_or(SdkError::Argument)?),
                };
                let row = AccountRow::Ua {
                    id: crate::vault::uuid4()?,
                    name: req.name.clone(),
                    kind: u64::from(req.kind),
                    account: u64::from(req.account),
                    index: u64::from(req.index),
                    ua,
                };
                add_row(&sdk, &req.seed, row).await
            })
            .await
    }

    /// Adds the native key of `network` at `index` (the address `scaas-ua` derives, as clientkeys `describe` prints it).
    /// `Argument`: an unknown network, a network without an address here (`ton`, `hedera_ed25519`); `AccountExists`:
    /// the same key twice.
    pub async fn add_native(&self, req: AddNative) -> Result<AccountInfo, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let network =
                    scaas_ua::wallet::Network::from_name(&req.network).ok_or(SdkError::Argument)?;
                if !name_ok(&req.name) {
                    return Err(SdkError::Argument);
                }
                let open = sdk.open_seed(&req.seed)?;
                let address = open
                    .wallet
                    .native_key(network, req.index, None)?
                    .address()
                    .ok_or(SdkError::Argument)?;
                let row = AccountRow::Native {
                    id: crate::vault::uuid4()?,
                    name: req.name.clone(),
                    network: network.name().into(),
                    index: u64::from(req.index),
                    coin_type: None,
                    change: None,
                    path: None,
                    ss58_prefix: None,
                    address,
                };
                add_row(&sdk, &req.seed, row).await
            })
            .await
    }

    /// A new passkey (spec §7 "Passkey keys"; owner 2026-11-19, S1): the `Authenticator` creates it on the deployment's RP ID
    /// (the seed's other passkeys excluded), its `webauthn-p256` (0x0100) key data and credential id stored as a key row of
    /// `seed` (unlocked: `WalletLocked`), the UA `scaas-ua` derives; the `KeyRef` that signs with it. `AuthenticatorRefused`: no
    /// authenticator or RP ID, a refusal; `Argument`: a bad name or key data.
    #[cfg(feature = "evm")]
    pub async fn create_passkey_key(
        &self,
        req: CreatePasskeyKey,
    ) -> Result<crate::op::KeyRef, SdkError> {
        self.sdk.secrets_allowed()?;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if !name_ok(&req.name) {
                    return Err(SdkError::Argument);
                }
                drop(sdk.open_seed(&req.seed)?);
                let auth = sdk
                    .authenticator
                    .clone()
                    .ok_or(SdkError::AuthenticatorRefused)?;
                let rp_id = sdk.rp_id.clone().ok_or(SdkError::AuthenticatorRefused)?;
                let exclude = sdk
                    .entry(&req.seed)
                    .await?
                    .accounts
                    .iter()
                    .filter_map(|r| match r {
                        AccountRow::Key {
                            credential_id: Some(c),
                            ..
                        } => crate::op::unhex(c).ok(),
                        _ => None,
                    })
                    .collect();
                let c = auth
                    .create_passkey(rp_id, req.name.clone(), exclude)
                    .await
                    .map_err(|_| SdkError::AuthenticatorRefused)?;
                let kind = crate::op::external::PASSKEY;
                let row = key_row(
                    &req.name,
                    kind,
                    &c.key_data,
                    Some(crate::op::hex(&c.credential_id)),
                    None,
                )?;
                key_ref(&sdk, &req.seed, row).await
            })
            .await
    }

    /// A new secure-element P-256 key (spec §7 "Secure-element keys"; S1): the `Authenticator` generates it under `policy`, its
    /// `p256` (0x0101) key data and handle stored as a key row of `seed` (unlocked); the `KeyRef` that signs with it (MESSAGE
    /// mode). Not recoverable without a second member or a guardian: the app says so. Errors as [`Account::create_passkey_key`].
    #[cfg(feature = "evm")]
    pub async fn create_se_key(&self, req: CreateSeKey) -> Result<crate::op::KeyRef, SdkError> {
        self.sdk.secrets_allowed()?;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if !name_ok(&req.name) {
                    return Err(SdkError::Argument);
                }
                drop(sdk.open_seed(&req.seed)?);
                let auth = sdk
                    .authenticator
                    .clone()
                    .ok_or(SdkError::AuthenticatorRefused)?;
                let k = auth
                    .p256_generate(req.policy)
                    .await
                    .map_err(|_| SdkError::AuthenticatorRefused)?;
                let kind = crate::op::external::SECURE_ELEMENT;
                let row = key_row(&req.name, kind, &k.key_data, None, Some(k.handle))?;
                key_ref(&sdk, &req.seed, row).await
            })
            .await
    }

    /// Adds a watch row: an id, no key; nothing is ever signed for it ([`Account::signs`]).
    pub async fn add_watch(&self, req: AddWatch) -> Result<AccountInfo, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let w = req.watch.to_ascii_lowercase();
                let hex_ok = w.strip_prefix("0x").is_some_and(|h| {
                    (h.len() == 40 || h.len() == 64) && h.bytes().all(|b| b.is_ascii_hexdigit())
                });
                if !hex_ok || !name_ok(&req.name) {
                    return Err(SdkError::Argument);
                }
                let row = AccountRow::Watch {
                    id: crate::vault::uuid4()?,
                    name: req.name.clone(),
                    watch: w,
                };
                add_row(&sdk, &req.seed, row).await
            })
            .await
    }

    /// Whether row `id` of seed `seed` holds a key the SDK signs with (a UA, native or key row); a watch row signs nothing.
    /// `Argument`: no such row.
    pub async fn signs(&self, seed: String, id: String) -> Result<bool, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let e = sdk.entry(&seed).await?;
                let row = e
                    .accounts
                    .iter()
                    .find(|r| row_id(r) == id)
                    .ok_or(SdkError::Argument)?;
                Ok(!matches!(row, AccountRow::Watch { .. }))
            })
            .await
    }
}

fn row_id(r: &AccountRow) -> &str {
    match r {
        AccountRow::Ua { id, .. }
        | AccountRow::Native { id, .. }
        | AccountRow::Key { id, .. }
        | AccountRow::Watch { id, .. } => id,
    }
}

fn next_account(e: &SeedEntry) -> u32 {
    e.accounts
        .iter()
        .filter_map(|r| match r {
            AccountRow::Ua { account, .. } => u32::try_from(*account).ok(),
            _ => None,
        })
        .max()
        .map_or(0, |a| a.saturating_add(1))
}

/// The same key twice: the same UA, the same native `(network, index)`, the same watched id.
fn same(a: &AccountRow, b: &AccountRow) -> bool {
    match (a, b) {
        (AccountRow::Ua { ua: x, .. }, AccountRow::Ua { ua: y, .. }) => x == y,
        (
            AccountRow::Native {
                network: n,
                index: i,
                ..
            },
            AccountRow::Native {
                network: m,
                index: j,
                ..
            },
        ) => n == m && i == j,
        (AccountRow::Watch { watch: x, .. }, AccountRow::Watch { watch: y, .. }) => x == y,
        _ => false,
    }
}

/// A key row of `kind` and `key_data`, its UA the one `scaas-ua` derives.
#[cfg(feature = "evm")]
fn key_row(
    name: &str,
    kind: u16,
    key_data: &[u8],
    credential_id: Option<String>,
    handle: Option<String>,
) -> Result<AccountRow, SdkError> {
    let ua = scaas_ua::derive_ua(kind, key_data, false).map_err(|_| SdkError::Argument)?;
    Ok(AccountRow::Key {
        id: crate::vault::uuid4()?,
        name: name.into(),
        kind: u64::from(kind),
        key_data: crate::op::hex(key_data),
        credential_id,
        handle,
        ua: crate::op::hex(&ua),
    })
}

/// `row` added to `seed`; its `KeyRef`.
#[cfg(feature = "evm")]
async fn key_ref(
    sdk: &Arc<Sdk>,
    seed: &str,
    row: AccountRow,
) -> Result<crate::op::KeyRef, SdkError> {
    let info = add_row(sdk, seed, row).await?;
    Ok(crate::op::KeyRef::Key {
        seed: seed.into(),
        id: info.id,
    })
}

async fn add_row(sdk: &Arc<Sdk>, seed: &str, row: AccountRow) -> Result<AccountInfo, SdkError> {
    add_rows(sdk, seed, vec![row], false)
        .await?
        .pop()
        .ok_or(SdkError::Internal)
}

/// Adds `rows` to seed `seed` in one change (the MAC rewritten): a row whose key is listed already is `AccountExists`, or with
/// `skip_known` left out (the restore scan). Returns the rows added.
pub(crate) async fn add_rows(
    sdk: &Arc<Sdk>,
    seed: &str,
    rows: Vec<AccountRow>,
    skip_known: bool,
) -> Result<Vec<AccountInfo>, SdkError> {
    let added = std::sync::Mutex::new(Vec::new());
    change_entry(sdk, seed, |e| {
        let mut new = Vec::new();
        for row in &rows {
            if e.accounts.iter().chain(new.iter()).any(|r| same(r, row)) {
                if skip_known {
                    continue;
                }
                return Err(SdkError::AccountExists);
            }
            new.push(row.clone());
        }
        e.accounts.extend(new.iter().cloned());
        *added.lock().map_err(|_| SdkError::Internal)? = new;
        Ok(())
    })
    .await?;
    let rows = added.into_inner().map_err(|_| SdkError::Internal)?;
    Ok(rows.iter().map(|r| info(seed, r, true)).collect())
}

/// The Zether UA (`zether-bls12381`, index 0 only) of an `add_ua` request: the facade's conf key `m/12381/60/<account>/7`, the
/// key that signs as `KeyRef::Ua { kind: 0x0141, .. }`; `None` for any other kind.
#[cfg(feature = "zether")]
fn zether_ua(sdk: &crate::Sdk, r: &AddUa) -> Result<Option<String>, SdkError> {
    if r.kind != crate::confidential::ZETHER_KIND {
        return Ok(None);
    }
    if r.index != 0 {
        return Err(SdkError::Argument);
    }
    Ok(Some(hex(&crate::confidential::handle(
        sdk, &r.seed, r.account,
    )?
    .1
    .ua())))
}

#[cfg(not(feature = "zether"))]
fn zether_ua(_: &crate::Sdk, _: &AddUa) -> Result<Option<String>, SdkError> {
    Ok(None)
}
