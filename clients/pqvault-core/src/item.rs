// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The redacting item layer (CLI-PQV-16 H1–H3; spec §6.8): an item's fields typed by one table, the per-type secret table, so
//! no front-end decides which field is secret. A field is `Plain` (a JSON value), `Secret` (a text in a `SecretBytes`),
//! `Custom` (the custom fields, each declaring itself secret or not) or `Opaque` (a field this client does not know, or a
//! table field in a shape it does not know: its canonical JSON kept byte for byte in a zeroizing buffer, never shown, and
//! written back on an edit). The canonical JSON is built in a zeroizing buffer of a fixed capacity (it never reallocates),
//! and parsed from the decrypted plaintext in place: a secret's text goes from the plaintext straight into its
//! `SecretBytes`, never into a `String`; a reader holds at most [`SECRETS_MAX`] of them per item. A secret field's earlier
//! values (the merge's `history`) are secret too (rule 25), and the merge retypes every value by the merged item's table
//! (a hidden body stays hidden). `Debug` prints counts only, no type, name or value (CLI-PQV-03). UNAUDITED.
use crate::content::{self, Bad, Out};
use scaas_sdk::app_core::SecretBytes;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// The fields every type holds, plain (spec §6.8).
pub const COMMON: [&str; 4] = ["title", "ts", "folder", "tags"];

/// The secret table (H2, owner 2026-11-27; spec §6.8): per type this client writes, its plain fields and its secret fields.
/// A note's `body` is plain unless the item's `hideBody` is `true` (H3); every type but `vaultRef` and `deleted` may hold the
/// custom fields `fields`; any other field is kept opaque.
pub const TABLE: [(&str, &[&str], &[&str]); 9] = [
    (
        "login",
        &["username", "urls", "notes"],
        &["password", "totp"],
    ),
    ("note", &["mediaType", "hideBody"], &[]),
    (
        "card",
        &["cardholderName", "brand", "expMonth", "expYear"],
        &["number", "code", "pin"],
    ),
    (
        "identity",
        &[
            "honorific",
            "firstName",
            "middleName",
            "lastName",
            "company",
            "email",
            "phone",
            "address1",
            "address2",
            "address3",
            "city",
            "state",
            "postalCode",
            "country",
            "username",
        ],
        &["nationalId", "passportNumber", "licenseNumber"],
    ),
    ("sshKey", &["publicKey"], &["privateKey", "passphrase"]),
    ("totp", &["algorithm", "digits", "period"], &["secret"]),
    (
        "file",
        &[
            "mediaType",
            "name",
            "size",
            "sha256",
            "ctSha256",
            "url",
            "keyWrap",
        ],
        &[],
    ),
    (
        "vaultRef",
        &[
            "vaultId",
            "homeChain",
            "homeVaultContract",
            "mode",
            "index",
            "acceptedEpoch",
            "state",
        ],
        &[],
    ),
    ("deleted", &[], &[]),
];

/// The custom fields of one item at most, and a custom field's name length (spec §6.8).
pub const CUSTOM_MAX: usize = 32;
pub const CUSTOM_NAME_MAX: usize = 128;
/// The secrets a reader opens of one item at most (fields, custom fields and history together; review C-4): each is a
/// locked block of its own, so a member's item cannot ask for more; past it the item is `Unreadable`.
pub const SECRETS_MAX: usize = 64;

/// How the table types a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Plain,
    Secret,
    Custom,
    Opaque,
}

/// The class of field `name` of an item of type `ty` whose `hideBody` is `hide`.
pub fn class(ty: &str, name: &str, hide: bool) -> Class {
    let Some((_, plain, secret)) = TABLE.iter().find(|(t, _, _)| *t == ty) else {
        // an unknown type: its common fields shown, the rest kept
        return if COMMON.contains(&name) {
            Class::Plain
        } else {
            Class::Opaque
        };
    };
    if ty == "deleted" {
        return Class::Opaque;
    }
    // a merge's history records a `type` it replaced (review C-3)
    if name == "type" || COMMON.contains(&name) || plain.contains(&name) {
        return Class::Plain;
    }
    if secret.contains(&name) || (ty == "note" && name == "body" && hide) {
        return Class::Secret;
    }
    match (ty, name) {
        ("note", "body") => Class::Plain,
        ("vaultRef", _) => Class::Opaque,
        (_, "fields") => Class::Custom,
        _ => Class::Opaque,
    }
}

/// One field's value.
#[derive(Clone)]
pub enum Field {
    /// a plain value (a text, a number, a flag, a list or object of plain values)
    Plain(Value),
    /// a secret text: its UTF-8 bytes
    Secret(Arc<SecretBytes>),
    /// the custom fields
    Custom(Vec<Custom>),
    /// a field this client does not know, or a table field in a shape it does not know: its canonical JSON, kept byte
    /// for byte and never shown (a zeroizing buffer, not a locked block: review C-4)
    Opaque(Arc<Zeroizing<Vec<u8>>>),
}

impl Field {
    /// A secret of the text `s` (a draft's, as typed).
    pub fn secret(s: &[u8]) -> Result<Field, Bad> {
        let b = SecretBytes::new(s.len()).map_err(|_| Bad::Shape)?;
        b.with_mut(|m| m.copy_from_slice(s));
        Ok(Field::Secret(Arc::new(b)))
    }
    fn kind(&self) -> &'static str {
        match self {
            Field::Plain(_) => "Plain",
            Field::Secret(_) => "Secret",
            Field::Custom(_) => "Custom",
            Field::Opaque(_) => "Opaque",
        }
    }
    /// Whether a writer may write this value where the table gives class `c`: its own kind, a kept part or a `null`
    /// anywhere (a field read in a shape this client does not know is written back as it was: spec §6.8, review C-2).
    fn of(&self, c: Class) -> bool {
        matches!(
            (self, c),
            (Field::Plain(_), Class::Plain)
                | (Field::Secret(_), Class::Secret)
                | (Field::Custom(_), Class::Custom)
                | (Field::Opaque(_), _)
                | (Field::Plain(Value::Null), _)
        )
    }

    /// The secrets this value holds.
    fn secrets(&self) -> usize {
        match self {
            Field::Secret(_) => 1,
            Field::Custom(c) => c.iter().map(|x| x.value.secrets()).sum(),
            _ => 0,
        }
    }

    /// This value retyped for class `c` (the merge's retyping, review C-3): its canonical JSON read again under `c`.
    fn retyped(&self, c: Class) -> Field {
        let mut out = Out::new();
        let again = write_field(self, 1, &mut out)
            .ok()
            .and_then(|_| serde_json::from_slice::<&RawValue>(out.bytes()).ok())
            .and_then(|raw| read_field(c, raw, 1, &mut 0).ok());
        again.unwrap_or_else(|| self.clone())
    }
}

/// Two values are equal when their canonical JSON is (a text plain on one side and secret on the other is the same text:
/// review C-3).
impl PartialEq for Field {
    fn eq(&self, o: &Field) -> bool {
        let (mut a, mut b) = (Out::new(), Out::new());
        match (write_field(self, 1, &mut a), write_field(o, 1, &mut b)) {
            (Ok(()), Ok(())) => a.bytes() == b.bytes(),
            _ => false,
        }
    }
}
impl Eq for Field {}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

/// A custom field (spec §6.8): its name, and its value a plain text or a secret (the field declares which).
#[derive(Clone, PartialEq, Eq)]
pub struct Custom {
    pub name: String,
    pub value: Field,
}

impl std::fmt::Debug for Custom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Custom({:?})", self.value)
    }
}

/// An earlier value of a field, kept by the merge (spec §7 "Merge"): typed as the field is (rule 25); a field the other side
/// removed is `Plain(null)`.
#[derive(Clone, PartialEq, Eq)]
pub struct Change {
    pub field: String,
    pub value: Field,
}

impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Change({:?})", self.value)
    }
}

/// An item (spec §6.8): its `type`, every other field by name, and its `history`.
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    pub ty: String,
    pub fields: BTreeMap<String, Field>,
    pub history: Vec<Change>,
}

/// Counts only: no type, field name or value reaches a log (CLI-PQV-03, review D-12).
impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Item({} fields, {} history)",
            self.fields.len(),
            self.history.len()
        )
    }
}

impl Item {
    /// An empty item of type `ty` (a draft).
    pub fn new(ty: &str) -> Item {
        Item {
            ty: ty.into(),
            fields: BTreeMap::new(),
            history: vec![],
        }
    }

    /// A tombstone (`{"type":"deleted"}`).
    pub fn deleted() -> Item {
        Item::new("deleted")
    }

    /// Sets `name` (a plain value given as `Value`; a secret as [`Field::secret`]); checked when the item is written.
    pub fn set(&mut self, name: &str, value: Field) -> &mut Item {
        self.fields.insert(name.into(), value);
        self
    }

    /// The plain value of `name`, if it is plain.
    pub fn plain(&self, name: &str) -> Option<&Value> {
        match self.fields.get(name)? {
            Field::Plain(v) => Some(v),
            _ => None,
        }
    }

    fn hide(&self) -> bool {
        self.ty == "note" && self.plain("hideBody") == Some(&Value::Bool(true))
    }

    /// The class of `name` in this item (the table, with this item's `hideBody`).
    pub fn class(&self, name: &str) -> Class {
        class(&self.ty, name, self.hide())
    }

    /// A writer's checks (spec §6.8): every field of the kind the table gives it (a secret given as plain, a plain one as a
    /// secret, an unknown one invented: `Shape`), a secret valid UTF-8, the custom fields' bounds, a tombstone with no other
    /// field, and [`content::check_item`]'s bounds over the plain fields.
    pub fn check(&self) -> Result<(), Bad> {
        if self.ty == "deleted" {
            return (self.fields.is_empty() && self.history.is_empty())
                .then_some(())
                .ok_or(Bad::Shape);
        }
        let mut plain = Map::new();
        plain.insert("type".into(), Value::String(self.ty.clone()));
        for (k, v) in &self.fields {
            // `history` is a field only as a kept part this client could not type (review D-8)
            let kept_history =
                k == "history" && matches!(v, Field::Opaque(_)) && self.history.is_empty();
            if k == "type" || (k == "history" && !kept_history) || !v.of(self.class(k)) {
                return Err(Bad::Shape);
            }
            kept_as_read(v, self.class(k))?;
            match v {
                // a kept `null` is no value to bound (re-check R-3)
                Field::Plain(Value::Null) => {}
                Field::Plain(p) => {
                    plain.insert(k.clone(), p.clone());
                }
                other => check_value(other, 1)?,
            }
        }
        // every earlier value typed as its field is (rule 25, review C-5)
        for h in &self.history {
            if h.field.is_empty() || !h.value.of(self.class(&h.field)) {
                return Err(Bad::Shape);
            }
            kept_as_read(&h.value, self.class(&h.field))?;
            check_value(&h.value, 3)?;
        }
        // what every reader opens, the writer bounds too (re-check R-2)
        if self.secrets() > SECRETS_MAX {
            return Err(Bad::Shape);
        }
        content::check_item(&Value::Object(plain))
    }

    /// The secrets this item holds: its secret fields, its secret custom fields, the secrets of its history.
    pub fn secrets(&self) -> usize {
        self.fields
            .values()
            .chain(self.history.iter().map(|h| &h.value))
            .map(Field::secrets)
            .sum()
    }

    /// The canonical JSON of the item (UA-7 P49), in a zeroizing buffer: `Shape` past 16,384 B or for a value no writer
    /// writes. Not checked against the table ([`Self::check`]).
    pub fn canonical(&self) -> Result<Zeroizing<Vec<u8>>, Bad> {
        let mut out = Out::new();
        self.write(&mut out)?;
        Ok(out.into_inner())
    }

    fn write(&self, out: &mut Out) -> Result<(), Bad> {
        let ty = Field::Plain(Value::String(self.ty.clone()));
        let mut keys: Vec<&str> = self.fields.keys().map(String::as_str).collect();
        keys.push("type");
        if !self.history.is_empty() {
            keys.push("history");
        }
        keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        keys.dedup();
        out.put(b"{")?;
        for (i, k) in keys.iter().enumerate() {
            if i > 0 {
                out.put(b",")?;
            }
            content::escape(k.as_bytes(), out)?;
            out.put(b":")?;
            match *k {
                "type" => write_field(&ty, 1, out)?,
                // a history this client typed; else the kept part of the field `history` below
                "history" if !self.history.is_empty() => {
                    out.put(b"[")?;
                    for (j, h) in self.history.iter().enumerate() {
                        if j > 0 {
                            out.put(b",")?;
                        }
                        out.put(b"{\"field\":")?;
                        content::escape(h.field.as_bytes(), out)?;
                        out.put(b",\"value\":")?;
                        write_field(&h.value, 3, out)?;
                        out.put(b"}")?;
                    }
                    out.put(b"]")?;
                }
                k => write_field(self.fields.get(k).ok_or(Bad::Shape)?, 1, out)?,
            }
        }
        out.put(b"}")
    }

    /// The item a writer writes: checked, canonical, padded to its bucket (VC9), every buffer zeroizing.
    pub fn plaintext(&self) -> Result<Zeroizing<Vec<u8>>, Bad> {
        self.check()?;
        content::pad(&self.canonical()?)
    }

    /// The item of a decrypted, padded plaintext ([`Self::from_canonical`] of its content).
    pub fn from_plaintext(pt: &[u8]) -> Result<Item, Bad> {
        Item::from_canonical(content::unpad(pt, false)?)
    }

    /// The item of canonical JSON bytes: an object with a `type` of 1–32 B, each field typed by the table (a secret field that
    /// is not a text, a custom list not of the custom shape: kept opaque; `null`: plain), its `history` typed alike; then
    /// written again and compared, so bytes another writer could have written differently are `Unreadable`. Nothing is
    /// checked against a writer's bounds (an unknown type is returned as it is, for the UI to show as unsupported).
    pub fn from_canonical(b: &[u8]) -> Result<Item, Bad> {
        let bad = |_| Bad::Unreadable;
        let top: BTreeMap<String, &RawValue> = serde_json::from_slice(b).map_err(bad)?;
        let ty: String =
            serde_json::from_str(top.get("type").ok_or(Bad::Unreadable)?.get()).map_err(bad)?;
        if !(1..=32).contains(&ty.len()) {
            return Err(Bad::Unreadable);
        }
        let hide = ty == "note" && top.get("hideBody").map(|r| r.get()) == Some("true");
        let mut it = Item::new(&ty);
        // the secrets opened so far (at most SECRETS_MAX)
        let mut n = 0;
        for (k, raw) in &top {
            match k.as_str() {
                "type" => {}
                "history" => {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct H<'a> {
                        field: String,
                        #[serde(borrow)]
                        value: &'a RawValue,
                    }
                    // a history this client cannot type (another shape, an empty list) is kept as it was (review D-8)
                    match serde_json::from_str::<Vec<H>>(raw.get()) {
                        Ok(hs) if !hs.is_empty() && hs.iter().all(|h| !h.field.is_empty()) => {
                            for h in hs {
                                let c = class(&ty, &h.field, hide);
                                let value = read_field(c, h.value, 3, &mut n)?;
                                it.history.push(Change {
                                    field: h.field,
                                    value,
                                });
                            }
                        }
                        _ => {
                            it.fields.insert("history".into(), opaque(raw, 1)?);
                        }
                    }
                }
                k => {
                    let f = read_field(class(&ty, k, hide), raw, 1, &mut n)?;
                    it.fields.insert(k.into(), f);
                }
            }
        }
        let mut again = Out::new();
        it.write(&mut again).map_err(|_| Bad::Unreadable)?;
        if again.bytes() != b {
            return Err(Bad::Unreadable);
        }
        Ok(it)
    }
}

/// A kept part stands where a reader would keep it only (re-check R-6): read again under the table's class `c`, it is
/// still a kept part (a secret's text or a plain value given as a kept part is `Shape`).
fn kept_as_read(v: &Field, c: Class) -> Result<(), Bad> {
    match v {
        Field::Opaque(_) if c != Class::Opaque && !matches!(v.retyped(c), Field::Opaque(_)) => {
            Err(Bad::Shape)
        }
        _ => Ok(()),
    }
}

fn utf8(s: &SecretBytes) -> Result<(), Bad> {
    s.with(|b| std::str::from_utf8(b).map(|_| ()))
        .map_err(|_| Bad::Shape)
}

/// A writer's checks of a value that is not plain, nested `d` levels in the item: a secret valid UTF-8, the custom fields'
/// bounds, a kept part canonical JSON.
fn check_value(v: &Field, d: usize) -> Result<(), Bad> {
    match v {
        Field::Plain(p) => {
            let mut out = Out::new();
            content::write_value_at(p, d, &mut out)
        }
        Field::Secret(s) => utf8(s),
        Field::Custom(c) => check_custom(c),
        Field::Opaque(o) => opaque_ok(o, d).map_err(|_| Bad::Shape),
    }
}

fn check_custom(c: &[Custom]) -> Result<(), Bad> {
    let ok = c.len() <= CUSTOM_MAX
        && c.iter().all(|x| {
            (1..=CUSTOM_NAME_MAX).contains(&x.name.len())
                && match &x.value {
                    Field::Plain(Value::String(_)) => true,
                    Field::Secret(s) => utf8(s).is_ok(),
                    _ => false,
                }
        });
    ok.then_some(()).ok_or(Bad::Shape)
}

/// Whether `b` is canonical JSON nested at most to the item's depth from level `d` (a kept part, on read and on write:
/// review C-1), else `Unreadable`.
fn opaque_ok(b: &[u8], d: usize) -> Result<(), Bad> {
    let mut v: Value = serde_json::from_slice(b).map_err(|_| Bad::Unreadable)?;
    let mut again = Out::new();
    let same = content::write_value_at(&v, d, &mut again).is_ok() && again.bytes() == b;
    wipe(&mut v);
    same.then_some(()).ok_or(Bad::Unreadable)
}

/// Every text of `v` zeroized (a kept part parsed only to be checked; ponytail: keys and numbers stay, a kept part is no
/// table secret).
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

/// `f`'s canonical JSON, nested `d` levels in the item.
fn write_field(f: &Field, d: usize, out: &mut Out) -> Result<(), Bad> {
    match f {
        Field::Plain(v) => content::write_value_at(v, d, out),
        Field::Secret(s) => s.with(|b| content::escape(b, out)),
        Field::Opaque(o) => out.put(o),
        Field::Custom(c) => {
            out.put(b"[")?;
            for (i, x) in c.iter().enumerate() {
                if i > 0 {
                    out.put(b",")?;
                }
                out.put(b"{\"name\":")?;
                content::escape(x.name.as_bytes(), out)?;
                let secret = matches!(x.value, Field::Secret(_));
                out.put(if secret {
                    b",\"secret\":true,\"value\":"
                } else {
                    b",\"secret\":false,\"value\":"
                })?;
                write_field(&x.value, d + 2, out)?;
                out.put(b"}")?;
            }
            out.put(b"]")
        }
    }
}

/// A kept part: `raw`'s bytes, canonical JSON nested from level `d` (else `Unreadable`), in a zeroizing buffer.
fn opaque(raw: &RawValue, d: usize) -> Result<Field, Bad> {
    let b = raw.get().as_bytes();
    opaque_ok(b, d)?;
    Ok(Field::Opaque(Arc::new(Zeroizing::new(b.to_vec()))))
}

/// A secret text read from its JSON literal straight into a `SecretBytes` (`n` counts them: past [`SECRETS_MAX`]
/// `Unreadable`); `None` when `raw` is not a text.
fn secret_of(raw: &RawValue, n: &mut usize) -> Result<Option<Field>, Bad> {
    let Some(inner) = raw
        .get()
        .as_bytes()
        .strip_prefix(b"\"")
        .and_then(|x| x.strip_suffix(b"\""))
    else {
        return Ok(None);
    };
    *n += 1;
    if *n > SECRETS_MAX {
        return Err(Bad::Unreadable);
    }
    let out = content::unescape(inner).ok_or(Bad::Unreadable)?;
    let s = SecretBytes::from_zeroizing(out).map_err(|_| Bad::Unreadable)?;
    Ok(Some(Field::Secret(Arc::new(s))))
}

/// The value `raw` of class `c`, nested `d` levels in the item; `n` the secrets opened so far.
fn read_field(c: Class, raw: &RawValue, d: usize, n: &mut usize) -> Result<Field, Bad> {
    if raw.get() == "null" {
        return Ok(Field::Plain(Value::Null));
    }
    match c {
        Class::Plain => {
            let v: Value = serde_json::from_str(raw.get()).map_err(|_| Bad::Unreadable)?;
            let mut out = Out::new();
            content::write_value_at(&v, d, &mut out).map_err(|_| Bad::Unreadable)?;
            Ok(Field::Plain(v))
        }
        Class::Secret => match secret_of(raw, n)? {
            Some(f) => Ok(f),
            None => opaque(raw, d),
        },
        Class::Opaque => opaque(raw, d),
        Class::Custom => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct C<'a> {
                name: String,
                secret: bool,
                #[serde(borrow)]
                value: &'a RawValue,
            }
            // a list past the writer's bound, or of another shape, is kept as it was
            let cs = match serde_json::from_str::<Vec<C>>(raw.get()) {
                Ok(cs) if cs.len() <= CUSTOM_MAX => cs,
                _ => return opaque(raw, d),
            };
            let mut out = Vec::with_capacity(cs.len());
            // counted only if the list is typed (a list kept as it was opens no secret: re-check R-8)
            let mut m = *n;
            for x in cs {
                let value = if x.secret {
                    secret_of(x.value, &mut m)?
                } else {
                    serde_json::from_str::<Value>(x.value.get())
                        .ok()
                        .filter(Value::is_string)
                        .map(Field::Plain)
                };
                let Some(value) = value else {
                    return opaque(raw, d);
                };
                out.push(Custom {
                    name: x.name,
                    value,
                });
            }
            *n = m;
            Ok(Field::Custom(out))
        }
    }
}

// ------------------------------------------------------------------ merge (spec §7 "Merge")

/// A three-way merge's outcome: clean, or the merged item with the fields both sides changed (the newer side's value kept,
/// the other's recorded in `history`, typed as the field is).
#[derive(Clone, PartialEq, Eq)]
pub enum Merge {
    Clean(Item),
    Conflict(Item, Vec<String>),
}

/// Counts only, as `Item`'s (re-check R-7: no field name in a log).
impl std::fmt::Debug for Merge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Merge::Clean(i) => write!(f, "Clean({i:?})"),
            Merge::Conflict(i, c) => write!(f, "Conflict({i:?}, {} fields)", c.len()),
        }
    }
}

/// Per field against `base` (the version an edit started from), `type` one of them: a field only one side changed takes that
/// side's value, one both changed alike stays, one both changed differently keeps `ours` (the edit being written is the
/// newer) and records `theirs` in `history` (appended; `Plain(null)` for a field `theirs` removed). Values compare by their
/// canonical JSON (a text is the same text plain or secret). Fields neither knows survive; `history` itself merges by
/// union. A tombstone on one side against an edit on the other keeps the edit whole (`deleted` recorded in its history, a
/// conflict on `type`); against no edit the tombstone stands. Every value, history included, is then retyped by the merged item's table, so a secret's losing value stays a
/// `Secret` (rule 25) and a body hidden on either side stays hidden (review C-3).
pub fn merge(base: &Item, ours: &Item, theirs: &Item) -> Merge {
    // a tombstone on one side: an edit on the other is kept whole, the deletion recorded; else the tombstone stands
    if (ours.ty == "deleted") != (theirs.ty == "deleted") && base.ty != "deleted" {
        let edit = if ours.ty == "deleted" { theirs } else { ours };
        if edit.ty == base.ty && edit.fields == base.fields {
            return Merge::Clean(Item::deleted());
        }
        let mut kept = edit.clone();
        kept.history.push(Change {
            field: "type".into(),
            value: Field::Plain(Value::String("deleted".into())),
        });
        return Merge::Conflict(kept, vec!["type".into()]);
    }
    let all = |x: &Item| {
        let mut m: BTreeMap<String, Field> = x.fields.clone();
        m.insert("type".into(), Field::Plain(Value::String(x.ty.clone())));
        m
    };
    let (b, o, t) = (all(base), all(ours), all(theirs));
    let mut history = ours.history.clone();
    for h in &theirs.history {
        if !history.contains(h) {
            history.push(h.clone());
        }
    }
    let mut out = BTreeMap::new();
    let mut conflicts = Vec::new();
    let mut keys: Vec<&String> = b.keys().chain(o.keys()).chain(t.keys()).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        let (bv, ov, tv) = (b.get(k), o.get(k), t.get(k));
        let pick = if ov == tv || tv == bv {
            ov
        } else if ov == bv {
            tv
        } else {
            conflicts.push(k.clone());
            history.push(Change {
                field: k.clone(),
                value: tv.cloned().unwrap_or(Field::Plain(Value::Null)),
            });
            ov
        };
        if let Some(v) = pick {
            out.insert(k.clone(), v.clone());
        }
    }
    let ty = match out.remove("type") {
        Some(Field::Plain(Value::String(s))) => s,
        _ => ours.ty.clone(),
    };
    // a body hidden on either side stays hidden: a merge never un-hides (re-check R-4); a user un-hides by an edit
    if ty == "note" && (ours.hide() || theirs.hide()) {
        let on = Field::Plain(Value::Bool(true));
        if out.get("hideBody") != Some(&on) && !conflicts.iter().any(|c| c == "hideBody") {
            conflicts.push("hideBody".into());
        }
        out.insert("hideBody".into(), on);
    }
    // a history of a newer client's shape is kept as it is: no typed entry beside it (re-check R-5)
    if matches!(out.get("history"), Some(Field::Opaque(_))) {
        history.clear();
    }
    let mut item = Item {
        ty,
        fields: out,
        history,
    };
    let fields: Vec<(String, Field)> = item
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), v.retyped(item.class(k))))
        .collect();
    item.fields = fields.into_iter().collect();
    let history: Vec<Change> = item
        .history
        .iter()
        .map(|h| Change {
            field: h.field.clone(),
            value: h.value.retyped(item.class(&h.field)),
        })
        // a losing value that nests too deep for the history is not recorded (its version stays on chain: R-5)
        .filter(|h| check_value(&h.value, 3).is_ok())
        .collect();
    item.history = history;
    // the oldest history entries go first while the item holds more secrets than a reader opens (re-check R-2;
    // every version stays on chain, `PqVault::history` reads it)
    while item.secrets() > SECRETS_MAX && !item.history.is_empty() {
        item.history.remove(0);
    }
    if conflicts.is_empty() {
        Merge::Clean(item)
    } else {
        Merge::Conflict(item, conflicts)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn of(v: Value) -> Item {
        Item::from_canonical(content::canonical(&v).unwrap().as_bytes()).unwrap()
    }
    fn text(f: &Field) -> String {
        match f {
            Field::Secret(s) => s.with(|b| String::from_utf8(b.to_vec()).unwrap()),
            Field::Opaque(o) => String::from_utf8(o.to_vec()).unwrap(),
            Field::Plain(v) => v.to_string(),
            Field::Custom(c) => format!("{c:?}"),
        }
    }

    /// H2: the secret table per type, one place; a note's body by its `hideBody` (H3); an unknown field opaque.
    #[test]
    fn the_secret_table() {
        let card = of(
            json!({"type": "card", "title": "Visa", "cardholderName": "A B", "brand": "visa",
            "number": "4111111111111111", "code": "123", "pin": "9876", "expMonth": "04", "expYear": "2031"}),
        );
        for s in ["number", "code", "pin"] {
            assert!(matches!(card.fields[s], Field::Secret(_)), "{s}");
        }
        for p in ["title", "cardholderName", "brand", "expMonth", "expYear"] {
            assert!(matches!(card.fields[p], Field::Plain(_)), "{p}");
        }
        let id = of(
            json!({"type": "identity", "title": "Me", "firstName": "A", "lastName": "B",
            "address1": "1 Main St", "city": "X", "nationalId": "123-45-6789", "passportNumber": "P123",
            "licenseNumber": "L9"}),
        );
        for s in ["nationalId", "passportNumber", "licenseNumber"] {
            assert!(matches!(id.fields[s], Field::Secret(_)), "{s}");
        }
        for p in ["firstName", "lastName", "address1", "city"] {
            assert!(matches!(id.fields[p], Field::Plain(_)), "{p}");
        }
        let login = of(
            json!({"type": "login", "title": "t", "username": "u", "password": "p", "totp": "otpauth://x"}),
        );
        assert!(matches!(login.fields["password"], Field::Secret(_)));
        assert!(matches!(login.fields["totp"], Field::Secret(_)));
        assert!(matches!(login.fields["username"], Field::Plain(_)));
        assert!(matches!(
            of(json!({"type": "totp", "title": "t", "secret": "JBSWY3DP"})).fields["secret"],
            Field::Secret(_)
        ));
        let ssh = of(
            json!({"type": "sshKey", "title": "t", "privateKey": "k", "passphrase": "p", "publicKey": "pk"}),
        );
        assert!(matches!(ssh.fields["privateKey"], Field::Secret(_)));
        assert!(matches!(ssh.fields["passphrase"], Field::Secret(_)));
        assert!(matches!(ssh.fields["publicKey"], Field::Plain(_)));
        let note = |hide: bool| {
            of(
                json!({"type": "note", "title": "t", "mediaType": "text/plain", "body": "b", "hideBody": hide}),
            )
        };
        assert!(
            matches!(note(false).fields["body"], Field::Plain(_)),
            "plain by default"
        );
        assert!(
            matches!(note(true).fields["body"], Field::Secret(_)),
            "hidden"
        );
        assert!(matches!(
            of(json!({"type": "note", "title": "t", "mediaType": "text/plain", "body": "b"}))
                .fields["body"],
            Field::Plain(_)
        ));
        let unknown = of(json!({"type": "login", "title": "t", "x-new": {"a": [1, "s"]}}));
        assert!(matches!(unknown.fields["x-new"], Field::Opaque(_)));
        assert_eq!(
            text(&unknown.fields["x-new"]),
            "{\"a\":[1,\"s\"]}",
            "kept byte for byte"
        );
        let alien = of(json!({"type": "spaceship", "title": "t", "warp": "9"}));
        assert!(matches!(alien.fields["title"], Field::Plain(_)));
        assert!(matches!(alien.fields["warp"], Field::Opaque(_)));
    }

    /// Custom fields declare themselves secret; a custom list not of the shape is kept opaque.
    #[test]
    fn custom_fields_declare_secret() {
        let it = of(json!({"type": "login", "title": "t", "fields": [
            {"name": "pin2", "secret": true, "value": "4321"}, {"name": "note", "secret": false, "value": "hi"}]}));
        let Field::Custom(c) = &it.fields["fields"] else {
            panic!()
        };
        assert!(matches!(c[0].value, Field::Secret(_)));
        assert_eq!(text(&c[0].value), "4321");
        assert!(matches!(c[1].value, Field::Plain(_)));
        let odd =
            of(json!({"type": "login", "title": "t", "fields": [{"name": "a", "value": "x"}]}));
        assert!(matches!(odd.fields["fields"], Field::Opaque(_)));
    }

    /// The writer's canonical JSON is the bytes `content::canonical` writes (the format unchanged); a secret with every
    /// character the escaper handles reads back as the same bytes; `Debug` prints no value.
    #[test]
    fn canonical_round_trip_and_silent_debug() {
        let all: String = (0u8..0x80)
            .map(char::from)
            .chain("é\u{1F600}\"\\".chars())
            .collect();
        let v = json!({"type": "login", "title": "t", "password": all, "urls": [{"url": "https://a", "match": "host"}]});
        let it = of(v.clone());
        assert_eq!(
            &it.canonical().unwrap()[..],
            content::canonical(&v).unwrap().as_bytes()
        );
        assert_eq!(text(&it.fields["password"]), all);
        let dbg = format!("{it:?} {:?} {:?}", it.fields["password"], it.fields);
        assert!(
            !dbg.contains("https://a") && !dbg.contains("\\u0001") && !dbg.contains('é'),
            "{dbg}"
        );
        assert!(dbg.contains("Secret"), "{dbg}");
        assert_eq!(
            format!("{it:?}"),
            "Item(3 fields, 0 history)",
            "counts only (CLI-PQV-03)"
        );
        assert_eq!(
            Item::from_canonical(b"{\"title\":\"t\", \"type\":\"login\"}"),
            Err(Bad::Unreadable)
        );
        assert_eq!(
            Item::from_canonical(b"{\"password\":\"\\u0041\",\"title\":\"t\",\"type\":\"login\"}"),
            Err(Bad::Unreadable)
        );
    }

    /// A writer's checks: a secret given as plain, a plain field as a secret, an invented unknown field: `Shape`; the twin
    /// typed by the table passes.
    #[test]
    fn a_field_of_the_wrong_kind_is_refused() {
        let mut ok = Item::new("card");
        ok.set("title", Field::Plain(json!("Visa")))
            .set("number", Field::secret(b"4111").unwrap());
        assert_eq!(ok.check(), Ok(()));
        let mut plain_secret = ok.clone();
        plain_secret.set("number", Field::Plain(json!("4111")));
        assert_eq!(plain_secret.check(), Err(Bad::Shape));
        let mut secret_plain = ok.clone();
        secret_plain.set("brand", Field::secret(b"visa").unwrap());
        assert_eq!(secret_plain.check(), Err(Bad::Shape));
        let mut invented = ok.clone();
        invented.set("x-new", Field::Plain(json!(1)));
        assert_eq!(invented.check(), Err(Bad::Shape));
        let mut tomb = Item::deleted();
        assert_eq!(tomb.check(), Ok(()));
        tomb.set("title", Field::Plain(json!("t")));
        assert_eq!(tomb.check(), Err(Bad::Shape));
    }

    /// Rule 25: the merge's losing value of a secret field stays a secret in `history`, and reads back as one; a plain one
    /// plain. Unknown fields survive.
    #[test]
    fn merge_keeps_the_losing_secret_secret() {
        let base = of(json!({"type": "login", "title": "a", "password": "p0", "x-new": 1}));
        let ours = of(json!({"type": "login", "title": "a2", "password": "p1", "x-new": 1}));
        let theirs =
            of(json!({"type": "login", "title": "a", "password": "p2", "x-new": 1, "notes": "n"}));
        let Merge::Conflict(m, f) = merge(&base, &ours, &theirs) else {
            panic!()
        };
        assert_eq!(f, vec!["password".to_string()]);
        assert_eq!(text(&m.fields["password"]), "p1");
        assert_eq!(m.plain("title"), Some(&json!("a2")));
        assert_eq!(m.plain("notes"), Some(&json!("n")));
        assert!(matches!(m.fields["x-new"], Field::Opaque(_)));
        assert_eq!(m.history.len(), 1);
        assert!(
            matches!(m.history[0].value, Field::Secret(_)),
            "the losing secret stays secret"
        );
        assert_eq!(text(&m.history[0].value), "p2");
        let back = Item::from_canonical(&m.canonical().unwrap()).unwrap();
        assert!(
            matches!(back.history[0].value, Field::Secret(_)),
            "and reads back as one"
        );
        assert_eq!(back, m);
        assert!(!format!("{m:?}").contains("p2"));
        let clean = merge(&base, &ours, &base);
        assert_eq!(clean, Merge::Clean(ours.clone()));
    }

    /// Review C-8 / F-5: the escaper writes every character as serde_json does (the known answer is serde_json's own
    /// writer, not the escaper again), and `unescape` reads it back.
    #[test]
    fn the_escaper_is_serde_jsons() {
        let mut all: Vec<String> = (0u32..0x80)
            .map(|c| char::from_u32(c).unwrap().to_string())
            .collect();
        all.extend(["é", "\u{2028}", "\u{FFFF}", "\u{1F600}", "a\"b\\c"].map(String::from));
        for t in all {
            let mut out = Out::new();
            content::escape(t.as_bytes(), &mut out).unwrap();
            assert_eq!(
                out.bytes(),
                serde_json::to_string(&t).unwrap().as_bytes(),
                "{t:?}"
            );
            let inner = &out.bytes()[1..out.bytes().len() - 1];
            assert_eq!(
                &content::unescape(inner).unwrap()[..],
                t.as_bytes(),
                "{t:?}"
            );
        }
    }

    /// Review C-1: a kept part is canonical JSON too, as the whole item was before (inner whitespace, key order, a float,
    /// duplicate keys, a depth past 8 for the whole item: `Unreadable`); the twin canonical part reads.
    #[test]
    fn a_kept_part_is_canonical() {
        let ok = br#"{"title":"t","type":"login","x":{"a":2,"b":[1]}}"#;
        assert!(Item::from_canonical(ok).is_ok());
        for bad in [
            &br#"{"title":"t","type":"login","x":{"b":1,"a":2}}"#[..],
            br#"{"title":"t","type":"login","x":{"a": 2}}"#,
            br#"{"title":"t","type":"login","x":1.5}"#,
            br#"{"title":"t","type":"login","x":{"a":1,"a":1}}"#,
            br#"{"title":"t","type":"login","x":[[[[[[[[1]]]]]]]]}"#,
            br#"{"password":{"b":1,"a":2},"title":"t","type":"login"}"#,
        ] {
            assert_eq!(
                Item::from_canonical(bad),
                Err(Bad::Unreadable),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // seven levels under the item is the most (the item itself is the eighth)
        assert!(
            Item::from_canonical(br#"{"title":"t","type":"login","x":[[[[[[[1]]]]]]]}"#).is_ok()
        );
    }

    /// Review C-2: what the reader keeps, it writes back as it was (spec §6.8 "kept verbatim on edit"): a `null`, a
    /// secret-class field that is no text, a custom list of a newer shape, an empty history, a history of another shape,
    /// unknown fields (their keys in UTF-16 order).
    #[test]
    fn what_is_kept_is_written_back() {
        for b in [
            &br#"{"password":null,"title":"t","type":"login","x-new":null}"#[..],
            br#"{"password":{"v":2},"title":"t","type":"login"}"#,
            br#"{"fields":[{"kind":"pin","name":"a","value":"1"}],"title":"t","type":"login"}"#,
            br#"{"history":[],"title":"t","type":"login"}"#,
            br#"{"history":[{"at":1,"field":"title","value":"a"}],"title":"t","type":"login"}"#,
            "{\"title\":\"t\",\"type\":\"login\",\"x-new\":{\"a\":[1,\"s\"]},\"\u{1F600}\":1,\"\u{FF5E}\":2}"
                .as_bytes(),
        ] {
            let it = Item::from_canonical(b).unwrap();
            assert_eq!(it.check(), Ok(()), "{}", String::from_utf8_lossy(b));
            assert_eq!(&it.canonical().unwrap()[..], b, "byte for byte");
        }
    }

    /// Review C-5: the history is typed and checked on write: a kept part there must be canonical JSON, a secret UTF-8, a
    /// secret's earlier value no plain text; the twin passes.
    #[test]
    fn history_is_checked() {
        let mut it = of(json!({"type": "login", "title": "t", "password": "p"}));
        it.history.push(Change {
            field: "password".into(),
            value: Field::secret(b"p0").unwrap(),
        });
        assert_eq!(it.check(), Ok(()));
        let with = |value: Field, field: &str| {
            let mut bad = it.clone();
            bad.history.push(Change {
                field: field.into(),
                value,
            });
            bad.check()
        };
        let not_json = Field::Opaque(Arc::new(Zeroizing::new(b"{not json".to_vec())));
        assert_eq!(with(not_json, "x"), Err(Bad::Shape));
        assert_eq!(
            with(Field::secret(&[0xff, 0xfe]).unwrap(), "password"),
            Err(Bad::Shape)
        );
        assert_eq!(
            with(Field::Plain(json!("p0")), "password"),
            Err(Bad::Shape),
            "a secret's earlier value given as plain"
        );
        assert_eq!(with(Field::Plain(json!("a")), "title"), Ok(()));
    }

    /// Review C-3: a `hideBody` change on one side and a body edit on the other merge cleanly, the body hidden; both
    /// editing the body under a hide keep the losing body secret; a tombstone against an edit keeps the edit.
    #[test]
    fn merge_retypes_by_the_merged_table() {
        let note = |hide: bool, body: &str| {
            of(
                json!({"type": "note", "title": "n", "mediaType": "text/plain", "hideBody": hide, "body": body}),
            )
        };
        let base = note(false, "b0");
        for (ours, theirs) in [
            (note(false, "b1"), note(true, "b0")),
            (note(true, "b0"), note(false, "b1")),
        ] {
            let Merge::Clean(m) = merge(&base, &ours, &theirs) else {
                panic!("a hide and an edit do not conflict")
            };
            assert!(
                matches!(m.fields["body"], Field::Secret(_)),
                "the body hidden"
            );
            assert_eq!(text(&m.fields["body"]), "b1");
            assert_eq!(m.check(), Ok(()));
        }
        for (ours, theirs) in [
            (note(false, "b1"), note(true, "b2")),
            (note(true, "b1"), note(false, "b2")),
        ] {
            let Merge::Conflict(m, f) = merge(&base, &ours, &theirs) else {
                panic!()
            };
            assert_eq!(f, vec!["body".to_string()]);
            assert!(matches!(m.fields["body"], Field::Secret(_)));
            assert_eq!(text(&m.fields["body"]), "b1", "ours kept");
            assert!(
                matches!(m.history[0].value, Field::Secret(_)),
                "the losing body secret"
            );
            assert_eq!(m.check(), Ok(()));
        }
        let login = |pw: &str| of(json!({"type": "login", "title": "t", "password": pw}));
        let Merge::Conflict(m, f) = merge(&login("p0"), &login("p1"), &Item::deleted()) else {
            panic!()
        };
        assert_eq!(f, vec!["type".to_string()]);
        assert_eq!(m.ty, "login");
        assert_eq!(text(&m.fields["password"]), "p1");
        assert_eq!(m.check(), Ok(()));
        let back = Item::from_canonical(&m.canonical().unwrap()).unwrap();
        assert!(
            matches!(back.history[0].value, Field::Plain(_)),
            "a type in history reads back plain"
        );
        assert_eq!(
            merge(&login("p0"), &login("p0"), &Item::deleted()),
            Merge::Clean(Item::deleted())
        );
    }

    /// Review C-4: at most SECRETS_MAX secrets are opened per item; the twin at the bound reads.
    #[test]
    fn secrets_per_item_are_bounded() {
        let at = |n: usize| {
            let h: Vec<Value> = (0..n)
                .map(|i| json!({"field": "password", "value": format!("p{i}")}))
                .collect();
            content::canonical(&json!({"type": "login", "title": "t", "history": h})).unwrap()
        };
        assert!(Item::from_canonical(at(SECRETS_MAX).as_bytes()).is_ok());
        assert_eq!(
            Item::from_canonical(at(SECRETS_MAX + 1).as_bytes()),
            Err(Bad::Unreadable)
        );
    }

    /// Review C-11: the custom fields' bounds and the writer's 16 KiB cap.
    #[test]
    fn custom_bounds_and_the_cap() {
        let custom = |n: usize, name: &str| {
            let mut it = Item::new("login");
            it.set("title", Field::Plain(json!("t"))).set(
                "fields",
                Field::Custom(
                    (0..n)
                        .map(|_| Custom {
                            name: name.into(),
                            value: Field::Plain(json!("v")),
                        })
                        .collect(),
                ),
            );
            it.check()
        };
        assert_eq!(custom(CUSTOM_MAX, "a"), Ok(()));
        assert_eq!(custom(CUSTOM_MAX + 1, "a"), Err(Bad::Shape));
        assert_eq!(custom(1, &"a".repeat(CUSTOM_NAME_MAX + 1)), Err(Bad::Shape));
        assert_eq!(custom(1, ""), Err(Bad::Shape));
        let mut big = Item::new("note");
        big.set("title", Field::Plain(json!("t")))
            .set("mediaType", Field::Plain(json!("text/plain")))
            .set("body", Field::Plain(json!("x".repeat(16_384))));
        assert_eq!(big.canonical().map(|_| ()), Err(Bad::Shape));
    }

    /// Re-check R-2: a writer holds an item to the secrets a reader opens; the merge drops the oldest history entries to
    /// stay within it (their versions stay on chain).
    #[test]
    fn the_writer_holds_the_secrets_bound() {
        let at = |n: usize| {
            let h: Vec<Value> = (0..n)
                .map(|i| json!({"field": "password", "value": format!("p{i}")}))
                .collect();
            of(json!({"type": "login", "title": "t", "password": "p", "history": h}))
        };
        assert_eq!(at(SECRETS_MAX - 1).check(), Ok(()));
        let mut over = at(SECRETS_MAX - 1);
        over.history.push(Change {
            field: "password".into(),
            value: Field::secret(b"one more").unwrap(),
        });
        assert_eq!(over.check(), Err(Bad::Shape));
        let base = at(SECRETS_MAX - 1);
        let mut ours = base.clone();
        ours.set("password", Field::secret(b"ours").unwrap());
        let mut theirs = base.clone();
        theirs.set("password", Field::secret(b"theirs").unwrap());
        let (Merge::Conflict(m, _) | Merge::Clean(m)) = merge(&base, &ours, &theirs);
        assert_eq!(m.secrets(), SECRETS_MAX);
        assert_eq!(m.check(), Ok(()));
        assert_eq!(
            text(&m.history.last().unwrap().value),
            "theirs",
            "the newest kept"
        );
    }

    /// Re-check R-3 and R-6: a kept `null` in a bounded field is written back; a kept part where no reader keeps one (a
    /// secret's text, a plain value) is `Shape`.
    #[test]
    fn kept_nulls_and_misplaced_kept_parts() {
        let it = Item::from_canonical(
            br#"{"folder":null,"tags":null,"title":"t","ts":null,"type":"login","urls":null}"#,
        )
        .unwrap();
        assert_eq!(it.check(), Ok(()));
        let kept = |b: &[u8]| Field::Opaque(Arc::new(Zeroizing::new(b.to_vec())));
        let mut it = of(json!({"type": "login", "title": "t"}));
        it.set("password", kept(br#""pw""#));
        assert_eq!(
            it.check(),
            Err(Bad::Shape),
            "a secret's text as a kept part"
        );
        it.set("password", kept(br#"{"v":2}"#));
        assert_eq!(it.check(), Ok(()), "the twin a reader keeps");
        it.set("username", kept(br#""u""#));
        assert_eq!(it.check(), Err(Bad::Shape), "a plain value as a kept part");
    }

    /// Re-check R-4: a merge never un-hides a body: hidden on one side, un-hidden on the other, it stays hidden (a conflict
    /// on `hideBody` for the UI to ask); re-check R-5: a losing value too deep for the history and a kept history beside a
    /// conflict leave an item the writer takes.
    #[test]
    fn merge_never_unhides_and_stays_writable() {
        let note = |hide: bool, body: &str| {
            of(
                json!({"type": "note", "title": "n", "mediaType": "text/plain", "hideBody": hide, "body": body}),
            )
        };
        let Merge::Conflict(m, f) = merge(&note(true, "b0"), &note(true, "b1"), &note(false, "b0"))
        else {
            panic!("an un-hide against a hidden edit is asked")
        };
        assert_eq!(f, vec!["hideBody".to_string()]);
        assert_eq!(m.plain("hideBody"), Some(&json!(true)));
        assert!(matches!(m.fields["body"], Field::Secret(_)));
        assert_eq!(m.check(), Ok(()));
        let x = |v: Value| of(json!({"type": "login", "title": "t", "x": v}));
        let deep = json!([[[[[[[1]]]]]]]);
        let Merge::Conflict(m, _) = merge(&x(json!(1)), &x(json!(3)), &x(deep)) else {
            panic!()
        };
        assert!(
            m.history.is_empty(),
            "too deep for the history: not recorded"
        );
        assert_eq!(m.check(), Ok(()));
        let kept = |v: &str| {
            Item::from_canonical(
                format!(r#"{{"history":[{{"at":1,"field":"title","value":"a"}}],"title":"{v}","type":"login"}}"#)
                    .as_bytes(),
            )
            .unwrap()
        };
        let (Merge::Conflict(m, _) | Merge::Clean(m)) =
            merge(&kept("t"), &kept("ours"), &kept("theirs"));
        assert!(m.history.is_empty());
        assert!(matches!(m.fields["history"], Field::Opaque(_)));
        assert_eq!(m.check(), Ok(()));
    }

    /// Re-check R-8: a custom list kept as it was opens no secret, so it counts none against the bound; re-check R-7: a
    /// merge's `Debug` names no field.
    #[test]
    fn kept_custom_lists_count_no_secret_and_merge_debug_is_silent() {
        let h: Vec<Value> = (0..SECRETS_MAX)
            .map(|i| json!({"field": "password", "value": format!("p{i}")}))
            .collect();
        let odd = json!([{"name": "a", "secret": true, "value": "s"}, {"name": "b", "value": "x"}]);
        let b = content::canonical(
            &json!({"type": "login", "title": "t", "history": h, "fields": odd}),
        )
        .unwrap();
        let it = Item::from_canonical(b.as_bytes()).unwrap();
        assert!(matches!(it.fields["fields"], Field::Opaque(_)));
        let login = |pw: &str| of(json!({"type": "login", "title": "t", "password": pw}));
        let m = merge(&login("p0"), &login("p1"), &login("p2"));
        let dbg = format!("{m:?}");
        assert!(!dbg.contains("password") && !dbg.contains("p2"), "{dbg}");
    }
}
