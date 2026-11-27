// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The redacting item layer (CLI-PQV-16 H1–H3; spec §6.8): an item's fields typed by one table, the per-type secret table, so
//! no front-end decides which field is secret. A field is `Plain` (a JSON value), `Secret` (a text in a `SecretBytes`),
//! `Custom` (the custom fields, each declaring itself secret or not) or `Opaque` (a field this client does not know: its
//! canonical JSON kept byte for byte in a `SecretBytes`, never shown). The canonical JSON is built in a zeroizing buffer of a
//! fixed capacity (it never reallocates), and parsed from the decrypted plaintext in place: a secret's text goes from the
//! plaintext straight into its `SecretBytes`, never into a `String`. A secret field's earlier values (the merge's `history`)
//! are secret too (rule 25). `Debug` names fields and their kinds, never a value. UNAUDITED.
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
    if COMMON.contains(&name) || plain.contains(&name) {
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
    /// a field this client does not know: its canonical JSON, kept byte for byte and never shown
    Opaque(Arc<SecretBytes>),
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
    fn of(&self, c: Class) -> bool {
        matches!(
            (self, c),
            (Field::Plain(_), Class::Plain)
                | (Field::Secret(_), Class::Secret)
                | (Field::Custom(_), Class::Custom)
                | (Field::Opaque(_), Class::Opaque)
        )
    }
}

impl PartialEq for Field {
    fn eq(&self, o: &Field) -> bool {
        match (self, o) {
            (Field::Plain(a), Field::Plain(b)) => a == b,
            (Field::Secret(a), Field::Secret(b)) | (Field::Opaque(a), Field::Opaque(b)) => {
                a.with2(b, |x, y| x == y)
            }
            (Field::Custom(a), Field::Custom(b)) => a == b,
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
        write!(f, "{}: {:?}", self.name, self.value)
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
        write!(f, "{}: {:?}", self.field, self.value)
    }
}

/// An item (spec §6.8): its `type`, every other field by name, and its `history`.
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    pub ty: String,
    pub fields: BTreeMap<String, Field>,
    pub history: Vec<Change>,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("type", &self.ty)
            .field("fields", &self.fields)
            .field("history", &self.history)
            .finish()
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
            if !v.of(self.class(k)) || k == "type" || k == "history" {
                return Err(Bad::Shape);
            }
            match v {
                Field::Plain(p) => {
                    plain.insert(k.clone(), p.clone());
                }
                Field::Secret(s) => utf8(s)?,
                Field::Custom(c) => check_custom(c)?,
                Field::Opaque(o) => opaque_ok(o)?,
            }
        }
        content::check_item(&Value::Object(plain))
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
                "type" => write_field(&ty, out)?,
                "history" => {
                    out.put(b"[")?;
                    for (j, h) in self.history.iter().enumerate() {
                        if j > 0 {
                            out.put(b",")?;
                        }
                        out.put(b"{\"field\":")?;
                        content::escape(h.field.as_bytes(), out)?;
                        out.put(b",\"value\":")?;
                        write_field(&h.value, out)?;
                        out.put(b"}")?;
                    }
                    out.put(b"]")?;
                }
                k => write_field(self.fields.get(k).ok_or(Bad::Shape)?, out)?,
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
                    let hs: Vec<H> = serde_json::from_str(raw.get()).map_err(bad)?;
                    for h in hs {
                        let value = read_field(class(&ty, &h.field, hide), h.value)?;
                        it.history.push(Change {
                            field: h.field,
                            value,
                        });
                    }
                }
                k => {
                    let f = read_field(class(&ty, k, hide), raw)?;
                    it.fields.insert(k.into(), f);
                }
            }
        }
        let mut again = Out::new();
        it.write(&mut again)?;
        if again.bytes() != b {
            return Err(Bad::Unreadable);
        }
        Ok(it)
    }
}

fn utf8(s: &SecretBytes) -> Result<(), Bad> {
    s.with(|b| std::str::from_utf8(b).map(|_| ()))
        .map_err(|_| Bad::Shape)
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

/// Whether `o` holds canonical JSON (a kept field written back as it was read).
fn opaque_ok(o: &SecretBytes) -> Result<(), Bad> {
    o.with(|b| {
        let mut v: Value = serde_json::from_slice(b).map_err(|_| Bad::Shape)?;
        let mut again = Out::new();
        let same = content::write_value(&v, &mut again).is_ok() && again.bytes() == b;
        wipe(&mut v);
        same.then_some(()).ok_or(Bad::Shape)
    })
}

/// Every text of `v` zeroized (a kept field parsed only to be checked).
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

fn write_field(f: &Field, out: &mut Out) -> Result<(), Bad> {
    match f {
        Field::Plain(v) => content::write_value(v, out),
        Field::Secret(s) => s.with(|b| content::escape(b, out)),
        Field::Opaque(o) => o.with(|b| out.put(b)),
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
                write_field(&x.value, out)?;
                out.put(b"}")?;
            }
            out.put(b"]")
        }
    }
}

fn opaque(raw: &RawValue) -> Result<Field, Bad> {
    let b = raw.get().as_bytes();
    let s = SecretBytes::new(b.len()).map_err(|_| Bad::Unreadable)?;
    s.with_mut(|m| m.copy_from_slice(b));
    Ok(Field::Opaque(Arc::new(s)))
}

/// A secret text read from its JSON literal straight into a `SecretBytes`; `None` when `raw` is not a text.
fn secret_of(raw: &RawValue) -> Result<Option<Field>, Bad> {
    let Some(inner) = raw
        .get()
        .as_bytes()
        .strip_prefix(b"\"")
        .and_then(|x| x.strip_suffix(b"\""))
    else {
        return Ok(None);
    };
    let out = content::unescape(inner).ok_or(Bad::Unreadable)?;
    let s = SecretBytes::from_zeroizing(out).map_err(|_| Bad::Unreadable)?;
    Ok(Some(Field::Secret(Arc::new(s))))
}

fn read_field(c: Class, raw: &RawValue) -> Result<Field, Bad> {
    let bad = |_| Bad::Unreadable;
    if raw.get() == "null" {
        return Ok(Field::Plain(Value::Null));
    }
    match c {
        Class::Plain => Ok(Field::Plain(serde_json::from_str(raw.get()).map_err(bad)?)),
        Class::Secret => match secret_of(raw)? {
            Some(f) => Ok(f),
            None => opaque(raw),
        },
        Class::Opaque => opaque(raw),
        Class::Custom => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct C<'a> {
                name: String,
                secret: bool,
                #[serde(borrow)]
                value: &'a RawValue,
            }
            let Ok(cs) = serde_json::from_str::<Vec<C>>(raw.get()) else {
                return opaque(raw);
            };
            let mut out = Vec::with_capacity(cs.len());
            for x in cs {
                let value = if x.secret {
                    secret_of(x.value)?
                } else {
                    serde_json::from_str::<Value>(x.value.get())
                        .ok()
                        .filter(Value::is_string)
                        .map(Field::Plain)
                };
                let Some(value) = value else {
                    return opaque(raw);
                };
                out.push(Custom {
                    name: x.name,
                    value,
                });
            }
            Ok(Field::Custom(out))
        }
    }
}

// ------------------------------------------------------------------ merge (spec §7 "Merge")

/// A three-way merge's outcome: clean, or the merged item with the fields both sides changed (the newer side's value kept,
/// the other's recorded in `history`, typed as the field is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merge {
    Clean(Item),
    Conflict(Item, Vec<String>),
}

/// Per field against `base` (the version an edit started from), `type` one of them: a field only one side changed takes that
/// side's value, one both changed alike stays, one both changed differently keeps `ours` (the edit being written is the
/// newer) and records `theirs` in `history` (appended; `Plain(null)` for a field `theirs` removed). Fields neither knows
/// survive; `history` itself merges by union. A secret's losing value stays a `Secret` (rule 25).
pub fn merge(base: &Item, ours: &Item, theirs: &Item) -> Merge {
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
    let item = Item {
        ty,
        fields: out,
        history,
    };
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
            Field::Secret(s) | Field::Opaque(s) => {
                s.with(|b| String::from_utf8(b.to_vec()).unwrap())
            }
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
        let dbg = format!("{it:?}");
        assert!(
            !dbg.contains("https://a") && !dbg.contains("\\u0001") && !dbg.contains('é'),
            "{dbg}"
        );
        assert!(dbg.contains("password") && dbg.contains("Secret"), "{dbg}");
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
}
