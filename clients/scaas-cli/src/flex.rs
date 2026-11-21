// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Named flags into the SDK's own types: a flag value is text, read as the field's type asks (a number, a bool, a string, a
//! `0x` hex byte string); `{…}` / `[…]` values are JSON. Unknown fields are the SDK types' own `deny_unknown_fields`. The
//! probe lists a type's fields (the command list) without a value.
use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde_json::{Map, Value};

pub type Error = serde_json::Error;

fn err(m: impl std::fmt::Display) -> Error {
    de::Error::custom(m)
}

/// A value from the command line.
pub struct Flex(pub Value);

macro_rules! num {
    ($($f:ident $v:ident $t:ty),*) => {$(
        fn $f<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
            match self.0 {
                Value::String(s) => v.$v(s.trim().parse::<$t>().map_err(|_| err(format!("not a number: {}", short(&s))))?),
                o => o.$f(v),
            }
        }
    )*};
}

/// At most 64 characters of a value in an error.
pub fn short(s: &str) -> String {
    s.chars().take(64).collect()
}

impl<'de> Deserializer<'de> for Flex {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Object(m) => v.visit_map(FlexMap(m.into_iter(), None)),
            Value::Array(a) => v.visit_seq(FlexSeq(a.into_iter())),
            o => o.deserialize_any(v),
        }
    }
    num!(deserialize_u8 visit_u8 u8, deserialize_u16 visit_u16 u16, deserialize_u32 visit_u32 u32,
        deserialize_u64 visit_u64 u64, deserialize_i8 visit_i8 i8, deserialize_i16 visit_i16 i16,
        deserialize_i32 visit_i32 i32, deserialize_i64 visit_i64 i64, deserialize_f64 visit_f64 f64,
        deserialize_f32 visit_f32 f32, deserialize_bool visit_bool bool);
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => v.visit_none(),
            o => v.visit_some(Flex(o)),
        }
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Array(a) => v.visit_seq(FlexSeq(a.into_iter())),
            Value::String(s) if s.starts_with("0x") => v.visit_seq(HexSeq(s, None)),
            o @ Value::String(_) => v.visit_seq(FlexSeq(vec![o].into_iter())),
            o => o.deserialize_seq(v),
        }
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, _n: usize, v: V) -> Result<V::Value, Error> {
        self.deserialize_seq(v)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _n: usize,
        v: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(v)
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Object(m) => v.visit_map(FlexMap(m.into_iter(), None)),
            o => o.deserialize_map(v),
        }
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(v)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Value::String(s) => v.visit_enum(s.into_deserializer()),
            Value::Object(m) if m.len() == 1 => {
                let Some((k, x)) = m.into_iter().next() else {
                    return Err(err("an enum value"));
                };
                v.visit_enum(FlexEnum(k, x))
            }
            _ => Err(err("an enum value: a variant name or {\"Variant\": …}")),
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, Error> {
        v.visit_newtype_struct(self)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.0.deserialize_string(v)
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.0.deserialize_string(v)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.0.deserialize_string(v)
    }
    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match self.0 {
            // `--confirm` alone, or `{}`: a unit or an empty marker
            Value::String(s) if s == "true" => v.visit_unit(),
            o => o.deserialize_unit(v),
        }
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_unit(v)
    }
    serde::forward_to_deserialize_any! { char bytes byte_buf ignored_any i128 u128 }
}

struct FlexSeq(std::vec::IntoIter<Value>);
impl<'de> SeqAccess<'de> for FlexSeq {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.0.next().map(|x| seed.deserialize(Flex(x))).transpose()
    }
}

/// `0x…` where a list is asked: bytes when its items are bytes, refused otherwise (a list of strings takes `[…]`).
struct HexSeq(String, Option<std::vec::IntoIter<u8>>);
impl<'de> SeqAccess<'de> for HexSeq {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.1.is_none() {
            self.1 = Some(hex(&self.0)?.into_iter());
            // the first item says what the list holds: only a byte list takes `0x`
            return match self.1.as_mut().and_then(Iterator::next) {
                Some(b) => seed.deserialize(Byte(b)).map(Some),
                None => Ok(None),
            };
        }
        match self.1.as_mut().and_then(Iterator::next) {
            Some(b) => seed.deserialize(Byte(b)).map(Some),
            None => Ok(None),
        }
    }
}

/// One byte of a `0x` value: a `u8` only.
struct Byte(u8);
impl<'de> Deserializer<'de> for Byte {
    type Error = Error;
    fn deserialize_u8<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_u8(self.0)
    }
    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(err("a 0x value is bytes; this list takes a JSON array"))
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf option unit unit_struct
        newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

/// `0x` + an even number of hex digits.
pub fn hex(s: &str) -> Result<Vec<u8>, Error> {
    let h = s.strip_prefix("0x").ok_or_else(|| err("a 0x hex value"))?;
    if h.len() % 2 != 0 {
        return Err(err("an even number of hex digits"));
    }
    (0..h.len())
        .step_by(2)
        .map(|i| {
            h.get(i..i + 2)
                .and_then(|d| u8::from_str_radix(d, 16).ok())
                .ok_or_else(|| err("hex digits"))
        })
        .collect()
}

struct FlexMap(serde_json::map::IntoIter, Option<Value>);
impl<'de> MapAccess<'de> for FlexMap {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.0.next() {
            Some((k, v)) => {
                self.1 = Some(v);
                seed.deserialize(Value::String(k)).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(Flex(self.1.take().unwrap_or(Value::Null)))
    }
}

struct FlexEnum(String, Value);
impl<'de> EnumAccess<'de> for FlexEnum {
    type Error = Error;
    type Variant = Flex;
    fn variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<(T::Value, Flex), Error> {
        Ok((seed.deserialize(Value::String(self.0))?, Flex(self.1)))
    }
}
impl<'de> VariantAccess<'de> for Flex {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }
    fn tuple_variant<V: Visitor<'de>>(self, _n: usize, v: V) -> Result<V::Value, Error> {
        self.deserialize_seq(v)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(v)
    }
}

/// The flags as JSON, and the `-fd` flags as (secret name, descriptor).
pub type Flags = (Map<String, Value>, Vec<(String, String)>);

/// The command line's flags as one JSON object: `--a.b x` nests, a repeated flag is a list, `{…}` / `[…]` values are JSON,
/// a flag without a value is `true`. `-fd` flags are kept apart (secrets come only by descriptor).
pub fn flags(words: &[String]) -> Result<Flags, Error> {
    let mut out = Map::new();
    let mut fds = vec![];
    let mut i = 0;
    while let Some(w) = words.get(i) {
        let name = w
            .strip_prefix("--")
            .filter(|n| !n.is_empty())
            .ok_or_else(|| err(format!("a --flag, not {}", short(w))))?;
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (name, None),
        };
        let value = match inline {
            Some(v) => v,
            None => match words.get(i + 1) {
                Some(v) if !v.starts_with("--") => {
                    i += 1;
                    v.clone()
                }
                _ => "true".into(),
            },
        };
        i += 1;
        if let Some(base) = name.strip_suffix("-fd") {
            fds.push((base.to_string(), value));
            continue;
        }
        let v = if value.starts_with('{') || value.starts_with('[') {
            serde_json::from_str(&value)?
        } else {
            Value::String(value)
        };
        let path: Vec<String> = name.split('.').map(|p| p.replace('-', "_")).collect();
        put(&mut out, &path, v)?;
    }
    Ok((out, fds))
}

fn put(m: &mut Map<String, Value>, path: &[String], v: Value) -> Result<(), Error> {
    let Some((first, rest)) = path.split_first() else {
        return Err(err("a flag name"));
    };
    if rest.is_empty() {
        match m.remove(first) {
            None => {
                m.insert(first.clone(), v);
            }
            Some(Value::Array(mut a)) => {
                a.push(v);
                m.insert(first.clone(), Value::Array(a));
            }
            Some(old) => {
                m.insert(first.clone(), Value::Array(vec![old, v]));
            }
        }
        return Ok(());
    }
    let e = m
        .entry(first.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    match e {
        Value::Object(inner) => put(inner, rest, v),
        _ => Err(err(format!("--{first} is both a value and a group"))),
    }
}

/// The field names of `T` (a struct's fields, an enum's variants), for the command list.
pub fn fields<'de, T: serde::Deserialize<'de>>() -> Vec<&'static str> {
    let mut out = vec![];
    let _ = T::deserialize(Probe(&mut out));
    out
}

struct Probe<'a>(&'a mut Vec<&'static str>);
impl<'de> Deserializer<'de> for Probe<'_> {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(err("probe"))
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        f: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Error> {
        self.0.extend_from_slice(f);
        Err(err("probe"))
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        f: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Error> {
        self.0.extend_from_slice(f);
        Err(err("probe"))
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf option unit unit_struct
        newtype_struct seq tuple tuple_struct map identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use serde::Deserialize;

    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct A {
        n: u64,
        s: String,
        b: bool,
        bytes: Vec<u8>,
        list: Vec<String>,
        o: Option<u32>,
        e: E,
    }
    #[derive(serde::Deserialize, Debug, PartialEq)]
    enum E {
        Unit,
        Named { x: u8 },
    }

    fn take(w: &[&str]) -> Result<A, Error> {
        let w: Vec<String> = w.iter().map(|s| s.to_string()).collect();
        A::deserialize(Flex(Value::Object(flags(&w)?.0)))
    }

    #[test]
    fn flags_read_as_the_field_asks() {
        let a = take(&[
            "--n",
            "7",
            "--s",
            "007",
            "--b",
            "--bytes",
            "0x0aff",
            "--list",
            "x",
            "--e.Named.x",
            "3",
        ])
        .unwrap();
        assert_eq!(
            a,
            A {
                n: 7,
                s: "007".into(),
                b: true,
                bytes: vec![10, 255],
                list: vec!["x".into()],
                o: None,
                e: E::Named { x: 3 }
            }
        );
        let a = take(&[
            "--n=1", "--s", "x", "--b", "false", "--bytes", "[1]", "--list", "a", "--list", "b",
            "--o", "2", "--e", "Unit",
        ])
        .unwrap();
        assert_eq!(
            (a.b, a.bytes, a.list.len(), a.o, a.e),
            (false, vec![1], 2, Some(2), E::Unit)
        );
    }

    #[test]
    fn unknown_flags_and_bad_values_refused() {
        let ok = [
            "--n", "1", "--s", "x", "--b", "--bytes", "0x", "--list", "x", "--e", "Unit",
        ];
        assert!(take(&ok).is_ok());
        let mut extra = ok.to_vec();
        extra.extend(["--other", "1"]);
        assert!(take(&extra).is_err());
        let mut bad = ok.to_vec();
        bad[1] = "x1";
        assert!(take(&bad).is_err());
        let mut odd = ok.to_vec();
        odd[6] = "0xabc";
        assert!(take(&odd).is_err());
        // a 0x value where a list of strings is asked
        let mut hexlist = ok.to_vec();
        hexlist[8] = "0x00";
        assert!(take(&hexlist).is_err());
    }

    #[test]
    fn fd_flags_kept_apart_and_fields_listed() {
        let w: Vec<String> = ["--vault-passphrase-fd", "3", "--label", "x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (m, fds) = flags(&w).unwrap();
        assert_eq!(fds, vec![("vault-passphrase".to_string(), "3".to_string())]);
        assert!(m.contains_key("label") && m.len() == 1);
        assert_eq!(
            fields::<A>(),
            vec!["n", "s", "b", "bytes", "list", "o", "e"]
        );
    }
}
