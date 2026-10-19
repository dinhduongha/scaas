//! Proof encoding: postcard's layout (no field names or tags; sequence lengths and enum variants as LEB128 varints),
//! but integers fixed-width big-endian and the format "human readable" for serde, so Plonky3's Goldilocks
//! serializes through `serialize_u64`: every field element is be8(canonical value), the bytes an EVM verifier reads
//! with one shift and hashes as they are (pqzh-solidity-verifier.md §6). Digests ([u8; 32]) are raw bytes.
//! Decoding rejects non-canonical field elements (Goldilocks' Deserialize) and anything malformed; never panics.

use serde::de::{self, DeserializeSeed, IntoDeserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, ser};

#[derive(Debug)]
pub struct Error(String);
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl ser::Error for Error {
    fn custom<T: core::fmt::Display>(m: T) -> Self {
        Error(m.to_string())
    }
}
impl de::Error for Error {
    fn custom<T: core::fmt::Display>(m: T) -> Self {
        Error(m.to_string())
    }
}
type R<T> = Result<T, Error>;
fn err<T>(m: &str) -> R<T> {
    Err(Error(m.into()))
}

pub fn to_vec<T: Serialize + ?Sized>(t: &T) -> R<Vec<u8>> {
    let mut s = Ser(Vec::new());
    t.serialize(&mut s)?;
    Ok(s.0)
}

/// decode one value; returns it and the unread rest
pub fn take_from_bytes<'a, T: Deserialize<'a>>(b: &'a [u8]) -> R<(T, &'a [u8])> {
    let mut d = De(b);
    let t = T::deserialize(&mut d)?;
    Ok((t, d.0))
}

struct Ser(Vec<u8>);

impl Ser {
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.0.push(v as u8 | 0x80);
            v >>= 7;
        }
        self.0.push(v as u8);
    }
}

macro_rules! ser_be {
    ($($f:ident $t:ty),*) => {$(
        fn $f(self, v: $t) -> R<()> {
            self.0.extend_from_slice(&v.to_be_bytes());
            Ok(())
        }
    )*};
}

impl<'a> ser::Serializer for &'a mut Ser {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn is_human_readable(&self) -> bool {
        true
    }
    fn serialize_bool(self, v: bool) -> R<()> {
        self.0.push(v as u8);
        Ok(())
    }
    ser_be!(serialize_i8 i8, serialize_i16 i16, serialize_i32 i32, serialize_i64 i64,
            serialize_u8 u8, serialize_u16 u16, serialize_u32 u32, serialize_u64 u64);
    fn serialize_f32(self, _: f32) -> R<()> {
        err("float")
    }
    fn serialize_f64(self, _: f64) -> R<()> {
        err("float")
    }
    fn serialize_char(self, _: char) -> R<()> {
        err("char")
    }
    fn serialize_str(self, v: &str) -> R<()> {
        self.serialize_bytes(v.as_bytes())
    }
    fn serialize_bytes(self, v: &[u8]) -> R<()> {
        self.varint(v.len() as u64);
        self.0.extend_from_slice(v);
        Ok(())
    }
    fn serialize_none(self) -> R<()> {
        self.0.push(0);
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> R<()> {
        self.0.push(1);
        v.serialize(self)
    }
    fn serialize_unit(self) -> R<()> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> R<()> {
        Ok(())
    }
    fn serialize_unit_variant(self, _: &'static str, i: u32, _: &'static str) -> R<()> {
        self.varint(i as u64);
        Ok(())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _: &'static str, v: &T) -> R<()> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(self, _: &'static str, i: u32, _: &'static str, v: &T) -> R<()> {
        self.varint(i as u64);
        v.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> R<Self> {
        let Some(n) = len else { return err("unknown length") };
        self.varint(n as u64);
        Ok(self)
    }
    fn serialize_tuple(self, _: usize) -> R<Self> {
        Ok(self)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> R<Self> {
        Ok(self)
    }
    fn serialize_tuple_variant(self, _: &'static str, i: u32, _: &'static str, _: usize) -> R<Self> {
        self.varint(i as u64);
        Ok(self)
    }
    fn serialize_map(self, len: Option<usize>) -> R<Self> {
        self.serialize_seq(len)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> R<Self> {
        Ok(self)
    }
    fn serialize_struct_variant(self, _: &'static str, i: u32, _: &'static str, _: usize) -> R<Self> {
        self.varint(i as u64);
        Ok(self)
    }
}

macro_rules! compound {
    ($($tr:ident $f:ident),*) => {$(
        impl<'a> ser::$tr for &'a mut Ser {
            type Ok = ();
            type Error = Error;
            fn $f<T: Serialize + ?Sized>(&mut self, v: &T) -> R<()> {
                v.serialize(&mut **self)
            }
            fn end(self) -> R<()> {
                Ok(())
            }
        }
    )*};
}
compound!(SerializeSeq serialize_element, SerializeTuple serialize_element, SerializeTupleStruct serialize_field,
          SerializeTupleVariant serialize_field);

impl<'a> ser::SerializeMap for &'a mut Ser {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> R<()> {
        k.serialize(&mut **self)
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> R<()> {
        v.serialize(&mut **self)
    }
    fn end(self) -> R<()> {
        Ok(())
    }
}
impl<'a> ser::SerializeStruct for &'a mut Ser {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, _: &'static str, v: &T) -> R<()> {
        v.serialize(&mut **self)
    }
    fn end(self) -> R<()> {
        Ok(())
    }
}
impl<'a> ser::SerializeStructVariant for &'a mut Ser {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, _: &'static str, v: &T) -> R<()> {
        v.serialize(&mut **self)
    }
    fn end(self) -> R<()> {
        Ok(())
    }
}

struct De<'a>(&'a [u8]);

impl<'a> De<'a> {
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if self.0.len() < n {
            return err("truncated");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> R<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn varint(&mut self) -> R<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.take(1)?[0];
            if i == 9 && b > 1 {
                return err("varint overflow");
            }
            v |= ((b & 0x7f) as u64) << (7 * i);
            if b < 0x80 {
                // minimal encodings only (review P-F): a final 0x00 after a continuation byte (`81 00` for `01`)
                // would give a second encoding of the same proof
                if b == 0 && i > 0 {
                    return err("varint not minimal");
                }
                return Ok(v);
            }
        }
        err("varint overflow")
    }
    /// a length that cannot exceed the remaining input (every element takes >= 1 byte except units, unused here)
    fn len(&mut self) -> R<usize> {
        let n = self.varint()?;
        if n > self.0.len() as u64 {
            return err("length");
        }
        Ok(n as usize)
    }
}

macro_rules! de_be {
    ($($f:ident $v:ident $t:ty),*) => {$(
        fn $f<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
            v.$v(<$t>::from_be_bytes(self.arr()?))
        }
    )*};
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut De<'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        true
    }
    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> R<V::Value> {
        err("not self-describing")
    }
    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        match self.take(1)?[0] {
            0 => v.visit_bool(false),
            1 => v.visit_bool(true),
            _ => err("bool"),
        }
    }
    de_be!(deserialize_i8 visit_i8 i8, deserialize_i16 visit_i16 i16, deserialize_i32 visit_i32 i32,
           deserialize_i64 visit_i64 i64, deserialize_u8 visit_u8 u8, deserialize_u16 visit_u16 u16,
           deserialize_u32 visit_u32 u32, deserialize_u64 visit_u64 u64);
    fn deserialize_f32<V: Visitor<'de>>(self, _: V) -> R<V::Value> {
        err("float")
    }
    fn deserialize_f64<V: Visitor<'de>>(self, _: V) -> R<V::Value> {
        err("float")
    }
    fn deserialize_char<V: Visitor<'de>>(self, _: V) -> R<V::Value> {
        err("char")
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        let n = self.len()?;
        v.visit_borrowed_str(core::str::from_utf8(self.take(n)?).map_err(|_| Error("utf8".into()))?)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        self.deserialize_str(v)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        let n = self.len()?;
        v.visit_borrowed_bytes(self.take(n)?)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        self.deserialize_bytes(v)
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        match self.take(1)?[0] {
            0 => v.visit_none(),
            1 => v.visit_some(self),
            _ => err("option"),
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        v.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(self, _: &'static str, v: V) -> R<V::Value> {
        v.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _: &'static str, v: V) -> R<V::Value> {
        v.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        let n = self.len()?;
        v.visit_seq(Seq(self, n))
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, n: usize, v: V) -> R<V::Value> {
        v.visit_seq(Seq(self, n))
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(self, _: &'static str, n: usize, v: V) -> R<V::Value> {
        v.visit_seq(Seq(self, n))
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> R<V::Value> {
        let n = self.len()?;
        v.visit_map(Seq(self, n))
    }
    fn deserialize_struct<V: Visitor<'de>>(self, _: &'static str, f: &'static [&'static str], v: V) -> R<V::Value> {
        v.visit_seq(Seq(self, f.len()))
    }
    fn deserialize_enum<V: Visitor<'de>>(self, _: &'static str, _: &'static [&'static str], v: V) -> R<V::Value> {
        v.visit_enum(self)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, _: V) -> R<V::Value> {
        err("identifier")
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _: V) -> R<V::Value> {
        err("ignored")
    }
}

struct Seq<'a, 'de>(&'a mut De<'de>, usize);

impl<'de, 'a> SeqAccess<'de> for Seq<'a, 'de> {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, s: T) -> R<Option<T::Value>> {
        if self.1 == 0 {
            return Ok(None);
        }
        self.1 -= 1;
        s.deserialize(&mut *self.0).map(Some)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.1)
    }
}

impl<'de, 'a> de::MapAccess<'de> for Seq<'a, 'de> {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, s: K) -> R<Option<K::Value>> {
        self.next_element_seed(s)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, s: V) -> R<V::Value> {
        s.deserialize(&mut *self.0)
    }
}

impl<'de, 'a> de::EnumAccess<'de> for &'a mut De<'de> {
    type Error = Error;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, s: V) -> R<(V::Value, Self)> {
        let i = self.varint()?;
        let i: u32 = i.try_into().map_err(|_| Error("variant".into()))?;
        Ok((s.deserialize(i.into_deserializer())?, self))
    }
}

impl<'de, 'a> de::VariantAccess<'de> for &'a mut De<'de> {
    type Error = Error;
    fn unit_variant(self) -> R<()> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, s: T) -> R<T::Value> {
        s.deserialize(self)
    }
    fn tuple_variant<V: Visitor<'de>>(self, n: usize, v: V) -> R<V::Value> {
        v.visit_seq(Seq(self, n))
    }
    fn struct_variant<V: Visitor<'de>>(self, f: &'static [&'static str], v: V) -> R<V::Value> {
        v.visit_seq(Seq(self, f.len()))
    }
}

#[cfg(test)]
mod tests {
    use crate::ring::F;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn field_elements_big_endian_and_canonical() {
        let x = F::from_u64(0x0102030405060708);
        let b = super::to_vec(&(x, vec![x], [7u8; 3])).unwrap();
        assert_eq!(b, [1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 7]);
        let (y, rest): (F, _) = super::take_from_bytes(&b).unwrap();
        assert_eq!((y, rest.len()), (x, 12));
        // p itself is not a canonical encoding
        assert!(super::take_from_bytes::<F>(&0xFFFF_FFFF_0000_0001u64.to_be_bytes()).is_err());
        assert!(super::take_from_bytes::<Vec<F>>(&[200, 1]).is_err()); // length beyond the input
    }

    /// review P-F: one encoding per value; the overlong `81 00` for the length `01` is rejected
    #[test]
    fn varints_minimal() {
        let b = super::to_vec(&vec![7u8]).unwrap();
        assert_eq!(b, [1, 7]);
        assert_eq!(super::take_from_bytes::<Vec<u8>>(&b).unwrap().0, [7]);
        assert!(super::take_from_bytes::<Vec<u8>>(&[0x81, 0x00, 7]).is_err());
        assert!(super::take_from_bytes::<Vec<u8>>(&[0x80, 0x80, 0x00]).is_err());
        let big = vec![0u8; 300]; // a two-byte length, AC 02
        let e = super::to_vec(&big).unwrap();
        assert_eq!(&e[..2], [0xac, 0x02]);
        assert_eq!(super::take_from_bytes::<Vec<u8>>(&e).unwrap().0.len(), 300);
        assert!(super::take_from_bytes::<Vec<u8>>(&[[0xac, 0x82, 0x00].as_slice(), &big].concat()).is_err());
    }
}
