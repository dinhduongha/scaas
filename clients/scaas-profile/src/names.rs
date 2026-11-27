// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The profile id and the name helpers (spec §4, §6; plan pinned format 10): a UUIDv7 as `uuid` 1's
//! `Builder::from_unix_timestamp_millis` builds it, 10 random bytes from the OS RNG; `name_key` (NFKC, then Unicode lower case),
//! the one comparison key of a name; `check_name` (NFC, 1 to 64 bytes, no `Cc` or `Cf` character). Rows:
//! smartcontracts/vectors/profile/ids.json.
use crate::Error;
use unicode_normalization::UnicodeNormalization;

/// The UUIDv7 of `ms` and `random`, canonical lower-case 36-character form.
pub fn uuid7(ms: u64, random: &[u8; 10]) -> String {
    uuid::Builder::from_unix_timestamp_millis(ms, random)
        .into_uuid()
        .hyphenated()
        .to_string()
}

/// A new profile id: now, and 10 bytes of the OS RNG.
pub(crate) fn new_id() -> Result<String, Error> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::VaultIo)?
        .as_millis();
    Ok(uuid7(
        u64::try_from(ms).map_err(|_| Error::VaultIo)?,
        &random()?,
    ))
}

/// `N` bytes of the OS RNG (getrandom, as the SDK's `uuid4` and `scaas-ua`'s `OsRng` draw).
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| Error::VaultIo)?;
    Ok(b)
}

/// Whether `s` is a UUID in its canonical lower-case form (a profile directory's name).
pub fn is_id(s: &str) -> bool {
    uuid::Uuid::try_parse(s).is_ok_and(|u| u.hyphenated().to_string() == s)
}

/// The comparison key of a name: NFKC, then Unicode lower case (`str::to_lowercase`).
pub fn name_key(s: &str) -> String {
    s.nfkc().collect::<String>().to_lowercase()
}

/// Whether two names have one `name_key`, compared in constant time over the longer length (each padded with zeros).
pub fn same_name(a: &str, b: &str) -> bool {
    let (a, b) = (name_key(a), name_key(b));
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let n = a.len().max(b.len());
    let diff = (0..n).fold(u8::from(a.len() != b.len()), |d, i| {
        d | (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0))
    });
    diff == 0
}

/// A name as stored: its NFC, 1 to 64 UTF-8 bytes, no control or format character; else `ProfileNameInvalid`.
pub fn check_name(s: &str) -> Result<String, Error> {
    let n: String = s.nfc().collect();
    if n.is_empty() || n.len() > 64 || n.chars().any(hidden) {
        return Err(Error::ProfileNameInvalid);
    }
    Ok(n)
}

/// Category `Cf` of Unicode 16.0 (`DerivedGeneralCategory.txt`), as ranges: the SDK's `text.rs` table (this crate depends on
/// no part of the SDK).
// ponytail: a fixed table; a later Unicode version adding a `Cf` code point needs a row here and in the SDK's
const CF: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

fn hidden(c: char) -> bool {
    let u = u32::from(c);
    c.is_control() || CF.iter().any(|(lo, hi)| (*lo..=*hi).contains(&u))
}
