// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Display text the user reads (owner 2026-11-18, Q2): a control character or a format character (Unicode category `Cf`: the
//! bidirectional marks and overrides U+200E/200F, U+202A–202E, U+2066–2069, the zero-widths, the tags …) can make one name look
//! like another. One rule for every name: an account name and a seed label refuse them (owner 2026-11-19, ruling E), an unlisted
//! token's name has them stripped (spec §8.2).

/// Category `Cf` of Unicode 16.0 (`DerivedGeneralCategory.txt`), as ranges.
// ponytail: a fixed table; a later Unicode version adding a `Cf` code point needs a row here
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

/// A control character or a format (`Cf`) character.
pub(crate) fn hidden(c: char) -> bool {
    let u = u32::from(c);
    c.is_control() || CF.iter().any(|(lo, hi)| (*lo..=*hi).contains(&u))
}

/// `b` as `0x` + lowercase hex.
#[cfg_attr(not(any(feature = "account", feature = "wallet")), allow(dead_code))]
pub(crate) fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// `0x` + an even number of hex digits as its bytes, else `Argument`.
#[cfg_attr(not(any(feature = "account", feature = "wallet")), allow(dead_code))]
pub(crate) fn unhex(s: &str) -> Result<Vec<u8>, crate::SdkError> {
    let h = s.strip_prefix("0x").ok_or(crate::SdkError::Argument)?;
    if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(crate::SdkError::Argument);
    }
    (0..h.len())
        .step_by(2)
        .map(|i| {
            h.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or(crate::SdkError::Argument)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn bidi_and_format_characters_are_hidden() {
        for c in [
            '\u{200E}',
            '\u{200F}',
            '\u{202A}',
            '\u{202E}',
            '\u{2066}',
            '\u{2069}',
            '\u{200B}',
            '\u{FEFF}',
            '\u{E0041}',
            '\u{7}',
        ] {
            assert!(super::hidden(c), "{:#x}", u32::from(c));
        }
        // control: letters, a combining mark, a space, an emoji, CJK
        for c in ['a', 'ü', '\u{0301}', ' ', '\u{1F600}', '中'] {
            assert!(!super::hidden(c), "{:#x}", u32::from(c));
        }
    }
}
