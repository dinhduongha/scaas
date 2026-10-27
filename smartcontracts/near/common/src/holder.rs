//! `Holder` (spec §2 row 1, plan ruling R5): who holds a balance in a SCaaS NEAR token. Borsh enum, variant 0
//! `Near(AccountId)` (a native NEAR account, NEP-141 ledger), variant 1 `Ua([u8; 32])` (a UA id, the UA ledger).
use near_sdk::{near, AccountId};
use std::fmt;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Holder {
    Near(AccountId),
    Ua([u8; 32]),
}

/// Event / log form: the account id, or `0x` ‖ 64 lower-case hex for a UA id (never a NEAR account id: an
/// ETH-implicit id is `0x` ‖ 40 hex).
impl fmt::Display for Holder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Holder::Near(a) => f.write_str(a.as_str()),
            Holder::Ua(id) => {
                f.write_str("0x")?;
                id.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Holder;

    #[test]
    fn borsh_and_display_match_the_vectors() {
        let n = Holder::Near("alice.test.near".parse().unwrap());
        let enc = near_sdk::borsh::to_vec(&n).unwrap();
        assert_eq!(enc, [&[0u8, 15, 0, 0, 0][..], b"alice.test.near"].concat()); // gen_vectors.py `holder`
        assert_eq!(near_sdk::borsh::to_vec(&Holder::Ua([0xab; 32])).unwrap(), [&[1u8][..], &[0xab; 32]].concat());
        assert_eq!(n.to_string(), "alice.test.near");
        assert_eq!(Holder::Ua([0xab; 32]).to_string(), format!("0x{}", "ab".repeat(32)));
    }
}
