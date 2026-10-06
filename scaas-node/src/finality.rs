//! Cổng finality — thuần, không I/O. Odoo chỉ thấy log trong vùng `safe_head` trả về.
use alloy::primitives::B256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `latest - depth`. Chain BFT/Clique một signer: depth 1 (canon §C9).
    Depth(u64),
    /// Tag `finalized` của node. Vắng tag ⇒ đứng chờ, không đoán.
    Tag,
}

pub fn safe_head(mode: &Mode, latest: u64, finalized: Option<u64>) -> Option<u64> {
    match mode {
        Mode::Depth(d) => latest.checked_sub(*d),
        Mode::Tag => finalized.map(|f| f.min(latest)),
    }
}

pub fn next_range(cursor: u64, safe: u64, max_span: u64) -> Option<(u64, u64)> {
    (safe > cursor).then(|| (cursor + 1, safe.min(cursor + max_span)))
}

/// Endpoint chính luôn được đếm; `others` là các endpoint độc lập còn lại.
pub fn quorum_ok(primary: B256, others: &[Option<B256>], quorum: usize) -> bool {
    1 + others.iter().filter(|h| **h == Some(primary)).count() >= quorum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_mode_subtracts_and_saturates() {
        assert_eq!(safe_head(&Mode::Depth(1), 10, None), Some(9));
        assert_eq!(safe_head(&Mode::Depth(20), 10, None), None);
        assert_eq!(safe_head(&Mode::Depth(0), 10, None), Some(10));
    }

    #[test]
    fn tag_mode_waits_without_a_finalized_block() {
        assert_eq!(safe_head(&Mode::Tag, 10, None), None);
        assert_eq!(safe_head(&Mode::Tag, 10, Some(4)), Some(4));
        assert_eq!(safe_head(&Mode::Tag, 3, Some(4)), Some(3)); // never above latest
    }

    #[test]
    fn ranges_are_contiguous_and_bounded() {
        assert_eq!(next_range(0, 5, 1000), Some((1, 5)));
        assert_eq!(next_range(5, 5, 1000), None);
        assert_eq!(next_range(0, 5000, 1000), Some((1, 1000)));
    }

    #[test]
    fn quorum_counts_the_primary() {
        let h = B256::repeat_byte(1);
        let x = B256::repeat_byte(2);
        assert!(quorum_ok(h, &[], 1));
        assert!(quorum_ok(h, &[Some(h)], 2));
        assert!(!quorum_ok(h, &[Some(x)], 2));
        assert!(!quorum_ok(h, &[None], 2));
    }
}
