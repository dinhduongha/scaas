//! Sổ lệnh trong bộ nhớ (ruling R16) và matcher fill-or-kill, FIFO.
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolValue;
use anyhow::{bail, Result};

use crate::abi::MetaTransaction;

/// `bytes4(keccak256("trade(address,uint256,address)"))` = `0x0e32db52`.
pub const OP_TRADE: [u8; 4] = [0x0e, 0x32, 0xdb, 0x52];

#[derive(Debug, Clone)]
pub struct Order {
    pub token: Address,
    pub m: MetaTransaction,
    pub sig: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    pub counter_token: Address,
    pub min_counter: U256,
    pub counterparty: Address,
}

impl Order {
    pub fn terms(&self) -> Result<Terms> {
        let d = &self.m.data;
        if d.len() != 100 || d[..4] != OP_TRADE {
            bail!("not a trade leg");
        }
        let (counter_token, min_counter, counterparty) = <(Address, U256, Address)>::abi_decode(&d[4..])?;
        Ok(Terms { counter_token, min_counter, counterparty })
    }

    fn live(&self, now: u64) -> bool {
        self.m.validUntil >= U256::from(now)
    }
}

fn crosses(a: &Order, ta: &Terms, b: &Order, tb: &Terms) -> bool {
    a.m.from != b.m.from
        && a.token != b.token
        && ta.counter_token == b.token
        && tb.counter_token == a.token
        && b.m.value >= ta.min_counter
        && a.m.value >= tb.min_counter
        && (ta.counterparty == Address::ZERO || ta.counterparty == b.m.from)
        && (tb.counterparty == Address::ZERO || tb.counterparty == a.m.from)
}

#[derive(Debug, Default)]
pub struct Book {
    orders: Vec<(Order, Terms)>,
}

impl Book {
    /// Thêm lệnh; khớp được lệnh đang nghỉ thì trả cặp `(resting, incoming)` và bỏ khỏi sổ.
    pub fn insert(&mut self, order: Order, now: u64) -> Option<(Order, Order)> {
        let terms = order.terms().ok()?;
        if !order.live(now) {
            return None;
        }
        let hit = self.orders.iter().position(|(r, rt)| r.live(now) && crosses(r, rt, &order, &terms));
        match hit {
            Some(i) => Some((self.orders.remove(i).0, order)),
            None => {
                self.orders.push((order, terms));
                None
            }
        }
    }

    pub fn list(&self, sell: Address, buy: Address, now: u64) -> Vec<&Order> {
        self.orders
            .iter()
            .filter(|(o, t)| o.token == sell && t.counter_token == buy && o.live(now))
            .map(|(o, _)| o)
            .collect()
    }

    pub fn purge(&mut self, now: u64) {
        self.orders.retain(|(o, _)| o.live(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metatx::MODE_RESTRICT_RELAYER;

    const A: Address = Address::repeat_byte(0xaa);
    const B: Address = Address::repeat_byte(0xbb);
    const DEX: Address = Address::repeat_byte(0xde);

    fn order(from: u8, sell: Address, value: u64, buy: Address, min: u64, valid_until: u64, cp: Address) -> Order {
        let mut data = OP_TRADE.to_vec();
        data.extend((buy, U256::from(min), cp).abi_encode());
        Order {
            token: sell,
            m: MetaTransaction {
                from: Address::repeat_byte(from),
                to: DEX,
                value: U256::from(value),
                data: data.into(),
                batch: U256::from(from),
                nonce: U256::ZERO,
                validUntil: U256::from(valid_until),
                mode: MODE_RESTRICT_RELAYER,
                relayer: DEX,
                fee: U256::ZERO,
                feeRecipient: Address::ZERO,
            },
            sig: Bytes::new(),
        }
    }

    #[test]
    fn op_trade_constant_is_the_selector() {
        assert_eq!(alloy::primitives::keccak256(b"trade(address,uint256,address)")[..4], OP_TRADE);
    }

    #[test]
    fn terms_decode() {
        let o = order(1, A, 100, B, 50, 99, Address::ZERO);
        let t = o.terms().unwrap();
        assert_eq!((t.counter_token, t.min_counter, t.counterparty), (B, U256::from(50), Address::ZERO));
    }

    #[test]
    fn crossing_orders_match_and_leave_the_book() {
        let mut book = Book::default();
        assert!(book.insert(order(1, A, 100, B, 50, 99, Address::ZERO), 10).is_none());
        let (maker, taker) = book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).unwrap();
        assert_eq!(maker.m.from, Address::repeat_byte(1));
        assert_eq!(taker.m.from, Address::repeat_byte(2));
        assert!(book.list(A, B, 10).is_empty());
    }

    #[test]
    fn non_crossing_orders_rest() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 70, 99, Address::ZERO), 10);
        assert!(book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
        assert_eq!(book.list(A, B, 10).len(), 1);
        assert_eq!(book.list(B, A, 10).len(), 1);
    }

    #[test]
    fn expired_resting_order_is_skipped() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 50, 5, Address::ZERO), 1);
        assert!(book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
        book.purge(10);
        assert!(book.list(A, B, 10).is_empty());
    }

    #[test]
    fn counterparty_is_respected() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 50, 99, Address::repeat_byte(9)), 10);
        assert!(book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
    }

    #[test]
    fn same_party_never_matches_itself() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 50, 99, Address::ZERO), 10);
        assert!(book.insert(order(1, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
    }

    #[test]
    fn non_trade_data_is_not_booked() {
        let mut book = Book::default();
        let mut o = order(1, A, 100, B, 50, 99, Address::ZERO);
        o.m.data = Bytes::from_static(&[1, 2, 3]);
        assert!(book.insert(o, 10).is_none());
        assert!(book.list(A, B, 10).is_empty());
    }
}
