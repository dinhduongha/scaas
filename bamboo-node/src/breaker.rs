//! Cầu dao gas (R55, GA 2.2#4) — một bộ mỗi lane, trong bộ nhớ (đặt lại khi khởi động). Thuần, không I/O:
//! runner nạp mẫu (base fee, số dư, phí đã trả) và hỏi `open()` trước khi nhận việc MỚI. Cầu dao không bao
//! giờ chặn indexing hay việc theo dõi/thay thế tx đã ký (SRS A§6.8) — runner chỉ hỏi ở cửa nhận việc.
use std::collections::VecDeque;

use tracing::warn;

use crate::config::BreakerCfg;

const HOUR: u64 = 3600;
/// Trung bình trượt cần ít mẫu này trước khi cầu dao spike có thể nhảy (vừa khởi động thì chưa biết "bình thường").
const MIN_SAMPLES: usize = 4;

pub const NAMES: [&str; 3] = ["base_fee_spike", "gas_budget", "balance_floor"];

#[derive(Debug)]
pub struct Breaker {
    cfg: BreakerCfg,
    fees: VecDeque<(u64, u128)>,
    spiking: bool,
    window: u64,
    spent: u128,
    budget_warned: bool,
    balance: Option<u128>,
}

impl Breaker {
    pub fn new(cfg: BreakerCfg) -> Self {
        Self { cfg, fees: VecDeque::new(), spiking: false, window: 0, spent: 0, budget_warned: false, balance: None }
    }

    /// Mẫu `baseFeePerGas` (EVM). So với trung bình 1 h của các mẫu TRƯỚC nó.
    pub fn base_fee(&mut self, now: u64, fee: u128) {
        while self.fees.front().is_some_and(|(t, _)| t + HOUR < now) {
            self.fees.pop_front();
        }
        let n = self.fees.len();
        self.spiking = self.cfg.spike_ratio > 0.0 && n >= MIN_SAMPLES && {
            let avg = self.fees.iter().map(|(_, f)| *f as f64).sum::<f64>() / n as f64;
            fee as f64 > self.cfg.spike_ratio * avg
        };
        self.fees.push_back((now, fee));
    }

    fn roll(&mut self, now: u64) {
        let w = now - now % HOUR;
        if w != self.window {
            self.window = w;
            self.spent = 0;
            self.budget_warned = false;
        }
    }

    /// Phí thực trả của một tx đã vào khối (gas_used × effective_gas_price), cửa sổ giờ cố định.
    pub fn spend(&mut self, now: u64, amount: u128) {
        self.roll(now);
        self.spent = self.spent.saturating_add(amount);
        if let Some(b) = self.cfg.gas_budget_per_hour {
            if !self.budget_warned && self.spent.saturating_mul(10) >= b.saturating_mul(9) {
                self.budget_warned = true;
                warn!(spent = %self.spent, budget = %b, "gas budget of this hour at 90 %");
            }
        }
    }

    /// Số dư coin gas của lane. Dưới 120 % sàn ⇒ cảnh báo (R1-1); dưới sàn ⇒ lane ngưng nhận việc.
    pub fn balance(&mut self, balance: u128) {
        self.balance = Some(balance);
        if let Some(floor) = self.cfg.min_relayer_balance {
            if balance >= floor && balance.saturating_mul(5) < floor.saturating_mul(6) {
                warn!(%balance, %floor, "relayer balance within 20 % of the floor: top up");
            }
        }
    }

    pub fn last_balance(&self) -> Option<u128> {
        self.balance
    }

    /// Trạng thái từng cầu dao theo thứ tự `NAMES`.
    pub fn states(&mut self, now: u64) -> [bool; 3] {
        self.roll(now);
        let budget = self.cfg.gas_budget_per_hour.is_some_and(|b| self.spent >= b);
        let floor = match (self.cfg.min_relayer_balance, self.balance) {
            (Some(f), Some(b)) => b < f,
            _ => false,
        };
        [self.spiking, budget, floor]
    }

    /// Tên cầu dao đầu tiên đang mở, hoặc `None` = được nhận việc mới.
    pub fn open(&mut self, now: u64) -> Option<&'static str> {
        self.states(now).iter().zip(NAMES).find(|(on, _)| **on).map(|(_, n)| n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(spike: f64, budget: Option<u128>, floor: Option<u128>) -> Breaker {
        Breaker::new(BreakerCfg { spike_ratio: spike, gas_budget_per_hour: budget, min_relayer_balance: floor })
    }

    #[test]
    fn spike_trips_against_the_hour_average_and_clears() {
        let mut k = b(3.0, None, None);
        let t = 7200;
        k.base_fee(t, 1000);
        assert_eq!(k.open(t), None, "no history yet");
        for i in 1..4 {
            k.base_fee(t + i, 100);
        }
        // avg of 4 samples = 325; 1000 > 3 × 325 but 900 is not
        k.base_fee(t + 10, 900);
        assert_eq!(k.open(t + 10), None);
        k.base_fee(t + 11, 5000);
        assert_eq!(k.open(t + 11), Some("base_fee_spike"));
        k.base_fee(t + 12, 300);
        assert_eq!(k.open(t + 12), None, "back under the ratio");
        // samples older than an hour drop out of the average
        let mut k = b(3.0, None, None);
        for i in 0..4 {
            k.base_fee(i, 10_000);
        }
        for i in 0..4 {
            k.base_fee(HOUR + 100 + i, 10);
        }
        k.base_fee(HOUR + 200, 100);
        assert_eq!(k.open(HOUR + 200), Some("base_fee_spike"));
        let mut off = b(0.0, None, None);
        for i in 0..5 {
            off.base_fee(i, 1);
        }
        off.base_fee(9, 1_000_000);
        assert_eq!(off.open(9), None, "ratio 0 disables");
    }

    #[test]
    fn hourly_budget_warns_trips_and_rolls() {
        let mut k = b(0.0, Some(1000), None);
        let t = 10 * HOUR + 5;
        k.spend(t, 850);
        assert!(!k.budget_warned);
        k.spend(t + 1, 60);
        assert!(k.budget_warned, "90 %");
        assert_eq!(k.open(t + 2), None);
        k.spend(t + 3, 90);
        assert_eq!(k.open(t + 4), Some("gas_budget"));
        assert_eq!(k.open(11 * HOUR), None, "next window");
        assert!(!k.states(11 * HOUR)[1]);
    }

    #[test]
    fn balance_floor_per_lane() {
        let mut k = b(0.0, None, Some(1000));
        assert_eq!(k.open(1), None, "unknown balance does not trip");
        k.balance(1100);
        assert_eq!(k.open(1), None);
        k.balance(999);
        assert_eq!(k.open(1), Some("balance_floor"));
        assert_eq!(k.last_balance(), Some(999));
        k.balance(5000);
        assert_eq!(k.open(1), None);
    }
}
