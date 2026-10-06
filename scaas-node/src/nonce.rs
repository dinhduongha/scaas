//! Cold start (`_USER-DECISIONS` §23.1 + ruling R18). Thuần: đầu vào là con số của chain
//! và journal của Odoo, đầu ra là việc phải làm.

#[derive(Debug, Clone)]
pub struct Inflight {
    pub job_id: i64,
    /// `None` khi job đã claim mà chưa ký (chưa có nonce vỏ).
    pub nonce: Option<u64>,
    pub state: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub next: u64,
    /// Nonce journal đã ghi mà chain không thấy (không trong block, không trong mempool).
    pub gap_fill: Vec<u64>,
    /// Job phải về `queued`: chưa ký, hoặc nonce của nó vừa bị lấp.
    pub requeue: Vec<i64>,
    /// Job đã ký với nonce < pending: tx có thật (block hoặc mempool) — theo dõi, KHÔNG ký lại.
    pub track: Vec<i64>,
}

pub fn plan(pending: u64, journal_max: Option<u64>, inflight: &[Inflight]) -> Plan {
    let next = journal_max.map_or(pending, |j| pending.max(j + 1));
    let mut p = Plan { next, gap_fill: (pending..next).collect(), ..Default::default() };
    for job in inflight {
        match job.nonce {
            Some(n) if job.state != "nonce_leased" && n < pending => p.track.push(job.job_id),
            _ => p.requeue.push(job.job_id),
        }
    }
    p
}

/// +25 % (SRS tích hợp §5.4), tối thiểu +1 wei, không vượt trần.
pub fn bump(fee: u128, cap: u128) -> u128 {
    (fee + fee / 4).max(fee + 1).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(id: i64, nonce: Option<u64>, state: &str) -> Inflight {
        Inflight { job_id: id, nonce, state: state.into() }
    }

    #[test]
    fn clean_start_uses_pending() {
        let p = plan(5, None, &[]);
        assert_eq!((p.next, p.gap_fill.len()), (5, 0));
    }

    #[test]
    fn journal_ahead_of_pending_is_gap_filled_and_requeued() {
        let p = plan(5, Some(7), &[j(1, Some(5), "broadcast"), j(2, Some(6), "signed"), j(3, Some(7), "broadcast")]);
        assert_eq!(p.next, 8);
        assert_eq!(p.gap_fill, vec![5, 6, 7]);
        assert_eq!(p.requeue, vec![1, 2, 3]);
    }

    #[test]
    fn jobs_below_pending_are_tracked_not_resent() {
        let p = plan(5, Some(4), &[j(1, Some(4), "broadcast"), j(9, None, "nonce_leased")]);
        assert_eq!(p.next, 5);
        assert_eq!(p.track, vec![1]);
        assert_eq!(p.requeue, vec![9]);
    }

    #[test]
    fn bump_is_a_quarter_and_capped() {
        assert_eq!(bump(100, 1_000), 125);
        assert_eq!(bump(900, 1_000), 1_000);
        assert_eq!(bump(0, 1_000), 1);
    }
}
