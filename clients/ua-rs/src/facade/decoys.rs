// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Decoy selection for PQZ op 7 and classical Zether multi-recipient transfers (CTR-UA-29, owner 2026-11-07; ua-rs-sign T15n):
//! a pure, I/O-free pick of `count` (= `M − 1`) decoys from a candidate list the reading layer supplies. No key is used.
//!
//! The candidates are the UAs of the token's per-kind list in the registry (`0x0142` for PQZ, `0x0141` for classical Zether)
//! up to the wallet's last sync point, read by the reading layer (`pqz-read --command decoys`, `zether-read-balance
//! --decoy-count`). **Default (owner 2026-11-07): uniform** over the candidates that are not excluded. **Option:** the
//! reading layer's token-activity filter supplies `weights` (recent activity in the token, a recency weight); the pick is
//! then weighted. The trade-off of the default, stated to the holder: registration is permissionless, so an observer can
//! register UAs of the kind and recognise its own decoys in a ring (threat S30); the filter raises that to gas-level cost only.
//!
//! Request `{candidates, exclude, count, weights?}` (named fields; the facades' command `pickDecoys`): `candidates` and
//! `exclude` arrays of 32-byte `0x` hex UAs (the sender and every real recipient in `exclude`), `count` a `u64`, `weights`
//! (optional) one `u64` per candidate (0: never picked). Answer `{decoys}`: `count` distinct candidates, never an excluded
//! one, in drawn order, each draw by the OS CSPRNG: sequential sampling without replacement, a candidate drawn with
//! probability weight / remaining total (all weights 1 without `weights`: a uniform subset in uniform order); every index by
//! rejection sampling (no modulo bias). `Argument` for a field not on the list, a missing one, a UA not 32 bytes, a
//! candidate given twice, `weights` of another length, or fewer eligible candidates (not excluded, weight > 0) than `count`.
//! The request is read by the bounded reader ([`MAX`] bytes, about 55,000 candidates). UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

use crate::wallet::{bounded, from_hex, to_hex, Error, Result};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};

/// The request's caps: 4 MiB (the PQZ facade's `CMD_MAX`), depth 2.
pub const MAX: usize = 4 << 20;
const DEPTH: usize = 2;

type Ua = [u8; 32];

fn uas(v: Option<&Value>) -> Result<Vec<Ua>> {
    v.and_then(Value::as_array)
        .ok_or(Error::Argument)?
        .iter()
        .map(|x| x.as_str().and_then(from_hex).and_then(|b| b.try_into().ok()).ok_or(Error::Argument))
        .collect()
}

/// A `pickDecoys` request, its named fields parsed (module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    candidates: Vec<Ua>,
    exclude: Vec<Ua>,
    count: u64,
    weights: Option<Vec<u64>>,
}

impl Request {
    /// The request's fields, each on the list and of its type, else `Argument`.
    pub fn from_map(o: &Map<String, Value>) -> Result<Request> {
        if !o.keys().all(|k| ["candidates", "exclude", "count", "weights"].contains(&k.as_str())) {
            return Err(Error::Argument);
        }
        let weights = match o.get("weights") {
            None => None,
            Some(w) => Some(w.as_array().ok_or(Error::Argument)?.iter().map(|x| x.as_u64().ok_or(Error::Argument)).collect::<Result<_>>()?),
        };
        let count = o.get("count").and_then(Value::as_u64).ok_or(Error::Argument)?;
        Ok(Request { candidates: uas(o.get("candidates"))?, exclude: uas(o.get("exclude"))?, count, weights })
    }

    /// `{decoys}`, drawn by the OS CSPRNG.
    pub fn pick(&self) -> Result<String> {
        let d = pick(&self.candidates, &self.exclude, self.count, self.weights.as_deref(), &mut OsRng)?;
        Ok(json!({"decoys": d.iter().map(|u| to_hex(u)).collect::<Vec<_>>()}).to_string())
    }
}

/// A uniform integer in `[0, n)`, `n > 0`, by rejection sampling; `Rng` when the generator fails.
fn below(rng: &mut impl RngCore, n: u128) -> Result<u128> {
    let zone = (u128::MAX / n) * n;
    loop {
        let mut b = [0u8; 16];
        rng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
        let x = u128::from_le_bytes(b);
        if x < zone {
            return Ok(x % n);
        }
    }
}

/// `count` distinct candidates, never an excluded one, drawn by `rng` (uniform, or weighted by `weights`).
fn pick(candidates: &[Ua], exclude: &[Ua], count: u64, weights: Option<&[u64]>, rng: &mut impl RngCore) -> Result<Vec<Ua>> {
    if weights.is_some_and(|w| w.len() != candidates.len()) {
        return Err(Error::Argument);
    }
    let mut seen = std::collections::BTreeSet::new();
    if !candidates.iter().all(|c| seen.insert(*c)) {
        return Err(Error::Argument);
    }
    let mut pool: Vec<(Ua, u128)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, weights.and_then(|w| w.get(i)).map_or(1, |w| u128::from(*w))))
        .filter(|(c, w)| *w > 0 && !exclude.contains(c))
        .collect();
    if (pool.len() as u64) < count {
        return Err(Error::Argument);
    }
    let mut out = Vec::new();
    for _ in 0..count {
        let mut r = below(rng, pool.iter().map(|p| p.1).sum())?;
        let i = pool
            .iter()
            .position(|p| {
                let hit = r < p.1;
                r = r.saturating_sub(p.1);
                hit
            })
            .ok_or(Error::Argument)?;
        out.push(pool.swap_remove(i).0);
    }
    Ok(out)
}

/// The command `pickDecoys` on its JSON (the bounded reader, [`MAX`] bytes): `{decoys}` (module doc).
pub fn pick_json(request_json: &[u8]) -> Result<String> {
    let Value::Object(o) = bounded::json(request_json, MAX, DEPTH)? else { return Err(Error::Argument) };
    Request::from_map(&o)?.pick()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn ua(i: u8) -> Ua {
        [i; 32]
    }

    /// Pearson's chi-square of `seen` against `want` (each expected count).
    fn chi2(seen: &[u64], want: &[f64]) -> f64 {
        seen.iter().zip(want).map(|(o, e)| (*o as f64 - e).powi(2) / e).sum()
    }

    /// Uniform by default: over 40,000 draws of 3 decoys from 10 candidates less 2 excluded (a fixed seed, so the test is
    /// deterministic), each eligible candidate's count and each first-position count pass chi-square at p = 0.001 (7 degrees
    /// of freedom: 24.32); no duplicate, never an excluded one.
    #[test]
    fn uniform_no_duplicates_exclusions_honoured() {
        let c: Vec<Ua> = (1..=10).map(ua).collect();
        let ex = [ua(3), ua(7)];
        let mut rng = ChaCha20Rng::seed_from_u64(29);
        let (n, k) = (40_000u64, 3u64);
        let (mut any, mut first) = ([0u64; 11], [0u64; 11]);
        for _ in 0..n {
            let d = pick(&c, &ex, k, None, &mut rng).unwrap();
            assert_eq!(d.len() as u64, k);
            let set: std::collections::BTreeSet<_> = d.iter().collect();
            assert_eq!(set.len() as u64, k, "no duplicates");
            assert!(d.iter().all(|u| !ex.contains(u)), "never excluded");
            d.iter().for_each(|u| any[u[0] as usize] += 1);
            first[d[0][0] as usize] += 1;
        }
        assert_eq!((any[3], any[7]), (0, 0));
        let eligible: Vec<usize> = (1..=10).filter(|i| *i != 3 && *i != 7).collect();
        let pick_of = |t: &[u64; 11]| eligible.iter().map(|i| t[*i]).collect::<Vec<_>>();
        let x_any = chi2(&pick_of(&any), &[(n * k) as f64 / 8.0; 8]);
        let x_first = chi2(&pick_of(&first), &[n as f64 / 8.0; 8]);
        assert!(x_any < 24.32 && x_first < 24.32, "chi-square {x_any} / {x_first}");
        // the control: a biased draw (the lowest index twice as often) fails the same bound
        let mut biased = pick_of(&any);
        biased[0] *= 2;
        assert!(chi2(&biased, &[(n * k) as f64 / 8.0; 8]) > 24.32, "the test can fail");
    }

    /// Weighted (the activity filter): one draw lands on a candidate in proportion to its weight (chi-square, 3 degrees of
    /// freedom at p = 0.001: 16.27); weight 0 is never drawn.
    #[test]
    fn weighted() {
        let c: Vec<Ua> = (1..=5).map(ua).collect();
        let w = [1u64, 2, 0, 3, 4];
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let n = 50_000u64;
        let mut seen = [0u64; 6];
        for _ in 0..n {
            seen[pick(&c, &[], 1, Some(&w), &mut rng).unwrap()[0][0] as usize] += 1;
        }
        assert_eq!(seen[3], 0, "weight 0");
        let x = chi2(&[seen[1], seen[2], seen[4], seen[5]], &[1.0, 2.0, 3.0, 4.0].map(|f| f * n as f64 / 10.0));
        assert!(x < 16.27, "chi-square {x}");
        // all eligible, distinct, when every positive weight is needed
        let d = pick(&c, &[], 4, Some(&w), &mut rng).unwrap();
        let set: std::collections::BTreeSet<_> = d.iter().collect();
        assert_eq!(set.len(), 4);
        assert!(!set.contains(&ua(3)));
    }

    /// An RNG that yields `0xff` bytes first, then zeros.
    struct Stub(usize);
    impl RngCore for Stub {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            d.iter_mut().for_each(|b| {
                *b = if self.0 > 0 { 0xff } else { 0 };
                self.0 = self.0.saturating_sub(1);
            });
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }

    /// Rejection sampling: `2^128 − 1 ≡ 3 (mod 7)` lies above the last full multiple of 7, so it is redrawn (the next draw, 0,
    /// gives 0), never reduced to 3.
    #[test]
    fn rejection_sampling() {
        assert_eq!(below(&mut Stub(16), 7).unwrap(), 0);
        assert_eq!(u128::MAX % 7, 3, "the control: a reduction would give 3");
    }

    #[test]
    fn refusals() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let c: Vec<Ua> = (1..=4).map(ua).collect();
        assert_eq!(pick(&c, &[ua(1)], 3, None, &mut rng).unwrap().len(), 3, "exactly enough");
        assert_eq!(pick(&c, &[ua(1)], 4, None, &mut rng), Err(Error::Argument), "too few after the exclusions");
        assert_eq!(pick(&c, &[], 4, Some(&[1, 1, 1, 0]), &mut rng), Err(Error::Argument), "too few with weight > 0");
        assert_eq!(pick(&c, &[], 1, Some(&[1, 1, 1]), &mut rng), Err(Error::Argument), "weights of another length");
        assert_eq!(pick(&[ua(1), ua(1)], &[], 1, None, &mut rng), Err(Error::Argument), "a candidate twice");
        assert_eq!(pick(&c, &[], 0, None, &mut rng).unwrap(), Vec::<Ua>::new(), "count 0");
        let ok = format!(r#"{{"candidates": ["{}", "{}"], "exclude": ["{}"], "count": 1}}"#, to_hex(&ua(1)), to_hex(&ua(2)), to_hex(&ua(1)));
        assert_eq!(pick_json(ok.as_bytes()).unwrap(), format!(r#"{{"decoys":["{}"]}}"#, to_hex(&ua(2))));
        for bad in [
            r#"{"candidates": [], "exclude": [], "count": 1}"#,
            r#"{"candidates": ["0x01"], "exclude": [], "count": 1}"#,
            r#"{"candidates": [], "count": 0}"#,
            r#"{"candidates": [], "exclude": []}"#,
            r#"{"candidates": [], "exclude": [], "count": 0, "key": "0x00"}"#,
            r#"{"candidates": [], "exclude": [], "count": 0, "weights": [-1]}"#,
            r#"{"candidates": [], "exclude": [], "count": -1}"#,
            r#"[]"#,
        ] {
            assert_eq!(pick_json(bad.as_bytes()), Err(Error::Argument), "{bad}");
        }
    }
}
