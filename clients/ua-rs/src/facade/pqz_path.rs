// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ proof path's word parsers (no-oracle spec §4.14; proof-path spec §2.2 and §3.2 on `ua-mtx-merge`; plan T20d1, T20d3,
//! C-PP-1): an op blob's 3h tail and a debit record from its two storage words. Public data only, nothing decrypted; every
//! refusal is `Argument`. Path (A)'s entry parse reads [`tail`]'s `R`; `balanceProven` and the proven debits (T20d4, T20d5) read
//! the rest. The `PqzDebitProof` event is decoded by the reading layer, not here (Fable P3-1 on the T20d0 delta). UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]
use super::pqz_pack::VP;
use crate::wallet::{Error, Result};
use pqz_ffi::stmt::{groups, Word};

/// `PqzCore` record flags: `RECORD` always set, `WIDE` when `w1` was written.
const RECORD: u8 = 1;
const WIDE: u8 = 2;
/// The most key versions an op blob's tail names (op 7: 8 legs and the auditor).
const KV_MAX: usize = 9;

/// The big-endian `uint64` at `b[at..at + 8]`.
fn be64(b: &[u8], at: usize) -> Result<u64> {
    let x: [u8; 8] = b.get(at..at + 8).and_then(|x| x.try_into().ok()).ok_or(Error::Argument)?;
    Ok(u64::from_be_bytes(x))
}

/// `pqzDebitRecord(ua, k)`'s view (`DebitRecordView`) of `debitRec[ua][k]`: `w0 = prevBlob(160) ‖ p(64) ‖ Δp(16) ‖ proofStore(8) ‖
/// flags(8)`, `w1 = shieldIn(64) ‖ keyVersion(64) ‖ prevCounter(64) ‖ 0(64)`.
#[cfg_attr(not(test), allow(dead_code))] // `prevCounter`: the version chain's walk (T20d7, T20d8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) prev_blob: [u8; 20],
    pub(crate) p: u64,
    pub(crate) delta_p: u64,
    pub(crate) proof_store: u8,
    pub(crate) shield_in: u64,
    pub(crate) key_version: u64,
    pub(crate) prev_counter: u64,
    pub(crate) has_prev: bool,
}

/// [`Record`] of debit `counter` from its two words, both read as storage (`w1` is zero when the record is narrow): `w0 = 0` is no
/// record (the contract's `DebitRecordUnknown`); `RECORD` set and no other flag than `WIDE`; `proofStore` 0 (NONE) or 1 (LOG); a
/// narrow record has `w1 = 0`, no `shieldIn`, version 0 and, with a predecessor, `prevCounter = counter − 1`; `w1`'s low 64 bits
/// are 0. A wide record's `w1` may be zero too (a gap in the counters alone makes it wide).
pub(crate) fn record(w0: &Word, w1: &Word, counter: u64) -> Result<Record> {
    let [.., delta_hi, delta_lo, proof_store, flags] = *w0;
    if *w0 == [0; 32] || flags & RECORD == 0 || flags & !(RECORD | WIDE) != 0 || proof_store > 1 || be64(w1, 24)? != 0 {
        return Err(Error::Argument);
    }
    let prev_blob: [u8; 20] = w0.get(..20).and_then(|x| x.try_into().ok()).ok_or(Error::Argument)?;
    let has_prev = prev_blob != [0; 20];
    let (shield_in, key_version, prev_counter) = if flags & WIDE != 0 {
        (be64(w1, 0)?, be64(w1, 8)?, be64(w1, 16)?)
    } else if *w1 != [0; 32] {
        return Err(Error::Argument);
    } else if has_prev {
        (0, 0, counter.checked_sub(1).ok_or(Error::Argument)?)
    } else {
        (0, 0, 0)
    };
    Ok(Record { prev_blob, p: be64(w0, 20)?, delta_p: u64::from(u16::from_be_bytes([delta_hi, delta_lo])), proof_store, shield_in,
        key_version, prev_counter, has_prev })
}

/// An op blob's 3h tail (proof-path spec §3.2, `PqzCore.rOf`), read from the data's last byte: `… ‖ P(v_f) ‖ ownTag(32) ‖
/// kv(8·n) ‖ u8(n)`, `n ≤ 9`; `r_len` is the length of `R`, the data before `P(v_f)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tail {
    pub(crate) r_len: usize,
    pub(crate) own_tag: Word,
    pub(crate) kv: Vec<u64>,
}

/// [`Tail`] of an op blob's data (its SSTORE2 code less the leading byte); `Argument` when it does not fit.
pub(crate) fn tail(d: &[u8]) -> Result<Tail> {
    let n = *d.last().ok_or(Error::Argument)? as usize;
    if n > KV_MAX {
        return Err(Error::Argument);
    }
    let at = d.len().checked_sub(33 + 8 * n).ok_or(Error::Argument)?;
    let r_len = at.checked_sub(VP).ok_or(Error::Argument)?;
    let own_tag = d.get(at..at + 32).and_then(|t| t.try_into().ok()).ok_or(Error::Argument)?;
    let kv = (0..n).map(|i| be64(d, at + 32 + 8 * i)).collect::<Result<_>>()?;
    Ok(Tail { r_len, own_tag, kv })
}

/// The shape `(G, M, auditorOn)` of a transfer op blob's `R` (`PqzCore._bundleShape`: `salt(16) ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖
/// UA_j)_{j<M}`, op 1 as `M = 1`) from `R`'s length, `pkp` and `vp` the set's packed `u` and `v` lengths: **exactly one** `(M,
/// auditorOn)` with `1 ≤ M ≤ 8` must fit, two fits or none is `Argument` (no-oracle spec §4.14.4 step 1, Fable P3-6 on the T20d0
/// delta: the same rule for path (A)'s entries and path (B)'s credits).
pub(crate) fn bundle_shape(r_len: usize, pkp: usize, vp: usize) -> Result<(usize, usize, bool)> {
    let rem = r_len.checked_sub(16 + pkp).ok_or(Error::Argument)?;
    let g = 1 + rem.checked_div(pkp).ok_or(Error::Argument)?;
    let rem = rem.checked_rem(pkp).ok_or(Error::Argument)?;
    let mut fit = None;
    for aud in [true, false] {
        let ls = 32 + vp * (1 + aud as usize);
        let m = rem / ls;
        if m != 0 && m <= 8 && rem == ls * m && groups(m, aud) == g && fit.replace((g, m, aud)).is_some() {
            return Err(Error::Argument);
        }
    }
    fit.ok_or(Error::Argument)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::facade::pqz_pack::PKP;
    use pqz_ffi::stmt as st;
    use serde_json::Value;

    /// The forge rows of this build's set (`PqzStateVectors.t.sol`, `ua-mtx-merge` T62: release 3h), if the set has them.
    fn rows() -> Option<Value> {
        let file = match st::SET {
            "n2304-kmax4096" => "n2304-kmax4096/state.json",
            "n2048-kmax1024" => "state.json",
            _ => return None,
        };
        let path = format!("{}/../../smartcontracts/vectors/pqz/{file}", env!("CARGO_MANIFEST_DIR"));
        Some(serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
    }
    fn h(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }
    fn w(v: &Value) -> Word {
        h(v).try_into().unwrap()
    }
    fn n(v: &Value) -> u64 {
        v.as_u64().unwrap()
    }

    /// `state.json` `records`: every debit record parses to the contract's `pqzDebitRecord` view, narrow and wide.
    #[test]
    fn record_rows_are_the_contracts_view() {
        let Some(r) = rows() else { return };
        assert_eq!(r["release"], "3h");
        let recs = r["records"].as_array().unwrap();
        for x in recs {
            let v = &x["view"];
            let got = record(&w(&x["w0"]), &w(&x["w1"]), n(&x["counter"])).unwrap();
            let want = Record { prev_blob: h(&v["prevBlob"]).try_into().unwrap(), p: n(&v["p"]), delta_p: n(&v["deltaP"]),
                proof_store: n(&v["proofStore"]) as u8, shield_in: n(&v["shieldIn"]), key_version: n(&v["keyVersion"]),
                prev_counter: n(&v["prevCounter"]), has_prev: v["hasPrev"].as_bool().unwrap() };
            assert_eq!(got, want, "record ({}, {})", x["ua"], x["counter"]);
        }
        assert!(recs.iter().any(|x| w(&x["w0"])[31] & WIDE != 0), "a wide record");
        assert!(recs.iter().any(|x| x["view"]["proofStore"] == 1), "a record under LOG");
        assert!(recs.iter().any(|x| x["view"]["hasPrev"] == true && w(&x["w0"])[31] & WIDE == 0), "a narrow one with a predecessor");
    }

    /// Each record refusal, one change from a valid row (positive control first).
    #[test]
    fn record_refusals() {
        let Some(r) = rows() else { return };
        let recs = r["records"].as_array().unwrap();
        let narrow = recs.iter().find(|x| x["view"]["hasPrev"] == true && w(&x["w0"])[31] & WIDE == 0).unwrap();
        let (w0, w1, k) = (w(&narrow["w0"]), w(&narrow["w1"]), n(&narrow["counter"]));
        assert!(record(&w0, &w1, k).is_ok(), "positive control");
        let with = |f: &dyn Fn(&mut Word, &mut Word)| {
            let (mut a, mut b) = (w0, w1);
            f(&mut a, &mut b);
            record(&a, &b, k)
        };
        let no = Err(Error::Argument);
        assert_eq!(record(&[0; 32], &[0; 32], k), no, "no record (w0 = 0)");
        assert_eq!(with(&|a, _| a[31] &= !RECORD), no, "RECORD clear");
        assert_eq!(with(&|a, _| a[31] |= 4), no, "an unknown flag");
        assert_eq!(with(&|a, _| a[30] = 2), no, "proofStore 2");
        assert_eq!(with(&|_, b| b[7] = 1), no, "a narrow record with a w1");
        assert_eq!(with(&|a, b| { a[31] |= WIDE; b[31] = 1 }), no, "w1's low 64 bits set");
        assert_eq!(record(&w0, &w1, 0), no, "a predecessor before the first counter");
        let wide = recs.iter().find(|x| w(&x["w0"])[31] & WIDE != 0).unwrap();
        let (a, b) = (w(&wide["w0"]), w(&wide["w1"]));
        assert_eq!(record(&a, &b, n(&wide["counter"])).unwrap().shield_in, n(&wide["view"]["shieldIn"]), "positive control: wide");
        let mut narrowed = a;
        narrowed[31] &= !WIDE;
        assert_eq!(record(&narrowed, &b, n(&wide["counter"])), no, "WIDE cleared with its w1");
    }

    /// `state.json` `tails`: every op blob's tail (`ownTag`, `kv`, `n`) and `R`'s length, as the contract wrote them.
    #[test]
    fn tail_rows_are_the_contracts() {
        let Some(r) = rows() else { return };
        let tails = r["tails"].as_array().unwrap();
        for x in tails {
            assert_eq!(n(&x["vp"]) as usize, VP, "{}: this set's P(v)", x["name"]);
            let code = h(&x["code"]);
            let t = tail(&code[1..]).unwrap();
            let kv: Vec<u64> = x["kv"].as_array().unwrap().iter().map(n).collect();
            assert_eq!((t.r_len, t.own_tag, t.kv.len() as u64), (n(&x["rLen"]) as usize, w(&x["ownTag"]), n(&x["n"])), "{}", x["name"]);
            assert_eq!(t.kv, kv, "{}", x["name"]);
        }
        assert!(tails.iter().any(|x| n(&x["n"]) == 0), "a burn's tail");
        assert!(tails.iter().any(|x| x["kv"].as_array().unwrap().iter().any(|v| n(v) != 0)), "a version other than 0");
    }

    /// Each tail refusal: an empty blob, `n` above 9, a tail longer than the data, no room for `P(v_f)`.
    #[test]
    fn tail_refusals() {
        let Some(r) = rows() else { return };
        let code = h(&r["tails"][0]["code"]);
        let d = &code[1..];
        assert!(tail(d).is_ok(), "positive control");
        let no = Err(Error::Argument);
        assert_eq!(tail(&[]), no, "empty");
        let mut ten = d.to_vec();
        *ten.last_mut().unwrap() = 10;
        assert_eq!(tail(&ten), no, "n = 10");
        assert_eq!(tail(&[0u8; 32]), no, "shorter than a tail");
        assert_eq!(tail(&[vec![0u8; 33 + VP - 1], vec![0]].concat()[1..]), no, "no room for P(v_f)");
        assert_eq!(tail(&[vec![0u8; VP + 32], vec![0]].concat()).unwrap().r_len, 0, "R empty, the shortest tail");
    }

    /// `state.json` `tails`: every transfer blob's `R` has exactly one shape, and it is the one its tail names (`n = M +
    /// auditorOn`, the auditor copy where the row's name says so); a burn's `R` (`P(u′)` alone) has none.
    #[test]
    fn bundle_shape_of_the_rows() {
        let Some(r) = rows() else { return };
        let mut seen = (false, false);
        for x in r["tails"].as_array().unwrap() {
            let (name, r_len) = (x["name"].as_str().unwrap(), n(&x["rLen"]) as usize);
            if name.starts_with("burn") {
                assert_eq!(bundle_shape(r_len, PKP, VP), Err(Error::Argument), "{name}");
                continue;
            }
            let (_, m, aud) = bundle_shape(r_len, PKP, VP).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!((m + aud as usize) as u64, n(&x["n"]), "{name}: n");
            assert_eq!(aud, name.contains("audited"), "{name}: the auditor copy");
            seen = (seen.0 || (aud && m > 1), seen.1 || (!aud && m > 1));
        }
        assert_eq!(seen, (true, true), "op 7 rows with and without the auditor");
    }

    /// Two fits are refused, not resolved by order (Fable P3-6). No real set has two (the two leg strides `32 + 2·VP` and `32 + VP`
    /// share no multiple below 9 legs), so the sizes here are made up: `vp = 0` makes both strides 32.
    #[test]
    fn bundle_shape_refuses_two_fits() {
        assert_eq!(bundle_shape(16 + 1000 + 32, 1000, 0), Err(Error::Argument), "two fits");
        // `vp = 16`: strides 64 (with the auditor) and 48 (without)
        assert_eq!(bundle_shape(16 + 1000 + 64, 1000, 16), Ok((1, 1, true)), "positive control: M = 1 with the auditor");
        assert_eq!(bundle_shape(16 + 1000 + 2 * 48, 1000, 16), Ok((1, 2, false)), "positive control: M = 2 without");
        assert_eq!(bundle_shape(16 + 1000 + 3 * 48, 1000, 16), Ok((1, 3, false)), "positive control: M = 3 without");
        assert_eq!(bundle_shape(16 + 1000 + 33, 1000, 16), Err(Error::Argument), "none fits");
        assert_eq!(bundle_shape(15, 1000, 16), Err(Error::Argument), "shorter than salt and u_0");
    }
}
