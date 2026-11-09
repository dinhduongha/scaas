// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Path (B), the PQZ proof path of release 3h (no-oracle spec §4.14; ua-rs-sign T20d4, C-PP-2): `provenOpen`, `provenAdd`,
//! `provenCancel`, `balanceProven`. Every part of the sum is checked before the key is used: a credit by its sender's debit proof
//! P over a statement the facade rebuilds (§4.14.4) with the handle's own `pk` at the leg the credit names, the holder's own
//! `v_f` by its `ownTag` (a seed-keyed MAC, independent of `s`), a migration credit by re-encryption from the debited version's
//! seed (3g KV-11; its P when the store holds no such seed), a TRIVIAL entry from its public amount. A tag proves authorship,
//! not inclusion: a source can omit a credit or replay an older own debit, and the result is then wrong, never a key leak
//! (§4.14.1). One session per handle, in the handle's memory: the running sum mod `q` of the checked parts, their kinds and the
//! accepted indexes, never a checked ciphertext.
//!
//! **A tag proves authorship, not inclusion** (§4.14.7): no command takes a tag match for the latest state; the latest own debit
//! is the record at `lastDebit − 1` of the session's source. **Sealing** (C-PP-5): `unsealed = pendingCount − p_last` counts the
//! entries no own debit has folded into a tagged `v_f`, each of which needs its P from history (or path (A)) after a reinstall;
//! `sealAdvised` is `unsealed > 0` (a refresh seals them; a wallet may advise one before it goes cold, never requires one; a
//! rollover seals nothing). After a reinstall (research §15A):
//!
//! | After a reinstall | Commands |
//! |---|---|
//! | no entry since the last own debit | `provenOpen` (`need` empty), `balanceProven`: the tag alone, nothing from history |
//! | new credits, every P in history | `provenOpen`, `provenAdd`, `balanceProven`; a `proveRefreshProven` seals |
//! | new credits, a P lost, a source under R1–R6 | path (A): `balance`, then `proveRefresh` seals |
//! | new credits, a P lost, no trusted source | refused; the funds stay until a trusted source exists |
//!
//! The library does not choose between the rows: `provenAdd` refuses a credit it cannot check, and the caller then takes path
//! (A) under R1–R6 or stops; the choice depends on availability, never on a decryption (research §8). UNAUDITED.
use super::*;
use crate::facade::pqz_path::{bundle_shape, record, tail, Record, Tail};
use pqz_ffi::stmt::{H_ID, H_OPTAG, OP_TAG_TRANSFER_MULTI};
use std::collections::{BTreeMap, BTreeSet};

/// The most key records of one credit (op 7: 8 legs and the auditor, and the sender's).
const KEY_RECORDS_MAX: usize = 10;
/// `ZetherTypes.TransferMode` (`HASH` 0, `BUNDLE` 1) as `PqzCore._bindMode` encodes it.
fn mode_word(m: Mode) -> Word {
    u64_word(match m {
        Mode::Hash => 0,
        Mode::Bundle => 1,
    })
}

/// A request's SSTORE2 codes `(address, code)`, each address once.
pub(super) type Codes = Vec<([u8; 20], Vec<u8>)>;

/// A part's kind in `balanceProven`'s `parts` (never a value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Own,
    Credit,
    Migration,
    Trivial,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Own => "own",
            Kind::Credit => "credit",
            Kind::Migration => "migration",
            Kind::Trivial => "trivial",
        }
    }
}

/// A pending slot of the window that is not TRIVIAL: its op blob and the offsets of the `(u, v)` it sums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Slot {
    ptr: [u8; 20],
    u_off: usize,
    v_off: usize,
}

/// `provenOpen`'s words, parsed and checked (public data only): the location, the window `[p_last, p)`, the own `v_f` with its
/// tag (checked with the seed at the open), the TRIVIAL entries and the slots each credit must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Open {
    id: Word,
    chain_id: u64,
    registry: [u8; 20],
    chain_uid: Word,
    token: [u8; 20],
    ua: Word,
    v: u64,
    auditor_ua: Word,
    p: u64,
    p_last: u64,
    rolled: u64,
    /// `pendingCount`: `unsealed = pendingCount − p_last` (§4.14.7).
    count: u64,
    send_counter: u64,
    /// Group 3g: the version is below the registry's `current` (KV-8: it only migrates or refreshes); `forOp7` (its `p`).
    stale: bool,
    op7: bool,
    /// `accBlob` (the last own debit's op blob) and that debit's record (`lastRecord`).
    acc_blob: [u8; 20],
    last: Option<Record>,
    /// `(counter, ownTag, u ‖ v_f)` of the last own debit (`lastDebit > 0`): the tag as stored, the ciphertext in 64-bit lanes.
    own: Option<(u64, Word, Vec<u8>)>,
    trivial: Vec<(u64, u64)>,
    need: BTreeMap<u64, Slot>,
    /// The materialised `acc` (`flags & MAT`), unpacked and checked against `accHash`: the proven debits' cross-check (T20d5).
    acc: Option<Vec<u8>>,
}

/// A credit of `provenAdd` (§4.14.4), its fields typed; the words are checked by [`PqzKey::check_credit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Credit {
    index: u64,
    from_ua: Word,
    k: u64,
    multi: bool,
    record: (Word, Word),
    sender_pending: Option<Vec<(u64, Word)>>,
    key_records: Option<Vec<(Word, u64, Word)>>,
    proof: Option<Vec<u8>>,
    header: Option<[Word; 20]>,
    call: Option<Call>,
}

/// A NONE debit's call fields (§4.14.4 step 4: op 1, op 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Call {
    beneficiary_ua: Word,
    fee: u64,
    valid_until_block: u64,
    mode: Mode,
    sealed_memo: Option<Vec<u8>>,
    binding: Word,
}

/// The handle's one session (§4.14.2): what `PqzCore` keeps while it sums.
pub(super) struct Session {
    id: [u8; 16],
    open: Open,
    sum: Vec<u64>,
    /// The own `v_f` and the parts below `rolled`: a debit's cross-check with the materialised `acc` (§4.14.3).
    below: Vec<u64>,
    accepted: BTreeSet<u64>,
    parts: Vec<(Option<u64>, Kind)>,
}

/// `c = (c + x) mod q` lane-wise (`x` 64-bit lanes, each below `2^B`).
fn add_mod(c: &mut [u64], x: &[u8]) {
    c.iter_mut().zip(x.chunks_exact(8)).for_each(|(a, b)| *a = (*a + b.iter().fold(0u64, |s, y| s << 8 | u64::from(*y))) % Q);
}

/// `c += Trivial(digits(amount))` mod `q`.
fn add_trivial_mod(c: &mut [u64], amount: u64) {
    add_trivial(c, amount);
    c.iter_mut().for_each(|a| *a %= Q);
}

/// `n` stored bytes at `off` of `d`, unpacked to 64-bit lanes.
fn part(d: &[u8], off: usize, n: usize) -> Result<Vec<u8>> {
    d.get(off..off.checked_add(n).ok_or(Error::Argument)?).and_then(unpack).ok_or(Error::Argument)
}

/// `(u, v_f)` offsets of an own debit's op blob (`PqzCore._uv`, `e2e.py` `acc_of`): a burn, refresh or unwrap has `R = P(u′)`,
/// `u` at 0; a transfer `salt ‖ u_0 ‖ …`, `u` at 16; `v_f` follows `R`.
fn uv_of(d: &[u8]) -> Result<(usize, usize, Tail)> {
    let t = tail(d)?;
    Ok((if t.r_len == PKP { 0 } else { 16 }, t.r_len, t))
}

/// A pending word: TRIVIAL (`vOff == 0`, its amount in the low 64 bits of the blob field) or a slot.
fn entry_of(e: &Word) -> Result<std::result::Result<u64, Slot>> {
    if *e == [0; 32] {
        return Err(Error::Argument);
    }
    let v_off = lo_u64(e, 8, 2)? as usize;
    Ok(if v_off == 0 {
        Ok(lo_u64(e, 12, 8)?)
    } else {
        Err(Slot { ptr: lo_addr(e, 12)?, u_off: lo_u64(e, 10, 2)? as usize, v_off })
    })
}

/// `{index, word}` entries, exactly `[from, to)` in order, at most `K_MAX`.
fn window(list: &[Value], from: u64, to: u64) -> Result<Vec<(u64, Word)>> {
    if to.checked_sub(from).ok_or(Error::Argument)? != list.len() as u64 || list.len() > K_MAX {
        return Err(Error::Argument);
    }
    list.iter()
        .enumerate()
        .map(|(k, e)| {
            let e = Fields::new(e.as_object().ok_or(Error::Argument)?, &["index", "word"])?;
            let (i, w) = (e.u64("index")?, e.word("word")?);
            if i != from + k as u64 {
                return Err(Error::Argument);
            }
            Ok((i, w))
        })
        .collect()
}

/// `provenOpen` (§4.14.2): the account of key version `keyVersion` of `ua`, its last record and the window `[p_last, p)`; the
/// registered key the handle must hold.
pub(super) fn open(f: &Fields<'_>) -> Result<(Open, Vec<u8>)> {
    let mut blobs = Blobs::new(f)?;
    let key = registered_key(&f.word("keyRecord")?, &mut blobs)?;
    let o = open_words(f, &mut blobs)?;
    blobs.done()?;
    Ok((o, key))
}

/// [`open`]'s words without the key: the account, `lastRecord`, the window (the quorum's check reads them too, with no key
/// word of the quorum).
fn open_words(f: &Fields<'_>, blobs: &mut Blobs) -> Result<Open> {
    let id = system(&f.word("psid")?)?;
    let is_stale = stale(f)?;
    let a = acct(&f.words("account")?, &f.word("sendCounterWord")?)?;
    if !(a.cleared <= a.floor && a.floor <= a.rolled && a.rolled <= a.count) {
        return Err(Error::Argument);
    }
    let (chain_uid, token) = (f.word("chainUid")?, f.arr("token")?);
    // the last own debit: its record gives `p_last`, `accBlob` its `(u, v_f)` and tag (rollovers keep `accBlob`)
    let (p_last, own, last) = match (a.last_debit, f.has("lastRecord")) {
        (0, false) if a.acc_blob == [0; 20] => (0, None, None),
        (n, true) if n > 0 => {
            let lr = Fields::new(f.get("lastRecord")?.as_object().ok_or(Error::Argument)?, &["w0", "w1"])?;
            let rec = record(&lr.word("w0")?, &lr.word("w1")?, n - 1)?;
            let d = blobs.data(&a.acc_blob)?;
            let (u_at, v_at, t) = uv_of(d)?;
            if (a.acc_u, a.acc_v) != (u_at, v_at) || rec.p > a.rolled {
                return Err(Error::Argument);
            }
            let ct = [part(d, u_at, PKP)?, part(d, v_at, VP)?].concat();
            if !coeffs_ok(&ct) {
                return Err(Error::Argument);
            }
            (rec.p, Some((n - 1, t.own_tag, ct)), Some(rec))
        }
        _ => return Err(Error::Argument),
    };
    // `p` as path (A) chooses it (CTR-PQZ-06); the parts: the own `v_f` and every entry of `[p_last, p)`, with `Trivial(shieldIn)`
    // at most `K_MAX` units
    let room = (K_MAX as u64).checked_sub(a.units + 1).ok_or(Error::Argument)?;
    let op7 = f.get("forOp7")?.as_bool().ok_or(Error::Argument)?;
    let inline = if op7 && id == PQZH_ID { INLINE_MAX_PQZH } else { INLINE_MAX };
    let p = a.count.min(a.rolled.saturating_add(inline.min(room)));
    if (p - p_last) + u64::from(own.is_some()) + 1 > K_MAX as u64 {
        return Err(Error::Argument);
    }
    let acc_words = f.words("accWords")?;
    let acc = if a.flags & MAT != 0 {
        let stream: Vec<u8> = acc_words.iter().flat_map(|w| w.map(|b| !b)).take(CTP).collect();
        if acc_words.len() != ACC_WORDS || crate::keccak256(&stream) != a.acc_hash {
            return Err(Error::Argument);
        }
        Some(unpack(&stream).ok_or(Error::Argument)?)
    } else if acc_words.is_empty() {
        None
    } else {
        return Err(Error::Argument);
    };
    let (mut trivial, mut need) = (Vec::new(), BTreeMap::new());
    for (i, e) in window(f.list("pending")?, p_last, p)? {
        match entry_of(&e)? {
            Ok(amount) => trivial.push((i, amount)),
            Err(slot) => {
                need.insert(i, slot);
            }
        }
    }
    Ok(Open {
        id,
        chain_id: f.u64("chainId")?,
        registry: f.arr("registry")?,
        chain_uid,
        token,
        ua: f.word("ua")?,
        v: f.u64("keyVersion")?,
        auditor_ua: f.word("auditorUA")?,
        p,
        p_last,
        rolled: a.rolled,
        count: a.count,
        send_counter: a.send_counter,
        stale: is_stale,
        op7,
        acc_blob: a.acc_blob,
        last,
        own,
        trivial,
        need,
        acc,
    })
}

/// `provenAdd`'s `blobs` (each address once) and `credits` (at most `K_MAX`), typed; a field missing or of another type is
/// `Argument` for the whole call.
pub(super) fn credits(f: &Fields<'_>) -> Result<(Codes, Vec<Credit>)> {
    let blobs = Blobs::new(f)?.0.into_iter().map(|(a, c, _)| (a, c)).collect();
    let list = f.list("credits")?;
    if list.len() > K_MAX {
        return Err(Error::Argument);
    }
    let credits = list
        .iter()
        .map(|c| {
            let c = Fields::new(
                c.as_object().ok_or(Error::Argument)?,
                &["index", "fromUA", "sendCounter", "form", "record", "senderPending", "keyRecords", "proof", "header", "call"],
            )?;
            let r = Fields::new(c.get("record")?.as_object().ok_or(Error::Argument)?, &["w0", "w1"])?;
            let multi = match c.get("form")?.as_str() {
                Some("transfer") => false,
                Some("transferMulti") => true,
                _ => return Err(Error::Argument),
            };
            let sender_pending = c
                .has("senderPending")
                .then(|| {
                    let l = c.list("senderPending")?;
                    if l.len() > K_MAX {
                        return Err(Error::Argument);
                    }
                    l.iter()
                        .map(|e| {
                            let e = Fields::new(e.as_object().ok_or(Error::Argument)?, &["index", "word"])?;
                            Ok((e.u64("index")?, e.word("word")?))
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?;
            let key_records = c
                .has("keyRecords")
                .then(|| {
                    let l = c.list("keyRecords")?;
                    if l.len() > KEY_RECORDS_MAX {
                        return Err(Error::Argument);
                    }
                    l.iter()
                        .map(|e| {
                            let e = Fields::new(e.as_object().ok_or(Error::Argument)?, &["ua", "version", "word"])?;
                            Ok((e.word("ua")?, e.u64("version")?, e.word("word")?))
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?;
            let header = c
                .has("header")
                .then(|| c.words("header")?.try_into().map_err(|_| Error::Argument))
                .transpose()?;
            let call = c.has("call").then(|| call(c.get("call")?)).transpose()?;
            if header.is_some() && call.is_some() {
                return Err(Error::Argument);
            }
            Ok(Credit {
                index: c.u64("index")?,
                from_ua: c.word("fromUA")?,
                k: c.u64("sendCounter")?,
                multi,
                record: (r.word("w0")?, r.word("w1")?),
                sender_pending,
                key_records,
                proof: c.has("proof").then(|| c.bytes("proof")).transpose()?,
                header,
                call,
            })
        })
        .collect::<Result<_>>()?;
    Ok((blobs, credits))
}

/// A NONE transfer's call fields: `beneficiaryUA?`, `fee`, `validUntilBlock`, `mode`, `sealedMemo` (on `HASH` only), `binding`.
fn call(v: &Value) -> Result<Call> {
    let c = Fields::new(v.as_object().ok_or(Error::Argument)?, &["beneficiaryUA", "fee", "validUntilBlock", "mode", "sealedMemo", "binding"])?;
    let mode = c.mode()?;
    if c.has("sealedMemo") != (mode == Mode::Hash) {
        return Err(Error::Argument);
    }
    Ok(Call {
        beneficiary_ua: c.opt_word("beneficiaryUA")?,
        fee: c.u64("fee")?,
        valid_until_block: c.u64("validUntilBlock")?,
        mode,
        sealed_memo: c.has("sealedMemo").then(|| c.bytes("sealedMemo")).transpose()?,
        binding: c.word("binding")?,
    })
}

/// A credit's op blob as the check reads it: `R`, its shape, the leg `j` to the holder and the offsets of `(u_{g(j)}, v_j)`.
struct Leg {
    t: Tail,
    e: Entry,
    j: usize,
    u_off: usize,
    v_off: usize,
}

/// Step 1 of §4.14.4: the tail, the one shape, the leg to `(ua, v)` (op 1 `toUA` and `kv[0]`; op 7 the one `j` with `UA_j == ua`
/// and `kv[j] == v`) and the pairing `(u_{g(j)}, v_j)` the relation defines, derived from `j`; the slot's offsets must be those.
fn leg(d: &[u8], multi: bool, ua: &Word, v: u64, slot: &Slot) -> Result<Leg> {
    let (t, e) = shape(d)?;
    let (m, aud) = (e.m, e.aud);
    if !multi && m != 1 {
        return Err(Error::Argument);
    }
    let mut js = (0..m).filter(|j| e.owner(*j).is_ok_and(|w| w == *ua) && t.kv.get(*j) == Some(&v));
    let j = js.next().ok_or(Error::Argument)?;
    if js.next().is_some() {
        return Err(Error::Argument);
    }
    let (u_off, v_off) = (16 + PKP * (j / legs_per_group(aud)), e.leg_at(j));
    if (slot.u_off, slot.v_off) != (u_off, v_off) {
        return Err(Error::Argument);
    }
    Ok(Leg { t, e, j, u_off, v_off })
}

/// A transfer op blob's tail and `R` with its one shape (`n = M + auditorOn`).
fn shape(d: &[u8]) -> Result<(Tail, Entry)> {
    let t = tail(d)?;
    let r = d.get(..t.r_len).ok_or(Error::Argument)?.to_vec();
    let (g, m, aud) = bundle_shape(r.len(), PKP, VP)?;
    if t.kv.len() != m + aud as usize {
        return Err(Error::Argument);
    }
    Ok((t, Entry { r, g, m, aud, entry_ref: [0; 32] }))
}

/// `T_k` by the proof-path spec §2.3: `prevBlob`'s `(u, v_f)` (zero without one) `+ Σ` the sender's window `[p − Δp, p)` `+
/// Trivial(digits(shieldIn))`, reduced.
fn t_k(rec: &Record, window: &[(u64, Word)], blobs: &mut Blobs) -> Result<Vec<u8>> {
    let mut c = vec![0u64; CT_BYTES / 8];
    if rec.has_prev {
        let d = blobs.data(&rec.prev_blob)?;
        let (u_at, v_at, _) = uv_of(d)?;
        add_mod(&mut c, &[part(d, u_at, PKP)?, part(d, v_at, VP)?].concat());
    }
    let start = rec.p.checked_sub(rec.delta_p).ok_or(Error::Argument)?;
    if window.len() as u64 != rec.delta_p || rec.delta_p + 2 > K_MAX as u64 {
        return Err(Error::Argument);
    }
    for (k, (i, e)) in window.iter().enumerate() {
        if *i != start + k as u64 {
            return Err(Error::Argument);
        }
        match entry_of(e)? {
            Ok(amount) => add_trivial_mod(&mut c, amount),
            Err(s) => add_mod(&mut c, &load(blobs.data(&s.ptr)?, s.u_off, s.v_off)?),
        }
    }
    add_trivial_mod(&mut c, rec.shield_in);
    Ok(c.iter().flat_map(|x| x.to_be_bytes()).collect())
}

/// `keccak256(abi.encode(binding == 0 ? TAG_DIRECT_MODE : binding, uint8(mode)))` (`PqzCore._bindMode`).
fn bind_mode(binding: &Word, mode: Mode) -> Word {
    let b = if *binding == [0; 32] { crate::keccak256(b"SCAAS-PQZ-DIRECT-MODE-V1") } else { *binding };
    crate::keccak256(&[b, mode_word(mode)].concat())
}

impl PqzKey {
    /// The session state after a command: the handle's one session, dropped once the handle is revoked (a lock).
    fn session(&self) -> Result<std::sync::MutexGuard<'_, Option<Session>>> {
        let mut g = self.session.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = self.secret.with(|_| ()) {
            *g = None;
            return Err(e);
        }
        Ok(g)
    }

    /// `provenOpen`: the own `v_f`'s tag checked with `K_v` (from the seed, never `s`), the session opened (a second replaces the
    /// first): `{session, p, sendCounter, need}`.
    pub(super) fn proven_open(&self, o: &Open) -> Result<Value> {
        let mut g = self.session()?;
        let (mut sum, mut below) = (vec![0u64; CT_BYTES / 8], vec![0u64; CT_BYTES / 8]);
        let mut parts = Vec::new();
        if let Some((counter, tag, ct)) = &o.own {
            let mut hd = [[0u8; 32]; 20];
            for (i, w) in [(H_CHAIN_UID, o.chain_uid), (H_TOKEN, addr(&o.token)), (H_FROM, o.ua), (H_SEND_COUNTER, u64_word(*counter))] {
                *hd.get_mut(i).ok_or(Error::Argument)? = w;
            }
            let (u, v_f) = ct.split_at(PK_BYTES);
            let want = self.secret.with(|seed32| own_tag(seed32, &hd, u, v_f))??;
            if !bool::from(want.ct_eq(tag)) {
                return Err(Error::Argument);
            }
            add_mod(&mut sum, ct);
            add_mod(&mut below, ct);
            parts.push((None, Kind::Own));
        }
        for (i, amount) in &o.trivial {
            add_trivial_mod(&mut sum, *amount);
            if *i < o.rolled {
                add_trivial_mod(&mut below, *amount);
            }
            parts.push((Some(*i), Kind::Trivial));
        }
        let id = os16()?;
        *g = Some(Session { id, open: o.clone(), sum, below, accepted: BTreeSet::new(), parts });
        let unsealed = o.count - o.p_last;
        Ok(json!({"session": to_hex(&id), "p": o.p, "sendCounter": o.send_counter, "need": o.need.keys().collect::<Vec<_>>(),
            "unsealed": unsealed}))
    }

    /// `provenAdd`: each credit checked on its own (keyless), `{accepted, refused}`; a refused one leaves the session as it was
    /// (owner ruling 2026-11-09, no-oracle spec §7 item 11).
    pub(super) fn proven_add(&self, sid: &[u8; 16], codes: &Codes, credits: &[Credit]) -> Result<Value> {
        let mut g = self.session()?;
        let s = g.as_mut().filter(|s| s.id == *sid).ok_or(Error::Argument)?;
        // every verdict first: a call that is `Argument` as a whole leaves the session as it was
        let mut blobs = Blobs(codes.iter().map(|(a, d)| (*a, d.clone(), false)).collect());
        let verdicts = credits.iter().map(|c| self.check_credit(&s.open, &s.accepted, c, &mut blobs)).collect::<Result<Vec<_>>>()?;
        let (mut accepted, mut refused) = (Vec::new(), Vec::new());
        for (c, v) in credits.iter().zip(verdicts) {
            match v {
                // an index accepted once (in this call too) is not summed twice
                Some((ct, kind)) if s.accepted.insert(c.index) => {
                    add_mod(&mut s.sum, &ct);
                    if c.index < s.open.rolled {
                        add_mod(&mut s.below, &ct);
                    }
                    s.parts.push((Some(c.index), kind));
                    accepted.push(c.index);
                }
                _ => refused.push(c.index),
            }
        }
        Ok(json!({"accepted": accepted, "refused": refused}))
    }

    /// `provenCancel`: the session dropped.
    pub(super) fn proven_cancel(&self, sid: &[u8; 16]) -> Result<Value> {
        let mut g = self.session()?;
        if g.as_ref().is_none_or(|s| s.id != *sid) {
            return Err(Error::Argument);
        }
        *g = None;
        Ok(json!({}))
    }

    /// `balanceProven`: once every `need` index is accepted (the slot range `provenOpen` fixed, never the set accepted so far),
    /// the key decrypts the sum: `{value, p, sendCounter, parts}`; the session closes.
    pub(super) fn balance_proven(&self, sid: &[u8; 16]) -> Result<Value> {
        let mut g = self.session()?;
        let s = g.as_ref().filter(|s| s.id == *sid).ok_or(Error::Argument)?;
        if !s.open.need.keys().all(|i| s.accepted.contains(i)) {
            return Err(Error::Argument);
        }
        let t: Vec<u8> = s.sum.iter().flat_map(|x| x.to_be_bytes()).collect();
        let t: &[u8; CT_BYTES] = t.as_slice().try_into().map_err(|_| Error::Argument)?;
        let value = self.with_sk(|_, sk| value(pqzl::dec(&sk.0.s, t)))?;
        let parts: Vec<Value> = s.parts.iter().map(|(i, k)| json!({"index": i, "kind": k.name()})).collect();
        let unsealed = s.open.count - s.open.p_last;
        let out = json!({"value": value, "p": s.open.p, "sendCounter": s.open.send_counter, "parts": parts, "unsealed": unsealed,
            "sealAdvised": unsealed > 0});
        *g = None;
        Ok(out)
    }

    /// One credit (§4.14.3, §4.14.4): `Some((u ‖ v, kind))` when it passes, `None` refused (the session unchanged); `Argument` for
    /// the whole call when a credit that needs its P lacks the fields of one.
    fn check_credit(&self, o: &Open, accepted: &BTreeSet<u64>, c: &Credit, blobs: &mut Blobs) -> Result<Option<(Vec<u8>, Kind)>> {
        let Some(slot) = o.need.get(&c.index).filter(|_| !accepted.contains(&c.index)) else { return Ok(None) };
        let Ok(rec) = record(&c.record.0, &c.record.1, c.k) else { return Ok(None) };
        // a migration credit (3g KV-11): the holder's own UA from a version below the handle's, re-encrypted from that seed
        if c.from_ua == o.ua && rec.key_version < o.v && !c.multi {
            match self.old_seed(o, &rec, c, blobs) {
                Some(seed) => return Ok(self.reencrypted(o, c, slot, &seed, blobs).ok().map(|ct| (ct, Kind::Migration))),
                None => return by_proof(&self.pk, o, &rec, c, slot, blobs).map(|r| r.map(|ct| (ct, Kind::Migration))),
            }
        }
        by_proof(&self.pk, o, &rec, c, slot, blobs).map(|r| r.map(|ct| (ct, Kind::Credit)))
    }

    /// The seed of the debited version `rec.keyVersion` from the handle's own store: a derived handle's `(account, index, v_old)`,
    /// an installed one's by the old key's hash (its record in `keyRecords`); `None` when the store holds none.
    fn old_seed(&self, o: &Open, rec: &Record, c: &Credit, blobs: &mut Blobs) -> Option<Zeroizing<Vec<u8>>> {
        let h = if self.account != u32::MAX {
            let (account, index, v) = (self.account, self.index, rec.key_version);
            self.secret.derive(KeyId::Pqz(account, index, v), |seed| {
                let seed32 = crate::wallet::derive::hkdf_pq_version(seed, TAG, account, index, v, 32)?;
                let pk = keygen(&seed32)?.0.pk.to_vec();
                Ok((seed32, pk))
            })
        } else {
            let (_, _, w) = c.key_records.as_ref()?.iter().find(|(u, x, _)| *u == o.ua && *x == rec.key_version)?;
            let pk = registered_key(w, blobs).ok()?;
            let kh = crate::key_hash_of(crate::PQZ_SCHEME, &pk).ok()??;
            self.secret.derive(KeyId::PqzHeld(kh), |_| Err(Error::Argument))
        };
        h.ok()?.0.with(|s| Zeroizing::new(s.to_vec())).ok()
    }

    /// A migration credit by re-encryption: CTR-PQZ-19's `seed_enc` of the debit `(ua, k)` from `seed32` of the debited version,
    /// then `u == Aᵀr + e1` and `v − pkᵀr − e2 ∈ Δ·[0, 16)^16` in constant time, `pk` the handle's (op 1 to its own UA).
    fn reencrypted(&self, o: &Open, c: &Credit, slot: &Slot, seed32: &[u8], blobs: &mut Blobs) -> Result<Vec<u8>> {
        let d = blobs.data(&slot.ptr)?.to_vec();
        let l = leg(&d, false, &o.ua, o.v, slot)?;
        let ct = load(&d, l.u_off, l.v_off)?;
        let salt: [u8; 16] = d.get(..16).and_then(|s| s.try_into().ok()).ok_or(Error::Argument)?;
        let seed = Zeroizing::new(seed_enc(seed32, &o.chain_uid, &o.token, &o.ua, c.k, &salt)?);
        let mut words = [[0u8; 32]; DISC_WORDS];
        *words.get_mut(1).ok_or(Error::Argument)? = o.id;
        let (enc, i) = self.sender_enc(&seed, &self.pk, l.e.aud, None, &words, [0; 16])?;
        let (u, v) = ct.split_at(PK_BYTES);
        let (_, v_eq) = sender_amount(v, enc.0.vs.get(i).ok_or(Error::Argument)?);
        if bool::from(enc.0.u[..].ct_eq(u) & v_eq) && coeffs_ok(&ct) {
            Ok(ct)
        } else {
            Err(Error::Argument)
        }
    }
}

/// A credit by its sender's P (§4.14.4 steps 1–6), `holder` the key at the holder's leg (the handle's `pk`, or a quorum member's
/// record of the quorum's): `Some(u_{g(j)} ‖ v_j)` when `pqz_ffi::precompile` accepts the rebuilt statement, `None` when a check
/// fails; `Argument` when the credit lacks P's fields.
fn by_proof(holder: &[u8], o: &Open, rec: &Record, c: &Credit, slot: &Slot, blobs: &mut Blobs) -> Result<Option<Vec<u8>>> {
    let (Some(window), Some(keys), Some(proof)) = (&c.sender_pending, &c.key_records, &c.proof) else { return Err(Error::Argument) };
    if c.header.is_none() && c.call.is_none() {
        return Err(Error::Argument);
    }
    Ok(verified(holder, o, rec, c, slot, window, keys, proof, blobs).ok())
}

/// The key of `(ua, v)` from a credit's `keyRecords` (its code in the request's blobs).
fn key_of(keys: &[(Word, u64, Word)], blobs: &mut Blobs, ua: &Word, v: u64) -> Result<Vec<u8>> {
    let (_, _, w) = keys.iter().find(|(u, x, _)| u == ua && *x == v).ok_or(Error::Argument)?;
    registered_key(w, blobs)
}

#[allow(clippy::too_many_arguments)]
fn verified(
    holder: &[u8], o: &Open, rec: &Record, c: &Credit, slot: &Slot, window: &[(u64, Word)], keys: &[(Word, u64, Word)], proof: &[u8],
    blobs: &mut Blobs,
) -> Result<Vec<u8>> {
    // the record's mode names where P is: LOG an event's header, NONE the call
    if (rec.proof_store == 1) != c.header.is_some() {
        return Err(Error::Argument);
    }
    let d = blobs.data(&slot.ptr)?.to_vec();
    let l = leg(&d, c.multi, &o.ua, o.v, slot)?;
    let ct = load(&d, l.u_off, l.v_off)?;
    if !coeffs_ok(&ct) {
        return Err(Error::Argument);
    }
    // step 2: `T_k`
    let t = t_k(rec, window, blobs)?;
    // step 3: the keys, the holder's leg its own `pk`, never a source's
    let pk_f = key_of(keys, blobs, &c.from_ua, rec.key_version)?;
    let (m, aud) = (l.e.m, l.e.aud);
    let mut pks = Vec::with_capacity(m);
    for j in 0..m {
        pks.push(if j == l.j { holder.to_vec() } else { key_of(keys, blobs, &l.e.owner(j)?, *l.t.kv.get(j).ok_or(Error::Argument)?)? });
    }
    let pk_a = if aud { Some(key_of(keys, blobs, &o.auditor_ua, *l.t.kv.get(m).ok_or(Error::Argument)?)?) } else { None };
    // step 4: the header, the event's (LOG) or built from the call (NONE)
    let hd = match (&c.header, &c.call) {
        (Some(h), _) => *h,
        (None, Some(call)) => transfer_header(o, rec, &c.from_ua, c.k, c.multi, call, &l.t, &l.e)?,
        _ => return Err(Error::Argument),
    };
    // steps 5 and 6
    transfer_proven(o, rec, &c.from_ua, c.k, c.multi, hd, &pk_f, &pks, pk_a.as_deref(), &t, &d, &l.t, &l.e, proof)?;
    Ok(ct)
}

/// A transfer debit's statement (op 1 / op 7, §4.14.4 steps 4–6) from its header `hd`, keys, `T_k` and op blob `d`, verified: the
/// words the facade knows must be the header's, the keys pairwise distinct (`KeyReused`), `pqz_ffi::precompile` must accept it.
#[allow(clippy::too_many_arguments)]
fn transfer_proven(
    o: &Open, rec: &Record, from: &Word, k: u64, multi: bool, hd: [Word; 20], pk_f: &[u8], pks: &[Vec<u8>], pk_a: Option<&[u8]>,
    t: &[u8], d: &[u8], tl: &Tail, e: &Entry, proof: &[u8],
) -> Result<()> {
    let (m, aud, r) = (e.m, e.aud, &e.r);
    distinct(&std::iter::once(pk_f).chain(pks.iter().map(|k| &k[..])).chain(pk_a).collect::<Vec<_>>())?;
    let op_tag = if multi { OP_TAG_TRANSFER_MULTI } else if aud { Form::Transfer.op_tag() } else { Form::Transfer0.op_tag() };
    known(o, &hd, &op_tag, from, k, rec)?;
    let v_f = part(d, tl.r_len, VP)?;
    let stmt = if multi {
        let us = (0..e.g).map(|g| part(r, 16 + PKP * g, PKP)).collect::<Result<Vec<_>>>()?.concat();
        let vs = (0..m).map(|j| part(r, e.leg_at(j), VP)).collect::<Result<Vec<_>>>()?.concat();
        let v_as = if aud { Some((0..m).map(|j| part(r, e.leg_at(j) + VP, VP)).collect::<Result<Vec<_>>>()?.concat()) } else { None };
        let pks = pks.concat();
        Multi { header: hd, m, pk_f, pks: &pks, pk_a, t, us: &us, vs: &vs, v_f: &v_f, v_as: v_as.as_deref() }.encode()
    } else {
        let (u, v_t) = (part(r, 16, PKP)?, part(r, 16 + PKP, VP)?);
        let v_a = if aud { Some(part(r, 16 + PKP + VP, VP)?) } else { None };
        let form = if aud { Form::Transfer } else { Form::Transfer0 };
        let pk_t = pks.first().ok_or(Error::Argument)?;
        Stmt::Debit(Debit { form, header: hd, pk_f, pk_t: Some(pk_t), pk_a, t, u: &u, v_t: Some(&v_t), v_f: &v_f, v_a: v_a.as_deref() }).encode()
    }
    .map_err(|_| Error::Argument)?;
    verify_p(if multi { pqz_ffi::stmt::OP_TRANSFER_MULTI } else { Form::Transfer.op() }, &stmt, proof)
}

/// The header words the facade knows (§4.14.4 step 4): opTag, the build's id, the token's words, `fromUA`, `k`, the record's `p`
/// and `shieldIn`.
fn known(o: &Open, hd: &[Word; 20], op_tag: &Word, from: &Word, k: u64, rec: &Record) -> Result<()> {
    for (i, w) in [
        (H_OPTAG, *op_tag),
        (H_ID, o.id),
        (H_CHAIN_ID, u64_word(o.chain_id)),
        (H_TOKEN, addr(&o.token)),
        (H_REGISTRY, addr(&o.registry)),
        (H_FROM, *from),
        (H_SEND_COUNTER, u64_word(k)),
        (H_P, u64_word(rec.p)),
        (H_PLAIN_USED, u64_word(rec.shield_in)),
        (H_CHAIN_UID, o.chain_uid),
    ] {
        if hd.get(i) != Some(&w) {
            return Err(Error::Argument);
        }
    }
    Ok(())
}

/// `pqz_ffi::precompile` (the chain's own function, panics caught) over `op ‖ statement ‖ proof` answers `…01`.
fn verify_p(op: u8, stmt: &[u8], proof: &[u8]) -> Result<()> {
    #[cfg(feature = "vectors")]
    VERIFIES.with(|n| n.set(n.get() + 1));
    if pqz_ffi::precompile(&pqz_ffi::stmt::input(op, stmt, proof)) != Ok(pqz_ffi::VALID) {
        return Err(Error::Argument);
    }
    Ok(())
}

/// A NONE transfer's header (§4.14.4 step 4, op 1 and op 7): the call's words, the record's `p` and `shieldIn`, the debit's
/// `fromUA` and `k`, the token's words, the blob's `salt`, `toUA` or `recipientsHash`, `M` and `auditorOn`; the envelope
/// binding of the call's mode and `memoHash = keccak256(memo ‖ ownTag_s)`.
#[allow(clippy::too_many_arguments)]
fn transfer_header(o: &Open, rec: &Record, from: &Word, k: u64, multi: bool, call: &Call, tl: &Tail, e: &Entry) -> Result<[Word; 20]> {
    let (r, m, aud) = (&e.r, e.m, e.aud);
    let salt = r.get(..16).ok_or(Error::Argument)?;
    let memo = match (&call.sealed_memo, call.mode) {
        (Some(s), Mode::Hash) if s.len() + 16 == pqz_ffi::memo::memo_len(m) => [salt, s].concat(),
        (None, Mode::Bundle) => Vec::new(),
        _ => return Err(Error::Argument),
    };
    let mut hd = header_of(o, rec, from, k, call.beneficiary_ua, call.fee, call.valid_until_block, bind_mode(&call.binding, call.mode))
        .fill(if multi { Multi::header(&o.id, m, aud) } else { Debit::header(if aud { Form::Transfer } else { Form::Transfer0 }, &o.id) });
    let to = if multi { crate::keccak256(&(0..m).map(|j| e.owner(j)).collect::<Result<Vec<_>>>()?.concat()) } else { e.owner(0)? };
    *hd.get_mut(H_TO).ok_or(Error::Argument)? = to;
    hd.get_mut(H_SALT).ok_or(Error::Argument)?.iter_mut().skip(16).zip(salt).for_each(|(x, b)| *x = *b);
    *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = crate::keccak256(&[&memo[..], &tl.own_tag[..]].concat());
    Ok(hd)
}

/// The header words a NONE debit's call and record give, before the form's.
#[allow(clippy::too_many_arguments)]
fn header_of(o: &Open, rec: &Record, from: &Word, k: u64, beneficiary_ua: Word, fee: u64, valid_until_block: u64, env: Word) -> Header {
    Header {
        chain_id: o.chain_id,
        token: o.token,
        registry: o.registry,
        from_ua: *from,
        beneficiary_ua,
        fee,
        send_counter: k,
        p: rec.p,
        valid_until_block,
        plain_used: rec.shield_in,
        chain_uid: o.chain_uid,
        envelope_binding: env,
    }
}

/// A proof-path debit's form fields (§4.14.2: those of `proveTransfer`, `proveTransferMulti`, `proveBurn`, `proveRefresh`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DebitForm {
    Transfer { to_ua: Word, pk_t: Vec<u8>, pk_a: Option<Vec<u8>>, amount: u64, mode: Mode },
    Multi { legs: Vec<(Vec<u8>, Word, u64)>, pk_a: Option<Vec<u8>>, mode: Mode },
    Burn { amount: u64, recipient: Word },
    Refresh,
}

/// A proof-path debit's caller fields; `T`, `p`, `sendCounter` and the location come from the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DebitArgs {
    form: DebitForm,
    chain_id: u64,
    registry: [u8; 20],
    beneficiary_ua: Word,
    fee: u64,
    valid_until_block: u64,
    shield_in: u64,
    envelope_binding: Word,
}

/// The fields of `prove*Proven` (`cmd`), typed.
pub(super) fn debit_args(cmd: &str, f: &Fields<'_>) -> Result<DebitArgs> {
    let form = match cmd {
        "proveTransferProven" => DebitForm::Transfer {
            to_ua: f.word("toUA")?,
            pk_t: f.pk("pkT")?,
            pk_a: f.opt_pk("pkA")?,
            amount: f.u64("amount")?,
            mode: f.mode()?,
        },
        "proveTransferMultiProven" => DebitForm::Multi { legs: f.legs()?, pk_a: f.opt_pk("pkA")?, mode: f.mode()? },
        "proveBurnProven" => DebitForm::Burn { amount: f.u64("amount")?, recipient: f.word("recipient")? },
        "proveRefreshProven" => DebitForm::Refresh,
        _ => return Err(Error::Argument),
    };
    Ok(DebitArgs {
        form,
        chain_id: f.u64("chainId")?,
        registry: f.arr("registry")?,
        beneficiary_ua: f.opt_word("beneficiaryUA")?,
        fee: f.u64("fee")?,
        valid_until_block: f.u64("validUntilBlock")?,
        shield_in: f.u64("shieldIn")?,
        envelope_binding: f.word("envelopeBinding")?,
    })
}

impl PqzKey {
    /// `prove*Proven` (§4.14.2, T20d5, C-PP-3): the debit of path (A)'s builder over the session's `T` (every `need` index
    /// accepted, plus `Trivial(shieldIn)`), its `p`, `sendCounter` and location; the materialised `acc` cross-checked against
    /// the parts below `rolled` (without one, `rolled == p_last`); group 3g's rules and the distinct keys as path (A). Path (A)'s
    /// output with `ownTag`; the session closes.
    pub(super) fn proven_debit(&self, sid: &[u8; 16], a: &DebitArgs, d: &Draw) -> Result<Value> {
        let mut g = self.session()?;
        let out = {
            let s = g.as_ref().filter(|s| s.id == *sid).ok_or(Error::Argument)?;
            let o = &s.open;
            let multi = matches!(a.form, DebitForm::Multi { .. });
            if !o.need.keys().all(|i| s.accepted.contains(i)) || o.op7 != multi || (a.chain_id, a.registry) != (o.chain_id, o.registry) {
                return Err(Error::Argument);
            }
            let cached = match &o.acc {
                Some(acc) => acc.chunks_exact(8).map(|c| c.iter().fold(0u64, |x, y| x << 8 | u64::from(*y))).eq(s.below.iter().copied()),
                None => o.rolled == o.p_last,
            };
            if !cached {
                return Err(Error::Argument);
            }
            let mut t = s.sum.clone();
            add_trivial_mod(&mut t, a.shield_in);
            let t: Vec<u8> = t.iter().flat_map(|x| x.to_be_bytes()).collect();
            let h = Header {
                chain_id: o.chain_id,
                token: o.token,
                registry: o.registry,
                from_ua: o.ua,
                beneficiary_ua: a.beneficiary_ua,
                fee: a.fee,
                send_counter: o.send_counter,
                p: o.p,
                valid_until_block: a.valid_until_block,
                plain_used: a.shield_in,
                chain_uid: o.chain_uid,
                envelope_binding: a.envelope_binding,
            };
            let id = &o.id;
            let v = match &a.form {
                // KV-8 / KV-9: a stale version only migrates to its own UA, the current one never pays itself
                DebitForm::Transfer { to_ua, pk_t, pk_a, amount, mode } => {
                    if o.stale != (*to_ua == o.ua) {
                        return Err(Error::Argument);
                    }
                    distinct(&[Some(&self.pk[..]), Some(&pk_t[..]), pk_a.as_deref()].into_iter().flatten().collect::<Vec<_>>())?;
                    self.with_sk(|seed32, sk| {
                        self.transfer(seed32, sk, d, id, &h, to_ua, pk_t, pk_a.as_deref(), &t, *amount, &Memo::Mode(*mode))
                    })?
                }
                DebitForm::Multi { legs, pk_a, mode } => {
                    if o.stale {
                        return Err(Error::Argument);
                    }
                    let keys = std::iter::once(&self.pk[..]).chain(legs.iter().map(|l| &l.0[..])).chain(pk_a.as_deref());
                    distinct(&keys.collect::<Vec<_>>())?;
                    self.with_sk(|seed32, sk| self.multi(seed32, sk, d, id, &h, legs, pk_a.as_deref(), &t, *mode, None))?
                }
                DebitForm::Burn { amount, recipient } => {
                    if o.stale {
                        return Err(Error::Argument); // KV-8: a stale version burns nothing (its refresh is `proveRefreshProven`)
                    }
                    let mut hd = h.fill(Debit::header(Form::Burn, id));
                    *hd.get_mut(H_AMOUNT).ok_or(Error::Argument)? = u64_word(*amount);
                    *hd.get_mut(H_RECIPIENT).ok_or(Error::Argument)? = *recipient;
                    self.with_sk(|seed32, sk| self.debit_own(seed32, sk, d, Form::Burn, hd, &t, amount.checked_add(h.fee), None))?
                }
                DebitForm::Refresh => self.with_sk(|seed32, sk| {
                    self.debit_own(seed32, sk, d, Form::Refresh, h.fill(Debit::header(Form::Refresh, id)), &t, Some(h.fee), None)
                })?,
            };
            with_p(v, &h)
        };
        *g = None;
        Ok(out)
    }
}

// ------------------------------------------------------------------------------------------------------------------------------
// The MPC quorum's check (no-oracle spec §4.14.8; T20d7, C-PP-6): keyless, no handle. A member runs it before any partial
// decryption: the quorum's own last debit and every credit since, each by its P, at the quorum's leg the member's own record
// of the quorum's key (its DKG record), never a source's.
// ------------------------------------------------------------------------------------------------------------------------------

/// The forms of the quorum's own last debit (§4.14.4's `form`, its `own` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OwnForm {
    Transfer,
    Multi,
    Burn,
    Refresh,
    Unwrap,
}

/// A NONE burn, refresh or unwrap call (§4.14.4 step 4): `binding` 0 direct, else the relayed envelope's; an unwrap's
/// `underlying` and `minOut`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BurnCall {
    beneficiary_ua: Word,
    fee: u64,
    amount: u64,
    recipient: Word,
    valid_until_block: u64,
    binding: Word,
    unwrap: Option<([u8; 20], u64)>,
}

/// The quorum's own last debit (`own`): `(fromUA, k)` is `(ua, lastDebit − 1)` and its record `lastRecord`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OwnDebit {
    form: OwnForm,
    sender_pending: Vec<(u64, Word)>,
    key_records: Vec<(Word, u64, Word)>,
    proof: Vec<u8>,
    header: Option<[Word; 20]>,
    call: Option<Call>,
    burn_call: Option<BurnCall>,
}

/// `checkProven`'s request: the account's words (no key word of the quorum), `pk`, `own`, the codes and the credits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Check {
    open: Open,
    pk: Vec<u8>,
    own: Option<OwnDebit>,
    codes: Codes,
    credits: Vec<Credit>,
}

/// `{index, word}` entries.
fn entries(l: &[Value]) -> Result<Vec<(u64, Word)>> {
    if l.len() > K_MAX {
        return Err(Error::Argument);
    }
    l.iter()
        .map(|e| {
            let e = Fields::new(e.as_object().ok_or(Error::Argument)?, &["index", "word"])?;
            Ok((e.u64("index")?, e.word("word")?))
        })
        .collect()
}

/// `{ua, version, word}` entries.
fn key_records(l: &[Value]) -> Result<Vec<(Word, u64, Word)>> {
    if l.len() > KEY_RECORDS_MAX {
        return Err(Error::Argument);
    }
    l.iter()
        .map(|e| {
            let e = Fields::new(e.as_object().ok_or(Error::Argument)?, &["ua", "version", "word"])?;
            Ok((e.word("ua")?, e.u64("version")?, e.word("word")?))
        })
        .collect()
}

/// `own`'s fields: `{form, senderPending, keyRecords, proof, header | call}`.
fn own_debit(v: &Value) -> Result<OwnDebit> {
    let f = Fields::new(v.as_object().ok_or(Error::Argument)?, &["form", "senderPending", "keyRecords", "proof", "header", "call"])?;
    let form = match f.get("form")?.as_str() {
        Some("transfer") => OwnForm::Transfer,
        Some("transferMulti") => OwnForm::Multi,
        Some("burn") => OwnForm::Burn,
        Some("refresh") => OwnForm::Refresh,
        Some("unwrap") => OwnForm::Unwrap,
        _ => return Err(Error::Argument),
    };
    let header: Option<[Word; 20]> = f.has("header").then(|| f.words("header")?.try_into().map_err(|_| Error::Argument)).transpose()?;
    let (call, burn_call) = match (f.has("call"), form) {
        (false, _) => (None, None),
        (true, OwnForm::Transfer | OwnForm::Multi) => (Some(call(f.get("call")?)?), None),
        (true, _) => (None, Some(burn_call(f.get("call")?, form == OwnForm::Unwrap)?)),
    };
    if header.is_some() == f.has("call") {
        return Err(Error::Argument);
    }
    Ok(OwnDebit {
        form,
        sender_pending: entries(f.list("senderPending")?)?,
        key_records: key_records(f.list("keyRecords")?)?,
        proof: f.bytes("proof")?,
        header,
        call,
        burn_call,
    })
}

/// A burn, refresh or unwrap call: `{beneficiaryUA?, fee, amount, recipient, validUntilBlock, binding}`, an unwrap's
/// `underlying` and `minOut` too.
fn burn_call(v: &Value, unwrap: bool) -> Result<BurnCall> {
    let mut list = vec!["beneficiaryUA", "fee", "amount", "recipient", "validUntilBlock", "binding"];
    if unwrap {
        list.extend(["underlying", "minOut"]);
    }
    let c = Fields::new(v.as_object().ok_or(Error::Argument)?, &list)?;
    Ok(BurnCall {
        beneficiary_ua: c.opt_word("beneficiaryUA")?,
        fee: c.u64("fee")?,
        amount: c.u64("amount")?,
        recipient: c.word("recipient")?,
        valid_until_block: c.u64("validUntilBlock")?,
        binding: c.word("binding")?,
        unwrap: if unwrap { Some((c.arr("underlying")?, c.u64("minOut")?)) } else { None },
    })
}

/// `checkProven`'s request, typed (no key word of the quorum: the allow-list has no `keyRecord`; `pk` the member's record).
pub(super) fn check_request(f: &Fields<'_>) -> Result<Check> {
    let mut blobs = Blobs::new(f)?;
    let open = open_words(f, &mut blobs)?;
    let pk = f.pk("pk")?;
    let own = match (open.own.is_some(), f.has("own")) {
        (true, true) => Some(own_debit(f.get("own")?)?),
        (false, false) => None,
        _ => return Err(Error::Argument),
    };
    let (codes, credits) = credits(f)?;
    Ok(Check { open, pk, own, codes, credits })
}

/// `checkProven` (§4.14.8): every part by its P with the member's `pk` at the quorum's leg and as its own debit's `pk_f`; any
/// failure, a key word of the quorum at the version checked among the `keyRecords`, or a credit outside the window or given twice
/// is `Argument` (no parts). `{parts, sum}`: the parts' indexes and kinds and the stored form of their sum mod `q`, which the
/// member's MPC step (later) opens; TRIVIAL entries are public amounts and not in it. It decrypts nothing and uses no key.
pub(super) fn check(c: &Check) -> Result<Value> {
    let o = &c.open;
    let mut blobs = Blobs(c.codes.iter().map(|(a, d)| (*a, d.clone(), false)).collect());
    // Fable P1-1: the source names no key the check certifies against
    let ours = |k: &[(Word, u64, Word)]| k.iter().any(|(u, v, _)| *u == o.ua && *v == o.v);
    if c.own.as_ref().is_some_and(|w| ours(&w.key_records)) || c.credits.iter().any(|x| x.key_records.as_deref().is_some_and(ours)) {
        return Err(Error::Argument);
    }
    let mut sum = vec![0u64; CT_BYTES / 8];
    let mut parts = Vec::new();
    if let (Some(w), Some((k, _, ct)), Some(rec)) = (&c.own, &o.own, &o.last) {
        own_proven(&c.pk, o, rec, *k, w, &mut blobs)?;
        add_mod(&mut sum, ct);
        parts.push(json!({"index": null, "kind": Kind::Own.name()}));
    }
    let mut seen = BTreeSet::new();
    for x in &c.credits {
        let slot = o.need.get(&x.index).filter(|_| seen.insert(x.index)).ok_or(Error::Argument)?;
        let rec = record(&x.record.0, &x.record.1, x.k)?;
        let ct = by_proof(&c.pk, o, &rec, x, slot, &mut blobs)?.ok_or(Error::Argument)?;
        add_mod(&mut sum, &ct);
        let kind = if x.from_ua == o.ua && rec.key_version < o.v { Kind::Migration } else { Kind::Credit };
        parts.push(json!({"index": x.index, "kind": kind.name()}));
    }
    let lanes: Vec<u8> = sum.iter().flat_map(|x| x.to_be_bytes()).collect();
    let packed = crate::facade::pqz_pack::pack(&lanes).ok_or(Error::Argument)?;
    Ok(json!({"parts": parts, "sum": to_hex(&packed)}))
}

/// The quorum's own last debit `(ua, k)` by its P (§4.14.8): its statement rebuilt as §4.14.4 with `pk_f` the member's `pk`,
/// `T` by §2.3; no tag (no seed). A transfer's keys from `keyRecords` by the tail's `kv`; a burn, refresh or unwrap has none.
fn own_proven(pk: &[u8], o: &Open, rec: &Record, k: u64, w: &OwnDebit, blobs: &mut Blobs) -> Result<()> {
    if (rec.proof_store == 1) != w.header.is_some() {
        return Err(Error::Argument);
    }
    let d = blobs.data(&o.acc_blob)?.to_vec();
    let t = t_k(rec, &w.sender_pending, blobs)?;
    match w.form {
        OwnForm::Transfer | OwnForm::Multi => {
            let multi = w.form == OwnForm::Multi;
            let (tl, e) = shape(&d)?;
            if !multi && e.m != 1 {
                return Err(Error::Argument);
            }
            let pks = (0..e.m).map(|j| key_of(&w.key_records, blobs, &e.owner(j)?, *tl.kv.get(j).ok_or(Error::Argument)?)).collect::<Result<Vec<_>>>()?;
            let pk_a = if e.aud { Some(key_of(&w.key_records, blobs, &o.auditor_ua, *tl.kv.get(e.m).ok_or(Error::Argument)?)?) } else { None };
            let hd = match (&w.header, &w.call) {
                (Some(h), _) => *h,
                (None, Some(call)) => transfer_header(o, rec, &o.ua, k, multi, call, &tl, &e)?,
                _ => return Err(Error::Argument),
            };
            transfer_proven(o, rec, &o.ua, k, multi, hd, pk, &pks, pk_a.as_deref(), &t, &d, &tl, &e, &w.proof)
        }
        OwnForm::Burn | OwnForm::Refresh | OwnForm::Unwrap => {
            let tl = tail(&d)?;
            if tl.r_len != PKP || !tl.kv.is_empty() {
                return Err(Error::Argument);
            }
            let form = if w.form == OwnForm::Refresh { Form::Refresh } else { Form::Burn };
            let hd = match (&w.header, &w.burn_call) {
                (Some(h), _) => *h,
                (None, Some(bc)) => burn_header(o, rec, k, w.form, bc, &tl)?,
                _ => return Err(Error::Argument),
            };
            known(o, &hd, &form.op_tag(), &o.ua, k, rec)?;
            let (u, v_f) = (part(&d, 0, PKP)?, part(&d, PKP, VP)?);
            let stmt = Stmt::Debit(Debit { form, header: hd, pk_f: pk, pk_t: None, pk_a: None, t: &t, u: &u, v_t: None, v_f: &v_f, v_a: None })
                .encode()
                .map_err(|_| Error::Argument)?;
            verify_p(form.op(), &stmt, &w.proof)
        }
    }
}

/// A NONE burn, refresh or unwrap header (§4.14.4 step 4, `PqzCore.prepareBurn`, `WrappedPqzToken._envUnwrap`): opTag REFRESH
/// when `amount = 0`, else BURN (a refresh's amount is 0, a burn's and an unwrap's not); `envelopeBinding` the call's `binding`
/// (burn, refresh) or `unwrapBinding(underlying, minOut)`, relayed `keccak256(abi.encode(binding, unwrapBinding))`; `memoHash
/// = keccak256(ownTag)`.
fn burn_header(o: &Open, rec: &Record, k: u64, form: OwnForm, bc: &BurnCall, tl: &Tail) -> Result<[Word; 20]> {
    let env = match (form, &bc.unwrap) {
        (OwnForm::Unwrap, Some((underlying, min_out))) => {
            let w = crate::keccak256(&[crate::keccak256(b"SCAAS-PQZ-UNWRAP-V1"), addr(underlying), u64_word(*min_out)].concat());
            if bc.binding == [0; 32] { w } else { crate::keccak256(&[bc.binding, w].concat()) }
        }
        (OwnForm::Burn | OwnForm::Refresh, None) => bc.binding,
        _ => return Err(Error::Argument),
    };
    if (form == OwnForm::Refresh) != (bc.amount == 0) {
        return Err(Error::Argument);
    }
    let f = if bc.amount == 0 { Form::Refresh } else { Form::Burn };
    let mut hd = header_of(o, rec, &o.ua, k, bc.beneficiary_ua, bc.fee, bc.valid_until_block, env).fill(Debit::header(f, &o.id));
    *hd.get_mut(H_AMOUNT).ok_or(Error::Argument)? = u64_word(bc.amount);
    *hd.get_mut(H_RECIPIENT).ok_or(Error::Argument)? = bc.recipient;
    *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = crate::keccak256(&tl.own_tag);
    Ok(hd)
}
