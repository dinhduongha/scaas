// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! LEGACY (not compiled): the pre-3h `memoHash` of `scaas_ua::facade::pqz` as it stood at e9b39a2b (ua-rs-sign T15b, T15k):
//! op 1 and op 7 on `HASH` `keccak256(salt ‖ sealedMemo)`, on `BUNDLE` 0, burn and refresh 0, and no `ownTag`. Release 3h
//! (proof-path spec C3, C4) replaced it with `memoHash = keccak256(memo ‖ ownTag)` and the debit's `ownTag` (ua-rs-sign T20d2,
//! the owner's ruling 4 of T20d: ua-rs reads and writes release 3h only). Kept for reference, never deleted.

// `PqzKey::transfer` (op 1): the statement's `memoHash` word per `mode`
        let (memo_hash, sealed) = match memo {
            Memo::Mode(Mode::Hash) => {
                let m = pqz_ffi::memo::seal(d.memo_key(seed32), &hd, pk_a.is_some(), &[(amount, *to_ua)]).ok_or(Error::Argument)?;
                (crate::keccak256(&m), Some(m))
            }
            Memo::Mode(Mode::Bundle) => ([0; 32], None),
            #[cfg(feature = "vectors")]
            Memo::Given(w) => (*w, None),
        };
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = memo_hash;

// `PqzKey::multi` (op 7): the memo per `mode`, then the statement word
        let memo = match mode {
            Mode::Hash => Some(pqz_ffi::memo::seal(memo_key, &hd, aud, &memo_legs).ok_or(Error::Argument)?),
            Mode::Bundle => None,
        };
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = memo.as_deref().map_or([0; 32], crate::keccak256);

// `PqzKey::debit_own` (op 2: burn, refresh): the word as the request carried it, 0 from the words commands
    fn debit_own(&self, sk: &Sk, d: &Draw, form: Form, mut hd: [Word; 20], t: &[u8], debit: Option<u64>, memo_hash: &Word) -> Result<Value> {
        system(hd.get(1).ok_or(Error::Argument)?)?;
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = *memo_hash;
    // …
}

// `from_json`, the words commands `proveBurn` / `proveRefresh`
            (Req::Burn { id, h, amount: f.u64("amount")?, recipient: f.word("recipient")?, t: o.t, memo_hash: [0; 32] }, Some(o.key))
            (Req::Refresh { id, h, t: o.t, memo_hash: [0; 32] }, Some(o.key))

// tests/facade_pqz.rs (feature `vectors`, the raw op 7 form): the pre-3h rule's two tests, replaced by facade_pqz_state.rs's
// `multi_bundle_memo_hash_is_the_tags` and `multi_hash_memo_hash_matches_contract` (the words command, 3h's formula)
/// `PqzCore._parseMulti` on BUNDLE: no memo (`sealedMemo` empty) and `memoHash` 0. The facade's statement has word
/// `H_MEMO_HASH` 0, the answer no `memo`, and the proof verifies.
#[cfg(feature = "vectors")]
#[test]
fn multi_bundle_memo_hash_is_zero() {
    unlock();
    let w = wallet();
    let (a, b) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap());
    let p = call(&a, "rawProveTransferMulti", &multi_req(&a, &b, "BUNDLE")).unwrap();
    let stmt = h(&p["stmt"]);
    assert!(verify(7, &stmt, &h(&p["proof"])));
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    assert_eq!(m.header[st::H_MEMO_HASH], [0; 32], "BUNDLE: memoHash 0");
    assert_eq!(p.get("memo"), None, "BUNDLE: no memo");
}

/// `PqzCore._parseMulti` on HASH: `memoHash = keccak256(abi.encodePacked(t.salt, t.sealedMemo))`, `salt` the header's
/// low 16 bytes and `sealedMemo` `2 + 40·M` bytes. The facade's `memo` is `salt ‖ sealedMemo`.
#[cfg(feature = "vectors")]
#[test]
fn multi_hash_memo_hash_matches_contract() {
    unlock();
    let w = wallet();
    let (a, b) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap());
    let p = call(&a, "rawProveTransferMulti", &multi_req(&a, &b, "HASH")).unwrap();
    let (stmt, memo) = (h(&p["stmt"]), h(&p["memo"]));
    assert!(verify(7, &stmt, &h(&p["proof"])));
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    let salt = &m.header[st::H_SALT][16..];
    let sealed = &memo[16..];
    assert_eq!((&memo[..16], sealed.len()), (salt, 2 + 40), "memo = salt ‖ sealedMemo");
    assert_eq!(m.header[st::H_MEMO_HASH], scaas_ua::keccak256(&[salt, sealed].concat()), "keccak256(salt ‖ sealedMemo)");
}

