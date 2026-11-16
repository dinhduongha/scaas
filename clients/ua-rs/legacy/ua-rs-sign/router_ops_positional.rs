// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! LEGACY (not compiled): the positional form of the router ops' struct hashes as it stood at c5492adee (ua-rs-sign after the
//! T21 merges): `scaas_ua::regulated::{struct_hash, digest}` over `params: &[[u8; 32]]` (one ABI word per field, in order) and
//! `scaas_ua::admin::{struct_hash, digest}` over `&[Param]`, with `admin::chain_entries_hash` over nine positional words.
//! T21 L45 (Fable part 4 finding 7; owner 2026-11-16 "ok, L45 option (b)") replaced them with one typed struct per signed op
//! (named fields, `regulated::RouterOp`), digests byte-identical. Kept for reference, never deleted.

// ---- src/regulated.rs (uses its REGULATED_OPS, type_string, ENVELOPE, RouterOpError, Envelope)

/// `hashStruct(UA<Op>)` over `params` (one ABI word each, in order), `relayer` hashed as 0 unless `mode & 1`,
/// `feeRecipient` as 0 unless `mode & 2` (`MetaTxLib.canon`).
pub fn struct_hash(op: &str, e: &Envelope, target: &[u8; 20], params: &[[u8; 32]]) -> Result<[u8; 32], RouterOpError> {
    let list = params_of(op).ok_or(RouterOpError::UnknownOp)?;
    let types: Vec<&str> = list.split(',').map(|f| f.split_once(' ').map_or(f, |(t, _)| t)).collect();
    if types.len() != params.len() {
        return Err(RouterOpError::Params);
    }
    if types.iter().zip(params).any(|(t, w)| *t == "uint64" && w[..24] != [0; 24]) {
        return Err(RouterOpError::Range);
    }
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let mut words: Vec<[u8; 32]> = vec![keccak256(type_string(op).unwrap().as_bytes()), e.from, address_word(target)];
    words.extend_from_slice(params);
    words.extend([e.batch, e.nonce, e.valid_until, word(e.mode as u64), canon(e.mode & 1 != 0, &e.relayer), e.fee,
        canon(e.mode & 2 != 0, &e.fee_recipient)]);
    Ok(keccak(&words.iter().map(|w| &w[..]).collect::<Vec<_>>()))
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`: what the holder signs.
pub fn digest(op: &str, domain_separator: &[u8; 32], e: &Envelope, target: &[u8; 20], params: &[[u8; 32]])
    -> Result<[u8; 32], RouterOpError>
{
    Ok(keccak(&[&[0x19, 0x01], domain_separator, &struct_hash(op, e, target, params)?]))
}

// ---- src/admin.rs (uses its ADMIN_OPS, type_string, ENVELOPE, CHAIN_ENTRIES_TYPE, words_hash, env_hash, Env)

/// One param: a static field as its ABI word (`bytes4` left-aligned), a `string`, an array as its elements' words, an `Env`,
/// the nine words of a `ChainEntries` in its field order (CTR-GOV-27).
#[derive(Debug, Clone, Copy)]
pub enum Param<'a> {
    Word([u8; 32]),
    Text(&'a str),
    Words(&'a [[u8; 32]]),
    Env(&'a Env),
    ChainEntries(&'a [[u8; 32]; 9]),
}

/// A static word fits its type: `uintN` / `bool` / `address` with the high bytes 0, `bytes4` with the low 28.
fn fits(ty: &str, w: &[u8; 32]) -> bool {
    let high = |n: usize| w[..32 - n].iter().all(|b| *b == 0);
    match ty {
        "bytes32" | "uint256" => true,
        "bytes4" => w[4..].iter().all(|b| *b == 0),
        "address" => high(20),
        "bool" => high(1) && w[31] <= 1,
        t => t.strip_prefix("uint").and_then(|b| b.parse::<usize>().ok()).is_some_and(|b| high(b / 8)),
    }
}

/// `hashStruct(ChainEntries)`: its typehash and the nine words (an address field with its high 12 bytes 0).
pub fn chain_entries_hash(w: &[[u8; 32]; 9]) -> Result<[u8; 32], RouterOpError> {
    let ty: Vec<&str> = CHAIN_ENTRIES_TYPE[13..CHAIN_ENTRIES_TYPE.len() - 1].split(',').map(|f| f.split_once(' ').unwrap().0).collect();
    if !ty.iter().zip(w).all(|(t, x)| fits(t, x)) {
        return Err(RouterOpError::Range);
    }
    let mut words = vec![keccak256(CHAIN_ENTRIES_TYPE.as_bytes())];
    words.extend_from_slice(w);
    Ok(words_hash(&words))
}

/// `hashStruct(UA<Op>)` over `params` (one per field, in order, each of its field's shape), `relayer` hashed as 0 unless
/// `mode & 1`, `feeRecipient` as 0 unless `mode & 2` (`MetaTxLib.canon`).
pub fn struct_hash(op: &str, e: &Envelope, target: &[u8; 20], params: &[Param]) -> Result<[u8; 32], RouterOpError> {
    let list = params_of(op).ok_or(RouterOpError::UnknownOp)?;
    let types: Vec<&str> = list.split(',').filter(|f| !f.is_empty()).map(|f| f.split_once(' ').map_or(f, |(t, _)| t)).collect();
    if types.len() != params.len() {
        return Err(RouterOpError::Params);
    }
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let mut words: Vec<[u8; 32]> = vec![keccak256(type_string(op).unwrap().as_bytes()), e.from, address_word(target)];
    for (ty, p) in types.iter().zip(params) {
        words.push(match (ty.strip_suffix("[]"), p) {
            (None, Param::Word(w)) if *ty != "string" && *ty != "Env" && *ty != "ChainEntries" => {
                if fits(ty, w) { *w } else { return Err(RouterOpError::Range) }
            }
            (None, Param::ChainEntries(c)) if *ty == "ChainEntries" => chain_entries_hash(c)?,
            (None, Param::Text(s)) if *ty == "string" => keccak256(s.as_bytes()),
            (None, Param::Env(v)) if *ty == "Env" => env_hash(v),
            (Some(el), Param::Words(ws)) if ws.iter().all(|w| fits(el, w)) => words_hash(ws),
            (Some(_), Param::Words(_)) => return Err(RouterOpError::Range),
            _ => return Err(RouterOpError::Params),
        });
    }
    words.extend([e.batch, e.nonce, e.valid_until, word(e.mode as u64), canon(e.mode & 1 != 0, &e.relayer), e.fee,
        canon(e.mode & 2 != 0, &e.fee_recipient)]);
    Ok(words_hash(&words))
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`, the router's domain (`regulated::router_domain_separator`).
pub fn digest(op: &str, domain_separator: &[u8; 32], e: &Envelope, target: &[u8; 20], params: &[Param])
    -> Result<[u8; 32], RouterOpError>
{
    Ok(keccak(&[&[0x19, 0x01], domain_separator, &struct_hash(op, e, target, params)?]))
}
