// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Tokens (spec §8.2): the profile's reviewed list and, on request, the factory's contract index (CTR-TOK-27, class 1 `TOKEN`)
//! read at one block; metadata (`name`, `symbol`, `decimals`, `chainUid()`) read once per session. A token whose `chainUid()`
//! is not the profile's is `ProfileMismatch`; an unlisted token's `name` and `symbol` are cut to 64 bytes and stripped of
//! control and format characters (`crate::text::hidden`, owner 2026-11-18 Q2), and its display carries the mark.
use super::Wallet;
use crate::op::{addr20, evm, hex};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{BlockChoice, ReadAt, ReadError};
use scaas_rpc::Purpose;
use std::sync::PoisonError;

/// A token as the wallet shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// `0x` + 40 hex, lower case
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    /// on the profile's reviewed list
    pub listed: bool,
    /// what a screen shows: the symbol, with `[unlisted]` before an unlisted one's
    pub display: String,
}

/// An unlisted token's text: control and format characters stripped, at most 64 bytes (cut at a character boundary).
pub(crate) fn sanitise(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !crate::text::hidden(*c)) {
        if out.len() + c.len_utf8() > 64 {
            break;
        }
        out.push(c);
    }
    out
}

/// The factory's class of tokens (CTR-TOK-27).
const TOKEN_CLASS: u16 = 1;
/// `contractsPage`'s `MAX_PAGE`.
const PAGE: u64 = 100;
/// The most index records read (bounded: an untrusted list).
const INDEX_MAX: u64 = 1_000;

pub(crate) fn selector(sig: &str) -> Vec<u8> {
    scaas_ua::keccak256(sig.as_bytes())
        .get(..4)
        .unwrap_or_default()
        .to_vec()
}

pub(crate) fn word(b: &[u8], i: usize) -> Result<&[u8], SdkError> {
    b.get(i * 32..i * 32 + 32).ok_or(SdkError::Argument)
}

pub(crate) fn small(w: &[u8]) -> Result<u64, SdkError> {
    let (hi, lo) = w.split_at(24);
    if hi.iter().any(|b| *b != 0) {
        return Err(SdkError::Argument);
    }
    Ok(lo.iter().fold(0u64, |a, b| a << 8 | u64::from(*b)))
}

/// The ABI `string` whose offset is head word `i` of a return value, at most 256 bytes read.
pub(crate) fn abi_string(b: &[u8], i: usize) -> Result<String, SdkError> {
    let off = usize::try_from(small(word(b, i)?)?).map_err(|_| SdkError::Argument)?;
    let len = usize::try_from(small(b.get(off..off + 32).ok_or(SdkError::Argument)?)?)
        .map_err(|_| SdkError::Argument)?;
    let s = b
        .get(off + 32..off + 32 + len.min(256))
        .ok_or(SdkError::Argument)?;
    Ok(String::from_utf8_lossy(s).into_owned())
}

/// `contract.f()` at the read's block.
async fn call(
    pool: &EvmPool,
    at: &ReadAt<alloy::primitives::B256>,
    contract: Address,
    data: Vec<u8>,
) -> Result<Bytes, ReadError> {
    pool.call_at(at, contract, Bytes::from(data)).await
}

fn bad(at: &ReadAt<alloy::primitives::B256>) -> ReadError {
    ReadError::Failure(scaas_rpc::EndpointFailure::new(
        at.endpoint,
        scaas_rpc::FailureKind::AnswerMalformed,
        "a token view's answer",
    ))
}

/// The metadata of `token` at one block: `(name, symbol, decimals, chainUid)`.
async fn metadata(
    pool: &EvmPool,
    token: Address,
) -> Result<(String, String, u8, Vec<u8>), SdkError> {
    let a = pool
        .read_at_block(BlockChoice::default(), Purpose::Plain, |at| async move {
            let name = call(pool, &at, token, selector("name()")).await?;
            let symbol = call(pool, &at, token, selector("symbol()")).await?;
            let decimals = call(pool, &at, token, selector("decimals()")).await?;
            let uid = call(pool, &at, token, selector("chainUid()")).await?;
            let s = |b: &Bytes| abi_string(b, 0).map_err(|_| bad(&at));
            let d = word(&decimals, 0).and_then(small).map_err(|_| bad(&at))?;
            Ok((
                s(&name)?,
                s(&symbol)?,
                u8::try_from(d).map_err(|_| bad(&at))?,
                uid.to_vec(),
            ))
        })
        .await?;
    Ok(a.value)
}

/// `token` on `chain`, from the session's cache or read once: `ProfileMismatch` when its `chainUid()` is not the profile's.
pub(crate) async fn token(sdk: &Sdk, chain: &str, token: &str) -> Result<TokenInfo, SdkError> {
    let address = hex(&addr20(&token.to_ascii_lowercase())?);
    let key = (chain.to_string(), address.clone());
    if let Some(t) = sdk
        .tokens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
    {
        return Ok(t.clone());
    }
    let (profile, _, pool) = evm(sdk, chain)?;
    let (name, symbol, decimals, uid) =
        metadata(&pool, address.parse().map_err(|_| SdkError::Argument)?).await?;
    if hex(&uid) != profile.chain_uid.to_ascii_lowercase() {
        return Err(SdkError::ProfileMismatch);
    }
    let listed = profile
        .tokens
        .iter()
        .find(|l| l.address.eq_ignore_ascii_case(&address));
    let info = match listed {
        // a listed token shows the profile's reviewed symbol and decimals
        Some(l) => TokenInfo {
            address,
            name: sanitise(&name),
            symbol: l.symbol.clone(),
            decimals: l.decimals,
            listed: true,
            display: l.symbol.clone(),
        },
        None => {
            let symbol = sanitise(&symbol);
            TokenInfo {
                address,
                name: sanitise(&name),
                display: format!("[unlisted] {symbol}"),
                symbol,
                decimals,
                listed: false,
            }
        }
    };
    sdk.tokens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, info.clone());
    Ok(info)
}

/// The factory's token index at one block (CTR-TOK-27), at most [`INDEX_MAX`] records, paged by `MAX_PAGE`.
async fn index(pool: &EvmPool, factory: Address) -> Result<Vec<String>, SdkError> {
    let a = pool
        .read_at_block(BlockChoice::default(), Purpose::Plain, |at| async move {
            let page = |from: u64| {
                let mut d = selector("contractsPage(uint16,uint256,uint256)");
                d.extend_from_slice(&U256::from(TOKEN_CLASS).to_be_bytes::<32>());
                d.extend_from_slice(&U256::from(from).to_be_bytes::<32>());
                d.extend_from_slice(&U256::from(PAGE).to_be_bytes::<32>());
                d
            };
            let mut out = Vec::new();
            let mut from = 0u64;
            loop {
                let b = call(pool, &at, factory, page(from)).await?;
                let total = word(&b, 1).and_then(small).map_err(|_| bad(&at))?;
                let off = word(&b, 0).and_then(small).map_err(|_| bad(&at))? as usize / 32;
                let n = word(&b, off).and_then(small).map_err(|_| bad(&at))?;
                for i in 0..n.min(PAGE) {
                    let w = word(&b, off + 1 + (i as usize) * 7).map_err(|_| bad(&at))?;
                    out.push(hex(w.get(12..).ok_or_else(|| bad(&at))?));
                }
                from = from.saturating_add(n.min(PAGE));
                if n == 0 || from >= total.min(INDEX_MAX) {
                    break;
                }
            }
            Ok(out)
        })
        .await?;
    Ok(a.value)
}

impl Wallet {
    /// The profile's tokens and, with `with_index`, every token of the factory's index (unlisted unless on the list), each read
    /// once per session. `ChainUnknown`; `ProfileMismatch`: a token's `chainUid()` is not the profile's; `Argument`: the
    /// index asked of a profile without a factory.
    pub async fn tokens(
        &self,
        chain: String,
        with_index: bool,
    ) -> Result<Vec<TokenInfo>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (profile, _, pool) = evm(&sdk, &chain)?;
                let mut addrs: Vec<String> = profile
                    .tokens
                    .iter()
                    .map(|t| t.address.to_ascii_lowercase())
                    .collect();
                if with_index {
                    let f: Address = profile
                        .factory
                        .as_deref()
                        .and_then(|f| f.parse().ok())
                        .ok_or(SdkError::Argument)?;
                    for a in index(&pool, f).await? {
                        if !addrs.contains(&a) {
                            addrs.push(a);
                        }
                    }
                }
                let mut out = Vec::with_capacity(addrs.len());
                for a in &addrs {
                    out.push(token(&sdk, &chain, a).await?);
                }
                Ok(out)
            })
            .await
    }
}
