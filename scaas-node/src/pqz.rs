// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Group 3f, PQZ verifier mode (spec 2026-11-06-attested-verify §11.1; NODE-JOB-22 draft): the node's side of a PQZ token's
//! `OFFCHAIN` mode. The node is open and **keyless** here: it relays a verdict, it never signs one.
//!
//! Every PQZ debit takes a `PqzSignedVerdict` last. On a `PRECOMPILE` token the node sends the empty one (the token never reads
//! it) and refuses a job naming `pqz_verdict` (`PQZ_VERDICT_NOT_EXPECTED`). On an `OFFCHAIN` token it REBUILDS the `PqzVerdict`
//! itself: the target, the chain id, `proofSystemId()`, the keccak of the statement the token's own view builds for the job's
//! named arguments and its envelope's binding, the keccak of the job's proof, and the verifier's epoch and `validUntil`; the
//! signature is the job's `pqz_verdict.auth` or the answer of the operator's `[pqz_verifier] endpoints` (in order, bounded in
//! time, bytes and `UASig` shape). A verdict at another epoch than `pqzVerifyConfig()`'s, or expiring within the margin, is
//! re-fetched once; none ⇒ `PQZ_VERDICT_MISSING`, zero sends. The precompile is never asked for (spec §3: OFFCHAIN ignores
//! whether one exists). With `refuse_shield_when_unserved`, a shield into an `OFFCHAIN` token whose verifier is revoked or
//! that no endpoint serves is `PQZ_VERIFIER_UNREACHABLE`. **UNAUDITED.**
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy::dyn_abi::DynSolValue as Val;
use alloy::primitives::{keccak256, Bytes, B256, U256};
use alloy::sol_types::SolValue;
use serde_json::{json, Map, Value};

use crate::abi::{IPqzToken, UAMetaTransaction, PQZ_OFFCHAIN};
use crate::chain::{Chain, SimError};
use crate::config::PqzVerifierCfg;
use crate::guard::Refusal;
use crate::submit::{now, Work};
use crate::typed::{self, PqzVerdictArgs, Row};

/// The PQZ verifier's route (spec §11.2).
const ROUTE: &str = "/v1/pqz-verdict";

/// Fable E N-7: an endpoint that did not answer (a timeout, a refused connection, a 5xx) is skipped for this long, so the lane's
/// single loop pays its `timeout_ms` once per window and endpoint, not once per job.
const ENDPOINT_BACKOFF: Duration = Duration::from_secs(10);

pub struct Verifier {
    cfg: PqzVerifierCfg,
    http: reqwest::Client,
    /// Endpoint index → until when it is skipped ([`ENDPOINT_BACKOFF`]).
    resting: Mutex<HashMap<usize, Instant>>,
    backoff: Duration,
}

/// The `pqzVerifyConfig()` of an `OFFCHAIN` token; `None` for a `PRECOMPILE` one or a contract without the view (no `OFFCHAIN`
/// token lacks it). A transport error is transient.
async fn offchain_config(chain: &Chain, token: alloy::primitives::Address) -> Result<Option<IPqzToken::PqzVerifyConfig>, Refusal> {
    match chain.call_view(token, IPqzToken::pqzVerifyConfigCall {}).await {
        Ok(c) if c.pqzVerifyMode == PQZ_OFFCHAIN => Ok(Some(c)),
        Ok(_) | Err(SimError::Revert(_)) => Ok(None),
        Err(SimError::Transport(e)) => Err(Refusal::Transport(format!("pqzVerifyConfig(): {e}"))),
    }
}

/// Group 3h (NODE-JOB-24): `w` is a PQZ debit (its estimate depends on the token's `proofStore()`).
pub fn is_debit(w: &Work) -> bool {
    debit_row(w).is_some()
}

/// The row of a PQZ debit (one taking the verdict last), `None` for any other work.
fn debit_row(w: &Work) -> Option<&'static Row> {
    w.typed.as_ref().filter(|t| t.contract == "pqz")?;
    let r = crate::guard::row(w.data.get(..4)?.try_into().ok()?, "pqz")?;
    typed::verdict_slot(r).map(|_| r)
}

/// The token's statement view of a PQZ debit row and its named inputs before `binding` (the forge artifact's ABI,
/// `tests::views_are_the_contracts`).
fn view_of(row: &str) -> Option<(String, &'static [&'static str])> {
    let (b, u) = (typed::abi_of("PqzBurnArgs"), typed::abi_of("Unwrap"));
    Some(match row {
        "UAPqzTransferSingle" | "UAPqzTransferSingleCompact" =>
            (format!("transferSingleStatement({},bytes32)", typed::abi_of("PqzTransferArgs")), &["args"]),
        "UAPqzTransfer" | "UAPqzTransferCompact" => (format!("transferStatement({},bytes32)", typed::abi_of("PqzMultiArgs")), &["args"]),
        "UAPqzUnshield" => (format!("burnStatement({b},uint256,bytes32,bytes32)"), &["args", "amount", "recipient"]),
        "UAPqzUnshieldUnwrap" => (format!("unshieldUnwrapStatement({b},{u},bytes32)"), &["args", "unwrap"]),
        _ => return None,
    })
}

/// The token's statement view of a PQZ debit row (its Solidity signature).
pub fn statement_view(row: &str) -> Option<String> {
    view_of(row).map(|v| v.0)
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

/// The statement the token's own view builds for debit `row`'s named arguments and its envelope's binding, and `op` as the
/// reference verifier reads it (scaas-pqz-verifier `Op`: `args`, `amount` / `recipient` or `unwrap`, `binding`; the sol types'
/// serde form, small uints as numbers). `None`: the view refused the op (its own refusal; the entry's simulation names it).
async fn statement_of(chain: &Chain, token: alloy::primitives::Address, row: &'static Row, vals: &[Val])
    -> Result<Option<(Bytes, Map<String, Value>)>, Refusal>
{
    let arg = |n: &str| typed::arg_of(row, vals, n).ok_or_else(|| Refusal::Policy(format!("BAD_PAYLOAD: no {n}")));
    let (word, num, at) = (|v: Val| v.as_fixed_bytes().map(|x| B256::from_slice(x.0)).unwrap_or_default(),
        |v: Val| v.as_uint().map(|x| x.0).unwrap_or_default(), |v: Val| v.as_address().unwrap_or_default());
    let m = UAMetaTransaction { from: word(arg("from")?.1), data: Bytes::new(), batch: num(arg("batch")?.1),
        nonce: num(arg("nonce")?.1), validUntil: num(arg("validUntil")?.1), mode: num(arg("mode")?.1).saturating_to(),
        relayer: at(arg("relayer")?.1), fee: num(arg("fee")?.1), feeRecipient: at(arg("feeRecipient")?.1) };
    let binding = chain.call_view(token, IPqzToken::envelopeBindingCall { m }).await.map_err(|e| match e {
        SimError::Transport(e) => Refusal::Transport(format!("envelopeBinding(): {e}")),
        SimError::Revert(e) => Refusal::Policy(format!("envelopeBinding(): {e}")),
    })?;
    let (sig, names) = view_of(row.name).expect("a debit row has a statement view");
    let (mut params, mut op) = (Vec::new(), Map::new());
    op.insert("entry".into(), json!(row.entry));
    for n in names {
        let (ty, v) = arg(n)?;
        op.insert(n.to_string(), typed::to_serde_json(&ty, &v));
        params.push(v);
    }
    op.insert("binding".into(), json!(format!("{binding:#x}")));
    params.push(Val::FixedBytes(binding, 32));
    let call = [&keccak256(sig.as_bytes())[..4], &Val::Tuple(params).abi_encode_sequence().unwrap_or_default()].concat();
    match chain.call_raw(token, call.into()).await {
        Ok(out) => Ok(Some((<Bytes as SolValue>::abi_decode(&out).map_err(|e| Refusal::Policy(format!("{sig}: decode: {e}")))?, op))),
        Err(SimError::Revert(_)) => Ok(None),
        Err(SimError::Transport(e)) => Err(Refusal::Transport(format!("{sig}: {e}"))),
    }
}

/// Round 3t (CTR-PQZ-36, Fable P3-4: one source): the job's proved fee word `p` against word 256 of `statement` (the token's
/// view). A mismatch is `PQZ_FEE_MISMATCH` with the word's three terms (`txFee` by the header's beneficiary word 224 and the
/// token's `confidentialFee()`, the verifier fee `vf` in force, `M·d` the rest), zero sends; `Transport`, so the lane keeps the
/// job in the queue until its deadline (a decrease may restore the word) and never reports it `dead`; the gateway answers 422.
pub async fn fee_check(chain: &Chain, token: alloy::primitives::Address, p: u64, statement: &[u8], vf: u64) -> Result<(), Refusal> {
    let w = |o: usize| statement.get(o..o + 32).map(U256::from_be_slice).unwrap_or_default();
    let e = w(256);
    if e == U256::from(p) {
        return Ok(());
    }
    let tx = if w(224).is_zero() { U256::ZERO } else {
        chain.call_view(token, IPqzToken::confidentialFeeCall {}).await.unwrap_or_default()
    };
    let md = e.saturating_sub(tx).saturating_sub(U256::from(vf));
    Err(Refusal::Transport(fee_mismatch(p, e, tx, vf, md)))
}

/// The `PQZ_FEE_MISMATCH` reason (spec §10): what was proved, the token's word and its three terms.
pub fn fee_mismatch(p: u64, e: U256, tx: U256, vf: u64, md: U256) -> String {
    format!("PQZ_FEE_MISMATCH: proved {p}, the token's fee word is {e} (txFee {tx}, verifierFee {vf}, M·d {md}); rebuild the \
        statement from the token's view and prove again")
}

impl Verifier {
    pub fn new(cfg: &PqzVerifierCfg) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder().timeout(Duration::from_millis(cfg.timeout_ms)).build()?;
        Ok(Self { cfg: cfg.clone(), http, resting: Default::default(), backoff: ENDPOINT_BACKOFF })
    }

    /// Endpoint `i` failed by transport within the last [`ENDPOINT_BACKOFF`]: it is not asked.
    fn resting(&self, i: usize) -> bool {
        self.resting.lock().is_ok_and(|m| m.get(&i).is_some_and(|t| *t > Instant::now()))
    }

    fn rest(&self, i: usize) {
        if let Ok(mut m) = self.resting.lock() {
            m.insert(i, Instant::now() + self.backoff);
        }
    }

    /// The trailing `PqzSignedVerdict` of a PQZ debit, rebuilt into `w.data` (module doc); any other work unchanged. `Policy`:
    /// never sendable as named (`dead`); `Transport`: may be later (back in the queue). Round 3t (CTR-PQZ-36, NODE-JOB-22's
    /// Change): first the fee pre-check, `args.pqz_fee` against word 256 of the statement the token's view builds
    /// ([`fee_check`]): required on an `OFFCHAIN` token, on a `PRECOMPILE` one checked when named (one view call).
    pub async fn fill(&self, chain: &Chain, w: &mut Work) -> Result<(), Refusal> {
        let Some(row) = debit_row(w) else { return Ok(()) };
        let slot = typed::verdict_slot(row).expect("a debit row");
        let bad = |e: anyhow::Error| Refusal::Policy(format!("{e:#}"));
        let mut vals = typed::call_values(row, &w.data).map_err(bad)?;
        let job = w.typed.as_ref().and_then(|t| t.pqz_verdict.clone());
        let pqz_fee = w.typed.as_ref().and_then(|t| t.pqz_fee);
        let Some(c) = offchain_config(chain, w.to).await? else {
            if job.is_some() {
                return Err(Refusal::Policy(format!("PQZ_VERDICT_NOT_EXPECTED: {:#x} is a PRECOMPILE token: it takes the empty verdict and \
                    never reads one; send the job without pqz_verdict", w.to)));
            }
            if let Some(p) = pqz_fee {
                if let Some((st, _)) = statement_of(chain, w.to, row, &vals).await? {
                    fee_check(chain, w.to, p, &st, 0).await?;
                }
            }
            return Ok(()); // the empty verdict of the parse
        };
        if c.verifier == B256::ZERO {
            return Err(Refusal::Transport(format!("PQZ_VERDICT_REFUSED: PqzVerifierRevoked: {:#x}'s verifier is revoked (epoch {}); \
                its proofs wait for a new verifier through a transfer", w.to, c.pqzVerifierEpoch)));
        }
        let psid = chain.call_view(w.to, IPqzToken::proofSystemIdCall {}).await.map_err(|e| match e {
            SimError::Transport(e) => Refusal::Transport(format!("proofSystemId(): {e}")),
            SimError::Revert(e) => Refusal::Policy(format!("proofSystemId(): {e}")),
        })?;
        // the op's own refusal (expired, malformed, a stale key version): the entry's simulation names it, never with a verdict
        let Some((statement, op)) = statement_of(chain, w.to, row, &vals).await? else { return Ok(()) };
        let Some(p) = pqz_fee else {
            return Err(Refusal::Policy(format!("BAD_PAYLOAD: no pqz_fee: a debit of the OFFCHAIN token {:#x} names its proved fee \
                word (args.pqz_fee, a decimal string; its verifier fee is {})", w.to, c.verifierFee)));
        };
        fee_check(chain, w.to, p, &statement, c.verifierFee).await?;
        let arg = |n: &str| typed::arg_of(row, &vals, n).ok_or_else(|| Refusal::Policy(format!("BAD_PAYLOAD: no {n}")));
        let proof = arg("proof")?.1.as_bytes().unwrap_or_default().to_vec();
        let req = json!({"token": format!("{:#x}", w.to), "chainId": chain.number, "op": Value::Object(op),
            "statement": hex(&statement), "proof": hex(&proof), "pqzVerifierEpoch": c.pqzVerifierEpoch});
        let usable = |v: &PqzVerdictArgs| v.epoch == c.pqzVerifierEpoch && v.valid_until >= now() + self.cfg.valid_margin_secs;
        // a fetch, and one re-fetch on a mismatch (spec §11.1); a job's own verdict is the first answer
        let (mut v, mut fetches) = (job.clone(), if job.is_some() { 1 } else { 2 });
        while !v.as_ref().is_some_and(usable) {
            let why = match &v {
                Some(x) => format!("a verdict at epoch {} until {}, the token's epoch {} (margin {} s)", x.epoch, x.valid_until,
                    c.pqzVerifierEpoch, self.cfg.valid_margin_secs),
                None => "the job names no pqz_verdict".into(),
            };
            if self.cfg.endpoints.is_empty() {
                return Err(Refusal::Policy(format!("PQZ_VERDICT_MISSING: {why}; no [pqz_verifier] endpoints on this node")));
            }
            if fetches == 0 {
                return Err(Refusal::Transport(format!("PQZ_VERDICT_MISSING: {why}, after one re-fetch")));
            }
            fetches -= 1;
            v = Some(self.fetch(&req).await.map_err(|e| Refusal::Transport(format!("PQZ_VERDICT_MISSING: no endpoint answered ({e})")))?);
        }
        let v = v.expect("usable");
        let sv = IPqzToken::PqzSignedVerdict { pqzVerdict: IPqzToken::PqzVerdict { token: w.to, chainId: U256::from(chain.number),
            proofSystemId: psid, statementHash: keccak256(&statement), proofHash: keccak256(&proof), pqzVerifierEpoch: v.epoch,
            validUntil: v.valid_until }, sig: v.auth.clone() };
        vals[slot] = typed::value_of("PqzSignedVerdict", &sv.abi_encode()).map_err(bad)?;
        w.data = typed::call_data(row, vals).into();
        // a replacement past the verdict's life would revert: the work's deadline is the sooner one, of the op's own deadline
        // (never of an earlier verdict's: a renewed verdict extends it, Fable recheck R-1)
        w.valid_until = w.envelope_until.min(v.valid_until);
        if let Some(t) = w.typed.as_mut() {
            t.pqz_verdict = Some(v); // the lane reuses what the gateway fetched
        }
        Ok(())
    }

    /// The configured endpoints in order; the first decoded answer. An error names the endpoint by its index only, its URL is
    /// logged (Fable E N-8: no endpoint URL in a job's error or a gateway reply).
    async fn fetch(&self, body: &Value) -> Result<PqzVerdictArgs, String> {
        let mut errs = Vec::new();
        for (i, e) in self.cfg.endpoints.iter().enumerate() {
            if self.resting(i) {
                errs.push(format!("endpoint {}: skipped, it did not answer in the last {} s", i + 1, self.backoff.as_secs()));
                continue;
            }
            match self.ask(e, body).await {
                Ok(v) => return Ok(v),
                Err((down, x)) => {
                    tracing::warn!(endpoint = i + 1, url = %e, "pqz verifier: {x}");
                    if down {
                        self.rest(i);
                    }
                    errs.push(format!("endpoint {}: {}", i + 1, crate::chain::redact_urls(&x)));
                }
            }
        }
        Err(errs.join("; "))
    }

    /// One endpoint: a 2xx JSON answer of at most `max_response_bytes` (read in chunks, never buffered past it), the reference
    /// verifier's `{pqzVerdict, pqzVerdictSig}`: of the verdict only its `pqzVerifierEpoch` and `validUntil` are read (the
    /// node rebuilds the rest), the signature through the bounded `UASig` decoder (two levels, 16 slots).
    /// `Err((true, _))`: the endpoint did not answer (transport, 5xx), [`Verifier::rest`]s it.
    async fn ask(&self, endpoint: &str, body: &Value) -> Result<PqzVerdictArgs, (bool, String)> {
        let url = format!("{}{ROUTE}", endpoint.trim_end_matches('/'));
        let mut r = self.http.post(url).json(body).send().await.map_err(|e| (true, e.without_url().to_string()))?;
        if !r.status().is_success() {
            return Err((r.status().is_server_error(), format!("HTTP {}", r.status())));
        }
        let max = self.cfg.max_response_bytes;
        let over = || (false, format!("an answer above max_response_bytes {max}"));
        if r.content_length().is_some_and(|n| n > max as u64) {
            return Err(over());
        }
        let mut buf = Vec::new();
        while let Some(c) = r.chunk().await.map_err(|e| (true, e.without_url().to_string()))? {
            if buf.len() + c.len() > max {
                return Err(over());
            }
            buf.extend_from_slice(&c);
        }
        let v: Value = serde_json::from_slice(&buf).map_err(|e| (false, format!("not JSON: {e}")))?;
        let (pv, sig) = (&v["pqzVerdict"], &v["pqzVerdictSig"]);
        let until = pv["validUntil"].as_u64().map(|n| json!(n.to_string())).unwrap_or_else(|| pv["validUntil"].clone());
        let picked = json!({"pqzVerifierEpoch": pv["pqzVerifierEpoch"], "validUntil": until, "auth": sig});
        typed::pqz_verdict_of(&picked, "answer").map_err(|e| (false, format!("{e:#}")))
    }

    /// `refuse_shield_when_unserved` (spec §11.1, C8): a shield or wrap-shield into an `OFFCHAIN` token whose verifier is revoked
    /// or that no endpoint serves is refused `PQZ_VERIFIER_UNREACHABLE`, for every consumer; a probe that did not get through is
    /// `PQZ_VERIFIER_PROBE_UNREAD`, back in the queue (Fable E N-2); off by default.
    pub async fn check_shield(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        if !self.cfg.refuse_shield_when_unserved || w.typed.as_ref().is_none_or(|t| t.contract != "pqz") {
            return Ok(());
        }
        let shield = w.data.get(..4).and_then(|s| crate::guard::row(s.try_into().ok()?, "pqz"))
            .is_some_and(|r| matches!(r.name, "UAShield" | "WrapShield"));
        if !shield {
            return Ok(());
        }
        let Some(c) = offchain_config(chain, w.to).await? else { return Ok(()) };
        let unserved = |why: String| Err(Refusal::Policy(format!("PQZ_VERIFIER_UNREACHABLE: {:#x}: {why}; this node refuses shields \
            into a pool nobody serves (refuse_shield_when_unserved)", w.to)));
        if c.verifier == B256::ZERO {
            return unserved(format!("its verifier is revoked (epoch {})", c.pqzVerifierEpoch));
        }
        match self.serves(chain, w.to).await {
            Some(true) => Ok(()),
            Some(false) => unserved("no [pqz_verifier] endpoint serves it (its probe)".into()),
            // Fable E N-2: a probe that did not get through says nothing about the pool: back in the queue, never `dead`
            None => Err(Refusal::Transport(format!("PQZ_VERIFIER_PROBE_UNREAD: {:#x}: no [pqz_verifier] endpoint serves it and \
                one did not answer its probe (transport); retried", w.to))),
        }
    }

    /// Some configured endpoint serves `token`: its probe (`POST /v1/pqz-verdict/probe {token, chainId}`, spec §4.2, §11.2: a
    /// verdict over the fixed probe statement) answers 2xx: `Some(true)`; every endpoint answered, none 2xx (or none configured):
    /// `Some(false)`; none served and one had a transport error (a timeout, a refused connection) or a 5xx: `None`, unknown.
    // ponytail: one probe per shield job; keep each endpoint's last outcome if shields come often
    async fn serves(&self, chain: &Chain, token: alloy::primitives::Address) -> Option<bool> {
        let body = json!({"token": format!("{token:#x}"), "chainId": chain.number});
        let mut known = true;
        for (i, e) in self.cfg.endpoints.iter().enumerate() {
            if self.resting(i) {
                known = false; // Fable E N-7: it did not answer a moment ago; not asked again inside the window
                continue;
            }
            let url = format!("{}{ROUTE}/probe", e.trim_end_matches('/'));
            match self.http.post(url).json(&body).send().await {
                Ok(r) if r.status().is_success() => return Some(true),
                // Fable recheck R-5: a 5xx (a restart behind a proxy) says nothing about the pool either
                Ok(r) if r.status().is_server_error() => {
                    tracing::warn!(endpoint = i + 1, "pqz verifier probe: HTTP {}", r.status());
                    self.rest(i);
                    known = false;
                }
                Ok(_) => {}
                Err(x) => {
                    tracing::warn!(endpoint = i + 1, "pqz verifier probe: {x}");
                    self.rest(i);
                    known = false;
                }
            }
        }
        known.then_some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{keccak256, Address, B256};
    use alloy::sol_types::SolCall;
    use crate::abi::IPqzToken;
    use crate::typed::{parse, struct_hash_of};

    /// The views the node rebuilds a verdict from are the contract's: the forge artifact's selectors (`out/`, T45's ABI; group 3h
    /// T59: the three args tuples with `ownTag`, the four statement views moved, 0x3a3bb45a -> 0x931415ee, 0xffdee909 -> 0x8a2161ba,
    /// 0x23a72649 -> 0xda8c9eed, 0xf4834cb9 -> 0x8e4ccf2e).
    #[test]
    fn views_are_the_contracts() {
        assert_eq!(IPqzToken::pqzVerifyConfigCall::SELECTOR, [0xdc, 0x59, 0xc6, 0x6e]);
        assert_eq!(IPqzToken::proofSystemIdCall::SELECTOR, [0x1f, 0x3b, 0x28, 0xf2]);
        assert_eq!(IPqzToken::envelopeBindingCall::SELECTOR, [0x35, 0xad, 0x08, 0xaa]);
        for (row, sel) in [("UAPqzTransferSingle", [0x93, 0x14, 0x15, 0xee]), ("UAPqzTransferSingleCompact", [0x93, 0x14, 0x15, 0xee]),
            ("UAPqzTransfer", [0x8a, 0x21, 0x61, 0xba]), ("UAPqzTransferCompact", [0x8a, 0x21, 0x61, 0xba]),
            ("UAPqzUnshield", [0xda, 0x8c, 0x9e, 0xed]), ("UAPqzUnshieldUnwrap", [0x8e, 0x4c, 0xcf, 0x2e])] {
            let v = statement_view(row).unwrap_or_else(|| panic!("{row}: no statement view"));
            assert_eq!(keccak256(v.as_bytes())[..4], sel, "{row}: {v}");
        }
        assert_eq!(statement_view("UAShield"), None);
    }

    /// Round 3t (spec §10, §12): the node's fee word parity against `smartcontracts/vectors/pqz/verifier_fee.json` (written from
    /// real token ops): every row's word is `txFee + vf + M·d`, and a mismatch names the three terms.
    #[test]
    fn verifier_fee_vectors_and_the_mismatch() {
        let p = format!("{}/../smartcontracts/vectors/pqz/verifier_fee.json", env!("CARGO_MANIFEST_DIR"));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len() as u64, v["rowCount"].as_u64().unwrap());
        for r in rows {
            let n = |k: &str| r[k].as_u64().unwrap();
            let tx = if r["beneficiary"].as_bool().unwrap() { n("confidentialFee") } else { 0 };
            assert_eq!(tx + n("verifierFee") + n("legs") * n("decoyFee"), n("feeWord"), "{}", r["form"]);
        }
        let m = fee_mismatch(5, U256::from(7u8), U256::from(3u8), 2, U256::from(2u8));
        assert!(m.starts_with("PQZ_FEE_MISMATCH: proved 5, the token's fee word is 7 (txFee 3, verifierFee 2, M·d 2)"), "{m}");
    }

    /// `smartcontracts/vectors/pqz/verdict.json` read by the node (spec §11.3): the node's `PqzVerdict` type is the contract's
    /// (type string, typehash), every row's struct hash and digest in the token's domain are the vector's, and the EOA verifier's
    /// signature recovers over the registry's `uaAuthDigest` (what the e2e test signs; the node itself signs nothing).
    #[test]
    fn pqz_verdict_vectors_digest() {
        let p = format!("{}/../smartcontracts/vectors/pqz/verdict.json", env!("CARGO_MANIFEST_DIR"));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let ty = "PqzVerdict(address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil)";
        assert_eq!(v["typeString"].as_str(), Some(ty));
        assert_eq!(format!("{:#x}", keccak256(ty)), v["typehash"].as_str().unwrap());
        let d = &v["domain"];
        let g = |k: &str| d[k].as_str().unwrap();
        let (chain, at, salt): (u64, Address, B256) = (d["chainId"].as_u64().unwrap(), g("verifyingContract").parse().unwrap(), g("salt").parse().unwrap());
        assert_eq!(g("name"), "SCaaS PqzToken");
        let sep = crate::dex::domain("SCaaS PqzToken", chain, at, salt).separator();
        assert_eq!(format!("{sep:#x}"), g("separator"));
        let verifier = Address::from_word(v["verifierUA"].as_str().unwrap().parse().unwrap());
        let rows = v["rows"].as_array().unwrap();
        for r in rows {
            let pv = serde_json::json!({"token": format!("{at:#x}"), "chainId": chain.to_string(), "proofSystemId": v["proofSystemId"],
                "statementHash": r["statementHash"], "proofHash": r["proofHash"], "pqzVerifierEpoch": r["pqzVerifierEpoch"],
                "validUntil": r["validUntil"].as_u64().unwrap().to_string()});
            let h = struct_hash_of("PqzVerdict", &parse("PqzVerdict", &pv, "v").unwrap()).unwrap();
            assert_eq!(format!("{h:#x}"), r["structHash"].as_str().unwrap(), "{}", r["form"]);
            let digest = keccak256([&[0x19, 0x01][..], sep.as_slice(), h.as_slice()].concat());
            assert_eq!(format!("{digest:#x}"), r["digest"].as_str().unwrap(), "{}", r["form"]);
            let ua: B256 = r["uaAuthDigest"].as_str().unwrap().parse().unwrap();
            let sig = alloy::hex::decode(&r["signature"].as_str().unwrap()[2..]).unwrap();
            assert!(crate::typed::recovers(ua, &sig, verifier), "{}", r["form"]);
        }
        assert_eq!(rows.len(), 22);
    }

    /// A verifier endpoint: `mode` 0 answers a verdict, 1 answers after a second (past the test's timeout), 2 answers 422; counting
    /// its requests (the verdict route and the probe alike).
    async fn endpoint(mode: u8) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let n2 = n.clone();
        let h = move || {
            let n2 = n2.clone();
            async move {
                n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if mode == 1 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                if mode == 2 {
                    return (axum::http::StatusCode::UNPROCESSABLE_ENTITY, axum::Json(json!({"error": "refused"})));
                }
                (axum::http::StatusCode::OK, axum::Json(json!({"pqzVerdict": {"pqzVerifierEpoch": 2, "validUntil": 1_800_000_000u64},
                    "pqzVerdictSig": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}})))
            }
        };
        let app = axum::Router::new().route(ROUTE, axum::routing::post(h.clone())).route(&format!("{ROUTE}/probe"), axum::routing::post(h));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, n)
    }

    /// Fable E N-7: an endpoint that did not answer is not asked again for the backoff window, so five jobs pay its timeout once,
    /// not five times, and the next endpoint answers each; the probe skips it too (unknown, never "not served"). A refusal (4xx)
    /// is an answer: that endpoint is asked again. Control: with no backoff every fetch asks the silent endpoint again.
    #[tokio::test]
    async fn a_silent_verifier_endpoint_rests_for_the_backoff_window() {
        use std::sync::atomic::Ordering::SeqCst;
        let (slow, slow_n) = endpoint(1).await;
        let (good, good_n) = endpoint(0).await;
        let (no, no_n) = endpoint(2).await;
        let cfg = PqzVerifierCfg { endpoints: vec![slow.clone(), no, good], timeout_ms: 200, ..Default::default() };
        let v = Verifier::new(&cfg).unwrap();
        let t = Instant::now();
        for _ in 0..5 {
            assert_eq!(v.fetch(&json!({})).await.unwrap().epoch, 2);
        }
        assert!(t.elapsed() < Duration::from_millis(800), "one timeout, not five: {:?}", t.elapsed());
        assert_eq!((slow_n.load(SeqCst), no_n.load(SeqCst), good_n.load(SeqCst)), (1, 5, 5));
        let chain = Chain::with_signer(&crate::config::ChainCfg { evm_chain_number: 1, rpc_urls: vec!["http://127.0.0.1:9".into()],
            ..Default::default() }, alloy::signers::local::PrivateKeySigner::random()).unwrap();
        let only_slow = Verifier { cfg: PqzVerifierCfg { endpoints: vec![slow.clone()], timeout_ms: 200, ..Default::default() },
            http: v.http.clone(), resting: Mutex::new(v.resting.lock().unwrap().clone()), backoff: ENDPOINT_BACKOFF };
        assert_eq!(only_slow.serves(&chain, Address::ZERO).await, None, "resting: unknown");
        assert_eq!(slow_n.load(SeqCst), 1, "the probe did not ask it");
        let mut c = Verifier::new(&cfg).unwrap();
        c.backoff = Duration::ZERO;
        for _ in 0..3 {
            c.fetch(&json!({})).await.unwrap();
        }
        assert_eq!(slow_n.load(SeqCst), 4, "control: no backoff, asked every time");
    }
}
