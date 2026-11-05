//! Nhận một envelope (spec mesh §7.2, L0–L3): thuần, không RPC. Store nằm sau `Seen`; giới hạn tốc độ theo peer
//! (`RATE_LIMITED`) và `STORE_FULL` là việc của puller/store (S4/S5), không ở đây.
use std::collections::HashMap;

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};

use super::digest::{self, Decoded};
use super::envelope::{self, b32, Envelope};
use super::{hubsig, Code, PeerClass, Visibility};
use crate::metatx;

/// R82 — mọi số là config.
#[derive(Debug, Clone, Copy)]
pub struct MeshParams {
    pub max_hops: u64,
    pub clock_skew_secs: u64,
    pub max_valid_for_secs: u64,
    pub exclusive_ms: u64,
}

impl Default for MeshParams {
    fn default() -> Self {
        Self { max_hops: 4, clock_skew_secs: 30, max_valid_for_secs: 3600, exclusive_ms: 10_000 }
    }
}

/// Những gì node biết về một chain. `Default` = chain chỉ có trong bảng policy: private (R76), không token, không lane.
#[derive(Debug, Clone, Default)]
pub struct ChainInfo {
    /// `chain_profile == public`.
    pub public: bool,
    /// Token đã đăng ký, dạng chuẩn của họ (R86).
    pub tokens: Vec<String>,
    /// Địa chỉ chuẩn của các lane của ta (`adapter.lanes()[i].address`, R61).
    pub lanes: Vec<String>,
    /// `[[chains]] fee_recipient` (EVM/Hedera).
    pub fee_recipient: Option<String>,
    /// EVM/Hedera: this chain's `chain_uid`, the salt of every SCaaS domain (NODE-GW-07); `None` ⇒ `UNKNOWN_CHAIN`.
    pub chain_uid: Option<alloy::primitives::B256>,
    /// Aptos: package; Solana: program id — để kiểm dẫn xuất account (§4.4).
    pub program: Option<String>,
    /// TON: master (raw) → (hash, depth) của wallet code.
    pub wallet_codes: HashMap<String, ([u8; 32], u16)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    None,
    ForwardOnly,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRecipientAllow {
    Any,
    SelfOrZero,
}

/// Một dòng `blockchain.target.policy` / `[[mesh.policy]]` (§7.1). `contract` = `token_of` hoặc `*`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRow {
    pub chain_key: String,
    pub contract: String,
    pub selector: String,
    pub support: Support,
    pub submit: bool,
    pub pool_visibility: Visibility,
    pub min_fee: String,
    pub fee_recipient_allow: FeeRecipientAllow,
}

/// Store: `intent_id` đã là một dòng, hoặc `(intent_id, body_hash)` đang bị tombstone (§6).
pub trait Seen {
    fn seen(&self, intent_id: &[u8; 32], body_hash: &[u8; 32]) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Gateway,
    Outbox,
    Peer(PeerClass),
}

pub struct Ctx<'a> {
    pub now: u64,
    pub params: MeshParams,
    /// `peer_id` của node này (exclusive cho chính mình).
    pub self_id: [u8; 32],
    pub chains: &'a HashMap<String, ChainInfo>,
    pub policies: &'a [PolicyRow],
    pub seen: &'a dyn Seen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Pooled,
    Submittable,
}

#[derive(Debug, Clone)]
pub struct Accepted {
    pub envelope: Envelope,
    pub body_hash: [u8; 32],
    pub decoded: Decoded,
    /// Chặt nhất của nhãn, policy và profile chain (§9).
    pub visibility: Visibility,
    /// Giá trị lưu: nhận từ peer = trên dây + 1.
    pub hop_count: u64,
    pub may_submit: bool,
    /// `None` = không có, hoặc bị bỏ vì vượt `exclusive_ms` (§8.2).
    pub exclusive_until: Option<u64>,
    pub exclusive_self: bool,
    pub state: State,
}

/// Thứ tự: `(contract, selector)`, `(contract, *)`, `(*, selector)`, `(*, *)`; không trộn (§7.1).
pub fn lookup<'a>(rows: &'a [PolicyRow], chain_key: &str, token: &str, selector: &str) -> Option<&'a PolicyRow> {
    [(token, selector), (token, "*"), ("*", selector), ("*", "*")]
        .into_iter()
        .find_map(|(c, s)| rows.iter().find(|r| r.chain_key == chain_key && r.contract == c && r.selector == s))
}

const ZERO_EVM: &str = "0x0000000000000000000000000000000000000000";

pub fn accept(bytes: &[u8], source: Source, ctx: &Ctx) -> Result<Accepted, Code> {
    // L0
    let envelope::Parsed { envelope, claimed_id, body_hash } = envelope::parse(bytes)?;
    let env = &envelope;
    let known = ctx.chains.get(&env.chain_key);
    if known.is_none() && !ctx.policies.iter().any(|r| r.chain_key == env.chain_key) {
        return Err(Code::UnknownChain);
    }
    let fallback = ChainInfo::default();
    let chain = known.unwrap_or(&fallback);

    // L1
    let peer = match source {
        Source::Peer(class) => Some(class),
        _ => None,
    };
    let hop_count = env.hop_count.saturating_add(peer.is_some() as u64);
    if peer.is_some() && hop_count > ctx.params.max_hops {
        return Err(Code::HopLimit);
    }
    if ctx.seen.seen(&claimed_id, &body_hash) {
        return Err(Code::Duplicate);
    }

    // L2
    let d = digest::decode(env, chain)?;
    if d.intent_id != claimed_id {
        return Err(Code::DigestMismatch);
    }
    if d.valid_until <= ctx.now.saturating_add(ctx.params.clock_skew_secs) {
        return Err(Code::Expired);
    }
    if d.valid_until > ctx.now.saturating_add(ctx.params.max_valid_for_secs) {
        return Err(Code::ValidTooLong);
    }
    if let Some(e) = &d.evm {
        digest::check_evm(e, &d.intent_id)?;
    }
    hubsig::verify(env, &d.intent_id, &body_hash)?;
    // Quá khứ chỉ nghĩa là exclusive đã hết (catch-up, H2); tương lai là đồng hồ hỏng hoặc gian.
    if env.hub.published_at > ctx.now.saturating_add(ctx.params.clock_skew_secs) {
        return Err(Code::BadEnvelope);
    }

    // L3
    let chain_vis = if chain.public { Visibility::Open } else { Visibility::Private };
    let label = if env.private() { Visibility::Private } else { Visibility::Open };
    if peer == Some(PeerClass::Open) && label.max(chain_vis) == Visibility::Private {
        return Err(Code::PrivateFromOpenPeer);
    }
    let row = lookup(ctx.policies, &env.chain_key, &d.token, &d.selector);
    let (support, submit, pool_vis) = row.map_or((Support::ForwardOnly, false, chain_vis), |r| (r.support, r.submit, r.pool_visibility));
    if support == Support::None {
        return Err(Code::Unsupported);
    }
    let visibility = label.max(pool_vis).max(chain_vis);
    let relayer_ok = d.relayer.as_ref().is_none_or(|r| chain.lanes.contains(r));
    let fee_ok = row.is_some_and(|r| {
        let min = metatx::uint(&r.min_fee).ok();
        if d.evm.is_none() {
            return min == Some(U256::ZERO);
        }
        min.is_some_and(|m| d.fee_effective >= m)
            && d.fee_recipient.as_ref().is_none_or(|fr| {
                r.fee_recipient_allow == FeeRecipientAllow::Any || fr == ZERO_EVM || chain.fee_recipient.as_ref() == Some(fr)
            })
    });
    let may_submit = support == Support::Full
        && submit
        && chain.tokens.contains(&d.token)
        && d.account_ok
        && !chain.lanes.is_empty()
        && relayer_ok
        && fee_ok
        && source != Source::Outbox;

    // §8.2: chỉ theo exclusive khi 0 < until − published_at ≤ exclusive_ms của CHÍNH node nhận.
    let honored = env.exclusive.as_ref().filter(|x| {
        x.until.checked_sub(env.hub.published_at).is_some_and(|span| span > 0 && span * 1000 <= ctx.params.exclusive_ms)
    });
    let exclusive_until = honored.map(|x| x.until);
    let exclusive_self = honored.is_some_and(|x| b32(&x.relayer_id, false) == Some(ctx.self_id));
    let now_ok = exclusive_until.is_none_or(|u| exclusive_self || ctx.now >= u);
    let state = if may_submit && now_ok { State::Submittable } else { State::Pooled };
    Ok(Accepted { envelope, body_hash, decoded: d, visibility, hop_count, may_submit, exclusive_until, exclusive_self, state })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(contract: &str, selector: &str, support: Support) -> PolicyRow {
        PolicyRow { chain_key: "evm:1".into(), contract: contract.into(), selector: selector.into(), support, submit: false,
                    pool_visibility: Visibility::Open, min_fee: "0".into(), fee_recipient_allow: FeeRecipientAllow::Any }
    }

    #[test]
    fn lookup_most_specific_wins_without_merging() {
        let rows = vec![row("*", "*", Support::None), row("*", "0xaa", Support::ForwardOnly), row("0xt", "*", Support::Full),
                        row("0xt", "0xaa", Support::None)];
        let s = |t: &str, sel: &str| lookup(&rows, "evm:1", t, sel).map(|r| r.support);
        assert_eq!(s("0xt", "0xaa"), Some(Support::None));
        assert_eq!(s("0xt", "0xbb"), Some(Support::Full));
        assert_eq!(s("0xu", "0xaa"), Some(Support::ForwardOnly));
        assert_eq!(s("0xu", "0xbb"), Some(Support::None));
        assert_eq!(lookup(&rows, "evm:2", "0xt", "0xaa"), None);
    }

    // --- một envelope EVM thật (ký bằng khoá secp256k1 + khoá hub) cho các mã không có trong vector §4.6.
    use crate::metatx::{Domain, Mtx};
    use crate::signer::{Curve, LocalSigner, Signer};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TOKEN: &str = "0x00000000000000000000000000000000000070c0";
    const NOW: u64 = 1_800_000_000;
    const UID: alloy::primitives::B256 = alloy::primitives::B256::repeat_byte(0x24);

    fn envelope(mode: u32, fee_recipient: &str, exclusive: Option<([u8; 32], u64)>) -> Vec<u8> {
        let user = LocalSigner::new(Curve::Secp256k1, &[9; 32]).unwrap();
        let z = format!("{:#x}", alloy::primitives::Address::ZERO);
        let m = json!({"from": user.address_hex(), "to": z, "value": "1", "entryRef": format!("{:#x}", alloy::primitives::B256::ZERO),
            "batch": "1", "nonce": "0", "validUntil": (NOW + 300).to_string(), "mode": mode, "relayer": z, "fee": "7",
            "feeRecipient": fee_recipient});
        let d = Domain { name: "T".into(), version: "1".into(), chain_id: 1, verifying_contract: TOKEN.parse().unwrap(), salt: UID };
        let id = Mtx::from_wire(Some("transfer"), &m).unwrap().digest(&d).0;
        let body = json!({"domain": {"name": "T", "version": "1"}, "struct": "transfer", "meta_tx": m,
            "signature": format!("0x{}", alloy::hex::encode(user.sign(&id).unwrap())), "sig_kind": "eoa"});
        let key = SigningKey::from_bytes(&[1; 32]);
        let hub = hubsig::peer_id(&key.verifying_key().to_bytes());
        let bh: [u8; 32] = Sha256::digest(envelope::canonical_body(&body).unwrap()).into();
        let msg = hubsig::hub_msg("evm:1", &id, &bh, &hub, NOW, false, exclusive.as_ref().map(|(r, u)| (r, *u))).unwrap();
        let mut v = json!({"spec": envelope::SPEC, "intent_id": format!("0x{}", alloy::hex::encode(id)), "chain_key": "evm:1", "family": "evm",
            "contract": TOKEN, "visibility": "open", "evm": body, "hop_count": 0,
            "hub": {"id": alloy::hex::encode(hub), "pubkey": alloy::hex::encode(key.verifying_key().to_bytes()), "published_at": NOW,
                    "sig": alloy::hex::encode(hubsig::sign(&key, &msg))}});
        if let Some((r, u)) = exclusive {
            v["exclusive"] = json!({"relayer_id": alloy::hex::encode(r), "until": u});
        }
        serde_json::to_vec(&v).unwrap()
    }

    struct Known(bool);
    impl Seen for Known {
        fn seen(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
            self.0
        }
    }

    fn run(bytes: &[u8], source: Source, rows: &[PolicyRow], seen: bool, chain: &str) -> Result<Accepted, Code> {
        let info = ChainInfo { public: true, tokens: vec![TOKEN.into()], lanes: vec!["0xlane".into()],
                               fee_recipient: Some("0x000000000000000000000000000000000000c01d".into()), chain_uid: Some(UID),
                               ..Default::default() };
        let chains = HashMap::from([(chain.to_string(), info)]);
        accept(bytes, source, &Ctx { now: NOW, params: MeshParams::default(), self_id: [5; 32], chains: &chains, policies: rows, seen: &Known(seen) })
    }

    fn full(allow: FeeRecipientAllow) -> Vec<PolicyRow> {
        vec![PolicyRow { chain_key: "evm:1".into(), contract: TOKEN.into(), selector: "*".into(), support: Support::Full, submit: true,
                         pool_visibility: Visibility::Open, min_fee: "0".into(), fee_recipient_allow: allow }]
    }

    #[test]
    fn codes_and_outcomes_outside_the_vectors() {
        let open = envelope(0x20, "0x0000000000000000000000000000000000000000", None);
        let peer = Source::Peer(PeerClass::Private);
        let rows = full(FeeRecipientAllow::Any);
        let a = run(&open, peer, &rows, false, "evm:1").unwrap();
        assert_eq!((a.may_submit, a.state, a.hop_count), (true, State::Submittable, 1));
        assert_eq!(run(&open, peer, &rows, true, "evm:1").err(), Some(Code::Duplicate));
        assert_eq!(run(&open, peer, &[], false, "evm:2").err(), Some(Code::UnknownChain));
        // a policy row makes a chain known, but an EVM intent needs the receiver's own chain_uid for its digest
        assert_eq!(run(&open, peer, &rows, false, "evm:2").err(), Some(Code::UnknownChain));
        let none = vec![PolicyRow { support: Support::None, ..rows[0].clone() }];
        assert_eq!(run(&open, peer, &none, false, "evm:1").err(), Some(Code::Unsupported));
        // no matching row ⇒ forward_only, visibility from the chain profile
        let a = run(&open, peer, &[], false, "evm:1").unwrap();
        assert_eq!((a.may_submit, a.visibility), (false, Visibility::Open));
        let hidden = vec![PolicyRow { pool_visibility: Visibility::None, ..rows[0].clone() }];
        assert_eq!(run(&open, peer, &hidden, false, "evm:1").unwrap().visibility, Visibility::None);
        // our own outbox job is never submitted from the mesh path; the origin does not bump hops
        let a = run(&open, Source::Outbox, &rows, false, "evm:1").unwrap();
        assert_eq!((a.may_submit, a.hop_count), (false, 0));
        assert!(run(&open, Source::Gateway, &rows, false, "evm:1").unwrap().may_submit);
        // exclusive to ourselves ⇒ submit now; to someone else ⇒ wait
        let mine = envelope(0x20, "0x0000000000000000000000000000000000000000", Some(([5; 32], NOW + 5)));
        let a = run(&mine, peer, &rows, false, "evm:1").unwrap();
        assert_eq!((a.exclusive_self, a.state), (true, State::Submittable));
        let theirs = envelope(0x20, "0x0000000000000000000000000000000000000000", Some(([6; 32], NOW + 5)));
        assert_eq!(run(&theirs, peer, &rows, false, "evm:1").unwrap().state, State::Pooled);
        // bound feeRecipient with self_or_zero: ours or 0 pass, someone else's does not
        let self_or_zero = full(FeeRecipientAllow::SelfOrZero);
        for (fr, ok) in [("0x000000000000000000000000000000000000c01d", true), ("0x0000000000000000000000000000000000000000", true),
                         ("0x0000000000000000000000000000000000000bad", false)] {
            let bound = envelope(0x22, fr, None);
            assert_eq!(run(&bound, peer, &self_or_zero, false, "evm:1").unwrap().may_submit, ok, "{fr}");
            assert!(run(&bound, peer, &rows, false, "evm:1").unwrap().may_submit, "any");
        }
        // min_fee compares the EFFECTIVE fee (FIXED 7)
        let min8 = vec![PolicyRow { min_fee: "8".into(), ..rows[0].clone() }];
        assert!(!run(&open, peer, &min8, false, "evm:1").unwrap().may_submit);
    }
}
