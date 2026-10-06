//! `may_export` (spec mesh §9): hàm DUY NHẤT quyết định cái gì rời node — route list và danh sách chain của
//! `/policy` đều gọi nó.
use super::{PeerClass, Visibility};

pub struct Peer<'a> {
    pub active: bool,
    pub class: PeerClass,
    /// Private: chain được nhận (bắt buộc). Open: bộ lọc tuỳ chọn, rỗng = mọi chain public.
    pub chains: &'a [String],
}

/// `from_peer`: dòng có `source = 'peer'` (R85: dòng private chỉ do origin phục vụ).
pub fn may_export(visibility: Visibility, from_peer: bool, chain_key: &str, chain_public: bool, peer: &Peer) -> bool {
    let listed = peer.chains.iter().any(|c| c == chain_key);
    peer.active
        && match visibility {
            Visibility::Open => (peer.chains.is_empty() || listed) && (chain_public || peer.class == PeerClass::Private),
            Visibility::Private => !from_peer && peer.class == PeerClass::Private && listed,
            Visibility::None => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_branch() {
        let ck = "evm:100".to_string();
        let chains = [ck.clone()];
        let other = ["evm:1".to_string()];
        let p = |active, class, chains: &'static [String]| Peer { active, class, chains };
        let open_any = Peer { active: true, class: PeerClass::Open, chains: &[] };
        let open_other = Peer { active: true, class: PeerClass::Open, chains: &other };
        let open_listed = Peer { active: true, class: PeerClass::Open, chains: &chains };
        let private = Peer { active: true, class: PeerClass::Private, chains: &chains };
        let private_other = Peer { active: true, class: PeerClass::Private, chains: &other };
        let inactive = p(false, PeerClass::Private, &[]);
        let ex = |v, from_peer, public, peer: &Peer| may_export(v, from_peer, &ck, public, peer);
        // open rows
        assert!(ex(Visibility::Open, true, true, &open_any), "open row, public chain, unfiltered open peer");
        assert!(ex(Visibility::Open, true, true, &open_listed));
        assert!(!ex(Visibility::Open, true, true, &open_other), "open peer filter excludes the chain");
        assert!(!ex(Visibility::Open, false, false, &open_any), "open peer never sees a private chain");
        assert!(ex(Visibility::Open, true, true, &private), "private peers also receive open intents");
        assert!(ex(Visibility::Open, false, false, &private));
        assert!(!ex(Visibility::Open, false, true, &inactive));
        // private rows
        assert!(ex(Visibility::Private, false, false, &private), "origin serves its private row to an allowlisted private peer");
        assert!(!ex(Visibility::Private, true, false, &private), "R85: a private row received from a peer is never re-served");
        assert!(!ex(Visibility::Private, false, false, &private_other), "chain not in the private peer's list");
        assert!(!ex(Visibility::Private, false, true, &open_listed), "never to an open peer");
        // none
        assert!(!ex(Visibility::None, false, true, &private));
        assert!(!ex(Visibility::None, false, true, &open_any));
    }
}
