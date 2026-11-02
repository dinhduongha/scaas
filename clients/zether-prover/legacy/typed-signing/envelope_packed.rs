//! The calldata builders of the packed `IConfidentialToken` signatures, before typed-signing C3: superseded by the explicit
//! parameters of `src/envelope.rs` (`IZetherToken`, Appendix X.3). Not built.

/// Calldata of a confidential transfer (`mtxConfidentialTransfer`, `…Compact`, `…Single`, all
/// `(bytes payload, bytes proof, bytes auth, bytes32 beneficiary, bytes accHint)`, the shared `IConfidentialToken`
/// signature; Zether: `auth` and `accHint` empty, the proof alone authorizes the spend, UA-6): the direct call and,
/// unchanged, the envelope's `data`.
pub fn transfer_call(sig: &str, payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
    let mut d = selector(sig).to_vec();
    d.extend(abi::encode(&[
        Tok::Bytes(payload.to_vec()),
        Tok::Bytes(proof.to_vec()),
        Tok::Bytes(Vec::new()),
        Tok::Word(*beneficiary),
        Tok::Bytes(Vec::new()),
    ]));
    d
}

/// `mtxUnshield(bytes payload, bytes proof, bytes auth, bytes32 beneficiary, bytes accHint, uint256 amount, bytes32
/// recipient)`, `auth` and `accHint` empty, `to` the recipient id: a padded address or a derived SIGNING UA (CTR-ZTH-51).
pub fn unshield_call(
    payload: &[u8],
    proof: &[u8],
    beneficiary: &[u8; 32],
    to: &[u8; 32],
    amount: u64,
) -> Vec<u8> {
    let mut d = selector("mtxUnshield(bytes,bytes,bytes,bytes32,bytes,uint256,bytes32)").to_vec();
    d.extend(abi::encode(&[
        Tok::Bytes(payload.to_vec()),
        Tok::Bytes(proof.to_vec()),
        Tok::Bytes(Vec::new()),
        Tok::Word(*beneficiary),
        Tok::Bytes(Vec::new()),
        Tok::Word(abi::u256(amount)),
        Tok::Word(*to),
    ]));
    d
}
