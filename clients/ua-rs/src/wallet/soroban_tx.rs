// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The Soroban native transaction (plan 2026-11-17-scaas-sdk T41.soroban; spec §27.5 (d)) from named fields: a `Transaction`
//! (Stellar-transaction.x) with one `InvokeHostFunctionOp` carrying a subject's checked op and its signature (a self-relay), or
//! one `Payment` of XLM (the Native column); its id `sha256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx)` and the `TransactionEnvelope`
//! v1 signed by its source. Byte-equal to clientkeys `src/fam/soroban.js` `nativeTx` and its rows in
//! `smartcontracts/vectors/native/soroban-tx.json`. The `SorobanTransactionData` is the payer's own simulation's, its ledger
//! keys one XDR object each as the RPC answered them (bounded here by count and length; the reader is scaas-rpc's). UNAUDITED.
use sha2::{Digest, Sha256};

use super::{Error, NativeKey, Network, Result, SignRequest, Signer};
use crate::families::soroban::{opaque, u32be, Address, Checked};

const ENVELOPE_TYPE_TX: u32 = 2;
const OP_PAYMENT: u32 = 1;
const OP_INVOKE_HOST_FUNCTION: u32 = 24;
/// The most ledger keys a footprint list takes, and the longest key.
pub const MAX_FOOTPRINT_KEYS: usize = 256;
pub const MAX_KEY_LEN: usize = 4096;

/// A transaction's resources as the payer's simulation gave them (`SorobanTransactionData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorobanData {
    /// `LedgerKey` XDR, one each
    pub read_only: Vec<Vec<u8>>,
    pub read_write: Vec<Vec<u8>>,
    pub instructions: u32,
    pub disk_read_bytes: u32,
    pub write_bytes: u32,
    pub resource_fee: i64,
    /// the footprint entries to restore (ext v1); empty: ext v0
    pub archived: Vec<u32>,
}

/// The transaction's one operation.
#[allow(clippy::large_enum_variant)] // one per transaction, short-lived
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxOp {
    /// the checked op as a host call, with the subject's signature as its auth entry and the simulation's data; `signature` and
    /// `data` absent only in a transaction that is simulated, never signed (`op` absent: the terms were refused)
    Invoke {
        op: Option<Checked>,
        signature: Option<[u8; 64]>,
        data: Option<SorobanData>,
    },
    /// a payment of `amount` stroops of XLM to a `G…`
    Payment { destination: String, amount: i128 },
}

/// A transaction from its named fields (`source` the `G…` that pays and signs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorobanTx {
    pub source: String,
    /// stroops; a `u32`
    pub fee: u64,
    /// the source's sequence + 1; an `i64` above 0
    pub seq: i128,
    pub min_time: u64,
    /// above 0: a transaction always has its time bound
    pub max_time: u64,
    pub op: TxOp,
}

/// A signed transaction: its XDR, its id, the source's signature and its key hint, the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSorobanTx {
    pub tx: Vec<u8>,
    pub hash: [u8; 32],
    pub signature: [u8; 64],
    pub hint: [u8; 4],
    pub envelope: Vec<u8>,
}

fn account(s: &str) -> Result<[u8; 32]> {
    match Address::parse(s) {
        Some(Address::Account(k)) => Ok(k),
        _ => Err(Error::Argument),
    }
}

fn keys(out: &mut Vec<u8>, l: &[Vec<u8>]) -> Result<()> {
    if l.len() > MAX_FOOTPRINT_KEYS
        || l.iter()
            .any(|k| k.is_empty() || k.len() > MAX_KEY_LEN || k.len() % 4 != 0)
    {
        return Err(Error::Argument);
    }
    u32be(out, l.len() as u32);
    l.iter().for_each(|k| out.extend_from_slice(k));
    Ok(())
}

impl SorobanData {
    fn xdr(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.archived.is_empty() {
            u32be(out, 0);
        } else {
            if self.archived.len() > MAX_FOOTPRINT_KEYS {
                return Err(Error::Argument);
            }
            u32be(out, 1);
            u32be(out, self.archived.len() as u32);
            self.archived.iter().for_each(|a| u32be(out, *a));
        }
        keys(out, &self.read_only)?;
        keys(out, &self.read_write)?;
        u32be(out, self.instructions);
        u32be(out, self.disk_read_bytes);
        u32be(out, self.write_bytes);
        out.extend_from_slice(&self.resource_fee.to_be_bytes());
        Ok(())
    }
}

impl SorobanTx {
    /// The `Transaction` XDR. `Argument`: a source that is no `G…`, a fee above `u32`, a sequence not a positive `i64`, no time
    /// bound or `min_time` after it, a payment not a positive `i64` or to no `G…`, a host call whose terms were refused.
    pub fn xdr(&self) -> Result<Vec<u8>> {
        let source = account(&self.source)?;
        let fee = u32::try_from(self.fee).map_err(|_| Error::Argument)?;
        let seq = i64::try_from(self.seq).map_err(|_| Error::Argument)?;
        if seq <= 0 || self.max_time == 0 || self.min_time > self.max_time {
            return Err(Error::Argument);
        }
        let mut o = Vec::with_capacity(512);
        u32be(&mut o, 0); // KEY_TYPE_ED25519
        o.extend_from_slice(&source);
        u32be(&mut o, fee);
        o.extend_from_slice(&seq.to_be_bytes());
        u32be(&mut o, 1); // PRECOND_TIME
        o.extend_from_slice(&self.min_time.to_be_bytes());
        o.extend_from_slice(&self.max_time.to_be_bytes());
        u32be(&mut o, 0); // MEMO_NONE
        u32be(&mut o, 1); // one operation, no source of its own
        u32be(&mut o, 0);
        match &self.op {
            TxOp::Payment {
                destination,
                amount,
            } => {
                let amount = i64::try_from(*amount).map_err(|_| Error::Argument)?;
                if amount <= 0 {
                    return Err(Error::Argument);
                }
                u32be(&mut o, OP_PAYMENT);
                u32be(&mut o, 0);
                o.extend_from_slice(&account(destination)?);
                u32be(&mut o, 0); // ASSET_TYPE_NATIVE
                o.extend_from_slice(&amount.to_be_bytes());
                u32be(&mut o, 0); // ext v0
            }
            TxOp::Invoke {
                op,
                signature,
                data,
            } => {
                let op = op.as_ref().ok_or(Error::Argument)?;
                u32be(&mut o, OP_INVOKE_HOST_FUNCTION);
                u32be(&mut o, 0); // HOST_FUNCTION_TYPE_INVOKE_CONTRACT
                op.call(&mut o);
                match signature {
                    None => u32be(&mut o, 0),
                    Some(sig) => {
                        u32be(&mut o, 1);
                        u32be(&mut o, 1); // SOROBAN_CREDENTIALS_ADDRESS
                        Address::Account(op.subject_key()).sc_address(&mut o);
                        o.extend_from_slice(&op.nonce().to_be_bytes());
                        u32be(&mut o, op.expiry());
                        account_signature(&mut o, &op.subject_key(), sig);
                        op.invocation(&mut o);
                    }
                }
                match data {
                    None => u32be(&mut o, 0),
                    Some(d) => {
                        u32be(&mut o, 1);
                        d.xdr(&mut o)?;
                    }
                }
            }
        }
        Ok(o)
    }

    /// The transaction's id: `sha256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx)`.
    pub fn hash(&self, network_id: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(id(network_id, &self.xdr()?))
    }

    /// The envelope with no signature: what a simulation reads (the host ignores the signatures there).
    pub fn unsigned_envelope(&self) -> Result<Vec<u8>> {
        let mut e = vec![];
        u32be(&mut e, ENVELOPE_TYPE_TX);
        e.extend_from_slice(&self.xdr()?);
        u32be(&mut e, 0);
        Ok(e)
    }
}

fn id(network_id: &[u8; 32], tx: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(network_id);
    h.update(ENVELOPE_TYPE_TX.to_be_bytes());
    h.update(tx);
    h.finalize().into()
}

/// A `G…` account's credential signature as the host reads it: `Vec[Map{public_key: Bytes, signature: Bytes}]`.
fn account_signature(o: &mut Vec<u8>, pk: &[u8; 32], sig: &[u8; 64]) {
    u32be(o, 16); // ScVal::Vec, present, one item
    u32be(o, 1);
    u32be(o, 1);
    u32be(o, 17); // ScVal::Map, present, two entries, keys sorted
    u32be(o, 1);
    u32be(o, 2);
    for (k, v) in [(&b"public_key"[..], &pk[..]), (&b"signature"[..], &sig[..])] {
        u32be(o, 15);
        opaque(o, k);
        u32be(o, 13);
        opaque(o, v);
    }
}

impl NativeKey {
    /// The subject's signature of a checked op (T27.soroban): ed25519 over [`Checked::digest`], on a `stellar` key that is the op's
    /// `from` only (`Argument` otherwise). The key signs only `check_terms`' own output.
    pub fn sign_soroban_auth(&self, op: &Checked) -> Result<[u8; 64]> {
        if self.network != Network::Stellar || self.public_key != op.subject_key() {
            return Err(Error::Argument);
        }
        let sig = self.sign_request(&SignRequest::RawMessage {
            message: op.digest().to_vec(),
        })?;
        sig.try_into().map_err(|_| Error::Argument)
    }

    /// The source's signature of `tx` (T41.soroban): ed25519 over its id, on the `stellar` key that is `tx.source` only, and a
    /// host call only with its auth entry and its simulation's data (`Argument` otherwise). The key signs only [`SorobanTx::xdr`]'s
    /// own output.
    pub fn sign_soroban_tx(
        &self,
        network_id: &[u8; 32],
        tx: &SorobanTx,
    ) -> Result<SignedSorobanTx> {
        if self.network != Network::Stellar || self.public_key != account(&tx.source)? {
            return Err(Error::Argument);
        }
        if matches!(
            &tx.op,
            TxOp::Invoke {
                signature: None,
                ..
            } | TxOp::Invoke { data: None, .. }
        ) {
            return Err(Error::Argument);
        }
        let x = tx.xdr()?;
        let hash = id(network_id, &x);
        let signature: [u8; 64] = self
            .sign_request(&SignRequest::RawMessage {
                message: hash.to_vec(),
            })?
            .try_into()
            .map_err(|_| Error::Argument)?;
        let mut hint = [0u8; 4];
        hint.copy_from_slice(self.public_key.get(28..32).ok_or(Error::Argument)?);
        let mut envelope = Vec::with_capacity(x.len() + 80);
        u32be(&mut envelope, ENVELOPE_TYPE_TX);
        envelope.extend_from_slice(&x);
        u32be(&mut envelope, 1);
        envelope.extend_from_slice(&hint);
        opaque(&mut envelope, &signature);
        Ok(SignedSorobanTx {
            tx: x,
            hash,
            signature,
            hint,
            envelope,
        })
    }
}
