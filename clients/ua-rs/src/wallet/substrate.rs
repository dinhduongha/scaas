// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Polkadot sr25519 (ua-rs-native spec §7; CLI-SGN-53, CLI-UAL-46): the `substrate-bip39` mini-secret from the BIP-39 entropy and
//! the passphrase as given (computed at open, kept in the arena), schnorrkel 0.11's Ed25519-mode expansion (the bare account),
//! the junction path grammar and chain codes of `sp-core` / polkadot.js with the refusals of §7.3, SS58, and signing with context
//! `substrate` over a one-shot RNG fed by `os_aux()`: an OS-RNG failure is `Error::Rng`, never a panic inside merlin, and every
//! signature is verified before it leaves. UNAUDITED.
use super::{Error, Result};
use rand_core::{CryptoRng, RngCore};
use schnorrkel::derive::{ChainCode, Derivation};
use schnorrkel::{
    context::attach_rng, signing_context, ExpansionMode, MiniSecretKey, PublicKey, SecretKey,
    Signature,
};
use zeroize::{Zeroize, Zeroizing};

const CONTEXT: &[u8] = b"substrate";
pub const MAX_PATH_BYTES: usize = 512;
pub const MAX_JUNCTIONS: usize = 16;
pub const MAX_JUNCTION_BYTES: usize = 64;

/// `substrate-bip39` `mini_secret_from_entropy`: `PBKDF2-HMAC-SHA512(entropy, "mnemonic" ‖ UTF-8(passphrase), 2048)[0..32]`; the
/// passphrase as given, not NFKD (an NFC and an NFD spelling are two accounts).
pub(crate) fn mini_secret(entropy: &[u8], passphrase: &str) -> Zeroizing<[u8; 32]> {
    let salt = Zeroizing::new([&b"mnemonic"[..], passphrase.as_bytes()].concat());
    let mut dk = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(entropy, &salt, 2048, &mut dk[..]);
    let mut mini = Zeroizing::new([0u8; 32]);
    mini.iter_mut().zip(dk.iter()).for_each(|(m, d)| *m = *d);
    mini
}

/// The bare account (spec §7.2): `MiniSecretKey::expand(ExpansionMode::Ed25519)`, as its 64-byte `SecretKey::to_bytes`.
pub(crate) fn bare(mini: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let m = MiniSecretKey::from_bytes(mini).map_err(|_| Error::Argument)?;
    Ok(Zeroizing::new(m.expand(ExpansionMode::Ed25519).to_bytes()))
}

fn secret(sk: &[u8]) -> Result<SecretKey> {
    SecretKey::from_bytes(sk).map_err(|_| Error::Argument)
}

/// The 32-byte public key of a 64-byte secret.
pub(crate) fn public(sk: &[u8]) -> Result<Vec<u8>> {
    Ok(secret(sk)?.to_public().to_bytes().to_vec())
}

/// One junction: hard (`//`) or soft (`/`) and its chain code.
pub(crate) struct Junction {
    pub hard: bool,
    pub chain_code: [u8; 32],
}

/// A junction's chain code (spec §7.3): a digit-only junction is its `u64` little-endian, any other the SCALE string (compact
/// length: one byte `len << 2` below 64, two bytes `(len << 2) | 1` LE at 64) ‖ bytes; an encoding of at most 32 bytes zero-padded
/// to 32, a longer one replaced by its BLAKE2b-256.
fn chain_code(j: &[u8]) -> Result<[u8; 32]> {
    use blake2::Digest as _;
    let enc = if j.iter().all(u8::is_ascii_digit) {
        let s = core::str::from_utf8(j).map_err(|_| Error::Argument)?;
        s.parse::<u64>()
            .map_err(|_| Error::Argument)?
            .to_le_bytes()
            .to_vec()
    } else if j.len() < 64 {
        [
            &[u8::try_from(j.len() << 2).map_err(|_| Error::Argument)?][..],
            j,
        ]
        .concat()
    } else {
        [
            &u16::try_from((j.len() << 2) | 1)
                .map_err(|_| Error::Argument)?
                .to_le_bytes()[..],
            j,
        ]
        .concat()
    };
    let mut cc = [0u8; 32];
    if enc.len() <= 32 {
        cc.iter_mut().zip(&enc).for_each(|(c, e)| *c = *e);
    } else {
        cc.copy_from_slice(&blake2::Blake2b::<blake2::digest::consts::U32>::digest(
            &enc,
        ));
    }
    Ok(cc)
}

/// The junctions of `path` (spec §7.3): `//` hard, `/` soft, `""` the bare key. `Argument` for `///` (a password part), an empty
/// junction, a byte outside `0x21`–`0x7e`, a junction over 64 bytes, a `0x` or `+` prefix, a digit-only junction outside `u64` or
/// with a leading zero (other than `0`), more than 16 junctions or 512 bytes. A path that passes is its own canonical spelling.
pub(crate) fn parse_path(path: &str) -> Result<Vec<Junction>> {
    let b = path.as_bytes();
    if b.len() > MAX_PATH_BYTES {
        return Err(Error::Argument);
    }
    let mut out = Vec::new();
    let mut rest = b;
    while let Some(after) = rest.strip_prefix(b"/") {
        let (hard, after) = match after.strip_prefix(b"/") {
            Some(a) => (true, a),
            None => (false, after),
        };
        let end = after.iter().position(|c| *c == b'/').unwrap_or(after.len());
        let (j, tail) = after.split_at(end);
        let digits = j.iter().all(u8::is_ascii_digit);
        if j.is_empty()
            || j.len() > MAX_JUNCTION_BYTES
            || j.iter().any(|c| !(0x21..=0x7e).contains(c))
            || j.starts_with(b"0x")
            || j.starts_with(b"+")
            || (digits && j.len() > 1 && j.first() == Some(&b'0'))
        {
            return Err(Error::Argument);
        }
        out.push(Junction {
            hard,
            chain_code: chain_code(j)?,
        });
        if out.len() > MAX_JUNCTIONS {
            return Err(Error::Argument);
        }
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::Argument);
    }
    Ok(out)
}

/// An RNG that yields 32 given bytes once, then wipes them; any further read, or a read of another length, yields zeros and marks
/// it misused, and its caller then discards the result (`Error::Rng`). Only merlin's `finalize` reads it (one 32-byte
/// `fill_bytes`, plan T0).
struct OneShot {
    r: Zeroizing<[u8; 32]>,
    reads: u32,
    misused: bool,
}

impl OneShot {
    fn new(r: [u8; 32]) -> OneShot {
        OneShot {
            r: Zeroizing::new(r),
            reads: 0,
            misused: false,
        }
    }
    /// `Ok` only after exactly one read of 32 bytes.
    fn check(&self) -> Result<()> {
        #[cfg(feature = "vectors")]
        vectors::note_reads(self.reads);
        if self.reads == 1 && !self.misused {
            Ok(())
        } else {
            Err(Error::Rng)
        }
    }
}

impl RngCore for OneShot {
    fn next_u32(&mut self) -> u32 {
        self.misused = true;
        0
    }
    fn next_u64(&mut self) -> u64 {
        self.misused = true;
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reads = self.reads.saturating_add(1);
        if self.reads == 1 && dest.len() == 32 {
            dest.copy_from_slice(self.r.as_slice());
        } else {
            self.misused = true;
            dest.fill(0);
        }
        self.r.zeroize();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for OneShot {}

/// The key of `junctions` from the bare secret: hard steps `hard_derive_mini_secret_key` → Ed25519 expansion, soft steps
/// `derived_key_simple_rng` over the one-shot RNG of `rand()` (a soft step draws a fresh nonce half).
pub(crate) fn derive(
    bare: &[u8],
    junctions: &[Junction],
    mut rand: impl FnMut() -> Result<[u8; 32]>,
) -> Result<Zeroizing<[u8; 64]>> {
    let mut sk = secret(bare)?;
    for j in junctions {
        sk = if j.hard {
            sk.hard_derive_mini_secret_key(Some(ChainCode(j.chain_code)), b"")
                .0
                .expand(ExpansionMode::Ed25519)
        } else {
            let mut rng = OneShot::new(rand()?);
            let (child, _) = sk.derived_key_simple_rng(ChainCode(j.chain_code), b"", &mut rng);
            rng.check()?;
            child
        };
    }
    Ok(Zeroizing::new(sk.to_bytes()))
}

/// sr25519 over `msg` with context `substrate` and randomness `r` through the one-shot RNG, verified against `check` (the key's own
/// public key in the release path) before it leaves; 64 bytes, schnorrkel's marker bit set.
pub(crate) fn sign(sk: &[u8], msg: &[u8], r: [u8; 32], check: &[u8]) -> Result<Vec<u8>> {
    let kp = secret(sk)?.to_keypair();
    let mut rng = OneShot::new(r);
    let sig = kp.sign(attach_rng(signing_context(CONTEXT).bytes(msg), &mut rng));
    rng.check()?;
    if !verify(check, msg, &sig.to_bytes()) {
        return Err(Error::Argument);
    }
    Ok(sig.to_bytes().to_vec())
}

/// sr25519 Verify with context `substrate`.
pub(crate) fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(pk), Signature::from_bytes(sig)) else {
        return false;
    };
    pk.verify(signing_context(CONTEXT).bytes(msg), &sig).is_ok()
}

/// SS58 (spec §7.4): `base58(pre ‖ pk ‖ BLAKE2b-512("SS58PRE" ‖ pre ‖ pk)[0..2])`, `pre` one byte below 64, else two; prefix 0 to
/// 16,383, not 46 or 47.
pub(crate) fn ss58(pk: &[u8], prefix: u16) -> Result<String> {
    use blake2::Digest as _;
    if prefix > 16_383 || prefix == 46 || prefix == 47 || pk.len() != 32 {
        return Err(Error::Argument);
    }
    let [lo, hi] = prefix.to_le_bytes();
    let pre = if prefix < 64 {
        vec![lo]
    } else {
        vec![((lo & 0xfc) >> 2) | 0x40, hi | ((lo & 0x03) << 6)]
    };
    let sum = blake2::Blake2b512::digest([&b"SS58PRE"[..], &pre, pk].concat());
    Ok(bs58::encode([&pre[..], pk, sum.get(..2).ok_or(Error::Argument)?].concat()).into_string())
}

/// The 32-byte key an SS58 `address` names under `prefix` (spec §7.4, the inverse of [`ss58`]): base58 of 35 bytes (one prefix
/// byte, below 64) or 36 (two), that prefix, the key and the first two bytes of `BLAKE2b-512("SS58PRE" ‖ pre ‖ pk)`. `Argument`:
/// another prefix, another length, a bad checksum, not base58, a prefix [`ss58`] refuses.
pub fn ss58_public_key(address: &str, prefix: u16) -> Result<[u8; 32]> {
    let raw = bs58::decode(address)
        .into_vec()
        .map_err(|_| Error::Argument)?;
    let pk: [u8; 32] = raw
        .len()
        .checked_sub(34)
        .and_then(|at| raw.get(at..at + 32))
        .and_then(|k| k.try_into().ok())
        .ok_or(Error::Argument)?;
    if ss58(&pk, prefix)? != address {
        return Err(Error::Argument);
    }
    Ok(pk)
}

/// The `System.Account` storage key of an sr25519 account (`frame_system`'s map, hasher `Blake2_128Concat`):
/// `twox128("System") ‖ twox128("Account") ‖ BLAKE2b-128(pk) ‖ pk`, 80 bytes.
pub fn system_account_key(pk: &[u8; 32]) -> [u8; 80] {
    use blake2::Digest as _;
    // twox128("System") ‖ twox128("Account"): constants of every FRAME chain
    const PREFIX: [u8; 32] = [
        0x26, 0xaa, 0x39, 0x4e, 0xea, 0x56, 0x30, 0xe0, 0x7c, 0x48, 0xae, 0x0c, 0x95, 0x58, 0xce,
        0xf7, 0xb9, 0x9d, 0x88, 0x0e, 0xc6, 0x81, 0x79, 0x9c, 0x0c, 0xf3, 0x0e, 0x88, 0x86, 0x37,
        0x1d, 0xa9,
    ];
    let h = blake2::Blake2b::<blake2::digest::consts::U16>::digest(pk);
    let mut k = [0u8; 80];
    k[..32].copy_from_slice(&PREFIX);
    k[32..48].copy_from_slice(&h);
    k[48..].copy_from_slice(pk);
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The one-shot RNG yields its bytes once; a second read gets zeros and marks it misused (spec §7.5).
    #[test]
    fn one_shot_yields_once() {
        let mut o = OneShot::new([7; 32]);
        let (mut a, mut b) = ([0u8; 32], [1u8; 32]);
        o.fill_bytes(&mut a);
        assert!(a == [7; 32] && o.check().is_ok());
        o.fill_bytes(&mut b);
        assert!(b == [0; 32] && o.misused && o.check() == Err(Error::Rng));
        let mut short = OneShot::new([7; 32]);
        short.fill_bytes(&mut [0u8; 16]);
        assert!(short.misused);
    }
}

#[cfg(feature = "vectors")]
pub(crate) mod vectors {
    use std::cell::Cell;
    thread_local! {
        static READS: Cell<u32> = const { Cell::new(0) };
    }
    pub(crate) fn note_reads(n: u32) {
        READS.with(|r| r.set(n));
    }
    /// The reads of the last one-shot RNG this thread checked.
    pub fn one_shot_reads() -> u32 {
        READS.with(Cell::get)
    }
}
