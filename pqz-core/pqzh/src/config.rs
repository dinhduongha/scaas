//! Plonky3 configuration of PQZH (one configuration, EVM-friendly choices of pqzh-solidity-verifier.md §6, owner
//! 2026-10-13): Goldilocks, FRI, Merkle trees of Keccak-256 over big-endian field elements (node = keccak256(l || r)),
//! a Keccak-256 challenger that absorbs and samples big-endian 8-byte words, seeded with the 32-byte statement digest
//! (rel::stmt_digest, itself Keccak-256). Plain and hiding (zero-knowledge) variants; challenge field Goldilocks^2 or
//! Goldilocks^5 (the PQZH choice).

use p3_challenger::{
    ByteGrindingChallenger, CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::{MerkleCap, MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha3::Digest;

use crate::ring::F;

pub type Challenge = BinomialExtensionField<F, 2>;
/// Quintic extension (≈ 2^320): the PQZH challenge field (owner 2026-10-13; pqzh-prototype.md §7).
pub type Challenge5 = BinomialExtensionField<F, 5>;

/// Leaf hash: keccak256(be8(x_0) || be8(x_1) || ...) of the canonical values of a row.
#[derive(Clone, Copy, Debug, Default)]
pub struct BeKeccak;

impl CryptographicHasher<F, [u8; 32]> for BeKeccak {
    fn hash_iter<I: IntoIterator<Item = F>>(&self, input: I) -> [u8; 32] {
        let mut h = sha3::Keccak256::new();
        for x in input {
            h.update(x.as_canonical_u64().to_be_bytes());
        }
        h.finalize().into()
    }
}

type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<F, u8, BeKeccak, Compress, 2, 32>;
type HidingValMmcs = MerkleTreeHidingMmcs<F, u8, BeKeccak, Compress, StdRng, 2, 32, 4>;
type Dft = Radix2DitParallel<F>;

/// Plonky3's SerializingChallenger64 over a Keccak-256 HashChallenger, with big-endian words: a field element is
/// absorbed as be8(canonical value), a sample reads 8 output bytes as a big-endian u64 (pqzh-solidity-verifier.md §6).
#[derive(Clone, Debug)]
pub struct BeChallenger(HashChallenger<u8, Keccak256Hash, 32>);

impl BeChallenger {
    pub fn new(seed: &[u8; 32]) -> Self {
        BeChallenger(HashChallenger::new(seed.to_vec(), Keccak256Hash {}))
    }
    fn word(&mut self) -> u64 {
        u64::from_be_bytes(self.0.sample_array())
    }
}

impl CanObserve<F> for BeChallenger {
    fn observe(&mut self, v: F) {
        self.0.observe_slice(&v.as_canonical_u64().to_be_bytes());
    }
}

impl<const N: usize> CanObserve<&MerkleCap<F, [u8; N]>> for BeChallenger {
    fn observe(&mut self, cap: &MerkleCap<F, [u8; N]>) {
        for d in cap.roots() {
            self.0.observe_slice(d);
        }
    }
}

impl<const N: usize> CanObserve<MerkleCap<F, [u8; N]>> for BeChallenger {
    fn observe(&mut self, cap: MerkleCap<F, [u8; N]>) {
        self.observe(&cap);
    }
}

impl<EF: BasedVectorSpace<F>> CanSample<EF> for BeChallenger {
    fn sample(&mut self) -> EF {
        // rejection sampling of a 64-bit word below p
        EF::from_basis_coefficients_fn(|_| loop {
            let v = self.word();
            if v < F::ORDER_U64 {
                break F::from_u64(v);
            }
        })
    }
}

impl CanSampleBits<usize> for BeChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < 64);
        (self.word() & ((1u64 << bits) - 1)) as usize
    }
}

impl CanSampleUniformBits<F> for BeChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(&mut self, bits: usize) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits)) // bytes from the hash are uniform: no rejection band
    }
}

impl FieldChallenger<F> for BeChallenger {}

impl GrindingChallenger for BeChallenger {
    type Witness = F;

    /// As SerializingChallenger64::grind: squeeze, then the witness w passes if the low `bits` of the next sampled
    /// word are zero after absorbing be8(w).
    fn grind(&mut self, bits: usize) -> F {
        if bits == 0 {
            return F::ZERO;
        }
        let mut sq = self.clone();
        let _: u8 = sq.0.sample();
        let mask = (1u64 << bits) - 1;
        let i = sq
            .0
            .find_witness(F::ORDER_U64, |i| i.to_be_bytes(), |b: [u8; 8]| u64::from_be_bytes(b) & mask == 0)
            .expect("no proof-of-work witness");
        let w = F::from_u64(i);
        assert!(self.check_witness(bits, w));
        w
    }

    fn check_witness(&mut self, bits: usize, w: F) -> bool {
        if bits == 0 {
            return true;
        }
        let _: u8 = self.0.sample();
        self.observe(w);
        self.sample_bits(bits) == 0
    }
}

pub type PlainCfg<EF> = StarkConfig<TwoAdicFriPcs<F, Dft, ValMmcs, ExtensionMmcs<F, EF, ValMmcs>>, EF, BeChallenger>;
pub type PlainConfig = PlainCfg<Challenge>;
pub type Plain5Config = PlainCfg<Challenge5>;
pub type ZkCfg<EF> =
    StarkConfig<HidingFriPcs<F, Dft, HidingValMmcs, ExtensionMmcs<F, EF, HidingValMmcs>, StdRng>, EF, BeChallenger>;
pub type ZkConfig = ZkCfg<Challenge>;
pub type Zk5Config = ZkCfg<Challenge5>;

/// FRI parameters, fixed per proofSystemId and never read from the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub max_log_arity: usize,
    pub log_final_poly_len: usize,
    pub query_pow_bits: usize,
    pub commit_pow_bits: usize,
    pub cap_height: usize,
    pub zk: bool,
    /// challenge field Goldilocks^5 instead of Goldilocks^2
    pub ext5: bool,
    /// proof-length limit checked before parsing (the PQZH kind: rel::MAX_PROOF; larger only for measurements)
    pub max_proof: usize,
    /// layout, not FRI: accumulator columns of the MV AIR (outputs per stacked group)
    pub mv_width: usize,
}

impl Params {
    /// Default: blowup 16, 28 queries + 16 grinding bits = 128 bits by the ethSTARK conjectured formula
    /// (queries * log_blowup + pow bits), FRI arity 8; p3-security 0.8.0 gives 100.6 bits conjectured / 71.9 proven
    /// (pqzh-prototype.md §7). Blowup 8 / 38 queries gave R_TX 176-178 KB, over MAX_PROOF.
    /// Proven bits for this and other settings: src/bin/pqzh_security.rs.
    pub const DEFAULT: Params = Params {
        log_blowup: 4,
        num_queries: 28,
        max_log_arity: 3,
        log_final_poly_len: 3,
        query_pow_bits: 16,
        commit_pow_bits: 0,
        cap_height: 0,
        zk: false,
        ext5: false,
        max_proof: crate::rel::MAX_PROOF,
        mv_width: 9,
    };

    fn fri<M>(&self, mmcs: M) -> FriParameters<M> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: self.max_log_arity,
            num_queries: self.num_queries,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: self.commit_pow_bits,
            query_proof_of_work_bits: self.query_pow_bits,
            mmcs,
        }
    }

    /// The challenger starts from the 32-byte statement digest (strong Fiat-Shamir).
    pub fn plain(&self, seed: &[u8; 32]) -> PlainConfig {
        self.plain_ext(seed)
    }

    pub fn plain_ext<EF: ExtensionField<F> + TwoAdicField>(&self, seed: &[u8; 32]) -> PlainCfg<EF> {
        let mmcs = ValMmcs::new(BeKeccak, Compress::new(Keccak256Hash {}), self.cap_height);
        let fri = self.fri(ExtensionMmcs::new(mmcs.clone()));
        let pcs = TwoAdicFriPcs::new(Dft::default(), mmcs, fri);
        StarkConfig::new(pcs, BeChallenger::new(seed))
    }

    /// Hiding variant; `rnd` seeds the masks and salts (prover randomness; the verifier passes anything).
    pub fn zk_ext<EF: ExtensionField<F> + TwoAdicField>(&self, seed: &[u8; 32], rnd: [u8; 32]) -> ZkCfg<EF> {
        let mut r = StdRng::from_seed(rnd);
        let mmcs =
            HidingValMmcs::new(BeKeccak, Compress::new(Keccak256Hash {}), self.cap_height, StdRng::from_rng(&mut r));
        let fri = self.fri(ExtensionMmcs::new(mmcs.clone()));
        let pcs = HidingFriPcs::new(Dft::default(), mmcs, fri, 4, StdRng::from_rng(&mut r));
        StarkConfig::new(pcs, BeChallenger::new(seed))
    }

    pub fn zk(&self, seed: &[u8; 32], rnd: [u8; 32]) -> ZkConfig {
        self.zk_ext(seed, rnd)
    }
}
