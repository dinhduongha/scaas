//! Plonky3 configuration: Goldilocks, quadratic extension, FRI, Keccak-f Merkle trees, Keccak-256 challenger
//! seeded with the statement digest (pqzh-design.md §4). Plain and hiding (zero-knowledge) variants.

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::ring::F;

pub type Challenge = BinomialExtensionField<F, 2>;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, 2, 4>;
type HidingValMmcs =
    MerkleTreeHidingMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, StdRng, 2, 4, 4>;
type Challenger = SerializingChallenger64<F, HashChallenger<u8, Keccak256Hash, 32>>;
type Dft = Radix2DitParallel<F>;

pub type PlainConfig =
    StarkConfig<TwoAdicFriPcs<F, Dft, ValMmcs, ExtensionMmcs<F, Challenge, ValMmcs>>, Challenge, Challenger>;
pub type ZkConfig = StarkConfig<
    HidingFriPcs<F, Dft, HidingValMmcs, ExtensionMmcs<F, Challenge, HidingValMmcs>, StdRng>,
    Challenge,
    Challenger,
>;

/// FRI parameters, fixed per proofSystemId and never read from the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub max_log_arity: usize,
    pub log_final_poly_len: usize,
    pub query_pow_bits: usize,
    pub commit_pow_bits: usize,
    pub cap_height: usize,
    pub zk: bool,
    /// layout, not FRI: accumulator columns of the MV AIR (outputs per stacked group)
    pub mv_width: usize,
}

impl Params {
    /// Default: blowup 16, 28 queries + 16 grinding bits = 128 bits by the ethSTARK conjectured formula
    /// (queries * log_blowup + pow bits), FRI arity 8. Blowup 8 / 38 queries gave R_TX 178 KB, over MAX_PROOF.
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

    fn hashes() -> (FieldHash, Compress) {
        let h = U64Hash::new(KeccakF {});
        (FieldHash::new(h), Compress::new(h))
    }

    /// The challenger starts from the 32-byte statement digest (strong Fiat-Shamir).
    pub fn plain(&self, seed: &[u8; 32]) -> PlainConfig {
        let (fh, c) = Self::hashes();
        let mmcs = ValMmcs::new(fh, c, self.cap_height);
        let fri = self.fri(ExtensionMmcs::new(mmcs.clone()));
        let pcs = TwoAdicFriPcs::new(Dft::default(), mmcs, fri);
        StarkConfig::new(pcs, Challenger::from_hasher(seed.to_vec(), Keccak256Hash {}))
    }

    /// Hiding variant; `rnd` seeds the masks and salts (prover randomness; the verifier passes anything).
    pub fn zk(&self, seed: &[u8; 32], rnd: [u8; 32]) -> ZkConfig {
        let (fh, c) = Self::hashes();
        let mut r = StdRng::from_seed(rnd);
        let mmcs = HidingValMmcs::new(fh, c, self.cap_height, StdRng::from_rng(&mut r));
        let fri = self.fri(ExtensionMmcs::new(mmcs.clone()));
        let pcs = HidingFriPcs::new(Dft::default(), mmcs, fri, 4, StdRng::from_rng(&mut r));
        StarkConfig::new(pcs, Challenger::from_hasher(seed.to_vec(), Keccak256Hash {}))
    }
}
