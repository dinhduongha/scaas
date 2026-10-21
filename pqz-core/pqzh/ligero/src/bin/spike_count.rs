//! Research spike B (plan 5h Task 8c spike, 2026-10-22; throwaway, kept as the record): base-field products of the
//! prover and of the verifier per relation at the build's preset (fq::spike_count: F_q products, 16 per F_q^4 product,
//! 4 per lazy term, the FFT's products; the honest prover's integer ring checks are not counted: the same at every
//! preset). Seed [0; 32]. No timing.
//!   spike_count       (--features spike-count,set-n2304-kmax4096: preset B; + fallback-retry: THE preset)

use pqzh_ligero::client::{inputs, rel_name, setup};
use pqzh_ligero::fq::spike_count;
use pqzh_ligero::{Params, RELS, Rel, multi_rels, prove, verify};

fn main() {
    let p = Params::proven();
    let s = setup();
    println!("{{\"set\": \"{}\", \"n\": {}, \"k\": {}, \"t\": {}, \"ell\": {}, \"n2\": {}}}", pqzh_ligero::set::NAME, p.n, p.k, p.t, p.ell, p.n2());
    for r in RELS.iter().map(|&f| Rel::Form(f)).chain(multi_rels()) {
        let (st, w) = inputs(&s, r);
        spike_count::take();
        let pf = prove(r.op(), &st, &w, [0; 32], &p).expect("prove");
        let cp = spike_count::take();
        let ok = verify(r.op(), &st, &pf, &p);
        let cv = spike_count::take();
        println!("{{\"rel\": \"{}\", \"proof_bytes\": {}, \"prover_products\": {cp}, \"verifier_products\": {cv}, \"verify\": {ok}}}", rel_name(r), pf.len());
    }
}
