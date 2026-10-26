# pqz-core/pqzl/params/aprime — parameter candidates for `K_MAX` ≈ 65,536 (plan Task 5h, design; history)

Owner choice of 2026-10-19 (decisions CTR-PQZ-06): larger lattice parameters so that the credit cap `K_MAX` reaches
≈ 65,536. This folder measured the candidates; nothing here is a frozen relation. The outcome is the parameter set
`n2816-kmax65536` ([`pqz-core/params/sets/n2816-kmax65536/`](../../../params/sets/README.md); a full PQZL set since
owner 2026-10-24, no PQZH), whose specs `gen_set.py` generates there; this folder is its research record. Design and conclusions:
[`docs/superpowers/specs/2026-10-20-pqz-state-redesign.md`](../../../../docs/superpowers/specs/2026-10-20-pqz-state-redesign.md) §6.

| File | What |
|---|---|
| `aprime.sage`, `run.sh` → `aprime.txt` | per candidate (n, q, K): the noise and digit budget of pq-zero-knowledge.md §4.3 generalised, sizes, encryption security (lattice-estimator `53da598` primal uSVP and full `LWE.estimate`; leaky-LWE-Estimator `0a9caf8` DDGR20 worst-case mixed hints at 0 / 32 / 80) |
| `ap<n>_<rel>_params.sage`, `run_proof.sh` → `proof-aprime.txt` | LaZer codegen sizing specs (n = 2688 and 2816, q = 2^54 − 327, the candidates' bit layouts) run through `../e_s1_proof.sage` unchanged: MSIS / MLWE ranks and the codegen proof size |

**Superseded research record (review finding F-7, 2026-10-25).** The `ap2816_*.sage` specs carry `pqz_delta` but no
`kmlwe_min`, so their proof MLWE rank came out at 41, where `proof-aprime.txt` shows dual_hybrid β 447 / 448 < 450; the
production set `n2816-kmax65536` has `kmlwe_min = 42` (dual_hybrid 462 / 463, `pqz-core/params/sets/n2816-kmax65536/`
`set.toml` and `SET.md` say why). Nothing builds from these specs.

## Rerun

```sh
git clone https://github.com/lducas/leaky-LWE-Estimator /tmp/lk && git -C /tmp/lk checkout 0a9caf8
git clone https://github.com/malb/lattice-estimator /tmp/le && git -C /tmp/le checkout 53da598
git clone https://github.com/lazer-crypto/lazer /tmp/lz && git -C /tmp/lz checkout 3330e48
# one DDGR20 instance at n ~ 2800 needs ~ 4 GB: run the candidates in parts (the container has --memory 5g)
ONLY=0,1,2,3 PARTS=2 scripts/capped pqz-core/pqzl/params/aprime/run.sh /tmp/lk /tmp/le
ONLY=4 PARTS=2       scripts/capped pqz-core/pqzl/params/aprime/run.sh /tmp/lk /tmp/le
ONLY=0,1,3,4 PARTS=3 scripts/capped pqz-core/pqzl/params/aprime/run.sh /tmp/lk /tmp/le
scripts/capped pqz-core/pqzl/params/aprime/run_proof.sh /tmp/lz /tmp/le ap2816_tx ap2816_burn ap2816_reg ap2816_txm8 \
  ap2688_tx ap2688_burn ap2688_reg ap2688_txm8
```

`aprime.txt` is the concatenation of those runs (the first run, with every candidate, was killed by the container's
3 GB limit at n = 2816 after n = 2688; candidates n = 3072 were not run through DDGR20: they fail the budget at
q = 2^54, and q = 2^55 is an option only).
