# zether-msm cryptographic review: the models

The scripts that reproduce the main results of `docs/research/zether-msm-crypto-review.md`, a machine review of snapshot `6fed9881`,
not an independent audit. They transcribe the verifier at that snapshot, before the `isSupportedOnThisChain` probes and the
`verifyFold` weight guard, neither of which moves a fold scalar. They are not a test gate.

Needs `py_ecc`, `sympy` and `pycryptodome`. Run from this directory through `scripts/capped`; they use exact curve arithmetic in
pure Python, so expect minutes.

| Script | Shows | Expected last line |
|---|---|---|
| `fold_equivalence.py` | the fold identity, slot by slot: symbolic at M = 1, 2, 3, 16, numeric at M = 1..16, every form | `ALL FORMS MATCH` |
| `zv.py` | the model the three below import: verifier, prover port, G1MSM semantics. Reads `test/vectors/zether/generators_bls12381.json` | none, a library |
| `attacks.py` | targeted forgeries, each with the code line that stops it | `UNEXPECTED verdicts: none` |
| `malleability.py` | every single-field edit of a proof | `single-field edits accepted: 0/51` |
| `torsion.py` | a hypothetical MSM with no subgroup check | `2/6 ... accepted (expected ~1/3); with the check: 0/6` |
