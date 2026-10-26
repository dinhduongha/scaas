# Superseded per-set generators (backup, not deleted)

Owner 2026-10-21 (per-set generation redesign): one input file per set (`../<set>/set.toml`) and one generic generator
/ driver (`../gen_set.py`, `../make.sh`) replace the per-set copies. Kept here as the record of how `n2304-kmax4096`'s specs and
headers were first made (plan 5h Task 8b):

| File | Was | Replaced by |
|---|---|---|
| `n2304-kmax4096/gen_pa.py` | `n2304-kmax4096`'s 14 LaZer codegen specs from hard-coded n / K_MAX / q | `gen_set.py n2304-kmax4096` (at the switch the same specs apart from the header comment lines: `gen_set.py`'s self-check pinned m1 / nbin / log2q, and the specs it wrote equalled gen_pa.py's with comment lines removed; the R0 review fix of 2026-10-25 has since changed the reg / dr / audited txm4 / txm8 specs, `pqz-core/research/code-review-2026-10-25/r01a-limits/`) |
| `n2304-kmax4096/regen.sh` | LaZer codegen of those specs + `to_rust.py` | `make.sh n2304-kmax4096 codegen rust` |

They are not run by any gate; paths inside them refer to their old location `../n2304-kmax4096/`.
