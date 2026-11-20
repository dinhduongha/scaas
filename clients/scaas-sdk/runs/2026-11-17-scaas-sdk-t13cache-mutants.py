# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13, owner 2026-11-19 T1: the ML-DSA expanded-key cache before registration (`cacheExpandedKey`) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13cache-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/account/register.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test account_ops -- --exact "
MUTANTS = [
    ("the cache written on a registry with the precompile (no probe)",
     [(R, "Bytes::from(probe))\n                .await\n                .is_ok()",
          "Bytes::from(probe))\n                .await\n                .is_ok()\n                || true")],
     T + "mldsa_cache_then_register"),
    ("a stored part written again",
     [(R, "                    if !read_record(&pool, registry, Landed::Cached(p), &ua).await? {",
          "                    if !read_record(&pool, registry, Landed::Cached(p), &ua).await? || true {")],
     T + "mldsa_cache_then_register"),
    ("a part's record read from another part's pointer (prepare and landed share the reader)",
     [(R, "word(out, usize::try_from(p).unwrap_or(3))", "word(out, 0)")],
     T + "mldsa_cache_then_register"),
]

if __name__ == "__main__":
    main("t13cache", MUTANTS)
