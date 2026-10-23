#!/usr/bin/env python3
"""PQZ parameter sets (owner 2026-10-21: one directory per set, chosen at compile time, one set per library build; one
input file per set, one generic generator). From sets/<set>/set.toml (n, k_max, q, pqz_delta, kmlwe_min, description,
approval, max_input, [pqzh_preset], the proofSystemId labels pqzl_id / pqzh_id: the only place these values are written) this writes every derived file of the set:

  <rel>_params.sage   the LaZer codegen specs of the 14 PQZL relations (reg, tx, tx0, burn, ds, dr, R_TXM M = 2 / 4 / 8
                      with and without the auditor, G = ceil(M / 4) randomness groups, and the bench-only M = 16)
  pqz_set.h           every parameter-dependent constant of the C core outside LaZer's codegen headers
  rust/set.rs         the same for the Rust crates (pqzl, pqz-stmt, pqzh-ligero; `#[path]` per cargo feature set-<set>);
                      a set with pqz-stmt (not core_only) also MAX_PROOF_PQZH and MAX_INPUT (plan 5h Task 8c part 2)
                      and PQZH_ID; every set PQZL_ID (plan 5h Task 8d: keccak256 of set.toml's labels, one id per
                      set and proof system, checked distinct across the sets and from the retired ids)
  set.json            every derived constant the Python tools need (pqz_kat.py, e_s0_set.py)
  PqzSet.sol          the Solidity constants of the set (make.sh <set> sol compiles it; PQZ_SOL_INSTALL=1 copies it to
                      smartcontracts/evm/src/pqz/)
  pqzh_set.rs         a set with `pqzh = true`: PQZH's (Ligero, pqz-core/pqzh/ligero) constants from set.toml's
                      [pqzh_preset] (radices, n, k, t) and q (the factors of q - 1, the generator, the non-square)

and keeps the per-set feature lists of the Rust crates in step (the `gen_set.py sets` blocks of their Cargo.toml and
the generated `stmt/src/sets.rs`, `pqzl/rust/src/params/mod.rs` comes from to_rust.py). The norm bounds, digit / carry
/ noise widths and Delta come from pqz-core/pqzl/params/n-study/budget.py (`budget`); the ring constants (NTT roots,
Barrett) are computed here. Stdlib only (Python >= 3.11: tomllib), deterministic:

  python3 -I pqz-core/params/sets/gen_set.py <set> | --all            write
  python3 -I pqz-core/params/sets/gen_set.py <set> | --all --check    exit 1 if a committed file differs, a set
                                                                       directory holds a file no step writes or lacks a
                                                                       codegen header, or the contracts' PqzSet.sol is
                                                                       not n2048-kmax1024's (until plan 5h Task 8d)

Adding a set: write sets/<set>/set.toml, then pqz-core/params/sets/make.sh <set> all (README.md beside this file).
"""
import json
import math
import os
import re
import sys
import textwrap
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.normpath(os.path.join(HERE, "..", ".."))
REPO = os.path.normpath(os.path.join(CORE, ".."))
sys.path.insert(0, os.path.join(CORE, "pqzl", "params", "n-study"))
from budget import budget  # noqa: E402

V3 = "n2048-kmax1024"  # the frozen v3 set: the contracts', pqz-stmt's and pqz-ffi's default until plan 5h Task 8d
SOL_EVM = os.path.join(REPO, "smartcontracts", "evm", "src", "pqz", "PqzSet.sol")
U64 = ("Q", "ZETA", "IROOT", "ZETA3", "INV2", "INVZ", "INVI", "INVZ3", "R64", "MUX")


# ---------------------------------------------------------------- proofSystemIds (plan 5h Task 8d: the one bump)
def keccak256(data):
    """Keccak-256 (rate 136, pad 0x01; not hashlib's SHA3-256): selfcheck() pins it to the retired v3 id"""
    rc = [1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009,
          0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
          0x8000000000008002, 0x8000000000000080, 0x800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080,
          0x80000001, 0x8000000080008008]
    rot = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    m64 = 2**64 - 1
    msg = bytearray(data) + b"\x01"
    msg += bytes(-len(msg) % 136)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), 136):
        for i in range(17):
            a[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        for r in rc:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[x - 1] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & m64) for x in range(5)]
            a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    n = rot[x][y]
                    b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << n) | (a[x][y] >> (64 - n))) & m64 if n else a[x][y]
            a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            a[0][0] ^= r
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# the retired ids (decisions CTR-PQZ-09): never a set's id; pqz-stmt's tests refuse them
RETIRED = {"scaas/pqz/lnp22/mlwe-d64k32-q42l4/v1": None,
           "scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2": "2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f",
           "scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3": "8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef",
           "scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1": "0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4",
           "scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1": "aa1f92ddc5763201c2582c8387bd6513842e52779310d6bcf39a7fec99284304"}


def ids(name):
    """{"pqzl": (label, id), "pqzh": (label, id)} of the set (no pqzh for a core_only set): keccak256 of set.toml's
    pqzl_id / pqzh_id labels. A label names the parameters it fixes (PQZL d64k<k>-q<log2q>, PQZH fq<log2q>-n<n>k<k>t<t>
    of [pqzh_preset]), so a label that no longer matches its set fails here"""
    t = load(name)
    k, L = t["n"] // 64, (t["q"] - 1).bit_length()
    out = {"pqzl": t["pqzl_id"]}
    assert f"/mlwe-d64k{k}-q{L}l4/" in out["pqzl"], f"{name}: pqzl_id {out['pqzl']} does not name d64k{k}-q{L}"
    if not t.get("core_only"):
        out["pqzh"] = t["pqzh_id"]
        p = t["pqzh_preset"]
        want = f"/ligero-fq{L}-n{p['n']}k{p['k']}t{p['t']}-"
        assert want in out["pqzh"], f"{name}: pqzh_id {out['pqzh']} does not name {want}"
    return {s: (lab, keccak256(lab.encode())) for s, lab in out.items()}


def check_ids():
    """every id of every set distinct, none retired (a proof of one set never verifies under another set's id)"""
    seen = {}
    for s in sets():
        for sys_, (lab, h) in ids(s).items():
            assert lab not in RETIRED and h.hex() not in RETIRED.values(), f"{s}: {sys_} id {lab} is retired"
            assert h not in seen, f"{s}: {sys_} id {lab} = {seen[h]}'s"
            seen[h] = f"{s} {sys_}"


def c_bytes(h):
    return "{ " + ", ".join(f"0x{x:02x}" for x in h) + " }"


def sets():
    return sorted(d for d in os.listdir(HERE) if os.path.exists(os.path.join(HERE, d, "set.toml")))


def load(name):
    with open(os.path.join(HERE, name, "set.toml"), "rb") as f:
        t = tomllib.load(f)
    n, K = t["n"], t["k_max"]
    want = f"n{n}-kmax{K}"
    assert name == want, f"set directory {name}: set.toml says {want}"
    return t


def consts(name):
    t = load(name)
    n, K, q = t["n"], t["k_max"], t["q"]
    b = budget(n, K, q)
    assert b["ok"] and q % 16 == 9, f"{name}: the §4.3 budget fails or q != 9 mod 16"
    L = (q - 1).bit_length()                  # the ring's log2q (LaZer codegen: ceil(log2(q - 1)))
    assert 2**(L - 1) < q < 2**L
    # g: the smallest quadratic non-residue >= 3, so zeta = g^((q - 1) / 8) has order 8 (g^((q - 1) / 2) = -1); 3 for
    # n2048-kmax1024, n2304-kmax4096 and n2560-kmax16384, 5 for n2816-kmax65536 (q = 2^54 - 327: 3 is a residue). Any
    # primitive 8th root gives the same ring arithmetic: the NTT is internal to the cores (2026-10-22, 8b item 6)
    g = next(g for g in range(3, q) if pow(g, (q - 1) // 2, q) == q - 1)
    z = pow(g, (q - 1) // 8, q)
    assert pow(z, 4, q) == q - 1, f"{name}: {g}^((q - 1) / 8) is not a primitive 8th root of unity"
    i, z3 = z * z % q, pow(z, 3, q)
    inv = lambda x: pow(x, q - 2, q)  # noqa: E731
    mbits, ebits = b["m"], b["e_bits"] + 1
    assert 2 * L + 4 <= L + 63           # Barrett: floor(x / 2^(L-1)) MUX < 2^128
    # pqz_sv.c's largest sum: c (sum over <= SVPR + SVBIN products of two values < q, 64 terms each; 65 at
    # n2304-kmax4096, 68 at n2816-kmax65536, pqz_sv.c asserts <= 128), 2^9 for c: < 2^(2L + 22);
    # NP primes near 2^30 hold |x| < P / 2 ~ 2^(30 NP - 1)
    sv_np = next(m for m in range(4, 8) if 30 * m - 1 > 2 * L + 22 + 1)
    c = [("SET_NAME", None, f'"{name}"', "the set's name"),
         ("K", b["k"], None, "polys per key / ciphertext vector u"), ("N", n, None, "ring dimension n = k d"),
         ("Q", q, None, "the modulus (prime, q = 9 mod 16)"), ("LOG2Q", L, None, "ceil(log2(q - 1)): coder / urandom width of a value mod q, A expansion"),
         ("DELTA", b["D"], None, f"floor(q / 2^{mbits + 2})"), ("K_MAX", K, None, "credits per account between refreshes"),
         ("MBITS", mbits, None, "digit sums M_i < 2^MBITS (15 K_MAX < 2^MBITS)"),
         ("CBITS", mbits - 3, None, "carries c_i + 64, i < 15"),
         ("EBITS", ebits, None, f"e_T,i + 2^{ebits - 1} and e'_i + 2^{ebits - 1} (|e| < E = 2^{ebits - 1})"),
         ("BETA_S", b["bs"], None, "||s||, ||r|| bound (CBD(1))"), ("BETA_E", b["be"], None, "||e||, ||e1|| bound (CBD(20))"),
         ("BETA_2", 64, None, "||e2_j|| bound (16 coefficients)"),
         ("ZETA", z, None, f"{g}^((q - 1) / 8), a primitive 8th root of unity"), ("IROOT", i, None, "zeta^2"),
         ("ZETA3", z3, None, "zeta^3"), ("INV2", inv(2), None, "1/2"), ("INVZ", inv(z), None, "1/zeta"),
         ("INVI", inv(i), None, "1/zeta^2"), ("INVZ3", inv(z3), None, "1/zeta^3"),
         ("R64", 2**64 % q, None, "2^64 mod q"),
         ("BARX", 2 * L + 4, None, "Barrett input range: x < 2^BARX = 2^(2 log2q + 4) > 16 q^2 (a basemul column sum)"),
         ("MUX", 2**(2 * L + 4) // q, None, "floor(2^BARX / q) < 2^(log2q + 5)"),
         ("SV_NP", sv_np, None, "30-bit CRT primes of the specialised verifier (pqz_sv.c): P / 2 above its largest sum")]
    return t, b, c


# ---------------------------------------------------------------- PQZH (plan 5h Task 8c part 2: the generator owns it)
def factor(m):
    """the prime factors of m, ascending, with multiplicity (trial division: q - 1 has small factors and one cofactor)"""
    out, d = [], 2
    while d * d <= m:
        while m % d == 0:
            out.append(d)
            m //= d
        d += 1
    return out + ([m] if m > 1 else [])


def limits(name):
    """(MAX_PROOF_PQZH, MAX_INPUT) of a set with pqz-stmt (not core_only): set.toml's max_input, [pqzh_preset]'s
    max_proof (262,144 without PQZH)"""
    t = load(name)
    return t.get("pqzh_preset", {}).get("max_proof", 262_144), t["max_input"]


def pqzh_preset(name):
    """the checked PQZH constants of a set with pqzh = true: (QM1, GEN, NR, radices, n, k, t, description)"""
    t = load(name)
    q, p = t["q"], t["pqzh_preset"]
    rad, n, k, tq = p["radices"], p["n"], p["k"], p["t"]
    f = factor(q - 1)
    primes = sorted(set(f))
    gen = next(g for g in range(2, q) if all(pow(g, (q - 1) // r, q) != 1 for r in primes))
    nr = next(g for g in range(2, q) if pow(g, (q - 1) // 2, q) == q - 1)
    dom = 4 * math.prod(rad)  # fft.rs: every domain size divides 4 * the product of the radices
    assert q % 4 == 1 and rad == sorted(set(rad)) and all((q - 1) % r == 0 for r in rad) and (q - 1) % dom == 0, \
        f"{name}: [pqzh_preset] radices {rad} vs q - 1 = {f}"
    assert dom % n == 0 and dom % k == 0 and 0 < tq < k - 1 and pow(gen, n * k // math.gcd(n, k), q) != 1, \
        f"{name}: [pqzh_preset] n {n}, k {k}, t {tq} (n, k on the radices' domains, GEN H_n and H_k disjoint)"
    return f, gen, nr, rad, n, k, tq, p["description"]


def pqzh_text(name):
    t = load(name)
    f, gen, nr, rad, n, k, tq, desc = pqzh_preset(name)
    mp, _ = limits(name)

    def fac(x):
        return " ".join(f"{r}^{e}" if e > 1 else str(r) for r, e in sorted({r: factor(x).count(r) for r in factor(x)}.items()))
    head = textwrap.wrap(f"PQZH (Ligero, pqz-core/pqzh/ligero) constants of parameter set `{name}` (q = {t['q']:,}): "
                         f"{desc}.", 116, initial_indent="//! ", subsequent_indent="//! ", break_on_hyphens=False)
    return "\n".join(head + [
        "//! Generated by `pqz-core/params/sets/gen_set.py` from set.toml's [pqzh_preset] and q: do not edit. Checked there",
        "//! (factors of q - 1, generator, non-square, radices dividing q - 1, n and k on their domains), by `python3 -I",
        f"//! pqz-core/pqzh/ligero/ligero_params.py --set {name}` (soundness, sizes) and the crate's unit tests `fq::tests` /",
        f"//! `fft::tests` / `ligero::tests`. MAX_PROOF_PQZH ({mp:,} B: the precompile's and the prover's limit) and the lattice",
        "//! constants (q, n, k, Delta, bit widths, bounds) are in ./rust/set.rs.",
        "#![allow(dead_code)]",
        "/// the prime factors of q - 1, with multiplicity",
        f"pub(crate) const QM1: &[u64] = &[{', '.join(f'{x:_}' for x in f)}];",
        "/// the smallest generator of F_q^*: the domains H_n = <GEN^((q - 1) / n)> and the commitment coset GEN H_n",
        f"pub(crate) const GEN: u64 = {gen};",
        "/// F_q^4 = F_q[X]/(X^4 - NR): NR the smallest non-square (q = 1 mod 4, so X^4 - NR is irreducible)",
        f"pub(crate) const NR: u64 = {nr};",
        "/// FFT radices, ascending (the largest is the deepest stage; each stage a direct r-point DFT); each divides q - 1, 4",
        "/// times their product bounds the domain sizes (fft.rs)",
        f"pub(crate) const RADICES: [usize; {len(rad)}] = [{', '.join(map(str, rad))}];",
        f"/// the preset (Params::proven): proven regime, n = {n:,} = {fac(n)} (the code on the coset {gen} H_n), k = {k:,} = {fac(k)},",
        f"/// t = {tq}, l = k - t - 1 = {k - tq - 1}",
        f"pub(crate) const PRESET_N: usize = {n:_};",
        f"pub(crate) const PRESET_K: usize = {k:_};",
        f"pub(crate) const PRESET_T: usize = {tq:_};",
        ""])


def c_text(name):
    t, _, cs = consts(name)
    out = [f"/* PQZL parameter set {name}: {t['description']}. Generated by pqz-core/params/sets/gen_set.py: do not edit.",
           "   One set per library build (pqzl/build.sh PQZ_SET=<set>: pqz-core/params/sets/<set>). */",
           "#ifndef PQZ_SET_H", "#define PQZ_SET_H", ""]
    for k, v, s, doc in cs:
        val = s if s is not None else (f"{v}ULL" if k in U64 else f"((int64_t){v})" if k == "DELTA" else str(v))
        out.append(f"#define PQZ_{k} {val} /* {doc} */")
    i = ids(name)
    out.append(f"/* proofSystemId (statement bytes 32..63) = keccak256(\"{i['pqzl'][0]}\"): the cores only hash it */")
    out.append(f"#define PQZ_PROOF_SYSTEM_ID {c_bytes(i['pqzl'][1])}")
    if "pqzh" in i:
        out.append(f"/* PQZH's proofSystemId = keccak256(\"{i['pqzh'][0]}\") (the C side writes it only in test tools) */")
        out.append(f"#define PQZ_PQZH_ID {c_bytes(i['pqzh'][1])}")
    out += ["", "#endif", ""]
    return "\n".join(out)


def rs_text(name):
    t, _, cs = consts(name)
    out = [f"//! PQZL parameter set `{name}`: {t['description']}. Generated by `pqz-core/params/sets/gen_set.py`: do not edit.",
           "//! One set per build (cargo features `set-<set>`); `crate::params::set` re-exports it.",
           "#![allow(dead_code)]"]
    for k, v, s, doc in cs:
        if s is not None:
            out.append(f"/// {doc}\npub(crate) const {k}: &str = {s};")
            continue
        ty = "u64" if k in U64 else "i64" if k == "DELTA" else "u32" if k in ("LOG2Q", "MBITS", "CBITS", "EBITS", "BARX") else "usize"
        out.append(f"/// {doc}\npub(crate) const {k}: {ty} = {v:_};")
    if not t.get("core_only"):  # pqz-stmt's per-set limits (plan 5h Task 8c part 2)
        mp, mi = limits(name)
        out.append(f"/// MAX_PROOF(PQZH id): the precompile's and the PQZH prover's proof limit (set.toml [pqzh_preset] max_proof)\n"
                   f"pub(crate) const MAX_PROOF_PQZH: usize = {mp:_};")
        out.append(f"/// MAX_INPUT: the precompile input limit of pqz-stmt (set.toml max_input)\npub(crate) const MAX_INPUT: usize = {mi:_};")
    for sys_, (lab, h) in ids(name).items():
        out.append(f"/// {sys_.upper()}'s proofSystemId label (set.toml {sys_}_id)\npub(crate) const {sys_.upper()}_LABEL: &str = \"{lab}\";")
        out.append(f"/// {sys_.upper()}'s proofSystemId: keccak256({sys_.upper()}_LABEL)\n"
                   f"pub(crate) const {sys_.upper()}_ID: [u8; 32] = [{', '.join(f'0x{x:02x}' for x in h)}];")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- the LaZer codegen specs (was the set's gen_pa.py)
def specs(name):
    """the 14 <rel>_params.sage of the set: the production shapes of the v3 set (pqzl/params/*.sage), the bit widths
    and norm bounds of the set, log2q rounded down as pqzl/params/n-study/gen_specs.py (LaZer's D loop hangs otherwise),
    pqz_delta / kmlwe_min from set.toml (e_s1's results; no kmlwe_min = LaZer's default hiding rank)."""
    t, b, _ = consts(name)
    N, K_MAX, Q = t["n"], t["k_max"], t["q"]
    k, bs, be, m, eb = N // 64, b["bs"], b["be"], b["m"], b["e_bits"] + 1
    tx_bits = 64 + 64 + 16 * m + 15 * (m - 3) + 16 * eb  # d, d', M_i, c_i + 64, e_T + 2^(eb-1)
    blk = f"{bs}^2 + {be}^2"
    log2q = Q.bit_length() if math.log2(Q) > Q.bit_length() - 0.01 else Q.bit_length() - 1
    head0 = (f"# Set {name} (pqz-core/params/sets/{name}/set.toml; generated by pqz-core/params/sets/gen_set.py: do not "
             f"edit):\n# n = {N} (k = {k}), q = {Q} (2^{math.log2(Q):.3f}, prime, q = 9 mod 16), Delta = {b['D']}, "
             f"beta_s = {bs}, beta_e = {be},\n# K_MAX = {K_MAX:,}: M_i {m} bits, carries {m - 3} bits (c_i + 64), "
             f"e_T / e' + 2^{eb - 1} in {eb} bits.\n"
             f"# pqz_delta / kmlwe_min: set.toml (checked by e_s1: MSIS beta >= 450, hiding MLWE uSVP and dual_hybrid >= 450).\n")
    kml = f"kmlwe_min = {t['kmlwe_min']}\n" if "kmlwe_min" in t else ""
    out = {}

    def spec(rel, what, ks, Bs, e2, bits, bprime, filler):
        nbin = math.ceil(bits / 64) if bits else 0
        m1 = len(ks) * k + e2 + nbin
        alpha = " + ".join(x for x in (f"{len(ks) // 2} * ({blk})" if len(ks) > 2 else blk,
                                       f"{e2} * 64^2" if e2 else "", f"{nbin} * 64" if nbin else "") if x)
        n = ", ".join([str(k)] * len(ks) + ["1"] * e2)
        B = ", ".join([str(x) for x in Bs] + ["64"] * e2)
        out[rel] = (f"# {what}\n" + head0 +
                    f"pqz_verbose = 1\nname = \"pqz_{rel}\"\nq_fixed = {Q}\npqz_L = 4\nlog2q = {log2q}\n"
                    f"pqz_delta = {t['pqz_delta']}\n{kml}d = 64\n\n"
                    f"m1 = {m1}\nalpha = sqrt({alpha})\nl = 0\n\nnbin = {nbin}\nn = [{n}]\nB = [{B}]\n\n"
                    f"# LaZer's tbox needs nprime > 0: a one-poly approximate l_inf proof as filler ({filler}).\n"
                    f"nprime = 1\nBprime = {bprime}\n")

    def debit(G):
        return [k] * (2 + 2 * G), [bs, be] * (1 + G)

    spec("reg", f"R_REG pk = A s + e; s1 = s, e ({k} polys each)", [k, k], [bs, be], 0, 0, 1, "s[0], in [-1, 1]")
    ks, Bs = debit(1)
    spec("tx", f"R_TX: s_f, e_f, r, e1 ({k} polys each), e2_t, e2_f, e2_a; {tx_bits} bits (d 64, d' 64, M 16x{m}, "
         f"c 15x{m - 3}, e_T 16x{eb})", ks, Bs, 3, tx_bits, 64, "e2_t, |coefficients| <= 20 < 64")
    spec("tx0", f"R_TX0 (auditor off): R_TX without e2_a; {tx_bits} bits", ks, Bs, 2, tx_bits, 64,
         "e2_t, |coefficients| <= 20 < 64")
    spec("burn", f"R_BURN / REFRESH: s_f, e_f, r, e1, e2_f; {tx_bits - 64} bits (d public)", ks, Bs, 1, tx_bits - 64,
         64, "e2_f, |coefficients| <= 20 < 64")
    spec("ds", f"R_DS: s1 = r, e1 ({k} polys each), e2_t", [k, k], [bs, be], 1, 0, 64, "e2_t, |coefficients| <= 20 < 64")
    spec("dr", f"R_DR: s1 = s, e ({k} polys each), e'_i + 2^{eb - 1} in {eb} bits ({16 * eb} bits)", [k, k], [bs, be], 0,
         16 * eb, 1, "s[0], in [-1, 1]")
    for M in (2, 4, 8, 16):
        G = (M + 3) // 4
        bits = tx_bits - 64 + 64 * M
        ks, Bs = debit(G)
        for aud in (1, 0):
            e2 = M + 1 + aud * M
            rel = f"txm{M}" + ("" if aud else "0")
            what = (f"R_TXM M = {M}, G = {G} randomness group(s) of <= 4 legs, auditor {'on' if aud else 'off'}: s_f, "
                    f"e_f, (r_g, e1_g) x {G}, e2_j, e2_f" + (", e2_{a,j}" if aud else "") +
                    f"; {e2} e2 blocks, {bits} bits" + ("; OVERSIZE (bench builds only, -DPQZ_TXM_OVERSIZE)" if M == 16 else ""))
            spec(rel, what, ks, Bs, e2, bits, 64, "e2_0, the first leg's noise, |coefficients| <= 20 < 64")
    return out


# ---------------------------------------------------------------- set.json and PqzSet.sol
def lengths(k):
    """the statement / object byte lengths of pqz-stmt for k polys per vector (v3: k = 32)"""
    pk, v, h = 512 * k, 128, 640
    return {"pk": pk, "v": v, "ct": pk + v, "header": h,
            "stmt": {"TRANSFER": h + 5 * pk + 4 * v, "TRANSFER0": h + 4 * pk + 3 * v, "BURN": h + 3 * pk + 2 * v,
                     "REFRESH": h + 3 * pk + 2 * v, "REGISTER": 96 + pk, "DISCLOSE-SENDER": 288 + 2 * pk + v,
                     "DISCLOSE-RECEIVER": 288 + 2 * pk + v, "DISCLOSE-AUDITOR": 288 + 2 * pk + v},
            "bundle": 16 + pk + 2 * v + 32, "bundle0": 16 + pk + v + 32}


def json_text(name):
    t, b, cs = consts(name)
    c = {k.lower(): v for k, v, s, d in cs if s is None}
    j = {"set": name, "description": t["description"], "approval": t["approval"], "core_only": t.get("core_only", False),
         "pqzh": t.get("pqzh", False), "pqz_delta": t["pqz_delta"], "kmlwe_min": t.get("kmlwe_min"), "d": 64} | c | {
        "e": 2**(c["ebits"] - 1), "b_fresh": 2 * c["beta_e"] * c["beta_s"] + c["beta_2"],
        "pack_bits": math.ceil(math.log2(t["q"])), "lengths": lengths(c["k"])}
    if not t.get("core_only"):
        j["max_proof_pqzh"], j["max_input"] = limits(name)
    for sys_, (lab, h) in ids(name).items():
        j[f"{sys_}_label"], j[f"{sys_}_id"] = lab, h.hex()
    if t.get("pqzh"):
        p = t["pqzh_preset"]
        j["pqzh_preset"] = {"radices": p["radices"], "n": p["n"], "k": p["k"], "t": p["t"], "ell": p["k"] - p["t"] - 1}
    return json.dumps(j, indent=1) + "\n"


def sol_text(name):
    t, b, cs = consts(name)
    c = {k: v for k, v, s, d in cs if s is None}
    ln = lengths(c["K"])
    u = lambda x: f"{x:_}"  # noqa: E731
    pack = math.ceil(math.log2(t["q"]))
    rows = [("N", c["N"], "ring dimension n = k d"), ("K", c["K"], "polys per key / ciphertext vector u"),
            ("Q", c["Q"], "the modulus"), ("DELTA", c["DELTA"], f"floor(q / 2^{c['MBITS'] + 2})"),
            ("K_MAX", c["K_MAX"], "credits per account between refreshes"),
            ("LOG2Q", c["LOG2Q"], "ceil(log2(q - 1))"),
            ("PACK_BITS", pack, "stored-blob packing width ceil(log2 q) (P46 ruling, owner 2026-10-21; built in 8d)"),
            ("PK", ln["pk"], "pk / u bytes (k polys x 64 be8)"), ("V", ln["v"], "v bytes (16 be8)"),
            ("CT", ln["ct"], "ciphertext u || v bytes"),
            ("STMT_TRANSFER", ln["stmt"]["TRANSFER"], "op 1 statement, auditor on"),
            ("STMT_TRANSFER0", ln["stmt"]["TRANSFER0"], "op 1 statement, auditor off"),
            ("STMT_BURN", ln["stmt"]["BURN"], "op 2 statement (burn / refresh)"),
            ("STMT_REGISTER", ln["stmt"]["REGISTER"], "op 3 statement"),
            ("STMT_DISCLOSE", ln["stmt"]["DISCLOSE-SENDER"], "op 4 / 5 statement"),
            ("BUNDLE", ln["bundle"], "disclosure bundle, auditor on"), ("BUNDLE0", ln["bundle0"], "disclosure bundle, auditor off")]
    out = ["// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0", "pragma solidity ^0.8.24;", "",
           f"/// @title PqzSet: the PQZ parameter set `{name}` ({t['description']})",
           "/// @notice Generated by pqz-core/params/sets/gen_set.py from the set's set.toml: do not edit. One set per build",
           "/// (owner 2026-10-21): `PQZ_SOL_INSTALL=1 pqz-core/params/sets/make.sh <set> sol` writes this file; the committed",
           "/// one is the set the contracts use (n2048-kmax1024 until plan 5h Task 8d, which wires PqzCt / PqzCore to it).",
           "library PqzSet {", f'    string internal constant NAME = "{name}";']
    for k, v, doc in rows:
        out.append(f"    /// {doc}\n    uint256 internal constant {k} = {u(v)};")
    for sys_, (lab, h) in ids(name).items():
        out.append(f"    /// {sys_.upper()}'s proofSystemId: keccak256(\"{lab}\")\n    bytes32 internal constant {sys_.upper()}_ID = 0x{h.hex()};")
    out += ["", "    /// op 7 statement bytes: header || pk_f || pk_0..pk_{M-1} || [pk_a] || T || u_0..u_{G-1} || v_0..v_{M-1} || v_f",
            "    /// || [v_{a,0}..v_{a,M-1}], G = ceil(M / 4) (pqz-stmt multi_len)",
            "    function multiLen(uint256 m, bool aud) internal pure returns (uint256) {",
            "        uint256 a = aud ? 1 : 0;",
            "        uint256 g = (m + 3) / 4; // randomness groups of <= 4 legs",
            "        return 640 + (1 + m + a + g) * PK + CT + (m + 1 + a * m) * V;",
            "    }", "}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- the Rust crates' per-set wiring
BEGIN, END = "# BEGIN gen_set.py sets", "# END gen_set.py sets"


def cargo_block(path, lines):
    """the Cargo.toml text of `path` with the lines between BEGIN and END replaced"""
    s = open(path, encoding="utf-8").read()
    i, j = s.index(BEGIN), s.index(END)
    return s[:s.index("\n", i) + 1] + "".join(x + "\n" for x in lines) + s[j:]


def wiring():
    """{path: text} of the per-set feature lists (one feature set-<set> per set in every crate that selects one)"""
    ss = sets()
    rs = [s for s in ss if not load(s).get("core_only")]  # sets with pqz-stmt / pqz-ffi (vectors, precompile)
    f = lambda s: "set-" + s  # noqa: E731
    out = {}
    p = os.path.join(CORE, "pqzl", "rust", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = []' for s in ss])
    p = os.path.join(CORE, "pqzl", "rust", "wasm", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = ["pqzl/{f(s)}"]' for s in ss])
    p = os.path.join(CORE, "stmt", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = []' for s in rs])
    p = os.path.join(CORE, "ffi", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = ["pqz-stmt/{f(s)}", "pqzl?/{f(s)}"' + (f', "pqzh-ligero?/{f(s)}", "pqzh"' if load(s).get("pqzh") else "") + "]"
                             for s in rs])
    p = os.path.join(CORE, "ffi", "wasm", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = ["pqz-ffi/{f(s)}"]' for s in rs])
    p = os.path.join(CORE, "fuzz", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = ["pqz-ffi/{f(s)}"]' for s in rs])
    # at most one set-<set>; none = the frozen set (a plain `cargo test` of pqz-stmt or pqzh-ligero; pqz-ffi, pqzh-ligero's
    # set features and the gate always pass one): the frozen set's module also stands for "no feature"
    others = [s for s in rs if s != V3]
    none = "not(any(" + ", ".join(f'feature = "{f(s)}"' for s in others) + "))"
    mods = "".join((f'#[cfg(any(feature = "{f(s)}", {none}))]' if s == V3 else f'#[cfg(feature = "{f(s)}")]')
                   + f'\n#[path = "../../params/sets/{s}/rust/set.rs"]\nmod set;\n' for s in rs)
    cnt = " + ".join(f'cfg!(feature = "{f(s)}") as u8' for s in rs)
    out[os.path.join(CORE, "stmt", "src", "sets.rs")] = (
        "// Generated by pqz-core/params/sets/gen_set.py: do not edit. The parameter set of this build (owner 2026-10-21:\n"
        "// pqz-core/params/sets/<set>/, one per build, cargo feature set-<set>; the same rust/set.rs as the PQZL crate).\n"
        f"{mods}const _: () = assert!({cnt} <= 1, \"pqz-stmt: at most one parameter set feature set-<set> (none: {V3})\");\n"
        f"/// the sets this crate builds for (set.toml without core_only)\npub const SETS: &[&str] = &[{', '.join(repr(s).replace(chr(39), chr(34)) for s in rs)}];\n")
    return out


def files(names):
    out = {}
    for s in names:
        d = os.path.join(HERE, s)
        out[os.path.join(d, "pqz_set.h")] = c_text(s)
        out[os.path.join(d, "rust", "set.rs")] = rs_text(s)
        out[os.path.join(d, "set.json")] = json_text(s)
        out[os.path.join(d, "PqzSet.sol")] = sol_text(s)
        out |= {os.path.join(d, f"{r}_params.sage"): x for r, x in specs(s).items()}
        if load(s).get("pqzh"):
            out[os.path.join(d, "pqzh_set.rs")] = pqzh_text(s)
    return out | wiring()


# the files a set directory may hold: set.toml, the docs, gen_set.py's, codegen's, to_rust.py's and make.sh's outputs
RELS = ("reg", "tx", "tx0", "burn", "ds", "dr", "txm2", "txm20", "txm4", "txm40", "txm8", "txm80", "txm16", "txm160")
SET_FILES = {"set.toml", "SET.md", "PQZH.md", "pqz_set.h", "PqzSet.sol", "set.json", "codegen.txt", "codegen-check.txt",
             "e-s0.txt", "e-s1.txt", "lazer-3330e48-kat.json", "lazer-3330e48-kat-build.txt", "rust/set.rs", "rust/mod.rs"}
SET_FILES |= {f"{r}_params.sage" for r in RELS} | {f"pqz_{r}_params.h" for r in RELS} | {f"rust/{r}.rs" for r in RELS}
# pqzh_set.rs: written above for a set with pqzh = true (stray() allows it there only). Hand-written research files of
# n2304-kmax4096 (plan 5h Task 8c part 1b, owner 2026-10-22), kept as they are: pqzh_set_fallback.rs (THE preset,
# fallback A = pqzh-ligero feature `fallback-retry`, never in production) and pqzh_set_spike_b.rs (the superseded t = 119
# spike, not compiled)
RESEARCH = {"n2304-kmax4096": {"pqzh_set_fallback.rs", "pqzh_set_spike_b.rs"}}  # allowed in that directory only


def stray(name):
    """paths in the set's directory that no step writes (dot files / directories are make.sh's scratch), and missing
    codegen headers"""
    d = os.path.join(HERE, name)
    ok = SET_FILES | ({"pqzh_set.rs"} if load(name).get("pqzh") else set()) | RESEARCH.get(name, set())
    out = [os.path.join(d, f"pqz_{r}_params.h") for r in RELS if not os.path.exists(os.path.join(d, f"pqz_{r}_params.h"))]
    for root, dirs, fs in os.walk(d):
        dirs[:] = [x for x in dirs if not x.startswith(".")]
        out += [os.path.join(root, f) for f in fs
                if not f.startswith(".") and os.path.relpath(os.path.join(root, f), d).replace(os.sep, "/") not in ok]
    return sorted(out)


def main(argv):
    check = "--check" in argv
    names = [a for a in argv if not a.startswith("--")]
    names = sets() if "--all" in argv or not names else names
    bad = [n for n in names if n not in sets()]
    if bad:
        print(f"gen_set.py: no set.toml for {bad}; sets: {sets()}")
        return 2
    check_ids()
    fs = files(names)
    diff = []
    for p, t in fs.items():
        if check:
            if not os.path.exists(p) or open(p, encoding="utf-8").read() != t:
                diff.append(os.path.relpath(p, REPO))
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(t)
    if check:
        # the contracts' PqzSet.sol: exactly n2048-kmax1024's generated text until plan 5h Task 8d (8b review m7)
        if not os.path.exists(SOL_EVM) or open(SOL_EVM, encoding="utf-8").read() != sol_text(V3):
            diff.append(os.path.relpath(SOL_EVM, REPO))
        diff += [os.path.relpath(p, REPO) for s in names for p in stray(s)]
    print("gen_set.py%s: %d sets, %d files%s" % (" --check" if check else "", len(names), len(fs) + check,
                                                 (", differ: " + " ".join(diff)) if diff else ""))
    return 1 if diff else 0


def selfcheck():
    # Keccak-256, not SHA3-256: the retired v3 / PQZH v1 ids (pqz_kat.py's keccak256, decisions CTR-PQZ-09)
    for lab, h in RETIRED.items():
        assert h is None or keccak256(lab.encode()).hex() == h, lab
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # the v3 set is main's frozen constants (pqz_ntt.c / pqz_rel.c / pqz_keys.c of main)
    c = {k: v for k, v, s, d in consts(V3)[2]}
    assert (c["K"], c["Q"], c["LOG2Q"], c["DELTA"], c["MBITS"], c["CBITS"], c["EBITS"]) == (32, 4398046510889, 42, 2**26 - 1, 14, 11, 25)
    assert (c["BETA_S"], c["BETA_E"], c["ZETA"], c["INVZ3"]) == (36, 164, 3367489746414, 1030556764475)
    assert lengths(32)["stmt"]["TRANSFER"] == 83_072 and lengths(32)["bundle"] == 16_688
    # the v3 specs' shapes are pqzl/params/*.sage's (the record the v3 headers were made from)
    s = specs(V3)
    assert "m1 = 146\n" in s["tx"] and "nbin = 15\n" in s["tx"] and "m1 = 231\n" in s["txm8"] and "nbin = 22\n" in s["txm8"]
    if "n2304-kmax4096" in sets():
        c = {k: v for k, v, s, d in consts("n2304-kmax4096")[2]}
        assert (c["K"], c["DELTA"], c["MBITS"], c["EBITS"], c["BETA_S"], c["BETA_E"]) == (36, 233747196, 16, 27, 38, 173)
        s = specs("n2304-kmax4096")  # as gen_pa.py (now legacy/) wrote them, comment lines aside
        assert "m1 = 163\n" in s["tx"] and "nbin = 16\n" in s["tx"] and "m1 = 160\n" in s["burn"] and "nbin = 15\n" in s["burn"]
        assert "m1 = 79\n" in s["dr"] and "m1 = 73\n" in s["ds"] and "m1 = 72\n" in s["reg"] and "log2q = 45\n" in s["tx"]
        assert "m1 = 172\n" in s["txm4"] and "m1 = 256\n" in s["txm8"] and "nbin = 23\n" in s["txm8"]


if __name__ == "__main__":
    selfcheck()
    sys.exit(main(sys.argv[1:]))
