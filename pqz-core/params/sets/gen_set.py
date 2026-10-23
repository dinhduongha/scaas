#!/usr/bin/env python3
"""PQZ parameter sets (owner 2026-10-21: one directory per set, chosen at compile time, one set per library build; one
input file per set, one generic generator). From sets/<set>/set.toml (n, k_max, q, pqz_delta, kmlwe_min, description,
approval: the only place these values are written) this writes every derived file of the set:

  <rel>_params.sage   the LaZer codegen specs of the 14 PQZL relations (reg, tx, tx0, burn, ds, dr, R_TXM M = 2 / 4 / 8
                      with and without the auditor, G = ceil(M / 4) randomness groups, and the bench-only M = 16)
  pqz_set.h           every parameter-dependent constant of the C core outside LaZer's codegen headers
  rust/set.rs         the same for the Rust crates (pqzl, pqz-stmt; `#[path]` per cargo feature set-<set>)
  set.json            every derived constant the Python tools need (pqz_kat.py, e_s0_set.py)
  PqzSet.sol          the Solidity constants of the set (make.sh <set> sol compiles it; PQZ_SOL_INSTALL=1 copies it to
                      smartcontracts/evm/src/pqz/)

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
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.normpath(os.path.join(HERE, "..", ".."))
REPO = os.path.normpath(os.path.join(CORE, ".."))
sys.path.insert(0, os.path.join(CORE, "pqzl", "params", "n-study"))
from budget import budget  # noqa: E402

V3 = "n2048-kmax1024"  # the frozen v3 set: the contracts', pqz-stmt's and pqz-ffi's default until plan 5h Task 8d
SOL_EVM = os.path.join(REPO, "smartcontracts", "evm", "src", "pqz", "PqzSet.sol")
U64 = ("Q", "ZETA", "IROOT", "ZETA3", "INV2", "INVZ", "INVI", "INVZ3", "R64", "MUX")


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


def c_text(name):
    t, _, cs = consts(name)
    out = [f"/* PQZL parameter set {name}: {t['description']}. Generated by pqz-core/params/sets/gen_set.py: do not edit.",
           "   One set per library build (pqzl/build.sh PQZ_SET=<set>: pqz-core/params/sets/<set>). */",
           "#ifndef PQZ_SET_H", "#define PQZ_SET_H", ""]
    for k, v, s, doc in cs:
        val = s if s is not None else (f"{v}ULL" if k in U64 else f"((int64_t){v})" if k == "DELTA" else str(v))
        out.append(f"#define PQZ_{k} {val} /* {doc} */")
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
    out[p] = cargo_block(p, [f'{f(s)} = ["pqz-stmt/{f(s)}", "pqzl?/{f(s)}"' + (', "pqzh"' if load(s).get("pqzh") else "") + "]"
                             for s in rs])
    p = os.path.join(CORE, "ffi", "wasm", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = ["pqz-ffi/{f(s)}"]' for s in rs])
    p = os.path.join(CORE, "fuzz", "Cargo.toml")
    out[p] = cargo_block(p, [f'{f(s)} = ["pqz-ffi/{f(s)}"]' for s in rs])
    mods = "".join(f'#[cfg(feature = "{f(s)}")]\n#[path = "../../params/sets/{s}/rust/set.rs"]\nmod set;\n' for s in rs)
    cnt = " + ".join(f'cfg!(feature = "{f(s)}") as u8' for s in rs)
    out[os.path.join(CORE, "stmt", "src", "sets.rs")] = (
        "// Generated by pqz-core/params/sets/gen_set.py: do not edit. The parameter set of this build (owner 2026-10-21:\n"
        "// pqz-core/params/sets/<set>/, one per build, cargo feature set-<set>; the same rust/set.rs as the PQZL crate).\n"
        f"{mods}const _: () = assert!({cnt} == 1, \"pqz-stmt: exactly one parameter set feature set-<set>\");\n"
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
    return out | wiring()


# the files a set directory may hold: set.toml, the docs, gen_set.py's, codegen's, to_rust.py's and make.sh's outputs
RELS = ("reg", "tx", "tx0", "burn", "ds", "dr", "txm2", "txm20", "txm4", "txm40", "txm8", "txm80", "txm16", "txm160")
SET_FILES = {"set.toml", "SET.md", "PQZH.md", "pqz_set.h", "PqzSet.sol", "set.json", "codegen.txt", "codegen-check.txt",
             "e-s0.txt", "e-s1.txt", "lazer-3330e48-kat.json", "lazer-3330e48-kat-build.txt", "rust/set.rs", "rust/mod.rs"}
SET_FILES |= {f"{r}_params.sage" for r in RELS} | {f"pqz_{r}_params.h" for r in RELS} | {f"rust/{r}.rs" for r in RELS}


def stray(name):
    """paths in the set's directory that no step writes (dot files / directories are make.sh's scratch), and missing
    codegen headers"""
    d = os.path.join(HERE, name)
    out = [os.path.join(d, f"pqz_{r}_params.h") for r in RELS if not os.path.exists(os.path.join(d, f"pqz_{r}_params.h"))]
    for root, dirs, fs in os.walk(d):
        dirs[:] = [x for x in dirs if not x.startswith(".")]
        out += [os.path.join(root, f) for f in fs
                if not f.startswith(".") and os.path.relpath(os.path.join(root, f), d).replace(os.sep, "/") not in SET_FILES]
    return sorted(out)


def main(argv):
    check = "--check" in argv
    names = [a for a in argv if not a.startswith("--")]
    names = sets() if "--all" in argv or not names else names
    bad = [n for n in names if n not in sets()]
    if bad:
        print(f"gen_set.py: no set.toml for {bad}; sets: {sets()}")
        return 2
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
        # the contracts' PqzSet.sol: exactly the v3 set's generated text until plan 5h Task 8d (8b review m7)
        if not os.path.exists(SOL_EVM) or open(SOL_EVM, encoding="utf-8").read() != sol_text(V3):
            diff.append(os.path.relpath(SOL_EVM, REPO))
        diff += [os.path.relpath(p, REPO) for s in names for p in stray(s)]
    print("gen_set.py%s: %d sets, %d files%s" % (" --check" if check else "", len(names), len(fs) + check,
                                                 (", differ: " + " ".join(diff)) if diff else ""))
    return 1 if diff else 0


def selfcheck():
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
