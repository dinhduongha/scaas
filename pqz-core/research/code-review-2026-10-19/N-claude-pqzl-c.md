# N: PQZL C core, security review round 2 (Claude, static, read-only), 2026-10-19

Tree: `/home/ha/work/ainative/scaas/.claude/worktrees/rev2` at `e9cabd1` (PQZL v3 merged: `361a86b`). Every reference below
is relative to that tree. I built nothing, ran nothing, fuzzed nothing and timed nothing.

Scope: `pqz-core/pqzl/src/` (`pqz_rel.c`, `pqz_sv.c`, `pqz_keys.c`, `pqz_arena.c`, `pqz_rt.h`, `pqz_mpn.h`, `pqz_fixexp.h`,
`pqz_glue.h`, `pqz_ntt.*`, `pqz_wasm_rt.c`, `pqz.h`, `pqz_int.h`), `pqz-core/pqzl/lazer/` (`coder.c`, `lnp-tbox.c`,
`lnp-quad.c`, `lnp-quad-many.c`, `rejection.c`, `grandom.c`, `dcompress.c`, `int.c`, `intvec.c`, `poly.c`, `polyvec.c`,
`polymat.c`, `spoly*.c`, `abdlop.c` hashcomm, `config.h`, `lazer-in2.h` macros), `pqz-core/pqzl/build.sh`,
`pqz-core/pqzl/check_symbols.sh`, `pqz-core/ffi/src/pqzl/c.rs`, `pqz-core/ffi/build.rs`, `pqz-core/ffi/csrc/wasm_ti3.c`.
For C = Rust parity: `pqz-core/pqzl/rust/src/{sv.rs, coder.rs, rel.rs, rand/fixexp.rs}`.

Order of work, as asked: what verifier input reaches (decoder, statement parsing, SV, generic verifier, arena), then
C = Rust verdict parity, then the prover (constant time after fix E, wiping).

**Bottom line.** No P0 and no P1. The v3 transcript is correct in the C SV, the C generic verifier and the C prover.
I found no memory-safety bug and no undefined behaviour reachable from verifier input on the precompile path
(`pqz_verify_fast`). I found no place where the C SV and the Rust SV can return different verdicts. What remains:

- one constant-time hypothesis on wasm32 that ctgrind cannot see (N-1). It also applies to the Rust crate.
- the known wiping gap (N-2).
- the arena-exhaustion overflow, re-confirmed with sizes and with more call sites than round 1 found (N-3).
- latent hygiene items (N-4 to N-6).

## Findings

### N-1 — P2 (hypothesis) — wasm32: a 128-bit shift by a secret-derived amount becomes a `__ashlti3` call that ctgrind never sees

**Locations**

- C: `pqz-core/pqzl/src/pqz_fixexp.h:104`, `tpos = (pqz_fx_u128)mant << ((uint64_t)sh & 1)`, inside
  `pqz_bernoulli_fp`.
- Rust (same arithmetic, production backend): `pqz-core/pqzl/rust/src/rand/fixexp.rs:63`.
- The branch-free helper: `pqz-core/pqzl/src/pqz_wasm_rt.c` `__ashlti3`. It is linked into the standalone C wasm
  (`build.sh wasm`).
- `pqz-core/ffi/csrc/wasm_ti3.c:1-3` and `pqz-core/ffi/build.rs` (the `wasm` branch): the pqz-ffi wasm32 build with
  `pqzl-c` relies on its helpers overriding "compiler_builtins' weak ones".

**Trigger (trace)**

The secret input, two paths:

- a mask coefficient's uniform part `urand` (`lazer/grandom.c:110-121`) → `gaussian155` →
  x = (b − c)(2k − b − c)/(2·1.55²) (`grandom.c:80-84`);
- or a rejection test's ⟨z, v⟩ (`lazer/rejection.c:110-117`, `:130-141`) → `_quot_q56`.

Both continue the same way:

1. `pqz_exp_fp` gives the exponent e (`pqz_fixexp.h:81-91`).
2. `pqz_bernoulli_fp` computes `sh = e + 1`, and every call takes the shift by `sh & 1` (`pqz_fixexp.h:98-104`). Both
   tneg and tpos are always computed.
3. On wasm32 an `unsigned __int128` shift by a variable amount is a libcall (that is why `pqz_wasm_rt.c` exists).

**Why ctgrind cannot see it**

- On x86-64 LLVM inlines the shift with `shld` / `cmov`, so memcheck (fix E) correctly reports nothing.
- In a module whose `__ashlti3` is compiler_builtins' (Rust), the source branches on the amount: the `shl & 64` and
  `shl == 0` cases in compiler-builtins' `int/shift.rs`.

Which `__ashlti3` ends up in which module:

- Every Rust-crate wasm32 build (`pqzl` alone, and pqz-ffi with `pqzl-rust`) gets compiler_builtins' version.
- The pqz-ffi wasm32 build with `pqzl-c` gets whichever definition the linker keeps. `wasm_ti3.c` only asserts that it
  wins.

**Impact (if the compiled helper branches)**

- Each Gaussian sample and each rejection test leaks the parity of floor(x / ln 2) through one branch.
- In the sampler that bit depends on the secret uniform part of the mask coefficient and on k. Masks y1 leak, and
  z1 = y1 + c·s1 is public.
- Exploiting it needs single-branch timing resolution inside a wasm32 client (a browser wallet). That is why this is
  P2 and a hypothesis, not P1.

**Confirmed or hypothesis.** Hypothesis. Confirmed:

- the source line;
- the libcall lowering on wasm32 (the reason `pqz_wasm_rt.c` and `wasm_ti3.c` exist);
- that the x86-64 ctgrind run cannot cover it.

Not confirmed: which definition each wasm module links, and whether LLVM turns compiler_builtins' branches into
`select`.

**Suggested fix (one line per core).** Replace the shift with a masked add:

`tpos = (pqz_fx_u128)mant + ((pqz_fx_u128)mant & ((pqz_fx_u128)0 - (pqz_fx_u128)(sh & 1)))`

(and the same in `fixexp.rs`). Then:

- No variable 128-bit shift is left on secret data. `pqz_div_q56` (`pqz_fixexp.h:117,121`) and Rust `div_q56` shift by
  the public loop counter only.
- Values are identical, so proof bytes and verdicts do not change.
- Add `wasm-objdump -d` / `llvm-objdump` of the client modules (no `call __ashlti3` / `__lshrti3` reachable from
  `pqz_bernoulli_fp`) to the ct check.

### N-2 — P2 — secret material is not wiped in the C core (Open item 8, triage B not applied to C): confirmed

**Locations (none of them cleared on any exit)**

Prover, stack or arena:

- `lazer/lnp-tbox.c:256` `expseed[96]` (the z3/z4 rejection seed and the protocol seeds); only the SHAKE state is
  cleared (`:346`).
- `lazer/lnp-tbox.c:337` / `:845`: `s`, the witness copy plus its automorphisms (2·(m1 + Z + l) polys), freed without
  wiping.
- `lazer/lnp-quad.c:46` / `:149` `yseed[32]` (the seed of every mask y1, y2). `y1`, `y2`, `cs1`, `cs2`, `s`, `w`, `w0`
  are freed without wiping (`:323-342`).
- `lazer/grandom.c:57` `buf[32]` (per-try sampler randomness) and `:110` `out[]` (the masks' uniform parts) are left on
  the stack.
- `src/pqz_rel.c:883-909` (`pf_t`: `s1`, `s2`, `m`, `tA2` in the arena, never freed, dropped by `pqz_arena_release`
  without a wipe, `:1392`).
- `src/pqz_rel.c:1123`: `debit_witness`'s stack arrays `d`, `dp`, `dsum`, `M`, `eT`, `c` (amounts, carries, noise).
- `src/pqz_rel.c:1149` `wv`, and `dec_w`'s arena `acc` (uᵀs, `:1097-1110`).
- `src/pqz_rel.c:1208` `dr_witness` `wv`.

Client helpers, in `ARENA_SMALL`, which the verify path of a long-running process shares:

- `pqz_keypair_from_secret` `sv`, `ev` (`pqz_rel.c:1477-1479`);
- `pqz_encrypt` `rv`, `ev` (`:1501-1505`);
- `pqz_decrypt_raw` `sv` (the secret key s) and `acc` (`:1541-1550`).

The arena itself: `pqz_arena_release` (`src/pqz_arena.c:189-208`), `poly_free` / `polyvec_free` / `intvec_free`
(`lazer/poly.c:22-31`, `lazer/polyvec.c:22-37`, `lazer/intvec.c:50-56`) never clear. `int_clear` / `intvec_clear` exist
but nothing on the PQZ path calls them.

What is cleared: `pqz_rel.c:1002` `wh`, `:1036` `ex`, `lnp-tbox.c:1877` `rbits`, `pqz_keys.c:205` `w`, every SHAKE
state.

**Trigger.**

- Any `pqz_prove`.
- `pqz_keygen` / `pqz_enc_seed` / `pqz_dec` through pqz-ffi `c.rs` (`keygen`, `enc`, `dec` all run on `ARENA_SMALL`,
  `c.rs:219-275`).

The secrets stay in the arena until later calls overwrite them.

**Impact.** Witness, mask seeds and secret keys stay readable to anything with a memory read of the process (core
dumps, swap, a co-resident bug). There is no transcript leak: the verifier never outputs arena contents. I checked that
every hashed buffer is written before it is hashed, so no uninitialised byte reaches a hash (`abdlop.c:223-231`, the
coder's first-byte masking `coder.c:81,248,362,482`).

**Confirmed.** Yes, by reading.

**Suggested fix.** No proof bytes change. The smallest change that covers every exit:

1. Add `pqz_arena_wipe_above (const pqz_arena_mark_t *m)` = `pqz_zeroize (base + m->top, peak_since_mark - m->top)`.
   This needs a per-call high-water mark: record `peak` at the mark, or keep `hiwater` reset in `pqz_arena_mark`.
2. Call it before `pqz_arena_release (&base)` in `pqz_prove` (`pqz_rel.c:1380,1392`) and in the three client helpers.
3. Add `explicit_bzero` of `expseed` (`lnp-tbox.c`, before return), `yseed` (`lnp-quad.c:323`), `grandom.c` `buf` / `out`,
   and the `debit_witness` / `dec_w` / `dr_witness` stack arrays.

The cost is one memset of the used arena per prove; Open item 8 already accepts that.

### N-3 — P3 — arena exhaustion writes far beyond the 1 MiB sink (C-F2 confirmed; also on the precompile entry and at `pqz_init`)

**Locations**

- `src/pqz_arena.c:19-21,33` (`PQZ_SINK` 1 MiB) and `:125-126,135-136,144-146`: any request that does not fit, or
  `len > cap`, returns the shared sink.
- Single allocations above 1 MiB that are then written in full:
  - `lazer/spolymat.c:61-62` (`_alloc` then `memset (nelems_max · sizeof (_spolymat_t))`), reached from
    `lazer/lnp-tbox.c:522,545,576,605` (prover) and `:1014,1037,1122,1151` (generic verifier) with
    `NELEMS_DIAG (np)`, and from `lazer/lnp-quad-many.c:26-29`.
  - `lazer/polymat.c:17-19` (`polymat_alloc`, one block, then `_polymat_init` over all elements), reached from
    `src/pqz_rel.c:162-166` (`rel_keys`: A1, A2', B'; then `abdlop_keygen` fills them) and `:189-190` (`pqz_init`:
    `A`, 32 × 32 polys, then `expand_A`).

**Sizes (computed from `params/*.h`)**

- `R_TXM8`: tbox m1 = 254 (Z = 23), quad_many l = 11, so np = 2·(254 + 11) = 530 and
  NELEMS_DIAG = 530·531/2 = 140,715 entries.
  - Native (16 B per `_spolymat_t`): 2,251,440 B per accumulator.
  - wasm32 (8 B): 1,125,720 B.
  - Both are above 1,048,576. `R_TXM80` (m1 = 238): 1,988,016 B native.
- `R_TX` (863,296 B) and `R_TXM4` (1,028,176 B) fit, just.
- `A1` of `R_TXM8` is 25 × 254 = 6,350 polys in one block (about 13 to 14 MB native).
- `A` is 1,024 polys (about 2 MB).

**Trigger**

The arena has less free space than the call needs:

- (a) `pqz_init` on an arena under about 2 MB.
- (b) The first `pqz_verify_fast` / `pqz_verify` / `pqz_prove` of a relation whose keys do not fit:
  `pqz_verify_fast` (`pqz_rel.c:1444`) → `rel_keys` → `polymat_alloc` → `abdlop_keygen` writes megabytes from `sink`.
  This is the `ffi/runs/ffi1d-arena-probe.txt` segfault ("4–12 MiB arena, exhaustion in the relation's key
  generation").
- (c) A prove or a generic verify of an M = 8 shape that hits the limit at the accumulators.

After exhaustion every failing allocation shares the same sink. Later struct headers and decoded proof coefficients
alias each other there, so a pointer read back from a sink-resident structure can hold proof data. That turns the
overflow into a wild write (hypothesis beyond the plain overflow, not traced to a concrete address).

**Not input-reachable on the precompile path**

- Every SV allocation is input-independent, except the transcript buffer (≤ `MAX_PROOF` + 65 B, `pqz_sv.c:1479-1483`).
- `tab_alloc` / `sv_alloc` check the sticky error before any write (`pqz_sv.c:863-889`, and the NULL checks at
  `:1484, 1602, 1641, 1651, 1738, 1829, 1896`). `pqz_sv_verify` skips the body on an allocation error (`:1418`).
- `ARENA_SMALL` = 512 MiB against a measured about 95 MB (`ffi/src/pqzl/c.rs:32-36`).

The paths that can hit the limit are the prover and the generic verifier (`ARENA_BIG` 1 GiB native against an `R_TXM8`
prove peak of 836 MB, `c.rs:37-40`), and any operator or test-hook arena size.

**Impact.** Native: the core overwrites up to about 14 MB of `.bss` beyond `sink` before
`with_core` sees `PQZ_ERR_ARENA` (`c.rs:138-145`).

- The NodeFault re-initialisation rebuilds the C core's own tables: `pqz_init` → `pqz_sv_reset` → `primes_init` /
  `aes_tables` run again.
- It does not repair whatever else the linked cdylib keeps there, including Rust statics.
- wasm32: linear memory beyond the sink.

**Confirmed or hypothesis.** The out-of-bounds write is confirmed (sizes and call chain read). The aliasing to wild
writes is a hypothesis.

**Suggested fix (no proof bytes or verdicts change)**

- Make exhaustion fatal and defined: in `pqz_arena_alloc`'s `fail:` path, `if (len > PQZ_SINK) __builtin_trap ();`.
  Better still, poison the context and trap on the next allocation, since LaZer never checks for NULL.
- Alternatively, carve a sink from the caller's arena at `pqz_init`, sized to the largest single allocation of the
  built relations, and clamp to it.
- Also drop or fix `pqz_arena_realloc` (`pqz_arena.c:170-178`). It is unused (no `_realloc` caller in `lazer/`, `src/`),
  but it would `memcpy` `olen` bytes from the sink or from a block shorter than the untrusted `olen`.

### N-4 — P3 — `ASSERT_ERR` is a sticky flag, not a guard: bounds asserts fall through into the out-of-bounds write

**Locations**

- `lazer/lazer-in2.h:1656-1667`: `ERR` / `ASSERT_ERR` only call `pqz_err_set`; execution continues.
- Guards that precede a write:
  - `lazer/spolyvec.c:328-333` and `lazer/spolymat.c:360-366`: `ASSERT_ERR (nelems < nelems_max)`, then
    `r->elems[nelems]` is written.
  - `lazer/coder.c:811-823` and `:870-882`: `coder_dec_urandom5/6`, `ASSERT_ERR (nelems <= nelems_max)`, then an
    input-sized VLA and inserts.
  - `lazer/polyvec.c:43-52`: `polyvec_get_subvec` bounds.

**Trigger.** None from input today:

- the insert counts on every path are fixed by the relation shape (the zero-skipping in `lnp-tbox.c:2757-2804` and
  `polyvec.c:255-292` only removes entries);
- `pqz_decproof` (`src/pqz_rel.c:379-411`) never calls the sparse decoders.

**Impact.** Latent. A future parameter or shape change, or a new caller of `coder_dec_urandom5/6`, turns an assert into
a heap overflow, with the verdict still "error" afterwards.

**Confirmed or hypothesis.** Confirmed as code behaviour; not reachable now.

**Suggested fix.** Make the guarding asserts return early (insert: set the error and return a scratch poly; decoders:
set `state->err` and return), or delete `coder_dec_urandom5/6`. No byte or verdict changes.

### N-5 — P3 (hypothesis) — the constant-time property of the C prover depends on an unpinned compiler in pqz-ffi

**Locations**

- `pqz-core/ffi/build.rs`: `b.compiler(env::var("CC").unwrap_or("clang"))`, any version.
- Fix E was checked with clang 18.1.3 (E-constant-time.md).
- Masked selects without `pqz_ct_barrier`, which a different optimiser may turn back into a branch or a cmov of
  pointers (fix E's a3 / a4 pattern):
  - `src/pqz_glue.h:54-55` (`pqz_int_set_centred`, every `poly_fromcrt` of secret polys);
  - `src/pqz_ntt.h:13-17` (`pqz_csubq`);
  - `src/pqz_rel.c:1106-1107` and `:1153-1154` (centring and rounding in `dec_w` / `debit_witness`);
  - `pqz_fixexp.h:31-34` (`pqz_ct_sel64`).

**Trigger.** A pqz-ffi C-backend build with another clang (or gcc), then a prove. **Impact.** A secret-dependent
branch or address, as before fix E. **Hypothesis.** Nothing was compiled here.

**Fix.** Either pin the compiler for the `pqzl-c` build (as the Rust toolchain is pinned), or route every mask through
`pqz_ct_barrier` (the cost is one empty `asm`). Also run `test/ct.sh` on the pqz-ffi-built archive, not only on
`build.sh` objects.

### N-6 — P3 — build and documentation hygiene

- `pqz-core/pqzl/check_symbols.sh` checks only undefined references. It does not assert that the test-hook symbols are
  absent (`pqz_test_cheat`, `pqz_test_mutate`, `pqz_test_last_ex`, `pqz_sz_trace_fn`, `pqz_l2dom_poc`).
  `ffi/build.rs` skips the scan entirely under feature `fuzz`, which also adds `-DPQZ_TEST_HOOKS`.
  - Today the production build defines none of `PQZ_TEST_HOOKS`, `PQZ_SZ_TRACE`, `PQZ_CTGRIND`, `PQZ_L2DOM_POC`,
    `PQZ_DEBUG_MALLOC`, `PQZ_TXM_OVERSIZE` (`ffi/build.rs` flags; `build.sh:24-37`), so the hooks are compiled out.
  - Even with them, `CHEAT` affects only the prover.
  - Suggest a negative list in `check_symbols.sh`.
- `src/pqz_rel.c:287-289`: the comment says every statement is "< 70,000 B". `PQZ_TXM_STMT_BYTES (8, 1)` is 215,936 B.
  `be32` is still exact (< 2^32), so this is a comment fix only.

## Round-1 findings: status in this tree

| Round-1 item | Status at `e9cabd1` | Evidence |
|---|---|---|
| C-F1 / lazer#28 part 1: `h` not absorbed before `μ` | **Fixed** in prover, generic verifier and SV | `lnp-tbox.c:803-806` (prover `_lnp_tbox_hash_h` before `lnp_quad_many_prove`), `:1344-1349` (verifier), `:2102-2131`; SV `pqz_sv.c:1542-1545` (`hash2`), `:1832-1837` (μ from `g2`), `:1946-1949` (final round on `hash2`) |
| D-1 / lazer#28 part 2: `z3`, `z4` not absorbed before V3 / V4 | **Fixed** | `lnp-tbox.c:415-418` (prover), `:1178-1185` (verifier, after the norm checks), `:2047-2094`; V on `hash0`, JL rows on `hashr` (`:700, 711, 3338, 3651`); SV `pqz_sv.c:1516-1530`, `:1593-1594`, `:1646` |
| F3 (SV transcript buffer sized from `proof_len`) | **Fixed** | `pqz_sv.c:1479-1485`. The z3‖z4 re-encoding is the same bit string as the proof's (bijective coder, decoded \|z\| < q/2 under `MAX_PROOF`, norm checks first), so it is ≤ 8·`proof_len` bits; `_inc_idx_zero`'s look-ahead byte and the pad byte fit in the +64 |
| D-2 (z2 rejection) | **Fixed** (Rej1 with σ2) | `lnp-quad.c:277-281`, `rejection.c:159-171` |
| D-3 (β sign bits) | **Fixed**, `rbits` cleared | `lnp-tbox.c:1667-1713`, `:1877` |
| C-F2 / Open item 2 (arena sink) | **Open**; worse than stated (also `rel_keys` / `pqz_init`) | N-3 |
| Open item 8 / triage B (wiping) | **Open in C** | N-2 |
| Triage A (length / proof cap before keys and hash) | **Fixed in C** | `rel_of` checks the exact length first (`pqz_rel.c:1290-1316`); `pqz_verify` `:1405-1417`, `pqz_verify_fast` `:1438-1450` check `proof_len > PQZ_MAX_PROOF` before `rel_keys`, `pqz_sv_setup`, `pqz_stmt_hash`; `pqz_prove` `:1369-1384` |
| Triage D (`-INT64_MIN` in the SV) | **Fixed** | `uabs64` `pqz_sv.c:1337-1342`, used at `:1350, 1496, 1554` |
| Fix E (prover constant time) | **Present**, x86-64 behaviour as documented | barriers `pqz_rt.h:41-46`, `pqz_mpn.h:139`, `dcompress.c:9-37`, `int.c:2692-2706`; `debit_witness` / `dr_witness` / `dec_w` masks and `ct_sdiv` (`pqz_rel.c:1081-1221`); `int_binexp` masked; keys `pqz_keys.c:113-207`. Gaps that ctgrind cannot see: N-1, N-5 |
| Open item 4 (UBSan nits) | Unchanged: zero-length VLAs for Z / M / nbin = 0 (`lnp-tbox.c:278-280, 946-948, 3631-3634`) | not input-dependent |
| Open item 6 (global state) | C keeps it; pqz-ffi serialises every call (`c.rs:103-146`); `pqz_enc_group_seed` runs without the lock and touches only its own SHAKE state (`pqz_keys.c:173-185`) | clean |

## Checked and clean

**Decoder (`lazer/coder.c`, `src/pqz_rel.c:379-411`)**

- Reads:
  - every variable-length read goes through `RDB` against `in_len` (`coder.c:8-10`);
  - the fixed-width decoder pre-checks that all `nelems·mbits` bits are present (`:393-397`), and `_udecode`
    rejects any value ≥ m (`:554-555`).
- Termination and length:
  - unary loops stop at the end of the buffer (`:172, 319`); time is linear in `proof_len`;
  - `coder_dec_end` requires the pad one and zero bits after it (`:419`), and `pqz_decproof` requires exactly `len`
    bytes (`pqz_rel.c:410`).
- Values: c is reduced mod 17 to [−8, 8] (`:399-402`). `ao·z1 + z0` cannot overflow (|z| < 2^39 at `MAX_PROOF`).
  Shifts are < width.
- `byte_off` / `bit_off` are `unsigned int`, enough for 98,304 B.
- Field sizes are fixed by the parameters (`pf_alloc`, `pqz_rel.c:889-909`; SV `pqz_sv.c:1415-1417`, matching the
  setup asserts `:1022-1025`).

**Statement parsing**

- `rd_poly` uses unsigned subtraction (no `INT64_MIN` UB, `pqz_rel.c:223-235`); `rd_word64` canonicality
  (`:629-637`).
- Every read lies inside the checked exact length:
  - generic `parse_debit` / `parse_disc` (`:652-705, 810-821`);
  - SV `parse_stmt` (`pqz_sv.c:1137-1201`; the `want` lengths equal `PQZ_TXM_STMT_BYTES` term by term).
- Op 7 picks the relation from the header words, length ≥ 640 first (`pqz_rel.c:1273-1285`).
- C and Rust `rel_of` are identical (`rust/src/rel.rs:124-150`).

**C SV (`pqz_sv.c`)**

- v3 order: hashcomm → z3 / z4 norm checks → ty round (cseed) → hz (hash0) → h-coefficient check → tg round (hash1) →
  hash2 (h) → μ (`g2`) → the final round on hash2 (`:1487-1545, 1832-1837, 1926-1956`).
- Norm checks equal the generic verifier's:
  - z1 bound formula equal to `lnp-quad.c` (`:1038-1043` against `lnp_quad_verify`);
  - z3 ℓ2 ≤ / z4 ℓ∞ ≤ (`:1493-1497`);
  - hint ℓ∞ ≤ m (`:1553-1555`);
  - c ∈ [−8, 8] (`:1559-1561`);
  - the joint (z21, w − γw1) ℓ2 bound (`:1959-1961`; the generic verifier also centres `w − γw1`, `poly.c:80-100`,
    `int.c:2692-2706`);
  - per-equation ℓ2 domains (`:1764-1765`).
- `UseHint` equals `dcompress_use_ghint` (`pqz_sv.c:1909-1922` against `dcompress.c:43-155`).
- Arithmetic preconditions hold at every call site:
  - `lift` / `modq` / `mulq` / `fwd` inputs: z1 after its norm check, z3 / z4 after theirs, the rest < q or small;
  - accumulators: fewer than about 500 terms of < 2^31;
  - integer-polynomial bounds < 2^106 against P/2 ≈ 2^119;
  - `l2_sum` < 2^63.
- Buffers and indices are in bounds:
  - `urandom` buffer (`URND_MAX` = 2,240 = 4·16·35);
  - JL fold sizes;
  - `Gm` / `Ab` / `PKe` / `T->vec` / `rb` indices (`SVPR` = 34, `SVBIN` = 30, slot / 64 ≤ M + 13 < nbin);
  - `SV_NBLK` 48 against 34 `sv_alloc` calls.
- No uninitialised read reaches a verdict or a hash (every `W.*`, `T`, `H`, `Gm`, `Ab` is written before use;
  `c.rs`'s `TEST_ARENA_FILL` covers this).

**C = Rust verdict parity (consensus)**

C `pqz_verify_fast` against Rust `verify_sv`, line by line:

- `rel_of`, then the proof cap, then the keys and the hash: `pqz_rel.c:1433-1456`, `sv.rs:1757-1778`.
- Statement parse: `pqz_sv.c:1137-1201`, `sv.rs:972-1060`.
- Decoder, equal accept set:
  - Rust stops at the first bad read; C continues with zeros and fails at the end;
  - the same bit order, the same ghint / grandom bijections, the same pad and length rule (`coder.rs:186-300`).
- Transcript rounds and seeds (`sv.rs:1290-1335`).
- Check order and bounds (`sv.rs:1341-1352`, `:1705-1748`).
- The final round over `hash2`.

**No input that makes one SV accept and the other reject was found.**

- C rejects on any sticky `pqz_err` (`pqz_sv.c:1418, 1423`). For an accepted proof no `ASSERT_ERR` on the SV path can
  fire, because every encoder input is canonical before it is encoded.
- Allocation failure: C reports `PQZ_ERR_ARENA` → NodeFault (`c.rs:138-145`), Rust reports `Err(Memory)`. Neither is
  a verdict.

**Generic verifier (`lnp-tbox.c:889-1400`, `lnp-quad.c:347-529`)**

- v3 rounds as above.
- The h-coefficient check happens before use (`:1188-1199`).
- `abdlop_hashcomm`'s `out` is fully written (`abdlop.c:213-233`: kmsis·64·29 bits is a multiple of 8, plus the pad
  byte).
- `_lnp_tbox_hash_z34` sizes its buffer exactly and skips the unbounded coder on an error (`:2047-2094`).
- `_lnp_tbox_hash_h` (`:2102-2131`).
- Sparse sizes are fixed by the shape.
- It runs only in differential tests and fuzzing (`c.rs:206-210`).

**Prover**

- Witness lengths are checked before any read (`pqz_rel.c:1319-1357`).
- `encproof` writes only after the exact length check (`:343-348`), and `do_prove` copies only `len ≤ *proof_len`
  (`:1039-1043`).
- Hedged seeds (`:993-1003`); `ex` is wiped (`:1036`).
- `ct_sdiv` and the `INT64_MIN` handling (`:1081-1089`).
- `pqz__div` is fixed-step (`pqz_mpn.h:149-184`).
- `pqz_absmod1` / `pqz_red128` have no data-dependent branch (`pqz_glue.h:10-48`, `pqz_ntt.c:30-38`).
- `_int2i128` declassifies only the abort verdict (`rejection.c:22-40`).
- Sampler: a full table scan; only the accept bit is declassified (`grandom.c:49-99`).

**Arena bookkeeping when not exhausted**

`pqz_arena.c:119-208`:

- size-class recycling, free-list links, and `pop` on top-of-stack frees;
- `free` ignores the sink, out-of-range pointers and double frees;
- mark / release rebuilds the lists.

I spot-checked the "long-lived objects do not allocate inside a call" invariant:

- keys and A are converted to NTT form before the mark (`pqz_rel.c:167-170`, `expand_A:146`);
- the SV reads `crtrep` without converting it (`pqz_sv.c:891-905`);
- `poly_set` copies (`poly.c:35-50`);
- matrix-times-vector products convert only the per-call operand.

**Other**

- **pqz-ffi `c.rs`.** One lock, one worker with a 16 MiB stack (`ffi/src/pqzl.rs:49-100`). `pqz_init` gets `need`,
  not the capacity. Every buffer handed to C has its exact size. `pqz_err` is read with a volatile read after the call.
- **wasm32 typing.** No `long`-width or `size_t`-width dependence on the verifier path (the coder's `int64_t`, the
  arena headers stored as `uint64_t`). The SV is 64-bit integer only. `PQZ_MUL128` = 0 is the limb path on wasm32.

## Not checked

- No build, no run, no ASan / UBSan, no ctgrind, no `wasm-objdump`. For N-1 I could not see which `__ashlti3` each
  wasm32 module links, nor whether LLVM turns compiler_builtins' branches into `select`.
- Which compiler the node image's `pqzl-c` build uses (N-5).
- The full Schwartz–Zippel accumulation algebra in `lnp-tbox.c` (`__schwartz_zippel_accumulate*`, `_auto`): I relied
  on the SV / generic differential and the vectors for the coefficient-level equality. Same for `lnp-quad-many.c`'s μ
  domain layout against the SV's `k + 1`.
- An exhaustive proof of the "no long-lived object allocates or frees inside a call" invariant for every LaZer routine
  that touches A, A1, A2', B'. Spot-checked only. A violation would be a use-after-release across calls (dangling
  `crtrep` above the mark).
- The Rust generic verifier (`rust/src/proof/tbox.rs`, `quad.rs`) line by line: only the SV path was compared, because
  it is the consensus path.
- Parameter derivations (`params/*.sage`), the knowledge-error figures, `shake128.c` / `aes256ctr.c` internals,
  `pqz_ntt.c` beyond the reduction bounds.
- The exact `.bss` layout after `sink` (what N-3 overwrites first).
