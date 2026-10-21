//! The oracles of the libFuzzer targets (P6e plan Task 10, D12, D15), called from `targets/<target>.c`.
//!
//! Every target runs on the precompile's production configuration: the Rust PQZL core (`pqz-ffi`'s default backend
//! since CTR-PQZ-09, 2026-10-18) with every form's keys and tables built by a warm-up pass, as in a long-running node.
//! Mode `pqzl-diff` (feature, `PQZ_FUZZ_MODE=pqzl-diff build.sh`; pqzl-rust plan Task 11) also links the C core (ASan +
//! UBSan, on the verify-only arena `pqzl::c::ARENA_SMALL`, 512 MiB) and compares the two cores on every input.
//! On every input each target asserts (a failed assertion aborts: a libFuzzer crash):
//! - no panic anywhere (the panic hook aborts, so even the panics `pqz-ffi` and Ligero would catch are findings);
//! - the C ABI never returns status 3 (input-caused panic) or 4 (node fault); status 1 (revert) only above
//!   `MAX_INPUT`;
//! - the same input twice gives the same status and output;
//! - the verdict: `…01` exactly for the unmodified honest inputs, the self-test hash for `06 00000000`, `…00` for
//!   everything else (a modified input that verifies is a wrong accept or a malleable encoding);
//! - mode `pqzl-diff`: every input that decodes as PQZL gets the C core's specialised verdict = the precompile's (the
//!   Rust core's); every `pqz_test_mutate` (mutate mode 1, codec 4) gives the same bytes from both cores (decoded,
//!   changed, re-encoded); the C arena's high-water mark stays ≤ `ARENA_BOUND` = `ARENA_SMALL` / 1.5 = 341 MiB (the
//!   maximum seen is printed).
//!
//! The honest inputs (every form of both ids, the fee-0 forms, every built op 7 `(id, M, auditorOn)` and the inputs
//! of `regress/valid/`) come from the frozen vectors (`smartcontracts/vectors/pqz/`, written to `$PQZ_FUZZ_HONEST` by
//! `seeds.py`); the core never proves.
use std::sync::OnceLock;
#[cfg(feature = "pqzl-diff")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use pqz_ffi::stmt::{self, Form};
use pqz_ffi::*;

/// The C core's verify-only arena's bound (mode `pqzl-diff`): 1.5 × margin below `ARENA_SMALL`.
#[cfg(feature = "pqzl-diff")]
pub const ARENA_BOUND: usize = pqzl::c::ARENA_SMALL / 3 * 2;

struct Honest {
    /// `None` for op 7 (`Stmt::Multi` has no `Form`)
    form: Option<Form>,
    op: u8,
    /// the `pqz_test_mutate` relation code (`rel`)
    rel: u8,
    pqzl: bool,
    stmt: Vec<u8>,
    proof: Vec<u8>,
    input: Vec<u8>,
}

static HONEST: OnceLock<Vec<Honest>> = OnceLock::new();
static SELFTEST: OnceLock<Word> = OnceLock::new();
static TARGET: OnceLock<String> = OnceLock::new();
#[cfg(feature = "pqzl-diff")]
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// mode `pqzl-diff`: PQZL inputs whose C verdict was compared with the Rust one, and test_mutate outputs compared
#[cfg(feature = "pqzl-diff")]
static CORE_DIFFS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "pqzl-diff")]
static CORE_MUTATES: AtomicU64 = AtomicU64::new(0);
static INPUTS: AtomicU64 = AtomicU64::new(0);
static DECODED: AtomicU64 = AtomicU64::new(0);
static VALIDS: AtomicU64 = AtomicU64::new(0);
static DIFFS: AtomicU64 = AtomicU64::new(0);
static CANON: AtomicU64 = AtomicU64::new(0);
static PQZL_INPUTS: AtomicU64 = AtomicU64::new(0);
/// op 7 (P6-ANON S5): inputs that decode as op 7 (precompile, mutate) / accepted over an op 7 base (codec), and
/// differentials on op 7
static MULTI: AtomicU64 = AtomicU64::new(0);
static MULTI_DIFFS: AtomicU64 = AtomicU64::new(0);

fn die(msg: &str) -> ! {
    eprintln!("pqz-fuzz FINDING ({}): {msg}", TARGET.get().map_or("?", |s| s.as_str()));
    std::process::abort()
}

fn honest() -> &'static [Honest] {
    HONEST.get().unwrap_or_else(|| die("not initialised"))
}

fn record(input: Vec<u8>) -> Honest {
    let i = decode(&input).unwrap_or_else(|e| die(&format!("cached honest input does not decode: {e:?}")));
    let (form, pqzl) = (i.stmt.form(), *i.stmt.proof_system_id().unwrap() == PQZL_ID);
    let (stmt, proof) = (i.stmt_bytes.to_vec(), i.proof.to_vec());
    Honest { form, op: i.op, rel: rel(&i.stmt), pqzl, stmt, proof, input }
}

/// The honest inputs from `seeds.py`'s file (`be32(len) ‖ input` records, built from the frozen vectors): PQZL's 8
/// forms in `FORMS` order, PQZH's 8, the fee-0 rows of both ids, the op 7 rows of PQZL then PQZH, `regress/valid/`.
fn load(path: &str) -> Vec<Honest> {
    let mut b = &std::fs::read(path).unwrap_or_else(|e| die(&format!("{path}: {e} (run seeds.py)")))[..];
    let mut v = Vec::new();
    while b.len() >= 4 {
        let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        v.push(record(b[4..4 + n].to_vec()));
        b = &b[4 + n..];
    }
    // PQZL's 8 forms, then (a build with PQZH: the v3 set until plan 5h Task 8c) PQZH's 8
    let n = if pqz_ffi::PQZH { 16 } else { 8 };
    let order = v.len() >= n && v.iter().take(n).enumerate().all(|(i, h)| h.pqzl == (i < 8) && h.form == Some(stmt::FORMS[i % 8]));
    if !order {
        die(&format!("{path}: expected PQZL then PQZH in FORMS order first"));
    }
    v
}

/// The C ABI on one input: (status, out), `out` pre-filled with 0xEE.
fn call(inp: &[u8]) -> (i32, Word) {
    let mut out = [0xEEu8; 32];
    // SAFETY: valid input and output buffers
    let rc = unsafe { pqz_precompile(inp.as_ptr(), inp.len(), out.as_mut_ptr(), out.len()) };
    (rc, out)
}

/// Mode `pqzl-diff`: the C core's arena peak within its bound; nothing otherwise (the Rust core has no arena).
fn arena_check() {
    #[cfg(feature = "pqzl-diff")]
    arena_check_c();
}

#[cfg(feature = "pqzl-diff")]
fn arena_check_c() {
    let p = pqzl::c::arena_peak();
    if p > PEAK.fetch_max(p, Relaxed) {
        eprintln!("pqz-fuzz: arena peak {p} B (bound {ARENA_BOUND} B)");
    }
    if p > ARENA_BOUND {
        die(&format!("arena peak {p} B over the bound {ARENA_BOUND} B"));
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The precompile oracle (module doc) on one input given the C ABI's results of two calls; returns the verdict.
fn check(inp: &[u8], a: (i32, Word), b: (i32, Word)) -> bool {
    INPUTS.fetch_add(1, Relaxed);
    if a != b {
        die(&format!("not deterministic: {} {} / {} {}", a.0, hex(&a.1), b.0, hex(&b.1)));
    }
    let over = inp.len() > MAX_INPUT;
    match a.0 {
        PQZ_FFI_REVERT if over && a.1 == INVALID => return false,
        PQZ_FFI_OK if !over => {}
        rc => die(&format!("status {rc} (input {} B)", inp.len())),
    }
    let expect = if inp == [6, 0, 0, 0, 0] {
        *SELFTEST.get().unwrap()
    } else if honest().iter().any(|h| h.input == inp) {
        VALID
    } else {
        INVALID
    };
    if a.1 != expect {
        die(&format!("verdict {} for an input that should give {} ({} B)", hex(&a.1), hex(&expect), inp.len()));
    }
    if let Ok(i) = decode(inp) {
        DECODED.fetch_add(1, Relaxed);
        MULTI.fetch_add((i.op == 7) as u64, Relaxed);
        #[cfg(feature = "pqzl-diff")]
        if i.stmt.proof_system_id() == Some(&PQZL_ID) {
            let c = pqzl::c::verify_fast(i.op, i.stmt_bytes, i.proof).unwrap_or_else(|_| die("node fault in the C core"));
            if c != (a.1 == VALID) {
                die(&format!("cores differ: C verdict {c}, Rust (precompile) {} (op {}, {} B)", hex(&a.1), i.op, inp.len()));
            }
            CORE_DIFFS.fetch_add(1, Relaxed);
        }
    }
    VALIDS.fetch_add((a.1 == VALID) as u64, Relaxed);
    arena_check();
    a.1 == VALID
}

/// `pqzl::test_mutate` (the backend's: the Rust core), and in mode `pqzl-diff` the same from the C core: equal bytes.
fn test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Option<Vec<u8>> {
    let r = pqzl::test_mutate(rel, proof, kind, r1, r2).unwrap_or_else(|_| die("node fault in pqz_test_mutate"));
    #[cfg(feature = "pqzl-diff")]
    {
        let c = pqzl::c::test_mutate(rel, proof, kind, r1, r2).unwrap_or_else(|_| die("node fault in the C core's pqz_test_mutate"));
        if c != r {
            die(&format!(
                "cores differ in pqz_test_mutate (rel {rel:#x}, kind {kind}, {} B): C {:?} B, Rust {:?} B",
                proof.len(),
                c.as_ref().map(|v| v.len()),
                r.as_ref().map(|v| v.len())
            ));
        }
        CORE_MUTATES.fetch_add(1, Relaxed);
    }
    r
}

extern "C" fn summary() {
    #[cfg(feature = "pqzl-diff")]
    let diff = format!(
        ", mode pqzl-diff: {} PQZL verdicts C = Rust, {} pqz_test_mutate C = Rust, C arena peak max {} B = {:.2} MiB (bound {} MiB, \
         ARENA_SMALL {} MiB)",
        CORE_DIFFS.load(Relaxed),
        CORE_MUTATES.load(Relaxed),
        PEAK.load(Relaxed),
        PEAK.load(Relaxed) as f64 / (1 << 20) as f64,
        ARENA_BOUND >> 20,
        pqzl::c::ARENA_SMALL >> 20
    );
    #[cfg(not(feature = "pqzl-diff"))]
    let diff = ", PQZL core: Rust";
    eprintln!(
        "pqz-fuzz summary ({}): {} inputs checked, {} decoded ({} op 7), {} valid (= unmodified honest; mutate skips those), \
         {} differential SV = generic ({} op 7), {} PQZL proof re-encodings equal{diff}",
        TARGET.get().map_or("?", |s| s.as_str()),
        INPUTS.load(Relaxed),
        DECODED.load(Relaxed),
        MULTI.load(Relaxed),
        VALIDS.load(Relaxed),
        DIFFS.load(Relaxed),
        MULTI_DIFFS.load(Relaxed),
        CANON.load(Relaxed),
    );
}

extern "C" {
    fn atexit(f: extern "C" fn()) -> i32;
}

/// `LLVMFuzzerInitialize`: the panic hook, the honest inputs, (mode `pqzl-diff`) the C core on its verify-only arena,
/// a warm-up pass (every honest input valid, the self-test).
///
/// # Safety
/// `target` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn pqz_fuzz_init(target: *const std::ffi::c_char) {
    let target = std::ffi::CStr::from_ptr(target).to_string_lossy().into_owned();
    TARGET.set(target.clone()).ok();
    std::panic::set_hook(Box::new(|i| die(&format!("panic: {i}"))));
    let path = std::env::var("PQZ_FUZZ_HONEST").unwrap_or_else(|_| "honest.bin".into());
    HONEST.set(load(&path)).ok();
    #[cfg(feature = "pqzl-diff")]
    if !pqzl::c::reinit(pqzl::c::ARENA_SMALL) {
        die("C core: reinit on the verify-only arena");
    }
    let st = call(&[6, 0, 0, 0, 0]);
    if st.0 != PQZ_FFI_OK {
        die("self-test status");
    }
    SELFTEST.set(st.1).ok();
    for h in honest() {
        if call(&h.input) != (PQZ_FFI_OK, VALID) {
            die(&format!("honest {:?} op {} rel {:#x} (PQZL {}) not valid", h.form, h.op, h.rel, h.pqzl));
        }
        #[cfg(feature = "pqzl-diff")]
        if h.pqzl && pqzl::c::verify_fast(h.op, &h.stmt, &h.proof) != Ok(true) {
            die(&format!("honest {:?} op {} rel {:#x}: not valid in the C core", h.form, h.op, h.rel));
        }
    }
    arena_check();
    #[cfg(feature = "pqzl-diff")]
    let mode = format!(
        "mode pqzl-diff (Rust core = the precompile, C core compared): C verify-only arena {} MiB, used {} B, peak {} B",
        pqzl::c::ARENA_SMALL >> 20,
        pqzl::c::arena_used(),
        pqzl::c::arena_peak()
    );
    #[cfg(not(feature = "pqzl-diff"))]
    let mode = "PQZL core: Rust";
    eprintln!("pqz-fuzz init ({target}): {} honest inputs valid, self-test {}, {mode}", honest().len(), hex(&st.1));
    atexit(summary);
}

/// `precompile` target: the C caller made both calls (`targets/precompile.c`); this checks them.
///
/// # Safety
/// `data` points to `len` bytes, `out1` / `out2` to 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn pqz_fuzz_check(data: *const u8, len: usize, rc1: i32, out1: *const u8, rc2: i32, out2: *const u8) {
    let inp = if len == 0 { &[][..] } else { std::slice::from_raw_parts(data, len) };
    let w = |p: *const u8| -> Word { std::slice::from_raw_parts(p, 32).try_into().unwrap() };
    check(inp, (rc1, w(out1)), (rc2, w(out2)));
}

/// 4-byte edits `[off lo, mid, hi, x]` XOR `x` into `buf[region.start + off % region.len()]`; a trailing 1–3 bytes
/// truncate (1 byte), extend with zeros (2) or with 0xFF (3) the end of `buf` by their sum mod 64.
fn edit(buf: &mut Vec<u8>, region: std::ops::Range<usize>, s: &[u8]) {
    let mut i = 0;
    while i + 4 <= s.len() {
        let off = s[i] as usize | (s[i + 1] as usize) << 8 | (s[i + 2] as usize) << 16;
        if !region.is_empty() {
            buf[region.start + off % region.len()] ^= s[i + 3];
        }
        i += 4;
    }
    let t = &s[i..];
    let n = t.iter().map(|&x| x as usize).sum::<usize>() % 64;
    match t.len() {
        1 => buf.truncate(buf.len().saturating_sub(n)),
        2 => buf.resize(buf.len() + n, 0),
        3 => buf.resize(buf.len() + n, 0xFF),
        _ => {}
    }
}

fn le64(b: &[u8]) -> u64 {
    b.iter().take(8).enumerate().fold(0, |a, (i, &x)| a | (x as u64) << (8 * i))
}

/// The `pqz_test_mutate` relation code of a statement (pqz_int.h: the op, `R_TX0` = 0x81, `R_TXM` =
/// `PQZ_REL_TXM(log2 M, auditorOn)` = 0x70 | auditorOn << 3 | log2 M).
fn rel(s: &stmt::Stmt) -> u8 {
    match (s, s.form()) {
        (_, Some(Form::Transfer0)) => 0x81,
        (_, Some(f)) => f.op(),
        (stmt::Stmt::Multi(m), None) => 0x70 | (m.pk_a.is_some() as u8) << 3 | m.m.trailing_zeros() as u8,
        _ => 0,
    }
}

/// differential sampling: the generic verifier on every `DIFF_EVERY`-th mutated PQZL input that decodes (≈ 100× a
/// fast verify)
const DIFF_EVERY: u64 = 256;

/// `mutate` target. Input: byte 0 = the honest input (mod their number: PQZL forms 0..7, PQZH 8..15 in
/// `pqz_stmt::FORMS` order, the fee-0 rows, the op 7 rows, `regress/valid/`);
/// byte 1 % 4 = mode: 0 edits anywhere in the precompile input (op, length field, statement, proof), 1 PQZL: one
/// decoded proof field changed and re-encoded (`pqz_test_mutate` kind byte 2 % 14, r1 / r2 from bytes 3..19; PQZH:
/// as mode 3) then edits in the proof, 2 edits in the statement, 3 edits in the proof; then the edit script (`edit`).
/// Oracle: `check`, plus for PQZL, sampled, the specialised verifier (the precompile's verdict) = the generic one.
///
/// # Safety
/// `data` points to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn pqz_fuzz_mutate(data: *const u8, len: usize) {
    if len < 2 {
        return;
    }
    let d = std::slice::from_raw_parts(data, len);
    let h = &honest()[d[0] as usize % honest().len()];
    let (mut mode, mut script) = (d[1] % 4, &d[2..]);
    let mut inp = h.input.clone();
    let (s0, p0) = (5, 5 + h.stmt.len());
    if mode == 1 {
        if h.pqzl && d.len() >= 19 {
            let (kind, r1, r2) = (d[2] as u32 % 14, le64(&d[3..11]), le64(&d[11..19]));
            match test_mutate(h.rel, &h.proof, kind, r1, r2) {
                Some(p) => inp = stmt::input(h.op, &h.stmt, &p),
                None => die("the honest proof does not decode in pqz_test_mutate"),
            }
            script = &d[19..];
        }
        mode = 3;
    }
    let region = match mode {
        0 => 0..inp.len(),
        2 => s0..p0,
        _ => p0..inp.len(),
    };
    edit(&mut inp, region, script);
    if inp == h.input {
        return; // unmodified: the warm-up pass checked it (a third of the inputs otherwise)
    }
    let valid = check(&inp, call(&inp), call(&inp));
    if h.pqzl && PQZL_INPUTS.fetch_add(1, Relaxed) % DIFF_EVERY == DIFF_EVERY - 1 {
        if let Ok(i) = decode(&inp) {
            if *i.stmt.proof_system_id().unwrap() == PQZL_ID {
                let g = pqzl::verify_generic(i.op, i.stmt_bytes, i.proof).unwrap_or_else(|_| die("node fault in the generic verifier"));
                if g != valid {
                    die(&format!("differential: generic {g}, specialised {valid}"));
                }
                DIFFS.fetch_add(1, Relaxed);
                MULTI_DIFFS.fetch_add((i.op == 7) as u64, Relaxed);
            }
        }
    }
}

/// The `i`-th PQZL honest input (mod their number; the first 8 are the P6e forms, so `i` < 8 keeps P6e's choice).
fn pqzl_honest(i: usize) -> &'static Honest {
    let n = honest().iter().filter(|h| h.pqzl).count();
    honest().iter().filter(|h| h.pqzl).nth(i % n).unwrap()
}

/// `codec` target (D15: every decoder accepts exactly one encoding; accepted ⇒ re-encoding is the input). Input: byte
/// 0 % 5 = codec, the honest input `(byte 0 / 5) << 4 | byte 1 & 15` (mod their number; codec 4: mod the PQZL ones),
/// an op override (byte 1 bit 4: op = bits 5..7, 0..7), then the edit script over the codec's bytes:
/// 0 `pqz_stmt::parse(op, stmt)` ⇒ `encode` = the bytes, the form's op and length; 1 `decode_input(input)` ⇒
/// `input(op, stmt, proof)` = the bytes and `parse` agrees; 2 `parse_bundle(bundle)` ⇒ `encode` = the bytes; 3
/// `parse_opening(abi.encode(bundle, proof))` ⇒ `opening` = the bytes; 4 the PQZL proof decoder (`pqz_decproof`, via
/// `pqz_test_mutate` with no change) ⇒ the re-encoded proof (`encproof`) = the bytes. Each decoder twice: equal results.
///
/// # Safety
/// `data` points to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn pqz_fuzz_codec(data: *const u8, len: usize) {
    if len < 2 {
        return;
    }
    let d = std::slice::from_raw_parts(data, len);
    let (codec, sel, script) = (d[0] % 5, d[1], &d[2..]);
    let idx = (d[0] as usize / 5) << 4 | (sel & 15) as usize;
    let h = &honest()[idx % honest().len()];
    let hl = pqzl_honest(idx); // codec 4: a PQZL proof
    let op = if sel & 0x10 != 0 { sel >> 5 } else { h.op };
    INPUTS.fetch_add(1, Relaxed);
    let tr = &honest()[(sel & 1) as usize]; // PQZL Transfer / Transfer0: the bundle's u, v_t, [v_a]
    let bundle = || {
        let Ok(stmt::Stmt::Debit(t)) = stmt::parse(tr.op, &tr.stmt) else { die("honest transfer") };
        let b = stmt::Bundle { salt: [0xA5; 16], u: t.u, v_t: t.v_t.unwrap(), v_a: t.v_a, to_ua: [0x22; 32] };
        b.encode().unwrap()
    };
    let mut b = match codec {
        0 => h.stmt.clone(),
        1 => h.input.clone(),
        2 => bundle(),
        3 => stmt::opening(&bundle(), &h.proof),
        _ => hl.proof.clone(),
    };
    let all = 0..b.len();
    edit(&mut b, all, script);
    let ok = match codec {
        0 => {
            let (r, r2) = (stmt::parse(op, &b), stmt::parse(op, &b));
            if r != r2 {
                die("parse not deterministic");
            }
            r.map(|s| {
                let shape = match (&s, s.form()) {
                    (_, Some(f)) => f.op() == op && f.stmt_len() == b.len(),
                    (stmt::Stmt::Multi(m), None) => op == 7 && stmt::multi_len(m.m, m.pk_a.is_some()) == b.len(),
                    _ => op == 6 && b.is_empty(),
                };
                if s.encode().as_deref() != Ok(&b[..]) || !shape {
                    die(&format!("parse/encode round trip, op {op}, form {:?}, {} B", s.form(), b.len()));
                }
            })
            .is_ok()
        }
        1 => {
            let (r, r2) = (decode(&b), decode(&b));
            if r != r2 {
                die("decode_input not deterministic");
            }
            r.map(|i| {
                if stmt::input(i.op, i.stmt_bytes, i.proof) != b || stmt::parse(i.op, i.stmt_bytes) != Ok(i.stmt.clone()) {
                    die("decode_input/input round trip");
                }
            })
            .is_ok()
        }
        2 => {
            let (r, r2) = (stmt::parse_bundle(&b), stmt::parse_bundle(&b));
            if r != r2 {
                die("parse_bundle not deterministic");
            }
            r.map(|x| {
                if x.encode().as_deref() != Ok(&b[..]) {
                    die("bundle round trip");
                }
            })
            .is_ok()
        }
        3 => {
            let (r, r2) = (stmt::parse_opening(&b), stmt::parse_opening(&b));
            if r != r2 {
                die("parse_opening not deterministic");
            }
            r.map(|(x, p)| {
                if stmt::opening(x, p) != b {
                    die("opening round trip");
                }
            })
            .is_ok()
        }
        _ => {
            let h = hl;
            let (r, r2) = (test_mutate(h.rel, &b, 99, 0, 0), test_mutate(h.rel, &b, 99, 0, 0));
            if r != r2 {
                die("PQZL proof decoder not deterministic");
            }
            if let Some(e) = &r {
                if *e != b {
                    die(&format!("PQZL proof {:?} (rel {:#x}): decoded {} B, re-encoded {} B differ (non-canonical encoding accepted)", h.form, h.rel, b.len(), e.len()));
                }
                CANON.fetch_add(1, Relaxed);
            }
            r.is_some()
        }
    };
    if ok {
        DECODED.fetch_add(1, Relaxed);
        MULTI.fetch_add((if codec == 4 { hl.op } else { h.op } == 7) as u64, Relaxed);
    }
    arena_check();
}
