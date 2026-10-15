//! The oracles of the libFuzzer targets (P6e plan Task 10, D12, D15), called from `targets/<target>.c`.
//!
//! Every target runs on the precompile's production configuration: the C core on the verify-only arena
//! (`pqzl::ARENA_SMALL`, 144 MiB) with every form's keys and tables built by a warm-up pass, as in a long-running node.
//! On every input each target asserts (a failed assertion aborts: a libFuzzer crash):
//! - no panic anywhere (the panic hook aborts, so even the panics `pqz-ffi` and Ligero would catch are findings);
//! - the C ABI never returns status 3 (input-caused panic) or 4 (node fault); status 1 (revert) only above
//!   `MAX_INPUT`;
//! - the same input twice gives the same status and output;
//! - the verdict: `…01` exactly for the unmodified honest inputs, the self-test hash for `06 00000000`, `…00` for
//!   everything else (a modified input that verifies is a wrong accept or a malleable encoding);
//! - the arena high-water mark stays ≤ `ARENA_BOUND` = `ARENA_SMALL` / 1.5 = 96 MiB (the maximum seen is printed).
//!
//! The honest inputs (every form of both ids and the fee-0 forms) come from the frozen vectors
//! (`smartcontracts/vectors/pqz/`, written to `$PQZ_FUZZ_HONEST` by `seeds.py`); the core never proves.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

use pqz_ffi::stmt::{self, Form};
use pqz_ffi::*;

/// The verify-only arena's bound: 1.5 × margin below `ARENA_SMALL`.
pub const ARENA_BOUND: usize = pqzl::ARENA_SMALL / 3 * 2;

struct Honest {
    form: Form,
    pqzl: bool,
    stmt: Vec<u8>,
    proof: Vec<u8>,
    input: Vec<u8>,
}

static HONEST: OnceLock<Vec<Honest>> = OnceLock::new();
static SELFTEST: OnceLock<Word> = OnceLock::new();
static TARGET: OnceLock<String> = OnceLock::new();
static PEAK: AtomicUsize = AtomicUsize::new(0);
static INPUTS: AtomicU64 = AtomicU64::new(0);
static DECODED: AtomicU64 = AtomicU64::new(0);
static VALIDS: AtomicU64 = AtomicU64::new(0);
static DIFFS: AtomicU64 = AtomicU64::new(0);
static CANON: AtomicU64 = AtomicU64::new(0);
static PQZL_INPUTS: AtomicU64 = AtomicU64::new(0);

fn die(msg: &str) -> ! {
    eprintln!("pqz-fuzz FINDING ({}): {msg}", TARGET.get().map_or("?", |s| s.as_str()));
    std::process::abort()
}

fn honest() -> &'static [Honest] {
    HONEST.get().unwrap_or_else(|| die("not initialised"))
}

fn record(input: Vec<u8>) -> Honest {
    let i = decode(&input).unwrap_or_else(|e| die(&format!("cached honest input does not decode: {e:?}")));
    let (form, pqzl) = (i.stmt.form().unwrap(), *i.stmt.proof_system_id().unwrap() == PQZL_ID);
    let (stmt, proof) = (i.stmt_bytes.to_vec(), i.proof.to_vec());
    Honest { form, pqzl, stmt, proof, input }
}

/// The honest inputs from `seeds.py`'s file (`be32(len) ‖ input` records, built from the frozen vectors): PQZL's 8
/// forms in `FORMS` order, PQZH's 8, then the fee-0 rows of both ids.
fn load(path: &str) -> Vec<Honest> {
    let mut b = &std::fs::read(path).unwrap_or_else(|e| die(&format!("{path}: {e} (run seeds.py)")))[..];
    let mut v = Vec::new();
    while b.len() >= 4 {
        let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        v.push(record(b[4..4 + n].to_vec()));
        b = &b[4 + n..];
    }
    let order = v.len() >= 16 && v.iter().take(16).enumerate().all(|(i, h)| h.pqzl == (i < 8) && h.form == stmt::FORMS[i % 8]);
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

fn arena_check() {
    let p = pqzl::arena_peak();
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
    if decode(inp).is_ok() {
        DECODED.fetch_add(1, Relaxed);
    }
    VALIDS.fetch_add((a.1 == VALID) as u64, Relaxed);
    arena_check();
    a.1 == VALID
}

extern "C" fn summary() {
    eprintln!(
        "pqz-fuzz summary ({}): {} inputs checked, {} decoded, {} valid (= unmodified honest; mutate skips those), {} differential SV = generic, \
         {} PQZL proof re-encodings equal, arena peak max {} B = {:.2} MiB (bound {} MiB, ARENA_SMALL {} MiB)",
        TARGET.get().map_or("?", |s| s.as_str()),
        INPUTS.load(Relaxed),
        DECODED.load(Relaxed),
        VALIDS.load(Relaxed),
        DIFFS.load(Relaxed),
        CANON.load(Relaxed),
        PEAK.load(Relaxed),
        PEAK.load(Relaxed) as f64 / (1 << 20) as f64,
        ARENA_BOUND >> 20,
        pqzl::ARENA_SMALL >> 20
    );
}

extern "C" {
    fn atexit(f: extern "C" fn()) -> i32;
}

/// `LLVMFuzzerInitialize`: the panic hook, the honest inputs, the verify-only core, a warm-up pass (every honest input
/// valid, the self-test).
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
    if !pqzl::reinit(pqzl::ARENA_SMALL) {
        die("reinit on the verify-only arena");
    }
    let st = call(&[6, 0, 0, 0, 0]);
    if st.0 != PQZ_FFI_OK {
        die("self-test status");
    }
    SELFTEST.set(st.1).ok();
    for h in honest() {
        if call(&h.input) != (PQZ_FFI_OK, VALID) {
            die(&format!("honest {:?} (PQZL {}) not valid", h.form, h.pqzl));
        }
    }
    arena_check();
    eprintln!(
        "pqz-fuzz init ({target}): {} honest inputs valid, self-test {}, verify-only arena {} MiB, arena used {} B, peak {} B",
        honest().len(),
        hex(&st.1),
        pqzl::ARENA_SMALL >> 20,
        pqzl::arena_used(),
        pqzl::arena_peak()
    );
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

/// The `pqz_test_mutate` relation code of a form (pqz_int.h: the op, `R_TX0` = 0x81).
fn rel(f: Form) -> u8 {
    if f == Form::Transfer0 { 0x81 } else { f.op() }
}

/// differential sampling: the generic verifier on every `DIFF_EVERY`-th mutated PQZL input that decodes (it needs the big arena
/// and a re-initialisation back to the verify-only one, ≈ 100× a fast verify)
const DIFF_EVERY: u64 = 256;

/// `mutate` target. Input: byte 0 = the honest input (mod their number: PQZL forms 0..7, PQZH 8..15 in
/// `pqz_stmt::FORMS` order, then the fee-0 rows);
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
            match pqzl::test_mutate(rel(h.form), &h.proof, kind, r1, r2) {
                Ok(Some(p)) => inp = stmt::input(h.form.op(), &h.stmt, &p),
                Ok(None) => die("the honest proof does not decode in pqz_test_mutate"),
                Err(_) => die("node fault in pqz_test_mutate"),
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
                if !pqzl::reinit(pqzl::ARENA_SMALL) {
                    die("reinit on the verify-only arena");
                }
            }
        }
    }
}

/// `codec` target (D15: every decoder accepts exactly one encoding; accepted ⇒ re-encoding is the input). Input: byte
/// 0 % 5 = codec, byte 1 = the honest input (bits 0..3) and an op override (bit 4: op = bits 5..7, 0..7), then the
/// edit script over the codec's bytes:
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
    let h = &honest()[sel as usize % 16];
    let op = if sel & 0x10 != 0 { sel >> 5 } else { h.form.op() };
    INPUTS.fetch_add(1, Relaxed);
    let tr = &honest()[(sel & 1) as usize]; // PQZL Transfer / Transfer0: the bundle's u, v_t, [v_a]
    let bundle = || {
        let Ok(stmt::Stmt::Debit(t)) = stmt::parse(tr.form.op(), &tr.stmt) else { die("honest transfer") };
        let b = stmt::Bundle { salt: [0xA5; 16], u: t.u, v_t: t.v_t.unwrap(), v_a: t.v_a, to_ua: [0x22; 32] };
        b.encode().unwrap()
    };
    let mut b = match codec {
        0 => h.stmt.clone(),
        1 => h.input.clone(),
        2 => bundle(),
        3 => stmt::opening(&bundle(), &h.proof),
        _ => honest()[sel as usize % 8].proof.clone(),
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
                let shape = match s.form() {
                    Some(f) => f.op() == op && f.stmt_len() == b.len(),
                    None => op == 6 && b.is_empty(),
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
            let h = &honest()[sel as usize % 8];
            let r = pqzl::test_mutate(rel(h.form), &b, 99, 0, 0).unwrap_or_else(|_| die("node fault in pqz_test_mutate"));
            let r2 = pqzl::test_mutate(rel(h.form), &b, 99, 0, 0).unwrap_or_else(|_| die("node fault in pqz_test_mutate"));
            if r != r2 {
                die("PQZL proof decoder not deterministic");
            }
            if let Some(e) = &r {
                if *e != b {
                    die(&format!("PQZL proof {:?}: decoded {} B, re-encoded {} B differ (non-canonical encoding accepted)", h.form, b.len(), e.len()));
                }
                CANON.fetch_add(1, Relaxed);
            }
            r.is_some()
        }
    };
    if ok {
        DECODED.fetch_add(1, Relaxed);
    }
    arena_check();
}
