// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T10: memory protection of the arena (spec §8.2, C-09). With feature `mlock` each arena chunk is locked in RAM
//! (`mlock`) and, on Linux and Android, kept out of core dumps (`MADV_DONTDUMP`) from its allocation to its release; on Linux
//! `/proc/self/smaps` shows the flags `lo` and `dd` on the pages of a derived key's slot, and neither after `lock()` released
//! them. Best effort: a refused `mlock` is reported by `Wallet::memory_protection()` and never fails the wallet. Without the
//! feature (and on wasm32) nothing is locked and the report says so. The tests share the process's `RLIMIT_MEMLOCK`, so they
//! run one at a time. UNAUDITED.
use scaas_ua::wallet::{MemoryProtection, Wallet};
use scaas_ua::{purpose_tag, ua_message};
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Whether this build locks and marks the chunks.
const PROTECTS: bool = cfg!(all(feature = "mlock", any(target_os = "linux", target_os = "android")));

fn signs(w: &Wallet) -> bool {
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    let (p, d) = (purpose_tag("metatx").unwrap(), [7u8; 32]);
    let m = ua_message(0x0108, &p, &d).unwrap();
    key.sign_ua(&p, &d).is_ok_and(|s| scaas_ua::verify::verify(0x0108, &key.key_data(), &m, &s, false))
}

#[test]
fn memory_protection_reports_the_arena() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    assert!(signs(&w));
    let mp = w.memory_protection();
    assert!(mp.chunks >= 1, "{mp:?}");
    if PROTECTS {
        assert_eq!((mp.locked, mp.no_dump), (mp.chunks, mp.chunks), "{mp:?}");
    } else {
        assert_eq!((mp.locked, mp.no_dump), (0, 0), "{mp:?}");
    }
    w.lock();
    assert_eq!(w.memory_protection(), MemoryProtection::default());
}

/// The flags of the mapping holding `addr` (`/proc/self/smaps` `VmFlags`), `None` if no mapping holds it.
#[cfg(all(target_os = "linux", feature = "mlock", feature = "vectors"))]
fn vm_flags(addr: usize) -> Option<Vec<String>> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut inside = false;
    for line in smaps.lines() {
        let range = line.split_once(' ').and_then(|(r, _)| r.split_once('-'));
        if let Some((Ok(a), Ok(b))) = range.map(|(a, b)| (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16))) {
            inside = (a..b).contains(&addr);
        } else if let Some(f) = line.strip_prefix("VmFlags:").filter(|_| inside) {
            return Some(f.split_whitespace().map(str::to_owned).collect());
        }
    }
    None
}

#[cfg(all(target_os = "linux", feature = "mlock", feature = "vectors"))]
#[test]
fn arena_chunks_locked_and_no_dump() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    assert!(key.vectors_secret_in_arena().unwrap(), "the slot lies in a chunk");
    let slot = key.vectors_with_secret(|s| s.as_ptr() as usize).unwrap();
    let flags = vm_flags(slot).unwrap();
    assert!(flags.iter().any(|f| f == "lo") && flags.iter().any(|f| f == "dd"), "slot {slot:#x}: {flags:?}");
    // the handle itself is not where the bytes are (and is not what is locked)
    let own = &key as *const _ as usize;
    assert!(vm_flags(own).is_some_and(|f| !f.iter().any(|x| x == "lo")), "the handle's own page is not locked");
    w.lock();
    // released: wiped, then unmarked and unlocked (the page may be gone or reused unlocked; never left locked)
    let after = vm_flags(slot).unwrap_or_default();
    assert!(!after.iter().any(|f| f == "lo" || f == "dd"), "slot {slot:#x} after lock(): {after:?}");
}

/// A refused `mlock` (`RLIMIT_MEMLOCK` 0) is reported and never fails the wallet. Skipped where the limit does not bind
/// (`CAP_IPC_LOCK`).
#[cfg(all(target_os = "linux", feature = "mlock"))]
#[test]
fn mlock_refused_never_fails_the_wallet() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut old = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: plain syscalls on a local struct
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut old) }, 0);
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: old.rlim_max };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) }, 0);
    // whether the limit binds here, by a probe of its own (a page of this test, not the wallet's)
    let mut probe = vec![0u8; 1 << 16];
    let page = (probe.as_mut_ptr() as usize + 4095) & !4095;
    let binds = unsafe { libc::mlock(page as *const libc::c_void, 4096) } != 0;
    if !binds {
        unsafe { libc::munlock(page as *const libc::c_void, 4096) };
    }
    let w = Wallet::from_mnemonic(WORDS, "");
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &old) }, 0);
    let w = w.unwrap();
    assert!(signs(&w), "the wallet works without the lock");
    let mp = w.memory_protection();
    assert!(mp.chunks >= 1);
    if binds {
        assert_eq!(mp.locked, 0, "a refused mlock is reported: {mp:?}");
        assert_eq!(mp.no_dump, mp.chunks, "no-dump does not depend on the lock: {mp:?}");
    } else {
        eprintln!("RLIMIT_MEMLOCK does not bind here (CAP_IPC_LOCK): the refusal is not exercised");
    }
    drop(probe);
}
