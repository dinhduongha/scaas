// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// serde_json differential (CLI-UAL-67): the same inputs through two releases; run.sh builds it against each and compares.
use serde_json::{json, Value};
use std::io::Write;
fn main() {
    let mut s: u64 = 0x9E3779B97F4A7C15;
    let mut r = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    let out = std::io::stdout();
    let mut o = std::io::BufWriter::new(out.lock());
    let specials = [0.0f64, -0.0, 1.0, 0.1, 1e15, 1e16, 1e17, 1e20, 1e21, 1e22, 1e-5, 1e-6, 1e-7, 5e-324, f64::MAX, f64::MIN,
        f64::MIN_POSITIVE, f64::EPSILON, 123456789012345680000.0, 9007199254740993.0, 2.5, -1.5e300, f64::NAN, f64::INFINITY];
    for x in specials { writeln!(o, "{} {}", serde_json::to_string(&x).unwrap(), serde_json::to_string(&(x as f32)).unwrap()).unwrap(); }
    for _ in 0..2_000_000 {
        let b = r();
        let f = f64::from_bits(b); let g = f32::from_bits(b as u32);
        writeln!(o, "{} {}", serde_json::to_string(&f).unwrap(), serde_json::to_string(&g).unwrap()).unwrap();
        // parse: a decimal string with up to 20 digits and an exponent, and the shortest form back
        let txt = format!("{}.{}e{}", r() % 1000, r(), (r() % 700) as i64 - 350);
        let p = serde_json::from_str::<f64>(&txt).map(f64::to_bits).map_err(|e| e.to_string());
        let v = serde_json::from_str::<Value>(&format!("[{txt},{},{},-{}]", r(), r() as i64, r() >> 1)).map(|v| v.to_string()).map_err(|e| e.to_string());
        writeln!(o, "{p:?} {v:?}").unwrap();
    }
    for i in [0u64, 1, u64::MAX] { writeln!(o, "{} {} {}", json!(i), json!(i as i64), serde_json::to_string(&(i as u128 * 3)).unwrap()).unwrap(); }
    writeln!(o, "{}", serde_json::to_string(&(i128::MIN, u128::MAX)).unwrap()).unwrap();
    // strings: every scalar below 0x800, the surrogate edges, random scalars; escapes both ways
    for c in (0u32..0x800).chain([0xD7FF, 0xE000, 0xFFFD, 0xFFFF, 0x10000, 0x10FFFF]) {
        let ch = char::from_u32(c).unwrap(); let st = format!("a{ch}\"\\/{ch}");
        let e = serde_json::to_string(&st).unwrap(); let back: String = serde_json::from_str(&e).unwrap(); assert_eq!(back, st);
        writeln!(o, "{e}").unwrap();
    }
    for _ in 0..100_000 { let st: String = (0..8).filter_map(|_| char::from_u32((r() % 0x110000) as u32)).collect(); writeln!(o, "{}", serde_json::to_string(&st).unwrap()).unwrap(); }
    let mut m = serde_json::Map::new();
    for k in ["zeta", "alpha", "Mid", "0", "\u{1F600}", "a\u{0}b", ""] { m.insert(k.into(), json!({"n": 1.5, "s": "x\ty", "a": [null, true, false, {}, []], "k": k})); }
    let v = Value::Object(m);
    writeln!(o, "{}\n{}\n{}", v, serde_json::to_string_pretty(&v).unwrap(), String::from_utf8(serde_json::to_vec(&v).unwrap()).unwrap()).unwrap();
    let rt: Value = serde_json::from_str(&serde_json::to_string_pretty(&v).unwrap()).unwrap(); writeln!(o, "{rt}").unwrap();
    writeln!(o, "{:?}", serde_json::from_str::<Value>("[1e400]").map_err(|e| e.to_string())).unwrap();
    writeln!(o, "{:?}", serde_json::from_str::<Value>(&"[".repeat(200)).map_err(|e| e.to_string())).unwrap();
}
