//! Cross-check against the C core's statements and pqz_kat.py (xcheck.sh writes the inputs; P6e Task 5).
//! PQZ_STMT_XCHECK=<dir>: <dir>/c/{reg,tx,burn,ds,dr,tx0}_stmt.bin (pqz_bench.c setup()) and <dir>/py.txt
//! (xcheck.py). Without the variable the test only says so.
use pqz_stmt::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn form_of(name: &str) -> Form {
    match name {
        "TRANSFER" => Form::Transfer,
        "TRANSFER0" => Form::Transfer0,
        "BURN" => Form::Burn,
        "REFRESH" => Form::Refresh,
        "REGISTER" => Form::Register,
        "DISCLOSE-SENDER" => Form::DiscloseSender,
        "DISCLOSE-RECEIVER" => Form::DiscloseReceiver,
        "DISCLOSE-AUDITOR" => Form::DiscloseAuditor,
        _ => panic!("form {name}"),
    }
}

/// pqz_kat.py's reason strings
fn reason(r: Reject) -> String {
    String::from(match r {
        Reject::MustBeZero(f) => return format!("{f}_must_be_0"),
        Reject::OpTag | Reject::Op => "opTag_does_not_belong_to_op",
        Reject::ProofSystemId => "unknown_proofSystemId",
        Reject::Length => "length",
        Reject::Fee => "fee_>=_2^64",
        Reject::Amount => "amount_>=_2^64",
        Reject::Salt => "salt_word_not_16_zero_bytes_||_salt",
        Reject::AuditorOn => "auditorOn_does_not_match_the_length",
        Reject::Coefficient => "coefficient_>=_q",
        Reject::Legs => "M_not_a_built_leg_count",
        Reject::Kind => "kind",
        _ => "other",
    })
}

fn words<const N: usize>(b: &[u8]) -> [Word; N] {
    let mut w = [[0u8; 32]; N];
    for (i, x) in w.iter_mut().enumerate() {
        x.copy_from_slice(&b[32 * i..32 * i + 32]);
    }
    w
}

/// The statement pqz-stmt builds from pqz_kat.py's fields
fn build(form: Form, f: &std::collections::HashMap<&str, Vec<u8>>) -> Vec<u8> {
    let g = |k: &str| f.get(k).map(|v| v.as_slice());
    let s = match form {
        Form::Register => Stmt::Register(Register { words: words::<3>(&f["words"]), pk: &f["pk"] }),
        Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor => Stmt::Disclose(Disclose {
            form,
            words: words::<DISC_WORDS>(&f["words"]),
            pk: &f["pk"],
            u: &f["u"],
            v: &f["v"],
        }),
        _ => Stmt::Debit(Debit {
            form,
            header: words::<20>(&f["hdr"]),
            pk_f: &f["pk_f"],
            pk_t: g("pk_t"),
            pk_a: g("pk_a"),
            t: &f["t"],
            u: &f["u"],
            v_t: g("v_t"),
            v_f: &f["v_f"],
            v_a: g("v_a"),
        }),
    };
    s.encode().unwrap()
}

/// Op 7: the statement pqz-stmt builds from pqz_kat.py's fields, and the fields it parses out
fn build_multi(f: &std::collections::HashMap<&str, Vec<u8>>) -> Vec<u8> {
    let header = words::<20>(&f["hdr"]);
    let m = word_u64(&header[H_LEGS]).unwrap() as usize;
    let g = |k: &str| f.get(k).map(|v| v.as_slice());
    let s = Multi {
        header,
        m,
        pk_f: &f["pk_f"],
        pks: &f["pks"],
        pk_a: g("pk_a"),
        t: &f["t"],
        us: &f["us"],
        vs: &f["vs"],
        v_f: &f["v_f"],
        v_as: g("v_as"),
    };
    s.encode().unwrap()
}

fn fields_multi(s: &Multi) -> Vec<(&'static str, Vec<u8>)> {
    let mut v = vec![("hdr", s.header.concat()), ("pk_f", s.pk_f.to_vec()), ("pks", s.pks.to_vec())];
    if let Some(a) = s.pk_a {
        v.push(("pk_a", a.to_vec()));
    }
    v.extend([("t", s.t.to_vec()), ("us", s.us.to_vec()), ("vs", s.vs.to_vec()), ("v_f", s.v_f.to_vec())]);
    if let Some(a) = s.v_as {
        v.push(("v_as", a.to_vec()));
    }
    v
}

/// The fields pqz-stmt parses out, by pqz_kat.py's names
fn fields(s: &Stmt) -> Vec<(&'static str, Vec<u8>)> {
    match s {
        Stmt::Register(r) => vec![("words", r.words.concat()), ("pk", r.pk.to_vec())],
        Stmt::Disclose(d) => {
            vec![("words", d.words.concat()), ("pk", d.pk.to_vec()), ("u", d.u.to_vec()), ("v", d.v.to_vec())]
        }
        Stmt::Debit(d) => {
            let mut v = vec![("hdr", d.header.concat()), ("pk_f", d.pk_f.to_vec())];
            for (k, o) in [("pk_t", d.pk_t), ("pk_a", d.pk_a)] {
                if let Some(o) = o {
                    v.push((k, o.to_vec()));
                }
            }
            v.push(("t", d.t.to_vec()));
            v.push(("u", d.u.to_vec()));
            for (k, o) in [("v_t", d.v_t), ("v_f", Some(d.v_f)), ("v_a", d.v_a)] {
                if let Some(o) = o {
                    v.push((k, o.to_vec()));
                }
            }
            v
        }
        Stmt::Multi(_) | Stmt::SelfTest => vec![],
    }
}

#[test]
fn xcheck_c_and_pqz_kat() {
    let Ok(dir) = std::env::var("PQZ_STMT_XCHECK") else {
        eprintln!("PQZ_STMT_XCHECK not set: cross-check skipped (xcheck.sh sets it)");
        return;
    };
    // 1. the C core's statements (bench setup, as `dump_setup DIR pqzh` writes them: opTag, PQZH id)
    let mut nc = 0;
    for (name, form) in [
        ("reg", Form::Register),
        ("tx", Form::Transfer),
        ("burn", Form::Burn),
        ("ds", Form::DiscloseSender),
        ("dr", Form::DiscloseReceiver),
        ("tx0", Form::Transfer0),
    ] {
        let st = std::fs::read(format!("{dir}/c/{name}_stmt.bin")).unwrap();
        assert_eq!(st.len(), form.stmt_len(), "{name}");
        let s = parse(form.op(), &st).unwrap_or_else(|e| panic!("C {name}: {e:?}"));
        assert_eq!(s.form(), Some(form), "C {name}");
        assert_eq!(s.proof_system_id(), Some(&PQZH_ID), "C {name}"); // dump_setup pqzh: real opTag, D3 id
        assert_eq!(s.encode().unwrap(), st, "C {name}: encode(parse(x)) != x");
        // built from the objects (fields) again: the same bytes
        let f: std::collections::HashMap<&str, Vec<u8>> = fields(&s).into_iter().collect();
        assert_eq!(build(form, &f), st, "C {name}: build from fields");
        nc += 1;
    }
    // 2. pqz_kat.py's statements and rejections
    let py = std::fs::read_to_string(format!("{dir}/py.txt")).unwrap();
    let (mut nok, mut nbad, mut npyc, mut nmulti, mut nbad7) = (0, 0, 0, 0, 0);
    for line in py.lines() {
        let t: Vec<&str> = line.split(' ').collect();
        match t[0] {
            "c" => npyc += 1,
            "ok" if t[1] == "7" => {
                let st = unhex(t[3]);
                let f: std::collections::HashMap<&str, Vec<u8>> =
                    t[4..].iter().map(|kv| kv.split_once('=').unwrap()).map(|(k, v)| (k, unhex(v))).collect();
                let s = parse_multi(&st).unwrap_or_else(|e| panic!("op 7: {e:?}"));
                let got = fields_multi(&s);
                assert_eq!(got.len(), f.len(), "op 7 M = {}: field count", s.m);
                for (k, v) in &got {
                    assert_eq!(&f[k], v, "op 7 M = {}: field {k}", s.m);
                }
                assert_eq!(build_multi(&f), st, "op 7: build from pqz_kat.py's fields");
                assert_eq!(s.encode().unwrap(), st);
                nmulti += 1;
            }
            "ok" => {
                let (op, form, st) = (t[1].parse::<u8>().unwrap(), form_of(t[2]), unhex(t[3]));
                let f: std::collections::HashMap<&str, Vec<u8>> =
                    t[4..].iter().map(|kv| kv.split_once('=').unwrap()).map(|(k, v)| (k, unhex(v))).collect();
                let s = parse(op, &st).unwrap_or_else(|e| panic!("{}: {e:?}", t[2]));
                assert_eq!(s.form(), Some(form));
                let got = fields(&s);
                assert_eq!(got.len(), f.len(), "{}: field count", t[2]);
                for (k, v) in &got {
                    assert_eq!(&f[k], v, "{}: field {k}", t[2]);
                }
                assert_eq!(build(form, &f), st, "{}: build from pqz_kat.py's fields", t[2]);
                assert_eq!(s.encode().unwrap(), st);
                nok += 1;
            }
            "bad" => {
                let (op, want, st) = (t[1].parse::<u8>().unwrap(), t[2], unhex(t[3]));
                let got = if op == OP_TRANSFER_MULTI { parse_multi(&st).err() } else { parse(op, &st).err() };
                let got = got.unwrap_or_else(|| panic!("accepted, pqz_kat.py: {want}"));
                nbad7 += (op == OP_TRANSFER_MULTI) as usize;
                assert_eq!(reason(got), want, "{got:?}");
                nbad += 1;
            }
            _ => panic!("line {line:.40}"),
        }
    }
    assert_eq!(npyc, 6, "pqz_kat.py rebuilt the six C statements");
    assert!(nok >= 8 && nbad >= 8);
    assert!(nmulti >= 14 && nbad7 >= 50, "op 7: {nmulti} statements, {nbad7} rejections");
    println!("xcheck: C {nc} / 6 forms equal; pqz_kat.py: {nok} statements + {nmulti} op 7 statements equal (fields and bytes), {nbad} rejections ({nbad7} op 7) with the same reason");
}
