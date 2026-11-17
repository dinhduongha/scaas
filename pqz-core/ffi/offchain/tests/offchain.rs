// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `verify_offchain`, the off-chain verifier's entry (three-key spec K3-4; UNAUDITED): the split transfer of
//! proof_pqzl_split.json (PQZL_SPLIT_ID, R_TXS / R_TXS0) accepted there and refused by `verify_input` / the precompile;
//! the PQZL TRANSFER accepted by both (the control of the id rows), refused by both under PQZL_SPLIT_ID; the split
//! statement under PQZL_ID / PQZH_ID refused; a tampered split proof or statement refused. Every negative changes one
//! thing against an input the test first shows accepted. cross_id_transcript_binding: a proof under one live id
//! re-labelled to the other refused, beside its control.
use pqz_ffi::stmt::{self as st, PQZL_SPLIT_ID};
use pqz_ffi::{precompile, verify_input, INVALID, PQZH_ID, PQZL_ID, VALID};
use pqz_offchain::verify_offchain;

fn dir() -> String {
    let set = if st::SET == "n2048-kmax1024" {
        String::new()
    } else {
        format!("{}/", st::SET)
    };
    format!(
        "{}/../../../smartcontracts/vectors/pqz/{set}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// the hex values of `"key": "…"` in a vector file, in file order (the files are flat rows of named fields)
fn values(file: &str, key: &str) -> Vec<Vec<u8>> {
    let t = std::fs::read_to_string(format!("{}{file}", dir()))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    let pat = format!("\"{key}\": \"");
    t.match_indices(&pat)
        .map(|(i, _)| {
            let h = &t[i + pat.len()..];
            let h = &h[..h.find('"').unwrap()];
            (0..h.len())
                .step_by(2)
                .map(|j| u8::from_str_radix(&h[j..j + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

fn with_id(s: &[u8], id: &[u8; 32]) -> Vec<u8> {
    let mut s = s.to_vec();
    s[32..64].copy_from_slice(id);
    s
}

#[test]
fn split_offchain_only() {
    let (stmts, proofs) = (
        values("proof_pqzl_split.json", "stmt"),
        values("proof_pqzl_split.json", "proof"),
    );
    assert_eq!(
        (stmts.len(), proofs.len()),
        (2, 2),
        "TRANSFER-SPLIT, TRANSFER-SPLIT0"
    );
    for (s, p) in stmts.iter().zip(&proofs) {
        assert_eq!(&s[32..64], &PQZL_SPLIT_ID);
        let inp = st::input(1, s, p);
        // positive control: the honest split input off-chain
        assert_eq!(
            verify_offchain(&inp),
            Ok(true),
            "honest split, {} B",
            s.len()
        );
        // the precompile never serves the split id
        assert_eq!(verify_input(&inp), Ok(false));
        assert_eq!(precompile(&inp), Ok(INVALID));
        // R_TXS under PQZL_ID / PQZH_ID: the decoder ties the split forms to PQZL_SPLIT_ID
        for id in [PQZL_ID, PQZH_ID, [0; 32]] {
            assert_eq!(
                verify_offchain(&st::input(1, &with_id(s, &id), p)),
                Ok(false)
            );
        }
        // tampered: a proof bit, the proof's length, u_f's low bit
        let mut q = p.clone();
        q[p.len() / 2] ^= 8;
        assert_eq!(
            verify_offchain(&st::input(1, s, &q)),
            Ok(false),
            "proof bit"
        );
        assert_eq!(
            verify_offchain(&st::input(1, s, &p[..p.len() - 1])),
            Ok(false),
            "proof truncated"
        );
        let mut t = s.clone();
        *t.last_mut().unwrap() ^= 1;
        assert_eq!(verify_offchain(&st::input(1, &t, p)), Ok(false), "u_f bit");
        // the other split form's proof
        let other = proofs.iter().find(|x| *x != p).unwrap();
        assert_eq!(
            verify_offchain(&st::input(1, s, other)),
            Ok(false),
            "other form's proof"
        );
    }
}

#[test]
fn transfer_under_split_id() {
    let s = &values("statement_transfer.json", "stmt")[0]; // TRANSFER, then TRANSFER0
    let p = &values("proof_pqzl.json", "proof")[0]; // TRANSFER
    let inp = st::input(1, &with_id(s, &PQZL_ID), p);
    // positive control: the PQZL TRANSFER through both entries
    assert_eq!(verify_input(&inp), Ok(true));
    assert_eq!(verify_offchain(&inp), Ok(true));
    assert_eq!(precompile(&inp), Ok(VALID));
    // R_TX under PQZL_SPLIT_ID: not a split form (decoder), refused by both
    let inp = st::input(1, &with_id(s, &PQZL_SPLIT_ID), p);
    assert_eq!(verify_offchain(&inp), Ok(false));
    assert_eq!(verify_input(&inp), Ok(false));
    // garbage and the self-test input are false, never a panic
    assert_eq!(verify_offchain(&[]), Ok(false));
    assert_eq!(verify_offchain(&[6, 0, 0, 0, 0]), Ok(false));
}

/// One row of a vector file by its form (the first row of that form): the JSON object.
fn row(file: &str, form: &str) -> serde_json::Value {
    let t = std::fs::read_to_string(format!("{}{file}", dir()))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    let j: serde_json::Value = serde_json::from_str(&t).unwrap();
    j["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["form"] == form && r.get("case").is_none())
        .unwrap_or_else(|| panic!("{file}: no {form}"))
        .clone()
}

fn hx(v: &serde_json::Value) -> Vec<u8> {
    let h = v.as_str().unwrap();
    (0..h.len())
        .step_by(2)
        .map(|j| u8::from_str_radix(&h[j..j + 2], 16).unwrap())
        .collect()
}

/// Cross-id test (three-key spec §14.8, K3-4; the transcript binds the proofSystemId word, statement bytes 32..63):
/// the forms both PQZL ids serve (BURN, REFRESH, DISCLOSE-SENDER) decode under either id, so a proof re-labelled to
/// the other id reaches the verifier and must fail there. PQZL_ID's proofs come from proof_pqzl.json; PQZL_SPLIT_ID's
/// are proved here from the same statement (id word aside), witness and rnd32 (the vectors hold none). Positive
/// control beside each: the proof under its own id is accepted. Then the op 1 forms, which each id serves apart: an
/// R_TX / R_TX0 proof re-labelled PQZL_SPLIT_ID and an R_TXS / R_TXS0 proof re-labelled PQZL_ID are refused by the
/// decoder (Length: the length then names the other id's form). PQZH (a set with it): its proofs under PQZL_SPLIT_ID
/// are refused (the decoder's ProofLength above PQZL's MAX_PROOF, else the PQZL verifier).
#[test]
fn cross_id_transcript_binding() {
    let files = [
        ("BURN", "statement_burn.json"),
        ("REFRESH", "statement_refresh.json"),
        ("DISCLOSE-SENDER", "statement_disclose.json"),
    ];
    let pqzh = std::path::Path::new(&format!("{}proof_pqzh.json", dir())).exists();
    let mut n = 0;
    for (form, file) in files {
        let s = hx(&row(file, form)["stmt"]);
        let pr = row("proof_pqzl.json", form);
        let (op, p) = (pr["op"].as_u64().unwrap() as u8, hx(&pr["proof"]));
        let (sl, ss) = (with_id(&s, &PQZL_ID), with_id(&s, &PQZL_SPLIT_ID));
        // positive control: the PQZL proof under PQZL_ID, both entries
        assert_eq!(
            verify_input(&st::input(op, &sl, &p)),
            Ok(true),
            "{form}: control (PQZL_ID)"
        );
        assert_eq!(
            verify_offchain(&st::input(op, &sl, &p)),
            Ok(true),
            "{form}: control off-chain (PQZL_ID)"
        );
        // re-labelled PQZL_SPLIT_ID: decodes (the split id serves the form), the verifier refuses
        let x = st::input(op, &ss, &p);
        assert!(
            pqz_ffi::decode(&x).is_ok(),
            "{form}: decodes under PQZL_SPLIT_ID"
        );
        assert_eq!(
            verify_offchain(&x),
            Ok(false),
            "{form}: PQZL proof under PQZL_SPLIT_ID"
        );
        assert_eq!(
            verify_input(&x),
            Ok(false),
            "{form}: the precompile never serves PQZL_SPLIT_ID"
        );
        // the reverse: a proof under PQZL_SPLIT_ID (control), re-labelled PQZL_ID
        let rnd: [u8; 32] = hx(&pr["rnd32"]).try_into().unwrap();
        let q = pqz_ffi::prove(op, &ss, &hx(&pr["wit"]), &rnd).expect("prove under PQZL_SPLIT_ID");
        assert_ne!(q, p, "{form}: the id is in the transcript (another proof)");
        assert_eq!(
            verify_offchain(&st::input(op, &ss, &q)),
            Ok(true),
            "{form}: control (PQZL_SPLIT_ID)"
        );
        let y = st::input(op, &sl, &q);
        assert!(pqz_ffi::decode(&y).is_ok());
        assert_eq!(
            verify_input(&y),
            Ok(false),
            "{form}: split proof under PQZL_ID (precompile)"
        );
        assert_eq!(
            verify_offchain(&y),
            Ok(false),
            "{form}: split proof under PQZL_ID (off-chain)"
        );
        if pqzh {
            let h = hx(&row("proof_pqzh.json", form)["proof"]);
            let z = st::input(op, &with_id(&s, &PQZH_ID), &h);
            assert_eq!(
                (verify_input(&z), verify_offchain(&z)),
                (Ok(true), Ok(true)),
                "{form}: control (PQZH_ID)"
            );
            // under PQZL_SPLIT_ID: the decoder refuses a PQZH proof over PQZL's MAX_PROOF (ProofLength), else the PQZL
            // verifier does
            let z = st::input(op, &ss, &h);
            let want = (h.len() > st::MAX_PROOF_PQZL).then_some(st::Reject::ProofLength);
            assert_eq!(
                pqz_ffi::decode(&z).err(),
                want,
                "{form}: PQZH proof ({} B) under PQZL_SPLIT_ID: decoder",
                h.len()
            );
            assert_eq!(
                verify_offchain(&z),
                Ok(false),
                "{form}: PQZH proof under PQZL_SPLIT_ID"
            );
        }
        n += 1;
    }
    // op 1: R_TX / R_TX0 re-labelled split, R_TXS / R_TXS0 re-labelled PQZL_ID: the decoder (Length)
    for (tx, sp) in [
        ("TRANSFER", "TRANSFER-SPLIT"),
        ("TRANSFER0", "TRANSFER-SPLIT0"),
    ] {
        let (s, p) = (
            with_id(&hx(&row("statement_transfer.json", tx)["stmt"]), &PQZL_ID),
            hx(&row("proof_pqzl.json", tx)["proof"]),
        );
        assert_eq!(
            verify_offchain(&st::input(1, &s, &p)),
            Ok(true),
            "{tx}: control"
        );
        let x = st::input(1, &with_id(&s, &PQZL_SPLIT_ID), &p);
        assert_eq!(
            pqz_ffi::decode(&x).err(),
            Some(st::Reject::Length),
            "{tx} under PQZL_SPLIT_ID: decoder"
        );
        assert_eq!(
            (verify_offchain(&x), verify_input(&x)),
            (Ok(false), Ok(false))
        );
        let r = row("proof_pqzl_split.json", sp);
        let (s, p) = (hx(&r["stmt"]), hx(&r["proof"]));
        assert_eq!(
            verify_offchain(&st::input(1, &s, &p)),
            Ok(true),
            "{sp}: control"
        );
        let y = st::input(1, &with_id(&s, &PQZL_ID), &p);
        assert_eq!(
            pqz_ffi::decode(&y).err(),
            Some(st::Reject::Length),
            "{sp} under PQZL_ID: decoder"
        );
        assert_eq!(
            (verify_offchain(&y), verify_input(&y)),
            (Ok(false), Ok(false))
        );
    }
    eprintln!("cross_id_transcript_binding ({}): {n} forms both ways{}, 4 op 1 forms re-labelled (decoder Length)", st::SET, if pqzh { " + PQZH" } else { "" });
}
