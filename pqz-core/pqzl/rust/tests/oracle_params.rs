//! The generated parameters (src/params, plan D8) against the C core's headers (feature `c-oracle`): every field of
//! every relation's `lnp_tbox_params_t` (rings and moduli, `_Bsq`, kmsis, m1 / m2, the dcompress, ABDLOP, quad and
//! tbox fields), read through the C compiler, equals the Rust constants; the relation lists have the same length.
use pqzl::c_oracle::c_params;
use pqzl::testkit::params_words;

#[test]
fn constants_eq_c() {
    let rels = params_words();
    assert_eq!(rels.len(), if cfg!(feature = "oversize") { 14 } else { 12 });
    for (i, (name, w)) in rels.iter().enumerate() {
        assert_eq!(c_params(i as u32).as_ref(), Some(w), "{name}");
    }
    assert_eq!(c_params(rels.len() as u32), None, "C has more relations");
}
