# Security Review Report: Unit R3 — PQZH Ligero (Code)

**Repository:** SCaaS core (`pqz-core/` at frozen commit `008e196c`)  
**Review Unit:** R3 — PQZH Ligero (code)  
**Scope:**
- `pqzh/ligero/src/{fq,fft,ligero,cs,client,merkle,ring,ct,set}.rs`
- `params/sets/*/pqzh_set*.rs`

**Review Mode:** Strictly read-only static code inspection. No build, test execution, compilation, benchmarking, or file modifications were performed.

---

## Findings

No P0, P1, or P2 vulnerabilities were identified in the production paths of the audited unit. One minor finding (P3) affects the optional, non-production fallback build configuration.

### [R3-1] Severity P3 — Fallback preset reuses incompatible production proof-system ID
- **File & Lines:**
  - [`pqzh/ligero/src/set.rs:15–25`](pqz-core/pqzh/ligero/src/set.rs#L15-L25)
  - [`params/sets/n2304-kmax4096/pqzh_set_fallback.rs:19–23`](pqz-core/params/sets/n2304-kmax4096/pqzh_set_fallback.rs#L19-L23)
  - [`params/sets/n2304-kmax4096/rust/set.rs:63–66`](pqz-core/params/sets/n2304-kmax4096/rust/set.rs#L63-L66)
  - [`pqzh/ligero/src/cs.rs:352–359, 938–945`](pqz-core/pqzh/ligero/src/cs.rs#L352-L359)
- **Claim:** Enabling features `set-n2304-kmax4096,fallback-retry` switches the Ligero proof system to fallback parameters ($n=32,756, k=817, t=121$) while retaining the production Preset B identifier (`PQZH_LABEL` / `PQZH_ID` corresponding to $n=45,752, k=952, t=120$).
- **Evidence:**
  In [`set.rs:15–25`](pqz-core/pqzh/ligero/src/set.rs#L15-L25):
  ```rust
  #[cfg(feature = "set-n2304-kmax4096")]
  #[path = "../../../params/sets/n2304-kmax4096/rust/set.rs"]
  mod lattice;
  ...
  #[cfg(all(feature = "set-n2304-kmax4096", not(feature = "fallback-retry")))]
  #[path = "../../../params/sets/n2304-kmax4096/pqzh_set.rs"]
  mod pqzh;
  #[cfg(all(feature = "set-n2304-kmax4096", feature = "fallback-retry"))]
  #[path = "../../../params/sets/n2304-kmax4096/pqzh_set_fallback.rs"]
  mod pqzh;
  ```
  `lattice` is unconditionally loaded from `n2304-kmax4096/rust/set.rs`, which defines:
  ```rust
  pub(crate) const PQZH_LABEL: &str = "scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v2";
  pub(crate) const PQZH_ID: [u8; 32] = [0xe4, 0xbc, 0x6d, 0x17, ...];
  ```
  Meanwhile, `pqzh_set_fallback.rs` defines:
  ```rust
  pub(crate) const PRESET_N: usize = 32_756;
  pub(crate) const PRESET_K: usize = 817;
  pub(crate) const PRESET_T: usize = 121;
  ```
  When `cs::parse` validates incoming statements ([`cs.rs:357`](pqz-core/pqzh/ligero/src/cs.rs#L357)):
  ```rust
  if *s.proof_system_id()? != PQZH_ID {
      return None;
  }
  ```
  it requires matching `PQZH_ID`. Under `fallback-retry`, the prover generates proofs using parameters $n=32,756, k=817, t=121$ (with test polynomials of degree $2k-1 = 1633$ and Merkle depth 15), but marks them with the production Preset B ID which expects $n=45,752, k=952, t=120$ (degree 1903, Merkle depth 16).
  This also causes the internal consistency test in [`cs.rs:938–945`](pqz-core/pqzh/ligero/src/cs.rs#L938-L945) to fail under `fallback-retry`:
  ```rust
  let p = crate::ligero::Params::proven();
  let want = format!("/ligero-fq{}-n{}k{}t{}-keccak256-zk-proven/", pqz_stmt::LOG2Q, p.n, p.k, p.t);
  assert!(PQZH_LABEL.contains(&want), "{PQZH_LABEL} vs {want}");
  ```
  Because `fallback-retry` is an experimental fallback mechanism documented in `docs/research/pqzh-set-a-proof-limit.md` and excluded from production builds (which use production Preset B), this does not cause a live production consensus split.
- **Suggested Fix:** Assign a distinct experimental proof system label and ID for the fallback preset (e.g. `scaas/pqz/pqzh/ligero-fq46-n32756k817t121-keccak256-zk-proven/v2-fallback`) and wire `set.rs` to import the corresponding identifier when `fallback-retry` is active, or remove the dead `fallback-retry` feature flag if no longer needed.

---

## Checked and Sound

All required invariants were verified across the codebase:

| Invariant | Status | Evidence |
|---|---|---|
| **Field arithmetic correct at every PQZH $q$ (native u128 and wasm32 limb split)** | **Sound** | [`fq.rs:49–73, 126–192, 203–208`](pqz-core/pqzh/ligero/src/fq.rs#L49-L73): Barrett reduction `redx` operates on bounds $X = 2L+4 \le 104$ where $((x \gg (L-1)) \times \text{MUX}) \le 2^{110} < 2^{128}$ fits in `u128` without overflow; $(1+3\text{NR})q^2 = 10q^2 < 2^X$ bounds $F_q^4$ products; `Fq::from_i64` handles `i64::MIN` via unsigned magnitude; on wasm32, 2 limbs ($W=21$) for $L \le 42$ and 3 limbs ($W=16$ or $17$) for $L > 42$ satisfy all accumulator and carry normalization limits. |
| **FFT domains (radices 2 / 7 / 17 / 19 / 43 / 431) & $\text{GEN} \cdot H_n \cap H_k = \emptyset$** | **Sound** | [`fft.rs:47–65, 109–170, 213–219`](pqz-core/pqzh/ligero/src/fft.rs#L47-L65): all radices divide $q-1$; twiddle factors $\omega = \text{GEN}^{(q-1)/n}$ are primitive roots; lazy sums accumulate at most 431 products $< 2^{109} < 2^{128}$ in `u128`; because $\text{lcm}(n, k)$ properly divides $q-1$ and $\text{GEN}=3$ is primitive, $\text{GEN}^{\text{lcm}(n, k)} \not\equiv 1 \pmod q$, guaranteeing $\text{GEN} \cdot H_n \cap H_k = \emptyset$ and non-zero Lagrange denominators $\eta - \omega_k^c \neq 0$. |
| **Verifier's checks complete (degree, linear, quadratic, Merkle)** | **Sound** | [`ligero.rs:533–540, 571–575, 598–644`](pqz-core/pqzh/ligero/src/ligero.rs#L533-L540): coefficient counts ($2k-1, 2k-1, 2k-1-\ell$) bound test polynomial degrees; linear check enforces sum $(q_0 + q_k)k = \text{comb.rhs}$ over $H_k$ and Lagrange evaluations at $\eta$ with distinct weights $\rho^{e_c}$ ($e_c \ge 1$); quadratic check $he \cdot Z_{\zeta}(\eta) == qa + bq$ validates all big and small multiplication and boolean triples; Merkle check verifies unsalted column leaves ($32 + w \times \text{EB}$ bytes $\neq 64$) against root and rejects trailing bytes. |
| **Soundness bits per preset $t$** | **Sound** | [`ligero.rs:65–72, 714–736`](pqz-core/pqzh/ligero/src/ligero.rs#L65-L72): classical ROM soundness accounting across all five error terms yields $\ge 127.23$ bits across all sets (`n2048-kmax1024` at $t=121 \implies 127.23$ bits; `n2304-kmax4096` at $t=120 \implies 127.40$ bits; `n2560-kmax16384` at $t=122 \implies 127.55$ bits). |
| **Native = wasm32** | **Sound** | [`fq.rs:257–267, 347–364, 366–401, 476–513`](pqz-core/pqzh/ligero/src/fq.rs#L257-L267): `mul`, `f4_mul`, and `Acc4` map to `limb::*` on wasm32 and `u128` Barrett on native with bit-identical outputs verified by `limb_matches_u128`; transcript sampling, Merkle paths, and verifier equations are completely shared across targets. |
| **Prover's constant-time paths (review O) still hold** | **Sound** | [`fft.rs:135–154`](pqz-core/pqzh/ligero/src/fft.rs#L135-L154) sparse FFT shortcut depends strictly on public structural padding (`len.div_ceil(stride)`), and `ifft` is always dense; [`ring.rs:73–87`](pqz-core/pqzh/ligero/src/ring.rs#L73-L87) `dot_int` has no zero-skipping branch and uses split negacyclic loops; [`ring.rs:91–94`](pqz-core/pqzh/ligero/src/ring.rs#L91-L94) centering uses `Fq::from_i64` and `ct::mask`; [`cs.rs:467–477`](pqz-core/pqzh/ligero/src/cs.rs#L467-L477) `round_delta` uses constant 64-step restoring division `ct_udiv`; [`cs.rs:445–582`](pqz-core/pqzh/ligero/src/cs.rs#L445-L582) witness checks accumulate 0/1 words into single verdicts; all secret buffers are cleared on drop via `Wiped<T: Wipe>` ([`lib.rs:46–89`](pqz-core/pqzh/ligero/src/lib.rs#L46-L89)). |

---

## Not Covered

The following items were outside the scope of Unit R3:
1. The PQZL lattice proof system (C and Rust implementations under `pqz-core/pqzl/`).
2. Full `pqz-stmt` decoder implementation beyond the statement types and interface functions consumed by Ligero.
3. The C ABI precompile bindings (`pqz-ffi`), Nethermind plugin, and EVM integration contracts.
4. Internal cryptographic primitives of external crates (`sha3` Keccak-f permutation).
5. Compiler-lowered machine code (x86-64 backend instruction selection, browser JIT tiers, and wasm runtime lowering of `select` and `__multi3`).
