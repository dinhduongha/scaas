> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# zkLogin, Chipmunk / ChipmunkRing and the KEMs: what SCaaS should take from Sui and Cellframe

Research of 2026-11-27 for the owner, who asked (1) for a key-scheme comparison with Sui and Cellframe and (2) for a
recommendation on three items from their lists: Sui's zkLogin, Cellframe's Chipmunk and ChipmunkRing, and Kyber / NewHope for
asymmetric encryption. The comparison table itself is [networks/key-schemes.md](../networks/key-schemes.md); this note does not
repeat it. Nothing here is built, specified or ruled: every "recommendation" is a proposal for the owner. The SCaaS cryptography
named here is **UNAUDITED** ([ARCH-POS-14](../decisions.md#ARCH-POS-14)) unless the audit ledger says otherwise.

Method: the primary sources of §6, each read on 2026-11-27 (Sui docs and blog, the DAP SDK source through the GitHub API, the
ChipmunkRing and zkLogin papers, NIST IR 8309, the CFRG hybrid-KEM draft); SCaaS facts from the component docs and
`clients/ua-rs`. Claims marked *(inference)* are mine, not the source's.

## Summary

| Item | Recommendation | Main reason | Cost if adopted |
|---|---|---|---|
| zkLogin as a UA kind | **No** (now and as planned); keep what works today: a Sui zkLogin address as a native Sui sender | it needs a JWK oracle inside every family's contracts (a trusted updater the immutable, admin-free contracts do not have), a Groth16 trusted setup, and it is not post-quantum; passkeys already give the "no seed phrase" sign-in | a new kind, a Groth16-over-BN254 verifier and a JWK feed on every family, the circuit and its vectors in every client, an audit |
| Chipmunk, ChipmunkRing | **No** | a single-author preprint, no peer review, no standard; the DAP SDK itself says signer anonymity is "NOT yet claimed"; 20–280 KB signatures; SCaaS has no use for sender ring anonymity (Zether keeps the sender public by rule, [CTR-ZTH-37](../contracts/zether.md#CTR-ZTH-37)) | a non-standard lattice scheme in every family and client, a stateful key (Chipmunk), its own audit |
| Kyber / NewHope | **Nothing missing now.** SCaaS already uses ML-KEM-1024 + X25519 (FIPS 203 ML-KEM, not round-3 Kyber). **Later:** enable the reserved scheme 2 (ML-KEM-1024 + HQC + X25519) once FIPS 207 is final. **Never:** NewHope | NewHope was not selected by NIST (2020) and is never more secure than Kyber; HQC's FIPS is not yet published | scheme 2: one scheme id and length in the registry check, clients, vectors; no new registry generation (by design of [CTR-UA-32](../contracts/accounts.md#CTR-UA-32)) |

## 1. zkLogin (Sui)

### 1.1 What it is

zkLogin (Baldimtsi et al., CCS 2024 [Z1]; Sui docs [Z2, Z3]) turns an OpenID Connect login into a Sui account:

1. The app makes an **ephemeral key pair** and puts a nonce into the OAuth request:
   `nonce = Poseidon_BN254(eph_pk_hi, eph_pk_lo, max_epoch, jwt_randomness)`, truncated, base64url.
2. The OpenID provider (Google, Apple, Facebook, Twitch, … on Mainnet) returns a JWT signed with its RS256 key; the JWT carries the
   nonce, so it vouches for the ephemeral key until `max_epoch`.
3. A **salt** per user (from a salt service, a user secret, device storage or an HKDF of a master seed) feeds the address:
   `addr_seed = Poseidon_BN254(kc_name, kc_value = sub, aud, Poseidon_BN254(salt))`,
   `address = Blake2b_256(0x05, iss_len, iss, addr_seed)`.
4. A **proving service** (Mysten's, or the self-hosted `mysten/zklogin:prover-stable` image) makes a **Groth16** proof that a JWT
   signed by a key in the provider's current JWK set contains the nonce and the claims behind `addr_seed`, without revealing the
   JWT.
5. A transaction carries the proof plus a signature by the ephemeral key. Validators check the proof against the JWKs that they
   fetch from the providers and agree on by a stake quorum (2f + 1).

The trusted setup: phase 1 from Perpetual Powers of Tau (challenge 0081, 80 contributions), phase 2 with 111 contributions,
2023-09-12 to 2023-09-18; verifying key in protocol version 25 [Z3]. The circuits were audited by zkSecurity [Z2]. Only RS256 JWTs
and the `sub` claim are supported [Z3].

### 1.2 Trust assumptions

| Party | What it can do | Source |
|---|---|---|
| OpenID provider | It cannot transact alone (the salt is the second factor). It can mint a JWT for any `sub` with any nonce, so **with the salt it takes the account** *(inference)*. A banned or deleted provider account loses the address unless a multisig backup signer exists. | [Z2, Z3] |
| Salt service | Mysten's service returns the salt to anyone who presents a valid JWT for an allow-listed client id [Z4]. So the "2-of-2" is between the provider and the salt service's policy: **the provider plus that salt service is full control** *(inference)*. A leaked salt links `sub` to the address; a lost salt loses the account. | [Z3, Z4] |
| Proving service | It sees the JWT and the salt, so it links the identity to the address; it cannot sign (no ephemeral key). Self-hosting keeps the JWT in-house. | [Z3, Z4] |
| Groth16 setup | Soundness needs one honest participant of the ceremony; a full compromise forges proofs for any address. | [Z3] |
| Validators | Their 2f + 1 quorum decides which JWKs are current. | [Z3] |

### 1.3 Post-quantum status and privacy

**Not post-quantum.** Groth16 over BN254 rests on pairings (discrete logarithms), and the ephemeral key is a classical Sui key;
Sui's PQ posts plan ML-DSA-65 accounts and SLH-DSA vaults and say nothing about a PQ zkLogin [Z5, Z6]. **Privacy:** `iss`, `aud`
and `kid` are public on chain, `sub` stays hidden [Z3]; the address does not reveal the e-mail, but the prover and the salt
service can link both.

### 1.4 How it would map onto a SCaaS UA kind

- **Today, with no change:** a Sui zkLogin address is a native Sui address, kind `0x0014` (accounts.md lists zkLogin among the
  native Sui forms); it acts wherever SCaaS takes the Sui transaction sender (`ctx.sender()`), as a Sui multisig does. It cannot
  sign a relayed SCaaS operation: the Move verifier takes flags 0, 1, 2 and 6 only, and the connectors refuse zkLogin
  ([sui.md §4](../networks/sui.md#signatures)). Aptos keyless accounts (AIP-61, Accepted) are the same idea on Aptos's native side.
- **As a derived kind** (a portable id on every chain) it would need, per family: a Groth16-over-BN254 verifier, Poseidon over
  BN254, the circuit's verifying key, and **the providers' current JWKs inside the contract**. The last is the blocker. Sui gets
  the JWKs from its validators' consensus; a SCaaS contract has no such feed. A JWK updater contract is a trusted party with
  write power over every zkLogin account's validity, which the SCaaS model avoids: contracts check everything themselves, hold no
  admin and are never upgraded *(inference from [CTR-GEN-02](../contracts/README.md#CTR-GEN-02) and the "nothing deployed is
  upgraded" rule)*. A fixed JWK set at deploy fails at the providers' next key rotation.
- **One rule on every chain, maximal support ([ARCH-POS-18](../decisions.md#ARCH-POS-18)):** the kind would have to run on every
  family, in software where a BN254 pairing is not callable; whether each family exposes one was not checked here, and a software
  pairing in a contract is the kind of cost that goes to the owner with numbers. On EVM the bn254 precompiles make a Groth16
  verify a few hundred thousand gas *(estimate, not measured)*.
- **Never a decryption oracle, never lose ciphertext:** not touched; zkLogin signs, it does not decrypt.

### 1.5 What it gives that passkey + msig + PQ kinds do not

- **Sign-in with an account the user already has**, on any device the user can log into, without a passkey sync domain. Passkeys
  (`webauthn-p256`, `0x0100`) already remove the seed phrase and sync through the platform's keychain.
- **Recovery by the provider account.** SCaaS's answer is an `msig` with a recovery member, or `SmartKeyAccount` guardians; both
  keep the user's own keys in charge.
- What it does **not** give: post-quantum security (passkeys are P-256 too, but the PQ kinds and a PQ `msig` member exist),
  independence from a provider, or privacy from the prover and salt service.

**Recommendation: no.** Not as a kind: the JWK feed contradicts the admin-free contract model, the trusted setup and the
provider are new trust anchors, and the gain over passkeys is small. Keep accepting Sui zkLogin and Aptos keyless addresses
where the family takes the native sender (no work). Revisit only if a JWK attestation appears that a contract can verify with no
updater (for example, providers signing their JWK sets under a long-lived key), and then as a classical kind beside the PQ ones.

## 2. Chipmunk and ChipmunkRing (Cellframe)

### 2.1 Two different "Chipmunks"

- **Chipmunk, the published scheme** (Fleischhacker, Herold, Simkin, Zhang, CCS 2023, ePrint 2023/1820 [C1]): a lattice
  **synchronized multi-signature**: signers share a time step (the block height suits it), each key signs a bounded number of
  messages (2^21 in the paper's figure), and up to thousands of signatures aggregate (about 37 KB for one, about 136 KB for 8,192
  aggregated, at 112-bit security). Peer reviewed; a later paper (Lemur, ePrint 2026/1161) reports multi-signatures about half
  Chipmunk's size, compared at corrected Chipmunk parameters.
- **Chipmunk in the DAP SDK** (`SIG_TYPE_CHIPMUNK` `0x0107`, branch `main` [C2]): "stateful many-time signatures with hypertree
  aggregation", a homomorphic one-time signature per tree leaf. Parameters in `chipmunk.h`: `N = 512`, `q = 3,168,257`,
  `CHIPMUNK_SEC_PARAM 112`, tree height 16, public key `32 + 512·4·2` = 4,128 B, signature `512·4·6` = 12,288 B, a leaf index in
  the private key, one signature per leaf. **Stateful:** reusing a leaf (a restored backup, two devices) breaks the one-time
  property *(inference from the one-time construction)*.
- **ChipmunkRing** (Gerasimov, arXiv 2510.09617, v1 of 2025-09-17, the only version [C3]): a ring signature built on the DAP SDK's
  Chipmunk. The paper cites the base scheme only as its own "Cellframe Technical Report, 2024", not [C1]. It reports signatures of
  20.5 KB (ring of 2) to 279.7 KB (ring of 64), signing 1.1–15.1 ms and verifying 0.4–4.5 ms on a Ryzen 9 7950X3D, and claims
  112-bit post-quantum security "(NIST Level 1)". Its core is "Acorn Verification", presented as a replacement for Fiat-Shamir.
- **The DAP SDK's ring code has moved on** from the paper: the production wire is "MRNG/v1", a logarithmic halving fold, a
  `t`-of-`N` linkable threshold ring under one type `SIG_TYPE_CHIPMUNK_RING` `0x010C` [C2]. Its README gives "~67–118 KB for
  N=2..16"; its redesign note estimates ~23–39 KB for N = 8–256 (threshold 1). The two figures disagree.

### 2.2 Review and standardisation status

- **No standard.** No NIST standard or draft covers ring signatures; the paper itself lists standardising Acorn as future work.
- **No peer review** of ChipmunkRing: an arXiv preprint, one author, no venue, no audit named; the paper says the work was done
  as part of Cellframe Network development. The base Chipmunk of the DAP SDK is described only in the author's own report.
- **The code's own warnings** [C2]: `dap_enc_key.h` marks ChipmunkRing `@experimental` and says, as of 2026-05-17, "True
  ring-signer ANONYMITY is **NOT yet claimed** … Do NOT use this key type for legally / financially significant anonymity claims".
  Its security analysis estimates **77 bits** post-quantum after the QROM loss of its Fiat-Shamir proofs, and lists the QROM
  argument as an open obligation.
- **The paper's gaps** *(my reading of [C3])*: its verification algorithm recomputes each member's Acorn value from a randomness
  the signature does not carry; its proofs speak of Fiat-Shamir challenges and the forking lemma that the Acorn construction
  says it replaced; it states anonymity against a quantum adversary as "vulnerable"; its security figures disagree (112, 149,
  2^67 for Acorn).

### 2.3 What a ring signature is for, and whether SCaaS needs one

A ring signature proves "one of these N keys signed" without saying which (signer ambiguity); a linkable one adds a tag that
repeats when the same key signs twice (double-spend detection, one vote per member); a threshold ring proves `t` of `N`. Uses:
anonymous membership, whistle-blowing, Monero-style sender anonymity, anonymous voting.

SCaaS today:

- **Zether** (classical) hides amounts and lets the sender add decoy **recipients**; "sender anonymity (a ring) is not wanted and
  the sender stays public" ([CTR-ZTH-37](../contracts/zether.md#CTR-ZTH-37)).
- **PQZ** (post-quantum, separate) hides amounts with MLWE ciphertexts and lattice proofs and hides the recipient among decoy
  legs drawn from the registry's `0x0142` list ([CLI-UAL-41](../clients/ua-libraries.md#CLI-UAL-41)); the anonymity analysis is
  [pqz-anonymity.md](pqz-anonymity.md).
- **The UA model** gives one id per key or structure; an `msig` or `bls12381-multi` shows which members signed. Unlinkability
  between a user's identities is by separate UAs, not by rings.

So SCaaS has no feature that needs signer ambiguity, and its stated Zether rule excludes it. If the owner ever wants sender
anonymity, it belongs in the confidential-token design (a PQZ proof over the sender set), not in a UA kind, and it would need
peer-reviewed PQ constructions.

### 2.4 Risk of a non-standard scheme

A new lattice scheme without review is where the repository's past P0s lived (transcript and statement bugs behind green tests).
ChipmunkRing adds an unproven Fiat-Shamir replacement and a stateful base key. Its sizes (20–280 KB per signature) exceed what the
families' transactions take; on most of them it would need chunked storage, and every family would need its verifier
(ARCH-POS-18).

**Recommendation: no** for Chipmunk and ChipmunkRing. **Watch** the published, peer-reviewed line (Chipmunk CCS 2023, Lemur): a
PQ aggregate multi-signature could one day be the post-quantum counterpart of `bls12381-multi`; it would be a separate study once
a construction is reviewed and its parameters settled.

## 3. Kyber, NewHope and the SCaaS KEM

### 3.1 What SCaaS uses (BUILT)

- **One KEM scheme on chain:** scheme `0x01` = ML-KEM-1024 (FIPS 203) + X25519, `kemPk = 0x01 ‖ ek (1,568) ‖ pk_X (32)` = 1,601 B,
  ciphertext 1,600 B, combiner `ss = SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1")` ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32);
  `clients/ua-rs/src/wallet/kem.rs`, crate `ml-kem` 0.3.4; `clientkeys` `kem.js`; vectors `vectors/ua/kem.json`, ACVP ML-KEM-1024).
- **Who uses it:** PqChat (flat wraps and TreeKEM nodes, `groupMode` 1), PqVault (the vault key wrapped to the UA KEM key), PQZ
  opening keys (each leg's `mlkemCt` and `x25519Eph`); the amounts in PQZ are MLWE ciphertexts of its own scheme `0x0142`, not ML-KEM.
- **Who holds a KEM key:** the PQ signer kinds only (`mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`, `fndsa1024`); an `msig` has none
  (`kem.rs`).
- **Reserved:** scheme `0x02` = ML-KEM-1024 + HQC + X25519 "after FIPS 207", refused today (`UAKemScheme`).
- **Transport:** the node mesh's TLS offers only X25519MLKEM768 ([gossip.md](../node/gossip.md)).

"Kyber" as SCaaS uses it is ML-KEM: FIPS 203 changed the round-3 Kyber, so Cellframe's `MLWE_KYBER` / `KEM_KYBER512` (round-3
Kyber code) and its newer `ML_KEM` type are not interchangeable *(inference: FIPS 203 is a distinct specification)*.

### 3.2 What could be missing

| Candidate | Recommendation | Why |
|---|---|---|
| ML-KEM-1024 + HQC + X25519 (scheme 2) | **later**, when FIPS 207 is final | a second, code-based KEM family against a break of module lattices. NIST selected HQC on 2025-03-11, planned a draft in about a year and a final standard in 2027 [K3]; no published draft was found on 2026-11-27. Cost: enable the id and its length, clients, vectors |
| Naming the combiner | **now, docs only** | the CFRG concrete hybrid KEMs draft (`-04`, 2026-07-06) defines MLKEM768-X25519 (= X-Wing), MLKEM768-P256 and MLKEM1024-P384, not ML-KEM-1024 + X25519 [K4]. Scheme 1 is X-Wing's combiner over ML-KEM-1024. A crypto reviewer should confirm in the KEM spec that X-Wing's argument (it hashes `ss_M` without the ML-KEM ciphertext, relying on ML-KEM's ciphertext binding) carries over to ML-KEM-1024 *(inference: the property is ML-KEM's, not its level's)* |
| ML-KEM-768 records | no | scheme 1 already uses the higher level; 768 stays for TLS, where the codepoint fixes it |
| Classic McEliece, FrodoKEM | no | conservative, but McEliece public keys are hundreds of KB and FrodoKEM's are tens of KB; too large for a 1,601-B-class on-chain key record. HQC covers the second-family goal |
| A KEM key for classical-only UAs | open question for the owner, not a gap in the KEM | a passkey-only or ed25519-only UA has no KEM key today (KEM holders are PQ kinds); a user reaches PqChat by a PQ holder |

### 3.3 NewHope: why not

NewHope reached the NIST second round and was not selected for the third (NIST IR 8309, July 2020 [K1]): "the security of
NewHope is never better than that of KYBER" (a tight reduction from RLWE to MLWE), the two have comparable core-SVP estimates,
Kyber was slightly faster in most benchmarks and has a category-3 set that NewHope lacks, so NIST "did not select NewHope to
continue into the third round". It has no FIPS, no maintained standard and no test vectors from NIST. Cellframe's
`RLWE_NEWHOPE_CPA_KEM` is the CPA variant: a CPA KEM under a long-lived key is open to reaction attacks, the reused-key failure
SCaaS rules out for its own decryptions ([ARCH-POS-13](../decisions.md#ARCH-POS-13)) *(inference)*. **Recommendation: never.**

## 4. Anything else worth a look

From Sui's and Cellframe's lists, one line each:

- **Key rotation keeping the address** (Sui's address aliases [Z5]): SCaaS ties an id to its key data, and a stable address
  across rotation is `SmartKeyAccount`'s job (accounts.md §1.1); an `msig` keeps its id across member updates (`updateMsig`, EVM). Nothing to add.
- **ML-DSA-65 inside the native multisig** (Sui [Z5]): SCaaS's `msig` already mixes classical and PQ members.
- **Hybrid composite signatures** (Cellframe `MULTI_COMBINED`, `MULTI_ECDSA_DILITHIUM`): the same role as an `msig` of a
  classical and a PQ member. Nothing to add.
- **SPHINCS+ / Dilithium before FIPS** (Cellframe `0x0104`, `0x0102`): SCaaS uses the final FIPS 204 / 205 forms; nothing to take.
- **BLISS, qTESLA-era TESLA, Picnic** (Cellframe): superseded or broken lines; no.
- **Shipovnik, NTRU Prime signatures** (Cellframe): outside the NIST track; no, unless a market requires a national standard.
- **NEAR's ML-DSA-65 access keys** (nearcore 2.13.0) and **Algorand's `mldsa_verify`** (AVM v14): new since the family PQ note
  [pq-signatures-per-family.md](pq-signatures-per-family.md) of 2026-10-29; both feed the `ua-near` and `ua-algorand` rounds
  ([networks/key-schemes.md §3](../networks/key-schemes.md#3-native-schemes-of-the-other-target-families)).

What SCaaS has that they lack:

- **Against Sui:** ML-DSA-44 and -87 (Sui plans -65 only), FN-DSA-512 and -1024 (Sui declined Falcon), SLH-DSA as a registered
  kind (Sui: Move vaults), BIP-340 / MuSig2 / FROST, BLS multi-signatures, one portable UA id across chains, an on-chain PQ KEM
  key record, and confidential tokens (Zether classical, PQZ post-quantum). Sui's PQ accounts are still before Mainnet.
- **Against Cellframe:** final FIPS forms (Cellframe's FIPS 204 type is on `main`, not `develop`), Ed25519, P-256 and passkeys,
  an AI audit-round process for its own cryptography (ARCH-POS-14), contracts on eight families, and a single hybrid KEM
  record rather than a list of legacy KEMs.

## 5. What this note does not decide

No owner ruling is proposed as made. The three recommendations, the combiner review item and the KEM-for-classical-UAs question
are for the owner.

## 6. Sources (all read 2026-11-27)

- [Z1] Baldimtsi, Chalkias, Ji, Lindstrøm, Maram, Riva, Roy, Sedaghat, Wang, "zkLogin: Privacy-Preserving Blockchain
  Authentication with Existing Credentials", CCS 2024 full version, arXiv 2401.11735v2: <https://arxiv.org/abs/2401.11735>
- [Z2] Sui docs, zkLogin integration: <https://docs.sui.io/sui-stack/zklogin-integration>
- [Z3] Sui docs, zkLogin technical reference: <https://docs.sui.io/sui-stack/zklogin-integration/zklogin>
- [Z4] Sui docs, zkLogin integration guide (salt and prover services): <https://docs.sui.io/sui-stack/zklogin-integration/integration-guide>
- [Z5] Sui Foundation, "Making Sui quantum ready", 2026-08-06: <https://www.sui.io/blog/making-sui-quantum-ready>
- [Z6] K. Chalkias, M. Sedaghat, "Sui's post-quantum signature schemes", 2026-08-18: <https://www.sui.io/blog/suis-post-quantum-signature-schemes>
- [Z7] Sui docs, transaction authentication overview (flags): <https://docs.sui.io/develop/transactions/transaction-auth/auth-overview>
- [Z8] Aptos AIP-61 "Keyless accounts" (Accepted): <https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-061-keyless-accounts.md>
- [C1] Fleischhacker, Herold, Simkin, Zhang, "Chipmunk: Better Synchronized Multi-Signatures from Lattices", CCS 2023, ePrint
  2023/1820: <https://eprint.iacr.org/2023/1820>; Lemur, ePrint 2026/1161: <https://eprint.iacr.org/2026/1161>
- [C2] DAP SDK branch `main` at `3b360f3a3bda` (2026-07-30): `module/crypto/include/dap_sign.h`, `dap_enc_key.h`,
  `module/crypto/src/sig/chipmunk/{README.md, chipmunk.h, CHIPMUNK_SECURITY_ANALYSIS.md, CHIPMUNK_RING_REDESIGN.md}`:
  <https://github.com/demlabs-cellframe/dap-sdk/tree/main/module/crypto>; branch `develop` at `0ba2a892e270` (2026-11-19):
  <https://github.com/demlabs-cellframe/dap-sdk/tree/develop/crypto/include>
- [C3] D. A. Gerasimov, "ChipmunkRing: A Practical Post-Quantum Ring Signature Scheme for Blockchain Applications", arXiv
  2510.09617v1: <https://arxiv.org/abs/2510.09617>, HTML <https://arxiv.org/html/2510.09617v1>
- [K1] NIST IR 8309, "Status Report on the Second Round of the NIST Post-Quantum Cryptography Standardization Process", July
  2020, §3.12: <https://doi.org/10.6028/NIST.IR.8309>
- [K2] FIPS 203, ML-KEM: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>
- [K3] NIST, "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption", 2025-03-11:
  <https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption>
- [K4] draft-irtf-cfrg-concrete-hybrid-kems-04, 2026-07-06: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/>
