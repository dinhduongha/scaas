# Universal Account (UA): kind-tagged account identifiers, per-chain registry, per-kind verifiers, optional credentials (component spec F)

Status: draft **rev 1.4**, 2026-10-07. Rev 1.1 folds in the owner's answers to §17 (rotation and v3 ledger confirmed; PQ
kinds and ed25519 enabled on every EVM chain with pure-Solidity verifiers where no precompile exists; BIP-43 purpose
`7622'`; spec E kind `0x0142` cross-referenced). Rev 1.2 accepts every remaining §17 default. **Rev 1.3 applies
independent review 1** (`docs/reviews/specs/2026-10-06-universal-account-review-1.md`, FIX-THEN-GO: H1–H4, M1–M9,
L1–L10) and the owner rulings of 2026-10-07 (MuSig2/FROST kinds kept and made checkable; Soroban role `kindNo` 18);
disposition in §18. **Rev 1.4 applies the Codex review** (`docs/reviews/specs/2026-10-06-universal-account-codex-review-1.md`,
FIX-THEN-GO: H1–H2, M1–M2, L1; disposition in §19) and the owner ruling of 2026-10-07 that the private chain id moves
from 9000 (also Evmos Testnet) to **7622**: wherever rev 1.3 said chain 9000 this spec says chain 7622 (formerly 9000).
Component spec **F**. Short name **UA**. Code at `scaas` `main` 36b56b9.
**Nothing in this spec is built**; the current `UniversalAccountRegistry` (Zether-only) is replaced by it (§12).
Rulings: **R290–R318, R330–R331** (§2). R150–R172 belong to the app spec, R180–R199 to spec B (TSS), R200–R217 to spec A (AS),
R230–R247 to spec C (OPS), R250–R268 to spec D (S4F), R270–R289 to spec E (PQ Zether). The owner rulings of
2026-10-06 (eight items) and the owner answers of rev 1.1 are folded in and marked `(owner)`; everything else is a decision of this spec.

Requirements and sources:

| Short | File | Section |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §8.6 (UA registry), §9 (keys and signing), §14.5, glossary |
| ZD | `specs/2026-10-03-zether-design.md` | §10 (envelope binding), §11 (auth + registry), RS2-1, RS2-9, RS2-10, RS2-18 |
| AR | `specs/blockchain-research/02-account-registry.md` | §2.1–§2.12 (background: hash ids, PoP, rogue key, BLS, PQ, rotation, non-EVM) |
| R3 | `specs/2026-10-03-blockchain-round3-design.md` | R31 (passkeys, `SubjectAccount`), R32 (seed paths), R33 (conf key paths, PoP binds account), R34 |
| TW2 | `specs/2026-10-06-token-wrappers-v2.md` | R131, R138–R140 (named functions, no second typehash), R145, §3.2 pipeline |
| AS | `specs/2026-10-06-asset-suite-design.md` | R206 (`ComplianceRegistry`, `attributes(UA)` withdrawn), R217, §3.7 |
| TSS | `specs/2026-10-06-tender-sponsorship-shredding.md` | R181, R192–R193 (receiver-fee co-sign), R195–R199 (crypto-shredding) |
| S4F | `specs/2026-10-06-signers-followups.md` | §3 (what moves to F, dual key uses), R251, R253, R263–R265, R268 |
| MESH | `specs/2026-10-05-relayer-mesh-design.md`, `2026-10-06-mesh-gossip-amendment.md` | R78, envelope `scaas-intent/1.2`, pre-gossip checks, V4/V6 |
| APP | `specs/2026-10-06-scaas-app-design.md` | R154, R155, R158, R165, screens 5 and 14, stream A3 |
| INT | `docs/integration.md` | §10.2 (UA registration flow) |
| E | `specs/2026-10-06-pq-zether-design.md` | R279–R282 (PQZ precompile, gas, PQ-only `authRef`, kind `0x0142`), §2.4 (ML-DSA/FN-DSA costs) |

Amends (status changes and pointers only; the text of those files is rewritten by the stream named):

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` §8.6, §9, glossary "UA" | pointers to this spec (done with this spec); §14.5 replaced at stream F1 |
| ZD | §11.2, `ZetherTypes.toUA`, `AuthScheme` | **superseded** by §4, §6, §12 (R290, R291, R305, R312) |
| R3 | R33 PoP binding `msg.sender` | **superseded** by R295 (PoP binds chain + registry + UA, not the caller) |
| AS | R206 "UA registry not extended" | **kept**: compliance flags stay in `ComplianceRegistry`; the VC layer feeds it (R310) |
| S4F | §3 "existing dual uses for F to rule on" | ruled by R300 (separate derivation for every kind and account role) |
| S4F | R269 / Q1 role `kindNo` for Soroban `C…` | **ruled** (owner 2026-10-07): 18 (`soroban-contract`), as D's default (§8.1) |
| S4F | R253 "today only the Cosmos passkey address is unsatisfiable" | pointer: with F, **every single-key derived UA** is unsatisfiable under `requireBackupKey` (D stream rewrites the sentence) |
| E | R282 PoP "binds chain, registry and UA" | pointer: F's PoP now also binds `authRef`, and the PQ `authRef` co-signs (R295, review H1), and the chain's `chain_uid` (R330) |
| E | R270 / §2.7 "a unique chain id for the private chain … also concerns F's chain-bound PoPs" | **ruled**: owner moves the private chain to 7622 (formerly 9000; E's text follows in its sweep); F does not rely on chain-id uniqueness and binds `chain_uid` (R330, Codex H1) |
| E | R281 "`fndsa512` once F enables it" | satisfied: F enables `fndsa512` with the frozen FIPS 206 draft encoding (R313); R282 "gen-1 kind" holds because chain 7622's (formerly 9000) gen 1 deploys after F9 (§6.5) |
| E | R281 hybrid/treasury `authRef` shapes | registrable through per-chain measured caps (R313, §6.2 step 4); the `{mldsa65 ×3} t=2` form fits only where an ML-DSA precompile exists (chain 7622 (formerly 9000)) |
| APP | R176, §6.2 (passkey origins, H4 de-dup) | passkey id is `x ‖ y ‖ rpIdHash` (no origin, §4.2): one passkey ⇒ one UA per `rpId`, any origin the browser accepts for that `rpId`; R176 "after F1–F3/N4" unchanged |
| INT | §10.2 | rewritten at stream F1 to the flow in §12.3 |

---

## 1. Scope and non-goals

### 1.1 In scope

- The **UA identifier**: how an account id is derived from key data or from a policy, for every key kind and
  account structure the repo supports or plans (§4).
- The **kind table**: number, tag, key-data layout, id derivation, whether registration is needed, proof of
  possession, verifier, families (§4).
- The **per-chain registry** contract (EVM interface, storage, events, errors; per-family realisation) (§6).
- The **verifier library** per kind, the calldata/caching policy, and the gas budget (§7, §14).
- **Function → accepted kinds** for every contract family function in the repo, and the UA-ledger functions that let
  our tokens hold balances for non-native UAs directly (§5).
- **One key = one purpose**, enforced in four layers (§8).
- The **optional attestation layer** (Verifiable Credentials / eKYC) (§9).
- `SubjectAccount` kept as **option (b)** (§10).
- Mesh, node, app/clientkeys and Odoo touchpoints (§11), migration (§12), security (§13), tests and vectors (§15),
  streams (§16).

### 1.2 Non-goals

- A wallet or proxy contract per account. A UA is an identifier, like an EOA address, not a contract (R290).
- Key rotation inside one UA. A UA is a function of its key data; changing the key data means a new UA (R302).
  Users who need a stable address across rotation use `SubjectAccount` (option (b), R307).
- Cross-chain state sync of registrations. Each chain has its own registry; the id is the same on every chain
  because it is a pure function (AR §2.8, model A).
- Registry-level freeze, revocation or compliance status. Compliance stays in `ComplianceRegistry` (AS R206) and in
  token controls; the registry is monotonic (R304).
- PQ Zether cryptography (spec E). This spec only defines the PQ **signing** kinds and how a Zether UA points to an
  authorization UA (R305, R313).
- A DID method, a credential issuer, or an on-chain credential parser (§9.6).

---

## 2. Rulings

Format: **ruling** — why — cost if wrong.

### 2.1 Identity

- **R290 (owner)** **A Universal Account is an identifier derived from key data, never a contract.** For a chain's
  native single-key account the id is the native address/key; for every other kind
  `UA = keccak256(keccak256(kind_tag) ‖ key_data)` (32 bytes), with a distinct versioned tag per kind (§4.1). The
  registry is a contract that stores kind data and commitments; the UA itself has no code, no storage of its own and
  nothing to deploy. — An EOA generalised to every signature scheme: free to create, deterministic, the same on every
  chain. — A per-account contract would cost a deploy per user per chain and would make the account upgradeable
  state.
- **R291 (owner)** **32-byte kind-tagged ids, never a 20-byte truncation; derived ids never collide with native ids or
  with each other.** Every derived id must have a non-zero top 96 bits (`ua >> 160 != 0`); the registry refuses the
  rest (`UAIdInNativeSpace`; honest probability 2^-96, the user derives the next index). Native 20-byte ids (EVM,
  Cosmos secp256k1) are zero-padded into the same 32-byte space, so on those families the two spaces are disjoint by
  construction and `>> 160` tells them apart. **Canonical form everywhere** (node, mesh, Odoo, vectors): lower-case hex;
  a 32-byte value whose top 96 bits are zero is the 20-byte native id and is always written, keyed and compared in its
  20-byte form. On families whose native ids are full 32-byte values (Solana, Aptos, Sui, Soroban, TON) native and
  derived ids share one space (collision 2^-128 birthday, infeasible) but **shape cannot tell them apart**: records,
  owners and subject accounts there store an explicit `owner_kind` and dispatch by kind, never by id shape (§6.6).
  Different kinds over the same point give different ids because the tag differs (Schnorr-bn254 over `Y` ≠ Zether-bn254
  over `Y`). — A 20-byte truncation of a policy hash shares the address space with EOAs: grinding an EOA key and a
  multisig policy to the same 20 bytes is a 2^80 birthday search, after which the grinder spends the "multisig" alone.
  — None; ids are 12 bytes longer in calldata (192 gas per id at 16 gas/byte).
- **R292** **One hash function for ids in every family: keccak256.** EVM opcode; native host functions on Solana
  (`sol_keccak256`), Soroban (`crypto().keccak256`), Aptos (`aptos_hash::keccak256`), Sui (`hash::keccak256`), TON
  (`HASHEXT` keccak256); pure Rust in CosmWasm. — The same key data gives the same UA on every chain of every family.
  — CosmWasm pays a few thousand gas units for a software keccak.
- **R293** **Kind numbers and tags are fixed by the kind table (§4.2) and shared by every family; a registry
  generation supports a fixed set of kinds.** Adding a kind is a new registry generation (§6.5) and a new row with
  vectors. A kind is enabled on a chain only if the registry generation was deployed with a verifier for it. — Kinds
  are part of the id; a mutable kind table would be an admin key over every account. — New schemes wait for a new
  registry generation and new token implementations that point to it.

### 2.2 Registration and proof of possession

- **R294 (owner)** **Native kinds are never registered; every other kind must be registered before it can sign or
  receive.** Native = EVM EOA and any EVM contract account (ERC-1271), Hedera native accounts, Solana ed25519, Stellar/Pi
  `G…`, Soroban `C…` contract accounts, Aptos native accounts (any native auth key incl. MultiKey), Sui native
  addresses (incl. native multisig, passkey flag 6, zkLogin), Cosmos native accounts. **TON is the exception:** a TON
  wallet is a contract, so the native TON account is the wallet contract address (registration-free like ERC-1271).
  Every derived kind registers on each chain where it is used. — Registration is where PoP and one-key-one-purpose are
  enforced (R295, R299); receiving to an unregistered derived id is refused so a typo reverts instead of burning funds
  (AR §2.1.6). — One registration per chain (bn254 ≈ 75 k gas; §14).
- **R295** **Proof of possession is kind-tagged and binds chain, registry, UA and `authRef` — not the caller.**
  `pop_digest = keccak256(POP_TAG ‖ chainKeyHash ‖ chainUid ‖ registry_id ‖ ua ‖ authRef)` where `POP_TAG =
  keccak256("scaas.ua.purpose.pop.v1")`, `chainKeyHash = keccak256(chain_key)` with `chain_key` the mesh form
  (`evm:<chainid>`, MESH R115) **computed from `block.chainid` in the constructor** (never a constructor string),
  `chainUid` the chain's immutable unique id (genesis hash, R330; the chain id alone is not unique),
  `registry_id` the 32-byte registry address/id, and `authRef = 0` for every non-Zether kind; then signed as a tagged
  message of the kind (R301). When `authRef ≠ 0` the authority **co-signs**: `register` also requires
  `requireAuthorized(authRef, PURPOSE_AUTHREF, pop_digest, authPop)` (purpose `authref`, §8.3), so nobody can name a
  victim's account as the authority of theirs. Every field of the record therefore follows from signed data:
  `register` derives no state from `msg.sender` or from any unsigned argument, so anyone may submit it (gasless,
  relayable) and front-running yields the identical record or a revert. Supersedes R33's `msg.sender` binding. — AR
  §2.2.2: binding the caller blocks gasless onboarding and adds nothing once the record is caller-independent;
  `authRef` is the one record field not implied by `keyData`, and an unsigned `authRef` let a front-runner freeze a
  Zether account or strip its separate authority (review H1). — A future field taken from `msg.sender` or left
  unsigned would turn front-running into capture; T-REG-3/3b guard it (§15.2).
- **R296** **Rogue-key protection, decided per aggregate kind:**
  | Kind | Approach | Why |
  |---|---|---|
  | `msig` (independent signatures, weighted threshold) | **per-member registration**: every member is a native id or a registered single-key UA (each with its own PoP), kinds ∈ MEMBER (§4.2) | no key aggregation happens, so there is no rogue key; members' keys are still proven once |
  | `musig2-secp256k1`, `musig2-bn254` | **BIP-327 KeyAgg recomputed on chain** from the registered member list (§4.3) **plus** one aggregate PoP by the result | the coefficients defeat rogue keys; MuSig2 is n-of-n, so a valid PoP by `KeyAgg(list)` proves every listed key took part |
  | `frost-secp256k1`, `frost-bn254` | **group key = Σ of the DKG constant-term commitments, each with its PoK, checked on chain** (§4.3) **plus** one group PoP | RFC 9591 leaves DKG out; the FROST paper's KeyGen round-1 PoK is the standard defence; the chain checks it instead of trusting it |
  | threshold ECDSA (MPC providers) | not a kind: the output is an ordinary ECDSA signature by an address ⇒ **native EOA** | the chain cannot tell, and need not |
  — Each defence is the one native to the scheme, and the registry checks it rather than trusting a hash of it
  (owner 2026-10-07: the kinds stay, made checkable). Group metadata the chain cannot check is listed as
  **attestation-only** in §4.3. — A FROST share distribution that went wrong off chain (bad VSS share, one party
  simulating several participants) is invisible to the chain; §4.3 says exactly what is and is not proven.
- **R297** **Structures commit to their members; nesting is one level.** `msig` key data lists members by
  `(kind, id, weight)`, strictly sorted by id; a member may not itself be a structure. (`bls12381-multi` is cut, review
  L10: no consumer, and `msig` over `bls12381-minsig` covers it; number `0x0121` stays reserved.) — Bounded gas, no
  cycles, simple audit. — Two-level governance uses `SubjectAccount` or Safe (native 1271) as a member.

### 2.3 Keys, purposes, tags

- **R298 (owner)** **One key = one purpose, enforced in four layers** (§8): (1) wallets/clientkeys derive a separate
  hardened path per kind and per account role and expose no generic "sign this digest with that key" for UA keys;
  (2) the registry keeps `keyOwner[keyHash] → ua` and refuses the same public key under another kind even with a valid
  PoP (`UAKeyInUse`); (3) every UA signature is over a tagged message carrying kind and purpose (R301); (4) EOAs stay
  unregistered, registered secp256k1 kinds sign kind-tagged messages only, and wallets refuse to use an EOA key for
  any other kind. — ECDSA and Schnorr over one secp256k1 key leak through nonce relations; a Schnorr signing oracle on
  an ElGamal key is a decryption-adjacent oracle; untagged digests replay across protocols. — None beyond §8.
- **R299** **`keyHash` is per group, not per kind**: `keccak256(group_tag ‖ canonical_pubkey)` with groups
  `secp256k1` (x-only), `p256` (x), `ed25519`, `bn254-g1`, `bls12381-g1`, `bls12381-g2`, `bn254-g2`, `mldsa44`,
  `mldsa65`, `fndsa512`, `pqz-mlwe` (spec E R282). All kinds over the same group share the namespace, so `schnorr-bn254`, `frost-bn254`,
  `musig2-bn254` and `zether-bn254` can never register the same point, nor `webauthn-p256` and `p256` the same key.
  For MuSig2/FROST the keyHash is over the **group key**; participant keys are not claimed (a participant key may sit
  in several groups; layer 1 gives it its own path). Key data must be the **unique canonical encoding** of its key
  (§4.2 validation), so one key has exactly one id and one keyHash. — Kind-tagged keyHash would let the same key
  register under two kinds. — Structures have no keyHash (members do).
- **R300** **Rules the dual key uses listed by S4F §3:** the EVM seed key `m/44'/60'/0'/0/i` is the EOA only; a
  `SubjectAccount` `SECP256K1` key, every Sui/Aptos/Solana subject-account owner key that is not the native address
  key, and every derived kind come from the UA tree `m/7622'/0'/<account>'/<kind>'/<i>'` (§8.1). The role-path
  `kindNo` is the kind of the account the key serves: EVM/Hedera `SubjectAccount` 2, Solana 16, **Soroban
  `scaas-account` `C…` 18 (`soroban-contract`; owner 2026-10-07, = D R269 default)**, Aptos 19, Sui 20. Existing dev
  accounts rotate (`rotateKey`) at migration (§12). — A key that is both an EOA and an account key is two purposes.
  — One more derivation per role; wallets show the role.
- **R301** **Tagged message:** every derived-UA signature is over
  `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)` (128-byte preimage, BIP-340-style tagged hashing)
  with `MSG_TAG = keccak256("scaas.ua.msg.v1")` (so no `ua_msg` preimage is ever an id preimage, review L1) and
  `purposeTag = keccak256(bytes("scaas.ua.purpose.<p>.v1"))` — the `bytes32` that every interface takes, used as-is,
  never hashed again. `digest` is the operation's own domain-separated digest (EIP-712 on EVM, the family digest
  elsewhere). Purposes are listed in §8.3. The kind's scheme then signs `ua_msg` its own way (§7.2). **Native signers
  behind the registry** (`requireAuthorized` on a native id: `msig` members, native `authRef`, PoP co-sign) sign the
  EIP-712 struct `UAAuth(bytes32 ua, bytes32 purpose, bytes32 digest)` under the registry's domain (§6.1), never a raw
  hash; native kinds on token-local paths keep their wallet-native signing (EIP-712 / family envelope) untouched. —
  Cross-kind and cross-purpose replay die at the hash; native wallets display what they sign, and no raw-hash
  (`eth_sign`) signature is ever asked of an EOA (review H4). — One extra keccak (~60 gas).

### 2.4 Functions, balances, verification

- **R302 (owner)** **No rotation inside a UA; no rotatable policy kind in v1.** A UA is immutable: key data, members and
  threshold are in the id. Rotation = new UA + move funds (a transfer, or a confidential transfer to the new Zether
  UA). A stable identity across rotation is `SubjectAccount` (R307) or another native contract account. — Immutable
  records make tokens' view of the registry cacheable and the registry admin-free. — Membership changes of a corporate
  `msig` require moving funds (confirmed by the owner, rev 1.1).
- **R303 (owner)** **Each function accepts the kinds it needs** (§5): native-address functions (v1/v2 tokens, DEX,
  mandates) keep accepting native ids only; the new UA-ledger functions on MetaToken v3 accept a native id or a
  registered SIGNING kind as `from` and as `to`; Zether functions accept Zether kinds only, registered first. The kind
  sets SIGNING, ZETHER and MEMBER are **closed and enforced** at each point that names them (§4.2): v3 `from`/`to`,
  `requireAuthorized` (SIGNING and native only; ZETHER reverts), `msig` members (MEMBER), Zether `authRef`. — No
  existing ABI changes; deployed v1/v2 clones stay valid; a Zether UA can never be a v3 receiver (it could never
  spend) nor sign through `requireAuthorized` (a signing use of the decryption key, R298). — UA holders need v3
  tokens (§5.3).
- **R304** **The registry is monotonic and admin-free**: no unregister, no freeze, no status, no owner, non-upgradeable,
  holds no value. A record never changes after `register`. — Tokens may then rely on a record forever (R306) and
  nobody can repoint a victim's key (AR §2.3a). — A compromised derived key is handled like a compromised EOA: move the
  funds; compliance freezes stay token-level (AS).
- **R305** **Zether kinds bind only the encryption key; authorization is an immutable `authRef`.** `zether-bn254` /
  `zether-bls12381` id = `keccak256(keccak256(tag) ‖ Y)`; the record carries `authRef` = `0` (self: the ZK proof is
  the authorization; owner ops are Schnorr by `x` under the Zether tag) or the id of a native account or a registered
  SIGNING UA. `authRef` is covered by the PoP and co-signed by the authority (R295). `authRef` may not be a Zether UA;
  a BLS UA on the same curve as `Y` is refused (canon C6.1). The PQ Zether kind
  `pqz-mlwe` (`0x0142`, spec E R282) tightens this: its `authRef` must be an `mldsa*`/`fndsa512` UA or an `msig` whose
  non-PQ members' weight is below the threshold; `0`, native ids and classical-only kinds are refused (E R281). Supersedes
  `AuthScheme` (8 values) and `link_eth`/`links`. — The token derives the receiver UA from `Y` in the payload with one
  keccak and no lookup; spend authority stays separate from decryption (`survivesEncKeyLeak` for `authRef ≠ 0`). —
  `authRef` cannot rotate (RS2-9 kept; §17 Q2 accepted).
- **R306** **Verification goes through the registry; small key data travels in calldata, large key data is stored
  once.** `requireAuthorized(ua, purpose, digest, auth)` does the lookup and the per-kind check in one call. For kinds
  with key data ≤ 256 bytes and for structures, `auth` carries the key data and the registry checks
  `keccak(tag ‖ keyData) == ua`; for **stored kinds** — PQ kinds (public key) and MuSig2/FROST (the checked group key,
  §4.3) — the registry stores the verification key at registration (SSTORE2 code pointer, `keyPtr`) and `auth`
  carries only the signature. Tokens do not cache records in v1 (one call per check); because records are
  immutable (R304) a cache would be safe, and is allowed in a later token version if measured worthwhile. — Calldata
  beats storage for small keys (a 64-byte key costs ~1 k gas in calldata vs 4.2 k for two cold SLOADs); PQ keys are
  1.3–2.6 KB (21–42 k gas each time in calldata vs ~3 k to read back). — None.
- **R307 (owner)** **`SubjectAccount` is option (b), kept as built**: an optional ERC-1271 smart account (P-256 +
  secp256k1 keys, guardian recovery, Merkle batch) for users who need a stable address across key rotation, guardian
  recovery, or compatibility with third-party contracts. It is a native id; it never registers. **Default = UA kinds
  verified directly by our tokens.** — Rotation and recovery are account features, not identifier features. — Two
  ways to hold a passkey; the app offers the default first (§11.3).
- **R308 (owner)** **EVM balances of derived UAs live in a separate `bytes32` ledger on MetaToken v3** (`_uaBalance[ua]`), never
  in an address projection; native ids in UA-ledger functions read and write the ERC-20 ledger. To ERC-20 observers
  the UA ledger is the **sub-ledger of one sentinel address** `UA_POOL = address(uint160(uint256(keccak256(
  "scaas.ua.pool.v1"))))`: `balanceOf(UA_POOL)` returns `_uaTotal` (= Σ `_uaBalance`, kept by every UA-ledger
  write; the native slot of `UA_POOL` is never written), so `totalSupply == Σ balanceOf(native incl. UA_POOL)`. Every
  movement emits `UATransfer(bytes32 from, bytes32 to, uint256 value)` when a side is derived, and every move that
  changes a native balance also emits ERC-20 `Transfer`: native → UA is `Transfer(sender, UA_POOL)`, UA → native
  (including a fee from a UA to `feeRecipient`) is `Transfer(UA_POOL, to)`; UA → UA emits `UATransfer` only. Native
  `transfer`/`transferFrom` and v3 `to` refuse `UA_POOL` (`UAPoolNotPayable`). — Projecting `bytes32 → address`
  re-creates the 2^80 collision (R291); without the pool, replaying `Transfer` logs would stop equalling
  `balanceOf` for native holders (review M5). — Naive ERC-20 indexers see one large `UA_POOL` holder; our indexer
  splits it (§11.2).
- **R309 (owner)** **The UA-ledger meta-transaction has its own struct and typehash** (`UAMetaTransaction`, `from`/`to` as
  `bytes32`), domain `("SCaaS MetaToken", "3", chainId, clone, salt = chainUid)` (the clone copies
  `registry.chainUid()` at `initialize`, R330), and the same nine-step pipeline (TW2 §3.2). This is a
  deliberate exception to R140 ("no second typehash"): R140 forbade a second hash of the **same** struct; this is a
  different struct whose `from` cannot be an `address`. — An `address`-typed `from` cannot carry a 32-byte id. —
  Clients build two struct shapes (vectors in §15).

### 2.5 Credentials, SubjectAccount, migration, families

- **R310 (owner)** **The VC/eKYC layer is optional and never mandatory.** Any account, native or derived, may attach
  Verifiable Credentials; nothing in a token or the registry requires one. Contracts consume credentials only through
  `ComplianceRegistry` flags set by an attester that verified them off chain (AS R206). The on-chain anchor contract
  (`UAAttestations`) is **deferred from v1** (review M8: optional, read by nothing on chain, leaks metadata; §9.4
  states what it must look like if reinstated). — "I register my EOA and here is my VC" works with zero chain
  changes; contracts never parse VCs. — No public co-statement of holder and issuer in v1; the evidence bundle
  (§9.7) carries the same facts privately.
- **R311** **Holder binding = a presentation signed by the account itself under purpose `vp`**, with audience and
  nonce from the relying party; for SD-JWT VC it is a standard KB-JWT with the private JWS `alg: "scaas-ua"` (§9.3);
  credential subjects are `did:pkh` (CAIP-10) for native ids and `urn:scaas:ua:v1:<kind>:<hex32>` for derived UAs.
  The subject should be a **dedicated identity UA** (its own `<account>'`, §8.1), not the paying UA, so credentials
  do not label the payment history. — The same verifier code (§7) checks presentations off chain. — `scaas-ua`
  KB-JWTs are accepted only by verifiers that implement it (our libraries); a stable subject id makes presentations
  linkable across relying parties (§9.2).
- **R312** **Migration is breaking, dev chains only** (§12): `UniversalAccountRegistry`, `IUniversalAccountRegistry`
  and `AuthScheme` are deleted; `ZetherTypes.toUA` becomes the tagged derivation; Zether accounts re-register; no data
  migration. — Only dev chains (RS2-1) hold registrations today. — Dev balances are recreated by scripts.
- **R313 (owner)** **PQ signing kinds (`mldsa44`, `mldsa65`, `fndsa512`) and `ed25519` are enabled on every EVM
  chain.** Verification uses a native precompile where one is probed (chain 7622 (formerly 9000): `MLDSA65` at `0x…0F10`, spec E R279;
  any future EIP-8051/8052/8355 address by probe, never by assumption) and a **pure-Solidity verifier** everywhere
  else. Every check, registration PoP included, completes **in one transaction** within the chain's
  `UA_VERIFY_BUDGET = min(12,000,000, ⌊0.7 × chain per-transaction gas cap⌋)` (EIP-7825 chains: 12 M ≈ 70 % of
  16,777,216; Hedera, 15 M cap: 10.5 M), a constructor immutable published in the chain profile. **Each kind's
  verify cap is measured per chain** (worst-case accepting and rejecting input, §15.2 T-GAS) and set as a
  constructor immutable `verifyCap[kind]`, also published: e.g. `mldsa65` ≈ 20 k with the chain-7622 (formerly 9000) precompile, the
  measured Solidity worst case elsewhere. Estimates (spec E §2.4; measured in F9): ML-DSA-65 1.2–8.1 M, ML-DSA-44
  lower, FN-DSA-512 0.6–2.5 M, ed25519 0.3–1.2 M. On public chains an enabled kind's measured cap must stay
  ≤ ~50 % of the budget, so a later gas repricing cannot push it over after funds are held (residual §13 S22).
  **If a measured verifier exceeds that bound on a chain, the kind is disabled there (verifier address 0: not
  registrable), never "registrable but unusable"**: a registrable but unusable kind can *receive* and then never
  spend, locking funds. Multi-transaction verification with stored partial state and chunked verify are rejected
  (resumable state is a new replay/griefing surface and a second audit target for no gain while the estimates fit).
  Structures are bounded by the same caps (§6.2 step 4): a hybrid `{mldsa65, p256}` fits everywhere, but a quorum
  of two Solidity-verified PQ members (2 × up to 8.1 M) does not, so spec E's `{mldsa65 ×3} t=2` treasury form is
  registrable only where an ML-DSA precompile exists (chain 7622 (formerly 9000)). `fndsa512` freezes the
  FIPS 206 draft encoding in the vectors; a final FIPS 206 with a different encoding is a new kind version
  (`…fndsa512.v2`), never a silent change. `PQ_COMMITMENT` ("verify off chain") is retired. — Owner rev 1.1: PQ and
  ed25519 everywhere; the budget keeps every authorization a single atomic check. — PQ checks cost real money on
  public chains (§14.2: an ML-DSA-65 signature is 53–132 k gas of calldata alone, plus 1.2–8.1 M execution).
- **R314** **Per-family registries share the kind table, the tags, the derivations and one vector file**
  (`smartcontracts/vectors/ua/kinds.json`); each family realises the registry in its own idiom (§6.6). TON has no
  registry in v1: a derived key on TON is bound by the native wallet owner's `set_key`, which **also carries a
  signature by the bound key** over `uaMessage(kind, POP_TAG, pop_digest)` (`registry_id` = the jetton-wallet
  address; TVM `CHKSIGNS` for ed25519, `P256_CHKSIGNS` for P-256), so binding is consent **and** possession;
  chain-wide keyHash uniqueness is not enforced there (layers 1, 3, 4 still hold). — TON calls are asynchronous
  (AR §2.9); owner consent alone would let a wallet claim someone else's key (review L6). — A TON user can bind the
  same key under two wallets; the wallet refuses it (layer 1).
- **R315** **Non-EVM passkey owners become the `webauthn-p256` UA id, and a derived id is never shown in a native
  address format.** Cosmos: the passkey account is the 32-byte UA id instead of `sha256("scaas.passkey.v1" ‖
  pk)[..20]`; Solana: the passkey owner is the UA id instead of `sha256("scaas.owner.p256" ‖ pk33)`. Both at the
  family stream (version bump). These ids are ledger keys inside our contracts, not accounts of the chain: nobody can
  sign for them as an x/auth account or a Solana pubkey, so a bank `MsgSend`, a SOL transfer or an ATA created for
  one burns funds. They are therefore **displayed and encoded only as `urn:scaas:ua:v1:<kind>:<hex32>`** (never the
  chain's account HRP, never base58 as a pubkey), and wallets/clientkeys refuse a native send to that form. — The
  Cosmos 20-byte form is exactly the truncation R291 forbids (2^80 against secp256k1 accounts); a bech32 account form
  invites native sends to a keyless address (review M6). — Dev accounts re-open; users copy a URN, not an address.
- **R316** **Mesh envelopes carry UA intents as a new EVM body `evm.ua_meta_tx` under `scaas-intent/1.3`, and only
  those**; every other body stays `scaas-intent/1.2`. 1.3 envelopes travel on the existing topic
  `/scaas/intent/1.2/<chain_key>` (the topic names the base stream, MESH R115); a 1.2 node **Ignores** them without
  penalty and without forwarding (MESH R118: minor above ours ⇒ Ignore; E-G4c). `from` is still decoded from the
  signed body, never read from JSON; `intent_id` is the v3 digest the contract emits (R78 unchanged). — No new
  trust in the envelope; 1.3 nodes keep talking 1.2 for everything else, so a rolling upgrade never partitions the
  mesh. — Mixed meshes relay UA intents only through upgraded nodes.
- **R317** **The node verifies every single-key UA kind natively before gossip** (P-256/WebAuthn, ed25519, BIP-340,
  bn254/BLS Schnorr, BLS, MuSig2/FROST group signatures, ML-DSA, FN-DSA) with the shared Rust kind library, and
  structures recursively over their members; only ERC-1271 members/`from` go to simulation. It reads the record once
  per chain (records are immutable: cached forever) and takes the kind from `recordOf`, never from the envelope. —
  Native PQ/BLS verification costs microseconds in Rust against 1.2–8.1 M gas of simulation; leaving them to
  simulation made garbage PQ intents the cheapest node DoS (review M4). — The node needs the registry address per
  chain (config) and the PQ/BLS crates.
- **R318** **Odoo stores UAs as addresses of a new kind, never derives policy off chain**: `blockchain.ua` (kind,
  canonical id per R291, key data, chain registrations), linked to partners only in the client store (erasable,
  SCaaS §11). — Same rule as every other address. — None.

### 2.6 Codex review rulings (rev 1.4)

- **R330** **A chain is identified by `(chain_key, chain_uid)`, never by its chain id alone.** `chain_uid` (`bytes32`,
  `≠ 0`) is the chain's genesis block hash as its RPC reports it (EVM, Hedera), a **constructor immutable** of the
  registry exposed as `chainUid()` and published in the chain profile. It is bound into `pop_digest` (R295), the
  registry's EIP-712 domain `salt` (`UAAuth`, §6.1), the v3 `UAMetaTransaction` domain `salt` (R309) and the
  `metatx-cancel` digest (§8.3). Being a constructor argument, it also makes the CREATE2 address (§6.3) differ per
  chain. The EVM cannot read its own genesis hash after block 256, so the registry cannot *prove* `chain_uid`; what
  the rule guarantees is that two honest registries on chains sharing a chain id (7622, or any other) never accept
  each other's PoPs, `UAAuth` or v3 signatures. A replica deployed elsewhere with a copy of our profile's arguments
  is trusted by nothing of ours: tokens bind the registry address at `initialize`, and the node binds the registry
  address, its `chainUid()` and the RPC's genesis hash per chain profile and refuses a mismatch (E §11.3's genesis
  binding). Non-EVM families take the family's genesis or network identifier where the runtime exposes it (e.g.
  Soroban network id, Solana genesis hash), else a chain-profile constant; each family stream fixes it with vectors.
  — Spec E §2.7: chain id 9000 is also Evmos Testnet; chain ids are a registry convention, not unique. The owner moved
  the private chain to 7622 (formerly 9000), but F does not rely on 7622 being unique either (Codex H1). — A chain
  reset (new genesis) needs a new registry; dev chains redeploy anyway.
- **R331** **EIP-7702 delegated EOAs are native EOAs whose key stays root; native classification is by code at verify
  time.** Wherever this spec verifies a native EVM id (`requireAuthorized`, `msig` native members, native `authRef`
  and its co-sign, v3's native path, §5.3): empty code ⇒ ECDSA low-s by the address; code that is exactly the
  EIP-7702 designator `0xef0100 ‖ address` (23 bytes) ⇒ ECDSA low-s by the address is accepted, and otherwise ERC-1271
  on the address (which runs the delegate code) under the 50 k cap; any other code ⇒ ERC-1271 only (50 k; 400 k for
  `SubjectAccount` clones). A member's stated kind `0x0001`/`0x0002` is a label checked for MEMBER, never the
  dispatch. — The base key of a 7702 account controls it at protocol level (it can send a transaction itself,
  re-delegate or clear the delegation), so no signature rule of ours can make it weaker than root; refusing its
  ECDSA would add no security and break plain 7702 wallets, while the 1271 fallback lets delegated wallets with
  session keys or passkeys sign. v2's `MetaTxCore._isContract` (7702 ⇒ "not a contract" ⇒ ECDSA only) is sound for
  the same reason and stays unchanged (R303); it only refuses such wallets' 1271 signatures. — If a future EIP lets
  a 7702 account disable its base key, ECDSA acceptance for it must follow that EIP's flag (new registry generation).

---

## 3. Model in one page

```
                 key data / policy                         per chain
 subject ──────► kind_tag ‖ key_data ──keccak──► UA id ───► UARegistry.register(kind, keyData, pop, authRef, authPop)
 device                                            │            stores {kind, registeredAt, keyPtr, authRef},
 (clientkeys,                                      │            keyOwner[keyHash] = ua  (one key = one purpose)
  per-kind path)                                   ▼
                                     token function (accepts the kinds it needs)
                                       ├─ native id (EOA / 1271)  → ECDSA / isValidSignature over the token's EIP-712 digest
                                       └─ derived SIGNING UA      → registry.requireAuthorized(ua, purpose, digest, auth)
                                                                      ├─ per-kind verifier over ua_msg (R301)
                                                                      └─ native signer behind the registry: EIP-712 UAAuth
 optional: VC (issuer-signed) + VP / KB-JWT (signed by the identity UA, purpose vp) → relying party / attester
```

---

## 4. Kinds

### 4.1 Derivation

```
kind_tag    = "scaas.ua." ‖ <name> ‖ ".v" ‖ <n>                        (ASCII, e.g. "scaas.ua.zether-bn254.v1")
TAG(kind)   = keccak256(kind_tag)
UA(kind, d) = keccak256(TAG(kind) ‖ d)                                 d = canonical key data (§4.2), raw bytes
valid       ⇔ UA >> 160 ≠ 0                                            (R291)
native id   = family native identifier, left-zero-padded to 32 bytes   (EVM/Cosmos 20 B; others 32 B)
canonical   = lower-case hex; top-96-zero values written in 20-byte form (R291)
member ref  = (uint16 kind, bytes32 id)                                (structures always type their members)
MSG_TAG     = keccak256("scaas.ua.msg.v1")
purposeTag  = keccak256("scaas.ua.purpose.<p>.v1")                      (bytes32, used as-is everywhere)
ua_msg      = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)      (R301)
```

Key-data encodings are byte-exact and identical in every family (the vectors pin them). Points are uncompressed in
the EVM precompile encodings (bn254 EIP-196/197, BLS12-381 EIP-2537), because the EVM verifiers need them that way
and decompression costs more than the calldata it saves (AR §2.1.5).

### 4.2 Kind table

Native kinds (no registration, no tag-derived id; listed so that structures and functions can name them):

| No. | Name | Native id | Families | Signature accepted |
|---|---|---|---|---|
| `0x0001` | `evm-eoa` | 20-byte address (incl. EIP-7702 delegated) | EVM, Hedera (ECDSA alias) | ECDSA low-s over the EIP-712 digest; 7702-delegated: ECDSA, else ERC-1271 of the delegate (R331) |
| `0x0002` | `evm-contract` | 20-byte address with code | EVM, Hedera | ERC-1271 `isValidSignature(digest, sig)`, 50 k gas (400 k for `SubjectAccount` clones) |
| `0x0003` | `hedera-native` | long-zero address `0.0.N` | **Hedera only** (never a member on another EVM chain, MEMBER below) | HIP-632 `isAuthorizedRaw` (64-byte ed25519), else as 0x0001/0x0002 |
| `0x0010` | `solana-ed25519` | 32-byte pubkey | Solana | ed25519 precompile instruction |
| `0x0011` | `stellar-account` | 32-byte `G…` pubkey | Soroban (Stellar, Pi) | host `require_auth` |
| `0x0012` | `soroban-contract` | 32-byte `C…` id | Soroban | `__check_auth` |
| `0x0013` | `aptos-account` | 32-byte address | Aptos | native auth key (ed25519, SingleKey, MultiKey, WebAuthn) |
| `0x0014` | `sui-address` | 32-byte address | Sui | native flags 0/1/2/6, native multisig, zkLogin |
| `0x0015` | `cosmos-account` | 20- or 32-byte account | Cosmos | ADR-036 secp256k1; native multisig |
| `0x0016` | `ton-wallet` | 32-byte account id (workchain from chain config) | TON | wallet contract (W5R1/V4R2/V3R2), TON Connect |

Derived kinds (registered; `d` = key data):

| No. | Name (tag `scaas.ua.<name>.v1`) | `d` (bytes) | keyHash group | PoP | Verifier (EVM) | Families (v1 → later) |
|---|---|---|---|---|---|---|
| `0x0100` | `webauthn-p256` | `x ‖ y ‖ rpIdHash` (96; **no origin**, see below) | `p256` | WebAuthn assertion, challenge = base64url(`ua_msg`) | `P256VERIFY` (EIP-7951/RIP-7212 `0x100`), OZ fallback | EVM → Soroban, Solana, Aptos, Cosmos |
| `0x0101` | `p256` | `x ‖ y` (64) | `p256` | ECDSA-P256-SHA256 over `ua_msg`, low-s | same | EVM (HSM, secure enclave) |
| `0x0102` | `ed25519` | `pk` (32) | `ed25519` | Ed25519(`ua_msg`) | Solidity ed25519 incl. SHA-512 (R313) | every EVM chain; native elsewhere |
| `0x0103` | `bip340` | x-only `pk` (32) | `secp256k1` | BIP-340 over `ua_msg` | `ecrecover` trick + SHA-256 tagged challenge | EVM → Cosmos |
| `0x0104` | `schnorr-bn254` | `Y` (64) | `bn254-g1` | scaas Schnorr (§7.2) over `ua_msg` | bn254 `0x06/0x07` (existing `_schnorr`) | EVM |
| `0x0105` | `schnorr-bls12381` | `Y` (128) | `bls12381-g1` | as 0x0104 on BLS12-381 G1 | EIP-2537 G1MSM | EVM (EIP-2537 chains) |
| `0x0106` | `bls12381-minsig` | `pk ∈ G2` (256) | `bls12381-g2` | BLS min-sig, DST_POP | `Bls12381.verifyMinSig` + `HashToCurve` | EVM (EIP-2537 chains) |
| `0x0107` | `bls-bn254-minsig` | `pk ∈ G2` (128, EIP-197 order) | `bn254-g2` | BLS min-sig, POP label | pairing `0x08` | EVM private chains only (~100-bit) |
| `0x0110` | `musig2-secp256k1` | `Q (33) ‖ u16 n ‖ n × pk_i (33)`; SEC1 compressed, `pk_i` strictly increasing (BIP-327 KeySort), 2 ≤ n ≤ 16 | `secp256k1` (x(Q)) | KeyAgg recomputed (§4.3) **and** one BIP-340 sig by x(Q) | as 0x0103, `Q` from `keyPtr` | EVM → Cosmos |
| `0x0111` | `frost-secp256k1` | `Y (33) ‖ u16 t ‖ u16 n ‖ n × (t × C_ik (33) ‖ R_i (33) ‖ μ_i (32))`, 2 ≤ t ≤ n ≤ 16 | `secp256k1` (x(Y)) | DKG PoKs and `Y = Σ C_i0` (§4.3) **and** one RFC 9591 FROST(secp256k1, SHA-256) sig by `Y` | `UAFrostSecp256k1Verifier` (RFC 9591, §7.2), `Y` from `keyPtr` | EVM → Cosmos |
| `0x0112` | `musig2-bn254` | `Q (64) ‖ u16 n ‖ n × P_i (64)`, `P_i` strictly increasing, 2 ≤ n ≤ 16 | `bn254-g1` | KeyAgg (bn254 port, §4.3) **and** one scaas Schnorr by `Q` | as 0x0104, `Q` from `keyPtr` | EVM |
| `0x0113` | `frost-bn254` | `Y (64) ‖ u16 t ‖ u16 n ‖ n × (t × C_ik (64) ‖ R_i (64) ‖ μ_i (32))`, 2 ≤ t ≤ n ≤ 16 | `bn254-g1` | DKG PoKs and `Y = Σ C_i0` **and** one FROST(bn254, keccak256) sig by `Y` (§4.3) | as 0x0104 (its H2 is the scaas Schnorr challenge), `Y` from `keyPtr` | EVM |
| `0x0120` | `msig` | `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, ids strictly increasing | — | none of its own; every member registered or native, kind ∈ MEMBER | inside the registry (members via their own kinds) | EVM → all |
| `0x0121` | *reserved* (was `bls12381-multi`, cut in rev 1.3) | — | — | — | — | — |
| `0x0130` | `mldsa44` | `pk` (1312) | `mldsa44` | ML-DSA-44 sign(`ua_msg`, ctx = `kind_tag`) | precompile where probed, else pure Solidity (R313) | every EVM chain |
| `0x0131` | `mldsa65` | `pk` (1952) | `mldsa65` | as 0x0130 | chain 7622 (formerly 9000) precompile `0x…0F10` (E R279), else Solidity | every EVM chain |
| `0x0132` | `fndsa512` | `pk` (897) | `fndsa512` | FN-DSA-512 (Falcon), FIPS 206 draft encoding pinned by vectors (R313) | as 0x0130 | every EVM chain |
| `0x0140` | `zether-bn254` | `Y` (64) | `bn254-g1` | scaas Schnorr by `x` under the **Zether** Schnorr tag (`SCAAS-ZETHER-SCHNORR-V1`) on `ua_msg` | existing Zether Schnorr | EVM |
| `0x0141` | `zether-bls12381` | `Y` (128) | `bls12381-g1` | as 0x0140 on BLS12-381 | existing | EVM (EIP-2537 chains) |
| `0x0142` | `pqz-mlwe` (**spec E R282**, §6.1 there) | `pk` (16 384) | `pqz-mlwe` | `R_REG` lattice proof over `uaMessage(0x0142, POP_TAG, popDigest(ua, authRef))` + the `authRef` co-sign (R295) | `UAPqzVerifier` → PQZ precompile `0x…0F01` op 3 | chain 7622 (formerly 9000) only (E R270); `authRef` PQ-only (E R281); `keyPtr` = SSTORE2(pk) |

Validation at registration, all kinds: **key data must be the unique canonical encoding of its key, else
`UAKeyData`** (one key ⇒ one id ⇒ one keyHash, R299): coordinates and scalars `<` the field modulus / group order
(bn254, BLS12-381, P-256 `x, y < p`; secp256k1 compressed prefix `02`/`03` only, `x < p`); ed25519 `y < p` and not
`x = 0` with the sign bit set; FN-DSA coefficients `< q` and ML-DSA keys as FIPS 204 `pkDecode` (lossless);
points on curve, in the prime-order subgroup (G1 BLS12-381, every G2), not the identity (RS2-18 kept for every BLS
key and signature); small-order ed25519 keys refused; `t`/`threshold` non-zero and ≤ total weight or `n`;
`count` ≤ 16 for `msig`, `n` ≤ 16 for MuSig2/FROST; ids / member keys strictly increasing (no duplicate member).

**Passkey id without origin (review M3, decided).** `webauthn-p256` key data is `x ‖ y ‖ rpIdHash`; the origin is
not in the id. The same credential reached from the web app, an Android app (`android:apk-key-hash:…`, Digital
Asset Links) or a desktop shell is one UA, so a user never splits funds across origins and D's "add passkey origin"
needs no new id. The scope is the authenticator's own anti-phishing scope, `rpId`: any origin the platform lets
assert for that `rpId` (its subdomains, WebAuthn related origins) can request a signature. Deployment rule: `rpId` is
the narrowest host covering the app's origins, and no untrusted content is served under it (the Odoo portal origin
is a TCB, S4F §5.3); residual in §13 S9. The verifier still enforces the clientDataJSON grammar (type, challenge,
`crossOrigin` absent or false) but compares no origin. A sorted origins root was rejected: origins are fixed at id
creation, so a later origin would still need a new UA.

**Closed kind sets (R303, enforced; review H2).**

| Set | Members | Enforced at |
|---|---|---|
| ZETHER | `0x0140`, `0x0141`, `0x0142` | Zether functions only (`requireZetherAuthorized`, `kindOf` in `ZetherToken`) |
| SIGNING | every derived kind not in ZETHER: single-key `0x0100`–`0x0107`, `0x0110`–`0x0113`, `0x0130`–`0x0132`, and the structure `0x0120` | `requireAuthorized` (native or SIGNING; ZETHER ⇒ `UAUnauthorized`); v3 `from`/`to` (native or registered SIGNING, else `UAKindNotAccepted(kind)`); Zether `authRef` (native or SIGNING; E R281 narrows `pqz-mlwe`) |
| MEMBER | SIGNING single-key kinds, plus the native kinds the chain profile can verify, all with `id >> 160 == 0` — on EVM `0x0001`–`0x0002`; `0x0003` **only** in a Hedera-profile registry (constructor immutable `hederaNative`, HIP-632) | `msig` members (`UAMemberUnknown`); no other family's native kind, no `hedera-native` outside Hedera (Codex M1) and no structure is ever an EVM member |

### 4.3 MuSig2 and FROST: what the registry checks (owner 2026-10-07)

The kinds stay separate from `bip340` / `schnorr-bn254` (owner, rejecting review M1's collapse) and are made sound:
every claim the id makes about the group is either **checked at registration** or listed as **attestation-only**.
The checked group key is stored (`keyPtr`), so a check costs one signature verification like a single key.

**MuSig2 (BIP-327).** `musig2-secp256k1`: the registry recomputes BIP-327 KeyAgg from the registered list:
`L = hash_{KeyAgg list}(pk_1 ‖ … ‖ pk_n)`, `a_i = hash_{KeyAgg coefficient}(L ‖ pk_i) mod N` (`a_i = 1` for the
second distinct key), `Q = Σ a_i·P_i`, and requires `Q` to equal the `Q` in key data (x and parity). The `pop` blob
carries hint points `H_i` (64 bytes each); each is checked with the `ecrecover` trick
(`address(H_i) == ecrecover(0, v(P_i), x(P_i), a_i·x(P_i) mod N)`, `x(P_i) < N` required) and summed with affine
additions, so no Solidity scalar multiplication is needed. Then one BIP-340 signature by `x(Q)` over the PoP `ua_msg`
(BIP-327 output is BIP-340-valid). `musig2-bn254`: the same KeyAgg with `ECMUL`/`ECADD` (`0x07`/`0x06`) instead of
hints; the hashes are BIP-327's tagged SHA-256 widened to 512 bits (`tagged(x ‖ 0x00) ‖ tagged(x ‖ 0x01)`) and
reduced mod `r`; no x-only / parity negation (points are full); nonce aggregation and partial signing as BIP-327
under the same port; challenge = the scaas Schnorr challenge, so the result verifies as `schnorr-bn254`.

**FROST (RFC 9591, DKG of the FROST paper).** Key data is the DKG transcript: for each participant `i = 1..n`
(RFC 9591 scalar identifiers), its full Feldman commitment vector `C_i0 … C_i(t−1)` and its round-1 PoK `(R_i, μ_i)`
of `a_i0`. The registry checks every point (canonical, on curve), every PoK — `R_i == μ_i·G − c_i·C_i0` with
`c_i = H_dkg(id_i ‖ C_i0 ‖ R_i)`, `H_dkg` the ciphersuite's `hash_to_field` with DST `contextString ‖ "dkg"`, exactly
as the ZF `frost-core` DKG (`keys::dkg::part1/part2`; the vectors are generated from it and pin it) — and
`Y == Σ_i C_i0`. Then one FROST signature by `Y` over the PoP `ua_msg`. Signatures are **RFC 9591 signatures and are
verified by an RFC 9591 verifier, never as BIP-340**:

| Kind | Ciphersuite | Verifier (EVM) | Vectors |
|---|---|---|---|
| `frost-secp256k1` | **FROST(secp256k1, SHA-256)**, RFC 9591 §6.5: `contextString = "FROST-secp256k1-SHA256-v1"`; `c = H2(SerializeElement(R) ‖ SerializeElement(Y) ‖ msg)`, `H2` = `hash_to_field` (`expand_message_xmd` SHA-256, DST `contextString ‖ "chal"`, 48 bytes, mod `N`); sig = `R (33) ‖ z (32)`; accept iff `z < N` and `z·G == R + c·Y` | `UAFrostSecp256k1Verifier`: `H2` via the SHA-256 precompile, `R` decompressed with one `MODEXP`, `z·G − c·Y` by the `ecrecover` trick compared with `address(R)` | RFC 9591 Appendix E.5 + generated `frost.json` (ZF `frost-secp256k1`) |
| `frost-bn254` | **FROST(bn254, keccak256)**, defined here per RFC 9591 §6's ciphersuite requirements: `contextString = "FROST-BN254-KECCAK256-SCAAS-v1"`; elements 64-byte EIP-196 uncompressed, scalars 32-byte big-endian; `H1`, `H3`, `H4`, `H5`, `H_dkg` = `keccak256(contextString ‖ label ‖ m ‖ 0x00) ‖ keccak256(… ‖ 0x01)` mod `r` (labels `rho`, `nonce`, `msg`, `com`, `dkg`); `H2` = the scaas Schnorr challenge (§7.2) | the `schnorr-bn254` verifier (`z·G == R + c·Y` is the RFC 9591 check) | generated `frost.json` from a `frost-core` `Ciphersuite` impl (single implementation, §15.1) |

**Attestation-only (shown as such, never presented as checked):**

| Kind | Checked on chain | Attestation-only |
|---|---|---|
| MuSig2 | `Q = KeyAgg(list)`; every listed key took part in the PoP (n-of-n) | which person or device holds each `pk_i`; that the `n` keys are `n` different parties |
| FROST | `Y` = the sum of `n` PoK-proven contributions; the published commitments have degree `t − 1` | that every participant received a share consistent with the commitments (Feldman checks are off chain, each participant's duty); that `n` contributions are `n` different parties (one party simulating several controls `Y` alone); hence that `t` shares are really needed; who holds which share |
| `msig` (for comparison) | every member registered/native with its own PoP | that a member agreed to be listed (membership is not consent; app rule §11.3) |

Signers (stream F3): clientkeys and the `scaas-ua` crate implement **BIP-327 MuSig2** (secp256k1; the bn254 port)
and **RFC 9591 FROST** with the DKG above (ZF `frost-secp256k1`; the bn254 ciphersuite as a `frost-core` impl,
WASM in clientkeys). Participant keys come from their own path (`kindNo` 0x0110–0x0113, §8.1) and are never a
`bip340`/`schnorr-*` key.

### 4.4 Which kind for whom (guidance for the app and the ERP)

| Subject | Default | Option |
|---|---|---|
| Outlet / staff with a phone | `webauthn-p256` UA | `SubjectAccount` (b) when they want recovery without moving funds |
| User with an extension wallet | native EOA | — |
| Board, finance approvers | `msig` over members' passkey UAs and/or EOAs | Safe (native 1271) |
| Agent cluster, MPC custody with Schnorr | `frost-secp256k1` (cheap on EVM) or `frost-bn254`; shown with §4.3's attestation-only caveats | threshold ECDSA ⇒ native EOA |
| HSM-held corporate key | `p256` (HSMs do P-256) | native EOA (secp256k1 HSM) |
| Confidential balances | `zether-*` with `authRef` = one of the above | `authRef = 0` (self) for single holders |
| Long-lived PQ-ready authority | `mldsa65` (any EVM chain; cheapest on chain 7622 (formerly 9000)) | `msig` mixing `mldsa65` and `p256` (hybrid; fits the caps on every chain, R313) |
| PQ confidential balances (chain 7622 (formerly 9000)) | `pqz-mlwe` with `authRef` = `mldsa65` (spec E) | PQ-dominant `msig` (E R281; two or more PQ signers only where a PQ precompile exists) |

---

## 5. Function → accepted kinds

Legend: **N** = native ids only (EOA, ERC-1271 incl. `SubjectAccount`/Safe/`MandateWallet`, Hedera native);
**U** = a native id or a registered SIGNING kind (§4.2; never ZETHER); **Z** = Zether kind matching the token's
verifier curve; **Z-auth** = the Zether record's `authRef` (self, native, or any SIGNING kind); **sender** = `msg.sender` (native by
definition).

### 5.1 EVM tokens v1 / v2 (unchanged ABIs, R303)

| Contract | Function | Subject parameter | Accepts | Verified by |
|---|---|---|---|---|
| `ERC20MetaTx` / `MetaToken` (v1), `MetaTxCore` (v2) | `executeMetaTransaction(m, sig)` | `m.from` | N | `_requireValidSignature`: EOA ECDSA or ERC-1271 |
| same | `cancelMetaNonce(batch)` | sender | N | — |
| same | `transfer`, `approve`, `transferFrom` | sender; `approve` spender | N; spender contract (R26) | — |
| `MetaTokenBase` (v2) | `mtxTransfer`, `mtxTransferWithFee`, `executeMetaTransactionWithFee`, `mtxPay`, `mtxUnwrap`, `mtxUnwrapWithFee`, `mtxBatch` | `from` / `m.from` | N | same pipeline |
| same | `payWithFee`, `wrap`, `unwrap`, `addReserve` | sender | N | — |
| TSS `mtxPayReceiverFee` (planned) | payer `m.from`, payee `m.to` co-sign | N (payer), N (payee) | `_requireValidSignature` |
| Hedera children | as above | as above | N incl. `hedera-native` | HIP-632 for 64-byte sigs from codeless accounts |
| AS regulated tokens (planned) | transfers, `recordOrder`, `freeze`, … | `to`, `account` | N (address-keyed `ComplianceRegistry`, R206) | — |

### 5.2 EVM Zether (`ZetherToken`, re-pointed by §12)

| Function | Subject | Accepts | Verified by |
|---|---|---|---|
| `fund(encodedY, amount)` | receiver `UA(zether, Y)`; sender pays | Z (registered); sender N | registry `kindOf` |
| `transferConfidential(payload, proof, authSig, beneficiary)` | `from = UA(Y_f)`, `to = UA(Y_t)`, `beneficiary` | Z, Z, Z | proof + `requireZetherAuthorized(from, digest, authSig, zkCovered = true)` ⇒ Z-auth |
| `burn(payload, amount, recipient, beneficiary, proof, authSig)` | `from`, `beneficiary`; `recipient` address | Z, Z; recipient N | as transfer |
| `rollOverSigned(ua, …, sig)`, `setRollOverMode(ua, …, sig)` | `ua` | Z | `requireZetherAuthorized(ua, digest, sig, zkCovered = false)` ⇒ Z-auth (self ⇒ Zether Schnorr by `x`, purpose `zether-owner`) |
| `rollOverPublic(ua)`, `rollOverBatch(uas)` | `ua` | Z | none (public) |
| `wrap`, `unwrap` | sender | N | — |
| `executeMetaTransaction(m, sig)` (envelope for `OP_ZTRANSFER`/`OP_ZBURN`, outer fee) | `m.from` (outer-fee payer) | N | `ZetherMetaTx._requireValidSignature` |
| views `registered`, `accountState`, `sendCounter` | `ua` | Z | — |

`authSig` for Z-auth: `0x` with a proof and `authRef = 0`; else `abi.encode(bytes authKeyData, bytes sig)` checked by
the registry against `authRef` with purpose `zether-auth` (native `authRef`: ECDSA/1271 over the EIP-712
`UAAuth(authRef, PURPOSE_ZETHER_AUTH, authDigest)` of §6.1, never the raw `authDigest`).

### 5.3 EVM MetaToken v3: the UA ledger (new implementations, R308–R309)

New implementation versions of the three tiers (`META_NONE`, `META_SINGLE`, `META_MULTI`) in factory v2; v1/v2
clones are untouched. Storage adds `_uaBalance[bytes32]` and `_uaNonce[bytes32][batch]` (the v3 nonce map is keyed by
`bytes32` for both paths; native ids are zero-padded).

```solidity
struct UAMetaTransaction {
    bytes32 from; bytes32 to; uint256 value; bytes data; uint256 batch; uint256 nonce;
    uint256 validUntil; uint32 mode; address relayer; uint256 fee; address feeRecipient;
}
// typehash: keccak256("UAMetaTransaction(bytes32 from,bytes32 to,uint256 value,bytes data,uint256 batch,"
//                     "uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
```

| Function | Mirrors (TW2 §7.1) | `from` | `to` |
|---|---|---|---|
| `uaExecute(UAMetaTransaction m, bytes auth)` | `executeMetaTransaction` | U | U (`UANotRegistered`, `UAKindNotAccepted`, `UAPoolNotPayable`) |
| `uaTransfer(from, to, amount, batch, nonce, validUntil, mode, relayer, auth)` | `mtxTransfer` | U | U |
| `uaTransferWithFee(…, fee, feeRecipient, auth)` | `mtxTransferWithFee` | U | U |
| `uaPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, auth)` | `mtxPay` (`batch = payLane(payId)`) | U | U |
| `uaUnwrap(from, underlying, wrapped, recipient, minOut, batch, nonce, validUntil, mode, relayer, auth)` | `mtxUnwrap` | U | `recipient` address (N) |
| `uaBatch(UAMetaTransaction[] ms, bytes[] auths)` | `mtxBatch` | each U | each |
| `uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, bytes auth)` | `cancelMetaNonce` | **derived** SIGNING `ua` only (purpose `metatx-cancel`); native ids use `cancelMetaNonce` (sender), which writes `_uaNonce[pad(sender)]` | — |
| `transferToUA(bytes32 to, uint256 amount)` | — | sender N | registered SIGNING (emits `Transfer(sender, UA_POOL)` + `UATransfer`) |
| views `balanceOfUA(bytes32)`, `uaNonce(bytes32, batch)`, `uaDigest(m)`, `registry()` | — | — | — |

Rules: step 5 of the pipeline is ECDSA/1271 over the v3 EIP-712 digest when `from` is a native id
(`from >> 160 == 0`), classified per R331 (a 7702-delegated `from`: ECDSA, else 1271 — not v2's `_isContract` rule), else `registry.requireAuthorized(from, PURPOSE_METATX, digest, auth)`. Ops allowed in
`m.data`: empty (transfer), `pay(bytes32)`, `unwrap(…)`; **`approve` and `trade` are refused in every `ua*`
function, for native `from` too** (`MetaTxUnknownOp`; natives use the v2 address-typed path; a UA-ledger allowance
model waits for DEX v2, §17 Q4). v3 **keeps the v2 address-typed entry points** (`executeMetaTransaction`,
`mtx*`) unchanged; they and the `ua*` functions share one nonce map, `_uaNonce[pad(addr)]`, so one native nonce
cannot be used on both paths (T-V3-1). Fees are paid from the `from` ledger to `feeRecipient` (an address, native
ledger; from a UA `from` it emits `Transfer(UA_POOL, feeRecipient)`, R308); the `FeeRecipientIsPayee` check compares
`bytes32(uint256(uint160(feeRecipient)))` with `m.to`. Event per item: `UAMetaTransactionExecuted(bytes32
indexed from, address indexed relayer, uint256 indexed batch, uint256 nonce, bytes32 digest, address feeRecipient,
uint256 fee)`; its `digest` is the mesh `intent_id` (R316).

Code size: if `--sizes` exceeds 24 576 bytes the `ua*` wrappers move to a `fallback` decoder (as TW2's
`mtxUnwrapWithFee`); verification code never lives in the token (§7).

### 5.4 EVM DEX, mandates, accounts, registry

| Contract | Function | Subject | Accepts | Note |
|---|---|---|---|---|
| `OrderBookDex` | `settle`, `settleOne`, `cancel`, `invalidateNonces`, `checkOrder` | `o.maker`, `maker` | N | `_validSig`; **finding:** its ERC-1271 branch has no gas cap (TW2 caps at 50 k/400 k) — fix in the DEX stream |
| `MetaTxDex` | `settle(a, b)` | `a.m.from`, `b.m.from` | N | via token `executeMetaTransaction`; UA legs wait for v3 `trade` (§17 Q4) |
| `MandateWallet` (native 1271 itself) | `setMandate`, `setPayee`, `revoke`, `execute`; `executeAsOwner`; `payUnderMandate`, `revokeWithSig` | owner; delegate | owner N (ECDSA); delegate N (ECDSA) | a UA owner/delegate = future `MandateWallet` v2 calling `requireAuthorized` (§17 Q5) |
| `SubjectAccount` (option (b)) | `executeAsOwner`, `isValidSignature`, recovery | its keys | P-256 WebAuthn, secp256k1 (account keys, §8.1) | is itself an N id |
| `UARegistry` | `register` | — | any derived kind | PoP |
| TSS `SealedBidTender` (planned) | `commitBid(… m, depositSig)`; `revealBid`, `withdrawDeposit` | bidder = `m.from` | N | a UA bidder needs a v3 deposit token; bidder id in the commitment becomes `bytes32` then |
| AS `VestingGrant`, `Distribution`, `ExchangeOffer` (planned) | `release`, `claim(account)`, `exchange(m, sig)` | beneficiary, account | N | AS beneficiaries "should be a `SubjectAccount`" — still valid as option (b) |

### 5.5 Non-EVM families

| Family | Today (subject) | With F |
|---|---|---|
| Soroban | `Address` (`G…`, `C…`); `scaas-account` keys `Ed25519`, `Passkey` (1-of-N) | native kinds unchanged; `webauthn-p256` key ids follow §4.1 when the account binds them; seed role keys of a `C…` account use `kindNo` 18 (R300); registry = the account factory's persistent map (§6.6) |
| Aptos | `owner: address`; Account keys ed25519 / WebAuthn | native unchanged; non-native owner keys keyed by UA id; `account_of(ua)` for passkey-first accounts |
| Sui | native address (flags 0/1/2/6) | native unchanged (Sui passkeys are native, flag 6); `Registry<T>` gains `key_owner` table |
| Solana | `owner: [u8;32]`; passkey owner `sha256("scaas.owner.p256" ‖ pk33)` | passkey owner = `webauthn-p256` UA id (R315), stored with `owner_kind`, shown only as URN; PDA `["acct", ua]`; PDA `["ukey", keyHash]` enforces R299 |
| Cosmos | bech32 `from`; passkey address 20-byte truncation | passkey owner = 32-byte UA id, a ledger key in our contracts, shown only as URN (R315); `bip340`/MuSig2/`frost-secp256k1` via an `ua-registry` contract |
| TON | `MetaOp.from` wallet; jetton-wallet `passkey` bound by `set_key` | native `ton-wallet`; no registry (R314) |

Families keep their entry points (`relay_pay`, `Relay{payload, auth}`, `SignedOp`…); F changes the owner ids and adds
the registry check where an account opens for a derived owner (order §16). Every non-EVM owner field gains an
explicit `owner_kind` (R291): on these families a native 32-byte key and a derived id cannot be told apart by shape.

---

## 6. Registry

### 6.1 EVM interface

```solidity
interface IUARegistry {
    struct Record { uint16 kind; uint40 registeredAt; address keyPtr; }   // one slot; keyPtr ≠ 0 only for stored kinds

    event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, bytes32 authRef);

    error UAKindDisabled(uint16 kind);            // not enabled in this generation (incl. kinds a predecessor offers, §6.5)
    error UAKeyData(uint16 kind);                 // non-canonical, curve, subgroup, identity, ordering, threshold, cap bound
    error UAIdInNativeSpace(bytes32 ua);          // R291
    error UAAlreadyRegistered(bytes32 ua);
    error UAKeyInUse(bytes32 keyHash, bytes32 owner);   // R298 layer 2
    error UAMemberUnknown(bytes32 member);        // structure member not native/registered, or kind ∉ MEMBER
    error UAAuthRef(bytes32 authRef);             // Zether: not native/SIGNING, same-curve BLS, E R281; others: ≠ 0
    error UAPoP();
    error UAUnauthorized(bytes32 ua);             // also: ua is ZETHER or unregistered

    function generation() external view returns (uint8);                     // 1 or 2 (§6.5)
    function predecessor() external view returns (address);
    function kindEnabled(uint16 kind) external view returns (bool);
    function verifyCap(uint16 kind) external view returns (uint64);          // measured per chain (R313)
    function verifyBudget() external view returns (uint64);                  // UA_VERIFY_BUDGET of this chain (R313)
    function chainUid() external view returns (bytes32);                     // genesis hash, constructor immutable (R330)
    function hederaNative() external view returns (bool);                    // Hedera profile: 0x0003 ∈ MEMBER (§4.2)
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32);
    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32);   // 0 for structures
    function popDigest(bytes32 ua, bytes32 authRef) external view returns (bytes32);          // R295
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32); // R301
    /// EIP-712 digest of UAAuth(ua, purposeTag, digest) under this registry's domain: what native signers sign.
    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);
    function eip712Domain() external view returns (bytes1 fields, string memory name, string memory version,
        uint256 chainId, address verifyingContract, bytes32 salt, uint256[] memory extensions);  // ERC-5267

    function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes32 authRef,
        bytes calldata authPop) external returns (bytes32 ua);              // authPop empty iff authRef == 0

    function recordOf(bytes32 ua) external view returns (Record memory r, bytes32 authRef);
    function kindOf(bytes32 ua) external view returns (uint16);              // 0 = not registered (native ids too)
    function isRegistered(bytes32 ua) external view returns (bool);
    function keyOwner(bytes32 keyHash) external view returns (bytes32);

    /// Reverts UAUnauthorized unless `auth` authorizes `digest` for `ua` under `purposeTag`.
    /// Native ids (ua >> 160 == 0): ECDSA low-s (EOA) or ERC-1271 (50 k cap; 400 k for SubjectAccount clones, by the
    ///   immutable clone codehash) over uaAuthDigest(ua, purposeTag, digest) — never over the raw digest.
    ///   Classified by code at call time (R331): empty ⇒ ECDSA; 7702 designator ⇒ ECDSA, else 1271; other ⇒ 1271.
    /// Derived SIGNING: auth = abi.encode(bytes keyData, bytes sig); keyData empty for stored kinds.
    /// ZETHER or unregistered: UAUnauthorized.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view;

    /// Zether: `authRef == 0` and zkCovered ⇒ auth must be empty; `authRef == 0` and !zkCovered ⇒ Zether Schnorr
    /// by x (purpose zether-owner); else requireAuthorized(authRef, PURPOSE_ZETHER_AUTH, digest, auth).
    function requireZetherAuthorized(bytes32 ua, bytes32 digest, bytes calldata auth, bool zkCovered) external view;
}
// UAAuth typehash = keccak256("UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)")
// domain          = EIP712Domain("SCaaS UARegistry", "<generation, decimal>", block.chainid, address(this),
//                                bytes32 salt = chainUid)                 // ERC-5267 fields = 0x1f (R330)
```

The `UAAuth` wrapper is what every native signer behind the registry signs: `msig` native members
(`UAAuth(memberId, PURPOSE_MEMBER, member_digest)`), a native Zether `authRef`, and a native `authRef`'s co-sign
(`PURPOSE_AUTHREF`). Wallets display it as typed data with its purpose; ERC-7739-style 1271 wallets rehash under the
registry's `eip712Domain()`. The domain's `salt` is the chain's `chain_uid` (R330): clientkeys refuses to sign a
`UAAuth` (or a v3 `UAMetaTransaction`) whose `salt` differs from the chain profile's `chain_uid`, the app shows it,
and the vectors (§15.1) pin it. The v3 token's own native path keeps its `UAMetaTransaction` typed data (§5.3).

### 6.2 `register` steps (cheap first)

1. `kindEnabled(kind)` (immutable table) — `UAKindDisabled`.
2. Key data is the canonical encoding and passes §4.2 validation — `UAKeyData`.
3. `ua = uaOf(kind, keyData)`; `ua >> 160 ≠ 0` — `UAIdInNativeSpace`; not registered here or in the predecessor —
   `UAAlreadyRegistered`.
4. Single-key kinds: `kh = keyHashOf(kind, keyData)`; `keyOwner[kh] == 0` here and in the predecessor —
   `UAKeyInUse`. Structures: every member's kind ∈ MEMBER of this registry's profile (`0x0003` only if
   `hederaNative()`) and the member is native or `kindOf(member) == memberKind`
   (here or in the predecessor) — `UAMemberUnknown`; and the worst-case verify gas of a minimal authorizing set — Σ of
   the `c` largest member `verifyCap`s plus a fixed per-member overhead, `c` = number of lightest-weight members
   needed to reach the threshold — is ≤ `verifyBudget()` — `UAKeyData`. The bound is sound because verification stops
   at the threshold (§7.2 `msig`), so no accepted set has more than `c` members.
5. Zether kinds: `authRef` is 0, a native id, or a registered SIGNING UA; a BLS UA on the curve of `Y` is refused;
   for `pqz-mlwe` only PQ `authRef`s per E R281 — `UAAuthRef`. Other kinds: `authRef == 0` and `authPop` empty —
   `UAAuthRef`.
6. PoP: verify `pop` over `uaMessage(kind, POP_TAG, popDigest(ua, authRef))` with the kind's verifier (MuSig2: the
   KeyAgg check, then one group signature; FROST: the DKG PoKs and `Y = Σ C_i0`, then one group signature (§4.3);
   structures: **no** PoP of their own — members proved theirs; Zether: Schnorr by `x` under the Zether tag) —
   `UAPoP`.
7. `authRef ≠ 0`: `requireAuthorized(authRef, PURPOSE_AUTHREF, popDigest(ua, authRef), authPop)` — the authority
   consents to this exact `(ua, authRef)` on this chain and registry (R295) — `UAUnauthorized(authRef)`.
8. Store `Record{kind, uint40(block.timestamp), keyPtr}` (stored kinds: `keyPtr = SSTORE2.write(vk)`, `vk` = PQ `pk`,
   MuSig2 `Q`, FROST `Y`), `authRef` (Zether only, own slot), `keyOwner[kh] = ua`; emit
   `UARegistered(ua, kind, keyData, authRef)`.

The event carries the full key data: records and ids are rebuildable offline from logs (AR §2.1.6 point 2).

Every verifier `staticcall` is capped at `verifyCap[kind]`; **any failure — revert, out-of-gas (including 63/64
starvation by the caller's gas limit), short or malformed return — is a failed check and reverts**; nothing ever
counts as success by default (T-AUTH-4).

### 6.3 Storage

```
mapping(bytes32 ua      => Record)  _records;     // slot: kind (16) | registeredAt (40) | keyPtr (160) = 216 bits
mapping(bytes32 ua      => bytes32) _authRef;     // Zether kinds only
mapping(bytes32 keyHash => bytes32) _keyOwner;    // single-key kinds
immutable: generation, predecessor, chainKeyHash (= keccak256("evm:" ‖ decimal(block.chainid)), computed in the
           constructor), chainUid (constructor argument, ≠ 0, R330), hederaNative, per-kind verifier addresses
           (0 = disabled), per-kind verifyCap, verifyBudget, SubjectAccount clone codehash (1271 cap),
           EIP-712 domain separator (incl. salt = chainUid)
```

No owner, no setter, no `payable`, no token balances (invariant test). Deployed by CREATE2 from a fixed salt per
generation; constructor arguments (chain uid, verifier set, caps, budget) differ per chain and are published in the
chain profile, so the address is predictable from the profile and differs between two chains sharing a chain id.

### 6.4 Verifiers

Per-kind verifiers are stateless contracts whose addresses are immutable in the registry; the registry `staticcall`s
them with the kind's measured cap (§6.2, R313). They share one interface:

```solidity
interface IUAKindVerifier {
    /// keyData already matched against the id (or vk read from keyPtr) by the registry; message = ua_msg (R301).
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}
```

`msig` is implemented inside the registry (it recurses into member records), not as an external verifier. The
MuSig2 KeyAgg and FROST DKG checks are registration-only code in the kind's verifier contract
(`checkGroup(keyData, pop)`), never run at verify time.

### 6.5 Generations

A registry generation fixes its kind set; at most two generations per chain (AR §2.3a: each fallback costs ~5 k
gas). Generation 2 takes `predecessor = gen1` and reads it for `UAAlreadyRegistered` / `UAKeyInUse` / `kindOf` /
`authRef` checks. Gen 1 is immutable and never sees gen 2, so uniqueness holds only if the generations cannot
overlap (review M2):

- **Gen 2 enables only single-key and Zether kinds whose kind *and* keyHash group are absent from every
  predecessor's enabled set.** A kind gen 1 enables keeps registering in gen 1 only; a kind gen 1 has disabled on
  this chain (verifier 0) may be enabled in gen 2 if its group is also new. Then no key can register under two kinds
  of one group across generations, and no Zether UA can get two records with different `authRef`s.
- **Structures (`msig`) may be re-enabled in gen 2**: a structure record is a pure function of its key data (no
  keyHash, no `authRef`), so the same id registered in both generations is the same record. A gen-1 `msig` can only
  name gen-1 members; an `msig` with a gen-2 member registers in gen 2.
- **Chain 7622's (formerly 9000) gen 1 deploys after F9**, with the PQ signing kinds and `pqz-mlwe` together, so `pqz-mlwe`'s PQ
  `authRef` is visible to it (E R282 "gen-1 kind" holds). On other chains PQ signing kinds may arrive as gen 2
  (their groups are new).

Tokens bind one registry address at `initialize` (immutable); a token that needs new kinds is a new implementation
version pointing to gen 2. Gen 2 sees gen-1 records, so nobody re-registers.

### 6.6 Other families

| Family | Where the records live | keyHash uniqueness | Notes |
|---|---|---|---|
| Hedera | the EVM registry with `hederaNative = true` (`0x0003` members via HIP-632) | yes | HSCS has the bn254 precompiles; EIP-2537 per probe; budget 10.5 M (15 M cap, R313) |
| Cosmos | `ua-registry` CosmWasm contract; tokens query it (`WasmQuery::Smart`) | yes | software keccak; secp256k1/P-256 host verify; derived ids shown as URN, never the account HRP (R315) |
| Soroban | persistent entries in the `scaas-account` factory (`UA(ua)`, `KEY(keyHash)`), TTL extended by the node like other persistent state | yes | `secp256r1_verify`, `ed25519_verify` host functions |
| Sui | `Registry<T>`: `Table<vector<u8>, address>` for `key_owner`; account objects keyed by UA | yes | native verify functions |
| Aptos | resource under the package root: `Table<vector<u8>, address>` | yes | pure-Move P-256 (UNAUDITED) |
| Solana | PDAs `["ua", ua]` (record) and `["ukey", keyHash]` (claim) | yes | precompile-instruction verification |
| TON | none (R314); wallet-bound keys with a key signature in `set_key` | no (documented gap) | async actor model |

On every family, records, account owners and subject accounts store an explicit **`owner_kind`** next to the id and
dispatch verification by that kind; id shape (`>> 160`) is an EVM/Cosmos-20-byte rule only (R291).

---

## 7. Verifier library

### 7.1 Message flow per check

```
digest   = the operation's domain-separated digest (EIP-712 v3 metatx; Zether authDigest; family digest)
ua_msg   = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)                           (R301)
registry : kind = record.kind ∈ SIGNING ; keccak(TAG(kind) ‖ keyData) == ua (or vk from keyPtr) ;
           verifier[kind].verify(keyData | vk, ua_msg, sig)   — capped staticcall, fails closed (§6.2)
native   : ECDSA / 1271 over uaAuthDigest(ua, purposeTag, digest), classified by code (R331) (§6.1)
```

### 7.2 Per kind

| Kind | `sig` | Check |
|---|---|---|
| `webauthn-p256` | `abi.encode(authenticatorData, clientDataJSON, r, s)` (SubjectAccount encoding, R31) | type `webauthn.get`, challenge = base64url(`ua_msg`), `rpIdHash`, UP+UV, low-s, P-256 over `sha256(authData ‖ sha256(clientDataJSON))`; the strict clientDataJSON grammar of `SubjectAccount._clientDataOk` is reused, **without** its origin comparison (§4.2: the id has no origin); `crossOrigin` absent or false |
| `p256` | `r ‖ s` (64) | low-s; P-256 over `sha256(ua_msg)` |
| `ed25519` | 64 | RFC 8032 strict (canonical `S`, no small-order `A`/`R`) over the 32-byte `ua_msg` |
| `bip340` / `musig2-secp256k1` | 64 | BIP-340 verify of `ua_msg` (x-only key; MuSig2: `x(Q)` from `keyPtr`); EVM: `ecrecover` trick with `e = sha256(tag "BIP0340/challenge")`, `R` lifted with one `MODEXP` |
| `frost-secp256k1` | `R (33) ‖ z (32)` (RFC 9591) | RFC 9591 FROST(secp256k1, SHA-256) verify (§4.3): `c = H2(R ‖ Y ‖ ua_msg)`, `z < N`, `z·G == R + c·Y`; **not** BIP-340 |
| `schnorr-bn254` / `musig2-bn254` / `frost-bn254` | `R ‖ z` (96) | `e = hashToScalar(keccak256("scaas.ua.schnorr.v1" ‖ R ‖ Y ‖ ua_msg))`, `[z]G − R − [e]Y == O`, `z < r`, `R ≠ O`, `e ≠ 0` (for `frost-bn254` this is its ciphersuite's RFC 9591 verify, §4.3) |
| `schnorr-bls12381` | `R ‖ z` (160) | as above on BLS12-381 G1 |
| `bls12381-minsig` | G1 sig (128) | `HashToCurve.hashToG1(ua_msg, DST)` with `DST_SIG = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_"`, PoP uses `…_POP_`; sig in subgroup, ≠ O |
| `bls-bn254-minsig` | G1 sig (64) | `mapToG1("SCAAS-UA-BLS-BN254-SIG-V1" ‖ ua_msg)` (POP label for PoP); pairing `0x08` |
| `msig` | `abi.encode(MemberSig[] sigs)`, `MemberSig{uint16 index; bytes keyData; bytes sig}` with strictly increasing `index`; the structure's key data is `auth.keyData` (not repeated) | for each: member `kind,id` from the structure; native ⇒ ECDSA/1271 over `uaAuthDigest(id, PURPOSE_MEMBER, member_digest)`; derived ⇒ `keccak(TAG(kind) ‖ keyData) == id` (stored kinds: `vk` from the member's `keyPtr`; no `kindOf` per member at verify: records are immutable and were checked at registration), verifier over `uaMessage(kind, PURPOSE_MEMBER, member_digest)`; `member_digest = keccak256(ua ‖ ua_msg)`; **stops at the threshold**: a `MemberSig` after Σ weight ≥ threshold ⇒ `UAUnauthorized` (keeps §6.2 step 4's bound sound) |
| `mldsa*` / `fndsa512` | raw signature | precompile if probed, else Solidity verifier, `pk` from `keyPtr` (EXTCODECOPY); ML-DSA context string = `kind_tag` (E §9.3 layout) |
| `pqz-mlwe` | as spec E §7 | spec E R279–R281: proofs via PQZ precompile; authorization via its PQ `authRef` |
| `zether-*` (self, owner ops) | `R ‖ z` | ZD §11.1 Schnorr with tag `SCAAS-ZETHER-SCHNORR-V1` over `ua_msg` — never the UA Schnorr tag, so a Zether key never produces a `schnorr-*` signature |

Members of `msig` (kinds ∈ MEMBER) may be native EOAs, native contracts (Safe, `SubjectAccount`), or registered
single-key UAs (incl. PQ, MuSig2, FROST); never a Zether UA or a structure; this is how a "UA4 = hash of an MPC/multisig structure that points to members with their own schemes" is
expressed (owner item 2).

### 7.3 Per-chain enablement

| Kind | Enabled on | Reason |
|---|---|---|
| `webauthn-p256`, `p256` | every EVM chain | precompile `0x100` where present (≈ 3.5–6.9 k gas), OZ Solidity fallback otherwise (measure; R31 already accepts it) |
| `bip340`, `musig2-*`, `frost-*`, `schnorr-bn254` | every EVM chain | `ecrecover`, SHA-256, `MODEXP`, bn254 `0x06/0x07` |
| `ed25519` | every EVM chain (owner, rev 1.1) | no precompile; Solidity verify incl. SHA-512 ≈ 0.3–1.2 M gas (estimate, F9 measures) |
| `bls12381-*`, `schnorr-bls12381`, `zether-bls12381` | chains where the `CurveCapability` probe passes (returndata compared, AR §2.5.5) | EIP-2537 |
| `bls-bn254-minsig` | private chains only | ~100-bit pairing security (AR §2.5.1) |
| `mldsa44/65`, `fndsa512` | every EVM chain (owner, rev 1.1); precompile where probed | Solidity ML-DSA-65 1.2–8.1 M, FN-DSA-512 0.6–2.5 M (estimates); measured cap ≤ ~50 % of the chain's `UA_VERIFY_BUDGET` on public chains, else disabled on that chain (R313) |
| `pqz-mlwe` | chain 7622 (formerly 9000) only | spec E R270, R279 |

The enabled set, each kind's measured `verifyCap` and the chain's `verifyBudget` are constructor arguments
(verifier address 0 = disabled); the chain profile publishes them; clients read `kindEnabled` and the caps before
offering a kind or building a structure.

---

## 8. One key = one purpose (R298)

### 8.1 Layer 1 — derivation and wallets (clientkeys, app, Odoo portal)

| Use | Path | Curve / scheme |
|---|---|---|
| Native account keys | unchanged family paths (S4F §7.1): EVM `m/44'/60'/0'/0/i`, Solana `m/44'/501'/i'/0'`, … | family |
| Every derived kind and every account-role key | `m/7622'/0'/<account>'/<kindNo>'/<i>'` | BIP-32 (secp256k1, P-256 via SLIP-10 nist256p1), SLIP-10 ed25519 |
| `SubjectAccount` SECP256K1 key (role of `evm-contract`) | `m/7622'/0'/<account>'/2'/<i>'` | secp256k1 |
| Non-native subject-account owner keys (Sui/Aptos/Solana/Soroban role keys) | `m/7622'/0'/<account>'/<native kindNo>'/<i>'`: Solana 16, **Soroban `C…` 18** (`soroban-contract`, owner 2026-10-07), Aptos 19, Sui 20 (R300, D R269) | ed25519 |
| `musig2-secp256k1` participant keys | `m/7622'/0'/<account>'/272'/<i>'` (kind 0x0110; never a `bip340` key); `musig2-bn254` as the bn254 row | secp256k1 |
| FROST shares | **not seed-derived**: DKG polynomial secrets are fresh randomness; the share is kept in the vault (S4F R259) and a lost share is a lost participant (S17) | — |
| `schnorr-bn254`, `musig2-bn254` keys from seed | EIP-2333-style `m/254/0/<account>/<kindNo>` (salt `"SCAAS-UA-BN254-v1"`) | bn254 |
| Identity UA for credentials (R311) | its own `<account>'` in the UA tree, never the paying account's | per kind |
| `bls12381-minsig`, `schnorr-bls12381` | EIP-2333 `m/12381/0/<account>/<kindNo>` | BLS12-381 |
| Zether conf key / viewing key | unchanged R33: `m/254|12381/<coin>/<account>/7`, `…/8` | bn254 / BLS12-381 |
| PQ seeds | `ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 i)` → FIPS 204 `KeyGen_internal(ξ)` / seeded FN-DSA keygen | ML-DSA, FN-DSA |
| Passkeys | one credential per `rpId` (APP R165); the same credential on several chains is the same kind (`webauthn-p256` or a family's native passkey) — allowed, the challenges are domain-separated digests | P-256 |

`7622'` is the SCaaS BIP-43 purpose for UA trees (owner, rev 1.1); coin level `0'` because a UA
id is chain-independent (one derived key ⇒ the same UA on every chain).

clientkeys API rules (stream F3):
- `signDigest(key, digest)` stays for **native** keys only; UA keys are `UAKey` objects created by
  `deriveUAKey(seed, {kind, account, index})` whose only signing method is `signUA(purpose, digest)` (builds `ua_msg`
  itself); there is no way to get a raw signature over an arbitrary 32 bytes from a UA key.
- `deriveUAKey` refuses a `kind` whose curve group equals a native path's curve **and** whose path would equal it
  (cannot happen with `7622'`, asserted in tests) and refuses the Zether `use` indices 7/8 for non-Zether kinds.
- `deriveConfKey` stops accepting a free `use` (only 7 and 8).
- MuSig2/FROST: `UAKey` session objects (`musig2.start/partial/aggregate`, `frost.dkg*/commit/sign/aggregate`) that
  also only ever sign `ua_msg`; vectors BIP-327, RFC 9591 Appendix E.5, `frost.json`.
- A Zether `x` must never be reused as an independent same-curve BLS key (it would make G1 DDH decidable and leak
  balances; C6.1 only blocks the `authRef` link): the BLS and Zether trees are disjoint, and a clientkeys test asserts
  `deriveUAKey` never yields a Zether conf scalar (residual for foreign wallets, §13 S12).
- The vault keeps one PRF/PIN wrapping for the seed and the conf key (S4F R259/R262); AAD labels already separate
  them.
- Wallets show the kind and the role of every key and never offer "use this EOA as a passkey/Schnorr/multisig member
  key" (layer 4).

### 8.2 Layer 2 — registry (R299)

`keyOwner[keccak256(group_tag ‖ canonical_pubkey)]`. Canonical forms: secp256k1 x-only (so a BIP-340 key and a
MuSig2 aggregate or FROST group key with the same x collide, as they must); P-256 `x`; bn254/BLS points
uncompressed; PQ `pk`. Valid PoP does not override `UAKeyInUse`. Because key data must be canonical (§4.2), one key
has one canonical form here.

### 8.3 Layer 3 — purposes

| Purpose tag (`scaas.ua.purpose.<p>.v1`) | Digest it wraps |
|---|---|
| `pop` | `popDigest(ua, authRef)` (R295) |
| `authref` | `popDigest(ua, authRef)`, signed by the authority `authRef` (consent to authorize that Zether `ua`, R295) |
| `metatx` | v3 EIP-712 digest of `UAMetaTransaction` |
| `metatx-cancel` | `keccak256(abi.encode(CANCEL_TAG, chainid, chainUid, token, ua, batch, validUntil))` (R330) — derived `ua` only (natives use `cancelMetaNonce`, §5.3) |
| `member` | `keccak256(structureUA ‖ ua_msg_of_structure)` (native members: inside `UAAuth`, §6.1) |
| `zether-auth` | ZD `authDigest` |
| `zether-owner` | ZD rollOver/mode digests |
| `keyop` | family subject-account key operations (replaces `scaas.keyop.v1` by version bump, S4F §3) |
| `receiver-fee` | TSS `ReceiverFee` co-sign (when the payee is a UA) |
| `vp` | VC presentation / KB-JWT (§9.3) |
| `vc-anchor` | *reserved* (anchor contract deferred, §9.4) |

Digests are already chain/contract-separated; purpose tags separate *uses*, kind tags *kinds*. Native signers behind
the registry get the same separation from the `purpose` field of `UAAuth` (§6.1).

### 8.4 Layer 4 — EOAs

EOAs are never registered and sign only their wallet-native formats: token EIP-712 structs and, behind the
registry, the EIP-712 `UAAuth` (§6.1) — never a raw hash. Registered secp256k1 kinds (`bip340`,
`musig2-secp256k1`, `frost-secp256k1`) sign only tagged `ua_msg`. The chain cannot detect that a BIP-340 key is also
someone's EOA key (EVM exposes no nonce/key mapping); layer 1 prevents it for our wallets, and the security analysis
(§13) records the residual risk for foreign wallets.

---

## 9. Optional attestation layer: Verifiable Credentials / eKYC (R310–R311)

### 9.1 Roles

| Role | Who | Holds |
|---|---|---|
| Holder | the subject controlling a UA or native account | the VC, the salts, the device keys |
| Issuer | KYC provider, bank, registrar, the brand itself | issuer key (a UA or a `did:web` key) |
| Relying party | company A, a managed-market operator, an asset issuer | trust list, presentations received, evidence bundles |
| Attester | the relying party's compliance service | `ComplianceRegistry` attester role (AS R206) |

### 9.2 Formats

W3C VC Data Model 2.0. Securing: **SD-JWT VC** (selective disclosure, salted claim digests) as the default.
`bbs-2023` stays an option (§17 Q14) **only with anonymous holder binding and per-verifier pseudonyms** (the W3C
Data Integrity BBS pseudonym feature): such a presentation discloses neither `credentialSubject.id` nor a
UA-signed proof, so the R311 binding below is not used for it. Its presentation header must carry the relying
party's `aud` and `nonce`, but it proves only "a holder of a credential bound to this pseudonym presented it", not
"this account presented it": **a bbs presentation is never accepted where the legal-recourse evidence trail (§9.7)
applies** — those workflows require the R311 binding (SD-JWT VC + `scaas-ua` KB-JWT, `nonce` = deal reference /
`intent_id`) (Codex M2). Until that feature is a final W3C/IETF text with an
implementation in our libraries, bbs is not offered: a bbs presentation bound to the stable UA (the same id on every
chain, §17 Q6) would be linkable anyway. Status: W3C Bitstring Status List (or IETF Token Status List); `validUntil`
on every credential. `credentialSubject.id`: `did:pkh:<caip10>` for native accounts (e.g.
`did:pkh:eip155:100:0xabc…`), `urn:scaas:ua:v1:<kind>:<hex32>` for derived UAs (resolution = the `UARegistered`
event or `recordOf` + key data). The subject is a dedicated identity UA (R311); presentations under one subject id
are linkable across relying parties by design.

### 9.3 Holder binding (presentation)

**SD-JWT VC: a standard KB-JWT with a private JWS algorithm.** The issuer puts
`cnf = {"kid": "<credentialSubject.id>"}` (RFC 7800) in the SD-JWT VC. The holder appends a KB-JWT exactly as
the SD-JWT VC spec defines it — header `{"typ": "kb+jwt", "alg": "scaas-ua"}`, payload `{iat, aud, nonce,
sd_hash}` — and signs it as follows:

```
vp_digest = keccak256(abi.encode(keccak256("scaas.vp.kb-jwt.v1"), sha256(ASCII(b64url(header) ‖ "." ‖ b64url(payload)))))
derived : signature = b64url(auth blob) of a UA signature over uaMessage(kind, PURPOSE_VP, vp_digest)
native  : signature = b64url(ECDSA / 1271 sig) over EIP-712 UAAuth(pad(account), PURPOSE_VP, vp_digest),
          domain EIP712Domain(name = "SCaaS VP", version = "1")   (off chain: no chainId, no contract)
```

The verifier checks `sd_hash`, `aud`, `nonce`, `iat` as the SD-JWT VC spec says, then the signature with the shared
kind library (§7, same vectors). `alg: "scaas-ua"` is not registered with IANA: external SD-JWT verifiers and wallets
accept these presentations only if they implement it (our JS/Rust/Python libraries do); that is the cost of never
letting a UA key produce a raw ES256/ES256K signature (R298).

`nonce` is chosen by the relying party (for a trade: the deal reference or the `intent_id`), so a presentation proves
"this account's key holder presented this credential to us for this deal at this time".

### 9.4 On-chain anchor: deferred

`UAAttestations` is **not in v1** (review M8, decided): it is optional, no token reads it, it publishes which UA holds
which issuer's credential, and the evidence bundle (§9.7) proves the same facts to the people who need them. If a
later spec reinstates it, consent must be EIP-712 `Anchor{bytes32 subject, bytes32 issuer, bytes32 schemaId, bytes32
commitment, uint64 expiresAt}` under its own domain `("SCaaS UAAttestations", "1", chainId, contract)` (derived
signers: that digest under purpose `vc-anchor`; native signers: the typed data itself), and revocation/withdrawal
digests are separate EIP-712 structs, so consent binds chain, contract and expiry. Commitments keep the TSS R196
format `keccak256(abi.encode(keccak256("scaas.commit.v1"), salt, sha256(JCS(credential))))`.

### 9.5 Privacy and erasure

- No personal data on chain (TSS §C.1). In v1 nothing credential-related is on chain at all.
- Correlation: a credential names its subject id, so every relying party that receives it can link it to that UA's
  public activity; hence the dedicated identity UA (R311). Payment UAs never appear in credentials.
- Erasure (TSS R195–R199): salts, credentials and relying-party evidence are held under the per-subject DEK;
  destroying the DEK makes them unreadable. It does **not** unlink the UA itself: counterparties and ERP records may
  still link the UA to the person by other means; erasure removes our copy of the claims and of the link, not the
  chain history.
- Selective disclosure: the relying party asks only for the claims it needs (SD-JWT disclosures); the evidence bundle
  keeps exactly what was disclosed.

### 9.6 Trust lists and consumption

- **Trust lists** are relying-party configuration, not chain state: issuer id + key, accepted schemas, assurance
  level, validity window. A managed-market operator publishes its list as a signed JSON document (its UA signs it,
  purpose `vp`-style digest `scaas.trustlist.v1`); its hash may be anchored with any commitment anchor. No on-chain
  trust-list contract (nothing on chain needs to read it).
- **Contracts** consume only `ComplianceRegistry` flags (AS §3.7). Flow: holder presents → attester verifies VP, VC,
  status, trust list → `ComplianceRegistry.attest([account], [flags], [validUntil ≤ credential validUntil])`. The
  registry stays address-keyed (AS R206); a v3 token that wants UA receivers in a regulated market needs a
  `bytes32`-keyed compliance check — not in this spec (§17 Q7).
- **Node**: does not verify credentials; it already refuses intents whose `validUntil` exceeds the receiver's
  attestation (AS §3.8).
- **App/ERP**: the holder's credentials and salts live in the client store only (R318), never in Odoo. On the
  relying-party side the Odoo addon stores presentations and evidence as `ir.attachment` on Garage/S3, **encrypted
  under the per-subject DEK** (TSS R197), with the hash in the record.

### 9.7 Legal-recourse evidence trail

For a trade where company A relied on a counterparty's credential, the relying party keeps an **evidence bundle**:

| Item | Proves |
|---|---|
| VC (issuer-signed) and its status at the time | who the issuer says the subject is |
| VP signed by the counterparty's account (R311 KB-JWT; a bbs pseudonymous presentation does not qualify, §9.2), `nonce` = deal reference / `intent_id` | the key holder of that account presented it for this deal |
| finalized tx hash + `intent_id` + event (`UAMetaTransactionExecuted`, `PaymentSettled`, …) | the account performed the on-chain act |
| `UARegistered` event (derived UAs) | the key data behind the id, and when it was registered |
| trust-list version and verification log | what A checked and when |

`bundleHash = sha256(JCS(bundle manifest))` is stored on the business document. Retention follows the legal-claims
basis of the applicable data-protection regime (market-neutral): erasure requests are honoured after the claim
period, by DEK destruction (R197).

---

## 10. `SubjectAccount` as option (b) (R307)

- Kept byte-identical; it is an `evm-contract` native id; tokens verify it through ERC-1271 (400 k cap for its
  clones, TW2 §3.1). Non-EVM equivalents (Sui/Aptos/Solana/Soroban accounts) keep their role likewise.
- When to offer it: the subject asks for recovery without moving funds, wants one address across key changes, or
  must interact with third-party contracts that only understand `address`.
- Keys: its `SECP256K1` keys come from the role path `m/7622'/0'/<account>'/2'/<i>'` (R300), never from the EOA
  path; its P-256 keys are passkeys (per `rpId`). A passkey that is a `webauthn-p256` UA may **also** be a
  `SubjectAccount` key: same kind, same WebAuthn scheme, digests differ (the account's challenge is the token's
  EIP-712 digest with `from` = the account); allowed.
- The S4F backup predicate (R251) applies to it unchanged; derived UAs are "single-key, no recovery" by construction
  and the app shows that (S4F R253 maps to F's native/derived split, S4F R268).
- `msig` UAs may list a `SubjectAccount` as a member (native contract member).

---

## 11. Touchpoints

### 11.1 Mesh (R316–R317)

- `scaas-intent/1.3` (only for this body; everything else stays 1.2, R316): EVM body
  `evm.ua_meta_tx = {token, m: UAMetaTransaction (hex fields), auth}`; `from` decoded from `m.from` (32-byte hex,
  canonicalised per R291). `intent_id` = `uaDigest(m)`. `sig_kind` values: `eoa`, `erc1271`, `ua`. No `from_kind`:
  the kind comes from `recordOf` (an unsigned JSON field would be a second source of truth).
- Topic: the existing `/scaas/intent/1.2/<chain_key>`; 1.2 nodes Ignore 1.3 envelopes (no penalty, no forwarding,
  MESH R118/E-G4c).
- Pre-gossip: `ua` ⇒ the node reads `recordOf(from)` once per chain (immutable; cache with no expiry; negative
  results cached 60 s), recomputes the id from `auth.keyData` (or reads `keyPtr` for stored kinds), and verifies every
  single-key kind and every structure natively (R317); only ERC-1271 goes to simulation. A failed UA check is
  `Ignore` for gossip acceptance (the kind and stored keys come from the record, i.e. our store, MESH R118): the
  intent is dropped and never simulated, without penalising the forwarder.
- V6 rate limit and V8 freshness key on the **canonical** `from` (R291: an EOA is the same 20-byte key whether it
  arrives via 1.2 or padded via 1.3); `uaNonce(from, batch)` is the freshness source.

### 11.2 Node (indexer, jobs, API)

- New job payload kind `ua_metatx` (same lifecycle as `metatx`, NI R89/R91); idempotency on `(chain, token, from,
  batch, nonce)` with `from: bytes32`.
- Indexer normalizes `UATransfer` and `UAMetaTransactionExecuted` (SCaaS §7.8) and `UARegistered` (with key data).
  `Transfer` to/from `UA_POOL` (R308) is paired with the `UATransfer` of the same log batch and reported as the UA
  movement, never as a `UA_POOL` balance. Balances feed `/v1/events` per canonical id; native ids keep today's form.
- Config per chain: `ua_registry` address and generation; enabled kinds read from chain at onboarding.
- The node never holds UA keys; `Signer`/lane keys (R59) are unaffected.

### 11.3 App and clientkeys

- `src/features/accounts/` (APP screen 5): the default "Create account" makes a `webauthn-p256` UA and registers it
  (gasless; R295 makes `register` relayable, so APP screen 14's "self-paid only" no longer applies); "Recoverable
  account" makes a `SubjectAccount` (option (b)).
- Screen 14 (Zether): registers `zether-*` with `authRef` picked from the user's existing accounts.
- Groups: an "Approvers" wizard builds `msig` key data from member accounts and shows the id before registering.
  **Membership is not consent**: the wizard collects each member's off-chain `member`-purpose signature over the
  structure id before showing the group as theirs, and a structure found on chain without them is shown as "members
  listed, not confirmed". MuSig2 groups show "all n keys signed at registration"; FROST groups show §4.3's
  attestation-only caveats (share holders and `t` not proven on chain).
- Derived ids on non-EVM families are copied and shown only as `urn:scaas:ua:v1:…` (R315); clientkeys refuses a
  native send to that form.
- clientkeys F3: `ua.js` (`uaOf`, `keyHashOf`, `uaMessage`, `popDigest`, `deriveUAKey`, `UAKey.signUA`, encoders per
  kind, `UAMetaTransaction` typed data), `zether.js` (`confPublic` returns the tagged UA; `zetherPop` signs the new
  PoP; `popMessage` removed), `fam/*` owner derivations per R315. Vectors §15.1.

### 11.4 Odoo (bamboo-dms, `dms_blockchain*`)

Today no Odoo model stores a UA, a Zether key or a registry address (§12.1). Changes (stream F6, parent repo):

| Where | Change |
|---|---|
| `dms_blockchain/models/` new `blockchain.ua` | `ua_id` (Char 66, indexed, **canonical** per R291: lower-case, 20-byte form when the top 96 bits are zero, normalised in `create`/`write` and by `lib/addresses.canonical`), `kind` (Selection from the kind table), `key_data` (hex), `registration_ids` (per chain: registry, tx hash, block, state); unique `(ua_id)` via `models.Constraint` (CLAUDE.md §5.2) |
| `blockchain.chain` config | `ua_registry_address`, `ua_registry_generation`, `ua_kinds_enabled` (read from chain) |
| `lib/addresses.py` (`canonical`) and `blockchain.address.mixin` | accept a 32-byte UA id as an address form on EVM (`0x` + 64 hex) alongside 20-byte addresses; never truncate |
| `blockchain.signed.op` | `auth_kind` gains `ua`; `from_address` holds the UA id |
| `blockchain.metatx`, `payment_request.payer_address`, `chain_event` from/to | accept UA ids; `blockchain.chain.event` maps `UATransfer` |
| `dms_portal_subject_account.py` | `register_start/register` gain the UA path (passkey ⇒ `webauthn-p256` UA) next to `SubjectAccount` |
| `lib/fam_*.py` `verify(...)` | `fam_evm.verify_ua(record, digest, auth)` using the shared Python kind library (same vectors) |
| `blockchain.subject.account.key` | `evm_address` keys created after F3 come from the role path (R300); migration note on existing dev keys |
| Credentials (optional, relying-party side only) | `blockchain.ua.credential`: issuer, schema, `validUntil`, status URL, received VP / evidence as `ir.attachment` (Garage) **encrypted under the per-subject DEK** (TSS R197), `bundleHash`; no claims in DB columns; holder-side credentials never reach Odoo |
| Partner link | partner ↔ UA only in the client store (erasable, SCaaS §11, TSS R197) |

---

## 12. Migration from `UniversalAccountRegistry` (R312)

### 12.1 What exists

`UniversalAccountRegistry` (Zether-only, `UA = keccak256(encodedY)`, untagged; `AuthScheme` 8 values; PoP binds
`msg.sender`; `links`/`link_eth`; no rotation). Consumers: `ZetherToken` (`registered` via `keyLengthOf`,
`requireAuthorized` ×4, `toUA` on fund/transfer/burn), `IZetherToken`, `ITransferDisclosure`, tests
(`UniversalAccountRegistry.t.sol`, `ZetherFixture`, `ZetherToken.t.sol`, `ZetherRevertPaths.t.sol`, `AuthScheme.t.sol`,
vectors `test/vectors/zether/*`), `zether-prover` (`keys.rs` `ua()`, `curve.rs` `ua_of`, `schnorr.rs` PoP and
`entryRef`, `api.rs`, `vectors.rs`, `r33_keys.json` + copies), clientkeys `zether.js` (`confPublic`, `popMessage`,
`zetherPop`, balance cache key `ua:token`), the built bundle in `dms_blockchain_bridge/static/lib/clientkeys/`, app
spec screens 5/14. Not used by deploy scripts, scaas-node, Odoo Python or non-EVM contracts.

### 12.2 Changes

| Item | Change |
|---|---|
| `src/registry/UniversalAccountRegistry.sol`, `IUniversalAccountRegistry.sol` | deleted; `UARegistry.sol`, `IUARegistry.sol`, `verifiers/*.sol` added |
| `src/common/AuthScheme.sol` + `test/AuthScheme.t.sol` | deleted (kinds replace schemes) |
| `src/common/MultiSig.sol` | kept as the EOA-member path of `msig` (sorted, low-s, threshold) |
| `ZetherTypes.toUA(encodedY)` | `keccak256(abi.encodePacked(TAG_ZETHER_<curve>, encodedY))`; curve from length |
| `ZetherToken.registered(ua)` | `registry.kindOf(ua) == ZETHER_<verifier curve>` |
| `ZetherToken` auth calls | `requireZetherAuthorized(ua, digest, sig, zkCovered)` |
| `entryRef` | unchanged formula; `fromUA` is the new id (vectors regenerate) |
| zether-prover | `ua_of` tagged; PoP per R295; vectors regenerated |
| clientkeys | as §11.3; `r33_keys.json` regenerated |
| `AuthScheme` → `authRef` | `SELF_SCHNORR` → `0`; `ECDSA_MULTISIG` → `msig` of EOA members; `FROST/MUSIG2_BN254` → `frost/musig2-bn254` UA (key data = the checked transcript / member list, §4.3; groups re-run their DKG or KeyAgg); `BLS_BN254/12381` → `bls-*` UA (cross-curve rule kept); `PQ_COMMITMENT` → retired (R313; spec E); `SMART_ACCOUNT_1271` → native contract id; `linkEVM` → retired (index `UARegistered`) |
| SCaaS §8.6, §9.7, §14.5; INT §10.2 | rewritten at F1 (pointers now) |

### 12.3 New registration flow (replaces INT §10.2)

1. Client derives the key for the kind (§8.1), builds `keyData`, computes `ua` and checks `ua >> 160 ≠ 0`.
2. Reads `popDigest(ua, authRef)` (or computes it: chain key, `chain_uid` from the chain profile — checked equal to
   `chainUid()` — registry address and `authRef` are known) and signs
   `uaMessage(kind, POP_TAG, popDigest)` with the kind's signer (`UAKey.signUA("pop", …)`; MuSig2/FROST: a group
   signing session, plus the KeyAgg hints or the DKG transcript). Zether with `authRef ≠ 0`: the authority signs
   `authPop` (purpose `authref`; native authority: EIP-712 `UAAuth`).
3. Anyone submits `register(kind, keyData, pop, authRef, authPop)` (self-paid, relayer job, or sponsored).
4. On the finalized `UARegistered` the client checks `recordOf(ua)` — kind **and `authRef`** equal what it asked
   for — and only then marks the account usable on that chain.

### 12.4 Order

F1 lands registry + Zether re-point + prover + clientkeys Zether change in one change set (the vectors are shared,
partial landing breaks the cross-language tests); dev chains 31337/1337 redeploy; fixtures re-register; dev
`SubjectAccount` secp256k1 keys rotate to the role path with `rotateKey` (script); non-EVM owner derivations (R315)
move with their family streams.

---

## 13. Security analysis

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| S1 | Namespace collision derived ↔ native (EVM 20-byte) | 32-byte ids; `ua >> 160 ≠ 0` required; native ids zero-padded (R291) | none at 2^-96 |
| S2 | Cross-kind collision (same point, two kinds) | tag in the id (R290); `keyOwner` per group (R299) | none |
| S3 | Rogue key in aggregates | per kind (R296); `msig` members registered with PoP; MuSig2 KeyAgg **recomputed on chain** + n-of-n PoP; FROST DKG PoKs and `Y = Σ C_i0` **checked on chain** + group PoP (§4.3) | §4.3's attestation-only list: FROST share distribution, distinct parties, real `t`; MuSig2 key ↔ person |
| S4 | Registering someone else's key | PoP over a chain+registry+UA digest | none |
| S5 | Front-running `register` (incl. a different Zether `authRef`: freeze or downgrade) | every record field follows from signed data: PoP binds `authRef`, the authority co-signs (R295); client checks `recordOf(ua).authRef` (§12.3); T-REG-3/3b | victim's relayer may lose one tx's gas (AR §2.2.3: economically reversed) |
| S6 | Spam registrations (state growth, sponsored pools) | sponsorship policy at the node (TSS R189–R191); no on-chain invite gate in v1 | self-paid spam pays its own gas (§17 Q8) |
| S7 | Key reuse across purposes | four layers (§8) | a foreign wallet reusing an EOA key for `bip340` (layer 4 cannot be enforced on chain) |
| S8 | Cross-protocol / cross-purpose replay | tagged `ua_msg` (R301); digests domain-separated | none |
| S9 | WebAuthn origin/iframe confusion | `SubjectAccount` clientDataJSON grammar reused (fail-closed), `crossOrigin` refused, `rpIdHash` in the id | no origin in the id (§4.2): any origin the platform lets assert for the `rpId` (subdomains, related origins) can request a signature; deployment rule: narrowest `rpId`, no untrusted content under it |
| S10 | ed25519 malleability / small-order keys | strict RFC 8032 verify; small-order `A` refused at registration | — |
| S11 | BLS subgroup / infinity | G2MSM k=1 at registration; signatures in subgroup, ≠ O (RS2-18) | — |
| S12 | Zether same-curve BLS auth (DDH) | refused at registration (C6.1); disjoint trees + clientkeys test (§8.1) | a foreign wallet reusing a Zether `x` as an independent same-curve BLS key makes G1 DDH decidable (not detectable on chain) |
| S13 | Zether key used as a signing key | `zether-*` signatures use the Zether Schnorr tag only; `schnorr-*` can never register the same point (R299) | — |
| S14 | Verifier DoS (huge structures, PQ; node intake) | `count`/`n` caps; measured per-chain caps; structure bound with stop-at-threshold; node verifies natively (R317) | — |
| S15 | Registry capture; permissive verifier | no admin, no upgrade, immutable verifier set; generations disjoint (§6.5); differential fuzzing of the pure-Solidity verifiers (§15.2 T-FUZZ) | a bug in a verifier is permanent for that generation (audit before public chains, RS2-1 gate kept); kinds with a single implementation (§15.1) are only self-consistent |
| S16 | Compromised derived key | like an EOA: move funds; compliance freeze at token level | no recovery by design; option (b) exists |
| S17 | Lost structure member (n-of-n MuSig2) | default FROST/`msig` with threshold < n | MuSig2 groups lose funds if one member is lost (UI warns) |
| S18 | Credential misuse / replay | KB-JWT `nonce` + `aud` + `sd_hash`; status checked | issuers are trusted for what they assert |
| S19 | Credential correlation | dedicated identity UA; no anchor in v1; no PII on chain; bbs only with per-verifier pseudonyms | presentations under one subject id are linkable by the relying parties that receive them |
| S20 | Typo in a UA id; Zether UA as receiver | unregistered `to` refused; `to` ∈ native ∪ SIGNING (`UAKindNotAccepted`) | none |
| S21 | ERC-20 replay of `Transfer` ≠ `balanceOf` | `UA_POOL` sub-ledger: every native balance change emits `Transfer` (R308) | naive tools show one large `UA_POOL` holder |
| S22 | Gas repricing pushes an enabled kind over budget after funds are held | public-chain caps ≤ ~50 % of the budget (R313); budget ≤ 70 % of the chain cap | a large repricing fork can still lock a PQ/ed25519 UA on that chain until a new generation and v3 version |
| S23 | Raw-hash signing by EOAs (`eth_sign` drain) | native signers behind the registry sign EIP-712 `UAAuth` only (§6.1); `uaCancelNonce` derived-only | none on our paths |
| S24 | Native send to a derived id on non-EVM (keyless address) | derived ids shown only as URN, never in the chain's address format (R315) | a user who converts the URN by hand |
| S25 | Membership shown as consent | app rules §11.3; MuSig2 PoP proves participation | `msig`/FROST groups found on chain without member confirmations |
| S26 | Chain-id collision (7622 or any id shared by two networks): PoP, `UAAuth` or v3 signature replayed to a same-address registry/token there | `chain_uid` (genesis hash) in `pop_digest`, both EIP-712 domain salts, the cancel digest and the CREATE2 init code (R330); node binds registry, `chainUid()` and genesis hash per profile | a replica built from a copy of our profile on a colliding chain can copy our records; nothing of ours trusts it |
| S27 | EIP-7702 delegated EOA: delegate policy bypassed by the base key | none needed: the base key is root at protocol level (R331); ECDSA accepted, 1271 fallback for delegated wallets | a 7702 wallet's own policy binds only signatures that go through its delegate |
| S28 | Foreign-family native member (`hedera-native` on a non-Hedera EVM chain) | MEMBER per chain profile; `0x0003` only where `hederaNative()` (§4.2, Codex M1) | — |
| S29 | Forwarded/brokered BBS presentation as legal evidence | bbs never accepted where §9.7 applies; KB-JWT bound to the account and `intent_id` (§9.2, Codex M2) | — |

---

## 14. Gas and calldata (estimates; measured numbers replace them in `test/ua/UAGas.t.sol`)

### 14.1 Verification per check (execution gas, EVM)

Caps below are **starting values**; the deployed `verifyCap[kind]` per chain is the measured worst case (R313,
T-GAS), published in the chain profile.

| Kind | Calldata (key data + sig) | Verify | Registry overhead | Cap |
|---|---|---|---|---|
| native EOA | 65 | ~3.5 k | none (token-local) | — |
| native 1271 | per account | per account | — | 50 k / 400 k (registry: by the immutable `SubjectAccount` codehash too) |
| native behind the registry (`UAAuth`) | 65 | ~3.5 k + EIP-712 hash ~1 k | ~5 k | 50 k / 400 k for 1271 |
| `webauthn-p256` | 96 + ~300 | ~6.9 k precompile / ~200 k+ OZ fallback (measure) | ~5 k (cold call + SLOAD + hash) | 400 k |
| `p256` | 64 + 64 | as above, no JSON | ~5 k | 400 k |
| `bip340` | 32 + 64 | ~5 k + `MODEXP` lift | ~5 k | 50 k |
| `musig2-secp256k1` | 64 (stored `Q`) | as `bip340` | ~5 k + EXTCODECOPY ~2.6 k | 50 k |
| `frost-secp256k1` | 65 (stored `Y`) | ~10 k (`expand_message_xmd` SHA-256 + `MODEXP` + `ecrecover`) | ~5 k + EXTCODECOPY ~2.6 k | 50 k |
| `schnorr-bn254` | 64 + 96 | ~13 k (measured `_schnorr`) | ~5 k | 50 k |
| `musig2-bn254`, `frost-bn254` | 96 (stored) | as `schnorr-bn254` | ~5 k + EXTCODECOPY ~2.6 k | 50 k |
| `bls12381-minsig` | 256 + 128 | ~120 k (measured, chain 7622 (formerly 9000)) | ~5 k | 200 k |
| `msig` k-of-n | 4 + 36n + Σ member | Σ member verifies (≤ `c` members, stop at threshold) + ~2 k; stored-kind members + EXTCODECOPY | ~5 k | Σ of the `c` largest member caps ≤ `verifyBudget` |
| `ed25519` | 32 + 64 | ~0.3–1.2 M (Solidity, SHA-512 dominates) | ~5 k | 1.5 M |
| `mldsa44` | 2 420 sig | precompile (chain 7622 (formerly 9000)) / ≤ ML-DSA-65 cost in Solidity | ~5 k + EXTCODECOPY ~3 k | measured; ≈ 20 k with a precompile |
| `mldsa65` | 3 309 sig | 9 k-class precompile / 1.2–8.1 M Solidity (E §2.4) | ~5 k + EXTCODECOPY ~3 k | measured: ≈ 20 k (chain 7622 (formerly 9000)), Solidity worst case elsewhere (≤ 50 % of budget on public chains) |
| `fndsa512` | ~666 sig | 0.6–2.5 M Solidity (AR §2.6.2) | ~5 k + EXTCODECOPY ~1.5 k | measured, as `mldsa65` |
| `zether-*` | — (proof path) | unchanged (ZD §15) | ~5 k (`kindOf` + `authRef`) | — |

### 14.2 Registration (execution gas, bn254 base; AR §2.2.5 corrected for the new layout)

| Kind | Storage | PoP | Total (est.) |
|---|---|---|---|
| `webauthn-p256` / `p256` | record + keyOwner = 2 × 22.1 k | 7–200 k | ~55 k – 250 k |
| `bip340`, `schnorr-bn254` | 2 × 22.1 k | 5–13 k | ~55–65 k |
| `bls12381-minsig` | 2 × 22.1 k + G2MSM 22.5 k | ~120 k | ~190 k |
| `msig` (n members) | 1 × 22.1 k | none (n member lookups, 2.6 k each) | ~30 k + 2.6 k·n + event |
| `musig2-secp256k1` (n) | record + keyOwner + SSTORE2(33 B) ≈ 2 × 22.1 k + ~40 k | KeyAgg: 2 SHA-256 + 1 `ecrecover` hint check + 1 affine add per member (~10 k·n) + one BIP-340 | ~0.1 M + 10 k·n |
| `musig2-bn254` (n) | as above, SSTORE2(64 B) | n `ECMUL` + `ECADD` (~6.2 k·n) + one scaas Schnorr | ~0.1 M + 7 k·n |
| `frost-secp256k1` (t, n) | as above | n PoKs (`MODEXP` lift + `ecrecover` + `hash_to_field`, ~15 k each) + n affine adds + one FROST verify; calldata ~33·t·n + 98·n B | ~0.1 M + 15 k·n + calldata |
| `frost-bn254` (t, n) | as above | n PoKs (~13 k each) + n `ECADD` + one scaas Schnorr | ~0.1 M + 14 k·n + calldata |
| `zether-bn254` | record + keyOwner + authRef (if ≠ 0) | ~13 k + the authority's co-sign (`authPop`) | ~60–80 k + co-sign |
| `mldsa44` / `mldsa65` | 2 slots + SSTORE2 1 312 / 1 952 B ≈ 0.3 / 0.43 M | one verify (R313) | ~0.35–0.5 M + verify |
| `pqz-mlwe` | as spec E §6.3 (SSTORE2 16 KB, ~0.13 M log) | `R_REG` via precompile | spec E §9.4 |

Calldata floor (EIP-7623): binds when execution gas < 24 × non-zero bytes. With a precompile (execution small) a
PQ check is floor-priced at 40 gas/byte: an ML-DSA-65 signature is ~132 k gas of calldata (~53 k at 16 gas/byte when
a Solidity verifier makes execution dominate). With a Solidity verifier the 1.2–8.1 M execution dominates: on a
public L1 at 10 gwei and ETH $3 000 that is ≈ $36–240 per ML-DSA-65 check — enabled because the owner wants PQ
everywhere, and shown to the user before they choose a PQ kind on such a chain. On rollups and Gnosis-class chains
it is cents; on private/PoA chains with zero gas price it is not money. EIP-7825 (16.78 M per tx) bounds a single
check, hence `UA_VERIFY_BUDGET` (min(12 M, 0.7 × chain cap)) and the structure bound (R313, §6.2).

### 14.3 Why not cache in tokens (R306)

A token-local "seen" bit saves the cold `CALL` (2.6 k) on later checks but costs a 22.1 k SSTORE once: break-even
after ~9 uses per (token, UA). Not worth the extra state in v1; immutable records keep the option open.

---

## 15. Tests and vectors

### 15.1 Cross-language vectors (`smartcontracts/vectors/ua/`)

`kinds.json` — for **every** kind in §4.2 (including native rows for member refs):

- `kind`, `tag`, `TAG(kind)`, `keyData` (hex), expected `ua`, `keyHash` (group + hash);
- `chain_key`, `chain_uid`, `registry_id`, `authRef`, expected `popDigest`, `ua_msg` for `pop`, a PoP signature and its validity
  (deterministic: Ed25519; BIP-340 with zero `aux_rand`; scaas Schnorr with a fixed nonce; BLS (deterministic);
  P-256 RFC 6979; WebAuthn with a fixed authenticatorData/clientDataJSON; ML-DSA deterministic variant; FN-DSA fixed
  seed);
- purpose vectors: `purposeTag` and `ua_msg` (with `MSG_TAG`) for every purpose tag of §8.3 over a fixed digest;
- negatives: same point under two kinds ⇒ two ids and one `UAKeyInUse`; a synthetic id with zero top 96 bits ⇒
  `UAIdInNativeSpace` (constructed by asserting the check on a fabricated id); wrong-tag PoP; PoP for another chain
  or registry; **PoP for two `evm:7622` chains with different `chain_uid`** (each refused by the other, R330); PoP
  for another `authRef`; unsorted / duplicate structure members; threshold 0 or > weight; BLS
  infinity; small-order ed25519 key; high-s P-256/ECDSA; **non-canonical encodings**: ed25519 `y ≥ p` and `x = 0`
  with the sign bit set, bn254/BLS coordinates `≥ p`, P-256 `x ≥ p`, secp256k1 prefix ∉ {02, 03}, FN-DSA
  coefficient `≥ q`.

`structures.json` — `msig` with mixed members (EOA, `SubjectAccount`, `webauthn-p256`, `bip340`, `mldsa44`) and the
member digests; **`UAAuth` typed data and digests** for native members, native `authRef` and `authPop` (§6.1),
with the domain `salt` = `chain_uid` (and the same struct under another `chain_uid` as a negative);
members ∉ MEMBER (Zether, structure, foreign native kind, `hedera-native` in a non-Hedera profile,
top-96-nonzero native) as negatives.

`groups.json` — MuSig2: BIP-327 KeyAgg/sign vectors, KeyAgg hints, a registered group and its PoP; the bn254 port.
FROST: RFC 9591 Appendix E.5 FROST(secp256k1, SHA-256) vectors, DKG transcripts with PoKs from the ZF
`frost-secp256k1` crate, a bad PoK, `Y ≠ Σ C_i0`; the FROST(bn254, keccak256) ciphersuite's vectors.

`metatx3.json` — `UAMetaTransaction` typed data (domain `salt` = `chain_uid`), digests and auth blobs per kind (v3
KAT, like `MetaTxKat`).

`derivation.json` — seed → per-kind keys for §8.1 paths (BIP-39 test mnemonic), including the role paths of R300 and
the PQ HKDF.

Consumers that must pass the same files: Foundry (`test/ua/*`), clientkeys (Jest), zether-prover (Rust),
scaas-node (Rust kind library), Odoo (`dms_blockchain/tests/test_ua_vectors.py`), and each family's tests when its
stream lands (Move, Soroban, CosmWasm, Solana). The files are generated by one script (`smartcontracts/scripts/
gen_ua_vectors.*`) from independent implementations (noble/`@noble/curves` in JS, `k256`/`p256`/`ed25519-dalek`/
`blst`/`ark-bn254` in Rust); a vector is accepted only when both agree. **Single-implementation kinds** — the scaas
Schnorr transcript (bn254/BLS), bn254 `mapToG1`, `musig2-bn254` (our BIP-327 port), FROST(bn254, keccak256),
`pqz-mlwe` — have no independent second implementation: for them "both agree" is self-consistency only, stated as
such in the vector files and the audit scope.

### 15.2 EVM tests

| Id | Test |
|---|---|
| T-REG-1 | every kind: register with the vector PoP ⇒ record, event, `keyOwner` |
| T-REG-2 | every negative vector reverts with its error |
| T-REG-3 | the same `register` calldata from two senders ⇒ identical storage diff (R295) |
| T-REG-3b | the same `pop` with a different `authRef` ⇒ `UAPoP`; a valid `pop` for `authRef` without the authority's `authPop` ⇒ `UAUnauthorized(authRef)`; non-Zether with `authRef ≠ 0` or non-empty `authPop` ⇒ `UAAuthRef` |
| T-REG-4 | gen-2 registry sees gen-1 records; `UAKeyInUse` across generations; gen 2 refuses (`UAKindDisabled`) every kind or keyHash group gen 1 enables, so registering in gen 1 after gen 2 for a shared group is impossible by construction; `msig` re-enabled in gen 2 gives an identical record; chain-7622 (formerly 9000) `pqz-mlwe` with an `mldsa65` `authRef` in gen 1 |
| T-REG-5 | invariants: registry balance 0, no record ever changes, `uaOf(record.keyData) == ua` |
| T-REG-6 | MuSig2: wrong `Q`, a bad hint, unsorted keys ⇒ `UAKeyData`/`UAPoP`; FROST: one bad PoK, `Y ≠ Σ C_i0`, a commitment vector of the wrong length ⇒ refused; the M1 attack (own key as `Q` with the board's list) ⇒ refused |
| T-AUTH-1 | `requireAuthorized` per kind × purpose; wrong purpose fails; wrong kind's tag fails |
| T-AUTH-1b | a Zether UA (any `authRef`) via `requireAuthorized` ⇒ `UAUnauthorized` |
| T-AUTH-2 | `msig` threshold/weights, duplicate member, unregistered member, nested structure, member ∉ MEMBER refused; a `MemberSig` after the threshold ⇒ `UAUnauthorized` |
| T-AUTH-3 | native paths: EOA low-s over `UAAuth` (a raw-digest signature fails), 1271 gas caps incl. the `SubjectAccount` codehash in the registry, ERC-7739 wallet against `eip712Domain()` (incl. `salt`); **EIP-7702 delegated accounts** (R331), in the registry and v3's native path: ECDSA by the base key passes; a 1271 signature through a delegate that implements it passes within 50 k; a delegate without 1271, a wrong magic value, a reverting or gas-exhausting delegate ⇒ fail; a designator-length code that is not `0xef0100…` is treated as a contract (1271 only) |
| T-CHAIN | two registries with the same `block.chainid` and different `chainUid` (and v3 clones bound to them): a PoP, a native `UAAuth` and a v3 signature from one fail on the other; `eip712Domain()` returns `fields = 0x1f` and `salt = chainUid`; the constructor refuses `chainUid = 0` (R330) |
| T-MEMBER | an `msig` with a `hedera-native` member registers in a `hederaNative` registry and is refused (`UAMemberUnknown`) in every other profile (Codex M1) |
| T-AUTH-4 | 63/64 starvation and out-of-gas inside every capped verifier `staticcall` ⇒ the check reverts, never passes; malformed/short returndata ⇒ revert |
| T-FROST | RFC 9591 vectors pass `UAFrostSecp256k1Verifier`; the same signatures fail the BIP-340 verifier and vice versa |
| T-FUZZ | **differential fuzzing** of the pure-Solidity ML-DSA-44/65, FN-DSA-512 and ed25519 (incl. SHA-512) verifiers against at least one independent implementation (e.g. the precompile's C core / `pqcrystals`, `ed25519-dalek` strict): accept/reject parity on mutated signatures, keys and messages; run before each generation is deployed (a permissive verifier is permanent, S15) |
| T-ZET-1 | Zether suite green with tagged UAs; `authRef` 0/native/derived; same-curve BLS refused; `zkCovered` rules |
| T-V3-1 | v3 equivalences (`uaTransfer ≡ uaExecute`, …) as TW2 §10.1; the v2 address-typed path and the `ua*` path share `_uaNonce[pad(addr)]` |
| T-V3-2 | invariants: `totalSupply == Σ balanceOf(native incl. UA_POOL)`, `balanceOf(UA_POOL) == Σ _uaBalance`, replaying `Transfer` logs equals `balanceOf` for every native holder; `UATransfer` emitted iff a side is derived |
| T-V3-3 | `to` unregistered ⇒ revert; `approve`/`trade` in any `ua*` function, native or derived `from` ⇒ `MetaTxUnknownOp`; `FeeRecipientIsPayee` with a padded `feeRecipient` |
| T-V3-3b | `to` = a Zether UA (`zether-*`, `pqz-mlwe`) ⇒ `UAKindNotAccepted`; `to` = `UA_POOL` ⇒ `UAPoolNotPayable`; `uaCancelNonce` with a native `ua` ⇒ refused |
| T-V3-4 | `--sizes` ≤ 24 576 for every v3 implementation |
| T-GAS | `UAGas.t.sol` replaces §14 estimates and produces each chain profile's `verifyCap`s; every enabled kind's worst-case verify ≤ its cap ≤ `verifyBudget` (public chains ≤ ~50 %); register spec E's two default `authRef` shapes (`{mldsa65, p256} t=2`, `{mldsa65 ×3} t=2`) on chain 7622 (formerly 9000) and the hybrid on a precompile-less chain; the PQ treasury on a precompile-less chain is refused; a structure over the bound is refused |

### 15.3 Off-chain

clientkeys: `UAKey` cannot sign raw digests (API test); derivation paths disjoint from native paths (property test
over kinds × accounts); `deriveConfKey` refuses other `use`; no BLS-kind key equals a Zether conf scalar (§8.1);
MuSig2/FROST sessions against `groups.json`; URN form refused as a native send target. Node: native verification of
every single-key kind matches the Foundry verdicts on all vectors; canonical `from` (20-byte vs padded) shares one
V6 bucket; pre-gossip rejection of bad UA signatures (garbage PQ intents never reach simulation); cache behaviour.
Odoo: `ua_id` canonicalised on write (padded EOA ⇒ 20-byte form, upper-case ⇒ lower) so the UNIQUE holds;
`pg_constraint` shows the `blockchain_ua` UNIQUE (CLAUDE.md §5.2); vectors pass in Python.

---

## 16. Streams

Constraints: at most three sub-agents, one heavy build/gate at a time (owner). Order of families follows the owner
order (EVM, Cosmos, Hedera, Soroban, TON, Sui, Aptos, Solana).

| Stream | Content | Depends on | Gate |
|---|---|---|---|
| **F0** | kind table libraries (Solidity `UAKinds.sol`, JS `ua.js`, Rust `scaas-ua` crate, Python `ua.py`) incl. closed sets, canonical encodings, `UAAuth`; vector generator, `vectors/ua/*` incl. `groups.json` | — | all four consumers pass the same vectors |
| **F1** | EVM `UARegistry` gen 1 (chain 7622 (formerly 9000): deployed after F9, §6.5), verifiers (P-256, WebAuthn, BIP-340, MuSig2 KeyAgg, FROST(secp256k1) RFC 9591 + DKG check, bn254/BLS Schnorr incl. MuSig2/FROST-bn254, BLS, ed25519 (Solidity), msig), `chainUid`/`hederaNative` profile immutables and 7702 classification (R330, R331), Zether re-point (§12), zether-prover + clientkeys Zether changes, deletes | F0 | T-REG, T-AUTH, T-CHAIN, T-MEMBER, T-FROST, T-FUZZ (ed25519), T-ZET green; dev chains redeployed |
| **F2** | MetaToken v3 (UA ledger, `UAMetaTransaction`, `ua*` functions) for the three tiers; factory v2 versions; Hedera children | F1 | T-V3, sizes, gas report |
| **F3** | clientkeys `UAKey`, derivation (§8.1), no-raw-sign API, role path for `SubjectAccount` keys, **BIP-327 MuSig2 and RFC 9591 FROST signers** (incl. DKG; bn254 port/ciphersuite), app screens 5/14, the approvers wizard with member confirmations (APP A3), URN display | F0 (F1 for registration) | clientkeys tests on BIP-327 / RFC 9591 / `groups.json`; app e2e on dev chain |
| **F4** | VC layer (no contract in v1, §9.4): KB-JWT `scaas-ua` signing and verification in the shared libraries, evidence-bundle format, DEK-encrypted relying-party attachments, attester flow into `ComplianceRegistry` (with AS1) | F1, AS1 | Odoo/app round trip |
| **F5** | node: `scaas-intent/1.3` `evm.ua_meta_tx` (UA bodies only), native verification of every single-key kind and structures, canonical ids, `ua_metatx` jobs, indexer events incl. `UA_POOL` pairing, config incl. the per-profile binding of registry address, `chainUid()` and the RPC's genesis hash (R330) | F0, F2 | mesh e2e on dev chains incl. a 1.2 node in the mesh |
| **F6** | Odoo (parent repo): `blockchain.ua`, address forms, signed ops, portal registration, credentials model | F1, F3 | Odoo tests + `pg_constraint` |
| **F7** | Cosmos: `ua-registry` contract, 32-byte passkey owners shown as URN (R315), `owner_kind`, `bip340`/MuSig2/FROST-secp | F0 | family tests on vectors |
| **F8** | Soroban (role `kindNo` 18), then TON (no registry; `set_key` with key signature), Sui, Aptos, Solana (passkey owner = UA id, `owner_kind`, `["ukey", keyHash]`) — one family per change | F0, family streams | family tests on vectors |
| **F9** | PQ kinds (`mldsa44/65`, `fndsa512`): pure-Solidity verifiers for every EVM chain (one audited implementation, vectors shared with the precompile's C core), precompile path on chain 7622 (formerly 9000), measured per-chain caps (R313); `pqz-mlwe` registration hook with spec E. Chain 7622's (formerly 9000) gen 1 waits for F9; on other chains PQ kinds landing after F1 arrive as registry gen 2 (§6.5) | F0, spec E | `UAGas.t.sol` caps; T-FUZZ (ML-DSA, FN-DSA); chain-7622 (formerly 9000) e2e |
| **F10** | DEX/mandate UA support (§17 Q4/Q5), `OrderBookDex` 1271 gas cap fix | F2 | DEX suite |

---

## 17. Owner to confirm

Decisions taken by this spec on the open design points, each with its default; a different answer changes only the
rulings named. **Rev 1.1:** items 1, 6, 9, 11 are answered by the owner (marked). **Rev 1.2 (owner 2026-10-06): all remaining defaults (2, 3, 4, 5, 7, 8, 10, 12, 13, 14) accepted as decided** — no open items remain. **Rev 1.3:** no new
questions; review fixes sharpen Q3 (MuSig2/FROST defences now checked on chain, owner 2026-10-07), Q13 (derived ids
shown as URN, never as a native address) and Q14 (bbs gated on per-verifier pseudonyms) without changing the
decisions. **Rev 1.4:** no new questions; the Codex fixes sharpen Q10 (`chain_uid`) and Q14 (bbs not accepted for
legal-recourse evidence) without changing the decisions.

1. **Identity vs rotation (R302). — Confirmed by the owner (rev 1.1).** Decided: a UA is immutable (single-key or policy hash); rotation and membership
   changes = new UA + move funds; stable identity = `SubjectAccount` (b). Alternative: a rotatable "policy" kind
   (id = hash of the first policy, current policy in the registry with a timelock) — rejected for v1 because it
   brings back an admin-like mutable record per account.
2. **Zether `authRef` immutability (R305).** Decided: immutable (RS2-9 kept). Alternative: timelocked
   `rotateZetherAuth` signed by the current `authRef` (AR §2.7.1 design with guardian veto limits).
3. **Rogue-key approach (R296).** Decided per kind: per-member registration (`msig`), KeyAgg coefficients
   recomputed on chain + aggregate PoP (MuSig2), DKG PoKs and `Y = Σ C_i0` checked on chain + group PoP (FROST),
   threshold ECDSA = native EOA (`bls12381-multi` cut in rev 1.3).
4. **DEX with UA makers (§5.4).** Decided: not in v1; UA holders trade through native accounts or option (b). Needs a
   UA-ledger allowance model (`uaApprove` to contracts) and `OrderBookDex` v2 with `bytes32 maker`.
5. **`MandateWallet` with a UA owner/delegate.** Decided: not in v1 (a `MandateWallet` v2 calling
   `requireAuthorized`).
6. **Derivation purpose and coin level (§8.1). — Owner: purpose `7622'` (rev 1.1).** Decided: one chain-independent UA tree (same UA
   on every chain). Alternative: per-coin trees (unlinkable across chains, different ids per chain).
7. **Regulated (AS) tokens and UA receivers.** Decided: AS regulated tokens stay native-only; a `bytes32`-keyed
   compliance check would be an AS amendment.
8. **On-chain registration gate (S6).** Decided: none in v1; sponsorship limits at the node. Alternative: an
   immutable `IRegistrationPolicy` (invite / attested) per registry generation (AR §2.3c).
9. **ed25519 and PQ kinds on public EVM (§7.3, R313). — Owner: enabled everywhere (rev 1.1)**, pure-Solidity
   verifiers where no precompile exists, single-transaction checks under `UA_VERIFY_BUDGET`; a kind over budget is
   disabled on that chain, never registrable-but-unusable.
10. **PoP chain binding (R295).** Decided: bound to chain (`chain_key` **and** `chain_uid`, R330, rev 1.4) and registry
    (one signature per chain). Alternative:
    chain-independent PoP (one signature registers everywhere; anyone can replicate a registration to other chains).
11. **Second typehash for v3 (R309). — Confirmed by the owner (rev 1.1).** Decided: `UAMetaTransaction` with its own typehash — an explicit exception to
    R140.
12. **TON (R314).** Decided: no registry; wallet-bound derived keys; chain-wide keyHash uniqueness not enforced.
13. **Cosmos 32-byte passkey accounts and Solana passkey owner = UA id (R315).** Decided: yes, at the family
    streams (breaking for dev accounts).
14. **Credential formats (§9.2).** Decided: SD-JWT VC default, BBS optional; subject ids `did:pkh` / `urn:scaas:ua:v1`;
    no DID method of our own.

---

## 18. Review disposition (review 1, rev 1.2 → rev 1.3)

Source: `docs/reviews/specs/2026-10-06-universal-account-review-1.md` (FIX-THEN-GO). No finding was found wrong on
verification; one is overridden by the owner with an alternative fix, two are applied in part where an owner
ruling keeps something the review proposed to cut.

| # | Finding | Disposition | Where |
|---|---|---|---|
| H1 | Zether `authRef` not covered by the PoP (front-run freeze/downgrade) | fixed: `pop_digest` binds `authRef` (0 for non-Zether); the authority co-signs `authPop` — under a dedicated purpose `authref` rather than `pop`, so the wallet shows the consent for what it is; client checks `recordOf(ua).authRef`; T-REG-3b | R295, R305, §6.1, §6.2 steps 5–7, §8.3, §12.3, S5 |
| H2 | Kind sets not closed per role (Zether `to` lock; Zether via `requireAuthorized`; undefined member kinds) | fixed: closed SIGNING / ZETHER / MEMBER sets with their enforcement points; `UAKindNotAccepted`; T-V3-3b, T-AUTH-1b | R303, §4.2, §5, §6.1, §6.2 step 4, §7.2, S20 |
| H3 | PQ cap = budget makes hybrid/PQ `msig` unregistrable | fixed: per-chain, per-kind measured `verifyCap` constructor immutables published in the profile; sum check kept; PQ treasury stated as precompile-only; T-GAS registers E's shapes | R313, §6.1–§6.3, §7.3, §14.1, T-GAS, Amends (E) |
| H4 | Raw-digest native signatures (`eth_sign`), purpose ignored | fixed: EIP-712 `UAAuth(ua, purpose, digest)` under `("SCaaS UARegistry", gen, chainId, registry)` + `eip712Domain()` for every native signer behind the registry; `uaCancelNonce` restricted to derived `ua`; `UAAuth` vectors | R301, §5.2, §5.3, §6.1, §7.1, §7.2, §8.3, §8.4, §15.1, S23 |
| M1 | MuSig2/FROST kinds carry unverifiable data; collapse into `bip340`/`schnorr-bn254` | **owner override (2026-10-07): kinds kept**, made sound instead: BIP-327 KeyAgg recomputed on chain from the registered list (hint points via `ecrecover`), FROST group key = Σ PoK-proven DKG commitments checked on chain, one aggregate PoP each; attestation-only list; RFC 9591 FROST signatures verified by an RFC 9591 verifier (FROST(secp256k1, SHA-256); FROST(bn254, keccak256) defined) with RFC/BIP vectors; BIP-327 and RFC 9591 signers in F3; app display rules (also for `msig` membership ≠ consent) | R296, §4.2, §4.3, §6.2 step 6, §7.2, §8.1, §11.3, §14, §15, F1/F3, S3, S25 |
| M2 | Generations break uniqueness; `pqz-mlwe` unregistrable if F9 after F1 | fixed: gen 2 enables only kinds and keyHash groups absent from every predecessor's enabled set (structures may repeat: identical records); chain 7622's (formerly 9000) gen 1 deploys after F9; T-REG-4 extended | §6.5, F1, F9, Amends (E), T-REG-4 |
| M3 | `originHash` in the id ⇒ one origin per passkey forever | fixed, decided **`rpId` only** (`x ‖ y ‖ rpIdHash`); a sorted origins root was rejected because origins would still be frozen at creation; residual and deployment rule recorded | §4.2, §7.2, S9, Amends (APP) |
| M4 | Node intake, envelope skew, non-canonical `from`, `from_kind` | fixed: native verification of every single-key kind and structures (only 1271 simulated); 1.3 only for `evm.ua_meta_tx`, old nodes Ignore per R118 on the named topic; canonical ids; `from_kind` dropped | R291, R316, R317, §11.1, §15.3 |
| M5 | Cross-ledger moves without ERC-20 `Transfer` | fixed: `UA_POOL` sentinel sub-ledger with `Transfer(sender, UA_POOL)` / `Transfer(UA_POOL, to)`; v2 entry points kept and sharing the nonce map; `approve`/`trade` refused in `ua*` for native `from` too; padded `FeeRecipientIsPayee` | R308, §5.3, §11.2, S21, T-V3-1/2/3 |
| M6 | Non-EVM burn addresses; id-shape dispatch on 32-byte families | fixed: derived ids shown/encoded only as `urn:scaas:ua:v1:…` (never the account HRP / base58); explicit `owner_kind`, dispatch by kind | R291, R315, §5.5, §6.6, §11.3, S24 |
| M7 | VC layer: unlinkability, holder binding, erasure overclaim, Odoo stores the link | fixed in part: dedicated identity UA; KB-JWT mapping with `alg: "scaas-ua"`; §9.5 reworded; relying-party attachments DEK-encrypted, holder credentials never in Odoo. "Drop bbs" **not taken** (owner default Q14 keeps it): bbs is gated on per-verifier pseudonyms instead | R311, §9.2, §9.3, §9.5, §9.6, §11.4, S19 |
| M8 | `UAAttestations` digests undefined | fixed: **deferred from v1** (decided); the EIP-712 `Anchor` + revocation digests a reinstatement must use are stated; F4 and T-ATT drop the contract | R310, §9.4, §9.7, §8.3, F4 |
| M9 | Test gaps | fixed: T-REG-3b, T-V3-3b, non-canonical negatives, T-REG-4 cross-generation, cap formula with PQ members (T-GAS), T-AUTH-4 (63/64, fail closed), T-FUZZ differential fuzzing of the Solidity ML-DSA/FN-DSA/ed25519 verifiers; single-implementation kinds named | §15.1, §15.2, S15 |
| L1 | Tag reuse; `purposeTag` ambiguity | fixed: `MSG_TAG` prefix in `ua_msg`; `purposeTag = keccak256(string)` used as-is | R301, §4.1, §7.1 |
| L2 | Canonical encodings | fixed: one rule, non-canonical ⇒ `UAKeyData` | R299, §4.2, §8.2 |
| L3 | Registry 1271 caps miss `SubjectAccount` | fixed: clone codehash immutable in the registry (400 k) | §6.1, §6.3, §14.1, T-AUTH-3 |
| L4 | Zether `x` reused as same-curve BLS key | fixed: residual recorded + clientkeys test | §8.1, §15.3, S12 |
| L5 | `chain_key` from a constructor string | fixed: computed from `block.chainid` (`evm:<chainid>`) | R295, §6.3 |
| L6 | TON `set_key` is consent, not PoP | fixed: `set_key` carries a signature by the bound key | R314, §6.6, F8 |
| L7 | Budget per chain; repricing | fixed: `min(12 M, 0.7 × chain cap)`; public-chain caps ≤ ~50 %; residual S22 | R313, §14.2, S22 |
| L8 | Cross-spec drift (E R281, S4F R253, Amends, App R176) | fixed: Amends rows for D, E, APP (pointers; those specs' text follows in their streams) | Amends |
| L9 | Odoo `ua_id` canonical | fixed | R318, §11.4, §15.3 |
| L10 | Over-engineering to cut | fixed in part: cut `bls12381-multi` (`0x0121` reserved), `from_kind`, per-member verify-time `kindOf`, duplicated `msig` key data; `UAAttestations` deferred (M8). **Kept:** MuSig2/FROST (owner 2026-10-07, M1) and `mldsa44` (named by E R281; same parameterised ML-DSA verifier) | R297, §4.2, §6.4, §7.2, §11.1, §14 |

Counts: 23 findings — **20 fixed as proposed** (H1–H4, M2–M6, M8, M9, L1–L9), **2 fixed in part** (M7, L10),
**1 owner override with an alternative fix** (M1), **0 rejected**. Owner rulings of 2026-10-07 recorded: MuSig2/FROST
kept and made checkable (R296, §4.3); Soroban `scaas-account` role keys use `kindNo` 18 (R300, §8.1).

---

## 19. Codex review disposition (rev 1.3 → rev 1.4)

Source: `docs/reviews/specs/2026-10-06-universal-account-codex-review-1.md` (FIX-THEN-GO). Each finding was checked
against this spec, spec E and the code at `main`; one premise (H2's "bypass") is verified wrong and gets an
alternative rule, the rest are applied as proposed. The owner ruling of 2026-10-07 (private chain id 9000 → 7622,
9000 being Evmos Testnet) is folded in throughout.

| # | Finding | Verified | Disposition | Where |
|---|---|---|---|---|
| H1 | PoP and native `UAAuth` bind `evm:<chainid>` only; same-chain-id networks replay them | **yes**: R295 / §6.3 bound `chainKeyHash` + registry address only; E §2.7 records 9000 = Evmos Testnet and E R270 names F's PoPs; derived-UA v3 signatures had the same gap (the v3 domain had no chain uid) | **fixed as proposed**, extended to every digest F defines: `chain_uid` (genesis hash, constructor immutable, `chainUid()`) in `pop_digest`, the registry EIP-712 `salt`, the v3 `UAMetaTransaction` `salt` and the `metatx-cancel` digest; it also separates CREATE2 addresses. Limit stated: the EVM cannot prove its genesis hash, so a replica built from a copy of our profile is possible but trusted by nothing of ours (tokens bind the registry, the node binds registry + `chainUid()` + genesis hash). Vectors for two `evm:7622` chains | R295, **R330**, R309, §6.1, §6.3, §8.3, §12.3, S26, §15.1, T-CHAIN, F1, F5, Q10, Amends (E) |
| H2 | EIP-7702 delegated EOAs bypass their delegate's policy if UA code inherits v2's "7702 is not a contract" | **in part**: `MetaTxCore._isContract` (`smartcontracts/evm/src/metatx/MetaTxCore.sol:123-131`) does classify the designator as not a contract and `_requireValidSignature` (`:135-148`) then uses ECDSA only, and F did not pin a rule. **The attack premise is wrong**: a 7702 account's base key is root at protocol level (it can transact directly, re-delegate or clear the delegation), so a stolen base key drains it whatever our contracts accept; neither "1271 only" nor "reject 7702" adds security | **fixed with an alternative rule**: classification by code at verify time; 7702 designator ⇒ ECDSA by the base key, else ERC-1271 through the delegate (50 k cap), so delegated wallets' session-key/passkey signatures work; other code ⇒ 1271 only; member kind labels never dispatch. v2 unchanged (sound, R303). T-AUTH-3 7702 cases added as asked | **R331**, §4.2 (0x0001), §5.3, §6.1, §7.1, S27, T-AUTH-3 |
| M1 | `hedera-native` (0x0003) admitted as an `msig` member on non-Hedera EVM chains | **yes**: MEMBER listed `0x0001`–`0x0003` for every EVM chain; HIP-632 exists only on Hedera | **fixed as proposed**: MEMBER is per chain profile; `0x0003` only where the registry's `hederaNative` immutable is set; negative vectors and T-MEMBER | §4.2 (0x0003, MEMBER), §6.1, §6.2 step 4, §6.3, §6.6, S28, §15.1, T-MEMBER |
| M2 | BBS anonymous holder binding contradicts the §9.7 evidence model | **yes**: §9.2 allowed bbs presentations with no account-signed proof; §9.7 relied on an account-signed VP | **fixed as proposed** (the reviewer's second option): bbs presentations carry `aud`/`nonce` but are never accepted where §9.7 applies; legal-recourse workflows require the R311 KB-JWT with `nonce` = deal reference / `intent_id` | §9.2, §9.7, S29, Q14 note |
| L1 | `UAAuth` domain comment omits the ERC-5267 `salt` | **yes**: `eip712Domain()` returns `salt` but the domain listed four fields | **fixed as proposed**: domain `salt = chainUid`, `fields = 0x1f`; clientkeys checks the salt against the chain profile before signing; vectors pin it | §6.1, §15.1, T-CHAIN, T-AUTH-3 |

Counts: 5 findings — **4 fixed as proposed** (H1, M1, M2, L1), **1 fixed with an alternative rule** after its attack
premise was verified wrong (H2), **0 rejected**. New rulings: R330 (chain uid), R331 (EIP-7702 / native
classification). Owner rulings unchanged; owner ruling recorded: private chain id 7622 (formerly 9000).
