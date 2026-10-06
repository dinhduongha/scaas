# Universal Account (UA): kind-tagged account identifiers, per-chain registry, per-kind verifiers, optional credentials (component spec F)

Status: draft rev 1, 2026-10-06. Component spec **F**. Short name **UA**. Code at `scaas` `main` 5257f69. **Nothing in
this spec is built**; the current `UniversalAccountRegistry` (Zether-only) is replaced by it (§12).
Rulings: **R290–R318** (§2). R150–R172 belong to the app spec, R180–R199 to spec B (TSS), R200–R217 to spec A (AS),
R230–R247 to spec C (OPS), R250–R268 to spec D (S4F), R270–R289 to spec E (PQ Zether). The owner rulings of
2026-10-06 (eight items) are folded in and marked `(owner)`; everything else is a decision of this spec.

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

Amends (status changes and pointers only; the text of those files is rewritten by the stream named):

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` §8.6, §9, glossary "UA" | pointers to this spec (done with this spec); §14.5 replaced at stream F1 |
| ZD | §11.2, `ZetherTypes.toUA`, `AuthScheme` | **superseded** by §4, §6, §12 (R290, R291, R305, R312) |
| R3 | R33 PoP binding `msg.sender` | **superseded** by R295 (PoP binds chain + registry + UA, not the caller) |
| AS | R206 "UA registry not extended" | **kept**: compliance flags stay in `ComplianceRegistry`; the VC layer feeds it (R310) |
| S4F | §3 "existing dual uses for F to rule on" | ruled by R300 (separate derivation for every kind and account role) |
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
  Cosmos secp256k1) are zero-padded into the same 32-byte space, so the two spaces are disjoint by construction.
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
- **R295** **Proof of possession is kind-tagged and binds chain, registry and UA — not the caller.**
  `pop_digest = keccak256(POP_TAG ‖ keccak256(chain_key) ‖ registry_id ‖ ua)` where `POP_TAG =
  keccak256("scaas.ua.purpose.pop.v1")`, `registry_id` the 32-byte registry address/id, then signed as a tagged
  message of the kind (R301). `register` derives no state from `msg.sender`, so anyone may submit it (gasless,
  relayable); front-running yields the identical record. Supersedes R33's `msg.sender` binding. — AR §2.2.2: binding
  the caller blocks gasless onboarding and adds nothing once the record is caller-independent. — A future field taken
  from `msg.sender` would turn front-running into capture; a storage-diff test guards it (§15.2 T-REG-3).
- **R296** **Rogue-key protection, decided per aggregate kind:**
  | Kind | Approach | Why |
  |---|---|---|
  | `msig` (independent signatures, weighted threshold) | **per-member registration**: every member is a native id or a registered single-key UA (each with its own PoP) | no key aggregation happens, so there is no rogue key; members' keys are still proven once |
  | `bls12381-multi` (aggregated pk at verify time) | **per-member PoP** via member registration (`bls12381-minsig` UAs); the verifier aggregates registered members only | the IETF BLS PoP scheme; aggregation coefficients would cost a G2 MSM per member per verify |
  | `musig2-secp256k1`, `musig2-bn254` | **key-aggregation coefficients** (BIP-327 KeyAgg; bn254 port with the same tags) **plus** one aggregate PoP | coefficients defeat rogue keys inside the scheme; the PoP proves the group actually signs |
  | `frost-secp256k1`, `frost-bn254` | **PoK of each participant's secret in the DKG** (FROST KeyGen round 1) **plus** one group PoP | RFC 9591 leaves DKG out; the paper's DKG PoK is the standard defence |
  | threshold ECDSA (MPC providers) | not a kind: the output is an ordinary ECDSA signature by an address ⇒ **native EOA** | the chain cannot tell, and need not |
  — Each defence is the one native to the scheme; nothing is invented. — A MuSig2/FROST group key produced with a
  broken DKG is the provider's problem; the registry only sees one key.
- **R297** **Structures commit to their members; nesting is one level.** `msig` and `bls12381-multi` key data list
  members by `(kind, id, weight)`, strictly sorted by id; a member may not itself be a structure. — Bounded gas, no
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
  `mldsa65`, `fndsa512`. All kinds over the same group share the namespace, so `schnorr-bn254`, `frost-bn254`,
  `musig2-bn254` and `zether-bn254` can never register the same point, nor `webauthn-p256` and `p256` the same key. —
  Kind-tagged keyHash would let the same key register under two kinds. — Structures have no keyHash (members do).
- **R300** **Rules the dual key uses listed by S4F §3:** the EVM seed key `m/44'/60'/0'/0/i` is the EOA only; a
  `SubjectAccount` `SECP256K1` key, every Sui/Aptos/Solana subject-account owner key that is not the native address
  key, and every derived kind come from the UA tree `m/7225'/0'/<account>'/<kind>'/<i>'` (§8.1). Existing dev
  accounts rotate (`rotateKey`) at migration (§12). — A key that is both an EOA and an account key is two purposes.
  — One more derivation per role; wallets show the role.
- **R301** **Tagged message:** every UA signature is over
  `ua_msg = keccak256(keccak256(kind_tag) ‖ keccak256(purpose_tag) ‖ digest)` (96-byte preimage, BIP-340-style
  tagged hashing), where `digest` is the operation's own domain-separated digest (EIP-712 on EVM, the family digest
  elsewhere). Purposes are listed in §8.3. The kind's scheme then signs `ua_msg` its own way (§7.2). Native kinds keep
  their wallet-native signing (EIP-712 / family envelope) untouched. — Cross-kind and cross-purpose replay die at the
  hash; native wallets keep displaying what they sign. — One extra keccak (~60 gas).

### 2.4 Functions, balances, verification

- **R302** **No rotation inside a UA; no rotatable policy kind in v1.** A UA is immutable: key data, members and
  threshold are in the id. Rotation = new UA + move funds (a transfer, or a confidential transfer to the new Zether
  UA). A stable identity across rotation is `SubjectAccount` (R307) or another native contract account. — Immutable
  records make tokens' view of the registry cacheable and the registry admin-free. — Membership changes of a corporate
  `msig` require moving funds; owner to confirm (§17 Q1).
- **R303 (owner)** **Each function accepts the kinds it needs** (§5): native-address functions (v1/v2 tokens, DEX,
  mandates) keep accepting native ids only; the new UA-ledger functions on MetaToken v3 accept any registered kind as
  `from` and any native or registered id as `to`; Zether functions accept Zether kinds only, registered first. — No
  existing ABI changes; deployed v1/v2 clones stay valid. — UA holders need v3 tokens (§5.3).
- **R304** **The registry is monotonic and admin-free**: no unregister, no freeze, no status, no owner, non-upgradeable,
  holds no value. A record never changes after `register`. — Tokens may then rely on a record forever (R306) and
  nobody can repoint a victim's key (AR §2.3a). — A compromised derived key is handled like a compromised EOA: move the
  funds; compliance freezes stay token-level (AS).
- **R305** **Zether kinds bind only the encryption key; authorization is an immutable `authRef`.** `zether-bn254` /
  `zether-bls12381` id = `keccak256(keccak256(tag) ‖ Y)`; the record carries `authRef` = `0` (self: the ZK proof is
  the authorization; owner ops are Schnorr by `x` under the Zether tag) or the id of a native account or a registered
  signing UA. `authRef` may not be a Zether UA; a BLS UA on the same curve as `Y` is refused (canon C6.1). Supersedes
  `AuthScheme` (8 values) and `link_eth`/`links`. — The token derives the receiver UA from `Y` in the payload with one
  keccak and no lookup; spend authority stays separate from decryption (`survivesEncKeyLeak` for `authRef ≠ 0`). —
  `authRef` cannot rotate (RS2-9 kept); owner to confirm (§17 Q2).
- **R306** **Verification goes through the registry; small key data travels in calldata, large key data is stored
  once.** `requireAuthorized(ua, purpose, digest, auth)` does the lookup and the per-kind check in one call. For kinds
  with key data ≤ 256 bytes and for structures, `auth` carries the key data and the registry checks
  `keccak(tag ‖ keyData) == ua`; for PQ kinds the registry stores the public key at registration (SSTORE2 code pointer)
  and `auth` carries only the signature. Tokens do not cache records in v1 (one call per check); because records are
  immutable (R304) a cache would be safe, and is allowed in a later token version if measured worthwhile. — Calldata
  beats storage for small keys (a 64-byte key costs ~1 k gas in calldata vs 4.2 k for two cold SLOADs); PQ keys are
  1.3–2.6 KB (21–42 k gas each time in calldata vs ~3 k to read back). — None.
- **R307 (owner)** **`SubjectAccount` is option (b), kept as built**: an optional ERC-1271 smart account (P-256 +
  secp256k1 keys, guardian recovery, Merkle batch) for users who need a stable address across key rotation, guardian
  recovery, or compatibility with third-party contracts. It is a native id; it never registers. **Default = UA kinds
  verified directly by our tokens.** — Rotation and recovery are account features, not identifier features. — Two
  ways to hold a passkey; the app offers the default first (§11.3).
- **R308** **EVM balances of derived UAs live in a separate `bytes32` ledger on MetaToken v3** (`_uaBalance[ua]`), never
  in an address projection; native ids in UA-ledger functions read and write the ERC-20 ledger. `totalSupply` covers
  both. Movements that touch the UA ledger emit `UATransfer(bytes32 from, bytes32 to, uint256 value)`; ERC-20
  `Transfer` stays native ↔ native only. — Projecting `bytes32 → address` re-creates the 2^80 collision (R291). — Naive
  ERC-20 indexers do not see UA balances; our indexer does (§11.2).
- **R309** **The UA-ledger meta-transaction has its own struct and typehash** (`UAMetaTransaction`, `from`/`to` as
  `bytes32`), domain `("SCaaS MetaToken", "3", chainId, clone)`, and the same nine-step pipeline (TW2 §3.2). This is a
  deliberate exception to R140 ("no second typehash"): R140 forbade a second hash of the **same** struct; this is a
  different struct whose `from` cannot be an `address`. — An `address`-typed `from` cannot carry a 32-byte id. —
  Clients build two struct shapes (vectors in §15).

### 2.5 Credentials, SubjectAccount, migration, families

- **R310 (owner)** **The VC/eKYC layer is optional and never mandatory.** Any account, native or derived, may attach
  Verifiable Credentials; nothing in a token or the registry requires one. Contracts consume credentials only through
  `ComplianceRegistry` flags set by an attester that verified them off chain (AS R206); the optional on-chain anchor
  (`UAAttestations`, §9.4) stores commitments only. — "I register my EOA and here is my VC" works with zero chain
  changes; contracts never parse VCs. — An anchor reveals that a UA holds *some* credential from *some* issuer (§9.5).
- **R311** **Holder binding = a presentation signed by the account itself under purpose `vp`**, with audience and
  nonce from the relying party; credential subjects are `did:pkh` (CAIP-10) for native ids and
  `urn:scaas:ua:v1:<kind>:<hex32>` for derived UAs. — The same verifier code (§7) checks presentations off chain. —
  None.
- **R312** **Migration is breaking, dev chains only** (§12): `UniversalAccountRegistry`, `IUniversalAccountRegistry`
  and `AuthScheme` are deleted; `ZetherTypes.toUA` becomes the tagged derivation; Zether accounts re-register; no data
  migration. — Only dev chains (RS2-1) hold registrations today. — Dev balances are recreated by scripts.
- **R313** **PQ signing kinds (`mldsa44`, `mldsa65`, `fndsa512`) are enabled per chain only where an on-chain verifier
  exists** (a native precompile on private/PoA chains first; an audited Solidity verifier on public EVM later). Where
  none exists the kind cannot register on that chain (PoP needs verification). `PQ_COMMITMENT` ("verify off chain")
  is retired. — A kind that cannot be verified on chain is not an authorization (RS2-10's "as SELF on chain" was a
  silent downgrade). — PQ authorization arrives chain by chain; spec E may define a hybrid Zether `authRef`.
- **R314** **Per-family registries share the kind table, the tags, the derivations and one vector file**
  (`smartcontracts/vectors/ua/kinds.json`); each family realises the registry in its own idiom (§6.6). TON has no
  registry in v1: derived keys on TON are bound by the native wallet owner (`set_key`), which is the PoP, and
  chain-wide keyHash uniqueness is not enforced there (layers 1, 3, 4 still hold). — TON calls are asynchronous
  (AR §2.9). — A TON user can bind the same key under two wallets; the wallet refuses it (layer 1).
- **R315** **Cosmos passkey addresses become 32-byte** (ADR-028 style, the `webauthn-p256` UA id as a 32-byte bech32
  account) instead of `sha256("scaas.passkey.v1" ‖ pk)[..20]`; the Solana passkey owner becomes the
  `webauthn-p256` UA id instead of `sha256("scaas.owner.p256" ‖ pk33)`. Both at the family stream (version bump). —
  The Cosmos form is exactly the 20-byte truncation R291 forbids (2^80 against secp256k1 accounts). — Dev accounts
  re-open.
- **R316** **Mesh envelopes carry UA intents as a new EVM body `evm.ua_meta_tx` under `scaas-intent/1.3`**; `from` is
  still decoded from the signed body, never read from JSON; `intent_id` is the v3 digest the contract emits (R78
  unchanged). 1.2 peers refuse 1.3 envelopes (fail closed). — No new trust in the envelope. — Mixed meshes do not
  relay UA intents until upgraded.
- **R317** **The node verifies cheap UA kinds before gossip** (webauthn-p256, p256, ed25519, bip340, schnorr-bn254)
  with the shared Rust kind library, after reading the record once per chain (records are immutable: cached forever);
  structures, BLS and PQ are left to simulation like ERC-1271 today. — Spam with garbage signatures dies at the edge.
  — The node needs the registry address per chain (config).
- **R318** **Odoo stores UAs as addresses of a new kind, never derives policy off chain**: `blockchain.ua` (kind,
  id, key data, chain registrations), linked to partners only in the client store (erasable, SCaaS §11). — Same
  rule as every other address. — None.

---

## 3. Model in one page

```
                 key data / policy                         per chain
 subject ──────► kind_tag ‖ key_data ──keccak──► UA id ───► UARegistry.register(kind, keyData, pop, authRef)
 device                                            │            stores {kind, registeredAt, keyPtr, authRef},
 (clientkeys,                                      │            keyOwner[keyHash] = ua  (one key = one purpose)
  per-kind path)                                   ▼
                                     token function (accepts the kinds it needs)
                                       ├─ native id (EOA / 1271)  → ECDSA / isValidSignature over EIP-712 digest
                                       └─ derived UA              → registry.requireAuthorized(ua, purpose, digest, auth)
                                                                      └─ per-kind verifier over ua_msg (R301)
 optional: VC (issuer-signed) + VP (signed by the UA, purpose vp) → relying party / ComplianceRegistry attester
```

Three things never happen: a UA is never deployed, a record never changes, a key never serves two kinds.

---

## 4. Kinds

### 4.1 Derivation

```
kind_tag    = "scaas.ua." ‖ <name> ‖ ".v" ‖ <n>                        (ASCII, e.g. "scaas.ua.zether-bn254.v1")
TAG(kind)   = keccak256(kind_tag)
UA(kind, d) = keccak256(TAG(kind) ‖ d)                                 d = canonical key data (§4.2), raw bytes
valid       ⇔ UA >> 160 ≠ 0                                            (R291)
native id   = family native identifier, left-zero-padded to 32 bytes   (EVM/Cosmos 20 B; others 32 B)
member ref  = (uint16 kind, bytes32 id)                                (structures always type their members)
```

Key-data encodings are byte-exact and identical in every family (the vectors pin them). Points are uncompressed in
the EVM precompile encodings (bn254 EIP-196/197, BLS12-381 EIP-2537), because the EVM verifiers need them that way
and decompression costs more than the calldata it saves (AR §2.1.5).

### 4.2 Kind table

Native kinds (no registration, no tag-derived id; listed so that structures and functions can name them):

| No. | Name | Native id | Families | Signature accepted |
|---|---|---|---|---|
| `0x0001` | `evm-eoa` | 20-byte address | EVM, Hedera (ECDSA alias) | ECDSA low-s over the EIP-712 digest |
| `0x0002` | `evm-contract` | 20-byte address with code | EVM, Hedera | ERC-1271 `isValidSignature(digest, sig)`, 50 k gas (400 k for `SubjectAccount` clones) |
| `0x0003` | `hedera-native` | long-zero address `0.0.N` | Hedera | HIP-632 `isAuthorizedRaw` (64-byte ed25519), else as 0x0001/0x0002 |
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
| `0x0100` | `webauthn-p256` | `x ‖ y ‖ rpIdHash ‖ originHash` (128) | `p256` | WebAuthn assertion, challenge = base64url(`ua_msg`) | `P256VERIFY` (EIP-7951/RIP-7212 `0x100`), OZ fallback | EVM → Soroban, Solana, Aptos, Cosmos |
| `0x0101` | `p256` | `x ‖ y` (64) | `p256` | ECDSA-P256-SHA256 over `ua_msg`, low-s | same | EVM (HSM, secure enclave) |
| `0x0102` | `ed25519` | `pk` (32) | `ed25519` | Ed25519(`ua_msg`) | Solidity ed25519 (enabled per chain, §7.3) | EVM private chains; native elsewhere |
| `0x0103` | `bip340` | x-only `pk` (32) | `secp256k1` | BIP-340 over `ua_msg` | `ecrecover` trick + SHA-256 tagged challenge | EVM → Cosmos |
| `0x0104` | `schnorr-bn254` | `Y` (64) | `bn254-g1` | scaas Schnorr (§7.2) over `ua_msg` | bn254 `0x06/0x07` (existing `_schnorr`) | EVM |
| `0x0105` | `schnorr-bls12381` | `Y` (128) | `bls12381-g1` | as 0x0104 on BLS12-381 G1 | EIP-2537 G1MSM | EVM (EIP-2537 chains) |
| `0x0106` | `bls12381-minsig` | `pk ∈ G2` (256) | `bls12381-g2` | BLS min-sig, DST_POP | `Bls12381.verifyMinSig` + `HashToCurve` | EVM (EIP-2537 chains) |
| `0x0107` | `bls-bn254-minsig` | `pk ∈ G2` (128, EIP-197 order) | `bn254-g2` | BLS min-sig, POP label | pairing `0x08` | EVM private chains only (~100-bit) |
| `0x0110` | `musig2-secp256k1` | `aggPk_x (32) ‖ u16 n ‖ keyAggListHash (32)` | `secp256k1` | one BIP-340 sig by the aggregate | as 0x0103 | EVM → Cosmos |
| `0x0111` | `frost-secp256k1` | `groupPk_x (32) ‖ u16 t ‖ u16 n ‖ participantsHash (32)` | `secp256k1` | one BIP-340 sig by the group | as 0x0103 | EVM → Cosmos |
| `0x0112` | `musig2-bn254` | `aggY (64) ‖ u16 n ‖ keyAggListHash (32)` | `bn254-g1` | one scaas Schnorr by the aggregate | as 0x0104 | EVM |
| `0x0113` | `frost-bn254` | `groupY (64) ‖ u16 t ‖ u16 n ‖ participantsHash (32)` | `bn254-g1` | one scaas Schnorr by the group | as 0x0104 | EVM |
| `0x0120` | `msig` | `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, ids strictly increasing | — | none of its own; every member registered or native | `UAMsigVerifier` (members via their own kinds) | EVM → all |
| `0x0121` | `bls12381-multi` | `u16 t ‖ u16 count ‖ count × bytes32 memberId` (members kind 0x0106), increasing | — | none; members registered with PoP | G2ADD over signer subset + one pairing | EVM (EIP-2537 chains) |
| `0x0130` | `mldsa44` | `pk` (1312) | `mldsa44` | ML-DSA-44 sign(`ua_msg`, ctx = `kind_tag`) | precompile / audited verifier only (R313) | private EVM first |
| `0x0131` | `mldsa65` | `pk` (1952) | `mldsa65` | as 0x0130 | as 0x0130 | private EVM first |
| `0x0132` | `fndsa512` | `pk` (897) | `fndsa512` | FN-DSA-512 (Falcon) once FIPS 206 is final | as 0x0130 | private EVM first |
| `0x0140` | `zether-bn254` | `Y` (64) | `bn254-g1` | scaas Schnorr by `x` under the **Zether** Schnorr tag (`SCAAS-ZETHER-SCHNORR-V1`) on `ua_msg` | existing Zether Schnorr | EVM |
| `0x0141` | `zether-bls12381` | `Y` (128) | `bls12381-g1` | as 0x0140 on BLS12-381 | existing | EVM (EIP-2537 chains) |

Validation at registration, all kinds: points valid, on curve, in the prime-order subgroup (G1 BLS12-381, every G2),
not the identity (RS2-18 kept for every BLS key and signature); `t`/`threshold` non-zero and ≤ total weight or `n`;
`count` ≤ 16 for `msig`, ≤ 64 for `bls12381-multi`; ids strictly increasing (no duplicate member).

**What the extra fields in MuSig2/FROST key data are for.** `n`, `t`, `participantsHash` / `keyAggListHash`
(keccak of the sorted participant public keys) are governance and audit data, not verification data — the chain
verifies one signature by one key (SCaaS §9.7). Putting them in the id makes "this is a 3-of-5 FROST group of these
five keys" a fact anyone can check against the id, and makes a changed group a new UA (R302).

### 4.3 Which kind for whom (guidance for the app and the ERP)

| Subject | Default | Option |
|---|---|---|
| Outlet / staff with a phone | `webauthn-p256` UA | `SubjectAccount` (b) when they want recovery without moving funds |
| User with an extension wallet | native EOA | — |
| Board, finance approvers | `msig` over members' passkey UAs and/or EOAs | Safe (native 1271) |
| Agent cluster, MPC custody with Schnorr | `frost-secp256k1` (cheap on EVM) or `frost-bn254` | threshold ECDSA ⇒ native EOA |
| HSM-held corporate key | `p256` (HSMs do P-256) | native EOA (secp256k1 HSM) |
| Confidential balances | `zether-*` with `authRef` = one of the above | `authRef = 0` (self) for single holders |
| Long-lived PQ-ready authority (private chain) | `mldsa65` | `msig` mixing `mldsa65` and `p256` (hybrid) |

---

## 5. Function → accepted kinds

Legend: **N** = native ids only (EOA, ERC-1271 incl. `SubjectAccount`/Safe/`MandateWallet`, Hedera native);
**U** = any registered derived kind except Zether, or a native id; **Z** = Zether kind matching the token's verifier
curve; **Z-auth** = the Zether record's `authRef` (self, native, or any U kind); **sender** = `msg.sender` (native by
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
the registry against `authRef` with purpose `zether-auth` (native `authRef`: ECDSA/1271 over the raw `authDigest`,
as `ECDSA_MULTISIG`/`SMART_ACCOUNT_1271` do today).

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
| `uaExecute(UAMetaTransaction m, bytes auth)` | `executeMetaTransaction` | U (native or registered) | native or registered (`UANotRegistered`) |
| `uaTransfer(from, to, amount, batch, nonce, validUntil, mode, relayer, auth)` | `mtxTransfer` | U | native or registered |
| `uaTransferWithFee(…, fee, feeRecipient, auth)` | `mtxTransferWithFee` | U | native or registered |
| `uaPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, auth)` | `mtxPay` (`batch = payLane(payId)`) | U | native or registered |
| `uaUnwrap(from, underlying, wrapped, recipient, minOut, batch, nonce, validUntil, mode, relayer, auth)` | `mtxUnwrap` | U | `recipient` address (N) |
| `uaBatch(UAMetaTransaction[] ms, bytes[] auths)` | `mtxBatch` | each U | each |
| `uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, bytes auth)` | `cancelMetaNonce` | U (signed, purpose `metatx-cancel`) | — |
| `transferToUA(bytes32 to, uint256 amount)` | — | sender N | registered |
| views `balanceOfUA(bytes32)`, `uaNonce(bytes32, batch)`, `uaDigest(m)`, `registry()` | — | — | — |

Rules: step 5 of the pipeline is `SigLib`-style ECDSA/1271 over the v3 EIP-712 digest when `from` is a native id
(`from >> 160 == 0`), else `registry.requireAuthorized(from, PURPOSE_METATX, digest, auth)`. Ops allowed in
`m.data`: empty (transfer), `pay(bytes32)`, `unwrap(…)`; **`approve` and `trade` are refused** for derived `from`
(R26: allowances only to contracts; a UA-ledger allowance model waits for DEX v2, §17 Q4). Fees are paid from the
`from` ledger to `feeRecipient` (an address, native ledger). Event per item: `UAMetaTransactionExecuted(bytes32
indexed from, address indexed relayer, uint256 indexed batch, uint256 nonce, bytes32 digest, address feeRecipient,
uint256 fee)`; its `digest` is the mesh `intent_id` (R316).

Code size: v3 adds the UA path to `MetaTokenBase`; if `--sizes` exceeds 24 576 bytes the named `ua*` wrappers move
to a `fallback` decoder as TW2 did for `mtxUnwrapWithFee`. Verification code is never inside the token (it lives in
the registry's verifiers, §7).

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
| Soroban | `Address` (`G…`, `C…`); `scaas-account` keys `Ed25519`, `Passkey` (1-of-N) | native kinds unchanged; `webauthn-p256` key ids follow §4.1 when the account binds them; registry = the account factory's persistent map (§6.6) |
| Aptos | `owner: address`; Account keys ed25519 / WebAuthn | native unchanged; non-native owner keys keyed by UA id; `account_of(ua)` for passkey-first accounts |
| Sui | native address (flags 0/1/2/6) | native unchanged (Sui passkeys are native, flag 6); `Registry<T>` gains `key_owner` table |
| Solana | `owner: [u8;32]`; passkey owner `sha256("scaas.owner.p256" ‖ pk33)` | passkey owner = `webauthn-p256` UA id (R315); PDA `["acct", ua]`; PDA `["ukey", keyHash]` enforces R299 |
| Cosmos | bech32 `from`; passkey address 20-byte truncation | passkey account = 32-byte UA id (R315); `bip340`/`frost-secp256k1` via an `ua-registry` contract |
| TON | `MetaOp.from` wallet; jetton-wallet `passkey` bound by `set_key` | native `ton-wallet`; no registry (R314) |

Moving value per family keeps the family's own entry points (`relay_pay`, `Relay{payload, auth}`, `SignedOp`…); F
changes which owner ids those accounts are keyed by and adds the registry check where an account is opened for a
derived owner. Order follows the owner's family order (§16).

---

## 6. Registry

### 6.1 EVM interface

```solidity
interface IUARegistry {
    struct Record { uint16 kind; uint40 registeredAt; address keyPtr; }   // one slot; keyPtr ≠ 0 only for PQ kinds

    event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, bytes32 authRef);

    error UAKindDisabled(uint16 kind);
    error UAKeyData(uint16 kind);                 // length, encoding, curve, subgroup, identity, ordering, threshold
    error UAIdInNativeSpace(bytes32 ua);          // R291
    error UAAlreadyRegistered(bytes32 ua);
    error UAKeyInUse(bytes32 keyHash, bytes32 owner);   // R298 layer 2
    error UAMemberUnknown(bytes32 member);        // structure member neither native nor registered
    error UAAuthRef(bytes32 authRef);             // Zether only: not native/registered signing UA, or same-curve BLS
    error UAPoP();
    error UAUnauthorized(bytes32 ua);

    function generation() external view returns (uint8);                     // 1 or 2 (§6.5)
    function predecessor() external view returns (address);
    function kindEnabled(uint16 kind) external view returns (bool);
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32);
    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32);   // 0 for structures
    function popDigest(bytes32 ua) external view returns (bytes32);          // R295 (before kind tagging)
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32); // R301

    function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes32 authRef)
        external returns (bytes32 ua);

    function recordOf(bytes32 ua) external view returns (Record memory r, bytes32 authRef);
    function kindOf(bytes32 ua) external view returns (uint16);              // 0 = not registered (native ids too)
    function isRegistered(bytes32 ua) external view returns (bool);
    function keyOwner(bytes32 keyHash) external view returns (bytes32);

    /// Reverts UAUnauthorized unless `auth` authorizes `digest` for `ua` under `purposeTag`.
    /// Native ids (ua >> 160 == 0): ECDSA (EOA) or ERC-1271 over the raw `digest`, purpose ignored.
    /// Derived: auth = abi.encode(bytes keyData, bytes sig); keyData empty for stored (PQ) kinds.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view;

    /// Zether: `authRef == 0` and zkCovered ⇒ auth must be empty; `authRef == 0` and !zkCovered ⇒ Zether Schnorr
    /// by x (purpose zether-owner); else requireAuthorized(authRef, PURPOSE_ZETHER_AUTH, digest, auth).
    function requireZetherAuthorized(bytes32 ua, bytes32 digest, bytes calldata auth, bool zkCovered) external view;
}
```

### 6.2 `register` steps (cheap first)

1. `kindEnabled(kind)` (immutable table) — `UAKindDisabled`.
2. Key-data shape and values (§4.2 validation) — `UAKeyData`.
3. `ua = uaOf(kind, keyData)`; `ua >> 160 ≠ 0` — `UAIdInNativeSpace`; not registered here or in the predecessor —
   `UAAlreadyRegistered`.
4. Single-key kinds: `kh = keyHashOf(kind, keyData)`; `keyOwner[kh] == 0` here and in the predecessor —
   `UAKeyInUse`. Structures: every member is native or `kindOf(member) == memberKind` and of an allowed member kind —
   `UAMemberUnknown`.
5. Zether kinds: `authRef` is 0, a native id, or a registered non-Zether UA; a BLS UA on the
   curve of `Y` is refused — `UAAuthRef`. Other kinds: `authRef == 0`.
6. PoP: verify `pop` over `uaMessage(kind, POP_TAG, popDigest(ua))` with the kind's verifier (MuSig2/FROST: one group
   signature; structures: **no** PoP of their own — members proved theirs; Zether: Schnorr by `x` under the Zether
   tag, and, when `authRef` is a derived UA, nothing more: the auth UA proved its own key) — `UAPoP`.
7. Store `Record{kind, uint40(block.timestamp), keyPtr}` (PQ: `keyPtr = SSTORE2.write(keyData)`), `authRef` (Zether
   only, own slot), `keyOwner[kh] = ua`; emit `UARegistered(ua, kind, keyData, authRef)`.

The event carries the full key data, so an indexer (or an auditor with the tx) can rebuild every record without
reading storage, and the UA id is checkable offline from the event alone (AR §2.1.6 point 2).

### 6.3 Storage

```
mapping(bytes32 ua      => Record)  _records;     // slot: kind (16) | registeredAt (40) | keyPtr (160) = 216 bits
mapping(bytes32 ua      => bytes32) _authRef;     // Zether kinds only
mapping(bytes32 keyHash => bytes32) _keyOwner;    // single-key kinds
immutable: generation, predecessor, chainKeyHash (keccak256(chain_key)), per-kind verifier addresses (0 = disabled)
```

No owner, no setter, no `payable`, no token balances (invariant test). Deployed by CREATE2 from a fixed salt per
generation so its address is predictable per chain; constructor arguments (verifier set, `chain_key`) differ per chain
and are published in the chain profile.

### 6.4 Verifiers

Per-kind verifiers are stateless contracts whose addresses are immutable in the registry; the registry `staticcall`s
them with a gas cap per kind (§14.1). They share one interface:

```solidity
interface IUAKindVerifier {
    /// keyData already matched against the id by the registry; message = ua_msg (R301) or the WebAuthn challenge input.
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}
```

`msig` and `bls12381-multi` are implemented inside the registry (they recurse into member records) — not as external
verifiers.

### 6.5 Generations

A registry generation fixes its kind set. Generation 2 (new kinds, e.g. a PQ verifier on a public chain) takes
`predecessor = gen1` and checks both for `UAAlreadyRegistered` / `UAKeyInUse` / `kindOf`; at most two generations
(AR §2.3a: each fallback costs ~5 k gas). Tokens bind one registry address at `initialize` (immutable); a token that
needs new kinds is a new implementation version pointing to gen 2. Gen 2 sees gen-1 records, so nobody re-registers.

### 6.6 Other families

| Family | Where the records live | keyHash uniqueness | Notes |
|---|---|---|---|
| Hedera | the EVM registry, unchanged | yes | HSCS has the bn254 precompiles; EIP-2537 per probe |
| Cosmos | `ua-registry` CosmWasm contract; tokens query it (`WasmQuery::Smart`) | yes | software keccak; secp256k1/P-256 host verify |
| Soroban | persistent entries in the `scaas-account` factory (`UA(ua)`, `KEY(keyHash)`), TTL extended by the node like other persistent state | yes | `secp256r1_verify`, `ed25519_verify` host functions |
| Sui | `Registry<T>`: `Table<vector<u8>, address>` for `key_owner`; account objects keyed by UA | yes | native verify functions |
| Aptos | resource under the package root: `Table<vector<u8>, address>` | yes | pure-Move P-256 (UNAUDITED) |
| Solana | PDAs `["ua", ua]` (record) and `["ukey", keyHash]` (claim) | yes | precompile-instruction verification |
| TON | none (R314); wallet-bound keys | no (documented gap) | async actor model |

---

## 7. Verifier library

### 7.1 Message flow per check

```
digest   = the operation's domain-separated digest (EIP-712 v3 metatx; Zether authDigest; family digest)
ua_msg   = keccak256(TAG(kind) ‖ keccak256(purpose_tag) ‖ digest)                         (R301)
registry : keccak(TAG(kind) ‖ keyData) == ua ; kind == record.kind ; verifier[kind].verify(keyData, ua_msg, sig)
```

### 7.2 Per kind

| Kind | `sig` | Check |
|---|---|---|
| `webauthn-p256` | `abi.encode(authenticatorData, clientDataJSON, r, s)` (SubjectAccount encoding, R31) | type `webauthn.get`, challenge = base64url(`ua_msg`), `rpIdHash`, origin hash, UP+UV, low-s, P-256 over `sha256(authData ‖ sha256(clientDataJSON))`; the strict clientDataJSON grammar of `SubjectAccount._clientDataOk` is reused verbatim |
| `p256` | `r ‖ s` (64) | low-s; P-256 over `sha256(ua_msg)` |
| `ed25519` | 64 | RFC 8032 strict (canonical `S`, no small-order `A`/`R`) over the 32-byte `ua_msg` |
| `bip340` / `musig2-secp256k1` / `frost-secp256k1` | 64 | BIP-340 verify of `ua_msg` (x-only key); EVM: `ecrecover` trick with `e = sha256(tag "BIP0340/challenge")` |
| `schnorr-bn254` / `musig2-bn254` / `frost-bn254` | `R ‖ z` (96) | `e = hashToScalar(keccak256("scaas.ua.schnorr.v1" ‖ R ‖ Y ‖ ua_msg))`, `[z]G − R − [e]Y == O`, `z < r`, `R ≠ O`, `e ≠ 0` |
| `schnorr-bls12381` | `R ‖ z` (160) | as above on BLS12-381 G1 |
| `bls12381-minsig` | G1 sig (128) | `HashToCurve.hashToG1(ua_msg, DST)` with `DST_SIG = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_"`, PoP uses `…_POP_`; sig in subgroup, ≠ O |
| `bls-bn254-minsig` | G1 sig (64) | `mapToG1("SCAAS-UA-BLS-BN254-SIG-V1" ‖ ua_msg)` (POP label for PoP); pairing `0x08` |
| `msig` | `abi.encode(bytes keyData, MemberSig[] sigs)`, `MemberSig{uint16 index; bytes keyData; bytes sig}` with strictly increasing `index` | for each: member `kind,id` from the structure; native ⇒ ECDSA/1271 over `member_digest`; derived ⇒ `kindOf(id) == kind`, `keccak(TAG ‖ keyData) == id`, verifier over `uaMessage(kind, PURPOSE_MEMBER, member_digest)`; `member_digest = keccak256(ua ‖ ua_msg)`; Σ weight ≥ threshold |
| `bls12381-multi` | `abi.encode(uint64 bitmap, bytes[] memberPks, bytes aggSig)` | popcount(bitmap) ≥ t; each `memberPks[i]` hashes to the member id; `pk = Σ G2ADD(pk_i)` (safe: members subgroup-checked at registration); one pairing over `ua_msg` |
| `mldsa*` / `fndsa512` | raw signature | precompile / verifier with `pk` from `keyPtr`; ML-DSA context string = `kind_tag` |
| `zether-*` (self, owner ops) | `R ‖ z` | ZD §11.1 Schnorr with tag `SCAAS-ZETHER-SCHNORR-V1` over `ua_msg` — never the UA Schnorr tag, so a Zether key never produces a `schnorr-*` signature |

Members of `msig` may be native EOAs, native contracts (Safe, `SubjectAccount`), or registered single-key UAs (incl.
PQ); this is how a "UA4 = hash of an MPC/multisig structure that points to members with their own schemes" is
expressed (owner item 2).

### 7.3 Per-chain enablement

| Kind | Enabled on | Reason |
|---|---|---|
| `webauthn-p256`, `p256` | every EVM chain | precompile `0x100` where present (≈ 3.5–6.9 k gas), OZ Solidity fallback otherwise (measure; R31 already accepts it) |
| `ed25519` | private EVM chains by default; public chains on request | no precompile; Solidity verify ≈ 0.4–1.2 M gas (estimate) |
| `bls12381-*`, `schnorr-bls12381`, `zether-bls12381` | chains where the `CurveCapability` probe passes (returndata compared, AR §2.5.5) | EIP-2537 |
| `bls-bn254-minsig` | private chains only | ~100-bit pairing security (AR §2.5.1) |
| PQ | chains with a precompile or audited verifier (R313) | — |

The enabled set is a constructor argument (verifier address 0 = disabled); the chain profile publishes it; clients
read `kindEnabled` before offering a kind.

---

## 8. One key = one purpose (R298)

### 8.1 Layer 1 — derivation and wallets (clientkeys, app, Odoo portal)

| Use | Path | Curve / scheme |
|---|---|---|
| Native account keys | unchanged family paths (S4F §7.1): EVM `m/44'/60'/0'/0/i`, Solana `m/44'/501'/i'/0'`, … | family |
| Every derived kind and every account-role key | `m/7225'/0'/<account>'/<kindNo>'/<i>'` | BIP-32 (secp256k1, P-256 via SLIP-10 nist256p1), SLIP-10 ed25519 |
| `SubjectAccount` SECP256K1 key (role of `evm-contract`) | `m/7225'/0'/<account>'/2'/<i>'` | secp256k1 |
| Non-native subject-account owner keys (Sui/Aptos/Solana/Soroban role keys) | `m/7225'/0'/<account>'/<native kindNo>'/<i>'` | ed25519 |
| `schnorr-bn254`, `frost/musig2-bn254` member shares from seed | EIP-2333-style `m/254/0/<account>/<kindNo>` (salt `"SCAAS-UA-BN254-v1"`) | bn254 |
| `bls12381-minsig`, `schnorr-bls12381` | EIP-2333 `m/12381/0/<account>/<kindNo>` | BLS12-381 |
| Zether conf key / viewing key | unchanged R33: `m/254|12381/<coin>/<account>/7`, `…/8` | bn254 / BLS12-381 |
| PQ seeds | `ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 i)` → FIPS 204 `KeyGen_internal(ξ)` / seeded FN-DSA keygen | ML-DSA, FN-DSA |
| Passkeys | one credential per `rpId` (APP R165); the same credential on several chains is the same kind (`webauthn-p256` or a family's native passkey) — allowed, the challenges are domain-separated digests | P-256 |

`7225'` is the SCaaS BIP-43 purpose for UA trees (owner to confirm the number, §17 Q6); coin level `0'` because a UA
id is chain-independent (one derived key ⇒ the same UA on every chain).

clientkeys API rules (stream F3):
- `signDigest(key, digest)` stays for **native** keys only; UA keys are `UAKey` objects created by
  `deriveUAKey(seed, {kind, account, index})` whose only signing method is `signUA(purpose, digest)` (builds `ua_msg`
  itself); there is no way to get a raw signature over an arbitrary 32 bytes from a UA key.
- `deriveUAKey` refuses a `kind` whose curve group equals a native path's curve **and** whose path would equal it
  (cannot happen with `7225'`, asserted in tests) and refuses the Zether `use` indices 7/8 for non-Zether kinds.
- `deriveConfKey` stops accepting a free `use` (only 7 and 8).
- The vault keeps one PRF/PIN wrapping for the seed and the conf key (S4F R259/R262); AAD labels already separate
  them.
- Wallets show the kind and the role of every key and never offer "use this EOA as a passkey/Schnorr/multisig member
  key" (layer 4).

### 8.2 Layer 2 — registry (R299)

`keyOwner[keccak256(group_tag ‖ canonical_pubkey)]`. Canonical forms: secp256k1 x-only (so a BIP-340 key and a
MuSig2 aggregate with the same x collide, as they must); P-256 `x`; bn254/BLS points uncompressed; PQ `pk`. Valid
PoP does not override `UAKeyInUse`.

### 8.3 Layer 3 — purposes

| Purpose tag (`scaas.ua.purpose.<p>.v1`) | Digest it wraps |
|---|---|
| `pop` | `popDigest(ua)` (R295) |
| `metatx` | v3 EIP-712 digest of `UAMetaTransaction` |
| `metatx-cancel` | `keccak256(abi.encode(CANCEL_TAG, chainid, token, ua, batch, validUntil))` |
| `member` | `keccak256(structureUA ‖ ua_msg_of_structure)` |
| `zether-auth` | ZD `authDigest` |
| `zether-owner` | ZD rollOver/mode digests |
| `keyop` | family subject-account key operations (replaces `scaas.keyop.v1` by version bump, S4F §3) |
| `receiver-fee` | TSS `ReceiverFee` co-sign (when the payee is a UA) |
| `vp` | VC presentation (§9.3) |
| `vc-anchor` | consent to an on-chain anchor (§9.4) |

A digest is always already domain-separated (chain, contract); the purpose tag separates *uses* of the same key,
the kind tag separates *kinds*.

### 8.4 Layer 4 — EOAs

EOAs are never registered and sign only their wallet-native formats. Registered secp256k1 kinds (`bip340`,
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

W3C VC Data Model 2.0. Securing: **SD-JWT VC** (selective disclosure, salted claim digests) as the default;
Data Integrity with `bbs-2023` as an option where unlinkable presentations are needed. Status: W3C Bitstring Status
List (or IETF Token Status List); `validUntil` on every credential. `credentialSubject.id`: `did:pkh:<caip10>` for
native accounts (e.g. `did:pkh:eip155:100:0xabc…`), `urn:scaas:ua:v1:<kind>:<hex32>` for derived UAs (resolution =
the `UARegistered` event or `recordOf` + key data).

### 9.3 Holder binding (presentation)

A presentation is accepted when, for the account named in `credentialSubject.id`:

```
vp_digest = keccak256(abi.encode(keccak256("scaas.vp.v1"), keccak256(audience), nonce, issuedAt, expiresAt,
                                 sha256(canonical VP body without proof)))
native  : EIP-712 typed data `Presentation{audience,nonce,issuedAt,expiresAt,bodyHash}` signed by the EOA / 1271
derived : UA signature over uaMessage(kind, PURPOSE_VP, vp_digest)
```

`nonce` is chosen by the relying party (for a trade: the deal reference or the `intent_id`), so a presentation proves
"this account's key holder presented this credential to us for this deal at this time". Verification uses the same
kind library as the chain (§7), off chain, from the shared vectors.

### 9.4 Optional on-chain anchor (`UAAttestations`, per chain, no admin)

```solidity
interface IUAAttestations {
    struct Anchor { bytes32 subject; bytes32 issuer; bytes32 schemaId; bytes32 commitment;
                    uint64 issuedAt; uint64 expiresAt; uint64 revokedAt; }
    event Anchored(bytes32 indexed anchorId, bytes32 indexed subject, bytes32 indexed issuer, bytes32 schemaId,
                   bytes32 commitment, uint64 expiresAt);
    event Revoked(bytes32 indexed anchorId, uint64 at);
    event Withdrawn(bytes32 indexed anchorId);
    /// both the subject (purpose vc-anchor) and the issuer (purpose vc-anchor) authorize; ids via IUARegistry
    function anchor(bytes32 subject, bytes32 issuer, bytes32 schemaId, bytes32 commitment, uint64 expiresAt,
                    bytes calldata subjectAuth, bytes calldata issuerAuth) external returns (bytes32 anchorId);
    function revoke(bytes32 anchorId, bytes calldata issuerAuth) external;      // issuer only
    function withdraw(bytes32 anchorId, bytes calldata subjectAuth) external;   // subject unlinks; history stays
    function anchorOf(bytes32 anchorId) external view returns (Anchor memory);
}
// anchorId = keccak256(abi.encode(subject, issuer, schemaId, commitment))
// commitment = TSS R196 format: keccak256(abi.encode(keccak256("scaas.commit.v1"), salt, sha256(JCS(credential))))
```

It answers one question publicly and timestamped: "at time T, the holder of this account and this issuer both stated
that a credential with this commitment exists". It is **optional** and **not consulted by tokens**. It never holds
claims, names, document numbers or hashes without a salt.

### 9.5 Privacy and erasure

- No personal data on chain (TSS §C.1): only the salted commitment, the issuer id and a schema id.
- Correlation: an anchor tells the world that a UA holds a credential of a schema from an issuer. Holders who do not
  want that use presentations only (the default); the app says so before anchoring.
- Erasure (TSS R195–R199): the salt and the credential are client-held under the per-subject DEK; destroying the DEK
  makes the commitment unopenable and the anchor unlinkable to the person. `withdraw` marks the anchor withdrawn;
  history is immutable.
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
- **App/ERP**: holds credentials (holder side) or presentations and evidence (relying-party side); the Odoo addon
  stores them as `ir.attachment` on Garage/S3 with the hash in the record.

### 9.7 Legal-recourse evidence trail

For a trade where company A relied on a counterparty's credential, the relying party keeps an **evidence bundle**:

| Item | Proves |
|---|---|
| VC (issuer-signed) and its status at the time | who the issuer says the subject is |
| VP signed by the counterparty's account, `nonce` = deal reference / `intent_id` | the key holder of that account presented it for this deal |
| finalized tx hash + `intent_id` + event (`UAMetaTransactionExecuted`, `PaymentSettled`, …) | the account performed the on-chain act |
| `UARegistered` event (derived UAs) | the key data behind the id, and when it was registered |
| optional `Anchored` event | public, timestamped co-statement of holder and issuer |
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
- Keys: its `SECP256K1` keys come from the role path `m/7225'/0'/<account>'/2'/<i>'` (R300), never from the EOA
  path; its P-256 keys are passkeys (per `rpId`). A passkey that is a `webauthn-p256` UA may **also** be a
  `SubjectAccount` key: same kind, same WebAuthn scheme, digests differ (the account's challenge is the token's
  EIP-712 digest with `from` = the account); allowed.
- The S4F backup predicate (R251) applies to it unchanged; derived UAs are "single-key, no recovery" by construction
  and the app shows that (S4F R253 maps to F's native/derived split, S4F R268).
- `msig` UAs may list a `SubjectAccount` as a member (native contract member).

---

## 11. Touchpoints

### 11.1 Mesh (R316–R317)

- `scaas-intent/1.3`: EVM body `evm.ua_meta_tx = {token, m: UAMetaTransaction (hex fields), auth, from_kind}`;
  `from` decoded from `m.from` (32-byte hex). `intent_id` = `uaDigest(m)`. `sig_kind` values: `eoa`, `erc1271`, `ua`.
- Pre-gossip: `ua` ⇒ the node reads `recordOf(from)` once per chain (immutable; cache with no expiry; negative
  results cached 60 s), recomputes the id from `auth.keyData`, and verifies cheap kinds locally (R317); others go to
  simulation.
- V6 rate limit and V8 freshness key on the 32-byte `from`; `uaNonce(from, batch)` is the freshness source.

### 11.2 Node (indexer, jobs, API)

- New job payload kind `ua_metatx` (same lifecycle as `metatx`, NI R89/R91); idempotency on `(chain, token, from,
  batch, nonce)` with `from: bytes32`.
- Indexer normalizes `UATransfer` and `UAMetaTransactionExecuted` (SCaaS §7.8) and `UARegistered` (with key data).
  Balances feed `/v1/events` per 32-byte id; native ids keep today's form.
- Config per chain: `ua_registry` address and generation; enabled kinds read from chain at onboarding.
- The node never holds UA keys; `Signer`/lane keys (R59) are unaffected.

### 11.3 App and clientkeys

- `src/features/accounts/` (APP screen 5): the default "Create account" makes a `webauthn-p256` UA and registers it
  (gasless; R295 makes `register` relayable, so APP screen 14's "self-paid only" no longer applies); "Recoverable
  account" makes a `SubjectAccount` (option (b)).
- Screen 14 (Zether): registers `zether-*` with `authRef` picked from the user's existing accounts.
- Groups: an "Approvers" wizard builds `msig` key data from member accounts and shows the id before registering.
- clientkeys F3: `ua.js` (`uaOf`, `keyHashOf`, `uaMessage`, `popDigest`, `deriveUAKey`, `UAKey.signUA`, encoders per
  kind, `UAMetaTransaction` typed data), `zether.js` (`confPublic` returns the tagged UA; `zetherPop` signs the new
  PoP; `popMessage` removed), `fam/*` owner derivations per R315. Vectors §15.1.

### 11.4 Odoo (bamboo-dms, `dms_blockchain*`)

Today no Odoo model stores a UA, a Zether key or a registry address (§12.1). Changes (stream F6, parent repo):

| Where | Change |
|---|---|
| `dms_blockchain/models/` new `blockchain.ua` | `ua_id` (Char 66, indexed), `kind` (Selection from the kind table), `key_data` (hex), `registration_ids` (per chain: registry, tx hash, block, state); unique `(ua_id)` via `models.Constraint` (CLAUDE.md §5.2) |
| `blockchain.chain` config | `ua_registry_address`, `ua_registry_generation`, `ua_kinds_enabled` (read from chain) |
| `lib/addresses.py` (`canonical`) and `blockchain.address.mixin` | accept a 32-byte UA id as an address form on EVM (`0x` + 64 hex) alongside 20-byte addresses; never truncate |
| `blockchain.signed.op` | `auth_kind` gains `ua`; `from_address` holds the UA id |
| `blockchain.metatx`, `payment_request.payer_address`, `chain_event` from/to | accept UA ids; `blockchain.chain.event` maps `UATransfer` |
| `dms_portal_subject_account.py` | `register_start/register` gain the UA path (passkey ⇒ `webauthn-p256` UA) next to `SubjectAccount` |
| `lib/fam_*.py` `verify(...)` | `fam_evm.verify_ua(record, digest, auth)` using the shared Python kind library (same vectors) |
| `blockchain.subject.account.key` | `evm_address` keys created after F3 come from the role path (R300); migration note on existing dev keys |
| Credentials (optional) | `blockchain.ua.credential`: issuer, schema, `validUntil`, status URL, VC/VP as `ir.attachment` (Garage), `commitment`, `anchor_tx`; no claims in DB columns |
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
| `AuthScheme` → `authRef` | `SELF_SCHNORR` → `0`; `ECDSA_MULTISIG` → `msig` of EOA members; `FROST/MUSIG2_BN254` → `frost/musig2-bn254` UA; `BLS_BN254/12381` → `bls-*` UA (cross-curve rule kept); `PQ_COMMITMENT` → retired (R313; spec E); `SMART_ACCOUNT_1271` → native contract id; `linkEVM` → retired (index `UARegistered`) |
| SCaaS §8.6, §9.7, §14.5; INT §10.2 | rewritten at F1 (pointers now) |

### 12.3 New registration flow (replaces INT §10.2)

1. Client derives the key for the kind (§8.1), builds `keyData`, computes `ua` and checks `ua >> 160 ≠ 0`.
2. Reads `popDigest(ua)` (or computes it: chain key + registry address are public) and signs
   `uaMessage(kind, POP_TAG, popDigest)` with the kind's signer (`UAKey.signUA("pop", …)`).
3. Anyone submits `register(kind, keyData, pop, authRef)` (self-paid, relayer job, or sponsored).
4. On the finalized `UARegistered` the client marks the account usable on that chain.

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
| S3 | Rogue key in aggregates | per kind (R296); members registered with PoP; MuSig2 KeyAgg; FROST DKG PoK | a broken off-chain DKG is invisible to the chain (provider audit) |
| S4 | Registering someone else's key | PoP over a chain+registry+UA digest | none |
| S5 | Front-running `register` | caller-independent record; storage-diff test | victim's relayer may lose one tx's gas (AR §2.2.3: economically reversed) |
| S6 | Spam registrations (state growth, sponsored pools) | sponsorship policy at the node (TSS R189–R191); no on-chain invite gate in v1 | self-paid spam pays its own gas (§17 Q8) |
| S7 | Key reuse across purposes | four layers (§8) | a foreign wallet reusing an EOA key for `bip340` (layer 4 cannot be enforced on chain) |
| S8 | Cross-protocol / cross-purpose replay | tagged `ua_msg` (R301); digests domain-separated | none |
| S9 | WebAuthn origin/iframe confusion | `SubjectAccount` clientDataJSON grammar reused (fail-closed), origin in the id | — |
| S10 | ed25519 malleability / small-order keys | strict RFC 8032 verify; small-order `A` refused at registration | — |
| S11 | BLS subgroup / infinity | G2MSM k=1 at registration; signatures in subgroup, ≠ O (RS2-18) | — |
| S12 | Zether same-curve BLS auth (DDH) | refused at registration (C6.1) | — |
| S13 | Zether key used as a signing key | `zether-*` signatures use the Zether Schnorr tag only; `schnorr-*` can never register the same point (R299) | — |
| S14 | Verifier DoS (huge structures, PQ) | `count` caps; per-kind gas caps; PQ only where enabled | — |
| S15 | Registry capture | no admin, no upgrade, immutable verifier set; generations append-only | a bug in a verifier is permanent for that generation (audit before public chains, RS2-1 gate kept) |
| S16 | Compromised derived key | like an EOA: move funds; compliance freeze at token level | no recovery by design; option (b) exists |
| S17 | Lost structure member (n-of-n MuSig2) | default FROST/`msig` with threshold < n | MuSig2 groups lose funds if one member is lost (UI warns) |
| S18 | Credential misuse / replay | VP nonce + audience; status checked; anchors need holder and issuer consent | issuers are trusted for what they assert |
| S19 | Credential correlation | presentations default; anchors opt-in; no PII on chain | anchor metadata (issuer, schema) is public |
| S20 | Typo in a UA id | unregistered `to` refused | none |
| S21 | Naive ERC-20 indexers mis-sum v3 supply | `UATransfer` + `balanceOfUA`; documented | third-party tools |

---

## 14. Gas and calldata (estimates; measured numbers replace them in `test/ua/UAGas.t.sol`)

### 14.1 Verification per check (execution gas, EVM)

| Kind | Calldata (key data + sig) | Verify | Registry overhead | Cap |
|---|---|---|---|---|
| native EOA | 65 | ~3.5 k | none (token-local) | — |
| native 1271 | per account | per account | — | 50 k / 400 k |
| `webauthn-p256` | 128 + ~300 | ~6.9 k precompile / ~200 k+ OZ fallback (measure) | ~5 k (cold call + SLOAD + hash) | 400 k |
| `p256` | 64 + 64 | as above, no JSON | ~5 k | 400 k |
| `bip340` (+ MuSig2/FROST secp) | 32(+36/38) + 64 | ~5 k | ~5 k | 50 k |
| `schnorr-bn254` (+ MuSig2/FROST bn254) | 64(+36/38) + 96 | ~13 k (measured `_schnorr`) | ~5 k | 50 k |
| `bls12381-minsig` | 256 + 128 | ~120 k (measured, chain 9000) | ~5 k | 200 k |
| `msig` k-of-n | 4 + 36n + Σ member | Σ member verifies + ~2 k + 2.6 k per derived member lookup | ~5 k | Σ caps |
| `bls12381-multi` (k signers) | 4 + 32n + 256k + 128 | ~120 k + 0.6 k·k (G2ADD) | ~5 k | 300 k |
| `ed25519` | 32 + 64 | ~0.4–1.2 M (no precompile; private chains) | ~5 k | 1.5 M |
| `mldsa44` | 2 420 sig | precompile-dependent / 1.5–4 M Solidity | ~5 k + EXTCODECOPY ~3 k | per chain |
| `zether-*` | — (proof path) | unchanged (ZD §15) | ~5 k (`kindOf` + `authRef`) | — |

### 14.2 Registration (execution gas, bn254 base; AR §2.2.5 corrected for the new layout)

| Kind | Storage | PoP | Total (est.) |
|---|---|---|---|
| `webauthn-p256` / `p256` | record + keyOwner = 2 × 22.1 k | 7–200 k | ~55 k – 250 k |
| `bip340`, `schnorr-bn254` | 2 × 22.1 k | 5–13 k | ~55–65 k |
| `bls12381-minsig` | 2 × 22.1 k + G2MSM 22.5 k | ~120 k | ~190 k |
| `msig` (n members) | 1 × 22.1 k | none (n member lookups, 2.6 k each) | ~30 k + 2.6 k·n + event |
| `zether-bn254` | record + keyOwner + authRef (if ≠ 0) | ~13 k | ~60–80 k |
| `mldsa44` | 2 slots + SSTORE2 1 312 B ≈ 0.3 M | precompile / verifier | ~0.35 M + verify |

Calldata floor (EIP-7623): binds when execution gas < 24 × non-zero bytes. PQ registrations with a precompile
(execution small, `pk` 1.3–2.6 KB) and any PQ check are floor-priced at 40 gas/byte: an ML-DSA-44 signature costs
~97 k gas of calldata alone on a public chain — PQ authorization is a private-chain feature until that changes
(R313). On private/PoA chains with zero gas price none of this is money.

### 14.3 Why not cache in tokens (R306)

A token-local "seen" bit saves the cold `CALL` (2.6 k) on later checks but costs a 22.1 k SSTORE once: break-even
after ~9 uses per (token, UA). Not worth the extra state in v1; immutable records keep the option open.

---

## 15. Tests and vectors

### 15.1 Cross-language vectors (`smartcontracts/vectors/ua/`)

`kinds.json` — for **every** kind in §4.2 (including native rows for member refs):

- `kind`, `tag`, `TAG(kind)`, `keyData` (hex), expected `ua`, `keyHash` (group + hash);
- `chain_key`, `registry_id`, expected `popDigest`, `ua_msg` for `pop`, a PoP signature and its validity
  (deterministic: Ed25519; BIP-340 with zero `aux_rand`; scaas Schnorr with a fixed nonce; BLS (deterministic);
  P-256 RFC 6979; WebAuthn with a fixed authenticatorData/clientDataJSON; ML-DSA deterministic variant; FN-DSA fixed
  seed);
- purpose vectors: `ua_msg` for every purpose tag of §8.3 over a fixed digest;
- negatives: same point under two kinds ⇒ two ids and one `UAKeyInUse`; a synthetic id with zero top 96 bits ⇒
  `UAIdInNativeSpace` (constructed by asserting the check on a fabricated id); wrong-tag PoP; PoP for another chain
  or registry; unsorted / duplicate structure members; threshold 0 or > weight; BLS infinity; small-order ed25519
  key; high-s P-256/ECDSA.

`structures.json` — `msig` with mixed members (EOA, `SubjectAccount`, `webauthn-p256`, `bip340`, `mldsa44`) and the
member digests; `bls12381-multi` bitmaps.

`metatx3.json` — `UAMetaTransaction` typed data, digests and auth blobs per kind (v3 KAT, like `MetaTxKat`).

`derivation.json` — seed → per-kind keys for §8.1 paths (BIP-39 test mnemonic), including the role paths of R300 and
the PQ HKDF.

Consumers that must pass the same files: Foundry (`test/ua/*`), clientkeys (Jest), zether-prover (Rust),
scaas-node (Rust kind library), Odoo (`dms_blockchain/tests/test_ua_vectors.py`), and each family's tests when its
stream lands (Move, Soroban, CosmWasm, Solana). The files are generated by one script (`smartcontracts/scripts/
gen_ua_vectors.*`) from independent implementations (noble/`@noble/curves` in JS, `k256`/`p256`/`ed25519-dalek`/
`blst`/`ark-bn254` in Rust); a vector is accepted only when both agree.

### 15.2 EVM tests

| Id | Test |
|---|---|
| T-REG-1 | every kind: register with the vector PoP ⇒ record, event, `keyOwner` |
| T-REG-2 | every negative vector reverts with its error |
| T-REG-3 | the same `register` calldata from two senders ⇒ identical storage diff (R295) |
| T-REG-4 | gen-2 registry sees gen-1 records; `UAKeyInUse` across generations |
| T-REG-5 | invariants: registry balance 0, no record ever changes, `uaOf(record.keyData) == ua` |
| T-AUTH-1 | `requireAuthorized` per kind × purpose; wrong purpose fails; wrong kind's tag fails |
| T-AUTH-2 | `msig` threshold/weights, duplicate member, unregistered member, nested structure refused |
| T-AUTH-3 | native paths: EOA low-s, 1271 gas caps |
| T-ZET-1 | Zether suite green with tagged UAs; `authRef` 0/native/derived; same-curve BLS refused; `zkCovered` rules |
| T-V3-1 | v3 equivalences (`uaTransfer ≡ uaExecute`, …) as TW2 §10.1; nonce shared across paths |
| T-V3-2 | `totalSupply == Σ native + Σ UA` (invariant); `UATransfer` emitted iff a side is derived |
| T-V3-3 | `to` unregistered ⇒ revert; `approve`/`trade` from derived ⇒ `MetaTxUnknownOp` |
| T-V3-4 | `--sizes` ≤ 24 576 for every v3 implementation |
| T-GAS | `UAGas.t.sol` replaces §14 estimates |
| T-ATT | `UAAttestations`: dual consent, issuer-only revoke, subject withdraw, no admin |

### 15.3 Off-chain

clientkeys: `UAKey` cannot sign raw digests (API test); derivation paths disjoint from native paths (property test
over kinds × accounts); `deriveConfKey` refuses other `use`. Node: pre-gossip rejection of bad UA signatures, cache
behaviour. Odoo: `pg_constraint` shows the `blockchain_ua` UNIQUE (CLAUDE.md §5.2); vectors pass in Python.

---

## 16. Streams

Constraints: at most three sub-agents, one heavy build/gate at a time (owner). Order of families follows the owner
order (EVM, Cosmos, Hedera, Soroban, TON, Sui, Aptos, Solana).

| Stream | Content | Depends on | Gate |
|---|---|---|---|
| **F0** | kind table libraries (Solidity `UAKinds.sol`, JS `ua.js`, Rust `scaas-ua` crate, Python `ua.py`), vector generator, `vectors/ua/*` | — | all four consumers pass the same vectors |
| **F1** | EVM `UARegistry` gen 1, verifiers (P-256, WebAuthn, BIP-340, bn254/BLS Schnorr, BLS, ed25519, msig, bls-multi), Zether re-point (§12), zether-prover + clientkeys Zether changes, deletes | F0 | T-REG, T-AUTH, T-ZET green; dev chains redeployed |
| **F2** | MetaToken v3 (UA ledger, `UAMetaTransaction`, `ua*` functions) for the three tiers; factory v2 versions; Hedera children | F1 | T-V3, sizes, gas report |
| **F3** | clientkeys `UAKey`, derivation (§8.1), no-raw-sign API, role path for `SubjectAccount` keys, app screens 5/14 and the approvers wizard (APP A3) | F0 (F1 for registration) | clientkeys tests; app e2e on dev chain |
| **F4** | VC layer: `UAAttestations` (EVM), VP digest + verification in the shared libraries, evidence-bundle format, attester flow into `ComplianceRegistry` (with AS1) | F1, AS1 | T-ATT; Odoo/app round trip |
| **F5** | node: `scaas-intent/1.3` `evm.ua_meta_tx`, pre-gossip UA checks, `ua_metatx` jobs, indexer events, config | F0, F2 | mesh e2e on dev chains |
| **F6** | Odoo (parent repo): `blockchain.ua`, address forms, signed ops, portal registration, credentials model | F1, F3 | Odoo tests + `pg_constraint` |
| **F7** | Cosmos: `ua-registry` contract, 32-byte passkey accounts (R315), `bip340`/FROST-secp | F0 | family tests on vectors |
| **F8** | Soroban, then TON (no registry; wallet-bound key rules), Sui, Aptos, Solana (passkey owner = UA id, `["ukey", keyHash]`) — one family per change | F0, family streams | family tests on vectors |
| **F9** | PQ kinds (`mldsa44/65`, `fndsa512`) on the private chain (precompile), registry gen 2 where needed; with spec E | F1, spec E | private-chain e2e |
| **F10** | DEX/mandate UA support (§17 Q4/Q5), `OrderBookDex` 1271 gas cap fix | F2 | DEX suite |

---

## 17. Owner to confirm

Decisions taken by this spec on the open design points, each with its default; a different answer changes only the
rulings named.

1. **Identity vs rotation (R302).** Decided: a UA is immutable (single-key or policy hash); rotation and membership
   changes = new UA + move funds; stable identity = `SubjectAccount` (b). Alternative: a rotatable "policy" kind
   (id = hash of the first policy, current policy in the registry with a timelock) — rejected for v1 because it
   brings back an admin-like mutable record per account.
2. **Zether `authRef` immutability (R305).** Decided: immutable (RS2-9 kept). Alternative: timelocked
   `rotateZetherAuth` signed by the current `authRef` (AR §2.7.1 design with guardian veto limits).
3. **Rogue-key approach (R296).** Decided per kind: per-member registration (`msig`, `bls12381-multi`), KeyAgg
   coefficients + aggregate PoP (MuSig2), DKG PoK + group PoP (FROST), threshold ECDSA = native EOA.
4. **DEX with UA makers (§5.4).** Decided: not in v1; UA holders trade through native accounts or option (b). Needs a
   UA-ledger allowance model (`uaApprove` to contracts) and `OrderBookDex` v2 with `bytes32 maker`.
5. **`MandateWallet` with a UA owner/delegate.** Decided: not in v1 (a `MandateWallet` v2 calling
   `requireAuthorized`).
6. **Derivation purpose number `7225'` and coin level `0'` (§8.1).** Decided: one chain-independent UA tree (same UA
   on every chain). Alternative: per-coin trees (unlinkable across chains, different ids per chain).
7. **Regulated (AS) tokens and UA receivers.** Decided: AS regulated tokens stay native-only; a `bytes32`-keyed
   compliance check would be an AS amendment.
8. **On-chain registration gate (S6).** Decided: none in v1; sponsorship limits at the node. Alternative: an
   immutable `IRegistrationPolicy` (invite / attested) per registry generation (AR §2.3c).
9. **ed25519 on public EVM (§7.3).** Decided: disabled by default (≈ 0.4–1.2 M gas); enabled per chain on request.
10. **PoP chain binding (R295).** Decided: bound to chain and registry (one signature per chain). Alternative:
    chain-independent PoP (one signature registers everywhere; anyone can replicate a registration to other chains).
11. **Second typehash for v3 (R309).** Decided: `UAMetaTransaction` with its own typehash — an explicit exception to
    R140.
12. **TON (R314).** Decided: no registry; wallet-bound derived keys; chain-wide keyHash uniqueness not enforced.
13. **Cosmos 32-byte passkey accounts and Solana passkey owner = UA id (R315).** Decided: yes, at the family
    streams (breaking for dev accounts).
14. **Credential formats (§9.2).** Decided: SD-JWT VC default, BBS optional; subject ids `did:pkh` / `urn:scaas:ua:v1`;
    no DID method of our own.
