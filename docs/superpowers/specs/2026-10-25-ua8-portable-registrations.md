# UA-8: portable UA registrations — a UA registered on one chain can be registered on any other chain by anyone

**Status:** short design, **registration flow approved by the owner 2026-10-25** (P1, P2, P7, P8); **scope: every family (owner 2026-10-29, P10)**; **PQ verification: on chain on EVM, added for Cosmos / Soroban / Sui (owner 2026-10-29), proposed additions NEAR `mldsa65` (host function) and Algorand `fndsa512` (after AVM v14), relayer-checked elsewhere (P11)**. Nothing is built. Queued **after plan 5h,
before fs3 Task 13** (owner 2026-10-25; the SCaaS testnet redeploys the registry once) and before UA-7. The choices below (P1–P9) are controller proposals; the owner may override them.

**Request (owner 2026-10-25).** "When an account is registered in `UARegistry` on Ethereum, anyone can take exactly
that information and register it on another chain: a UA account does not depend on the chain (its transactions do).
The KEM keys likewise."

## 1. Today

- The **UA id is already chain-independent**: `UA = keccak256(keccak256(kind_tag) ‖ key_data)`, a pure function, the
  same on every chain ([accounts.md](../../contracts/accounts.md) scope, CTR-UA-03).
- The **registration is not**: `register(kind, keyData, pop, pqzKey, pqzPop)` checks a proof of possession over
  `uaMessage(kind, POP, popDigest(...))` with
  `popDigest = keccak256(PURPOSE_POP ‖ chainKeyHash ‖ chainUid ‖ registry ‖ ua ‖ pqzKeyHash)` (`UAKinds.sol`); the
  chain id and the registry address are inside, so only the key holder can register on another chain (a new PoP
  per chain). The PQZ key's `R_REG` proof absorbs the same digest.
- **Writes** (`requireAuthorized`, the mtx envelopes) are bound to the chain by `uaAuthDomainSeparator(generation,
  chainId, registry, chainUid)`. That stays: transactions depend on the chain.

## 2. Design

**P1 — Portable proof of possession.** New digest without chain or registry:
`portablePopDigest = keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)` under a new versioned tag
(`PURPOSE_POP_V2`; `kemRecordHash` = the hash of the initial KEM record `(version, pk)` given in `register`, P2; each
hash 0 when that attribute is absent). The PQZ key's `R_REG` proof is made over
`uaMessage(0x0142, POP_V2, portablePopDigest)`; the signer's `pop` over `uaMessage(kind, POP_V2,
keccak256(portablePopDigest ‖ pqzPopHash))` (`pqzPopHash` = keccak256 of the `R_REG` proof, in `attrs`; 0 only
without a PQZ key): the
proof is made first, then signed, so one signature also covers the proof (no cycle: the proof's own message does not
contain its hash). Both are made once and valid on every chain. `register` accepts only this form (one rule; all chains are test-only, so the registries are
redeployed with no migration).

**P2 — One `register`, everything in one call; anyone may submit it.**

```solidity
struct UAAttrs { bytes pqzKey; bytes32 pqzPopHash; uint64 kemVersion; bytes kemPk; }   // empty / 0 = absent

function register(uint16 kind, bytes calldata keyData, UAAttrs calldata attrs,
    bytes calldata pop,      // required: the signer's signature over portablePopDigest(ua, pqzKeyHash, kemRecordHash)
    bytes calldata pqzPop)   // optional here: the R_REG proof itself (its hash is attrs.pqzPopHash); else storePqzPop
    external returns (bytes32 ua);
```

registers the UA **with its attributes** in one transaction (owner 2026-10-25: not two steps; this form approved the
same day). `keyData` is the identity (it alone defines the UA id, so it never holds the attributes: a PQZ key inside
it would make the same signing key two UAs, and a new KEM version would change the id); `attrs` are the keys
attached to the UA; `pop` is the consent over identity and attributes; `pqzPop` (a zero-knowledge proof about a
different key, the PQZ one, made by a different proof system) is optional (P8). It stays permissionless: the submitter
pays the gas. Copying a UA to another chain = sending the same fields to that chain's registry; a client or a relayer
service can do it for any UA it sees on another chain. Today the registry stores `keyData` and the PQZ key (SSTORE2)
but not `pop` / `pqzPop`; **UA-8 stores every `register` field in contract state** (owner 2026-10-25: "store all of
it": `pop`, `pqzPop`, the KEM record and its signature, as SSTORE2 blobs), so anyone can rebuild the registration from
state and re-submit it elsewhere even when logs are gone (history expiry); the event carries them as well. Cost
[estimate, ≈ 1,530 state gas per byte]: `pop` 65 B (secp256k1) to 3,309 B (ML-DSA-65), ≈ 0.1–5 M; `pqzPop` (the
`R_REG` proof, 28,080–35,420 B by set) ≈ 43–54 M; the PQZ key itself (16–22 KB) ≈ 25–35 M is stored already. A full
PQ registration with a stored proof is then ≈ 75–95 M of state gas: more than a 60 M block, so on such a chain the
proof is stored by a second call `storePqzPop` (P9) — on chains with larger blocks (SCaaS testnet 200 M) one `register` holds everything. Later KEM versions come by
`setKemKey` (P7).

**P3 — What must match.** The same kind must be enabled in the target registry's generation (a PQ kind needs its
verifier there; a PQZ key needs `UAPqzVerifier` and the PQZ precompile of the same parameter set — otherwise the copy
reverts like any registration of a disabled kind). `msig` UAs: the structure is key data, so the id and the members'
PoP are portable the same way (members sign `uaMessage(MSIG, POP_V2, portablePopDigest)`).

**P4 — Only the chat (KEM) key changes; the balance key never does.** The PQZ key (balance encryption, UA-6) is
immutable: part of the registration, set once and copied unchanged to every chain (owner 2026-10-25). The only
attribute a UA may change is UA-7's KEM (chat) key: a new key is a record `(ua, version, pk)` signed by the UA over a
chain-independent digest `uaMessage(kind, purpose, keccak256(tag ‖ ua ‖ version ‖ keccak256(pk)))`, stored by anyone
on any chain, **in any order** (owner 2026-10-25: a lower version may be stored after a higher one, because others
may still use it). Each `(ua, version)` is written once. **There is no revocation** (owner 2026-10-25): a key that has
been on chain stays public forever and cannot be withdrawn; the highest version only says which key is the latest.

**P5 — Versions are the same on every chain.** The version is inside the record the UA signed, so version v names
the same key on every chain (owner 2026-10-25). A chain holds whichever versions someone copied to it, in any order;
every stored version is usable (UA-7 C3 accepts a wrap to any of them); clients normally pick the highest version they
see, and need no warning for an older one. If an old
secret key may have leaked, the UA must assume that anything sent to that key can be read.

**P6 — Unchanged.** UA ids, key data, `keyHash` and `_keyOwner` uniqueness (per chain; kept for the signer keys and for
**proven** PQZ keys (P8), owner 2026-10-25: a front-runner cannot claim a PQZ key for another UA because `R_REG` is
bound to the registering UA's id — with the portable digest too — so copying a registration only ever registers the
same UA), the per-chain generations and
kind caps, write authorization (chain-bound), ML-DSA expanded-key caches (per chain, rebuilt on registration).

**P7 — The KEM (chat) key in `UARegistry` (owner 2026-10-25: registered in UA-8; every version needs the UA's
signature, and the signature is stored with it).** The UA signs a **chain-independent** record
`kemRecord = (ua, version, pk)` (the digest has no chain id and no registry address, P4); `UARegistry.setKemKey(ua, version, pk, sig)` stores it on any chain, submitted by **anyone**
(the submitter pays the gas; no fee, P9): the contract checks the signature
against the UA's registered key and stores the record under `(ua, version)` if that version is not stored yet (any
order, P4). So a key set on Ethereum can be copied to any other chain by anyone, every version likewise (owner 2026-10-25: "UA accounts do
not depend on the chain; the KEM keys too"). `keyId` = `version`. **One
scheme only: ML-KEM-1024 + X25519** (owner 2026-10-25: the default and the only one): the X-Wing combiner with
ML-KEM-1024 (FIPS 203, NIST level 5) in place of ML-KEM-768, the QSF construction of the CFRG hybrid-KEM draft; pk
1,600 B, ciphertext 1,600 B, shared secret 32 B; secure while either part holds. The contract accepts only 1,600-byte
keys. **No revocation** (owner 2026-10-25: what is on chain cannot be withdrawn): an older key stays public and usable,
on chain and off chain (P5). The balance (PQZ) key never changes. **Several keys per UA (one per device) later** (owner
2026-10-25: one key first): the storage is keyed by `(ua, keyId)` from the start, so adding `addKemKey` later
changes no layout; until then the devices of one UA share its key. **Only PQ kinds may hold a KEM key** (owner 2026-10-25), as
for the PQZ key: the UA-6 U3 holder set — `mldsa44` / `mldsa65` / `fndsa512`, or an `msig` whose non-PQ weight
(members outside 0x0130–0x0133) is below its threshold (`slhdsa128s` is not a direct holder of either key, owner
2026-10-25); `register` with a KEM record and `setKemKey` revert for any other kind
(`UAPqzHolder`-style error).

**No one-owner check for KEM keys** (unlike the signer and PQZ keys): a KEM record carries no proof of possession of
the KEM secret, so a uniqueness check would let anyone who sees a key first register it under their own UA and block
the real owner on that chain; a UA that lists someone else's KEM key gains nothing (it cannot decrypt). The registry stores each version's `pk` **and its signature** in state (SSTORE2), so any version can be copied to
another chain from state alone. Views: `kemKeyOf(ua) → (version, pk, sig)` (the highest stored version),
`kemKeyAt(ua, version) → (pk, sig)`, `popOf(ua)`, `pqzPopOf(ua)`. Event `UAKemKeySet(ua, version, keyHash)`.

**P8 — The balance-key proof is optional (owner 2026-10-25).** So that a UA with all its keys — signing key, PQZ
(balance) key, KEM key — can be registered on chains without the PQZ precompile (Ethereum, for example). The two
checks in a registration:

| What | Proves | Checked where |
|---|---|---|
| the **signer's signature** (`pop`) | possession of the signing key, and the UA's consent to its attributes (PQZ key, KEM key) | every chain where the kind is enabled: secp256k1 (`ecrecover`), P256 (precompile), ML-DSA / FN-DSA / SLH-DSA (Solidity verifiers; ≈ 6–19 M gas on Ethereum, accounts.md §1.6) |
| the **`R_REG` proof** | possession of the PQZ secret key | only chains with the PQZ precompile |

In the one `register` call (P2):

1. **`pop` (the signer's signature over `portablePopDigest`) is always required and checked**, as today. It also
   binds the attributes: without it, anyone could attach their own PQZ key to someone else's UA first; the PQZ key
   never changes, so payments to that UA would be encrypted to the attacker's key. One signature covers the UA and
   both attributes (the digest holds both hashes, P1), so one verification.
2. **Only PQ kinds may attach the PQZ key or a KEM record** (owner 2026-10-25; the PQZ rule of UA-6 U3, extended to
   the KEM key): the U3 holder set (`mldsa44` / `mldsa65` / `fndsa512`, or a PQ-eligible `msig`); any other kind
   reverts.
3. **Only the proof for the balance-encryption key is optional (owner 2026-10-25); each PQZ key carries a `proven`
   flag.** A PQZ key always comes with `attrs.pqzPopHash` ≠ 0 (the client makes the proof before registering; the hash
   is covered by `pop`, P1), and the registry stores that hash. The proof bytes `pqzPop` may be given in `register` or
   later by `storePqzPop` (P9); either way they must hash to the stored `pqzPopHash`. On a chain with the PQZ verifier
   they are also checked: `proven = true` (a bad proof reverts). On a chain without it they are stored unchecked,
   `proven = false`. Until the bytes are given the key is `proven = false`. PQZ token
   contracts accept only proven keys; a chain without the precompile has no PQZ tokens, so an unproven key there is a
   directory entry to copy elsewhere.
4. **The one-UA-per-PQZ-key check applies only to proven keys.** If unproven keys claimed the key, anyone could list a
   victim's PQZ key without a proof and block the victim. A UA that lists someone else's PQZ key without a proof gains
   nothing: PQZ tokens do not accept it.
5. **The kind rule stays:** a kind must be enabled on the chain (its verifier exists), so that nothing can be received
   that can never be spent.

On Ethereum the cost of a registration is then the signer's signature check (cheap for secp256k1 / P256; ≈ 6–19 M
gas for ML-DSA in Solidity) plus storage; when the UA is copied to a chain with PQZ, anyone attaches the `R_REG` proof
and the key becomes proven.

**P9 — The later writes (owner 2026-10-25: relayable, no fee).** Besides `register`, two writes, each with a chain-independent signature that is **stored** with the data:

```solidity
function setKemKey(bytes32 ua, uint64 version, bytes calldata kemPk, bytes calldata sig) external;
// sig over uaMessage(kind, PURPOSE_KEM, keccak256(KEM_TAG ‖ ua ‖ version ‖ keccak256(kemPk)))     (P7)
function storePqzPop(bytes32 ua, bytes calldata pqzPop) external;   // after register; no signature
```

`storePqzPop` needs **no signature** (owner 2026-10-25): `register` stored `pqzPopHash`, which the UA's `pop` covers,
so the call only checks `keccak256(pqzPop) == pqzPopHash` — garbage cannot match — and does nothing if the bytes are
already stored. Where the PQZ verifier exists it also checks the proof (`proven = true`). `setKemKey` keeps its
signature (a new KEM version is new consent); an `msig` signs it with its m-of-n members.

**All of them are mtx-style writes without a chain and without a fee** (owner 2026-10-25): signed by the UA, relayable
by anyone (the submitter — the UA or a relayer — pays the gas), chain-independent, so the same record can be moved to
any chain. **There are no `mtx*` fee forms** (`mtxRegister` / `mtxSetKemKey` / `mtxStorePqzPop` dropped): these writes
are not token operations, so there is no token to take a fee from; a relayer that wants payment arranges it off chain.

**P10 — Every family (owner 2026-10-29: "UA-8 phủ tất cả family").** The portable registration is one record with
the same bytes on every family, not an EVM feature. Common rules:

- `portablePopDigest` (P1), `uaMessage(kind, POP_V2, …)` and the KEM record digest (P7) are byte-identical on every
  family; one vector file (`smartcontracts/vectors/ua/`) is run by every family's tests. Every family has keccak256
  (EVM opcode; Cosmos software keccak, already used; Soroban `crypto().keccak256`; Sui `sui::hash::keccak256`; Aptos
  `aptos_hash::keccak256`; Solana `keccak` syscall; NEAR `env::keccak256`; Algorand `keccak256` opcode).
- A family accepts a registration only for the kinds it verifies (P3); any other kind is refused there, the record
  stays valid elsewhere.
- PQZ exists only where its verifier exists (EVM today): elsewhere the record stores `pqzKeyHash` / `pqzPopHash` with
  `proven = false` and never uses them (P8's "registry without the PQZ verifier").
- Anyone may submit; the submitter pays gas and storage (the family's storage rule: deposit, MBR, rent or TTL), no fee
  form (P9).
- `keyHash` uniqueness (P6) per family as today.

Where the record lives (controller proposals for the families without a registry; owner may override):

| Family | Today | With UA-8 |
|---|---|---|
| EVM, Hedera | `UARegistry` | P1–P9 as written |
| Cosmos | `ua-registry` CosmWasm contract | the same `register` / `setKemKey` / `storePqzPop` messages |
| Soroban | persistent entries in the `SmartKeyAccount` factory (`UA(ua)`, `KEY(keyHash)`) | the same entries plus KEM records; TTL extended by the node like other persistent state |
| Sui | `Registry<T>` (`key_owner` table) | the same functions; KEM records in a table keyed `(ua, version)` |
| Aptos | registry resource under the package root | the same functions; KEM records in a table keyed `(ua, version)` |
| Solana | PDAs `["ua", ua]`, `["ukey", keyHash]` | the same instructions; KEM record PDA `["ukem", ua, version]` |
| NEAR | **no registry**: each token contract keeps its own subject records (`Holder` → keys, origins, guardian, policy; Aptos `Account` model), a `Ua` opened lazily by its first signed op (id checked against the key data, no PoP), key ops fanned out to every held token | **a new `ua-registry` contract per deployment** holding the portable record and the KEM / PQZ attributes (discovery, chat keys). Tokens keep their per-token key records and the lazy open: a cross-contract read is asynchronous on NEAR, so a token never waits on the registry |
| Algorand | one `account` app per deployment holds the subject records shared by every token (tokens, mandate and DEX call its `verify` by inner app call), lazily opened, no PoP | the **`account` app gains** `register` (portable PoP), `set_kem_key`, `store_pqz_pop`, the record and KEM boxes; the lazy open stays |
| TON (GRAM) | **no registry** (documented gap: wallet-bound keys, `set_key` with a key signature) | **a new `ua-registry` contract** (actor messages `Register`, `SetKemKey`, `StorePqzPop`; one child contract per UA if a single contract's state would grow without bound) — needs its own short design before the plan |

Order: EVM first (P1–P9), then every family with a registry (Cosmos, Soroban, Sui, Aptos, Solana), then Algorand (the
`account` app gains the writes; after the near-algorand merge), then NEAR (a new `ua-registry` contract; after the
near-algorand merge), TON last (after its registry design). NEAR and Algorand are separate tasks: different storage
(per-token records vs one `account` app), different execution (asynchronous receipts vs atomic groups) and different
storage payment (NEAR storage staking by attached deposit vs Algorand box MBR by a payment transaction). Each family is
a task of the same plan or a follow-up plan; the vector file is the shared contract between them.

**P11 — PQ verification per family, and the relayer's part where a chain cannot verify (owner 2026-10-29: option
(a) plus part of (b) — Cosmos, Soroban, Sui).** A KEM key is held only by PQ kinds (P7), so a family that cannot verify
the UA's PQ signature cannot check `pop` or a KEM record on chain. State of each family (web check 2026-10-29; re-check
before the plan, these move fast):

| Family | What exists for PQ signatures (contract-callable) | Fit with our kinds | UA-8 rule |
|---|---|---|---|
| EVM, Hedera | our verifiers (`UAMldsaVerifier`, `UAFndsaVerifier`, `UASlhdsaVerifier`); EIP-8051 / -8052 / -8355 still drafts | all PQ kinds | **(a)** on chain, P1–P9 |
| NEAR | **host function `ml_dsa_verify`** (nearcore 2.14.0, protocol 88): ML-DSA-65, empty context, message as-is, ≈ 0.54 Tgas | `mldsa65` exactly; others pure Wasm only | **(b), proposed addition**: `mldsa65` on chain through the host function in the NEAR `ua-registry`; other PQ kinds relayer-checked (or a pure-Wasm spike) |
| Soroban | **CAP-0087** `verify_sig_ml_dsa_{44,65,87}` (Implemented, Protocol 30, not on mainnet yet); pure-Rust ML-DSA measured at 51 M / 77.5 M instructions (third party, testnet) | `mldsa44`, `mldsa65` exactly; `fndsa512` / `slhdsa128s` pure only | **(b)**: the host functions once Protocol 30 is live, pure Rust until then (spike against the network's budget) |
| Cosmos | none (SDK 0.55 `ml_dsa_65` is for account / consensus keys only) | all four as pure Rust → Wasm (unmeasured) | **(b)**: our Wasm verifier in `ua-registry`, gated by a spike |
| Sui | none callable from Move; ML-DSA-65 native accounts on devnet (mainnet Q1 2027); SLH-DSA-SHA2-128s Move vaults announced, code not published | `slhdsa128s` via Mysten's vault code; pure-Move ML-DSA / Falcon judged infeasible | **(b)**: `slhdsa128s` when Mysten publishes the Move code (or our own pure-Move spike), a Move ML-DSA function when Sui ships one; relayer-checked meanwhile |
| Algorand | **opcode `falcon_verify`** (AVM v12+): deterministic Falcon-1024 only; AVM v14 (go-algorand master, unreleased) adds deterministic Falcon-512 | today none of ours; `fndsa512` after AVM v14 if the client signs deterministically (fixed salt; needs a test vector that the deterministic signature verifies under our standard verifiers) | **(b), proposed addition**: `fndsa512` on chain in the `account` app once AVM v14 is on mainnet; relayer-checked until then; a separate `fndsa1024-det` kind is not proposed |
| Aptos | none callable from Move; AIP-137 (proposed) adds SLH-DSA-SHA2-128s account signatures | `slhdsa128s` pure Move plausible (estimate) | relayer-checked |
| Solana | none; SIMD-0416 proposes a Falcon-512 verify syscall (not activated) | `fndsa512` if its encoding matches | relayer-checked; revisit when SIMD-0416 activates |
| TON | nothing found; no registry yet (P10) | — | after its registry design |

Facts, sources and read dates: [research/pq-signatures-per-family.md](../../research/pq-signatures-per-family.md)
(web check 2026-10-29; the NEAR host function and CAP-0087 re-checked against their primary sources).

Native PQ **accounts** (Cosmos `ml_dsa_65`, Sui ML-DSA-65, NEAR NEP-645) are not enough: they sign the chain's own
transactions, while a UA registry must verify a UA's signature over the portable digest inside a contract. A family
gets status (b) only when a contract can run the verifier.

**Relayer-checked mode (owner 2026-10-29: "phải có thêm phần trách nhiệm của relayer").** Where a part cannot be
verified on chain — the PQ signature of `pop` or of a KEM record, the PQZ proof (P8, already "unproven"), a KEM key
proof if one is added later — the record may still be stored, under these rules (controller proposals, owner may
override):

1. **The relayer checks off chain before it submits**: the full verification the EVM registry does (UA id from key
   data, `pop` over `portablePopDigest`, every KEM record signature, the PQZ proof where it has the verifier). A node
   never submits a registration or a KEM record that fails it.
2. **Only listed relayers may write in this mode**: the registry takes the list at deployment (the same pattern as the
   relay router's targets); writes that the chain can verify stay open to anyone.
3. **The record says who checked each part**: `checked = chain | relayer(<relayer id>) | none` per part (signature,
   PQZ proof, KEM record), stored with the record and in the event.
4. **Everything needed to re-check is stored** (P2 already stores `pop`, `pqzPop`, every KEM record and its signature),
   and **clients always re-verify off chain** before they use a KEM key or a PQZ key read from such a chain; a record
   that fails is ignored. The UA id is a hash of its key data, so a client never trusts the relayer for the identity.
5. **A relayer-checked record never authorises anything on that chain**: a UA whose kind the chain cannot verify cannot
   sign writes there (transactions stay chain-bound, P6); the record serves discovery (KEM keys for UA-7, PQZ key
   lookup, copying to other chains).
6. **Residual, accepted with the mode**: a listed relayer that stores a bad record first takes that write-once
   `(ua, version)` slot on that chain (clients ignore it, the relayer id is on record, the slot is lost there); the
   operator delists such a relayer. Nothing is lost on any other chain.

Families in status (b) move a part from `relayer` to `chain` as soon as their verifier lands; records written earlier
keep their `checked` value (re-checking on chain is a later, optional call).

## 3. Work (for the plan after 5h)

1. `UAKinds` (`PURPOSE_POP_V2`, `portablePopDigest`), `UARegistry.register` on the portable digest, `pop` / `pqzPop`
   in `UARegistered`; forge tests (copy a registration between two registries with different chain ids /
   addresses; disabled kind reverts; msig).
2. P8: the optional `pqzPop`, the `proven` flag and `storePqzPop`, uniqueness only for proven PQZ keys; PQZ token contracts read `proven`; forge tests (register on a
   registry without the PQZ verifier, prove later on one with it; an unproven listing does not block the owner).
3. P7: `setKemKey` / `kemKeyOf` / `kemKeyAt`, the record digest (`UAKinds.recordDigest`), the 1,600-byte key check,
   write-once per version (any order), the event; forge tests (copy key records between two registries, a lower
   version after a higher one, a repeated version refused).
4. P9: `setKemKey` (signature), `storePqzPop` (hash check against the stored `pqzPopHash`, no-op when stored); forge
   tests (submitted by a third party, a `storePqzPop` with other bytes refused).
5. Clients (`ua-rs`, `ua-cs`, `ua-qt`, JS) and vectors (`smartcontracts/vectors/ua/`: portable PoP rows, KEM
   key record rows); accounts.md, decisions entry; `pqz_reg_message` in the clients and the PQZ e2e scripts on the new digest (the
   `R_REG` relation, statement and precompile do not change — only the 32-byte message's pre-image).
6. P10, per family (order as P10): the same three writes and the reads on each family's registry; the shared vector
   file run by every family's tests (copy a registration from the EVM registry to the family and back; a kind the
   family does not verify is refused; PQZ attributes stored unproven where there is no verifier); the node relays the
   writes as `call` jobs; Algorand `account` changes, then the NEAR `ua-registry` contract, each its own task, after the near-algorand merge;
   TON after its registry design.
7. P11: per family the `checked` field and the relayer-checked mode (listed relayers, off-chain check in the node,
   events); the node's off-chain verifier for every kind (reuse `ua-rs` / the clients' verifiers); client re-check
   before use. Spikes first for Cosmos (CosmWasm gas), Soroban (CPU / memory budget) and Sui (Move computation budget,
   or Sui's own verifier when published): each a pass / fail gate like the NEAR P-256 spike; a family that fails its
   spike stays relayer-checked.
