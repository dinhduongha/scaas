# UA-8: portable UA registrations — a UA registered on one chain can be registered on any other chain by anyone

**Status:** short design, **registration flow approved by the owner 2026-10-25** (P1, P2, P7, P8). Nothing is built. Queued **after plan 5h,
before fs3 Task 13** (owner 2026-10-25; the SCaaS testnet redeploys the registry once) and before UA-7. The choices below (P1–P8) are controller proposals; the owner may override them.

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
hash 0 when that attribute is absent). The
signer's `pop` and the PQZ key's `R_REG` proof are made once, over `uaMessage(kind, POP_V2, portablePopDigest)`, and
are valid on every chain. `register` accepts only this form (one rule; all chains are test-only, so the registries are
redeployed with no migration).

**P2 — One `register`, everything in one call; anyone may submit it.**

```solidity
struct UAAttrs { bytes pqzKey; uint64 kemVersion; bytes kemPk; }   // empty = absent

function register(uint16 kind, bytes calldata keyData, UAAttrs calldata attrs,
    bytes calldata pop,      // required: the signer's signature over portablePopDigest(ua, pqzKeyHash, kemRecordHash)
    bytes calldata pqzPop)   // optional: the R_REG proof; given and the PQZ verifier present => proven
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
proof is stored by a second call `storePqzPop(ua, pqzPop)` (anyone; checked where the PQZ verifier exists, else kept
unchecked as in P8) — on chains with larger blocks (SCaaS testnet 200 M) one `register` holds everything. Later KEM versions come by
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
(the submitter pays the gas; through mtx when a relayer charges the UA a fee): the contract checks the signature
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
3. **Only the proof for the balance-encryption key is optional (owner 2026-10-25): `pqzPop` (the `R_REG` proof) may be empty; each PQZ key carries a `proven` flag.** Empty: the key is stored with
   `proven = false`. Non-empty on a chain with the PQZ verifier: checked, `proven = true` (a bad proof reverts).
   Non-empty on a chain without it: not checked, emitted with the registration (P2), `proven = false`. Anyone may
   later submit `provePqzKey(ua, pqzPop)` on a chain with the precompile; with the portable digest (P1) the proof bytes
   made once are valid everywhere. PQZ token
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

## 3. Work (for the plan after 5h)

1. `UAKinds` (`PURPOSE_POP_V2`, `portablePopDigest`), `UARegistry.register` on the portable digest, `pop` / `pqzPop`
   in `UARegistered`; forge tests (copy a registration between two registries with different chain ids /
   addresses; disabled kind reverts; msig).
2. P8: the optional `pqzPop`, the `proven` flag and `provePqzKey`, uniqueness only for proven PQZ keys; PQZ token contracts read `proven`; forge tests (register on a
   registry without the PQZ verifier, prove later on one with it; an unproven listing does not block the owner).
3. P7: `setKemKey` / `kemKeyOf` / `kemKeyAt`, the record digest (`UAKinds.recordDigest`), the 1,600-byte key check,
   write-once per version (any order), the event; forge tests (copy key records between two registries, a lower
   version after a higher one, a repeated version refused).
4. Clients (`ua-rs`, `ua-cs`, `ua-qt`, JS) and vectors (`smartcontracts/vectors/ua/`: portable PoP rows, KEM
   key record rows); accounts.md, decisions entry; `pqz_reg_message` in the clients and the PQZ e2e scripts on the new digest (the
   `R_REG` relation, statement and precompile do not change — only the 32-byte message's pre-image).
