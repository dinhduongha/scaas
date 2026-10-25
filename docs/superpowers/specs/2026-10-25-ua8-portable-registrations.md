# UA-8: portable UA registrations — a UA registered on one chain can be registered on any other chain by anyone

**Status:** short design for the owner's review (controller, 2026-10-25). Nothing is built. Queued **after plan 5h,
before fs3 Task 13** (owner 2026-10-25; the SCaaS testnet redeploys the registry once) and before UA-7. The choices below (P1–P7) are controller proposals; the owner may override them.

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
`portablePopDigest = keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash)` under a new versioned tag (`PURPOSE_POP_V2`). The
signer's `pop` and the PQZ key's `R_REG` proof are made once, over `uaMessage(kind, POP_V2, portablePopDigest)`, and
are valid on every chain. `register` accepts only this form (one rule; all chains are test-only, so the registries are
redeployed with no migration).

**P2 — Anyone may register.** `register(kind, keyData, pop, pqzKey, pqzPop)` stays permissionless (it already is): the
submitter pays the gas. Copying a UA to another chain = sending the same five fields to that chain's registry; a
client or a relayer service can do it for any UA it sees on another chain. Today `UARegistered(ua, kind, keyData,
pqzKey)` keeps the key data and the PQZ key's pointer but not the proofs; UA-8 adds `pop` and `pqzPop` to the event so
anyone can read all five fields from the source chain and re-submit them.

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

**P6 — Unchanged.** UA ids, key data, `keyHash` and `_keyOwner` uniqueness (per chain), the per-chain generations and
kind caps, write authorization (chain-bound), ML-DSA expanded-key caches (per chain, rebuilt on registration).

**P7 — The KEM (chat) key in `UARegistry` (owner 2026-10-25: registered in UA-8).** The UA signs a **chain-independent** record
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
changes no layout; until then the devices of one UA share its key. The key is post-quantum authenticated only if the UA's signer is a PQ
kind (`mldsa44` / `mldsa65` / `fndsa512` or a PQ-dominant `msig`); clients show the others as "not PQ-authenticated".

**No one-owner check for KEM keys** (unlike the signer and PQZ keys): a KEM record carries no proof of possession of
the KEM secret, so a uniqueness check would let anyone who sees a key first register it under their own UA and block
the real owner on that chain; a UA that lists someone else's KEM key gains nothing (it cannot decrypt). Views: `kemKeyOf(ua) → (version, pk)` (the highest stored version), `kemKeyAt(ua, version)`. Event `UAKemKeySet(ua, version, keyHash)`.

## 3. Work (for the plan after 5h)

1. `UAKinds` (`PURPOSE_POP_V2`, `portablePopDigest`), `UARegistry.register` on the portable digest, `pop` / `pqzPop`
   in `UARegistered`; forge tests (copy a registration between two registries with different chain ids /
   addresses; disabled kind reverts; msig).
2. P7: `setKemKey` / `kemKeyOf` / `kemKeyAt`, the record digest (`UAKinds.recordDigest`), the 1,600-byte key check,
   write-once per version (any order), the event; forge tests (copy key records between two registries, a lower
   version after a higher one, a repeated version refused).
3. Clients (`ua-rs`, `ua-cs`, `ua-qt`, JS) and vectors (`smartcontracts/vectors/ua/`: portable PoP rows, KEM
   key record rows); accounts.md, decisions entry; `pqz_reg_message` in the clients and the PQZ e2e scripts on the new digest (the
   `R_REG` relation, statement and precompile do not change — only the 32-byte message's pre-image).
