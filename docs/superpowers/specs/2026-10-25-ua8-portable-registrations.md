# UA-8: portable UA registrations — a UA registered on one chain can be registered on any other chain by anyone

**Status:** short design for the owner's review (controller, 2026-10-25). Nothing is built. Queued **after plan 5h**,
before UA-7 (whose KEM keys use §2). The choices below (P1–P6) are controller proposals; the owner may override them.

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
on any chain, accepted only with `version` > the stored one. **There is no revocation** (owner 2026-10-25): a key
that has been on chain stays public forever and cannot be withdrawn; a newer version only says which key is current.

**P5 — What the version does and does not do (stated, not solved).** It orders the keys: on a chain, the contract
uses the highest version it holds for new on-chain sessions (UA-7 C3 checks that each wrap names the member's current
version on that chain). It does **not** stop anyone from encrypting to an older key: the old public key stays on
every chain where it was stored, and a sender can use it off chain, or on a chain where nobody has copied the newer
record yet. A new key reaches chain X only when someone submits it there. So: honest clients use the highest version
they can see (the chain they use and the UA's home chain when known); the recipient's client shows a warning for
anything wrapped to an older key; and if an old secret key may have leaked, the UA must assume that anything sent to
that key — before or after the change — can be read.

**P6 — Unchanged.** UA ids, key data, `keyHash` and `_keyOwner` uniqueness (per chain), the per-chain generations and
kind caps, write authorization (chain-bound), ML-DSA expanded-key caches (per chain, rebuilt on registration).

## 3. Work (for the plan after 5h)

1. `UAKinds` (`PURPOSE_POP_V2`, `portablePopDigest`), `UARegistry.register` on the portable digest, `pop` / `pqzPop`
   in `UARegistered`; forge tests (copy a registration between two registries with different chain ids /
   addresses; disabled kind reverts; msig).
2. The record form of P4 as a shared library (`UAKinds.recordDigest`), used by UA-7's `PqChat`.
3. Clients (`ua-rs`, `ua-cs`, `ua-qt`, JS) and vectors (`smartcontracts/vectors/ua/`: portable PoP rows, a record
   row); accounts.md, decisions entry; `pqz_reg_message` in the clients and the PQZ e2e scripts on the new digest (the
   `R_REG` relation, statement and precompile do not change — only the 32-byte message's pre-image).
