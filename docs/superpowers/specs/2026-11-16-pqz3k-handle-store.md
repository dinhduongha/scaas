# The three-key PQZ handle in the wallet's store (T21 O5 (b))

Status: **BUILT** (branch `pqz3k-handle`; gates `smartcontracts/evm/runs/2026-11-16-pqz3k-handle-gates.txt`, mutants
`smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.txt`). UNAUDITED.

Owner 2026-11-16, T21 O5 (b): "ok, as proposed" (TODO, ua-rs-sign line "Before the freeze (O5 (b))"). Rules this note
implements, not reopens: [CLI-SGN-51](../../clients/signers-clientkeys.md#CLI-SGN-51) (K3-7, the key handle, the marks),
[ARCH-POS-13](../../decisions.md#ARCH-POS-13) (never a decryption oracle), spec
[2026-11-13-pqz-three-keys.md](2026-11-13-pqz-three-keys.md) §6 / §14.1 / §14.18 / §14.19, signer spec §8.2 (lock revokes every
handle), T21 L82 (read lease). Ledger rows closed: L39 (handle outside the store), L43 (empty-window bypass), L47 (`Accepted`
names no token), L66a (ua-rs runs no `opening.json` `rejects` row).

## 1. What moves

| Before (O5 (a), `vectors` only) | After |
|---|---|
| `PqzKeyHandle::new(seed64, …, layout)`: both seeds in plain struct fields, `Drop` = `fill(0)` | `Wallet::pqz_scoped_key(&Scope)`: both seeds derived inside `SecretStore`, one arena slot, revoked by `lock()` |
| `check(credit, closure(open_kem_seed, input))`: the caller's closure got the 96-byte KEM seed | `check(&Credit)`: the handle runs pqz-ffi `opening::check_recipient` itself; no caller code sees the KEM seed |
| `with_secret_own(own, f)` and `with_secret_window(entries, f)`, two entries, `with_secret_window(&[], f)` passes | one entry `with_secret_debit(&Debit, f)`: own part and window together, own required when `lastDebit > 0`, an empty debit refused |
| `Accepted { handle, index, content }`, `WindowEntry` without a token | both name the token; a window entry of another token, or an acceptance of another token, is refused |
| local `hmac` / `hkdf` (`prk` unwiped) | `wallet::hkdf_sha256` / `hmac_sha256`, `Zeroizing` outputs |
| layout passed by the caller | the build's set (`pqz_pack::B`, `stmt::N`): one set per build (spec §10.2) |

The old code is kept in `clients/ua-rs/legacy/pqz3k-handle/` and `clients/clientkeys/legacy/pqz3k-handle/` (not built).

## 2. API (ua-rs, feature `pqz`; `src/pqz3k/handle.rs`, re-exported as `scaas_ua::pqz3k::*`)

```rust
pub struct Scope { pub account: u32, pub index: u32, pub ua: [u8; 32], pub chain_uid: [u8; 32],
                   pub token: Option<[u8; 20]>, pub version: u64 }            // token None: offchain-shared (class 2)
impl Wallet { pub fn pqz_scoped_key(&self, scope: &Scope) -> Result<PqzKeyHandle, Error> }  // WalletLocked while locked

impl PqzKeyHandle {
    pub fn class(&self) -> KeyClass;  pub fn scope(&self) -> [u8; 20];  pub fn version(&self) -> u64;
    pub fn pk(&self) -> Vec<u8>;           // keygen(seed32).pk, public, computed at derivation
    pub fn open_kem_pk(&self) -> Vec<u8>;  // 0x01 ‖ ek ‖ X25519 pk (CTR-UA-32 scheme 1), public
    pub fn seed_commitment(&self) -> Result<[u8; 32], Refused>;          // keccak256(seed32), the KAT's view
    pub fn check(&self, c: &Credit) -> Result<Checked, Refused>;         // K3-7
    pub fn marks(skips: &[Skip]) -> Result<Vec<u64>, Refused>;           // unchanged (Fable P2-1)
    pub fn with_secret_debit<R>(&self, d: &Debit, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Refused>;
    pub fn with_secret_keygen<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Refused>;   // R_REG, counted apart
    pub fn secret_loads(&self) -> u32;  pub fn keygens(&self) -> u32;
}
pub struct Credit<'a> { pub token: [u8; 20], pub index: u64, pub slot: [u8; 32], pub code: &'a [u8],
                        pub auditor: Option<AuditorKeys<'a>>, pub reads: Reads }
pub struct AuditorKeys<'a> { pub ua: [u8; 32], pub pk: &'a [u8], pub kem_pk: &'a [u8] }
pub enum Checked { Accepted(Accepted, u64 /* amount */), Skip(Skip) }
pub struct Accepted { handle, token, index, content }                 // fields private; made by `check` only
pub struct Debit<'a> { pub token: [u8; 20], pub last_debit: u64, pub own: Option<Own<'a>>, pub window: &'a [WindowEntry<'a>] }
pub struct Own<'a> { pub pu: &'a [u8], pub pvf: &'a [u8], pub own_tag: [u8; 32] }
pub struct WindowEntry<'a> { pub token: [u8; 20], pub index: u64, pub slot: [u8; 32], pub code: Option<&'a [u8]>,
                             pub accepted: Option<&'a Accepted> }
```

Explicit named parameters, one entry point per operation (`check`, `with_secret_debit`, `with_secret_keygen`). Test-only
(feature `vectors`): `PqzKeyHandle::vectors_from_seed(seed64, &Scope)` (the same derivation into a store of its own) and
`PqzKeyHandle::vectors_from_secrets(seed32, open_kem_seed96, &Scope)` (the rows of `opening.json` key by KeyGen seed); the raw
derivations `open_kem_seed` and `pqz_token_key_seed_without_opening` stay `vectors`-only (O5 (a)). A release build names none of
them (`compile_fail` doctests). `Wallet::pqz_scoped_key` refuses in a `vectors` build until `facade::vectors_unlock` (the
marker every key-handle constructor checks, no-decryption-oracle §4.8).

`pqz_token_key_seed_without_opening` (a class-3 token **without** the opening, CTR-PQZ-37's accepted exposure) gets no store
path in this task: the TODO text names the handle of keys with the opening only.

## 3. Where each secret lives

- **Derivation**: `SecretStore::key(KeyId::PqzScoped(account, index, ua, chain_uid, token, version), derive)` under the store's
  write lock, from the arena's BIP-39 seed. `derive` returns `seed32 ‖ openKemSeed` (128 bytes, `Zeroizing`) and the public
  data `pk ‖ kemPk`. `seed32` is K3-2 (`HKDF-SHA256(seed, "scaas.ua.pq.v1", label ‖ u32 account ‖ u32 index ‖ chainUid ‖ [token]
  ‖ be64 v)`), `openKemSeed` K3-6b (`HKDF-SHA256(seed, "scaas.ua.kem.v1", label ‖ ua ‖ chainUid ‖ [token] ‖ be64 v, 96)`), both
  through `wallet::hkdf_sha256`. A second call with the same scope returns the same slot.
- **The handle** holds a `Handle` (the store's `Arc`, the generation, the slot) and public data only: class, scope, ua,
  chain, version, its id `keccak256("scaas.pqz3k.handle.v1" ‖ chainUid ‖ scope ‖ ua ‖ be64 v)`, `pk`, `kemPk`, two atomic
  counters. No secret byte is a field; `Debug` shows class, scope and version.
- **Use**: every entry that needs a secret takes a read lease of the store (T21 L82), copies the bytes it needs into a
  `Zeroizing` buffer under the read guard (`seed32` for the debit and keygen entries and the own-tag check; `openKemSeed` for
  `check`), drops the guard, marks `wallet::copied()` (the `vectors` pause hook), uses the copy, and wipes it before the lease
  ends. So `lock()` waits for an entry in flight (a prover's closure, a check), and the long work does not hold the store's guard
  (other signers run).
- **Lock**: `Wallet::lock()` wipes the arena and raises the generation; every later call of an earlier handle is
  `Refused::KeyRevoked` before any input is read for a secret; an unlock does not revive it (a new `pqz_scoped_key` gives a new
  handle with the same commitment).

Outside the store's coverage, as for every other key (signer spec §8.2): the copies the crates make (HKDF state, ML-KEM and
X25519 types inside pqz-ffi, wiped by their own `zeroize` where they have one), the caller's closure and what it keeps.

## 4. The holder check (`check`, K3-7)

In order, each refusal before any secret is read: TRIVIAL slot → `Input`; code not `STOP ‖ data` → `Input`; not an opening op 1
blob of this build's set → `Input`; a token not the handle's (class 3), `toUA` not the handle's UA, `kv[0]` not its version →
`NotThisHandle`; an audited leg without `AuditorKeys`, or an auditor `pk` of another length → `Input`. Then, under the lease, the
handle builds pqz-ffi's `opening::Credit` from the blob's own bytes (`u`, `v_t`, `[v_a]` unpacked from the stored form; `O_t`,
`[O_a]`, `kv[1]`), its own `pk` and `kemPk`, the auditor's keys as given, and calls `opening::check_recipient(openKemSeed, …)`:
`Some(digits)` → `Checked::Accepted(Accepted { handle id, token, index, h(i) }, Σ dᵢ·16ⁱ)`; `None` → `Checked::Skip(Skip { index,
h(i), reads })`. Every failure of the check is the one outcome, skip (no detail). `h(i)` is hashed by the handle from the bytes it
checked (`entry_hash`). The PQZ seed is not an input of `check`.

## 5. The gated debit entry (`with_secret_debit`)

A debit proves over `T = own (u_f, v_f) of the last debit + Σ pending[p_last, p) + Trivial(shieldIn)` (CTR-PQZ-33). The entry
takes both parts in one call and refuses, in this order, before the seed is copied unless stated:

1. `d.token` is not the handle's (class 3) → `NotThisHandle`.
2. `last_debit > 0` and no `own` → `OwnRequired` (no empty-window bypass, L43: a window of zero entries never skips the own
   part).
3. `last_debit == 0` and an `own` → `Input` (an account that never debited has no own ciphertext).
4. `last_debit == 0` and an empty window → `EmptyDebit` (nothing in the debit is gated: the seed never leaves on no input).
5. Each window entry: its `token` not `d.token` → `Window`; skip-marked or TRIVIAL → passes; else it needs an `Accepted` made by
   this handle with the same token, index and `h(i)` of the entry's slot and code → else `Window`.
6. `own`: `last_debit − 1 ≥ 2³²` → `Input`; then, with the seed copied under the lease, `ownTag = HMAC(K, chainUid ‖ token ‖ ua ‖
   be32(last_debit − 1) ‖ keccak256(P(u_f) ‖ P(v_f)))`, `K = HKDF(seed32, ∅, "PQZ/owntag/v1")`, compared in constant time with
   `own.own_tag` → `OwnTag`. The counter is the account's (`lastDebit` is the next counter, the last own debit is
   `(ua, lastDebit − 1)`, as path (B)'s `open_words`), so the own part names no counter of its own.
7. `f(&seed32)`, counted in `secret_loads`; its result returned.

Refusals by name: `Refused::{NotThisHandle, Input(&str), Window, OwnTag, OwnRequired, EmptyDebit, Unconfirmed, KeyRevoked}`.

**What the gate does and does not bind.** The gates decide whether the seed may be used for the debit the caller describes;
the closure is the binding's prover code (trusted, in the wallet), not a node. ARCH-POS-13's attacker is whoever chooses a
ciphertext the wallet decrypts (a node, a sender): every ciphertext part of a debit is either the holder's own (its tag verifies)
or an entry the handle accepted, marked or TRIVIAL. The binding must build `T` from exactly the parts it passed; nothing in a
closure API can force that, and no binding in this repository proves through the handle yet (CLI-SGN-51). `with_secret_keygen`
is the same: for the public key and the `R_REG` proof of registration, counted apart; `pk()` already gives the public key
without it.

**Residual (owner 2026-11-16, "ok, as proposed"):** step 4 refuses a first debit whose `T` is
`Trivial(shieldIn)` alone (no window, no own part), although such a debit holds no ciphertext a node chose. `EmptyDebit` keeps
refusing the shielded-in-only first debit (fail closed) until the Fable + Codex review confirms the contract allows it and a
client needs it.

## 6. ua-rs reads every `opening.json` rejection row through pqz-ffi (L66a)

`tests/pqz3k.rs` (`opening_rejects_through_pqz_ffi`, every `pqz` cell, the build's set directory) rebuilds the audited row's credit from its seeds
(pqz-ffi `enc_split` with KeyGen seeds `0x46 / 0x54 / 0x41`, the readers' opening KEM seeds of `openKemSeeds`), checks the honest
openings byte-equal to the row, then applies each `rejects` row's one change (`to.opening`, `auditor.opening`, `to.kemPk`,
`auditor.kemPk`, `chainUid`, `to.keyVersion`) and asserts pqz-ffi `check_recipient` / `check_auditor` give the row's `recipient` /
`auditor` outcome exactly (positive control: the unchanged credit is `accepted:<digits>` / `read:<digits>`). The rows whose
field the handle takes from the credit (`to.opening`, `auditor.opening`, `auditor.kemPk`, `chainUid` by a handle of that chain,
`to.keyVersion` by a handle of that version) also go through `PqzKeyHandle::check` (`opening_rejects_through_the_handle`, `vectors` cell: `vectors_from_secrets`) on the op 1 blob
built from the credit: skip on every row whose opening keeps its 1,648 bytes, `Input` (no op 1 blob, never an acceptance) on the
wrong lengths, which no opening token stores; accepted with the row's amount on the unchanged one. `to.kemPk` rows do not apply to
the handle (its `kemPk` is its own derivation; asserted equal to the row's reader key).

## 7. clientkeys (same entry shape)

`pqzKeyHandle(seed, { account, index, chainUid, token, ua, version, layout })` keeps its constructor (clientkeys holds the BIP-39
seed in its own process; its custody rule is CLI-SGN-02's, not this store). Its entries take the same shape and names:

- `withSecretDebit({ token, lastDebit, own: { pu, pvf, ownTag } | undefined, window: [{ token, index, slot, code, accepted }] }, f)`
  with steps 1-7 of §5 (the same order; the errors name `OwnRequired` / `EmptyDebit` / the window / the ownTag);
  `withSecretOwn` and `withSecretWindow` removed.
- `check(credit, verify)` returns `{ accepted: { token, index, entryHash }, value }` or `{ skip }`; the acceptance names the
  token and is checked against the window entry's token.
- `withSecretKeygen(f)`, `seedCommitment()`, `wipe()`, `pqzMarks` unchanged.

## 8. Other users

`smartcontracts/evm/script/pqz/wallet` (the on-chain matrix's wallet simulator, a test tool) builds `scaas-ua` with
`vectors` and uses `vectors_from_seed` and `with_secret_debit` (`lastDebit` from the account, which `PqzWallet.s.sol` passes);
it did not build since O5 (a) made the raw constructor `vectors`-only. No C ABI or binding exports the handle (unchanged).

## 9. Tests and mutants

- Revocation: a handle from `pqz_scoped_key` checks and debits; after `lock()` every entry is `KeyRevoked` and the closure never
  runs; after `unlock` the old handle stays revoked and a new one has the same commitment. `lock()` during a leased check and
  during a leased debit closure waits for it (`vectors_pause_after_copy`, as L82's tests).
- The debit entry: positive controls (own only, window only, both), then one change each: `lastDebit > 0` without own
  (`OwnRequired`, at zero entries too), own at `lastDebit 0`, empty debit, a foreign own tag (another handle's key, one byte of
  `P(u_f)`, the counter off by one), a window entry of another token, an acceptance of another token / handle / index / bytes,
  an unaccepted unmarked credit; `secret_loads` unchanged on every refusal.
- KATs equal clientkeys': `pq_kat.json` `pqzScopedSeeds` and `pqz3k_kat.json` `handles` through `Wallet::pqz_scoped_key` from the
  mnemonic (release path), `ownTagOpening` through `with_secret_debit`; `opening.json` `openKemSeeds` against `open_kem_pk`.
- `opening.json` rejects (§6); the planted probe (§14.1 / §14.18) with real pqz-ffi credits on a class-2 and a class-3 handle.
- `tests/no_oracle.rs`: the crafted query as the own part (a tag not the holder's), as an unaccepted window entry, and as a credit
  through `check` (a skip, never a decryption); `secret_loads` stays 0; positive control: the honest own part opens.
- Mutants (`smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.py`, one per guard), each red: every step of §5, the token
  of `Accepted`, the lease dropped before `f`, `check`'s handle refusal.
