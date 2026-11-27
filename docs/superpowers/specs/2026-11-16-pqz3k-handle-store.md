# The three-key PQZ handle in the wallet's store (T21 O5 (b))

Status: **BUILT** (branch `pqz3k-handle`; gates `smartcontracts/evm/runs/2026-11-16-pqz3k-handle-gates.txt`, mutants
`smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.txt`). UNAUDITED.

Owner 2026-11-16, T21 O5 (b), as proposed (TODO, ua-rs-sign line "Before the freeze (O5 (b))"). Rules this note
implements, not reopens: [CLI-SGN-51](../../clients/signers-clientkeys.md#CLI-SGN-51) (K3-7, the key handle, the marks),
[ARCH-POS-13](../../decisions.md#ARCH-POS-13) (never a decryption oracle), spec
[2026-11-13-pqz-three-keys.md](2026-11-13-pqz-three-keys.md) §6 / §14.1 / §14.18 / §14.19, signer spec §8.2 (lock revokes every
handle), T21 L82 (read lease). Ledger rows closed: L39 (handle outside the store), L43 (empty-window bypass), L47 (`Accepted`
names no token), L66a (ua-rs runs no `opening.json` `rejects` row).

**The review (2026-11-16):** the Fable and Codex reviews of a8927561e (their reports are kept outside the repository), owner
"ok, as proposed" on all of them: the slot offsets bound in `check` (Fable F1), the handle id bound to the keys and the
derivation path (Codex 1, Fable F7), the window ordered and bounded (F2), **owner decision (a)**: no caller code sees the seed in
a release build (F3) — the handle builds and decrypts the debit's `T` and proves its own registration —, the matrix simulator on
that entry (F4, Codex 3), clientkeys' acceptance keeps a copy of its token (Codex 2), the lease test inside the use (Codex 4),
the auditor refusals tested (F6), `KeyRevoked` first and the documented order (P3), **owner decision** on the shielded-in-only
first debit (a named `shield_in`).

## 1. What moves

| Before (O5 (a), `vectors` only) | After |
|---|---|
| `PqzKeyHandle::new(seed64, …, layout)`: both seeds in plain struct fields, `Drop` = `fill(0)` | `Wallet::pqz_scoped_key(&Scope)`: both seeds derived inside `SecretStore`, one arena slot, revoked by `lock()` |
| `check(credit, closure(open_kem_seed, input))`: the caller's closure got the 96-byte KEM seed | `check(&Credit)`: the handle runs pqz-ffi `check_recipient` itself, on a slot at an op 1 credit's offsets only |
| `with_secret_own(own, f)`, `with_secret_window(entries, f)`, `with_secret_keygen(f)`: the seed in caller closures, `with_secret_window(&[], f)` passes | release: `open_debit(&Debit)` (gates, then `T` built and decrypted inside) and `prove_reg(id)` (the record's `R_REG` inside); the closures `with_secret_debit(d, f(seed, T))` / `with_secret_keygen` are `vectors` only |
| `Accepted { handle, index, content }`, an id of `(chain, scope, ua, version)` | `Accepted` and `WindowEntry` name the token; the id binds the class, account, index, `keccak256(pk)`, `keccak256(kemPk)` |
| local `hmac` / `hkdf` (`prk` unwiped) | `wallet::hkdf_sha256` / `hmac_sha256`, `Zeroizing` outputs |
| layout passed by the caller | the build's set (`pqz_pack::B`, `stmt::N`, `stmt::K_MAX`): one set per build (spec §10.2) |

The old code is kept in `clients/ua-rs/legacy/pqz3k-handle/` and `clients/clientkeys/legacy/pqz3k-handle/` (not built).

## 2. API (ua-rs, feature `pqz`; `src/pqz3k/handle.rs`, re-exported as `scaas_ua::pqz3k::*`)

```rust
pub struct Scope { pub account: u32, pub index: u32, pub ua: [u8; 32], pub chain_uid: [u8; 32],
                   pub token: Option<[u8; 20]>, pub version: u64 }            // token None: offchain-shared (class 2)
impl Wallet { pub fn pqz_scoped_key(&self, scope: &Scope) -> Result<PqzKeyHandle, Error> }  // WalletLocked while locked

impl PqzKeyHandle {                                      // release build
    pub fn class(&self) -> KeyClass;  pub fn scope(&self) -> [u8; 20];  pub fn version(&self) -> u64;
    pub fn pk(&self) -> Vec<u8>;           // keygen(seed32).pk, public, computed at derivation
    pub fn open_kem_pk(&self) -> Vec<u8>;  // 0x01 ‖ ek ‖ X25519 pk (CTR-UA-32 scheme 1), public
    pub fn seed_commitment(&self) -> Result<[u8; 32], Refused>;          // keccak256(seed32), the KAT's view
    pub fn check(&self, c: &Credit) -> Result<Checked, Refused>;         // K3-7
    pub fn marks(skips: &[Skip]) -> Result<Vec<u64>, Refused>;           // unchanged (Fable P2-1)
    pub fn open_debit(&self, d: &Debit) -> Result<OpenedDebit, Refused>; // { t, balance }: T of the gated parts, decrypted
    pub fn prove_reg(&self, proof_system_id: &[u8; 32]) -> Result<Registration, Refused>; // { pqz_key_hash, message, stmt, proof }
    pub fn secret_loads(&self) -> u32;  pub fn keygens(&self) -> u32;
}
pub struct Credit<'a> { pub token: [u8; 20], pub index: u64, pub slot: [u8; 32], pub code: &'a [u8],
                        pub auditor: Option<AuditorKeys<'a>>, pub reads: Reads }
pub struct AuditorKeys<'a> { pub ua: [u8; 32], pub pk: &'a [u8], pub kem_pk: &'a [u8] }
pub enum Checked { Accepted(Accepted, u64 /* amount */), Skip(Skip) }
pub struct Accepted { handle, token, index, content }                 // fields private; made by `check` only
pub struct Debit<'a> { pub token: [u8; 20], pub last_debit: u64, pub own: Option<Own<'a>>, pub window: &'a [WindowEntry<'a>],
                       pub shield_in: u64 }
pub struct Own<'a> { pub pu: &'a [u8], pub pvf: &'a [u8], pub own_tag: [u8; 32] }
pub struct WindowEntry<'a> { pub token: [u8; 20], pub index: u64, pub slot: [u8; 32], pub code: Option<&'a [u8]>,
                             pub accepted: Option<&'a Accepted> }
```

Explicit named parameters, one entry point per operation. Test-only (feature `vectors`): `PqzKeyHandle::vectors_from_seed(seed64,
&Scope)`, `vectors_from_secrets(seed32, open_kem_seed96, &Scope)`, `with_secret_debit(&Debit, f(&seed32, &T))` (the same gates,
the same `T`), `with_secret_keygen(f)`, `vectors_prove_reg(id, rnd32)`; the raw derivations `open_kem_seed` and
`pqz_token_key_seed_without_opening` stay `vectors`-only (O5 (a)). A release build names none of them (`compile_fail` doctests).
`Wallet::pqz_scoped_key` refuses in a `vectors` build until `facade::vectors_unlock` (no-decryption-oracle §4.8).

`pqz_token_key_seed_without_opening` (a class-3 token **without** the opening, CTR-PQZ-37's accepted exposure) gets no store
path in this task: the TODO text names the handle of keys with the opening only.

## 3. Where each secret lives

- **Derivation**: `SecretStore::key(KeyId::PqzScoped(account, index, ua, chain_uid, token, version), derive)` under the store's
  write lock, from the arena's BIP-39 seed. `derive` returns `seed32 ‖ openKemSeed` (128 bytes, `Zeroizing`) and the public
  data `pk ‖ kemPk`. `seed32` is K3-2 (`HKDF-SHA256(seed, "scaas.ua.pq.v1", label ‖ u32 account ‖ u32 index ‖ chainUid ‖ [token]
  ‖ be64 v)`), `openKemSeed` K3-6b (`HKDF-SHA256(seed, "scaas.ua.kem.v1", label ‖ ua ‖ chainUid ‖ [token] ‖ be64 v, 96)`), both
  through `wallet::hkdf_sha256`. A second call with the same scope returns the same slot.
- **The handle** holds a `Handle` (the store's `Arc`, the generation, the slot) and public data only: class, scope, ua, chain,
  version, its id, `pk`, `kemPk`, two atomic counters. The id is `keccak256("scaas.pqz3k.handle.v2" ‖ u8 class ‖ be32 account ‖
  be32 index ‖ chainUid ‖ scope ‖ ua ‖ be64 v ‖ keccak256(pk) ‖ keccak256(kemPk))` (Codex 1, Fable F7: two handles of other keys
  never share an id, whatever `Scope.ua` the caller gave). No secret byte is a field; `Debug` shows class, scope and version.
- **Use**: every entry first asks whether the wallet is still open (`KeyRevoked` before any other refusal). An entry that uses a
  secret takes a read lease of the store (T21 L82), copies the bytes it needs into a `Zeroizing` buffer under the read guard
  (`seed32` for `open_debit`, `prove_reg` and the own-tag check; `openKemSeed` for `check`), drops the guard, marks
  `wallet::copied()` (the `vectors` pause hook), uses the copy (pqz-ffi's check, the decryption of `T`, the `R_REG` prover), and
  wipes it before the lease ends. So `lock()` waits for an entry in flight, and the long work does not hold the store's guard.
  Nothing inside an entry may lock the same wallet (it would wait for its own lease); a release build runs no caller code there.
- **Lock**: `Wallet::lock()` wipes the arena and raises the generation; every later call of an earlier handle is
  `Refused::KeyRevoked`; an unlock does not revive it (a new `pqz_scoped_key` gives a new handle with the same commitment).

Outside the store's coverage, as for every other key (signer spec §8.2): the copies the crates make (HKDF state, ML-KEM and
X25519 types inside pqz-ffi, wiped by their own `zeroize` where they have one; pqzl's key types clear `s`, `e` on drop).

## 4. The holder check (`check`, K3-7)

In order, each refusal before any secret is read: revoked → `KeyRevoked`; TRIVIAL slot → `Input`; the slot's `(uOff, vOff)` not
`(16, 16 + P(u))`, the offsets the contract writes for an op 1 credit (`PqzCore._credit`), → `Input` (Fable F1: the acceptance
vouches for exactly the bytes it checked, and every reader of `T` loads the entry at the slot's offsets); code not `STOP ‖ data`
→ `Input`; not an opening op 1 blob of this build's set → `Input`; a token not the handle's (class 3), `toUA` not the handle's
UA, `kv[0]` not its version → `NotThisHandle`; an audited leg without `AuditorKeys`, or an auditor `pk` of another length →
`Input`. Then, under the lease, pqz-ffi `opening::check_recipient(openKemSeed, …)` on the blob's own bytes, the handle's `pk`
and `kemPk`, the auditor's keys as given: `Some(digits)` → `Checked::Accepted(Accepted { id, token, index, h(i) }, Σ dᵢ·16ⁱ)`;
`None` → `Checked::Skip(Skip { index, h(i), reads })`, one outcome. The PQZ seed is not an input of `check`.

## 5. The debit (`open_debit`)

A debit proves over `T = own (u_f, v_f) of the last debit + Σ pending[p_last, p) + Trivial(shieldIn)` (CTR-PQZ-33). The handle
takes all parts in one call and refuses, in this order, before the seed is copied unless stated:

1. revoked → `KeyRevoked`.
2. `d.token` is not the handle's (class 3) → `NotThisHandle`.
3. `last_debit > 0` and no `own` → `OwnRequired` (a window of zero entries never skips the own part, L43).
4. `last_debit == 0` and an `own` → `Input` (an account that never debited has no own ciphertext).
5. `last_debit == 0`, no `own`, an empty window and `shield_in == 0` → `EmptyDebit` (the debit names nothing). With
   `shield_in > 0` the first debit of `Trivial(shieldIn)` alone passes (owner 2026-11-16, below).
6. With `own`: `last_debit − 1 ≥ 2³²`, or `P(u_f)` / `P(v_f)` not of this set's lengths → `Input`. These are decided with the own
   part's other inputs, before any window entry (both clients; the reviews found this order in the code and not in the note: the
   note follows the code, since the own part's form is one input and the window another).
7. More than `K_MAX − 2` window entries (the own and the `shieldIn` units beside them: `unitsOf(T) ≤ K_MAX`, F2) → `Window`.
8. Each window entry, in order: another token than `d.token`, an index not above the previous one (strictly ascending, so no
   entry twice, F2) → `Window`; skip-marked or TRIVIAL → passes; else it needs an `Accepted` made by this handle for the same
   token, index and `h(i)` → else `Window`.
9. With the seed copied under the lease: the own part's `ownTag = HMAC(K, chainUid ‖ token ‖ ua ‖ be32(last_debit − 1) ‖
   keccak256(P(u_f) ‖ P(v_f)))`, `K = HKDF(seed32, ∅, "PQZ/owntag/v1")`, compared in constant time → `OwnTag`. The counter is the
   account's (`lastDebit` is the next counter; the last own debit is `(ua, lastDebit − 1)`, as path (B)'s `open_words`).
10. Counted in `secret_loads`; `T` is built from exactly the gated parts — the own `(u_f, v_f)`, each accepted entry's `(u, v_t)`
    at the offsets `check` bound, each TRIVIAL entry's amount, zero for a mark, `Trivial(shield_in)` — mod q, and decrypted with
    `s` inside the lease. `OpenedDebit { t, balance }` (`t` the statement's `T`, 64-bit lanes) is returned; a `T` that does not
    decrypt to an amount is `Input` (not reachable from gated parts within `K_MAX` units).

**Threat model (owner decision (a)).** In a release build no caller code sees the PQZ seed: `check` re-encrypts from the opening
(pqz-ffi, no `s`), `open_debit` decrypts only a `T` it built itself from parts that are the holder's own (its tag verifies), an
acceptance of this handle (K3-7 passed for this key at these offsets), a TRIVIAL amount, a mark or the public `shieldIn`, at most
`K_MAX` units, so the noise stays within the set's budget; `prove_reg` proves the handle's own record message, built from its own
fields. ARCH-POS-13's attacker (whoever chooses a ciphertext: a node, a sender) has no entry that decrypts a ciphertext of its
choice. The `vectors` closures keep the old shape for tests; they get the same gates and the same `T`.

**Owner decision 2026-11-16 (as proposed) on the shielded-in-only first debit.** The reviews confirmed the contract allows
it (`PqzCore._total`: a new account, `p = rolled = 0`, `Trivial(shieldIn)` alone, one unit) and a client needs it (the contract
docs give wallets the same-call `shieldIn` top-up for "shield and spend now"). `Debit` takes the named field `shield_in`
(`shieldIn` in clientkeys): `(lastDebit 0, no own part, empty window)` passes exactly when `shield_in > 0` (`T = Trivial(shieldIn)`,
no chosen ciphertext); every other empty debit stays `EmptyDebit`.

## 6. `prove_reg`

`pqzKeyHash = keyHashOf(0x0142, pk)`, `message = uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, typed(UAPqzScopedKey(ua, class,
chainUid, token or 0, version, pqzKeyHash)))` (pqz3k_kat.json's `regMessage` formula), the op 3 statement `[opTag, id, message] ‖
pk` and its proof by the crate's prover (`facade::pqz::register_proof`), randomness from the OS RNG; `id` this build's PQZL or
PQZH id, else `Input`. Counted in `keygens`.

## 7. ua-rs reads every `opening.json` rejection row through pqz-ffi (L66a)

`tests/pqz3k.rs` (`opening_rejects_through_pqz_ffi`, every `pqz` cell, the build's set directory) rebuilds the audited row's
credit from its seeds (pqz-ffi `enc_split` with KeyGen seeds `0x46 / 0x54 / 0x41`, the readers' opening KEM seeds of
`openKemSeeds`), checks the honest openings byte-equal to the row, then applies each `rejects` row's one change and asserts
pqz-ffi `check_recipient` / `check_auditor` give the row's outcomes exactly (positive control: the unchanged credit is
`accepted:<digits>` / `read:<digits>`). The rows whose field the handle takes from the credit also go through
`PqzKeyHandle::check` (`opening_rejects_through_the_handle`, `vectors` cell): skip on every row whose opening keeps its 1,648
bytes, `Input` on the wrong lengths (no op 1 blob), accepted with the row's amount on the unchanged one, `Input` without the
auditor's keys or with an auditor key of another length (F6).

## 8. clientkeys (same entry shape)

`pqzKeyHandle(seed, { account, index, chainUid, token, ua, version, layout })` keeps its constructor (clientkeys holds the BIP-39
seed in its own process; its custody is CLI-SGN-02's). Its entries take the same shape, order and error names (the `Refused`
names start each message):

- `check(credit, verify)`: the same offsets rule; the acceptance `{ token, index, entryHash }` keeps a **copy** of its token bytes
  (Codex 2: a caller overwriting its buffer moves nothing).
- `withSecretDebit({ token, lastDebit, own, window, shieldIn }, f)`: steps 1-9 of §5 (`kMax` from `pqzLayout(n, packBits,
  kMax)`, required for a debit). clientkeys has no PQZ arithmetic (no decryption, no prover), so `f(seed32)` stays: it is the
  binding's code, and the owner's decision (a) is carried out where the code is (ua-rs).
- The id binds the class, account, index, the seed commitment (clientkeys derives no `pk`) and `keccak256(kemPk)`.
- `withSecretKeygen(f)`, `seedCommitment()`, `wipe()` (every entry refuses `KeyRevoked` first after it), `pqzMarks` unchanged.

## 9. Other users

`smartcontracts/evm/script/pqz/wallet` (the on-chain matrix's wallet simulator, a test tool) builds the release `scaas-ua`
(owner 2026-11-17, option (b): no `vectors` in any normal dependency, `scripts/check_test_features.py`): each
record names its test wallet's BIP-39 entropy, the tool restores it with `Wallet::from_mnemonic` and takes the handle from
`Wallet::pqz_scoped_key`, so the matrix runs the shipped API; the auditor tool (pqz-ffi `check_auditor`, no handle entry) takes
the same mnemonic's opening KEM seed through pqz-ffi (equal to the wallet's, the tool's test). It opens the debit with
`open_debit` only (F4, Codex 3): the request carries no `T`; the own part comes
from the account's last debit blob (`window.ownCode`) and `window.shieldIn` is named. `PqzWallet.s.sol` compares the handle's `T`
with the debit statement's `T`, and after the refresh runs the own branch on chain: the matrix's refresh (a verdict over stand-in
bytes) wrote an own part no key of the holder tagged, so the next debit is `OwnTag`, the seed unused. No C ABI or binding exports
the handle.

## 10. Tests and mutants

- Revocation: `KeyRevoked` from every entry after `lock()`, before any other refusal (a TRIVIAL credit, a malformed blob, an empty
  debit, no own part, another proof system); unlock does not revive; `lock()` waits for a leased check (pause at the copy) and
  for a debit's closure while it runs (the closure blocks inside the use, Codex 4).
- `check`: offsets moved by one (each), `vOff = 200`; recipient, key version, token, short blob, no STOP, TRIVIAL; the auditor
  refusals (F6); the planted probe with real pqz-ffi credits on a class-2 and a class-3 handle.
- `open_debit`: every gate of §5 one change at a time with its control; balances exact (window, TRIVIAL, `shieldIn`, a real own
  ciphertext under its true tag); duplicates, descending, `K_MAX − 1` entries (control `K_MAX − 2`); acceptances of another
  version, account, index and wallet refused (Codex 1's reproducer); `secret_loads` unchanged on every refusal.
- `prove_reg`: the message from the handle's fields, the proof verified by pqz-ffi, another proof system refused.
- KATs equal clientkeys' (`pq_kat.json`, `pqz3k_kat.json` through the release path); `opening.json` rejects (§7).
- `tests/no_oracle.rs`: the crafted query as an own part (a zero tag; under `vectors` the holder's tag of another counter), as
  an unaccepted window entry, as a credit through `check`; the seed unused; control (`vectors`): an honest own ciphertext under
  its true tag decrypts to its amount.
- Mutants (`smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.py`): one per guard in both clients, each the code before its
  fix; results and the equivalent mutants in the `.txt`.
