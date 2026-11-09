# No decryption oracle: bringing the client libraries in line with ARCH-POS-13 — fix spec

**Status:** built on `ua-rs-sign` (T15b … T15k, the fix wave T15l after the Fable review of 2026-11-07); the reading layer
outside this repository SPECIFIED; the PQZ reference reading layer `pqz-read` built (plan task T15m, owner-approved 2026-11-07).
First written SPECIFIED (2026-11-06). Revised twice the same day: after the Fable review (P1-1 … P3-3, accepted by
the controller), then by **owner rulings 2026-11-06**: `ua-rs` contains no light client and no chain-state verifier; the check
that words are real chain state belongs to the layer that reads the chain (the wallet layer and the app, as `ua-rs-sign` spec
§10.2 already places chain reading); `ua-rs` keeps the library duties of §4.3. The owner then decided Q1, Q1b and Q3 as
recommended and recorded Q2 as moot for `ua-rs` (2026-11-06, §7). Revised again after independent Fable and Codex reviews
(2026-11-06 / 07, all items accepted, §9). Fix spec for owner ruling ARCH-POS-13 "Never a
decryption oracle" (`docs/decisions.md` on branch `ua-mtx-merge`, commit `62adb3d7`; on this branch since T19, the same text; also in
`AGENTS.md`). The owner's words: **"NO oracle!"**: absolute, no exception, no opt-in. Plan tasks: appended to
[`plans/2026-11-05-ua-rs-sign.md`](../plans/2026-11-05-ua-rs-sign.md) (section "ARCH-POS-13 rework"). Inputs: the read-only code
audit of decrypt entry points (2026-11-06, findings F1 to F9 below) and the research note
`docs/research/pqz-threshold-decrypt-prove.md` §12.1 / §12.5 (branch `ua-mtx-merge`). Everything here is **UNAUDITED**. Zether
and PQZ are separate schemes, modules and handles; each section names the one it is about.

**Revised 2026-11-09 (plan T20d0): path (B), the PQZ proof path for tokens of release 3h, SPECIFIED in §4.14** (the contract
interface of [`2026-11-06-pqz-proof-path.md`](2026-11-06-pqz-proof-path.md) §9 and its client items §13.3, built on
`ua-mtx-merge` by T58–T65 and merged here at plan T20b milestone 4), with the owner rulings of 2026-11-09 (§7, items 5–9); §3's
row (B), §4.2's R5, §4.10, §4.12, §4.13, §5, §6 and §8 carry Change notes. Path (A) is unchanged except for 3h's layout and
`memoHash`.

## 1. The rule, and what counts as an oracle

ARCH-POS-13, in short: no part of SCaaS decrypts, opens or test-decrypts a ciphertext **chosen by anyone other than the key
holder** and lets that party learn anything about the result (plaintext, success or failure, an error code, timing, or a
later action that depends on it). A result reaches only the key holder or a viewer the holder names. A ciphertext that
arrives from outside (an RPC or indexer response, a disclosure bundle, a peer message) gives that source nothing.

Why PQZ needs it: PQZ encryption is IND-CPA, not CCA. A query with `u` the unit polynomial at polynomial `j` and
`v_i = ⌈Δ/2⌉ + off` returns `M_i = [s_j[16w + i] ≤ off]`, so 8·K queries (288 at `n2304-kmax4096`; the audit's tighter
construction needs 144) recover `s` exactly (research §12.1, N3b). Zether's lifted ElGamal has no such key recovery, but
the rule is one rule for every scheme.

**Three facts the design rests on** (all from `docs/contracts/pq-zero-knowledge.md` on `ua-mtx-merge`):

1. **Contract state is always well-formed.** Every ciphertext enters PQZ state with a proof of exact norms (T4), the only
   trivial term is built by the contract, and the noise budget is worst case over proven norms plus `K_MAX`, enforced at
   credit and at debit (§4.3, CTR-PQZ-03, T5): "an accepted state never decrypts wrongly or fails". So decrypting a
   ciphertext that **is** contract state gives its value and nothing else: no rounding near `Δ/2`, no information on `s`.
2. **A ciphertext's bytes say nothing about whether they are state.** A crafted `(u, v)` and a real one have the same form.
   Only an outside check can tell them apart, and that check must use **public data only**: a check that uses `s` (a
   noise bound, a digit range) refuses exactly on the crafted queries, so the refusal is the oracle bit (research §12.5).
3. **Every outward action after a decryption is a signal.** A debit proof leaves the device by design; whether it was
   produced is visible to the relayer and to the chain. So "keep the result on the device" cannot cover a debit.

## 2. Findings this spec resolves

| Id | Sev. | Where (ua-rs-sign unless [M] = `ua-mtx-merge`) | Problem | Resolved in |
|---|---|---|---|---|
| F1 | P1 | `clients/ua-rs/src/facade/pqz.rs` command `dec {ct, window}` (parse ~337, run ~641, `value` ~504); every binding through `scaas_ua_pqz_call` (`ua-c` `lib.rs` ~2426, `ua-py`, `ua-go`, `ua-cs`, `ua-cxx`, `ua-dart-frb`) | any well-formed caller ciphertext → all 16 digits: the rounding oracle | §4.3, §4.5, §4.8 |
| F2 | P1 | same file, `proveDisclose {stmt}` (~392, ~673) | the whole op 5 statement is the caller's; proof or refusal is a 1-bit oracle (≤ 2n queries) | §4.6 |
| F3 | P2 | same file, `proveTransfer`, `proveBurn`, `proveRefresh`, `proveTransferMulti` (~348–372, ~655–667, `rest` ~709) | decrypt the caller's `T`; the success bit reaches a malicious RPC or relayer | §4.5 |
| F4 | P3 | `pqz-core`: C `pqz.h` ~156–193, `pqz_keys.c` ~229–252; Rust `pqzl/rust/src/lib.rs` ~389–406 (`decrypt_raw`); `pqz-core/ffi/src/pqzl/{rust,c}.rs` (`dec`, `dec_win`) | return digits and noise / raw `w` to any in-process caller; [M] T6 says "noise never leaves `pqz_dec`" (`pq-zero-knowledge.md` ~2435) | §4.8 |
| F5 | P2 | [M] `docs/clients/signers-clientkeys.md` ~81–88 (CLI-SGN-31), [M] `docs/research/07-custody-providers.md` ~111 (PLANNED) | `zk_mul_by_x(points, ctx)` is a static-DH oracle that bypasses `ChainWitness` | §4.9 |
| F6 | P3 | `clients/zether-prover/src/api.rs` ~685–708 (`decrypt`, `decryptPending`, `checkBalance`); `clients/ua-rs/src/facade/zether.rs` | caller `(C, D)`: no key recovery, but plaintext and timing leak; variable-time `D·x` on an attacker's `D` | §4.7 |
| F7 | P3 | `zether-prover` binary `zether-read-balance --rpc` | decrypts what an RPC hands it | §4.7 |
| F8 | P3 | `openMemo` in both facades (PQZ: `pqz_ffi::memo::open`, a keystream without MAC) | a crafted memo with a real memo's header and salt returns the keystream, which opens the real memo (no key recovery) | §4.3, §4.6, §4.7 |
| F9 | — | docs: PQZ CTR-PQZ-03 / -14 / T6; Zether `zether.md` says nothing; NODE-LANE-03 and CLI-SGN-31 cover only the server oracle; `docs/clients/ua-libraries.md` says nothing | the rule is not stated where implementers read | §6 |
| F10 | P2 | `pqz.rs` `multi` (~803): `memoHash = keccak(memo)` always | the contract fills `memoHash` only in HASH mode (`PqzCore._parseMulti`, ~430) and leaves 0 in BUNDLE; an op 7 BUNDLE proof from the facade is refused | §4.10 |

F10 is not an oracle; it is a correctness bug in the same facade, found by the T16a agent (2026-11-06), fixed with this rework.

## 3. The central question: how is a ciphertext known to be chain state?

| Construction | Removes the oracle? | Why / why not |
|---|---|---|
| **(A) Proven state**: every ciphertext is assembled from words that are real contract state of a catalogued token, read from a source the holder trusts | **yes**, up to that source (§4.12) | the only check that tells "on chain" from "forged"; whoever reads the chain makes it; works from state alone (CTR-PQZ-07 keeps holding) |
| (B) Well-formedness certificates: verify the proof that admitted each ciphertext | no (not buildable) | a PQZ credit's proof is the sender's debit proof, whose statement contains the **sender's** `T` at that block (`Debit.t`), which is not in state (materialised `acc` is overwritten, window slots are deleted); proofs live in calldata (history expiry); an op 4 `SENDER_S` proof would certify a credit without `T` but needs the sender's cooperation, and a keeper's rollover of an uncertified credit would strand the account. Zether has the same shape. Even where available, a forged but well-formed composition still leaks the real balance through the holder's later actions |
| (C) Containment: results never leave the device, failures never signalled | no | a debit proof leaves the device by design; whether one was produced is the oracle bit (fact 3) |
| (D) Noise-bound or digit-range filter before use | no | the refusal is the oracle: the same 8·K queries, moved to the filter's edge |
| (E) Noise flooding (add random noise before rounding) | no | the attacker scales `u` (`u = c·unit`), so the `s`-dependent term outgrows any flooding that keeps honest decryption correct (budget at `n2304-kmax4096`: worst-case noise ≈ 2^25.7 against `Δ/2` ≈ 2^26.8) |
| (F) Several untrusted RPCs must agree | no | it trusts their operators; not by construction |

**Chosen: (A) proven state, checked where the chain is read (owner ruling 2026-11-06).** `ua-rs` does not read the chain
(`ua-rs-sign` spec §10.2) and does not verify it: no light client, no anchors table, no Merkle-Patricia or factory and
registry proofs in the library. The layer that reads the chain (the wallet layer and the app) reads from a source the holder
trusts and is responsible that the words it hands to `ua-rs` are real chain state of a catalogued token and a registered key
(§4.2). `ua-rs` makes a bare ciphertext impossible to hand over: it takes named locations and storage words, and rebuilds
every ciphertext exactly as the contract does (§4.3). The owner judged "each member reads state itself" not reasonable for MPC
quorum members (research §12.5); that quorum question is not reopened here.

**Change (2026-11-09): row (B) is buildable for tokens of release 3h** (§4.14). Its objections, against the proof-path spec: the
sender's `T` is rebuilt from state (one debit record and pending slots kept for good, §2 there); P lives in the chain's history
(the calldata, or a `PqzDebitProof` event under `LOG`); a rollover strands nothing (`acc` is a cache, `T` is rebuilt from its
parts); the holder's own `v_f` is checked by `ownTag`, burns and refreshes included. The composition objection stays (research
§3.3) and decides where R1 still binds (§4.14.6). (A) stays the construction for every token; (B) is added beside it.

## 4. Design

### 4.1 Who is responsible for what

| Layer | Duty under ARCH-POS-13 |
|---|---|
| The layer that reads the chain (wallet layer, app; outside this repository) | reads from one source the holder trusts; guarantees the words are chain state of a catalogued token on a known chain, and that the selected leg belongs to the handle's key (R1 to R7, §4.2); never reports anything about a decryption to the source |
| `ua-rs` (facades and every binding) | no bare ciphertext, statement or `T` API in a production artifact, and no way for a dependency to switch one back on (§4.8); decrypting commands take named location fields and the **raw** storage words; the facade alone parses them and rebuilds `T`, `p`, entries and the op 5 statement exactly as the contract; one refusal status; nothing about a decryption returned to anyone but its caller (§4.3) |
| The enclave of CLI-SGN-31 (PLANNED) | as `ua-rs`, and whole operations only (§4.9); the layer feeding it bears R1 to R7 |

### 4.2 Requirements on the layer that reads the chain (normative; not `ua-rs` code)

These bind the wallet layer and the app under ARCH-POS-13: reading the words from an untrusted RPC or indexer and passing them
to `ua-rs` is an oracle, and the fault is that layer's. Each requirement has a checkable assertion (EVM; another family states
its own equivalent before its layout parser lands).

| Id | Requirement | Checkable assertion |
|---|---|---|
| R1 | **Trusted sources, one or several** (owner decision Q1, 2026-11-06, §7; Change owner 2026-11-08, ARCH-POS-15): every source is an RPC endpoint the holder **named** (their own node or one they configured), a **default** in the release's own reviewed list (from public RPC information, trusted like a named one), a **discovered** endpoint (found at run time), or a verifying light client in the reading layer. A layer may take several (a wallet layer and the app may; the reference readers do, named only: `--rpc` repeated, `--rpc-agree`): by default **failover** in the order given, every word of a request from the one source that answered the whole read and the next source from scratch after a failure, never a mix; with the **agreement option** a **strict majority** of the sources (⌊n/2⌋ + 1) must return the same complete read at one block, counted per source over the whole read, else the read is refused. A discovered endpoint serves a read that feeds a decryption only under the agreement option with at least three sources. | the request's words are one source's (failover) or the identical read of a strict majority (agreement); a discovered source alone, or under agreement with fewer than three sources, is refused by the reading layer |
| R2 | **Known chain.** `(chainId, chain_uid)` from the holder's configuration (genesis hashes as pinned in `smartcontracts/evm/chain-uids.json`, [NET-ALL-22](../../networks/README.md#NET-ALL-22)). | `eth_chainId` and `eth_getBlockByNumber("0x0").hash` equal the configured pair |
| R3 | **One final block.** All words from one block that is final by the chain's rule, or at the holder's configured confirmation depth where the chain has no finality (a single-signer chain, [NET-EVM-04](../../networks/evm.md#NET-EVM-04)). | every read names the same block number and hash; `head − block ≥ depth` or the block is at or below the chain's finalized tag |
| R4 | **Real storage, not views.** Storage words by `eth_getStorageAt` / `eth_getProof` at that block; blob and key code by `eth_getCode`, whose `keccak256` equals the account's `codeHash` (proven where the source is a light client). `eth_call` views only from R1's own or configured node, never as the sole source of a word a light client verifies. | `keccak256(code) == codeHash` for each pointer; the storage method and block recorded per word |
| R5 | **Catalogued token.** The token is catalogued by that chain's `OpenFactory` (its configured address) with a PQZ kind for the PQZ facade, a Zether kind for the Zether facade. **Change (owner 2026-11-09):** a PQZ token is of release 3h or later (it answers `proofStore()`, proof-path spec C9); an earlier release is refused by name, since the facade parses 3h's layout only (§4.14.1). | `_info[token]` read as storage: `exists` set and `kind` in the facade's kinds; PQZ: `proofStore()` answers at the read block from R1's node |
| R6 | **The selected leg belongs to the handle.** For the leg the command reads: its recipient UA's registered key equals the handle's key (PQZ: `pqzKeyOf(ua)` with `proven` set and `keccak256(GROUP("pqz-mlwe") ‖ pk)` equal to the handle's; Zether: the registered `Y`). For an auditor read: the account is the token's `auditorUA`, the token's `auditorMode` is not NONE, and the entry actually holds an auditor copy for that leg (an entry without one is refused); for a disclosure kind, the token's `disclosureMode` allows it. | the registry and token words read as storage at the same block; the comparisons above |
| R7 | **Nothing back.** No result, failure, error code, result-dependent timing, follow-up read or log line that depends on a decryption goes back to the source; a result goes to the holder or a viewer the holder names. | no request to the source after a decrypt depends on its outcome (reviewable in the reading layer's code) |

`pkT`, `pkA` and the op 7 legs' keys of a debit stay plain caller fields: encryption to a public key is public, and a wrong
recipient or auditor key is refused on chain by `PqzCore._creditKey` (and the auditor-key check).

**The source's residual (owner decision Q1b, 2026-11-06, §7):** the holder's own full node re-executes the chain, so it trusts
nothing beyond the chain's rules; a light client trusts the chain's sealing keys (a sealer or a leaked sealing key can seal a
header over a fabricated `stateRoot`, one key on a single-signer chain); another operator's node trusts that operator. This is
the holder's chosen trust, stated in `zether.md` and `pq-zero-knowledge.md` (T19b).

### 4.3 `ua-rs`: raw words for a named location, parsed and rebuilt only by the facade

> **A facade decrypts only a ciphertext it rebuilt itself from raw storage words supplied for a named location.** No
> production command takes ciphertext bytes, a statement, a `T` or parsed state fields. A decrypting command takes the
> location in named, typed fields (`chainUid`, `token`, `ua`, `block`, and `entryRef` with `leg`, `fromUA`, `sendCounter`,
> `mode` where they apply), the token's `psid` word, and the raw words the reading layer read at that block. The facade alone
> parses them by the pinned layout (§4.4), checks they are consistent, rebuilds the ciphertext exactly as the contract does,
> and only then uses the key. Every refusal before the key is used returns one status, `Argument`, with no detail. The only
> other statuses a decrypting command returns are about the handle, not the ciphertext: `KeyRevoked` (the wallet was locked
> or freed) and, for the balance-cache box, `Aead`.

- **`psid` first.** The token's `proofSystemId` word is compared with the build's `PQZL_ID` / `PQZH_ID` before anything is
  parsed (another set: `PqzSetMismatch`, as today).
- **Raw words (PQZ), in named fields:** `account: [word]` (the account struct's slots in slot order, as pinned), `pending:
  [{index, word}]`, `accWords: [word]` (the materialised `acc` slots as stored; the facade applies `not()` and unpacks),
  `blobs: [{address, code}]`, and for an entry `entryPtr: word`, `memo: bytes`. A word is 32 bytes; a blob's code and a memo
  are the only `bytes`.
- **Consistency checks** (public, before the key): pending indexes are exactly `[rolled, p)` (the facade selects them by that
  range only, never by content); offsets inside their blob; the unpacked `acc` hashing to `accHash` when materialised;
  `unitsOf(T) ≤ K_MAX`; the leg inside the entry. They catch a careless caller; they do not make words authentic (§4.12).
- **Leg and role (Codex C5; the library's half of R6).** The request also carries the registry's key record words for `ua`
  (the record slot words and the key's SSTORE2 code) and, for an auditor command, the token's `auditorUA` and `auditorMode`
  words. Before the key is used the facade checks: the selected leg's `UA_j` in the entry blob equals `ua`; the stored key
  hashes (`keccak256(GROUP("pqz-mlwe") ‖ pk)`) to the handle's key hash and is `proven`; for `auditRead` / `AUDITOR`,
  `auditorUA == ua`, `auditorMode` is not NONE and the entry holds an auditor copy for that leg. Like every word check, this
  binds the role; it does not make the words authentic.
- **Old entries (`openMemo`, `proveDisclose`):** the request names the entry's original `fromUA` and `sendCounter`; the facade
  recomputes `entryRef` from them (as the contract derives it) and refuses a mismatch before the key is used. The header words
  of the memo come from those fields and the entry blob, never from free fields.

### 4.4 PQZ: words to ciphertexts

- **Layout pin.** `scaas.pqz` (and `scaas.zether`) are not yet in `smartcontracts/evm/test/v2/layout/namespaces.json`. A
  contract-side task on `ua-mtx-merge` (T19c) pins every field of the PQZ account struct and `PqzStorage` (and the Zether
  ones) there, with its `Layout.t.sol` test; the facade reads that pin file as a vector (it does not hand-copy slot numbers).
- **Pending slot word:** `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`; a **TRIVIAL** entry is `vOff == 0`, with the amount in
  the low 64 bits of the blob field (`pq-zero-knowledge.md` §7.1), never `blob == 0`.
- **Stored form.** Blobs and the materialised `acc` hold coefficients in `PACK_BITS`-bit fields (stored form P46 at
  `n2304-kmax4096`, 42 / 46 / … bits per set); `ua-rs` gains a Rust unpacker equal to the contract's, tested by vectors at two
  sets at least, with mutants.
- `acc`: a reference → the blob's `u_0 ‖ v_f` at its offsets; materialised (`flags & 1`) → `not()` of each `accWords` slot,
  unpacked, checked against `accHash`; never debited → `Trivial(0)`. Pending `[rolled, p)`: a credit → `u ‖ v` at `uOff` /
  `vOff` of its blob; a TRIVIAL entry → `Trivial(digits(amount))`. `T = acc ± Σ pending[window) + Trivial(shieldIn)` exactly
  as `PqzCore`, `unitsOf(T) ≤ K_MAX`; **the facade chooses `p`** by CTR-PQZ-06. An entry `(entryRef, leg)`: `entryPtr` → blob →
  the leg's `u_g`, `v_j` (or the auditor copy `v_{a,j}` at window `w`).
- **Vectors** are versioned by contract commit: a forge writer over the built token dumps the raw words with the contract's
  own `T` and entry ciphertexts (from its statement views); the facade reproduces them byte for byte.

### 4.5 PQZ: what replaces `dec` and the debit inputs

| Old (absent from production builds, T15c / T15c2) | New | Output, to whom |
|---|---|---|
| `dec {ct, window}` | `balance {chainUid, token, ua, block, psid, words, forOp7}` (`forOp7` a named boolean, no default: the `p` an op 7 would use, `INLINE_MAX_PQZH` on a PQZH token; T15l, Fable P3-6) | `{value, p, sendCounter}` to the caller (the holder's own balance) |
| `proveTransfer / proveBurn / proveRefresh / proveTransferMulti` with `T`, `p` | the same commands with location, `psid` and words in place of `T` and `p`; `pkT`, `pkA`, legs and `mode` stay | `{stmt, proof}`; a refusal after the key (balance below amount + fee) goes to the caller only |
| (none) | `auditRead {chainUid, token, entryRef, fromUA, sendCounter, leg, block, psid, words}` on the **auditor's** key handle (one auditor key per token) | `{amount}` of the audited copy at its window, to the auditor |

The old commands and their `Req` variants and match arms are compiled only under `vectors` (T15c2), so a production build cannot
even construct `Req::Dec`. pqz-ffi's `dec` / `dec_win` calls move into the one private function that decrypts a rebuilt
ciphertext; `value()` keeps wiping the noise.

### 4.6 PQZ: disclosure and memo

- `proveDisclose {chainUid, token, entryRef, fromUA, sendCounter, leg, kind, block, psid, words}`, `kind ∈ {RECEIVER_X,
  AUDITOR}`: `entryRef` recomputed (§4.3), the leg rebuilt from the entry blob, decrypted, the op 5 statement built inside
  (CTR-PQZ-14 layout, `pk` = the handle's) and proven; the output goes to the viewer the holder names. On chain,
  `verifyTransferAmount` reads the entry and the registry key itself.
- `proveDiscloseSender {chainUid, token, entryRef, fromUA, sendCounter, entryPtr, leg, registry, block, psid, words,
  legKeyRecord}` (op 4 `SENDER_S`, on the **sender's** handle; T15l, Fable P2-1): `keyRecord` is `fromUA`'s and must be the
  handle's key, `legKeyRecord` the registry's `pqzKey[UA_j]` (with its code), the statement's `pk`; `entryRef` recomputed
  (§4.3), the leg `u_g`, `v_j` rebuilt from the entry blob and the salt read from it. The facade re-derives `r, e1, e2_j` from
  CTR-PQZ-19's `seed_enc` by encrypting zero to the leg owner's key (an `M = 1` entry has op 1's and op 7's shape alike: both
  re-derivations are made, the matching one used), reads the **amount from the entry itself** (each `(v_j − v0) mod q` is
  `Δ·digit`, the digits counted branch-free) and requires `u_g` and `v_j` to equal the re-derivation at that amount (constant
  time); then it builds the op 4 statement (CTR-PQZ-14 layout) and proves it: `{stmt, proof, amount}`. No request field
  carries an amount or a statement, so no caller can test a guess against the holder's sent amounts (the previous form took a
  caller's statement: success or `Argument` was a plaintext-equality test, no key recovery). The statement form stays only
  under `vectors` (`rawProveDiscloseSender`, the vector rows). On chain, `verifyTransferAmount` reads the entry and the leg
  owner's registry key itself.
- `openMemo {chainUid, token, entryRef, fromUA, sendCounter, block, psid, words}`: the memo is `memos[entryRef]`, `entryRef`
  recomputed, header words from the named fields and the blob.
- op 1, burn and refresh still take `memoHash` as a free word; after T36a the facade computes it per `mode` as for op 7 (plan
  row T15k).

### 4.7 Zether (separate module, separate handle)

- The same library duties. `decrypt`, `decryptPending`, `checkBalance` and every `acc` / `balance` / `(C, D)` input of
  `proveTransfer`, `proveTransferMulti`, `proveBurn`, `recoverTransfer`, `openDisclosure`, `openMemo` are replaced by location
  fields and the Zether token's raw words, parsed by its pinned layout (T19c) and rebuilt as the contract does. Raw words
  (EVM, names as pinned by T19c):

  | Word group | What the facade reads |
  |---|---|
  | account | the account struct's slots in slot order: `acc` point words, `pending` point words, `accSeq`, `pendingSeq`, `lastRolledPendingSeq`, `sendCounter` |
  | dynamic `bytes` slots | the length slot and the `keccak256(slot)`-addressed data slots, as `{slot, word}` |
  | entries | `entryPtrs[entryRef]` (SSTORE2 pointer) and the record code `{address, code}`: `mode`, legs, `C_out_j`, `D`, `C_aud_j` |
  | token | `auditorMode`, `disclosureMode`, `auditorKey` word(s) for R6 |

  A layout parser exists per family where a Zether token is deployed (EVM first); another family's words are refused until
  its parser exists.
- `zether-prover`: the raw commands stay behind `hazmat` (T15c), and so do the public helpers that bypass the dispatcher
  (`api::open_memo_json` and the decrypt and disclosure primitives in `api.rs`, `elgamal.rs`, `schnorr.rs`): `pub` only under
  `hazmat`, `pub(crate)` otherwise, so the crate's own code keeps its access (T15c2).
- A debit's optional balance hint (the holder's plaintext, zether-limits D5: a balance above the device BSGS bound) and
  `checkBalance` take the holder's own **sealed balance-cache box** `{iv, ct}` (`cacheBox`; clientkeys `sealBalanceCache`),
  never a number (T15l, Fable P3-1): the box is opened inside under the handle's key (`HKDF-SHA256(x,
  "scaas-zether-balance-cache-v1")`, AAD `zether-cache:bls12381`), its entry `<UA>:<token>` is used only at the words'
  `accSeq` and checked against the rebuilt `acc` (`[b]G == C − [x]D`); a stale entry falls back to BSGS of the rebuilt `acc`.
  No one without the key can make a box that opens, so the rule "the hint comes from the holder's own box" is code, not a duty
  of the caller. Residual: fabricated words with the holder's real box are still a balance-equality test (§4.12). A box that
  does not open is `Argument` inside a command (the standalone `open_balance_cache` keeps `Aead`).
- **Every multiplication by `key.x` on a supplied point** runs through `scaas_ct::secret_mul`: decrypt and check, and the
  transfer, multi-recipient, burn and disclosure paths in `zether.rs` and `schnorr.rs` (T14b), not only `decrypt_point`.
  Residual (Fable P3-7): the per-transfer secrets still use arkworks' variable-time multiplication (`elgamal::encrypt`'s
  `y·r`, `st.y_t·k_s`, `y_f·k_s`, `open_sender_cp`'s `e.y_t·s`); a timing leak there reveals that transfer's amounts, never `x`.
- `zether-read-balance`: `--rpc` is a reading layer and is re-enabled only as one meeting R1 to R7; a raw `--ct` (a
  ciphertext typed in by hand: a social oracle, plaintext only) moves under `hazmat`; the production CLI accepts the holder's
  own sealed balance-cache box or R1-fetched state instead.

### 4.8 No test feature in a production artifact; pqz-core `hazmat`

- **The risk (Codex C1).** Cargo unifies features: any dependency that enables `scaas-ua/vectors` restores `dec` and the raw
  commands in a `--release` build, and the C / FRB compile asserts do not cover a Rust user of the crate.
- **Enforcement (T15c2):** (1) `scaas_ua::VECTORS` (`cfg!(feature = "vectors")`) and the `vectors` bit of
  `scaas_ua_features()`; every binding refuses to load a library with the bit set, and the facade's constructor of a key
  handle refuses (`Argument`) in a build with `vectors` unless the test-only marker type is used; (2) a repository check
  (`scripts/check_test_features.py`, run in CI and the gate) that fails if any `Cargo.toml` enables `vectors` or `hazmat` of
  `scaas-ua`, `zether-prover` or `pqz-ffi` outside `[dev-dependencies]` or a test-only crate; (3) a negative production-build
  check: `cargo tree -e features` of each production artifact (`ua-c`, `ua-dart-frb`'s crate, `zether-read-balance`) shows no
  `vectors` and no `zether-prover/hazmat`, parsed as a graph including transitive default features (Codex C7), and the same
  build with `vectors` forced is shown to fail the check (positive control).
- **pqz-core `hazmat` (owner decision Q3, 2026-11-06):** a feature over `pqzl` `decrypt_raw`, pqz-ffi's `dec` / `dec_win` and
  the C `pqz_dec` family; it lands with the next pqz-core change; the four-set full gate is waived for this `cfg`-only change
  and replaced by a build at all four sets plus `kat`. It is defence in depth: `ua-rs` enables it for its private decrypt
  path, so it is in every `ua-rs` + `pqz` binary; the name follows the RustCrypto convention and is not a security boundary;
  the command set is.

### 4.9 Server key oracle (CLI-SGN-31, PLANNED; F5)

The enclave interface loses `zk_mul_by_x(points, ctx)` (a static-DH oracle on `x`), `zk_nonce_commit` / `zk_response` as
separate calls (a response to a caller-chosen challenge is a proof or signature oracle) and the raw `elgamal_decrypt(C, D,
ChainWitness)`. **Whole operations inside the enclave** (group B': balance, transfer, burn, disclosure), each taking location
fields and raw words and rebuilding as `ua-rs` does; the layer that feeds it meets R1 to R7. Results go to the tenant (the key
holder), never to the relayer or the broker's logs. The planned threshold auditor key (CTR-ZTH-41, `y_audit` 3-of-5) is a
quorum decryption: ARCH-POS-13 covers it, and it stays blocked on research §12.5's open question.

### 4.10 Op 7 `memoHash` per mode (F10; owner decision 2026-11-06)

`PqzCore` on `ua-mtx-merge`: `memo = mode == HASH ? 2 + 40·m : 0` (~408) and `if (memo != 0) o.memoHash =
keccak256(abi.encodePacked(t.salt, t.sealedMemo))` (~430); op 1 the same at ~286 / ~304 with `SEALED = 41`. The facade's
memo is `salt(16) ‖ sealed` (`pqz_ffi::memo::seal`), so `keccak(memo)` equals the HASH formula, but BUNDLE needs 0.
**Decided (owner 2026-11-06):** the facade takes the memo mode as an explicit named request field, `mode` = `"HASH"` or
`"BUNDLE"` (no default), for op 7 now and op 1 once T36a lands, and computes `memoHash` exactly as the contract does per
mode: HASH → `keccak256(salt ‖ sealedMemo)` and the memo returned; BUNDLE → `memoHash = 0` and no memo returned. The token's
`disclosureMode` decides which a caller may use (COMPACT refuses BUNDLE on chain, ~399). Built in T15b.

**Change (2026-11-09, proof-path spec C3; owner ruling §7 item 8):** on a token of release 3h every debit's `memoHash` is
`keccak256(memo ‖ ownTag)`, `memo = salt ‖ sealedMemo` on HASH and empty on BUNDLE, burn, refresh and unwrap (§4.14.5); the
facade serves release 3h only, and the formulas above (and T15k's) move to `clients/ua-rs/legacy/ua-rs-sign/`. The explicit
`mode` field stays.

### 4.11 What does not change

`enc` (public), `proveRegister`, `proveKeyRecord`, the balance-cache boxes, the vault and backup formats, the KEM `open`
(ML-KEM is CCA-secure; `ua-rs-sign` spec §6.2's handle rule stays), the C ABI's status set; no contract code, node or
byte-format change (T19c adds layout pins and tests only). `ua-rs` stays I/O-free and holds no chain trust.

### 4.12 Residuals (stated plainly)

- **`ua-rs` alone cannot tell chain state from forged words** (stated plainly after the Fable review of 2026-11-07, its
  verdict 1). With the owner's ruling (no verifier in `ua-rs`), the library decrypts **any internally consistent fabricated
  words**: a fabricated "blob" holding crafted `(u, v)` is rebuilt and decrypted like a real one, so **the full key-recovery
  oracle of §1 exists for any app that breaks the reading-layer requirements R1 to R7** (8·K fabricated `balance` requests
  recover `s`; `auditRead` and `proveDisclose` give the same at their windows). The library makes the bare-ciphertext path
  impossible and the location explicit, and every word check refuses a careless caller; none makes words authentic. The
  residual control of §5 (`no_oracle.rs`) shows this on purpose. ARCH-POS-13 then binds the app.
- **Path (B) (2026-11-09, §4.14) closes that residual for what it decrypts:** a fabricated part has no valid P and no tag, so
  the 8·K requests are refused whatever the reading layer hands over. What stays for path (B): the composition (a wrong
  balance, and a balance bit through an outward action, hence a debit's R1 words, §4.14.6); availability (a P gone from history
  means path (A) under R1–R6, or a refusal); a quorum's operator window (§4.14.8); the soundness argument is an audit item
  (§4.14.1). Path (A) keeps the residual above.
- **Reference reading layers.** Zether has one: `zether-read-balance --rpc` (R1 to R7, T14b). PQZ has `pqz-read` (a binary of
  the `ua-rs` package, T15m, owner-approved 2026-11-07): `balance` and `auditRead` only; its residuals (hand-copied
  `OpenFactory._info` offsets until the factory index pins them, the registry's `pqzKey` slot hand-copied and `--registry`
  unchecked against the token's immutable, no `codeHash` check) in `docs/clients/ua-libraries.md#CLI-UAL-40`. An app
  reading PQZ state for another command builds its own reading layer under the R1 to R7 assertions of §4.2.
- **The reading layer's source:** see §4.2 (owner decision Q1b).
- A stale read shows an old balance; a debit over it is refused on chain (T8 retry), revealing nothing about `s`.
- A genuine state is composed partly by senders (credits, decoys); its decryption is the holder's own data and reveals
  nothing about `s` (fact 1).
- Timing after the key is used (BSGS for Zether, the PQZ prover) depends on the holder's own genuine value: a privacy residual
  to a local observer, not a key leak.

### 4.13 Prepared for a later proof path (no build in this rework)

**Change (2026-11-09):** that proof path is §4.14; the reserved label `PQZ/owntag/v1` is the proof-path spec's C4.


A later round may let `ua-rs` check state proofs itself again (the owner ruled it out of this rework). So that nothing here
blocks it: requests carry raw slot words by index (§4.3), which a proof path can verify unchanged; binding tests assert that a
command is **in** `COMMANDS`, not that `COMMANDS` equals a list; a proof verifier may be compiled into `ua-rs` unexposed later
without an API change; the HKDF label `PQZ/owntag/v1` is reserved for an own-output tag; pending entries are selected by
`[rolled, p)` only; state vectors are versioned by contract commit.

### 4.14 PQZ: the proof path (B), release 3h — SPECIFIED (2026-11-09)

**Source:** the contract interface of the proof-path spec on `ua-mtx-merge` ([`2026-11-06-pqz-proof-path.md`](2026-11-06-pqz-proof-path.md)
§9, built there by T58–T65 and merged here at plan T20b milestone 4) and its client items (§13.3, C-PP-1 … C-PP-10); research
[`pqz-leg-proof-option.md`](../../research/pqz-leg-proof-option.md) §3, §4, §8–§10, §15 and §15A (the owner's agreed design);
the owner rulings of 2026-11-09 (§7, items 5–12). Plan task T20d (T20d0 is this section). [CLI-UAL-60](../../decisions.md#CLI-UAL-60).
Revised 2026-11-09 after the Fable review of the delta (approve with fixes: P1-1, P2-1 … P2-3, P3-1 … P3-6, all applied; §7
items 10–12 the owner's rulings on its questions). UNAUDITED.

#### 4.14.1 What path (B) gives, and what it does not

- **Key-safe from any source.** Every part of a proven sum is a ciphertext the library checked itself, before the key is used:
  a credit by its sender's debit proof P, which the library verifies over a statement it rebuilds with **its own key** in the
  leg the credit names; the holder's own `v_f` by its `ownTag` (a seed-keyed MAC, proof-path spec PP-3); a migration credit by
  re-encryption from the debited version's seed (3g KV-11); a TRIVIAL entry rebuilt from its public amount. One of §1's crafted
  `(u, v)` has no valid P (a short `(r, e1)` with `Aᵀr + e1 = u` would break MSIS / MLWE, research §3.1) and no tag (`K` is the
  holder's), so it is refused with the key unused; a well-formed ciphertext that someone proved to the holder's key decrypts to
  the digits its prover chose, which says nothing about `s` (fact 1 extended to parts outside state). So the words, logs and
  calldata of path (B) may come from **any** source for viewing, unlike R1–R6 of §4.2 for path (A).
- **Not the composition** (research §3.3). A check certifies a part, not that the parts are the account's state: a source can
  omit a credit, add a part it proved itself, or replay an older own debit (**a tag proves authorship, not inclusion**). The
  result is then wrong, never a key leak; an outward action that depends on it gives the source a balance bit. Hence §4.14.6:
  viewing takes its words from any source, a debit takes every word and code that fixes `T`'s bytes from a source under R1–R5.
- **Formal status.** The argument is the "encrypt, then prove knowledge of the plaintext" route (Naor–Yung); a proof for PQZL
  and PQZH needs simulation-sound extractability of their Fiat–Shamir proofs under adaptive queries, which nobody has written:
  an audit item, not a claim (research §3.1).
- **Scope.** Tokens of release 3h only (owner ruling 2026-11-09, §7 item 8): the facade parses 3h's layout for path (A) and (B)
  alike (`acct[ua][v]`: `lastDebit` inner 2, `accHash` 3, `pending` 4, `accWords` 5; `debitRec` slot 19; `proofStore` slot 0
  byte 23, the `scaas.pqz` pin), and the reading layer refuses an earlier release by name (R5's Change, §4.2). Path (A) stays for
  every 3h token and is the single holder's fallback (§4.14.7). Zether gets nothing (ElGamal has no key-recovery oracle, research
  §11.4; Zether ≠ PQZ). Not in this round: the auditor's and the disclosure commands (`auditRead`, `proveDisclose`,
  `proveDiscloseSender`, `openMemo`) stay on path (A).

#### 4.14.2 Commands

On the PQZ handle of the account's key version (`PqzKey::call`, `scaas_ua_pqz_call`) unless marked. Named, typed fields as §4.3
(only code, a log's `data`, a memo and a proof are `bytes`); every refusal before the key is the one status `Argument`; the
handle's states give `KeyRevoked`.

| Command | Fields | Output |
|---|---|---|
| `provenOpen` | `balance`'s location and account fields (`chainUid`, `token`, `ua`, `block`, `psid`, `blobs`, `keyRecord`, `keyVersion`, `keyVersions`, `account` (the 4 slots of `acct[ua][v]`), `accWords`, `sendCounterWord`, `forOp7`), `lastRecord` (`{w0, w1}` of `debitRec[ua][lastDebit − 1]`; absent exactly when `lastDebit = 0`), `pending` (`{index, word}` for exactly `[p_last, p)`), `auditorUA` | `{session, p, sendCounter, need, unsealed}`; opens the handle's one session |
| `provenAdd` | `session`, `credits` (each as §4.14.4) | `{accepted, refused}`: the indexes of this call that passed and that failed their check |
| `provenCancel` | `session` | `{}` |
| `balanceProven` | `session` | `{value, p, sendCounter, parts, unsealed, sealAdvised}`; closes the session |
| `proveTransferProven`, `proveTransferMultiProven`, `proveBurnProven`, `proveRefreshProven` | `session` and the debit fields of `proveTransfer`, `proveTransferMulti`, `proveBurn`, `proveRefresh` (`chainId`, `registry`, `beneficiaryUA`, `fee`, `validUntilBlock`, `shieldIn`, `envelopeBinding`; `toUA`, `pkT`, `pkA`, `legs`, `amount`, `recipient`, `mode` by form) | path (A)'s output (`{stmt, proof}`, `memo` on HASH) plus `ownTag`; closes the session |
| `checkProven` (no handle: `scaas_ua_pqz_check`) | §4.14.8 | `{parts, sum}` |

- `p` is the facade's choice as in §4.4 (CTR-PQZ-06, `forOp7`); `p_last` is `lastRecord`'s `p` (0 when never debited). A
  session's parts are the own `v_f` (in `accBlob`, the blob of the account's last debit, proof-path spec C2) and every entry of
  `[p_last, p)`; `need` lists the indexes there that are not TRIVIAL. `balanceProven` and the debits refuse until every `need`
  index is accepted. `parts` names each part's index and kind (`own`, `credit`, `migration`, `trivial`), never a value.
- **The session** is the streaming form C-PP-7 asks for: a credit's material is 93–186 KB at `n2304-kmax4096` (research §15.2),
  so one request of `CMD_MAX` (4 MiB) holds a few tens, a window up to `K_MAX − 1` credits. **One session per handle**, held in
  the handle's memory and never exported; a second `provenOpen` replaces it; `lock()` and freeing the handle drop it. It keeps
  what `PqzCore` keeps while it sums: the running sum mod `q` of the parts checked so far (and, for a debit's cross-check of
  §4.14.3, the sum of those below `rolled`), their units and a bitmap of the accepted indexes, never the checked ciphertexts
  themselves (Fable P3-3). **A credit that fails its check is refused alone**
  (owner ruling 2026-11-09, §7 item 11): `provenAdd` names it in `refused`, the session and its accepted parts stay, and the
  caller may send that index again (another source's material) or take path (A). Every `provenAdd` check is keyless (P
  verification, re-encryption from a seed, a public amount), so a kept session leaks nothing and closing it would buy no key
  safety; a malformed request (a field, a bound) is still `Argument` for the whole call. The key is used only by
  `balanceProven` and the debits, once every `need` index is accepted.
- Path (A)'s commands keep their fields; they read 3h's layout and build the 3h `memoHash` (§4.14.5).

#### 4.14.3 How each part is checked (all before the key)

| Part | Check | What it binds |
|---|---|---|
| own `v_f` (`lastDebit > 0`) | `accBlob`'s tail `… ‖ P(v_f) ‖ ownTag ‖ kv(8·n) ‖ u8(n)` parses through one `rOf` twin; `ownTag` equals `HMAC-SHA256(K_v, chainUid ‖ token ‖ ua ‖ be32(lastDebit − 1) ‖ keccak256(P(u) ‖ P(v_f)))`, `K_v = HKDF-SHA256(seed_v, "", "PQZ/owntag/v1", 32)` from the handle's seed, compared in constant time; `u` is `u_0` after the 16-byte salt (op 1, op 7) or `u′` at 0 (burn, refresh, unwrap), told apart by `R`'s length as `e2e.py` `acc_of`; `P(·)` the stored form as the contract hashes it (clientkeys `pqzOwnTag` and the KAT are the reference) | `K_v` (independent of `s`) |
| credit (an op 1 or op 7 leg to `ua`) | the sender's statement rebuilt as §4.14.4 with the handle's own `pk` at the leg; `pqz_ffi::precompile(op ‖ statement ‖ proof)` answers `…01` | the handle's `pk`; the leg's bytes, which are the bytes summed; the pairing `(u_{g(j)}, v_j)` the relation defines |
| migration credit (`fromUA == ua`, the sender's version below `v`) | re-encryption (3g KV-11): `r, e1, e2` from `seed_enc` of the debited version's seed (CTR-PQZ-19: chain, token, `fromUA`, the sender's counter, the blob's salt), then `u == Aᵀr + e1` and `v − pkᵀr − e2 ∈ Δ·[0, 16)^16` byte for byte, constant time, the amount read from the digits; the old version's seed comes from the handle's own store (a derived handle: `(account, index, v_old)`; an installed one: that version's key hash); **when the store holds no such seed, the credit is checked by its P like any credit** (owner ruling 2026-11-09, §7 item 12; Fable P3-2): it is an op 1 leg to the handle's own `pk` | the seeds, or the P |
| TRIVIAL (`vOff == 0`) | `Trivial(digits(amount))` from the word's low 64 bits | public |

- The sum `v_f + Σ parts + Trivial(shieldIn)` is built exactly as `PqzCore` builds `T` (mod `q`, `unitsOf ≤ K_MAX`); for a debit
  it is that debit's `T`, which its proof binds verbatim.
- Under path (B) the materialised `acc` is a cache: never decrypted and never summed. For a debit only, it is cross-checked
  against the parts: with `flags & MAT`, `accWords` (unpacked and checked against `accHash` as §4.4) equal the sum of `v_f` and
  the parts below `rolled`; without it, `rolled == p_last`. A mismatch is `Argument`.

#### 4.14.4 Rebuilding a credit's sender statement (proof-path spec §9.4)

Each element of `credits`:

| Field | Content |
|---|---|
| `index` | the pending index of the credit (one of the session's `need`) |
| `fromUA`, `sendCounter` | the sender's debit `(fromUA, k)` |
| `form` | a credit: `"transfer"` (op 1) or `"transferMulti"` (op 7), the only forms that credit another UA; a quorum's own last debit (§4.14.8, its `own` field): also `"burn"`, `"refresh"`, `"unwrap"` |
| `record` | `{w0, w1}` of `debitRec[fromUA][k]`, both read as storage (C-PP-1's parser: `w0 ≠ 0`, `RECORD` set and no flag but `WIDE`, `proofStore` 0 or 1, `w1` zero when narrow, `w1`'s low 64 bits 0, a narrow record's `prevCounter = k − 1` when it has a predecessor) |
| `senderPending` | `{index, word}` for exactly `[p − Δp, p)` of `pending[fromUA][record.keyVersion]` |
| `blobs` | `{address, code}`: the op blob (the pending slot's `blob`), the record's `prevBlob`, each blob `senderPending` names; a code listed once per request |
| `keyRecords` | `{ua, version, word}` of the registry's `pqzKey[ua][version]` (its code in `blobs`): the sender's at `record.keyVersion`, and every key the tail's `kv` names except the holder's own leg (op 7: the legs' `UA_j` from the blob; the auditor's: `auditorUA` at `kv`'s last entry) |
| `proof` | P: the `proof` of the debit's `PqzDebitProof` event (LOG) or the `proof` parameter of its call (NONE) |
| either `header` | the 20 words of the event's `header` (LOG; the verified statement's first 640 bytes) |
| or `call` | the debit call's header words a reader takes from its calldata (NONE), one shape per form (step 4) |

The reading layer decodes the event (its topics `blob`, `ua`, `sendCounter` name the debit; its `data` holds `header` and
`proof`) and hands the two as named fields: no ABI decoder of a log in the facade (Fable P3-1), and a header the reader got wrong
only fails the verification.

A migration credit (`fromUA == ua`) needs only `index`, `fromUA`, `sendCounter`, `form`, `record` (its `keyVersion` names the
seed) and the op blob in `blobs` while the store holds the debited version's seed (re-encryption, §4.14.3); without that seed
it is checked by its P and carries this table's other fields too, else `Argument`. A credit wrongly given as one fails the
re-encryption.

The facade, in order, each failure `Argument`:

1. Parses `record` and the op blob's tail (`n ≤ 9`, `kv` `be64` in statement order, `ownTag_s`, `v_f`, `R`). The leg: op 1
   `toUA` (the 32 bytes that end `R`) `== ua` and `kv[0] == v`; op 7 the one leg `j` with `UA_j == ua` and `kv[j] == v`, `M` and
   the auditor copy from `n` and `R`'s length, **exactly one `(M, auditorOn)` fitting** (two fits, or none, is `Argument`; Fable
   P3-6; `e2e.py` `rebuild` takes the first). The part's `(u, v)` is **the pairing the relation defines**, `u_{g(j)}` with `v_j`
   (`g(j) = j / legsPerGroup(auditorOn)`), derived from `j`; the holder's pending slot's `uOff` / `vOff` must equal those two
   offsets in `R` and are never the source of the pairing (Fable P2-3).
2. `T_k` by the proof-path spec §2.3: `prevBlob`'s `(u, v_f)` (`Trivial(0)` when `prevBlob = 0`) `+ Σ senderPending +
   Trivial(digits(shieldIn))`, `unitsOf ≤ K_MAX`.
3. The keys: `pk_f` the sender's record code; each other key by its `kv` from `keyRecords`; at the holder's leg the handle's own
   `pk`, never a source's; pairwise distinct (the contract's `KeyReused`).
4. The header's 20 words. LOG: the `header` field. NONE: built from `call`, the record (`p`, `plainUsed = shieldIn`), `fromUA`,
   `k`, the token's words (`psid`, `chainId`, `token`, `registry`, `chainUid`), the blob (`salt`, `toUA` or the legs'
   `recipientsHash`, `M`, `auditorOn`) and `memoHash = keccak256(memo ‖ ownTag_s)`. In both, the words the facade knows
   (`proofSystemId` the build's, `opTag` the form's, `fromUA`, `sendCounter`, `p`, `plainUsed`, `chainUid`, `token`) must be the
   header's. **One `call` shape per form** (Fable P2-1; `e2e.py` `header_of`'s three branches are the reference, `PqzCore`
   `prepareBurn`, `WrappedPqzToken._envUnwrap`):

   | Form | `call` fields | `envelopeBinding` word | `memoHash` |
   |---|---|---|---|
   | op 1, op 7 | `beneficiaryUA`, `fee`, `validUntilBlock`, `mode`, `sealedMemo` on HASH, `binding` | `keccak256(abi.encode(b, uint8(mode)))` (`PqzCore._bindMode`): `b = keccak256("SCAAS-PQZ-DIRECT-MODE-V1")` direct (`binding = 0`), `b = binding` relayed; computed by the facade | `memo = salt ‖ sealedMemo` on HASH, empty on BUNDLE |
   | burn, refresh | `beneficiaryUA`, `fee`, `amount`, `recipient`, `validUntilBlock`, `binding` | `binding` as given: 0 direct, the envelope's relayed (no `_bindMode`); `opTag` REFRESH when `amount = 0`, else BURN | `keccak256(ownTag)` |
   | unwrap (kind 5) | `beneficiaryUA`, `fee`, `amount`, `recipient`, `validUntilBlock`, `underlying`, `minOut`, `binding` | `unwrapBinding(underlying, minOut) = keccak256(abi.encode(keccak256("SCAAS-PQZ-UNWRAP-V1"), underlying, minOut))` direct (`binding = 0`), `keccak256(abi.encode(binding, unwrapBinding(…)))` relayed; computed by the facade | `keccak256(ownTag)` |

   `binding` is 0 on a direct call, else the relayed call's envelope binding, a word the reading layer reads or computes from the
   envelope (`envelopeBinding(UAEnvelope)`); a wrong one only fails the verification. **`fee`** is the header's word: on op 1,
   a burn, a refresh and an unwrap the token's `confidentialFee` when `beneficiaryUA ≠ 0`, else 0; on op 7 that plus `M ·
   decoyFee`, `decoyFee` an argument of the debit's own call. `confidentialFee` is set once at the token's initialisation
   (`PqzStateLib`, ~95) and has no setter, so it is the token's word at any block; if a release ever adds a setter, it must emit
   an event, so a reader finds the value at a past debit's block (a note for the contract side).
5. The body in the form's statement layout (op 1 `pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ u ‖ v_t ‖ v_f ‖ [v_a]`; op 7 `pk_f ‖ pk_1 … pk_M ‖
   [pk_a] ‖ T ‖ u_0 … u_{G−1} ‖ v_1 … v_M ‖ v_f ‖ [v_{a,1} … v_{a,M}]`; `e2e.py` `rebuild` is the reference, test code).
6. `pqz_ffi::precompile` over `op ‖ statement ‖ proof` (the chain's own function, panics caught) answers `…01`; the part is then
   the leg's `(u, v)` as the statement carried it.

Three things bind safety: step 3's own `pk` at the holder's leg, the bytes step 6 verified, and step 1's pairing `(u_{g(j)},
v_j)` as the relation defines it (derived from `j`, checked against the pending slot's offsets, never taken from them: a `v_j`
summed with another group's verified `u` would decrypt to the digits plus a small linear function of `(s, e)` the sender
chose, Fable P2-3). Any other word a source gets wrong fails the verification (liveness, never the key).

#### 4.14.5 `ownTag` and `memoHash` in every debit (C-PP-4)

Every debit command of path (A) and path (B) (op 1, op 7, burn, refresh, unwrap, a migration), after it builds `u` (`u_0` or `u′`)
and `v_f`: `ownTag` as PP-3 with the debited version's seed and its `sendCounter` (`be32`; a counter at or above 2^32 is
`Argument`, as `seed_enc`); `memoHash = keccak256(memo ‖ ownTag)`, `memo = salt ‖ sealedMemo` on HASH and empty on BUNDLE, burn,
refresh and unwrap (proof-path spec C3). The output carries `ownTag`; the caller puts it in the payload (`PqzTransferArgs` and
`PqzMultiArgs` after `salt`, `PqzBurnArgs` after `beneficiaryUA`; a node job's `args.ownTag`, NODE-JOB-24's job shape). The
shared KAT is `smartcontracts/vectors/ua/pq_kat.json` `ownTag` and `memoHash` (proof-path spec C4). Changes §4.10 and T15k: their
pre-3h formulas move to `clients/ua-rs/legacy/ua-rs-sign/` (owner ruling §7 item 8).

#### 4.14.6 Where the words may come from

| Use | Words | Source |
|---|---|---|
| viewing (`balanceProven`) | all | any source; R2 (the configured chain) and R7 (nothing back) still bind |
| a debit (`prove*Proven`) | every word and code that fixes `T`'s bytes: `account`, `sendCounterWord`, `keyRecord`, `keyVersions`, `psid`, `lastRecord`, `pending`, `accWords`, the codes of `accBlob` and of each credit's op blob | one source under R1–R5 at one block (R3), as path (A); R7 |
| a debit | what only makes a part's check pass: each credit's `record`, `senderPending`, the sender's other blobs, `keyRecords`, `header` or `call`, `proof` | any source |
| either | history: `eth_getLogs` by the `blob` topic (LOG), the debit's transaction (NONE, proof-path spec §9.5; a call made through another contract needs a trace, which many RPCs do not serve: then path (A)) | any full node or mirror of that chain |

This binds more than research §3.3, which narrowed a debit's trusted words to the account words: a credit's code from another
source can be a part that source proved itself, and a debit over it fails on chain, a balance bit.

#### 4.14.7 Sealing and the reinstall table (C-PP-5)

- `unsealed = pendingCount − p_last`: the entries no own debit has folded into a tagged `v_f`; each needs its P from history (or
  path (A)) on a later reinstall. `sealAdvised = unsealed > 0`: a refresh seals them; a wallet may advise one before it goes cold
  and never requires one (no periodic holder action, research §15A). A rollover seals nothing.
- **A tag proves authorship, not inclusion:** no command treats a tag match as the latest state; the latest own debit is the
  record at `lastDebit − 1` of the session's source.

| After a reinstall | Commands |
|---|---|
| no entry since the last own debit | `provenOpen` (`need` empty), `balanceProven`: the tag alone, nothing from history |
| new credits, every P in history | `provenOpen`, `provenAdd`, `balanceProven`; a `proveRefreshProven` seals |
| new credits, a P lost, a source under R1–R6 | path (A): `balance`, then `proveRefresh` seals |
| new credits, a P lost, no trusted source | refused; the funds stay until a trusted source exists |

The library does not choose between the rows: `provenAdd` refuses a credit it cannot check, and the caller then takes path (A)
under R1–R6 or stops. The choice depends on availability, never on a decryption (research §8).

#### 4.14.8 An MPC quorum (C-PP-6; owner ruling 2026-11-09)

A quorum has no seed and would decrypt by MPC. That partial decryption is not built and waits for the threshold protocol
(research `pqz-threshold-decrypt-prove.md` §12.5). Built now: **`checkProven`**, keyless, through a C function without a handle
(`scaas_ua_pqz_check`, beside `scaas_ua_pqz_call`; no new status). A member runs it before any partial:

- **the quorum's own last debit by its P** (found by `lastDebit`; burn, refresh and migration included): its statement rebuilt
  as §4.14.4 with `pk_f` the member's own `pk` (below, never a source's) and `T` by the proof-path spec §2.3; no tag (no seed);
- **every credit since by its P**, migration credits included (no seed, so no re-encryption), at most `K_MAX` parts.

Fields: `provenOpen`'s location and account fields without a handle and without any key word of the quorum, plus **`pk`, the
quorum's key, from the member's own record of the key generation** (the member's DKG record; a named `bytes` field of the set's
key length), `own` (the last debit's material, the fields of §4.14.4) and `credits`. The facade puts that `pk` at the quorum's
leg of every credit and as `pk_f` of the own last debit, as the handle path puts the handle's `pk`; **the source names no key of
the quorum** (owner ruling 2026-11-09, §7 item 10; Fable P1-1): a `keyRecord` for the quorum (or any key word of it) is
`Argument`, so a source cannot make the check certify parts under a key it controls, which the later MPC partial would turn
into a share leak. Output `{parts, sum}`: the indexes checked and the packed sum of their ciphertexts, which the member's MPC
step (later) opens; a batch per call, the member adding the batches' sums (public arithmetic). It decrypts nothing and uses no
key. Its bounds are `PqzKey::call`'s, applied by the same bounded reader although no handle is involved (Fable P3-4): `CMD_MAX`
4 MiB and depth 8 per request, `pqz_ffi::MAX_INPUT` per statement, at most `K_MAX` parts.

A quorum never uses path (A); with a P gone from history the fallback is the proof-path spec §9.6's: `k`
members rebuild `seed32` from the k-of-n backup (T16a), one becomes the operator, seals by refresh under path (A) with a trusted
source and rotates the key version (3g); from rebuild to rotation the operator holds the whole key.

#### 4.14.9 Bounds (C-PP-7)

- Every request within §4.3's caps (`CMD_MAX`, depth 8); a credit's statement within `pqz_ffi::MAX_INPUT`, its `proof` within
  the set's largest; `n ≤ 9`; a window and a session within `K_MAX − 1` credits.
- Batches are the caller's: `provenAdd` as often as needed; cancellation by `provenCancel` or by dropping the handle. A code is
  listed once per request and referred to by address, so a reader fetches a shared op 7 blob once and sends the credits that
  share it in one batch.
- The version chain: a sender's predecessor is in its record (`prevBlob`, no walk); the quorum's last debit by `lastDebit`,
  older ones by `prevCounter`, one lookup per step.
- Cost on the device (research §15.2): 45–51 ms per credit verify at `n2304-kmax4096` (one core, p99 proxy), 93–186 KB fetched.

#### 4.14.10 C ABI and bindings (C-PP-8)

The session commands through `scaas_ua_pqz_call` (no new status); `scaas_ua_pqz_check` the one new export, additive (no struct
or status changes, so ABI 6 is kept; the header regenerated), with §4.14.8's bounds; a session lives in the Rust handle, never
in a binding. `ua-cxx`, `ua-dart-frb`, `ua-py`, `ua-go`, `ua-cs`: the new
commands in their `COMMANDS` membership tests and `checkProven` beside their PQZ call; `ua-qt` exposes no PQZ key and gets none.

#### 4.14.11 The reference reader: `pqz-read --command balanceProven` (owner ruling 2026-11-09)

`pqz-read` (T15m) gains `--command balanceProven`: the composition words as for `balance` (R1–R5 at one block, R3's re-check),
the senders' records, windows, blobs and keys from state (pending slots and records are never deleted), each credit's
`(fromUA, k)` from the `PqzDebitProof` topics (LOG) or from the call and the `Credited` log's `entryRef`, which `(fromUA, k)` must
recompute (NONE), P and the header by `eth_getLogs` on the `blob` topic (LOG; the reader decodes the event's `data` into
`header` and `proof`, P3-1) or
from the debit's transaction (NONE: a direct call or a SCaaS envelope parsed by its ABI; a call through another contract is
refused by name: it needs a trace). Before anything else it probes `proofStore()` and refuses a token of a release before 3h by
name (R5's Change), for `balance` and `auditRead` too. Tested against a local `anvil` (plan T20d8).

#### 4.14.12 Vectors

Shared rows from their generators, never by hand: `pq_kat.json` `ownTag` and `memoHash`; `pqz/state.json` and
`pqz/n2304-kmax4096/state.json` `records`, `tails`, `proofLogs` (`ua-mtx-merge` T62; proofs mocked); `typed_ops.json`'s six 3h
debit rows and `UASetProofStore`. **Owner ruling 2026-11-09:** the rows that tie a NONE debit's call fields to the header the
contract built, and a relayed debit's envelope binding, at both vector sets, are a test-only follow-up of T62 on
`ua-mtx-merge` (T62a, after T77), taken at the next sync; until then the NONE header is held to the `pqz_chain` model and the
LOG row, **so the NONE path is BUILT against the model and contract-checked only after the T62a sync** (Fable P3-5: the model and
the facade are both this repository's code; a shared misreading stays green until those rows arrive). The op 7 shape fit is held
to `tails` rows with and without the auditor at both sets (`op7 M=2 audited …`, `op7 M=4 carol->[bob,alice,dave,erin]`; P3-6). Real proofs come from the facade's own prover on the `pqz_chain` model, verified with pqz-ffi, as T15e's tests; the
contract side's real-proof check is `ua-mtx-merge` T65.

## 5. Tests that must be able to fail

- **The oracle harness** (`clients/ua-rs/tests/no_oracle.rs`): the 8·K crafted queries of research §12.1 at the default set.
  Positive control: through the `vectors`-only raw `dec` they recover `s` exactly. Negative: no production command or binding
  call accepts a bare ciphertext, statement, `T`, `p` or parsed field (one status, key-use counter 0).
- **Residual control (§4.12):** the same crafted `(u, v)` wrapped as consistent fabricated raw words **is** decrypted: the
  test records that authenticity is the reading layer's duty.
- **Word negatives** (one status, key unused): a `psid` of another set; indexes other than `[rolled, p)`; an offset outside its
  blob; an `acc` not hashing to `accHash`; more than `K_MAX` units; a leg outside its entry; a `fromUA` / `sendCounter` that
  does not recompute to `entryRef`; an auditor read of an entry without an auditor copy; a missing or extra word.
- **Leg and role (Codex C5):** a foreign leg (its `UA_j` is another account), a registry key of another account or not
  `proven`, a receiver read on the auditor handle, an auditor read on a receiver handle, an auditor read of a token with
  `auditorMode` NONE: each refused with zero key use.
- **Production artifacts (§4.8):** `check_test_features.py` and the `cargo tree -e features` check pass on the real manifests
  and fail on a scratch manifest enabling `vectors` (positive control); a binding refuses a library whose `vectors` bit is set.
- Mutants (each must turn a test red): the caller's `T` accepted again; `p` taken from the request; `not()` skipped on
  `accWords`; TRIVIAL read as `blob == 0`; the `accHash` comparison skipped; the unpacker's field width off by one; `entryRef`
  not recomputed; the auditor window ignored; F10's `memoHash` always set; the `vectors` load check removed. Every mutant run
  is bracketed by `git diff --exit-code` (restored tree).
- Byte equality with the contract: the forge state snapshots of §4.4 at the default set and one other set.
- **Path (B) (2026-11-09; plan T20d2–T20d10):** positive control first (op 1 with and without the auditor, op 7 with `M` legs
  and the auditor, burn, refresh, unwrap, a migration, after rollovers, an un-roll and a rotation, and the forms the
  contract-side gate did not run: `shieldIn ≠ 0`, a PQZH token, a relayed debit), `balanceProven`'s value equal to path (A)'s
  `balance` over the same state; then, each refused with the key unused: the proof-path spec §11.4's negatives (a wrong
  historical key version, a swapped leg, a wrong auditor window, a wrong `shieldIn`, a wrong predecessor or `Δp`, a version
  boundary crossed, P of another debit, the mode of another record), a forged `T`, more than `K_MAX` parts, a non-canonical
  coefficient, a forged `ownTag`, an older own blob under the current `lastDebit` and record (its tag's counter differs); the
  residual control's crafted `(u, v)` refused by path (B) (no P); `checkProven` with a `keyRecord` whose code differs from the
  member's `pk` (Fable P1-1: refused, no parts); `pq_kat.json`'s `ownTag` and `memoHash` rows; `state.json`'s `records`,
  `tails`, `proofLogs` at both sets; `checkProven` with no handle. **Residual control of path (B)** (Fable P2-2, recorded like the
  one above): an older own debit with its own older `lastDebit`, record and blob, all genuinely the holder's, is **accepted** by
  `balanceProven` (a tag proves authorship, not inclusion: the result is a past balance, never a key leak); a debit over it is
  stopped only because `account`, `lastRecord` and the `accBlob` code are R1–R5 words (§4.14.6). Mutants per task (plan T20d),
  among them "the leg paired with another group's `u`" (Fable P2-3; red on the op 7 positive control).

## 6. Doc changes

On `ua-rs-sign` (task T15j): `ua-rs-sign` spec §10.1 / §10.2 (decrypt rows → location and raw words; chain reading and its
checks stay with the reading layer); `docs/clients/ua-libraries.md`: a rule group for the library duties (§4.3, §4.8) and one
for "the wallet layer that reads the chain" (R1 to R7 with their assertions; current docs name no consumer), with their
`decisions.md` entries at build (T19).
**Change (2026-11-09, plan T20d11):** `docs/clients/ua-libraries.md` gains path (B) beside path (A) (§4.14: the commands, the
3h-only rule, `ownTag` in the output and a node job's `args.ownTag`, `PROOF_STORE_OVER_LANE_CAP` linked to the node docs on
`ua-mtx-merge`, the residuals); [CLI-UAL-60](../../decisions.md#CLI-UAL-60) records the owner rulings now and its status at build.

On `ua-mtx-merge` (tasks T19b docs, T19c layout pins; not edited from here):

| File | Change |
|---|---|
| `smartcontracts/evm/test/v2/layout/namespaces.json`, `test/v2/Layout.t.sol` (T19c) | `scaas.pqz` and `scaas.zether`: every account-struct and storage field pinned (namespace slot, slot in struct, byte in word), tested by a write and `vm.load` as the existing pins; no contract code change |
| `docs/contracts/pq-zero-knowledge.md` | T6: "noise never leaves `pqz_dec`" → decryption only of ciphertexts rebuilt from raw words a trusted reading layer supplies, the core's raw decrypt is `hazmat`; CTR-PQZ-14 and §4.2's owner-only `Dec` point at ARCH-POS-13; §7.8 "Restore from state alone" → from state read from a trusted source (views only from R1's node); the source-trust residual linked to NET-EVM-04 |
| `docs/contracts/zether.md` | a rule (new id) pointing at ARCH-POS-13: the same split; `zether-read-balance` (line ~252) is a reading layer under R1 to R7, raw `--ct` under `hazmat`; the residual linked to NET-EVM-04; CTR-ZTH-41's threshold key blocked on §12.5 |
| `docs/clients/signers-clientkeys.md` | CLI-SGN-31 group B per §4.9; the `y_audit` note; the clientkeys `zether.js` wording; a link to R1 to R7 |
| `docs/integration.md` | confidential payments: an integrator reading PQZ or Zether state for a holder is a reading layer under R1 to R7 |
| `docs/research/07-custody-providers.md` | a dated note at ~111: the group B sketch is superseded by ARCH-POS-13 / CLI-SGN-31 |
| `docs/node/submit-lanes.md`, `docs/node/gateway.md` | NODE-LANE-03: the node never decrypts; a reading layer uses a node only as R1 allows (no new node guarantee) |
| `docs/decisions.md` | ARCH-POS-13's source: the audit done, this spec; entries for the owner rulings and decisions of 2026-11-06 (no verifier in `ua-rs`; the reading layer's duty; Q1, Q1b, Q3), the library input rule, R1 to R7, the production-artifact rule, CLI-SGN-31 and the Zether rule, each in full |
| `docs/research/pqz-threshold-decrypt-prove.md` | §12.5: a link to this spec's §3; the quorum question stays open |

## 7. Owner decisions (2026-11-06 and 2026-11-09; formerly the open questions)

1. **Q1 — decided (owner 2026-11-06): R1's trusted source** is the holder's own node, a node the holder configured
   explicitly, or a verifying light client in the reading layer. **Changed (owner 2026-11-08, ARCH-POS-15):** several sources
   allowed (failover by default, a strict majority under the agreement option); named, default (the release's reviewed list)
   and discovered endpoints allowed, a discovered one feeding a decryption only under the agreement option with three or more.
2. **Q1b — decided (owner 2026-11-06): the residual of the chosen source** (a light client trusts the chain's sealing keys;
   another operator's node trusts that operator) is the holder's chosen trust. It is stated in `zether.md` and
   `pq-zero-knowledge.md` (T19b).
3. **Q2 — recorded as moot for `ua-rs` (owner 2026-11-06).** `ua-rs` has no chain adapters, so nothing in it blocks Zether on
   Soroban, Algorand or Solana; a reading layer there must meet R1 (a trusted node of that family), and `ua-rs` needs that
   family's Zether layout parser.
4. **Q3 — decided (owner 2026-11-06): `hazmat`** lands with the next pqz-core change; the four-set full gate is waived for this
   `cfg`-only change and replaced by a build at all four sets plus `kat`.

5. **C-PP-6 — decided (owner 2026-11-09):** a keyless check now (`checkProven`, a C function without a handle) and the
   documented fallback; the MPC partial decryption waits for the threshold protocol (§4.14.8).
6. **The reference reader — decided (owner 2026-11-09):** `pqz-read --command balanceProven` is path (B)'s reference reading
   layer (§4.14.11).
7. **Vector rows — decided (owner 2026-11-09):** the rows for a NONE debit's header and a relayed debit's binding are a
   test-only follow-up of T62 on `ua-mtx-merge` (T62a, after T77), taken at the next sync (§4.14.12).
8. **Releases — decided (owner 2026-11-09):** release 3h only; the readers refuse an earlier token by a named error; the pre-3h
   `memoHash` formulas move to `legacy/` (§4.2 R5, §4.10, §4.14.1).
9. **Review — decided (owner 2026-11-09):** a full Fable review of §4.14 (design, security, crypto) before any code; Codex only
   on the owner's word.
10. **The quorum's key — decided (owner 2026-11-09, on the Fable review's P1-1):** a quorum member's `pk` comes from its own DKG
    record, as a named `pk` field of `scaas_ua_pqz_check`; the source names no key of the quorum (§4.14.8).
11. **A failed credit — decided (owner 2026-11-09, P3-3):** `provenAdd` refuses that one credit and keeps the session; no
    fail-closed close (every check is keyless or under `K_v`; closing buys no key safety) (§4.14.2).
12. **A migration credit without its old seed — decided (owner 2026-11-09, P3-2):** it falls back to verifying its P like any
    credit (§4.14.3, §4.14.4).

No owner question remains open in this spec.

## 8. Effort

Plan tasks T15c2, T19c, T15e, T14b, T15g–T15k and T19b remain (T15b and T15c are being finished; T15d and T15f were dropped
by the owner rulings): **23.5–31.5 agent-days**, critical path (T15c2 ∥ T19c) → T15e → T15g → T15i ≈ 12.5–16.5 days (details in
the plan). Not counted: the reading layer's checks (R1 to R7) in the wallet layer and the apps, outside this repository.
**Path (B) (2026-11-09, plan T20d):** 18–22 agent-days (the proof-path spec's C-PP items 14–16.5, this delta and its review
fixes 1–1.5, 3h's formats in every client 1.5–2, `pqz-read --command balanceProven` 1–1.5; +0.5 after the Fable review: one
NONE header shape per form, the `(M, auditorOn)` fit and the pairing in T20d4, the log decoded by the reader in T20d8 instead
of the facade in T20d3); critical path ≈ 11–13.5.

## 9. Review response (Fable and Codex, 2026-11-06 / 07)

All items accepted. Conflicts and choices: Codex C4 and Fable P2-2 are the same item (`openMemo` / disclosure of old entries:
named `fromUA`, `sendCounter`, `entryRef` recomputed), merged in §4.3. Codex C7 and Fable's mechanical gate (`cargo tree -e
features`) are one check, built in T15c2 and run again by T15i's gate. Fable P1-1's raw words replace the parsed word fields of
the previous revision: the explicit-parameters rule still holds (every word sits in a named field; only code, memos and proofs
are `bytes`), and one parser in the facade beats a parser in every reading layer. Fable P3-4 (`--ct`): the CLI accepts the
holder's sealed cache box or R1-fetched state, and raw `--ct` moves under `hazmat`, rather than only documenting the residual,
because a hand-typed ciphertext is exactly "a ciphertext chosen by someone else".
