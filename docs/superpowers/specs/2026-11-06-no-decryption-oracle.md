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
| R5 | **Catalogued token.** The token is catalogued by that chain's `OpenFactory` (its configured address) with a PQZ kind for the PQZ facade, a Zether kind for the Zether facade. | `_info[token]` read as storage: `exists` set and `kind` in the facade's kinds |
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

A later round may let `ua-rs` check state proofs itself again (the owner ruled it out of this rework). So that nothing here
blocks it: requests carry raw slot words by index (§4.3), which a proof path can verify unchanged; binding tests assert that a
command is **in** `COMMANDS`, not that `COMMANDS` equals a list; a proof verifier may be compiled into `ua-rs` unexposed later
without an API change; the HKDF label `PQZ/owntag/v1` is reserved for an own-output tag; pending entries are selected by
`[rolled, p)` only; state vectors are versioned by contract commit.

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

## 6. Doc changes

On `ua-rs-sign` (task T15j): `ua-rs-sign` spec §10.1 / §10.2 (decrypt rows → location and raw words; chain reading and its
checks stay with the reading layer); `docs/clients/ua-libraries.md`: a rule group for the library duties (§4.3, §4.8) and one
for "the wallet layer that reads the chain" (R1 to R7 with their assertions; current docs name no consumer), with their
`decisions.md` entries at build (T19).

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

## 7. Owner decisions (2026-11-06; formerly the open questions)

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

No owner question remains open in this spec.

## 8. Effort

Plan tasks T15c2, T19c, T15e, T14b, T15g–T15k and T19b remain (T15b and T15c are being finished; T15d and T15f were dropped
by the owner rulings): **23.5–31.5 agent-days**, critical path (T15c2 ∥ T19c) → T15e → T15g → T15i ≈ 12.5–16.5 days (details in
the plan). Not counted: the reading layer's checks (R1 to R7) in the wallet layer and the apps, outside this repository.

## 9. Review response (Fable and Codex, 2026-11-06 / 07)

All items accepted. Conflicts and choices: Codex C4 and Fable P2-2 are the same item (`openMemo` / disclosure of old entries:
named `fromUA`, `sendCounter`, `entryRef` recomputed), merged in §4.3. Codex C7 and Fable's mechanical gate (`cargo tree -e
features`) are one check, built in T15c2 and run again by T15i's gate. Fable P1-1's raw words replace the parsed word fields of
the previous revision: the explicit-parameters rule still holds (every word sits in a named field; only code, memos and proofs
are `bytes`), and one parser in the facade beats a parser in every reading layer. Fable P3-4 (`--ct`): the CLI accepts the
holder's sealed cache box or R1-fetched state, and raw `--ct` moves under `hazmat`, rather than only documenting the residual,
because a hand-typed ciphertext is exactly "a ciphertext chosen by someone else".
