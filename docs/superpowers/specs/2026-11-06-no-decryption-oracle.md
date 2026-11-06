# No decryption oracle: bringing the client libraries in line with ARCH-POS-13 — fix spec

**Status:** SPECIFIED, nothing built (2026-11-06); revised after the Fable review of the same day (findings P1-1 … P3-3, all
accepted by the controller: token and key binding, chain enrolment by a pinned table, the sealer residual stated, a stateless
genesis-signer light client, no vault change, a smaller first step). Fix spec for owner ruling
ARCH-POS-13 "Never a decryption oracle" (`docs/decisions.md` on branch `ua-mtx-merge`, not yet on this branch,
commit `62adb3d7`; also in `AGENTS.md`). The owner's words: **"NO oracle!"**: absolute, no exception, no opt-in. This spec
offers no option that keeps any oracle; where a design choice remains it recommends one and says why. Plan tasks: appended
to [`plans/2026-11-05-ua-rs-sign.md`](../plans/2026-11-05-ua-rs-sign.md) (section "ARCH-POS-13 rework"). Inputs: the
read-only code audit of decrypt entry points (2026-11-06, findings F1 to F9 below) and the research note
`docs/research/pqz-threshold-decrypt-prove.md` §12.1 / §12.5 (branch `ua-mtx-merge`). Everything here is **UNAUDITED**.
Zether and PQZ are separate schemes, modules and handles; each section names the one it is about.

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
| F1 | P1 | `clients/ua-rs/src/facade/pqz.rs` command `dec {ct, window}` (parse ~337, run ~641, `value` ~504); every binding through `scaas_ua_pqz_call` (`ua-c` `lib.rs` ~2426, `ua-py`, `ua-go`, `ua-cs`, `ua-cxx`, `ua-dart-frb`) | any well-formed caller ciphertext → all 16 digits: the rounding oracle | §4.6, §4.7 |
| F2 | P1 | same file, `proveDisclose {stmt}` (~392, ~673) | the whole op 5 statement is the caller's; proof or refusal is a 1-bit oracle (≤ 2n queries) | §4.7 |
| F3 | P2 | same file, `proveTransfer`, `proveBurn`, `proveRefresh`, `proveTransferMulti` (~348–372, ~655–667, `rest` ~709) | decrypt the caller's `T`; the success bit reaches a malicious RPC or relayer | §4.6 |
| F4 | P3 | `pqz-core`: C `pqz.h` ~156–193, `pqz_keys.c` ~229–252; Rust `pqzl/rust/src/lib.rs` ~389–406 (`decrypt_raw`); `pqz-core/ffi/src/pqzl/{rust,c}.rs` (`dec`, `dec_win`) | return digits and noise / raw `w` to any in-process caller; [M] T6 says "noise never leaves `pqz_dec`" (`pq-zero-knowledge.md` ~2435) | §4.9 |
| F5 | P2 | [M] `docs/clients/signers-clientkeys.md` ~81–88 (CLI-SGN-31), [M] `docs/research/07-custody-providers.md` ~111 (PLANNED) | `zk_mul_by_x(points, ctx)` is a static-DH oracle that bypasses `ChainWitness` | §4.10 |
| F6 | P3 | `clients/zether-prover/src/api.rs` ~685–708 (`decrypt`, `decryptPending`, `checkBalance`); `clients/ua-rs/src/facade/zether.rs` | caller `(C, D)`: no key recovery, but plaintext and timing leak; variable-time `D·x` on an attacker's `D` | §4.8 |
| F7 | P3 | `zether-prover` binary `zether-read-balance --rpc` | decrypts what an RPC hands it | §4.8 |
| F8 | P3 | `openMemo` in both facades (PQZ: `pqz_ffi::memo::open`, a keystream without MAC) | a crafted memo with a real memo's header and salt returns the keystream, which opens the real memo (no key recovery) | §4.7, §4.8 |
| F9 | — | docs: PQZ CTR-PQZ-03 / -14 / T6; Zether `zether.md` says nothing; NODE-LANE-03 and CLI-SGN-31 cover only the server oracle; `docs/clients/ua-libraries.md` says nothing | the rule is not stated where implementers read | §6 |
| F10 | P2 | `pqz.rs` `multi` (~803): `memoHash = keccak(memo)` always | the contract fills `memoHash` only in HASH mode (`PqzCore._parseMulti`, ~430) and leaves 0 in BUNDLE; an op 7 BUNDLE proof from the facade is refused | §4.11 |

F10 is not an oracle; it is a correctness bug in the same facade, found by the T16a agent (2026-11-06), fixed with this rework.

## 3. The central question: how does the library know a ciphertext is chain state?

| Construction | Removes the oracle? | Why / why not |
|---|---|---|
| **(A) Proven state**: the library assembles every ciphertext itself from contract state it has verified against a block header its own light client accepted (EIP-1186 `eth_getProof` on EVM) | **yes**, up to the chain's sealers (§4.13) | the only check that tells "on chain" from "forged" without re-executing the chain; it uses public data only, so a refusal says nothing about `s` or the plaintext; it works from state alone (CTR-PQZ-07 keeps holding) |
| (B) Well-formedness certificates: verify the proof that admitted each ciphertext | no (not buildable) | a PQZ credit's proof is the sender's debit proof, whose statement contains the **sender's** `T` at that block (`Debit.t`), which is not in state (materialised `acc` is overwritten, window slots are deleted); proofs live in calldata (history expiry); an op 4 `SENDER_S` proof would certify a credit without `T` but needs the sender's cooperation, and a keeper's rollover of an uncertified credit would strand the account. Zether has the same shape (the transfer statement carries the sender's account ciphertext). Even where available, a forged but well-formed composition (an RPC adds an honest encryption of a known value to the real `T`) still leaks the real balance through the holder's later actions |
| (C) Containment: results never leave the device, failures never signalled | no | a debit proof leaves the device by design; whether one was produced is the oracle bit (fact 3) |
| (D) Noise-bound or digit-range filter before use | no | the refusal is the oracle: the same 8·K queries, moved to the filter's edge |
| (E) Noise flooding (add random noise before rounding) | no | the attacker scales `u` (`u = c·unit`), so the `s`-dependent term outgrows any flooding that keeps honest decryption correct (budget at `n2304-kmax4096`: worst-case noise ≈ 2^25.7 against `Δ/2` ≈ 2^26.8) |
| (F) Several RPCs must agree | no | it trusts their operators; not by construction |
| (G) The holder names a trusted RPC | no | "no opt-in"; an RPC is an outside source in the rule's own words |

**Chosen: (A) proven state.** It is the only construction found that removes the oracle by construction, keeps "restore
from state alone", and needs no contract change. Its cost is a verifier inside `ua-rs` (§4.2, §4.4), and it inherits the chain's own trust in its sealers (§4.13, Q1b), which is why fetching stays
outside the library and only verification moves in. The owner judged a similar restriction for MPC quorum members "not
reasonable" (research §12.5, 2026-11-06); this spec applies it only to the key holder's own library, where no other
construction works; owner question Q1 asks to confirm it. §12.5's quorum question is not reopened here.

## 4. Design

### 4.1 The input rule (one rule, every scheme, every chain)

> **A facade decrypts only a ciphertext it has assembled itself from proven state of a catalogued token on an enrolled
> chain, for a key the registry holds for that account.** No decrypt-path command takes ciphertext bytes, a statement or
> a `T` from its caller. It takes a **locator** in named, typed fields (`chainUid`, `token`, `ua`, and `entryRef` with `leg`
> where an entry is meant) and **evidence** (headers and state proofs as the chain's RPC returns them). The facade checks,
> in this order and before the key is touched: the chain is in the library's pinned table (§4.2); the head is final under
> that chain's rule; the token is catalogued by the chain's pinned factory as a PQZ (or Zether) kind; the registry the token
> names holds, for `ua`, the key of the handle in use; then it reads the state words by the contract's pinned storage
> layout and assembles the ciphertext exactly as the contract does. Every refusal before the key is used is a function of
> public inputs only, and all of them return the same status (`StateProof`), with no detail.

What may still fail after the key is used is a fact about the holder's own genuine data (a balance below the debit), and it
goes to the holder's caller only. A genuine state never fails to decrypt (fact 1), so no failure after the key is a
decryption failure.

### 4.2 Where the trust comes from: a pinned chain table and the chain's own sealers

- **Enrolment: a pinned table, never a request field.** `ua-rs` carries a generated table `chain-anchors` (one row per
  chain: `chainUid`, `chainId`, engine, the genesis signer set, Clique `period` and `epoch`, and the `OpenFactory` address),
  built from `smartcontracts/evm/chain-uids.json` (which already pins each genesis hash, NET-ALL-22) and the deployment
  record of the factory. A `chainUid` that is not in the table is `StateProof`. A decrypt request never creates trust, and
  there is no holder-side `enrollChain`: a phished holder could enrol an attacker's factory, and a table changes only with
  a library release (a customer chain gets its row the same way). Recommended over a holder-only `enrollChain` for that
  reason; a row is generated, never hand-edited.
- **Head: stateless, genesis signers, majority of descendants** (EVM Clique, the SCaaS testnet). The caller gives the head
  header and the next headers. The library checks: each header's parent hash links; each seal recovers to a signer of the
  **genesis set** (from the pinned row; the genesis header's `extraData` hashes into `chainUid`, so the row's set is checked
  once at generation); the headers carry `floor(N/2) + 1` distinct genesis signers (the head counts), which is Clique's
  "a majority has built on it"; and the latest epoch checkpoint at or below the head (number `head − head mod epoch`, from
  the pinned `epoch`) is given, sealed by a genesis signer, and lists exactly the genesis set in its `extraData`. Any other
  set, a vote in a header, or a missing checkpoint is `StateProof`: no voting, no epoch walk, no chain from genesis. So a
  head costs `k + 1` headers. **No head is stored** (staleness is liveness, not safety; no vault or backup change). Rotation
  of signers and a monotonic stored head are built only when a chain that rotates its signers is targeted.
- **Other engines and families.** QBFT / IBFT commit seals, Ethereum PoS sync committee, AuRa, and non-EVM families are
  adapters added when a PQZ or Zether token is used there; until a family's adapter exists, decryption on it fails closed
  (`StateProof`). Which non-EVM families can have one is task T15f's report (owner question Q2).
- **State proofs (EVM).** EIP-1186 against the head's `stateRoot`: the account proofs of the factory, the token, the
  registry and each SSTORE2 pointer read (blob, key), each pointer's `codeHash` with `keccak256(code)` compared to it, and
  storage proofs of the slots read. Verifier: `alloy-rlp` (already a dependency, T5) plus a Merkle-Patricia proof check;
  every decoder bounded by length **and** depth (same class as the node's rule).
- **Operator note.** All proofs of one request are against one block's `stateRoot`. A pruning node (Nethermind's default)
  serves `eth_getProof` only for recent blocks, so callers ask at a recent head; an archive node is not needed. This goes
  into the node's ops doc (T19b).

```mermaid
flowchart LR
  APP[caller: fetches bytes from any RPC or indexer] -->|headers, eth_getProof, code| V
  subgraph ua-rs [ua-rs, no I/O]
    T[(pinned chain-anchors)] --> V
    V[chain enrolled, head final,<br/>token catalogued, key registered,<br/>MPT proofs, codeHash] -->|state words| A[assemble ciphertext<br/>as the contract does]
    A --> K[key handle: decrypt / prove]
    V -. any failure: StateProof, public data only .-> R[refusal]
  end
  K -->|value or proof| APP
```

### 4.3 Evidence in named fields

Every decrypt-path command takes `{chainUid, token, ua, evidence}` and, where an entry is meant, `entryRef` and `leg`
(explicit parameters: no packed blob of several fields). `evidence` is `{headers: [bytes], accounts: [{address,
accountProof: [bytes], storageProofs: [{slot, value, proof: [bytes]}]}], codes: [{address, code}]}`, the shapes
`eth_getBlockByNumber` (raw header), `eth_getProof` and `eth_getCode` return. A proof node is a crypto object, so each stays
`bytes`. `need(cmd, locator, partial)` lists what to fetch (the head's checkpoint number, accounts, slots of the pinned
layouts, pointer addresses once their slots are known); it is in the C ABI too (T15g). Missing or extra items are refused
alike.

### 4.4 Token and key binding (both schemes)

Proven storage of a contract that only copies the layout is not PQZ state. Before reading the token:

- **Catalogued token.** A storage proof of the pinned factory's `_info[token]` (`{creator, kind, version, exists}`,
  `OpenFactory`) with `exists` set and `kind` a PQZ kind (`NORMAL_PQZ` / `WRAPPED_PQZ`) for the PQZ facade, a Zether kind
  for the Zether facade. A catalogued implementation is trusted code, so the token's own proven words (its `registry`, its
  auditor) can be read next.
- **Registered key, every command.** A storage proof of the registry's PQZ key record for `ua` (`pqzKeyOf(ua)`: pointer,
  `proven`) and the pointer's code; `keccak256(GROUP("pqz-mlwe") ‖ pk)` of the stored key must equal the key hash of the
  handle's `pk`, and `proven` must be set. For `auditRead` and `AUDITOR` disclosure the account is the token's `auditorUA`.
  Zether: the account's registered `Y` equals the handle's. A mismatch is `StateProof`, before the key is used.
- **What stays a caller input.** `pkT` and `pkA` of a debit (and the legs' keys of op 7) stay caller fields: encryption to a
  public key is public, and a wrong recipient or auditor key is refused on chain by `PqzCore._creditKey` (and the
  auditor-key check), so it can only waste the holder's own transaction.

### 4.5 PQZ: state words to ciphertexts (layout of `pq-zero-knowledge.md` §7.1, pinned in `test/v2/layout/`)

- `AccountState` from its ERC-7201 slots (`pendingCount`, `rolled`, `floor`, `cleared`, `acc` word, `accUnits`, `flags`,
  `sendCounter`, `accHash`).
- `acc`: a reference → the blob's `u_0 ‖ v_f` at its offsets (blob code proven by `codeHash`); materialised (`flags & 1`)
  → the packed stream given by the caller and checked against the **proven** `accHash` slot, as the contract checks its
  own `accHint` (one storage proof instead of `ACC_WORDS` of them); never debited: `Trivial(0)`.
- Pending `[rolled, p)`: each slot word proven; a credit → `u ‖ v` at `uOff` / `vOff` of its proven blob; a TRIVIAL entry
  → `Trivial(digits(amount))` built here, like the contract.
- `T = acc ± Σ pending[window) + Trivial(shieldIn)` exactly as `PqzCore` builds it, `unitsOf(T) ≤ K_MAX` checked. **The
  facade chooses `p`** by CTR-PQZ-06 (`pendingCount`, or the largest `p` the inline window allows), so `p` leaves the
  request.
- An entry `(entryRef, leg)`: `entryPtr[entryRef]` proven → blob → the leg's `u_g`, `v_j` (or the auditor copy `v_{a,j}` and
  its window `w`), `memos[entryRef]` proven where a memo is read.
- Vectors: a forge writer over the built token dumps state snapshots (slot words, blob codes) with the contract's own `T`
  and entry ciphertexts (from its statement views); the facade must reproduce them byte for byte. The contract is the
  authority; no hand-written expected bytes.

### 4.6 PQZ: what replaces `dec` and the debit inputs

| Old (removed from release builds) | New | Output, to whom |
|---|---|---|
| `dec {ct, window}` | `balance {chainUid, token, ua, evidence}` | `{value, p, sendCounter, block}` to the holder's caller: its own balance |
| `proveTransfer / proveBurn / proveRefresh / proveTransferMulti` with `T`, `p` | the same commands with the locator and evidence in place of `T` and `p`; `pkT`, `pkA`, legs stay (§4.4) | `{stmt, proof}`; a refusal after the key (balance below amount + fee) goes to the holder's caller only |
| (none) | `auditRead {chainUid, token, entryRef, leg, evidence}` on the **auditor's** key handle (one auditor key per token) | `{amount}` of the audited copy at its window, to the auditor (the key holder) |

The old commands stay only under the test feature `vectors` (the vector files feed `T` and `ct`), never in a release
build, with a `compile_fail` doc test as today's `vectors_call` (backup, not delete). The pqz-ffi `dec` / `dec_win` calls
move into the one private function that decrypts an assembled ciphertext; `value()` keeps wiping the noise.

### 4.7 PQZ: disclosure and memo

- `proveDisclose {chainUid, token, entryRef, leg, kind, evidence}` with `kind ∈ {RECEIVER_X, AUDITOR}`: the facade reads the
  leg from proven state (§4.5) with the key binding of §4.4, decrypts, builds the op 5 statement itself (layout of
  CTR-PQZ-14: `chainId`, `chainUid`, `token`, `registry`, `entryRef`, `amount`, `kind + 256·w`, `pk`, `u`, `v`) and proves.
  The output (statement with the amount, and the proof) goes to the viewer the holder names; it discloses one genuine
  entry, which is what disclosure is for. The audit's suggested check against `transferCiphertextHash` is subsumed: the
  blob itself is proven.
- `proveDiscloseSender` (op 4) decrypts nothing: it re-derives `r, e1, e2_t` from `seed32` and compares with the statement
  (a MAC-like equality: an attacker passes only with the genuine bytes). It stays as built; it is not an oracle.
- `openMemo {chainUid, token, entryRef, evidence}`: the memo bytes from proven `memos[entryRef]` and the header words from
  the proven entry, never from the caller. This closes F8's keystream reuse: the facade opens only the memo that is in state
  for that header and salt.

### 4.8 Zether (separate module, separate handle)

- The same input rule, with §4.2 and §4.4: `decrypt`, `decryptPending`, `checkBalance` and every `acc` / `balance` /
  `(C, D)` input of `proveTransfer`, `proveTransferMulti`, `proveBurn`, `recoverTransfer`, `openDisclosure`, `openMemo` are
  replaced by locators and evidence, read by the Zether token's pinned layout on that family. The balance hint stays a
  cache of the holder's own value, checked against the proven account (the `checkBalance` use).
- `zether-prover`'s `api` keeps the raw commands behind a new feature `hazmat` (off by default and in every wasm build);
  `ua-rs` calls the internal functions only with assembled ciphertexts. `clientkeys/src/zether.js` comments that name the
  prover wasm's `decrypt` / `decryptPending` change with it (no JS byte format changes).
- `D·x` in decrypt and check runs through `scaas_ct::secret_mul` (the owner's 2026-11-05 answer planned moving
  zether-prover's own secret multiplications onto `scaas-ct` "after this round"; ARCH-POS-13 makes the decrypt path's
  multiplication part of this rework).
- `zether-read-balance --rpc` refuses (`StateProof`) until it reads through the same verifier; then it takes evidence like
  the facade. Its no-RPC use on a local backup is unchanged.
- Families: Zether runs on non-EVM families too. Each family's adapter is a task of its own; until it exists, Zether
  decryption there fails closed (Q2). That includes `zether-soroban` ([NET-SOR-25](../../networks/soroban.md#NET-SOR-25),
  Part Z) and Zether on Algorand and Solana, so T15f's report comes before Part Z is built.

### 4.9 pqz-core: the core decrypt functions (F4)

`pqzl` `decrypt_raw`, the C `pqz_dec` family and pqz-ffi's `dec` / `dec_win` return noise or raw `w` to any in-process
caller. They are not reachable from outside today (pqz-ffi's own C ABI exports only `pqz_precompile` and
`pqz_max_input`; the C core is the oracle library, not production; the Rust callers are pqz-ffi's self-test, the vector
generator, the `pqzl` tests and the facade). A feature `hazmat` around those exports, enabled by the self-test, `vectors`,
the vector generator and `ua-rs`, changes no transcript, relation or byte. It is **defence in depth only**: Cargo unifies
features, so every binary built with `ua-rs` and `pqz` has `dec` compiled in; what keeps it unreachable is the facade's
command set (§4.1), not the feature. **Gate:** AGENTS.md's full-gate rule names `pqzl` and `ffi/src`. Recommended: land it
with the next core change, and ask the owner to waive the four-set full gate for a `cfg`-only change in favour of a build
at all four sets plus `kat` (Q3). T6's wording is fixed now (§6).

### 4.10 Server key oracle (CLI-SGN-31, PLANNED; F5)

The enclave interface loses `zk_mul_by_x(points, ctx)` (a static-DH oracle on `x` for any caller point),
`zk_nonce_commit` / `zk_response` as separate calls (a response to a caller-chosen challenge is a proof or signature
oracle) and the raw `elgamal_decrypt(C, D, ChainWitness)`. **Recommended: whole operations inside the enclave** (group B'
only: balance, transfer, burn, disclosure), each taking a locator and evidence verified in the enclave by the same
verifier (§4.2, §4.4); `ChainWitness` becomes that evidence. Binding every caller point to chain state instead was
rejected: a proof's internal points (commitments, transcript-derived bases) are not state, so it would leave the
multiplications that matter unbound. Results go to the tenant (the key holder) over its channel, never to the relayer or
the broker's logs. The planned threshold auditor key (CTR-ZTH-41, `y_audit` 3-of-5 in CLI-SGN-31) is a quorum decryption:
ARCH-POS-13 covers it, and it stays blocked on the same open question as the PQZ quorum (research §12.5), not settled here.

### 4.11 Op 7 `memoHash` per mode (F10; owner decision 2026-11-06)

`PqzCore` on `ua-mtx-merge`: `memo = mode == HASH ? 2 + 40·m : 0` (~408) and `if (memo != 0) o.memoHash =
keccak256(abi.encodePacked(t.salt, t.sealedMemo))` (~430); op 1 the same at ~286 / ~304 with `SEALED = 41`. The facade's
memo is `salt(16) ‖ sealed` (`pqz_ffi::memo::seal`), so `keccak(memo)` equals the HASH formula, but BUNDLE needs 0.
**Decided (owner 2026-11-06):** the facade takes the memo mode as an explicit named request field, `mode` = `"HASH"` or
`"BUNDLE"` (no default), for op 7 now and op 1 once T36a lands, and computes `memoHash` exactly as the contract does per
mode: HASH → `keccak256(salt ‖ sealedMemo)` and the memo returned; BUNDLE → `memoHash = 0` and no memo returned. The token's
`disclosureMode` decides which a caller may use (COMPACT refuses BUNDLE on chain, ~399); the facade does not guess it. A
test fails on the old behaviour: a BUNDLE op 7 statement's `H_MEMO_HASH` word is 0 and equals the forge-built statement for
the same inputs. Op 1 waits for T36a (the contract still refuses a 58-byte op 1 memo: `PqzCore.SEALED` is 41).

### 4.12 What does not change

`enc` (public), `proveRegister`, `proveKeyRecord`, `proveDiscloseSender`, the balance-cache boxes, the vault and backup
formats, the KEM `open` (ML-KEM is CCA-secure; `ua-rs-sign` spec §6.2's handle rule stays), no contract, node or
byte-format change (the storage layouts are read, not changed). `ua-rs` stays I/O-free: the caller fetches; `ua-rs`
verifies.

### 4.13 Residuals (stated plainly)

- **Sealers (the one residual that is an oracle).** A light client trusts sealing keys. A sealer, or anyone holding a
  leaked sealing key, can seal a header over a fabricated `stateRoot` holding crafted ciphertexts; the library accepts it
  as final if enough genesis signers' seals are on it (one on a single-signer chain, [NET-EVM-04](../../networks/evm.md#NET-EVM-04)),
  and the holders' spend attempts on that chain become the oracle of §1, against every holder who reads through it. Only
  re-executing the chain removes this. This spec treats it as the chain's own trust model (the same keys already order and
  finalise every write) and asks the owner to accept it (Q1b). It is written into `zether.md` and `pq-zero-knowledge.md`
  with a link to NET-EVM-04 (T19b).
- A stale head shows an old balance; a debit over it is refused on chain (T8 retry), revealing nothing about `s`.
- A genuine state is composed partly by senders (credits, decoys); its decryption is the holder's own data and reveals
  nothing about `s` (fact 1).
- Timing after the key is used: BSGS (Zether) and the PQZ prover take time that depends on the holder's own genuine value.
  That is a privacy residual of the holder's balance to a local observer, not a key leak, and not about any ciphertext an
  outsider chose.

## 5. Tests that must be able to fail

- **The oracle harness as a test** (`clients/ua-rs/tests/no_oracle.rs`): the 8·K crafted queries of research §12.1 at the
  default set, through every public command and every binding's call path. Positive control: the same queries through the
  `vectors`-only raw `dec` recover `s` exactly (the harness can fail). Negative: through release commands, every query is
  refused with one status before the key is touched (a `vectors` counter of key uses stays 0) and the refusal is identical
  for every `off`.
- Evidence negatives, each `StateProof` before any key use: a `chainUid` not in the table; a token the factory does not
  catalogue (a layout-compatible copy deployed in the test); a token of the other scheme's kind; a registry key of another
  account or `proven = false`; a flipped byte in any proof node; a slot of another account; code not matching `codeHash`;
  a header sealed by a non-signer; one signer short of the majority; a checkpoint listing another set; a materialised `acc`
  stream that does not hash to `accHash`.
- **Sealer positive control (§4.13):** a header sealed by the test chain's genesis signer over a crafted `stateRoot` whose
  account holds a crafted ciphertext **is accepted**: the test shows the residual exists and that the library's trust is the
  sealers', nothing more.
- Mutants (each must turn a test red): the caller's `T` accepted again; `p` taken from the request; the catalogue check
  skipped; the key-hash comparison skipped; the `accHash` check skipped; the majority count off by one; `codeHash` not
  compared; F10's `memoHash` always set.
- Byte equality with the contract: the forge state snapshots of §4.5 at the default set and one other set.

## 6. Doc changes

On `ua-rs-sign` (this branch): this spec; `ua-rs-sign` spec §10.1 / §10.2 tables (decrypt rows → proven state);
`docs/clients/ua-libraries.md` gets a `CLI-UAL` rule for §4.1 with its `decisions.md` entry at build (T19).

On `ua-mtx-merge` (listed as task T19b; not edited from here):

| File | Change |
|---|---|
| `docs/contracts/pq-zero-knowledge.md` | T6: "noise never leaves `pqz_dec`" → decryption runs only on proven state inside the holder's library, the core's raw decrypt is `hazmat`; CTR-PQZ-14 and §4.2's "`Dec` is used by the owner only" point at ARCH-POS-13; §7.8 "Restore from state alone" → from proven state; the sealer residual of §4.13 with a link to NET-EVM-04 |
| `docs/contracts/zether.md` | a rule (new id) pointing at ARCH-POS-13: Zether decryption only on proven state; `zether-read-balance` (line ~252) reads through it; the sealer residual with a link to NET-EVM-04; CTR-ZTH-41's threshold auditor key blocked on §12.5's question |
| `docs/networks/soroban.md` | NET-SOR-25: Zether on Soroban is read through `ua-rs` only once a Soroban state adapter exists (Q2) |
| `docs/clients/signers-clientkeys.md` | CLI-SGN-31: group B rewritten per §4.10 (no `zk_mul_by_x`, no separate nonce / response calls, no raw `elgamal_decrypt`; whole operations in the enclave; `ChainWitness` = verified evidence); the `y_audit` note; the clientkeys `zether.js` wording |
| `docs/research/07-custody-providers.md` | a dated note at ~111 that the group B sketch is superseded by ARCH-POS-13 / CLI-SGN-31 (research stays background) |
| `docs/node/submit-lanes.md`, `docs/node/gateway.md`, `docs/node/ops.md` | NODE-LANE-03: the node never decrypts and serves evidence as plain RPC data, untrusted by design (no new guarantee); ops: `eth_getProof` on a pruning node serves recent blocks only (§4.2) |
| `docs/decisions.md` | ARCH-POS-13's source: the audit done, this spec; entries for the `CLI-UAL` input rule, the pinned chain table, the sealer residual, the CLI-SGN-31 change and the Zether rule, each in full |
| `docs/research/pqz-threshold-decrypt-prove.md` | §12.5: a link to this spec's §3 (single holder); the quorum question stays open as written |

## 7. Owner questions

1. **Q1 — proven state for the holder's library.** Every decrypt path in `ua-rs` (and the enclave of §4.10) assembles its
   ciphertexts from state of a catalogued token on a chain of the pinned table, under a head its own light client accepted.
   **Recommended: yes**, (B) to (G) in §3 do not remove the oracle. It is close to the restriction judged not reasonable for
   MPC members (§12.5) and is proposed only for the key holder's own library.
2. **Q1b — the sealer residual.** A sealer or a leaked sealing key can fabricate state the library accepts (§4.13).
   **Recommended: accept it as the chain's own trust model**; the only alternative is re-executing the chain in the wallet.
3. **Q2 — families without verifiable state.** Zether decryption fails closed where a family has no checkable finality or no
   proof of contract state (expected, T15f confirms: Solana, Stellar / Soroban, Algorand application state, possibly
   Hedera). This blocks `zether-soroban` (NET-SOR-25, Part Z) and Zether on Algorand and Solana through `ua-rs` until an
   adapter exists; T15f runs before Part Z. **Recommended: accept** (the rule has no exception). PQZ is not affected.
4. **Q3 — pqz-core `hazmat`.** **Recommended: land it with the next core change and waive the four-set full gate for this
   `cfg`-only change** (a build at all four sets plus `kat` instead); it is defence in depth only (§4.9).

## 8. Effort

Plan tasks T15b–T15j, T14b and T19b: **25.5–35 agent-days** (T15h without a full gate run), critical path T15c → T15d →
T15e → T15g → T15i ≈ 16–21 days (details and sizes in the plan). Not counted: the fetch side in the consumers
(`scaas-wallet`, `pqchat-core`: calling `need()` and an RPC for headers, proofs and code), outside this repository.
