# No decryption oracle: bringing the client libraries in line with ARCH-POS-13 — fix spec

**Status:** SPECIFIED, nothing built (2026-11-06). Revised twice the same day: after the Fable review (P1-1 … P3-3, accepted by
the controller), then by **owner rulings 2026-11-06**: `ua-rs` contains no light client and no chain-state verifier; the check
that words are real chain state belongs to the layer that reads the chain (the wallet layer and the app, as `ua-rs-sign` spec
§10.2 already places chain reading); `ua-rs` keeps the library duties of §4.3. The owner then decided Q1, Q1b and Q3 as
recommended and recorded Q2 as moot for `ua-rs` (2026-11-06, §7). Fix spec for owner ruling ARCH-POS-13 "Never a
decryption oracle" (`docs/decisions.md` on branch `ua-mtx-merge`, not yet on this branch, commit `62adb3d7`; also in
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
| F1 | P1 | `clients/ua-rs/src/facade/pqz.rs` command `dec {ct, window}` (parse ~337, run ~641, `value` ~504); every binding through `scaas_ua_pqz_call` (`ua-c` `lib.rs` ~2426, `ua-py`, `ua-go`, `ua-cs`, `ua-cxx`, `ua-dart-frb`) | any well-formed caller ciphertext → all 16 digits: the rounding oracle | §4.3, §4.5 |
| F2 | P1 | same file, `proveDisclose {stmt}` (~392, ~673) | the whole op 5 statement is the caller's; proof or refusal is a 1-bit oracle (≤ 2n queries) | §4.6 |
| F3 | P2 | same file, `proveTransfer`, `proveBurn`, `proveRefresh`, `proveTransferMulti` (~348–372, ~655–667, `rest` ~709) | decrypt the caller's `T`; the success bit reaches a malicious RPC or relayer | §4.5 |
| F4 | P3 | `pqz-core`: C `pqz.h` ~156–193, `pqz_keys.c` ~229–252; Rust `pqzl/rust/src/lib.rs` ~389–406 (`decrypt_raw`); `pqz-core/ffi/src/pqzl/{rust,c}.rs` (`dec`, `dec_win`) | return digits and noise / raw `w` to any in-process caller; [M] T6 says "noise never leaves `pqz_dec`" (`pq-zero-knowledge.md` ~2435) | §4.8 |
| F5 | P2 | [M] `docs/clients/signers-clientkeys.md` ~81–88 (CLI-SGN-31), [M] `docs/research/07-custody-providers.md` ~111 (PLANNED) | `zk_mul_by_x(points, ctx)` is a static-DH oracle that bypasses `ChainWitness` | §4.9 |
| F6 | P3 | `clients/zether-prover/src/api.rs` ~685–708 (`decrypt`, `decryptPending`, `checkBalance`); `clients/ua-rs/src/facade/zether.rs` | caller `(C, D)`: no key recovery, but plaintext and timing leak; variable-time `D·x` on an attacker's `D` | §4.7 |
| F7 | P3 | `zether-prover` binary `zether-read-balance --rpc` | decrypts what an RPC hands it | §4.7 |
| F8 | P3 | `openMemo` in both facades (PQZ: `pqz_ffi::memo::open`, a keystream without MAC) | a crafted memo with a real memo's header and salt returns the keystream, which opens the real memo (no key recovery) | §4.6, §4.7 |
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
| The layer that reads the chain (wallet layer, app; outside this repository) | reads from a source the holder trusts; guarantees the words are chain state of a catalogued token on a known chain, for the account's registered key (R1 to R6, §4.2); never reports anything about a decryption to the source |
| `ua-rs` (facades and every binding) | no bare ciphertext, statement or `T` API in release builds; decrypting commands take named location fields and the supplied storage words; rebuilds `T`, `p`, entries and the op 5 statement exactly as the contract; one refusal status; nothing about a decryption returned to anyone but its caller (§4.3) |
| The enclave of CLI-SGN-31 (PLANNED) | as `ua-rs`, and whole operations only (§4.9); the layer feeding it bears R1 to R6 |

### 4.2 Requirements on the layer that reads the chain (normative; not `ua-rs` code)

These are rules for the wallet layer and the app. They bind them under ARCH-POS-13: reading the words from an untrusted RPC or
indexer and passing them to `ua-rs` is an oracle, and the fault is that layer's.

- **R1 Trusted source.** Words come from a source the holder trusts: the holder's own node, a node the holder configured
  explicitly, or a light client of the reading layer that verifies finality and state proofs. A default or discovered endpoint
  is not trusted for this (owner decision Q1, 2026-11-06, §7).
- **R2 Known chain.** The chain is the pair `(chainId, chain_uid)` of the holder's configuration (genesis hashes as pinned in
  `smartcontracts/evm/chain-uids.json`, [NET-ALL-22](../../networks/README.md#NET-ALL-22)), never the source's own answer.
- **R3 Catalogued token.** The token is catalogued by that chain's `OpenFactory` (its known address) with a PQZ kind for the
  PQZ facade, a Zether kind for the Zether facade (`_info[token]`: `exists`, `kind`). A contract that only copies the layout
  is not PQZ or Zether state.
- **R4 Registered key.** The registry the token names holds, for the account, the key of the handle in use: PQZ
  `pqzKeyOf(ua)` with `proven` set and `keccak256(GROUP("pqz-mlwe") ‖ pk)` equal to the handle's; for `auditRead` and
  `AUDITOR` disclosure the account is the token's `auditorUA`; Zether, the registered `Y` equal to the handle's.
- **R5 One block.** Every word of one request is from one block's state. (A pruning node such as Nethermind's default serves
  `eth_getProof` only for recent blocks; a reading layer that verifies proofs asks at a recent head.)
- **R6 Nothing back.** No result, failure, error code or result-dependent timing of a decryption goes back to the source; a
  result goes to the holder or a viewer the holder names.

`pkT`, `pkA` and the op 7 legs' keys stay plain caller fields: encryption to a public key is public, and a wrong recipient or
auditor key is refused on chain by `PqzCore._creditKey` (and the auditor-key check).

**What the source's trust costs (stated, §4.12):** the holder's own full node re-executes the chain, so it trusts nothing more
than the chain's rules. A light client trusts the chain's sealing keys: a sealer, or a leaked sealing key, can seal a header over
a fabricated `stateRoot` (one key on a single-signer chain, [NET-EVM-04](../../networks/evm.md#NET-EVM-04)), and then the
holders' spend attempts become the oracle of §1. A node operated by someone else trusts that operator.

### 4.3 `ua-rs`: location-bound words, rebuilt as the contract does

> **A facade decrypts only a ciphertext it rebuilt itself from storage words supplied for a named location.** No
> release-build command takes ciphertext bytes, a statement or a `T`. A decrypting command takes the location in named,
> typed fields (`chainUid`, `token`, `ua`, `block`, and `entryRef` with `leg`, `mode` where they apply) and the storage words
> the reading layer read at that block, in named fields. `ua-rs` parses them by the contract's pinned layout, checks that
> they are consistent with each other, rebuilds the ciphertext exactly as the contract does, and only then uses the key. Every
> refusal before the key is used returns one status (`Argument`, as every other facade refusal), with no detail.

The consistency checks are public: indexes `[rolled, p)` contiguous, offsets inside their blob, a materialised `acc` stream
hashing to the supplied `accHash`, `unitsOf(T) ≤ K_MAX`, the entry's leg inside the entry. They catch a careless caller; they
do not make words authentic (§4.12).

**Words, named fields (PQZ):** `account {pendingCount, rolled, floor, cleared, accBlob, accUOff, accVOff, accUnits, flags,
sendCounter, accHash}`, `accStream` (bytes, the materialised `acc`, when `flags & 1`), `pending [{index, blob, uOff, vOff,
block, amount}]` (the slot word's fields; `blob = 0` with `amount` for a TRIVIAL entry), `blobs [{address, code}]` (SSTORE2
code of each blob read), and for an entry `entryBlob {address, code}`, `memo` (bytes, `memos[entryRef]`). One crypto object
stays `bytes`: a blob's code, the `acc` stream, a memo. The list of what to read for a command and a location is documented
with the commands (no separate helper).

### 4.4 PQZ: words to ciphertexts (layout of `pq-zero-knowledge.md` §7.1, pinned in `test/v2/layout/`)

- `acc`: a reference → the blob's `u_0 ‖ v_f` at its offsets; materialised (`flags & 1`) → `accStream`, checked against
  `accHash` as the contract checks its own `accHint`; never debited → `Trivial(0)`.
- Pending `[rolled, p)`: a credit → `u ‖ v` at `uOff` / `vOff` of its blob; a TRIVIAL entry → `Trivial(digits(amount))`,
  built here like the contract.
- `T = acc ± Σ pending[window) + Trivial(shieldIn)` exactly as `PqzCore` builds it, `unitsOf(T) ≤ K_MAX`. **The facade
  chooses `p`** by CTR-PQZ-06 (`pendingCount`, or the largest `p` the inline window allows), so `p` leaves the request.
- An entry `(entryRef, leg)`: the blob → the leg's `u_g`, `v_j` (or the auditor copy `v_{a,j}` and its window `w`).
- Vectors: a forge writer over the built token dumps state snapshots (the words above) with the contract's own `T` and entry
  ciphertexts (from its statement views); the facade must reproduce them byte for byte. The contract is the authority.

### 4.5 PQZ: what replaces `dec` and the debit inputs

| Old (refused in release builds, T15c) | New | Output, to whom |
|---|---|---|
| `dec {ct, window}` | `balance {chainUid, token, ua, block, words}` | `{value, p, sendCounter}` to the caller (the holder's own balance) |
| `proveTransfer / proveBurn / proveRefresh / proveTransferMulti` with `T`, `p` | the same commands with location and words in place of `T` and `p`; `pkT`, `pkA`, legs and `mode` stay | `{stmt, proof}`; a refusal after the key (balance below amount + fee) goes to the caller only |
| (none) | `auditRead {chainUid, token, entryRef, leg, block, words}` on the **auditor's** key handle (one auditor key per token) | `{amount}` of the audited copy at its window, to the auditor (the key holder) |

The old commands stay only under the test feature `vectors`, never in a release build (backup, not delete). pqz-ffi's `dec` /
`dec_win` calls move into the one private function that decrypts a rebuilt ciphertext; `value()` keeps wiping the noise.

### 4.6 PQZ: disclosure and memo

- `proveDisclose {chainUid, token, entryRef, leg, kind, block, words}` with `kind ∈ {RECEIVER_X, AUDITOR}`: the leg rebuilt
  from the entry blob (§4.4), decrypted, the op 5 statement built inside (layout of CTR-PQZ-14: `chainId`, `chainUid`,
  `token`, `registry`, `entryRef`, `amount`, `kind + 256·w`, `pk` = the handle's, `u`, `v`) and proven. The output goes to the
  viewer the holder names. On chain, `verifyTransferAmount` reads the entry from state and the key from the registry, so a
  disclosure over forged words is refused there.
- `proveDiscloseSender` (op 4) decrypts nothing: it re-derives `r, e1, e2_t` and compares (a MAC-like equality). Unchanged.
- `openMemo {chainUid, token, entryRef, block, words}`: the memo is `memos[entryRef]` and the header words come from the entry
  blob, never free fields; this closes F8 as far as the words are real (§4.12).

### 4.7 Zether (separate module, separate handle)

- The same library duties: `decrypt`, `decryptPending`, `checkBalance` and every `acc` / `balance` / `(C, D)` input of
  `proveTransfer`, `proveTransferMulti`, `proveBurn`, `recoverTransfer`, `openDisclosure`, `openMemo` are replaced by location
  fields and the Zether token's storage words, parsed by its pinned layout and rebuilt as the contract does; the balance hint
  stays a cache of the holder's own value. A layout parser exists per family where a Zether token is deployed (EVM first);
  another family's words are refused until its parser exists.
- `zether-prover`'s `api` keeps the raw commands behind feature `hazmat` (T15c). `D·x` in decrypt and check runs through
  `scaas_ct::secret_mul`.
- `zether-read-balance --rpc` reads the chain, so it is a reading layer: refused by T15c, then re-enabled only as one that
  meets R1 to R6 (the holder names the node; it checks the chain, the catalogue and the registered `Y`) and passes words to
  the same rebuild.

### 4.8 pqz-core: the core decrypt functions (F4)

`pqzl` `decrypt_raw`, the C `pqz_dec` family and pqz-ffi's `dec` / `dec_win` return noise or raw `w` to any in-process
caller. Not reachable from outside today (pqz-ffi's own C ABI exports only `pqz_precompile` and `pqz_max_input`). A feature
`hazmat` around those exports, enabled by the self-test, `vectors`, the vector generator and `ua-rs`, changes no transcript,
relation or byte; defence in depth only, since Cargo unifies features and every binary with `ua-rs` + `pqz` has `dec` compiled
in (the command set is what keeps it unreachable). **Gate (owner decision Q3, 2026-11-06):** it lands with the next pqz-core change; the
four-set full gate is waived for this `cfg`-only change and replaced by a build at all four sets plus `kat`.

### 4.9 Server key oracle (CLI-SGN-31, PLANNED; F5)

The enclave interface loses `zk_mul_by_x(points, ctx)` (a static-DH oracle on `x`), `zk_nonce_commit` / `zk_response` as
separate calls (a response to a caller-chosen challenge is a proof or signature oracle) and the raw `elgamal_decrypt(C, D,
ChainWitness)`. **Whole operations inside the enclave** (group B': balance, transfer, burn, disclosure), each taking location
fields and words and rebuilding as `ua-rs` does; the layer that feeds it meets R1 to R6, so `ChainWitness` becomes "words from
the tenant's trusted reading layer". Results go to the tenant (the key holder), never to the relayer or the broker's logs.
The planned threshold auditor key (CTR-ZTH-41, `y_audit` 3-of-5) is a quorum decryption: ARCH-POS-13 covers it, and it stays
blocked on research §12.5's open question.

### 4.10 Op 7 `memoHash` per mode (F10; owner decision 2026-11-06)

`PqzCore` on `ua-mtx-merge`: `memo = mode == HASH ? 2 + 40·m : 0` (~408) and `if (memo != 0) o.memoHash =
keccak256(abi.encodePacked(t.salt, t.sealedMemo))` (~430); op 1 the same at ~286 / ~304 with `SEALED = 41`. The facade's
memo is `salt(16) ‖ sealed` (`pqz_ffi::memo::seal`), so `keccak(memo)` equals the HASH formula, but BUNDLE needs 0.
**Decided (owner 2026-11-06):** the facade takes the memo mode as an explicit named request field, `mode` = `"HASH"` or
`"BUNDLE"` (no default), for op 7 now and op 1 once T36a lands, and computes `memoHash` exactly as the contract does per
mode: HASH → `keccak256(salt ‖ sealedMemo)` and the memo returned; BUNDLE → `memoHash = 0` and no memo returned. The token's
`disclosureMode` decides which a caller may use (COMPACT refuses BUNDLE on chain, ~399). A test fails on the old behaviour: a
BUNDLE op 7 statement's `H_MEMO_HASH` word is 0 and equals the forge-built statement for the same inputs.

### 4.11 What does not change

`enc` (public), `proveRegister`, `proveKeyRecord`, `proveDiscloseSender`, the balance-cache boxes, the vault and backup
formats, the KEM `open` (ML-KEM is CCA-secure; `ua-rs-sign` spec §6.2's handle rule stays), the C ABI's status set; no
contract, node or byte-format change. `ua-rs` stays I/O-free and holds no chain trust.

### 4.12 Residuals (stated plainly)

- **`ua-rs` alone cannot tell chain state from forged words.** Internally consistent words of a fabricated "blob" holding
  crafted `(u, v)` are rebuilt and decrypted like real ones. An app that feeds `ua-rs` words from an untrusted source
  creates the oracle of §1, and ARCH-POS-13 binds that app (R1 to R6). The library's part is to make the bare-ciphertext
  path impossible and the location explicit; the test of §5 shows this residual on purpose.
- **The reading layer's source.** A full node of the holder's: none beyond the chain's rules. A light client: the chain's
  sealing keys (a sealer or a leaked sealing key can fabricate state, one key on a single-signer chain, NET-EVM-04). Another
  operator's node: that operator (owner decision Q1b, 2026-11-06, §7).
- A stale read shows an old balance; a debit over it is refused on chain (T8 retry), revealing nothing about `s`.
- A genuine state is composed partly by senders (credits, decoys); its decryption is the holder's own data and reveals
  nothing about `s` (fact 1).
- Timing after the key is used (BSGS for Zether, the PQZ prover) depends on the holder's own genuine value: a privacy residual
  to a local observer, not a key leak.

## 5. Tests that must be able to fail

- **The oracle harness as a test** (`clients/ua-rs/tests/no_oracle.rs`): the 8·K crafted queries of research §12.1 at the
  default set. Positive control: through the `vectors`-only raw `dec` they recover `s` exactly. Negative: no release command
  or binding call accepts a bare ciphertext, statement, `T` or `p` (one status, key-use counter 0).
- **Residual control (§4.12):** the same crafted `(u, v)` wrapped as a consistent fabricated blob and supplied as words **is**
  decrypted: the test records that authenticity is the reading layer's duty, not the library's.
- Word negatives (one status, key unused): inconsistent indexes, an offset outside its blob, an `acc` stream not hashing to
  `accHash`, more than `K_MAX` units, a leg outside its entry, a missing or extra word, a field of the wrong type.
- Mutants (each must turn a test red): the caller's `T` accepted again; `p` taken from the request; the `accHash` comparison
  skipped; a TRIVIAL entry built as `Trivial(0)`; the auditor window ignored; F10's `memoHash` always set.
- Byte equality with the contract: the forge state snapshots of §4.4 at the default set and one other set.

## 6. Doc changes

On `ua-rs-sign` (task T15j): `ua-rs-sign` spec §10.1 / §10.2 (decrypt rows → location and words; chain reading and its checks
stay with the reading layer); `docs/clients/ua-libraries.md`: two rule groups, the library duties of §4.3 and the reading-layer
requirements R1 to R6 of §4.2, written for "the wallet layer that reads the chain" (current docs name no consumer), with their
`decisions.md` entries at build (T19).

On `ua-mtx-merge` (task T19b; not edited from here):

| File | Change |
|---|---|
| `docs/contracts/pq-zero-knowledge.md` | T6: "noise never leaves `pqz_dec`" → decryption only of ciphertexts rebuilt from chain words a trusted reading layer supplies, the core's raw decrypt is `hazmat`; CTR-PQZ-14 and §4.2's owner-only `Dec` point at ARCH-POS-13; §7.8 "Restore from state alone" → from state read from a trusted source; the source-trust residual linked to NET-EVM-04 |
| `docs/contracts/zether.md` | a rule (new id) pointing at ARCH-POS-13: the same split; `zether-read-balance` (line ~252) is a reading layer under R1 to R6; the residual linked to NET-EVM-04; CTR-ZTH-41's threshold key blocked on §12.5 |
| `docs/clients/signers-clientkeys.md` | CLI-SGN-31 group B per §4.9; the `y_audit` note; the clientkeys `zether.js` wording; a link to the reading-layer requirements |
| `docs/integration.md` | confidential payments: an integrator that reads PQZ or Zether state for a holder is a reading layer under R1 to R6 |
| `docs/research/07-custody-providers.md` | a dated note at ~111: the group B sketch is superseded by ARCH-POS-13 / CLI-SGN-31 |
| `docs/node/submit-lanes.md`, `docs/node/gateway.md` | NODE-LANE-03: the node never decrypts; a holder's reading layer may use a node only as R1 allows (no new node guarantee) |
| `docs/decisions.md` | ARCH-POS-13's source: the audit done, this spec; entries for the owner rulings of 2026-11-06 (no verifier in `ua-rs`; the reading layer's duty), the library input rule, R1 to R6, the CLI-SGN-31 change and the Zether rule, each in full |
| `docs/research/pqz-threshold-decrypt-prove.md` | §12.5: a link to this spec's §3; the quorum question stays open |

## 7. Owner decisions (2026-11-06; formerly the open questions)

1. **Q1 — decided (owner 2026-11-06): R1's trusted source** is the holder's own node, a node the holder configured
   explicitly, or a verifying light client in the reading layer; never an app default or a discovered endpoint.
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

Plan tasks T15b, T15c, T15e, T14b, T15g–T15j and T19b (T15d and T15f dropped by the owner rulings): **17–23.5 agent-days**,
critical path T15c → T15e → T15g → T15i ≈ 8.5–12 days. Not counted: the reading layer's checks (R1 to R6) in the wallet layer
and the apps, outside this repository.
