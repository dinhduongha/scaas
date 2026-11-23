# PqChat TreeKEM mode (`groupMode = 1`), minimal scope: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task by task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-23):** PLANNED, nothing built. **UNAUDITED.** Revision 2, after the reviews of revision 1 by Codex and Fable.
Spec [`2026-11-23-pqchat-treekem.md`](../specs/2026-11-23-pqchat-treekem.md) (cited "spec §n", its controller calls "C1"–"C27",
its open points "O1", "O2"; a review finding by its id, `codex-n` or `fable-n`); research
[`2026-11-23-treekem-pqchat.md`](../../research/2026-11-23-treekem-pqchat.md).

**Owner rulings (2026-11-23, owner: yes):** minimal mode 1 is built now, before the pre-freeze tag: a commit with UpdatePath, Add
and Remove, Welcome by wraps; external commits, PSKs and ReInit are out; a new DELEGATECALL body module is accepted; the
committer's path secrets are seed-derived; our own TreeKEM in `ua-rs`, no MLS library; PqVault accepts only 0; the leaf is the
registry KEM key; a non-admin commits for its own UA's leaves only; no tree session on a `none` home or a replica; ML-KEM-1024
the one node scheme; `TREE_LEAVES_MAX` = 256, to be confirmed on the spec's new figures (spec §1, O1).

**Goal:** `PqChatTree` and its entries, the reference and vectors, `ua-rs`, the node's rows, the SDK calls, `pqchat-core`'s tree
client, bindings, an e2e and the docs, in one round with one matrix at its end.

## 1. Order and dependencies

```mermaid
flowchart LR
  T0["T0 second spec review, O1 and O2"] --> T1a["T1a clientkeys: records, tree math, hashes"]
  T1a --> T1b["T1b clientkeys: secrets, scenarios, vectors frozen"]
  SIGS["pqchat-sigs landed"] --> T3a
  T1a --> T3a["T3a contract: module, storage, cold tree"]
  T3a --> T3b["T3b contract: commit, pieces, completion"]
  T1b --> T3b
  T3b --> T3c["T3c contract: views, gas, size, layout pins"]
  T1b --> T2["T2 ua-rs"]
  T1b --> T4["T4 node rows"]
  T3b --> T4
  T2 --> T5["T5 SDK calls"]
  T3b --> T5
  T5 --> T6a["T6a pqchat-core: tree, commit"]
  T6a --> T6b["T6b pqchat-core: replay, store"]
  T6b --> T7["T7 bindings"]
  T3c --> T8["T8 e2e: anvil, then the local Nethermind copy"]
  T6b --> T8
  T4 --> T8
  T7 --> T9["T9 docs"]
  T8 --> T9
  T9 --> T10a["T10a code review and fixes"]
  T10a --> T10b["T10b round matrix on the reviewed tree"]
```

- **`pqchat-sigs` lands first.** The contract work (T3) branches from it: it needs the signature-storage setting (C1), several
  `keyId`s per UA and `groupMode` in `PqChatSession`. The round's branch is `pqchat-treekem`, made from the branch `pqchat-sigs`
  merged into; T1a may start before that on clientkeys alone and is rebased once.
- **T0 gates the code:** the second review of the spec's revision 2 and its fixes; O1 (the cap on the new figures) and O2 (the
  joiner without `init`) answered. O2 changes derivations and the replay rule, not a record: T1a may start before it, T1b not.
  A change to a record after T1b moves every vector: settle the records in T0.
- **T1b before T3b and T4 (fable-14).** T3b's first tests are the `scenario` rows end to end and T4's gate rebuilds the rows'
  calldata; both rows are T1b's. T3a needs only T1a's rows (type strings, the cold tree hash, the admission check).
- **Byte formats change everywhere at once:** the rows of `smartcontracts/vectors/pqchat/tree.json` come only from the clientkeys
  generator; no language edits a reproducer alone.

## 2. Parallel split

One agent's context holds one or two tasks. Four lanes, each a worktree of `pqchat-treekem` with real `lib/`, `node_modules`
and `algorand/out` directories:

| Lane | Agents, in order | Starts when |
|---|---|---|
| A, reference and crypto | A1: T1a → A2: T1b → A3: T2 | T0 done (T1a: the records settled) |
| B, contract | B1: T3a → B2: T3b → B3: T3c | `pqchat-sigs` landed and T1a's rows exist; **T3b when T1b's rows are frozen** |
| C, node | C1: T4 | T1b's rows and T3b's selectors |
| D, clients | D1: T5 → D2: T6a → D3: T6b → D4: T7 | T2 and T3b's ABI |
| Controller | T0, T8 (one agent), T9, T10a, T10b, the merges between lanes | |

Lane B's T3a runs beside lane A's T1b; T3b waits for T1b. Each agent reports its gates, mutants and pins (old → new); the full
matrix runs once, in T10b, on the final tree (round rule of 2026-11-18). Heavy commands go through `scripts/capped`, in the
foreground.

## 3. Tasks

### T0. Second spec review and owner points

- [x] First review (Codex, Fable) of revision 1; revision 2 of the spec; the decisions entries updated; the resolution table.
- [ ] Second review of revision 2 (Fable: design, security, crypto; Codex only on the owner's request); its fixes.
- [ ] O1 and O2 put to the owner; the spec's constants, §5 and §10 follow the answers.

### T1a. clientkeys: records, tree math, hashes (`clients/clientkeys`)

- [ ] `src/pqchat-tree.js`: Appendix C tree math, resolution, filtered path, `th` with `kemHash` in the leaf (spec §4); the
      typehashes and `hashStruct` of `PqChatCommit`, `TreeAdd`, `TreeRemove`, `PathList`, `PathCt`, `treeId` (spec §5, §6);
      applying Removes and Adds; `ctTargets`; the target that covers a leaf; the key admission check (spec §8).
- [ ] `scripts/pqchat-vectors.mjs`: `tree.json` rows `treeMath` (RFC 9420's tree-math vectors as a control), `resolution`,
      `treeHash` (cold 2, 3, 5 and 8 keys; after a commit, a Remove, an Add, growth; **an Add and a Remove under a copath child
      of the author**, fable-9), `admission` (one key per refused case: a coefficient at 3,329, each of the seven small-order
      `pk_X` with and without bit 255, a wrong scheme byte, a wrong length; and accepted controls), `typehashes`, `digests`.
- [ ] Gates: `scripts/capped npm test` in `clients/clientkeys`; the generator's `--check` (a regenerated file is byte-identical).
- [ ] Mutants (each must turn a test red, one at a time): resolution lists right before left; a blank leaf counted; the filtered
      path keeps an empty level; `th` of an empty subtree non-zero; the leaf hash without `kemHash`; a sibling hash taken before
      the changes; the admission check without the small-order list; one field dropped from the `PqChatCommit` type string.

### T1b. clientkeys: secrets, scenarios, the vectors frozen

- [ ] The path secrets, node keys from the 96-byte seed form, `pathContext` and `ps[0]`, the path ciphertext (`kek`, `aad`), the
      schedule (`ctx`, `joiner`, `S`, `K`; O2's answer), the tree wrap label, building and processing a commit, the joiner's
      path, the roster by undo, replay with its fixed read list (spec §5, §10).
- [ ] Rows `secrets`, `pathCt`, `schedule`, and `scenario`: create (3 UAs, one with 2 keys) → commit by B → Add of a UA →
      **a commit by a third member, outside the new member's subtree, right after the Add** (codex-5, fable-5) → a commit by
      the new member → `remove` then a commit → Remove by `(ua, keyId)`; per step every record, piece, tree hash, roster, and
      each member's `K`; one row with non-zero unbound fields where a digest canonicalises any.
- [ ] Rows for the repeats (fable-1, codex-7): the same change, nonce and target indices on a tree with other keys (scenario A)
      and in a twin session at another home (scenario B): `ps[0]` differs in both.
- [ ] Rows for healing (codex-15, fable-6, fable-4): a leaked node set that one commit locks out and one that it does not; a
      member that did not follow an epoch and follows the next commit that reaches its leaf (O2's answer decides the expected
      result).
- [ ] Negative rows with the expected named result: a wrong target, a wrong `treeHash`, a list that does not hash, a node key
      that does not match its secret, a Welcome that disagrees with the path, a `sealedInfo` that does not open, a valid
      substituted leaf key with the tree unchanged (codex-1), a fetched ciphertext or key altered with the signature unchanged
      (codex-13).
- [ ] Gates: as T1a; the mode-0 rows of `records.json`, `keys.json`, `messages.json` byte-identical (mode 0 does not move).
- [ ] Mutants: `pathContext` without `parentTreeHash`, without `treeId`, without `ctTargets`; `K` from `joiner` directly; the
      ciphertext `aad` without the target; a tree wrap under the flat label; a processed commit that skips the derived-key
      comparison; a joiner that skips its path ciphertext (the third-member row must fail); a ciphertext index chosen from the
      held secrets instead of the list (the read list of the failing member must differ and the test must see it).

### T2. `ua-rs`: the tree behind handles (`clients/ua-rs`)

- [ ] `src/wallet/tree.rs`: a tree-epoch handle (`K`, known node secrets, in the secret store); joining from a wrap and the
      path ciphertext; opening a ciphertext with the leaf key or a held node and deriving upward with the key comparison; the
      committer's recovery. No function returns a secret byte (C1 of the SDK, A-3); errors named (`TreeKeyMismatch`,
      `TreeNotHeld`, `KemCheck`).
- [ ] **The typed commit-signing operation (codex-12, spec §15):** one named operation that authenticates the target keys,
      draws and returns the nonce, builds the path, the list, the pieces and the record inside the boundary, shows the review
      and signs. Tests: a normal signing; a request whose pieces differ from the reviewed ones is refused; no entry signs a
      `PqChatCommit` digest from outside.
- [ ] **The registry KEM record check (codex-1, spec §8 step 4):** key data hashes to the UA; a version above 0 by its kept
      signature over `kemRecordDigest`; version 0 by the registration's committed hash. Encapsulation takes only a key that
      passed. Tests: each form accepted; a substituted valid key refused; a record signed by another UA refused.
- [ ] The public side as plain functions: tree math, resolution, hashes, the record digests, `ctTargets`, the admission check.
- [ ] Gates: `scripts/capped cargo test` with the features the vector tests need, over every `tree.json` row; clippy `-D
      warnings`; the existing KEM and PqChat tests unchanged; `cargo fmt --check`.
- [ ] Mutants: as T1b's, in Rust; plus a handle whose secret is readable through `Debug` (a test greps the output); a held
      node kept after a Remove blanked it; the registry check skipped for an added key; a nonce reused for a rebuilt commit.
- [ ] No new dependency (HKDF, AES-GCM, ML-KEM and X25519 are in the crate).

### T3a. Contract: the module, its storage, the cold tree (`smartcontracts/evm`)

- [ ] `PqGroupBase._land` split into storing wraps and completing an epoch; `_authorOf`'s offset-free form moved from `PqChat`
      to a base the module inherits (fable-U2); mode 0's behaviour and events unchanged (`PqChat` and `PqVault` bytecode may
      move: size and gas pins old → new in the commit).
- [ ] `src/pqchat/PqChatTree.sol` (SPDX header), a DELEGATECALL body module as `PqChatTopics`; namespace `scaas.pqchat.tree`
      (spec §7); `PqChat` gains the immutable `TREE`, `modules()` lists it, the factory release and `script/onchain/PqChat.s.sol`
      pass it. Library-split checks: storage through the hooks only, no `this`, `msg.sender` unused, return data forwarded.
- [ ] `createSession` with `groupMode = 1`: `PqChatTreeSigStore`, `PqChatTreeHome`, the caps, `treeId`; **leaf `i`, `liveKey`,
      `keysOf` and the hashes above it written when wrap `i` lands (C15)**, with the admission check and `PqChatTreeKeyLive`;
      `genesisTreeHash` when epoch 0 completes; `groupMode` 2–255 still `PqChatModeUnsupported`; `rekey` on a tree session
      `PqChatModeEntry`.
- [ ] Tests first (`test/pqchat/PqChatTree.t.sol`), each refusal with its positive control; the cold `treeHash` against the
      vector rows, with the wraps landed in order, in reverse and one per transaction; every `admission` row; two members with
      one key; the author read from a three-part blob; `test/v2/layout/` gains the module's namespace and proves `PqChat`'s
      and `PqVault`'s layouts unmoved.
- [ ] Gates: every forge directory at the default set; the size gate (`PqChat` under 35,286 B, a new `PqChatTree` row with its
      reason); `forge fmt --check`.
- [ ] Mutants: mode 1 accepted on a `none` home; on a replica; the cap off by one; a leaf hash without its index or without
      `kemHash`; the leaves written in the record's transaction; the author offset back to the constant 96; the admission
      check reduced to scheme and length.

### T3b. Contract: `commit`, the pieces, completion

- [ ] `PqChatTypes`: the five typehashes and hashes (`*TypehashIsPinned` against the vectors); `IPqChat`: the structs, entries,
      views, errors and the `PqChatPath` event of spec §6 and §11.
- [ ] `commit`: the acceptance checks of spec §8 (with `treeId`, `kemHash`, `liveKey`, the shapes of C24) and the rights of §9;
      `addPathList`, `addPathKeys`, `addPath`; `addWraps`, `leave`, `remove` (with `owed`, C21, and `PqChatTreeAdmins`),
      `postMessage` forwarded for a tree session; `Epoch.wraps` = pieces + 1 (C20); completion steps 1–7 in order, all or
      nothing, also from `commit` itself.
- [ ] Tests first: the `scenario` rows end to end (single transaction and chunked, pieces sent by a third party, in any order);
      every named error of spec §11 with its positive control; a commit staged before a `remove` that then fails to complete;
      two commits racing for one head; a piece landed twice; a wrong piece by a third party refused and the right one still
      landing; the list, the ciphertexts and the keys read back byte for byte from state.
- [ ] Tests that name a finding: `epochComplete`, `postMessage`, `remove` and a child `commit` on a staged commit without Adds,
      on a losing one and on a zero-piece one, false or refused before completion and true after (codex-10, fable-7); `remove`
      owing 32 leaves accepted and 33 refused, by one record and by several (codex-6, fable-2); an Add of a live `(ua, keyId)`,
      of another `keyId` with the same key bytes, and of a key freed by a Remove of the same commit (codex-2, fable-10); an Add
      whose `kemHash` is another valid key (codex-1); a node key that fails the admission check with every hash matching
      (codex-8); a commit signed for a twin session at another home (codex-7); a commit and a `remove` that would leave a
      keyless admin only (codex-21); an added UA in `sessionsOf` once, also after a second key and after remove and re-add
      (fable-11, codex-17); `ctCount ≥ leaves`, 33 admins, 4,097 B and 0 B of `sealedInfo` refused at acceptance (codex-20).
- [ ] Gates: every forge directory at the default set; `forge test --isolate` for the gas files.
- [ ] Mutants: the walk on the tree before the changes; one target unchecked; `treeHash` unchecked; the hashes compared before
      they are recomputed; completion without the removed-UA check; a non-admin adding another UA's key; the slot taken before
      the last piece; `wraps` without the extra unit; a direct-path node outside the filtered path left with its key; a
      ciphertext or the list kept as its hash only; `liveKey` not freed by a Remove; `owed` not reset at completion.

### T3c. Contract: views, gas, size, pins

- [ ] The views of spec §6, with `TREE_RANGE_MAX`; `supportsInterface` and `interfaceId` (old → new).
- [ ] `test/pqchat/PqChatTreeGas.t.sol`: every row of spec §13 measured (2, 8, 64 and 256 keys; warm, after a removal, cold; the
      session record at 64, 128, 192 and 256 member keys; a genesis wrap with its leaf, typical and first of a subtree; the
      record at its bounds; the list at 255 targets; the node keys; completion at its bounds; with the ML-DSA-65 check on the
      cached key). **The file runs with `--enable-tx-gas-limit`, and each row asserts `regular < 2^24` and `(regular + state)
      × 1.05 ≤ 60 M` in the test itself (fable-15; the session record at 256 member keys is expected above 60 M and is recorded
      with its figure, with the largest key count that fits):** a positive control row that exceeds 2^24 (the FIPS-key verify) must fail
      under the flag, or the flag is not in force. **A row that does not fit stops the task: numbers to the owner (O1), no bound
      edited to pass.** Timing or calibration runs: ask first.
- [ ] A reachability test (fable-3): a tree at the cap with 224 silent added leaves, then `remove`s to `owed` = 32: the next
      commit's pieces are the bounds of §13 and each fits.
- [ ] Pins: `size-baseline.json` (old → new, reasons), the gas pins of `PqChatGas.t.sol` that the base split moved, the layout
      files, `LinkClosure` release pins.
- [ ] Gates: every forge directory at the default set; `script/pqz/at-set.sh others sensitive`, then `others modules` (no outer
      `capped`); `PqzSet.sol` restored.

### T4. Node: typed and guard rows (`scaas-node`)

- [ ] `typed.rs`: `TYPED` rows for `PqChatCommit`, `TreeAdd`, `TreeRemove`, `PathList`, `PathCt`; entry rows `commit` (record and
      `UASig`) and `addPathList`, `addPathKeys`, `addPath` (no signature); every array bounded by length and depth before bytes
      are built, **with the contract's bounds** (`TREE_LEAVES_MAX`, `TREE_CHANGES_MAX`, `TREE_ADMINS_MAX`, `TREE_INFO_MAX`, the
      depth, `ctCount < leaves`; codex-20). `guard.rs`: `commit` as the signed writes, the three unsigned entries under
      `relay_unsigned_pqchat` as `addWraps`. `selector_audit.json`. Both directions equal to the contract's.
- [ ] `docs/node/job-api.md`: the four calls' named fields; a note for operators (job shapes were added, none changed).
- [ ] Gates: `scripts/capped cargo test`, clippy `-D warnings`; the node rebuilds the vector rows' calldata byte for byte.
- [ ] Mutants: a missing bound on `ctTargets`; a bound one above the contract's; an unsigned entry relayed with the option off;
      one selector missing on either side.

### T5. SDK: thin calls (`clients/scaas-sdk`)

- [ ] Named ABI rows for `commit`, `addPathList`, `addPathKeys`, `addPath` and the views; the `app_core` calls that pass
      `ua-rs`'s tree handles and the signing operation through; the registry read that returns the KEM key **with** its kept
      signature and the registration (codex-1); chunk planning from the chain's limits as for wraps, refusing by name a chain
      whose block is under the largest piece (the gas table stays release data). No tree logic, no key byte.
- [ ] Gates: the SDK's tests over the `tree.json` digests and calldata; clippy; the binding surface check.
- [ ] Mutants: a chunk plan that exceeds the block-limit rule; a call that names `rekey` for a tree session; the decoder that
      drops the signature again.

### T6a. `pqchat-core`: the public tree and building a commit (`clients/pqchat-core`)

- [ ] The mode branch at "obtain `K`"; state, consent and pins keyed by `treeId` (C16); the home's setting from pinned data or a
      majority read (C27); the tree from `treeOf`, `treeLeaves`, `treeNodes`, `treeNodeKey` under the read rules (ARCH-POS-15);
      the steps of spec §8 "before a client encrypts" (the checkpoint, the recomputed root, the head's signature and right, each
      key against its hash); asking `ua-rs` for a commit (plain, Add, Remove, by UA, "refresh") and sending its pieces; the
      rules of spec §11 for a candidate; the size hint (C3); a `none` home refused by name.
- [ ] Gates: `scripts/capped cargo test` over the vector rows; `tests/hostile`: a substituted node key, a substituted live leaf
      key, a substituted key of an added member, a head below the checkpoint, a forged continuation, a flat twin with the
      setting changed on an empty store (the pinned case as control; codex-14), each refused before any encryption.
- [ ] Mutants: encrypting before the signature check; the tree hash not recomputed; a tree read from a replica; the checkpoint
      not consulted; the setting taken from one discovered node.

### T6b. `pqchat-core`: replay, the store, not followed

- [ ] Replay from state (spec §10) on a fresh store: the fixed read list, the checks at the read boundary, the roster by undo
      and the rights check, the periods of a key no longer live; the store's tree rows as a cache; the "not followed" state:
      shown, nothing sent; a seed-restored device opens its own commits; a device key's commits open on that device only.
- [ ] **The trace test (codex-3, fable-8):** the harness records every RPC call (method, arguments, order) and every send of a
      device replaying a session in which it follows every epoch, and of the same device when one path ciphertext is replaced
      by garbage; the two traces are equal, later polls included, and sends are 0. Control: with the T1b mutant (index from held
      secrets) the traces differ.
- [ ] Gates: `tests/recovery.rs` over the `scenario` rows for every member, for a late joiner, for a removed key and for an
      unchanged third member as message author (codex-11); a losing signed candidate is not followed; the real-crypto e2e gate.
- [ ] Mutants: any automatic write after a failed open; a read skipped after a failed open; replay that reads an event; replay
      that needs an epoch before the join; a commit author not checked against the roster.

### T7. Bindings

- [ ] Regenerate `pqchat-core`'s bindings with the new calls and errors; the per-language smoke tests. After `capped dotnet`:
      `dotnet build-server shutdown`.

### T8. e2e

- [ ] Local only. On anvil, deployed through the deploy script (the release with `TREE`): a tree session of 8 keys, a commit by
      a non-admin, an Add, a commit by a third member, a `remove` and the commit after it, a Remove of one device key, messages
      before and after each, a fresh device replaying, a second device racing a commit; through the node's relay with fee 0,
      pieces by a third party.
- [ ] **On the local Nethermind copy (`pqz-core/nethermind/chain/copy.sh`; fable-15), which enforces EIP-7825 and EIP-8037:** the session record at
      192 member keys (and at 256, expected refused at a 60 M block), a commit's record at its bounds, completion at its bounds and a whole warm commit at 64 keys, each
      included or reported with its figures. Docker bypasses `capped`: `--memory` set.
- [ ] Gates: `cargo test --test e2e -- --ignored` in `scaas-node`; the deploy e2e (a deploy-script change); progress lines, the
      full output in a git-ignored log.

### T9. Docs

- [ ] `docs/contracts/pqchat.md` §16 and `docs/clients/pqchat-core.md` to BUILT with the test names and the measured gas rows;
      `docs/node/job-api.md`; `docs/decisions.md` status lines; the summary `step | commit | rc | counts` under `runs/`.
- [ ] Gates: `python3 scripts/docs_check.py check` and `paths`, `python3 scripts/test_docs_check.py`.

### T10a. Code review and fixes

- [ ] Fable code review of the contract and of `ua-rs`'s tree (Codex on the owner's request); fixes, with the suites they touch.

### T10b. The round's matrix, once, on the reviewed tree (codex-22)

- [ ] After T7 and T10a, on the final tree: every forge directory at the default set; the set-sensitive tests and `modules` at
      the other three sets; the size gate; node tests, clippy and e2e; clientkeys, `ua-rs`, the SDK, `pqchat-core`,
      `pqvault-core` (still refusing 1), every `ua-*` that reads `smartcontracts/vectors/pqchat/`; the vector `--check`; docs.
      The summary records the SHA that was reviewed and tested; a change after it reruns the matrix on the new tree.
- [ ] No `pqz-core` path changes: no gate there.
- [ ] The code is UNAUDITED until an AI audit round covers it at its commit. Merge and push on the owner's word.

## 4. Pins this round moves

| Pin | Why |
|---|---|
| `interfaceId` of `IPqChat`, `selector_audit.json`, the node's rows | new entries and views |
| `size-baseline.json`: `PqChat` (dispatch), `PqVault` (if the base split moves it), a new `PqChatTree` row | spec §13 |
| Gas pins of `PqChatGas.t.sol` and `PqVault`'s that the base split moves; the new tree rows | old → new in the commit |
| Layout: a new namespace file; `PqChat` and `PqVault` proven unmoved | spec §7 |
| Typehash pins: five new; none of mode 0 moves | spec §6 |
| Vectors: a new `tree.json`; the mode-0 files byte-identical | T1 |

## 5. Effort and risks

**Effort (revised).** Revision 1 took the note's 10 to 13 agent-days. Revision 2 adds: the list piece and two more entries, the
admission check in Solidity, `kemHash` and `liveKey`, the cold tree with the wraps, the registry record check and the typed
signing operation in `ua-rs`, the fixed read schedule with its trace test, the roster, the pins per `treeId`, and the Nethermind
run; it removes the parent hash and, with O2 (a), the `init` chain.

| Task | Agent-days |
|---|---:|
| T0 (second review, fixes) | 1 |
| T1a, T1b | 1.5 + 2 |
| T2 | 2.5 |
| T3a, T3b, T3c | 1.5 + 3 + 1.5 |
| T4 | 1 |
| T5 | 1 |
| T6a, T6b | 1.5 + 2 |
| T7, T8, T9 | 0.5 + 1 + 0.5 |
| T10a, T10b | 1 + 0.5 |
| **Total** | **about 22 (20 to 24)** |

In four lanes the longest chain is T0 → T1a → T1b → T3b → T3c → T8 → T10: about 10 days of work, 7 to 9 calendar days.

- **Time to the tag:** about twice revision 1's estimate; the contract's completion (C7) and `ua-rs`'s signing operation carry
  the most.
- **The cap (O1)** may come back from T3c with numbers: the session record is the one row at the line (about 200 member keys
  at 60 M by estimate).
- **O2** decides T1b's schedule rows and T6b's healing tests; nothing else waits for it.
- **A record change after T1b** restarts T1b's rows and every reader: T0 must close the records.
- **A new protocol before the audit:** every deviation of spec §3 is outside RFC 9420's analyses.
