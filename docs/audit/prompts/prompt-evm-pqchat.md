# AI audit prompt, unit `evm-pqchat` (DRAFT, 2026-11-16)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed -n` /
`cat`; `python3 scripts/docs_check.py resolve <id>` (it only prints). Not allowed: any build, test, fuzz, benchmark, gas or timing
run (`forge`, `cargo`, `npm`, `dotnet`, `anvil`, `docker`, `gate.sh`, `at-set.sh`, which rewrites `PqzSet.sol` in place); any
edit, file creation (except the one result file below), deletion, commit, checkout, stash or push; any network access to a
chain or RPC. The machine runs other heavy jobs: a large build here gets the terminal killed.

## 2. Target

- Run from the root of the main checkout of the SCaaS repository (public).
- Code under audit: the detached worktree `.claude/worktrees/audit-<TAG>` at tag `<TAG>`, commit `<SHA>`. Below, `T/` means that
  directory. Read code and docs **only** under `T/`; the main checkout's own tree may be on another branch.
- First step: `git -C .claude/worktrees/audit-<TAG> rev-parse HEAD` must print `<SHA>`. If it does not, stop and write only that.
- Prior reports named below live in the main checkout's `scratchpad/` (git-ignored, local; not under `T/`).
- The whole unit is in scope, including code that did not change since an earlier review.

## 3. Result file

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-evm-pqchat.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-evm-pqchat.md`, `20261120-09-agy-gemini-4-argon-high-evm-pqchat.md`). Use the tool's
  configured model and effort (read from its config at run time; the owner may change any reviewer's model); do not
  override them. Name that model in the report's title line; the ledger records it. The unit name is always last.
- If your sandbox cannot write files, print the whole report as your final message; the runner saves it under that name.

## 4. Which source wins

1. Owner rulings: entries in `T/docs/decisions.md` with `owner: yes`, and their dated `Change` lines. They override code that has
   not caught up: **a difference between code and an owner ruling is a finding against the code.**
2. Component docs: `T/docs/contracts/`, `T/docs/clients/`, `T/docs/node/`, `T/docs/networks/`, `T/docs/integration.md`.
3. Code, for pinned byte formats only; `T/smartcontracts/vectors/` is the authority for bytes.
4. `T/docs/history/`; 5. `T/docs/research/`: background only.

`T/docs/decisions.md` is about 1.8 MB: search it by rule id (`### CTR-UA-37`, `<a id="...">`), never read it whole. An old id in a
comment resolves with `python3 scripts/docs_check.py resolve <id>`. Follow a stated rule as stated; do not propose reopening it.

## 5. Absolute rules (a break of any one is at least P1)

1. **Never lose ciphertext.** PQZ and Zether ciphertexts stay in contract state, never only a hash plus calldata or events (logs
   and history expire; state does not).
2. **No decryption oracle** (ARCH-POS-13). Nothing decrypts a ciphertext someone else chose and leaks anything about the result
   (a revert, a status, an error code, a timing, a signed verdict). Scoped exceptions are under section 7.
3. **Explicit parameters** (CTR-MTX-28, CTR-MTX-29, CTR-UA-36). Named, typed parameters and typed EIP-712, one entry point per
   operation; no packed `bytes` holding several fields, no hex bundles. Only a single crypto object stays `bytes` (a proof, a
   ciphertext, a key, a signature). Node JSON uses named fields; the old hex forms are refused (`HEX_ARGS_REFUSED`,
   `HEX_DATA_REFUSED`).
4. **Every state-changing `mtx*` is relayable**, with a fee of 0 too. A relayer can refuse or delay, never forge or alter.
5. **No EIP-7702.** An EOA signs with its own key and runs no code; a 7702 delegate never authorises (no ERC-1271 through it) and
   a delegated caller is refused (CTR-UA-24 and its Change of 2026-10-30, NET-EVM-07).
6. **No assumption about a chain:** no gas price 0, no block gas limit of ours; the PQZ / ML-DSA precompiles may ship to customer
   chains. **One rule on every chain:** never a rule split by L1, L2 or chain kind.
7. **EIP-8037 inclusion:** a transaction fits only if its regular gas plus its state gas fit the block gas limit;
   `gas_used = max(...)` is accounting, not inclusion. Do not conclude from it that a large deploy or call fits.
8. **EIP-7825 cap:** regular gas per transaction is at most 2^24 = 16,777,216 on Osaka and later (Nethermind enforces it, in
   `eth_call` too). forge / anvil 1.8.5 do not enforce it by default, so a path that is green in `forge test` above 2^24 fails on
   a chain (example found 2026-11-15: pure-Solidity ML-DSA-65 verify on an uncached key, about 19.0 M).
9. **Nothing deployed is upgraded.** Contracts are immutable; versions live in the factory's catalogue.
10. **Authorization lives in contracts.** Off-chain checks are extra, never the only guard. Fail closed: a refusal, a named error,
    zero sends.
11. **Zether is not PQZ** (separate systems, separate rules); **NEAR is not Algorand**.

A green gate is not evidence of soundness: three P0s in this repository sat behind green tests. Do not trust a test because it
passes; check that a negative test can fail. When you find a transcript, statement, digest or signature bug, check the same class
everywhere it can recur (C, Rust, wasm32, generic and specialised verifiers, Solidity, clients) and list each place.

## 6. Threat model

Attackers: any EOA or contract; a relayer (may refuse or delay, must never forge or alter); a front-runner; a colluding key holder
or `msig` member; a malicious token, DEX, executor, verifier or factory caller; a role holder exceeding its grant; a replayer
across chain id, `chainUid`, registry generation, token, release, kind, operation or nonce lane; a chain whose gas, block limit or
precompiles differ from the SCaaS testnet. Goals: forgery, theft, an unbacked mint, a leak of amounts or balances, a permanent
lock, replay, griefing that blocks others, a call that cannot fit a block (EIP-8037, EIP-7825). Prefer a concrete call sequence
to a pattern match. Across units: every optimisation that replaced code with shared code, a library or a module (DELEGATECALL)
must keep behaviour; say so when it does not.

## 7. Do not report (accepted by the owner; skip unless the code does something worse than the accepted behaviour)

- **Hybrid wrapped tokens:** a minter may mint unbacked units and unwrap them against the reserve users deposited (CTR-GOV-30,
  CTR-TOK-05 "not claimed on a hybrid"; owner 2026-11-13, USDC -> VND CBDC).
- **`BURNER`:** holders cannot stop a user sending to an unspendable address (not a burn; CTR-GOV-29).
- **Own-key `OFFCHAIN` PQZ token** (`pqzOwnKey = true`, `pqzOpening = false`): whoever can make that token's verifier sign can
  recover that token's key; the risk lies in that token only (ARCH-POS-13 Change 2026-11-13, CTR-PQZ-37).
- **The hybrid KEM** (ML-KEM-1024 + X25519, IND-CCA by its combiner): a decapsulation of a sender-chosen ciphertext and its
  one-shot AEAD are outside ARCH-POS-13 (Change 2026-11-13). Still report any PQZ or Zether key applied to a value that was
  not first shown well formed by re-encryption and byte comparison.
- **Shared-key `OFFCHAIN` class (class 2):** `msig` refused and op 7 unsupported at first; the auditor guarantee as ruled (an
  honest recipient cannot spend an unreadable credit; collusion leaves a named unreadable leg) (three-key spec, Q8 / Q9).
- **CTR-DEX-19:** `dex` must be a contract, nothing more; a contract made to look like a DEX can report any fill and take the
  signed amount (owner-accepted residual risk).
- **CTR-TOK-31:** R10 Sybil on the net wrap / unwrap rule; Q17 (a) the shielded id of a confidential kind is not always the
  public id (disclosed).
- **Classical Zether:** handing `s` over opens every leg, decoys included (CTR-ZTH-37); the sender may leave the auditor out of
  one transfer (CTR-ZTH-42); `fund` burns public Zether units from the caller (CTR-ZTH-35).
- **`msig`:** one with no `pop` is unusable until enough weight accepted, on each registry (CTR-UA-37).
- **`fndsa1024`:** built on the Falcon round-3 specification v1.2, the FIPS 206 risk accepted (CTR-UA-40 Q1).
- **`PqChat`:** a member can take the slot first and make the admin rekey again (CTR-CHAT-09, O2); what an open topic accepts
  cannot be removed, and its state-gas cost per KiB is accepted (CTR-CHAT-16, D20).
- **`OPERATOR_TRANSFER` / grants:** a `WHOLE` holder is unbounded by design (CTR-GOV-20).
- **PQZ rollover floor C0-6** of the 2026-10-26 review: accepted, spec corrected (CTR-PQZ-08 (a)).
- **Sizes and deploy gas:** the code-size ceiling is 64 KiB (Amsterdam / Glamsterdam is required on every chain, NET-EVM-06):
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 / 70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `evm-pqchat`

The `PqChat` contract (UA-7): sessions, epochs, wraps, messages, topics and entries, the signature storage and
`groupMode`, the TreeKEM mode (`groupMode = 1`), and the registry views it relies on.

**Scope (paths under `T/`):**
- `smartcontracts/evm/src/pqchat/`
- `smartcontracts/evm/src/pqgroup/PqGroupBase.sol`, the base shared with `PqVault` (CTR-PQV-12; added 2026-11-22): audited
  here, once, for both contracts; unit `evm-pqvault` reads it only for PqVault's use and sends a base defect here
- read-only: `src/ua/UARegistry*.sol` for `requirePortable`, the KEM records and `msig` expansion
- the signature storage and `groupMode` (on `ua-rs-sign` since the `pqchat-sigs` merge; added 2026-11-24): `sigStore` fixed
  at `initialize(ownerUA, sigStore)` (CTR-CHAT-23), several KEM keys per member UA (CTR-CHAT-24), `uint8 groupMode` the last
  field of `PqChatSession` (CTR-CHAT-25); tests `test/pqchat/PqChatSigs.t.sol`, `PqChatSigGas.t.sol`, `PqChatDevices.t.sol`,
  `PqChatGroupMode.t.sol`; plan `T/docs/superpowers/plans/2026-11-23-pqchat-signatures.md`
- **the TreeKEM mode** (added 2026-11-24; finalized 2026-11-26: the build merged from `pqchat-treekem` and was fixed in the
  review-fix round): `src/pqgroup/PqGroupTree.sol` (the app-agnostic tree base: tree math, tree hash, key admission, the
  tree namespace, the no-return sets, acceptance and completion; `TREE_LEAVES_LIMIT` 512), `src/pqgroup/IPqGroupTree.sol`
  (the app-agnostic change records `TreeAdd` / `TreeRemove`, inherited by `IPqChat`; review A-6: the ABI is the tuple, nothing
  signed moved), `src/pqchat/PqChatTree.sol` (PqChat's DELEGATECALL body module: `commit`, `addPathList`, `addPathKeys`,
  `addPath`, the glue to `PqChatCore`), `src/pqchat/PqChatTreeMembers.sol` (the fourth body module, split out 2026-11-25
  under the owner's pre-approval: the tree exits `treeLeave` / `treeRemove`, and mode 0's `leave` / `remove`, moved out of
  `PqChat` when E-3 took it over its size line; `implArgs = abi.encode(topics, tree, views, members)`),
  `src/pqchat/PqChatTreeViews.sol` / `IPqChatTreeViews.sol` (the read-only module), the tree records in `PqChatTypes.sol` /
  `IPqChat.sol`; tests `test/pqchat/PqChatTree.t.sol`, `PqChatTreeCommit.t.sol` (plays every world of `tree-secrets.json`,
  its world count pinned), `PqChatTreeRules.t.sol`, `PqChatTreeGuards.t.sol`, `PqChatTreeExits.t.sol`, `PqChatTreeGas.t.sol`,
  `PqChatTreeViews.t.sol`, `PqGroupTreeBase.t.sol`, `PqChatEpochs.t.sol` (the mode-0 exits and the replica copies),
  `PqChatTreeModel.sol`; the tree rows of `test/vectors/selector_audit.json`; `T/smartcontracts/vectors/pqchat/tree.json`
  (with a depth-9 commit), `tree-secrets.json` (read for the bytes)

**Specifications and rules to read first:**
- `T/docs/contracts/pqchat.md`, decisions CTR-CHAT-01 to -25 (D1-D22, P1-P49 as recorded; CTR-CHAT-20 removal, -21 home,
  -22 `PqChatStore`, -23 signature storage, -24 several keys per member, -25 `groupMode`)
- the round's Changes of 2026-11-24 to -26 under CTR-CHAT-07, -10, -20, -27 (E-3: exits checked and applied at the head;
  the spec check's lag `EXIT_LAG_MAX`; E-2 / A-16: the named epoch's lists and the replica rule; A-15: an empty `addWraps`
  refused; C38-C40; R8 512 leaves and C10's 20 changes, owner 2026-11-25); CTR-UA-74 in `T/docs/contracts/accounts.md` (an
  `msig`'s version tag inside the signature object; `msig-replica-copy`: a replica's copy carries the replica's tag)
- TreeKEM: spec `T/docs/superpowers/specs/2026-11-23-pqchat-treekem.md` (§4 the tree, §6 records and
  entries, §7 storage, §8 what the contract checks and what only clients check, §9 rights, leave, removal, §11 refusals, §13
  bounds and gas, §14 threats), plan `T/docs/superpowers/plans/2026-11-23-pqchat-treekem.md`, decisions CTR-CHAT-26 (the
  mode, two layers, no return), CTR-CHAT-27 (the checks and bounds, controller calls C1-C40, R8 512 leaves at depth 9, C10's `TREE_CHANGES_MAX` 20), CTR-CHAT-28 (the tree is
  app-agnostic); `T/docs/clients/pqchat-core.md` CLI-PQC-17 (what only clients check)

**Invariants to check (beyond section 5):**
1. Every accepted record kept in full in state (SSTORE2 within the code-size limit, CTR-CHAT-05); events only notify.
2. Epochs: `epoch = parent + 1`, the home-chain child slot (the removal attack refused), plain rekey rules (CTR-CHAT-09), `PqChatRemove` by an admin of a complete epoch.
3. Wraps by hash, chunked (`createSession` / `rekey` / `addWraps`), each wrap hashing to its signed hash; members sorted, at least 2.
4. `postMessage` membership and nonce scopes; `storeMessage` unsigned and bounded; no record carries a fee, deadline or submitter; every write relayable with fee 0 (CTR-CHAT-19).
5. `requirePortable(ua, purposeTag, ...)` over `uaMessage(kind, purpose, typedDigest)`, the `msig` minimal form; an `msig` holds no KEM key.
6. Topics and entries (D18-D22, CTR-CHAT-16): name 1-512 B, bodies in state, edits as versions by the author; `initialize(ownerUA)` accepts 0 or the creator only.
7. `PqGroupBase` (added 2026-11-22): holds no state of its own, PqChat's behaviour is unchanged by the move into it (CTR-PQV-12, CTR-PQV-15: no test, pin or vector edited), and each rule it holds (parent, home slot, admins, leave, remove, `PqVaultRemovedKept` / the PqChat twin, an admin that is no member removable, F1-F3, F7) is correct for both users; list what `PqVault` overrides.
8. **Signature storage and `groupMode`** (CTR-CHAT-23 to -25; added 2026-11-24): `sigStore` 0 or 2 only
   (`PqChatSigStore`), no setter; on an `sstore2` instance every accepted session, epoch, leave and removal record and every
   posted message keeps exactly the signed bytes in state, read by views; on `none` the `sigHash` only and the views refuse; a
   mismatched signature refused at write in both modes; members sorted by `(ua, keyId)`, at most 8 keys per UA, one wrap per
   key, rights, leave and removal per UA; `groupMode` fixed at creation, signed in the record, values above 1 refused
   `PqChatModeUnsupported`; `PqVault` accepts only 0 (`PqVaultModeUnsupported`).
9. **The TreeKEM mode** (CTR-CHAT-26 to -28): a tree session only on an
   `sstore2` home and only at its home instance; flat entries refused on a tree session and tree entries on a flat one
   (`PqChatModeEntry`); `treeId = hashStruct(PqChatSession)` and `parentTreeHash` bound in every commit; at acceptance the
   tree computed in memory on the head (path length, resolution targets `PqChatTreeTargets`, root against `treeHash`
   `PqChatTreeHash`), then each piece once against its signed hash; node keys of scheme 1, 1,601 B, through the admission
   check (canonical X25519 `pk_X`, `PqChatKemKey`), no two live leaves with the same key bytes; the no-return sets `gone`,
   `goneOwnKey`, `goneKey` never cleared; a non-admin changes keys of its own UA only; `admins` cannot keep a UA that is gone
   (`PqChatRemovedKept`); `TREE_LEAVES_MAX` 512 (depth 9), `TREE_CHANGES_MAX` 20, `TREE_ADMINS_MAX` 32, `TREE_INFO_MAX` 4,124 B; every
   ciphertext, node key and path list kept in SSTORE2; the last piece's completion within EIP-8037 and 2^24; the
   `PqGroupTree` storage namespace apart from `PqGroupBase`'s and `PqChat`'s (`test/v2/layout/namespaces.json`).
10. **Exits at the head** (added 2026-11-26; E-3 of the TreeKEM code review, owner "Yes, both modes"; the spec check's lag;
   E-2 and A-16 of the re-review; CTR-CHAT-10, -20, -27 C9): at home a leave or removal (mode 0's `leave` / `remove`, the
   tree's `treeLeave` / `treeRemove`, all in `PqChatTreeMembers`) names the head or a complete ancestor of it
   (`PqChatIncomplete` for a staged child) at most `EXIT_LAG_MAX` = 16 epochs below the head (`PqChatExitLag(named, head)`;
   no withdrawal, no typehash moved), and is checked and applied at the head (the leaver a member of the head, the remover a
   live admin of it, its UAs members or admins of it); when the named epoch is not the head the signer and every named UA are
   also in the named epoch's lists (E-2); a repeated exit, or one that newly flags nobody, is `PqChatNotMember`; the flag, the
   record and the event are the head's. A replica keeps the epoch named, its flag allows an ancestor within `EXIT_LAG_MAX`,
   and it takes a repeat naming one epoch (A-16); the tree has no replica (C4). Hunt: a front-runner that strands a signed
   exit, home and replica judging one record differently, `PqGroupBase`'s bounded ancestor walk wrong for one of its users.
11. **The round's other contract fixes** (added 2026-11-26): an `addWraps` with no wrap is `PqChatShape` in both modes,
   checked first (A-15; `_storeWraps` unchanged for `createSession`, `rekey`, `commit`); C39 (an Add's key held by a leaf a
   Remove of the same commit takes out is free in every order), C40 (`addPath` carries at least one ciphertext), C38 (a
   `treeRemove` naming a UA already `gone` refused whole); an `msig` author's records carry its version tag inside
   `UASig.signature`, accepted only when current (CTR-UA-74), and a replica's copy carries the replica registry's current tag
   (`test_a1_replicaCopyCarriesTheReplicaTag`), so a home record and its copy differ in `sigHash`: check every view and
   check that assumed them equal.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/pqz-core/research/code-review-2026-10-26/README.md` (whole-contract review at `64549aa4`) and `code-review-2026-10-19/README.md`
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `scratchpad/review-ua-mtx-merge/` (A-regulated, B-metatx-ua, C-pqz-zether, D-factory-gov-dex-pqchat, recheck-*, recheck2-*)
- TreeKEM: the spec reviews `scratchpad/treekem-review-20261123-1426/` (Fable and Codex, rounds 1-3, `resolution.md`)
- the review-fix round (2026-11-24 to -26, local): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the tag's closing gate summary under `T/smartcontracts/evm/runs/` (every forge directory at the default set, the set-sensitive tests at the other three sets)
- `T/smartcontracts/evm/runs/2026-11-15-3zh-core-g2.txt`, `2026-11-15-burner-wrap-caps.txt`, `2026-11-15-pqz-three-keys-round/summary.txt`, `2026-11-13-fix3-chainuid/summary.txt`, `2026-11-14-msig-members/mutants.txt`, `2026-11-15-3zh-mldsa.txt`
- `T/smartcontracts/evm/size-baseline.json` with `T/scripts/size_gate.py` (the size ratchet, ceiling 64 KiB)
- `T/smartcontracts/evm/runs/2026-11-23-pqchat-sigs-summary.txt`, `2026-11-23-pqchat-sigs-mutants.txt` (14 of 14 killed)
- TreeKEM: `T/smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3a-summary.txt` to `-t3d-summary.txt` and their mutant
  records; `2026-11-25-treekem512-nethermind.py` (the last-live-leaf commit at 512 leaves on the local Nethermind copy, which
  enforces 2^24)
- the review-fix round: `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt` (with
  `2026-11-24-review-fix-contract-mutants.py`), `2026-11-26-review-fix4-contract-summary.txt`, and the round's closing
  matrix (`2026-11-26-round-matrix.sh` and its summary)

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-CHAT-01 to -28 with their Changes of 2026-11-24 to -26 (invariants 10, 11) one by one against `src/pqchat/`, `src/pqgroup/PqGroupBase.sol`, `PqGroupTree.sol`, `IPqGroupTree.sol`; the BUILT status of each row in `docs/contracts/pqchat.md` with its test (`PqChatSigs.t.sol`, `PqChatDevices.t.sol`, `PqChatGroupMode.t.sol`, the tree tests). |
| 2 | Cryptography | On-chain cryptography of the unit: the typehashes and `DS_C` domain of every record (session, epoch, leave, remove, message, topic, entry, and the tree's `PqChatCommit`, `TreeAdd`, `TreeRemove`, `PathList`, `PathCt`, `PqChatTreeLeave`, `PqChatTreeRemove`); `uaMessage(kind, purpose, typedDigest)` under `PURPOSE_PQCHAT`; wrap hashes and `sigHash` binding to session, epoch and member `(ua, keyId)`; `treeId = hashStruct(PqChatSession)`, `parentTreeHash`, the typed tree hash (leaf `TreeLeaf`, parent `TreeParent`, no RFC parent hash) computed in `PqGroupTree.sol` against `treeHash`; `genesisCtx`; `kemHash = keccak256(kemPk)` and the scheme-1 admission check (canonical X25519 `pk_X`, 1,601-B node keys); what each hash does not bind (a node key known only by its signed hash). |
| 3 | Security | Authorship of each record (the signer the record names, `requirePortable`); admins and rights per UA (a non-admin changes its own UA's keys only); removal and leave; the home-chain child slot; replay of a record to another session, epoch, instance or chain; nonce scopes; front-running the child slot (CTR-CHAT-09 O2 accepted); downgrade between `groupMode` values and between `sigStore` settings; the no-return sets (`gone`, `goneOwnKey`, `goneKey`); exits at the head: a front-runner stranding a signed exit (the lag), home and replica judging one exit differently (E-2, A-16). |
| 4 | Rules that do not bend | Every record and ciphertext kept in full in state (CTR-CHAT-05; tree node keys and path ciphertexts in SSTORE2); no decryption oracle (no check depends on a wrap's content); explicit parameters (one entry per tree operation); relayable with fee 0 (CTR-CHAT-19, the pieces by anyone); one rule on every chain; nothing upgradable. |
| 5 | Secrets and privacy | Metadata a public observer learns: member UAs and key ids, epoch cadence, message sizes (padding buckets), tree shape and who commits; signatures in state on `sstore2` instances (what they reveal). |
| 6 | Robustness and denial of service | Bounds: name 1-512 B, wraps chunked, at most 8 keys per UA, `TREE_LEAVES_MAX` 512 (depth 9), `TREE_CHANGES_MAX` 20, `TREE_ADMINS_MAX` 32, `TREE_INFO_MAX` 4,124 B, 64 leaves per `treeLeaves` call; `PqChatTreeBacklog`; a staged commit no piece can complete; the completion's transaction (about 49.1 M asked) and the last-leaf commit (near 2^24) against EIP-8037 and EIP-7825; open topics' state growth (accepted); the exit lag's ancestor walk (at most `EXIT_LAG_MAX` reads). |
| 7 | Failure handling | Named errors; no partial epoch after a refused wrap or piece; a closed tree session; recovery from state alone (CTR-CHAT-14: `sessionsOf`, `latestEpoch`, `storedRange`, the tree's commits since a Welcome); reentrancy through the registry call. |
| 8 | Consistency across languages and layers | Records, typehashes and wrap hashes equal `T/smartcontracts/vectors/pqchat/` (`records.json`, `tree.json`) as clientkeys `pqchat.js` / `pqchat-tree.js` / `treekem.js`, `ua-rs` `wallet/pqchat.rs` / `tree.rs` / `tree_public.rs` and pqchat-core build them; the six tree rows and the flat rows of `selector_audit.json` equal the node's `typed.rs` rows both ways; PqVault's use of `PqGroupBase` unchanged; the node refuses an empty `addWraps` as the contract does (A-5). |
| 9 | Contract specifics | Layout pins `PqChat.json`, `PqChatStore.json`, `namespaces.json` (the tree namespace `scaas.pqchat.tree` apart); typehash pins (`PqChatTypes.t.sol`); the body modules (`PqChatTopics`, `PqChatTree`, `PqChatTreeMembers`, the read-only `PqChatTreeViews`; the `implArgs` order) by DELEGATECALL: storage, `msg.sender`, return data; the size gate; gas pins with old -> new figures (`PqChatGas.t.sol`, `PqChatSigGas.t.sol`, the tree gas rows). |
| 10 | Performance and cost | Gas per entry against `docs/contracts/pqchat.md` and the TreeKEM spec §13 (estimates until pinned); the state gas of the no-return slots (97,920 each); who pays the last piece's completion. |
| 11 | Interfaces and misuse | Entries hard to misuse: a flat entry on a tree session refused by name; the piece order a client must follow (one ciphertext held back) documented; stable error codes. |
| 12 | Tests | Each refusal has a positive twin; the sigs mutants (14 of 14) and the TreeKEM mutants (T3a-T3d) and the review-fix round's contract mutants cover each check; `PqChatTreeModel.sol` as an independent model that can disagree with the contract; vectors read by the forge tests. |
| 13 | Operations and the supply chain | N/A for config and dependencies (pure Solidity); SPDX headers on the new files (`PqGroupTree.sol`, `IPqGroupTree.sol`, `PqChatTree.sol`, `PqChatTreeMembers.sol`, `PqChatTreeViews.sol`). |

## 9. Report format (Markdown, English)

```
# evm-pqchat: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### PQC-1 [P1] <short title>
- Where: T/<path>:<line>[-<line>] (every place, if the class recurs)
- Rule or invariant: <rule id or invariant from section 8>
- Dimension: <number and name, from the dimension table of section 8 (`docs/review.md` §1)>
- Claim: <one or two sentences>
- Failure scenario: <concrete inputs or call sequence -> wrong outcome (forgery, loss, leak, lock, crash, divergence)>
- Evidence: <quoted code, doc or standard clause, and the reasoning>
- Fix: <concrete change>
- Confidence: CONFIRMED (traced end to end) | PLAUSIBLE (say what is not traced)

## Earlier findings in this unit
<for each finding of the prior reports in section 8 that touches this unit: closed / open / regressed, with file:line>

## Checked and sound
<what you checked and found holding, with file:line, so a reader knows the coverage>

## Not covered
<what you did not reach>
```

Severity: **P0** forgery, theft or loss of funds, an unbacked mint, a break of privacy of amounts, balances or keys, a permanent
lock, a decryption oracle, a lost ciphertext, a consensus split; **P1** a break of a section-5 rule or an owner ruling with a
real path, a relayer able to alter an intent, a DoS of a whole contract or node; **P2** a bounded loss, griefing, a wrong
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
