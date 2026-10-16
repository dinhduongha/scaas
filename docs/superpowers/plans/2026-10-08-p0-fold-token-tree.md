# P0 — Fold the token tree and the Zether multi-recipient drafts into the docs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the component docs and `docs/decisions.md` state the accepted token tree (T1–T15) and the accepted
Zether multi-recipient design (Z1–Z13), so phases P1–P5 code against the docs, not against the drafts.

**Architecture:** Docs only, no code. Each rule gets one normative home (an `<a id="ID">` anchor in a component doc)
and one register entry in `docs/decisions.md`; other docs link the anchor. Code that does not yet match carries a
"Transitional (BUILT)" note. The two drafts are frozen into `docs/history/specs/` with an id map.

**Tech Stack:** Markdown, `scripts/docs_check.py` (stdlib Python checker, CI job `docs`).

**Spec:** `docs/superpowers/specs/2026-10-08-token-tree-design.md` (T1–T15) and
`docs/superpowers/specs/2026-10-08-zether-multi-recipient-design.md` (Z1–Z13, rev 6).

## Global Constraints

- Register format (`docs/decisions.md` header): `### <ID> — <title>`, meta line `- old: … · status: … · owner: yes|no · date: … · normative: <file#ID> · superseded-by: …`, then **Rule.** (optional) **Why.** **Cost if wrong.** **Source.**
- Ids `<AREA>-<TOPIC>-<NN>`, never renumbered; a superseded entry keeps its id, gets `status: superseded`, `superseded-by: <new id>` and keeps one sentence of what it said.
- A rule is defined once, at its anchor in the normative doc; every other doc links it and never restates it.
- Every owner decision of this fold is `owner: yes`, `date: 2026-10-08`.
- New ids (next free numbers at plan time): `CTR-ZTH-37…47`, `CTR-TOK-21…25`, `CTR-MTX-25`, `CTR-AS-17`, `CTR-DEX-24`, `CTR-ACC-11`, `CTR-PQZ-22`. Re-check with the command in Task 1 Step 1 before using them.
- Code is unchanged in P0: every rule that differs from the built code gets a "Transitional (BUILT)" sentence naming the phase (P1…P5) that implements it.
- PQZ: only the `pqz…` names and the reserved kinds are folded. Z9/Z10/Z12 for PQZ and PQZ multi-recipient are **not** owner-ruled yet — do not fold them; record them as an `open` note only.
- `python3 scripts/test_docs_check.py`, `python3 scripts/docs_check.py check` and `python3 scripts/docs_check.py facts check` end with 0 errors after every task.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- A rule restated in a second doc instead of linked (drift source) — each task's grep step checks its new terms appear with one anchor only.
- A link still pointing at a superseded rule as if current (e.g. `CTR-TOK-02`, `CTR-AS-01`, `CTR-ZTH-10`) — Task 7 Step 2 greps every superseded id outside `decisions.md` and `history/`.
- Built code described as if already changed (a missing "Transitional (BUILT)" note) — each task lists the notes it must add.
- PQZ decisions folded that the owner has not ruled (Z9/Z10/Z12 mirrors, multi-recipient) — Task 5 Step 4 greps `pq-zero-knowledge.md`.
- Old names left in normative text (`transferConfidential`, `burn` for Zether, `SubjectAccount`, `META_SINGLE`, `createTiered`) — Task 7 Step 2 greps them.

---

### Task 1: Fold the Zether multi-recipient draft (Z1–Z13)

**Files:**
- Modify: `docs/contracts/zether.md` (sections *Statement (byte layout)* :287, *Σ-protocol* :330, *Proof wire format* :434, *Disclosure* :674, *Gas (measured)* :916, *Interfaces* :1002)
- Modify: `docs/decisions.md` (Zether block)
- Move: `docs/superpowers/specs/2026-10-08-zether-multi-recipient-design.md` → `docs/history/specs/2026-10-08-zether-multi-recipient-design.md`

**Interfaces:**
- Produces anchors: `CTR-ZTH-37` multi-recipient transfer (Z1, Z2, Z3, Z7, Z8), `CTR-ZTH-38` three storage modes (Z4), `CTR-ZTH-39` attestation removed (Z9), `CTR-ZTH-40` `SENDER_CP` and `j` in the challenge (Z10), `CTR-ZTH-41` threshold auditor key (Z11), `CTR-ZTH-42` per-transfer auditor opt-out (Z12), `CTR-ZTH-43` disclosure in `ZetherDisclosure` (Z13). Tasks 5 and 7 link them.

- [ ] **Step 1: Confirm the free ids**

Run: `grep -oE '^### CTR-(ZTH|TOK|MTX|AS|DEX|ACC|PQZ)-[0-9]+' docs/decisions.md | sort -t- -k3 -n | awk -F- '{print $1"-"$2, $3}' | awk '$2<80{m[$1]=$2} END{for(k in m) print k, m[k]}'`
Expected: `CTR-ZTH 36`, `CTR-TOK 20`, `CTR-MTX 24`, `CTR-AS 16`, `CTR-DEX 23`, `CTR-ACC 10`, `CTR-PQZ 21`. If any differs, shift that area's new ids up by the difference in every task.

- [ ] **Step 2: Write the normative text in `zether.md`**

Add a section `## Multi-recipient transfer` after *Proof wire format* with anchors `CTR-ZTH-37` and `CTR-ZTH-38`: copy §3 (relation, E1–E8), §4 (encoding, opTag, `MAX_RECIPIENTS = 16`, errors) and §5 (effects, storage-mode table) of the draft verbatim, with the Z12 paragraph (*Auditor per transfer*) under anchor `CTR-ZTH-42`. In *Disclosure*: replace the three-kind table by the four-kind table of draft §5.1 under anchor `CTR-ZTH-40`; add the sentence "There is no on-chain attestation" under anchor `CTR-ZTH-39`; add anchor `CTR-ZTH-43`: "`verifyTransferAmount` and `transferCiphertext` live in the stateless `ZetherDisclosure`; the token exposes `transferEntry(entryRef)` and the implementation-immutable `disclosure()`; the challenge binds the token address"; add anchor `CTR-ZTH-41` (Z11 text). In *Gas (measured)*: replace the transfer table by tables (a) and (b) of draft §7 (rev 6 figures). In *Interfaces*: update `IZetherToken` / `ITransferDisclosure` signatures to the built code (`smartcontracts/evm/src/zether/IZetherToken.sol`, `ITransferDisclosure.sol`, `ZetherDisclosure.sol`).

- [ ] **Step 3: Register entries**

Append to the Zether block of `decisions.md` seven entries, one per anchor, e.g.:

```markdown
<a id="CTR-ZTH-40"></a>
### CTR-ZTH-40 — SENDER_CP opening; leg index in every disclosure challenge
- old: ZM:Z10 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-40 · superseded-by: —

**Why.** Handing `s` over opens every leg of a multi-recipient transfer, decoys included; a Chaum-Pedersen proof opens leg `j` only.
**Cost if wrong.** A sender proving one payment reveals its decoys, so the decoys stop hiding the real recipient.
**Source.** history/specs/2026-10-08-zether-multi-recipient-design.md §5.1.
```

Update the existing disclosure entry (the one whose title mentions attestation; find it with `grep -n 'attest' docs/decisions.md`) to `status: superseded`, `superseded-by: CTR-ZTH-39`, if its rule is the attestation; otherwise edit its text to drop attestation. Update `CTR-ZTH-14` (bundle stored) to point at `CTR-ZTH-38` for the modes.

- [ ] **Step 4: Freeze the draft**

`git mv docs/superpowers/specs/2026-10-08-zether-multi-recipient-design.md docs/history/specs/`; set its **Status:** line to `ACCEPTED by the owner 2026-10-08 and folded into the component docs; frozen here as the design record. Ids: Z1/Z2/Z3/Z7/Z8 → CTR-ZTH-37, Z4 → CTR-ZTH-38, Z9 → CTR-ZTH-39, Z10 → CTR-ZTH-40, Z11 → CTR-ZTH-41, Z12 → CTR-ZTH-42, Z13 → CTR-ZTH-43; Z5/Z6 need no rule (spike merged; CTR-ZTH-30 unchanged).`

- [ ] **Step 5: Verify**

Run: `python3 scripts/docs_check.py --write && python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check`
Expected: `check: 0 error(s)`; `facts check` 0 errors (if it reports a load-bearing token of the frozen draft as absent, add it to `docs/history/dropped-artifacts.tsv` only when the token is deliberately gone, e.g. `attestTransferAmount`).
Run: `grep -rn 'attestTransferAmount\|AmountAttested' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research'`
Expected: only lines that say it was removed.

- [ ] **Step 6: Commit**

```bash
git add -A docs
git commit -m "docs: fold the accepted Zether multi-recipient design (Z1-Z13) into the component docs"
```

### Task 2: Token tree, kinds, features, libraries, factory (T1–T3, T7, T8, T10, T13)

**Files:**
- Modify: `docs/contracts/token-wrappers.md` (*Overview* :11, *Tiers* :73, *Admin exceptions* :433, *Factory* :498, *Interfaces* :656, *Storage layout (clones)* :702, *Hedera* :763, *Conformance* :785)
- Modify: `docs/contracts/metatx.md` (*Native mixin, no forwarder* :19 — `CTR-MTX-07`; *Interfaces* :569; *Transitional (BUILT)* :818)
- Modify: `docs/contracts/README.md` (*Immutable at deploy* :73, *Admin powers (complete list)* :122)
- Modify: `docs/decisions.md`

**Interfaces:**
- Produces anchors: `CTR-TOK-21` tree and kinds (one implementation per kind; `NONE`, `UNDERLYING` 1–8 legs, `NONE_ZETHER`, `UNDERLYING_ZETHER`; PQZ kinds reserved), `CTR-TOK-22` features (`features`, `lockedFeatures`, bit table of spec §5, validation in `initialize`, `disableFeature`, `PAYABLE` default off and immutable), `CTR-TOK-23` Hedera as `IS_HEDERA`, `CTR-TOK-24` libraries, ERC-7201 namespaces, size budget 20,480 B, `CTR-TOK-25` factory `createToken` / `createTokenUnregistered` / `TokenConfig` / `TokenCreated`, `CTR-MTX-25` one `SigCheck`. Tasks 3–5 link `CTR-TOK-22` and `CTR-TOK-25`.

- [ ] **Step 1: `token-wrappers.md` — tree and kinds**

Replace the class list and diagram of *Overview* by spec §3's tree (Mermaid `classDiagram`, the checker refuses ASCII art — C11) and the kinds table; anchor `CTR-TOK-21` on the paragraph "One implementation per kind; features are flags (CTR-TOK-22)". Rename section *Tiers* to *Kinds*; merge the tier-2 and tier-3 subsections into `### UNDERLYING — UnderlyingToken (1–8 legs)` keeping every rate/reserve rule (`CTR-TOK-04/05/06/07/13/19`) with "tier 2/3" replaced by "a one-leg / multi-leg `UnderlyingToken`"; add the single-asset ABI rule (works only with one leg, `UnderlyingRequired`).

- [ ] **Step 2: `token-wrappers.md` — features**

Rewrite *Admin exceptions* as `## Features` with anchor `CTR-TOK-22`: spec §5 table and bullets verbatim (bits 0–8, roles, valid kinds, errors `FeatureInvalidForKind(bit)`, `LockedNotSubset()`, `RoleMismatch(bit)`, `FeatureLocked(bit)`, `FeatureNotSet(bit)`, event `FeatureDisabled(bit, by)`, `supportsInterface(IERC20Payment)` iff `PAYABLE`). Link `CTR-AS-17` for bits 5–8 (Task 3 creates it).

- [ ] **Step 3: `token-wrappers.md` — factory, storage, Hedera, libraries**

*Factory*: anchor `CTR-TOK-25` with spec §7's Solidity block and bullets except the DEX lines (Task 4). *Storage layout (clones)*: anchor `CTR-TOK-24` with spec §4 (library table, hot paths inline, namespaces, budget, CI gate). *Hedera*: anchor `CTR-TOK-23` (`IS_HEDERA`, `HederaLib`, no children). Add a `### Transitional (BUILT)` paragraph: "Built: v1 line, `MetaTxCore`/`MetaTokenBase`, `SingleUnderlyingToken`/`MultiUnderlyingToken`, three Hedera children, `OpenFactoryV2.createTiered`; replaced in P1."

- [ ] **Step 4: `metatx.md` and `contracts/README.md`**

Edit the `CTR-MTX-07` paragraph to the tree `MetaTxBase → ERC20MetaTx → MetaTokenBase` with the layer contents of spec §3 (trade and pay in `MetaTokenBase`, not in `ERC20MetaTx`). Add anchor `CTR-MTX-25`: "One internal `SigCheck` (ECDSA low-s, ERC-1271 with the gas-cap rule, the HIP-632 hook) used by `MetaTxBase`, `OrderBookDex`, `MandateWallet`, `SmartKeyAccount`; `SigLib` deleted." In `contracts/README.md` *Immutable at deploy*: add "features and lockedFeatures (CTR-TOK-22)"; *Admin powers*: replace the per-tier role list by the role column of CTR-TOK-22 and add `disableFeature`.

- [ ] **Step 5: Register entries**

Add `CTR-TOK-21…25` and `CTR-MTX-25` (format of Task 1 Step 3; **Source.** `history/specs/2026-10-08-token-tree-design.md` §n). Set `CTR-TOK-02` (three tiers) `status: superseded`, `superseded-by: CTR-TOK-21`. Edit `CTR-TOK-03` (factory, kinds) to link `CTR-TOK-25` for the API and drop the kind list; edit `CTR-TOK-09` (renounceable minter) and `CTR-TOK-10` (creation-time exceptions) to point at `CTR-TOK-22`; edit `CTR-MTX-07`'s title to "One meta-tx tree: MetaTxBase, ERC20MetaTx, MetaTokenBase".

- [ ] **Step 6: Verify**

Run: `python3 scripts/docs_check.py --write && python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check`
Expected: 0 errors.
Run: `grep -rn 'META_SINGLE\|META_MULTI\|createTiered' docs/contracts docs/node docs/clients docs/networks docs/integration.md`
Expected: only lines inside "Transitional (BUILT)" paragraphs.

- [ ] **Step 7: Commit**

```bash
git add -A docs
git commit -m "docs: fold the token tree — kinds, features, libraries, factory (T1-T3, T7, T8, T10, T13)"
```

### Task 3: Regulated controls become flags (T8, T11)

**Files:**
- Modify: `docs/contracts/asset-suite.md` (*Regulated module* :57, *Storage layout pins* :955, *Touchpoints* :932)
- Modify: `docs/contracts/token-wrappers.md` (the `*_REG` rows, e.g. :32, :447, :629)
- Modify: `docs/decisions.md`

**Interfaces:**
- Consumes: `CTR-TOK-22` (Task 2).
- Produces: anchor `CTR-AS-17` "Regulated controls are flags 5–8 (`FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`) on the ordinary kinds, code in `AdminLib`; refused on confidential kinds (T11)".

- [ ] **Step 1: Rewrite the module's frame**

In *Regulated module*: replace the "separate implementations, kinds 5–7, `RegulatedControls` + `RegulatedLib`, `HederaRegulated*`" framing by anchor `CTR-AS-17`. Keep `CTR-AS-03…09` rules unchanged in substance; replace "a regulated token" by "a token with flag `FREEZE`/`FORCE`/`PAUSE`/`ALLOWLIST`" and "controls bits set at creation, only cleared" by a link to `CTR-TOK-22` (locked or disableable per flag). Remove the `virtual` requirements list (no children any more). *Storage layout pins*: the controls live in the `scaas.admin` namespace (`CTR-TOK-24`).

- [ ] **Step 2: Remove `*_REG` kinds elsewhere**

In `token-wrappers.md` delete the "regulated child per tier" row and the `META_*_REG = 5…7` mentions, linking `CTR-AS-17` once from the kinds table.

- [ ] **Step 3: Register entries**

Add `CTR-AS-17`. Set `CTR-AS-01` `status: superseded`, `superseded-by: CTR-AS-17`. Edit `CTR-AS-02` (third creation-time exception) to "is part of the features of CTR-TOK-22".

- [ ] **Step 4: Verify**

Run: `python3 scripts/docs_check.py --write && python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check`
Expected: 0 errors.
Run: `grep -rn '_REG\b\|RegulatedControls\|HederaRegulated' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research\|decisions.md'`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add -A docs
git commit -m "docs: regulated controls become creation-time flags on every non-confidential kind (T8, T11)"
```

### Task 4: Factory-made DEX and the advisory DEX registry (T12)

**Files:**
- Modify: `docs/contracts/dex.md` (*Fees and admin* :233 — `CTR-DEX-03`; *The named `dex`* :352; *Transitional (BUILT)* :452)
- Modify: `docs/contracts/token-wrappers.md` (*Factory*, `CTR-TOK-25`)
- Modify: `docs/node/dex-venue.md`, `docs/clients/signers-clientkeys.md` (the "DEX list" sentences)
- Modify: `docs/decisions.md`

**Interfaces:**
- Consumes: `CTR-TOK-25`.
- Produces: anchor `CTR-DEX-24` "`OpenFactory.createDex(version, DexConfig, salt)` makes an `OrderBookDex` clone; `admin` written once by `initialize`; `DexPuller` deployed by `initialize`; `isDex(addr)` is advisory: tokens never consult it".

- [ ] **Step 1: `dex.md`**

Add anchor `CTR-DEX-24` under *Fees and admin* with spec §7's `DexConfig` and the clone bullet. Edit `CTR-DEX-03`: "`admin` is set once at creation (CTR-DEX-24) and has no setter". In *The named `dex`*: keep `CTR-DEX-19` unchanged and add one sentence: "`isDex` (CTR-DEX-24) feeds the client and node checks; tokens do not consult it, so the factory admin gains no power over trades (owner)". Transitional note: built `OrderBookDex` has a constructor and an immutable `admin`; P2.

- [ ] **Step 2: Factory and consumers**

Add `createDex`, `DexCreated(dex, creator, version, implementation, admin)` and `isToken`/`isDex`/`versionOf` to `CTR-TOK-25`'s block. In `node/dex-venue.md` and `clients/signers-clientkeys.md`, where the chain profile's DEX list is described, add "a listed DEX is `isDex` and of a non-deprecated version (CTR-DEX-24)".

- [ ] **Step 3: Register, verify, commit**

Add `CTR-DEX-24`; edit `CTR-DEX-03`'s summary. Run the four checker commands of Task 2 Step 6 (expected 0 errors).

```bash
git add -A docs
git commit -m "docs: factory-made DEX clones and an advisory DEX registry (T12)"
```

### Task 5: Zether layer over the public balance; names; ZetherStatements (T4–T6, T9, T11, T14)

**Files:**
- Modify: `docs/contracts/zether.md` (*Scope* :20, *ElGamal state and lifecycle* :189, *Meta-transaction envelope and replay protection* :458, *Underlying, verifier gas, chains* :732, *Interfaces* :1002, and every `transferConfidential*` / `burn` / `fund` / `wrap` mention)
- Modify: `docs/contracts/pq-zero-knowledge.md` (the selector list near :1112 and the *Contracts* table :1100)
- Modify: `docs/integration.md`, `docs/node/job-api.md`, `docs/clients/signers-clientkeys.md` (Zether entry-point names)
- Modify: `docs/decisions.md`

**Interfaces:**
- Consumes: `CTR-TOK-21` (kinds), `CTR-TOK-22` (flags), `CTR-ZTH-37…43` (Task 1).
- Produces anchors: `CTR-ZTH-44` confidential layer (spec §6.1, §6.3: `ZetherLayer` + `ZetherLib`, no own underlying, reserve invariant with `totalShielded·shieldScale`, minter never mints shielded), `CTR-ZTH-45` entry points and names (spec §6.2 table; no `zetherRegister`), `CTR-ZTH-46` `ZetherStatements`, `CTR-ZTH-47` regulated flags refused on confidential kinds (link `CTR-AS-17`); `CTR-PQZ-22` `pqz…` names mirror `CTR-ZTH-45`, kinds reserved.

- [ ] **Step 1: Layer and invariant**

Rewrite *Underlying, verifier gas, chains* as `## Confidential layer` with anchor `CTR-ZTH-44` (spec §6.1 and §6.3 verbatim) and anchor `CTR-ZTH-47`. Edit `CTR-ZTH-08` (Zether on the one base) to "a `ZetherLayer` on `MetaTokenBase` kinds `NONE_ZETHER` / `UNDERLYING_ZETHER` (CTR-TOK-21)". In *Meta-transaction envelope*: the envelope (`ZetherMetaTx`, `_executeOp`, `relayed*`) becomes allowlisted self-calls of `mtxExecute` — link the MT-6 rule already there; mark the built envelope Transitional (P3).

- [ ] **Step 2: Names**

Add anchor `CTR-ZTH-45` with spec §6.2's table. Replace, in `zether.md`, `integration.md`, `node/job-api.md`, `clients/signers-clientkeys.md`: `transferConfidential` → `zetherTransfer`, `transferConfidentialBundle` → `zetherTransferBundle`, `transferConfidentialNoBundle` → `zetherTransferNoBundle`, `transferConfidentialSingle` → `zetherTransferSingle`, Zether `burn` → `zetherUnshield`, `fund` → `zetherShield`, `rollOver*` → `zetherRollOver*`, `setRollOverMode` → `zetherSetRollOverMode`. One Transitional sentence lists the built names (P3).

- [ ] **Step 3: ZetherStatements and the register**

Add anchor `CTR-ZTH-46` (spec T14 + §6.1 sentence). Add register entries `CTR-ZTH-44…47`. Set `CTR-ZTH-10` (underlying ERC-20 in v1) `status: superseded`, `superseded-by: CTR-ZTH-44`. Edit `CTR-ZTH-14` to drop "fee-on-transfer underlyings refused" if it now lives in `UnderlyingLib`'s rule (`CTR-TOK-11`), linking it.

- [ ] **Step 4: PQZ — names only**

In `pq-zero-knowledge.md`, add anchor `CTR-PQZ-22`: "PQZ entry points are `pqzShield`, `pqzWrapShield`, `pqzTransfer`, `pqzUnshield`, `pqzUnshieldUnwrap`, `pqzRollOver`; kinds `NONE_PQZ`, `UNDERLYING_PQZ` (and `*_ZETHER_PQZ`) are reserved (CTR-TOK-21)". Rename the selectors in the normative ABI line accordingly (`pqzBurn` → `pqzUnshield`, `fund` → `pqzShield`). Add one `open` sentence: "Disclosure changes Z9/Z10/Z12 and multi-recipient transfers are not ruled for PQZ (owner review pending)." Register `CTR-PQZ-22`.
Run: `grep -n 'SENDER_CP\|attest\|opt-out\|MAX_RECIPIENTS' docs/contracts/pq-zero-knowledge.md`
Expected: no new lines beyond the `open` sentence.

- [ ] **Step 5: Verify and commit**

Run the four checker commands (0 errors).
Run: `grep -rn 'transferConfidential\b\|transferConfidentialBundle\|transferConfidentialNoBundle' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research\|decisions.md'`
Expected: only Transitional sentences.

```bash
git add -A docs
git commit -m "docs: Zether as a layer over the public balance, zether*/pqz* names, ZetherStatements (T4-T6, T9, T11, T14)"
```

### Task 6: `SubjectAccount` → `SmartKeyAccount` in the docs (T15)

**Files:**
- Modify: every file listed by `grep -rln 'SubjectAccount' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research'` (expect `contracts/accounts.md` section *Smart account (optional): `SubjectAccount`* :1323, `contracts/metatx.md`, `contracts/dex.md`, `contracts/mandates.md`, `networks/*.md`, `node/*.md`, `clients/*.md`, `integration.md`)
- Modify: `docs/decisions.md`

**Interfaces:**
- Produces: anchor `CTR-ACC-11` "The multi-key ERC-1271 contract account is named `SmartKeyAccount` (factory `SmartKeyAccountFactory`) in every chain family".

- [ ] **Step 1: Rename**

Run: `grep -rl 'SubjectAccount' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research' | xargs sed -i 's/SubjectAccountFactory/SmartKeyAccountFactory/g; s/SubjectAccount/SmartKeyAccount/g'`
Then add anchor `CTR-ACC-11` at the top of the *Smart account* section of `accounts.md` with one Transitional sentence: "Built code and non-EVM programs still use `SubjectAccount`; renamed in P4 (every family at once)." Register `CTR-ACC-11`; titles in `decisions.md` that say `SubjectAccount` are renamed by the same `sed` (check the alias index is regenerated by `--write`).

- [ ] **Step 2: Verify and commit**

Run the four checker commands (0 errors).
Run: `grep -rn 'SubjectAccount' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research'`
Expected: only the Transitional sentence of `CTR-ACC-11`.

```bash
git add -A docs
git commit -m "docs: SubjectAccount is SmartKeyAccount (T15)"
```

### Task 7: Merge `SCaaS-v2.md` into `docs/README.md` and complete it

**Files:**
- Modify: `docs/README.md` (82 lines; sections *Reading order* :8, *Map* :20, *Precedence* :33, *Status tags* :47, *Ids, aliases and history* :60, *Checks* :76)
- Delete: `docs/SCaaS-v2.md` (89 lines; sections *What SCaaS is* :6, *Who it is for* :26, *What it offers* :40, *Deployment shapes* :62, *How to start* :71)
- Modify: `scripts/docs_check.py` (`BUDGET` :31 and the no-anchor list :431), `docs/decisions.md` (`ARCH-POS-01` text :35), `docs/architecture.md` (:7), root `README.md` (:192, :732), `docs/history/README.md` if it links the file

**Interfaces:**
- Produces: `docs/README.md` is the single entry page: product introduction + doc map. Task 8 links it as "the introduction".

- [ ] **Step 1: New structure of `docs/README.md`**

Write `docs/README.md` with these sections, in order (no anchors `<a id=…>`: the page defines no rules — checker rule at `docs_check.py:431`):
1. `# SCaaS — SmartContract as a Service` and a 3-line lead (what it is, that this page is the entry point).
2. `## What SCaaS is` — from `SCaaS-v2.md` *What SCaaS is*, updated: contract families, the node, clients; the EVM token model in one paragraph (kinds `NONE`/`UNDERLYING` × confidential layer, features chosen at creation, link `CTR-TOK-21`, `CTR-TOK-22`).
3. `## Who it is for` — from `SCaaS-v2.md`, unchanged in substance.
4. `## What it offers` — from `SCaaS-v2.md`, each bullet ending with a link to its component doc (tokens → `contracts/token-wrappers.md`, gasless meta-tx → `contracts/metatx.md`, payments → `integration.md`, DEX → `contracts/dex.md`, confidential balances → `contracts/zether.md`, accounts → `contracts/accounts.md`, tender/asset suite, node mesh → `node/README.md`). Replace any v1/v2 names (`MetaToken`, `SubjectAccount`, tiers) by the folded names.
5. `## Deployment shapes` — from `SCaaS-v2.md`.
6. `## How to start` — from `SCaaS-v2.md`, plus "build and test: `smartcontracts/scripts/{build,test}.sh <family>`; docs check: `python3 scripts/docs_check.py check`".
7. `## Reading order`, `## Map`, `## Precedence`, `## Status tags`, `## Ids, aliases and history`, `## Checks` — the current sections, with every `SCaaS-v2.md` link removed (Reading order item 1 becomes "this page").

- [ ] **Step 2: Remove the file and its references**

`git rm docs/SCaaS-v2.md`. In `scripts/docs_check.py`: drop `'SCaaS-v2.md': 150` from `BUDGET`, set `'README.md': 250`, drop `'SCaaS-v2.md'` from the no-anchor tuple. In `decisions.md` `ARCH-POS-01` **Rule.** sentence "…[architecture.md](architecture.md), [SCaaS-v2.md](SCaaS-v2.md) and [README.md](README.md) are not normative" → "[architecture.md](architecture.md) and [README.md](README.md) are not normative". Fix the links in `architecture.md:7` and root `README.md:192`, `:732` to `docs/README.md`.
Run: `grep -rn 'SCaaS-v2' --include=*.md --include=*.py . | grep -v '/history/\|/reviews/'`
Expected: no output.

- [ ] **Step 3: Verify and commit**

Run: `python3 scripts/docs_check.py --write && python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check`
Expected: 0 errors; `README.md` under 250 lines.

```bash
git add -A docs scripts README.md
git commit -m "docs: README.md is the one entry page (SCaaS-v2.md merged into it)"
```

### Task 8: Complete `docs/architecture.md`

**Files:**
- Modify: `docs/architecture.md` (421 lines; *Positioning* :14, *Service model* :124, *Components* :196, *Node roles* :216, *Topology* :231, *Data flows* :285, *Trust model* :311, *Families* :347, *Economics* :355, *Data protection* :374, *Glossary* :394)
- Modify: `scripts/docs_check.py` (`BUDGET['architecture.md']` 450 → 900)

**Interfaces:**
- Consumes: the folded anchors of Tasks 1–6 (it links them, defines nothing).

- [ ] **Step 1: Components table is current**

Rewrite the EVM and Hedera rows of *Components* (:198–200): EVM row lists the token tree (`MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → kinds `NONE`, `UNDERLYING`, `NONE_ZETHER`, `UNDERLYING_ZETHER`), the libraries, `OpenFactory` (tokens + DEX), `OrderBookDex`, `MandateWallet`, `SmartKeyAccount`, `UniversalAccountRegistry`, Zether verifiers, `ZetherDisclosure`, `ZetherStatements`; status "BUILT: v1/v2 lines and `ZetherToken`; target tree SPECIFIED (P1–P5)". Hedera row: "no separate contracts; implementations deployed with `IS_HEDERA` (CTR-TOK-23)". Contents line at :9 lists the new sections of Steps 2–4.

- [ ] **Step 2: New section `## Contract layer` (after *Components*)**

Subsections, each a short explanation plus links, no rule restated:
- `### EVM token tree` — Mermaid `classDiagram` of spec §3 (bases, kinds, `ZetherLayer`, libraries as `<<library>>`), then a table *kind × valid features* (copy of the "Valid kinds" column of CTR-TOK-22, linked), then two sentences on why kinds are code and features are flags (size limit EIP-170, one code copy per feature).
- `### Meta-transactions` — `MetaTransaction` vs `MetaTransfer`, lanes, who pays gas (relayer, sponsor, receiver-pays), the allowlisted self-call; links `contracts/metatx.md`.
- `### Accounts and keys` — native accounts, Universal Account (registry, relayable registration), `SmartKeyAccount` (ERC-1271, many keys, guardian), `MandateWallet`; Mermaid `flowchart` of who signs for whom.
- `### Confidential balances` — public ↔ shielded paths (`zetherShield`, `zetherWrapShield`, `zetherUnshield`, `zetherUnshieldUnwrap`), verifier / registry / `ZetherDisclosure` / `ZetherStatements` around the token; Mermaid `flowchart LR`.
- `### Trading` — `TradeOrder` signed on the token, `OrderBookDex` (clone from the factory), `DexPuller`, exchange path to AMMs; advisory `isDex`.
- `### Non-EVM families` — table: family × meta-tx mechanism (`MetaCall`/`MetaTransfer`, native auth on Soroban, cells on TON …) × account model × DEX × confidential (none outside EVM); link `networks/README.md`.

- [ ] **Step 3: Replace *Data flows* bullets by sequence diagrams**

Keep the text bullets as one-line captions and add a Mermaid `sequenceDiagram` for each of: (1) client payment ERP → node → chain → feed; (2) gasless transfer through door A; (3) DEX order to settlement; (4) UA registration submitted by a relayer; (5) confidential: wrap-shield → multi-recipient transfer → unshield-unwrap; (6) disclosure by `SENDER_CP` checked off chain and through `ZetherDisclosure`. Participants named as in the component docs.

- [ ] **Step 4: Trust model and families**

*Trust model*: add a table "who can do what after deployment" — factory admin (register / deprecate implementations; cannot touch tokens), token roles per feature flag (CTR-TOK-22), DEX admin (four powers, CTR-DEX-03), auditor (reads `C_aud` only, threshold key CTR-ZTH-41), relayers (cannot change signed fields). *Families*: keep the paragraph, add a pointer to the new *Non-EVM families* table.

- [ ] **Step 5: Verify and commit**

Set `BUDGET['architecture.md'] = 900` in `scripts/docs_check.py`.
Run: `python3 scripts/docs_check.py --write && python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check`
Expected: 0 errors (C11 refuses ASCII art: every diagram is Mermaid).
Run: `grep -c '```mermaid' docs/architecture.md`
Expected: ≥ 12 (2 today + 1 tree + 3 layer diagrams + 6 sequences).

```bash
git add docs/architecture.md scripts/docs_check.py
git commit -m "docs: architecture.md gains the contract layer, sequence diagrams and the authority table"
```

### Task 9: Freeze the token-tree draft; TODO, HANDOFF, README; final sweep

**Files:**
- Move: `docs/superpowers/specs/2026-10-08-token-tree-design.md` → `docs/history/specs/`
- Modify: `TODO.md` (§00), `HANDOFF.md` (top section), root `README.md` (contract list)

- [ ] **Step 1: Freeze and re-plan the streams**

`git mv` the draft; set **Status:** to `ACCEPTED by the owner 2026-10-08 and folded; frozen here. Ids: T1/T10/T13 (kinds) → CTR-TOK-21, T2/T8 → CTR-TOK-22, T3/T13 (Hedera) → CTR-TOK-23, §4 → CTR-TOK-24, CTR-MTX-25, §7 → CTR-TOK-25, T11 → CTR-AS-17, CTR-ZTH-47, T12 → CTR-DEX-24, T4/T5 → CTR-ZTH-44, T6 → CTR-ZTH-45, CTR-PQZ-22, T14 → CTR-ZTH-46, T15 → CTR-ACC-11; T7/T9 need no rule.` In `TODO.md` §00 replace the MT-1…MT-9 order by the phase table of spec §9 (P1 = MT-1+MT-2+MT-3+MT-4 on the new tree, P2 = MT-5, P3 = MT-6, P4 = MT-7 + rename, P5 = MT-8/9), keeping each MT item's text as the phase's checklist and deleting what spec §8 deletes. In `HANDOFF.md` add a dated section (2026-10-08 evening): spec accepted, P0 done, next P1. In the root `README.md` replace the token class list by the four kinds and the flags line (the `docs/README.md` links were fixed in Task 7).

- [ ] **Step 2: Final sweep**

Run: `for id in CTR-TOK-02 CTR-AS-01 CTR-ZTH-10; do grep -rn "$id" docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research\|decisions.md'; done`
Expected: no link presents a superseded id as current (fix any hit to the new id).
Run: `grep -rn 'SubjectAccount\|META_SINGLE\|createTiered\|transferConfidential\b' docs --include=*.md | grep -v '^docs/history\|^docs/reviews\|^docs/research\|decisions.md' | grep -v -i 'transitional'`
Expected: no output.
Run: `python3 scripts/docs_check.py --write && python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check`
Expected: 0 errors.

- [ ] **Step 3: Commit**

```bash
git add -A docs TODO.md HANDOFF.md README.md
git commit -m "docs: freeze the token-tree design; TODO streams become phases P1-P5"
```

---

Plans for P1–P5 are written after P0 lands, one per phase, against the folded rules (`CTR-TOK-21…25`, `CTR-MTX-25`,
`CTR-AS-17`, `CTR-DEX-24`, `CTR-ZTH-37…47`, `CTR-ACC-11`).
