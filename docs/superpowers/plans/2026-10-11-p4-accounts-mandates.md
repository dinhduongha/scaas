# P4 — `SmartKeyAccount` and `MandateWallet` on `MetaTxBase`; `SubjectAccount` → `SmartKeyAccount` in every family — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** MT-7 and every TODO item tagged P4 (TODO.md §00 phase row P4, **P4 — MT-7**, MT-4 "SmartKeyAccount,
MandateWallet P4"): the multi-key ERC-1271 account renamed `SmartKeyAccount` (factory `SmartKeyAccountFactory`,
CTR-ACC-11) and moved onto the generic base (CTR-ACC-10, CTR-MTX-22): key management is a `MetaTransaction` signed by
the account itself (`from = address(this)`), allowlisted self-calls, the 2D lane nonce, fee mode `NONE`,
`mtxExecuteAsOwner` as the named builder, salted domain `("SCaaS SmartKeyAccount", "1", chainId, account, chain_uid)`
with `chain_uid` from the factory (MT-4); `MandateWallet` on the same base (CTR-ACC-06/07): the delegate's
`payUnderMandate` and epoch-bound `revoke(token, epoch)` and the owner's `setMandate`/`setPayee`/`revoke`/`execute` as
`MetaTransaction` self-calls, `mtxPayUnderMandate` / `mtxRevoke` / `mtxExecuteAsOwner` deriving their lanes, domain
`("SCaaS MandateWallet", "1", chainId, wallet, chain_uid)`, Hedera `mtxExecuteAsOwnerRaw` over the same digest
(NET-HED-03); the typed `OwnerCall` / `PayUnderMandate` / `RevokeMandate` line backed up in `smartcontracts/evm/legacy/p4/`
(owner: backup, not delete); the rename in every family that still says `SubjectAccount` (Solana's account type, the
Move comments); clientkeys' owner-call check on the salted `MetaTransaction`; KATs regenerated; deploy JSON keys
`smart_key_account_*`.

**Architecture:** `SmartKeyAccount is MetaTxBase, IERC1271` keeps the built account (keys, WebAuthn check, Merkle
batch, guardian recovery, linear storage) and replaces `executeAsOwner`/`OwnerCall`/`ownerNonce` by the base pipeline:
the base gains one hook, `MetaTxBase._selfSender()` (the `SelfSender` revert of step 1, a function now), which the
account overrides with nothing; its `_requireValidSignature` checks `from == this` through its own `isValidSignature`
(a static self-call) and everyone else through `SigCheck` (only `cancelNonce` can run for them). `onlySelf` reads
`_msgSender()`. The factory takes `chainUid` and passes it to `new SmartKeyAccount(chainUid)`; tokens and the DEX keep
computing the 400 k cap codehash from `SMART_KEY_ACCOUNT_IMPL`, which `Deploy.s.sol` sets to the new factory's
`IMPLEMENTATION` everywhere. `MandateWallet is MetaTxBase, IERC1271` keeps the built limits and adds `epoch[token]`;
`onlyOwner` and the delegate check read `_msgSender()`; one internal `_named(from, data, batch, nonce, validUntil, sig)`
builds the struct for the three named entries. `HederaMandateWallet` routes 64-byte signatures from accounts without
code to HIP-632 (`HederaAccountAuth.asView`, the tokens' CTR-TOK-23 rule) on every entry. Nothing in `scaas-node`
reads the account or the wallet (the node relays Odoo-built `call` jobs; the call table is P5), so the node changes
only its e2e (it pins the new deploy JSON keys).

**Tech Stack:** Solidity 0.8.37 (`osaka`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0, forge-std 1.16.2; Anchor 1.2.0 +
LiteSVM (Solana), Sui and Aptos CLIs (Move), soroban-sdk, cosmwasm, Tact + jest (TON); `clients/clientkeys`
(`node --test`); `scaas-node` e2e on anvil.

**Spec:** `docs/contracts/accounts.md` (CTR-ACC-01…05, CTR-ACC-08…11, §3, §3.1), `docs/contracts/mandates.md`
(CTR-ACC-06, CTR-ACC-07, NET-HED-03 paragraph, §1.1), `docs/contracts/metatx.md` (CTR-MTX-02, -15, -17…-19, -21, -22,
-25, §15 KATs, §16 transitional), `docs/networks/hedera.md` (NET-HED-03), `docs/networks/solana.md` (NET-SOL-05, -06,
-20), `docs/networks/{sui,aptos,soroban,ton,cosmos}.md` (each family's account names), `docs/clients/signers-clientkeys.md`
(CLI-SGN-05, -27, -33, -34), `docs/node/job-api.md` (call table), `docs/node/gateway.md` (NODE-GW-07); TODO.md §00 P4 row,
MT-4, MT-7, P1b note (c); HANDOFF.md (P3 session "Not done / next").

**Base:** `main` at `dc9d219` (P3 merged; 977 forge tests). Every code block below was applied task by task to a scratch
worktree from `main` (`dc9d219`) and run green: forge **993** (977 − 67 moved to `legacy/p4/` + 83), size gate 0 errors
after each task, Solana `cargo test` 42 (was 41), Sui 68, Aptos 105 + the entry-visibility check, Soroban 28, Cosmos 10,
TON 28, clientkeys 52 passed + 2 skipped (was 51 + 2), `scaas-node` clippy clean, e2e 4/4 and e2e_hedera 1/1, docs
checkers 0 errors and 0 fact misses, mutation probe 69/69 killed.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; worktree `.claude/worktrees/p4` on branch `p4-accounts` from `main`.
  forge in `smartcontracts/evm` of the worktree: `lib/` is not tracked — `mkdir lib`, copy
  `smartcontracts/evm/lib/forge-std` into it, symlink `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts`.
  clientkeys and TON: symlink `node_modules` from the main checkout (never `git add` it). Heavy commands only through
  `scripts/capped`, one at a time. `/usr/bin/grep`; in worktrees a hook blocks bare `git`: use `/usr/bin/git`. Rust:
  `CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/scaas-node/target` for the node.
- The family commands are the repo's own (`smartcontracts/scripts/test.sh <family>`, CI `.github/workflows/ci.yml`):
  `forge test`; size gate `forge build src --sizes --json > /tmp/sizes.json; python3 scripts/size_gate.py /tmp/sizes.json
  smartcontracts/evm/size-baseline.json`; `FOUNDRY_PROFILE=private7622 forge build`; `test.sh solana` (builds the SBF
  program first, LiteSVM loads `target/deploy/scaas.so`), `test.sh sui`, `test.sh aptos`, `test.sh soroban`,
  `test.sh cosmos`, `test.sh ton`; `npm test` in `clients/clientkeys`; in `scaas-node` `cargo clippy --all-targets -- -D
  warnings`, `cargo test --test e2e -- --ignored --test-threads=1` and `cargo test --test e2e_hedera -- --ignored` (run
  a full `forge build` first so the e2e's `forge script` does not compile under its timeout).
- Owner rules: superseded code goes to `smartcontracts/evm/legacy/p4/` by `git mv` (backup, never delete); code size is
  not a concern (Glamsterdam), the ratchet baseline records sizes; open questions stay open; doc-vs-code conflicts are
  ruled here (L1–L18), component docs say "controller ruling, pending the owner", never an L-id.
- Tests: compute anything that makes an external call (`mtxDigest`, `mtxTransferDigest`, `mandatePayLane`) **before**
  `vm.prank` / `vm.expectRevert`, or the cheatcode is consumed by that call. Every mutant of the probe (Task 5) has a
  named killer.
- Pages over their line budget (`docs_check.py` notes/warns) change by net ≤ 0 lines; `docs/history/` and
  `docs/decisions.md` are records (only `dropped-artifacts.tsv` gains rows).
- Commit trailer (both lines): `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01GBLbPyQuG5HXALewwBZ7Bb`. Never `git add claude-code-api.txt`.

## Review Focus

- **The account signs as itself, and only its keys do (CTR-ACC-10).** `from == address(this)` passes step 1 only on the
  account (`_selfSender` override); its signature is one of its keys (passkey or seed, Merkle batch allowed); a malformed
  signature is `MetaTxBadSignature`. Another signer's `MetaTransaction` runs as that signer, so every self-only function
  refuses it (`NotSelf`), and its `cancelNonce` moves only its own lane. `test_otherSignerIsNotTheAccount`,
  `test_owner_call_replay_expiry_and_foreign_key`, `test_namedBuilderIsMtxExecute`, `test_accountCancelsItsOwnLane`,
  `test_self_only_functions`; tokens still refuse `from = token` (`test_fromTheTokenItselfRefused`, existing).
- **Never zero keys, recovery adds after the delay (CTR-ACC-03).** `test_never_zero_keys`, `test_remove_unknown_index`,
  `test_rotate_passkey_to_new_passkey`, `test_guardian_recovery_after_delay` (one second early refused, exactly at
  `readyAt` accepted), `test_key_cancels_recovery`, `test_recovery_guards`, `test_no_guardian_no_recovery`.
- **`execute` cannot re-enter.** `test_executeCannotReenter` (self target and a contract that calls back `mtxExecute`),
  `test_owner_executes_and_cannot_reenter`.
- **The 400 k cap stays consistent (CTR-ACC-05).** The tokens and the DEX compute the clone codehash from
  `SMART_KEY_ACCOUNT_IMPL`; `Deploy.s.sol` passes the new factory's `IMPLEMENTATION` to `MetaToken`, `_deployTokenFactory`
  (NONE, the DEX, the Zether kinds); `test_cloneCodehashIsWhatTokensCap`, `ZetherDeploy.t` (`SMART_KEY_ACCOUNT_IMPL ==
  new SmartKeyAccountFactory(ZUID).IMPLEMENTATION()`), the existing token-side `test_erc1271Gets400kOnlyAsSmartKeyAccountClone`
  and the DeployBase `require(dexImpl.SMART_KEY_ACCOUNT_IMPL() == none.SMART_KEY_ACCOUNT_IMPL())`.
- **Mandate money rules (CTR-ACC-06).** Delegate only (`NotDelegate`), mandate live (`NoMandate`, `MandateExpired` at
  `expiry + 1`, not at `expiry`), payee per token, `0 < amount ≤ maxPerPayment`, the period total `≤ maxPerPeriod` with the
  roll-over at exactly `periodStart + periodSeconds`, `entryRef` once per wallet (also across lanes), a token answering
  false reverts everything. `test_per_payment_cap_and_zero`, `test_per_period_cap_and_rollover`, `test_expired_mandate`,
  `test_payee_not_allowed_and_removed`, `test_payee_is_per_token`, `test_entry_ref_pays_once`,
  `test_signer_must_be_the_delegate`, `test_new_delegate_voids_old_signatures`, `test_pay_failed_reverts_everything`.
- **Revocation epoch (CTR-ACC-07).** Every `setMandate` and revoke bumps `epoch[token]`; a public revoke signature from
  an earlier epoch is `StaleEpoch(current, signed)`; a current-epoch revoke works and its replay is the used lane.
  `test_revoke_signature_is_bound_to_its_epoch`, `test_delegate_signed_revoke_kills_it`,
  `test_owner_revoke_kills_it_and_bumps_the_epoch`, `test_only_the_delegate_revokes_by_signature`.
- **Allowlists, shapes, fee `NONE` only (CTR-MTX-19/22).** `test_allowlistPinned` (both), `test_staticShapes`,
  `test_unlistedSelectorsRefused`, `test_unlistedSelectorsAndShapes`, `test_feeModesRefused`,
  `test_feeModesAndSelfSender` (the wallet is not a self-signer).
- **Domains and vectors (CTR-ACC-11, MT-4, metatx.md §15).** `test_domainIsSaltedSmartKeyAccount`,
  `test_domainAndLanes`; forge KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`, `mandate_revoke_kat.json`
  (they really execute) read by clientkeys (`SmartKeyAccount owner call = forge KAT`, `MandateWallet pay and revoke =
  forge KATs`); `smart_key_account_create2.json` (formula unchanged).
- **Hedera (NET-HED-03).** ED25519 owner through HIP-632 on the same digest and lane, ERC-1271 stays ECDSA:
  `HederaMandateWalletTest` (4).
- **No orphaned consumer.** `scaas-node` reads neither the account nor the wallet; its e2e pins
  `smart_key_account_factory` / `_implementation` in the real deploy JSON. clientkeys' `checkOwnerCall` refuses the old
  shape (`OwnerCall`, domain `SCaaS SubjectAccount`, no salt).

## Rulings (docs vs code) and defaults taken

- **L1 — The self-signer hook.** CTR-ACC-10 says the account overrides "the `SelfSender` guard of tokens", which is
  inside the non-virtual `_checkEnvelope`. Ruled: step 1 calls `_selfSender()` when `from == address(this)`; the base's
  reverts `SelfSender()`, `SmartKeyAccount` overrides it with nothing. Cost 8 B per token (a revert-hook beat a
  `bool _selfSigns()` hook, 11 B); the ratchet baseline is raised by 8 B for the four token kinds.
- **L2 — How the account checks its own signature.** `_requireValidSignature(from == this)` calls its own
  `isValidSignature` by `staticcall`, so a malformed `(keyIndex, proof, sig)` is a `MetaTxBadSignature`, not an empty
  revert (one extra frame, ~2.6 k gas); any other `from` goes through `SigCheck`.
- **L3 — The account allowlist** (metatx.md CTR-MTX-19 lists `addKey`, `removeKey`, `rotateKey`, `setGuardian`,
  `execute`; CTR-ACC-03 cancels a recovery "through `mtxExecuteAsOwner(cancelRecovery)`"). Ruled: `cancelRecovery` is
  allowlisted too; with `cancelNonce` the list is seven, all `ABSOLUTE` (fee `NONE` only), static lengths 164/36/196/36/4,
  `execute` dynamic. The table in metatx.md gains `cancelRecovery`.
- **L4 — Names that stay.** `SubjectKey` (a key of the subject, not the account; clientkeys exports `passkeySubjectKey`
  / `secpSubjectKey`, CLI-SGN docs name them, the Odoo bundle uses them) and `KeyKind` keep their names; the frozen v1
  `MetaToken` keeps `SUBJECT_ACCOUNT_IMPL` and its comments (its ABI is the v1 line's until P5); the key-proof prefix
  `scaas-subject-key-proof-v1` is pinned with Odoo and stays.
- **L5 — Factory.** `SmartKeyAccountFactory(bytes32 chainUid)` (CTR-ACC-05, contracts/README CTR-GEN-05 table), plus a
  `chainUid()` view (the implementation's) so `Deploy.s.sol` gates it like every chain-bound contract. Salt, `predict`,
  idempotent `deploy` unchanged; `subject_account_create2.json` is renamed `smart_key_account_create2.json` (same
  numbers: the formula does not involve `chain_uid`).
- **L6 — No migration of deployed clones and wallets.** Clones of the old implementation keep their code (typed
  `OwnerCall`); tokens of a P4 deploy give the 400 k cap only to clones of the new implementation. A subject moves to a
  new account with the old `executeAsOwner(execute(token.transfer…))`; a payer redeploys its wallet with
  `<owner> <chain_uid>` and withdraws from the old one the same way. No chain in the e2e keeps both.
- **L7 — MandateWallet errors and lanes.** `NotDelegate` (new: `_msgSender()` is not the mandate's delegate) after
  `NoMandate`; the named builders read the delegate and revert `NoMandate` when there is none (instead of an opaque
  `MetaTxBadSignature`); `‖` in mandates.md is `abi.encodePacked` with the epoch as 8 bytes:
  `mandatePayLane(ref) = keccak256(abi.encodePacked("scaas.mandate.pay", ref))`,
  `mandateRevokeLane(token, e) = keccak256(abi.encodePacked("scaas.mandate.revoke", token, uint64 e))` (views named
  apart from the tokens' `payLane`, which has another prefix). The named builders sign mode 0, no relayer, no fee.
- **L8 — Epoch.** `epoch[token]` (`uint64`) bumps on every `setMandate` and every revoke, also an owner revoke of an
  absent mandate (as built it deleted and emitted); `revoke(token, e)` requires `e == epoch[token]`:
  `StaleEpoch(current, signed)`.
- **L9 — Events unchanged** (`MandateSet`, `MandateRevoked(token, by)` with `by = _msgSender()`, `PayeeSet`,
  `PaidUnderMandate`; the account's `KeyAdded` … `RecoveryCancelled`); `OwnerCallExecuted` goes (the base emits
  `MetaTransactionExecuted`). The epoch is read by `epoch(token)`.
- **L10 — The owner.** `onlyOwner` = `_msgSender() == owner` (direct, or signed through `mtxExecute` /
  `mtxExecuteAsOwner`); the wallet is not a self-signer (`from = wallet` is `SelfSender`); ERC-1271 answers for an ECDSA
  owner as built, so the owner still pays by hand with a `MetaTransfer` from the wallet.
- **L11 — Hedera.** `HederaMandateWallet._requireValidSignature` sends a 64-byte signature from an address without code
  to HIP-632 (`isAuthorizedRaw` over the same digest) on every entry; `mtxExecuteAsOwnerRaw` (NET-HED-03's name) is the
  owner builder under that name. ERC-1271 stays ECDSA (STATICCALL halts HIP-632). The v1 Hedera wallet test moves to
  `legacy/p4/test/hedera/`.
- **L12 — "Every family" (CTR-ACC-11 vs the family docs).** Code that says `SubjectAccount` is renamed in P4: the EVM
  line, Solana's `state::SmartKeyAccount` (with its Cargo description and comments; solana.md already says
  `SmartKeyAccount` PDA), the Sui and Aptos comments. Sui/Aptos `meta::Account<T>`, Soroban `scaas-account` (`Account`),
  the TON wallet and Cosmos (no account contract) keep the names their networks docs specify (decisions.md's "Why" of
  CTR-ACC-11 names "the Solana, Sui, Aptos and Soroban equivalents"; the normative family docs win; open question). A
  Move struct cannot be renamed by a package upgrade: that rename would ride the NM-SUI/NM-APT new packages.
- **L13 — Solana state.** Anchor's discriminator follows the type name (`sha256("account:SmartKeyAccount")[..8]`, pinned
  by `smart_key_account_discriminator_follows_the_name`). No migration: a deployed program is immutable (upgrade authority
  None, NET-SOL-20), so no `SubjectAccount` data meets the renamed code; the PDA seeds (`["acct", owner]`), the layout,
  the instructions and their account order are unchanged (the `subject` field names stay: they are the subject's PDA).
- **L14 — Deploy JSON.** `subject_account_factory` / `subject_account_implementation` become
  `smart_key_account_factory` / `smart_key_account_implementation` (one name, CTR-ACC-11). The node reads neither (its e2e
  asserts the new keys and the absence of the old); Odoo's seeding follows (bamboo-dms, TODO).
- **L15 — clientkeys.** `ownerCallTypedData` / `checkOwnerCall` take the signer's pinned `chainUid` and rebuild the
  account's `MetaTransaction` exactly as `mtxExecuteAsOwner` builds it (lane 0, mode 0, no fee) in the salted domain
  (CLI-SGN-05, CLI-SGN-33: a missing or different salt is refused); `metaTxTypedData` builds any `MetaTransaction` in a
  salted SCaaS domain (the mandate KATs check it). `checkPayment` stays the v1 token check (P5). The Odoo side issues the
  new owner call in bamboo-dms (TODO).
- **L16 — No node code.** The node relays `call` jobs with Odoo-built calldata and has no call table yet (NODE-JOB-20,
  P5): the renamed rows of job-api.md stay transitional until the release that deploys P4 contracts.
- **L17 — Size.** `SmartKeyAccount` 18,738 B, `SmartKeyAccountFactory` 1,250 B (init 20,842 B), `MandateWallet` 15,430 B,
  `HederaMandateWallet` 15,918 B (all under EIP-170); tokens +8 B (L1): baseline `NoUnderlyingToken` 22,986,
  `UnderlyingToken` 30,044, `NoUnderlyingZetherToken` 30,667, `UnderlyingZetherToken` 40,389.
- **L18 — Docs.** Transitional notes become built text with net ≤ 0 lines on budgeted pages; `decisions.md` and
  `docs/history/` stay records (four renamed tokens go to `dropped-artifacts.tsv` for the C7/facts ledger);
  `token-axes.svg` carries no P4 text (only `account-forms.svg` changes; both alt texts checked).

## Open questions (not blocking)

- **Agent mandates** (`docs/research/node-ai-agents.md` row c, not accepted by the owner, not built): several delegates
  per token, per-payee caps, a co-sign threshold, a gateway route for mandate payments. P4 keeps one delegate per
  token; the research's lazy answer (one wallet per payer and agent) works unchanged.
- **L12:** rename Sui/Aptos `meta::Account<T>` and Soroban `scaas-account` to `SmartKeyAccount` too (with the NM-*
  new packages), or keep the family names?
- **L6:** a runbook to move subjects and payers off accounts and wallets deployed before P4, if any chain has them.
- **L4:** rename `SubjectKey` (and the clientkeys exports) to an account-neutral name?
- ERC-7739 wrapping of 1271 digests stays rejected (accounts.md §3 documented limitation); the scoped receiver-fee key
  (§3.1) stays planned.
- `entryRef = 0` pays once per wallet like any other reference (as built): refuse it?

---
### Task 1: `SmartKeyAccount` on `MetaTxBase` (EVM), the rename, the `_selfSender` hook, the old account to `legacy/p4/`

**Model:** Opus, effort high (auth path of the account; the base hook touches every contract).

**Files:**
- Move (`git mv`): `smartcontracts/evm/src/account/SubjectAccount.sol`, `SubjectAccountFactory.sol` → `legacy/p4/src/account/`;
  `test/SubjectAccount.t.sol` → `legacy/p4/test/`; `test/vectors/subject_account_create2.json` → `test/vectors/smart_key_account_create2.json`
- Create: `src/account/SmartKeyAccount.sol`, `src/account/SmartKeyAccountFactory.sol`, `test/account/SmartKeyAccount.t.sol`,
  `test/account/AccountKat.t.sol`, `test/vectors/smart_key_account_kat.json` (written by the KAT test)
- Modify: `src/metatx/MetaTxBase.sol`, `src/metatx/MetaTokenBase.sol` (comment), `script/Deploy.s.sol`,
  `test/zether/ZetherDeploy.t.sol`, `size-baseline.json`, `legacy/README.md`

**Interfaces:** Produces `MetaTxBase._selfSender()` (L1); `SmartKeyAccount(bytes32 chainUid)` with `initialize(SubjectKey,
address)`, `isValidSignature`, `mtxExecuteAsOwner(bytes,uint256,uint256,bytes)`, `addKey`, `removeKey`, `rotateKey`,
`setGuardian`, `cancelRecovery`, `execute` (self-only, allowlisted), `initiateRecovery`, `completeRecovery`, views `keyAt`,
`keyIdOf`, `batchLeaf`, `hasKey`, `keyCount`, `nextKeyIndex`, `guardian`, `pendingRecovery`, `recoveryReadyAt`,
`RECOVERY_DELAY`, `FACTORY`, and the base's `mtxExecute`, `mtxBatch`, `cancelNonce`, `mtxNonce`, `mtxDigest`,
`mtxSelectors`, `chainUid`, `supportedModes`, `eip712Domain`; `SmartKeyAccountFactory(bytes32 chainUid)` with
`IMPLEMENTATION`, `chainUid()`, `salt`, `predict`, `deploy`; `MtxKatBase` (test helper reused by Task 2); deploy JSON keys
`smart_key_account_factory`, `smart_key_account_implementation` (L14).

- [ ] **Step 1: Worktree** (Global Constraints), then move the built line:

```bash
cd smartcontracts/evm
mkdir -p legacy/p4/src/account legacy/p4/test test/account
/usr/bin/git mv src/account/SubjectAccount.sol src/account/SubjectAccountFactory.sol legacy/p4/src/account/
/usr/bin/git mv test/SubjectAccount.t.sol legacy/p4/test/
/usr/bin/git mv test/vectors/subject_account_create2.json test/vectors/smart_key_account_create2.json
```

- [ ] **Step 2: The base hook, the comment, the deploy script, the Zether deploy test, the baseline, the legacy note** (apply):

```diff
diff --git a/smartcontracts/evm/script/Deploy.s.sol b/smartcontracts/evm/script/Deploy.s.sol
index c9d0212..de68281 100644
--- a/smartcontracts/evm/script/Deploy.s.sol
+++ b/smartcontracts/evm/script/Deploy.s.sol
@@ -6,7 +6,7 @@ import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
 import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
 import {MetaToken} from "../src/metatx/MetaToken.sol";
 import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
-import {SubjectAccountFactory} from "../src/account/SubjectAccountFactory.sol";
+import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
 import {SCaaSDexV1} from "../src/dex/SCaaSDexV1.sol";
 import {DeployBase} from "./DeployBase.sol";
 
@@ -28,7 +28,8 @@ contract Deploy is DeployBase {
         _setup();
         vm.startBroadcast(pk);
         OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
-        SubjectAccountFactory accounts = new SubjectAccountFactory{salt: salt}();
+        SmartKeyAccountFactory accounts = new SmartKeyAccountFactory{salt: salt}(uid);
+        _gate(address(accounts));
         MetaToken impl = new MetaToken{salt: salt}(address(factory), accounts.IMPLEMENTATION());
         if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
         _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
@@ -47,8 +48,8 @@ contract Deploy is DeployBase {
         vm.serializeAddress(k, "factory", address(factory));
         vm.serializeAddress(k, "implementation", address(impl));
         vm.serializeAddress(k, "dex", address(dex));
-        vm.serializeAddress(k, "subject_account_factory", address(accounts));
-        vm.serializeAddress(k, "subject_account_implementation", accounts.IMPLEMENTATION());
+        vm.serializeAddress(k, "smart_key_account_factory", address(accounts));
+        vm.serializeAddress(k, "smart_key_account_implementation", accounts.IMPLEMENTATION());
         vm.serializeAddress(k, "scaas_dex", address(scaasDex));
         string memory out = vm.serializeAddress(k, "demo_token", demo);
         vm.createDir("./deployments", true);
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index 1ea808f..c6230f9 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,7 +1,7 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
-  "NoUnderlyingToken": 22978,
-  "UnderlyingToken": 30036,
-  "NoUnderlyingZetherToken": 30659,
-  "UnderlyingZetherToken": 40381
+  "NoUnderlyingToken": 22986,
+  "UnderlyingToken": 30044,
+  "NoUnderlyingZetherToken": 30667,
+  "UnderlyingZetherToken": 40389
 }
diff --git a/smartcontracts/evm/src/metatx/MetaTokenBase.sol b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
index 2c6ae9e..f4296d0 100644
--- a/smartcontracts/evm/src/metatx/MetaTokenBase.sol
+++ b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
@@ -29,7 +29,7 @@ abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IER
 
     address public immutable FACTORY;
     address private immutable _SELF;
-    /// @notice SmartKeyAccount implementation of this chain (built: `SubjectAccount`, renamed in P4; 0 = none). Only its EIP-1167 clones get 400k gas for
+    /// @notice SmartKeyAccount implementation of this chain (0 = none). Only its EIP-1167 clones get 400k gas for
     ///         ERC-1271; every other contract wallet 50k.
     address public immutable SMART_KEY_ACCOUNT_IMPL;
     bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;
diff --git a/smartcontracts/evm/src/metatx/MetaTxBase.sol b/smartcontracts/evm/src/metatx/MetaTxBase.sol
index a0c7707..31fc23e 100644
--- a/smartcontracts/evm/src/metatx/MetaTxBase.sol
+++ b/smartcontracts/evm/src/metatx/MetaTxBase.sol
@@ -165,7 +165,7 @@ abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
         }
         uint256 expected = _mtxStorage().nonce[from][batch];
         if (expected != nonce) revert MetaTxBadNonce(expected, nonce);
-        if (from == address(this)) revert SelfSender();
+        if (from == address(this)) _selfSender();
     }
 
     /// @dev Step 4: consume the lane's current nonce (call after `_checkEnvelope` passed).
@@ -233,6 +233,12 @@ abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
         return SigCheck.ERC1271_GAS;
     }
 
+    /// @notice Step 1 for `from == address(this)`: the `SelfSender` guard by default; `SmartKeyAccount`, which signs its
+    ///         own `MetaTransaction`s and checks them against its own key set, overrides it with nothing (CTR-ACC-10).
+    function _selfSender() internal pure virtual {
+        revert SelfSender();
+    }
+
     /// @notice The envelope binding a proof inside the self-call carries (CTR-ZTH-34): every envelope field except
     ///         `data`. 0 (none) by default; a confidential token returns its own (Zether, and PQZ with its own tag).
     ///         Step 5 writes it only when non-zero, which is safe only while an override is never 0 or always 0: one
diff --git a/smartcontracts/evm/test/vectors/smart_key_account_create2.json b/smartcontracts/evm/test/vectors/smart_key_account_create2.json
new file mode 100644
index 0000000..2d2e040
--- /dev/null
+++ b/smartcontracts/evm/test/vectors/smart_key_account_create2.json
@@ -0,0 +1,10 @@
+{
+  "note": "Fixed factory/implementation addresses (any). first key = SECP256K1(vm.addr(0x5EED)), guardian 0x...6A2D. Pinned by test/account/SmartKeyAccount.t.sol test_pinned_create2_vector (SubjectAccount.t.sol before P4); the same numbers are checked by Odoo (blockchain.subject.account) and clientkeys.",
+  "deployer": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
+  "factory": "0x7544c919C95986C97C93fb0F7e95286bb25E9591",
+  "implementation": "0xa919244A0b93635Efc9942A8863108d0d2354FA1",
+  "seedPrivateKey": "0x5eed",
+  "guardian": "0x0000000000000000000000000000000000006A2D",
+  "salt": "0x38578a35be68ec1a8ef8de88a7df8d8ce1d54e3a9a6a979e19d61f5a497a1956",
+  "account": "0x6395d2b970a69eb54996207494cc4Ec92732310e"
+}
diff --git a/smartcontracts/evm/test/zether/ZetherDeploy.t.sol b/smartcontracts/evm/test/zether/ZetherDeploy.t.sol
index 45d0b6d..fc5b72e 100644
--- a/smartcontracts/evm/test/zether/ZetherDeploy.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherDeploy.t.sol
@@ -11,7 +11,7 @@ import {UniversalAccountRegistry} from "../../src/registry/UniversalAccountRegis
 import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
 import {ZetherStatements} from "../../src/zether/ZetherStatements.sol";
 import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
-import {SubjectAccountFactory} from "../../src/account/SubjectAccountFactory.sol";
+import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
 import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
 import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
 import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
@@ -33,7 +33,7 @@ contract DeployHarness is DeployBase {
 contract ZetherDeployTest is Test {
     /// EIP-7825 (Osaka): the per-transaction gas cap.
     uint256 constant TX_GAS_CAP = 1 << 24;
-    address ska = new SubjectAccountFactory().IMPLEMENTATION();
+    address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
 
     function _at(DeployHarness h, bytes memory initCode) internal pure returns (address) {
         return vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(initCode), address(h));
diff --git a/smartcontracts/evm/legacy/README.md b/smartcontracts/evm/legacy/README.md
index c17a962..fcfa7c1 100644
--- a/smartcontracts/evm/legacy/README.md
+++ b/smartcontracts/evm/legacy/README.md
@@ -16,3 +16,6 @@ Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`,
   own underlying) with their tests (`ZetherToken.t`, `ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherGate.t` and the
   fixture), as they stood on `main` before P3 replaced them by the `*_ZETHER` kinds; not built. Nothing in the node or
   the e2e read them. `OpenFactoryV1` keeps its `ZETHER` kind (mock-tested) until the v1 line moves (P5).
+- `p4/`: the built `SubjectAccount` and `SubjectAccountFactory` (typed `OwnerCall`, own nonce, domain `SCaaS SubjectAccount`
+  without salt) and their test `SubjectAccount.t.sol`, as they stood on `main` before P4 put `SmartKeyAccount` on
+  `MetaTxBase` (CTR-ACC-10, CTR-ACC-11); not built. Clones deployed from them keep working with their own code.
```
- [ ] **Step 3: Create `src/account/SmartKeyAccount.sol`:**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

enum KeyKind {
    NONE,           // 0: empty or removed slot
    P256_WEBAUTHN,  // 1: passkey: (x, y) P-256 + rpIdHash + originHash
    SECP256K1       // 2: seed-derived key: x = address (right-aligned), the rest 0
}

/// @dev One authorised key of the subject. `keyId = keccak256(abi.encode(key))`.
struct SubjectKey {
    KeyKind kind;
    bytes32 x;
    bytes32 y;
    bytes32 rpIdHash;    // sha256(rpId): the first 32 bytes of authenticatorData
    bytes32 originHash;  // keccak256(origin): the "origin" value of clientDataJSON
}

/// @title The multi-key ERC-1271 account of one subject on one EVM chain (CTR-ACC-09…11), on `MetaTxBase`.
/// @notice ERC-1271 for tokens and the DEX: `isValidSignature(digest, abi.encode(uint256 keyIndex, bytes32[] proof,
///         bytes sig))` (CTR-ACC-02): an empty `proof` signs the digest, a non-empty one a Merkle root whose leaf is
///         `batchLeaf(digest)`; P-256 `sig = abi.encode(authenticatorData, clientDataJSON, r, s)` with challenge =
///         base64url(message), secp256k1 `sig` = 65-byte ECDSA (low-s) over the raw message.
///
///         Key management is a `MetaTransaction` signed by the account itself (CTR-ACC-10): `from = address(this)`
///         (its passkeys have no address), checked against its own key set, domain `("SCaaS SmartKeyAccount", "1",
///         chainId, account, chain_uid)`, the 2D lane nonce, fee mode `NONE`. `addKey`, `removeKey`, `rotateKey`,
///         `setGuardian`, `cancelRecovery` and `execute` are allowlisted self-calls, `onlySelf`. `mtxExecuteAsOwner` is
///         the named builder of that `MetaTransaction` on lane 0. Guardian recovery adds a key after `RECOVERY_DELAY`
///         (CTR-ACC-03); the account never has zero keys. No owner or admin: the factory only initialises.
contract SmartKeyAccount is MetaTxBase, IERC1271 {
    uint256 public constant RECOVERY_DELAY = 2 days;
    bytes4 private constant _INVALID = 0xffffffff;
    uint8 private constant _FLAG_UP = 0x01;
    uint8 private constant _FLAG_UV = 0x04;

    address public immutable FACTORY;

    bool private _initialized;
    mapping(uint256 index => SubjectKey) private _keys;
    mapping(bytes32 keyId => bool) public hasKey;
    uint256 public keyCount;
    uint256 public nextKeyIndex;
    address public guardian;
    bytes32 public pendingRecovery;   // keyId of the key the guardian wants to add
    uint256 public recoveryReadyAt;

    event KeyAdded(uint256 indexed index, KeyKind kind, bytes32 indexed keyId);
    event KeyRemoved(uint256 indexed index, bytes32 indexed keyId);
    event GuardianSet(address indexed guardian);
    event RecoveryInitiated(bytes32 indexed keyId, uint256 readyAt);
    event RecoveryCancelled(bytes32 indexed keyId);

    error NotFactory();
    error AlreadyInitialized();
    error NotSelf();
    error NotGuardian();
    error BadKey();
    error DuplicateKey();
    error NoSuchKey(uint256 index);
    error LastKey();
    error CallFailed(bytes reason);
    error NoRecovery();
    error RecoveryNotReady(uint256 readyAt);

    /// @dev Inside the one self-call of `mtxExecute` the sender is the signer; only the account itself passes.
    modifier onlySelf() {
        if (_msgSender() != address(this)) revert NotSelf();
        _;
    }

    /// @dev Runs once, on the implementation, deployed by the factory; locks the implementation.
    constructor(bytes32 chainUid_) MetaTxBase("SCaaS SmartKeyAccount", chainUid_) {
        FACTORY = msg.sender;
        _initialized = true;
    }

    /// @notice Factory only, in the same transaction as the clone (CTR-ACC-01): no front-run window.
    function initialize(SubjectKey calldata firstKey, address guardian_) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        _addKey(firstKey);
        if (guardian_ != address(0)) {
            guardian = guardian_;
            emit GuardianSet(guardian_);
        }
    }

    receive() external payable {}

    // ------------------------------------------------------------------ ERC-1271

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _isValid(hash, signature) ? IERC1271.isValidSignature.selector : _INVALID;
    }

    // ------------------------------------------------------------------ signed by the account (CTR-ACC-10)

    /// @notice Named builder (CTR-MTX-21): the `MetaTransaction{from: this, data, batch: 0, nonce, validUntil}`, no
    ///         relayer or fee binding, run through the base pipeline. Same digest and lane as `mtxExecute`.
    function mtxExecuteAsOwner(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m;
        m.from = address(this);
        m.data = data;
        m.nonce = nonce;
        m.validUntil = validUntil;
        return _execute(m, signature);
    }

    function addKey(SubjectKey calldata key) external nonReentrant onlySelf returns (uint256) {
        return _addKey(key);
    }

    function removeKey(uint256 index) external nonReentrant onlySelf {
        _removeKey(index);
    }

    /// @notice Add the new key, then remove the old one, atomically.
    function rotateKey(uint256 index, SubjectKey calldata key) external nonReentrant onlySelf returns (uint256 added) {
        added = _addKey(key);
        _removeKey(index);
    }

    /// @notice A new guardian also cancels the old guardian's pending recovery.
    function setGuardian(address guardian_) external nonReentrant onlySelf {
        guardian = guardian_;
        _clearRecovery();
        emit GuardianSet(guardian_);
    }

    function cancelRecovery() external nonReentrant onlySelf {
        if (pendingRecovery == bytes32(0)) revert NoRecovery();
        _clearRecovery();
    }

    /// @notice The subject does what it wants with its own assets; tokens still apply their own rules (no EOA
    ///         approve). Runs under the guard, so the target cannot re-enter the account.
    function execute(address target, uint256 value, bytes calldata data)
        external nonReentrant onlySelf returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    // ------------------------------------------------------------------ guardian (CTR-ACC-03)

    /// @notice Called again while pending: replaces the key and restarts the clock.
    function initiateRecovery(SubjectKey calldata key) external {
        if (msg.sender != guardian || guardian == address(0)) revert NotGuardian();
        _checkKey(key);
        bytes32 id = keyIdOf(key);
        pendingRecovery = id;
        recoveryReadyAt = block.timestamp + RECOVERY_DELAY;
        emit RecoveryInitiated(id, recoveryReadyAt);
    }

    /// @notice Anyone, after the delay. ADDS the key; no key is removed (the subject removes the lost key with the
    ///         new one).
    function completeRecovery(SubjectKey calldata key) external returns (uint256 index) {
        bytes32 id = pendingRecovery;
        if (id == bytes32(0) || keyIdOf(key) != id) revert NoRecovery();
        if (block.timestamp < recoveryReadyAt) revert RecoveryNotReady(recoveryReadyAt);
        pendingRecovery = bytes32(0);
        recoveryReadyAt = 0;
        index = _addKey(key);
    }

    // ------------------------------------------------------------------ views

    function keyAt(uint256 index) external view returns (SubjectKey memory) {
        return _keys[index];
    }

    function keyIdOf(SubjectKey calldata key) public pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }

    /// @notice Merkle leaf of one digest of a batch: `keccak256(keccak256(0x00 ‖ digest))`.
    function batchLeaf(bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes1(0x00), digest))));
    }

    /// @notice The allowlist (CTR-MTX-19): the base `cancelNonce`, then the six self-only functions; fee `NONE` only.
    function mtxSelectors()
        public pure override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](7);
        c = new uint8[](7);
        a = new uint8[](7);
        s[0] = IMetaTx.cancelNonce.selector;
        s[1] = SmartKeyAccount.addKey.selector;
        s[2] = SmartKeyAccount.removeKey.selector;
        s[3] = SmartKeyAccount.rotateKey.selector;
        s[4] = SmartKeyAccount.setGuardian.selector;
        s[5] = SmartKeyAccount.cancelRecovery.selector;
        s[6] = SmartKeyAccount.execute.selector;
        for (uint256 i; i < 7; ++i) c[i] = FEE_CLASS_ABSOLUTE;
    }

    // ------------------------------------------------------------------ MetaTxBase hooks

    /// @dev Static lengths: a key is five words; `execute` has dynamic `data`.
    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == SmartKeyAccount.addKey.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 164);
        if (sel == SmartKeyAccount.removeKey.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SmartKeyAccount.rotateKey.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 196);
        if (sel == SmartKeyAccount.setGuardian.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SmartKeyAccount.cancelRecovery.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        if (sel == SmartKeyAccount.execute.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    /// @dev The account is the signer of its own key management (CTR-ACC-10).
    function _selfSender() internal pure override {}

    /// @dev `from == this`: one of the account's keys, through its own `isValidSignature` (a static self-call, so a
    ///      malformed signature is a `MetaTxBadSignature`, not an empty revert); anyone else (only `cancelNonce` on
    ///      their own lane runs for them): EOA or ERC-1271 through `SigCheck`.
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (from != address(this)) return super._requireValidSignature(from, digest, sig);
        (bool ok, bytes memory ret) =
            address(this).staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, sig)));
        if (!ok || ret.length != 32 || bytes4(ret) != IERC1271.isValidSignature.selector) revert MetaTxBadSignature();
    }

    // ------------------------------------------------------------------ private

    function _addKey(SubjectKey calldata key) private returns (uint256 index) {
        _checkKey(key);
        bytes32 id = keyIdOf(key);
        if (hasKey[id]) revert DuplicateKey();
        hasKey[id] = true;
        index = nextKeyIndex++;
        _keys[index] = key;
        keyCount += 1;
        emit KeyAdded(index, key.kind, id);
    }

    function _removeKey(uint256 index) private {
        SubjectKey storage k = _keys[index];
        if (k.kind == KeyKind.NONE) revert NoSuchKey(index);
        if (keyCount == 1) revert LastKey();
        bytes32 id = keccak256(abi.encode(k));
        delete hasKey[id];
        delete _keys[index];
        keyCount -= 1;
        emit KeyRemoved(index, id);
    }

    function _clearRecovery() private {
        bytes32 id = pendingRecovery;
        if (id != bytes32(0)) {
            pendingRecovery = bytes32(0);
            recoveryReadyAt = 0;
            emit RecoveryCancelled(id);
        }
    }

    function _checkKey(SubjectKey calldata k) private pure {
        if (k.kind == KeyKind.P256_WEBAUTHN) {
            if (!P256.isValidPublicKey(k.x, k.y) || k.rpIdHash == 0 || k.originHash == 0) revert BadKey();
        } else if (k.kind == KeyKind.SECP256K1) {
            if (k.x == 0 || uint256(k.x) >> 160 != 0 || k.y != 0 || k.rpIdHash != 0 || k.originHash != 0) {
                revert BadKey();
            }
        } else {
            revert BadKey();
        }
    }

    function _isValid(bytes32 digest, bytes calldata signature) private view returns (bool) {
        (uint256 index, bytes32[] memory proof, bytes memory sig) =
            abi.decode(signature, (uint256, bytes32[], bytes));
        SubjectKey storage k = _keys[index];
        bytes32 message = proof.length == 0 ? digest : MerkleProof.processProof(proof, batchLeaf(digest));
        KeyKind kind = k.kind;
        if (kind == KeyKind.SECP256K1) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(message, sig);
            return err == ECDSA.RecoverError.NoError && rec == address(uint160(uint256(k.x)));
        }
        if (kind == KeyKind.P256_WEBAUTHN) return _verifyWebAuthn(k, message, sig);
        return false;
    }

    /// @dev WebAuthn assertion (CTR-ACC-08): rpIdHash, flags UP and UV, clientDataJSON, then P-256 over
    ///      `sha256(authenticatorData ‖ sha256(clientDataJSON))`. `P256.verify` refuses s > n/2 (clients normalise).
    function _verifyWebAuthn(SubjectKey storage k, bytes32 message, bytes memory sig) private view returns (bool) {
        (bytes memory authData, bytes memory clientData, bytes32 r, bytes32 s) =
            abi.decode(sig, (bytes, bytes, bytes32, bytes32));
        if (authData.length < 37) return false;
        bytes32 rpIdHash;
        assembly ("memory-safe") { rpIdHash := mload(add(authData, 32)) }
        if (rpIdHash != k.rpIdHash) return false;
        if (uint8(authData[32]) & (_FLAG_UP | _FLAG_UV) != (_FLAG_UP | _FLAG_UV)) return false;
        if (!_clientDataOk(clientData, message, k.originHash)) return false;
        bytes32 h = sha256(abi.encodePacked(authData, sha256(clientData)));
        return P256.verify(h, r, s, k.x, k.y);
    }

    /// @dev The bounded WebAuthn L3 §5.8.1.2 check: the fixed prefix with type and challenge, the origin up to the
    ///      next `"`, then exactly one of: `}` as the last character (Safari, L2), or `,"crossOrigin":false` followed
    ///      by `}` or `,` (Chrome, Firefox, L3). Everything else (`crossOrigin:true`, a member before crossOrigin,
    ///      whitespace) fails closed.
    function _clientDataOk(bytes memory cd, bytes32 challenge, bytes32 originHash) private pure returns (bool) {
        bytes memory prefix = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '","origin":"');
        uint256 p = prefix.length;
        uint256 n = cd.length;
        if (n < p + 2 || _hashSlice(cd, 0, p) != keccak256(prefix)) return false;
        uint256 end = p;
        while (end < n && cd[end] != '"') ++end;
        if (end + 1 >= n || _hashSlice(cd, p, end - p) != originHash) return false;
        if (cd[end + 1] == "}") return end + 2 == n;
        bytes memory crossFalse = ',"crossOrigin":false';
        uint256 after_ = end + 1 + crossFalse.length;
        if (after_ >= n || _hashSlice(cd, end + 1, crossFalse.length) != keccak256(crossFalse)) return false;
        if (cd[after_] == "}") return after_ + 1 == n;
        return cd[after_] == ",";
    }

    function _hashSlice(bytes memory b, uint256 start, uint256 len) private pure returns (bytes32 h) {
        assembly ("memory-safe") { h := keccak256(add(add(b, 32), start), len) }
    }
}
```
- [ ] **Step 4: Create `src/account/SmartKeyAccountFactory.sol`:**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {SmartKeyAccount, SubjectKey} from "./SmartKeyAccount.sol";

/// @title Permissionless, predictable `SmartKeyAccount` deploys (CTR-ACC-01, CTR-ACC-05).
/// @notice EIP-1167 clones by CREATE2, salt = `keccak256(abi.encode(firstKey, guardian))`: whoever deploys gets the
///         same account for the same key and guardian, and a repeated `deploy` returns that address instead of
///         reverting. The guardian is in the salt, or the first deployer would choose it. The factory takes the
///         chain's `chain_uid` and passes it to `new SmartKeyAccount(chainUid)` (the account's salted domain), so the
///         implementation, and every account, has a different address on each chain.
contract SmartKeyAccountFactory {
    address public immutable IMPLEMENTATION;

    event AccountDeployed(address indexed account, bytes32 indexed firstKeyId, address guardian);

    constructor(bytes32 chainUid_) {
        IMPLEMENTATION = address(new SmartKeyAccount(chainUid_));
    }

    /// @notice The `chain_uid` of the accounts (the deploy gate reads it, CTR-GEN-05).
    function chainUid() external view returns (bytes32) {
        return SmartKeyAccount(payable(IMPLEMENTATION)).chainUid();
    }

    function salt(SubjectKey calldata firstKey, address guardian) public pure returns (bytes32) {
        return keccak256(abi.encode(firstKey, guardian));
    }

    function predict(SubjectKey calldata firstKey, address guardian) public view returns (address) {
        return Clones.predictDeterministicAddress(IMPLEMENTATION, salt(firstKey, guardian));
    }

    function deploy(SubjectKey calldata firstKey, address guardian) external returns (address account) {
        account = predict(firstKey, guardian);
        if (account.code.length != 0) return account;
        Clones.cloneDeterministic(IMPLEMENTATION, salt(firstKey, guardian));
        SmartKeyAccount(payable(account)).initialize(firstKey, guardian);
        emit AccountDeployed(account, keccak256(abi.encode(firstKey)), guardian);
    }
}
```
- [ ] **Step 5: Create `test/account/SmartKeyAccount.t.sol`** (48 tests: every case of the 47 built ones ported, some merged, onto a token of the new tree and the pipeline, plus the allowlist, shapes, fee, domain, batch, relayer, re-entry and other-signer cases):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {V2Fixture, UID_, noneInit} from "../v2/helpers/V2Fixture.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";

/// Software authenticator: a fixed P-256 key, authenticatorData/clientDataJSON in the WebAuthn format (L3 §5.8.1.1),
/// the signature normalised to low-s as clients do.
abstract contract WebAuthnSoft is V2Fixture {
    uint256 internal constant N = P256.N;
    string internal constant RP_ID = "pay.example.com";
    string internal constant ORIGIN = "https://pay.example.com";
    string internal constant TAIL = ',"crossOrigin":false}';

    struct Assertion {
        bytes authData;
        bytes clientData;
        bytes32 r;
        bytes32 s;
    }

    function _passkey(uint256 pk) internal pure returns (SubjectKey memory) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        return SubjectKey(KeyKind.P256_WEBAUTHN, bytes32(x), bytes32(y), sha256(bytes(RP_ID)), keccak256(bytes(ORIGIN)));
    }

    function _seedKey(uint256 pk) internal pure returns (SubjectKey memory) {
        return SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(pk)))), 0, 0, 0);
    }

    function _clientData(bytes32 challenge, string memory origin, string memory tail)
        internal pure returns (bytes memory)
    {
        return abi.encodePacked('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)),
                                '","origin":"', origin, '"', tail);
    }

    function _signAssertion(uint256 pk, bytes memory authData, bytes memory clientData)
        internal pure returns (Assertion memory a)
    {
        bytes32 h = sha256(abi.encodePacked(authData, sha256(clientData)));
        (bytes32 r, bytes32 s) = vm.signP256(pk, h);
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        a = Assertion(authData, clientData, r, s);
    }

    function _assertion(uint256 pk, bytes32 message) internal pure returns (Assertion memory) {
        return _signAssertion(pk, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
                              _clientData(message, ORIGIN, TAIL));
    }

    function _enc(Assertion memory a) internal pure returns (bytes memory) {
        return abi.encode(a.authData, a.clientData, a.r, a.s);
    }

    function _sig(uint256 index, bytes memory inner) internal pure returns (bytes memory) {
        return abi.encode(index, new bytes32[](0), inner);
    }

    function _pk(uint256 index, uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        return _sig(index, _enc(_assertion(pk, message)));
    }

    function _ecdsa(uint256 index, uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, message);
        return _sig(index, abi.encodePacked(r, s, v));
    }
}

/// Calls back into the account from inside its `execute` (the guard must refuse it).
contract ReenterAccount {
    function hit(SmartKeyAccount a, MetaTxLib.MetaTransaction calldata m, bytes calldata sig) external {
        a.mtxExecute(m, sig);
    }
}

/// CTR-ACC-01…05, CTR-ACC-08…11 on `MetaTxBase` (CTR-MTX-22): WebAuthn and batch checks (ported from the built
/// `SubjectAccount` tests, `legacy/p4/`), payments through a token of the new tree, key management as a
/// `MetaTransaction` signed by the account itself, recovery, the factory, the allowlist and the pipeline.
contract SmartKeyAccountTest is WebAuthnSoft {
    uint256 internal constant PASSKEY = 0xC0FFEE1234567890;
    uint256 internal constant PASSKEY2 = 0xBADC0DE5;
    uint256 internal constant SEED = 0x5EED;
    address internal constant GUARDIAN = address(0x6A2D);
    address internal shop = address(0x5409);
    bytes4 internal constant MAGIC = IERC1271.isValidSignature.selector;

    SmartKeyAccountFactory internal fac;
    SmartKeyAccount internal acct;
    NoUnderlyingToken internal t;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        fac = new SmartKeyAccountFactory(UID_);
        NoUnderlyingToken impl = new NoUnderlyingToken(address(this), fac.IMPLEMENTATION(), UID_, false);
        t = NoUnderlyingToken(_clone(address(impl), address(this), new address[](0),
            abi.encode(noneInit("Points", "PTS", 0, 0, address(this), address(this)))));
        acct = SmartKeyAccount(payable(fac.deploy(_passkey(PASSKEY), GUARDIAN)));
        t.mint(address(acct), 1000);
    }

    function _valid(SmartKeyAccount a, bytes32 digest, bytes memory sig) internal view returns (bool) {
        return a.isValidSignature(digest, sig) == MAGIC;
    }

    /// The account's own `MetaTransaction` on lane 0 (what `mtxExecuteAsOwner` builds).
    function _own(bytes memory data, uint256 nonce) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m.from = address(acct);
        m.data = data;
        m.nonce = nonce;
        m.validUntil = block.timestamp + 300;
    }

    /// Signs the account's next lane-0 call with key `index` (passkey or seed) and submits it by `mtxExecuteAsOwner`.
    function _ownerCall(bytes memory data, uint256 index, uint256 pk, bool passkey) internal returns (bytes memory) {
        MetaTxLib.MetaTransaction memory m = _own(data, acct.mtxNonce(address(acct), 0));
        bytes32 d = acct.mtxDigest(m);
        bytes memory sig = passkey ? _pk(index, pk, d) : _ecdsa(index, pk, d);
        vm.prank(relayer);
        return acct.mtxExecuteAsOwner(data, m.nonce, m.validUntil, sig);
    }

    function _ownerCallFails(bytes memory data, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _own(data, acct.mtxNonce(address(acct), 0));
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(err);
        acct.mtxExecuteAsOwner(data, m.nonce, m.validUntil, sig);
    }

    // ------------------------------------------------------------------ WebAuthn: published vectors

    /// Published vectors: base/webauthn-sol `test/WebAuthn.t.sol` (Coinbase Smart Wallet), real Chrome and Safari
    /// assertions, rpId "localhost", origin "http://localhost:3005".
    function _baseAccount() internal returns (SmartKeyAccount) {
        SubjectKey memory k = SubjectKey(
            KeyKind.P256_WEBAUTHN,
            bytes32(uint256(28573233055232466711029625910063034642429572463461595413086259353299906450061)),
            bytes32(uint256(39367742072897599771788408398752356480431855827262528811857788332151452825281)),
            sha256("localhost"), keccak256("http://localhost:3005"));
        return SmartKeyAccount(payable(fac.deploy(k, address(0))));
    }

    bytes32 internal constant BASE_CHALLENGE = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    function test_published_chrome_vector() public {
        SmartKeyAccount a = _baseAccount();
        bytes memory inner = abi.encode(
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a",
            _clientData(BASE_CHALLENGE, "http://localhost:3005", TAIL),
            bytes32(uint256(29739767516584490820047863506833955097567272713519339793744591468032609909569)),
            bytes32(uint256(45947455641742997809691064512762075989493430661170736817032030660832793108102)));
        assertTrue(_valid(a, BASE_CHALLENGE, _sig(0, inner)));
        assertFalse(_valid(a, keccak256("other"), _sig(0, inner)));
    }

    function test_published_safari_vector() public {
        SmartKeyAccount a = _baseAccount();
        bytes memory inner = abi.encode(
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
            _clientData(BASE_CHALLENGE, "http://localhost:3005", "}"),
            bytes32(uint256(43684192885701841787131392247364253107519555363555461570655060745499568693242)),
            bytes32(uint256(22655632649588629308599201066602670461698485748654492451178007896016452673579)));
        assertTrue(_valid(a, BASE_CHALLENGE, _sig(0, inner)));
    }

    /// Generated by the Node software authenticator (`clientkeys/scripts/webauthn-vector.mjs`).
    function test_node_software_authenticator_vector() public {
        string memory j = vm.readFile("test/vectors/webauthn_soft.json");
        SubjectKey memory k = SubjectKey(
            KeyKind.P256_WEBAUTHN, vm.parseJsonBytes32(j, ".qx"), vm.parseJsonBytes32(j, ".qy"),
            sha256(bytes(vm.parseJsonString(j, ".rpId"))), keccak256(bytes(vm.parseJsonString(j, ".origin"))));
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(k, address(0))));
        bytes32 challenge = vm.parseJsonBytes32(j, ".challenge");
        assertTrue(_valid(a, challenge, vm.parseJsonBytes(j, ".signature")));
        assertFalse(_valid(a, keccak256("other"), vm.parseJsonBytes(j, ".signature")));
    }

    // ------------------------------------------------------------------ WebAuthn: refusals

    bytes32 internal constant D = keccak256("operation digest");

    function _withAuth(bytes1 flags, string memory origin, string memory tail) internal pure returns (bytes memory) {
        return _sig(0, _enc(_signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), flags, uint32(0)),
                                           _clientData(D, origin, tail))));
    }

    function test_soft_assertion_valid() public view {
        assertTrue(_valid(acct, D, _pk(0, PASSKEY, D)));
    }

    function test_wrong_challenge() public view {
        assertFalse(_valid(acct, D, _pk(0, PASSKEY, keccak256("another op"))));
    }

    function test_wrong_origin_and_prefix_origin() public view {
        assertFalse(_valid(acct, D, _withAuth(0x05, "https://evil.example.com", TAIL)));
        assertFalse(_valid(acct, D, _withAuth(0x05, "https://pay.example.com.evil", TAIL)));
    }

    function test_wrong_rp_id_hash() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256("evil.example.com"), bytes1(0x05), uint32(0)),
                                            _clientData(D, ORIGIN, TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_flags() public view {
        assertFalse(_valid(acct, D, _withAuth(0x04, ORIGIN, TAIL)), "UP missing");
        assertFalse(_valid(acct, D, _withAuth(0x01, ORIGIN, TAIL)), "UV missing");
        assertTrue(_valid(acct, D, _withAuth(0x1d, ORIGIN, TAIL)), "BE|BS on top of UP|UV");
    }

    function test_high_s_is_refused() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.s = bytes32(N - uint256(a.s));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_tampering() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.authData[36] = 0x01;   // sign counter
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
        a = _assertion(PASSKEY, D);
        a.clientData = _clientData(D, ORIGIN, ',"crossOrigin":false,"x":1}');
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
        a = _assertion(PASSKEY, D);
        a.r = bytes32(uint256(a.r) ^ 1);
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
        a = _assertion(PASSKEY, D);
        a.authData = abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05));   // 33 bytes
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_type_create_is_refused() public view {
        bytes memory cd = abi.encodePacked('{"type":"webauthn.create","challenge":"',
            Base64.encodeURL(abi.encodePacked(D)), '","origin":"', ORIGIN, '"', TAIL);
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)), cd);
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_client_data_layouts() public view {
        assertTrue(_valid(acct, D, _withAuth(0x05, ORIGIN,
            ',"crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"}')));
        assertTrue(_valid(acct, D, _withAuth(0x05, ORIGIN, "}")), "Safari: origin then }");
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":true,"topOrigin":"https://evil.example.com"}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"x":1,"crossOrigin":true}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin": true}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":true}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":false')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":falsey}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, "}x")));
    }

    function test_other_passkey_and_unknown_index_are_refused() public view {
        assertFalse(_valid(acct, D, _pk(0, PASSKEY2, D)));
        assertFalse(_valid(acct, D, _pk(5, PASSKEY, D)));
    }

    // ------------------------------------------------------------------ batch (Merkle)

    function _tree(bytes32[4] memory d) internal view returns (bytes32 root, bytes32[][4] memory proofs) {
        bytes32[4] memory l;
        for (uint256 i; i < 4; ++i) l[i] = acct.batchLeaf(d[i]);
        bytes32 n01 = Hashes.commutativeKeccak256(l[0], l[1]);
        bytes32 n23 = Hashes.commutativeKeccak256(l[2], l[3]);
        root = Hashes.commutativeKeccak256(n01, n23);
        for (uint256 i; i < 4; ++i) {
            proofs[i] = new bytes32[](2);
            proofs[i][0] = l[i ^ 1];
            proofs[i][1] = i < 2 ? n23 : n01;
        }
    }

    function _ops() internal pure returns (bytes32[4] memory d) {
        for (uint256 i; i < 4; ++i) d[i] = keccak256(abi.encode("op", i));
    }

    function test_batch_one_passkey_assertion_covers_each_op() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        bytes32[4] memory d = _ops();
        (bytes32 root, bytes32[][4] memory proofs) = _tree(d);
        bytes memory inner = _enc(_assertion(PASSKEY, root));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SEED, root);
        for (uint256 i; i < 4; ++i) {
            assertTrue(_valid(acct, d[i], abi.encode(uint256(0), proofs[i], inner)), "passkey leaf");
            assertTrue(_valid(acct, d[i], abi.encode(uint256(1), proofs[i], abi.encodePacked(r, s, v))), "seed leaf");
        }
        assertFalse(_valid(acct, keccak256("not in batch"), abi.encode(uint256(0), proofs[0], inner)));
        assertFalse(_valid(acct, d[0], abi.encode(uint256(0), proofs[1], inner)));
        assertFalse(_valid(acct, d[0], _sig(0, inner)));
    }

    function test_batch_leaf_is_not_an_inner_node() public view {
        bytes32[4] memory d = _ops();
        (bytes32 root, bytes32[][4] memory proofs) = _tree(d);
        bytes32 n01 = Hashes.commutativeKeccak256(acct.batchLeaf(d[0]), acct.batchLeaf(d[1]));
        bytes32[] memory p = new bytes32[](1);
        p[0] = proofs[0][1];
        assertFalse(_valid(acct, n01, abi.encode(uint256(0), p, _enc(_assertion(PASSKEY, root)))));
    }

    // ------------------------------------------------------------------ token payments (new tree)

    function _payment(address from, bytes32 ref) internal view returns (MetaTxLib.MetaTransfer memory x, bytes32 d) {
        x = _tr(from, shop, 400, ref, uint256(ref), RR);
        d = t.mtxTransferDigest(x);
    }

    function _payWith(MetaTxLib.MetaTransfer memory x, bytes memory sig) internal {
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, sig);
    }

    function test_token_pay_signed_with_passkey() public {
        (MetaTxLib.MetaTransfer memory x, bytes32 d) = _payment(address(acct), keccak256("r1"));
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(acct), shop, 400, 0, relayer, keccak256("r1"));
        _payWith(x, sig);
        assertEq(t.balanceOf(shop), 400);
    }

    function test_second_key_then_pay_with_each() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 2);
        (MetaTxLib.MetaTransfer memory x1, bytes32 d1) = _payment(address(acct), keccak256("seed"));
        _payWith(x1, _ecdsa(1, SEED, d1));
        (MetaTxLib.MetaTransfer memory x2, bytes32 d2) = _payment(address(acct), keccak256("passkey"));
        _payWith(x2, _pk(0, PASSKEY, d2));
        assertEq(t.balanceOf(shop), 800);
    }

    function test_seed_first_account_pays() public {
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(_seedKey(SEED), address(0))));
        t.mint(address(a), 500);
        (MetaTxLib.MetaTransfer memory x, bytes32 d) = _payment(address(a), keccak256("s1"));
        _payWith(x, _ecdsa(0, SEED, d));
        assertEq(t.balanceOf(shop), 400);
    }

    function test_signature_for_one_account_does_not_pay_from_another() public {
        SmartKeyAccount b = SmartKeyAccount(payable(fac.deploy(_passkey(PASSKEY), address(0))));
        t.mint(address(b), 1000);
        (, bytes32 dA) = _payment(address(acct), keccak256("x"));
        (MetaTxLib.MetaTransfer memory xB,) = _payment(address(b), keccak256("x"));
        bytes memory sig = _pk(0, PASSKEY, dA);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(xB, sig);
    }

    function test_removed_key_cannot_pay() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        _ownerCall(abi.encodeCall(SmartKeyAccount.removeKey, (0)), 1, SEED, false);
        (MetaTxLib.MetaTransfer memory x, bytes32 d) = _payment(address(acct), keccak256("gone"));
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, sig);
    }

    /// CTR-ACC-05: the token computes the 400k cap codehash from `SMART_KEY_ACCOUNT_IMPL` (pinned on the token side by
    /// `test_erc1271Gets400kOnlyAsSmartKeyAccountClone`); it must be the factory's implementation, whose EIP-1167
    /// clones the accounts are. With the native P256VERIFY a passkey check is about 37k; the Solidity verifier
    /// (chains without the precompile) needs the 400k.
    function test_cloneCodehashIsWhatTokensCap() public {
        assertEq(t.SMART_KEY_ACCOUNT_IMPL(), fac.IMPLEMENTATION());
        assertEq(address(acct).codehash, keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", fac.IMPLEMENTATION(), hex"5af43d82803e903d91602b57fd5bf3")));
        bytes memory sig = _pk(0, PASSKEY, D);
        uint256 g = gasleft();
        assertTrue(_valid(acct, D, sig));
        emit log_named_uint("isValidSignature, passkey, native P256VERIFY", g - gasleft());
    }

    // ------------------------------------------------------------------ key management (CTR-ACC-10)

    function test_never_zero_keys() public {
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.removeKey, (0)), abi.encodeWithSelector(SmartKeyAccount.LastKey.selector));
        assertEq(acct.keyCount(), 1);
    }

    function test_rotate_passkey_to_new_passkey() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.rotateKey, (0, _passkey(PASSKEY2))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 1);
        assertTrue(_valid(acct, D, _pk(1, PASSKEY2, D)));
        assertFalse(_valid(acct, D, _pk(0, PASSKEY, D)));
        assertFalse(acct.hasKey(keccak256(abi.encode(_passkey(PASSKEY)))));
    }

    function test_remove_unknown_index() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.removeKey, (7)),
            abi.encodeWithSelector(SmartKeyAccount.NoSuchKey.selector, 7));
    }

    function test_owner_call_replay_expiry_and_foreign_key() public {
        bytes memory data = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes32 d = acct.mtxDigest(m);
        bytes memory sig = _pk(0, PASSKEY, d);
        bytes memory foreign = _pk(0, PASSKEY2, d);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, foreign);
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        acct.mtxExecuteAsOwner(data, 1, m.validUntil, sig);
    }

    /// One signature, one digest, one lane: the named builder and `mtxExecute` consume the same nonce.
    function test_namedBuilderIsMtxExecute() public {
        bytes memory data = abi.encodeCall(SmartKeyAccount.setGuardian, (address(0xD00D)));
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectEmit(true, true, true, true, address(acct));
        emit IMetaTx.MetaTransactionExecuted(address(acct), relayer, 0, 0, acct.mtxDigest(m), relayer, 0);
        vm.prank(relayer);
        acct.mtxExecute(m, sig);
        assertEq(acct.guardian(), address(0xD00D));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
    }

    function test_duplicate_and_bad_keys() public {
        bytes4 bad = SmartKeyAccount.BadKey.selector;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (_passkey(PASSKEY))),
            abi.encodeWithSelector(SmartKeyAccount.DuplicateKey.selector));
        SubjectKey memory k = _passkey(PASSKEY2);
        k.y = bytes32(uint256(k.y) ^ 1);                                   // off the curve
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _seedKey(SEED);
        k.x = bytes32(uint256(k.x) | (1 << 200));                          // dirty bits above the address
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _passkey(PASSKEY2);
        k.originHash = 0;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _passkey(PASSKEY2);
        k.rpIdHash = 0;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _seedKey(SEED);
        k.y = bytes32(uint256(1));
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _seedKey(SEED);
        k.x = 0;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        SubjectKey memory none;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (none)), abi.encodeWithSelector(bad));
    }

    function test_self_only_functions() public {
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.addKey(_seedKey(SEED));
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.removeKey(0);
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.rotateKey(0, _seedKey(SEED));
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.setGuardian(address(this));
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.cancelRecovery();
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.execute(address(t), 0, "");
    }

    /// Another signer's `MetaTransaction` runs as that signer: the self-only functions refuse it, and its
    /// `cancelNonce` moves only its own lane.
    function test_otherSignerIsNotTheAccount() public {
        uint256 pk = 0xA11CE;
        address alice = vm.addr(pk);
        MetaTxLib.MetaTransaction memory m = _call(alice, abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, RR);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, acct.mtxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.mtxExecute(m, abi.encodePacked(r, s, v));
        m = _call(alice, abi.encodeCall(IMetaTx.cancelNonce, (0)), 9, RR);
        (v, r, s) = vm.sign(pk, acct.mtxDigest(m));
        vm.prank(relayer);
        acct.mtxExecute(m, abi.encodePacked(r, s, v));
        assertEq(acct.mtxNonce(alice, 0), 1);
        assertEq(acct.mtxNonce(alice, 9), 1);
        assertEq(acct.mtxNonce(address(acct), 0), 0);
        // for `from = account` only the account's keys sign: a plain EOA signature, a key the account does not hold,
        // or an ECDSA blob under the passkey's index is a `MetaTxBadSignature`
        m = _own(abi.encodeCall(IMetaTx.cancelNonce, (0)), 0);
        (v, r, s) = vm.sign(SEED, acct.mtxDigest(m));
        bytes[3] memory bad = [abi.encodePacked(r, s, v), _sig(1, abi.encodePacked(r, s, v)), _sig(0, abi.encodePacked(r, s, v))];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
            acct.mtxExecute(m, bad[i]);
        }
    }

    function test_accountCancelsItsOwnLane() public {
        _ownerCall(abi.encodeCall(IMetaTx.cancelNonce, (5)), 0, PASSKEY, true);
        assertEq(acct.mtxNonce(address(acct), 5), 1);
        assertEq(acct.mtxNonce(address(acct), 0), 1);
    }

    function test_execute_moves_funds() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.execute,
                                  (address(t), 0, abi.encodeCall(t.transfer, (shop, 100)))), 0, PASSKEY, true);
        assertEq(t.balanceOf(shop), 100);
    }

    /// `execute` runs under the guard: it cannot call the account's own functions or take a second signed call.
    function test_executeCannotReenter() public {
        bytes memory inner = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.execute, (address(acct), 0, inner)),
            abi.encodeWithSelector(SmartKeyAccount.CallFailed.selector,
                abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        ReenterAccount re = new ReenterAccount();
        MetaTxLib.MetaTransaction memory m2 = _own(inner, 1);
        bytes memory sig2 = _pk(0, PASSKEY, acct.mtxDigest(m2));
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.execute, (address(re), 0, abi.encodeCall(re.hit, (acct, m2, sig2)))),
            abi.encodeWithSelector(SmartKeyAccount.CallFailed.selector,
                abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        assertEq(acct.keyCount(), 1);
    }

    function test_mtxBatchIsAtomic() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _own(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0);
        ms[1] = _own(abi.encodeCall(SmartKeyAccount.removeKey, (0)), 1);
        sigs[0] = _pk(0, PASSKEY, acct.mtxDigest(ms[0]));
        sigs[1] = _pk(0, PASSKEY, acct.mtxDigest(ms[1]));
        vm.prank(relayer);
        acct.mtxBatch(ms, sigs);
        assertEq(acct.keyCount(), 1);
        assertTrue(acct.hasKey(keccak256(abi.encode(_seedKey(SEED)))));
        // a failing item reverts the batch: the removed passkey no longer signs item 1
        ms[0] = _own(abi.encodeCall(SmartKeyAccount.setGuardian, (address(1))), 2);
        ms[1] = _own(abi.encodeCall(SmartKeyAccount.setGuardian, (address(2))), 3);
        sigs[0] = _ecdsa(1, SEED, acct.mtxDigest(ms[0]));
        sigs[1] = _pk(0, PASSKEY, acct.mtxDigest(ms[1]));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxBatch(ms, sigs);
        assertEq(acct.guardian(), GUARDIAN);
    }

    function test_relayerBinding() public {
        MetaTxLib.MetaTransaction memory m = _own(abi.encodeCall(IMetaTx.cancelNonce, (1)), 0);
        m.mode = RR;
        m.relayer = relayer;
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, address(0xBAD)));
        acct.mtxExecute(m, sig);
        vm.prank(relayer);
        acct.mtxExecute(m, sig);
    }

    // ------------------------------------------------------------------ allowlist, fee, domain (CTR-MTX-19/22)

    function test_allowlistPinned() public view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = acct.mtxSelectors();
        bytes4[7] memory want = [IMetaTx.cancelNonce.selector, SmartKeyAccount.addKey.selector,
            SmartKeyAccount.removeKey.selector, SmartKeyAccount.rotateKey.selector, SmartKeyAccount.setGuardian.selector,
            SmartKeyAccount.cancelRecovery.selector, SmartKeyAccount.execute.selector];
        assertEq(s.length, 7);
        for (uint256 i; i < 7; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], 1, "ABSOLUTE");
            assertEq(a[i], 0);
        }
        assertEq(SmartKeyAccount.addKey.selector, bytes4(keccak256("addKey((uint8,bytes32,bytes32,bytes32,bytes32))")));
        assertEq(SmartKeyAccount.rotateKey.selector,
            bytes4(keccak256("rotateKey(uint256,(uint8,bytes32,bytes32,bytes32,bytes32))")));
        assertEq(acct.supportedModes(), 0x03);
    }

    function _signedFails(bytes memory data, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(err);
        acct.mtxExecute(m, sig);
    }

    function test_unlistedSelectorsRefused() public {
        bytes4 no = IMetaTx.MtxSelectorNotAllowed.selector;
        bytes[6] memory calls = [
            abi.encodeCall(SmartKeyAccount.initiateRecovery, (_seedKey(SEED))),
            abi.encodeCall(SmartKeyAccount.completeRecovery, (_seedKey(SEED))),
            abi.encodeCall(SmartKeyAccount.initialize, (_seedKey(SEED), address(0))),
            abi.encodeCall(SmartKeyAccount.mtxExecuteAsOwner, ("", 0, 0, "")),
            abi.encodeCall(SmartKeyAccount.isValidSignature, (D, "")),
            abi.encodeCall(IMetaTx.mtxBatch, (new MetaTxLib.MetaTransaction[](0), new bytes[](0)))
        ];
        for (uint256 i; i < calls.length; ++i) _signedFails(calls[i], abi.encodeWithSelector(no, bytes4(calls[i])));
    }

    function test_staticShapes() public {
        bytes memory k = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        assertEq(k.length, 164);
        _signedFails(abi.encodePacked(k, bytes32(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.addKey.selector));
        _signedFails(abi.encodePacked(SmartKeyAccount.cancelRecovery.selector, bytes32(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.cancelRecovery.selector));
        _signedFails(abi.encodePacked(abi.encodeCall(SmartKeyAccount.removeKey, (0)), bytes1(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.removeKey.selector));
        _signedFails(abi.encodePacked(abi.encodeCall(SmartKeyAccount.setGuardian, (address(0))), bytes1(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.setGuardian.selector));
        _signedFails(abi.encodePacked(abi.encodeCall(SmartKeyAccount.rotateKey, (0, _seedKey(SEED))), bytes1(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.rotateKey.selector));
    }

    function test_feeModesRefused() public {
        MetaTxLib.MetaTransaction memory m = _own(abi.encodeCall(IMetaTx.cancelNonce, (1)), 0);
        m.mode = MetaTxLib.MODE_FEE_PERCENT;
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IMetaTx.cancelNonce.selector, m.mode));
        acct.mtxExecute(m, sig);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 1;
        sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, m.mode));
        acct.mtxExecute(m, sig);
    }

    /// CTR-ACC-11, MT-4: `("SCaaS SmartKeyAccount", "1", chainId, account, chain_uid)`, on every clone.
    function test_domainIsSaltedSmartKeyAccount() public view {
        (bytes1 f, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt_,) =
            acct.eip712Domain();
        assertEq(f, hex"1f");
        assertEq(name, "SCaaS SmartKeyAccount");
        assertEq(version, "1");
        assertEq(chainId, 7622);
        assertEq(vc, address(acct));
        assertEq(salt_, UID_);
        assertEq(acct.chainUid(), UID_);
        assertEq(fac.chainUid(), UID_);
        MetaTxLib.MetaTransaction memory m = _own(hex"12345678", 3);
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS SmartKeyAccount"), keccak256("1"), uint256(7622), address(acct), UID_));
        assertEq(acct.mtxDigest(m), keccak256(abi.encodePacked(hex"1901", ds, MetaTxLib.hashStruct(m))));
    }

    // ------------------------------------------------------------------ recovery (CTR-ACC-03)

    function test_guardian_recovery_after_delay() public {
        SubjectKey memory k = _seedKey(SEED);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.expectRevert(abi.encodeWithSelector(SmartKeyAccount.RecoveryNotReady.selector, block.timestamp + 2 days));
        acct.completeRecovery(k);
        vm.warp(block.timestamp + 2 days - 1);
        vm.expectRevert(abi.encodeWithSelector(SmartKeyAccount.RecoveryNotReady.selector, block.timestamp + 1));
        acct.completeRecovery(k);
        vm.warp(block.timestamp + 1);
        vm.prank(address(0xA11));                  // anyone submits
        uint256 idx = acct.completeRecovery(k);
        assertEq(acct.pendingRecovery(), bytes32(0));
        assertEq(acct.keyCount(), 2, "recovery adds, removes nothing");
        assertTrue(_valid(acct, D, _ecdsa(idx, SEED, D)));
        _ownerCall(abi.encodeCall(SmartKeyAccount.removeKey, (0)), idx, SEED, false);
        assertEq(acct.keyCount(), 1);
    }

    function test_key_cancels_recovery() public {
        SubjectKey memory k = _seedKey(SEED);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        _ownerCall(abi.encodeCall(SmartKeyAccount.cancelRecovery, ()), 0, PASSKEY, true);
        vm.warp(block.timestamp + 3 days);
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.completeRecovery(k);
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.cancelRecovery, ()),
            abi.encodeWithSelector(SmartKeyAccount.NoRecovery.selector));
    }

    function test_recovery_guards() public {
        SubjectKey memory k = _seedKey(SEED);
        SubjectKey memory other = _passkey(PASSKEY2);
        vm.expectRevert(SmartKeyAccount.NotGuardian.selector);
        acct.initiateRecovery(k);
        vm.prank(GUARDIAN);
        vm.expectRevert(SmartKeyAccount.BadKey.selector);
        acct.initiateRecovery(SubjectKey(KeyKind.NONE, 0, 0, 0, 0));
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.completeRecovery(other);
        _ownerCall(abi.encodeCall(SmartKeyAccount.setGuardian, (address(0xD00D))), 0, PASSKEY, true);
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.completeRecovery(k);
        vm.prank(GUARDIAN);
        vm.expectRevert(SmartKeyAccount.NotGuardian.selector);
        acct.initiateRecovery(k);
    }

    function test_no_guardian_no_recovery() public {
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(_seedKey(SEED), address(0))));
        SubjectKey memory k = _passkey(PASSKEY);
        vm.prank(address(0));
        vm.expectRevert(SmartKeyAccount.NotGuardian.selector);
        a.initiateRecovery(k);
    }

    // ------------------------------------------------------------------ factory (CTR-ACC-01)

    function test_factory_predictable_permissionless_idempotent() public {
        SubjectKey memory k = _passkey(PASSKEY2);
        address predicted = fac.predict(k, GUARDIAN);
        assertEq(predicted.code.length, 0);
        vm.prank(address(0xD3AD));
        address a = fac.deploy(k, GUARDIAN);
        assertEq(a, predicted);
        assertEq(fac.deploy(k, GUARDIAN), a);
        assertTrue(fac.predict(k, address(0)) != a);
        assertEq(SmartKeyAccount(payable(a)).guardian(), GUARDIAN);
        assertEq(SmartKeyAccount(payable(a)).keyCount(), 1);
    }

    function test_initialize_is_factory_only_and_once() public {
        vm.expectRevert(SmartKeyAccount.NotFactory.selector);
        acct.initialize(_seedKey(SEED), address(0));
        SmartKeyAccount impl = SmartKeyAccount(payable(fac.IMPLEMENTATION()));
        vm.prank(address(fac));
        vm.expectRevert(SmartKeyAccount.AlreadyInitialized.selector);
        impl.initialize(_seedKey(SEED), address(0));
        vm.prank(address(fac));
        vm.expectRevert(SmartKeyAccount.AlreadyInitialized.selector);
        acct.initialize(_seedKey(SEED), address(0));
    }

    /// The implementation, and so every account, differs per chain (the factory passes `chain_uid`).
    function test_accountAddressDependsOnChainUid() public {
        SmartKeyAccountFactory other = new SmartKeyAccountFactory(keccak256("another chain"));
        assertTrue(other.IMPLEMENTATION().codehash != fac.IMPLEMENTATION().codehash, "chain_uid is an immutable");
        assertEq(SmartKeyAccount(payable(other.IMPLEMENTATION())).chainUid(), keccak256("another chain"));
        vm.expectRevert();
        new SmartKeyAccountFactory(bytes32(0));
    }

    /// The CREATE2 formula Odoo (`blockchain.subject.account._predict`) and clientkeys check against the same file:
    /// salt of (key, guardian) and the clone address of (implementation, salt, factory).
    function test_pinned_create2_vector() public view {
        SubjectKey memory k = _seedKey(SEED);
        string memory j = vm.readFile("test/vectors/smart_key_account_create2.json");
        bytes32 s = fac.salt(k, GUARDIAN);
        assertEq(s, vm.parseJsonBytes32(j, ".salt"));
        assertEq(Clones.predictDeterministicAddress(
            vm.parseJsonAddress(j, ".implementation"), s, vm.parseJsonAddress(j, ".factory")),
            vm.parseJsonAddress(j, ".account"));
        assertEq(fac.predict(k, GUARDIAN), Clones.predictDeterministicAddress(fac.IMPLEMENTATION(), s, address(fac)));
    }

    // ------------------------------------------------------------------ gas

    function test_gas_deploy_and_owner_call() public {
        uint256 g = gasleft();
        fac.deploy(_passkey(PASSKEY2), GUARDIAN);
        emit log_named_uint("factory.deploy (clone + initialize, passkey key)", g - gasleft());
        bytes memory data = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        g = gasleft();
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        emit log_named_uint("mtxExecuteAsOwner(addKey), passkey", g - gasleft());
    }
}
```
- [ ] **Step 6: Create `test/account/AccountKat.t.sol`** (the shared KAT writer and the account vector; Task 2 appends the wallet vectors):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";

/// Shared writer of the account-side `MetaTransaction` KATs (metatx.md §15: the `MandateWallet` and `SmartKeyAccount`
/// vectors are `MetaTransaction` vectors in their own domains), chain 7622 with its real `chain_uid`.
/// `WRITE_KAT=true forge test --match-path test/account/AccountKat.t.sol` rewrites them; clientkeys reads them.
abstract contract MtxKatBase is Test {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;

    function _domainSep(string memory name, address vc) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256("1"), uint256(7622), vc, UID));
    }

    /// Serialises domain, struct, hashes and `sig` under `k`; writes `path` with `WRITE_KAT`, then checks the file.
    function _kat(string memory k, string memory path, string memory name, address vc, MetaTxLib.MetaTransaction memory m,
        bytes32 digest, bytes memory sig) internal returns (string memory out)
    {
        assertEq(digest, keccak256(abi.encodePacked(hex"1901", _domainSep(name, vc), m.hashStruct())), "digest formula");
        vm.serializeString(k, "domain_name", name);
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(vc));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "domain_separator", vm.toString(_domainSep(name, vc)));
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATX_TYPEHASH));
        vm.serializeString(k, "struct_hash", vm.toString(m.hashStruct()));
        vm.serializeString(k, "digest", vm.toString(digest));
        out = vm.serializeString(k, "signature", vm.toString(sig));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, path);
        string memory onDisk = vm.readFile(path);
        assertEq(vm.parseJsonString(onDisk, ".domain_name"), name);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), vc);
        assertEq(vm.parseJsonBytes32(onDisk, ".salt"), UID);
        assertEq(vm.parseJsonBytes(onDisk, ".data"), m.data);
        assertEq(vm.parseJsonUint(onDisk, ".batch"), m.batch);
        assertEq(vm.parseJsonBytes32(onDisk, ".struct_hash"), m.hashStruct());
        assertEq(vm.parseJsonBytes32(onDisk, ".digest"), digest);
        assertEq(vm.parseJsonBytes(onDisk, ".signature"), sig);
    }

    function _ecdsa(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }
}

/// `smart_key_account_kat.json`: the account's own `addKey(SECP256K1(0x77…77))` on lane 0 (what `mtxExecuteAsOwner`
/// builds and clientkeys' `checkOwnerCall` rebuilds), signed by its seed key 0 in the account encoding
/// `abi.encode(0, [], ecdsa)`; it really executes.
contract SmartKeyAccountKatTest is MtxKatBase {
    uint256 internal constant SEED = 0x5EED;

    function test_smartKeyAccountKat() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        SmartKeyAccountFactory fac = new SmartKeyAccountFactory(UID);
        SubjectKey memory first = SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(SEED)))), 0, 0, 0);
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(first, address(0))));
        SubjectKey memory added = SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(address(0x7777777777777777777777777777777777777777)))), 0, 0, 0);
        MetaTxLib.MetaTransaction memory m;
        m.from = address(a);
        m.data = abi.encodeCall(SmartKeyAccount.addKey, (added));
        m.validUntil = 1_800_000_300;
        bytes32 digest = a.mtxDigest(m);
        bytes memory sig = abi.encode(uint256(0), new bytes32[](0), _ecdsa(SEED, digest));
        a.mtxExecuteAsOwner(m.data, 0, m.validUntil, sig);
        assertEq(a.keyCount(), 2);
        vm.serializeString("ska", "signer_key", vm.toString(vm.addr(SEED)));
        _kat("ska", "./test/vectors/smart_key_account_kat.json", "SCaaS SmartKeyAccount", address(a), m, digest, sig);
    }
}
```
- [ ] **Step 7: Write the vector and check it.** `WRITE_KAT=true scripts/capped forge test --match-path test/account/AccountKat.t.sol`, then the same without `WRITE_KAT`; `test/vectors/smart_key_account_kat.json` must be exactly:

```json
{
  "batch": "0",
  "chain_id": "7622",
  "data": "0xde1b566700000000000000000000000000000000000000000000000000000000000000020000000000000000000000007777777777777777777777777777777777777777000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "digest": "0x81da08c4b53a7962413181c9d220f7c305f105fba5fb15790636dbcb0b4393ec",
  "domain_name": "SCaaS SmartKeyAccount",
  "domain_separator": "0x85a6002d82de4a3dc9ac25ce4e53c696e43f0951cf3286fc85005e94f7cd8c2a",
  "domain_version": "1",
  "fee": "0",
  "fee_recipient": "0x0000000000000000000000000000000000000000",
  "from": "0xaEf14B9dE72FaE22F436928CCDC25b0776f4df92",
  "mode": "0",
  "nonce": "0",
  "relayer": "0x0000000000000000000000000000000000000000",
  "salt": "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464",
  "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004134427a64dbfad68f88d330ebf8a6c86fb8d6dcd84811fba68cb3127e28f7be41600d5e7accf2df7678434d2e5c60a86635f3620b6083d2f86fe719a986106f621b00000000000000000000000000000000000000000000000000000000000000",
  "signer_key": "0xF52B978d064A638e263ad7B397172E414c20BA84",
  "struct_hash": "0xe9aeaf1b955eea09af73459219a8386c29863740fbd5b48cbcfdfd05d02268ed",
  "type_hash": "0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888",
  "valid_until": "1800000300",
  "verifying_contract": "0xaEf14B9dE72FaE22F436928CCDC25b0776f4df92"
}
```
- [ ] **Step 8: Run** `scripts/capped forge test --match-path 'test/account/*'` → 49 passed; full `scripts/capped forge test` →
  **979** passed (977 − 47 + 49); size gate (Global Constraints) → 0 errors (the four tokens +8 B, the baseline above);
  `FOUNDRY_PROFILE=private7622 scripts/capped forge build` → no error.
- [ ] **Step 9: Commit** `P4: SmartKeyAccount on MetaTxBase (CTR-ACC-10/11), the _selfSender hook, SubjectAccount to legacy/p4` + trailer.

---

### Task 2: `MandateWallet` and `HederaMandateWallet` on `MetaTxBase`, the revocation epoch, the old wallet to `legacy/p4/`

**Model:** Opus, effort high (money path).

**Files:**
- Move (`git mv`): `src/wallet/MandateWallet.sol` → `legacy/p4/src/wallet/`, `src/hedera/HederaMandateWallet.sol` →
  `legacy/p4/src/hedera/`, `test/MandateWallet.t.sol`, `test/MandateWalletKat.t.sol` → `legacy/p4/test/`
- Create: `src/wallet/MandateWallet.sol`, `src/hedera/HederaMandateWallet.sol`, `test/wallet/MandateWallet.t.sol`,
  `legacy/p4/test/hedera/HederaMandateWallet.t.sol` (cut from the v1 Hedera test), `test/vectors/mandate_pay_kat.json`,
  `test/vectors/mandate_revoke_kat.json` (written by the KAT test)
- Modify: `test/hedera/HederaMetaToken.t.sol` (the wallet test leaves), `test/account/AccountKat.t.sol` (append),
  `legacy/README.md`

**Interfaces:** Produces `MandateWallet(address owner, bytes32 chainUid)`: `setMandate`, `setPayee`, `revoke(address)`,
`execute` (owner), `payUnderMandate(address,address,uint256,bytes32)`, `revoke(address,uint64)` (delegate),
`mtxPayUnderMandate(token, payee, amount, entryRef, validUntil, sig)`, `mtxRevoke(token, epoch, validUntil, sig)`,
`mtxExecuteAsOwner(data, nonce, validUntil, sig)`, views `owner`, `mandates`, `payeeAllowed`, `refUsed`, `epoch`,
`mandatePayLane`, `mandateRevokeLane`, `isValidSignature`, the base's views; errors `NotOwner`, `NotDelegate`, `NoMandate`,
`MandateExpired`, `PayeeNotAllowed`, `OverPaymentCap`, `OverPeriodCap`, `RefAlreadyPaid`, `StaleEpoch`, `CallFailed`,
`ZeroOwner`, `BadMandate`, `PayFailed`; `HederaMandateWallet(owner, chainUid)` + `mtxExecuteAsOwnerRaw`. Consumes Task 1's
`MtxKatBase`.

- [ ] **Step 1: Move the built wallet line and cut the v1 Hedera wallet test into the backup:**

```bash
cd smartcontracts/evm
mkdir -p legacy/p4/src/wallet legacy/p4/src/hedera legacy/p4/test/hedera test/wallet
/usr/bin/git mv src/wallet/MandateWallet.sol legacy/p4/src/wallet/
/usr/bin/git mv src/hedera/HederaMandateWallet.sol legacy/p4/src/hedera/
/usr/bin/git mv test/MandateWallet.t.sol test/MandateWalletKat.t.sol legacy/p4/test/
python3 - <<'EOF'
p = 'test/hedera/HederaMetaToken.t.sol'
s = open(p).read()
i = s.index("contract HederaMandateWalletTest is HederaFixture {")
j = s.index("contract HederaHtsWrapperTest is HederaFixture {")
hdr = '''// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// Backup (P4): the `HederaMandateWalletTest` of `test/hedera/HederaMetaToken.t.sol` as it stood before P4 moved
// `MandateWallet` onto `MetaTxBase`; it tested `legacy/p4/src/hedera/HederaMandateWallet.sol`. Not built.

'''
open('legacy/p4/test/hedera/HederaMandateWallet.t.sol', 'w').write(hdr + s[i:j].rstrip() + "\n")
s = s[:i] + s[j:]
s = s.replace('import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";\n', '')
s = s.replace('import {MandateWallet} from "../../src/wallet/MandateWallet.sol";\n', '')
open(p, 'w').write(s)
EOF
/usr/bin/git add legacy/p4/test/hedera/HederaMandateWallet.t.sol
```

The resulting change to `test/hedera/HederaMetaToken.t.sol` and `legacy/README.md`:

```diff
diff --git a/smartcontracts/evm/test/hedera/HederaMetaToken.t.sol b/smartcontracts/evm/test/hedera/HederaMetaToken.t.sol
index 610df27..eaf05f5 100644
--- a/smartcontracts/evm/test/hedera/HederaMetaToken.t.sol
+++ b/smartcontracts/evm/test/hedera/HederaMetaToken.t.sol
@@ -10,8 +10,6 @@ import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
 import {IERC20PaymentV1} from "../../src/metatx/IERC20PaymentV1.sol";
 import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
 import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
-import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
-import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
 import {MockERC20} from "../helpers/Mocks.sol";
 import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
 import {MockHederaAccountService, MockHts} from "./HederaMocks.sol";
@@ -280,69 +278,6 @@ contract HederaMetaTokenTest is HederaFixture {
     }
 }
 
-contract HederaMandateWalletTest is HederaFixture {
-    uint256 constant OWNER_KEY = 0x0E1;
-    uint256 constant DELEGATE_PK = 0xDE1;
-    address owner;
-    HederaMandateWallet wallet;
-    HederaMetaToken tok;
-
-    function setUp() public {
-        _setUpHedera();
-        owner = _nativeAccount(2_000_001, OWNER_KEY);
-        wallet = new HederaMandateWallet(owner);
-        tok = _token("HBUSD", 1_000_000e6);
-        tok.transfer(address(wallet), 1_000e6);
-    }
-
-    function _setMandateCall() internal view returns (bytes memory) {
-        return abi.encodeCall(MandateWallet.setMandate,
-            (address(tok), vm.addr(DELEGATE_PK), 100e6, 300e6, 1 days, uint64(block.timestamp + 30 days)));
-    }
-
-    function test_ed25519OwnerSetsMandateGasless() public {
-        bytes memory data = _setMandateCall();
-        uint256 vu = block.timestamp + 300;
-        bytes memory sig = _edSign(OWNER_KEY, wallet.ownerCallDigest(data, 0, vu));
-        vm.prank(relayer);
-        wallet.executeAsOwnerRaw(data, 0, vu, sig);
-        (address d,,,,,,) = wallet.mandates(address(tok));
-        assertEq(d, vm.addr(DELEGATE_PK));
-        assertEq(wallet.ownerNonce(), 1);
-        // replay
-        vm.expectRevert(MandateWallet.BadNonce.selector);
-        wallet.executeAsOwnerRaw(data, 0, vu, sig);
-    }
-
-    function test_ownerRawRejectsOtherKeyAndExpiry() public {
-        bytes memory data = _setMandateCall();
-        uint256 vu = block.timestamp + 300;
-        bytes memory bad = _edSign(DELEGATE_PK, wallet.ownerCallDigest(data, 0, vu));
-        vm.expectRevert(MandateWallet.BadSignature.selector);
-        wallet.executeAsOwnerRaw(data, 0, vu, bad);
-        bytes memory sig = _edSign(OWNER_KEY, wallet.ownerCallDigest(data, 0, vu));
-        vm.warp(vu + 1);
-        vm.expectRevert(MandateWallet.SignatureExpired.selector);
-        wallet.executeAsOwnerRaw(data, 0, vu, sig);
-    }
-
-    /// Delegate (custody secp256k1 của platform) trả trong hạn mức; payRef một lần — như MandateWallet.
-    function test_delegatePaysUnderMandateSetByEd25519Owner() public {
-        bytes memory data = _setMandateCall();
-        uint256 vu = block.timestamp + 300;
-        wallet.executeAsOwnerRaw(data, 0, vu, _edSign(OWNER_KEY, wallet.ownerCallDigest(data, 0, vu)));
-        bytes memory payee = abi.encodeCall(MandateWallet.setPayee, (address(tok), address(0x5409), true));
-        wallet.executeAsOwnerRaw(payee, 1, vu, _edSign(OWNER_KEY, wallet.ownerCallDigest(payee, 1, vu)));
-        bytes32 ref = bytes32(uint256(7));
-        (uint8 v, bytes32 r, bytes32 s) =
-            vm.sign(DELEGATE_PK, wallet.payDigest(address(tok), address(0x5409), 50e6, ref, vu));
-        wallet.payUnderMandate(address(tok), address(0x5409), 50e6, ref, vu, abi.encodePacked(r, s, v));
-        assertEq(tok.balanceOf(address(0x5409)), 50e6);
-        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, ref));
-        wallet.payUnderMandate(address(tok), address(0x5409), 50e6, ref, vu, abi.encodePacked(r, s, v));
-    }
-}
-
 contract HederaHtsWrapperTest is HederaFixture {
     MockERC20 hts; // mặt tiền ERC-20 của token HTS (HIP-218)
     HederaMetaToken wrapper;
diff --git a/smartcontracts/evm/legacy/README.md b/smartcontracts/evm/legacy/README.md
index fcfa7c1..a3f5507 100644
--- a/smartcontracts/evm/legacy/README.md
+++ b/smartcontracts/evm/legacy/README.md
@@ -18,4 +18,7 @@ Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`,
   the e2e read them. `OpenFactoryV1` keeps its `ZETHER` kind (mock-tested) until the v1 line moves (P5).
 - `p4/`: the built `SubjectAccount` and `SubjectAccountFactory` (typed `OwnerCall`, own nonce, domain `SCaaS SubjectAccount`
   without salt) and their test `SubjectAccount.t.sol`, as they stood on `main` before P4 put `SmartKeyAccount` on
-  `MetaTxBase` (CTR-ACC-10, CTR-ACC-11); not built. Clones deployed from them keep working with their own code.
+  `MetaTxBase` (CTR-ACC-10, CTR-ACC-11); and the built `MandateWallet` / `HederaMandateWallet` (typed `PayUnderMandate`,
+  `RevokeMandate`, `OwnerCall`, no epoch, no salt) with `MandateWallet.t.sol`, `MandateWalletKat.t.sol` and the Hedera
+  wallet test cut from `test/hedera/HederaMetaToken.t.sol` (CTR-ACC-06, CTR-ACC-07); not built. Clones and wallets
+  deployed from them keep working with their own code.
```
- [ ] **Step 2: Create `src/wallet/MandateWallet.sol`:**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IERC20Payment} from "../metatx/IERC20Payment.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title The wallet of ONE payer with limited delegated payment (CTR-ACC-06, CTR-ACC-07), on `MetaTxBase`.
/// @notice The payer (`owner`) keeps its key; a delegate (the platform's custody key, or an agent key) may pay only
///         within the mandate the owner set per token, every limit checked here on chain: per payment, per period,
///         approved payees, an expiry, and an `entryRef` that pays once per wallet. No allowance: the funds sit in the
///         wallet, which pays by `IERC20Payment.payWithFee` as `msg.sender`, so `PaymentSettled` carries `entryRef`
///         as a manual payment does. Every signed action is a `MetaTransaction` self-call (domain `("SCaaS
///         MandateWallet", "1", chainId, wallet, chain_uid)`, fee mode `NONE`): the delegate signs
///         `payUnderMandate` and `revoke(token, epoch)`; the owner signs `setMandate`, `setPayee`, `revoke(token)` and
///         `execute`. `mtxPayUnderMandate`, `mtxRevoke` and `mtxExecuteAsOwner` are the named builders and derive
///         their lanes. ERC-1271 answers for the owner (ECDSA), so the owner also pays by hand with `from = wallet`.
contract MandateWallet is MetaTxBase, IERC1271 {
    struct Mandate {
        address delegate;      // 0 = none or revoked
        uint64 expiry;         // unix seconds
        uint64 periodSeconds;
        uint64 periodStart;
        uint128 maxPerPayment;
        uint128 maxPerPeriod;
        uint128 spentInPeriod;
    }

    address public immutable owner;
    mapping(address token => Mandate) public mandates;
    mapping(address token => mapping(address payee => bool)) public payeeAllowed;
    mapping(bytes32 entryRef => bool) public refUsed;
    /// @notice Bumped by every `setMandate` and every revoke (CTR-ACC-07): a delegate's signed revoke names it.
    mapping(address token => uint64) public epoch;

    event MandateSet(address indexed token, address indexed delegate, uint256 maxPerPayment,
                     uint256 maxPerPeriod, uint256 periodSeconds, uint256 expiry);
    event MandateRevoked(address indexed token, address indexed by);
    event PayeeSet(address indexed token, address indexed payee, bool allowed);
    event PaidUnderMandate(address indexed token, address indexed payee, uint256 amount, bytes32 indexed entryRef);

    error NotOwner();
    error NotDelegate();
    error NoMandate();
    error MandateExpired();
    error PayeeNotAllowed(address payee);
    error OverPaymentCap(uint256 amount, uint256 cap);
    error OverPeriodCap(uint256 wouldSpend, uint256 cap);
    error RefAlreadyPaid(bytes32 entryRef);
    error StaleEpoch(uint64 current, uint64 signed);
    error CallFailed(bytes reason);
    error ZeroOwner();
    error BadMandate();
    error PayFailed();

    modifier onlyOwner() {
        if (_msgSender() != owner) revert NotOwner();
        _;
    }

    /// @param chainUid_ the chain's `chain_uid` from its profile (CTR-GEN-05); the node checks `chainUid()` before relaying.
    constructor(address owner_, bytes32 chainUid_) MetaTxBase("SCaaS MandateWallet", chainUid_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    receive() external payable {}

    // ------------------------------------------------------------------ owner

    function setMandate(address token, address delegate, uint128 maxPerPayment, uint128 maxPerPeriod,
                        uint64 periodSeconds, uint64 expiry) external nonReentrant onlyOwner {
        // periodSeconds == 0 would reset the period cap at every payment.
        if (delegate == address(0) || periodSeconds == 0 || maxPerPayment == 0
            || maxPerPayment > maxPerPeriod) revert BadMandate();
        mandates[token] = Mandate(delegate, expiry, periodSeconds, uint64(block.timestamp),
                                  maxPerPayment, maxPerPeriod, 0);
        ++epoch[token];
        emit MandateSet(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry);
    }

    function setPayee(address token, address payee, bool allowed) external nonReentrant onlyOwner {
        payeeAllowed[token][payee] = allowed;
        emit PayeeSet(token, payee, allowed);
    }

    function revoke(address token) external nonReentrant onlyOwner {
        _revoke(token);
    }

    /// @notice The owner does what it wants with its funds (withdraw, move, pay by hand).
    function execute(address target, uint256 value, bytes calldata data)
        external nonReentrant onlyOwner returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    // ------------------------------------------------------------------ delegate

    /// @notice The delegate's payment: `_msgSender()` is the mandate's delegate, the mandate is live, the payee approved,
    ///         `0 < amount ≤ maxPerPayment`, the period total `≤ maxPerPeriod`, `entryRef` unused.
    function payUnderMandate(address token, address payee, uint256 amount, bytes32 entryRef) external nonReentrant {
        Mandate storage md = mandates[token];
        if (md.delegate == address(0)) revert NoMandate();
        if (_msgSender() != md.delegate) revert NotDelegate();
        if (block.timestamp > md.expiry) revert MandateExpired();
        if (!payeeAllowed[token][payee]) revert PayeeNotAllowed(payee);
        if (amount == 0 || amount > md.maxPerPayment) revert OverPaymentCap(amount, md.maxPerPayment);
        if (refUsed[entryRef]) revert RefAlreadyPaid(entryRef);
        if (block.timestamp >= uint256(md.periodStart) + md.periodSeconds) {
            md.periodStart = uint64(block.timestamp);
            md.spentInPeriod = 0;
        }
        uint256 spent = uint256(md.spentInPeriod) + amount;
        if (spent > md.maxPerPeriod) revert OverPeriodCap(spent, md.maxPerPeriod);
        md.spentInPeriod = uint128(spent);
        refUsed[entryRef] = true;
        if (!IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, address(0), entryRef)) revert PayFailed();
        emit PaidUnderMandate(token, payee, amount, entryRef);
    }

    /// @notice The platform's kill switch: the delegate revokes its own mandate, bound to the current epoch so a public
    ///         revoke signature cannot delete a mandate the owner re-established (CTR-ACC-07).
    function revoke(address token, uint64 epoch_) external nonReentrant {
        Mandate storage md = mandates[token];
        if (md.delegate == address(0)) revert NoMandate();
        if (_msgSender() != md.delegate) revert NotDelegate();
        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);
        _revoke(token);
    }

    // ------------------------------------------------------------------ named builders (CTR-MTX-21)

    /// @notice `MetaTransaction{from: delegate, data: payUnderMandate(…), batch: mandatePayLane(entryRef), nonce: 0}`.
    function mtxPayUnderMandate(address token, address payee, uint256 amount, bytes32 entryRef, uint256 validUntil,
                                bytes calldata sig) external nonReentrant {
        _named(_delegateOf(token), abi.encodeCall(MandateWallet.payUnderMandate, (token, payee, amount, entryRef)),
            mandatePayLane(entryRef), 0, validUntil, sig);
    }

    /// @notice `MetaTransaction{from: delegate, data: revoke(token, epoch), batch: mandateRevokeLane(token, epoch), nonce: 0}`.
    function mtxRevoke(address token, uint64 epoch_, uint256 validUntil, bytes calldata sig) external nonReentrant {
        _named(_delegateOf(token), abi.encodeWithSelector(_REVOKE_SIGNED, token, epoch_),
            mandateRevokeLane(token, epoch_), 0, validUntil, sig);
    }

    /// @notice `MetaTransaction{from: owner, data, batch: 0, nonce}`.
    function mtxExecuteAsOwner(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(owner, data, 0, nonce, validUntil, sig);
    }

    // ------------------------------------------------------------------ views

    function mandatePayLane(bytes32 entryRef) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.mandate.pay", entryRef)));
    }

    function mandateRevokeLane(address token, uint64 epoch_) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.mandate.revoke", token, epoch_)));
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && rec == owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    /// @notice The allowlist (CTR-MTX-19): the base `cancelNonce`, the delegate's two, the owner's four; fee `NONE` only.
    function mtxSelectors() public pure override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a) {
        s = new bytes4[](7);
        c = new uint8[](7);
        a = new uint8[](7);
        s[0] = IMetaTx.cancelNonce.selector;
        s[1] = MandateWallet.payUnderMandate.selector;
        s[2] = _REVOKE_SIGNED;
        s[3] = MandateWallet.setMandate.selector;
        s[4] = MandateWallet.setPayee.selector;
        s[5] = _REVOKE_OWNER;
        s[6] = MandateWallet.execute.selector;
        for (uint256 i; i < 7; ++i) c[i] = FEE_CLASS_ABSOLUTE;
    }

    // ------------------------------------------------------------------ internals

    bytes4 private constant _REVOKE_OWNER = bytes4(keccak256("revoke(address)"));
    bytes4 private constant _REVOKE_SIGNED = bytes4(keccak256("revoke(address,uint64)"));

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == MandateWallet.payUnderMandate.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 132);
        if (sel == _REVOKE_SIGNED) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == MandateWallet.setMandate.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 196);
        if (sel == MandateWallet.setPayee.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (sel == _REVOKE_OWNER) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == MandateWallet.execute.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    function _delegateOf(address token) private view returns (address d) {
        d = mandates[token].delegate;
        if (d == address(0)) revert NoMandate();
    }

    /// @dev The named builders' struct: no relayer or fee binding (mode 0, fee 0), run through the base pipeline.
    function _named(address from, bytes memory data, uint256 batch, uint256 nonce, uint256 validUntil,
                    bytes calldata sig) internal returns (bytes memory) {
        MetaTxLib.MetaTransaction memory m;
        m.from = from;
        m.data = data;
        m.batch = batch;
        m.nonce = nonce;
        m.validUntil = validUntil;
        return _execute(m, sig);
    }

    function _revoke(address token) private {
        delete mandates[token];
        ++epoch[token];
        emit MandateRevoked(token, _msgSender());
    }
}
```
- [ ] **Step 3: Create `src/hedera/HederaMandateWallet.sol`:**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MandateWallet} from "../wallet/MandateWallet.sol";
import {HederaAccountAuth} from "./HederaAccountAuth.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title `MandateWallet` on Hedera (NET-HED-03).
/// @notice A 64-byte signature from an address without code (a native ED25519 account) is checked by HIP-632
///         `isAuthorizedRaw` over the same `MetaTransaction` digest, on the same lane nonces (CTR-TOK-23's rule for
///         tokens); every other signature takes the EVM path. So an ED25519 owner signs its owner calls
///         (`mtxExecuteAsOwnerRaw`, the spec's name for them, or `mtxExecuteAsOwner` / `mtxExecute`), and an owner
///         call `execute(token, payWithFee…)` is how it pays by hand: `isValidSignature` (ERC-1271, under STATICCALL
///         where HIP-632 halts) stays ECDSA, so a meta-transaction with `from = wallet` works for ECDSA owners only.
contract HederaMandateWallet is MandateWallet {
    constructor(address owner_, bytes32 chainUid_) MandateWallet(owner_, chainUid_) {}

    /// @notice `mtxExecuteAsOwner` under its Hedera name: the owner's `MetaTransaction` on lane 0, any signature kind.
    function mtxExecuteAsOwnerRaw(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(owner, data, 0, nonce, validUntil, sig);
    }

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (sig.length == 64 && !SigCheck.isContract(from)) {
            if (!HederaAccountAuth.asView()(from, digest, sig)) revert MetaTxBadSignature();
            return;
        }
        super._requireValidSignature(from, digest, sig);
    }
}
```
- [ ] **Step 4: Create `test/wallet/MandateWallet.t.sol`** (29 + 4 tests; every case of the 16 built wallet tests and the 3 Hedera ones ported, plus the epoch, the lanes, the named builders, the allowlist and the base):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {V2Fixture, UID_, noneInit} from "../v2/helpers/V2Fixture.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";

/// A "token" whose `payWithFee` answers false without moving anything.
contract FalsePayToken {
    function payWithFee(address, uint256, FeeMode, uint256, address, bytes32) external pure returns (bool) {
        return false;
    }
}

/// A `MandateWallet` of `owner` holding 10 000 of a kind-NONE token, a mandate for `delegate` (1 000 per payment,
/// 2 500 per day, 30 days) and one approved payee; chain 7622 with its real `chain_uid`.
abstract contract MandateFixture is V2Fixture {
    uint256 internal constant OWNER_PK = 0x0A11CE;
    uint256 internal constant DELEGATE_PK = 0xDE1E;
    address internal owner = vm.addr(OWNER_PK);
    address internal delegate = vm.addr(DELEGATE_PK);
    address internal npp = address(0x4EE);
    address internal stranger = address(0x5745);
    NoUnderlyingToken internal t;
    MandateWallet internal w;

    function setUp() public virtual {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        t = _none(address(this), 0, address(this));
        w = new MandateWallet(owner, UID_);
        t.mint(address(w), 10_000);
        vm.startPrank(owner);
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        w.setPayee(address(t), npp, true);
        vm.stopPrank();
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// The `MetaTransaction` `mtxPayUnderMandate` builds.
    function _payM(address payee, uint256 amount, bytes32 ref) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m.from = delegate;
        m.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), payee, amount, ref));
        m.batch = w.mandatePayLane(ref);
        m.validUntil = block.timestamp + 300;
    }

    function _pay(address payee, uint256 amount, bytes32 ref) internal {
        _payExpect(payee, amount, ref, "");
    }

    /// Signed by the delegate, submitted through the named entry by a relayer.
    function _payExpect(address payee, uint256 amount, bytes32 ref, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _payM(payee, amount, ref);
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(relayer);
        w.mtxPayUnderMandate(address(t), payee, amount, ref, m.validUntil, sig);
    }

    function _owner(bytes memory data) internal {
        uint256 n = w.mtxNonce(owner, 0);
        uint256 vu = block.timestamp + 300;
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.nonce, m.validUntil) = (owner, data, n, vu);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecuteAsOwner(data, n, vu, sig);
    }

}

/// CTR-ACC-06, CTR-ACC-07 on `MetaTxBase` (CTR-MTX-22): every limit of a delegated payment, the epoch-bound signed
/// revoke, the owner's calls, the named builders and their lanes, the allowlist; ported from the built tests
/// (`legacy/p4/test/MandateWallet.t.sol`) onto a token of the new tree.
contract MandateWalletTest is MandateFixture {
    // ------------------------------------------------------------------ the delegate's payment

    function test_pays_within_mandate_and_settles_like_a_manual_payment() public {
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(w), npp, 700, 0, address(0), keccak256("inv-1"));
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.PaidUnderMandate(address(t), npp, 700, keccak256("inv-1"));
        _pay(npp, 700, keccak256("inv-1"));
        assertEq(t.balanceOf(npp), 700);
        assertEq(t.balanceOf(address(w)), 9_300);
        assertTrue(w.refUsed(keccak256("inv-1")));
        assertEq(w.mtxNonce(delegate, w.mandatePayLane(keccak256("inv-1"))), 1);
    }

    /// One signature, one digest: the named entry and `mtxExecute` run the same struct on the same lane.
    function test_named_entry_is_mtxExecute() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("same"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecute(m, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("same"), m.validUntil, sig);
    }

    function test_per_payment_cap_and_zero() public {
        _payExpect(npp, 1_001, keccak256("big"), abi.encodeWithSelector(MandateWallet.OverPaymentCap.selector, 1_001, 1_000));
        _payExpect(npp, 0, keccak256("zero"), abi.encodeWithSelector(MandateWallet.OverPaymentCap.selector, 0, 1_000));
        _pay(npp, 1_000, keccak256("exact"));
    }

    function test_per_period_cap_and_rollover() public {
        _pay(npp, 1_000, keccak256("a"));
        _pay(npp, 1_000, keccak256("b"));
        _payExpect(npp, 600, keccak256("c"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 2_600, 2_500));
        _pay(npp, 500, keccak256("d"));                       // exactly the cap
        vm.warp(block.timestamp + 1 days - 1);
        _payExpect(npp, 1, keccak256("e"), abi.encodeWithSelector(MandateWallet.OverPeriodCap.selector, 2_501, 2_500));
        vm.warp(block.timestamp + 1);                        // the period ends at periodStart + periodSeconds
        _pay(npp, 600, keccak256("c"));
        (,,, uint64 start,,, uint128 spent) = w.mandates(address(t));
        assertEq(start, block.timestamp);
        assertEq(spent, 600);
        assertEq(t.balanceOf(npp), 3_100);
    }

    function test_payee_not_allowed_and_removed() public {
        _payExpect(stranger, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, stranger));
        _owner(abi.encodeCall(MandateWallet.setPayee, (address(t), npp, false)));
        _payExpect(npp, 10, keccak256("y"), abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, npp));
    }

    function test_payee_is_per_token() public {
        NoUnderlyingToken t2 = _none(address(this), 0, address(this));
        t2.mint(address(w), 100);
        vm.prank(owner);
        w.setMandate(address(t2), delegate, 10, 10, 1 days, uint64(block.timestamp + 1 days));
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.batch, m.validUntil) = (delegate, w.mandatePayLane("t2"), block.timestamp + 300);
        m.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(t2), npp, 5, bytes32("t2")));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.PayeeNotAllowed.selector, npp));
        w.mtxExecute(m, sig);
    }

    function test_expired_mandate() public {
        vm.warp(block.timestamp + 30 days);                  // at the expiry: still live
        _pay(npp, 10, keccak256("last"));
        vm.warp(block.timestamp + 1);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.MandateExpired.selector));
    }

    function test_expired_delegate_signature() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("x"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("x"), m.validUntil, sig);
    }

    /// `entryRef` pays once per wallet, also on another lane through `mtxExecute`.
    function test_entry_ref_pays_once() public {
        _pay(npp, 10, keccak256("once"));
        _payExpect(npp, 10, keccak256("once"), abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("once"));
        m.batch = 77;
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, keccak256("once")));
        w.mtxExecute(m, sig);
    }

    function test_signer_must_be_the_delegate() public {
        // the owner signing a delegate's payment: a valid signature of the wrong party
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("x"));
        m.from = owner;
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxExecute(m, sig);
        // a stranger's signature under the delegate's name
        sig = _sig(0xBAD, w.mtxDigest(_payM(npp, 10, keccak256("x"))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("x"), block.timestamp + 300, sig);
        // and the delegate calling directly is the delegate (it pays its own gas)
        vm.prank(delegate);
        w.payUnderMandate(address(t), npp, 10, keccak256("direct"));
        vm.prank(stranger);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.payUnderMandate(address(t), npp, 10, keccak256("direct2"));
    }

    function test_signature_binds_amount_payee_ref_and_token() public {
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(_payM(npp, 10, keccak256("x"))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), npp, 999, keccak256("x"), vu, sig);
        vm.prank(owner);
        w.setPayee(address(t), stranger, true);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), stranger, 10, keccak256("x"), vu, sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);  // another ref: another lane and another digest
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("y"), vu, sig);
    }

    /// A new delegate voids what the old one signed (the struct's `from` is the current delegate).
    function test_new_delegate_voids_old_signatures() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 10, keccak256("old"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.prank(owner);
        w.setMandate(address(t), stranger, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxPayUnderMandate(address(t), npp, 10, keccak256("old"), m.validUntil, sig);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.mtxExecute(m, sig);
    }

    // ------------------------------------------------------------------ revocation (CTR-ACC-07)

    function _revokeSig(uint64 e) internal view returns (MetaTxLib.MetaTransaction memory m, bytes memory sig) {
        m.from = delegate;
        m.data = abi.encodeWithSignature("revoke(address,uint64)", address(t), e);
        m.batch = w.mandateRevokeLane(address(t), e);
        m.validUntil = block.timestamp + 300;
        sig = _sig(DELEGATE_PK, w.mtxDigest(m));
    }

    function test_owner_revoke_kills_it_and_bumps_the_epoch() public {
        assertEq(w.epoch(address(t)), 1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), owner);
        vm.prank(owner);
        w.revoke(address(t));
        assertEq(w.epoch(address(t)), 2);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.payUnderMandate(address(t), npp, 10, keccak256("x"));
    }

    /// A token that answers false moved nothing: the payment reverts, so `entryRef` and the period stay unspent.
    function test_pay_failed_reverts_everything() public {
        FalsePayToken f = new FalsePayToken();
        vm.startPrank(owner);
        w.setMandate(address(f), delegate, 10, 10, 1 days, uint64(block.timestamp + 1 days));
        w.setPayee(address(f), npp, true);
        vm.stopPrank();
        vm.prank(delegate);
        vm.expectRevert(MandateWallet.PayFailed.selector);
        w.payUnderMandate(address(f), npp, 10, keccak256("f"));
        assertFalse(w.refUsed(keccak256("f")));
    }

    function test_delegate_signed_revoke_kills_it() public {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _revokeSig(1);
        vm.expectEmit(true, true, true, true, address(w));
        emit MandateWallet.MandateRevoked(address(t), delegate);
        vm.prank(relayer);
        w.mtxRevoke(address(t), 1, m.validUntil, sig);
        assertEq(w.epoch(address(t)), 2);
        _payExpect(npp, 10, keccak256("x"), abi.encodeWithSelector(MandateWallet.NoMandate.selector));
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxRevoke(address(t), 1, m.validUntil, sig);
    }

    /// The replay CTR-ACC-07 closes: a public revoke signature cannot delete a mandate the owner re-established.
    function test_revoke_signature_is_bound_to_its_epoch() public {
        (MetaTxLib.MetaTransaction memory m, bytes memory sig) = _revokeSig(1);
        vm.startPrank(owner);
        w.revoke(address(t));                                                     // epoch 2
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 3
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxRevoke(address(t), 1, m.validUntil, sig);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.StaleEpoch.selector, 3, 1));
        w.mtxExecute(m, sig);
        _pay(npp, 10, keccak256("alive"));
        // a current-epoch revoke works; its replay is the used lane
        (m, sig) = _revokeSig(3);
        w.mtxRevoke(address(t), 3, m.validUntil, sig);
        vm.prank(owner);
        w.setMandate(address(t), delegate, 1_000, 2_500, 1 days, uint64(block.timestamp + 30 days));  // epoch 5
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxRevoke(address(t), 3, m.validUntil, sig);
    }

    function test_only_the_delegate_revokes_by_signature() public {
        vm.prank(stranger);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.revoke(address(t), 1);
        vm.prank(owner);
        vm.expectRevert(MandateWallet.NotDelegate.selector);
        w.revoke(address(t), 1);
        bytes memory bad = _sig(0xBAD, w.mtxDigest(_revokeSigM(1)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxRevoke(address(t), 1, block.timestamp + 300, bad);
    }

    function _revokeSigM(uint64 e) internal view returns (MetaTxLib.MetaTransaction memory m) {
        (m,) = _revokeSig(e);
    }

    // ------------------------------------------------------------------ the owner

    function test_mandate_parameters_are_validated() public {
        vm.startPrank(owner);
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), delegate, 1_000, 2_500, 0, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), delegate, 3_000, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), address(0), 1_000, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.expectRevert(MandateWallet.BadMandate.selector);
        w.setMandate(address(t), delegate, 0, 2_500, 1 days, uint64(block.timestamp + 1 days));
        w.setMandate(address(t), delegate, 2_500, 2_500, 1 days, uint64(block.timestamp + 1 days));
        vm.stopPrank();
        assertEq(w.epoch(address(t)), 2);
        vm.expectRevert(MandateWallet.ZeroOwner.selector);
        new MandateWallet(address(0), UID_);
    }

    function test_owner_only_functions() public {
        vm.startPrank(delegate);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setPayee(address(t), stranger, true);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.setMandate(address(t), delegate, 1, 1, 1, 1);
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.revoke(address(t));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.execute(address(t), 0, "");
        vm.stopPrank();
        // the delegate's own signature does not make it the owner
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil) = (delegate, abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true)),
            block.timestamp + 300);
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(MandateWallet.NotOwner.selector);
        w.mtxExecute(m, sig);
    }

    function test_owner_configures_gasless() public {
        bytes memory data = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        uint256 vu = block.timestamp + 300;
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil) = (owner, data, vu);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecuteAsOwner(data, 0, vu, sig);
        assertTrue(w.payeeAllowed(address(t), stranger));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecuteAsOwner(data, 0, vu, sig);
        bytes memory foreign = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxExecuteAsOwner(data, 0, vu, foreign);
        m.nonce = 1;
        foreign = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecuteAsOwner(data, 1, vu, foreign);
    }

    function test_owner_executes_and_cannot_reenter() public {
        _owner(abi.encodeCall(MandateWallet.execute, (address(t), 0, abi.encodeCall(t.transfer, (owner, 100)))));
        assertEq(t.balanceOf(owner), 100);
        bytes memory inner = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        uint256 vu = block.timestamp + 300;
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.nonce, m.validUntil) =
            (owner, abi.encodeCall(MandateWallet.execute, (address(w), 0, inner)), 1, vu);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.CallFailed.selector,
            abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        w.mtxExecuteAsOwner(m.data, 1, vu, sig);
    }

    /// The owner still pays by hand from the wallet: a `MetaTransfer` with `from = wallet`, ERC-1271 by the owner.
    function test_owner_still_pays_manually_through_meta_tx() public {
        bytes32 ref = keccak256("manual");
        MetaTxLib.MetaTransfer memory x = _tr(address(w), npp, 50, ref, t.payLane(ref), RR);
        bytes memory sig = _sig(OWNER_PK, t.mtxTransferDigest(x));
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, sig);
        assertEq(t.balanceOf(npp), 50);
        x = _tr(address(w), npp, 50, keccak256("d"), 1, RR);
        sig = _sig(DELEGATE_PK, t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, sig);
    }

    /// The delegated path never uses an allowance: no `approve` / `transferFrom` / `permit` / `increaseAllowance`
    /// selector anywhere in the wallet's bytecode.
    function test_bytecode_has_no_allowance_selectors() public view {
        bytes memory code = address(w).code;
        bytes4[4] memory banned = [bytes4(0x095ea7b3), 0x23b872dd, 0xd505accf, 0x39509351];
        for (uint256 b = 0; b < banned.length; b++) {
            for (uint256 i = 0; i + 4 <= code.length; i++) {
                bool hit = code[i] == banned[b][0] && code[i + 1] == banned[b][1]
                    && code[i + 2] == banned[b][2] && code[i + 3] == banned[b][3];
                assertFalse(hit, "allowance selector in MandateWallet bytecode");
            }
        }
    }

    // ------------------------------------------------------------------ the base (CTR-MTX-19/21/22, MT-4)

    function test_allowlistPinned() public view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = w.mtxSelectors();
        bytes4[7] memory want = [IMetaTx.cancelNonce.selector,
            bytes4(keccak256("payUnderMandate(address,address,uint256,bytes32)")),
            bytes4(keccak256("revoke(address,uint64)")),
            bytes4(keccak256("setMandate(address,address,uint128,uint128,uint64,uint64)")),
            bytes4(keccak256("setPayee(address,address,bool)")),
            bytes4(keccak256("revoke(address)")),
            bytes4(keccak256("execute(address,uint256,bytes)"))];
        assertEq(s.length, 7);
        for (uint256 i; i < 7; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], 1);
            assertEq(a[i], 0);
        }
        assertEq(w.supportedModes(), 0x03);
    }

    function _signedFails(bytes memory data, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.batch, m.validUntil) = (owner, data, 5, block.timestamp + 300);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(err);
        w.mtxExecute(m, sig);
    }

    function test_unlistedSelectorsAndShapes() public {
        bytes[4] memory calls = [
            abi.encodeCall(MandateWallet.mtxExecuteAsOwner, ("", 0, 0, "")),
            abi.encodeCall(MandateWallet.mtxPayUnderMandate, (address(t), npp, 1, 0, 0, "")),
            abi.encodeCall(MandateWallet.mtxRevoke, (address(t), 1, 0, "")),
            abi.encodeCall(MandateWallet.isValidSignature, (bytes32(0), ""))
        ];
        for (uint256 i; i < calls.length; ++i) {
            _signedFails(calls[i], abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(calls[i])));
        }
        bytes memory sp = abi.encodeCall(MandateWallet.setPayee, (address(t), stranger, true));
        assertEq(sp.length, 100);
        _signedFails(abi.encodePacked(sp, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(sp)));
        bytes memory pu = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), npp, 1, 0));
        assertEq(pu.length, 132);
        _signedFails(abi.encodePacked(pu, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(pu)));
        bytes memory sm = abi.encodeCall(MandateWallet.setMandate, (address(t), delegate, 1, 1, 1, 1));
        assertEq(sm.length, 196);
        _signedFails(abi.encodePacked(sm, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(sm)));
        bytes memory r2 = abi.encodeWithSignature("revoke(address,uint64)", address(t), uint64(1));
        _signedFails(abi.encodePacked(r2, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(r2)));
        bytes memory r1 = abi.encodeWithSignature("revoke(address)", address(t));
        _signedFails(abi.encodePacked(r1, bytes1(0)), abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(r1)));
    }

    function test_feeModesAndSelfSender() public {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil, m.mode) =
            (owner, abi.encodeCall(IMetaTx.cancelNonce, (1)), block.timestamp + 300, MetaTxLib.MODE_FEE_PERCENT);
        bytes memory sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IMetaTx.cancelNonce.selector, m.mode));
        w.mtxExecute(m, sig);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, m.mode));
        w.mtxExecute(m, sig);
        // the wallet is not a self-signer: `from = wallet` is refused at step 1 even with the owner's 1271 signature
        m.mode = 0;
        m.from = address(w);
        sig = _sig(OWNER_PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.SelfSender.selector);
        w.mtxExecute(m, sig);
    }

    function test_domainAndLanes() public view {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt_,) = w.eip712Domain();
        assertEq(name, "SCaaS MandateWallet");
        assertEq(version, "1");
        assertEq(chainId, 7622);
        assertEq(vc, address(w));
        assertEq(salt_, UID_);
        assertEq(w.chainUid(), UID_);
        assertEq(w.mandatePayLane(keccak256("r")), uint256(keccak256(abi.encodePacked("scaas.mandate.pay", keccak256("r")))));
        assertEq(w.mandateRevokeLane(address(t), 3),
            uint256(keccak256(abi.encodePacked("scaas.mandate.revoke", address(t), uint64(3)))));
        assertEq(w.mandateRevokeLane(address(t), 3), uint256(keccak256(bytes.concat(
            bytes("scaas.mandate.revoke"), bytes20(address(t)), bytes8(uint64(3))))));
    }

    function test_noMandateOnTheNamedEntries() public {
        vm.prank(owner);
        w.revoke(address(t));
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxPayUnderMandate(address(t), npp, 1, 0, block.timestamp, "");
        vm.expectRevert(MandateWallet.NoMandate.selector);
        w.mtxRevoke(address(t), 2, block.timestamp, "");
    }

    function test_gas() public {
        MetaTxLib.MetaTransaction memory m = _payM(npp, 700, keccak256("g"));
        bytes memory sig = _sig(DELEGATE_PK, w.mtxDigest(m));
        vm.prank(relayer);
        uint256 g = gasleft();
        w.mtxPayUnderMandate(address(t), npp, 700, keccak256("g"), m.validUntil, sig);
        emit log_named_uint("mtxPayUnderMandate (first payment of the period)", g - gasleft());
    }
}

/// NET-HED-03: an ED25519 owner (no code, 64-byte signature) through HIP-632 over the same `MetaTransaction` digest
/// and lane; the delegate stays ECDSA; ERC-1271 for the owner stays ECDSA.
contract HederaMandateWalletTest is MandateFixture {
    address constant HAS = address(0x16a);
    uint256 constant ED_KEY = 0x0E1;
    address edOwner;
    HederaMandateWallet hw;

    function setUp() public override {
        super.setUp();
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        edOwner = address(uint160(2_000_001));
        MockHederaAccountService(HAS).setEdKey(edOwner, vm.addr(ED_KEY));
        hw = new HederaMandateWallet(edOwner, UID_);
        t.mint(address(hw), 1_000);
    }

    function _ed(bytes32 d) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 vs) = vm.signCompact(ED_KEY, d);
        return abi.encodePacked(r, vs);
    }

    function _edOwnerCall(bytes memory data, uint256 nonce) internal returns (MetaTxLib.MetaTransaction memory m) {
        (m.from, m.data, m.nonce, m.validUntil) = (edOwner, data, nonce, block.timestamp + 300);
    }

    function test_ed25519OwnerSetsMandateAndPaysByHand() public {
        MetaTxLib.MetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setMandate,
            (address(t), delegate, 100, 300, 1 days, uint64(block.timestamp + 30 days))), 0);
        bytes memory sig = _ed(hw.mtxDigest(m));
        vm.prank(relayer);
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, sig);
        (address d,,,,,,) = hw.mandates(address(t));
        assertEq(d, delegate);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, sig);
        // pays by hand: an owner call `execute(token, payWithFee…)`, on the same lane as `mtxExecuteAsOwner`
        bytes memory pay = abi.encodeCall(IERC20Payment.payWithFee, (npp, 40, FeeMode.NONE, 0, address(0), keccak256("hand")));
        m = _edOwnerCall(abi.encodeCall(MandateWallet.execute, (address(t), 0, pay)), 1);
        sig = _ed(hw.mtxDigest(m));
        hw.mtxExecuteAsOwner(m.data, 1, m.validUntil, sig);
        assertEq(t.balanceOf(npp), 40);
    }

    function test_ed25519OwnerRefusals() public {
        MetaTxLib.MetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setPayee, (address(t), npp, true)), 0);
        (bytes32 r, bytes32 vs) = vm.signCompact(DELEGATE_PK, hw.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, abi.encodePacked(r, vs));
        bytes memory sig = _ed(hw.mtxDigest(m));
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, sig);
    }

    /// ERC-1271 runs under STATICCALL, where HIP-632 halts: a `MetaTransfer` with `from = wallet` and the ED25519
    /// owner's signature fails, as specified.
    function test_ed25519OwnerCannotSignAs1271() public {
        MetaTxLib.MetaTransfer memory x = _tr(address(hw), npp, 5, keccak256("1271"), 3, RR);
        bytes memory sig = _ed(t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, sig);
    }

    function test_delegatePaysUnderMandateSetByEd25519Owner() public {
        MetaTxLib.MetaTransaction memory m = _edOwnerCall(abi.encodeCall(MandateWallet.setMandate,
            (address(t), delegate, 100, 300, 1 days, uint64(block.timestamp + 30 days))), 0);
        hw.mtxExecuteAsOwnerRaw(m.data, 0, m.validUntil, _ed(hw.mtxDigest(m)));
        m = _edOwnerCall(abi.encodeCall(MandateWallet.setPayee, (address(t), npp, true)), 1);
        hw.mtxExecuteAsOwnerRaw(m.data, 1, m.validUntil, _ed(hw.mtxDigest(m)));
        MetaTxLib.MetaTransaction memory p;
        (p.from, p.batch, p.validUntil) = (delegate, hw.mandatePayLane(bytes32(uint256(7))), block.timestamp + 300);
        p.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(t), npp, 50, bytes32(uint256(7))));
        bytes memory sig = _sig(DELEGATE_PK, hw.mtxDigest(p));
        hw.mtxPayUnderMandate(address(t), npp, 50, bytes32(uint256(7)), p.validUntil, sig);
        assertEq(t.balanceOf(npp), 50);
    }
}
```
- [ ] **Step 5: Append the wallet vectors to `test/account/AccountKat.t.sol`:**

```diff
diff --git a/smartcontracts/evm/test/account/AccountKat.t.sol b/smartcontracts/evm/test/account/AccountKat.t.sol
index c2d19a2..b1b19db 100644
--- a/smartcontracts/evm/test/account/AccountKat.t.sol
+++ b/smartcontracts/evm/test/account/AccountKat.t.sol
@@ -5,6 +5,10 @@ import {Test} from "forge-std/Test.sol";
 import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
 import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
 import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
+import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
+import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
+import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
+import {noneInit} from "../v2/helpers/V2Fixture.sol";
 
 /// Shared writer of the account-side `MetaTransaction` KATs (metatx.md §15: the `MandateWallet` and `SmartKeyAccount`
 /// vectors are `MetaTransaction` vectors in their own domains), chain 7622 with its real `chain_uid`.
@@ -87,3 +91,46 @@ contract SmartKeyAccountKatTest is MtxKatBase {
         _kat("ska", "./test/vectors/smart_key_account_kat.json", "SCaaS SmartKeyAccount", address(a), m, digest, sig);
     }
 }
+
+/// `mandate_pay_kat.json` and `mandate_revoke_kat.json`: the delegate's `payUnderMandate` on its derived pay lane and
+/// its epoch-bound `revoke(token, 1)` on the derived revoke lane, as `mtxPayUnderMandate` / `mtxRevoke` build them
+/// (mode 0, no fee); both really execute.
+contract MandateWalletKatTest is MtxKatBase {
+    uint256 internal constant OWNER_PK = 0x0A11CE;
+    uint256 internal constant DELEGATE_PK = 0xDE1E;
+    address internal constant PAYEE = address(0x4EE);
+
+    function test_mandateWalletKat() public {
+        vm.chainId(7622);
+        vm.warp(1_800_000_000);
+        NoUnderlyingToken tok =
+            NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), UID, false))));
+        tok.initialize(address(this), 1, noneInit("Points", "PTS", 6, 0, address(this), address(this)));
+        MandateWallet w = new MandateWallet(vm.addr(OWNER_PK), UID);
+        tok.mint(address(w), 1_000e6);
+        vm.startPrank(vm.addr(OWNER_PK));
+        w.setMandate(address(tok), vm.addr(DELEGATE_PK), 100e6, 250e6, 1 days, 1_900_000_000);
+        w.setPayee(address(tok), PAYEE, true);
+        vm.stopPrank();
+
+        bytes32 ref = keccak256("scaas.kat.entryRef");
+        MetaTxLib.MetaTransaction memory m;
+        m.from = vm.addr(DELEGATE_PK);
+        m.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(tok), PAYEE, 12_345_678, ref));
+        m.batch = w.mandatePayLane(ref);
+        m.validUntil = 1_800_000_300;
+        bytes32 digest = w.mtxDigest(m);
+        bytes memory sig = _ecdsa(DELEGATE_PK, digest);
+        w.mtxPayUnderMandate(address(tok), PAYEE, 12_345_678, ref, m.validUntil, sig);
+        assertEq(tok.balanceOf(PAYEE), 12_345_678);
+        _kat("pay", "./test/vectors/mandate_pay_kat.json", "SCaaS MandateWallet", address(w), m, digest, sig);
+
+        m.data = abi.encodeWithSignature("revoke(address,uint64)", address(tok), uint64(1));
+        m.batch = w.mandateRevokeLane(address(tok), 1);
+        digest = w.mtxDigest(m);
+        sig = _ecdsa(DELEGATE_PK, digest);
+        w.mtxRevoke(address(tok), 1, m.validUntil, sig);
+        assertEq(w.epoch(address(tok)), 2);
+        _kat("revoke", "./test/vectors/mandate_revoke_kat.json", "SCaaS MandateWallet", address(w), m, digest, sig);
+    }
+}
```
- [ ] **Step 6: Write the vectors and check them** (`WRITE_KAT=true … --match-path test/account/AccountKat.t.sol`, then without). `test/vectors/mandate_pay_kat.json`:

```json
{
  "batch": "87972948312805241958943890214427271183497668661645623194678295884516753404625",
  "chain_id": "7622",
  "data": "0xd1acac840000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b00000000000000000000000000000000000000000000000000000000000004ee0000000000000000000000000000000000000000000000000000000000bc614e17b3a4b47b86824218fba3a68c90cd53ea80198f8a5efef1a8775864b2cb5eca",
  "digest": "0x3c590280d6cf891fa2cad34b5adae5e10ee9a7cfe84ff94bdefb60667030ae3a",
  "domain_name": "SCaaS MandateWallet",
  "domain_separator": "0xdac9cd8a260e8a9815c4338716dfdc082952558c45ad28413f9f582f5907820a",
  "domain_version": "1",
  "fee": "0",
  "fee_recipient": "0x0000000000000000000000000000000000000000",
  "from": "0x53FA7154E0fCF1d93315ddDD9cda6Ee53e4728e8",
  "mode": "0",
  "nonce": "0",
  "relayer": "0x0000000000000000000000000000000000000000",
  "salt": "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464",
  "signature": "0x32e5c460a94680fad2f6ed59b3cbbe2b27432d033919bfc1239b03bb270d56eb70acdf5dd4906d0f3df0c6193725bddfb9d6ac1e71251134e900531947cacb481b",
  "struct_hash": "0x652fb829147df6abd2a7a6af44f95fbc364e8227d0f9e4f906ee9816478b09e5",
  "type_hash": "0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888",
  "valid_until": "1800000300",
  "verifying_contract": "0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"
}
```
`test/vectors/mandate_revoke_kat.json`:

```json
{
  "batch": "96563714397914206525617153011167034560542929599038512642790731222898199908997",
  "chain_id": "7622",
  "data": "0x5ba216f60000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b0000000000000000000000000000000000000000000000000000000000000001",
  "digest": "0x9fe6d3d4baa00c6018e58d1e2a372a52a7dcbf5d4fda1f7708cbaba26f3e57b3",
  "domain_name": "SCaaS MandateWallet",
  "domain_separator": "0xdac9cd8a260e8a9815c4338716dfdc082952558c45ad28413f9f582f5907820a",
  "domain_version": "1",
  "fee": "0",
  "fee_recipient": "0x0000000000000000000000000000000000000000",
  "from": "0x53FA7154E0fCF1d93315ddDD9cda6Ee53e4728e8",
  "mode": "0",
  "nonce": "0",
  "relayer": "0x0000000000000000000000000000000000000000",
  "salt": "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464",
  "signature": "0xd747e82617d3e2d44d0ae93622fcbd2cb64f745bcf09bd0f32f83f4ea41f11dc2861379d70b03845ffd59728672235b4e269225f70fb5dd3c66ad7b58dde1cc21c",
  "struct_hash": "0xb637c67650d0d65f8b5a709d335e191e3e93390507f0e9eb353f79c4195728a1",
  "type_hash": "0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888",
  "valid_until": "1800000300",
  "verifying_contract": "0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"
}
```
- [ ] **Step 7: Run** `scripts/capped forge test --match-path 'test/wallet/*'` → 33 passed; `--match-path test/account/AccountKat.t.sol`
  → 2; full suite → **993** passed (979 − 16 − 1 − 3 + 33 + 1); size gate 0 errors (`MandateWallet` 15,430 B,
  `HederaMandateWallet` 15,918 B; no token changes).
- [ ] **Step 8: Commit** `P4: MandateWallet and HederaMandateWallet on MetaTxBase (CTR-ACC-06/07), revocation epoch, old wallet to legacy/p4` + trailer.

---

### Task 3: The rename in the other families (Solana type, Move comments); Soroban, TON, Cosmos checked

**Model:** Sonnet, effort medium (mechanical; L12, L13).

**Files:** Modify `smartcontracts/solana/programs/scaas/{Cargo.toml,src/account.rs,src/dex.rs,src/lib.rs,src/mandate.rs,src/state.rs,tests/antilock.rs,tests/common/mod.rs,tests/account.rs}`,
`smartcontracts/move/sui/sources/meta.move`, `smartcontracts/move/sui/tests/meta_tests.move`, `smartcontracts/move/aptos/sources/meta.move`.

**Interfaces:** Solana `scaas::state::SmartKeyAccount` (was `SubjectAccount`; same fields, PDA `["acct", owner]`,
discriminator `sha256("account:SmartKeyAccount")[..8]`). No program interface, instruction, PDA or Move/Soroban/TON/Cosmos
interface changes.

- [ ] **Step 1: Rename every `SubjectAccount` in those two families:**

```bash
cd smartcontracts
/usr/bin/grep -rl 'SubjectAccount' solana/programs move --include=*.rs --include=*.toml --include=*.move \
  | xargs sed -i 's/\bSubjectAccount\b/SmartKeyAccount/g'
/usr/bin/grep -rn 'SubjectAccount' solana move soroban ton cosmos --include=*.rs --include=*.toml --include=*.move \
  --include=*.ts --include=*.tact --include=*.fc | /usr/bin/grep -v target   # → nothing
```

The resulting diff (Solana and Move), plus the pinned discriminator test appended to `tests/account.rs`:

```diff
diff --git a/smartcontracts/move/aptos/sources/meta.move b/smartcontracts/move/aptos/sources/meta.move
index 7de7c72..e3487e2 100644
--- a/smartcontracts/move/aptos/sources/meta.move
+++ b/smartcontracts/move/aptos/sources/meta.move
@@ -35,7 +35,7 @@ module scaas::meta {
     const RESET_KEYS: u8 = 6;
     const MAX_KEYS: u64 = 8;
     const MAX_ORIGINS: u64 = 8;
-    /// `RECOVERY_DELAY` của `SubjectAccount` EVM: guardian chờ 2 ngày, khoá hiện có / chủ huỷ được.
+    /// `RECOVERY_DELAY` của `SmartKeyAccount` EVM: guardian chờ 2 ngày, khoá hiện có / chủ huỷ được.
     const RECOVERY_DELAY_S: u64 = 172_800;
     /// `prune` chỉ xoá lane/pay_ref sau `valid_until + PRUNE_DELAY_S` (review M2). Odoo phát mọi `valid_until` của
     /// một request trong `LANE_HORIZON_S` (= 30 ngày) kể từ lúc tạo request ⇒ khi lane bị xoá, mọi op khác đã ký cho
diff --git a/smartcontracts/move/sui/sources/meta.move b/smartcontracts/move/sui/sources/meta.move
index 4e3ac39..24d5299 100644
--- a/smartcontracts/move/sui/sources/meta.move
+++ b/smartcontracts/move/sui/sources/meta.move
@@ -30,7 +30,7 @@ const SET_GUARDIAN: u8 = 4;
 const CANCEL_RECOVERY: u8 = 5;
 const MAX_KEYS: u64 = 8;
 const MAX_ORIGINS: u64 = 8;
-/// `RECOVERY_DELAY` của `SubjectAccount` EVM (round-3 §C): guardian chờ 2 ngày, khoá hiện có huỷ được.
+/// `RECOVERY_DELAY` của `SmartKeyAccount` EVM (round-3 §C): guardian chờ 2 ngày, khoá hiện có huỷ được.
 const RECOVERY_DELAY_S: u64 = 172_800;
 
 #[error]
diff --git a/smartcontracts/move/sui/tests/meta_tests.move b/smartcontracts/move/sui/tests/meta_tests.move
index 96c1bd9..23ecd9d 100644
--- a/smartcontracts/move/sui/tests/meta_tests.move
+++ b/smartcontracts/move/sui/tests/meta_tests.move
@@ -315,7 +315,7 @@ fun passkey_account_keeps_one_origin() {
     sc.end();
 }
 
-/// Guardian khôi phục sau `RECOVERY_DELAY` (2 ngày, như `SubjectAccount` EVM): khoá mới ký được.
+/// Guardian khôi phục sau `RECOVERY_DELAY` (2 ngày, như `SmartKeyAccount` EVM): khoá mới ký được.
 #[test]
 fun guardian_recovers_after_the_delay() {
     let mut sc = funded();
diff --git a/smartcontracts/solana/programs/scaas/Cargo.toml b/smartcontracts/solana/programs/scaas/Cargo.toml
index abc0e61..1c14eb0 100644
--- a/smartcontracts/solana/programs/scaas/Cargo.toml
+++ b/smartcontracts/solana/programs/scaas/Cargo.toml
@@ -3,7 +3,7 @@ name = "scaas"
 version = "0.1.0"
 edition = "2021"
 publish = false
-description = "SCaaS meta-transaction program: SubjectAccount PDA, lanes, mandates, DEX settlement (S12)"
+description = "SCaaS meta-transaction program: SmartKeyAccount PDA, lanes, mandates, DEX settlement (S12)"
 
 [lib]
 crate-type = ["cdylib", "lib"]
diff --git a/smartcontracts/solana/programs/scaas/src/account.rs b/smartcontracts/solana/programs/scaas/src/account.rs
index 49406a2..922e009 100644
--- a/smartcontracts/solana/programs/scaas/src/account.rs
+++ b/smartcontracts/solana/programs/scaas/src/account.rs
@@ -1,4 +1,4 @@
-//! Config, SubjectAccount, `relay_pay`, quản trị khoá (KeyOp), khôi phục, `prune` (spec §3, §5.1).
+//! Config, SmartKeyAccount, `relay_pay`, quản trị khoá (KeyOp), khôi phục, `prune` (spec §3, §5.1).
 use anchor_lang::prelude::*;
 use anchor_spl::associated_token::AssociatedToken;
 use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};
@@ -35,16 +35,16 @@ pub fn initialize(ctx: Context<Initialize>, network: [u8; 32], admin: Pubkey) ->
 
 // ------------------------------------------------------------------ open
 
-fn new_subject(owner: [u8; 32], bump: u8, key: AuthKey, origins: Vec<String>) -> SubjectAccount {
-    SubjectAccount { owner, bump, keys: vec![key], origins, guardian: None, recovery: None, key_nonce: 0, policy: 0 }
+fn new_subject(owner: [u8; 32], bump: u8, key: AuthKey, origins: Vec<String>) -> SmartKeyAccount {
+    SmartKeyAccount { owner, bump, keys: vec![key], origins, guardian: None, recovery: None, key_nonce: 0, policy: 0 }
 }
 
-fn write_subject(info: &AccountInfo, s: &SubjectAccount) -> Result<()> {
+fn write_subject(info: &AccountInfo, s: &SmartKeyAccount) -> Result<()> {
     let mut data = info.try_borrow_mut_data()?;
     s.try_serialize(&mut &mut data[..])
 }
 
-fn create_subject<'info>(payer: &AccountInfo<'info>, info: &AccountInfo<'info>, system: &AccountInfo<'info>, s: &SubjectAccount) -> Result<()> {
+fn create_subject<'info>(payer: &AccountInfo<'info>, info: &AccountInfo<'info>, system: &AccountInfo<'info>, s: &SmartKeyAccount) -> Result<()> {
     require!(info.data_is_empty(), ScaasError::AlreadyOpen);
     util::create_pda(payer, info, system, &[b"acct", &s.owner, &[s.bump]], s.space())?;
     write_subject(info, s)
@@ -57,7 +57,7 @@ pub struct Open<'info> {
     #[account(mut)]
     pub payer: Signer<'info>,
     pub owner: Signer<'info>,
-    /// CHECK: SubjectAccount PDA, created here.
+    /// CHECK: SmartKeyAccount PDA, created here.
     #[account(mut, seeds = [b"acct", owner.key().as_ref()], bump)]
     pub subject: UncheckedAccount<'info>,
     pub system_program: Program<'info, System>,
@@ -79,7 +79,7 @@ pub fn p256_owner(pk33: &[u8; 33]) -> [u8; 32] {
 pub struct OpenPasskey<'info> {
     #[account(mut)]
     pub payer: Signer<'info>,
-    /// CHECK: SubjectAccount PDA of `sha256("scaas.owner.p256" ‖ pk33)`, created here.
+    /// CHECK: SmartKeyAccount PDA of `sha256("scaas.owner.p256" ‖ pk33)`, created here.
     #[account(mut, seeds = [b"acct", owner.as_ref()], bump)]
     pub subject: UncheckedAccount<'info>,
     /// CHECK: instructions sysvar.
@@ -153,7 +153,7 @@ pub struct RelayPay<'info> {
     pub lane: Signer<'info>,
     #[account(seeds = [b"config"], bump = config.bump)]
     pub config: Account<'info, Config>,
-    /// CHECK: SubjectAccount PDA; opened lazily on the first pay (writable only then), else read in the handler.
+    /// CHECK: SmartKeyAccount PDA; opened lazily on the first pay (writable only then), else read in the handler.
     #[account(seeds = [b"acct", owner.as_ref()], bump)]
     pub subject: UncheckedAccount<'info>,
     #[account(init_if_needed, payer = lane, space = 8 + LanePda::INIT_SPACE,
@@ -190,7 +190,7 @@ pub fn relay_pay(ctx: Context<RelayPay>, owner: [u8; 32], args: PayArgs, auth: A
         s
     } else {
         require_keys_eq!(*info.owner, crate::ID, ScaasError::BadOwner);
-        SubjectAccount::try_deserialize(&mut &info.try_borrow_data()?[..])?
+        SmartKeyAccount::try_deserialize(&mut &info.try_borrow_data()?[..])?
     };
     subject.check_policy()?;
     let op = args.metaop(a.config.network, a.subject.key(), a.mint.key(), OP_PAY, owner);
@@ -287,7 +287,7 @@ pub struct ManageSigned<'info> {
     #[account(seeds = [b"config"], bump = config.bump)]
     pub config: Account<'info, Config>,
     #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
     /// CHECK: destination of `withdraw_lamports` (must equal the signed `to`).
     #[account(mut)]
     pub to: Option<UncheckedAccount<'info>>,
@@ -297,7 +297,7 @@ pub struct ManageSigned<'info> {
     pub system_program: Program<'info, System>,
 }
 
-fn add_origin(s: &mut SubjectAccount, origin: &str) -> Result<()> {
+fn add_origin(s: &mut SmartKeyAccount, origin: &str) -> Result<()> {
     require!(!origin.is_empty() && origin.len() <= MAX_ORIGIN_LEN, ScaasError::BadOrigin);
     if !s.origins.iter().any(|o| o == origin) {
         require!(s.origins.len() < MAX_ORIGINS, ScaasError::TooMany);
@@ -373,7 +373,7 @@ pub struct StartRecovery<'info> {
     pub guardian: Signer<'info>,
     #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump,
               constraint = subject.guardian == Some(guardian.key()) @ ScaasError::NotGuardian)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
     pub system_program: Program<'info, System>,
 }
 
@@ -391,7 +391,7 @@ pub fn start_recovery(ctx: Context<StartRecovery>, key: AuthKey, origin: String)
 #[derive(Accounts)]
 pub struct FinishRecovery<'info> {
     #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
 }
 
 /// Sau trễ: khoá khôi phục thay MỌI khoá cũ (khoá mất/bị lộ). Không cần quyền — đã hẹn trước 2 ngày, khoá hiện có huỷ
diff --git a/smartcontracts/solana/programs/scaas/src/dex.rs b/smartcontracts/solana/programs/scaas/src/dex.rs
index 38b5ab5..685b13f 100644
--- a/smartcontracts/solana/programs/scaas/src/dex.rs
+++ b/smartcontracts/solana/programs/scaas/src/dex.rs
@@ -116,9 +116,9 @@ pub struct Settle<'info> {
     #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
     pub market: Box<Account<'info, Market>>,
     #[account(seeds = [b"acct", a.maker.as_ref()], bump = subject_a.bump)]
-    pub subject_a: Box<Account<'info, SubjectAccount>>,
+    pub subject_a: Box<Account<'info, SmartKeyAccount>>,
     #[account(seeds = [b"acct", b.maker.as_ref()], bump = subject_b.bump)]
-    pub subject_b: Box<Account<'info, SubjectAccount>>,
+    pub subject_b: Box<Account<'info, SmartKeyAccount>>,
     #[account(init_if_needed, payer = lane, space = 8 + Fill::INIT_SPACE,
               seeds = [b"fill", market.key().as_ref(), hash_a.as_ref()], bump)]
     pub fill_a: Box<Account<'info, Fill>>,
@@ -174,7 +174,7 @@ fn check_order(
     network: &[u8; 32],
     market: &Market,
     market_key: &Pubkey,
-    subject: &SubjectAccount,
+    subject: &SmartKeyAccount,
     counterparty: &[u8; 32],
     lane: &Pubkey,
     min_nonce: u64,
@@ -286,7 +286,7 @@ pub struct CancelSigned<'info> {
     #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
     pub market: Account<'info, Market>,
     #[account(seeds = [b"acct", order.maker.as_ref()], bump = subject.bump)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
     #[account(init_if_needed, payer = lane, space = 8 + Fill::INIT_SPACE,
               seeds = [b"fill", market.key().as_ref(), order_hash.as_ref()], bump)]
     pub fill: Account<'info, Fill>,
@@ -323,7 +323,7 @@ pub struct InvalidateNonces<'info> {
     #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
     pub market: Account<'info, Market>,
     #[account(seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
     #[account(init_if_needed, payer = lane, space = 8 + MinNonce::INIT_SPACE,
               seeds = [b"minnonce", market.key().as_ref(), subject.key().as_ref()], bump)]
     pub min_nonce: Account<'info, MinNonce>,
diff --git a/smartcontracts/solana/programs/scaas/src/lib.rs b/smartcontracts/solana/programs/scaas/src/lib.rs
index 59ff22d..b0d34ab 100644
--- a/smartcontracts/solana/programs/scaas/src/lib.rs
+++ b/smartcontracts/solana/programs/scaas/src/lib.rs
@@ -1,7 +1,7 @@
 //! `scaas` — meta-transaction cấp program trên Solana (S12, `docs/networks/solana.md`;
 //! bản đóng băng `docs/history/specs/2026-10-04-net-solana.md`).
 //! Chủ thể ký thông điệp tách miền (ed25519 raw/OCMS qua precompile Ed25519, passkey qua precompile Secp256r1); relayer
-//! gửi tx từ lane của chính nó. Số dư = token account của SubjectAccount PDA. Đường nóng chỉ GHI account riêng của thao
+//! gửi tx từ lane của chính nó. Số dư = token account của SmartKeyAccount PDA. Đường nóng chỉ GHI account riêng của thao
 //! tác (RS12-2).
 #![allow(unexpected_cfgs, ambiguous_glob_reexports)]
 use anchor_lang::prelude::*;
diff --git a/smartcontracts/solana/programs/scaas/src/mandate.rs b/smartcontracts/solana/programs/scaas/src/mandate.rs
index 06ef7e2..74882a2 100644
--- a/smartcontracts/solana/programs/scaas/src/mandate.rs
+++ b/smartcontracts/solana/programs/scaas/src/mandate.rs
@@ -57,7 +57,7 @@ pub struct MandateOpen<'info> {
     #[account(seeds = [b"config"], bump = config.bump)]
     pub config: Account<'info, Config>,
     #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
     #[account(init, payer = lane, space = 8 + Mandate::INIT_SPACE,
               seeds = [b"mandate", subject.key().as_ref(), init.seed.as_ref()], bump)]
     pub mandate: Account<'info, Mandate>,
@@ -239,7 +239,7 @@ pub struct MandateClose<'info> {
     #[account(seeds = [b"config"], bump = config.bump)]
     pub config: Account<'info, Config>,
     #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
-    pub subject: Account<'info, SubjectAccount>,
+    pub subject: Account<'info, SmartKeyAccount>,
     #[account(mut, close = rent_payer, seeds = [b"mandate", mandate.account.as_ref(), mandate.seed.as_ref()],
               bump = mandate.bump, has_one = rent_payer, constraint = mandate.account == subject.key() @ ScaasError::BadOwner)]
     pub mandate: Account<'info, Mandate>,
diff --git a/smartcontracts/solana/programs/scaas/src/state.rs b/smartcontracts/solana/programs/scaas/src/state.rs
index 2922117..35c1120 100644
--- a/smartcontracts/solana/programs/scaas/src/state.rs
+++ b/smartcontracts/solana/programs/scaas/src/state.rs
@@ -53,7 +53,7 @@ pub struct Recovery {
 
 /// Chủ thể (RS12-3/4/5). Số dư = token account có owner = PDA này. Kích thước theo số khoá/origin (lớn dần).
 #[account]
-pub struct SubjectAccount {
+pub struct SmartKeyAccount {
     pub owner: [u8; 32],
     pub bump: u8,
     pub keys: Vec<AuthKey>,
@@ -64,7 +64,7 @@ pub struct SubjectAccount {
     pub policy: u8,
 }
 
-impl SubjectAccount {
+impl SmartKeyAccount {
     pub fn space(&self) -> usize {
         8 + borsh::to_vec(self).map(|v| v.len()).unwrap_or(0)
     }
diff --git a/smartcontracts/solana/programs/scaas/tests/account.rs b/smartcontracts/solana/programs/scaas/tests/account.rs
index 1a7083e..9c60ddf 100644
--- a/smartcontracts/solana/programs/scaas/tests/account.rs
+++ b/smartcontracts/solana/programs/scaas/tests/account.rs
@@ -348,3 +348,14 @@ fn two_signed_ops_for_one_request_pay_once_before_and_after_prune() {
     expect_err(env.pay(&alice, &usd, TOKEN, &op2), E::Expired);
     assert_eq!(env.balance(&src), 90, "paid exactly once");
 }
+
+/// CTR-ACC-11 (P4): the account type is `SmartKeyAccount`; Anchor's discriminator follows the name. A deployed program
+/// is immutable (upgrade authority None, NET-SOL-20), so no `SubjectAccount` data ever meets this code: a new build is
+/// a new deployment. The PDA (`["acct", owner]`) and its layout are unchanged.
+#[test]
+fn smart_key_account_discriminator_follows_the_name() {
+    use sha2::{Digest, Sha256};
+    let d = <scaas::state::SmartKeyAccount as anchor_lang::Discriminator>::DISCRIMINATOR;
+    assert_eq!(d, &Sha256::digest(b"account:SmartKeyAccount")[..8]);
+    assert_ne!(d, &Sha256::digest(b"account:SubjectAccount")[..8]);
+}
diff --git a/smartcontracts/solana/programs/scaas/tests/antilock.rs b/smartcontracts/solana/programs/scaas/tests/antilock.rs
index ca71f61..f5c65ae 100644
--- a/smartcontracts/solana/programs/scaas/tests/antilock.rs
+++ b/smartcontracts/solana/programs/scaas/tests/antilock.rs
@@ -1,5 +1,5 @@
 //! R30 trên Solana (L8, L12): thao tác khác contract của cùng chủ thể không chung khoá — không nonce chung, không
-//! account GHI chung (trừ lane relayer); Config/Market/SubjectAccount chỉ đọc trên đường nóng.
+//! account GHI chung (trừ lane relayer); Config/Market/SmartKeyAccount chỉ đọc trên đường nóng.
 mod common;
 
 use std::collections::BTreeSet;
@@ -77,7 +77,7 @@ fn two_assets_two_lanes_in_any_order() {
     assert_eq!((w.env.balance(&ata(&bob, &w.usd, &TOKEN)), w.env.balance(&ata(&bob, &w.eur, &TOKEN))), (7, 3));
 }
 
-/// L12: tập account GHI của hai thao tác khác contract (trừ lane) rời nhau; Config/Market/SubjectAccount readonly.
+/// L12: tập account GHI của hai thao tác khác contract (trừ lane) rời nhau; Config/Market/SmartKeyAccount readonly.
 #[test]
 fn hot_path_write_sets_are_disjoint() {
     let w = setup();
@@ -118,7 +118,7 @@ fn hot_path_write_sets_are_disjoint() {
     assert!(wx.is_disjoint(&wx2), "two assets of one Account");
     let fixed = [env.config(), w.market, w.alice.account(), account_of(&bob.pk())];
     for (name, ix) in [("pay", &x), ("pay2", &x2), ("mandate_pay", &y), ("cancel", &z), ("settle", &s)] {
-        assert!(readonly(ix, &fixed), "{name} writes Config/Market/SubjectAccount");
+        assert!(readonly(ix, &fixed), "{name} writes Config/Market/SmartKeyAccount");
     }
     assert_eq!(wz.len(), 1);
     println!("pay writes {} accounts besides the lane: {:?}", wx.len(), wx);
diff --git a/smartcontracts/solana/programs/scaas/tests/common/mod.rs b/smartcontracts/solana/programs/scaas/tests/common/mod.rs
index 1017a16..bd49d98 100644
--- a/smartcontracts/solana/programs/scaas/tests/common/mod.rs
+++ b/smartcontracts/solana/programs/scaas/tests/common/mod.rs
@@ -420,7 +420,7 @@ impl Env {
         self.send(&[ed_ix(&[e]), ix], &[])
     }
 
-    pub fn subject(&self, addr: &Pubkey) -> scaas::state::SubjectAccount {
+    pub fn subject(&self, addr: &Pubkey) -> scaas::state::SmartKeyAccount {
         self.account(addr).expect("subject account")
     }
```
- [ ] **Step 2: Run each family's own suite** (one at a time): `scripts/capped smartcontracts/scripts/test.sh solana` → 42
  passed (account 12 incl. the new test, antilock 4, dex 7, mandate 7, pay 10, unit 2); `test.sh sui` → 68; `test.sh aptos`
  → 105 and `ok: 8 relayed entries and p256::verify_with are not callable from other modules`; untouched but run as the
  every-family check: `test.sh soroban` → 28, `test.sh cosmos` → 10, `test.sh ton` → 28 (4 suites).
- [ ] **Step 3: Commit** `P4: SmartKeyAccount in Solana and the Move comments (CTR-ACC-11)` + trailer.

---

### Task 4: clientkeys — the owner call as the account's salted `MetaTransaction`, the KATs

**Model:** Sonnet, effort medium (L15).

**Files:** Modify `clients/clientkeys/src/evm.js`, `src/webauthn.js` (comment), `test/evm.test.js`, `test/webauthn.test.js` (title).

**Interfaces:** `metaTxTypedData({name, contract, chainId, chainUid, message})` (new);
`ownerCallTypedData({account, chainId, chainUid, data, nonce, validUntil})` and `checkOwnerCall(td, {account, chainId,
chainUid, newKey, now, maxWindow})` gain `chainUid` (breaking for callers: the Odoo signer page, bamboo-dms TODO).
`passkey-signer.js` / `seed-signer.js` re-exports unchanged. Consumes the three KATs of Tasks 1–2 and
`smart_key_account_create2.json`.

- [ ] **Step 1: Apply:**

```diff
diff --git a/clients/clientkeys/src/evm.js b/clients/clientkeys/src/evm.js
index 5cb73b9..f3de35f 100644
--- a/clients/clientkeys/src/evm.js
+++ b/clients/clientkeys/src/evm.js
@@ -1,4 +1,4 @@
-// EVM pieces: EIP-712 digests, addresses, SubjectAccount key/salt/CREATE2, Merkle batch.
+// EVM pieces: EIP-712 digests, addresses, SmartKeyAccount key/salt/CREATE2, Merkle batch.
 import {
   keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, addressWord, abiEncode,
 } from './bytes.js';
@@ -47,7 +47,7 @@ export function hashTypedData(td) {
   ));
 }
 
-// ------------------------------------------------------------------ SubjectAccount
+// ------------------------------------------------------------------ SmartKeyAccount (CTR-ACC-01, CTR-ACC-02)
 
 export const KEY_P256_WEBAUTHN = 1;
 export const KEY_SECP256K1 = 2;
@@ -78,7 +78,7 @@ export function predictAccount(implementation, salt, factory) {
   return checksumAddress(hex(h.subarray(12)));
 }
 
-/** `abi.encode(keyIndex, proof, sig)` — what `SubjectAccount.isValidSignature` decodes (RS4-3). */
+/** `abi.encode(keyIndex, proof, sig)` — what `SmartKeyAccount.isValidSignature` decodes (CTR-ACC-02). */
 export function accountSignature(keyIndex, proof, inner) {
   return abiEncode(['uint256', 'bytes32[]', 'bytes'], [keyIndex, proof, inner]);
 }
@@ -122,8 +122,12 @@ export function processProof(proof, leaf) {
 
 const DOMAIN_TYPE = [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
   { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
-const OWNER_CALL_TYPES = { EIP712Domain: DOMAIN_TYPE, OwnerCall: [{ name: 'data', type: 'bytes' },
-  { name: 'nonce', type: 'uint256' }, { name: 'validUntil', type: 'uint256' }] };
+// The salted domain of every contract on `MetaTxBase` (CTR-MTX-02, CLI-SGN-33) and its generic struct (CTR-MTX-15).
+const SALTED_DOMAIN_TYPE = [...DOMAIN_TYPE, { name: 'salt', type: 'bytes32' }];
+const MTX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransaction: ['from:address', 'data:bytes', 'batch:uint256',
+  'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
+  .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })) };
+const ZERO_ADDRESS = '0x' + '00'.repeat(20);
 const PAY_TYPES = { EIP712Domain: DOMAIN_TYPE, MetaTransaction: ['from:address', 'to:address', 'value:uint256',
   'data:bytes', 'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256',
   'feeRecipient:address'].map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })) };
@@ -159,21 +163,34 @@ export function addKeyCalldata(key) {
   return concatBytes(ADD_KEY_SELECTOR, abiEncode([KEY_TUPLE], [key]));
 }
 
-export function ownerCallTypedData({ account, chainId, data, nonce, validUntil }) {
+/** A `MetaTransaction` (CTR-MTX-15) of the SCaaS contract `contract` in its salted domain `(name, "1", chainId,
+ *  contract, chainUid)`; unset fields are 0 (no relayer or fee binding, fee mode NONE). */
+export function metaTxTypedData({ name, contract, chainId, chainUid, message }) {
+  const m = { from: ZERO_ADDRESS, data: '0x', batch: '0', nonce: '0', validUntil: '0', mode: 0, relayer: ZERO_ADDRESS,
+    fee: '0', feeRecipient: ZERO_ADDRESS, ...message };
   return {
-    types: OWNER_CALL_TYPES, primaryType: 'OwnerCall',
-    domain: { name: 'SCaaS SubjectAccount', version: '1', chainId: Number(chainId), verifyingContract: account },
-    message: { data: hex(data), nonce: String(nonce), validUntil: String(validUntil) },
+    types: MTX_TYPES, primaryType: 'MetaTransaction',
+    domain: { name, version: '1', chainId: Number(chainId), verifyingContract: contract, salt: hex(fromHex(chainUid)) },
+    message: { ...m, data: typeof m.data === 'string' ? m.data : hex(m.data), batch: String(m.batch),
+      nonce: String(m.nonce), validUntil: String(m.validUntil), fee: String(m.fee) },
   };
 }
 
-/** The server's OwnerCall must be exactly `addKey(newKey)` on `account`/`chainId`; nonce and a
- *  near deadline come from the server. Returns the digest to sign, or throws. */
-export function checkOwnerCall(td, { account, chainId, newKey, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
+/** The account's own call (CTR-ACC-10): `MetaTransaction{from: account, data, batch: 0, nonce, validUntil}` in the
+ *  domain `SCaaS SmartKeyAccount`, exactly what `mtxExecuteAsOwner(data, nonce, validUntil, sig)` builds. */
+export function ownerCallTypedData({ account, chainId, chainUid, data, nonce, validUntil }) {
+  return metaTxTypedData({ name: 'SCaaS SmartKeyAccount', contract: account, chainId, chainUid,
+    message: { from: account, data, nonce, validUntil } });
+}
+
+/** The server's owner call must be exactly `addKey(newKey)` signed by `account` itself on lane 0, on `chainId` and the
+ *  signer's own pinned `chainUid` (a missing or different salt is refused, CLI-SGN-33); nonce and a near deadline come
+ *  from the server. Returns the digest to sign, or throws (CLI-SGN-05). */
+export function checkOwnerCall(td, { account, chainId, chainUid, newKey, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
   const m = (td && td.message) || {};
   const nonce = uint(m.nonce, 'the nonce');
   const until = deadline(m.validUntil, now, maxWindow);
-  const mine = digestOf(ownerCallTypedData({ account, chainId, data: addKeyCalldata(newKey), nonce, validUntil: until }));
+  const mine = digestOf(ownerCallTypedData({ account, chainId, chainUid, data: addKeyCalldata(newKey), nonce, validUntil: until }));
   if (hex(digestOf(td)) !== hex(mine)) refuse('this is not the key change you asked for');
   return mine;
 }
diff --git a/clients/clientkeys/src/webauthn.js b/clients/clientkeys/src/webauthn.js
index e24d1b9..92919e3 100644
--- a/clients/clientkeys/src/webauthn.js
+++ b/clients/clientkeys/src/webauthn.js
@@ -1,4 +1,4 @@
-// WebAuthn (passkey) helpers for SubjectAccount (R31). Nothing secret: the private key never
+// WebAuthn (passkey) helpers for SmartKeyAccount (R31). Nothing secret: the private key never
 // leaves the authenticator; we only shape options and re-encode what it returns.
 import { abiEncode, fromHex, fromB64url } from './bytes.js';
 
diff --git a/clients/clientkeys/test/evm.test.js b/clients/clientkeys/test/evm.test.js
index 8b7177f..41e6c59 100644
--- a/clients/clientkeys/test/evm.test.js
+++ b/clients/clientkeys/test/evm.test.js
@@ -5,7 +5,7 @@ import { secp256k1 } from '@noble/curves/secp256k1.js';
 import {
   hashTypedData, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
   batchLeaf, evmAddress, passkeySubjectKey, addKeyCalldata, ownerCallTypedData, checkOwnerCall, checkPayment,
-  keyProofMessage,
+  keyProofMessage, metaTxTypedData,
 } from '../src/evm.js';
 import { abiEncode, hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
 
@@ -31,18 +31,37 @@ test('EIP-712 digest of the typed data Odoo issues = MetaTx KAT (MetaTxKat.t.sol
   assert.equal(hex(hashTypedData(td)), k.digest);
 });
 
-test('OwnerCall typed data (as Odoo issues it) hashes to the digest pinned in SubjectAccount.t.sol', () => {
-  const td = {
-    types: {
-      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
-        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
-      OwnerCall: [{ name: 'data', type: 'bytes' }, { name: 'nonce', type: 'uint256' }, { name: 'validUntil', type: 'uint256' }],
-    },
-    primaryType: 'OwnerCall',
-    domain: { name: 'SCaaS SubjectAccount', version: '1', chainId: 31337, verifyingContract: '0x' + '00'.repeat(18) + 'acc0' },
-    message: { data: '0x1234', nonce: '3', validUntil: '1800000000' },
-  };
-  assert.equal(hex(hashTypedData(td)), '0xcb4f8a0d408df2dc182b5e27404206cffebb38f25930b952979fb368425931e6');
+test('SmartKeyAccount owner call = forge KAT (AccountKat.t.sol, smart_key_account_kat.json)', () => {
+  const k = read('smart_key_account_kat.json');
+  assert.equal(hex(addKeyCalldata(secpSubjectKey('0x' + '77'.repeat(20)))), k.data);
+  const td = ownerCallTypedData({ account: k.verifying_contract, chainId: Number(k.chain_id), chainUid: k.salt,
+    data: k.data, nonce: k.nonce, validUntil: k.valid_until });
+  assert.equal(hex(hashTypedData(td)), k.digest);
+  assert.equal(hex(checkOwnerCall(td, { account: k.verifying_contract, chainId: 7622, chainUid: k.salt,
+    newKey: secpSubjectKey('0x' + '77'.repeat(20)), now: 1_800_000_000 })), k.digest);
+  // the account encoding of the seed key's ECDSA signature (key index 0, no batch proof)
+  const sig = fromHex(k.signature).subarray(160, 225);
+  assert.equal(hex(accountSignature(0, [], sig)), k.signature);
+  const r = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27);
+  assert.equal(evmAddress(r.recoverPublicKey(fromHex(k.digest)).toBytes(false)), k.signer_key);
+});
+
+test('MandateWallet pay and revoke = forge KATs (mandate_pay_kat.json, mandate_revoke_kat.json)', () => {
+  for (const f of ['mandate_pay_kat.json', 'mandate_revoke_kat.json']) {
+    const k = read(f);
+    const td = metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: Number(k.chain_id),
+      chainUid: k.salt, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until } });
+    assert.equal(hex(hashTypedData(td)), k.digest, f);
+  }
+  // the derived lanes: keccak256("scaas.mandate.pay" ‖ entryRef), keccak256("scaas.mandate.revoke" ‖ token ‖ uint64 epoch)
+  const pay = read('mandate_pay_kat.json');
+  const ref = fromHex(pay.data).subarray(100, 132);
+  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.pay'), ...ref])))), BigInt(pay.batch));
+  const rev = read('mandate_revoke_kat.json');
+  const token = fromHex(rev.data).subarray(16, 36);
+  const epoch = new Uint8Array(8); epoch[7] = 1;
+  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.revoke'), ...token, ...epoch])))),
+    BigInt(rev.batch));
 });
 
 test('passkey keyId = keccak(abi.encode(SubjectKey)) as cast computes it', async () => {
@@ -54,8 +73,8 @@ test('passkey keyId = keccak(abi.encode(SubjectKey)) as cast computes it', async
   assert.equal(hex(keyId(key)), '0xe01e0b8f122754973202cd330eb728c9d9b19f4f31bbe7e33d012e745be6f631');
 });
 
-test('SubjectAccount CREATE2: salt and clone address match the forge-pinned vector', () => {
-  const v = read('subject_account_create2.json');
+test('SmartKeyAccount CREATE2: salt and clone address match the forge-pinned vector', () => {
+  const v = read('smart_key_account_create2.json');
   const addr = evmAddress(secp256k1.getPublicKey(fromHex(v.seedPrivateKey.slice(2).padStart(64, '0')), false));
   const salt = accountSalt(secpSubjectKey(addr), v.guardian);
   assert.equal(hex(salt), v.salt);
@@ -90,49 +109,59 @@ const ACCOUNT = '0x' + 'ac'.repeat(20);
 const NOW = 1_800_000_000;
 const NEW_KEY = secpSubjectKey('0x' + '77'.repeat(20));
 
-/** OwnerCall exactly as Odoo `_owner_call_typed_data` issues it. */
-function odooOwnerCall(data, { account = ACCOUNT, chainId = 31337, nonce = '2', validUntil = String(NOW + 600) } = {}) {
-  return {
-    types: {
-      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
-        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
-      OwnerCall: [{ name: 'data', type: 'bytes' }, { name: 'nonce', type: 'uint256' }, { name: 'validUntil', type: 'uint256' }],
-    },
-    primaryType: 'OwnerCall',
-    domain: { name: 'SCaaS SubjectAccount', version: '1', chainId, verifyingContract: account },
-    message: { data: hex(data), nonce, validUntil },
-  };
+const UID = '0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464';   // chain 7622 (chain-uids.json)
+
+/** The account's owner call as a server issues it: a `MetaTransaction` in the salted `SCaaS SmartKeyAccount` domain. */
+function serverOwnerCall(data, { account = ACCOUNT, chainId = 7622, salt = UID, nonce = '2', validUntil = String(NOW + 600),
+  ...over } = {}) {
+  const td = metaTxTypedData({ name: 'SCaaS SmartKeyAccount', contract: account, chainId, chainUid: salt,
+    message: { from: account, data, nonce, validUntil, ...over } });
+  td.message.nonce = nonce;
+  return td;
 }
 
-test('OwnerCall: the client signs only addKey(the key it just made) on its own account', () => {
-  const want = { account: ACCOUNT, chainId: 31337, newKey: NEW_KEY, now: NOW };
-  const td = odooOwnerCall(addKeyCalldata(NEW_KEY));
+test('owner call: the client signs only addKey(the key it just made) as its own account, on its chain', () => {
+  const want = { account: ACCOUNT, chainId: 7622, chainUid: UID, newKey: NEW_KEY, now: NOW };
+  const td = serverOwnerCall(addKeyCalldata(NEW_KEY));
   assert.equal(hex(checkOwnerCall(td, want)), hex(hashTypedData(td)));
-  assert.equal(hex(hashTypedData(ownerCallTypedData({ account: ACCOUNT, chainId: 31337, data: addKeyCalldata(NEW_KEY),
-    nonce: '2', validUntil: String(NOW + 600) }))), hex(hashTypedData(td)));
+  assert.equal(hex(hashTypedData(ownerCallTypedData({ account: ACCOUNT, chainId: 7622, chainUid: UID,
+    data: addKeyCalldata(NEW_KEY), nonce: '2', validUntil: String(NOW + 600) }))), hex(hashTypedData(td)));
   // addKey(abi.encode(key)): selector of addKey((uint8,bytes32,bytes32,bytes32,bytes32)) + 5 words.
   assert.equal(hex(addKeyCalldata(NEW_KEY).subarray(0, 4)),
     hex(keccak_256(utf8ToBytes('addKey((uint8,bytes32,bytes32,bytes32,bytes32))')).subarray(0, 4)));
   const drain = concatSel('execute(address,uint256,bytes)');
+  const unsalted = serverOwnerCall(addKeyCalldata(NEW_KEY));
+  unsalted.types = { ...unsalted.types, EIP712Domain: unsalted.types.EIP712Domain.slice(0, 4) };
+  delete unsalted.domain.salt;
+  const oldShape = serverOwnerCall(addKeyCalldata(NEW_KEY));
+  oldShape.domain.name = 'SCaaS SubjectAccount';
   const refused = [
-    odooOwnerCall(drain),                                                      // any other call
-    odooOwnerCall(addKeyCalldata(secpSubjectKey('0x' + '66'.repeat(20)))),     // someone else's key
-    odooOwnerCall(addKeyCalldata(NEW_KEY), { account: '0x' + 'bd'.repeat(20) }),
-    odooOwnerCall(addKeyCalldata(NEW_KEY), { chainId: 1 }),
-    odooOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW - 1) }),
-    odooOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW + 7200) }),
-    odooOwnerCall(addKeyCalldata(NEW_KEY), { nonce: '-1' }),
-    { ...odooOwnerCall(addKeyCalldata(NEW_KEY)), primaryType: 'MetaTransaction' },
+    serverOwnerCall(drain),                                                      // any other call
+    serverOwnerCall(addKeyCalldata(secpSubjectKey('0x' + '66'.repeat(20)))),     // someone else's key
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { account: '0x' + 'bd'.repeat(20) }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { from: '0x' + 'bd'.repeat(20) }),  // signed as another party
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { chainId: 1 }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { salt: '0x' + '11'.repeat(32) }),  // another chain_uid
+    unsalted,                                                                    // no salt (CLI-SGN-33)
+    oldShape,                                                                    // the built domain name
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { batch: '1' }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { mode: 1, relayer: '0x' + '02'.repeat(20) }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { fee: '1' }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW - 1) }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW + 7200) }),
+    serverOwnerCall(addKeyCalldata(NEW_KEY), { nonce: '-1' }),
+    { ...serverOwnerCall(addKeyCalldata(NEW_KEY)), primaryType: 'OwnerCall' },
   ];
-  const extra = odooOwnerCall(addKeyCalldata(NEW_KEY));
-  extra.types.OwnerCall.push({ name: 'value', type: 'uint256' });
+  const extra = serverOwnerCall(addKeyCalldata(NEW_KEY));
+  extra.types = { ...extra.types, MetaTransaction: [...extra.types.MetaTransaction, { name: 'value', type: 'uint256' }] };
   extra.message.value = '1';
   refused.push(extra);
   for (const [i, bad] of refused.entries()) assert.throws(() => checkOwnerCall(bad, want), /Refusing to sign/, `case ${i}`);
+  assert.throws(() => checkOwnerCall(td, { ...want, chainUid: '0x' + '11'.repeat(32) }), /Refusing to sign/);
   // A passkey key is rebuilt from the server's rpId/origin and the coordinates the device returned.
   const pk = passkeySubjectKey({ x: new Uint8Array(32).fill(1), y: new Uint8Array(32).fill(2), rpId: 'pay.example.com',
     origin: 'https://pay.example.com' });
-  checkOwnerCall(odooOwnerCall(addKeyCalldata(pk)), { ...want, newKey: pk });
+  checkOwnerCall(serverOwnerCall(addKeyCalldata(pk)), { ...want, newKey: pk });
 });
 
 function concatSel(sig) {
@@ -171,7 +200,7 @@ test('payment: the client signs only a pay of the amount it showed, from its own
   checkPayment(odooPayment({ value: '125000000000' }), { ...intent, amount: 125000 });
   checkPayment(odooPayment({ mode: 0, relayer: '0x' + '00'.repeat(20) }), intent);
   const refused = [
-    odooOwnerCall(addKeyCalldata(NEW_KEY)),                       // an owner call disguised as a payment
+    serverOwnerCall(addKeyCalldata(NEW_KEY)),                     // an owner call disguised as a payment
     odooPayment({ value: '125000500001' }),                       // more than shown
     odooPayment({ from: '0x' + 'bd'.repeat(20) }),
     odooPayment({ data: hex(concatSel('trade(address,uint256,address)')) }),
diff --git a/clients/clientkeys/test/webauthn.test.js b/clients/clientkeys/test/webauthn.test.js
index 991ca28..e688832 100644
--- a/clients/clientkeys/test/webauthn.test.js
+++ b/clients/clientkeys/test/webauthn.test.js
@@ -63,7 +63,7 @@ test('software authenticator: SPKI → (x,y), assertion verifies over sha256(aut
   assert.throws(() => publicKeyFromSpki(auth.spki.subarray(1)), /SPKI/);
 });
 
-test('clientDataJSON shape is what SubjectAccount checks (RS4-2)', async () => {
+test('clientDataJSON shape is what SmartKeyAccount checks (RS4-2)', async () => {
   const auth = await softAuthenticator({ rpId: RP, origin: ORIGIN });
   const a = await auth.get(new Uint8Array(32).fill(0xab));
   assert.equal(new TextDecoder().decode(a.clientDataJSON),
```
- [ ] **Step 2: Run** `cd clients/clientkeys && scripts/capped npm test` → 54 tests, 52 passed, 2 skipped (was 53 / 51 / 2): the
  KAT tests `SmartKeyAccount owner call = forge KAT`, `MandateWallet pay and revoke = forge KATs`, the CREATE2 vector and
  the 16 refusals of `owner call: the client signs only addKey(…)` (the old `OwnerCall` shape, the old domain name and an
  unsalted domain among them).
- [ ] **Step 3: Commit** `P4: clientkeys owner call on the salted SmartKeyAccount MetaTransaction, mandate KATs` + trailer.

---

### Task 5: Deploy, e2e, size, the mutation probe

**Model:** Sonnet, effort medium (runs; one assertion in the e2e).

**Files:** Modify `scaas-node/tests/e2e.rs`. (The deploy script changed in Task 1, so `Deploy.s.sol` compiles once the old
factory moved.)

- [ ] **Step 1: Pin the deploy JSON keys in the e2e (L14):**

```diff
diff --git a/scaas-node/tests/e2e.rs b/scaas-node/tests/e2e.rs
index 5f6f095..f8fe9b4 100644
--- a/scaas-node/tests/e2e.rs
+++ b/scaas-node/tests/e2e.rs
@@ -91,7 +91,11 @@ fn deploy(rpc: &str, chain_id: u64, holder: Address) -> Value {
         .expect("forge in PATH");
     assert!(status.success(), "forge script failed");
     let raw = std::fs::read_to_string(format!("{sc}/deployments/{chain_id}.json")).expect("deployments json");
-    serde_json::from_str(&raw).unwrap()
+    let dep: Value = serde_json::from_str(&raw).unwrap();
+    // P4: the account keys are `smart_key_account_*` (the node reads neither; Odoo seeds from them)
+    assert!(dep["smart_key_account_factory"].is_string() && dep["smart_key_account_implementation"].is_string());
+    assert!(dep.get("subject_account_factory").is_none(), "pre-P4 deploy JSON key");
+    dep
 }
 
 /// Bản sao bảng chuyển trạng thái của `dms_blockchain` (`blockchain_relay_job.TRANSITIONS`):
```
- [ ] **Step 2: Run, one at a time:** `cd smartcontracts/evm && scripts/capped forge build && FOUNDRY_PROFILE=private7622
  scripts/capped forge build`; then in `scaas-node` (with `CARGO_TARGET_DIR` as in Global Constraints)
  `scripts/capped cargo clippy --all-targets -- -D warnings` → clean; `scripts/capped cargo test --test e2e -- --ignored
  --test-threads=1` → 4 passed; `scripts/capped cargo test --test e2e_hedera -- --ignored` → 1 passed. The written
  `smartcontracts/evm/deployments/31901.json` carries `smart_key_account_factory` and `smart_key_account_implementation`
  (and no `subject_account_*`). Size gate → 0 errors, 59 contracts.
- [ ] **Step 3: The mutation probe.** Save as `/tmp/p4-mutate.py` (paths are the worktree's) and run
  `python3 /tmp/p4-mutate.py`; every mutant must be killed (the script restores each file in `finally`; check `git diff
  --stat src` is empty afterwards). Result of the validation run: **69/69 killed**.

```python
#!/usr/bin/env python3
"""P4 mutation probe: apply each mutant, run the suites, record the first failing test (the killer), restore."""
import re, subprocess, sys, json
EVM = '/home/ha/work/ainative/scaas/.claude/worktrees/p4/smartcontracts/evm'
CAP = '/home/ha/work/ainative/scaas/scripts/capped'
W, A, B = 'src/wallet/MandateWallet.sol', 'src/account/SmartKeyAccount.sol', 'src/metatx/MetaTxBase.sol'
H = 'src/hedera/HederaMandateWallet.sol'
M = [
 # id, file, old, new
 ('W1', W, 'if (md.delegate == address(0)) revert NoMandate();\n        if (_msgSender() != md.delegate) revert NotDelegate();\n        if (block.timestamp > md.expiry)', 'if (_msgSender() != md.delegate) revert NotDelegate();\n        if (block.timestamp > md.expiry)'),
 ('W2', W, 'if (_msgSender() != md.delegate) revert NotDelegate();\n        if (block.timestamp > md.expiry)', 'if (msg.sender != md.delegate) revert NotDelegate();\n        if (block.timestamp > md.expiry)'),
 ('W3', W, 'if (_msgSender() != md.delegate) revert NotDelegate();\n        if (block.timestamp > md.expiry)', 'if (block.timestamp > md.expiry)'),
 ('W4', W, 'if (block.timestamp > md.expiry)', 'if (block.timestamp >= md.expiry)'),
 ('W5', W, 'if (block.timestamp > md.expiry) revert MandateExpired();', ''),
 ('W6', W, 'if (!payeeAllowed[token][payee]) revert PayeeNotAllowed(payee);', ''),
 ('W7', W, 'if (amount == 0 || amount > md.maxPerPayment)', 'if (amount > md.maxPerPayment)'),
 ('W8', W, 'amount > md.maxPerPayment)', 'amount >= md.maxPerPayment)'),
 ('W9', W, 'if (refUsed[entryRef]) revert RefAlreadyPaid(entryRef);', ''),
 ('W10', W, 'refUsed[entryRef] = true;', ''),
 ('W11', W, 'if (block.timestamp >= uint256(md.periodStart) + md.periodSeconds)', 'if (block.timestamp > uint256(md.periodStart) + md.periodSeconds)'),
 ('W12', W, '            md.spentInPeriod = 0;\n', ''),
 ('W13', W, '            md.periodStart = uint64(block.timestamp);\n', ''),
 ('W14', W, 'if (spent > md.maxPerPeriod)', 'if (spent >= md.maxPerPeriod)'),
 ('W15', W, 'md.spentInPeriod = uint128(spent);', ''),
 ('W16', W, 'if (!IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, address(0), entryRef)) revert PayFailed();', 'IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, address(0), entryRef);'),
 ('W17', W, 'if (delegate == address(0) || periodSeconds == 0', 'if (periodSeconds == 0'),
 ('W18', W, '|| periodSeconds == 0 || maxPerPayment == 0', '|| maxPerPayment == 0'),
 ('W19', W, '|| maxPerPayment == 0\n', '\n'),
 ('W20', W, 'maxPerPayment > maxPerPeriod)', 'maxPerPayment >= maxPerPeriod)'),
 ('W21', W, '                                  maxPerPayment, maxPerPeriod, 0);\n        ++epoch[token];', '                                  maxPerPayment, maxPerPeriod, 0);'),
 ('W22', W, '        delete mandates[token];\n        ++epoch[token];', '        delete mandates[token];'),
 ('W23', W, 'if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);', ''),
 ('W24', W, 'if (_msgSender() != md.delegate) revert NotDelegate();\n        if (epoch_', 'if (epoch_'),
 ('W25', W, 'if (_msgSender() != owner) revert NotOwner();', 'if (msg.sender != owner) revert NotOwner();'),
 ('W26', W, 'function setPayee(address token, address payee, bool allowed) external nonReentrant onlyOwner {', 'function setPayee(address token, address payee, bool allowed) external nonReentrant {'),
 ('W27', W, 'mandatePayLane(entryRef), 0, validUntil, sig);', '0, 0, validUntil, sig);'),
 ('W28', W, 'mandateRevokeLane(token, epoch_), 0, validUntil, sig);', 'mandateRevokeLane(token, 0), 0, validUntil, sig);'),
 ('W29', W, '        if (d == address(0)) revert NoMandate();\n', ''),
 ('W30', W, 'return MtxRule(FEE_CLASS_ABSOLUTE, 0, 132);', 'return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);'),
 ('W31', W, 'rec == owner ? IERC1271', 'rec != address(0) ? IERC1271'),
 ('W32', W, 'return _named(owner, data, 0, nonce, validUntil, sig);', 'return _named(owner, data, 1, nonce, validUntil, sig);'),
 ('W33', W, 'function execute(address target, uint256 value, bytes calldata data)\n        external nonReentrant onlyOwner', 'function execute(address target, uint256 value, bytes calldata data)\n        external nonReentrant'),
 ('W34', W, 's[2] = _REVOKE_SIGNED;', 's[2] = _REVOKE_OWNER;'),
 ('H1', H, 'if (sig.length == 64 && !SigCheck.isContract(from))', 'if (sig.length == 65 && !SigCheck.isContract(from))'),
 ('H2', H, 'if (!HederaAccountAuth.asView()(from, digest, sig)) revert MetaTxBadSignature();', ''),
 ('S1', A, 'if (_msgSender() != address(this)) revert NotSelf();', 'if (msg.sender != address(this)) revert NotSelf();'),
 ('S2', A, 'function addKey(SubjectKey calldata key) external nonReentrant onlySelf', 'function addKey(SubjectKey calldata key) external nonReentrant'),
 ('S3', A, '    function _selfSender() internal pure override {}\n', ''),
 ('S4', A, 'if (from != address(this)) return super._requireValidSignature(from, digest, sig);', 'if (from == address(this)) return super._requireValidSignature(from, digest, sig);'),
 ('S5', A, 'if (!ok || ret.length != 32 || bytes4(ret) != IERC1271.isValidSignature.selector) revert MetaTxBadSignature();', ''),
 ('S6', A, 'if (!ok || ret.length != 32 || bytes4(ret) != IERC1271.isValidSignature.selector)', 'if (!ok || ret.length != 32)'),
 ('S7', A, 'if (keyCount == 1) revert LastKey();', 'if (keyCount == 0) revert LastKey();'),
 ('S8', A, 'if (k.kind == KeyKind.NONE) revert NoSuchKey(index);', ''),
 ('S9', A, 'if (hasKey[id]) revert DuplicateKey();', ''),
 ('S10', A, 'if (!P256.isValidPublicKey(k.x, k.y) || k.rpIdHash == 0', 'if (k.rpIdHash == 0'),
 ('S11', A, 'uint256(k.x) >> 160 != 0 || ', ''),
 ('S12', A, '|| k.rpIdHash == 0 || k.originHash == 0) revert BadKey();', '|| k.originHash == 0) revert BadKey();'),
 ('S13', A, '|| k.originHash == 0) revert BadKey();', ') revert BadKey();'),
 ('S14', A, 'if (msg.sender != guardian || guardian == address(0)) revert NotGuardian();', 'if (guardian == address(0)) revert NotGuardian();'),
 ('S15', A, 'if (block.timestamp < recoveryReadyAt)', 'if (block.timestamp <= recoveryReadyAt)'),
 ('S16', A, 'RECOVERY_DELAY = 2 days;', 'RECOVERY_DELAY = 1 days;'),
 ('S17', A, 'if (id == bytes32(0) || keyIdOf(key) != id) revert NoRecovery();', 'if (id == bytes32(0)) revert NoRecovery();'),
 ('S18', A, '        guardian = guardian_;\n        _clearRecovery();', '        guardian = guardian_;'),
 ('S19', A, 'if (pendingRecovery == bytes32(0)) revert NoRecovery();', ''),
 ('S20', A, 'if (msg.sender != FACTORY) revert NotFactory();', ''),
 ('S21', A, 'if (_initialized) revert AlreadyInitialized();', ''),
 ('S22', A, 'if (rpIdHash != k.rpIdHash) return false;', ''),
 ('S23', A, 'if (uint8(authData[32]) & (_FLAG_UP | _FLAG_UV) != (_FLAG_UP | _FLAG_UV)) return false;', 'if (uint8(authData[32]) & _FLAG_UP != _FLAG_UP) return false;'),
 ('S24', A, 'return MtxRule(FEE_CLASS_ABSOLUTE, 0, 164);', 'return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);'),
 ('S25', A, 's[5] = SmartKeyAccount.cancelRecovery.selector;', 's[5] = SmartKeyAccount.execute.selector;'),
 ('S26', A, '        m.from = address(this);\n', ''),
 ('S27', A, 'external nonReentrant onlySelf returns (bytes memory)\n    {', 'external onlySelf returns (bytes memory)\n    {'),
 ('S28', A, 'return _isValid(hash, signature) ? IERC1271.isValidSignature.selector : _INVALID;', 'return IERC1271.isValidSignature.selector;'),
 ('S29', A, 'bytes32 message = proof.length == 0 ? digest : MerkleProof.processProof(proof, batchLeaf(digest));', 'bytes32 message = MerkleProof.processProof(proof, batchLeaf(digest));'),
 ('S30', A, 'if (sel == SmartKeyAccount.cancelRecovery.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);', ''),
 ('S31', A, '        _removeKey(index);\n    }\n\n    /// @notice A new guardian', '    }\n\n    /// @notice A new guardian'),
 ('B1', B, 'if (from == address(this)) _selfSender();', ''),
 ('B2', B, '    function _selfSender() internal pure virtual {\n        revert SelfSender();\n    }', '    function _selfSender() internal pure virtual {}'),
]
only = set(sys.argv[1:])
res = []
for mid, f, old, new in M:
    if only and mid not in only: continue
    p = f'{EVM}/{f}'
    src = open(p).read()
    n = src.count(old)
    if n != 1:
        res.append((mid, f'BAD PATTERN ({n})', '')); print(mid, 'BAD PATTERN', n, flush=True); continue
    open(p, 'w').write(src.replace(old, new))
    try:
        mp = 'test/[amw]*/*.t.sol' if f in (B,) else 'test/[aw]*/*.t.sol'
        out = subprocess.run([CAP, 'forge', 'test', '--match-path', mp], cwd=EVM, capture_output=True, text=True); out = out.stdout + out.stderr
        fails = re.findall(r'\[FAIL.*\] (\w+)\(\) \(', out)
        if 'Compiler run failed' in out or 'Error (' in out: status, killer = 'COMPILE', ''
        elif fails: status, killer = 'killed', fails[0]
        else: status, killer = 'SURVIVED', ''
    finally:
        open(p, 'w').write(src)
    res.append((mid, status, killer)); print(mid, status, killer, flush=True)
json.dump(res, open('/tmp/p4-mutants.json', 'w'))
print(sum(1 for r in res if r[1] == 'killed'), '/', len(res), 'killed')
```
| Mutant | File | Mutation | Killed by |
|---|---|---|---|
| W1 | MandateWallet | `if (md.delegate == address(0)) revert NoMandate(); if (_msgSender() !=…` → `if (_msgSender() != md.delegate) revert NotDelegate(); if (block.times…` | `test_owner_revoke_kills_it_and_bumps_the_epoch` |
| W2 | MandateWallet | `if (_msgSender() != md.delegate) revert NotDelegate(); if (block.times…` → `if (msg.sender != md.delegate) revert NotDelegate(); if (block.timesta…` | `test_mandateWalletKat` |
| W3 | MandateWallet | `if (_msgSender() != md.delegate) revert NotDelegate(); if (block.times…` → `if (block.timestamp > md.expiry)` | `test_new_delegate_voids_old_signatures` |
| W4 | MandateWallet | `if (block.timestamp > md.expiry)` → `if (block.timestamp >= md.expiry)` | `test_expired_mandate` |
| W5 | MandateWallet | drop `if (block.timestamp > md.expiry) revert MandateExpired();` | `test_expired_mandate` |
| W6 | MandateWallet | drop `if (!payeeAllowed[token][payee]) revert PayeeNotAllowed(payee);` | `test_payee_is_per_token` |
| W7 | MandateWallet | `if (amount == 0 \|\| amount > md.maxPerPayment)` → `if (amount > md.maxPerPayment)` | `test_per_payment_cap_and_zero` |
| W8 | MandateWallet | `amount > md.maxPerPayment)` → `amount >= md.maxPerPayment)` | `test_pay_failed_reverts_everything` |
| W9 | MandateWallet | drop `if (refUsed[entryRef]) revert RefAlreadyPaid(entryRef);` | `test_entry_ref_pays_once` |
| W10 | MandateWallet | drop `refUsed[entryRef] = true;` | `test_entry_ref_pays_once` |
| W11 | MandateWallet | `if (block.timestamp >= uint256(md.periodStart) + md.periodSeconds)` → `if (block.timestamp > uint256(md.periodStart) + md.periodSeconds)` | `test_per_period_cap_and_rollover` |
| W12 | MandateWallet | drop `md.spentInPeriod = 0;` | `test_per_period_cap_and_rollover` |
| W13 | MandateWallet | drop `md.periodStart = uint64(block.timestamp);` | `test_per_period_cap_and_rollover` |
| W14 | MandateWallet | `if (spent > md.maxPerPeriod)` → `if (spent >= md.maxPerPeriod)` | `test_pay_failed_reverts_everything` |
| W15 | MandateWallet | drop `md.spentInPeriod = uint128(spent);` | `test_per_period_cap_and_rollover` |
| W16 | MandateWallet | `if (!IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, a…` → `IERC20Payment(token).payWithFee(payee, amount, FeeMode.NONE, 0, addres…` | `test_pay_failed_reverts_everything` |
| W17 | MandateWallet | `if (delegate == address(0) \|\| periodSeconds == 0` → `if (periodSeconds == 0` | `test_mandate_parameters_are_validated` |
| W18 | MandateWallet | `\|\| periodSeconds == 0 \|\| maxPerPayment == 0` → `\|\| maxPerPayment == 0` | `test_mandate_parameters_are_validated` |
| W19 | MandateWallet | drop `\|\| maxPerPayment == 0` | `test_mandate_parameters_are_validated` |
| W20 | MandateWallet | `maxPerPayment > maxPerPeriod)` → `maxPerPayment >= maxPerPeriod)` | `test_mandate_parameters_are_validated` |
| W21 | MandateWallet | `maxPerPayment, maxPerPeriod, 0); ++epoch[token];` → `maxPerPayment, maxPerPeriod, 0);` | `test_mandateWalletKat` |
| W22 | MandateWallet | `delete mandates[token]; ++epoch[token];` → `delete mandates[token];` | `test_mandateWalletKat` |
| W23 | MandateWallet | drop `if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);` | `test_revoke_signature_is_bound_to_its_epoch` |
| W24 | MandateWallet | `if (_msgSender() != md.delegate) revert NotDelegate(); if (epoch_` → `if (epoch_` | `test_only_the_delegate_revokes_by_signature` |
| W25 | MandateWallet | `if (_msgSender() != owner) revert NotOwner();` → `if (msg.sender != owner) revert NotOwner();` | `test_delegatePaysUnderMandateSetByEd25519Owner` |
| W26 | MandateWallet | `function setPayee(address token, address payee, bool allowed) external…` → `function setPayee(address token, address payee, bool allowed) external…` | `test_owner_only_functions` |
| W27 | MandateWallet | `mandatePayLane(entryRef), 0, validUntil, sig);` → `0, 0, validUntil, sig);` | `test_mandateWalletKat` |
| W28 | MandateWallet | `mandateRevokeLane(token, epoch_), 0, validUntil, sig);` → `mandateRevokeLane(token, 0), 0, validUntil, sig);` | `test_mandateWalletKat` |
| W29 | MandateWallet | drop `if (d == address(0)) revert NoMandate();` | `test_delegate_signed_revoke_kills_it` |
| W30 | MandateWallet | `return MtxRule(FEE_CLASS_ABSOLUTE, 0, 132);` → `return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);` | `test_unlistedSelectorsAndShapes` |
| W31 | MandateWallet | `rec == owner ? IERC1271` → `rec != address(0) ? IERC1271` | `test_owner_still_pays_manually_through_meta_tx` |
| W32 | MandateWallet | `return _named(owner, data, 0, nonce, validUntil, sig);` → `return _named(owner, data, 1, nonce, validUntil, sig);` | `test_ed25519OwnerSetsMandateAndPaysByHand` |
| W33 | MandateWallet | `function execute(address target, uint256 value, bytes calldata data) e…` → `function execute(address target, uint256 value, bytes calldata data) e…` | `test_owner_only_functions` |
| W34 | MandateWallet | `s[2] = _REVOKE_SIGNED;` → `s[2] = _REVOKE_OWNER;` | `test_allowlistPinned` |
| H1 | HederaMandateWallet | `if (sig.length == 64 && !SigCheck.isContract(from))` → `if (sig.length == 65 && !SigCheck.isContract(from))` | `test_delegatePaysUnderMandateSetByEd25519Owner` |
| H2 | HederaMandateWallet | drop `if (!HederaAccountAuth.asView()(from, digest, sig)) revert MetaTxBadSi…` | `test_ed25519OwnerRefusals` |
| S1 | SmartKeyAccount | `if (_msgSender() != address(this)) revert NotSelf();` → `if (msg.sender != address(this)) revert NotSelf();` | `test_otherSignerIsNotTheAccount` |
| S2 | SmartKeyAccount | `function addKey(SubjectKey calldata key) external nonReentrant onlySel…` → `function addKey(SubjectKey calldata key) external nonReentrant` | `test_otherSignerIsNotTheAccount` |
| S3 | SmartKeyAccount | drop `function _selfSender() internal pure override {}` | `test_smartKeyAccountKat` |
| S4 | SmartKeyAccount | `if (from != address(this)) return super._requireValidSignature(from, d…` → `if (from == address(this)) return super._requireValidSignature(from, d…` | `test_otherSignerIsNotTheAccount` |
| S5 | SmartKeyAccount | drop `if (!ok \|\| ret.length != 32 \|\| bytes4(ret) != IERC1271.isValidSignatur…` | `test_mtxBatchIsAtomic` |
| S6 | SmartKeyAccount | `if (!ok \|\| ret.length != 32 \|\| bytes4(ret) != IERC1271.isValidSignatur…` → `if (!ok \|\| ret.length != 32)` | `test_mtxBatchIsAtomic` |
| S7 | SmartKeyAccount | `if (keyCount == 1) revert LastKey();` → `if (keyCount == 0) revert LastKey();` | `test_never_zero_keys` |
| S8 | SmartKeyAccount | drop `if (k.kind == KeyKind.NONE) revert NoSuchKey(index);` | `test_remove_unknown_index` |
| S9 | SmartKeyAccount | drop `if (hasKey[id]) revert DuplicateKey();` | `test_duplicate_and_bad_keys` |
| S10 | SmartKeyAccount | `if (!P256.isValidPublicKey(k.x, k.y) \|\| k.rpIdHash == 0` → `if (k.rpIdHash == 0` | `test_duplicate_and_bad_keys` |
| S11 | SmartKeyAccount | drop `uint256(k.x) >> 160 != 0 \|\|` | `test_duplicate_and_bad_keys` |
| S12 | SmartKeyAccount | `\|\| k.rpIdHash == 0 \|\| k.originHash == 0) revert BadKey();` → `\|\| k.originHash == 0) revert BadKey();` | `test_duplicate_and_bad_keys` |
| S13 | SmartKeyAccount | `\|\| k.originHash == 0) revert BadKey();` → `) revert BadKey();` | `test_duplicate_and_bad_keys` |
| S14 | SmartKeyAccount | `if (msg.sender != guardian \|\| guardian == address(0)) revert NotGuardi…` → `if (guardian == address(0)) revert NotGuardian();` | `test_recovery_guards` |
| S15 | SmartKeyAccount | `if (block.timestamp < recoveryReadyAt)` → `if (block.timestamp <= recoveryReadyAt)` | `test_guardian_recovery_after_delay` |
| S16 | SmartKeyAccount | `RECOVERY_DELAY = 2 days;` → `RECOVERY_DELAY = 1 days;` | `test_guardian_recovery_after_delay` |
| S17 | SmartKeyAccount | `if (id == bytes32(0) \|\| keyIdOf(key) != id) revert NoRecovery();` → `if (id == bytes32(0)) revert NoRecovery();` | `test_recovery_guards` |
| S18 | SmartKeyAccount | `guardian = guardian_; _clearRecovery();` → `guardian = guardian_;` | `test_recovery_guards` |
| S19 | SmartKeyAccount | drop `if (pendingRecovery == bytes32(0)) revert NoRecovery();` | `test_key_cancels_recovery` |
| S20 | SmartKeyAccount | drop `if (msg.sender != FACTORY) revert NotFactory();` | `test_initialize_is_factory_only_and_once` |
| S21 | SmartKeyAccount | drop `if (_initialized) revert AlreadyInitialized();` | `test_initialize_is_factory_only_and_once` |
| S22 | SmartKeyAccount | drop `if (rpIdHash != k.rpIdHash) return false;` | `test_wrong_rp_id_hash` |
| S23 | SmartKeyAccount | `if (uint8(authData[32]) & (_FLAG_UP \| _FLAG_UV) != (_FLAG_UP \| _FLAG_U…` → `if (uint8(authData[32]) & _FLAG_UP != _FLAG_UP) return false;` | `test_flags` |
| S24 | SmartKeyAccount | `return MtxRule(FEE_CLASS_ABSOLUTE, 0, 164);` → `return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);` | `test_staticShapes` |
| S25 | SmartKeyAccount | `s[5] = SmartKeyAccount.cancelRecovery.selector;` → `s[5] = SmartKeyAccount.execute.selector;` | `test_allowlistPinned` |
| S26 | SmartKeyAccount | drop `m.from = address(this);` | `test_smartKeyAccountKat` |
| S27 | SmartKeyAccount | `external nonReentrant onlySelf returns (bytes memory) {` → `external onlySelf returns (bytes memory) {` | `test_executeCannotReenter` |
| S28 | SmartKeyAccount | `return _isValid(hash, signature) ? IERC1271.isValidSignature.selector …` → `return IERC1271.isValidSignature.selector;` | `test_batch_leaf_is_not_an_inner_node` |
| S29 | SmartKeyAccount | `bytes32 message = proof.length == 0 ? digest : MerkleProof.processProo…` → `bytes32 message = MerkleProof.processProof(proof, batchLeaf(digest));` | `test_smartKeyAccountKat` |
| S30 | SmartKeyAccount | drop `if (sel == SmartKeyAccount.cancelRecovery.selector) return MtxRule(FEE…` | `test_key_cancels_recovery` |
| S31 | SmartKeyAccount | `_removeKey(index); } /// @notice A new guardian` → `} /// @notice A new guardian` | `test_rotate_passkey_to_new_passkey` |
| B1 | MetaTxBase | drop `if (from == address(this)) _selfSender();` | `test_fromTheTokenItselfRefused` |
| B2 | MetaTxBase | `function _selfSender() internal pure virtual { revert SelfSender(); }` → `function _selfSender() internal pure virtual {}` | `test_fromTheTokenItselfRefused` |

- [ ] **Step 4: Commit** `P4: e2e pins the smart_key_account deploy keys` + trailer.

---

### Task 6: Docs, TODO, HANDOFF

**Model:** Sonnet, effort medium (text; L18).

**Files:** Modify `docs/contracts/accounts.md`, `docs/contracts/mandates.md`, `docs/contracts/metatx.md`,
`docs/contracts/README.md`, `docs/architecture.md`, `docs/networks/evm.md`, `docs/node/job-api.md`, `docs/clients/app.md`,
`docs/clients/signers-clientkeys.md`, `docs/assets/account-forms.svg`, `docs/history/dropped-artifacts.tsv`, `README.md`,
`TODO.md`, `HANDOFF.md`. (`docs/assets/token-axes.svg` has no P4 text; its alt text in `docs/contracts/README.md` already
says "a SmartKeyAccount (ERC-1271, built)".)

- [ ] **Step 1: Apply** (net lines: accounts.md −1, mandates.md −2, metatx.md −2, every other page 0; `dropped-artifacts.tsv` +4):

```diff
diff --git a/HANDOFF.md b/HANDOFF.md
index 405c7fe..bcc6142 100644
--- a/HANDOFF.md
+++ b/HANDOFF.md
@@ -1,5 +1,30 @@
 # HANDOFF — scaas
 
+## Session 2026-10-11 (P4)
+
+**State:** P4 on branch `p4-accounts`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
+992 forge tests; size gate 0 errors (every token +8 B for the `_selfSender` hook, baseline raised); clientkeys 52 + 2 skipped;
+Solana 42, Sui 68, Aptos 105 (+ entry check), Soroban 28, Cosmos 10, TON 28; e2e 4/4 and e2e_hedera 1/1; mutation probe 69/69 killed.
+
+**Built:** `src/account/SmartKeyAccount.sol` and `SmartKeyAccountFactory.sol` (`chainUid` constructor argument, `chainUid()`),
+`src/wallet/MandateWallet.sol` (`owner`, `chainUid`; `epoch[token]`, `revoke(token, epoch)`, `mtxPayUnderMandate`, `mtxRevoke`,
+`mtxExecuteAsOwner`, `mandatePayLane`, `mandateRevokeLane`), `src/hedera/HederaMandateWallet.sol` (HIP-632 for 64-byte signatures,
+`mtxExecuteAsOwnerRaw`), `MetaTxBase._selfSender`; Solana `state::SmartKeyAccount`; clientkeys `metaTxTypedData`,
+`ownerCallTypedData`/`checkOwnerCall` on the salted `MetaTransaction`; KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`,
+`mandate_revoke_kat.json`, `smart_key_account_create2.json`; deploy JSON `smart_key_account_factory` / `_implementation`. Tests
+`test/account/SmartKeyAccount.t`, `AccountKat.t`, `test/wallet/MandateWallet.t`. The typed-struct line is in
+`smartcontracts/evm/legacy/p4/` (not built).
+
+**Rulings L1–L18 (plan header).** **L1** the `_selfSender` hook; **L2** the account checks itself through its own
+`isValidSignature`; **L3** `cancelRecovery` allowlisted; **L4** `SubjectKey` keeps its name; **L6** no migration of deployed
+clones or wallets; **L7** `NotDelegate`, lane encodings; **L11** Hedera HIP-632 on every wallet entry; **L12** non-EVM renames
+only where code said `SubjectAccount` (Solana; Sui/Aptos/Soroban keep their family names); **L13** Solana discriminator follows
+the name, no state migration; **L14** deploy JSON keys renamed.
+
+**Not done / next:** bamboo-dms follows (owner call, mandate digests and calldata, CREATE2 file, JSON key; TODO P4); the node's
+call table for the renamed rows (P5); open questions in the plan (agent mandates from `docs/research/node-ai-agents.md`, the
+Sui/Aptos/Soroban type names, migration of accounts and wallets deployed before P4).
+
 ## Session 2026-10-11 (P3)
 
 **State:** P3 on branch `p3-zether`, merge pending; head is the fix-wave-2 commit on `f847471` (final review I1, m1–m7). Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`.
diff --git a/README.md b/README.md
index c28e6ae..c2a2f90 100644
--- a/README.md
+++ b/README.md
@@ -279,7 +279,7 @@ heavy logic sits in external libraries ([CTR-TOK-21](docs/contracts/token-wrappe
 | Tradable tokens | `mtxTrade`: the token pulls a signed `TradeOrder` into the DEX named in it | `IERC20MetaTx` | SPECIFIED (`TradeLib`, P2; today: the `trade` op and the legacy `MetaTxDex`, both to be removed) | [metatx](docs/contracts/metatx.md), [legacy DEX](docs/contracts/dex.md#legacy-metatxdex) |
 | DEX | `SCaaSDex`, `DexPuller` | `EIP712` + `ReentrancyGuardTransient`; one taker against many makers per call on two paths, no maker allowance; `mtxExchange` fills the same orders against AMMs (Uniswap v2/v3), multi-hop or in a cycle, surplus to the signers ([CTR-DEX-20](docs/contracts/dex.md#CTR-DEX-20)) | BUILT (P2c: the exchange path on the new `SCaaSDex`) | [dex](docs/contracts/dex.md) |
 | Mandates | `MandateWallet` | `MetaTxBase` + `IERC1271` | BUILT (own signed structs; on `MetaTxBase` in P4) | [mandates](docs/contracts/mandates.md) |
-| Smart account (optional) | `SmartKeyAccount`, `SmartKeyAccountFactory` (built: `SubjectAccount`) | `MetaTxBase` + `IERC1271`; P-256 passkeys; signs its own calls as itself ([CTR-ACC-10](docs/contracts/accounts.md#CTR-ACC-10)) | BUILT (`OwnerCall`; on `MetaTxBase` in P4) | [accounts](docs/contracts/accounts.md#subjectaccount) |
+| Smart account (optional) | `SmartKeyAccount`, `SmartKeyAccountFactory` | `MetaTxBase` + `IERC1271`; P-256 passkeys; signs its own calls as itself ([CTR-ACC-10](docs/contracts/accounts.md#CTR-ACC-10)) | BUILT (on `MetaTxBase`, P4) | [accounts](docs/contracts/accounts.md#subjectaccount) |
 | Universal Accounts | today the Zether-only `UniversalAccountRegistry`; next the UA registry with one verifier per kind, and MetaToken v3 with a UA ledger | the signature, multisig, BLS and hash-to-curve libraries | legacy registry BUILT; UA registry and v3 SPECIFIED | [accounts](docs/contracts/accounts.md#universal-account) |
 | Zether | the `*_ZETHER` kinds (`ZetherLayer` + `ZetherLib`), `ZetherStatements`, `ZetherVerifierBn254`, `ZetherVerifierBls12381`, `ITransferDisclosure` | `MetaTokenBase`; EIP-196/197 and EIP-2537 precompiles | BUILT, unaudited (P3) | [zether](docs/contracts/zether.md) |
 | PQ Zether | `PqzToken` | `ERC20MetaTx`, relayed like Zether ([CTR-PQZ-21](docs/contracts/pq-zether.md#CTR-PQZ-21)); a lattice precompile on chain 7622 — public chains once they offer one | SPECIFIED | [pq-zether](docs/contracts/pq-zether.md) |
diff --git a/TODO.md b/TODO.md
index a61503a..6315e38 100644
--- a/TODO.md
+++ b/TODO.md
@@ -16,7 +16,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 | P1 | The complete base on the new tree: `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer; kinds `NONE`, `UNDERLYING`; factory `createToken`; the v1/v2 lines to the backup (v2 done in P1e, v1 renamed `…V1` until P3/P5) | MT-1, MT-2, MT-3, MT-4 |
 | P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done, merged `d85fc8b`) | MT-5 |
 | P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done on branch `p3-zether`, merge pending the final review) | MT-6 |
-| P4 | `MandateWallet`, `SmartKeyAccount` (rename, every family) on `MetaTxBase` | MT-7 (+ rename in NM-*) |
+| P4 | `MandateWallet`, `SmartKeyAccount` (rename, every family) on `MetaTxBase`; the typed-struct line to `legacy/p4/` (done on branch `p4-accounts`, merge pending the final review) | MT-7 (+ rename in NM-*) |
 | P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |
 
 **P1 start checklist (owner decisions 2026-10-08):**
@@ -49,7 +49,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
       `msg.sender` directly except the allowed spots; UA path split into `UAMetaTransaction`/`UAMetaTransfer` +
       `uaExecuteTransfer`/`uaBatchTransfer` (CTR-UA-26); KATs `metatx_kat.json`, `metatransfer_kat.json`, v3 pair.
 - [ ] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; open: v1 line (P5, E1); `mtxWrap` for a SCaaS underlying done in P2a (UnderlyingToken), inherited by `UnderlyingZetherToken` (P3); the approve rule holds on both Zether kinds (tested in P3).
-- [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the other domains: SmartKeyAccount, MandateWallet P4, UA registry UA F1; Zether digests done in P3) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
+- [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the UA registry, UA F1; Zether digests done in P3, SmartKeyAccount and MandateWallet in P4) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
       UA registry, Zether digests); deploy scripts on a CREATE2 deployer; deploy gate checks `chainUid()`.
 
 - UA ledger split (CTR-UA-26: `UAMetaTransaction`/`UAMetaTransfer`, `uaExecuteTransfer`/`uaBatchTransfer`) moved from P1b to UA F1 (R4).
@@ -78,9 +78,9 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 - [~] **MT-6** Zether (done in P3: transient envelope binding, `zetherShield` from the public balance, `mtxWrap` inherited, the `zether*` renames, binding without `to`/`value`, prover `Header.chain_uid`, `HEADER_LEN` 416; open: `PqzToken` on the one base, PQZ selectors not batchable, CTR-PQZ-21, with the PQZ stream).
 
 **P4 — MT-7**
-- [ ] **MT-7** `MandateWallet` and `SmartKeyAccount` (renamed from `SubjectAccount`, CTR-ACC-11) on `MetaTxBase` (CTR-ACC-06/07/10): delegate/owner calls as
-      `MetaTransaction` self-calls, `SmartKeyAccount` signs as itself, typed `PayUnderMandate`/`RevokeMandate`/`OwnerCall`
-      removed, named entries derive their lanes; Hedera `mtxExecuteAsOwnerRaw` over the same owner digest; `mtx…` renames.
+- P4 (done on branch `p4-accounts`, merge pending the final review): `SmartKeyAccount` / `SmartKeyAccountFactory(chainUid)` and `MandateWallet(owner, chainUid)` / `HederaMandateWallet` on `MetaTxBase` (domains `SCaaS SmartKeyAccount`, `SCaaS MandateWallet`, `salt = chain_uid`), the account signs its own key management (`_selfSender` hook), `mtxExecuteAsOwner`, `mtxPayUnderMandate`, `mtxRevoke` with derived lanes, `revoke(token, epoch)` (CTR-ACC-07), `mtxExecuteAsOwnerRaw`; Solana `state::SmartKeyAccount`; clientkeys `checkOwnerCall` on the salted `MetaTransaction`; KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`, `mandate_revoke_kat.json`, `smart_key_account_create2.json`; deploy JSON `smart_key_account_factory` / `_implementation`; the typed-struct `SubjectAccount`, `MandateWallet`, `HederaMandateWallet` and their tests in `smartcontracts/evm/legacy/p4/`. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
+- [ ] bamboo-dms (other repo, P4 follow-up): the Odoo owner call (`_owner_call_typed_data`, `_owner_call_digest`) becomes the account's salted `MetaTransaction` (`smart_key_account_kat.json`); the mandate digests and calldata (`lib/eip712.py`, `lib/abi.py`, `test_eip712.TestMandateKat`) move to `mtxPayUnderMandate` / `mtxRevoke(token, epoch, …)` (`mandate_pay_kat.json`, `mandate_revoke_kat.json`); `blockchain.subject.account._predict` reads `smart_key_account_create2.json`; deploy seeding reads `smart_key_account_factory`; wallets are deployed with `<owner> <chain_uid>`.
+- [ ] Agent mandates (research `docs/research/node-ai-agents.md` row c, not accepted): several delegates per token, per-payee caps, a co-sign threshold, a gateway route for mandate payments — owner decision.
 
 **P5 — MT-8, MT-9**
 - [ ] v1 line to backup: once the node (`src/abi.rs` v1 struct, `executeMetaTransaction`, salt-less domain; e2e v1 `MetaToken` demo tokens) and clientkeys (`metatx_v1_kat.json`) are on the new ABI, move the v1 contracts and the v1 deploy path to `smartcontracts/evm/legacy/` (E1).
diff --git a/docs/architecture.md b/docs/architecture.md
index 6f957ea..0f5b775 100644
--- a/docs/architecture.md
+++ b/docs/architecture.md
@@ -255,10 +255,10 @@ agent signs, a relayer pays gas); Zether keeps commercial amounts confidential w
 </details>
 
 **Target and built.** The contract sections below describe the target that the component docs specify. The built EVM
-code already has the P1 base and the two public kinds (P1a–P1d) and still carries the older lines (the v1 tokens,
-`SubjectAccount`; the old `ZetherToken` is in `legacy/p3/`); every component doc says what is built in a *Transitional (BUILT)* note naming the
+code already has the P1 base and the two public kinds (P1a–P1d) and still carries the older lines (the v1 tokens; the old `ZetherToken`
+is in `legacy/p3/`, the typed-struct `SubjectAccount` and `MandateWallet` in `legacy/p4/`); every component doc says what is built in a *Transitional (BUILT)* note naming the
 phase that replaces it: P1 the base, the two public kinds and `createToken` (P1e); P2 `TradeLib` and the DEX clone; P3 the Zether kinds; P4 `MandateWallet` and `SmartKeyAccount` on the
-base; P5 node and client support for the new ABI ([contracts/token-wrappers.md](contracts/token-wrappers.md#transitional-built-tokens),
+base (built); P5 node and client support for the new ABI ([contracts/token-wrappers.md](contracts/token-wrappers.md#transitional-built-tokens),
 [contracts/metatx.md](contracts/metatx.md#transitional-built)). Nothing is deployed, so the target replaces the built
 lines in place; there is no migration between them.
 
diff --git a/docs/assets/account-forms.svg b/docs/assets/account-forms.svg
index 58b867b..877c692 100644
--- a/docs/assets/account-forms.svg
+++ b/docs/assets/account-forms.svg
@@ -1,6 +1,6 @@
 <svg xmlns="http://www.w3.org/2000/svg" width="960" height="580" viewBox="0 0 960 580" role="img" aria-labelledby="t d">
   <title id="t">Accounts and keys</title>
-  <desc id="d">Three account forms. Native account: the chain’s own account (EVM EOA or ERC-1271 contract, Solana, Stellar, Aptos, Sui, Cosmos, TON), no registration. Universal Account, the default (specified, nothing built): an id derived from key data or a policy, for passkeys, P-256, ed25519, Schnorr, BLS, MuSig2 and FROST groups, weighted multisig, post-quantum and Zether keys, registered once per chain in the UARegistry with proof of possession. SmartKeyAccount, optional (built): an ERC-1271 clone from SmartKeyAccountFactory with several P-256 passkey and secp256k1 keys and guardian recovery. A passkey can serve as a UA or as a SmartKeyAccount key. Every token kind accepts all three forms and verifies the signature itself. MandateWallet (built) is a payment authority, not an account: the payer owns it and deposits into it, a delegate pays approved payees within per-payment and per-period caps until expiry or revocation.</desc>
+  <desc id="d">Three account forms. Native account: the chain’s own account (EVM EOA or ERC-1271 contract, Solana, Stellar, Aptos, Sui, Cosmos, TON), no registration. Universal Account, the default (specified, nothing built): an id derived from key data or a policy, for passkeys, P-256, ed25519, Schnorr, BLS, MuSig2 and FROST groups, weighted multisig, post-quantum and Zether keys, registered once per chain in the UARegistry with proof of possession. SmartKeyAccount, optional (built, on MetaTxBase): an ERC-1271 clone from SmartKeyAccountFactory with several P-256 passkey and secp256k1 keys and guardian recovery. A passkey can serve as a UA or as a SmartKeyAccount key. Every token kind accepts all three forms and verifies the signature itself. MandateWallet (built, on MetaTxBase with a revocation epoch) is a payment authority, not an account: the payer owns it and deposits into it, a delegate pays approved payees within per-payment and per-period caps until expiry or revocation.</desc>
   <defs>
     <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
       <path d="M0 0 L10 5 L0 10 z" fill="#57606a"/>
@@ -54,7 +54,7 @@
   <text class="s" x="658" y="226">anyone completeRecovery after the delay</text>
   <text class="s" x="658" y="245">key changes: MetaTransactions signed by</text>
   <text class="s" x="658" y="264">the account itself (stable address)</text>
-  <text class="n" x="658" y="283">built code still named SubjectAccount until P4</text>
+  <text class="n" x="658" y="283">on MetaTxBase, domain SCaaS SmartKeyAccount</text>
   <rect x="430" y="300" width="420" height="26" rx="13" fill="#ffffff" stroke="#57606a" stroke-dasharray="4 3"/>
   <text class="lab" x="640" y="317" text-anchor="middle">a passkey can be a webauthn-p256 UA or a SmartKeyAccount key</text>
   <line class="flow" x1="166" y1="315" x2="166" y2="352" marker-end="url(#ah)"/>
@@ -66,7 +66,7 @@
 
   <rect x="16" y="420" width="928" height="110" rx="12" fill="#fef3c7" stroke="#d97706"/>
   <text class="tier" x="30" y="445">MandateWallet</text>
-  <rect x="150" y="433" width="42" height="16" rx="8" fill="#dafbe1"/><text class="chip" x="171" y="445" text-anchor="middle" fill="#1a7f37">BUILT</text><text class="s" x="198" y="445">revocation epoch</text><rect x="290" y="433" width="70" height="16" rx="8" fill="#ddf4ff"/><text class="chip" x="325" y="445" text-anchor="middle" fill="#0969da">SPECIFIED</text>
+  <rect x="150" y="433" width="42" height="16" rx="8" fill="#dafbe1"/><text class="chip" x="171" y="445" text-anchor="middle" fill="#1a7f37">BUILT</text><text class="s" x="198" y="445">on MetaTxBase, revocation epoch</text>
   <text class="s" x="30" y="466">A payment authority, not an account: delegated, capped payment from the payer's own wallet</text>
   <rect x="30" y="478" width="150" height="40" rx="8" fill="#ffffff" stroke="#d97706"/>
   <text class="b" x="105" y="503" text-anchor="middle">Payer (owner)</text>
diff --git a/docs/clients/app.md b/docs/clients/app.md
index f16bf16..f4f9bab 100644
--- a/docs/clients/app.md
+++ b/docs/clients/app.md
@@ -200,7 +200,7 @@ Fake wallets are not duplicated: end-to-end tests inject clientkeys `test/wallet
 `key` is the node's `chain_key` (`config.rs:746`); non-EVM curated tokens and assets carry `symbol`/`decimals` the same
 way; a chain without `gatewayNode` has the self-paid path only. `npm run config:from-deployments -- <rpc>` reads
 `smartcontracts/evm/deployments/<chainid>.json` and maps `scaas_dex` → `contracts.dex`, `factory` →
-`contracts.factoryV1`, `token_factory` (was `factory_v2`) → `contracts.factoryV2`, `subject_account_factory` → `contracts.subjectAccountFactory`;
+`contracts.factoryV1`, `token_factory` (was `factory_v2`) → `contracts.factoryV2`, `smart_key_account_factory` (P4; was `subject_account_factory`) → `contracts.smartKeyAccountFactory`;
 the deployment's `dex` key is `MetaTxDex`, a different contract, and is not mapped; other families are written by hand.
 Target (SPECIFIED): the deployment file also carries `chain_uid` and the DEX list ([NET-EVM-05](../networks/evm.md#NET-EVM-05)),
 mapped to `chainUid` and `contracts.dexes` (with `contracts.dex` = the venue's DEX, which must be on the list); the
@@ -750,7 +750,7 @@ Unit (Vitest / `node --test`, no network):
 
 | Area | Vectors / method |
 |---|---|
-| EVM encoders | `metatx_kat` (v3), `metatx_v1_kat` (built v1, until P5), `metatransfer_kat`, `dex_kat`, `hedera_kat`, `wrap_rate_vectors`, `subject_account_create2`, `webauthn_soft` |
+| EVM encoders | `metatx_kat` (v3), `metatx_v1_kat` (built v1, until P5), `metatransfer_kat`, `dex_kat`, `hedera_kat`, `wrap_rate_vectors`, `smart_key_account_create2`, `smart_key_account_kat`, `mandate_pay_kat`, `mandate_revoke_kat`, `webauthn_soft` |
 | Non-EVM encoders (clientkeys) | `mesh-envelope-v1.2.json` cross-language payloads, `ton-vectors.json`, `fam_*.json` per family, `sui_vectors.json`, the seed-signed vectors, `solana_derivation.json` |
 | UA (clientkeys) | `smartcontracts/vectors/ua/*`: ids, keyHash, `ua_msg`, PoP, `UAMetaTransaction` digests; `deriveUAKey` paths under `m/7622'` |
 | Backup / vault | `backup_policy.json` plus the de-duplication and `msig` rows; `vault_v2_fixture.json` |
diff --git a/docs/clients/signers-clientkeys.md b/docs/clients/signers-clientkeys.md
index 9b27e43..ed0f267 100644
--- a/docs/clients/signers-clientkeys.md
+++ b/docs/clients/signers-clientkeys.md
@@ -222,8 +222,8 @@ which works offline, or from the contract's `eip712Domain()` read once and cache
 payments, self-calls, trade orders), mandate wallets, subject accounts, the DEX and the registry. What protects the
 user is the contract — a contract on another chain computes its digest with that chain's `chain_uid`, so the signature
 fails there whichever wallet made it; the client check catches a wrong profile or a hostile server before the user is
-asked. Transitional (BUILT): only the Universal Account domains carry `salt` (the existing check of the PoP flow,
-[integration.md](../integration.md)); the other domains are unsalted until the salted contracts are deployed.
+asked. Transitional (BUILT): clientkeys builds and checks `salt` for the Universal Account (PoP flow,
+[integration.md](../integration.md)) and, since P4, the `SmartKeyAccount` owner call; the v1 token checks stay unsalted (P5).
 
 <a id="CLI-SGN-34"></a>**CLI-SGN-34** — **A meta-transaction's `data` is decoded and shown before the user signs;
 a selector outside the token's allowlist is refused.** Status: **SPECIFIED**. clientkeys and the app encode
diff --git a/docs/contracts/README.md b/docs/contracts/README.md
index 0cfdc68..c03d26f 100644
--- a/docs/contracts/README.md
+++ b/docs/contracts/README.md
@@ -57,7 +57,7 @@ are normative targets for future versions and keep the built conventions: custom
 contract itself, lane nonces, contract-only allowances, no proxy upgrades.
 
 EIP-712 domains: name per implementation (`"SCaaS MetaToken"`, `"SCaaS ZetherToken"`, `"SCaaS MandateWallet"`,
-`"SCaaS SubjectAccount"` (built; target `SCaaS SmartKeyAccount`, P4), `"SCaaS Dex"`, `"SCaaS PqzToken"`, `"SCaaS UARegistry"`), version `"1"` (the UA
+`"SCaaS SmartKeyAccount"`, `"SCaaS Dex"`, `"SCaaS PqzToken"`, `"SCaaS UARegistry"`), version `"1"` (the UA
 registry: its generation), `chainId`,
 `verifyingContract` = the clone or contract itself, `salt` = the chain's `chain_uid` ([CTR-GEN-05](#CTR-GEN-05)). All
 clones of one implementation share the name; replay safety comes from `verifyingContract` and the salt
@@ -233,7 +233,7 @@ by rolling to block 1), else the script stops; unset it defaults to that hash.
 
 The script creates `deployments/` itself. It deploys `OpenFactory` with `NoUnderlyingToken` as version 1 of `NONE` (`UnderlyingToken` is over
 EIP-170 and waits for the size work) and, for the node until P5, the v1 line: `OpenFactoryV1` with `MetaToken` (version 1
-of `META`, when the registrar is the deployer), `SubjectAccountFactory`, `MetaTxDex` and `SCaaSDexV1`. The JSON gains
+of `META`, when the registrar is the deployer), `MetaTxDex` and `SCaaSDexV1`, plus `SmartKeyAccountFactory`. The JSON gains
 `token_factory`, `implementation_none`, `dex_implementation` (the `SCaaSDex` implementation) and `chain_uid`. `forge script … --broadcast` needs `--sender <deployer address>`; `DEPLOY_SALT` is optional.
 
 <a id="CTR-GEN-06"></a>**CTR-GEN-06** — **Every SCaaS EVM contract is deployed through a deterministic CREATE2
diff --git a/docs/contracts/accounts.md b/docs/contracts/accounts.md
index ddc3d1e..b1e3194 100644
--- a/docs/contracts/accounts.md
+++ b/docs/contracts/accounts.md
@@ -13,7 +13,7 @@ Passkeys can serve either way: as a `webauthn-p256` Universal Account, or as a k
 ([passkeys on chain](#passkeys)). Delegated, capped payment from a payer's own wallet is a separate contract:
 [mandates.md](mandates.md).
 
-<p align="center"><img src="../assets/account-forms.svg" width="860" alt="Accounts and keys: a native account (the chain’s own account, no registration); a Universal Account, the default (specified, nothing built: an id derived from key data or a policy, registered once per chain in the UARegistry with proof of possession); a SmartKeyAccount, optional (built: an ERC-1271 clone from SmartKeyAccountFactory with P-256 passkeys and secp256k1 keys, guardian recovery, key changes signed by the account itself). A passkey can be a webauthn-p256 UA or a SmartKeyAccount key. Every token kind accepts all three and checks the signature itself. MandateWallet (built; revocation epoch specified) is a payment authority, not an account: the payer deposits, a delegate pays approved payees within per-payment and per-period caps."></p>
+<p align="center"><img src="../assets/account-forms.svg" width="860" alt="Accounts and keys: a native account (the chain’s own account, no registration); a Universal Account, the default (specified, nothing built: an id derived from key data or a policy, registered once per chain in the UARegistry with proof of possession); a SmartKeyAccount, optional (built: an ERC-1271 clone from SmartKeyAccountFactory with P-256 passkeys and secp256k1 keys, guardian recovery, key changes signed by the account itself). A passkey can be a webauthn-p256 UA or a SmartKeyAccount key. Every token kind accepts all three and checks the signature itself. MandateWallet (built, with its revocation epoch) is a payment authority, not an account: the payer deposits, a delegate pays approved payees within per-payment and per-period caps."></p>
 
 <a id="universal-account"></a>
 **Contents**
@@ -1370,7 +1370,7 @@ On EVM the subject account is the built registry's `AuthScheme.SMART_ACCOUNT_127
 account, holding several passkeys `(qx, qy, rpIdHash)`; key types are `P256_WEBAUTHN(qx,qy,rpIdHash)` or
 `SECP256K1(address)`; the account signature was first specified as `abi.encode(keyIndex, payload)` and is now
 `abi.encode(keyIndex, bytes32[] proof, bytes sig)` for both key types. Key lifecycle: `addKey`/`removeKey`/`setGuardian`
-only through `mtxExecuteAsOwner` signed by an existing key (own nonce), or `recover(newKey)` by the guardian after
+only through `mtxExecuteAsOwner` signed by an existing key (the account's lane nonce), or `recover(newKey)` by the guardian after
 `RECOVERY_DELAY` (default 2 days, cancellable by a key); the account never has zero keys. P-256 verification per
 family: Sui `ecdsa_r1::secp256r1_verify`; Soroban `env.crypto().secp256r1_verify` (CAP-51); Cosmos `secp256r1_verify`
 (cosmwasm-std 2.1+); Hedera as EVM (probe the precompile, Solidity fallback); TON: TVM has
@@ -1388,7 +1388,7 @@ a seed key; precompile and Solidity gas; end to end: add a second key (seed when
 
 Status: **BUILT** (`smartcontracts/evm/src/account/`).
 
-<a id="CTR-ACC-11"></a>**CTR-ACC-11** — **The multi-key ERC-1271 contract account is named `SmartKeyAccount` (factory `SmartKeyAccountFactory`) in every chain family**: "smart" marks a contract account, "key" its many keys. **Transitional:** built code and non-EVM programs still use `SubjectAccount`; including the EIP-712 domain name, built `SCaaS SubjectAccount`, target `SCaaS SmartKeyAccount`; the vectors change with it; renamed in P4 (every family at once).
+<a id="CTR-ACC-11"></a>**CTR-ACC-11** — **The multi-key ERC-1271 contract account is named `SmartKeyAccount` (factory `SmartKeyAccountFactory`) in every chain family**: "smart" marks a contract account, "key" its many keys. Renamed in P4 in every family at once (EVM contract, factory, domain `SCaaS SmartKeyAccount` and vectors; the Solana PDA type; Sui/Aptos `meta::Account<T>` and Soroban `scaas-account` keep their family names, [networks](../networks/README.md)); the built `SubjectAccount` is in `smartcontracts/evm/legacy/p4/`.
 
 <a id="subjectaccount"></a>
 <a id="CTR-ACC-09"></a>**CTR-ACC-09** — **`SmartKeyAccount` is option (b), kept as built**: an optional ERC-1271 smart
@@ -1404,8 +1404,8 @@ identifier features. Tokens verify a `SmartKeyAccount` through ERC-1271 with the
 - Keys: multiple authorized keys (`P256_WEBAUTHN(x, y, rpIdHash, originHash)`, `SECP256K1(address)`), never zero keys (`LastKey`);
   guardian `initiateRecovery(newKey)` → anyone `completeRecovery` after `RECOVERY_DELAY`. Its
   `SECP256K1` keys come from the role path `m/7622'/0'/<account>'/2'/<i>'` ([CLI-SGN-30](../clients/signers-clientkeys.md#CLI-SGN-30)),
-  never from the EOA path (the factory salt and the 400 k cap as built: `SmartKeyAccountFactory.sol:21-23`,
-  `MetaToken.sol:141-144`); registering a key whose address equals the subject's own EOA (its payer address) on the
+  never from the EOA path (the factory salt and the 400 k cap as built: `SmartKeyAccountFactory.salt`,
+  `MetaTokenBase._erc1271Gas`); registering a key whose address equals the subject's own EOA (its payer address) on the
   same account is refused ([CLI-SGN-07](../clients/signers-clientkeys.md#CLI-SGN-07)). Its P-256 keys are passkeys
   (per `rpId`). A passkey that is a `webauthn-p256` UA may **also** be a `SmartKeyAccount` key: same kind, same
   WebAuthn scheme, digests differ (the account's challenge is the token's EIP-712 digest with `from` = the account);
@@ -1416,10 +1416,9 @@ identifier features. Tokens verify a `SmartKeyAccount` through ERC-1271 with the
   Its keys include P-256 passkeys that have no address, so the signer of the `MetaTransaction` is **the account**:
   `from = address(this)` is allowed here (the `SelfSender` guard of tokens is overridden) and `_requireValidSignature`
   checks the signature against the account's own key set (its ERC-1271 logic), signed by an existing key. Domain
-  `("SCaaS SubjectAccount", "1", chainId, account, chain_uid)` (built; target `SCaaS SmartKeyAccount`, P4), the 2D lane nonce, fee mode `NONE` (the relayer pays
-  gas). `mtxExecuteAsOwner(data, nonce, validUntil, signature)` keeps its signature as the named builder of that
-  `MetaTransaction` with `batch = 0`. A plain EOA never rotates. **Transitional (BUILT):** `executeAsOwner` verifies
-  its own `OwnerCall(bytes data,uint256 nonce,uint256 validUntil)` with a single nonce.
+  `("SCaaS SmartKeyAccount", "1", chainId, account, chain_uid)`, the 2D lane nonce, fee mode `NONE` (the relayer pays
+  gas); `cancelRecovery` and the base `cancelNonce` are allowlisted too. `mtxExecuteAsOwner(data, nonce, validUntil,
+  signature)` is the named builder of that `MetaTransaction` with `batch = 0`. A plain EOA never rotates. BUILT (P4).
 - The client backup predicate ([CLI-SGN-13](../clients/signers-clientkeys.md#CLI-SGN-13)) applies to it unchanged;
   derived UAs are "single-key, no recovery" by construction and the app shows that.
 - `msig` UAs may list a `SmartKeyAccount` as a member (native contract member).
@@ -1470,7 +1469,7 @@ implementation pins the chain's `SmartKeyAccount` implementation (constructor pa
 gas on chains without the precompile. Other contract wallets (Safe, …) keep 50 k. `Deploy.s.sol` deploys
 `SmartKeyAccountFactory` before the token and records its address in `deployments/<chainid>.json`. The same rule is
 applied by `SCaaSDex` ([CTR-DEX-08](dex.md#CTR-DEX-08)) and to Zether envelopes ([CTR-ZTH-21](zether.md#CTR-ZTH-21)).
-`SmartKeyAccount` has its own salted domain `("SCaaS SubjectAccount","1", chainId, account, chain_uid)` (built; target `SCaaS SmartKeyAccount`, P4); the factory
+`SmartKeyAccount` has its own salted domain `("SCaaS SmartKeyAccount","1", chainId, account, chain_uid)`; the factory
 takes `chain_uid` as a constructor argument and passes it to `new SmartKeyAccount(chainUid)`, so a user's account has a
 different address on each chain and the node and app predict it per chain ([CTR-GEN-05](README.md#CTR-GEN-05)).
 
@@ -1483,7 +1482,7 @@ is rejected for now: it would change every 1271 digest, every KAT and every clie
 |---|---|
 | `initialize(firstKey, guardian)` | factory only, once |
 | `isValidSignature(digest, sig)` | ERC-1271; [CTR-ACC-02](#CTR-ACC-02) encoding |
-| `mtxExecuteAsOwner(data, nonce, validUntil, signature)` | self-call of `addKey`/`removeKey`/`rotateKey`/`setGuardian`/`execute`; the nonce increments before the call |
+| `mtxExecuteAsOwner(data, nonce, validUntil, signature)`, `mtxExecute` | self-call of `addKey`/`removeKey`/`rotateKey`/`setGuardian`/`cancelRecovery`/`execute`, signed as the account; the lane nonce increments before the call |
 | `initiateRecovery` / `completeRecovery` / `cancelRecovery` | [CTR-ACC-03](#CTR-ACC-03) |
 | factory `predict`, `deploy` | idempotent, [CTR-ACC-01](#CTR-ACC-01) |
 
diff --git a/docs/contracts/mandates.md b/docs/contracts/mandates.md
index a28c848..ddcf697 100644
--- a/docs/contracts/mandates.md
+++ b/docs/contracts/mandates.md
@@ -3,7 +3,7 @@
 A mandate lets a delegate pay from a payer's own wallet within limits the chain enforces: per payment, per period,
 to approved payees, until an expiry, revocable at any time. It is a payment authority, not an account: the payer keeps
 its own account ([accounts.md](accounts.md)) and the funds sit in its `MandateWallet`. Status: **BUILT**
-(`smartcontracts/evm/src/wallet/`); revocation epoch, the `mtx` names and the salted domain **SPECIFIED**.
+(`smartcontracts/evm/src/wallet/`, on `MetaTxBase` since P4; the typed-struct wallet before it is in `legacy/p4/`).
 
 ## <a id="mandatewallet"></a>1. `MandateWallet`
 
@@ -27,7 +27,8 @@ has, `msg.sender` = the wallet — no allowance. Kill switch: `revoke(token)` by
 and only build the matching `MetaTransaction`; their signatures carry no lane, so they derive it as `mtxPay` does:
 `mtxPayUnderMandate` → `batch = uint256(keccak256("scaas.mandate.pay" ‖ entryRef))`, `nonce = 0` (one payment per
 `entryRef`); `mtxRevoke` → `batch = uint256(keccak256("scaas.mandate.revoke" ‖ token ‖ epoch))`, `nonce = 0`;
-`mtxExecuteAsOwner` → `batch = 0`. The lane nonce replaces the replay checks of the earlier typed structs. `PaymentSettled` still carries `entryRef`, so
+`mtxExecuteAsOwner` → `batch = 0` (`‖` is `abi.encodePacked`, the epoch 8 bytes; views `mandatePayLane`,
+`mandateRevokeLane`). Each builder reverts `NoMandate` when the token has no delegate. The lane nonce replaces the replay checks of the earlier typed structs. `PaymentSettled` still carries `entryRef`, so
 reconciliation is exactly that of a manual payment (the design sketch was `payUnderMandate(order, delegateSig)`).
 
 **Why a wallet per payer** rather than an allowance to one shared mandate contract: a
@@ -41,12 +42,9 @@ is `("SCaaS MandateWallet","1", chainId, wallet, salt = chain_uid)` with `chain_
 chain profile ([CTR-GEN-05](README.md#CTR-GEN-05)); because the deployer chooses that value per wallet, the node checks
 the wallet's `chainUid()` against the chain profile before relaying anything for it.
 
-**Transitional (BUILT):** the
-entry points are named `payUnderMandate(token, payee, amount, entryRef, validUntil, sig)`, `revokeWithSig` and
-`executeAsOwner`, each verifying its own typed struct (`PayUnderMandate(address token,address payee,uint256
-amount,bytes32 entryRef,uint256 validUntil)`, `RevokeMandate(…)`, the owner call) instead of a `MetaTransaction`, and
-the domain has no `salt`; the renames follow [CTR-MTX-21](metatx.md#CTR-MTX-21), the move onto `MetaTxBase`
-[CTR-MTX-22](metatx.md#CTR-MTX-22).
+**Errors** (besides the base's): `NotOwner`, `NotDelegate` (`_msgSender()` is not the mandate's delegate), `NoMandate`,
+`MandateExpired`, `PayeeNotAllowed`, `OverPaymentCap`, `OverPeriodCap`, `RefAlreadyPaid`, `StaleEpoch(current, signed)`,
+`BadMandate`, `PayFailed` (a token answering false: the whole payment reverts), `CallFailed`, `ZeroOwner`.
 
 Delegated payment and the kill switch, as a sequence:
 
@@ -72,10 +70,10 @@ sequenceDiagram
 keeps `epoch[token]` (uint64), incremented by every `setMandate` and every revoke; the delegate's signed revoke is a
 `MetaTransaction` with `data = revoke(token, epoch)` on the lane `keccak256("scaas.mandate.revoke" ‖ token ‖ epoch)`,
 and `revoke(address,uint64)` requires `epoch == epoch[token]`, so a public revoke signature cannot be replayed until
-its `validUntil` to delete a mandate the owner re-established. The built wallet has the typed `RevokeMandate(address
-token,uint256 validUntil)` and no epoch; the client digest builders and the forge KAT change together. EVM only: the Solana mandate binds a generation, and the Sui/Aptos/Cosmos mandates are one-shot. Tests:
-revoke, `setMandate` again, replay ⇒ `BadSignature`/`StaleEpoch`; a current-epoch revoke works; client digest == forge
-vector. Status **SPECIFIED**.
+its `validUntil` to delete a mandate the owner re-established. Forge KATs `mandate_pay_kat.json` and `mandate_revoke_kat.json`, read by
+clientkeys. EVM only: the Solana mandate binds a generation, and the Sui/Aptos/Cosmos mandates are one-shot. Tests:
+revoke, `setMandate` again, replay ⇒ `StaleEpoch`; a current-epoch revoke works; client digest == forge
+vector. Status **BUILT** (P4).
 
 **Hedera ED25519 owners** pay from a `MandateWallet` only through `HederaMandateWallet.mtxExecuteAsOwnerRaw`
 (`HederaMandateWallet.sol`): ERC-1271 runs under STATICCALL, where HIP-632 `isAuthorizedRaw` halts, so a meta-tx with
@@ -84,7 +82,7 @@ vector. Status **SPECIFIED**.
 
 | Entry point | Rule |
 |---|---|
-| `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee` | owner |
+| `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee`, `execute` | owner (directly, or signed: `mtxExecute`, `mtxExecuteAsOwner`) |
 | `revoke` | owner; bumps `epoch[token]` |
 | `payUnderMandate(token, payee, amount, entryRef)` | delegate-signed `MetaTransaction` (`mtxExecute`, or the named `mtxPayUnderMandate(token, payee, amount, entryRef, validUntil, sig)`); anyone submits |
 | `revoke(token, epoch)` | delegate-signed `MetaTransaction` (`mtxExecute`, or the named `mtxRevoke`) |
diff --git a/docs/contracts/metatx.md b/docs/contracts/metatx.md
index 77b1fdc..ff412fa 100644
--- a/docs/contracts/metatx.md
+++ b/docs/contracts/metatx.md
@@ -165,7 +165,7 @@ They are locked by known-answer vectors generated by forge (`vm.writeJson`):
 `smartcontracts/evm/test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`) and `metatransfer_kat.json` (`MetaTransfer`);
 `metatx_v1_kat.json` is the built v1 struct (`LegacyMetaTransaction`), read by scaas-node and clientkeys until P5,
 the two v3 vectors written by `TokenKat.t.sol` on a `NoUnderlyingToken` clone, each with domain (with `salt`), struct, `structHash`, digest and the signature of key `0xA11CE`; the `MandateWallet` and
-`SmartKeyAccount` vectors are `MetaTransaction` vectors in their own domains. The contract, node and client tests read
+`SmartKeyAccount` vectors are `MetaTransaction` vectors in their own domains (`mandate_pay_kat.json`, `mandate_revoke_kat.json`, `smart_key_account_kat.json`, P4). The contract, node and client tests read
 the same files; changing a typehash turns three tests red. Clients decode `MetaTransaction.data` against the
 contract's published allowlist (`mtxSelectors()`) and show the selector and its arguments before asking for a
 signature; a `MetaTransfer` shows its typed fields.
@@ -174,7 +174,7 @@ signature; a `MetaTransfer` shows its typed fields.
 `verifyingContract` = the clone and `salt` = the chain's `chain_uid`: `("SCaaS MetaToken", "1", chainId, clone,
 chain_uid)` for every kind, `("SCaaS ZetherToken", "1", chainId, clone, chain_uid)` for Zether; every other SCaaS
 contract on `MetaTxBase` uses `("SCaaS <Contract>", "1", chainId, contract, chain_uid)` (e.g. `"SCaaS MandateWallet"`,
-`"SCaaS SubjectAccount"` (built; target `SCaaS SmartKeyAccount`, P4); a contract built on SCaaS names its own); both structs of a contract share its domain; `eip712Domain()`
+`"SCaaS SmartKeyAccount"`; a contract built on SCaaS names its own); both structs of a contract share its domain; `eip712Domain()`
 (ERC-5267) reports fields `0x1f`. `chain_uid` is the implementation's constructor immutable, so a clone (which runs the
 implementation's code by `DELEGATECALL`) uses it with no storage and cannot declare another value
 ([CTR-GEN-05](README.md#CTR-GEN-05)). There is no cross-token replay because `verifyingContract` differs, and no
@@ -255,7 +255,7 @@ prefix:
 
 | Step | Check / action | Error |
 |---|---|---|
-| 1 | `MODE_RESTRICT_RELAYER` ⇒ `msg.sender == m.relayer`; `block.timestamp ≤ m.validUntil`; `validateMode(m.mode)`; `m.nonce == mtxNonce(from, batch)`; the fee-recipient binding; `from ≠ address(this)` (overridden by `SmartKeyAccount`, which signs as itself, [CTR-ACC-10](accounts.md#CTR-ACC-10)) | `MetaTxUnauthorizedRelayer`, `MetaTxExpired`, `MetaTxUnknownMode`, `MetaTxBadNonce(expected, got)`, `SelfSender()` |
+| 1 | `MODE_RESTRICT_RELAYER` ⇒ `msg.sender == m.relayer`; `block.timestamp ≤ m.validUntil`; `validateMode(m.mode)`; `m.nonce == mtxNonce(from, batch)`; the fee-recipient binding; `from ≠ address(this)` (the `_selfSender` hook; overridden by `SmartKeyAccount`, which signs as itself, [CTR-ACC-10](accounts.md#CTR-ACC-10)) | `MetaTxUnauthorizedRelayer`, `MetaTxExpired`, `MetaTxUnknownMode`, `MetaTxBadNonce(expected, got)`, `SelfSender()` |
 | 2 | Signature over the digest (`_hashTypedDataV4(hashStruct(m))`) through the virtual `_requireValidSignature`: EOA ⇒ `ECDSA.tryRecover` (65 bytes, low-s); contract ⇒ ERC-1271 `isValidSignature` staticcall (50 000 gas; 400 000 for `SmartKeyAccount` clones, which verify P-256 in Solidity when no precompile, [CTR-ACC-05](accounts.md#CTR-ACC-05)) | `MetaTxBadSignature` |
 | 3 | Shape: `data.length ≥ 4`; `bytes4(data)` allowlisted; `data.length` equals the selector's static ABI length where it has one; the fee mode is allowed by the selector's fee class ([CTR-MTX-20](#CTR-MTX-20)) and by `supportedModes()` | `MtxSelectorNotAllowed(bytes4)`, `MtxDataShape(bytes4)`, `MtxFeeClass(bytes4, uint32 mode)`, `MetaTxUnknownMode` |
 | 4 | Write `mtxNonce = expected + 1` | — |
@@ -320,7 +320,7 @@ it. Nothing else is reachable through `mtxExecute`.
 | | `zetherTransfer`, `…Bundle`, `…NoBundle`, `…Single` `(bytes,bytes,bytes,bytes32)`, `zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)`, `zetherUnshieldUnwrap` | `ABSOLUTE`; envelope binding through the ticket ([CTR-ZTH-34](zether.md#CTR-ZTH-34)) |
 | `PqzToken` | `pqzTransfer(bytes,bytes,bytes[],bytes,bytes)`, `pqzUnshield(bytes,bytes,bytes[],uint256,address,bytes,bytes)`, `pqzShield(bytes32,uint256)`, `pqzRollOver(bytes32,bytes,bytes[])` | `ABSOLUTE`; not batchable ([CTR-PQZ-21](pq-zether.md#CTR-PQZ-21)) |
 | `MandateWallet` | delegate: `payUnderMandate(address,address,uint256,bytes32)`, `revoke(address,uint64)`; owner: `setMandate`, `setPayee`, `revoke(address)`, `execute` ([CTR-ACC-06](mandates.md#CTR-ACC-06)) | fee `NONE` only |
-| `SmartKeyAccount` | `addKey`, `removeKey`, `rotateKey`, `setGuardian`, `execute`, signed by the account itself ([CTR-ACC-10](accounts.md#CTR-ACC-10)) | fee `NONE` only |
+| `SmartKeyAccount` | `addKey`, `removeKey`, `rotateKey`, `setGuardian`, `cancelRecovery`, `execute`, signed by the account itself ([CTR-ACC-10](accounts.md#CTR-ACC-10)) | fee `NONE` only |
 
 Transfer and payment are `MetaTransfer`s ([CTR-MTX-23](#CTR-MTX-23)); neither `transfer` nor `pay` is ever
 allowlisted, so one transfer has one encoding and one digest. `UnderlyingToken`'s two-argument `unwrap(uint256,address)` is not listed (the same intent with a
@@ -912,15 +912,13 @@ named in brackets). The v2 tiers run on the new tree (last bullet).
   `WrapperHasNoMint`; errors `NotMinter`, `NotAWrapper`) and `HederaMetaToken`; the Zether kinds are on `MetaTokenBase` (P3; the old `ZetherMetaTx` is in `legacy/p3/`). Invariants as
   built: `Σ balance == totalSupply`; wrapper `reserve >= totalSupply`, fuzzed as `reserve >= supply`.
 - **Signature checks** ([CTR-MTX-25](#CTR-MTX-25)). Built (P1a): `SigCheck` serves `MetaTxBase` and the built bases
-  `ERC20MetaTxV1`, `ERC20MetaTx` (and the Zether kinds through `MetaTokenBase`, P3); `SigLib` is deleted. `SCaaSDex`, `MandateWallet` and
-  `SmartKeyAccount` keep their own checks until P2/P4, and the HIP-632 override stays in the four Hedera children
-  until P1c.
+  `ERC20MetaTxV1`, `ERC20MetaTx` (and the Zether kinds through `MetaTokenBase`, P3), `MandateWallet` and `SmartKeyAccount`
+  (on `MetaTxBase`, P4; the account checks its own keys); `SigLib` is deleted. The v1 `SCaaSDexV1` keeps its own check.
 - **Structs** ([CTR-MTX-15](#CTR-MTX-15), [CTR-MTX-23](#CTR-MTX-23)). v1 (and the pre-P3 Zether line, `legacy/p3/`): one 11-field
   `MetaTransaction{from, to, value, data, batch, nonce, validUntil, mode, relayer, fee, feeRecipient}` (typehash
   `MetaTransaction(address from,address to,uint256 value,bytes data,…)`) carries transfers (`data` empty), payments
   (`data = pay(bytes32)`) and the ops below, named `MetaTxLib.LegacyMetaTransaction` (typehash unchanged, vector
-  `metatx_v1_kat.json`). `MandateWallet` and `SmartKeyAccount` verify their own typed structs (`PayUnderMandate`,
-  `RevokeMandate`, `OwnerCall`) with their own nonces.
+  `metatx_v1_kat.json`). Before P4, `MandateWallet` and `SmartKeyAccount` verified their own typed structs (`legacy/p4/`).
 - **Domains** ([CTR-MTX-02](#CTR-MTX-02)). v1 `("SCaaS MetaToken", "1", chainId, clone)`; no salt.
 - **Dispatch** ([CTR-MTX-17](#CTR-MTX-17), [CTR-MTX-19](#CTR-MTX-19)). v1 `executeMetaTransaction(m, signature)` runs
   the legacy steps: relayer, expiry, mode, `m.nonce == metaNonce(from, batch)`, signature, then the fee and `_checkOp`,
diff --git a/docs/history/dropped-artifacts.tsv b/docs/history/dropped-artifacts.tsv
index c3d3751..9cec652 100644
--- a/docs/history/dropped-artifacts.tsv
+++ b/docs/history/dropped-artifacts.tsv
@@ -828,3 +828,7 @@ script/DeployZether.s.sol	obsolete	never built; the Zether stack deploys with DE
 ZetherMetaTx._requireValidSignature	renamed	MetaTxBase._requireValidSignature (P3), contracts/accounts.md
 ZetherToken.registered(ua)	renamed	ZetherLayer.registered(ua) (P3), contracts/accounts.md
 ConfidentialTransfer(entryRef)	obsolete	old ZetherToken OP_ZTRANSFER event (legacy/p3); the kinds emit ZetherTransfer with entryRef, contracts/zether.md
+contracts.subjectAccountFactory	renamed	contracts.smartKeyAccountFactory, from the deploy key smart_key_account_factory (P4), clients/app.md
+subject_account_create2	renamed	smart_key_account_create2 (P4), clients/app.md
+"SCaaS SubjectAccount"	renamed	"SCaaS SmartKeyAccount" (P4, CTR-ACC-11), contracts/accounts.md
+SCaaS SubjectAccount	renamed	SCaaS SmartKeyAccount (P4, CTR-ACC-11), contracts/accounts.md
diff --git a/docs/networks/evm.md b/docs/networks/evm.md
index 72613d1..bcbb797 100644
--- a/docs/networks/evm.md
+++ b/docs/networks/evm.md
@@ -172,12 +172,12 @@ chain, deploy it first (the keyless presigned deployment transaction of that pro
 and re-run. `forge script … --broadcast` needs `--sender <deployer address>`, which `deploy.sh` and the e2e pass; forge
 places the linked libraries from that sender, not by CREATE2. It deploys `OpenFactory` with `NoUnderlyingToken` as
 version 1 of `NONE` (`UnderlyingToken` is over EIP-170 and is not deployed until the size work) and, for the node until
-P5, the v1 line (`OpenFactoryV1` with `MetaToken` as version 1 of `META`, `MetaTxDex`), `SubjectAccountFactory` and
+P5, the v1 line (`OpenFactoryV1` with `MetaToken` as version 1 of `META`, `MetaTxDex`), `SmartKeyAccountFactory` (P4) and
 `SCaaSDexV1` (plus the `SCaaSDex` implementation, registered as DEX version 1 on the factory), optionally a tier-1 demo token ([deploy](../contracts/README.md#build-ci-and-pins)).
 
 It writes
-`deployments/<chainid>.json` (`factory`, `implementation`, `dex`, `subject_account_factory`,
-`subject_account_implementation`, `scaas_dex`, `demo_token`, and `token_factory`, `implementation_none`, `dex_implementation`, `chain_uid`),
+`deployments/<chainid>.json` (`factory`, `implementation`, `dex`, `smart_key_account_factory`,
+`smart_key_account_implementation` (were `subject_account_*` before P4), `scaas_dex`, `demo_token`, and `token_factory`, `implementation_none`, `dex_implementation`, `chain_uid`),
 which seeds the client and the node configuration. forge writes it during the simulation, before the broadcast; `deploy.sh` puts the previous file back (or removes the new one) when the broadcast fails.
 Zether (built, P3; dev chains only, UNAUDITED): opt in with `DEPLOY_ZETHER=1` (default off, so a plain anvil deploys as before P3, every contract under EIP-170; on a non-dev chain the script refuses). It adds the account registry, `ZetherDisclosure`, `ZetherStatements`, both verifiers and the two confidential implementations (versions 1 of `NONE_ZETHER` and `UNDERLYING_ZETHER`, the factory's Zether gate on when the deployer is the registrar), and the keys `zether_registry`, `zether_disclosure`, `zether_statements`, `zether_verifier_bn254`, `zether_verifier_bls12381`, `implementation_none_zether`, `implementation_underlying_zether`. The implementations exceed 24,576 B and the BLS verifier's deploy uses ~14.1 M gas (forge's estimate ~15.0 M), so `deploy.sh` then passes `--code-size-limit 65536 --gas-estimate-multiplier 105` to `forge script` (the default ×1.30 exceeds the Osaka per-transaction cap of 16,777,216, EIP-7825; ×1.13 or more fails) and the anvil needs `--code-size-limit 65536`; `ZetherDeploy.t` checks each deploy fits.
 Integration tests use `anvil --hardfork osaka --gas-limit 16777216 --code-size-limit 65536` (64 KiB code, as EIP-7954 proposes; owner 2026-10-11 — real chains keep 24,576, so a contract that only fits this anvil still cannot be deployed there).
diff --git a/docs/node/job-api.md b/docs/node/job-api.md
index aa831a8..6961762 100644
--- a/docs/node/job-api.md
+++ b/docs/node/job-api.md
@@ -380,7 +380,7 @@ equals `chain.chain_uid` ([NODE-GW-07](gateway.md#NODE-GW-07)); a mismatch ⇒ `
 | Selector | Target rule | Typical producer |
 |---|---|---|
 | `SmartKeyAccountFactory.deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)` | the chain's account factory (`chain_contract.kind = account_factory`) | client subject-account onboarding |
-| `SmartKeyAccount.mtxExecuteAsOwner(bytes,uint256,uint256,bytes)` (built as `SubjectAccount.mtxExecuteAsOwner`, renamed in P4) | runtime code = EIP-1167 clone of that factory's `IMPLEMENTATION` (checked at lease, cached); the account address is predicted per chain (the factory's constructor takes `chain_uid`, so the same owner has a different account address on each chain) | client subject accounts; role holders that are subject accounts |
+| `SmartKeyAccount.mtxExecuteAsOwner(bytes,uint256,uint256,bytes)` (built in P4) | runtime code = EIP-1167 clone of that factory's `IMPLEMENTATION` (checked at lease, cached); the account address is predicted per chain (the factory's constructor takes `chain_uid`, so the same owner has a different account address on each chain) | client subject accounts; role holders that are subject accounts |
 | `MandateWallet.mtxPayUnderMandate`, `mtxRevoke` (epoch-bound, [CTR-ACC-07](../contracts/mandates.md#CTR-ACC-07)), `mtxExecuteAsOwner`; `HederaMandateWallet.mtxExecuteAsOwnerRaw` | any address that is not a registered token and whose `chainUid()` equals `chain.chain_uid` (self-authenticating: the target checks the delegate/owner signature; a wallet is deployed per user with a deployer-chosen value, so it is read at lease and cached) | client payment requests, auto-pay |
 | `SCaaSDex.mtxSettle` / `mtxExchange` / `mtxExchangeVia` ([CTR-DEX-20](../contracts/dex.md#CTR-DEX-20), BUILT on the new `SCaaSDex` (P2c); the node side, [NODE-DEX-17](dex-venue.md#NODE-DEX-17), SPECIFIED) / `mtxCancelOrders` / `mtxInvalidateNonces` | a DEX on the chain profile's DEX list (`chain_contract.kind = dex`, [NET-ALL-24](../networks/README.md#NET-ALL-24)); never any other address | DEX venue (`~dex`) |
 | `UniversalAccountRegistry.register` (`UARegistry.register` once the UA registry is deployed) | `chain.ua_registry`, `~gateway` only ([NODE-GW-03](gateway.md#NODE-GW-03)) | node gateway |
@@ -391,8 +391,8 @@ equals `chain.chain_uid` ([NODE-GW-07](gateway.md#NODE-GW-07)); a mismatch ⇒ `
 
 `pqz_call` jobs are not `call` jobs: their own selector list is in the kinds table above.
 
-Transitional (BUILT): the deployed contracts and the node's built table use the earlier names —
-`SmartKeyAccount.executeAsOwner(bytes,uint256,uint256,bytes)`, `MandateWallet.payUnderMandate`/`revokeWithSig`/`executeAsOwner`,
+Transitional (BUILT): the contracts are renamed (P4: `SmartKeyAccount`, `MandateWallet` on `MetaTxBase`); chains deployed
+before P4 and the node's built table use the earlier names — `SubjectAccount.executeAsOwner`, `MandateWallet.payUnderMandate`/`revokeWithSig`/`executeAsOwner`,
 `SCaaSDexV1.settle`/`cancel`/`invalidateNonces` — and the DEX row also matches the chain's single `dex` field. The
 renamed rows replace them in the release that deploys the renamed contracts; no deployed chain keeps both.
```
- [ ] **Step 2: Run** `python3 scripts/test_docs_check.py` → ok; `python3 scripts/docs_check.py check` → 0 errors (the
  `dex.md` and `token-wrappers.md` budget warnings predate this plan); `python3 scripts/docs_check.py facts check` → 0
  misses; `/usr/bin/grep -rn 'SubjectAccount' docs README.md --include=*.md | /usr/bin/grep -v 'docs/history\|docs/reviews\|superpowers\|docs/research\|integration'`
  → only the "was"/legacy mentions in architecture.md, networks/evm.md, node/job-api.md, clients/app.md and decisions.md.
- [ ] **Step 3: Commit** `P4: docs (accounts, mandates, metatx), TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh): rerun the probe (Task 5 Step 3) and probe beyond it — a SmartKeyAccount as
  the guardian of another, a passkey Merkle batch signing a key change and a payment in one assertion, `mtxBatch` mixing
  the account's lane 0 and another lane, a wallet whose owner is a SmartKeyAccount (ERC-1271 owner, 50 k cap on the
  wallet), the delegate changed between sign and submit of `mtxRevoke`, a HIP-632 delegate on `HederaMandateWallet`;
  the open questions above parked or answered by the owner; one fix wave; scoped re-review.
- Merge `p4-accounts` into `main` `--no-ff`; push; remove the worktree `.claude/worktrees/p4` (and its `node_modules`
  symlinks); then the bamboo-dms follow-up (TODO P4).
