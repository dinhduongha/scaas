> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Requested by the owner (2026-11-05); it reviewed the first draft of [the pay-meta-tax spec](../superpowers/specs/2026-11-05-pay-meta-tax.md). Copied verbatim below.

# Payment metadata and tax: Codex security review

Reviewed the uncommitted `docs/superpowers/specs/2026-11-05-pay-meta-tax.md` on `ua-mtx-merge`, against current source and repository documents. **UNAUDITED; static design review only.** No build, tests, generators, benchmarks, deployments or source edits were performed. Only this report was written. The parallel counter-review was not used.

Source evidence refers to the files as read. Concurrent tracked edits appeared during the review in `ERC20MetaTx.sol`, `UAMetaTxBase.sol`, `ZetherLayer.sol` and `PlusZero.t.sol`; those later edits were not re-reviewed, and may move the cited line numbers. They were not made by this review.

The draft is not an implementation. In particular, the proposed regulated hooks and `RegulatedLib` tax bodies cannot yet be verified as executable code. Findings below distinguish integration gaps exposed by current code from future-family risks. No critical issue or demonstrated high-severity EVM signature forgery was found. There are four medium and three low findings, and one informational domain-separation finding.

## Findings

### 1. Medium — The node's nested-payment machinery assumes the receiver-fee signer and emitted digest

**Spec:** §5.2–5.3, §7.1, T42.

**Problem:** Adding a `UAPayWithTax` table row is insufficient. The current parser interprets a nested `payment` without a top-level `from` as a receiver-fee operation: it selects `payment.to` as the signer and unconditionally makes the inner payment hash the lane's execution hash. Both assumptions are wrong for tax. The tax signature belongs to `payment.from`; §5.3 passes the outer tax struct hash to `_uaExecuteTransfer`, which emits the **outer** digest.

With distinct native payer and payee, reusing this machinery rejects a valid payer signature as `BAD_SIGNATURE` against the payee. If it gets past that check, a landed taxed payment can be classified as `superseded` because the node searches for the inner digest while the contract reports the outer one. This can mislead operators into requesting a fresh signature after a payment already landed; free lanes make a subsequent duplicate payment possible.

**Concrete fix:** Make these two behaviors specific to `UAReceiverFee`. For `UAPayWithTax`, select the payer as signer, retain the payer's nested lane, and use the outer hash for both the job identity and execution matching. The new `t` job name must map explicitly to the signed `payment` member. Include a distinct-payer/payee case and a consumed-nonce/landed-elsewhere case in T42's planned checks; keep receiver-fee behavior unchanged.

**Evidence:** `scaas-node/src/typed.rs:840`–`875` (signer fallback and unconditional `lane_hash` for `payment`); `scaas-node/src/typed.rs:727` (execution digest selection); `scaas-node/src/guard.rs:675`–`685` (fills `MetaRef.digest`), `:550`–`570` (`BAD_SIGNATURE`); `scaas-node/src/submit.rs:656`–`662` (digest mismatch becomes `superseded`). `smartcontracts/evm/src/metatx/ERC20MetaTx.sol:253`–`258` emits `o.digest`; `MtxPipelineLib.sol:287`–`292` uses the supplied alternate struct hash.

### 2. Medium — Open relay-fee forwarding bypasses RK-6 for the ultimate frozen relayer

**Spec:** §4 (retains today's router behavior), §7.1; regulated spec §2.2, §3.2, RK-6.

**Problem:** In open mode the signed relay-fee payee is the router. The token's proposed `_regFeeTo(payee, value)` therefore checks the router, then the router forwards the fee with an ordinary ERC-20 transfer to `msg.sender`. Ordinary credits permit a frozen recipient. An eligible frozen relayer can consequently collect this token fee through an unfrozen router, although paying the same relayer directly fails RK-6. This is a pre-existing composition gap in the regulated design carried into this redesign, not an exploit of free nonces.

**Concrete fix:** For regulated fee tokens, require the signed payee to be the final relayer and refuse router-forwarded open mode, or specify a token-recognized forwarding operation that checks the final beneficiary under RK-6. A node-only restriction does not fix permissionless router calls. Do not silently extend the DEX's explicitly accepted ordinary-credit exception to this token fee.

**Evidence:** `smartcontracts/evm/src/metatx/MtxRelayFee.sol:69`–`72`, `:89`–`94` (payment to router followed by `safeTransfer(msg.sender, value)`); regulated spec `:132`, `:291` (check relay `payee`), `:293` (only DEX share explicitly treated as ordinary credit), RK-6 at `:701`. Its ledger rule at `:294` checks frozen **sender**, not frozen ordinary receiver.

### 3. Medium — Removing horizon obligations wholesale would revive stale nonce-slot authorizations on pruning families

**Spec:** §2.2, §8, §10's CTR-MTX-04 change.

**Problem:** The statement that horizon obligations hold only for clients choosing the old pay-once convention is too broad. Pruning a free lane still forgets that a nonce slot was consumed. For example, a payer signs alternative payments A and B on arbitrary lane 7, nonce 0. A expires on day 1; B expires on day 90. A lands; after A's recorded expiry plus the pruning delay, lane 7 is deleted. B can then run despite A having already consumed their common nonce slot. The payer intended alternatives, not two authorizations that become sequential after pruning. Cancellation can be undermined by the same forgotten-state mechanism.

This is **not a present EVM replay issue**: its nonce mapping is persistent. It is a flaw in the family-neutral rule proposed for later rounds. It requires multiple authorizations with different expiries, not replaying one expired signature.

**Concrete fix:** Remove invoice-level pay-once while retaining nonce-lifetime safeguards on every pruning family, independently of `entryRef` or lane convention. Keep the existing signing/retention restrictions until the family's free-lane design specifies persistent generations, tombstones, or another complete replay solution. Explicitly distinguish lifetime reuse of a lane from the narrower payment-request convention in §10.

**Evidence:** CTR-MTX-04, `docs/contracts/metatx.md:569` onward; `docs/networks/aptos.md:169`–`193` explicitly describes permissionless pruning and the different-expiry attack on one lane/nonce, including why an execution-time TTL cap alone is insufficient. Current EVM persistence: `smartcontracts/evm/src/metatx/MtxPipelineLib.sol:59`–`63`, `:175`–`176`, `:275`–`278`.

### 4. Medium — Class zero is declared tax-free but its rate remains writable

**Spec:** §6.2 storage table and Rate/Class rules; §13 J4.

**Problem:** The mapping defines class 0 as “no class: rate 0,” and every account starts there. But `setTaxRate(uint8 taxClass, uint32 ratePpm)` permits class 0, while the effective-rate algorithm selects the stored rate without a class-zero exception. Two reasonable implementations disagree: either a bit-23 holder can tax every unclassified payee after setting rate 0's policy, or class-zero policy writes silently have no effect. Wallets treating “unclassified” as exempt can construct transactions that revert or display a misleading policy.

**Concrete fix:** Reserve zero explicitly: reject `setTaxRate(0, …)` and define `effectiveRate(0) == 0` in the contract, node and clients. `setTaxClass(account, 0)` should remain the way to remove a class. Pin this case in the planned tax vectors. If zero is intended to be taxable, remove the exemption claim and make that policy visible instead.

**Evidence:** Draft §6.2 (`mapping account ⇒ uint8 taxClass`, zero description, unconstrained setter and generic `effectiveRate(c)`); §5.3 step 3 and §7.1 both consume that lookup. No implemented tax setter exists to resolve the ambiguity.

### 5. Low — The notice disclosure overstates protection against an effective rate increase

**Spec:** §6.2–6.3, §11 Q9, PT-5.

**Problem:** A holder can immediately move a payee from a 0% class to an already effective 100% class. No `setTaxRate` increase occurs, so the payee's applicable PERCENT rate rises without notice. The literal per-class setter rule permits this, but “a rate increase waits the notice period” in the disclosure suggests broader protection. Also, the claimed factory “floor 3 days on public chains” is not enforced by `OpenFactory`: its constructor permits zero. The three-day mainnet floor is a deployment-script check, and listed public test chains have lower defaults.

The exact signed `tax` prevents this from silently increasing an existing payment's deduction: a changed result causes `TaxMismatch`, except where flooring leaves the same tax. The remaining exposure is policy trust and transaction invalidation, not an unsigned tax-amount increase.

**Concrete fix:** Preserve the owner's notice-on-rate-only ruling, but state precisely that class reassignment can raise an account's effective rate immediately, and display the actual factory period rather than promising a universal floor. If per-payee advance notice is intended, it needs an additional rule for class changes; the present state machine cannot promise it.

**Evidence:** Draft §6.2 explicitly makes class changes immediate; §6.3 omits this consequence. `smartcontracts/evm/src/factory/OpenFactory.sol:57`–`62` enforces only the upper bound; `smartcontracts/evm/script/DeployBase.sol:270`–`271` supplies the conditional lower bound. `docs/networks/evm.md:281`–`284` describes smaller test-chain defaults. Draft §5.3 step 3 binds execution to the exact signed tax.

### 6. Low — Privacy claims conflate a hidden preimage with a published salted commitment

**Spec:** §3.2–3.3, §9, PT-7.

**Problem:** “`entryRef` stays unlinkable when `salt` is random” needs a scope. Once non-empty `PayMeta` is submitted, the salt is public in transaction calldata and the reference is explicitly indexed in `PaymentMeta`; randomness does not hide that association. Reusing one reference for partial payments deliberately links those payments. Conversely, “anyone who holds the document … can find the payment by its number … whatever the schema” is not generally true for schema 4 or an off-chain commitment with an undisclosed random salt and no clear `payNo`. Public addresses alone do not make a hidden document number searchable.

**Concrete fix:** State three separate properties: an unpublished random-salted preimage resists document-number guessing; a clear `payNo` or clear body is publicly searchable; repeated `entryRef` values are linkable regardless of salt. Qualify the document-holder statement by whether the holder also knows the preimage, addresses or other identifying information. Keep the owner's warning-only policy, but make the warning accurate.

**Evidence:** Draft §3.1 formula, §3.2 event, §3.3 final two bullets, §2.2 partial-payment reuse; `MetaTokenBase.sol:218`–`219` shows the current salt/preimage commitment pattern. The new ABI also explicitly carries the salt. CTR-MTX-26's older privacy wording contains the same overly broad unlinkability claim.

### 7. Low — The signature commits to metadata content, not its on-chain publication

**Spec:** §2.1, §3.2, §7.1, §11 Q6, §13 J1.

**Problem:** A submitter can replace non-empty `PayMeta` with the all-empty value without changing the signed `UAMetaTransfer` or `UAPayWithTax`; the empty branch accepts the same `entryRef`. For ordinary pay it can also submit the signed transfer through the generic path. The payment then consumes the nonce without emitting `PaymentMeta`. This does not alter signed money or allow forged metadata, but an ERP cannot rely on signing a metadata-bearing request to guarantee the on-chain business reference will be published. The first-partial-payment convention is particularly exposed: the “first” log may never arrive.

**Concrete fix:** Within the owner's unchanged transfer typehash and optional-metadata design, document publication as best effort and require reconciliation to retain the off-chain preimage. Make the node preserve the submitted metadata and avoid converting such a job into a plain transfer batch; define how a same-digest empty/non-empty job is deduplicated. Add a planned stripping case that verifies the limitation instead of claiming publication is signed. A mandatory-publication guarantee would require a separately signed requirement and is a different design decision.

**Evidence:** Draft §3.2 empty branch accepts any client reference; §2.1 deliberately retains the generic path. `smartcontracts/evm/src/metatx/MtxPipelineLib.sol:200`–`206` hashes only the transfer fields; `ERC20MetaTx.sol:222`–`237` accepts that signature through individual/batch transfer paths. This limitation also exists between today's `mtxPayMeta` and generic transfer; the redesign broadens its prominence, not its cryptographic cause.

### 8. Info — The changed commitment format has no version-specific domain

**Spec:** §3.1, §7.3, §8, §14's “old formula refused” case.

**Problem:** Both formats use `keccak256("scaas.pay.meta" || salt || keccak256(payload))`. The old contract accepts an arbitrary raw `meta` payload without parsing it. Set that old raw payload to `abi.encode(newPayNo, newSchema, newBody)` and both helpers return exactly the same reference. This is a constructed equality of inputs, not a Keccak collision. Canonically encoded old schema bodies will normally differ, but the two format namespaces are not disjoint. Keeping old and new formulas across families makes provenance/version confusion more likely in off-chain lookup tools. An all-empty metadata call can also accept any old reference, so “old formula refused” cannot be an unconditional assertion.

**Concrete fix:** Give the new commitment a new derivation tag, such as `scaas.pay.meta.v2`, before generating vectors, or explicitly require format/family context in off-chain references and limit the negative test to a non-empty canonical new preimage checked against its old-form hash. Do not describe the existing tag as format-version separation. No token or chain field needs to be added solely for signature replay protection: the signed payment domain already provides those boundaries.

**Evidence:** `smartcontracts/evm/src/metatx/MetaTokenBase.sol:218`–`219`, `:224`–`243` (raw bytes hashed and emitted, never decoded); draft §3.1 new formula, §3.2 empty branch, §8 coexistence. CTR-MTX-26 likewise explicitly says the contract never parses the old metadata.

## Assessment of §10's rule changes

| Changed rule / conflict | Security judgment |
|---|---|
| CTR-MTX-03: free payment lanes and partial payments | Safe on persistent EVM nonces. Duplicate **separately signed** payments are now authorized behavior, not signature replay. The client convention is useful but not a protocol guarantee. |
| CTR-MTX-04: pay-once horizon | Invoice pay-once can be dropped; nonce pruning safeguards cannot be dropped with it. Finding 3. |
| CTR-MTX-10: reference-based reconciliation | Summing legitimate partials is consistent. Retain the full `(token, payer, payee, entryRef)` key, per-event identity and finalized-log deduplication; `payNo` alone is never an authorization or settlement key. Gross and net must remain separate for taxed rows. |
| CTR-MTX-06: receiver-fee free lanes | Safe: the payee signs the full nested payment, including batch/nonce, and the payer's nonce is consumed once. Unchanged restricted-relayer binding prevents an open submitter from moving a co-signature to another relayer. |
| CTR-MTX-26: optional metadata / new formula | ABI encoding avoids new-field boundary ambiguity. Publication and cross-version claims need the qualifications in Findings 7–8. |
| CTR-MTX-09 / -30: struct entry, metadata last, retired twin | No inherent authorization loss. ERC-165 ids/selectors/callers must move together; this is a release change on immutable test-only contracts, not an upgrade of an existing instance. |
| CTR-MTX-27: relay-fee free lanes and typehash | Safe against replay of one signature if both batch and nonce are hashed and checked. Two fresh signed fees may pay a repeatable target twice by O4. Executor separation and atomic rollback must remain. Finding 2 concerns the regulated final beneficiary, independently. |
| CTR-MTX-11: second payer-signed tax type | Appropriate security separation: an ordinary transfer signature cannot authorize the tax leg, and a tax signature cannot validate as a plain transfer. The nested canonical hash is essential. Finding 1 covers the node's different digest semantics. |
| Privacy prohibition becomes recommendation | An accepted owner policy change, not a cryptographic mitigation. Clear identifiers permanently expose business linkage; Findings 6–7 delimit what signing and salting guarantee. |
| CTR-MTX-29: opaque body exception | Security-safe for the token as a commitment preimage it never executes. It remains a deliberate API-rule exception requiring an explicit decision. Node encoders must reject unnamed hex bundles for structured schemas; arbitrary crypto ciphertext remains one object. |
| Cross-family vectors change in separate rounds | Acceptable only with explicit family/format selection and separate legacy vectors. A green legacy-family test does not establish conformance to the new commitment. Finding 8 addresses the unversioned derivation. |
| Transparent kinds vs Zether/PQZ | Restricting this group to kinds 8/9 is conservative and sound. Zether 10/11 and PQZ 12/13 must remain named separately; adding a public-only taxed entry to a confidential kind would require a later scoped rule. |
| Unsigned configured recipient plus rate-only notice | Accepts issuer-directed redirection of pending signed tax legs, as O7 expressly rules. Alerts cannot prevent it. The exact signed tax bounds the deduction, but the wallet's displayed recipient is a signing-time snapshot, not a payer-enforced destination. This is an explicit governance trust exposure, not a missing signature check accidentally overlooked by the draft. |

## What was checked and found sound

- **Signature boundaries:** `UAPayWithTax` has a distinct outer type with the full nested transfer, mode and exact tax. The type string includes its `UAMetaTransfer` dependency; it must hash the nested **struct hash**, not an EIP-712 digest. Canonical zeroing of unbound relayer/fee-recipient fields matches `MtxPipelineLib.sol:200`–`206`; the planned non-zero-unbound vectors are necessary and well targeted. New relay-fee batch/nonce fields are signed, not merely router arguments. `SaltedEIP712.sol:58`–`68` binds chain id, clone address and chain UID, preventing signature transplant across token instances/kinds or chains with different domains. The unversioned metadata reference does not defeat that signature domain.
- **Replay on EVM:** all typed paths share `(from, batch)` state and consume the checked nonce (`MtxPipelineLib.sol:164`–`177`, `:295`–`298`). A pay signature can choose among permitted ordinary-payment paths but cannot land twice. Receiver-fee's co-signature nests that same nonce and cannot be reused for another partial payment. Free lanes do not authorize the relayer to choose a different lane after signing.
- **Encoding and salt:** `abi.encode(string,uint16,bytes)` separates the dynamic fields with offsets and lengths; unlike packing multiple variable fields, `payNo="ab", body="c"` cannot alias `payNo="a", body="bc"`. The outer packed fields have fixed boundaries: constant tag, 32-byte salt, 32-byte inner hash. The all-empty sentinel and nonzero-salt shape checks are coherent, including a pay-number-only reference. Nonzero does not prove entropy: the specified CSPRNG generation remains a signer responsibility. Unknown schemas and malformed body encodings cannot alter token execution because the token never interprets them; clients must treat undecodable bodies as opaque data, never verified invoice facts.
- **Money bounds:** `tax <= value` and `Math.mulDiv(value, rate, 1e6)` with rate at most 1e6 prevent negative net and avoid intermediate-multiply overflow. The existing fee remains on gross value and is separately capped at 1% (`FeePolicy.sol:32`–`51`); tax does not accidentally inherit that cap. `MtxPipelineLib.sol:243`–`255` requires gross plus fee before consuming the nonce. Equal account roles require summing their deltas when testing J3: payer may equal payee, recipient may equal payer, and tax recipient may equal fee recipient. Those allowed aliases do not create supply, but J3's four independent balance assertions are valid only for distinct accounts.
- **Tax trust limits:** AMOUNT can divert the entire gross amount to the configured collector because the owner explicitly permits the payer-signed amount without payee consent. This is unsuitable as evidence that the payee agreed to a net amount, but is the chosen policy. PERCENT changes invalidate a pending transaction when they change its exact tax; they do not grant the issuer an unsigned larger deduction. O7 explicitly allows untaxed entries, so a tax class is not mandatory withholding enforcement. No attempt to enforce universal tax should be inferred from these entries.
- **Frozen payee and pools:** Q2's recommended `_poolMove` is safe in this narrow atomic tax entry when bounded by the just-credited gross, with payer freeze/pause checks and payee receiver checks retained on the first leg, and `_regFeeTo` on the tax destination before effects. It must not become a general unhooked debit helper exposed to callers. The frozen receiver-fee refusal remains intentional and distinct. `_poolMove` bypasses pool/receiver validation (`ERC20MetaTx.sol:281`–`300`), so init/setter exclusions of zero, token and both pools, plus SIGNING-UA validation through `_checkTo`, are material prerequisites. The proposed recipient-equals-payee refusal avoids a misleading self-tax receipt. No recipient hook is invoked by the current ledger's qualified `ERC20._update`.
- **Governance and escalation:** bit 23 does not imply FORCE, RECORD or operator-transfer power. Existing `GovernanceUse.use` checks feature and holder and consumes limited-grant usage (`GovernanceBase.sol:14`–`20`). The planned masks must include 23 in the valid, role, contract-only, issuer and regulated-msig sets for 8/9 only, while excluding scalar/scope and delayed-relaxation masks. Adding only `REGULATED_ROLES` would not grant it at init: current `GovernanceLib.sol:119`–`122` uses `ISSUER_BITS`. The spec's explicit init-grant requirement covers this dependency. Existing `_check` enforces contract/msig holders at grants (`GovernanceLib.sol:484`–`499`). A contract-only holder is an accepted governance boundary, not proof its own public methods are restricted.
- **Router and library context:** the existing router signs target and arguments, holds a transient subject/target pair and exposes subject only to that live target (`GovernanceRouterBase.sol:193`–`233`). `_govSubject()` must be evaluated in the token, as the regulated spec §3.1 explicitly requires. Under the library DELEGATECALL, `address(this)` is the token, storage is the token's namespace, and `msg.sender` is the direct caller/router, not the payer or governance subject. Pass token immutables such as factory/registry explicitly as needed; do not read nonexistent library copies. Appending +5…+7 after the regulated spec's +0…+4 is nonoverlapping on paper. `LinkClosure` membership can remain unchanged if the existing linked library grows, but release codehash pins still need the new bytecode's hash.
- **Reentrancy / atomicity:** preserve the token's existing common `nonReentrant` guard around the whole new tax entry, not merely around a setter or the first leg (`MetaTxBase.sol:51`–`55`, `:285`–`297`). Registry/signature checks are view/static paths; the specified compliance query is gas-capped, fixed-output and fail-closed (RK-9). There is no proposed user recipient callback between the gross credit and tax debit. `MtxRelayFee` retains its independent guard, code check, unprivileged executor and target-then-payment order (`MtxRelayFee.sol:26`–`29`, `:66`–`94`); a failed target/payment/forward rolls back the whole transaction. No new bypass was identified in that ordering.
- **Resource abuse and gas:** the 64-byte `payNo` bound and node's configured combined body bound limit relayed hashing/logging only if checked before schema encoding allocates unbounded input. Existing ingress length/depth limits must continue to apply to named schema objects and nested auth; the proposed body limit does not replace them. An uncapped direct body costs its submitter calldata, memory, hashing and event gas; it is not unbounded persistent token storage. Free lanes can reuse nonce slots and save state gas but cannot guarantee a cheaper transaction: fresh lanes and fresh derived recipients still allocate storage. The draft delegates deployment inclusion to the regulated spec's regular-plus-state EIP-8037 method and labels its byte/gas figures estimates. No gas estimate or block-fit claim was validated here.
- **Node allow-lists:** §7.1 correctly requires retired shapes to fail by name and parity per deployed kind. Preserve the distinction between direct selectors reachable by the generic path and independently signed named entries: current `GovernanceRouterBase.sol:175`–`178` intentionally publishes an empty generic allow-list despite having named ops, and CTR-MTX-29/30 do not make named signing entries generic self-call targets. Compare each table against its corresponding surface in both directions, including direct TAX powers, new pay selectors and the router's three signed ops. Check kind 8/9 restriction against the actual target kind, not merely a caller-supplied node category. The proposed old-shape refusals, operator notice, named error decoding and mesh refusal are appropriate; their implementation remains future work.

No executable checks were run, and cryptographic, gas, size and implementation soundness are not established by this report. The owner's accepted immediate recipient redirection, payer-chosen AMOUNT tax, optional tax usage and loss of invoice pay-once remain material product trust boundaries even after the findings are addressed.
