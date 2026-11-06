> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Requested by the owner (2026-11-06); Codex reviewed the first draft of [the attested-verify spec](../superpowers/specs/2026-11-06-attested-verify.md), with Zether still in (removed afterwards by owner ruling R1). Copied verbatim below.

# Security review: attested verification design

Reviewed 2026-11-06 on `ua-mtx-merge`, against the working-tree spec and source, including the existing uncommitted `PqzLayer.sol` change. This is a design review, not verification of an implementation: the books and Solidity curve do not exist yet. **UNAUDITED.** No builds, tests, generators, deployments, or source edits were performed. Only this report was written. The parallel counter-review was not used as evidence.

The owner has explicitly accepted replacing proof soundness with verifier trust (O1–O5). That choice, including a dishonest verifier draining the shielded pool or wrapped escrow, is not itself reported as a vulnerability. The findings concern promises the proposed design does not actually enforce, missed integration paths, and concrete availability/security requirements.

## Numbered findings

### 1. High — The signed attestation has no epoch; an old signature can acquire a new epoch

**Spec:** §4.2, §5.1–§5.3, §6.4, I3, §16.

**Problem:** `epoch` is assigned when a signature is submitted to the book, but is absent from both signed type strings. Checking the epoch of an already stored record only invalidates storage, not the authorization that can recreate it. For example, A signs an unused statement/proof in epoch 1; the owner changes A → B → A; anyone resubmits A's old signature before `validUntil`. The book verifies it against current A and writes the current epoch, making the supposedly killed authorization usable again. The spec also does not prohibit `next == current`: a same-UA change followed by resubmission defeats an epoch bump without even changing identities. An unused debit can retain the same counter and state throughout. Disclosure signatures have the same revival issue. The existing negative test only tries the old verifier while a different verifier is current, and misses this case.

**Concrete fix:** Include a typed epoch in both proof-attestation structs, require it to equal `cfg[token].epoch` at submission and in the disclosure view, and copy that signed epoch into the record. Expose it to clients and the verifier service, including the nested job field and vectors. Keep incrementing it on every effective transfer. Specify checked overflow. Add cases for a withheld signature, A → B → A, and a same-UA epoch change if allowed.

**Evidence:** spec `docs/superpowers/specs/2026-11-06-attested-verify.md:167`, `:191`, `:228`, `:248`, `:255`, `:337`; debit counters are part of the rebuilt statements in `smartcontracts/evm/src/pqz/PqzCore.sol:913` and `smartcontracts/evm/src/zether/ZetherLib.sol:715`. A storage epoch is not part of either signed statement today.

### 2. High — Native multisig members can change verification policy without the notice period

**Spec:** §4.1, §6.3–§6.4, §18 risk 6.

**Problem:** The design refuses ERC-1271 verifiers because their policy can change without notice, but expressly checks native multisig members only at init/proposal. An accepted native slot can later acquire contract code; `requireAuthorized` then checks that slot by ERC-1271. If enough such slots reach the threshold, a contract policy can approve arbitrary attestations without the original EOA signatures, token governance, a verifier change, or an epoch bump. An immutable multisig UA does not make this dispatch immutable. This is an acknowledged residual in the spec, but it directly defeats the stated restriction and applies to the recommended multisig configuration. Checking the top-level UA for code does not inspect its members. Registry key attestations and the attested disclosure view also need coverage.

**Concrete fix:** Either refuse native slots in verifier multisigs and use the existing derived `secp256k1` kind, or recheck every native member's current code on every use of the verifier's authority, including key-attestation acceptance/use and disclosure. Permit only the existing own-key ECDSA treatment of empty code/EIP-7702 designators. If the registry remains permissive for arbitrary attesters, enforce this restriction at the token/book boundary too; a key approval obtained through a forbidden policy must not become a usable token key.

**Evidence:** spec `:134`, `:150`, `:327`; `smartcontracts/evm/src/ua/UARegistry.sol:685` routes native members to `_native`, `:703` calls `UAStore.byCode`; `smartcontracts/evm/src/ua/UAStore.sol:190` selects ECDSA or ERC-1271 from code at call time. CTR-UA-13 forbids rotatable UA policy; this design intends a stricter verifier policy than the general registry.

### 3. Medium — Last-write-wins permits expiry rollback and debit griefing

**Spec:** §5.3, especially the claim that a front-runner can only store the same record earlier.

**Problem:** `validUntil` is not part of the storage key and the latest submission overwrites it. Suppose an honest verifier renews the same statement/proof from a short expiration to a longer one. A third party with the earlier public signature can overwrite the renewed record with the shorter expiration while that signature is still live. The pending debit then fails after the shorter expiration even though the long-lived approval was already stored. Repeated renewals can be raced this way. No verifier compromise or subject signature forgery is required. This does not authorize a different debit, but costs failed transactions and defeats the claimed harmless front-running property.

**Concrete fix:** For the same current epoch and statement/proof key, keep the maximum valid expiration; submitting an older/equal expiration must not shorten the record. Replace expired/old-epoch entries normally. Explicitly test renewed approval → replay shorter approval → debit after the shorter expiration. Make clear that shortening/revoking approvals uses the governed epoch change, not overwrite order.

**Evidence:** spec `:249`, `:255`, `:260`; both expiry variants sign the same storage key because the key contains only `statementHash` and `proofHash`.

### 4. Medium — Zether's external views still use the immutable proof verifier

**Spec:** §7.2–§7.3, T48, the claim that only `_check` needs to branch.

**Problem:** Assigning `s.verifier = ZetherSolCurve` changes the context used inside `ZetherLib`, but `ZetherLayer.verifier()` returns `TRANSFER_VERIFIER`, an implementation immutable. `ZetherDisclosure` and `ZetherStatements` obtain the curve through that external getter. On a no-precompile release whose proof-verifier dependency is zero, both external services fail. On a release with the usual proof verifier, disclosure still invokes its EIP-2537 arithmetic, contradicting the pure-Solidity ATTESTED path. The statement helper can also disagree with the token's actual context. `curve()` has the same immutable dependency. Thus unchanged disclosure code is safe only after the token getter is changed.

**Concrete fix:** Specify that the public arithmetic/verifier getter and `curve()` resolve to the token's selected arithmetic provider, with PRECOMPILE retaining its release verifier. Define the separate meaning of `burnVerifier()` and preserve PRECOMPILE role checks. Include `ZetherStatements` and `ZetherDisclosure` in the integration ripple and require their exact statement bytes/verdicts against an ATTESTED token whose proof-verifier dependencies are zero.

**Evidence:** spec `:372`, `:384`; `smartcontracts/evm/src/zether/ZetherLayer.sol:97`, `:99`; internal context uses storage at `smartcontracts/evm/src/zether/ZetherLib.sol:569`; external helpers use the getter at `smartcontracts/evm/src/zether/ZetherStatements.sol:88` and `smartcontracts/evm/src/zether/ZetherDisclosure.sol:111`.

### 5. Medium — PQZ init conflates the release verifier contract with the attester UA

**Spec:** §6.1 and §3.

**Problem:** §6.1 says `verifier = release.verifier` and then passes `verifier` to `book.initToken` and `pqzKeyFor`. The former is an address of `UAPqzVerifier`, possibly zero; the latter two require the creator's `bytes32 attestVerifier` UA. They are different identities and types. Literal implementation either fails the type boundary, configures zero on the chains this feature targets, or treats a contract address as a native UA and fails the specified kind restriction. The auditor check also needs the attester UA, not the proof-verifier address.

**Concrete fix:** Name the values separately: `releaseProofVerifier` (address, possibly zero) and `attesterUA = c.attestVerifier` (bytes32, nonzero and validated). Pass only `attesterUA` to book configuration and attested-key lookup; retain the release address only for its documented PRECOMPILE/view role. State this explicitly for wrapped and regulated init paths too.

**Evidence:** spec `:295`–`:298`; current `smartcontracts/evm/src/pqz/PqzStateLib.sol:23`, `:42`, `:49` uses an address verifier to obtain precompile metadata; `smartcontracts/evm/src/pqz/PqzCore.sol:64` stores that address. The new creator UA is separately specified in spec §3.

### 6. Medium — The new verification endpoint has no usable, bounded request contract

**Spec:** §11.1, T50.

**Problem:** The optional public service accepts proof-verification work, but the spec does not define its request shape or size/depth/work bounds. The current gateway's body limit is 64 KiB. The spec's own representative PQZ statement is approximately 83 KB and its proof approximately 42 KB; even the proof alone as JSON hex exceeds that HTTP limit. Simply inheriting the limit makes the advertised endpoint unusable; simply removing it exposes the open node to unbounded allocation and expensive verification. Rate limiting alone does not bound one request. The explicit `WireUASig` field also needs to preserve the existing finite signature structure rather than introducing recursive arbitrary JSON conversion.

**Concrete fix:** Define named request fields and per-set/per-operation statement/proof limits before decoding or scheduling verification. If the service receives token operation fields instead of statement bytes, specify rebuilding the canonical statement and the bounded sizes of those fields. Set an explicit route-specific HTTP limit accounting for JSON expansion; bound nesting, member counts and byte fields; bound verifier concurrency/queue and execution resources. Reuse the existing typed `UASig` decoder for both job forms and endpoint inputs. Require oversized/deep inputs to be refused before any signing or sends.

**Evidence:** spec `:404`, `:505`–`:509`; `scaas-node/src/gateway.rs:142` sets 64 KiB and `:143` allows 32 concurrent requests; `scaas-node/src/typed.rs:74`–`:76`, `:460`–`:489` already bound signature structure to two levels and 16 slots per list. `AGENTS.md:100` requires length and depth bounds at every untrusted decoder.

### 7. Medium — Same-lane ordering does not establish that an attestation succeeded

**Spec:** §5.3 flow, §11.1's attest-before-operation guarantee, T50.

**Problem:** Two transactions on one lane establish nonce order, not successful execution of the first transaction. An attest can revert after simulation because its verifier epoch changed, it expired, or the registry refused it; the lane's next transaction can still execute and fail `ProofNotAttested`. Conversely, a crash after submitting the attest must not lose track of a transaction that can still land. The spec defines neither the durable two-transaction job states nor the dependency check. Treating the pair as the node's existing single-send job is insufficient for its claimed guarantee and invites repeated gas loss on a failing first leg.

**Concrete fix:** Specify persisted attest/op hashes and states. Gate the op send on a successful landed attest and a recheck of the current epoch, expiration and exact record, or an equivalent state-aware sequential simulation/submission mechanism. Track both transactions across restart and reorg; retry/refetch only with their pending/landed status known. Price/bound the two sends as one workflow. A reverted attest must produce zero op sends; a reverted op must retain the separately landed record because the token's consume reverted too.

**Evidence:** spec `:273`–`:278`, `:500`, `:505`, `:511`; node guard already treats simulation and lane gas as money-safety boundaries (`scaas-node/src/guard.rs:1`). The spec's consume is inside the op transaction (`:256`), so it cannot make a failed earlier transaction successful or persist its own deletion through an op revert.

### 8. Medium — The optional in-node signer changes the node's key-custody guarantee

**Spec:** §10 row 9, §11.1 C9.

**Problem:** A keystore in a separate module of the same node still places the verifier's signing authority in the node. That UA is the subject authorizing book/key-attestation writes and can enable a pool/escrow drain. Keeping it distinct from a lane key satisfies the lane-role restriction, but does not satisfy the independent promise that the node never holds subject keys. §10 calls both guarantees unchanged. An operator enabling a public HTTP service therefore crosses a materially different security boundary that the conflict table currently denies.

**Concrete fix:** Keep the ordinary open relayer as a caller of an external verifier/signer service with its own process, resource limits and custody boundary; describe that service as a separately operated trust role. If an embedded signer is intentionally retained, record an explicit owner-approved exception and change the node custody/security documentation and operator disclosure; do not describe module/keystore separation alone as preserving the guarantee. Continue enforcing that no lane key is an attester.

**Evidence:** spec `:488`, `:509`; `AGENTS.md:60`–`:61` contains both restrictions. AV-1 itself identifies false verifier signatures as sufficient to drain the pool/escrow.

### 9. Low — The zero-verifier release change targets a factory check that no longer exists

**Spec:** §3, §7.2, §9, §10 row 12, T45/T48.

**Problem:** The design says OpenFactory's canonical-verifier check will admit zero. Current OpenFactory has no such check: 5g-Z2 moved dependency validation into release constructors. PQZ's constructor rejects a zero/non-contract dependency, and Zether's constructor requires a complete, distinct transfer/burn/IP set. Updating OpenFactory as described does not open the ATTESTED release path. More dangerously, using the always-supported Solidity curve as a replacement proof-verifier dependency must not allow a default PRECOMPILE token to pass init and accept shields while every proof entry later reverts.

**Concrete fix:** Define the new `Env.deps` positions/shape and constructor validation for both families. Separate optional proof-verifier dependencies from mandatory pinned books/curve/disclosure dependencies. Put the named nonzero-proof-verifier check in each token's PRECOMPILE init branch before any metadata call; never infer ATTESTED from a missing dependency or use the curve's support result as proof-verifier support. Retain PQZ's exact precompile/set self-test and Zether's transfer/burn/IP consistency checks whenever those dependencies are supplied. Require the creation matrix for all eight kinds, both modes, missing/partial/swapped dependencies and absent precompiles.

**Evidence:** `smartcontracts/evm/src/factory/OpenFactory.sol:264`, `:308`, `:342`; `smartcontracts/evm/src/pqz/PqzLayer.sol:69`; `smartcontracts/evm/src/zether/ZetherLayer.sol:66`; `smartcontracts/evm/src/pqz/PqzStateLib.sol:42`; `smartcontracts/evm/src/zether/ZetherLib.sol:208`; CTR-ZTH-20 explicitly documents the removal of the old canonical factory list at `docs/contracts/zether.md:1367`. The intended explicit zero checks in the spec are safe; their actual placement and dependency encoding need correction.

### 10. Low — Parent-block statement views do not establish the promised audit reconstruction

**Spec:** AV-1 auditability, §5.4, §18 risk 8.

**Problem:** A transaction's pre-state is not necessarily its parent block's final state. An earlier transaction in the same block can debit the same account, roll over Zether, or transfer the verifier. A later debit's counter/accumulator/epoch will differ from a parent-block `eth_call`. Historical calls also need the inclusion block's number/timestamp for expiry checks and the actual direct/relayed binding. An archive node plus a parent-state statement view alone is therefore not the claimed audit recipe.

**Concrete fix:** Require replay/trace to the exact transaction position, with the transaction's execution context and envelope binding; rebuild and compare `statementHash` before re-verifying the calldata proof. Index the epoch/verifier and transaction position alongside the events. Alternatively retain the exact canonical statement with sufficient provenance outside consensus. Demonstrate two sequential same-account debits and a rollover/rotation earlier in the same block in the planned audit-reconstruction checks.

**Evidence:** spec `:89`–`:91`, `:283`, §18 risk 8; `smartcontracts/evm/src/pqz/PqzCore.sol:740`, `:748`, `:870`; `smartcontracts/evm/src/zether/ZetherLib.sol:715`, `:775`, `:848`.

### 11. Low — The advertised response to a dishonest verifier excludes fixed/renounced configurations

**Spec:** AV-1, §4.2, §18 risks 1–2.

**Problem:** AV-1 says the answer on every kind is a verifier transfer and that on plain kinds the only on-chain answer is transfer. Fixed verifiers cannot be transferred, and renouncing ownership also eliminates this response. Thus a plain fixed/owner-renounced token has no on-chain containment mechanism for a dishonest verifier, not merely a liveness risk if its key is lost. A regulated kind also supplies PAUSE/FREEZE only when those features and live roles exist. PQZ shields additionally depend on usable keys, so a verifier's refusal to attest new holders' keys can block their shields even though the text says shields are unaffected.

**Concrete fix:** State the full combinations in creation/shield disclosure: fixed or owner-renounced plain token = no governance containment; transferable with live owner = delayed replacement, with the old verifier retaining authority during the notice; regulated token = emergency controls only if actually configured and actionable. Qualify the shield-liveness statement by current key usability and the need for key attestations for new holders.

**Evidence:** spec `:92`–`:99`, `:158`, `:179`, `:305`; `smartcontracts/evm/src/pqz/PqzStateLib.sol:63`; `smartcontracts/evm/src/regulated/RegulatedLib.sol:64`, `:71` requires enabled controls and live roots. The fixed-verifier choice is O2 and is not reopened here.

## Judgment on every §10 conflict

| Row | Judgment |
|---|---|
| 1 | Safe as an explicit O1 change to CTR-PQZ-01: skipping proof self-test only in immutable ATTESTED mode is the accepted trust trade. Preserve the PRECOMPILE self-test and the production licence/audit gates; ATTESTED does not discharge those gates. |
| 2 | Safe as the explicit O1/O2 policy reversal. Classical or single-party verifier UAs must be disclosed as such; no implicit claim of PQ security or quorum remains. |
| 3 | Safe only behind the stated curve and account gates. Attesting verdicts alone does not replace registry PoP/owner Schnorr. Q1(a) is fail-closed and can leave the target no-EIP-2537 chains unsupported; it must remain visible as a feature limitation. Finding 4 covers the missed external arithmetic path. |
| 4 | The drain risk is consciously accepted by O2, so safe as a disclosed trust change. Canonical book/curve code does not restore proof soundness. Preserve the release-code trust root and fix findings 1–2. |
| 5 | Safe in principle under O3: attested usability must remain separate from `proven`, uniqueness and list membership. Keep current-key/proof-hash matching and token-side set-length checks. No registry-level revocation is introduced: changing the token's current verifier stops consulting the old attester, not deleting its fact. Returning to that attester would reuse its persistent key approvals; disclose this separately from debit-epoch invalidation. |
| 6 | The direct disclosure view records nothing, but the general permissionless `attestPqzProof` accepts arbitrary signed statement hashes and has no debit-only discriminator. A disclosure signature can therefore also be stored/emitted through it, contrary to the row's assertion that stored attestations are only debits. This cannot make a disclosure statement consume as a debit because their op tags differ. Clarify CTR-PQZ-14/CTR-ZTH-39 to permit generic proof-book records without treating them as token amount-disclosure records, or type/restrict book submission by operation. The consume-once book is not an on-chain disclosure verdict API. |
| 7 | Necessary explicit threat-model change, with finding 11's qualifications. PQZ's independent subject signature survives; Zether's knowledge-of-x authority does not survive a dishonest attester. |
| 8 | Safe: attest is a separate authorized operation; no confidential ABI twin or packed proof/signature bundle is required. Governance writes must still pass their router's typed envelope and target binding. |
| 9 | Not safe as an “unchanged” claim: separate keystore/module satisfies only lane-key separation. Finding 8. |
| 10 | Safe application of the accepted factory period, including zero. Zero means no advance notice; wallets must display the actual period. Do not substitute creator-controlled `grantDelay`. |
| 11 | Cached ML-DSA verification is the correct requirement, but not a blanket liveness guarantee for arbitrary multisig quorums. Preserve the registry's aggregate budget/signability checks and the actual chain's gas limit; do not accept a verifier merely because its kind id is listed. |
| 12 | Safe intent, incorrect current-code description. Finding 9: construction and init gates belong to the release path, not a removed factory canonical list. |
| 13 | Scheduling change, no intrinsic security conflict. The new curve/account/dependency paths must be included in the freeze/audit, as O5 requires. |
| 14 | Preserves the existing fail-closed Hedera refusal in CTR-ZTH-52 and the layer constructors. It is nevertheless a real family/env exception to O1's literal “same rule on every chain,” even if it is a release flag rather than runtime detection. State it as the retained scope exception requiring reconciliation, not as proof that no exception exists. Do not silently remove the refusal under this group. |

## What I checked and found sound

- **Operation binding:** PQZ's `_header`, transfer/multi/burn builders and `_total` substantiate the correction from “acc hash” to `T`. `p`, counter, expiry, sender/recipient/beneficiary, fee, public amount, output ciphertexts, keys, salt/memo and mode/envelope binding enter the canonical statement. A rollover preserving `T` is intentional, not a replay vulnerability. `_sent` increments the counter on successful refresh as well as other debits. Zether's corresponding header binds counter, `accSeq`, validity and relay context, and its builders include the actual accumulator/output points. Evidence: `PqzCore.sol:204`, `:249`, `:378`, `:559`, `:743`, `:913`; `ZetherLib.sol:629`, `:659`, `:686`, `:711`.
- **Cross-token/chain/kind/system separation:** Recomputing the complete statement and proof hashes at consumption, token-keyed records and `msg.sender`-scoped consume prevent another token/caller stealing a record. Statement chain id plus `chainUid` covers different networks sharing an id; op tags and statement proof-system ids distinguish operations/systems, with separate PQZ/Zether book domains and typehashes. Ignoring the redundant outer `proofSystemId` is not itself a replay bypass if the verifier validates the complete canonical statement against the selected system; it must never dispatch on that metadata while ignoring an inconsistent statement id. Registration portability remains deliberately different. Evidence: CTR-PQZ-01, CTR-UA-07; `PqzCore.sol:913`, `ZetherLib.sol:715`, `UAKinds` message separation and `UARegistry.sol:651`.
- **Consumption and failure atomicity:** A token's book deletion and state settlement are in the same EVM transaction; a later revert, including payout/unwrap/compliance failure, rolls both back. A separately landed attest remains available after such failure. Successful token counters prevent executing the same debit again even if someone resubmits its signature to recreate an orphan record. Deletion still needs an independent storage/event assertion in the planned tests: counter replay refusal alone will not kill a “delete omitted” mutant. No extra permanent “used” map is necessary for debit safety. Evidence: `PqzCore.sol:857`, `:870`; `ZetherLib.sol:311`, `:325`, `:401`, `:826`; spec §5.3.
- **Verifier transfer structure:** Owner-UA authorization, same-proposer/same-next confirmation, fixed immutability, bounded confirmation window, cancellation and a period snapshotted from the factory are appropriate. They must continue checking the current nonzero owner on confirmation, not merely the stored proposer. If the book claims full RK-2 equivalence, specify invalidation across ownership generations too: `GovernanceLib.sol:290` and `:395` already do this for governance pending grants, while the proposed book config lacks that generation. Refusing precompile-dependent verifier kinds and nested verifier multisigs is a sensible conservative list; finding 2 is the mutable-native exception.
- **Attested registry keys:** Binding `ua`, the current key hash and the stored proof hash, requiring proof bytes to remain retrievable, and leaving `proven`/`keyOwner` untouched preserves the PRECOMPILE trust boundary. Preserve `_keyPtr`'s exact set-length check. The verifier service must reconstruct the correct R_REG message: registration uses the portable record including the initial KEM commitment, whereas `setPqzKey` uses `PURPOSE_PQZ_KEY` and `pqzKeyDigest`; the current code distinguishes them at `UARegistryLib.sol:454`–`:468`. No signature from one path should be treated as evidence for the other. Monotonic attestation facts provide no selective revocation; current-verifier selection is the proposed containment mechanism.
- **PQZ disclosure:** `AttestationRequired()` is an honest named failure instead of a false cryptographic verdict. Rebuilding the disclosure from the stored entry and matching amount/leg/kind/proof hashes supports the proposed view. Preserve starvation as `UAVerifyGas` through signature checks. Independent off-chain verification remains possible from public statement/proof bytes and needs no attester trust. Evidence: CTR-PQZ-14; `PqzViewLib.sol:93`, `:100`; `UAStore.sol:220`; spec §6.4. Apply finding 1 to the view signature too.
- **Zether arithmetic and gas:** Separating canonical on-chain arithmetic from attested verdicts is the right design boundary. The specified canonical encoding, on-curve/subgroup validation, infinity cases, rejected malformed inputs and mandatory differential gate are necessary. The reference distinction is precise: G1ADD checks on-curve, while multiply/MSM/isValid perform subgroup checks (`ZetherCurves.sol:153`, `:177`, `:207`, `:214`, `:235`). The new ladder must validate subgroup membership before any scalar reduction/zero shortcut; otherwise `[r]P == O` can become a vacuous check. The planned edge corpus should explicitly include 2^64−1/2^64, 256-bit scalars, mixed subgroup/torsion points, and noncanonical encodings even with zero scalars. No actual new curve code or gas measurements exist to certify. Full debit/shield/owner-signature costs, including worst supported legs and the chain's real limits, remain the spike's required evidence; a support constant is not gas evidence.
- **Node allow-lists:** Both-direction equality, named fields, explicit mesh refusal and nonterminal handling of transactions that may land are correct requirements. Book targets must be the configured pinned family book, bound to the chain, not an arbitrary contract merely answering its views; the new `attest_book` class needs an actual target rule, analogous to `Rule::UaRegistry`, not only selector rows (`guard.rs:41`–`:75`). Existing bounded `UASig` parsing is reusable. These are design requirements, not implemented protections of the proposed jobs today.
- **Trust model:** Public-only verification does not inherently reveal honest clients' secret keys or witnesses. Ciphertext retention and shared settlement paths preserve recoverability; they do not restore integrity after false attestations. The spec correctly discloses pool/escrow drain, verifier censorship, lack of slashing, and that Zether proof authorization is itself attested. PQZ's separate chain-checked subject signature remains an independent guard (`PqzCore.sol:818`); a dishonest attester can fabricate a balance under an attacker-controlled signing UA but cannot create the victim's PQ signature. “Confidentiality unchanged” should be read as secrecy of honestly formed data under the existing cryptographic assumptions, not a guarantee that maliciously attested outputs are valid encryptions, correct auditor copies or recoverable balances.

Read-only review covered the requested spec, the cited current contract rules/decision entries, relevant PQZ/Zether/UA/factory/governance/regulated source, deployment wiring and node decoding/target guards. No execution, gas calibration, differential curve testing or cryptographic soundness audit was performed; the new ATTESTED implementation remains unbuilt and UNAUDITED.
