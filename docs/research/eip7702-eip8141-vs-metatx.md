> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# EIP-7702 and EIP-8141 compared with the SCaaS meta-transaction

Written 2026-10-11 for the owner ("EIP-7702 and EIP-8141 need to be compared with MetaTx"). SCaaS facts cite rule ids
of the component docs; outside facts cite the sources in §6. **[unverified]** marks a claim that rests on secondary
reporting or memory and was not confirmed against a primary source. EIP-8141 is a Draft: everything said about it may
change.

## 1. Summary

**EIP-7702 (Set code for EOAs; Final; live on Ethereum since Pectra, 2025-05-07).** A new transaction type `0x04`
carries an `authorization_list` of tuples `[chain_id, address, nonce, y_parity, r, s]`, each an EOA's secp256k1
signature over `keccak(0x05 ‖ rlp([chain_id, address, nonce]))`. Processing writes the 23-byte delegation designator
`0xef0100 ‖ address` into the EOA's code, so calls to the EOA run the delegate's code in the EOA's own storage. The
**sender of the 0x04 transaction pays all gas** (including 12 500–25 000 gas per tuple); the EOA itself need not be
the sender, which is how a relayer or an ERC-4337 bundler "sponsors" it. `chain_id = 0` makes one authorization valid
on every chain. Delegating to `address(0)` clears it. The EOA's private key **stays root**: it can still send
transactions, re-delegate or clear the delegation. The EIP itself tells wallets never to offer a generic "sign an
authorization" screen (a delegation is total control); in practice phishing followed at once — Wintermute counted over
80 %, later 97 %, of early mainnet delegations pointing to one sweeper contract ("CrimeEnjoyor").

**EIP-8141 (Frame Transaction; Draft, created 2026-01-29; Scheduled for Inclusion in Hegotá at ACDE #244,
2026-08-27/28).** A new type `0x06` whose payload is `[chain_id, nonce, sender, frames, signatures, fees, blob hashes]`;
a frame is `[mode, flags, target, limits, value, data]`, at most 64. Modes: `DEFAULT` (caller = the entry point
`0xaa`), `VERIFY` (read-only validation; ends with the new opcode `APPROVE`), `SENDER` (caller = `tx.sender`, only
after execution approval). `APPROVE` scopes: `APPROVE_EXECUTION` (only the sender's own code), `APPROVE_PAYMENT` (the
approving target becomes the **payer**, the sender nonce increments, `max_cost` is collected),
`APPROVE_EXECUTION_AND_PAYMENT`. So any contract — the account itself or a sponsor/paymaster — can pay gas, and the
account's own code decides what a valid signature is (protocol schemes `SECP256K1`, `P256`, and `ARBITRARY` bytes
checked by account code, the stated off-ramp to post-quantum schemes). An account without code runs "default code"
(a secp256k1 check), so plain EOAs get batching and sponsorship too. Public-mempool rules bound validation:
`MAX_VERIFY_GAS = 100 000`, validation may read and write only the sender's storage, environment opcodes are banned,
a canonical paymaster is recognised by its runtime code, a non-canonical one may back only 1 pending transaction.
Consecutive frames with `ATOMIC_BATCH_FLAG` form an all-or-nothing batch. It runs on Ethereum L1 only after the
Hegotá fork (targeted 2027 **[unverified]**, no date set); Glamsterdam, the fork before it, reached Sepolia on
2026-10-06 and has no confirmed mainnet date. Base and EIP-8141 authors failed to agree on one format; Base backs its
own EIP-8130 **[unverified, secondary reporting]**, so L2 adoption of 8141 is open.

**ERC-4337 (context).** Account abstraction without a fork: users sign `UserOperation`s, bundlers submit them to the
singleton `EntryPoint` contract, paymasters pay gas (and may take an ERC-20 in return). EntryPoint v0.8 accepts
EIP-7702 authorizations so delegated EOAs use the same bundlers and paymasters.

**SCaaS meta-transaction.** The subject signs EIP-712 typed data whose `verifyingContract` is the SCaaS contract
itself; anyone submits it; the contract runs it on itself only — a `MetaTransaction` (a self-call of an allowlisted
selector) or, on tokens, a typed `MetaTransfer` ([CTR-MTX-16](../contracts/metatx.md#CTR-MTX-16),
[CTR-MTX-15](../contracts/metatx.md#CTR-MTX-15)). No forwarder, no ERC-4337 dependency
([NET-ALL-02](../networks/README.md#NET-ALL-02)). The relayer pays native gas and may be paid in **the same token**
with a signer-chosen fee mode ([CTR-MTX-13](../contracts/metatx.md#CTR-MTX-13)). The same model exists natively on
eight families, most of which have neither 7702 nor 8141.

**Bottom line for SCaaS.** Neither EIP replaces the meta-transaction. 7702 is already handled: a delegated EOA is an
EOA whose key signs SCaaS intents ([CTR-UA-24](../contracts/accounts.md#CTR-UA-24),
[CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)); it gives users batching but still needs someone to pay ETH.
8141 is the first protocol path where a user could be gasless on EVM **without a relayer** (a sponsor contract pays),
but only on Ethereum L1, not before 2027, with a single sequential nonce per account and no fee-in-token logic of its
own. Keep meta-tx as the cross-chain baseline; prepare two small seams (a 7702 signature-path decision, an 8141
sponsor role for the node); adopt nothing now.

## 2. Comparison

| Aspect | SCaaS meta-tx | EIP-7702 | EIP-8141 |
|---|---|---|---|
| What is signed | EIP-712 intent per contract: `MetaTransaction`/`MetaTransfer` ([CTR-MTX-14](../contracts/metatx.md#CTR-MTX-14)) | an authorization tuple (delegate address) + whatever the delegate's own scheme signs | the canonical signature hash of the whole frame transaction, or a 32-byte `msg` |
| Who submits / pays gas | any relayer lane (node), payee, or the subject itself ([payers](../contracts/metatx.md#payers)) | the 0x04 sender (the EOA or a relayer/bundler) | the account or any sponsor contract that calls `APPROVE_PAYMENT`; the tx goes to the public mempool |
| Fee in an ERC-20 / the token | yes, in **this** token, `NONE`/`PERCENT`/`FIXED`, 1 % cap, fee after the call ([CTR-MTX-20](../contracts/metatx.md#CTR-MTX-20)); receiver-pays ([CTR-MTX-05](../contracts/metatx.md#CTR-MTX-05)) | not in the protocol; a delegate or ERC-4337 paymaster can take tokens | not in the protocol; spec example: sponsor `VERIFY` + a `SENDER` frame with an ERC-20 `transfer` to the sponsor + a post-op frame |
| Sponsorship model | node policy rows, gas booked to a sponsor ([NODE-SPN-01](../node/sponsorship.md#NODE-SPN-01)) | off-protocol (relayer, bundler, paymaster) | on-chain sponsor/paymaster contracts; canonical paymaster code gets mempool reservation accounting |
| Batching | `mtxBatch` / `mtxBatchTransfer`, atomic, one contract ([CTR-MTX-24](../contracts/metatx.md#CTR-MTX-24)) | delegate code (e.g. ERC-7821-style `execute`) can batch across contracts | `ATOMIC_BATCH_FLAG` across contracts, protocol-level |
| Replay protection | 2D nonce `(from, lane)`; `validUntil`; domain `chainId` + `salt = chain_uid` + `verifyingContract` ([CTR-MTX-02](../contracts/metatx.md#CTR-MTX-02)) | tuple nonce = EOA nonce; `chain_id` or 0 (all chains) | one sequential account nonce; `chain_id`; expiry only through the canonical `EXPIRY_VERIFIER` frame |
| Key types | secp256k1, ERC-1271 (`SmartKeyAccount`: P-256 WebAuthn), UA kinds incl. ML-DSA/FN-DSA ([accounts.md](../contracts/accounts.md#kinds)) | secp256k1 root; anything the delegate verifies | `SECP256K1`, `P256` native; anything via `ARBITRARY` + account code (PQ path) |
| Rotation / recovery | `SmartKeyAccount` keys + guardian, 2-day delay ([CTR-ACC-03](../contracts/accounts.md#CTR-ACC-03)); UAs single-key by design | none for the root key; delegate may add session keys | account code decides; an EOA keeps its secp256k1 key |
| Chains | every SCaaS family ([networks](../networks/README.md#families-and-chains)) | Ethereum, Gnosis, BSC, Polygon PoS, Base, Celo, SCaaS testnet (§4.7); no non-EVM family | none today; Ethereum L1 after Hegotá; L2s undecided |
| Mempool / inclusion | node lanes, own simulation, breakers ([submit-lanes](../node/submit-lanes.md)) | normal mempool; clients keep 1 pending tx per delegated EOA | public mempool with bounded validation (100 k gas, sender-only storage) |
| Trust | relayer can delay or drop, never alter (all fields signed, optional relayer binding) | delegate code has total control; relayer risks unpaid gas | sponsor contract code; no relayer needed |
| Token changes needed | built in (`MetaTxBase`, `ERC20MetaTx`) | none | none (a `SENDER` frame calls the token directly) |
| Allowance | only contracts approve/spend ([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)) | delegated EOA counts as EOA: no approve | EOA sender: no approve; contract sender: may approve |
| Phishing surface | one typed intent per contract, shown field by field | a delegation signature = whole account | account code + sponsor see all frame data before approval |
| Status | specified, v1/v2 built ([metatx.md](../contracts/metatx.md)) | Final, live | Draft, SFI Hegotá, spec "may significantly change" |

## 3. How they meet SCaaS

**7702 today.** A delegated EOA signs a SCaaS intent with its key; `SigCheck.isContract` treats exactly the 23-byte
`0xef0100…` code as "no contract", so the signature is checked as ECDSA low-s and never through ERC-1271
([CTR-MTX-25](../contracts/metatx.md#CTR-MTX-25), `smartcontracts/evm/src/common/SigCheck.sol`). The UA registry path is
broader: ECDSA, **else** ERC-1271 of the delegate under 50 k ([CTR-UA-24](../contracts/accounts.md#CTR-UA-24)). The
node's gateway never reads code at accept: a recovering ECDSA signature passes, a non-recovering one is an ERC-1271
candidate left to simulation ([gateway.md](../node/gateway.md#eip-7702)). A delegated EOA cannot approve or hold an
allowance on a SCaaS token ([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)). Consequence: the common ERC-4337
"ERC-20 paymaster" pattern (approve, then `transferFrom` by the paymaster) **does not work** with SCaaS tokens for EOAs
or 7702 accounts; a paymaster must be paid by a plain `transfer` inside the batch — or, better, by our own fee field.

**8141 later.** A frame transaction whose `sender` is the subject can call any token function directly (`SENDER`
frame, `msg.sender` = subject), so a subject with an 8141 account needs neither `mtxExecute` nor a relayer to act: a
sponsor's `VERIFY` frame pays the ETH. Fee in the token then becomes a `SENDER` frame `transfer(sponsor, fee)` in the
same atomic flow — it works on SCaaS tokens unchanged (no approve), but loses what our fee path adds: the fee cap,
the "fee never to the payee" rule ([CTR-MTX-08](../contracts/metatx.md#CTR-MTX-08)), `PaymentSettled` with the fee,
and the lane/pay-once model ([CTR-MTX-03](../contracts/metatx.md#CTR-MTX-03)). A relayer could also put
`mtxExecute`/`mtxExecuteTransfer` in a frame of its **own** frame transaction — that is just today's relayer with a new
transaction type. On every chain without 8141 (all non-Ethereum chains SCaaS targets, all non-EVM families) the
meta-tx path is the only path.

## 4. Applicability to SCaaS, component by component

| # | Component | EIP-7702 | EIP-8141 |
|---|---|---|---|
| 1 | Token meta-tx path (`mtxExecute`, `MetaTransfer`, fee in token) | **already handled**; not a replacement | **prepare** (L1 only, ≥ 2027); keep the path |
| 2 | `SmartKeyAccount` (passkeys, recovery) | **prepare** (owner decision); not possible as built | **not applicable** now; watch |
| 3 | CTR-TOK-01 and `SigCheck` designator = EOA | **already handled**; one open choice (1271 fallback) | **already handled** |
| 4 | Relayer node (lanes, sponsorship) | **not applicable** | **prepare** (sponsor-signer role) |
| 5 | DEX (`TradeOrder`, ERC-1271 cap) | **already handled** | **not applicable** |
| 6 | Hedera and non-EVM families | **not applicable** | **not applicable** |
| 7 | SCaaS testnet and public EVM chains | **already handled** (live on all) | **not applicable** (live nowhere) |

**(1) Token meta-tx path.** A 7702 EOA can batch its own calls (transfer on token A, `pay` on token B) in one
transaction, but **it pays ETH as the sender**; to be gasless it still needs someone to submit a 0x04 or a call into
its delegate — a relayer or bundler, which is our relayer under another name, without our typed display, lanes,
pay-once or `PaymentSettled` fee fields. Fee in the token still needs our path (7702 has no fee concept). 8141 removes
the relayer only on L1 and only for subjects whose wallet builds frame transactions; its one sequential nonce per
account is exactly the "account sequence as ordering lock" that [NET-ALL-02](../networks/README.md#NET-ALL-02) avoids,
and the mempool keeps few pending transactions per account **[unverified scope]**. So meta-tx stays for business flows
(many concurrent lanes, payments); 8141 would be an extra door.

**(2) `SmartKeyAccount` as a 7702 delegation target.** Attractive: an existing EOA keeps its address and gains
passkeys and guardian recovery. As built it cannot work: `initialize` accepts only `msg.sender == FACTORY`; state
uses ordinary sequential slots (`_initialized` at slot 0, mappings), not ERC-7201 namespaces, so a previous delegate's
storage can collide; and tokens would never ask it, because `SigCheck` verifies a designator account by ECDSA only and
grants the 400 k ERC-1271 cap by the **clone** codehash ([CTR-ACC-05](../contracts/accounts.md#CTR-ACC-05)) — a
designator's `EXTCODEHASH` is the hash of `0xef0100‖impl`. The value is also smaller than it looks: the EOA key stays
root (whoever steals it can re-delegate and sweep), so recovery covers a lost passkey or a lost EOA key, never a
stolen EOA key. Needed changes if the owner wants it: a 7702 init path signed by the EOA key itself (the EIP's
front-running warning), namespaced storage, `SigCheck` "ECDSA, else ERC-1271" for designators (as
[CTR-UA-24](../contracts/accounts.md#CTR-UA-24) already does), a cap rule that recognises `0xef0100 ‖ SMART_KEY_ACCOUNT_IMPL`,
wallet UX that shows the delegate (phishing), and a new subsection in accounts.md §3. With 8141, a `SmartKeyAccount`
could itself be a frame-transaction sender (its `VERIFY` frame checks passkeys) **[unverified: needs 8141 final
text]**; not applicable until the fork.

**(3) CTR-TOK-01 and `SigCheck`.** Still right under 7702: the key is root, so treating the account as an EOA loses no
security, and refusing it `approve` keeps the "no ordinary account is a spender" invariant. Under 8141 still right: an
EOA sender with default code has empty code (EOA); a contract sender is a contract and may approve as today. 8141 drops
EIP-3607 for frame transactions (a contract can be the origin); SCaaS reads no `tx.origin` (checked: none in
`smartcontracts/evm/src`). Open choice: `SigCheck` refuses ERC-1271 for designators (passkey or session-key 7702
wallets cannot sign SCaaS intents) while the UA registry accepts it; align one way, by owner decision.

**(4) Relayer node.** 7702: nothing to do — the node never needs to send 0x04 transactions, since tokens verify the
intent, not the account. 8141: the node's lanes stay for every other chain; on L1 a new optional role would be a
**sponsor signer**: the node funds a (canonical) paymaster deposit and signs sponsorship approvals under the same
policy rows ([NODE-SPN-01](../node/sponsorship.md#NODE-SPN-01)), while the subject broadcasts. Breakers, simulation
and cost metering would move into the paymaster's validation budget (100 k gas, no environment opcodes) **[canonical
paymaster mechanics unverified]**.

**(5) DEX.** `TradeOrder` signatures go through the same check; a 7702 maker signs by ECDSA; the codehash-based
400 k cap ([CTR-DEX-08](../contracts/dex.md#CTR-DEX-08)) correctly never applies to a designator. 8141 changes nothing
in `mtxSettle`; a maker could settle by its own frame transaction, which the direct functions already allow.

**(6) Hedera and non-EVM families.** Both EIPs are EVM-protocol changes. Hedera has its own account keys and the
HIP-632 path ([CTR-TOK-23](../contracts/token-wrappers.md#CTR-TOK-23)); whether Hedera adopts 7702 (a HIP-1340 was
discussed) is **[unverified]** and the designator rule in `SigCheck` is harmless there either way. Cosmos, Soroban,
Sui, Aptos, TON and Solana have their own native sponsorship (feegrant, fee-bump, sponsored transactions, fee payer,
W5), which SCaaS already uses only so a relayer pays ([NET-ALL-02](../networks/README.md#NET-ALL-02)).

**(7) Chains.** 7702 is live on every EVM chain SCaaS profiles: SCaaS testnet (Fusaka + BPO2, Prague features, per
[CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)), Ethereum (Pectra, 2025-05-07), Gnosis (Pectra, 2025-04-30),
BSC (Pascal, 2025-03-20), Polygon PoS (Bhilai, 2025-07-01), Base (Isthmus, 2025-05 **[date unverified]**; live per the
RPC probe in [networks/evm.md](../networks/evm.md)), Celo (Isthmus, 2025-07-09). 8141 is live on none; no production
client implements it; the SCaaS testnet should not enable it from a devnet build.

## 5. Recommendations

| Decision | What | Risk if wrong |
|---|---|---|
| **Keep** | Meta-tx as the cross-chain baseline (lanes, typed intents, fee in token, pay-once, receiver-pays) | none new: it is the only path on 7 of 8 families and on every EVM chain but L1-after-Hegotá |
| **Keep** | CTR-TOK-01 and "designator = EOA"; no ERC-4337 dependency | an outside ERC-20 paymaster that needs `approve` cannot serve SCaaS tokens (accepted: our fee path covers it) |
| **Decide** | `SigCheck` for 7702 accounts: ECDSA only (as built) or ECDSA else ERC-1271 (as CTR-UA-24) | ECDSA only: passkey/session-key 7702 wallets cannot sign; with 1271: a buggy delegate answers for the account (the key is root anyway) |
| **Prepare** | A study, not code: `SmartKeyAccount` as a 7702 target (EOA-signed init, ERC-7201 storage, cap by designator target) | storage collisions on re-delegation; delegation phishing; recovery cannot stop a stolen root key |
| **Prepare** | Watch 8141 through Hegotá devnets; keep `mtx…` direct-call equivalents usable from a `SENDER` frame; sketch the node's sponsor-signer role | spec churn (number and shape may change, L2 split with EIP-8130); per-account nonce reintroduces head-of-line blocking |
| **Do not** | Enable 8141 on the SCaaS testnet early, or route business payments through a single-nonce account path | a private fork of a moving spec; stuck subjects |

Unverified points to re-check before any decision: Hegotá's date; the final `APPROVE` and paymaster rules; whether
8141 keeps one nonce per account; Base's Isthmus date; Hedera's 7702 status; which SCaaS-relevant wallets ship 7702
delegates (MetaMask, Coinbase, Ambire were named in 2025 coverage **[unverified]**).

## 6. Sources

- EIP-7702: https://eips.ethereum.org/EIPS/eip-7702
- EIP-8141: https://eips.ethereum.org/EIPS/eip-8141
- ACDE #244 (8141 SFI for Hegotá; Glamsterdam schedule): https://christinedkim.substack.com/p/acde-244
- Hegotá EL tracker (8141 and FOCIL SFI, devnets): https://github.com/ethereum/execution-specs/issues/3664
- Frame Transaction breakout #2, 2026-08-25: https://ethereum-magicians.org/t/frame-transaction-breakout-2-august-25-2026/29419
- Base / 8141 split, EIP-8130: https://thedefiant.io/news/infrastructure/base-ethereum-account-abstraction-collaboration-broke-down-developer-says
- Glamsterdam on Sepolia: https://ethdaily.io/glamsterdam-activates-on-sepolia-testnet
- 7702 phishing (Wintermute): https://www.theblock.co/news/ecosystems/2025-06-01-wintermute-warns-pectra-upgrade-leaves-ethereum-users-at-risk-of-automated-attacks-356481
- EntryPoint v0.8 and 7702: https://erc4337.substack.com/p/entrypoint-v08-released
- Gnosis Pectra: https://docs.gnosischain.com/about/specs/hard-forks/pectra
- BSC Pascal: https://forum.bnbchain.org/t/faq-about-pascal-hardfork/3093
- Polygon Bhilai: https://polygon.technology/blog-tags/green-manifesto
- Celo Isthmus: https://docs.celo.org/operate/notices/archive/isthmus-upgrade.md
- OP Stack Isthmus (Prague features incl. 7702): https://gov.optimism.io/t/proposal-preview-implement-prague-features-on-the-op-stack/9703
