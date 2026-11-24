> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# What SCaaS can learn from Zama (the Zama Confidential Blockchain Protocol, fhEVM)

Research of 2026-11-24 for the owner. Nothing here is built, specified or ruled; every design below is a proposal, and all
SCaaS cryptographic code named here is **UNAUDITED** ([ARCH-POS-14](../decisions.md#ARCH-POS-14)). Background on FHE itself,
the scheme families and why PQZ uses additive MLWE only is in [pq-fhe.md](pq-fhe.md) (2026-10-18, 2026-11-09); this note does
not repeat it.

Tags: **[F]** a fact with its source (a SCaaS fact cites a repository path or rule id); **[V]** a vendor claim, Zama's or
OpenZeppelin's own statement about its own system, not checked by us; **[I]** our inference; **[E]** an estimate. Web sources
were read on 2026-11-24. The L2BEAT page in the brief now redirects to ETHBEAT (`ethbeat.org`), a third party; its statements
are tagged [F] as that site's findings, not ours.

**Contents**

1. [Comparison](#1-comparison)
2. [What not to copy, and why](#2-what-not-to-copy-and-why)
3. [High-priority items](#3-high-priority-items)
4. [ACL and delegated decryption](#4-acl-and-delegated-decryption)
5. [A public trust model](#5-a-public-trust-model)
6. [Medium and later items](#6-medium-and-later-items)
7. [Research question: compute on encrypted state](#7-research-question-compute-on-encrypted-state)
   - 7a [Sealed bids where losers need not open](#7a-sealed-bids-where-losers-need-not-open)
8. [Proposed TODO items](#8-proposed-todo-items)
9. [Sources and what could not be verified](#9-sources-and-what-could-not-be-verified)

## 1. Comparison

The two systems solve different problems. Zama computes **on** encrypted values held under one network key, so contracts can
compare, add and branch on amounts nobody sees. SCaaS's PQZ and Zether keep each holder's values under **that holder's own
key**. The holder proves its own update, and the chain only verifies. Everything below follows from that split [I].

| Point | Zama Protocol (fhEVM) | SCaaS |
|---|---|---|
| Technique | TFHE (the TFHE-rs library) for computation; ZK proofs of knowledge on encrypted inputs [V, litepaper] | **PQZ**: additive module-LWE with BFV-style encoding, plus one fixed-relation lattice proof (PQZL, LNP22 family) or hash proof (PQZH, Ligero) per operation ([CTR-PQZ-02](../contracts/pq-zero-knowledge.md#CTR-PQZ-02), [overview](../contracts/pq-zero-knowledge.md#overview)). **Zether** (classical, separate): lifted ElGamal on BLS12-381 with Σ-protocols and Bulletproofs ([zether.md](../contracts/zether.md)) |
| Where compute happens | off-chain FHE coprocessors, "initially … 5 FHE Coprocessors" [V, litepaper]; the litepaper also says "3 operators run FHE nodes", which it does not reconcile | the **holder's device** builds the new ciphertexts and the proof; the chain verifies. PQZ verifies in the `PQZ` precompile (`PRECOMPILE` tokens) or accepts a signed verdict of the token's verifier UA (`OFFCHAIN` tokens, [CTR-PQZ-27](../contracts/pq-zero-knowledge.md#CTR-PQZ-27)); Zether verifies in Solidity over the EIP-2537 precompiles ([CTR-ZTH-52](../contracts/zether.md#CTR-ZTH-52)) |
| Where ciphertexts live | the host contract holds `bytes32` handles; "the actual data is stored by coprocessors", with "a public storage layer (e.g., S3) for ciphertext availability"; the Gateway gets only "commitments to ciphertexts" [V, litepaper, coprocessor and gateway docs]. ETHBEAT lists as a risk that "the coprocessors lose ciphertext data, so balances can no longer be decrypted" [F, ETHBEAT] | **in contract state**, always: every PQZ ciphertext (an SSTORE2 op blob per debit, a slot per pending entry, a materialised `acc`) and every Zether point ([CTR-PQZ-07](../contracts/pq-zero-knowledge.md#CTR-PQZ-07), AGENTS.md "never lose ciphertext") |
| Decryption | a threshold MPC KMS: "13 nodes with a 2/3 majority rule", in AWS Nitro Enclaves, "robust … with up to 1/3 malicious nodes"; user decryption re-encrypts to the user, public decryption reveals to everyone [V, litepaper, KMS doc]. The KMS doc gives "e.g., 9 out of 13"; ETHBEAT reads thresholds of 7 (public) and 9 (user) on chain and writes that "any 5 KMS operators together can decrypt every amount" [F, ETHBEAT; the figures are not reconciled there] | **the holder** decrypts its own ciphertexts on its device (PQZ: direct rounding, [CTR-PQZ-16](../contracts/pq-zero-knowledge.md#CTR-PQZ-16); Zether: BSGS). A viewer learns an amount only by a per-transfer disclosure proof (`verifyTransferAmount`, [CTR-PQZ-14](../contracts/pq-zero-knowledge.md#CTR-PQZ-14), [CTR-ZTH-40](../contracts/zether.md#CTR-ZTH-40)) or as the token's auditor ([CTR-ZTH-41](../contracts/zether.md#CTR-ZTH-41), [CTR-PQZ-43](../contracts/pq-zero-knowledge.md#CTR-PQZ-43)). Nothing decrypts a ciphertext chosen by someone else ([ARCH-POS-13](../decisions.md#ARCH-POS-13)) |
| Trust for confidentiality | the KMS threshold (and its enclaves), the coprocessors, Zama's relayer and app [V; F, ETHBEAT]; one key for everyone: "all ciphertexts need to be encrypted under the same public key" [V, litepaper] | the holder's key alone on `PRECOMPILE` tokens and on `offchain-shared` / `offchain-token` with the sealed opening when the wallet follows the holder check; on an `offchain-token` without the opening, that token's verifier can recover that token's key ([CTR-PQZ-37](../contracts/pq-zero-knowledge.md#CTR-PQZ-37), owner-accepted) |
| Trust for integrity (no money printing) | the coprocessor majority, attested through the Gateway (an "Arbitrum rollup", [V, gateway doc]); ETHBEAT reports a "priority coprocessor mode" in which one coprocessor "can ignore the majority threshold" (2026-10-08) [F, ETHBEAT] | the proof, checked by the contract through the precompile; on `OFFCHAIN` tokens the verifier UA's signed verdict, so soundness becomes trust in that UA (threat T27, [§9.5](../contracts/pq-zero-knowledge.md#pqz-verifier-mode)) |
| Upgrades and pauses | "Zama's governance multisigs can upgrade every contract instantly" (multisigs 9/17 and 3/6); any one of 17 pausers can halt every token; "fails the walkaway test" [F, ETHBEAT] | no contract has an upgrade key; versions live in the factory catalogue; admin powers are fixed at creation and public ([CTR-GEN-02](../contracts/README.md#CTR-GEN-02), [CTR-TOK-18](../contracts/token-wrappers.md#CTR-TOK-18), [architecture §7.1](../architecture.md#authority-after-deployment)) |
| Post-quantum: confidentiality | "Zama's FHE technology is already post-quantum" [V, litepaper]; ML-KEM-512 for user decryption since v0.8 [V, changelog]. But ETHBEAT: "whoever breaks elliptic-curve cryptography recovers a user's wallet key from any past transaction", and that key can authorize decryption [F, ETHBEAT] | **PQZ**: MLWE ciphertexts (core-SVP 139 classical / 126 quantum at the default set, [overview](../contracts/pq-zero-knowledge.md#overview)); decryption needs the PQZ secret, which no ECDSA key controls. **Zether is classical** and gives no post-quantum confidentiality |
| Post-quantum: authentication | "signature schemes used by Host Chains are not currently post-quantum" [V, litepaper]; users sign an EIP-712 permit with their wallet [V, SDK docs] | PQZ spends need a PQ signing UA (`mldsa65`, `mldsa44`, `fndsa512` or a PQ-dominant `msig`, [CTR-PQZ-12](../contracts/pq-zero-knowledge.md#CTR-PQZ-12)); the UA registry also has `mldsa87`, `fndsa1024`, `slhdsa128s` ([accounts.md](../contracts/accounts.md)); validity rests on MSIS/MLWE. Still classical: the block signer, relayer lane keys, public ERC-20 legs ([what stays classical](../contracts/pq-zero-knowledge.md#what-stays-classical)) |
| Features | arbitrary FHE programs: comparisons, `select`, `FHE.sum`, `FHE.isIn` (v0.13); ACL per handle; delegated decryption; contracts can hold encrypted balances; ERC-7984 tokens with operators and callbacks; sealed-bid auction (their token sale, about $118M, January 2026) [V, changelog, press release] | confidential transfers (single and multi-recipient with decoys), shield, unshield, rollover, per-transfer disclosure, auditor (with consent-based replacement under bit 32), wrap of 1–8 legs, the DEX, the tender (SPECIFIED), PqChat, PqVault; **no computation on values from several parties** ([pq-fhe.md §9](pq-fhe.md)) |
| Chains | Ethereum mainnet since the end of December 2025 (a third-party report gives 31 December 2025 with the first cUSDT transfer; [pq-fhe.md §7](pq-fhe.md) recorded 2025-12-30); mainnet address pages for Polygon, BSC and HyperEVM; Solana planned for H2 2026, but only the $ZAMA token is on Solana today [V, F, address index] | PQZ on any EVM chain: `PRECOMPILE` where the precompile passes the self-test (the SCaaS testnet today), `OFFCHAIN` elsewhere ([CTR-PQZ-01](../contracts/pq-zero-knowledge.md#CTR-PQZ-01)); Zether where EIP-2537 exists; nothing holds value on any chain yet (all test-only) |
| Audit status | protocol "being audited by Trail of Bits and Zenith", "over 34 audit-weeks" [V, litepaper]; OpenZeppelin publishes audits of the confidential contracts (0.3.0 extensions 2026-03-18; the token and wrapper; the v0.5 diff 2026-06-16) [F, titles only, reports not read] | **UNAUDITED** everywhere; an AI audit round ([ARCH-POS-14](../decisions.md#ARCH-POS-14)) is planned before the freeze ([audit index](../audit/INDEX.md)); PQZ also waits for the licence gate G-LIC ([CTR-PQZ-01](../contracts/pq-zero-knowledge.md#CTR-PQZ-01)) |
| Usage | ETHBEAT: "Value locked: $84.45 M" (latest update shown 2026-11-18). The brief's "about $130M" was not found; the $131M figure in the press is shielded stablecoin volume, not TVL [F, ETHBEAT] | none (test chains only) |

**What Zama does better today** [I]: a working ecosystem (a standard co-written with OpenZeppelin, a wrappers registry with
about 30 official wrappers, SDKs, Hardhat mocks, a public auction); contracts that compose with encrypted values; a published
trust page by a third party (ETHBEAT) that lists who can do what. **What SCaaS does better** [I]: no party holds anyone's key;
ciphertexts never leave state; post-quantum spend authorization on PQZ; immutable contracts with bounded, public admin powers.

## 2. What not to copy, and why

- **A threshold KMS holding one network key.** Zama's model needs it: a contract can only branch on encrypted values if
  someone can decrypt the result. For SCaaS it would break three rules at once [I]:
  - ARCH-POS-13: a KMS that decrypts on the request of whoever the ACL names is the decryption service the rule forbids. PQZ is
    IND-CPA, and 288 crafted queries recover a key at `n2304-kmax4096` ([ARCH-POS-13](../decisions.md#ARCH-POS-13) "Why").
    Zama's answer is to decrypt only handles the protocol computed and attested; SCaaS has no such protocol. Inside a quorum the
    oracle problem stays open ([pqz-threshold-decrypt-prove.md](pqz-threshold-decrypt-prove.md) §12.5, cited by ARCH-POS-13).
  - Holder-held keys: "keys never leave the device" ([architecture §7](../architecture.md#7-trust-model),
    [CTR-ACC-08](../contracts/accounts.md#CTR-ACC-08)). A network key means 5 colluding operators read every amount,
    by ETHBEAT's reading.
  - The two key axes ([architecture §7](../architecture.md#7-trust-model)): with Zama, the ECDSA wallet key authorizes decryption,
    so a broken signing key also opens the balances. SCaaS keeps `auth_custody` and `conf_custody` apart.
- **Ciphertexts off chain, handles on chain.** It is what makes fhEVM affordable: a TFHE `euint64` is tens of KB
  ([pq-fhe.md §10.2](pq-fhe.md)), and gas would be prohibitive [I]. It is also exactly what "never lose ciphertext" forbids. A
  lost S3 object or a lost coprocessor database is a lost balance, and ETHBEAT lists it as a risk. SCaaS pays the state gas
  instead: a PQZ ciphertext is 16,512 B at `n2048-kmax1024`.
- **ECDSA-only authentication.** A confidential system whose spends and decryption permits are signed by secp256k1 keys is
  harvest-now-forge-later: Zama's own litepaper says the host chains' signatures are not post-quantum [V]. PQZ already requires a
  PQ signing UA ([CTR-PQZ-12](../contracts/pq-zero-knowledge.md#CTR-PQZ-12)); keep it so. An ERC-7984 interface keyed by
  `address` would quietly bring this back (§3.1).
- **Upgradeable contracts behind multisigs, a global pauser** [F, ETHBEAT]. SCaaS's immutability and the "your key, your funds"
  table ([contracts README §3](../contracts/README.md#admin-powers-complete-list)) are a selling point; never trade them for
  convenience.

## 3. High-priority items

### 3.1 (H1) An ERC-7984 adapter for the PQZ and Zether kinds

**What it is.** [ERC-7984](https://eips.ethereum.org/EIPS/eip-7984) "Confidential Fungible Token": **Status Draft**, created
2025-07-03, Standards Track ERC, requires EIP-165, ERC-165 id `0x4958f2a4`; authors from OpenZeppelin and Zama among others
[F, eips.ethereum.org]. The EIP itself is pointer-neutral: "All amounts in this standard are represented by confidential
pointers", `bytes32`, so that pointer-based systems "including FHE systems" fit; `data` "contains implementation-specific
information such as cryptographic proofs" [F]. `euint64`, `externalEuint64` with `inputProof`, and the receiver name
`IERC7984Receiver` are **OpenZeppelin's implementation**, not the EIP [F, OpenZeppelin API docs]. The EIP never mentions
ERC-20; "not ERC-20 compliant" is OpenZeppelin's wording on its token guide [F].

The EIP interface, in full [F]:

```solidity
function name() external view returns (string memory);
function symbol() external view returns (string memory);
function decimals() external view returns (uint8);
function contractURI() external view returns (string memory);
function confidentialTotalSupply() external view returns (bytes32);
function confidentialBalanceOf(address account) external view returns (bytes32);
function isOperator(address holder, address spender) external view returns (bool);
function setOperator(address operator, uint48 until) external;
function confidentialTransfer(address to, bytes32 amount) external returns (bytes32);
function confidentialTransfer(address to, bytes32 amount, bytes calldata data) external returns (bytes32);
function confidentialTransferFrom(address from, address to, bytes32 amount) external returns (bytes32);
function confidentialTransferFrom(address from, address to, bytes32 amount, bytes calldata data) external returns (bytes32);
function confidentialTransferAndCall(address to, bytes32 amount, bytes calldata callData) external returns (bytes32);
function confidentialTransferAndCall(address to, bytes32 amount, bytes calldata data, bytes calldata callData)
    external returns (bytes32);
function confidentialTransferFromAndCall(address from, address to, bytes32 amount, bytes calldata callData)
    external returns (bytes32);
function confidentialTransferFromAndCall(address from, address to, bytes32 amount, bytes calldata data, bytes calldata callData)
    external returns (bytes32);
event ConfidentialTransfer(address indexed from, address indexed to, bytes32 indexed amount);
event OperatorSet(address indexed holder, address indexed operator, uint48 until);
event AmountDisclosed(bytes32 indexed handle, uint256 amount);
// receiver, unnamed in the EIP; on failure it "SHOULD revert or return a pointer to the false boolean"
function onConfidentialTransferReceived(address operator, address from, bytes32 amount, bytes calldata data)
    external returns (bytes32 success);
```

**What SCaaS has today.** One `mtx*` interface for both confidential layers, `IConfidentialToken`
(`smartcontracts/evm/src/confidential/IConfidentialToken.sol`, [CTR-ZTH-45](../contracts/zether.md#CTR-ZTH-45)), with the
layer-only parts in `IPqzToken` (`smartcontracts/evm/src/pqz/IPqzToken.sol`) and `IZetherToken`; the public side of every
token is ERC-20 on `ERC20MetaTx` ([CTR-TOK-21](../contracts/token-wrappers.md#CTR-TOK-21)). Accounts are UA ids (`bytes32`):
a PQZ account is a PQ signing UA carrying the PQZ key ([CTR-PQZ-13](../contracts/pq-zero-knowledge.md#CTR-PQZ-13)), a Zether
account a UA of a Zether kind, neither an `address`.

**Function by function** [I unless cited]:

| ERC-7984 | PQZ | Zether | Verdict |
|---|---|---|---|
| `name`, `symbol`, `decimals` | ERC-20 metadata of the token | same | faithful |
| `contractURI` | none in `src/` | none | could be added in a new release; cheap |
| `confidentialTotalSupply()` | no encrypted total: the shielded total is public (`SHIELD_POOL`'s balance, [CTR-PQZ-15](../contracts/pq-zero-knowledge.md#CTR-PQZ-15)) | same ([CTR-ZTH-51](../contracts/zether.md#CTR-ZTH-51)) | a pointer to a public value would mislead; no faithful mapping |
| `confidentialBalanceOf(address)` | a balance is `acc` plus an ordered pending queue per `(UA, keyVersion)` (`pqzAcc`, `pqzPending*`), several 16 KB ciphertexts, not one value; and the key is a UA id, not an `address`: no PQZ account can be named by an `address` at all | one point pair per UA id | **no faithful mapping**; a `bytes32` account form would be a different interface |
| `confidentialTransfer(to, amount[, data])` | the sender is `msg.sender`; a PQZ transfer needs `fromUA`, the PQ signature `authSig`, the proof, `u`, `v_t`, `v_f`, `v_a`, the openings, the fee word (`PqzTransferArgs`, [CTR-PQZ-40](../contracts/pq-zero-knowledge.md#CTR-PQZ-40)); `data` would have to pack them | same shape with its own fields | packing them into `data` breaks **explicit parameters** (AGENTS.md); `msg.sender` as the sender drops the PQ signer and the relayability of every `mtx*` |
| `setOperator`, `isOperator`, `confidentialTransferFrom*` | an operator cannot spend: every debit needs a proof made with the holder's PQZ secret over its current balance, and the holder's `PqzAuth` ([CTR-PQZ-12](../contracts/pq-zero-knowledge.md#CTR-PQZ-12)). Someone who only relays a holder-signed, holder-proven intent is already the relayer | same (the proof needs `x`) | not implementable as specified; `isOperator` could only answer `false` |
| `confidentialTransferAndCall*`, `onConfidentialTransferReceived` | a receiving contract learns a pointer it cannot use: no contract can decrypt or compute on a PQZ amount, and a contract holds no PQZ key, so it cannot own a confidential balance or refund "by an encrypted `false`" | same | a notification at most; the EIP's refund semantics do not exist without FHE |
| `ConfidentialTransfer(address,address,bytes32)` | ours is `ConfidentialTransfer(bytes32 entryRef, bytes32 fromUA, bytes32 toUA, …)`; an `address` form cannot name a UA | same event | a second, lossy event of the same name |
| `AmountDisclosed(bytes32,uint256)` | disclosure is a **view** with no on-chain trace by owner ruling: no `attestTransferAmount`, no `AmountAttested` ([CTR-PQZ-14](../contracts/pq-zero-knowledge.md#CTR-PQZ-14), [CTR-ZTH-39](../contracts/zether.md#CTR-ZTH-39)) | same | emitting it would bring back the on-chain attestation the owner removed |

**The options.**

1. **A faithful ERC-7984 PQZ token**: not possible. The `address` accounts, `msg.sender` spends, operators and callbacks assume
   that some party other than the holder can compute on and decrypt amounts, which is the fhEVM model [I].
2. **A partial or view-only facade in a future release** (metadata, `contractURI`, ERC-165 id, the events): it would claim an
   interface id while every core function reverts or answers `false`. A wallet that trusts `supportsInterface(0x4958f2a4)` would
   then try `confidentialTransfer` and fail. Partial support of a Draft is worse than none [I].
3. **A separate wrapper** that holds PQZ and exposes ERC-7984: the wrapper would itself have to hold a PQZ balance, so it would
   need a PQZ secret in a contract, which is impossible; or it would hold the secret off chain, which is a custodian, the KMS
   problem again [I].
4. **Nothing on chain; track the standard** (recommended). The cost of waiting is a missing logo in ERC-7984 wallet lists. The
   cost of a wrong standard is permanent, since releases are immutable and versions live in the catalogue
   ([CTR-TOK-18](../contracts/token-wrappers.md#CTR-TOK-18)). A Draft can still change its interface id; "Draft" means exactly
   that.

**Cost, risk, what it touches.** Option 4 costs nothing on chain. If a later Final ERC-7984 (or a successor) gains `bytes32`
accounts and proof-carrying, named entry points, a new **class** in the generic catalogue
([CTR-TOK-28](../contracts/token-wrappers.md#CTR-TOK-28)) can implement it next to the existing kinds, with no change to
deployed tokens. Touches nothing today; later contracts, SDK, clients and the node's allow-lists (`typed.rs`, `guard.rs`).

**Recommendation.** No ERC-7984 code in any release while it is Draft. Two cheap steps instead:
(a) a short mapping page, this table reworked, so integrators see why PQZ is not ERC-7984 and which SCaaS call does each job;
(b) an SDK-level "confidential token" view type in `scaas-sdk` whose field names follow ERC-7984 where the meaning is the same
(`name`, `symbol`, `decimals`, the balance read through the holder's own decryption), with no contract change. Whether SCaaS
comments publicly on the EIP (asking for non-`address` account ids and for named proof fields) is an owner question (§8, Q1).

### 3.2 (H2) Official wrappers for major assets

**What Zama has.** A "Wrappers Registry" contract and about 30 confidential wrappers on Ethereum mainnet: cUSDC, cUSDT,
cWETH, cWBTC, cXAUt and more, at published addresses; "official ERC-7984 wrappers are live on both mainnet and testnet" [V,
mainnet address page, blog 2026-05-07]. A court order made Circle freeze the USDC behind cUSDC (about $12.5M) from
2026-05-29; the freeze was later lifted [V, Zama blog]. ETHBEAT notes that observers on Zama's wrappers have "wildcard,
non-expiring decryption access to all of a wrapper's balances", and that wrap and unwrap amounts are public [F, ETHBEAT].

**What SCaaS has.** `WRAPPED_PQZ` (`WrappedPqzToken`, 1–8 legs at per-leg rates, wrap-shield and unshield-unwrap,
[CTR-TOK-21](../contracts/token-wrappers.md#CTR-TOK-21), [CTR-TOK-26](../contracts/token-wrappers.md#CTR-TOK-26)), and
`WRAPPED_ZETHER`. The factory is open, and **there is deliberately no "official" wrapper on chain**:
`getWrapper(creator, underlying)` answers "which is A's"; "which is *the* xDAI wrapper" would lie
([CTR-TOK-16](../contracts/token-wrappers.md#CTR-TOK-16), [CTR-TOK-17](../contracts/token-wrappers.md#CTR-TOK-17)).

**What "official" must mean here** [I]: wrappers **created by a named SCaaS creator UA** through the ordinary factory, listed
in the repository's deployment books (`deployments/<key>.json`, [NET-EVM-13](../networks/evm.md#NET-EVM-13)) and on a public
page. Nothing in the contracts changes, and `getWrapper(scaasCreatorUA, USDC)` gives the on-chain check. Zama's registry
contract has no SCaaS counterpart, and needs none: the factory index already is one ([CTR-TOK-27](../contracts/token-wrappers.md#CTR-TOK-27)).

**What is needed, after mainnet 22776** [I]:

- The production gates first: G-LIC and the audit for PQZ ([CTR-PQZ-01](../contracts/pq-zero-knowledge.md#CTR-PQZ-01)), the
  audit for Zether, and the registrar multisig ([CTR-TOK-18](../contracts/token-wrappers.md#CTR-TOK-18)).
- Where the assets are. On 22776 a major asset exists only if it is bridged, which adds the bridge's trust, a row of §5. On a
  public chain PQZ runs `OFFCHAIN` (no precompile), so each wrapper names a verifier UA (threat T27) and an operator for it.
- A fixed configuration per wrapper, published with it: admin `0` (no admin) or a named multisig; no `MINTABLE` (no hybrid);
  rate 1:1 per leg with `RATE_ADJUSTABLE` off; `WRAP_DISABLEABLE` and `SUPPLY_CAP_ADJUSTABLE` choices stated; the auditor mode
  (NONE unless a regulated use asks); the PQZ key class and set; the verifier and its fee cap
  ([CTR-PQZ-36](../contracts/pq-zero-knowledge.md#CTR-PQZ-36)).
- Disclosure of what the underlying's issuer can do: a USDC or USDT reserve can be frozen by its issuer, as cUSDC showed.
  SCaaS cannot prevent that and must say so next to the address.
- Block-explorer verification of each wrapper and its children (the repository's deploy practice), and the size check: a
  `WrappedPqzToken` is the one kind pinned above 64 KiB (AGENTS.md, size gate), so it deploys only where the chain's code-size
  limit takes it ([2026-11-22-evm-size-64k.md](2026-11-22-evm-size-64k.md)).

**Touches:** deployment scripts and books, docs, the SDK's token list; no contract code. **Recommendation:** plan it as a
post-mainnet operations item, gated on the production gates; write the per-wrapper configuration sheet before then.

### 3.3 (H3) Developer tooling

**What Zama has** [V, Zama docs]: a Hardhat plugin whose in-memory and node modes "use mock encryption" (Sepolia uses real
encryption); `forge-fhevm` for Foundry, which deploys the **real** host contracts and mocks only the input signer and KMS
signer keys, so it is not a mock-prover mode; `@zama-fhe/sdk` and a React SDK (beta; the relayer SDK is unsupported from
2026-11-06); OpenZeppelin's confidential contracts library with extensions (ERC20Wrapper, Freezable, ObserverAccess,
Restricted, Omnibus, Rwa, Votes, Hooked with BalanceCap / HolderCap) [F, OpenZeppelin API docs].

**What SCaaS has today** [F]:

- Interfaces in `src/`: `IConfidentialToken`, `IConfidentialWrappedToken`, `IPqzToken`, `IZetherToken`; they are the ABI, not a
  package for third parties.
- One composition point that already works for any contract: the disclosure **view** `verifyTransferAmount`, which "any
  contract, third-party ones included, can call" ([CTR-ZTH-39](../contracts/zether.md#CTR-ZTH-39),
  [CTR-PQZ-14](../contracts/pq-zero-knowledge.md#CTR-PQZ-14)); public-balance composition through `mtxExecuteTransfer` (the
  tender's path, [contracts README](../contracts/README.md)).
- Internal test helpers: `smartcontracts/evm/test/pqz/helpers/PqzMock.sol` mocks the `PQZ` precompile with `vm.mockCall`
  (the self-test answer, and a chosen word per op); `PqzFixture.sol`, `PqzOffchainBase.sol` (verdict signing),
  `PqzRegistryBase.sol`. Not packaged, and they import repository paths.
- Clients: `clientkeys` (JS), `ua-rs` and its bindings, `scaas-sdk`; `clients/ua-rs/examples/` holds benchmarks only. No
  sample application repository. The worked integration is [integration-odoo-example.md](../integration-odoo-example.md).

**Options and analysis** [I]:

- **A Solidity package for composing with confidential tokens.** What a third-party contract can do with a PQZ or Zether token
  is narrow, by design: check a disclosure (view), react to the public events, move public units. It cannot hold or spend a
  confidential balance. So the package is small: the interfaces, a `DisclosureCheck` helper (calls `verifyTransferAmount`, and
  the verdict form on `OFFCHAIN` tokens, which reverts `PqzVerdictRequired()` without one), and event decoders. Hooks or callbacks
  on confidential transfers would only notify, and each adds bytes to immutable kinds near their size limit; not recommended.
- **A Foundry mock-prover mode.** Generalise `PqzMock` into a published test library: the precompile answers "valid" for every
  statement, the self-test passes, and a fixture creates tokens through a local factory. It is safe by construction, since
  `vm.mockCall` exists only in forge and cannot reach a chain. The same is possible for Zether's verifier contracts with
  `vm.mockCall` on their addresses. The `OFFCHAIN` route is a second mock: a test verifier UA that signs every verdict; it
  needs no precompile and runs on anvil. Size: about a day each [E].
- **Sample apps**: (1) pay-by-confidential-transfer with a merchant who checks the amount with the disclosure view (the
  integration flow exists in prose); (2) a payroll batch with op 7 multi-recipient transfers; (3) the tender once it is built
  ([tender.md](../contracts/tender.md), SPECIFIED). Each sample runs on anvil with the mock and on the SCaaS testnet for real.

**Touches:** a new test library (outside `src/`, so no release or size effect), `scaas-sdk` examples, docs. **Recommendation:**
do the mock library and one sample (payment plus disclosure check) before P6-PUB; the Solidity package with them, interfaces
and helper only; no hooks in token code.

## 4. ACL and delegated decryption

The owner's question: "needs careful study; it may be done, or as a feature bit". This section analyses; it rules nothing.

### 4.1 What Zama does

Every handle has an ACL kept by the protocol: `FHE.allow(handle, address)` (long-term), `FHE.allowThis`, `FHE.allowTransient`
(one transaction), `FHE.makePubliclyDecryptable`; and, for users, `delegateUserDecryption`,
`delegateUserDecryptionWithoutExpiration`, `revokeUserDecryptionDelegation` [F, Zama ACL guide]. Delegated decryption ("lets
a designated party" decrypt "specific encrypted values on behalf of a user") came as contract delegation in v0.10 (October
2025), end to end in v0.11 (February 2026), and "all-contracts delegation" in v0.13 [V, changelog, blog]. OpenZeppelin's
`ERC7984ObserverAccess` lets each account name "an observer who is given access to their transfer and balance amounts", as
permanent ACL access [F, OpenZeppelin API].

**Why it works there** [I]: the KMS holds the key and decides who may learn a plaintext. The ACL is enforced by the decryptor.
**In SCaaS no party holds another's key**, so no contract or service can enforce a view right. A view right can only be
something the holder (or the sender) hands over. Every design below is a delivery mechanism, not an enforcement mechanism.

### 4.2 What SCaaS has

- **Per-transfer disclosure** by zero-knowledge proof, one leg at a time, checked by a view; three kinds on PQZ without the
  opening (`SENDER_S`, `RECEIVER_X`, `AUDITOR`), one kind (`SENDER_S`, provable by anyone holding the leg seed) on opening tokens
  ([CTR-PQZ-14](../contracts/pq-zero-knowledge.md#CTR-PQZ-14) and its Change); four kinds on Zether
  ([CTR-ZTH-40](../contracts/zether.md#CTR-ZTH-40)). Nothing reveals `r` or the noise.
- **The auditor**, set at token creation, reads each transfer that includes it (FULL, or OPTIONAL and the sender's choice,
  [CTR-ZTH-42](../contracts/zether.md#CTR-ZTH-42)), ideally a k-of-n threshold key ([CTR-ZTH-41](../contracts/zether.md#CTR-ZTH-41)).
  Under bit 32 `AUDITOR` it can be replaced with the new auditor's signed consent after `max(noticePeriod(), grantDelay)`; each
  audited entry keeps its epoch's auditor ([CTR-GOV-31](../decisions.md#CTR-GOV-31),
  [CTR-PQZ-43](../contracts/pq-zero-knowledge.md#CTR-PQZ-43), [CTR-ZTH-95](../contracts/zether.md#CTR-ZTH-95)). The consent is
  reusable within an epoch (owner 2026-11-18, accepted).
- **The three-key model and the sealed opening** ([CTR-PQZ-37](../contracts/pq-zero-knowledge.md#CTR-PQZ-37),
  [CTR-PQZ-40](../contracts/pq-zero-knowledge.md#CTR-PQZ-40)): on an opening token the sender seals the leg seed `seed_leg` to the
  recipient's and the auditor's opening KEM keys (ML-KEM-1024 + X25519, [CTR-UA-32](../contracts/accounts.md#CTR-UA-32),
  [CTR-UA-43](../contracts/accounts.md#CTR-UA-43)), in state. The holder **re-encrypts and compares**, never decrypts a credit with
  `s` ([CLI-SGN-51](../clients/signers-clientkeys.md#CLI-SGN-51)). A reader of the seed learns that leg's amount and nothing
  about any PQZ secret. The owner ruled KEM decryption outside ARCH-POS-13 (2026-11-13, quoted in
  [ARCH-POS-13](../decisions.md#ARCH-POS-13) "Source").
- **PqVault's per-note share**: single notes go through a reusable "share box", one shared vault per recipient set, each later
  share a `createItems` copy; no contract change, no per-item keys (controller call 2026-11-21, decisions.md, normative
  [CLI-PQV-07](../clients/ua-libraries.md#CLI-PQV-07)). A vault epoch key is wrapped to each member's UA KEM key, in state
  ([CTR-PQV-06](../contracts/pqvault.md#CTR-PQV-06)); every accepted record is kept in full ([CTR-PQV-05](../contracts/pqvault.md#CTR-PQV-05)).
- **ARCH-POS-13 already names the target**: "A decryption result reaches only the key holder, or a viewer the key holder
  names." A holder-granted viewer is inside the rule; what is outside is any path where the grantee or a third party chooses
  the ciphertext and observes a reaction.

### 4.3 A unified model: the holder grants view rights

A **grant** = (holder UA, grantee UA, token, scope, `validFrom`, `validUntil`), where the scope is one of:

- **per transfer**: named entries (`entryRef`, leg);
- **per balance**: the holder's balance in that token at named blocks;
- **per token**: every entry of the holder in that token within the window, incoming and outgoing.

Revocable means: no new material after the revocation. Nothing can take back what a grantee already read (§4.5).

**What a grantee receives, per token class** [I]:

| Token class | Per-transfer material | Can the grantee check it without trusting the holder? |
|---|---|---|
| opening token (`offchain-shared`, `offchain-token` with the opening) | the leg's `seed_leg`, resealed to the grantee's KEM key | **yes**: from `seed_leg` and the amount it re-derives `r, e1, e2_t` and compares `u`, `v_t` with state, as the holder check does; it can even produce the `SENDER_S` disclosure itself |
| `registry` (`PRECOMPILE`) and `offchain-token` without the opening | the amount plus a `RECEIVER_X` (incoming) or `SENDER_S` (outgoing) disclosure proof | yes, by the `verifyTransferAmount` view (the verdict form on `OFFCHAIN`) |
| Zether | the amount plus the matching opening of [CTR-ZTH-40](../contracts/zether.md#CTR-ZTH-40) | yes, by the view |

**Per balance**: PQZ has no balance-disclosure relation. A grantee can rebuild a balance from verified per-entry disclosures
(credits minus debits minus the public fee and unshield words) [I]; a direct balance proof would be a new relation, hence a
new `proofSystemId`, new vectors in every client and a full gate (AGENTS.md "Cryptography"). Not proposed.

**Per token, by sharing the PQZ secret `s`**: rejected. On the `registry` class `s` covers every `PRECOMPILE` token of that
holder on that chain, not one token ([CTR-UA-16](../contracts/accounts.md#CTR-UA-16)). It is irrevocable until a key-version
change ([CTR-PQZ-31](../contracts/pq-zero-knowledge.md#CTR-PQZ-31)), and it makes the grantee a second key holder exposed to
the oracle attack. Zama's "observer" is this, with the KMS in between; SCaaS should not offer it.

### 4.4 Ways to build it

| | (a) Client only | (b) On-chain grant record (ACL) | (c) Re-encryption into state | (d) A feature bit on the token |
|---|---|---|---|---|
| What | the holder's wallet reseals the material of §4.3 to the grantee's KEM key and sends it off chain (PqChat message, file) | a contract records grants (holder-signed, `validUntil`, revoke); wallets read it and honour it | the resealed material is **written to state**: either (c1) into a PqVault share box, holder to grantee, or (c2) by the **sender** inside the transfer, as an extra `PqzOpening openingViewer` beside `openingTo` / `openingAuditor` | the token enables (b) or (c2) at creation, on its own bit |
| Never lose ciphertext | if delivered by PqChat, the bytes are in PqChat state; by file, no: the grantee's only copy can be lost | n/a (no ciphertext) | yes | as (b) / (c2) |
| Contract change | none | a new contract, no admin, any chain; no token change | (c1) none: PqVault is BUILT ([pqvault.md](../contracts/pqvault.md)); (c2) a new token release: `PqzTransferArgs` and its typehash move for every class, `memoHash` covers the new opening ([CTR-PQZ-34](../contracts/pq-zero-knowledge.md#CTR-PQZ-34)), size grows on kinds near the limit | (c2) plus the bit's row in `GovernanceBits`, `governance_bits.json`, every client's table |
| Who acts | holder, per entry or by policy | holder signs the grant; nothing on chain acts on it | (c1) holder; (c2) the sender, for the holder's incoming legs, without the holder online | as above |
| Revocation | stop sending | a revoke record; wallets stop | stop writing; (c2) the sender's wallet stops reading the grant | the admin's one-way `disableFeature` would end every grant on the token, a bigger power than the holder's own |
| Metadata | none on chain | **public**: who lets whom see which token, since when, until when; per-transfer scopes even mark the transfers of interest | (c1) PqVault records show members and a write per share (sizes, timing); (c2) every transfer to that holder shows a viewer opening, so the grant's existence is public | as (b) / (c2) |

**Option (d), the bit.** The bands: bits 0–127 SCaaS's, 128–255 the customer's ([CTR-GOV-10](../decisions.md#ctr-gov-10--bit-bands-0-127-one-meaning-128-255-per-application-none-refused)).
Allocated today: 0–12, 15–32; 13 and 14 are "never allocated, never reused"
(`smartcontracts/vectors/governance/governance_bits.json`). The next free SCaaS bit is **33**. A proposal, if the owner wants
the bit: bit 33 `VIEW_GRANT`, a **capability** (no holder; grants are each holder's own act, not a role), valid on the
confidential kinds 2–5 and 10–13 only (the same mask as bit 32), set at creation only (not in `ENABLEABLE`), lockable at
creation. Disabling it should be refused or locked by default: otherwise an admin's one-way disable silently cuts every
holder's grantee off, a balance-adjacent power the "your key, your funds" table does not list today. A bit is only needed if
the token itself changes (c2). (a), (b) and (c1) need none, because they do not touch the token.

### 4.5 Checks against ARCH-POS-13, revocation, metadata, regulated kinds

**No decryption oracle** [I]:

- **The selection must be the holder's, never the grantee's.** A wallet that answers "please share entry X" with a decryption
  of X is an oracle if X can be a crafted ciphertext. A grant therefore fixes its scope when it is signed (named entries, or
  "every entry in this window"), and the wallet shares by that scope, never on request.
- **Share-or-skip must not depend on a secret.** If the scope is "every entry" and the wallet shares all but entry X, the
  grantee learns that X failed. An attacker who is also the grantee can credit X and watch. By class:
  - opening tokens: the holder check uses the sealed opening and re-encryption, never `s`
    ([CLI-SGN-51](../clients/signers-clientkeys.md#CLI-SGN-51)), so a failure leaks nothing about a PQZ secret. It does depend
    on the holder's KEM decapsulation, which ARCH-POS-13's Change of 2026-11-13 puts outside the rule: "the holder's reaction
    depends only on whether the sender's ciphertext or opening is well formed, which the sender already knows" (Q4 asks only
    for confirmation of this use);
  - `PRECOMPILE` tokens: every credit is proven well formed on chain, so its decryption cannot fail (the bounds of
    [§4.3 of the PQZ spec](../contracts/pq-zero-knowledge.md#43-noise-and-digit-budget-worst-case));
  - `offchain-token` without the opening: credits are not proven to the holder, and the token's key is already exposed to
    its verifier by the owner's acceptance; grants there add a second observer of the same reactions. The rule should be: no
    grant scope "every entry" on that class, named entries only.
- **(c2) moves the decision to the sender**, who seals to the grantee the same seed it seals to the recipient. Nothing applies
  a PQZ secret; the grantee's KEM decryption of a junk opening is the same accepted residual as a junk opening to the
  recipient ([CTR-PQZ-37](../contracts/pq-zero-knowledge.md#CTR-PQZ-37) "Residuals").
- The grantee's own tools fall under ARCH-POS-13 like any reader: it applies its KEM key only to openings that reached it from
  chain state at named locations ([CLI-UAL-30](../clients/ua-libraries.md#CLI-UAL-30) … CLI-UAL-38).

**Revocation limits.** Every shared seed or opening is permanent knowledge. Revoking stops future material; a revoked grantee
keeps every amount it read and can prove them to others with the disclosure view. Wallets must say so when a grant is made.
A time-bounded grant is a promise of the holder's wallet (and, with (c2), of senders' wallets), not a cryptographic bound.

**Metadata.** Option (b) and (c2) publish the relationship. On a regulated token that may be wanted (evidence of consent); on
a private payroll token it may itself be the secret (who is the accountant of whom). (a) and (c1) publish less, and (c1)
still shows PqVault membership and write timing.

**Regulated kinds and the auditor.** A grant is additive and holder-chosen; it never replaces the auditor. On a FULL auditor
token the auditor still reads every transfer, and no grant lets a holder route around it. On the regulated kinds 10–13 a
mandated viewer is the auditor's job, consent-based under bit 32. A holder grant is for the holder's own advisers
(accountant, lender, tax office). Nothing here touches `FORCE` or `FREEZE` (public balances only,
[CTR-TOK-22](../contracts/token-wrappers.md#CTR-TOK-22)).

### 4.6 Recommendation and open questions

**Recommendation** [I]: build **(c1)** first, the PqVault share box, holder to grantee. No contract change, ciphertext in state,
scope fixed by the holder, revocation by stopping. Material per class as in §4.3, so the grantee verifies without trusting the
holder. Specify it as a client rule next to CLI-PQV-07 and CLI-SGN-51, with the two ARCH-POS-13 rules of §4.5 (holder-fixed
scope; share-or-skip never driven by a PQZ-secret result; named entries only on an `offchain-token` without the opening).
Keep **(b)** and **(c2) with bit 33** as later options, to be taken only if a customer needs incoming amounts visible to a
viewer while the holder is offline (c2), or a public consent record (b). Never share `s`.

**Open questions for the owner** (no ruling made here):

- **Q2.** Is a view grant wanted at all before the freeze, or after mainnet?
- **Q3.** Which scopes matter: per transfer, per balance (built from entries), per token?
- **Q4.** On opening tokens, the share-or-skip decision depends on the holder's KEM decapsulation through the opening check.
  By its text, ARCH-POS-13's Change of 2026-11-13 ("KEM và ARCH-POS-13: Coi là nằm ngoài") covers it. Confirm that, or prefer
  that a grant shares every entry in scope, junk included, and lets the grantee's own check reject it.
- **Q5.** If (c2) is ever built: bit 33 `VIEW_GRANT` as a capability set at creation, and may the admin disable it (which ends
  every holder's grants on that token), or must it be locked?
- **Q6.** On the regulated kinds, should a grant be allowed alongside the auditor, or is the auditor the only viewer there?
- **Q7.** Is the public relationship metadata of (b) acceptable, or must grants stay off the public record except through
  PqVault?

## 5. A public trust model

**What it is.** One page that tells a user, per chain and per kind, **whom they trust, for what, and what a dishonest party
could do**, with the rule id beside each row. ETHBEAT's Zama page is that page written by an outsider (upgrade multisigs,
pausers, KMS thresholds, "fails the walkaway test"). SCaaS should publish its own first, with the same frankness, including
what is UNAUDITED [I]. Most of the content exists, spread over [architecture §7](../architecture.md#7-trust-model), §7.1, the
node docs and the [admin-power list](../contracts/README.md#admin-powers-complete-list).

**Draft table** (from the cited docs; wording to be checked against each rule when the page is written):

| Party | Trusted for | A dishonest party can | Cannot | Source |
|---|---|---|---|---|
| Relayer / node submit lane | liveness: submitting the subject's signed intent | delay or refuse it; pick the fee recipient where the intent leaves it unbound | change a signed field, move funds, sign for the subject | [CTR-MTX-17](../contracts/metatx.md#CTR-MTX-17), [NODE-LANE-16](../node/submit-lanes.md#NODE-LANE-16), [architecture §7.1](../architecture.md#authority-after-deployment) |
| Node indexer and event feed | the truth of `/v1/events` for clients that use it | lie on the feed; see pending payments it simulates | lie past the event-set quorum of independent RPC endpoints (bounds one dishonest provider, not a compromised node) | [NODE-IDX-01](../node/indexer-feeds.md#NODE-IDX-01), [NODE-IDX-02](../node/indexer-feeds.md#NODE-IDX-02), [architecture §7](../architecture.md#7-trust-model) |
| RPC nodes of a wallet or reader | the chain state it reads; under the agreement option, that fewer than ⌊n/2⌋ + 1 lie together | under failover, one named node can feed a wrong state; a discovered node never feeds a decryption alone | under strict majority, a minority cannot change a read | [ARCH-POS-15](../decisions.md#ARCH-POS-15), [CLI-UAL-31](../clients/ua-libraries.md#CLI-UAL-31), [CLI-UAL-38](../clients/ua-libraries.md#CLI-UAL-38) |
| `PQZ` precompile (`PRECOMPILE` tokens) | soundness: it runs the same verifier core as the prover, checked by the constructor self-test | a wrong chain client could accept a false proof (mint); that is the chain operator's client, not a party per token | run on a chain whose precompile fails the self-test (the token does not initialise) | [CTR-PQZ-09](../contracts/pq-zero-knowledge.md#CTR-PQZ-09), [CTR-PQZ-10](../contracts/pq-zero-knowledge.md#CTR-PQZ-10), [CTR-PQZ-01](../contracts/pq-zero-knowledge.md#CTR-PQZ-01) |
| PQZ verifier UA (`OFFCHAIN` tokens) | soundness, replaced by its signed verdict; classical or PQ as disclosed | accept a false proof and let a holder print units in that token (T27's maximum loss); make holders pay gas to mark junk; on an `offchain-token` without the opening, recover holders' keys of that token | spend anyone's funds (every debit needs `PqzAuth`); act on another token | [CTR-PQZ-27](../contracts/pq-zero-knowledge.md#CTR-PQZ-27), [CTR-PQZ-28](../contracts/pq-zero-knowledge.md#CTR-PQZ-28), [CTR-PQZ-29](../contracts/pq-zero-knowledge.md#CTR-PQZ-29), [CTR-PQZ-37](../contracts/pq-zero-knowledge.md#CTR-PQZ-37) |
| Factory registrar | publishing release code and envs; enabling kinds | publish a bad new version; deprecate a version (marks, never blocks) | touch any token, change a deployed implementation, stop a token | [CTR-TOK-18](../contracts/token-wrappers.md#CTR-TOK-18), [CTR-TOK-25](../contracts/token-wrappers.md#CTR-TOK-25) |
| Token admin and role holders | the powers of the bits set at creation, within their grants and `grantDelay` | mint to public balances (if `MINTABLE`; a hybrid's minted units are unbacked), step a rate under its timelock, disable wrap, replace the auditor with consent (bit 32); on regulated kinds freeze, force against a recorded order, bounded pause | set a new flag, touch a reserve, move a shielded balance, upgrade | [CTR-TOK-22](../contracts/token-wrappers.md#CTR-TOK-22), [CTR-GOV-31](../decisions.md#CTR-GOV-31), [contracts README §3](../contracts/README.md#admin-powers-complete-list) |
| Auditor | reading the transfers that include it | read those amounts; give `AUDITOR` openings | read balances; read a transfer the sender left out (OPTIONAL) | [CTR-ZTH-41](../contracts/zether.md#CTR-ZTH-41), [CTR-ZTH-42](../contracts/zether.md#CTR-ZTH-42), [CTR-PQZ-43](../contracts/pq-zero-knowledge.md#CTR-PQZ-43) |
| UA registry and KEM key records | binding keys to UAs; nobody administers it | nothing as a party; a holder's own KEM record is signed, write-once, never revoked, so a leaked KEM key exposes every opening sealed to it | be changed by anyone after deployment | [CTR-UA-15](../contracts/accounts.md#CTR-UA-15), [CTR-UA-32](../contracts/accounts.md#CTR-UA-32), [CTR-UA-43](../contracts/accounts.md#CTR-UA-43) |
| Sender of a sealed opening | that the opening matches the leg | seal junk: the recipient cannot spend that credit (the sender's loss); a disclosure proves an amount, not receipt | read the recipient's other credits | [CTR-PQZ-40](../contracts/pq-zero-knowledge.md#CTR-PQZ-40), [CTR-PQZ-37](../contracts/pq-zero-knowledge.md#CTR-PQZ-37) "Residuals" |
| The holder's wallet | following the holder check and ARCH-POS-13 | a wallet that decrypts credits with `s` on an `offchain-shared` token exposes the holder's shared key | — (the contract cannot enforce it) | [CLI-SGN-51](../clients/signers-clientkeys.md#CLI-SGN-51), [ARCH-POS-13](../decisions.md#ARCH-POS-13) |
| Chain validators (per chain) | ordering, liveness, the chain's own rules; the block signer is classical | censor, reorder, halt | forge a subject's signature or a proof | [what stays classical](../contracts/pq-zero-knowledge.md#what-stays-classical), `docs/networks/<family>.md` |
| A bridge (only where an asset is bridged) | the backing of the bridged asset | anything its design allows | — | not specified in SCaaS; per asset (§3.2) |

**Where it should live** [I]: as `docs/trust-model.md`, a current component doc with status tags, linked from
[architecture §7](../architecture.md#7-trust-model), which keeps the boundary table and points to the new page; or as a new
§7.2 of `architecture.md` if the owner prefers one file. Either way each row links its rule, nothing is restated, and the page
says per kind and chain which rows apply (a `PRECOMPILE` token on the SCaaS testnet has no verifier-UA row; an `OFFCHAIN`
token on a public chain has it). It is **pre-P6-PUB work**: the publication drafts will be read next to Zama's ETHBEAT page.

## 6. Medium and later items

- **Node monitoring of consensus drift.** Zama's v0.13 added "coprocessor consensus drift monitoring" [V, changelog]. SCaaS's
  counterparts: (1) drift between RPC nodes: the indexer already refuses ingest when its endpoints disagree on the final head
  or event set, and reports `scaas_finality_quorum{chain}` ([NODE-IDX-01](../node/indexer-feeds.md#NODE-IDX-01)); a metric that
  counts disagreements per endpoint pair would show a drifting provider before it causes a stop [I]. (2) Drift between the PQZ
  verifier (off-chain) and the precompile: on a chain that has both, an operator job could replay recent `PRECOMPILE`
  statements through `scaas-pqz-verifier`'s check and alarm on any different verdict. Same core, so any difference is a build
  or set mismatch worth knowing [I]. Touches the node's ops metrics ([ops.md](../node/ops.md)) and the verifier.
- **Custody partners.** Organisations will want their PQ signing keys and PQZ secrets in custody. The research exists
  ([07-custody-providers.md](07-custody-providers.md)); architecture §7 already notes that commercial HSMs do not support the
  curves, and the same holds for ML-DSA plus a PQZ secret with a narrow proving interface today [I]. A partner must hold
  `conf_custody` without becoming a decryption service for others, which is ARCH-POS-13 again. After mainnet.
- **A bug bounty before mainnet 22776.** Zama and OpenZeppelin publish audits and advisories; search results also show an
  OpenZeppelin confidential-contracts advisory on a wrapper `wrap` failure fixed in 0.3.1 (not opened, §9). A public bounty
  is the cheapest outside review a public repository can get. The old roadmap draft priced a $300,000 bounty float
  ([16-decomposition-roadmap.md](16-decomposition-roadmap.md), [_MANIFESTS.md](_MANIFESTS.md)); scope, size and payer are the
  owner's. It belongs after the AI audit round and before value on 22776.

## 7. Research question: compute on encrypted state

Which patterns really need computation over values from several parties that none may see? [I throughout]

| Pattern | Needs shared hidden state? | (a) Purpose-built ZK statement | (b) Optional fhEVM where it runs | (c) Skip |
|---|---|---|---|---|
| Sealed-bid auction | only during bidding; at the end the winner and price are public | commit-reveal already works: the tender ([tender.md](../contracts/tender.md), SPECIFIED) hides bids until the deadline, with deposits; losing bids can stay hidden without any ZK statement, by the owner's design of §7a | hides losers' bids without any reveal round, at the price of KMS trust for the result | no: the tender and §7a cover the need |
| Tender (procurement) | as above, plus the buyer's evaluation | as above; a buyer that must not see bids before the deadline is what commit-reveal gives | same as the auction | no |
| Order matching (dark pool) | yes, continuously: prices and sizes compared across parties | hard: matching is a computation over others' orders; a trusted matcher with ZK proofs of correct matching is possible (the DEX's matching modes, [dex-matching-modes.md](dex-matching-modes.md)), but the matcher sees orders | the natural fit for FHE: encrypted order book, comparisons on chain; all of Zama's trust comes with it | open: the strongest case for (b) |
| Voting | hidden tallies until close | additive tallies need only additive encryption, which PQZ has ([pq-fhe.md §9](pq-fhe.md)); per-voter ciphertexts under a tally key held by a threshold of talliers | possible, KMS trust | **out of scope now**: the owner ruled no governance or voting token for now (TODO.md, owner 2026-11-05) |
| Payroll, B2B settlement, confidential payments | no: each payment is its sender's computation | already PQZ and Zether | not needed | — |

**Option (b) in detail: could fhEVM live inside `scaas-pqz-verifier`?** (Owner question, relayed 2026-11-24.)

- **Not inside the verifier.** `scaas-pqz-verifier` only verifies PQZ proofs and signs a `PqzVerdict`. It "decrypts nothing and
  holds no PQZ secret" ([§9.5 of the PQZ spec](../contracts/pq-zero-knowledge.md#pqz-verifier-mode)). fhEVM needs FHE compute
  (the coprocessors) and threshold decryption (the KMS) holding a network key [V, litepaper].
  - Run by SCaaS, a service that decrypts on others' request is what [ARCH-POS-13](../decisions.md#ARCH-POS-13) forbids. It
    would also break the three-key model ([CTR-PQZ-37](../contracts/pq-zero-knowledge.md#CTR-PQZ-37): no class holds a key
    for others) and mix FHE with PQZ in one trust role.
  - Rebuilding the coprocessors and the KMS ourselves means building a network, and while SCaaS runs it alone, it is
    single-operator trust: weaker than Zama's 13-node threshold, not stronger.
- **Where an integration would sit instead:**
  - a **separate, optional fhEVM kind** (its own contract and catalogue entry, [CTR-TOK-28](../contracts/token-wrappers.md#CTR-TOK-28))
    built on Zama's Solidity library, reached through `mtx*` entries with UA signatures, so it stays relayable at fee 0;
  - an **SDK wrapper** of Zama's SDK (`@zama-fhe/sdk`; the older relayer SDK is unsupported from 2026-11-06 [V, changelog]) for
    encrypted inputs and their proofs, with the write signed by the UA;
  - **node relaying** under the normal allow-lists (`typed.rs`, `guard.rs` rows equal to the kind's `mtxSelectors`).
- **Availability.** The kind exists only where Zama runs (Ethereum, and the EVM chains on Zama's address index). It is an
  optional kind with an external dependency, not a rule split by chain, so "one rule on every chain" holds. It does meet
  [ARCH-POS-18](../decisions.md#ARCH-POS-18) head on: that rule says a missing dependency never disables a kind and the check runs
  in software. No software path can stand in for Zama's network, so this kind would be the first that cannot exist everywhere.
  Under ARCH-POS-18 that takes the owner's explicit confirmation per chain (Q9).
- **Trust.** Whoever uses that kind accepts Zama's KMS and coprocessor trust and its upgradeable contracts (§1). Every other
  kind keeps SCaaS's rules. It must never be called PQZ, and its amounts are not post-quantum on the authentication side
  (ECDSA permits, §2).
- **Cost.** A new kind with a new audit surface, Zama's patent licence for commercial TFHE-rs use
  ([pq-fhe.md §7](pq-fhe.md)), and a dependency on contracts that can be upgraded under it. [E]: weeks, not days.

**Assessment.** Only dark-pool order matching clearly needs (b). Auctions and tenders are served by commit-reveal, and
losing bids can stay hidden by the owner's design of §7a, with no ZK statement. Voting is out by ruling. So (b) is a research
watch item until a customer brings a matching use case.

### 7a. Sealed bids where losers need not open

**Today.** `SealedBidTender` is SPECIFIED, not built ([tender.md](../contracts/tender.md)). Commit and deposit are one
signature ([CTR-TND-01](../contracts/tender.md#CTR-TND-01)). The commitment is
`keccak256(abi.encode(BID_TAG, chainid, tender, tenderId, bidder, price, salt))` ([CTR-TND-02](../contracts/tender.md#CTR-TND-02)).
Reveal and withdraw are permissionless ([CTR-TND-03](../contracts/tender.md#CTR-TND-03)). **Every bidder must reveal or
forfeit**: a non-reveal or an out-of-range reveal goes to `slashSink` ([CTR-TND-04](../contracts/tender.md#CTR-TND-04),
[CTR-TND-05](../contracts/tender.md#CTR-TND-05)). The contract keeps the top `k ≤ 3` valid reveals, so the buyer can disqualify
the leader during `dqWindow` ([CTR-TND-06](../contracts/tender.md#CTR-TND-06)). There is one immutable contract per chain, with
no admin ([CTR-TND-08](../contracts/tender.md#CTR-TND-08)). Every price is public once revealed.

**The owner's direction (2026-11-24), verbatim:** "người thua chứng minh bằng ZK rằng mình thua => Không cần, chỉ cần người thắng
chứng minh mình thắng. Nếu người thua thấy người thắng đặt giá cao hơn (hoặc thấp hơn - đấu giá ngược) thì có thể tự chứng minh
mình là người thắng. Bên chủ thầu có thể là vai như auditor hoặc gì đó. mọi người đều phải mở giá, ai không mở thì mất tiền cọc
=> Cái này không đúng, chỉ cần trả lại tiền, vì họ không mở giá, họ đã thua. Chưa cần làm gì cả, chỉ cần ghi vào tài liệu."

In English, as the owner's design. It is recorded here only: nothing is built, and the details are not ruled.

1. **No ZK proof from losers.** Only the winner proves it won, by revealing its opening `(price, salt)` against its
   commitment.
2. **Challenge window.** A loser who sees that the claimed winner's price is worse than its own reveals its own opening and
   becomes the winner. "Worse" means higher in procurement or a reverse auction, lower in a forward auction. This repeats until
   the window closes, and the best revealed bid wins.
3. **Non-revealers get their deposit back.** They did not reveal, so they lost. This **replaces** CTR-TND-04's forfeit of a
   non-reveal to `slashSink`.
4. **The buyer may hold an auditor-like role.** Each bid is also sealed to the buyer's KEM key, as option A below. The buyer can
   then check bids or settle disputes without making losing prices public. Owner, 2026-11-24: option A is the direction, and
   the decrypted tender data is treated "like a chat message, or PqVault items shared out".

**The options the coordinator asked to compare**, placed against that direction:

- **A. Sealed to the buyer** (point 4 of the direction).
  - Each bid is the commitment plus a ciphertext of `(price, salt)` under the buyer's per-tender KEM key, stored in state,
    so no ciphertext is lost. The aad binds `chainid ‖ tender ‖ tenderId ‖ bidder ‖ commitment`, so one bid's ciphertext
    cannot be copied into another bid.
  - After the deadline the buyer decrypts locally. The buyer, or the winner, reveals the winner's opening; the contract
    checks it against the commitment, as `revealBid` does today.
  - Losers stay hidden from the public. The buyer sees all bids.
  - Disputes: a loser reveals its own opening to show a better bid (point 2), and a buyer who picked wrongly is penalised;
    the penalty is open (Q10).
  - Size [E]: about 1,700 B per bid (KEM ciphertext 1,600 B, sealed 48 B for `price ‖ salt`, the tag); at 1,530 state gas per
    byte ([pq-fhe.md §10](pq-fhe.md)) about 2.6 M gas per bid on top of today's commit.
- **B. Losers prove "my bid is worse" in zero knowledge: not needed (owner).** For the record [E, scaled from
  [pqz-general-purpose.md](pqz-general-purpose.md)], it would have been a new PQZH relation with a new `proofSystemId`, vectors
  in every client and a full gate. With today's keccak commitment the circuit is about 3 × 10^5 constraints (two Keccak-f
  permutations emulated in F_q, plus a 128-bit comparison), so the proof is about 400 KB, above the 262,144 B PQZH input
  limit, and the calldata alone is about 14 M gas. With a field-friendly commitment the proof is about 70 KB and about 3 M gas
  per loser.
- **C. fhEVM, for comparison only.** Bids are `euint64` under Zama's network key; the contract keeps the best with
  `FHE.lt` / `FHE.select`, and only the winning price is publicly decrypted. Zama's own token sale ran this way (January 2026)
  [V]. The cost is KMS trust: 5 to 9 of 13 operators, by the figures of §1, can read every bid. Add the coprocessors, ECDSA
  permits, upgradeable contracts, and Zama's chains only.

| | Today (CTR-TND) | Owner's design (winner claims, challenges) | … with A (buyer-sealed copy) | C (fhEVM) |
|---|---|---|---|---|
| Public sees | every revealed price | the winning price and the challengers' prices (each is better than the claim it beat); not the silent losers' | the same | the winning price |
| Buyer sees | every revealed price | the same as the public | **every committed price**, after the deadline | the winning price (as the public) |
| Whom you trust | nobody for secrecy (prices are public by design); the contract for the ranking | the contract for the ranking; each bidder to challenge if it is better | in addition, the buyer, not to leak losing prices; the KEM scheme's IND-CCA security | Zama's KMS and coprocessors |
| Non-revealer | forfeits | refunded (owner) | refunded; the buyer still knows its price | n/a (no reveal) |
| Effort | spec exists | spec revision only (tender not built) | spec revision; client sealing (the scheme-1 seal of PqChat and PqVault); a crypto review | a separate fhEVM kind (§7 (b)) |

**Analysis of the owner's design.** These are open questions, not rulings [I].

- **The free option.** With refunds for non-revealers, a bidder can commit several bids at different prices, from several UAs,
  and reveal only the one it likes after seeing the claimed winner. Prices are fixed at commit, so no bid can be raised.
  But a bidder can withdraw for free, which today costs the deposit, and colluders can keep a fallback bid that they reveal
  only if the outsider's bid beats theirs. Mitigations, for the owner:
  - one bid per UA (it does not stop a bidder with several UAs);
  - a commit fee that is not refunded (prices the option, does not remove it);
  - the buyer-sealed copy A (the buyer sees every committed price and can show a pattern, but cannot force a reveal unless Q12
    allows it);
  - refund only after settlement (the deposit stays locked through the challenge window).
- **Ordering and timing.**
  - A claim deadline after `commitDeadline`, then a challenge window. Each successful challenge may restart or extend the
    window, or not; a fixed end is simpler, an extension stops last-block sniping of the challenge itself.
  - Ties keep the existing rule, the earliest commit `seq` ([CTR-TND-05](../contracts/tender.md#CTR-TND-05)): a challenger at an
    equal price wins only with an earlier `seq`.
  - A **griefing claim**: a claim that is not the best only delays, because any better bidder can challenge. Its cost is the
    challengers' gas, and every challenger's price becomes public. A claim fee, or forfeiting a claim that was beaten, would
    price it. Forfeiting would hit honest bidders who simply did not know they were second.
  - `dqWindow` ([CTR-TND-06](../contracts/tender.md#CTR-TND-06)) assumes the contract knows the next-best bid. Under this
    design it knows only the challengers. After a disqualification, the next leader must come from a new claim round, or
    from the buyer's sealed copies (A).
- **The buyer's role.**
  - As auditor, may the buyer reveal a better sealed bid on a bidder's behalf (Q12)? Technically the buyer can, because it holds
    `(price, salt)`, and `revealBid` is permissionless. It would close the free option for any bid the buyer can open. It also
    gives the buyer a choice to make public, or not, a bidder's price.
  - **Which buyer key** (Q13): its registry KEM key version, as PqChat uses ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32):
    signed, versioned, write-once, never revoked), or a **fresh scheme-1 KEM key per tender**? A fresh key bounds the damage of
    a leaked key to one tender's bids, and it allows a later escrowed release of that key to an arbiter without touching the
    buyer's chats or other tenders. The registry key needs no new record, but a leak of it opens every tender sealed to it and
    the buyer's chats. Open question; no ruling here.
  - **ARCH-POS-13: option A does not breach it.** The owner's words (2026-11-24): the decrypted tender data is treated "like a
    chat message, or PqVault items shared out". The rule already covers this. Its Change of 2026-11-13 ("KEM và ARCH-POS-13:
    Coi là nằm ngoài" [KEM and ARCH-POS-13: treat it as outside]) reads: "The rule is about decryption with a PQZ or a Zether
    key. A decapsulation of the hybrid KEM scheme of CTR-UA-32 (ML-KEM-1024 + X25519, IND-CCA by its combiner), under a chat
    key or an opening key, and the one-shot AEAD keyed by it are outside the rule." ([ARCH-POS-13](../decisions.md#ARCH-POS-13),
    on `ua-rs-sign` at `6db173f7c`). A bid sealed to the buyer with scheme 1 KEM + AEAD is built exactly like a PqChat message
    or a shared PqVault item, so the buyer's decryption is outside the rule. The conditions that keep it so:
    - **no PQZ or Zether key ever encrypts bid data**; the same Change "gives no leave to apply a PQZ or Zether key to
      anything the decapsulated value has not first shown, by re-encryption and byte comparison, to be well formed";
    - **a confidential PQZ deposit stays under ARCH-POS-13** like any PQZ token, so the sealed bid and the deposit are kept
      apart, and nothing about the deposit's decryption depends on the bid or the other way round. Today the deposit token
      refuses the Zether kinds and takes plain or wrapped kinds only ([CTR-TND-07](../contracts/tender.md#CTR-TND-07));
    - **the ciphertext stays in state**, beside the commitment;
    - **the commitment is checked at reveal**, so the buyer cannot alter a price: any opening it reveals must match the
      bidder's commitment. A bidder can always prove its own bid by revealing its opening.
  - **Points for a crypto review of the sealed copy** (the rule question above is settled; these are about the tender's own
    soundness):
    1. the aad binding against copied or replayed bids;
    2. how a dispute shows that a sealed copy was well formed, so a bidder who sealed junk cannot have the buyer penalised.
       One route is deterministic encapsulation coins derived from the salt, as the sealed opening does: anyone holding the
       opening can re-encrypt and compare. Checking that on chain needs ML-KEM-1024 encapsulation, X25519 and AES-GCM in
       software (ARCH-POS-18), estimated at 5–15 M gas [E, not measured];
    3. how a per-tender key, if chosen, is generated and erased.
  - **Where the option sits.** The tender has no `GovernanceBase` and no admin (CTR-TND-08), so it has no feature word.
    The natural form is a per-tender, immutable creation parameter (say `bidPrivacy`: public reveals, or a buyer-sealed copy
    with the buyer's per-tender KEM key). If the owner wants it as a governance bit anyway, it falls in SCaaS's band 0–127
    ([CTR-GOV-10](../decisions.md#ctr-gov-10--bit-bands-0-127-one-meaning-128-255-per-application-none-refused)): the next free
    bit is 33, or 34 if §4's `VIEW_GRANT` takes 33 (Q11).
- **What changes in [tender.md](../contracts/tender.md) when this is specified.** Nothing is edited now.
  - CTR-TND-04: a non-reveal is refunded; `slashSink` keeps only the declared forfeit classes and the HOLD bond claim.
  - CTR-TND-05: an out-of-range reveal still forfeits, or only fails to win; the "reveal garbage to exit" escape it closed
    is now free anyway.
  - CTR-TND-03 and §3.2: the reveal phase becomes a claim, then the challenge window.
  - CTR-TND-06: settlement after the window; `minBidders` counts claims and challenges, not all reveals; the top-`k` list and
    `dqWindow` are reworked.
  - CTR-TND-01 / CTR-TND-02 with A: the sealed copy at commit, its aad, and the `BID_TAG` if the commitment changes.
  - Invariant I1 and the §8 security table: the free option, and the buyer's knowledge under A.

**Recommendation** [I]: record the owner's design (above), with A as its chosen form (owner 2026-11-24), as the direction for a
tender v2. When it is specified, run a crypto review of the three points above. Keep B dropped (owner) and C as comparison
only. Timing is the owner's (Q14);
the tender is not built, so nothing waits on it.

## 8. Proposed TODO items

No rulings; each item waits for the owner.

| # | Item | Depends on |
|---|---|---|
| T-Z1 | `docs/trust-model.md` (or architecture §7.2): the §5 table, per chain and kind, with rule ids | nothing; before P6-PUB |
| T-Z2 | ERC-7984 mapping page (§3.1 table), and track the EIP's status; no contract code while it is Draft | nothing; owner Q1 on public comment |
| T-Z3 | `scaas-sdk` confidential-token view type with ERC-7984-aligned names | T-Z2 |
| T-Z4 | Published Foundry test library: the precompile mock (from `PqzMock`), a Zether verifier mock, a test `OFFCHAIN` verifier UA, a factory fixture | nothing; before P6-PUB |
| T-Z5 | One sample app: payment plus merchant disclosure check, on anvil (mock) and the SCaaS testnet (real) | T-Z4 |
| T-Z6 | Solidity composition package: interfaces plus a disclosure-check helper, no hooks in token code | T-Z4 |
| T-Z7 | View grants, client rule (c1): PqVault share box per §4.3, the ARCH-POS-13 rules of §4.5 | owner Q2–Q4, Q6, Q7; PqVault client (CLI-PQV-07) |
| T-Z8 | (later, only on a customer need) on-chain grants (b) or sender-side viewer openings (c2) with bit 33 | T-Z7; owner Q5; a new token release |
| T-Z9 | SCaaS-created wrappers for major assets: per-wrapper configuration sheet, publication in `deployments/<key>.json` and docs | mainnet 22776; G-LIC and audit gates; registrar multisig |
| T-Z10 | Node metric: disagreements per RPC endpoint pair; operator job comparing `scaas-pqz-verifier` verdicts with the precompile | node ops round |
| T-Z11 | Bug bounty: scope, size, payer, platform | AI audit round; before value on 22776; owner |
| T-Z12 | Research watch: fhEVM as a separate optional kind for order matching (§7) | a customer use case; owner Q8, Q9 |
| T-Z13 | Tender v2 (owner direction 2026-11-24): winner claims, challenge window, non-revealers refunded, optional buyer-sealed copy; spec later (§7a) | owner Q10–Q14; crypto review for the sealed copy |

**Further open questions for the owner:**

- **Q1.** Should SCaaS comment publicly on ERC-7984 (non-`address` account ids, named proof fields)?
- **Q8.** Is a separate fhEVM kind (§7) ever in scope, given its KMS trust and its upgradeable dependency?
- **Q9.** If yes, does ARCH-POS-18 allow a kind that cannot exist on chains without Zama, and is that recorded per chain as
  the rule asks?
- **Q10.** Tender v2: the penalty for a buyer's wrong pick under A, and whether a beaten claim or a griefing claim costs
  anything. Also which mitigation of the free option applies: one bid per UA, a commit fee, refund only after settlement, or
  none.
- **Q11.** Is the buyer-sealed copy a per-tender creation parameter, or a governance bit (band 0–127, bit 33 or 34)?
- **Q12.** May the buyer see all bids (A) at all? If so, may it reveal a better sealed bid on a bidder's behalf?
- **Q13.** The buyer's key: its registry KEM key version, as in PqChat, or a fresh scheme-1 KEM key per tender?
- **Q14.** Timing: tender v2 before the EVM freeze, or after mainnet?

## 9. Sources and what could not be verified

Read 2026-11-24:

- Zama Protocol litepaper: <https://docs.zama.org/protocol/zama-protocol-litepaper> (TFHE-rs; 13 KMS nodes, 2/3 rule, Nitro
  Enclaves, up to 1/3 malicious; one network key; 5 coprocessors and "3 operators"; Gateway as optimistic rollup; PQ claims;
  audits; roadmap: other EVM chains H1 2026, Solana H2 2026).
- Zama docs: coprocessor <https://docs.zama.org/protocol/protocol/overview/coprocessor>, gateway
  <https://docs.zama.org/protocol/protocol/overview/gateway>, KMS <https://docs.zama.org/protocol/protocol/overview/kms>, ACL
  <https://docs.zama.org/protocol/solidity-guides/smart-contract/acl>, inputs
  <https://docs.zama.org/protocol/solidity-guides/smart-contract/inputs>, SDK
  <https://docs.zama.org/protocol/sdk/guides/encrypt-decrypt>, Hardhat
  <https://docs.zama.org/protocol/solidity-guides/development-guide/hardhat/run_test>, Foundry
  <https://docs.zama.org/protocol/solidity-guides/development-guide/foundry>, addresses
  <https://docs.zama.org/protocol/protocol-apps/addresses> (Ethereum mainnet page; Solana mainnet page).
- Changelog: <https://docs.zama.org/protocol/changelog> (v0.8 ML-KEM-512; v0.10 October 2025; v0.11 February 2026; v0.13 of
  2026-06-29: `@fhevm/sdk`, `FHE.sum` / `FHE.isIn`, all-contracts delegation, coprocessor consensus drift monitoring).
- Blog: <https://www.zama.org/post/zama-protocol-update-new-sdk-delegated-decryption-developer-tooling-and-protocol-apps>
  (2026-05-07); cUSDC freeze lifted: <https://www.zama.org/post/the-freeze-on-zamas-cusdc-contract-has-been-lifted-and-all-systems-are-back-to-normal>.
- ERC-7984: <https://eips.ethereum.org/EIPS/eip-7984>. OpenZeppelin: <https://docs.openzeppelin.com/confidential-contracts/token>,
  <https://docs.openzeppelin.com/confidential-contracts/api/token>.
- ETHBEAT (formerly the L2BEAT URL <https://l2beat.com/privacy/projects/zama-confidential-tokens>, now redirecting):
  <https://ethbeat.org/privacy/projects/zama-confidential-tokens>.
- Third-party reports: mainnet launch and first cUSDT transfer
  <https://www.kucoin.com/news/flash/zama-protocol-launches-mainnet-completes-first-cusdt-transfer-on-ethereum>; public auction
  <https://www.theblock.co/press-releases/387247/zamas-public-auction-attracts-118m-for-ethereums-first-encrypted-ico>.
- OpenZeppelin audit pages (titles seen, reports not read):
  <https://www.openzeppelin.com/news/zama-confidential-contracts-0.3.0-release-audit>,
  <https://www.openzeppelin.com/news/zama-confidential-fungible-token-audit>,
  <https://www.openzeppelin.com/news/openzeppelin-confidential-contracts-v0.5-diff-audit>.

**Not verified:**

- whether Zama's input ZKPoKs are post-quantum;
- the KMS signature scheme;
- any KMS-specific audit, and the content of the OpenZeppelin audit reports;
- a Zama primary source for the exact mainnet date;
- whether the Gateway is an Arbitrum Orbit chain specifically;
- which of the threshold figures (9 of 13, 7, 5) applies to what;
- the OpenZeppelin advisories seen only as search snippets (a wrapper `wrap` failure fixed in 0.3.1, and one on
  `VestingWalletConfidential`); their identifiers are not quoted here for that reason.

**Corrected from the brief:** TVL is $84.45M on ETHBEAT, not about $130M; ERC-7984 uses `bytes32`, and `euint64` /
`externalEuint64` / `inputProof` are OpenZeppelin's; the EIP does not mention ERC-20 (OpenZeppelin says "not ERC-20
compliant"); no confidential protocol runs on Solana yet; Zama's Foundry tool is not a mock mode.
