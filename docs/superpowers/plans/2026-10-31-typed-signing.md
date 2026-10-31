# `typed-signing` (typed EIP-712 for every user-signed op, named entry points, explicit parameters) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** every operation a user signs is a typed, readable EIP-712 struct whose fields are the operation's own
explicit parameters — (P) the chain-free UA records (`register` PoP, `R_REG` message, KEM record, PQZ key record, `msig`
member signatures, Zether PoP) under a domain with only `name` + `version`; (C) every chain-bound meta-transaction as a
**named entry point per operation** with its own typehash (the generic `mtxExecute` / `mtxBatch` / `uaExecute` / `uaBatch` stay beside them, owner 2026-10-31), the
UA twins, the trade / DEX cancels, receiver fee, relay fee, wrap-by-signature, Zether owner ops and PQZ auth; (X) every
entry point takes **explicit named parameters** (REST/JSON-style), never a packed blob of several fields; (N) the node's
job API takes explicit JSON fields per operation and builds the calldata / XDR itself.

**Architecture:** branch `typed-signing` (worktree `.claude/worktrees/typed-signing`) from `main` at `9f88f43b`. Four
parts, in this order: **Part P** (portable digests + `kindName`) and **Part R** (registry explicit ABI) first — they block
`ua8-soroban` M2 / M3 / B1–B3 / B5 / B7; P + R are offered to the owner as one merge to `main`, then `ua8-soroban` merges
`main` and continues. **Part X0** (explicit-parameter inventory + calldata measurement) runs in parallel with P and gates
Part C. **Part C** (named typed entry points on every EVM contract) after X0's sign-off. **Part N** (node job API and
indexer) after C. Docs (D) and gates / review (G) close each merge unit. Agents stop at the branch; merge / push only
after the owner's approval.

**Tech Stack:** Solidity / Foundry v1.8.5 (`evm_version = "amsterdam"`, 65,536 B runtime ceiling); Node `node --test`
(`clients/clientkeys`, `@noble/curves` 2.4.0, `@noble/post-quantum` 0.7.1); Rust `scaas-ua` (`clients/ua-rs`), cxx-qt
(`clients/ua-qt`, Qt 6.12 at `~/usr/Qt/6.12.0/gcc_64`), `zether-prover`, `scaas-node` (alloy `sol!`), pqz-core `ffi`
vector generator; .NET / Python / Go / C / C++ / Dart reproducers; Soroban `soroban-sdk = "=30.0.0-rc.1"`.

**Inputs:** private note `scratchpad/eip712-inventory.md` (inventory + "Owner decisions 2026-10-31" items 1–8);
TODO.md item 2d; owner rulings relayed 2026-10-31 by the controller: `kindName` view; **option B** (named entry point per
operation, replaces decision 5); **explicit parameters** (general rule). UA-8 plan
`docs/superpowers/plans/2026-10-30-ua8-portable-registrations.md` (UA8-D1, UA8-D2, ruling C7) and decisions.md CTR-UA-07
"Change (2026-10-25 / 2026-10-30)"; `git show ua8-soroban:docs/superpowers/plans/2026-10-31-ua8-soroban.md` (M1 done at
`bb27d77b` on that branch; M2/M3/B1–B3/B5/B7 wait for this round); docs/clients/signers-clientkeys.md CLI-SGN-27,
docs/clients/app.md CLI-APP-09, docs/networks/README.md NET-ALL-23 / NET-ALL-84; docs/contracts/pq-zero-knowledge.md
"Findings for the owner" (3) (PQZH headroom).

## Global Constraints

Owner rules (quoted or restated without change):

- **Scope** (owner 2026-10-31, decision 1): "every operation an EOA wallet sees **plus the UA paths** (for the app review /
  audit) **plus the portable functions**".
- **Portable records** (decision 2): "typed EIP-712 under a domain with only `name` + `version` ("SCaaS UA Portable",
  "1"); the `ua_msg` wrapper kept". No Ledger / Trezor test first (decision 3).
- **Native EOA msig members** (decision 4): "sign the typed record (`eth_signTypedData_v4`) instead of `personal_sign`".
- **Option B** (owner 2026-10-31, replaces decision 5): "a named entry point per operation, everything explicit" —
  `mtxUnwrap(…, <envelope>, sig)`, `mtxWrap`, `mtxWrapToUA`, `mtxUnwrapToUA`, `mtxBurn`, `mtxAddReserve`,
  `mtxCancelNonce`, Zether / PQZ `mtxShield` etc., MandateWallet `mtxSetMandate` / `mtxSetPayee` / `mtxRevokeMandate`,
  SmartKeyAccount `mtxAddKey` / `mtxRemoveKey` / `mtxRotateKey` / `mtxSetGuardian` / `mtxCancelRecovery`, and their `ua*`
  twins — each with its own typehash. A generic `Execute(address target,uint256 value,bytes data,…)` only where the call
  is inherently arbitrary (SmartKeyAccount / MandateWallet `execute`).
- **Relay fee and wrap-by-signature** (decision 6): dedicated typed structs `RelayFee(...)`, `WrapOrder(...)`.
- **`0x0108` in MetaMask** (decision 7): pending; controller proposal "not a goal" — this plan does not build it.
- **`kind`** (decision 8): "`uint16` only (no string field); the name is looked up in the kind table (app / docs). No
  `paramSet`." Plus (owner 2026-10-31): a public `UARegistry` view returning a kind id's name.
- **Explicit parameters** (owner 2026-10-31, general): "every parameter is explicit, as in a REST / JSON / RPC API — no
  packed / opaque `bytes` that bundle several fields"; genuine cryptographic blobs stay `bytes` "but as their own named
  parameter (`proof`, `ciphertext`, `kemPk`, `pqzKey`, `signature`, …)"; "the statement / digest bytes that pqz-stmt and
  the verifiers hash stay byte-identical (the contract assembles them from the explicit params)"; the node job API takes
  "explicit named JSON fields per operation instead of opaque hex blobs; the node builds the XDR / calldata".
- Never lose ciphertext: PQZ / Zether ciphertexts and PQZ key / proof bytes stay in contract state (an explicit
  parameter is stored exactly as the packed bytes were). Zether ≠ PQZ (separate tasks, tests, docs). NEAR ≠ Algorand.
- Every state-changing write relayable (owner 2026-10-20): every named `mtx*` / `ua*` entry is submitted by a relayer,
  fee may be 0; the relay-fee router keeps working with the new entries.
- One rule everywhere (owner 2026-10-25): never split a rule by chain kind. The typed EIP-712 form is the EVM family's
  wallet-readable form; other families keep their own readable form (NET-ALL-23) and hash the portable records
  byte-identically; explicit parameters apply to every family (later rounds: NET-ALL-84 row).
- Code size (owner 2026-10-21): the only ceiling is 65,536 B runtime (EIP-7954); no micro-optimisation; the size gate
  ratchet (`scripts/size_gate.py` + `smartcontracts/evm/size-baseline.json`) records new numbers; the library / module
  split pattern (metatx split variant A: `MtxPipelineLib`, `WrappedLib`) is the tool. Never mention the 24 K limit.
- All chains test-only (no migration, no compat). "SCaaS testnet" in prose. Parameter sets only as `n2048-kmax1024` …
  `n2816-kmax65536`. No EIP-7702 (an EOA signs with its own key only).

House rules for every task:

- Decisions recorded in full in `docs/decisions.md` (content, who: "owner 2026-10-31" or "controller call, owner may
  override", status, commit); never a bare label; **no branch commit hashes** — write "typed-signing <task>" and add the
  `main` merge commit when it lands.
- Superseded built code goes to `legacy/typed-signing/` of its package (contracts: `smartcontracts/evm/legacy/typed-signing/`,
  clients: `clients/<pkg>/legacy/typed-signing/`, vectors: `smartcontracts/vectors/ua/legacy/typed-signing/` with a
  README line, as the UA-8 precedent), never deleted. Local tag `ref/pre-typed-signing` at the start (never pushed).
- Heavy commands (forge, cargo, npm, dotnet, ctest) only through `scripts/capped`, never inside `timeout`; cargo `-j2`;
  `dotnet build-server shutdown` after capped dotnet; no docker in this round. Foreground runs; no background shell left.
- Gates log per step (`# <step> at commit <sha>` first line, `rc=<n>` last) and skip a step done at the same commit with a
  clean tree (resume, never restart; read `runs/gate/last` and the latest logs first); never two gate runners at once.
  No full pqz-core gate (no core / set-parameter change; TS-D20) — if a set's `debit_min_gas` or a calibrated row moves,
  stop and ask.
- Max 3 implementer agents at once; tasks that touch the same files run sequentially (see Order).
- Commit per task, message `typed-signing <task>: …` ending `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
  no merge, no push, never `git stash`.

## Plan decisions (TS-D*; recorded in full by D1 / D2; "controller call, owner may override" unless marked owner)

**Part P**

- **TS-D1 Portable domain and structs (owner decisions 2 + 8; exact strings: controller call).**
  `EIP712Domain(string name,string version)`, name `"SCaaS UA Portable"`, version `"1"`;
  `DS_P = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version)"), keccak256("SCaaS UA Portable"), keccak256("1")))`
  `= 0x9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1` (computed with cast 1.8.5; P1 / P3 re-derive
  and pin it). Structs (EIP-712 `encodeType`: primary, then referenced types sorted by name):

  | Struct | Type string (fields in order) | typehash |
  |---|---|---|
  | `UAKemRecord` | `UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)` | `0x0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201` |
  | `UAPortableRecord` | `UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)UAKemRecord(…)` | `0x0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f` |
  | `UARegistration` | `UARegistration(UAPortableRecord record,bytes32 pqzPopHash)UAKemRecord(…)UAPortableRecord(…)` | `0xc78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e` |
  | `UAPqzKey` | `UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)` | `0x827d90728b100bc830d06b04dd2b9b5f7853adaa05502b4082875f881d925a00` |
  | `UAPqzKeyRecord` | `UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)` | `0xaba20a80603724f71232573a76d2506ae38f60f39ea9cd8e71f4b64775dd7567` |

  Field values: `kind` = the registering kind (uint16, e.g. `0x0120` msig, `0x0141` Zether); `pqzKeyHash =
  keyHashOf(0x0142, pqzKey)` (unchanged group hash), 0 without a key; `kemPkHash = keccak256(kemPk)` over the whole
  1,601-byte scheme-1 key (scheme byte included), `scheme = kemPk[0]`; `pqzPopHash = keccak256(pqzPop)`, 0 without a key.
  Only `UAPortableRecord` carries `kind` (the other records name the UA by `ua`; its kind is fixed by the id).
  `typed(s) = keccak256(0x1901 ‖ DS_P ‖ hashStruct(s))`.
- **TS-D2 "No KEM record" encoding.** No initial KEM record ⇒ the nested `kem` is `UAKemRecord{ua, 0, 0, 0}`
  (`version 0` is never a valid record, `UAKemVersion`, so the zero record is unambiguous). Replaces today's
  `kemRecordHash = 0`.
- **TS-D3 What signs what (the `ua_msg` wrapper kept, owner decision 2; purpose tags unchanged, the struct type adds the
  record type).**
  | Record | Signed / proven message | Who |
  |---|---|---|
  | `register` PoP | `uaMessage(kind, PURPOSE_POP_V2, typed(UARegistration{UAPortableRecord{ua,kind,pqzKeyHash,kem}, pqzPopHash}))` | the key (every single kind); PQ-eligible `msig` members |
  | `R_REG` at `register` / `storePqzPop` (first key) | `uaMessage(0x0142, PURPOSE_POP_V2, typed(UAPortableRecord{…}))` | pqz prover |
  | `setKemKey` | `uaMessage(kind, PURPOSE_KEM, typed(UAKemRecord{ua,version,scheme,kemPkHash}))` | KEM holders |
  | `setPqzKey` signature | `uaMessage(kind, PURPOSE_PQZ_KEY, typed(UAPqzKeyRecord{UAPqzKey{ua,pqzKeyHash}, pqzPopHash}))` | PQZ holders |
  | `R_REG` of a later key (`storePqzPop` after `setPqzKey`) | `uaMessage(0x0142, PURPOSE_PQZ_KEY, typed(UAPqzKey{ua,pqzKeyHash}))` | pqz prover |
  | Zether PoP (`0x0141`) | Schnorr over `uaMessage(0x0141, PURPOSE_POP_V2, typed(UARegistration{UAPortableRecord{ua,0x0141,0,UAKemRecord{ua,0,0,0}}, 0}))` | zether-prover |

  `pqz-core` is unchanged (the R_REG message stays 32 bytes). `KEM_RECORD_TAG` / `PQZ_KEY_RECORD_TAG` become unused
  (legacy). Purpose tags are not bumped (test-only chains, no old signature can verify under the new digests).
- **TS-D4 `msig` members of a portable record (owner decision 4; derived / contract details: controller call).**
  `md = keccak256(structureUa ‖ uaMessage(MSIG, purpose, typedDigest))` stays for **derived** members (they sign
  `uaMessage(memberKind, PURPOSE_MEMBER, md)`, unchanged code). A **native EOA** member (code-less or the 23-byte 7702
  designator: its own key only) signs `typedDigest` itself — the digest `eth_signTypedData_v4` returns for the record's
  typed data — 65-byte `r ‖ s ‖ v`, low s; replaces `personal_sign(md)`. A **contract** member answers ERC-1271
  `isValidSignature(typedDigest, sig)`. The structure is bound by `record.ua` (every portable struct carries `ua`), the
  operation by the struct type. Chain-bound member authorisations (`requireAuthorized`, `UAAuth`) are unchanged.
- **TS-D5 `kindName` (owner 2026-10-31; failure mode: controller call).** `UARegistry.kindName(uint16 kind) external pure
  returns (string memory)` = `UAKinds.name(kind)`; an unknown id **reverts `UAKindUnknown(kind)`** (the existing
  behaviour of `UAKinds.name`, no new code path; an app treats a revert as "unknown"). In `IUARegistry`. Every kind id of
  the table answers, enabled or not (it is a name table, not an enablement view). Soroban `ua-registry` gets the same
  view `kind_name(kind: u32) -> String` (`KindUnknown` panic for an unknown id) in `ua8-soroban` (U8S item, TS-D9);
  NEAR / Algorand: written into NET-ALL-84 for their UA rounds.
- **TS-D6 Registry digest views.** The five raw views are replaced (same names where the meaning maps, new argument
  lists): `portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash) → typed(UAPortableRecord)`,
  `kemRecordHash(bytes32 ua, uint64 version, KemKey kem) → hashStruct(UAKemRecord)` (zero record for version 0 + empty key),
  `registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash, bytes32 pqzPopHash) → typed(UARegistration)`,
  `kemRecordDigest(bytes32 ua, uint64 version, KemKey kem) → typed(UAKemRecord)`,
  `pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) → typed(UAPqzKey)`,
  `pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) → typed(UAPqzKeyRecord)`,
  `portableDomainSeparator() → DS_P`. (`KemKey` is Part R's explicit KEM key, TS-D11; until R lands, P1 uses `bytes kemPk`.)
- **TS-D7 Vectors.** Every file holding a portable digest or PoP is regenerated and the pre-round copy kept in
  `legacy/typed-signing/`: `portable.json`, `signatures.json`, `pq_signatures.json`, `structures.json`, `groups.json`,
  `kinds.json` (if any PoP field moves), zether-prover `r33_keys.json` (+ its copies `clients/clientkeys/test/vectors/r33_keys.json`,
  `smartcontracts/evm/test/vectors/zether/s3/r33_keys.json`). **R_REG proofs:** `portable.json`'s `pqzPop` values are
  deterministic SHAKE256 fillers (`ua-signers.mjs` `pqzPopOf`, UA8-D17), regenerated in seconds; the forge suite mocks
  the precompile; the only real R_REG proofs are made at run time by `smartcontracts/evm/script/pqz/e2e.py`
  (`pq.prove(3, K.build_register(portable("reg", …)))`), so no stored real proof needs regenerating — the next SCaaS
  testnet e2e proves over the typed message at its usual per-holder cost. pqz-core self-test `statement_register.json` is
  over a fixed message: unchanged.
- **TS-D8 Soroban alignment (controller call).** Part P updates what `main` already runs on Soroban — `ua-registry`
  `digest.rs` `portable_pop_digest` / `registration_digest` → `portable_record_hash` / `registration_digest` (typed, with
  `kind`), the `register` call site, `check_msig`'s portable `evm-eoa` member (ECDSA over the typed digest, replacing
  `verify::check_evm_eoa_personal_sign`), and the tests that read `portable.json` (`ua-registry`, `ua-common`, `token`
  `test_ua.rs`) — so `main` stays green. The **new** Soroban digests (`kem_record_digest`, `pqz_key_digest`,
  `pqz_key_record_digest`, typed from the start) stay `ua8-soroban` **B1**; Part P hands B1 the DS_P constant, the
  typehashes and the `portable.json` rows.
- **TS-D9 `ua8-soroban` coordination (controller call).** P + R land on `main` first (owner approval of the merge);
  `ua8-soroban` then merges `main`: conflicts in `ua-portable-vectors.mjs`, `ua-signers.mjs`, `ua-rs/src/ua8.rs`,
  `portable.json` are resolved by taking `main`'s typed digest / explicit-ABI code plus M1's minimal-slot code and
  **regenerating** `portable.json` (M1's negative `msig-pop-not-minimal` is re-signed over the typed digest; its rule and
  expectation unchanged; a second generator run gives no diff). New `ua8-soroban` items handed over: `kind_name` view
  (TS-D5), Soroban `register` / `set_kem_key` / `set_pqz_key` / `require_authorized` with explicit typed arguments
  (Part R's shapes as `contracttype` structs, TS-D12), the Soroban packed-`Bytes` inventory of X0 (TS-D17).

**Part R (registry explicit ABI, owner explicit-parameter rule; shapes: controller call)**

- **TS-D10 `msig` structure as typed members.** `struct MsigMember { uint16 kind; bytes32 id; uint16 weight; }`,
  `struct MsigStructure { uint16 threshold; MsigMember[] members; }`. `registerMsig(MsigStructure s, UAAttrs attrs,
  MemberSig[] pop, bytes pqzPop)` replaces `register(0x0120, keyData, …)`; the id stays `keccak256(TAG(msig) ‖ packed)`
  with the packed CTR-UA-09 layout **assembled by the registry** (ids and every digest byte-identical); `registrationOf`
  / `keyOf` keep returning the packed key data **and** a typed view `msigOf(bytes32 ua) → MsigStructure` is added.
- **TS-D11 KEM key explicit.** `struct KemKey { uint8 scheme; bytes mlkemEk; bytes32 x25519; }` (scheme-1: 1,568-byte
  ek); `UAAttrs { bytes pqzKey; bytes32 pqzPopHash; uint64 kemVersion; KemKey kem; }`; `setKemKey(bytes32 ua, uint64
  version, KemKey kem, UASig sig)`. The registry assembles `scheme ‖ ek ‖ x25519` (1,601 B) for storage and for
  `kemPkHash` (byte-identical digests); `kemKeyOf` / `kemKeyAt` return `KemKey`.
- **TS-D12 Signatures explicit.** `struct MemberSig { uint16 index; bytes keyData; bytes sig; }` (exists) is passed as
  `MemberSig[]`, never `abi.encode`d into `bytes`. `struct UASig { bytes keyData; bytes signature; MemberSig[] members; }`
  replaces the `bytes auth` = `abi.encode(keyData, sig)` blob of `requireAuthorized` and every `ua*` entry (native: only
  `signature`; derived single key: `keyData` (empty for stored kinds, CTR-UA-17/33) + `signature`; `msig`: only
  `members`). Kind-specific signature encodings that are one cryptographic object (a WebAuthn assertion, a BLS / Schnorr
  / MuSig2 / FROST signature, an ML-DSA / FN-DSA / SLH-DSA signature, a HIP-632 signature) stay one `bytes signature`
  (open question 3). External standards keep their ABI: ERC-1271 `isValidSignature(bytes32, bytes)`, Uniswap callbacks.
- **TS-D13 Single-key `keyData`.** A single public key (p256, ed25519, secp256k1, BLS, ML-DSA, …) is one cryptographic
  object and stays `bytes keyData`; X0 lists every kind whose key data bundles fields (candidates: `webauthn-p256`
  key ‖ rpIdHash ‖ originHash, MuSig2 / FROST prefix bytes) and gives each a typed struct, assembled to the same bytes.

**Part C (named typed entry points; controller calls unless marked)**

- **TS-D14 Named entries added beside the kept generic path (owner option B; owner ruling 2026-10-31 on the plan:
  keep `mtxExecute`, `mtxBatch`, `uaExecute`, `uaBatch`).** Every op that was allowlisted gets
  `mtx<Op>(MetaTxLib.Envelope e, <explicit op params>, bytes sig)` and, where it was UA-allowed,
  `ua<Op>(MetaTxLib.UAEnvelope e, <params>, UASig auth)`. `Envelope { address from; uint256 batch; uint256 nonce;
  uint256 validUntil; uint32 mode; address relayer; uint256 fee; address feeRecipient; }` (`UAEnvelope`: `bytes32 from`).
  Struct of op `<Op>`: `<Op>(address from,<op params>,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)`,
  UA twin `UA<Op>(bytes32 from,…)` (same canonical-zero rule for `relayer` / `feeRecipient` as today, `MetaTxLib.canon`).
  **Kept as they are (owner):** the four generic entries `mtxExecute`, `mtxBatch`, `uaExecute`, `uaBatch` with the
  `MetaTransaction` / `UAMetaTransaction` structs, typehashes, `mtxDigest` / `uaDigest`, `mtxSelectors`, `_mtxRule` and
  `_uaAllowed` (the generic path still serves every allowlisted op and atomic mixed batches, CTR-MTX-11). Clients and the
  node build the named typed entry by default and use the generic path only for a mixed batch or an op with no named
  entry. Controller call, owner may override: `executeMetaTransaction` (EIP-1776 alias) and `mtxExecuteWithFee` are
  removed (→ legacy) — they duplicate `mtxExecute`. The direct (non-meta) functions stay as they are. Mechanism: the
  named entry builds the op's call and runs the existing ticket self-call (`_selfCall`, as `uaUnwrap` does today), so the
  op bodies and `_msgSender()` semantics are unchanged; nonces are shared with the generic path (one `(from, batch)`
  lane, so the same op cannot be replayed through the other entry).
- **TS-D15 Batching.** `mtxBatch` / `uaBatch` stay (owner); `mtxBatchTransfer` / `uaBatchTransfer` stay. No typed
  mixed batch (EIP-712 arrays are homogeneous); a homogeneous `mtxBatch<Op>(Envelope[]…)` only for a named use case.
- **TS-D16 Entry names (controller call).** Entry = `mtx` / `ua` + struct name. Where the existing *operation* function
  already carries that name (the confidential ops `mtxShield`, `mtxConfidentialTransfer*`, `mtxUnshield*`, `mtxRollOver*`,
  `mtxSetRollOverMode`, `mtxPrepareAcc`, `mtxWrapShield`), the signed entry is an **overload** whose first parameter is
  `MetaTxLib.Envelope` (distinct selector; open question 2 offers renaming the direct ops instead). The wrap-by-signature
  entries `mtxWrap(address, TradeOrder, bytes)` / `uaWrap(…)` are renamed `mtxWrapOrder(WrapOrder o, bytes sig)` /
  `uaWrapOrder(UAWrapOrder o, UASig auth)` so `mtxWrap` is the named entry of `wrap(uint256)`.
- **TS-D17 Explicit parameters for the confidential ops (owner rule; shapes from X0).** Zether and PQZ `payload` blobs
  become typed structs (header words as typed fields; each curve point / ciphertext part a named fixed-size or `bytes`
  field; legs as `Leg[]`); the token assembles the **byte-identical** statement / payload bytes that the verifiers and
  pqz-stmt hash, and stores the same bytes (never lose ciphertext). The typed EIP-712 struct of the entry is the
  explicit parameter struct itself (nested EIP-712 types; `bytes` fields hashed by the EIP-712 rule) — so amounts are
  absent (encrypted), the real recipient is one of the legs, payload parts and `proof` appear as hashes.
- **TS-D18 Code size (owner rule; controller plan).** C0 measures before any bulk work: the per-entry cost of the
  pattern (thin external entry → shared internal helper → `MtxPipelineLib.preNamed` external) and the code freed by
  TS-D14's removals, projected per contract. If every runtime stays ≤ 65,536 B: pattern A everywhere. If one would
  exceed: **STOP**, report the table; the controller proposes, for that kind only, the confidential named entries in a
  stateless module behind the token's `fallback` (metatx-lib spike variant B′) or dropping envelope entries for ops
  whose authority is the proof / an inner signature (open question 4) — **the owner decides** (variant A was the
  owner's 2026-10-21 choice). The size gate runs in every Part C task.
- **TS-D19 Other typed structs (owner decisions 1 + 6; field sets: controller call).** Nested cancels
  `CancelOrder(TradeOrder order)`, `CancelUAOrder(UATradeOrder order)`, `CancelWrapOrder(WrapOrder order)`,
  `CancelUAWrapOrder(UAWrapOrder order)`, `CancelDexOrder(DexOrder order)` (the cancel nests the struct the order was
  signed in; the `pulled` key stays the order digest). `ReceiverFee(MetaTransfer payment,…)` / `UAReceiverFee(UAMetaTransfer
  payment,…)`. `WrapOrder` / `UAWrapOrder` = the 13 `TradeOrder` fields with `receiveToken → wrappedToken`,
  `receiveAmount → minMinted` and `dex` dropped; the underlying's `tradeOrderDigest` hashes an order with
  `dex == receiveToken` (only a wrap: the wrapped token pulls for itself) as `WrapOrder`, every other as `TradeOrder`.
  `RelayFee` / `UARelayFee` with a new token path `mtxRelayFee` / `uaRelayFee` (relayer = router, lane `payLane(ref)`,
  nonce 0 implicit, `ref = keccak256("scaas.relayfee" ‖ chainid ‖ target ‖ callDataHash)` = today's `relayRef`).
  `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)`. Zether owner ops `ZetherRollOver` /
  `ZetherSetRollOverMode` under the token domain. `PqzAuth` = `uint8 op` + the 20 statement header words verbatim +
  `bodyHash = keccak256(statement[640:])`.
- **TS-D20 PqzAuth is not a core change (controller call, owner may override).** The authority digest is computed by the
  token (`PqzCore._check`), e2e.py, `pqz_kat.py` and the `pqz-core/ffi` vector generator (`pqz-vectors.rs`
  `auth_digest`); no prover, verifier, statement or set parameter changes ⇒ the affected steps run, not the full
  pqz-core gate. The statement vectors' `auth_digest` field is regenerated (every other byte identical, `--check`).
- **TS-D21 Node job API explicit (owner rule).** Part N: one JSON object per operation with named fields (the typed
  struct's message + `signature` / `auth`), the node builds the calldata (EVM) / XDR (Soroban); hex `data` / `op.args` /
  `op.extra.call` blobs are retired from the API (the relay-fee `call` becomes the named target call object). Follows C.

## Review Focus (every task review reads these)

1. **Typehash string exactness:** each type string is pinned in Solidity (`test_*TypehashIsPinned`), clientkeys and the
   node; referenced types sorted by name; no space, no field order drift; `uint16 kind`, `uint64 version`, `uint8
   scheme`; `relayer` / `feeRecipient` canonical-zeroed when their mode bit is off (nested `MetaTransfer` too).
2. **Cross-language byte equality:** every reproducer reads the same vector rows (`portable.json`, `typed_ops.json`)
   and checks typehash, struct hash and digest; `hashTypedData(td)` of the JSON a wallet signs equals the contract's
   digest (MetaMask v4 rules: `bytes` / `string` hashed, nested structs hashed, arrays of structs hashed elementwise).
3. **No field left opaque that the owner wanted visible:** amounts / addresses / ids / `kind` / validity in their own
   fields; hashes only for cryptographic blobs; explicit parameters never re-pack several fields.
4. **Replay:** portable records replay on every chain by design (CTR-UA-07), bound by domain + struct type + `ua` +
   KEM `version` + content hashes; chain-bound structs keep chain id / verifying contract / salt in the domain and the
   lane nonce; cancels bind the full order; one accepted form per operation (no second digest accepted for the same op).
5. **Byte-identical statements:** a statement / payload assembled from explicit params equals the packed one byte for
   byte (old vs new KAT per op, per set); proofs verify unchanged.
6. **Size and gas:** size gate green per task; gas pins moved only with old → new figures in the commit; PQZH
   `n2048-kmax1024` debits still fit 2^24 regular gas on both relay paths.

---

## File Structure (main paths; tasks list the rest)

| Path | Responsibility |
|---|---|
| `smartcontracts/evm/src/ua/{UAKinds,UARegistry,IUARegistry}.sol` | P: typed portable digests, `kindName`, views; R: explicit ABI |
| `smartcontracts/evm/src/common/MetaTxLib.sol`, `src/metatx/{MetaTxBase,MtxPipelineLib,ERC20MetaTx,MetaTokenBase,NormalToken,WrappedToken,WrappedLib,MtxRelayFee,IMetaTx,IERC20MetaTx,IUALedger,IWrappedToken}.sol` | C: envelope structs, named entries, removals, receiver / relay fee |
| `smartcontracts/evm/src/zether/*`, `src/pqz/*` | C: Zether / PQZ named entries, explicit payload structs, owner ops, `PqzAuth` |
| `smartcontracts/evm/src/{wallet/MandateWallet,account/SmartKeyAccount}.sol` | C: wallet named entries, `Execute` |
| `smartcontracts/evm/src/{trade/TradeLib,trade/ITradeToken,dex/SCaaSDex,dex/ISCaaSDex}.sol` | C: nested cancels, `WrapOrder` |
| `smartcontracts/vectors/ua/*.json`, `smartcontracts/vectors/typed/typed_ops.json` (new) | vectors |
| `smartcontracts/soroban/contracts/{ua-registry,ua-common,token}/src/*` | P: Soroban alignment (TS-D8) |
| `clients/clientkeys/{src/ua.js,src/evm.js,src/zether.js,scripts/*.mjs,test/*}` | JS reference, typed-data builders, generators |
| `clients/{ua-rs,ua-c,ua-cxx,ua-qt,ua-cs,ua-py,ua-go,ua-dart,ua-dart-frb,zether-prover}` | reproducers |
| `scaas-node/src/{metatx,submit,guard,dex,dex/venue,gateway,abi,odoo}.rs`, `docs/node/job-api.md` | N |
| `smartcontracts/evm/script/{pqz/e2e.py,ZetherE2E.s.sol,DeployBase.sol}`, `smartcontracts/vectors/pqz/pqz_kat.py`, `pqz-core/ffi/src/bin/pqz-vectors.rs` | scripts, PQZ vectors |
| `docs/contracts/{accounts,metatx,token-wrappers,dex,mandates,zether,pq-zero-knowledge}.md`, `docs/clients/{signers-clientkeys,app}.md`, `docs/networks/README.md`, `docs/decisions.md`, `TODO.md` | D |
| `smartcontracts/evm/runs/2026-10-31-typed-signing-{p,c}-gates.sh` | G (on the base runner) |

## Setup (before P1)

- [ ] `git log --oneline -1` shows `9f88f43b` or later `main`; `git tag ref/pre-typed-signing HEAD`.
- [ ] Copy the vector files of TS-D7 to `smartcontracts/vectors/ua/legacy/typed-signing/` (+ README line) and the r33
  copies to `clients/zether-prover/vectors/legacy/typed-signing/` etc.; commit `typed-signing setup: legacy copies`.

## Order (≤ 3 agents at once)

| Wave | Tasks (parallel within a wave) | Depends on |
|---|---|---|
| 1 | **P1** (clientkeys + vectors) · **X0** (inventory + calldata, read-only + one measuring test) | Setup |
| 2 | **P2** (ua-rs + groups.json) · **P3** (EVM UAKinds / UARegistry / kindName) · **P4** (zether-prover + r33) | P1 |
| 3 | **P5** (Soroban alignment) · **P6** (ua-c, ua-cxx, ua-qt, ua-dart-frb) · **P7** (ua-py, ua-go, ua-cs, ua-dart) | P2 (P6), P1 (P5, P7) |
| 4 | **R1** (registry explicit ABI, EVM + JS + ua-rs) → **R2** (reproducers + Soroban test updates) · **P8** (e2e.py / helpers) | P3, X0 sign-off (R1) |
| 5 | **PD** (docs P + R) → **PG** (gates P + R) → **PRV** (review + fixes) → owner merge go → `ua8-soroban` merges `main` | all P, R |
| 6 | **C0** (size spike, pattern) | PRV, X0 sign-off |
| 7 | **C1** (clientkeys typed builders + `typed_ops.json`) · **C2** (base + public tokens) | C0 |
| 8 | **C3** (Zether) · **C4** (PQZ + PqzAuth) · **C5** (wallets) | C2 (shared bases); C1 (vectors) |
| 9 | **C6** (trade / DEX / receiver fee / relay fee / UA cancel) · **C7** (reproducers that build EVM digests) · **C8** (scripts, e2e, Deploy) | C2 (C6 shares `ERC20MetaTx` / `MetaTokenBase`); C1 (C7) |
| 10 | **N1** (node: job API, calldata builders, guard, dedup, indexer) → **N2** (Soroban explicit JSON) | C2–C6 |
| 11 | **CD** (docs C + N) → **CG** (gates) → **CRV** (review + fixes) | all |

Sequential because of shared files: P3 → R1 (`UARegistry`); C2 → C3 / C4 / C5 / C6 (`MetaTxBase`, `MtxPipelineLib`,
`ERC20MetaTx`, `MetaTokenBase`, `WrappedToken`); C3 and C4 touch different kinds but both `size-baseline.json` (each
updates only its rows; the later rebases). Never two forge-suite runs at once (one capped job each).

---

# Part P — portable typed records + `kindName`

### Task P1: clientkeys reference, typed-data builders, vectors

**Files:** Modify `clients/clientkeys/src/ua.js` (portable digests, member signing), `clients/clientkeys/src/evm.js`
(reuse `hashStruct` / `hashTypedData`), `clients/clientkeys/scripts/{ua-signers.mjs,ua-portable-vectors.mjs,ua-sig-vectors.mjs,ua-vectors.mjs}`,
`clients/clientkeys/test/{ua8.test.js,ua.test.js,ua-sig.test.js,pq-sig.test.js}`; regenerate
`smartcontracts/vectors/ua/{portable,signatures,pq_signatures,structures,kinds}.json` (each only if it moves);
legacy: `clients/clientkeys/legacy/typed-signing/ua-portable-raw.js` (the raw `portablePopDigest` / `registrationDigest`
/ `kemRecordDigest` / `pqzKeyDigest` / `pqzKeyRecordDigest` / `personalSignDigest` member path).

**Interfaces (produces):** `PORTABLE_DOMAIN`, `PORTABLE_TYPES`, `portableDomainSeparator()`;
`kemRecordStruct({ua, version, kemPk})`, `portableRecordStruct({ua, kind, pqzKeyHash, kem})`,
`portableTypedData(primaryType, message)` (the exact JSON for `eth_signTypedData_v4`: `{domain:{name,version}, types:{EIP712Domain:[name,version],…}, primaryType, message}`),
`registrationDigest(…)`, `portableRecordDigest(…)`, `kemRecordDigest(…)`, `pqzKeyDigest(…)`, `pqzKeyRecordDigest(…)`
(all typed, TS-D1/D3), `holderPopMessage` / `pqzRegMessage` / `kemRecordMessage` / `pqzKeyRecordMessage` with the same return shapes (fields renamed where they named the raw digests:
`portablePopDigest → portableRecordDigest`), `msig` member signing per TS-D4 (`nativeDigest = typedDigest`).
`portable.json` rows carry `typedData` (the JSON a native member signs) next to every digest.

- [ ] **Step 1: failing tests** (`ua8.test.js`): `portable domain separator is 0x9a2c…4ca1`, `portable typehashes pinned`
  (the five TS-D1 values), `typed digest equals hashTypedData(portableTypedData(…)) for every row`, `no-KEM record is
  {ua,0,0,0}`, `native EOA member signs the typed digest (ECDSA recovers the member)`, `personal_sign of md is refused by
  the reference verifier`, `zether PoP message (0x0141, no PQZ, no KEM)`, `kind field equals the row's kind`.
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test` — FAIL.
- [ ] **Step 3: implement**; regenerate (`node scripts/ua-portable-vectors.mjs`, `node scripts/ua-sig-vectors.mjs`,
  `node scripts/ua-vectors.mjs`); a second run gives no diff; `git diff --stat` of the vector files lists only PoP /
  digest / member-signature fields (report any other moved field before commit). New negatives in `portable.json`:
  `native-member-personal-sign` (old form, `UAPoP`), `record-kind-mismatch` (a pop over another `kind`, `UAPoP`),
  `kem-record-as-registration` (a KEM-record signature submitted as a `pop`, `UAPoP`).
- [ ] **Step 4:** Step 2 — PASS; `cd clients/ua-py && python3 -m unittest -v tests.test_vectors` shows the expected FAIL
  list (consumers not yet updated) — recorded in the report, not fixed here.
- [ ] **Step 5: commit** `typed-signing P1: clientkeys typed portable records (domain name+version), vectors regenerated`.

### Task P2: ua-rs + `groups.json`

**Files:** `clients/ua-rs/src/{ua8.rs,lib.rs}`, `clients/ua-rs/tests/{ua8.rs,vectors.rs,signatures.rs,groups.rs,groups_verify.rs}`;
regenerate `smartcontracts/vectors/ua/groups.json` (`cargo test --test groups` generator mode as in UA-8 A2); legacy:
`clients/ua-rs/legacy/typed-signing/portable_raw.rs` (not compiled).

**Interfaces:** `scaas_ua::ua8::{PORTABLE_DOMAIN_SEPARATOR, kem_record_hash, portable_record_hash, portable_record_digest,
registration_digest, kem_record_digest, pqz_key_digest, pqz_key_record_digest}` (typed); `holder_pop_message` etc. keep
signatures with renamed output fields; `member_sign` native path over the typed digest.

- [ ] Step 1: failing tests `ua8::portable_typehashes_pinned`, `ua8::domain_separator_pinned`, `ua8::portable_rows_typed`
  (every `portable.json` row: struct hashes, digests, messages), `groups::portable_pop_rows` (the group kinds' pops).
- [ ] Step 2: `cd clients/ua-rs && ../../scripts/capped cargo test -j2` — FAIL. Step 3: implement, regenerate
  `groups.json` (only PoP rows move). Step 4: `cargo test -j2` and `cargo test -j2 --features signers` — PASS.
- [ ] Step 5: commit `typed-signing P2: ua-rs typed portable digests, groups.json regenerated`.

### Task P3: EVM `UAKinds`, `UARegistry`, `IUARegistry`, `kindName`

**Files:** `smartcontracts/evm/src/ua/{UAKinds,UARegistry,IUARegistry}.sol`; tests `test/ua/{UAKinds.t.sol,UARegistryUA8.t.sol,UARegistryPq.t.sol,UARegistryUA6.t.sol,UARegistryPqzBound.t.sol,UAGas.t.sol}`,
`test/pqz/{PqzUA8.t.sol,UAPqzVerifier.t.sol,helpers/PqzRegistryBase.sol}`, `test/zether/ZetherDeploy.t.sol` (its PoP);
legacy: `smartcontracts/evm/legacy/typed-signing/UAKindsPortableRaw.sol` (the five raw digest functions + tags, not compiled).

**Interfaces:** `UAKinds`: `PORTABLE_DOMAIN_SEPARATOR` (constant, TS-D1 value), the five typehash constants,
`kemRecordHash(ua, version, kemPk)` (zero record when `version == 0`), `portableRecordHash(ua, kind, pqzKeyHash, kemHash)`,
`registrationHash(recordHash, pqzPopHash)`, `pqzKeyHash_(ua, pqzKeyHash)` / `pqzKeyRecordHash(…)` (struct hashes) and
`portableDigest(structHash) = keccak256(0x1901 ‖ DS_P ‖ structHash)`. `UARegistry`: `_attrs` returns the record's struct
hash (needs `kind`), `_consent` / `_pqzAttach` / `storePqzPop` (kind from `kindOf(ua)`, gen-1 host included) /
`setKemKey` / `setPqzKey` / `_kemHash` use them; `_msig` passes the typed digest to `_memberOk`; `_nativePortable(a,
digest, sig) = _byCode(a, digest, digest, sig)` (no EIP-191); TS-D6 views; `kindName` (TS-D5).

- [ ] **Step 1: failing tests:** `test_portableTypehashesPinned`, `test_portableDomainSeparatorPinned`,
  `test_portableRecordDigestVectors` / `test_registrationDigestVectors` / `test_kemRecordDigestVectors` /
  `test_pqzKeyRecordDigestVectors` (rename of the UA-8 tests, now typed), `test_ua8_everyKindFromVectors` (all rows of
  the regenerated `portable.json`), `test_msigNativeMemberTypedDigest` (EOA member signs `typedDigest`),
  `test_msigNativeMemberPersonalSignRefused`, `test_msigContractMember1271OverTypedDigest`,
  `test_storePqzPopGen2HostKindFromGen1`, `test_kindNameEveryKind` (every id of `kinds.json` → its name),
  `test_kindNameUnknownReverts` (`UAKindUnknown(0x0109)`), `test_noKemRecordIsZeroRecord`.
- [ ] Step 2: `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/ua/*'` — FAIL.
- [ ] Step 3: implement. Step 4: the UA + PQZ test paths — PASS; whole suite at the default set
  (`n2304-kmax4096`) then the four sets via the round runner `--only forge-<set>`; `sizes` step (UARegistry row
  re-recorded); re-pin moved `UAGas.t.sol` rows (old → new in the commit message). Stop rule: a moved `debit_min_gas`
  pin in `UARegistryPqzBound.t.sol` ⇒ report, do not re-pin.
- [ ] Step 5: commit `typed-signing P3: UARegistry typed portable digests, native msig members sign the typed record, kindName`.

### Task P4: zether-prover portable PoP + `r33_keys.json`

**Files:** `clients/zether-prover/src/{schnorr.rs,api.rs,vectors.rs}`, `tests/r33_keys.rs`; regenerate
`vectors/r33_keys.json` and copy to `clients/clientkeys/test/vectors/r33_keys.json`,
`smartcontracts/evm/test/vectors/zether/s3/r33_keys.json`.

- [ ] Step 1: failing `r33_keys::pop_over_typed_registration` (the TS-D3 Zether row), `schnorr::zether_registration_digest_pinned`
  (cross-checked against `portable.json`'s zether row). Step 2: `cd clients/zether-prover && ../../scripts/capped cargo test -j2` — FAIL.
- [ ] Step 3: implement (`zether_registration_digest(ua)` = the typed digest); regenerate + copy; `clientkeys`
  `zether.test.js` and forge `ZetherDeploy` read the copies. Step 4: zether-prover tests + `wasm-zether-prover` build — PASS.
- [ ] Step 5: commit `typed-signing P4: zether-prover typed portable PoP, r33_keys.json regenerated`.

### Task P5: Soroban alignment (TS-D8)

**Files:** `smartcontracts/soroban/contracts/ua-registry/src/{digest.rs,lib.rs,verify.rs,test.rs,test_verify.rs}`,
`contracts/ua-common/src/lib.rs`, `contracts/token/src/test_ua.rs`.

- [ ] Step 1: failing tests `digest::portable_typehashes_pinned`, `digest::domain_separator_pinned`,
  `register_rows_from_portable_json` (existing test now over typed rows), `msig_evm_eoa_member_typed_digest`,
  `msig_evm_eoa_personal_sign_refused`. Step 2: `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-ua-registry` — FAIL.
- [ ] Step 3: implement (`register` passes `kind`; `check_msig` portable `evm-eoa` = secp256k1 recover over the typed
  digest). No new entry points (B1 adds the rest). Step 4: `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] Step 5: commit `typed-signing P5: Soroban ua-registry typed portable digests (register path), evm-eoa member typed`.

### Task P6: ua-rs wrappers — ua-c, ua-cxx, ua-qt, ua-dart-frb

**Files:** `clients/ua-c/{src/lib.rs,include/scaas_ua.h,tests/test_vectors.py}`, `clients/ua-cxx/{src/lib.rs,src/scaas_ua.cpp,include/scaas_ua.hpp,tests/vectors_test.cpp}`,
`clients/ua-qt/{src/ua_kinds.rs,tests/tst_ua.qml}`, `clients/ua-dart-frb/{rust/src/api/ua.rs,lib/src/rust/api/ua.dart,test/vectors_test.dart}`
(+ regenerated `frb_generated.*`); each package's `legacy/typed-signing/` for removed exports; ABI version bump in ua-c.

- [ ] Step 1: each package's vector test over the regenerated `portable.json` — FAIL. Step 2: the base runner's steps
  `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb` — FAIL. Step 3: implement (renamed exports per TS-D6; new `kindName` export
  where the package exposes registry views). Step 4: same steps — PASS (each builds before it tests).
- [ ] Step 5: commit `typed-signing P6: ua-c / ua-cxx / ua-qt / ua-dart-frb typed portable digests`.

### Task P7: native reproducers — ua-py, ua-go, ua-cs, ua-dart

**Files:** `clients/ua-py/{scaas_ua/__init__.py,tests/test_vectors.py}`, `clients/ua-go/{ua.go,ua_test.go}`,
`clients/ua-cs/{Scaas.Ua/Ua.cs,Scaas.Ua.Tests/VectorTests.cs}`, `clients/ua-dart/{lib/src/ua.dart,test/vectors_test.dart}`;
`legacy/typed-signing/` per package.

- [ ] Step 1: vector tests (typehashes, DS_P, every `portable.json` row) — FAIL. Step 2: steps `ua-py`, `ua-go`, `ua-cs`
  (then `dotnet build-server shutdown`), `ua-dart` — FAIL. Step 3: implement (a small generic `hashStruct` over 32-byte
  words is enough: every portable field is a word or a nested struct hash). Step 4: PASS.
- [ ] Step 5: commit `typed-signing P7: ua-py / ua-go / ua-cs / ua-dart typed portable digests`.

### Task P8: scripts and helpers

**Files:** `smartcontracts/evm/script/pqz/e2e.py` (`_PORTABLE_JS` calls the renamed clientkeys functions; `kind`
passed), `smartcontracts/evm/script/ZetherE2E.s.sol` (if it builds a PoP), `test/pqz/helpers/PqzRegistryBase.sol`
(portable R_REG message helper uses `UAKinds`), `smartcontracts/near` / `algorand` — none (no registry).

- [ ] Step 1: `python3 -I smartcontracts/evm/script/pqz/e2e.py --self-test` (or its dry mode; else a unit check of
  `portable()` against `portable.json`) — FAIL. Step 3: implement. Step 4: PASS; forge PQZ tests that use the helper — PASS.
- [ ] Step 5: commit `typed-signing P8: e2e.py and test helpers on the typed portable messages`.

---

# Part X0 — explicit-parameter inventory and calldata measurement (gates R1 and Part C)

### Task X0: inventory every packed blob, give each a typed signature, measure calldata

**Done 2026-10-31:** results in [2026-10-31-typed-signing-appendix-x.md](2026-10-31-typed-signing-appendix-x.md) (Appendix X:
typed structs, exact entries and EIP-712 strings, the 22-row inventory, calldata per set and path; test
`smartcontracts/evm/test/v2/ExplicitParamsCalldata.t.sol`, logs `smartcontracts/evm/runs/2026-10-31-typed-signing-x0-calldata-*.txt`).

**Files:** append **Appendix X** to this plan (the table below completed, exact Solidity signatures and EIP-712 type
strings for every confidential op); add `smartcontracts/evm/test/v2/ExplicitParamsCalldata.t.sol` (measurement only) and
its run log `smartcontracts/evm/runs/2026-10-31-typed-signing-x0-calldata-<set>.txt`.

First-pass inventory (controller, 2026-10-31; X0 verifies it against `smartcontracts/evm/src` — multi-line signatures
included — and adds what is missing):

| # | Where | Blob today | Explicit form (proposal) | Digest / statement |
|---|---|---|---|---|
| 1 | Zether `mtxConfidentialTransferSingle` | `payload = be32 accSeq ‖ be32 sendCounter ‖ be32 validUntilBlock ‖ salt16 ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud` | `ZetherSingle { uint64 accSeq; uint64 sendCounter; uint64 validUntilBlock; bytes16 salt; G1 from; G1 to; G1 cOut; G1 dOut; G1 cDeb; G1 cAud; }`, `G1` = the token curve's point as a fixed-size static type (X0 picks: `bytes32[k]` or a struct of words) | statement assembled byte-identical |
| 2 | Zether `mtxConfidentialTransfer` / `…Compact` | multi payload (`… ‖ be32 M ‖ be32 decoyFee ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j)_j [‖ memo 17 + 40·M]`) | `ZetherMulti { …header…; uint256 decoyFee; G1 from; G1 dOut; G1 cDeb; ZetherLeg[] legs; }`, `ZetherLeg { G1 to; G1 cOut; G1 cAud; G1 dAud; }`, memo: `ZetherMemo { bytes16 salt; …per-leg fields… }` (X0 decodes the 17 + 40·M layout) | byte-identical; memo hash unchanged |
| 3 | Zether `mtxUnshield`, `mtxUnshieldUnwrap` | `payload = be32 accSeq ‖ be32 sendCounter ‖ be32 validUntilBlock ‖ Y_f` (+ `Unwrap x` struct, already typed) | `ZetherBurn { uint64 accSeq; uint64 sendCounter; uint64 validUntilBlock; G1 from; }` + `amount`, `recipient` | byte-identical |
| 4 | Zether ops `auth`, `accHint` (always empty) | `bytes` | dropped from the Zether entries (they are PQZ's); the direct functions keep the shared interface only if `IConfidentialToken` requires it (X0 decides; TS-D17) | — |
| 5 | PQZ transfer / single / compact / single-compact | `payload = p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ toUA ‖ beneficiaryUA ‖ salt16 ‖ out(u ‖ v_t ‖ v_f ‖ v_a)` | `PqzTransferArgs { uint64 p; uint64 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 toUA; bytes32 beneficiaryUA; bytes16 salt; bytes u; bytes vTo; bytes vFrom; bytes vAuditor; }` | header + body byte-identical |
| 6 | PQZ op 7 (multi) | `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ beneficiaryUA ‖ M ‖ decoyFee ‖ salt16 ‖ legUAs ‖ u_0…u_{G−1} ‖ (v_j ‖ [v_aj])_j` | `PqzMultiArgs { …header…; uint256 decoyFee; bytes32[] legs; bytes[] u; PqzLegCt[] out; }`, `PqzLegCt { bytes v; bytes vAuditor; }` | byte-identical |
| 7 | PQZ burn / unshield / unshield-unwrap | `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ beneficiaryUA ‖ u' ‖ v_f` | `PqzBurnArgs { uint64 p; uint64 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 beneficiaryUA; bytes u; bytes vFrom; }` | byte-identical |
| 8 | PQZ `accHint` | packed hint | typed struct of its fields (X0 decodes `PqzLayer` / `PqzStateLib`) | — |
| 9 | every `ua*` / `requireAuthorized` `bytes auth` | `abi.encode(bytes keyData, bytes sig)` / `abi.encode(MemberSig[])` / raw native sig | `UASig` (TS-D12) | digests unchanged |
| 10 | `register(kind, keyData, attrs, pop, pqzPop)` for `msig`; `pop` of a PQ-eligible msig | packed CTR-UA-09 structure; `abi.encode(MemberSig[])` | `registerMsig(MsigStructure, UAAttrs, MemberSig[], bytes pqzPop)` (TS-D10) | id + digests byte-identical |
| 11 | `UAAttrs.kemPk`, `setKemKey(…, kemPk, sig)` | `scheme ‖ ek ‖ x25519` | `KemKey` (TS-D11) | byte-identical |
| 12 | single-key `keyData` with several fields | e.g. `webauthn-p256` (x ‖ y ‖ rpIdHash ‖ originHash?), MuSig2 / FROST prefix bytes | typed per kind (TS-D13), X0 lists | ids byte-identical |
| 13 | SmartKeyAccount signature for its own entries (`accountSignature(keyIndex, proof, inner)`) | packed / encoded | `AccountSig { uint256 keyIndex; bytes32[] proof; bytes signature; }` on `mtx*` entries; ERC-1271 `isValidSignature(bytes32, bytes)` keeps `bytes` (standard) | — |
| 14 | `mtxPayMeta(…, bytes meta)`, `metaPayId(salt, meta)` | `encodeMeta(schema, body)` | `PayMeta { bytes32 schema; bytes body; }` if `meta` bundles fields (X0 reads `evm.js` `encodeMeta`) | `payId` byte-identical |
| 15 | factory / token / DEX `initialize(…, bytes initArgs)`, `createDex(…, initArgs, …)` | `abi.encode(<config>)` | the config struct as the parameter | — |
| 16 | `MtxRelayFee.relay(target, callData, …)`, DEX `mtx*Via(plan, executor, data)` | the target / executor call | stays `bytes callData` / `bytes data` as its own named parameter (owner rule) | — |
| 17 | Hedera `mtxExecuteAsOwnerRaw` | HIP-632 | X0 checks for bundled fields | — |
| 18 | views returning packed records (`transferEntry`, `pqzEntryBlob`, `registrationOf` blob parts) | packed | typed view structs where the blob bundles fields (read side, same rule) | — |
| 19 | Soroban (`ua-registry`, `token`, mandate / DEX contracts) | `key_data: Bytes` (msig), `pop: Bytes`, `auth: Bytes` (and any other) | typed `contracttype` structs — **handed to `ua8-soroban`** (registry) and the later Soroban rounds | — |

- [ ] **Step 1:** grep every `external` / `public` function (and interface) in `smartcontracts/evm/src` with a `bytes`
  parameter or a `bytes` struct field, open each decoder (`ZetherLib`, `PqzCore`, `PqzLayer`, `PqzStateLib`,
  `UARegistry`, `UAKinds.validateKeyData`, `SmartKeyAccount`, `MetaTokenBase`, factories, DEX); classify:
  *bundles fields* / *one crypto object* / *a call* / *external standard*. Complete the table; every row gets the exact
  Solidity signature, the EIP-712 type string of its entry (Part C) and the assembly rule back to today's bytes.
- [ ] **Step 2: calldata measurement** (`ExplicitParamsCalldata.t.sol`, no contract change): ABI-encode each op's
  explicit form next to today's packed form (vectors from `smartcontracts/vectors/pqz/` and the Zether e2e rows), count
  bytes / zero bytes / EIP-7623 + EIP-7976 floor tokens, per set (`n2048-kmax1024` … `n2816-kmax65536`) and per relay
  path (`mtx*` entry vs `ua*` entry with `UASig`), and print the remaining regular-gas headroom against 2^24 using the
  pinned rows of `pq-zero-knowledge.md` "Findings for the owner" (3). **Flag** every form whose headroom goes negative;
  the PQZH `n2048-kmax1024` debits on the UA path (0.09–0.18 M today, 1,361–2,769 B) are the expected tight spot
  (`bytes[]` per leg adds ≈ 64–96 B per element). For a flagged form, X0 proposes a static-size encoding (fixed-length
  arrays, `bytesN` words) before any packed fallback; a packed fallback is the **owner's** call.
- [ ] **Step 3: Soroban inventory** (read-only): list every `Bytes` argument of the Soroban contracts that bundles
  fields (TS-D9 hand-over list for `ua8-soroban`; NEAR / Algorand: a NET-ALL-84 note, no code).
- [ ] **Step 4: controller sign-off** of Appendix X (the controller may ask the owner on any flagged row); commit
  `typed-signing X0: explicit-parameter inventory and calldata measurement`.

---

# Part R — registry explicit ABI (before `ua8-soroban` resumes)

### Task R1: `UARegistry` explicit ABI (EVM + clientkeys + ua-rs)

**Files:** `smartcontracts/evm/src/ua/{UARegistry,IUARegistry,UAKinds}.sol`, every caller of `requireAuthorized` /
`bytes auth` that is the registry interface (`MtxPipelineLib._authorize`, `ZetherLib._requireOwner`, `PqzCore._check`
— they forward `UASig` unchanged), tests under `test/ua/`, `test/pqz/`, `test/zether/` that build `auth`;
`clients/clientkeys/src/ua.js` + generators, `clients/ua-rs/src/{lib.rs,ua8.rs}`; `portable.json` / `signatures.json`
gain the typed argument form (`registration.args`) next to the bytes; legacy copies of the old entry ABIs.

**Interfaces:** TS-D10–D13; `register(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop)` for single
keys (with `UAAttrs.kem` a `KemKey`), `registerMsig(…)`, `setKemKey(bytes32, uint64, KemKey, UASig)`,
`setPqzKey(bytes32, bytes pqzKey, bytes32 pqzPopHash, UASig)`, `requireAuthorized(bytes32, bytes32, bytes32, UASig)`,
`msigOf`, `kemKeyOf` / `kemKeyAt` → `KemKey`. The token-side `ua*` entries change their `bytes auth` to `UASig` in
Part C (one move per entry); until then `MtxPipelineLib` decodes the old blob into `UASig` (one helper, removed in C2).

- [ ] Step 1: failing tests `test_registerMsigTypedMembersSameId` (id equals the packed-keyData id of every `msig` row),
  `test_kemKeyAssembledBytes`, `test_requireAuthorizedUASigEveryKind` (`signatures.json` rows), `test_msigOfRoundTrip`,
  `test_registrationOfUnchangedBytes`; clientkeys `register args typed`, ua-rs `registration_args_typed`.
- [ ] Step 2–4: FAIL → implement → `test/ua`, `test/pqz`, `test/zether`, `test/metatx` paths PASS; whole suite at the
  default set; `sizes`; gas pins (old → new).
- [ ] Step 5: commit `typed-signing R1: UARegistry explicit ABI (registerMsig, KemKey, UASig, MemberSig[])`.

### Task R2: reproducers + Soroban tests on the typed registry arguments

**Files:** the P6 / P7 packages (argument builders where they build `register` / `setKemKey` calls), Soroban tests that
read the EVM argument form (`registration.args`), `smartcontracts/evm/script/pqz/e2e.py` (`REGISTER` signature,
`setKemKey`, `storePqzPop` calls).

- [ ] Steps: failing builder tests per package → implement → package steps PASS → commit
  `typed-signing R2: reproducers and scripts build the typed registry arguments`.

### Task PD: docs of Parts P + R

**Files:** `docs/contracts/accounts.md` (§1.4, §1.8, CTR-UA-07, -09, -16, -17, -24, -32, -33 text; new **CTR-UA-35**
`kindName` and **CTR-UA-36** registry explicit ABI — CTR-UA-34 is reserved by `ua8-soroban` B8; re-check the next free
ids at the time), `docs/clients/signers-clientkeys.md` (CLI-SGN-27 text: the portable typed data; new **CLI-SGN-41**
portable typed-data builders), `docs/clients/app.md` (CLI-APP-09: the review renders the typed record and the kind name),
`docs/networks/README.md` (NET-ALL-84 row: typed portable digests byte-identical, `kind_name` view, explicit registry
arguments — every family's UA round), `docs/decisions.md` (Change entries below + TS-D1–D13 in the alias index),
TODO.md (2d progress; `ua8-soroban` hand-over items), this plan's status line.

Change entries (in full, "Change (2026-10-31, owner …/controller call …): …. Status: built in typed-signing <task>"):
CTR-UA-07 (portable PoP digests typed: TS-D1–D3; supersedes the UA8-D1 encoding and ruling C7's `personal_sign`),
CTR-UA-16 (PQZ key record typed), CTR-UA-32 (KEM record typed + `KemKey`), CTR-UA-33 (msig members: native typed / 1271
over the typed digest; `MemberSig[]` explicit), CTR-UA-24 (unchanged chain-bound native rule, cross-reference),
CTR-UA-35 (kindName), CTR-UA-36 (explicit registry ABI), CLI-SGN-27 / CLI-SGN-41, CLI-APP-09, NET-ALL-84.

- [ ] `python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check` — PASS; commit `typed-signing PD: docs and decisions (Parts P, R)`.

### Task PG / PRV: gates and review of P + R

- [ ] Runner `smartcontracts/evm/runs/2026-10-31-typed-signing-p-gates.sh` on the base runner (UA-8 pattern):
  `STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys ua-rs ua-rs-signers ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb soroban vectors-check named-tests"`
  with a new step `vectors-check` (each generator run twice, `git diff --exit-code` on the vector files) and
  `NEW_TESTS` listing every test added in P1–P8, R1–R2.
- [ ] PRV: whole-branch review (focus 1, 2, 4; TS-D4 member paths; `storePqzPop` on a gen-2 host), fix wave, re-run
  the touched steps; report to the controller → **owner's merge go** → merge to `main`; notify `ua8-soroban` (TS-D9).

---

# Part C — named typed entry points (EVM contracts)

Static operations (exact; `E` = `uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient`;
typehashes computed with cast 1.8.5 for these exact strings, re-pinned by C1 / C2):

| Entry (`mtx` / `ua`) | Contract | Struct type string | typehash |
|---|---|---|---|
| `mtxCancelNonce` | every `MetaTxBase` | `CancelNonce(address from,uint256 lane,E)` | `0x77d6b4d4…f857dbf4bc` |
| `mtxBurn` / `uaBurn` | `NormalToken` | `Burn(address from,uint256 amount,E)` / `UABurn(bytes32 from,…)` | `0x89bf2320…a925bbf925` / `0xeed13c9a…fe9238f540` |
| `mtxWrap` | `WrappedToken` | `Wrap(address from,uint256 amount,E)` | `0xd2fe0a6e…b2adac31` |
| `mtxWrapLeg` | `WrappedToken` | `WrapLeg(address from,address underlying,uint256 amount,E)` | `0x5846a8b8…46912147` |
| `mtxUnwrap` / `uaUnwrap` | `WrappedToken` | `Unwrap(address from,uint256 wrapped,address recipient,uint256 minOut,E)` / `UAUnwrap` | `0x7272e86d…4f4af742` / `0x914311a4…84d3aa93` |
| `mtxUnwrapLeg` / `uaUnwrapLeg` | `WrappedToken` | `UnwrapLeg(address from,address underlying,uint256 wrapped,address recipient,uint256 minOut,E)` / `UAUnwrapLeg` | `0xaccc7271…0c972a58e2` / `0xdbbb5d3f…f7cc1a48` |
| `mtxAddReserve` | `WrappedToken` | `AddReserve(address from,address underlying,uint256 amount,E)` | `0x189280a9…a2162dfe` |
| `mtxWrapToUA` | `WrappedToken` | `WrapToUA(address from,address underlying,uint256 amount,bytes32 to,E)` | `0x3a2ec74d…25895dcde` |
| `mtxUnwrapToUA` / `uaUnwrapToUA` | `WrappedToken` | `UnwrapToUA(address from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,E)` / `UAUnwrapToUA` | `0x9df2319a…1cdb4732` / `0x8bb1bc05…af2d9a04` |
| `mtxShield` / `uaShield` (overload) | Zether, PQZ | `Shield(address from,bytes32 toUA,uint256 amount,E)` / `UAShield` | `0x60bd57f6…3d165ad` / `0xf86740a1…efb08337` |
| `mtxWrapShield` (overload) | Wrapped Zether, Wrapped PQZ | `WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,E)` | `0x9188b9d0…b011ef` |
| `mtxRollOver` / `uaRollOver` (overload) | Zether, PQZ | `RollOver(address from,bytes32 ua,uint256 n,E)` / `UARollOver` | `0xcd3e09a9…5e9df` / `0xd5ad0bcf…0465fd` |
| `mtxPrepareAcc` / `uaPrepareAcc` (overload) | PQZ | `PrepareAcc(address from,bytes32 ua,uint256 half,E)` / `UAPrepareAcc` | `0xf3726703…b16834` / `0x33e99b3c…c460e5` |
| `mtxSetMandate` | `MandateWallet` | `SetMandate(address from,address token,address delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,E)` | `0x826b6b56…df746275` |
| `mtxSetPayee` | `MandateWallet` | `SetPayee(address from,address token,address payee,bool allowed,E)` | `0x0c9b1692…fa8a5985` |
| `mtxRevokeMandate` | `MandateWallet` (owner `revoke(address)`) | `RevokeMandate(address from,address token,E)` | `0x4e4e4b87…c4f9d14` |
| `mtxPayUnderMandate` | `MandateWallet` (delegate) | `PayUnderMandate(address from,address token,address payee,uint256 amount,bytes32 entryRef,uint64 epoch,E)` | `0xe68ac74c…f2d82acf` |
| `mtxDelegateRevoke` | `MandateWallet` (`revoke(address,uint64)`) | `DelegateRevoke(address from,address token,uint64 epoch,E)` | `0xd36a49f4…8d1983f9da` |
| `mtxAddKey` | `SmartKeyAccount` | `AddKey(address from,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,E)` (SubjectKey flattened) | `0x9d156f1f…7244a6bb` |
| `mtxRemoveKey` | `SmartKeyAccount` | `RemoveKey(address from,uint256 index,E)` | `0xcef46d27…618280b3` |
| `mtxRotateKey` | `SmartKeyAccount` | `RotateKey(address from,uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,E)` | `0x5b8f8761…64fb0777` |
| `mtxSetGuardian` | `SmartKeyAccount` | `SetGuardian(address from,address guardian,E)` | `0xd2603850…6b967689f6` |
| `mtxCancelRecovery` | `SmartKeyAccount` | `CancelRecovery(address from,E)` | `0x3df995dd…1213adda` |
| `mtxExecute` | `SmartKeyAccount`, `MandateWallet` | `Execute(address from,address target,uint256 value,bytes data,E)` — the wallet shows target and value; the inner `data` stays hex (it is an arbitrary call by nature) | C5 pins |

Other typed structs (exact):

| Struct | Type string | typehash |
|---|---|---|
| `ReceiverFee` | `ReceiverFee(MetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)MetaTransfer(…today's 11 fields…)` | `0x7c08a6ca…28232305` |
| `UAReceiverFee` | `UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)UAMetaTransfer(…)` | `0xb12d2a08…7c75021a` |
| `RelayFee` | `RelayFee(address from,address target,bytes32 callDataHash,address payee,uint256 value,uint256 validUntil,address relayer)` | `0x8018f06a…302b7909f` |
| `UARelayFee` | `UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 validUntil,address relayer)` | `0x77fa32c7…cd3eb54d` |
| `WrapOrder` | `WrapOrder(address from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)` | `0x07a267c8…29eb6555` |
| `UAWrapOrder` | same with `bytes32 from`, `bytes32 destination` | `0x2a01cb57…fc04533c` |
| `CancelOrder` | `CancelOrder(TradeOrder order)TradeOrder(…)` | `0x29879342…42e789a5` |
| `CancelUAOrder` | `CancelUAOrder(UATradeOrder order)UATradeOrder(…)` | `0x47eb46c7…a1eaeba` |
| `CancelWrapOrder` | `CancelWrapOrder(WrapOrder order)WrapOrder(…)` | `0xf2691001…e9ae399` |
| `CancelUAWrapOrder` | `CancelUAWrapOrder(UAWrapOrder order)UAWrapOrder(…)` | `0x7679e176…2326d9d` |
| `CancelDexOrder` | `CancelDexOrder(DexOrder order)DexOrder(address sellToken,TradeOrder order)TradeOrder(…)` | `0xcc35e105…f433c6` |
| `UACancelNonce` | `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)` (purpose `metatx-cancel`, token domain) | `0xf5d81494…5ca227` |
| `ZetherRollOver` | `ZetherRollOver(bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock)` (purpose `zether-owner`) | `0x52e2c8f8…71768b1e` |
| `ZetherSetRollOverMode` | `ZetherSetRollOverMode(bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock)` | `0x5f5a4ffa…4d55e09d` |
| `PqzAuth` | `PqzAuth(uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,bytes32 to,bytes32 beneficiary,uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,bool auditorOn,uint256 shieldIn,bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash)` (purpose `zether-auth`, PQZ token domain) | `0x380b0de6…42644e6f` |

The full 32-byte typehashes are in `typed_ops.json` (C1) and pinned by tests; the truncated values above are for review.
Confidential envelope structs (`ZetherTransfer`, `ZetherTransferCompact`, `ZetherTransferSingle`, `ZetherUnshield`,
`ZetherUnshieldUnwrap`, `RollOverBatch`, `RollOverSigned`, `SetRollOverMode`, `PqzTransfer`, `PqzTransferCompact`,
`PqzTransferSingle`, `PqzTransferSingleCompact`, `PqzUnshield`, `PqzUnshieldUnwrap` and UA twins) = `<Name>(address from,
<the X0 explicit parameter struct(s)>,bytes32 beneficiary,…,bytes proof,E)<nested types>`: exact strings in Appendix X.
Names: the envelope field `mode` collides with the Zether roll-over mode ⇒ that field is `rollOverMode`; the inner
owner signature field is `ownerSig`; `CancelNonce`'s cancelled lane is `lane` (the envelope's own `batch` is the lane
of the cancel itself).

Kept unchanged: `MetaTransfer`, `UAMetaTransfer`, `TradeOrder`, `UATradeOrder`, `DexOrder`, `InvalidateNonces`,
`UAInvalidateNonces`, `UAAuth` (registry native rule), every domain (names, version "1", chain id, verifying contract,
salt = chain uid).

### Task C0: size spike and the entry pattern

**Files:** `smartcontracts/evm/src/common/MetaTxLib.sol` (`Envelope`, `UAEnvelope`), `src/metatx/MtxPipelineLib.sol`
(`preNamed(Ctx, bytes32 typehash, Envelope/UAEnvelope, bytes args, CallFacts, bool ua, UASig/bytes sig)`: struct hash
`keccak256(typehash ‖ from ‖ args ‖ batch ‖ nonce ‖ validUntil ‖ mode ‖ canon(relayer) ‖ fee ‖ canon(feeRecipient))`
with every envelope word ABI-encoded — never `encodePacked` on `uint32 mode`), `src/metatx/MetaTxBase.sol`
(`_named(…)` helper: pre → `_selfCall` → fee → event); the entries for **one** op per kind (`mtxUnwrap` on
`WrappedToken`, `mtxShield` on `WrappedPqzToken` and `WrappedZetherToken`, `mtxSetMandate`), the generic entries kept
(owner 2026-10-31: nothing is freed, so the projection counts only added bytes); run log `runs/2026-10-31-typed-signing-c0-sizes.txt`.

- [ ] Step 1: tests `test_c0_unwrapTyped` (a wallet-made `Unwrap` signature executes; the same op through the kept
  `mtxExecute` still executes and shares the `(from, batch)` nonce lane, so one signature cannot run twice), `test_c0_shieldTyped` (PQZ, Zether), `test_c0_setMandateTyped`.
- [ ] Step 2: `forge build --sizes`; record per contract: entry cost (bytes per `mtx` / `ua` entry), freed bytes, and a
  projection for the full Part C entry list (C2–C6 counts: `WrappedPqzToken` ≈ 18 `mtx` + 11 `ua` entries,
  `WrappedZetherToken` ≈ 19 + 13, `NormalToken` 2 + 1, …).
- [ ] Step 3: **decision gate (TS-D18):** every projected runtime ≤ 65,536 B ⇒ continue with pattern A; else STOP and
  report to the controller (owner decides B′ / dropping proof-authorised envelope entries).
- [ ] Step 4: commit `typed-signing C0: named-entry pattern and size projection` (the spike code is kept as the start
  of C2–C5).

### Task C1: clientkeys typed builders + `typed_ops.json`

**Files:** `clients/clientkeys/src/evm.js` (one `<op>TypedData({domain…, message})` + `<op>Calldata(td, sig)` per named
entry, built from one table of type strings; `checkCall` → `checkOp(td, expectations)` per struct family (CLI-SGN-27:
check then sign exactly what was checked); `receiverFeeTypedData` nested; `cancelOrderTypedData` nested;
`buildRelayFee` → `RelayFee`; `ownerCallTypedData` → the SmartKeyAccount structs; the `MetaTransaction` builders →
legacy), `clients/clientkeys/src/zether.js` (`ZetherRollOver` / `ZetherSetRollOverMode` digests, confidential
envelope builders from the explicit structs), new `clients/clientkeys/scripts/typed-ops-vectors.mjs` →
`smartcontracts/vectors/typed/typed_ops.json` (per struct: `typeString`, `typehash`, a domain per contract kind, a
message, `structHash`, `digest`, the entry's calldata, a native ECDSA signature), regenerate `metatx3.json` /
`uatrade_kat.json` via `ua-sig-vectors.mjs` (the UA ops / cancels move); tests `test/{evm,relayfee,paymeta,ua-metatx3,ua-trade,zether}.test.js`.

- [ ] Step 1: failing tests: `every typehash pinned`, `hashTypedData(td) == row.digest`, `calldata decodes to the
  message`, `checkOp refuses a changed field`, `nested cancel / receiver fee`, `canonical zero for unbound relayer`.
- [ ] Steps 2–4: FAIL → implement → `npm test` PASS; generators twice, no diff. Step 5: commit
  `typed-signing C1: clientkeys typed builders for every named entry, typed_ops.json`.

### Task C2: base + public tokens

**Files:** `MetaTxLib.sol`, `MetaTxBase.sol`, `MtxPipelineLib.sol`, `ERC20MetaTx.sol`, `MetaTokenBase.sol`,
`NormalToken.sol`, `WrappedToken.sol`, `IMetaTx.sol`, `IERC20MetaTx.sol`, `IUALedger.sol`, `IWrappedToken.sol`
(ERC-165 ids re-pinned); the `ua*` entries take `UASig` (removes R1's decode helper); legacy
`smartcontracts/evm/legacy/typed-signing/` (generic entries, `MetaTransaction` structs / typehashes, `mtxSelectors`);
tests `test/metatx/*`, `test/v2/*` that used `mtxExecute` / `uaExecute` / `mtxBatch`, new `test/metatx/TypedOps.t.sol`
(reads `typed_ops.json`), `test/ua/UAMetaTx3Vectors.t.sol`, gas `test/v2/MetaTxGasV2.t.sol` (`AMS_*` re-pinned).

- [ ] Step 1: failing tests `test_typedOpsVectors_<op>` for `CancelNonce`, `Burn`, `UABurn`, `Wrap`, `WrapLeg`,
  `Unwrap`, `UAUnwrap`, `UnwrapLeg`, `UAUnwrapLeg`, `AddReserve`, `WrapToUA`, `UnwrapToUA`, `UAUnwrapToUA`;
  `test_genericEntriesGone` (selectors absent), `test_namedEntryReplayRefused` (nonce), `test_namedEntryOtherOpDigestRefused`
  (an `Unwrap` signature on `mtxUnwrapLeg`), `test_namedEntryFeeClass` (amount-class fee on unwrap, absolute on wrap),
  `test_relayFeeRouterRunsNamedEntry` (router + executor call `mtxUnwrap` with fee 0).
- [ ] Steps 2–4: FAIL → implement → `test/metatx`, `test/v2`, `test/ua` PASS; whole suite (default set); `sizes`
  (STOP rule TS-D18); gas pins old → new.
- [ ] Step 5: commit `typed-signing C2: named typed entries on the base and public tokens; named typed entries added; generic mtxExecute / mtxBatch / uaExecute / uaBatch kept`.

### Task C3: classical Zether

**Files:** `src/zether/{ZetherLayer,ZetherLib,NormalZetherToken,WrappedZetherToken,IZetherToken,ZetherTypes}.sol`,
`src/confidential/IConfidentialToken.sol`; tests `test/zether/*`; `smartcontracts/evm/test/vectors/zether/*` call-shaped
rows regenerated by their generator (zether-prover `vectors.rs`) — statement rows byte-identical.

- [ ] Step 1: failing tests: `test_zetherNamedShield` (+UA), `test_zetherNamedWrapShield`, `test_zetherTransferExplicitStatementBytes`
  (statement from the explicit struct == the packed payload's statement, every e2e row), `test_zetherTransferTyped_<form>`,
  `test_zetherUnshieldExplicit`, `test_zetherOwnerRollOverTyped`, `test_zetherSetRollOverModeTyped`,
  `test_zetherEnvelopeBindingNamed` (TAG_RELAYED binding of the named entry's envelope), `test_zetherTransferStoredBytesUnchanged`.
- [ ] Steps 2–4: FAIL → implement (explicit structs per Appendix X; `Env` carries the token domain separator for the
  owner digests) → `test/zether` PASS; `ZetherE2E.s.sol` dry run on anvil; whole suite; `sizes`; gas pins.
- [ ] Step 5: commit `typed-signing C3: classical Zether named entries, explicit transfer parameters, typed owner ops`.

### Task C4: PQZ + `PqzAuth`

**Files:** `src/pqz/{PqzLayer,PqzCore,PqzStateLib,NormalPqzToken,WrappedPqzToken,IPqzToken}.sol`; tests `test/pqz/*`;
`smartcontracts/vectors/pqz/pqz_kat.py` (auth digest = `PqzAuth` typed digest), `pqz-core/ffi/src/bin/pqz-vectors.rs`
(`auth_digest` field; per-set dirs `smartcontracts/vectors/pqz/<set>/`), `smartcontracts/evm/script/pqz/e2e.py`
(explicit op arguments, `PqzAuth`).

- [ ] Step 1: failing tests: `test_pqzAuthTypehashPinned`, `test_pqzAuthDigestVectors` (every statement row, every set),
  `test_pqzExplicitStatementBytes_<op>` (transfer, single, compact, single-compact, op 7, burn, unshield-unwrap),
  `test_pqzNamed<Op>` (+UA), `test_pqzStoredCiphertextUnchanged`, `test_pqzhN2048FitsBothPaths` (regular gas < 2^24 for
  every PQZH `n2048-kmax1024` row that fitted before, on `mtx*` and `ua*`).
- [ ] Step 2: `cargo run -j2 --release --bin pqz-vectors -- --check` in `pqz-core/ffi` reports only `auth_digest`
  changes; `python3 -I smartcontracts/vectors/pqz/pqz_kat.py --check` FAIL before / PASS after.
- [ ] Steps 3–4: implement → `test/pqz` PASS at every set (round runner `--only forge-<set>`); `gen-set` step;
  `sizes`; gas pins. Stop rule: a calibrated row or `debit_min_gas` moves ⇒ report.
- [ ] Step 5: commit `typed-signing C4: PQZ named entries, explicit op parameters, typed PqzAuth`.

### Task C5: MandateWallet + SmartKeyAccount

**Files:** `src/wallet/MandateWallet.sol` (+ the Hedera variant under `src/hedera/`), `src/account/SmartKeyAccount.sol`
(`AccountSig` for its own entries, TS inventory row 13), `SmartKeyAccountFactory.sol` if it builds calls; tests
`test/v2/*Mandate*`, `test/v2/*SmartKey*`, `test/account/*`.

- [ ] Step 1: failing tests per struct (`SetMandate` … `CancelRecovery`, `Execute` on both wallets), `test_mandateEpochBound`
  (delegate signatures still bound to `epoch`, CTR-ACC-07), `test_skaMerkleBatchLeafIsTypedDigest`, `test_skaPasskeyChallengeTypedDigest`.
- [ ] Steps 2–4 → PASS; `sizes`; commit `typed-signing C5: MandateWallet and SmartKeyAccount named typed entries, Execute`.

### Task C6: trade / DEX / receiver fee / relay fee / UA cancel

**Files:** `src/trade/{TradeLib,ITradeToken}.sol`, `src/metatx/{ERC20MetaTx,MetaTokenBase,WrappedToken,WrappedLib,MtxRelayFee,IERC20MetaTx}.sol`,
`src/dex/{SCaaSDex,ISCaaSDex}.sol`; tests `test/v2/{Trade,DexOutside,ReceiverPays}.t.sol`, `test/metatx/MtxRelayFee.t.sol`,
`test/ua/UATradeVectors.t.sol`; `uatrade_kat.json` + the DEX KAT regenerated (C1's generators).

- [ ] Step 1: failing tests: `test_cancelOrderNested`, `test_cancelUAOrderNested`, `test_cancelWrapOrderNested`,
  `test_cancelDexOrderNested`, `test_wrapOrderTyped` (`dex == receiveToken` ⇒ `WrapOrder`), `test_tradeOrderStillTradeOrder`,
  `test_mtxWrapOrderRenamed`, `test_receiverFeeNested` (+UA), `test_relayFeeTyped` (+UA; lane `payLane(ref)`, nonce 0,
  relayer = router, open mode), `test_relayFeeDirectCallRefused` (`msg.sender != relayer`), `test_uaCancelNonceTyped`.
- [ ] Steps 2–4 → PASS; whole suite; `sizes`; gas pins. Step 5: commit
  `typed-signing C6: nested cancels, WrapOrder, ReceiverFee, RelayFee path, UACancelNonce typed`.

### Task C7: reproducers that build EVM op digests

**Files:** clientkeys done in C1; `clients/ua-rs/src/lib.rs` (UA metatx / cancel / trade digests it builds),
`clients/zether-prover/src/api.rs` (owner digests, explicit Zether op structs), and every package of P6 / P7 that exposes
a chain-bound digest (X0 lists them by grep of `metatx-cancel`, `UAMetaTransaction`, `CancelOrder`, `ZETHER_ROLLOVER`);
`legacy/typed-signing/` per package.

- [ ] Steps: failing vector tests over `typed_ops.json` / `metatx3.json` / `uatrade_kat.json` → implement → package
  steps PASS → commit `typed-signing C7: reproducers build the typed op digests`.

### Task C8: scripts and deploy

**Files:** `smartcontracts/evm/script/*` (Deploy scripts that call removed entries, `ZetherE2E.s.sol`, `pqz/e2e.py`
call shapes), `smartcontracts/evm/README.md` snippets. The SCaaS testnet is not redeployed in this round: the next
reset (work order item 6) deploys the new contracts (controller call).

- [ ] Steps: `forge script` dry runs on anvil for each touched script; e2e.py self-checks → commit
  `typed-signing C8: scripts on the named entries`.

---

# Part N — node: explicit job API (after C)

### Task N1: EVM job API, calldata builders, guard, dedup, indexer

**Files:** `scaas-node/src/{metatx.rs,submit.rs,guard.rs,dex.rs,dex/venue.rs,gateway.rs,abi.rs,odoo.rs}`, tests,
`scaas-node/legacy/typed-signing/`, `docs/node/job-api.md`.

- Job kinds: one `op` object per named entry (`{"entry": "mtxUnwrap", "token": …, "envelope": {from, batch, nonce,
  validUntil, mode, relayer, fee, feeRecipient}, "args": {underlying, wrapped, recipient, minOut}, "signature": …}`;
  UA twins with `auth` as the `UASig` object; confidential ops with the X0 struct fields as JSON; relay fee with
  `call: {entry, token, envelope, args, signature}` instead of hex calldata). The node builds the calldata from the
  entry table (alloy `sol!`), checks the typed digest locally against the signature (gateway pre-check), and uses the
  typed digest as the dedup key (no chain view; `mtxDigest` is gone). Hex `data` / `calldata` fields are refused with
  a named error.
- `guard.rs`: the allow-list per entry selector (rules per contract kind); `dex.rs` `cancel_digest` nested;
  `venue.rs` cancels; indexer: `MetaTransactionExecuted` keeps its fields (digest = the typed digest); new events from C
  (if any) indexed.
- [ ] Steps: failing tests `typed_ops_kat_every_entry` (digest + calldata against `typed_ops.json`), `job_api_explicit_json_roundtrip`,
  `hex_data_refused`, `guard_allows_every_named_entry_only`, `relay_fee_call_object`, `dedup_by_typed_digest`;
  `cargo-scaas-node` + `node-e2e-anvil` steps PASS; commit `typed-signing N1: node explicit job API for the named entries`.

### Task N2: Soroban jobs explicit

**Files:** `scaas-node/src/adapters/soroban.rs`, `docs/node/job-api.md` (Soroban rows), tests.

- `ua_metatx` `op.args` hex XDR and `op.extra.call` InvokeContractArgs XDR → named JSON fields per Soroban function; the
  node builds the XDR. Coordinate with `ua8-soroban` B6 (Soroban `call` jobs): whichever lands second adapts to the
  other; the controller picks at that time.
- [ ] Steps: failing `soroban_job_explicit_args_build_xdr`, `soroban_hex_args_refused` → implement → PASS → commit
  `typed-signing N2: Soroban jobs with explicit JSON arguments`.

---

# Part D / G — docs, gates, review of Parts C + N

### Task CD: docs

Change entries (in full) in `docs/decisions.md` and the text of: **CTR-MTX-09** (named functions: every op), **-11**
(generic batch dropped, TS-D15), **-15 / -16 / -17 / -19 / -20 / -22** (the generic `MetaTransaction` path and allowlist
replaced by named typed entries, TS-D14), **-05 / -06** (`ReceiverFee` nested), **-27** (`RelayFee` token path), new
**CTR-MTX-28** (named-entry typed-struct rule: struct = `from` + explicit params + envelope) and **CTR-MTX-29**
(explicit-parameter rule, the owner's text); **CTR-TOK-20** (`WrapOrder`, `mtxWrapOrder`) and the wrap / unwrap /
burn / reserve entries; **CTR-DEX-02 / -15 / -18 / -25** (nested cancels); **CTR-ACC-05 / -07 / -10** and the mandate
entries (wallet named entries, `Execute`); **CTR-ZTH-16 / -17** (typed owner ops), **-34** (envelope binding of named
entries), **-35 / -37 / -38 / -51** (explicit parameters); **CTR-PQZ-21** (batching), the PQZ auth entry (`PqzAuth`) and
the op parameter entries; **CLI-SGN-27** (checks per struct), **CLI-SGN-42** (typed op builders), **CLI-APP-09**;
**NET-ALL-23** (EVM: typed EIP-712 is the readable form), **NET-ALL-84** (explicit parameters every family);
**NODE-JOB-*** (job API explicit JSON; ids re-checked). TS-D14–D21 in the alias index. Re-check every id is free.

- [ ] docs step PASS; commit `typed-signing CD: docs and decisions (Parts C, N)`.

### Task CG / CRV: gates and review

- [ ] Runner `2026-10-31-typed-signing-c-gates.sh`: the P step list + `gen-set` + `node-e2e-anvil` + `pqz-kat`
  (`pqz_kat.py --check`, `pqz-vectors --check`) + `vectors-check` (now with `typed_ops.json`); `NEW_TESTS` = every test
  of C0–C8, N1–N2.
- [ ] CRV: whole-branch review (focus 1–6), fix wave, touched steps re-run; report → owner's merge go.

---

## Open questions for the owner (none blocks a task; each has the default the plan proceeds with)

1. **Batching (TS-D15):** default — no generic batch; `mtxBatchTransfer` / `uaBatchTransfer` stay. Alternative: a
   homogeneous `mtxBatch<Op>` for named ops on request.
2. **Overloaded names (TS-D16):** default — the signed confidential entries overload the existing op names
   (`mtxShield(Envelope, …)`). Alternative: rename the direct ops (`shield`, `confidentialTransfer`, …) so every `mtx*`
   name is a signed entry (wider churn: tests, e2e, zether-prover, node).
3. **Kind-specific signature encodings (TS-D12):** default — a WebAuthn assertion / group signature / PQ signature stays
   one `bytes signature`. Alternative: typed per-kind signature structs (e.g. `WebAuthnSig {authenticatorData,
   clientDataJSON, r, s}`) — more ABI surface, same bytes.
4. **If C0 projects a runtime above 65,536 B (TS-D18):** B′ module for that kind, or no envelope entries for ops whose
   authority is the proof / an inner signature (transfers, unshield, roll-overs: still relayable as direct calls, fee via
   the beneficiary or the relay-fee router; the relayed envelope binding then unused).
5. **Part R timing (TS-D9):** default — R lands with P before `ua8-soroban` resumes (one build of the Soroban registry
   entry points). Alternative: P alone first (unblocks `ua8-soroban` sooner; its new Soroban entry points then change
   again after R).
6. **`kindName` on an unknown id (TS-D5):** default — revert `UAKindUnknown`; alternative — empty string.
7. **`0x0108` in MetaMask (decision 7):** still pending; this plan does not build it.
8. **A packed fallback for a calldata-flagged form (X0 Step 2):** only with the owner's ruling.


## Owner rulings on this plan (2026-10-31)
- Approved, except: **keep `mtxExecute`, `mtxBatch`, `uaExecute`, `uaBatch`** (TS-D14 / TS-D15 rewritten; C2's
  removals limited to `executeMetaTransaction` and `mtxExecuteWithFee`, controller call).
- Open questions 1–8: the defaults stand (no generic typed batch; existing Zether / PQZ names with an `Envelope` first
  parameter; one `bytes signature` per kind; over 64 KiB → module behind `fallback`; Part R lands with Part P;
  `kindName` reverts `UAKindUnknown` on an unknown id; `0x0108` in MetaMask not built; a packed fallback only on an
  owner ruling per form).
- Rollback point: branch `pre-typed-signing` and tag `ref/pre-typed-signing` at main `10ac1417` (the last packed /
  generic-envelope "economy" version).
- **KEM key at `register` (owner rulings 2026-10-31, for Part R / R1 and Part P's struct values):**
  1. The KEM key given at `register` **always has version (index) 0** — the first record; `register` takes no
     `kemVersion` argument any more. `setKemKey` adds later versions ≥ 1 (write-once per version, as today). "No KEM
     key" is then told by the record itself, not by version 0: `UAKemRecord{ua, 0, scheme 0, kemPkHash 0}` = absent;
     a present version-0 record has `scheme ≠ 0`. `kemKeyOf` returns the highest stored version; `kemKeyAt(ua, 0)` is
     the registration key.
  2. **Hash-commit only when the full key does not fit one transaction.** Normally `register` carries the full
     `KemKey` (as today). Only when the registration transaction would not fit (X0 found one case: PQZH
     `n2560-kmax16384` with a PQZ key and a KEM key, 175 B over the calldata floor today) does the client send
     `register` with the KEM record's hash only (the PoP signs the same `UAKemRecord{ua,0,scheme,kemPkHash}`), and a
     second transaction `storeKemKey(bytes32 ua, KemKey key)` — open to anyone, no new signature, the pattern of
     `storePqzPop` — stores version 0 after checking `hash(key) == kemPkHash`. Until then `kemKeyOf` / `kemKeyAt(ua, 0)`
     return nothing (registered, KEM not usable yet); the full key always ends up in contract state (P2 / UA-8 copy).
     Soroban: the same rule in `ua8-soroban` B2 / B3 (it already has `store_pqz_pop`).
  3. **No separate `storeKemKey` (owner 2026-10-31): `setKemKey` takes version 0** when version 0 holds only the
     committed hash (registered by hash, key not stored yet). Then `setKemKey(ua, 0, KemKey, sig)` stores it after
     checking `hash(key) == kemPkHash`; the PoP already signed that record, so `sig` must be empty and the call is
     open to anyone (as `storePqzPop`). Version 0 already stored, or never committed → `UAKemVersion(ua, 0)`.
     Versions ≥ 1 keep today's rule (holder signature, write-once). Replaces the `storeKemKey` of item 2.
