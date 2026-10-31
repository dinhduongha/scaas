# Appendix X — explicit parameters and calldata (X0)

> Output of Task X0 of the plan [`2026-10-31-typed-signing.md`](2026-10-31-typed-signing.md) ("Part X0 — explicit-parameter inventory and calldata measurement"); test `smartcontracts/evm/test/v2/ExplicitParamsCalldata.t.sol`, logs `smartcontracts/evm/runs/2026-10-31-typed-signing-x0-calldata-<set>.txt`.

**Outcome.** No typed form turns a form that fits today into one that does not, on either relay path, at any set. Every new form is byte-identical to today's statement and payload once reassembled. Zether and the static ops get *smaller*. PQZ forms grow by 0 to 1,632 B, all of it ABI overhead: 64 B per `bytes` part and +160 B per op 7 leg.

The tightest spot is where the plan expected it: PQZH `n2048-kmax1024`, op 7 M = 4 without the auditor, on `ua*`. It still fits, with **561 B** of headroom left (369 B on commit-reveal); today it has 1,361 B. One form does not fit, and it is not caused by typing: a PQZH `n2560-kmax16384` registration carrying both a PQZ key and a KEM key is already 175 B over today (owner question 1).

**The measuring test.** `ExplicitParamsCalldata.t.sol` makes no contract change and has two tests, both PASS at all four sets:

- `test_x0_calldata` measures each form.
- `test_x0_reassemblesPayload` asserts that the typed structs reassemble today's payload byte for byte: op 1 commit-reveal with the auditor, op 7 M = 4 with the auditor, burn, Zether single, Zether multi M = 3 commit-reveal.

To re-run one set (Foundry's sparse mode compiles only the test and its imports, about 20 s per set):
`FOUNDRY_SPARSE_MODE=true scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --match-path test/v2/ExplicitParamsCalldata.t.sol -vv`

How the test works:

- It builds today's calls exactly as `PqzStatePinGasTest`'s gas table does (`_envelopeVia`, `_op1p`, `_op7a`, `_burnP`, `_msigHolder`). Proof lengths come from `test/vectors/pqz-gas/<set>.json`.
- Its "today" byte counts reproduce the pinned rows exactly (260,132 / 259,268 / 260,196 / 260,548 / 259,140 B on `ua*` at `n2048-kmax1024`).
- The one exception is the register row: 212,580 B against the pinned 212,420 B. The pinned row predates UA-8's `pqzPop` parameter.
- It resets the free memory pointer after each row; without that, the test runs out of memory gas.

## X.1 Rules applied

- **Classes.** Each `bytes` parameter or `bytes` struct field in `smartcontracts/evm/src` is classified as:
  - *bundles fields*: becomes typed;
  - *one crypto object*: stays `bytes`, as its own named parameter;
  - *a call*: stays `bytes`;
  - *external standard*: keeps its ABI.
- **Integer types.**
  - Statement words that today carry a range check with a custom error keep `uint256`: `validUntilBlock`, `shieldIn`, `decoyFee`.
  - PQZ `p` is `uint64`. Today it reverts `BadPayload` above 2^64 − 1; with the typed field the ABI decoder reverts instead.
  - Zether `accSeq` and `sendCounter` are `uint64`. Today they are compared against `uint64` state, so the outcome is unchanged; only the error differs.
- **No duplicates.**
  - `M` is `legs.length`.
  - The separate shared `bytes32 beneficiary` parameter is dropped; it lives once, in the struct.
  - The memo's clear salt is the struct's `salt`. The memo travels as `bytes sealedMemo = memo[16:]`; the token prepends `salt`, so `memoHash` is unchanged and `MemoSaltMismatch` can no longer happen.
- **Signed struct of a confidential entry.** It contains the explicit struct, `proof`, PQZ `accHint` (kept signed, as it is today inside `data`) and `E`. Signature fields (`auth`, `pqzAuth`, `sig`) are never inside a signed struct. Recommendation, as a controller call: the plan's `RollOverSigned` `ownerSig` field follows the same rule.
- **`E`** = `uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient`. The UA twin of a struct is `UA<Name>(bytes32 from,…)`.
- **Zether points.** Only BLS12-381 verifiers are built (`ZetherCurves` `POINT_BYTES` 128; there is no bn254 verifier contract). A point is therefore the static `struct G1 { bytes32 x0; bytes32 x1; bytes32 y0; bytes32 y1; }` (EIP-2537 encoding). `abi.encode(G1)` is the 128 packed bytes, so the overhead is zero.
- **PQZ ciphertext parts** stay `bytes` (one crypto object each). `u` is `PK` bytes and varies by set (16,384 / 18,432 / 20,480 / 22,528). `v` is `V` = 128 at every set.

## X.2 Typed parameter structs (exact Solidity)

```solidity
// MetaTxLib (TS-D14; UAEnvelope: bytes32 from)
struct Envelope { address from; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode; address relayer; uint256 fee; address feeRecipient; }
// UARegistry (TS-D12): exists today
struct MemberSig { uint16 index; bytes keyData; bytes sig; }
struct UASig { bytes keyData; bytes signature; MemberSig[] members; }

// PQZ (IPqzToken)
struct PqzTransferArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 toUA; bytes32 beneficiaryUA;
    bytes16 salt; bytes u; bytes vTo; bytes vFrom; bytes vAuditor /* empty: auditor off */; bytes sealedMemo /* HASH: 41 B, else empty */; }
struct PqzLeg { bytes32 ua; bytes v; bytes vAuditor /* empty: auditor off */; }
struct PqzMultiArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 beneficiaryUA; uint256 decoyFee;
    bytes16 salt; bytes[] u /* G = ⌈M/S_AUD⌉ with auditor, ⌈M/4⌉ without */; PqzLeg[] legs; bytes vFrom; bytes sealedMemo /* HASH: 2 + 40·M B */; }
struct PqzBurnArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 beneficiaryUA; bytes u; bytes vFrom; }

// Zether (IZetherToken)
struct G1 { bytes32 x0; bytes32 x1; bytes32 y0; bytes32 y1; }
struct ZetherSingle { uint64 accSeq; uint64 sendCounter; uint256 validUntilBlock; bytes16 salt; bytes32 beneficiaryUA;
    G1 yFrom; G1 yTo; G1 cOut; G1 dOut; G1 cDeb; G1 cAud; }
struct ZetherLeg { G1 yTo; G1 cOut; G1 cAud; G1 dAud; }
struct ZetherMulti { uint64 accSeq; uint64 sendCounter; uint256 validUntilBlock; bytes16 salt; bytes32 beneficiaryUA; uint256 decoyFee;
    G1 yFrom; G1 dOut; G1 cDeb; ZetherLeg[] legs; bytes sealedMemo /* HASH: 1 + 40·M B */; }
struct ZetherBurn { uint64 accSeq; uint64 sendCounter; uint256 validUntilBlock; bytes32 beneficiaryUA; G1 yFrom; }

// Registry (TS-D10 / TS-D11 / TS-D13)
struct KemKey { uint8 scheme; bytes mlkemEk; bytes32 x25519; }              // assembled scheme ‖ ek(1,568) ‖ x25519 = 1,601 B
struct UAAttrs { bytes pqzKey; bytes32 pqzPopHash; uint64 kemVersion; KemKey kem; } // no KEM: KemKey(0, "", 0)
struct MsigMember { uint16 kind; bytes32 id; uint16 weight; }
struct MsigStructure { uint16 threshold; MsigMember[] members; }
struct WebAuthnKey { bytes32 x; bytes32 y; bytes32 rpIdHash; }               // keyData x ‖ y ‖ rpIdHash (96 B)
struct MuSig2Key { bytes aggKey; bytes[] memberKeys; }                        // aggKey ‖ u16 n ‖ n × key (33 B secp / 64 B bn254)
struct FrostMember { bytes[] commitments; bytes r; bytes32 z; }               // t commitments ‖ R_i ‖ z_i
struct FrostKey { bytes groupKey; uint16 threshold; FrostMember[] members; }  // groupKey ‖ u16 t ‖ u16 n ‖ n × member

// Other
struct AccountSig { uint256 keyIndex; bytes32[] proof; bytes signature; }    // SmartKeyAccount; today abi.encode(uint256, bytes32[], bytes)
struct PayMeta { uint16 schema; bytes body; }                                 // today meta = abi.encode(uint16, bytes)
```

**Reassembly rules.** The token rebuilds exactly today's bytes; the statement, `memoHash`, stored blobs and `entryRef` are unchanged.

- **PQZ op 1.** `abi.encode(uint256(p), validUntilBlock, shieldIn, fromUA, toUA, beneficiaryUA) ‖ salt ‖ u ‖ vTo ‖ vFrom ‖ vAuditor ‖ [salt ‖ sealedMemo]`
  - Required lengths: `u` = `PK`; `v*` = `V`; `vAuditor` ∈ {0, `V`}; `sealedMemo` = 41 B on HASH and 0 otherwise.
- **PQZ op 7.** `abi.encode(uint256(p), validUntilBlock, shieldIn, fromUA, beneficiaryUA, legs.length, decoyFee) ‖ salt ‖ (legs[j].ua)_j ‖ u_0…u_{G−1} ‖ (legs[j].v)_j ‖ vFrom ‖ [(legs[j].vAuditor)_j] ‖ [salt ‖ sealedMemo]`
  - `auditorOn` holds when every `vAuditor` is non-empty; a mix of empty and non-empty is `BadPayload`.
  - `u.length` must equal G.
- **PQZ burn.** `abi.encode(uint256(p), validUntilBlock, shieldIn, fromUA, beneficiaryUA) ‖ u ‖ vFrom`.
- **Zether single.** `abi.encode(accSeq, sendCounter, validUntilBlock) ‖ salt ‖ yFrom ‖ yTo ‖ cOut ‖ dOut ‖ cDeb ‖ cAud`.
- **Zether multi.** `abi.encode(accSeq, sendCounter, validUntilBlock) ‖ salt ‖ abi.encode(legs.length, decoyFee) ‖ yFrom ‖ dOut ‖ cDeb ‖ (yTo ‖ cOut ‖ cAud ‖ dAud)_j ‖ [salt ‖ sealedMemo]`.
- **Zether burn.** `abi.encode(accSeq, sendCounter, validUntilBlock) ‖ yFrom`.

## X.3 Entries (exact Solidity signatures)

**PQZ** (`NormalPqzToken` / `WrappedPqzToken`; the direct op keeps its name, the signed entry is an overload per TS-D16):

```solidity
function mtxConfidentialTransferSingle(PqzTransferArgs calldata t, bytes calldata proof, UASig calldata pqzAuth, bytes calldata accHint) external returns (bytes32);
function mtxConfidentialTransferSingle(MetaTxLib.Envelope calldata e, PqzTransferArgs calldata t, bytes calldata proof, UASig calldata pqzAuth, bytes calldata accHint, bytes calldata sig) external returns (bytes32);
function uaConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, PqzTransferArgs calldata t, bytes calldata proof, UASig calldata pqzAuth, bytes calldata accHint, UASig calldata auth) external returns (bytes32);
//   …SingleCompact: same three shapes, mode HASH
function mtxConfidentialTransfer(PqzMultiArgs calldata t, bytes calldata proof, UASig calldata pqzAuth, bytes calldata accHint) external returns (bytes32);
//   + Envelope overload, uaConfidentialTransfer, …Compact (same pattern)
function mtxUnshield(PqzBurnArgs calldata b, uint256 amount, bytes32 recipient, bytes calldata proof, UASig calldata pqzAuth, bytes calldata accHint) external;
//   + Envelope overload, uaUnshield
function mtxUnshieldUnwrap(PqzBurnArgs calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, UASig calldata pqzAuth, bytes calldata accHint) external;
//   + Envelope overload, uaUnshieldUnwrap
// views (read side, same structs):
transferStatement(PqzMultiArgs, bytes32 binding); transferSingleStatement(PqzTransferArgs, bytes32 binding);
burnStatement(PqzBurnArgs, uint256 amount, bytes32 recipient, bytes32 binding); unshieldUnwrapStatement(PqzBurnArgs, Unwrap, bytes32 binding)
```

**Zether.** Row 4 decided: `auth` and `accHint` are dropped, since they are always empty (`_noAuth`).

```solidity
function mtxConfidentialTransferSingle(ZetherSingle calldata t, bytes calldata proof) external returns (bytes32);
function mtxConfidentialTransferSingle(MetaTxLib.Envelope calldata e, ZetherSingle calldata t, bytes calldata proof, bytes calldata sig) external returns (bytes32);
function uaConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, ZetherSingle calldata t, bytes calldata proof, UASig calldata auth) external returns (bytes32);
//   mtxConfidentialTransfer / …Compact: ZetherMulti (same three shapes)
//   mtxUnshield(ZetherBurn b, uint256 amount, bytes32 recipient, bytes proof) (+ Envelope / UA)
//   mtxUnshieldUnwrap(ZetherBurn b, IConfidentialWrappedToken.Unwrap x, bytes proof) (+ Envelope / UA)
//   mtxRollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, UASig ownerSig)
//   mtxSetRollOverMode(ZetherTypes.UA ua, ZetherTypes.RollOverMode mode, uint64 validUntilBlock, UASig ownerSig)
// views: ZetherStatements.transferStatement(address token, ZetherMulti, ZetherTypes.TransferMode, bytes32), …Single(…, ZetherSingle, …),
//        unshieldStatement(…, ZetherBurn, uint256, bytes32, bytes32), unshieldUnwrapStatement(…, ZetherBurn, uint256, bytes32, address, uint256, bytes32)
```

**`IConfidentialToken`**: the shared transfer and unshield signatures go, because their argument structs are kind-specific. The interface keeps the events, `mtxShield` and `mtxRollOver`. The transfer and unshield entries move to `IPqzToken` / `IZetherToken`, and `mtxUnshieldUnwrap` moves out of `IConfidentialWrappedToken` into the kind interfaces. ERC-165 ids are re-pinned in C3 / C4.

## X.4 EIP-712 type strings (confidential entries)

Referenced types are sorted by name. `…` stands for the full nested string given in the "Nested" lines.

- Nested PQZ:
  - `PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)`
  - `PqzLeg(bytes32 ua,bytes v,bytes vAuditor)`
  - `PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)`
  - `PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,bytes u,bytes vFrom)`
  - `Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)`
- PQZ entries:
  - `PqzTransferSingle(address from,PqzTransferArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzTransferArgs(…)`; `PqzTransferSingleCompact` is identical apart from the name.
  - `PqzTransfer(address from,PqzMultiArgs args,bytes proof,bytes accHint,E)PqzLeg(…)PqzMultiArgs(…)`; `PqzTransferCompact` is identical apart from the name.
  - `PqzUnshield(address from,PqzBurnArgs args,uint256 amount,bytes32 recipient,bytes proof,bytes accHint,E)PqzBurnArgs(…)`
  - `PqzUnshieldUnwrap(address from,PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint,E)PqzBurnArgs(…)Unwrap(…)`
- Nested Zether:
  - `G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)`
  - `ZetherSingle(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud)`
  - `ZetherLeg(G1 yTo,G1 cOut,G1 cAud,G1 dAud)`
  - `ZetherMulti(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo)`
  - `ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)`
- Zether entries:
  - `ZetherTransferSingle(address from,ZetherSingle args,bytes proof,E)G1(…)ZetherSingle(…)`
  - `ZetherTransfer(address from,ZetherMulti args,bytes proof,E)G1(…)ZetherLeg(…)ZetherMulti(…)` (and `ZetherTransferCompact`)
  - `ZetherUnshield(address from,ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof,E)G1(…)ZetherBurn(…)`
  - `ZetherUnshieldUnwrap(address from,ZetherBurn args,Unwrap unwrap,bytes proof,E)G1(…)Unwrap(…)ZetherBurn(…)`
- Roll-over entries:
  - `RollOverSigned(address from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,E)`
  - `SetRollOverMode(address from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,E)`
  - `RollOverBatch(address from,bytes32[] uas,E)`
- UA twins: `UA<Name>(bytes32 from,…)` with the same tail.

Typehashes are pinned in C1 (`typed_ops.json`).

## X.5 Inventory (complete; ✓ = the first-pass row confirmed)

| # | Where | Today | Class | Explicit form |
|---|---|---|---|---|
| 1 ✓ | Zether `mtxConfidentialTransferSingle` | payload `w32 accSeq ‖ w32 sendCounter ‖ w32 validUntilBlock ‖ salt16 ‖ 6 × 128-B points` (880 B; the "be32" are 32-byte words) | bundles | `ZetherSingle` |
| 2 ✓ | Zether `mtxConfidentialTransfer` / `…Compact` | `… ‖ salt16 ‖ w32 M ‖ w32 decoyFee ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j)_j [‖ memo = salt ‖ sealed(1 + 40·M)]` | bundles | `ZetherMulti` / `ZetherLeg[]` / `sealedMemo` |
| 3 ✓ | Zether `mtxUnshield`, `mtxUnshieldUnwrap` | `3 words ‖ Y_f` (224 B) | bundles | `ZetherBurn` (+ `amount`, `recipient`; `Unwrap` struct unchanged) |
| 4 ✓ | Zether `auth`, `accHint` | always empty (`_noAuth`) | — | **dropped** from every Zether entry; `IConfidentialToken` loses the shared transfer signatures (X.3) |
| 5 ✓ | PQZ op 1 (4 forms) | `p ‖ vub ‖ shieldIn ‖ from ‖ to ‖ ben ‖ salt16 ‖ u ‖ v_t ‖ v_f ‖ [v_a] [‖ memo57 = salt ‖ sealed41]` | bundles | `PqzTransferArgs` |
| 6 ✓ | PQZ op 7 | `p ‖ vub ‖ shieldIn ‖ from ‖ ben ‖ M ‖ decoyFee ‖ salt16 ‖ UA_j… ‖ u_0..u_{G−1} ‖ v_j… ‖ v_f ‖ [v_{a,j}…] [‖ salt ‖ sealed(2 + 40·M)]` | bundles | `PqzMultiArgs` / `PqzLeg[]`: each leg carries its UA with its ciphertext parts, JSON-like |
| 7 ✓ | PQZ burn / refresh / unshield-unwrap | `p ‖ vub ‖ shieldIn ‖ from ‖ ben ‖ u' ‖ v_f` | bundles | `PqzBurnArgs` |
| 8 | PQZ `accHint` | the packed stream of `acc` (`PqzCt.CTP` B), used only when its hash is `accHash` | **one crypto object** (a ciphertext) | stays `bytes accHint` (corrects the first pass, which listed a struct) |
| 9 ✓ | every `ua*` / `requireAuthorized` / `MtxPipelineLib.authorize` / `preCall` / `preTransfer` `bytes auth` | `abi.encode(keyData, sig)` / `abi.encode(MemberSig[])` / raw native sig | bundles | `UASig`. Covers: `uaTrade`, `uaCancelOrder`, `uaInvalidateNonces`, `uaExecute`, `uaBatch` (`bytes[] auths` → `UASig[]`), `uaExecuteTransfer`, `uaBatchTransfer`, `uaCancelNonce`, `uaTransfer*`, `uaPay*`, `uaPayReceiverFee` (`payerAuth` / `payeeAuth`), `uaUnwrap`, `uaWrap`, `MtxRelayFee.uaRelay`, `WrappedLib.wrapBySigUA`, Zether `mtxRollOverSigned` / `mtxSetRollOverMode` `sig` (= `abi.encode("", schnorr)` → `UASig.signature`), PQZ `pqzAuth` |
| 10 ✓ | `register(0x0120 msig, keyData, …, pop, …)` | CTR-UA-09 `u16 t ‖ u16 n ‖ n × (u16 kind ‖ id ‖ u16 weight)`; `pop = abi.encode(MemberSig[])` | bundles | `registerMsig(MsigStructure s, UAAttrs attrs, MemberSig[] pop, bytes pqzPop)` |
| 11 ✓ | `UAAttrs.kemPk`, `setKemKey`, `kemRecordDigest(bytes32,uint64,bytes)` | `scheme ‖ ek ‖ x25519` | bundles | `KemKey` |
| 12 ✓ | single-key `keyData` that bundles fields (`UAKinds.validateKeyData`) | `webauthn-p256` 96 B `x ‖ y ‖ rpIdHash`; `musig2-secp256k1` / `-bn254` `agg ‖ u16 n ‖ n × key` (33 / 64 B); `frost-secp256k1` / `-bn254` `group ‖ u16 t ‖ u16 n ‖ n × (t commitments ‖ R_i ‖ z_i)` | bundles | `WebAuthnKey`, `MuSig2Key`, `FrostKey` via `registerWebAuthn` / `registerMuSig2` / `registerFrost` (as `registerMsig`; ids from the reassembled bytes). Every other kind (p256, ed25519, bip340, secp256k1, schnorr, BLS, ML-DSA, FN-DSA, SLH-DSA, zether, pqz) is one key and stays `bytes`. UARegistry runtime is 37,365 B, so there is room for the extra entries. |
| 13 ✓ | `SmartKeyAccount.mtxExecuteAsOwner(bytes data, uint256 nonce, uint256 validUntil, bytes signature)` | `signature = abi.encode(uint256 keyIndex, bytes32[] proof, bytes sig)` (`_isValid`) | bundles | `AccountSig` on its `mtx*` entries. ERC-1271 `isValidSignature(bytes32, bytes)` keeps `bytes` (standard). The inner WebAuthn assertion stays one `bytes` (open question 3 default). |
| 14 ✓ | `mtxPayMeta` / `uaPayMeta` / `metaPayId(bytes32 salt, bytes meta)` | `meta = abi.encode(uint16 schema, bytes body)` (`evm.js` `encodeMeta`); the token only hashes it | bundles | `PayMeta { uint16 schema; bytes body; }` with `payId` byte-identical. `body` stays `bytes`: it is the app's schema document (schema 1 a note, schema 2 `abi.encode(bytes creditor, bytes invoice, uint64 dueDate)`), and per-schema structs would put app schemas into the token ABI (controller call). |
| 15 ✓ | `MetaTokenBase.initialize(address, uint64, bytes initArgs)`, `OpenFactory.createToken` / `createTokenUnregistered(…, bytes initArgs, …)`, `SCaaSDex.initialize`, `createDex(uint64, bytes initArgs, bytes32)` | `abi.encode(TokenConfig)` / `abi.encode(DexConfig)` | bundles | `TokenConfig` / `DexConfig` as the parameter. `deployImplementation` / `deployDexImplementation` `initcode` + `implArgs` stay `bytes` (generic deployment payload). |
| 16 ✓ | `MtxRelayFee.relay` / `uaRelay` / `exec` / `relayRef` `callData`; DEX `mtxExchangeVia` / `mtxHybridVia` `data`; `Interaction.data`; `execute(target, value, data)`; `mtxExecuteAsOwner` `data` | a call | a call | stays `bytes` |
| 17 ✓ | Hedera `mtxExecuteAsOwnerRaw(bytes data, uint256, uint256, bytes sig)`, `HederaLib.requireValid` | 64-B ed25519 (HIP-632) or 65-B ECDSA / 1271 | one crypto object | stays |
| 18 ✓ | views returning packed records | see the next column | read side | Return typed views: `msigOf → MsigStructure`, `kemKeyOf` / `kemKeyAt → KemKey` (TS-D10 / D11). `registrationOf` / `keyOf` keep the raw bytes (the hashed id input). `transferEntry` / `pqzEntryBlob` keep the raw bytes (`keccak256(R)` is the commitment); a typed `transferRecord(entryRef)` is optional (controller call, not a C gate). `ITransferDisclosure.transferCiphertext` and Zether `AccountState` points: `G1` optional. |
| 19 ✓ | Soroban | see X.7 | — | hand-over |
| 20 new | DEX `Leg` / `ExchangeLeg` `{ …, uint8 shape, bytes order, bytes sig, … }` (`mtxSettle*` legs) | `order = abi.encode(TradeOrder)` (shape 0) or `abi.encode(UATradeOrder)` (shape 1) | bundles | `DexLeg { address sellToken; uint8 shape; TradeOrder order; UATradeOrder uaOrder; bytes sig; UASig auth; uint256 fill; }`, with the unused member zero (controller call; the DEX is far from every limit) |
| 21 new | `UniswapExecutor` `Hop { uint8 kind; bytes args; }` (inside the executor call) | `abi.encode(address, address, uint24)` / `abi.encode(PoolKey, bool)` | executor-defined (inside "a call") | stays. Typed `V3Hop` / `V4Hop` are optional and outside Part C. |
| 22 new | statement / disclosure views taking `payload` (`PqzLayer`, `WrappedPqzToken.unshieldUnwrapStatement`, `ZetherStatements`) | packed payload | bundles | the same structs as the entries (X.3) |
| — | `UAPqzVerifier.verifyPop` / `verify`, `IUAVerifier` verifiers (`Ed25519Verifier.verifyRaw`, `Musig2*`, `PairingVerifiers.check`), `MlDsa.*`, `IZetherVerifier.verify*(bytes statement, bytes proof)`, `g1*`, `isValidSignature`, ERC-1271, Uniswap callbacks, `mtxCancelOrders` `bytes[] sigs`, `TradeOrder` / `MetaTransfer` signatures, `ConfidentialConfig.auditorKey` | — | one crypto object / internal verifier ABI / external standard | stay |

## X.6 Calldata measurement

**Model.**

- Regular gas = max(15,000 + standard + execution + precompile, floor). The floor is 15,000 + 64 per calldata byte (EIP-7976), and the cap is 2^24 (EIP-7825).
- Every PQZH debit is floor-bound, so its headroom is 2^24 − 15,000 − 64 · bytes.
  - On the PQZH forms that fit, execution stays 3.6–4.7 M below the floor. For example, `ua*` op 7 M = 4 without the auditor comes to 15,000 + 4.03 M + 6.39 M + 2.64 M = 13.07 M against a 16.69 M floor.
  - The extra hashing of the typed digest (an estimate: `proof` 235 KB ≈ 0.05 M of keccak) stays inside that gap. Hash `proof` in place inside the precompile buffer; copying it to fresh memory would cost about +0.5 M of memory expansion. C4's `test_pqzhN2048FitsBothPaths` measures it.
- PQZL rows are execution-bound. The smallest headroom (2026-10-26 logs) is 3.54 M at `n2048-kmax1024`, op 7 M = 8 with the auditor on `uaExecute`. Typing adds at most +6,840 gas of standard calldata there.

**Size deltas from typing.**

- op 1: +160 B on `mtx*`, +192 B on `ua*`.
- op 7: +288 B at M = 1 plus +160 B per further leg; each extra randomness group adds 64 B (+768 / +800 B at M = 4).
- burn / refresh / unwrap: −32 B on `mtx*`, 0 B on `ua*`.
- `msig` holder: −160 to −224 B (`UASig` drops the structure `keyData` and the nested `bytes`).
- register: +96 B without a KEM key, +32 B with one.
- Zether: −160 to −320 B.
- static `Unwrap`: −128 B (`mtx*`), −96 B (`ua*`).

### PQZH `n2048-kmax1024`

The only set where PQZH debits fit today. Cells give calldata today → typed (B), then headroom to 2^24 today → typed, in gas (bytes).

| Form | `mtx*` | `ua*` | Verdict |
|---|---|---|---|
| op 1, auditor | 256,772 → 256,932; 328,808 → 318,568 (4,977 B) | 260,132 → 260,324; 113,768 → 101,480 (1,585 B) | fits |
| op 1, no auditor | 255,908 → 256,068; 384,104 → 373,864 | 259,268 → 259,460; 169,064 → 156,776 (2,449 B) | fits |
| op 1 commit-reveal, auditor / no auditor | 314,472 / 369,768 left | 97,384 (1,521 B) / 152,680 left | fits |
| op 7 M = 1, auditor | 256,836 → 257,124; 306,280 left | 260,196 → 260,516; 109,672 → 89,192 (1,393 B) | fits |
| op 7 M = 1, no auditor | 361,576 left | 164,968 → 144,488 (2,257 B) | fits |
| op 7 M = 2, auditor | 257,124 → 257,572; 277,608 left (4,337 B) | 260,484 → 260,964; 91,240 → 60,520 (**945 B**) | fits |
| op 7 M = 2, auditor, commit-reveal | 271,464 left | 54,376 left (**849 B**) | fits |
| op 7 M = 2, no auditor | 293,992 left | 107,624 → 76,904 (1,201 B) | fits |
| **op 7 M = 4, no auditor** | 257,188 → 257,956; 302,184 → 253,032 (3,953 B) | 260,548 → 261,348; 87,144 → **35,944 (561 B)** | **tight, fits** |
| **op 7 M = 4, no auditor, commit-reveal** | 240,744 left (3,761 B) | 260,740 → 261,540; 74,856 → **23,656 (369 B)** | **tight, fits** |
| op 7 M = 4, auditor | 318,372 → 319,204; over by 3.61 → 3.67 M | 321,732 → 322,596; over | does not fit, today and typed (D20: not built) |
| op 1 materialised + hint | over | over | does not fit, today and typed (unchanged; no hint for PQZH) |
| burn 1 / refresh | 255,780 → 255,748; 392,296 → 394,344 (6,161 B) | 259,140 → 259,140; 177,256 (2,769 B) | fits |
| unshield-unwrap | 390,248 left | 259,204 → 259,204; 173,160 (2,705 B) | fits |
| burn, 2-of-2 `mldsa65` `msig` holder | 259,652 → 259,460; 144,488 → 156,776 (2,449 B) | 263,012 → 262,852; −70,552 → −60,312 | `mtx*` fits; `ua*` does not fit, today and typed (C0-2 holder verdict unchanged) |
| burn, 3-of-3 `msig` holder | −82,840 → −68,504 | −297,880 → −285,592 | does not fit, today and typed (unchanged) |
| register (direct), PQZ key, no KEM key / with KEM key | 212,580 → 212,676 / 214,212 → 214,244; 3.15 M / 3.05 M left | — | fits |

### Other sets

- **PQZH `n2304-kmax4096` and `n2560-kmax16384` debits.** Over 2^24 today at every form (≥ 274,692 B / ≥ 328,548 B), so PQZH stays a backup only. Typing changes them by −32 to +864 B; the verdict is unchanged: not built.
- **PQZH registration** (direct call):
  - `n2304-kmax4096`: 231,876 → 231,972 B; 1.92 M of headroom left.
  - `n2560-kmax16384`, without a KEM key: 260,452 → 260,548 B; 93,288 → **87,144 gas (1,361 B)**; fits.
  - **`n2560-kmax16384`, with a KEM key: 262,084 → 262,116 B, which is −11,160 → −13,208 gas. It does not fit today (175 B over) and does not fit typed (207 B over).** This is new information, not caused by typing (owner question 1).
  - `n2816-kmax65536` has no PQZH.
- **PQZL, every set and both paths.** Deltas range from −224 to +1,632 B. The largest calldata is op 7 M = 8 with the auditor on `ua*`: 162,692 B at `n2048-kmax1024`, a 10.43 M floor, below the 13.23 M execution path. Execution-bound headroom is ≥ 3.5 M everywhere: **fits**.
- **Zether**, BLS12-381, set-independent:
  - single 10,980 → 10,692 B (`ua*`);
  - multi M = 8 20,804 → 20,644 B (21,156 → 20,996 B commit-reveal);
  - unshield 7,300 → 7,012 B.
  - Calldata gets smaller everywhere: **fits**. The per-form M limit (6 to 8, zether.md §19) is execution-bound; C3 re-pins it once the EIP-712 hashing is in place (35 `G1` struct hashes at M = 8, a few thousand gas).
- **Static ops** (e.g. `mtxUnwrap` / `uaUnwrap`): 676 → 548 B and 4,036 → 3,940 B. Every named static entry is smaller than its generic `mtxExecute` / `uaExecute` form, because the nested `data` (its length word, the inner selector and padding) disappears.

**Static-size fallback for the tight rows.** It is not needed, since they fit. If more margin is wanted: with `V` = 128 at every set, an auditor-off leg could be the static `PqzLegNoAud { bytes32 ua; bytes32[4] v; }`. That removes 160 B per leg (+640 B back at M = 4, to ≈ 1,201 B of headroom on `ua*`). It needs separate auditor-on and auditor-off types and a second entry shape, and it hard-codes `V` into the ABI. Default: not built.

## X.7 Soroban inventory (Step 3; hand-over to `ua8-soroban`, TS-D9)

These were found by a read-only Explore agent and not checked line by line.

**Rows that bundle fields** (they become `#[contracttype]` structs, reassembled to the same bytes for `ua_of` / `key_hash`):

1. `ua-registry` `register` (`lib.rs:305`) and `ua_of` (`lib.rs:419`), `key_data`, msig form:
   - Bytes: `u16 t ‖ u16 n ‖ n × (u16 kind ‖ id ‖ u16 weight)` (decoders `msig_layout_ok` :152, `member` :135).
   - Struct: `MsigKey { threshold: u32, members: Vec<MsigMember{kind: u32, id: BytesN<32>, weight: u32}> }`.
2. The same `key_data`, `webauthn-p256` form:
   - Bytes: `x ‖ y ‖ rpIdHash`.
   - Struct: `WebAuthnKey { x, y, rp_id_hash: BytesN<32> }`.
3. `auth` / `pop`, `webauthn-p256` form (`webauthn.rs:65-84`):
   - Bytes: `abi.encode(bytes, bytes, bytes32, bytes32)`.
   - Struct: `WebAuthnAuth { authenticator_data: Bytes, client_data_json: Bytes, r, s: BytesN<32> }`. Per open question 3's default it could stay one `Bytes`; the controller decides.
4. `auth` / `pop`, msig form (`abi::decode_member_sigs` `abi.rs:56`):
   - Bytes: `abi.encode(MemberSig[])`.
   - The argument becomes `Vec<MemberSig>`; the type already exists at `abi.rs:8`.
5. `UaAttrs.kem_pk` (`ua-common/src/lib.rs:29`; forced empty today):
   - Struct: `KemKey { scheme: u32, ek: BytesN<1568>, x25519: BytesN<32> }`.

Because the layout depends on the stored `kind`, typing these on Soroban means one enum per argument: `UaKey` / `UaAuth`, with one variant per kind.

**`auth: Bytes`** (= the registry `auth`, row 3) appears on:

- `require_authorized` (`lib.rs:388`);
- token: `ua_transfer`, `ua_pay`, `ua_pay_meta`, `ua_burn`, `ua_cancel_nonce`, `ua_trade` (`token/src/ua.rs` :229–:328);
- mandate: `mtx_set_mandate`, `mtx_set_payee`, `mtx_revoke`, `mtx_withdraw`, `mtx_mandate_pay` (`mandate/src/lib.rs` :251–:356);
- DEX: `ua_cancel`, `settle` (`maker_auth` / `taker_auth`) (`dex/src/lib.rs` :201, :216);
- relay fee: `ua_relay` (`relay-fee/src/lib.rs:149`).

Each becomes the Soroban `UASig` equivalent.

**Rows that stay:**

- A call: `relay-fee` `args: Vec<Val>`, `relay-executor.exec`.
- An opaque app memo: `pay_meta` / `ua_pay_meta` `meta`. It parallels EVM row 14, so it could become `PayMeta { schema, body }`.
- `smart-key-account` is already typed (`Key`, `WebAuthnSig`).

**Not present on Soroban:** `set_kem_key` and `set_pqz_key`. Their data travels in `register`'s `UaAttrs`, which must be empty.

**Node (Part N2):** `adapters/soroban.rs` fields carrying hex XDR or hex blobs:

- `op.args` (`ua_call` :1020);
- `op.extra.call` (`host_call` :133, `relay_fee_job` :869);
- `op.payload`, `op.extra.auth[].payload`, `op.auth[].payload`;
- `op.signature` (a `C…` signer: XDR `ScVal`);
- `op.salt`, `op.meta`.

**NEAR / Algorand:** no code. Add a NET-ALL-84 note: "explicit parameters and the same typed structs apply in their UA rounds".

## Owner questions (forms that do not fit)

1. **PQZH `n2560-kmax16384` registration with a PQZ key and a KEM key does not fit one transaction**, today or typed: 262,084 B → 262,116 B against a 261,909 B limit. Registration without the KEM key fits (1,361 B left typed).
   - Proposed default: at that set, clients register without the KEM key and add it in a separate `setKemKey`, which is about 1.8 KB and fits.
   - Alternative: a deploy note that PQZH registries at `n2560-kmax16384` take the KEM key only via `setKemKey`.
   - PQZH at that set is backup-only for debits anyway.
2. **Tight but fitting, no ruling needed unless more margin is wanted.** PQZH `n2048-kmax1024` op 7 M = 4 without the auditor, on `ua*`, keeps 561 B after typing (369 B on commit-reveal); today it keeps 1,361 B. The static auditor-off leg (X.6) would bring it back to ≈ 1,201 B. Default: keep the uniform `PqzLeg`.

Unchanged, for the record (already decided, nothing new): PQZH `n2048-kmax1024` op 7 M = 4 with the auditor and the hint forms (D20); `msig` holders 2-of-2 on `ua*` and 3-of-3 on both paths (C0-2 / C0-5); every PQZH debit at `n2304-kmax4096` / `n2560-kmax16384`. Typing shrinks the holder rows by 160–224 B, which does not bring them under the cap.

## Controller calls (owner may override; recorded in full by D1 / D2)

- Zether `auth` / `accHint` are dropped.
- The shared `IConfidentialToken` transfer signatures are split per kind.
- Signature fields are kept out of signed structs, including the plan's `ownerSig`.
- `accHint` stays signed.
- `sealedMemo` replaces the full memo.
- `PayMeta.body` stays `bytes`.
- The DEX leg gets `DexLeg` with both order members.
- Registry key data gets `registerWebAuthn` / `registerMuSig2` / `registerFrost` entries.
- `transferEntry` keeps its raw bytes.
- `uint64` / `uint256` per X.1.

Size flag for C0's projection: `WrappedPqzToken` is 61,748 B and `WrappedZetherToken` 60,893 B, and the struct ABI decoders add code to both.
