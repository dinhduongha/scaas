Reviewed frozen commit `64549aa4f95f52618edbb6d55ac9c90dc6abf5fb`, strictly read-only. **Four findings: one P1 and three P2.** No confirmed forgery or balance-conservation defect. The two gas-budget findings are already documented as unresolved; they are not regressions of findings marked fixed in the previous review.

## Findings

### C2-1 — P1 — PQZH value tokens can initialize despite unusable shipped withdrawal proofs

**Locations:** `smartcontracts/evm/src/pqz/PqzStateLib.sol:41–44,59–65`; `PqzSafety.sol:53–55`; `PqzCore.sol:875–879`.

**Claim:** At `n2304-kmax4096` and `n2560-kmax16384`, initialization accepts PQZH as the token’s immutable proof system, and shielding remains enabled, although ordinary transfer, burn and refresh proofs exceed the required Amsterdam calldata budget.

**Evidence:** Initialization copies `PROOF_SYSTEM_ID()` and calls `requirePqz`, whose accepted set includes PQZH whenever `HAS_PQZH` is true. Neither initialization nor shielding checks whether that system has an executable debit path.

This affects honest proofs, not merely padded maximum-size inputs:

- The committed `test/vectors/pqz-gas/n2304-kmax4096.json:4` records a **248,504-byte honest BURN proof**. Adding only the required burn payload gives `248,504 + 160 + 18,560 = 267,224` bytes, already above the **261,909-byte** calldata ceiling, before ABI encoding or authorization.
- At `n2560-kmax16384`, the same metadata records a **298,116-byte honest BURN proof**, exceeding the ceiling by itself.
- `docs/research/pqzh-calldata-cap.md:138–142` records that ordinary debit forms fail at both sets.

A registrar can publish such a PQZH release; a user can then shield successfully and encounter no usable withdrawal through the shipped prover. The token cannot switch to PQZL: its statement always contains the stored `psid`.

**Suggested fix:** Reject PQZH **value-token initialization** at sets without a debit path that fits the required budget. Keep PQZH registration/disclosure verification available separately. Enforce this in the token as well as release tooling.

**Qualification:** P1 reflects demonstrated withdrawal failure for shipped proofs. This review did not establish mathematical impossibility of every exceptionally short Ligero transcript or identify an already funded deployed instance.

### C2-2 — P2 — Eight-leg transfers remain enabled beyond the required block budget

**Locations:** `smartcontracts/evm/src/pqz/PqzCore.sol:405,478–482,506–522`.

**Claim:** The contract accepts PQZL `M = 8` shapes whose state creation cannot fit the required 60 M block budget.

**Evidence:** `_parseMulti` permits eight legs for every PQZL set:

```solidity
m == 8 && s.psid != PQZH_ID
```

Settlement writes the entire operation blob through one `SSTORE2.write`. The committed measurements in `docs/contracts/pq-zero-knowledge.md:2015–2016` give these concrete full-transaction state costs:

| Shape | n2048 | n2304 | n2816 |
|---|---:|---:|---:|
| M = 8, auditor on | 70.45 M | 65.66 M | 63.44 M |
| M = 8, auditor off | — | — | 62.11 M |

These calls cannot be included in a 60 M block despite passing the contract’s shape checks and fitting the regular transaction-gas cap. COMPACT mode retains the same blob, so it does not resolve the failure.

**Suggested fix:** Restrict the contract’s supported shapes per set to those fitting both budgets, and align clients and selector documentation. Preserve larger shapes in the separately reviewed core if needed. Splitting into smaller transfers is the existing practical alternative.

This is the open measurement result recorded in the specification, not a newly discovered gas measurement.

### C2-3 — P2 — A zero auditor ID passes initialization and disables audited transfers

**Locations:** `smartcontracts/evm/src/pqz/PqzStateLib.sol:34–39,52`; `PqzCore.sol:222–227,417–418,448,862–864`.

**Claim:** FULL and OPTIONAL configurations accept `auditorKey = abi.encode(bytes32(0))`.

**Evidence:** The mode check tests the byte-array length, but the registration check skips a decoded zero:

```solidity
bytes32 a = aud.length == 32 ? bytes32(aud) : bytes32(0);
if (a != 0 && !PqzCore._registered(registry, a)) revert ...;
```

Concrete sequence:

1. Create a token with FULL mode and 32 zero auditor bytes. Initialization succeeds.
2. An auditor-off transfer reverts `AuditorRequired`.
3. An auditor-on transfer calls `_keyPtr(registry, bytes32(0))`, which reverts `AccountNotRegistered`.

The auditor setting is immutable. FULL tokens therefore permanently lack confidential transfers; OPTIONAL tokens permanently lack audited transfers. Burn/unshield remains available, so this is not a permanent funds lock.

**Suggested fix:** Whenever auditor bytes are present, require a nonzero ID and validate it through `_keyPtr`, including the expected key length. Add the zero-ID case beside the existing initialization rejection cases.

### C2-4 — P2 — Native-coin wrap-shield has no token relay path

**Locations:** `smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol:56–58,175–176`; `smartcontracts/evm/src/metatx/MetaTxBase.sol:101–105,213–220`; `UnderlyingLib.sol:156–163`.

**Claim:** A valid native-coin `mtxWrapShield` call cannot execute through either token relay path, contrary to the supplied relayability rule.

**Evidence:** For a native leg, `mtxWrapShield` passes `msg.value` to `UnderlyingLib.wrap`; `_pull` requires:

```solidity
if (value != amount) revert NativeValueMismatch(value, amount);
```

The address relay entry is nonpayable and its self-call is:

```solidity
(ok, ret) = address(this).call(data);
```

Thus relaying `mtxWrapShield(address(0), amountIn, toUA)` with `amountIn > 0` supplies zero value and reverts. The UA path explicitly excludes `mtxWrapShield`. Pre-funding the wrapper does not help because `_pull` checks the call’s value.

ERC-20 wrap-shield is relayable; the native branch is not. The shared wrapper documents this limitation for `wrapToUA`, but it still conflicts with the owner rule supplied for this review.

**Suggested fix:** Provide a value-carrying relay path with the native amount bound to authorization and forwarded to the self-call. Keep it unbatched and preserve the existing reentrancy ticket checks.

## Checked and sound

These are static conclusions, subject to the findings above.

| Invariant | Evidence |
|---|---|
| Op 1 statement | `PqzCore.sol:247–266,875–879`: header, registered keys, reconstructed `T`, and output order match `pqz-stmt`. |
| Op 2 burn/refresh | `PqzCore.sol:549–593`: distinct tags, refresh zero recipient, public amount, zero unused fields, and correct body. |
| Op 3 registration | `UAPqzVerifier.sol:70–75` and `UARegistry.sol:420–425`: framed REGISTER statement includes the registry-derived UA-bound message and key. |
| Ops 4–5 disclosure | `PqzCore.sol:606–665`: stored ciphertext/key selection, entry reference, amount, and auditor window match the codec. |
| Op 7 and S_AUD groups | `PqzCore.sol:237–244,398–473,493–522`: grouping is consistently 2/3/4/4 with auditing and four without; headers and stored offsets agree. |
| Precompile address, input, gas and result | `PqzSafety.sol:12,61–64`; `PqzCore.sol:681–686,869–871`: pinned address, correct framing, available gas forwarded, success plus exactly 32 bytes containing one required. Gas-price calibration was outside scope. |
| Queue, rollover, preparation and replay | `PqzStateLib.sol:73–130`; `PqzCore.sol:741–805,832–847`: bounded ordered processing, preserved un-roll entries, disjoint idempotent preparation halves, MAT-gated hints, and incremented send counter. No additional permanent-lock mechanism found. |
| Packing and carry bounds | `PqzCt.sol:30–50,203–250,315–371`: pack/expand are inverse operations at all four widths; generated rollover bounds and inline bounds keep lanes below `2^64`; accumulator gaps accommodate each batch. |
| Ciphertexts retained and recoverable | Transfer/burn settlement stores blobs; rollover stores packed accumulator words. `PqzLayer.sol:64–105` exposes account, pending ciphertext, accumulator and entry bytes. |
| Pool accounting and fees | `_debit` and `_pay` apply matching `shieldIn − amount − fee` movements; op 7 binds `txFee + M·d` and pays `d` to every leg. Zero fees are accepted. |
| Auditor modes and AuditorAsParty | Mode enforcement and sender/recipient exclusion cover both transfer forms through shared builders; initialization has C2-3. |
| Disclosure views | Bundles are read from state; leg bounds, auditor availability and window offsets are checked. Invalid disclosure requests are caught by `verifyTransferAmount`. |
| ROLL_MAX on relay paths | Constants are 96/80/64/32; source bounds every rollover. Committed records cover both address and ML-DSA-65 relay paths below the prescribed margin; measurements were not rerun. |
| External calls and reentrancy | PQZ write entries use the shared guard. Underlying payouts update reserves before external calls and verify exact outgoing balance deltas; failure rolls back the debit. |
| Release access and initialization | Factory-only, one-time initialization; registry chain UID checked; verifier dependency is release-bound; token pins the actual precompile/system/self-test. C2-1 and C2-3 remain configuration gaps. |
| Relayability | PQZ selectors, including rollover and preparation, have relay rules; percentage fees and batching are refused. Native wrap-shield has C2-4; gas-infeasible shapes have C2-1/C2-2. |

Previous fixes checked: W-A mode binding, W-B precompile pinning, and the CHAIN-01 zero-`u` carry-over remain present. The redesigned queue replaces W-E’s retained-base mechanism; its documented bounded retry residuals remain.

## Not covered

Read all C2 Solidity files and all four generated `PqzSet.sol` files. Outside this review: proof-system soundness and native precompile internals; classical Zether; UA signature implementations; general factory/relay behavior beyond the integration paths cited above; clients and deployed chain configuration. The complete test suite was not read.

No files were changed, and no builds, tests, benchmarks or timing runs were performed. Gas conclusions rely on committed records; the findings were not dynamically reproduced.