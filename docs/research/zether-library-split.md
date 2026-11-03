> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Zether token bodies into `ZetherLib` / `ZetherWrappedLib` (2026-11-03)

Owner ruling 2026-11-03 ([CTR-ZTH-94](../contracts/zether.md#CTR-ZTH-94)): move the Zether token function bodies into the
existing libraries, shared code into `ZetherLib`, wrapped-only code into `ZetherWrappedLib`; no new library. Goal: a smaller
deploy transaction for `NormalZetherToken` and `WrappedZetherToken` on public chains (ETH about 60 M gas per block, BSC about
70 M) under EIP-8037 (a transaction fits only if regular + state gas fits the block), and more room under the 64 KiB ceiling
(EIP-7954).

## 1. Measured first (main `db9f9d86`)

Runtime bytes per function, from the solc source map of each token (the AST plus the generated Yul sources, the
`generatedSources` output): every instruction is charged to the innermost function whose source range holds it. Shared
blocks that the optimizer merged are charged to one of their users, so a figure is a lower bound for that function.

| | `NormalZetherToken` | `WrappedZetherToken` |
|---|---:|---:|
| Runtime | 52,874 | 62,305 |
| Of which: generated Yul (ABI coders, utilities) | 15,943 | 17,506 |
| Of which: dispatcher and compiler code | 6,461 | 7,254 |
| Of which: functions of the Zether layer (`ZetherLayer`, the kind, inlined `ZetherLib`) | 7,063 | 8,134 |
| Coders of the Zether types (`G1`, `ZetherMulti`, `ZetherSingle`, `ZetherBurn`, `Unwrap`, `Env`, `Paid`) | ~4,500 | 4,898 |
| Of which decoders of the entries' own arguments (stay: the ABI is the token's) | ~2,000 | 2,182 |

The bodies themselves are already thin: every op calls `ZetherLib` for its logic. What the token still carries per op is the
ABI **encoding** of its calldata structs, to hand them to the library (`ZetherLib.transferMulti(t, proof, mode, _env())`) and
to build a signed entry's struct words and op call (`_multiCall`: `ZetherLib.hashMulti(t)`, `abi.encodeWithSelector(sel, t,
proof)`). `abi_encode_struct_G1_calldata` alone is 780 B on the wrapped kind. Largest Zether functions on the token
(bytes, normal / wrapped):

| Function | NZT | WZT | Hot path |
|---|---:|---:|---|
| `mtxSelectors()` (the table) | 1,008 | 157 (in `ZetherWrappedLib` since C3) | no (a view) |
| `_init` + the `TokenConfig` decoder of `initialize` | 295 + ~1.3 K | in `ZetherWrappedLib` since C3 | no (once per clone) |
| `mtxUnshieldUnwrap` (direct) / `_unwrapCall` | — | 428 / 339 | unwrap |
| `_multi` / `_multiCall` | 239 / 234 | 239 / 234 | transfer |
| `_unshieldCall` / `_singleCall` | 235 / 225 | 235 / 225 | unshield / transfer |
| `mtxUnshield` (direct) / `mtxConfidentialTransferSingle` (direct) | 210 / 172 | 229 / 181 | |
| `accountState` / `transferEntry` / `transferMemo` (views) | 278 / 266 / 209 | 244 / 240 / 199 | eth_call |
| `mtxWrapShield` (direct) | — | 354 | wrap |
| each signed `mtx*` / `ua*` entry (stub) | 48–92 | 59–84 | |

## 2. Plan (written before coding)

**The pattern.** A moved entry keeps its external declaration on the token (selector, ABI, the decoder of its arguments,
`nonReentrant`), and its body becomes one DELEGATECALL into the library with the entry's **own calldata as it arrived**
(`msg.data[4:]` under the library function's selector, decoded there), followed by the words the library cannot read itself
(the immutables of `_env()`: registry, `chainUid`, burn verifier, domain separator, and the binding of this call). The
library returns what the token must do with its own internals (`_poolMove`, `_fromPool`, `_namedCall`), which stay on the
token. So no coder of a Zether struct stays in the token: the library decodes the arguments it needs; the token only decodes
the library's flat return.

| Entry (both kinds unless noted) | Moves to | What stays on the token |
|---|---|---|
| `mtxConfidentialTransfer` / `…Compact` (direct) | `ZetherLib.transferMulti` | the pool payouts (`Paid`) |
| `mtxConfidentialTransferSingle` (direct) | `ZetherLib.transferSingle` | the fee payout |
| `mtxUnshield` (direct) | `ZetherLib.unshield` | the recipient check, the pool moves |
| the signed and `ua*` forms of the three (6 + 6 entries) | `ZetherLib.multiCall` / `uaMultiCall`, `singleCall` / `uaSingleCall`, `unshieldCall` / `uaUnshieldCall`: the struct words, the op call, the typehash | `_namedCall` / `_namedCallUA` (nonce, signature, self-call, fee) |
| `mtxUnshieldUnwrap` (direct, wrapped) | `ZetherWrappedLib.unshieldUnwrap` (the binding and `ZetherLib`'s unshield logic, inlined) | the leg index, the pool moves, `WrappedLib.payOutTo` |
| `mtxUnshieldUnwrap` / `uaUnshieldUnwrap` (signed, wrapped) | `ZetherWrappedLib.unwrapCall` / `uaUnwrapCall` | `_namedCall` / `_namedCallUA` |
| `NormalZetherToken`: `initialize`'s decode and `_init`; `mtxSelectors()` | `ZetherLib.initNormal`, `ZetherLib.normalSelectors` (as C3 did on the wrapped kind) | `AdminLib.init` and `_mint` from the returned words (so `ZetherLib` gains no DELEGATECALL) |

**Not moved.** `mtxShield`, `mtxWrapShield`, the roll-overs and their signed forms: static arguments, no struct coder, the
body is mostly token internals (`_poolMove`, `WrappedLib.wrap`); the gain would be the call stubs only. The views: a view
cannot DELEGATECALL without a cast past the view checker, and legacy codegen keeps the return encoder in the external
wrapper anyway (§8 of `evm-size-levers.md`, R1′).

**Expected saving** (from §1; the encoders go only when every site that encodes the type goes):

| | `NormalZetherToken` | `WrappedZetherToken` |
|---|---:|---:|
| Signed builders and their typehashes | ~0.9 K | ~1.2 K |
| Direct op bodies | ~0.3 K | ~0.5 K |
| Zether struct encoders | ~2.0 K | ~2.1 K |
| Init path and selector table | ~2.3 K | — (done in C3) |
| New forwarding helper and return decoders | −0.3 K | −0.3 K |
| **Total** | **~5.2 K → ~47.7 K** | **~3.5 K → ~58.8 K** |

**Deploy transaction** (EIP-8037, measured on main by `ZetherDeploy.t.sol`'s `test_zetherStack_fitsOneOsakaTx`): state gas
is 1,530 gas per code byte plus the new account, regular gas about 70 per init-code byte, so about 1,600 gas per byte in all.
`NormalZetherToken` 3,731,285 + 81,178,740 = 84.9 M, `WrappedZetherToken` 4,345,035 + 95,608,170 = 100.0 M. A 60 M block holds
about 37.3 KB of runtime, 70 M about 43.5 KB. **This ruling alone does not bring either kind under 60 M or 70 M**: the base
kinds are `NormalToken` 37,487 B and `WrappedToken` 48,278 B, so even the whole Zether layer moved out would leave
`WrappedZetherToken` above 70 M. It removes about 8 M (normal) and 6 M (wrapped) of the deploy transaction.

**Extra gas per call** (expected): the signed and `ua*` entries today already make one DELEGATECALL (`ZetherLib.hash*`); the
new one replaces it, and the library returns the op call, which the token copies once more (a few words per 32 B of proof):
about +0.5 K to +2 K per call against a transfer of 4.3 M (BLS12-381). The direct ops replace an ABI encode by a calldata copy:
about 0 or less. Init: one-off. `mtxSelectors()`: an `eth_call`.

**Checks** (AGENTS, a library split is not free): storage (the library writes the token's `scaas.zether`, `scaas.token` and
`scaas.wrapped` namespaces by DELEGATECALL, as today; no new state), `this` and `msg.sender` (unchanged under DELEGATECALL;
`msg.data` is the forwarded copy, read only for the tail), return data (flat words decoded on the token; a revert bubbles
verbatim), reentrancy (the guard stays on the token's entries; the libraries make no call back), `LinkClosure` (`ZetherLib`
keeps 0 DELEGATECALLs, `ZetherWrappedLib` keeps 2; the release closures do not change).

## 3. Result (branch `zether-lib`)

**Sizes** (`forge build src --sizes`, runtime, init in brackets):

| | main `db9f9d86` | `zether-lib` | Change | Expected (§2) |
|---|---:|---:|---:|---:|
| `NormalZetherToken` | 52,874 (56,446) | 47,470 (51,042) | −5,404 | ~−5.2 K |
| `WrappedZetherToken` | 62,305 (65,887) | 58,407 (61,986) | −3,898 | ~−3.5 K |
| `ZetherLib` | 19,690 | 26,131 | +6,441 | |
| `ZetherWrappedLib` | 4,958 | 11,471 | +6,513 (holds a copy of the unshield code) | |

What stays of the Zether layer on the token is mostly the decoders of the entries' own arguments (about 2.5 K on the normal kind,
2.8 K on the wrapped one), the views (`accountState`, `transferEntry`, `transferMemo`, `curve`), `mtxShield`, `mtxWrapShield`, the
roll-overs, `_env()` and the two envelope bindings.

**Deploy transaction** (regular + state gas; `ZetherDeploy.t.sol` `test_zetherStack_fitsOneOsakaTx`, the libraries by the same
CREATE2 probe in a scratch test):

| | main | `zether-lib` | 60 M | 70 M |
|---|---:|---:|---|---|
| `NormalZetherToken` | 3,731,285 + 81,178,740 = 84,910,025 | 3,381,760 + 72,910,620 = 76,292,380 | no | no |
| `WrappedZetherToken` | 4,345,035 + 95,608,170 = 99,953,205 | 4,093,293 + 89,644,230 = 93,737,523 | no | no |
| `ZetherLib` | ≈ 31.6 M (formula) | 1,725,675 + 40,164,030 = 41,889,705 | yes | yes |
| `ZetherWrappedLib` | ≈ 8.1 M (formula) | 772,803 + 17,734,230 = 18,507,033 | yes | yes |

State gas is 1,530 per runtime byte plus 281,520 for a token (183,600 for a library); regular gas about 71 per byte. Still to go:
`NormalZetherToken` 10.2 KB (60 M) / 3.9 KB (70 M), `WrappedZetherToken` 21.1 KB / 14.9 KB.

**Gas per call** against main (`forge test --match-path 'test/zether/*' --gas-report` and the suites' own gas lines; forge gas is
deterministic; min / median / max where the call counts match):

| Entry | Change |
|---|---|
| `mtxConfidentialTransfer` (direct), `M = 1 … 8`, BUNDLE and HASH, auditor in or out | −1,195 … −4,554 |
| `mtxConfidentialTransferSingle` (direct) / relayed through `mtxExecute` (bn254 row) | −337 … −437 / −439 |
| `mtxUnshield` (direct) | +116 … +222 |
| `mtxUnshieldUnwrap` (direct, wrapped) | max −39 |
| `mtxConfidentialTransfer` (signed) | +5,737 / +1,218 / +13,926 |
| `mtxConfidentialTransferCompact` (signed) | +5,718 / +4,055 / +17,010 |
| `mtxConfidentialTransferSingle` (signed) | +3,969 / +1,898 / +3,569 |
| `mtxUnshield` (signed) | +2,608 / +1,217 / +2,789 |
| `uaConfidentialTransfer` / `…Compact` / `…Single` | median +1,046 / +1,089 / +1,717, max +3,778 / +3,883 / +3,375 |
| `uaUnshield` | +1,046 / +1,834 / +2,622 |
| `mtxUnshieldUnwrap` / `uaUnshieldUnwrap` (signed, wrapped) | +405 / +1,089 / +1,773 and +303 / +991 / +1,678 |
| `NormalZetherToken.initialize` (once per clone) | median +5,668 |
| `mtxSelectors()` on `NormalZetherToken` (an `eth_call`) | +13,228 |
| not moved (dispatch order): `mtxShield`, `mtxRollOver`, `mtxRollOverSigned`, `mtxSetRollOverMode`, `curve` | +26, +45, +5, −62, +34 |

The signed forms pay for the op call crossing the library boundary: the library encodes it (its memory) and the token reads the
returned copy (its memory), where the token encoded it once before; at `M = 8` the call is about 31.5 KB. Two copies were removed
while measuring: Solidity's `delegatecall(bytes)` copies its argument once more (so `_lib` builds the request in place in
assembly), and `abi.decode` of the returned `(bytes32, bytes, bytes)` copies the op call again (so `_built` reads it in place).
Before those two the direct transfers cost +0.9 K to +8.2 K and the signed ones up to +55.7 K.

**Checks.** Every test of `forge test` passes unchanged, no gas pin and no KAT moved; the ABI and the method identifiers of both
tokens are identical to main's; `LinkClosure.test_libraryOpcodes` (0 DELEGATECALLs in `ZetherLib`, 2 in `ZetherWrappedLib`),
the layout pins (`test/v2/layout/`) and the typed-ops vector rows (`ZetherTyped.t.sol` `test_typedOpsVectors_*`: the cross-language
signatures over the moved typehashes and struct words still reach the op) pass. New: `ZetherMulti.t.sol`
`test_nestedOffsetReadsAnAppendedWord` pins the malformed-calldata difference (a `sealedMemo` offset aimed at the appended
binding word reads it, 0, as the empty memo of the well-formed BUNDLE call; aimed past the appended words it is refused).

**Not done, for a later round.** The roll-over family (static arguments; about 0.3 K of helpers left), the views (need a view
cast past the checker), and anything beyond the Zether layer: closing the remaining gap needs the `NormalToken` / `WrappedToken`
bases themselves to shrink (the `mtx*` / `ua*` merge round, or lever 3).
