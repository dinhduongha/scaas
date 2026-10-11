# TODO — scaas

Ordered by what blocks what (shutdown 2026-10-08). Owner rule: **finish all specs before app code**.
Max 3 agents, one heavy build at a time (`scripts/capped`). The Odoo side lives in bamboo-dms (`dms_blockchain*`).

## 00. Meta-transaction redesign — code streams (accepted 2026-10-08; rules in the component docs)

Order: contracts first (one heavy build at a time), then node, clients, the Odoo connector (bamboo-dms).
Design record: `docs/history/specs/2026-10-08-token-tree-design.md` (accepted and folded 2026-10-08; rules CTR-TOK-21…26,
CTR-MTX-25, CTR-AS-17, CTR-DEX-24, CTR-ZTH-37…47, CTR-ACC-11, CTR-PQZ-22). The MT-1…MT-9 streams are regrouped into
phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TOK-24) and the full forge suite.

| Phase | Content | Streams |
|---|---|---|
| P0 | Spec and fold into the component docs and `decisions.md` | done |
| P1 | The complete base on the new tree: `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer; kinds `NONE`, `UNDERLYING`; factory `createToken`; the v1/v2 lines to the backup (v2 done in P1e, v1 renamed `…V1` until P3/P5) | MT-1, MT-2, MT-3, MT-4 |
| P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, branch `p2a-trade`); **P2b** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle`, `DexPuller` (old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2c** exchange path | MT-5 |
| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; delete `ZetherToken` | MT-6 |
| P4 | `MandateWallet`, `SmartKeyAccount` (rename, every family) on `MetaTxBase` | MT-7 (+ rename in NM-*) |
| P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |

**P1 start checklist (owner decisions 2026-10-08):**
- [x] Keep the old code for reference: git tag `ref/pre-token-tree` on the last commit before P1, and copy the v1/v2 token
      sources and the old `ZetherToken` to `smartcontracts/evm/legacy/` (not built, not tested; a README says "reference only").
- [ ] P1 refactors in place (`git mv` + edit), not a rewrite. Reuse map: `MetaTxCore` → `MetaTxBase`/`ERC20MetaTx`;
      `MetaTokenBase` pay → `PayLib` (not built: pay is inline behind `PAYABLE`, controller ruling pending the owner); `Single`+`Multi` → `UnderlyingLib`/`UnderlyingToken`; `HederaV2Lib` → `HederaLib`;
      `ZetherToken` → `ZetherLib`/`ZetherLayer` (P3); tests ported. `TradeLib` (P2) reuses the owner's prototype
      `/home/ha/work/blockchain/metatx/contracts` (`MtxTradeOrderLib`, `ERC1776Tradeable.mtxTradeOrder`,
      `ERC1776Dex.mtxTrade`) and the `OP_TRADE` legs of `MetaToken`/`MetaTokenBase`/`MetaTxDex`.

**P1 — MT-1…MT-4**
- P1 is split into five plans, written one at a time: **P1a** (MetaTxBase, SigCheck, SaltedEIP712, tag + legacy) — **done 2026-10-09**, merged `1d51d22` (712 tests); plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`; **P1b** ERC20MetaTx — **done 2026-10-10** merged `fb2a234` (758 tests); **P1c** MetaTokenBase + AdminLib/HederaLib + kind NONE (no `PayLib`, C3) — **done 2026-10-10**, merged `3a43c2e` (792 tests); **P1d** UnderlyingLib + UnderlyingToken (1–8 legs, native leg, roles) — **done 2026-10-11**, merged `d03d894` (814 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1d-underlyingtoken.md`; **P1e** `OpenFactory` (`createToken`/`TokenConfig`), CREATE2 deployer + `chainUid()` gate, size gate (ratchet), v1 renamed `…V1`, factory v2 backed up — **done 2026-10-11**, merged `e433bf5` (819 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1e-openfactory.md`. P1 is complete except the partial items MT-1 (v1 line kept as `…V1`), MT-3 (v1 approve), MT-4 (other domains) and the parked items below.
- Asset-suite wording follow-up (P1c final re-review): `asset-suite.md` ~791/793/794/854/906 still say "minter renounced" as the precondition for bond redemption and splits; since P1c the rule is "`MINTABLE` disabled (`disableFeature`)" — `renounceRole` alone leaves the flag set and still yields `MinterLive` (fails closed). Reword when the asset-suite stream starts.
- P1b notes (2026-10-10: all done in P1b except (c), a P5 node item, and (g), deliberately not done; (d) done on bamboo-dms branch `scaas-metatx-v1-kat`, owner merges): (a) `MetaTxBase` alone is ≈ 9.4 KB on the mock — watch the 20,480 B token budget; (b) pin 'every allowlisted function is nonReentrant' without the mock's `poke` forwarder — resolved in P1a final review: `_selfCall` requires ticket 2; (c) relayer gas estimate for SubjectAccount/SmartKeyAccount signers must cover 400k·64/63 + 5k for the ERC-1271 call (P5 node); (d) bamboo-dms `dms_blockchain/tests/test_eip712.py:14` must be repointed to `metatx_v1_kat.json` (other repo). (e) `ERC20MetaTx` (git mv of `MetaTxCore`) sits on `MetaTxBase`: drop `MetaTxCore`'s own `nonReentrant` and `_metaNonce`, declare `_msgSender() override(Context, MetaTxBase)`, `MetaTransfer` path uses `_checkEnvelope` + `_useNonce` (watch the order of the three adjacent uint256 args `batch, nonce, validUntil`); (f) each token re-pins `mtxSelectors()` == `_mtxRule`, and keeps the "no `mtx…` in the allowlist" test; (g) optional: fee checks before the call (`_checkFee` in step 3) so a doomed tx is cheap; a dedicated error for an unguarded allowlisted target (today `Reentrancy()`); (h) `eip712Domain` drop `virtual`; v1 KAT writer `MetaTxKat.t.sol` gets the `WRITE_KAT` guard.
- P1c notes (from the P1b reviews, 2026-10-10): (a) the typed path's "cannot fail after step 3" and `mtxPayReceiverFee` step 5 hold only while `_update` refuses nothing beyond `to == this`: any P1c pause/freeze/feature refusal added to `_update` must be mirrored in `_checkTransfer` (and checked before the receiver-fee transfer); (b) `_chargeFee` re-derives the fee class from `_mtxRule`, so rules must stay constant per selector (hardened in P1b: an ABSOLUTE+FIXED fee is taken as is); (c) Multi `_mtxRule` falls back to `MetaTxBase._mtxRule`, so rules P1c adds in `ERC20MetaTx`/`MetaTokenBase` are dropped on Multi (moot after P1d; otherwise switch it to `MetaTokenBase._mtxRule`); (d) `HederaAccountAuth.sol:29` `asView` safety comment names `executeMetaTransaction` as the sole call site: there are now many non-view call sites (all `nonReentrant`, non-static frames), still safe; repoint the comment in P1c (HederaLib); (e) deferred test gaps still open: Task 3 — `FeePolicy.validateRecipient` is unreachable on both paths (the resolved recipient is never 0; delete or pin), no success-path test of a relayer-filled third-party `feeRecipient` on the typed path (only the `== to` refusal, `test/v2/Base.t.sol`); Task 4 — unwrap: no raw `ERC20InsufficientBalance`-from-`_burn` case when the reserve suffices, no dirty-address-word case; Task 5 — no SmartKeyAccount-clone (400k) payee test, no single-field tamper tests (`fee`/`feeRecipient`/`rfValidUntil`), no invalid-fee-nibble shape case, no RP4 assertions after a failed co-signature. Task 6's gaps were closed in the P1b final fix wave.
- P1c notes dispositions (2026-10-10): (a) no `_update` refusal was added in P1c (flags 5–8 are refused at init, C2): carry to the asset-suite stream; (b) unchanged; (c) done in P1d (`UnderlyingToken._mtxRule` falls back to `super._mtxRule`); (d) done (`HederaLib`, `asView` comment repointed); (e) open test gaps stay as listed.
- Asset-suite stream, from the P1c final review (C2): issuer and compliance must be contract-only when flags 5–8 are built; roles are keyed by flag bit and `_grant` requires the role's own bit, which cannot express FORCE = issuer + compliance or one issuer shared by FREEZE/FORCE/PAUSE, so the stream must key roles by role id (issuer, compliance) or map bits; and any `_update` refusal (freeze/pause/allowlist) must be mirrored in `_checkTransfer` and before the receiver-fee transfer.
- [~] **MT-1** (built through P1e: kinds on `TokenConfig`, `OpenFactory.createToken`; the v1 line is kept as `…V1` until P3/P5, see the backup items under P3 and P5; owner: backup, not delete) Two bases: generic `MetaTxBase` (any SCaaS contract; `_chargeFee` refuses all but `NONE`, CTR-MTX-22) and
      the token base `ERC20MetaTx is MetaTxBase` (absorbs `MetaTxCore`) with `MetaTokenBase` on top; kinds `NONE` and
      `UNDERLYING` (the native-coin leg, CTR-TOK-26) with `AdminLib`, `UnderlyingLib`, `HederaLib`, `SigCheck` (CTR-TOK-21…24); factory
      `createToken` (CTR-TOK-25). Delete what token-tree spec §8 deletes: `ERC20MetaTx`(v1), `MetaToken`, `HederaMetaToken`,
      v1 `OpenFactory`, `MetaTxDex`, `MetaTxCore`, `Single`/`MultiUnderlyingToken` (merged), the `Hedera*UnderlyingToken`
      children, `SigLib`, `OpenFactoryV2.createMetaToken` (gone with factory v2, P1e), the regulated children (flags instead, CTR-AS-17).
- [ ] **MT-2** (P1b built all but the UA split and `mtxWrap`; open: UA path, see UA F1) Two structs, one lane space (CTR-MTX-15): `MetaTransaction{from, data, …}` + `mtxExecute` (+ alias), `mtxBatch`;
      tokens' typed `MetaTransfer{from, to, value, entryRef, …}` + `mtxExecuteTransfer`, `mtxBatchTransfer` (CTR-MTX-23/24);
      named functions keep their signatures and build their struct (CTR-MTX-09); receiver-pays on `MetaTransfer`;
      transient sender and one-shot ticket, per-implementation allowlist + `mtxSelectors()`, fee classes,
      all-or-nothing; `_msgSender()` everywhere per the `msg.sender` inventory; lint/test that no token reads
      `msg.sender` directly except the allowed spots; UA path split into `UAMetaTransaction`/`UAMetaTransfer` +
      `uaExecuteTransfer`/`uaBatchTransfer` (CTR-UA-26); KATs `metatx_kat.json`, `metatransfer_kat.json`, v3 pair.
- [ ] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; open: v1 line (P3/P5, E1); `mtxWrap` for a SCaaS underlying done in P2a (UnderlyingToken; `ZetherToken` in P3).
- [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the other domains: SmartKeyAccount, MandateWallet P4, SCaaSDex P2, UA registry UA F1, Zether digests P3) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
      UA registry, Zether digests); deploy scripts on a CREATE2 deployer; deploy gate checks `chainUid()`.

- UA ledger split (CTR-UA-26: `UAMetaTransaction`/`UAMetaTransfer`, `uaExecuteTransfer`/`uaBatchTransfer`) moved from P1b to UA F1 (R4).
- P1e sizes: `UnderlyingToken` 26,449 B is over EIP-170 (24,576) until the size work (owner: optimise later; baseline in `size-baseline.json`); `UnderlyingLib` 10,096 B; `NoUnderlyingToken` 20,196 B; `OpenFactory` 6,715 B; the deploy scripts deploy only `NONE` for the new factory.
- P1d follow-ups (parked test gaps, not fixed): no `mtxExecute(single-asset selector)` on a two-leg token test; native `UnderlyingTransferMismatch` untested; `addReserve` with native `msg.value > amount` untested; guardian revoke untested (these stay parked; the dead `META_MULTI` count branch is gone with factory v2: done in P1e).
- P1d follow-ups (final review): (a) the native leg is absent from the `WrapperInvariant` handler: add a 4th leg (native, with a `vm.deal` forced coin) and a §12 conformance row for CTR-TOK-26; (b) the deploy scripts must deploy `UnderlyingToken` (it links `UnderlyingLib` and `AdminLib`) once it fits EIP-170.
- P1e follow-ups (parked): (a) the size ratchet does not tighten itself: when a baselined contract shrinks, lower its entry in `smartcontracts/evm/size-baseline.json` by hand (the gate only notes an entry that now fits); (b) `smartcontracts/scripts/deploy.sh` requires `PRIVATE_KEY` (it derives `--sender` from it), so a KMS or hardware-wallet deployer needs a script change; (c) `OpenFactory` accepts the registration of kinds 2 and 3 (`*_ZETHER`) before P3: only the PQZ kinds 4–7 are `KindReserved`; (d) integrators: the factory's underlying index is only as truthful as the implementation, trust it for registered versions (`versionOf(token).version != 0`); `createTokenUnregistered` records version 0; (e) libraries stay placed by forge from the sender's nonce, not by CREATE2 (E7); (f) the P1d parked test gaps above stay.

**P2 — MT-5**
- P2a (done, branch `p2a-trade`, merge pending the final review): `TradeLib` (`scaas.trade`) and the trade entries on every token, `mtxWrap` + `NativeNotGasless` on `UnderlyingToken` (D1 closed; a native wrap by `mtxExecute(wrap(…))` still reverts `NativeValueMismatch(0, amount)`); 855 tests. Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. Open for P2b/P2c: the DEX side below. **F4 (owner): `NoUnderlyingToken` is 22,951 B, over its 20,480 B budget (ratchet baseline), `UnderlyingToken` 29,974 B: optimise later (slimmer `MetaTxBase`, more behind libraries, or a budget change).**
- P2 notes (from P1c, P1d): (2) Named `mtxTransfer` is +9 execution gas over `mtxExecuteTransfer` (33,681 vs 33,672): the row is logged, not asserted; `mtxPay` on a fresh lane is +2.6 k (the `PAYABLE` gate's cold SLOAD, C3). (3) The asset suite's inline per-transfer admin check (CTR-TOK-24) also needs NONE bytes: it competes with the size debt in F4.
- [x] Rename `OrderBookDex` → `SCaaSDex` (owner 2026-10-09; EIP-712 domain name `SCaaS Dex`); git mv + docs + node names. (done 2026-10-09)
- [~] **MT-5** DEX (P2a done: `TradeOrder` + `mtxTrade`/`mtxCancelOrder`/`mtxInvalidateNonces` in the tokens, `receiveToken == this` accepted, flag 4 not read by the token; open: P2b/P2c): `SCaaSDex.mtxSettle`
      (Path A/B, 1 taker + N makers, 50 % floor, fee split, conservation invariant); outside-token legs through the
      `DexPuller` (CTR-DEX-22); exchange path `mtxExchange`/`mtxExchangeVia` (CTR-DEX-20), surplus distribution
      (CTR-DEX-21), interaction blocklist + `LISTED_POOLS`/listed-only (CTR-DEX-23), admin `setExchangeTarget`/
      `setListedOnly` (CTR-DEX-03); tokens accept `receiveToken == this` and flag 4 (CTR-DEX-15).

**P3 — MT-6**
- [ ] v1 line to backup: when `ZetherToken`, `ZetherMetaTx`, `IZetherToken` and `LegacyMetaTransaction` move to the new base, `git mv` `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1` (with `MetaToken`/`HederaMetaToken`/`MetaTxDex` if P5 is done) to `smartcontracts/evm/legacy/` (E1; owner: backup, not delete), and drop them from the deploy scripts.
- [ ] `mtxBatch` needs a not-batchable hook for PQZ selectors (`MtxNotBatchable(selector)`, pq-zether.md CTR-PQZ-21): a batchable flag in `MtxRule` or a `_mtxBatchable(sel)` check in the loop.
- [ ] **MT-6** Zether: transient envelope binding, `zetherShield` from the public balance (CTR-ZTH-45), `mtxWrap`; renames (`zetherRollOverSigned`,
      `zetherSetRollOverMode`, CTR-ZTH-45; built: `rollOverSigned`, `setRollOverMode`); envelope binding without `to`/`value` (CTR-ZTH-06); `PqzToken` on the one base like Zether,
      no `PqzMetaTx`, PQZ selectors not batchable (CTR-PQZ-21); prover `Header` gains `chain_uid` as word 3,
      `HEADER_LEN` 384 → 416 (`clients/zether-prover/src/zether.rs`).

**P4 — MT-7**
- [ ] **MT-7** `MandateWallet` and `SmartKeyAccount` (renamed from `SubjectAccount`, CTR-ACC-11) on `MetaTxBase` (CTR-ACC-06/07/10): delegate/owner calls as
      `MetaTransaction` self-calls, `SmartKeyAccount` signs as itself, typed `PayUnderMandate`/`RevokeMandate`/`OwnerCall`
      removed, named entries derive their lanes; Hedera `mtxExecuteAsOwnerRaw` over the same owner digest; `mtx…` renames.

**P5 — MT-8, MT-9**
- [ ] v1 line to backup: once the node (`src/abi.rs` v1 struct, `executeMetaTransaction`, salt-less domain; e2e v1 `MetaToken` demo tokens) and clientkeys (`metatx_v1_kat.json`) are on the new ABI, move the v1 contracts and the v1 deploy path to `smartcontracts/evm/legacy/` (E1).
- [ ] **MT-8** Node: `mtxInvalidateNonces` replay reverts `MinNonceNotIncreasing` (strictly increasing): the cancel job treats that revert as success; two `sol!` structs, `metatx`/`ua_metatx` jobs name their struct (`call` | `transfer`), selector tables for
      every contract on `MetaTxBase` (NODE-JOB-20), call table names, breaker per `(from, selector)` (`MetaTransfer` =
      `transfer`/`pay`), batching via `mtxBatchTransfer`/`mtxBatch` never mixed (NODE-LANE-11), `chainUid()` check
      (NODE-GW-07), DEX venue `mtxSettle` (NODE-DEX-15/16), intake `allowance(from, puller)`, TradeEngine with
      `trade_engine.*` config and `/v1/dex/exchanges/{ref}` (NODE-DEX-17/18), NODE-IDX-06 `repeat_of`.
- [ ] **MT-9** clientkeys/app and the reference ERP's `lib/eip712.py`: both structs (`MetaTransfer` typed in wallets,
      `MetaTransaction` decoded via `mtxSelectors()`), `domain.salt`, refuse an unlisted `dex`, no EOA approve, wrap by
      signature (CLI-SGN-05, CLI-SGN-33…36); `SmartKeyAccount`/mandate digests as `MetaTransaction`s; vectors/KATs regenerated.

**Non-EVM families (NM-*)**
- [ ] **NM-APT** Aptos: `MetaCall`/`MetaTransfer` (BCS), public `scaas::metacall::verify`, `mtx_` entries incl. key and
      mandate entries, `KeyOp`/`MandateInit`/`key_nonce` removed; new immutable package (NET-APT-27, NET-ALL-26…29).
- [ ] **NM-SUI** Sui: as Aptos plus `mtx_forward` (no `ForwardOp`), client encoders byte-identical (NET-SUI-18, NET-SUI-16).
- [ ] **NM-SOR** Soroban: `mtx_` functions, SEP-41 `transfer` kept, `__check_auth` context allowlist per key (NET-SOR-16,
      NET-SOR-04); new deployments.
- [ ] **NM-COS** Cosmos: `scaas-metacall` crate, `MtxTransfer`/`MtxPay`/`MtxExecuteTransfer`/`MtxExecute` (inner
      `MtxTrade`, `CancelNonce`, mandate `PayUnderMandate`), mandate JSON removed; new code ids (NET-COS-12).
- [ ] **NM-TON** TON: `MetaCall`/`MetaTransfer` cells, `Mtx` messages replacing `SignedOp` ops and `MandatePay`, opcodes
      fixed with vectors; new code (NET-TON-20).
- [ ] **NM-SOL** Solana: fixed layouts, `scaas-metacall` crate, `mtx_` instructions incl. key and mandate entries, `KeyOp`
      and `MandateInit` removed; new program (NET-SOL-33).
- Node (adapters, `signed_op` `op_kind` `call`/`transfer`, per-contract `mtx_` lists, NODE-JOB-20) and clients (`fam/*.js`
  encoders, CLI-SGN-27 checks) follow each family stream; vectors regenerated per family.
- [x] Non-EVM generic signed call (NM-1…5) accepted and folded 2026-10-08; record `docs/history/specs/2026-10-08-nonevm-metacall-design.md`.
- [x] Meta-tx generic call (GC-1…10) accepted and folded 2026-10-08; record `docs/history/specs/2026-10-08-metatx-generic-call-design.md`.
- [x] DEX exchange path (DS-1…8) accepted and folded 2026-10-08; record `docs/history/specs/2026-10-08-dex-exchange-design.md`.

## 0. Finish the spec phase (5 items left)

- [ ] **P0 follow-ups (minor, deferred by the final review):** `zether.md` gas-cap / 2.5 M paragraphs quote only
      single-recipient figures; `zether.md` ~1327 `recipient` vs target `to`, ~216/220/238 informal `zetherShield(Y…)`
      prose; architecture sequence 5 lacks `UnderlyingLib`; `asset-suite.md` 893–897 "BUILT" next to `createToken`, `IRegulatedToken` block old names (`issuer()`, `compliance()`, `ControlsDisabled`, `RoleRenounced`);
      `clients/app.md` CLI-APP-26 cites CTR-TOK-21 for built kinds; `node/store.md`:157 SQL comments; `node/job-api.md`:328
      unlabelled `SmartKeyAccount.mtxExecuteAsOwner`; CTR-TOK-26 "the invariant" wording; `dropped-artifacts.tsv` duplicates
      and the bare token `273`; CTR-ACC-80 "(then named SubjectAccount)"; budget warnings `token-wrappers.md`, `dex.md` (owner).

- [ ] **Rewrite `docs/integration.md`** (owner 2026-10-09: later). Goal to settle when started: shorten/restructure, align with the token tree and meta-tx v3, ERP-neutral; then `integration-odoo-example.md`. Keep the 27 `INT-ERP-*` ids (supersede, never renumber). No code dependency; PQZ parts stay open.

Done 2026-10-07: every spec reviewed — Codex on PQZ/UA/NI/B, Claude on the 16 older specs — and every review
folded (dispositions inside each spec; review files in `docs/reviews/specs/`, git-ignored). Owner rulings today:
chainId 9000 → **7622**; `PqzToken` implements `IERC20MetaTx` (PQZ rev 1.4 R284); Move/Solana (and Cosmos
`--no-admin`) programs **immutable at deploy** (round3 CR-R3-11, NI R348).

- [x] **Docs reorg** (plan `docs/history/plans/2026-10-07-docs-reorg.md`), done 2026-10-07: component docs from
      [`docs/README.md`](docs/README.md), register + alias index in `docs/decisions.md`, history frozen in `docs/history/`,
      ledgers in `docs/history/reorg/`, Phase 4 reviews (28 findings) and a 10 % second sample (3 minor) fixed, all
      diagrams Mermaid (checker C11), CI `docs` job. Review files: `docs/reviews/reorg/` (git-ignored).
- [x] ~~**Sync `docs/SCaaS.md` + `docs/integration.md`**~~ (closed by the docs reorg; files now `docs/history/SCaaS-2026-10-07.md`,
      `docs/history/integration-2026-10-07.md`) with the latest folds — collect every "Amends"/"amendments"
      table in: NI rev 3.7 (R340–R349), PQZ rev 1.4 (R284 meta-tx, register row still says 1.2), round3 rev 1.2,
      payments rev 1.1, wallets addendum, signing-formats, infra rev 1.2, DEX rev 1.1, Zether rev 1.1, net-* rev 1.1/1.2.
      Known SCaaS.md errors: §7.7 Solana `MetaOp` is 336 B not 337; §7.6 TON TODO #8 done, `BindKey` doesn't exist
      (stateInit in `SignedOp`, R10-5); §7.4 Soroban nonce is `sha256("scaas.soroban.nonce"‖entryRef‖validUntil)`, `pay_ref`
      lock per `(from, pay_ref)` (R8-9), DEX needs relayer binding (R8-10); §7.2 `associateUnderlying()` superseded
      (R6-8, TW2 R144); §7.5 add lane-horizon client obligation (RS7-11, RS11-24, RS12-24) + Aptos multisig-wrap risk;
      §1.2/§1.3 immutability now true by ruling; admin-exception list; outbox rules into integration.md.
- [x] **NODE-IDX-06** rules in the docs (`node/indexer-feeds.md`, `integration.md`); the code is stream MT-8 (node) and the
      client refund check.
- [x] Cross-spec nits, closed by the reorg and the meta-tx fold (checked 2026-10-08): Soroban has no open form
      (`networks/README.md`, [NET-SOR-10]); PAY-FIX6 = the 1271 cap [CTR-DEX-08]; PAY-FIX7 = fee round-up [CTR-DEX-11];
      `job.sponsor_fallback` in `node/job-api.md`, `node/sponsorship.md`.
- [ ] **Codex reviews still owed** (credit ran out after 4): AS, TW2, app, OPS, S4F, mesh, A2 (SCaaS.md and integration.md
      dropped: frozen in `docs/history/`; reorg Phase 4 reviews the new docs). Review the current component doc of each
      area (map in `docs/README.md`), not the frozen spec.
      All already have a Claude review. Run with `codex exec -m gpt-5.5 -s read-only -C <scaas> -o <out.md> "<prompt>"`
      (default `gpt-6.1-sol` is rejected for a ChatGPT account); outputs `docs/reviews/specs/*-codex-review-1.md`; fold.
- [x] **ChainId 9000 → 7622** stream CHAINID done 2026-10-07: genesis reset (`0x24e43dcb…c464`), `private7622` dir +
      foundry profile, KAT/mesh vectors regenerated, node examples, Odoo chain record + tests. Left: `private9000`
      mentions in `docs/history/SCaaS-2026-10-07.md` + `docs/history/integration-2026-10-07.md` (history: the reorg writes 7622 only); `chain_uid` = genesis hash binding (UA R330, not built);
      redeploy the dev contracts on the empty chain.
- [x] Doc nits: Zether chains set `max_gas_per_tx` ≥ 4.2 M (`contracts/zether.md` gas table). Left as code: `wasm-smoke.sh`
      builds `--target nodejs` only; a `--target web` build for the app is client work (S4F/app).

## 1. Code streams (after §0)

**Fix first (bugs found in BUILT code by the 2026-10-07 reviews):**
1. **NET-TON-FIX1** (BLOCK: unbounded forward TON drains a lane — no job API/mesh/gateway path may reach a TON lane until the node half lands), NET-TON-FIX2…4.
2. Node money safety: **NR1** breaker meters fees/value/deposits + attempt cap + grief score (R340–R342), **NR2** payload-sourced fields, value-out cap, deposit rule (R344–R346), NR3 mesh sig verify (R343, before S5), NR4 journals → `outer_tx` (R347), NR5 immutable-program check + one custody key per family (R348–R349).
3. **PAY-FIX1** Odoo outbox ACL + immutable job fields, **PAY-FIX2** node `call` target/selector table, PAY-FIX3 event-set quorum, PAY-FIX4 gateway intake, PAY-FIX5 idempotent signed report; ADW-FIX1–4.
4. DEX: DX-FIX1–5 (dust maker freeze, poison fee token, 1271 gas cap, non-EVM relayer binding).
5. Per family: R3-FIX1–15 (Cosmos passkey v2, WebAuthn vectors, event quorum, Soroban `pay_ref`, Solana build-time network, Sui `Keys`, guardians, TON domain, **R3-FIX15 immutable deploy + gate + redeploy**), WSF-FIX1–2, NET-{COSMOS,SUI,HEDERA,SOROBAN,APTOS,SOLANA}-FIXn (code-stream tables of the frozen `docs/history/specs/net-*`), ZF-FIX1–3.

Then the first feature wave: **NI P2 → P3** (money-safety core), **UA F0 → F1** (many specs depend on it), **app A1 + A0-evm**.

Stream ids are unchanged by the docs reorg. **Doc** = the current rules a stream implements; **Scope** = the frozen
stream definition (scope, gate, depends) in `docs/history/specs/` — section numbers as in those files.

| Area | Streams (spec) | Doc | Scope |
|---|---|---|---|
| Node | P2 job API + client API keys + built-in admin/CLI → P3 submit/lanes from store → P4 indexer + `/v1/events` → P5 Odoo client (bamboo-dms) → P6 push e2e + cutover runbook → [owner cutover] → P2b OIDC + admin routes + CORS → P1b PostgreSQL/MySQL → P7 DEX in store → S1b′ → S5 mTLS bus → S6′ → G1 libp2p/QUIC-PQ → G2 announce/exclusivity/hints → G3 DEX book gossip (home-bound + unbound) → S7″ → P9 remove pull path → S8″ docs. Plus N1/N2/N4 (app §9.6), N3 non-EVM DEX books, OPS OP1–OP8, SP1 sponsorship · DX-FIX1 dust maker skip, DX-FIX2 fee-token allowlist + pair-failure attribution, DX-FIX5 pending commitment + market re-check + IOC single-maker + late-Matched debit (DEX spec rev 1.1; fold into P7 if P7 starts first) · ZF-FIX3 Zether verifier/registry pin (gateway + clientkeys), cache key chain id, `schnorrSign` k test-only (Zether rev 1.1) | [node/](docs/node/README.md): [store](docs/node/store.md), [job-api](docs/node/job-api.md), [submit-lanes](docs/node/submit-lanes.md), [indexer-feeds](docs/node/indexer-feeds.md), [admin-auth](docs/node/admin-auth.md), [dex-venue](docs/node/dex-venue.md), [mesh](docs/node/mesh.md), [gossip](docs/node/gossip.md), [ops](docs/node/ops.md), [runbooks](docs/node/runbooks.md#cutover), [sponsorship](docs/node/sponsorship.md) | P*: `2026-10-06-node-independence-design.md` §17; S*: `2026-10-05-relayer-mesh-design.md` §14 + NI §13.2; G*/S6′/S7″/S8″: `2026-10-06-mesh-gossip-amendment.md` §17; OP*: `2026-10-06-operations-design.md` §13; SP1: `2026-10-06-tender-sponsorship-shredding.md` §8; N1–N4: `2026-10-06-scaas-app-design.md` §9.6; DX-FIX: `2026-10-03-dex-design.md` §8 (Claude review disposition); ZF-FIX: `2026-10-03-zether-design.md` (Claude review disposition) |
| Contracts | TW2 T7 (node/Odoo/SDK follow-ups) · AS1–AS9 asset suite · TB1–TB3 tender, RP1–RP2 receiver-pays (RP1 before production registration O3), CS1–CS2 shredding, PL1 pool (later) · UA F0–F10 · PQZ E-S0…E-S9 (spikes first; licence gate G-LIC before production) · DX-FIX3 `SCaaSDex` 1271 gas cap + bounded returndata (redeploy), DX-FIX4 non-EVM DEX relayer binding (Cosmos/Soroban/TON) + `min_nonce` caps (Sui/Aptos/Solana) · ZF-FIX1 `ZetherMetaTx` 1271 400k/50k + FeeWouldStick + disclosure NatSpec, ZF-FIX2 Zether invariant/subgroup/`D_out = O` tests | [contracts/](docs/contracts/README.md): [token-wrappers](docs/contracts/token-wrappers.md), [asset-suite](docs/contracts/asset-suite.md), [tender](docs/contracts/tender.md), [universal-account](docs/contracts/accounts.md), [pq-zether](docs/contracts/pq-zether.md), [dex](docs/contracts/dex.md), [zether](docs/contracts/zether.md); [networks/](docs/networks/README.md) for non-EVM | T7: `2026-10-06-token-wrappers-v2.md` §15; AS*: `2026-10-06-asset-suite-design.md` §13; TB/RP/CS/PL: `2026-10-06-tender-sponsorship-shredding.md` §8; F*: `2026-10-06-universal-account-design.md` §16; E-S*: `2026-10-06-pq-zether-design.md` §16; DX-FIX/ZF-FIX: as above |
| Clients | S4F D1–D7 · app A0–A18 (order in app spec §15) | [clients/signers-clientkeys](docs/clients/signers-clientkeys.md), [clients/app](docs/clients/app.md) | D*: `2026-10-06-signers-followups.md` §10; A*: `2026-10-06-scaas-app-design.md` §15 |
| Odoo (bamboo-dms) | P5, UA F6, AS/TB/SP Odoo parts, connectors wiring (S4F finding: non-EVM portal connectors not wired) | [integration.md](docs/integration.md), [integration-odoo-example.md](docs/integration-odoo-example.md) | P5: NI §17; F6: UA §16; AS: `2026-10-06-asset-suite-design.md` §9.2; TB/SP: TSS §8; connectors: S4F §10 |

## 2. Ops / housekeeping

- [ ] Redeploy all dev/test contracts (tags renamed); update `blockchain.token.domain_name` / Cosmos `network_key`.
- [ ] Remove merged worktrees under `.claude/worktrees/`.
- [ ] Residual TON: a `final` from the indexer before the node's `mined` still flags `landed_elsewhere` (informational).
- [ ] Queued research: none open beyond the specs above.

Owner/operator gates from `docs/history/HANDOFF-blockchain.md` §1 (O1–O8 are standing rules in
[node/runbooks.md#production-gates](docs/node/runbooks.md#production-gates)):

- [ ] O9 — Decide the DPIA / CI gate for landing on-chain payments into the ERP (SRS deltas #11).
- [ ] O10 — Write the onboarding procedure for `MandateWallet` / subject accounts (deployed outside the ERP, R29).
- [ ] O11 — Every collecting entity that receives on-chain needs a `chain` payment provider, a journal and an approved
  receiving wallet (after the territory consolidation; GA 2.4#4).
