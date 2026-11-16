# Deploy set `mldsa-on`: the real-transaction rows

Status: **PLANNED** (inventory, 2026-11-16; branch `mldsa-on-e2e`). Test chains only. **UNAUDITED.**

Owner 2026-11-16 ("Ok, cách 2, một chain hai bộ deploy"; "Ok, cách 1, bắt đầu viết ngay"): reset 5 deploys the same build twice on
the SCaaS testnet, set `mldsa-off` (`MLDSA_PRECOMPILE=off`, the registry's expanded-key cache) for the whole forge matrix
([README.md](README.md)) and set `mldsa-on` (the shipped default: `MldsaVerifier` on the chain's ML-DSA precompiles) checked by
real transactions. Forge's EVM has neither the ML-DSA nor the PQZ precompile: a forge script runs every call in that EVM before
it sends one, so any step that verifies an ML-DSA signature through `MldsaVerifier` on a precompile, or an `R_REG` proof through
the registry's `PqzKeyVerifier` (kind 0x0142), reverts there and the script sends **nothing** (not even its earlier, classical
steps). The forge scripts stay as they are: the rows of local anvil and of set `mldsa-off`. The Python rows below cover only what
forge cannot run on set `mldsa-on`.

## Which rows

The two sets are one build; they differ only in the registry's ML-DSA verifiers (`mldsa44_verifier`, `mldsa65_verifier`,
`mldsa87_verifier`, `mldsa_precompile` in the book). A row that never verifies an ML-DSA signature runs the same code on both
sets, so set `mldsa-off`'s forge run covers it; it is not repeated here.

| forge group | on set `mldsa-on` | rows here |
|---|---|---|
| gov, dex, liquidity, misc, zether, rescue, wraplimits | no ML-DSA holder: run as on `mldsa-off` | none |
| verifiers, views | Python `eth_call` on the node (the precompile answers) | none |
| misc's `cacheExpandedKey(mldsa44)` | listed as a `_neg` (`UAKeyCache`), checked by `eth_call` on the node | none |
| mldsaalt | main `on`: the throwaway registry is `off` (cache), forge runs it; its `on` side is set `mldsa-on` itself | `mldsa` |
| tokens | `_registerMl` in `run()` reverts: nothing sent | `tokens`: the ML-DSA rows only |
| pqchat | `_members` reverts: nothing sent | `pqchat`: every signed write |
| pqzkeys | local only today (`PQZK_WHY` in matrix.sh; 0x0142 on both sets) | `pqzkeys`: the ML-DSA and 0x0142 rows |
| pqzwallet | as pqzkeys | `pqzwallet` |
| pq, pqoff | e2e.py on its own deploy (owner 2026-11-15), unchanged | none |

### `mldsa`: the registry's precompile path (MldsaAlt.s.sol `_kind` 63-91, `_refusals` 98-112: its `on` side)

Per ML-DSA kind enabled on the set's registry (0x0130, 0x0131, 0x0134; `kindEnabled`): `register` with its PoP (the vector key of
`vectors/ua/pq_signatures.json` rows 0, 1, 4, or a fresh seed when the vector UA is already registered), `requireAuthorized` as a
transaction of its own; negatives by `eth_call`: `cacheExpandedKey` refused `UAKeyCache`, a signature with one byte changed refused
(its positive control: the same call with the good signature answers).

### `tokens`: the ML-DSA-65 signer (Tokens.s.sol `_registerMl` 177-198, `_pq` 443-462 from `_common` 420-430)

`uaM`, an ML-DSA-65 UA, `register` on the set's registry (no cache part: a precompile verifier refuses the cache). Per kind 0, 1, 2,
3, 8, 9, 10, 11 one token on the set's factory, then as `_pq`: `transferToUA(uaM, 10 000)` by test key 1, `mtxTransfer` fee 0 and
`mtxTransferWithFee` (FIXED 5 to test key 3) signed by `uaM`, sent by test key 2; the balance checked; a negative by `eth_call`:
the same transfer with one signature byte changed. The tokens carry only what the ML-DSA row needs (the wrapped kinds one
MockERC20 leg wrapped by test key 1; the Zether kinds BLS12-381 version 1 without an auditor; the regulated kinds no KYC / TAX
flag): the kinds' other features are set `mldsa-off`'s rows.

### `pqchat`: every signed write (PqChat.s.sol 217-598)

The set's release and instance (`pqchat_implementation`, `pqchat_instance`), three ML-DSA-65 members with a KEM key at version 0
(`register`), a kind-0 fee token, then as forge: `_whole`, `_chunks` (`addWraps` through `RelayFeeRouter`), `_rekeys`, `_replica`
(a second instance by `createInstance`), `_postChunked`, `_removeRace`, `_post`, `_leaveAndDrop`, `_store`, `_topic`, `_entries`,
`_votes`, the views read back after each step, the same negatives by `eth_call`. Not here: `_rescue` (no signature: set
`mldsa-off`). The typed digests come from the contracts' own code: `PqChatDigests` (PqChat.s.sol 22-80, forge's artifact) run by
`eth_call` with its runtime code placed by the call's state override, never sent and never a Python reproducer.

### `pqzkeys`: the three-key model (PqzKeys.s.sol)

Holders `uaM`, `bob`, `carol` (ML-DSA-65, `_holder` 488-504), the msig `mu` (`_msig` 506-527: `registerMsig`, `acceptMembership`,
member signatures by ML-DSA). PQZ tokens of kinds 4, 5, 12, 13 created **on the set's factory** (its PQZ releases, DEPLOY_PQZ) in
the `OFFCHAIN` verify mode with the verifier EOA `vA` (`_conf` 433-435; `PqzStateLib.init` takes `OFFCHAIN` on any release, the
precompile is never called for it), not on a factory of the group's own as forge does on anvil, so the rows run the set's
releases. Then `_confidential` 881-915: the scoped records of the six tokens (`setPqzScopedKey` signed by the holder,
`storePqzScopedPop` with a **real** `R_REG` proof of a **real** PQZ key: the set's registry checks it through `PqzKeyVerifier` and
refuses forge's filler bytes `UAPoP`), `_life` 917-950 per token (shields, op 1 and its compact form, op 7 and its compact form
or the `OpUnsupported` negative, unshields, unshield-unwrap, `mtxPrepareAcc`), the msig's record and credit, `_namedLife`
1019-1030, `_wrapShield` 999-1007, `_rotation` 1009-1017, `_openingKinds` 1032-1048, `_registryKeys` 1052-1068 (`setPqzKey` +
`storePqzPop` real, `setKemKey`), `_burnerPqz` 952-975 (bob's unshield), the record and registry negatives (`_registryNegatives`
1171-1210). Ciphertexts and op proofs stay filler as in forge (an `OFFCHAIN` token checks `vA`'s signed `PqzVerdict`, not the
proof). Then the roll phase (`PqzKeysRoll` 1256-1351), after `ROLL_AGE` + 1 = 6 blocks: on a remote chain the run waits for real
blocks (~30 s at the testnet's Clique period of 5 s; bounded, a named stop), on anvil `evm_mine`; the signed rollovers
(`_signed`, `_rollByAddress`, `_signedBob` with their negatives), the public rollovers, the debit over the rolled `acc`, the
owner's ops.

Not here (no ML-DSA, no 0x0142; decision D1 below): `_publicLayer` 600-612 but its `_pq` rows, `_trades` 630-662, `_pull`,
`_regulatedPowers` 1070-1096, `_wrapLimits` 1122-1153, `_factoryNegatives` 1212-1226. `_pq` on the PQZ kinds 4, 5, 12, 13 (the
public layer's ML-DSA rows) is in `tokens`, on tokens of those kinds.

### `pqzwallet` (PqzWallet.s.sol)

After `pqzkeys` (its holders, bob's records): dave and erin (`_holder` 85-99), their records with the real keys of
`pqz-wallet-sim keys` (`_real` 136-167), the two tokens `c2w`, `c3w`, bob's honest and planted credits (`_credits`, `_credit`
188-218); after `ROLL_AGE` + 1 blocks the wallet's refusal while a skip is unmarked, the marks by the signed rollover, the window,
the refresh, the auditor's outcomes, the modified wallet (`PqzWalletRoll` 240-357). The wallet tool `pqz-wallet-sim` (through
ua-rs `pqz3k::PqzKeyHandle`) is driven as forge drives it, by its JSON on stdin. Its records' `R_REG`: decision D3.

## Design

- **One script**, `script/onchain/mldsa_on.py`, groups by name (`--groups mldsa,tokens,pqchat,pqzkeys,pqzwallet`, the default all
  in that order). It imports `script/pqz/e2e.py` as `pq.py` does (its `rpc`, `Sender`, ABI encoder `cd` / `enc`, `PQ`: ML-DSA by
  `mldsa.mjs` over clientkeys' `@noble/post-quantum`, `R_REG` proofs by pqz-ffi's `pqz_prove`; `K` = `pqz_kat` for KeyGen and the
  `R_REG` statement) and `pq.py`'s `create_cfg` (the factory's `TokenConfig`). No new signer, prover or digest reproducer: every
  digest is the contract's own view (`mtxTransferDigest`, `uaMessage`, `pqzScopedKeyRecordDigest`, `tradeOrderDigest`, …) as in
  the forge rows, or a forge-compiled helper run by `eth_call` with a state override (`PqChatDigests`); the typed `pqzAuth` by
  e2e's `K.auth_digest` / clientkeys (`_ck`), as e2e.py's rows.
- **The set by name:** `--set mldsa-on` (or `mldsa-off`, for the local test) is required. The book is
  `deployments/<chain key>.json` (deploybook.py: the key from `chain-uids.json` by chain id and genesis hash, or `DEPLOY_NAME`),
  its set the entry `sets.<label>` (reset 5's `deploybook.set_book`); an unknown label `DEPLOY_SET_UNKNOWN`, a book without the
  set `DEPLOY_SET_MISSING`, a set whose `mldsa_precompile` is not the label's `DEPLOY_SET_MISMATCH`; a flat book (no `sets`, a
  single deploy: local anvil) is that one set only if its `mldsa_precompile` is the label's. Nothing is sent before these checks.
- **Keys:** as matrix.sh: `PRIVATE_KEY`, `ONCHAIN_K1`..`ONCHAIN_K3` from the environment (the test keys 0x…01-0x…03 on a local
  target); never in argv, logs or commits. The verifier EOA `vA` derived from test key 1 as forge's `_vInit`. ML-DSA and PQZ seeds
  from the run's salt (test only), kept in the run's state file (git-ignored `deployments/mldsa-on-<net>-state.json`) for the roll
  phase and pqzwallet.
- **Gas:** every transaction asks the node's `eth_estimateGas` × 1.5 + 300 k (pq.py's margin), at most the latest block's
  `gasLimit`, never a fixed figure of ours. An estimate above the block limit is a named stop (`GAS_OVER_BLOCK`), nothing sent.
  EIP-8037: the estimate is regular + state gas; the chain caps the regular part at 2^24 (EIP-7825), which no RPC reports
  apart, so a limit above 2^24 is logged as relying on state gas (`asked > 2^24: regular part capped by the chain`) and its
  receipt's status is the check; a reverted receipt is a named FAIL with its hash.
- **Never silent:** one line per transaction (group, row, tx hash, gasUsed), `[net/group] start`, `ok N txs, negatives n/m (Xs)`
  or `FAIL <row>: <why>`, and a 30 s heartbeat thread with the senders' nonce deltas (`… 42 tx on chain, 95s`). Addresses, UAs,
  tx hashes only. Full output in the git-ignored `$MATRIX_OUT/mldsa-on-<net>.log`; records `records-<net>-<group>-on.jsonl` in
  matrix.sh's shape (contract, selector, tx, gasUsed, status; a negative with the error expected and got).
- **Negatives** by `eth_call` on the node against the state at that point, each with its positive control (the same call with the
  good input answers, or is refused by another named error), one input changed at a time.

## Tests without the testnet

- `script/onchain/test_mldsa_on.py` (no chain): the set selection and its named refusals (each with a control); the calldata of
  each row against the ABI in `out/` (e2e.py's `abi_check` way) and against what the forge row builds for the same values; the
  relayed digests with a **non-zero unbound** `relayer` / `feeRecipient` (they must sign the canonical zero, `MetaTxLib.canon`),
  against `vectors/` where a row exists (`typed_ops.json`, `portable.json`); mutants: each builder changed by one field must fail
  its test.
- On local anvil: a local deploy with `MLDSA_PRECOMPILE=off` (anvil runs the cache path: every row but the precompile itself runs
  for real; `run --set mldsa-off`, plus the cache parts the cache path needs, by flag), every group green. anvil has no
  `PqzKeyVerifier`: the `R_REG` proofs are checked there only by pqz-ffi's own verify, and on the chain only on set `mldsa-on`.
  (matrix.sh's local Nethermind copy has both precompiles: a local deploy of set `mldsa-on` on it would check them before the
  testnet.)

## Decisions asked (2026-11-16, to the coordinator)

- **D1** The EOA-signed rows of pqzkeys on the PQZ kinds (public layer but `_pq`, trades, pulls, regulated powers, wrap limits,
  factory negatives) need no precompile but run nowhere on the testnet: PqzKeysSetup is one forge run and stops at its first
  ML-DSA / 0x0142 step. Per the ruling they are not ported (forge runs them on anvil). Default: local only, listed in
  `notrun.json` with that reason.
- **D2** Settled by the code: pqzkeys' tokens on the set's factory, `OFFCHAIN` (above).
- **D3** pqzwallet's real keys live in the wallet (ua-rs `PqzKeyHandle`), which has no `R_REG` prover; forge stores filler bytes
  (anvil does not check them), which set `mldsa-on`'s registry refuses (`UAPoP`). An `OFFCHAIN` token reads an unproven record
  (`PqzCore._usable`: `OFFCHAIN` any stored key, its verifier checks `R_REG` off chain), so the wallet rows need no proof. Default: pqzwallet writes its records without `storePqzScopedPop` on a
  registry with a `PqzKeyVerifier` (the record stays unproven, logged), the proven-record rows being pqzkeys'. The other way: a
  `rreg` command in `pqz-wallet-sim` (a tool change, its own review).
