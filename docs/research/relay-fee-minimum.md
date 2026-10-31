> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Relay-fee minimum before mainnet: the options (R1, ua8-soroban)

Status: **research, owner decision pending.** Owner ruling 2026-10-28 item 7 kept the flat
`params.relay_fee.min_amount` until before mainnet and asked for a re-decision then (TODO.md, "Relay-fee minimum before
mainnet"; decisions.md, the 2026-10-28 owner-rulings entry, item 7). This note lists what exists, the four options, and
what each costs. It builds nothing. Plan: `docs/superpowers/plans/2026-10-31-ua8-soroban.md` Task R1 (U8S-D10).

Scope: the fee of a **relay-fee job** ([CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27): a token payment to the relayer
for a call that has no fee of its own). `metatx` and `ua_metatx` jobs are not in scope: they get no fee check by rule
(every state-changing mtx* is relayable with fee 0, owner 2026-10-20; decisions.md, node-ua-jobs entry item 7).

## 1. Today, per family (code as of `main` d883ce5f / `ua8-soroban` worktree)

**One shared rule, every family.** `scaas-node/src/adapter.rs:191-206` `relay_fee_ours(open, payee_is_lane, amount, p)`:
a fee that reaches the node's own lane (open mode, or a payee bound to the lane) must be `>= p.min_amount`; a fee bound
to anyone else is refused unless `relay_bound_payee = true`, and is then a sponsored job with no minimum.
`scaas-node/src/config.rs:820-839` `RelayParams { router, min_amount (default 1), relay_bound_payee (default false),
max_pay_meta_bytes }`. `min_amount` is in the fee token's **base units**, one number per chain for every token and every
target call. Callers: EVM `guard.rs:273`, Soroban `adapters/soroban.rs:906` (`relay`) and `:1102` (`ua_relay`), Solana
`adapters/solana.rs:551`, Cosmos `adapters/cosmos.rs:333`, Sui `adapters/sui.rs:745`, Aptos `adapters/aptos.rs:533`,
NEAR `adapters/near.rs:866`, Algorand `adapters/algorand.rs:2007`, TON `adapters/ton.rs:951` (always open mode).

**Per-token price keys already built** (the operator's floor price of one base unit of the fee token, in the chain's
native unit; static config, no price feed):

| Family | Key | Rule | Required? |
|---|---|---|---|
| EVM | `min_wei_value = { "<token>" = wei per base unit }` (`guard.rs:173-203`; `"<wei>/<10^k>"` allowed) | fee × price ≥ quote = gas limit × fee ceiling (`FEE_HEADROOM` 2 × first max fee) + 2 × the OP-stack L1 data fee (`guard.rs:284-330`, `submit.rs:556-579`); below the quote is a requeue, not a kill | **`uaRelay`: yes** (a UA's verify gas depends on its kind; `guard.rs:299-310`). Address `relay`: only when the token has a price, else `min_amount` alone |
| NEAR | `min_yocto_value = { "<token>" = yocto per base unit }` (`adapters/near.rs:600-681`) | fee × price ≥ prepaid gas × node gas price + every attached deposit (`near.rs:869-878`) | yes for a fee that is the node's |
| Algorand | `min_microalgo_value = { "<app id>" = µALGO per base unit }` (`adapters/algorand.rs:329-408`) | fee × price ≥ group fee + every MBR payment (`algorand.rs:2104-2112`) | yes for a fee that is the node's |
| TON | `min_ton_value = { "<master>" = nanoton per base unit }` (`adapters/ton.rs:885-922`) | fee × price ≥ the router's `get_relay_value` for this body (the TON the relay puts at risk; `ton.rs:1515-1517`) | yes (`ton.rs:944-946`) |
| Solana | `min_lamports_value = { "<mint>" = lamports per base unit }` (`adapters/solana.rs:457-493`) | fee × price ≥ the rent of a first-use lane PDA (56 B) only (`solana.rs:468-480`); the transaction fee itself is not priced | only when the lane PDA is new |
| Soroban | none | `min_amount` only (`adapters/soroban.rs:769-781`) | — |
| Cosmos | none | `min_amount` only (`adapters/cosmos.rs:225-234`) | — |
| Sui | none | `min_amount` only (`adapters/sui.rs:641-651`) | — |
| Aptos | none | `min_amount` only (`adapters/aptos.rs:425-445`) | — |
| Hedera | none | `adapters/hedera.rs` builds no `Guard` / `RelayFee` policy (the EVM `Guard` is built in `adapters/evm.rs:49` and `main.rs:280`); no relay-fee check of its own, not even `min_amount` | — |

So where a price key exists and is required (NEAR, Algorand, TON, EVM `uaRelay`), `min_amount` is in practice
redundant (any fee that covers the quote is far above 1 base unit). Where none exists (Soroban, Cosmos, Sui, Aptos,
EVM address `relay` on an unpriced token, Solana beyond first-use rent), `min_amount` is the **only** protection of the
lane, and its default 1 base unit protects nothing.

**On chain: no router enforces a minimum.** EVM `MtxRelayFee` requires fee mode `NONE`, `t.fee == 0` and takes
`t.value` as the fee with no lower bound ([CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27) step 2); the Soroban
`relay-fee` contract (`smartcontracts/soroban/contracts/relay-fee/src/lib.rs`) has no amount check; no relay-fee router
or wrapper on any family (`evm/src/metatx/MtxRelayFee.sol`, `near/relayfee`, `near/token/src/relayfee.rs`,
`algorand/contracts/relayfee.py`, `solana/programs/scaas/src/wrappers.rs`, Cosmos `relayfee`, Sui / Aptos
`relayfee`, TON router) has a `min_fee` / `min_amount`. CTR-MTX-27: "The payment is optional: the same call can always
be submitted without it."

## 2. The options

### (a) Flat floor per chain (status quo: `params.relay_fee.min_amount`)

- **Changes:** nothing. Node config only.
- **Who maintains:** the operator, one number per chain.
- **Failure / abuse:** one base-unit number cannot fit tokens of different decimals and value: set for a 6-decimal
  stablecoin it is either meaningless for an 18-decimal token or prohibitive for a 0-decimal one. On the families
  without a price key any payer can pay `min_amount` for a call whose gas is worth more, and repeat it: the lane loses
  the difference on every job (the simulation stops reverts, not under-pricing). It also assumes a gas price, which the
  owner ruled out for customer chains (no zero-gas / no block-limit assumption, 2026-10-21).
- **Cost if wrong:** too low = the operator subsidises every relay-fee job on Soroban / Cosmos / Sui / Aptos / Hedera
  and unpriced EVM tokens; too high = small-token users priced out. Operator-only, changeable by config at any time.
- **Freeze:** no impact. **Tests:** none change.

### (b) Per-token minimum (`min_amount` keyed by token)

- **Changes:** node only. `RelayParams.min_amount` becomes a table `{ "<token>" = base units }` (or a per-token table
  beside the chain default); `relay_fee_ours` takes the token; every caller listed in §1 passes it; `Config::validate` /
  each adapter's `from_cfg` parse it (same startup-error rule as today). Lands with P6i.
- **Who maintains:** the operator, one number per token per chain.
- **Failure / abuse:** fixes the decimals/value mismatch of (a), but still a fixed token amount against a moving cost:
  gas price, native/token rate and the call's own gas (a 12-passkey msig vs one ed25519 key, a PQ verify 1.4–5.95 M gas
  vs 0.05 M) all vary, so the number is either set for the most expensive call (overcharges the cheap ones) or the lane
  loses on the expensive ones. The UA-kind problem is exactly why EVM `uaRelay` already requires a price (decisions.md,
  node-ua-jobs item 6).
- **Cost if wrong:** as (a), per token. Operator-only, config change.
- **Freeze:** no impact. **Tests:** `adapter.rs` `relay_fee_ours` unit test; each adapter's `min_amount` tests
  (`sui.rs` ~1641-1687 / 1813-1829, `soroban.rs` ~1449-1496, `cosmos.rs` ~1098-1211, `submit.rs` ~1839-1943 / 2105) and
  config-parsing tests.

### (c) Gas-proportional (a per-token price key and the quote rule on every family)

- **Changes:** node only. Extend what EVM / NEAR / Algorand / TON / Solana already do to the families without it:
  a per-token price key in the native unit and "fee × price ≥ quote", where the quote is the family's own cost of the
  job taken from the simulation the adapter already runs:
  - Soroban: the simulated resource fee (incl. any restore within `max_deposit_per_job`) + the inclusion fee the lane bids;
  - Cosmos: gas limit × gas price of the lane's transaction;
  - Sui: the PTB's gas budget × reference gas price (storage rebate ignored, conservative);
  - Aptos: max gas amount × gas unit price;
  - Hedera: the EVM quote over the JSON-RPC relay (`eth_gasPrice × 1.2`, `hedera.rs:129`), once Hedera has a
    relay-fee check at all;
  - Solana: the transaction fee (+ priority fee) added to the first-use rent already priced;
  - EVM address `relay`: make the price required, as for `uaRelay` (flips the "only when priced" branch,
    `guard.rs:308` and the `submit.rs` ~2139-2142 test).
  `min_amount` can stay as a per-chain sanity floor (default 1) or be dropped where a price is required. Lands with P6i.
- **Who maintains:** the operator, one price per token per chain (native units per base unit). The quote itself is
  computed per job, so gas price, call size and UA kind are tracked automatically.
- **Failure / abuse:** the price is static config (no feed, by design since T17): when the token/native rate moves, the
  lane under- or over-charges by the drift until the operator updates it. A mis-set price is bounded to that token's
  jobs. A token without a price gets no relay-fee job that is the node's (the NEAR / Algorand / TON behaviour), so a
  missing key fails closed. The quote of the first send can be lower than a fee-bumped replacement (EVM recorded
  ceiling, decisions.md node-ua-jobs item 10); the same holds per family where the lane re-bids.
- **Cost if wrong:** a lane loss or a refused job per token, operator-only, changeable by config.
- **Freeze:** no impact. **Tests:** new per-family "covers the quote / one unit below refused / no price refused"
  tests for Soroban, Cosmos, Sui, Aptos, Hedera and Solana's tx fee, as the existing NEAR / Algorand / TON / EVM ones;
  the EVM address-`relay` unpriced test flips; an e2e per family where one exists (Soroban `SourceAccount` e2e is still
  owed, soroban.md "Owed").

### (d) A minimum enforced in the router contracts

- **Changes:** contracts on **every** family that has a relay-fee router or wrappers: EVM `MtxRelayFee` (also Hedera,
  same bytecode), Soroban `relay-fee`, Solana `relay_fee_<entry>` wrappers and generic `relay_fee`, Cosmos `relayfee`,
  Sui / Aptos `relayfee`, NEAR `relayfee` + the 13 `relay_fee_<entry>` token wrappers, Algorand `relayfee.py`, TON
  router. Plus vectors, gas re-pins and the audit scope. Must land **before the freeze** (work order item 7).
- **Who maintains:** nobody after deploy. The routers have no owner and no admin by rule (EVM stateless CREATE2; Cosmos
  refuses an admin; Sui / Aptos packages immutable, NET-SUI-15 / NET-APT-20), so the number is either a constant in the
  code or a constructor argument. Changing it means a new router: on EVM a new CREATE2 address on every chain, and every
  client signs `relayer = router`, so outstanding signed payments to the old router stay valid only there.
- **Failure / abuse:** a contract cannot know the native/token rate or the operator's cost, so the on-chain number is
  a token amount, i.e. option (b) frozen. It does not protect the relayer any better than (a)–(c): the relayer already
  decides off chain whether to submit, and only the relayer loses on an under-priced job. What it adds is a restriction
  on users: a payee self-relay or a sponsored bound-payee payment (`relay_bound_payee`) with a small or 0 fee becomes
  impossible through the router, against "the payment is optional" (CTR-MTX-27) and the spirit of "fee may be 0"
  (owner 2026-10-20). A per-token on-chain table would need an admin or a registry, which the routers deliberately do
  not have.
- **Cost if wrong:** frozen into immutable contracts on every chain; a wrong number means a redeploy of every router and
  a client change. Affects users (refused payments), not the operator.
- **Freeze:** blocks it (all families' routers change). **Tests:** every router's test suite on nine families, shared
  relay-fee vectors, the EVM gas pins, the contracts audit.

## 3. Summary

| | Where | Freeze | Maintainer | Tracks gas / UA kind | Change later |
|---|---|---|---|---|---|
| (a) flat per chain | node config | no | operator, 1 / chain | no | config |
| (b) per token | node code + config (P6i) | no | operator, 1 / token / chain | no | config |
| (c) gas-proportional | node code + config (P6i) | no | operator, 1 price / token / chain | yes | config |
| (d) on-chain floor | contracts, every family | **yes, before freeze** | none (immutable) | no | redeploy every router |

(c) contains (b): a price and a quote give a per-job minimum of `ceil(quote / price)` base units. Only (d) changes
contracts, so only (d) has to be decided before the freeze; (a)–(c) can be decided any time before mainnet and built
with P6i.

## 4. Controller recommendation (not a decision; the owner rules)

(c) on every family, one rule (no split by chain kind): a fee that reaches the node's lane needs a price for its token
and must cover the family's simulated cost of the job; `min_amount` stays as the per-chain floor; sponsored fees stay
unpriced. Not (d): it freezes a token amount into immutable routers, protects no one the node does not already protect,
and blocks zero-fee sponsored relays. Since only (d) touches contracts, the freeze does not wait on this ruling.

**Question for the owner:** keep (a) for mainnet, or adopt (c) (per-token price + quote on every family, node only,
built with P6i) — and confirm (d) is out, so the freeze does not wait on it?
