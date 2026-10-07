# decisions-netcli — register fragment (Phase 1, networks / clients / integration)

One entry per id in the NET-, CLI- and INT- prefixes: current, open, superseded and unused. Phase 2 merges this
fragment into `docs/decisions.md`. Normative text lives in the file named by `normative`; the entry gives the
reason.

## Networks — common model

### NET-ALL-01 — Pruning families keep executed lanes for H
- old: CR-PD-4(pruning), CR-R3-8(pruning) · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-01 · superseded-by: —

**Rule.** Families that prune executed lane state keep an executed lane for at least the horizon H after the op's `validUntil`.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 901; [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 700.

### NET-ALL-02 — Contract-level meta-tx default on every network
- old: R30, UD:§1:eip1776, UD:§21.5 · status: current · owner: yes · date: 2026-10-03 · normative: networks/README.md#NET-ALL-02 · superseded-by: —

**Rule.** Contract-level meta-transactions are the default path on every network; the subject's account sequence is never an ordering lock.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 517; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 40; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1538.

### NET-ALL-03 — Head-of-line table and anti-lock test
- old: R62 · status: current · owner: no · date: 2026-10-05 · normative: networks/README.md#NET-ALL-03 · superseded-by: —

**Rule.** Every adapter states how it avoids head-of-line blocking, and every family passes the anti-lock test.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 535.

### NET-ALL-04 — One WebAuthn grammar for every family
- old: CR-R3-1(grammar), RS4-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-04 · superseded-by: —

**Rule.** One WebAuthn rule and one bounded `clientDataJSON` grammar for every family.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 630; [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 15.

### NET-ALL-05 — Key lifecycle stated per family
- old: CR-R3-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-05 · superseded-by: —

**Rule.** Key rotation and recovery are stated per family; every gap is listed, never implied away.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 679.

### NET-ALL-06 — Indexer filters registered contracts; empty stalls
- old: net-aptos:L1, net-solana:L1 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-06 · superseded-by: —

**Rule.** The indexer filters by the registered contracts in the family's own address form, and an empty list never advances the cursor.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 37; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 41.

### NET-ALL-07 — e2e fakes return real token ids
- old: net-aptos:L2, net-solana:L2 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-07 · superseded-by: —

**Rule.** End-to-end fakes return real token ids and refuse unregistered emitters.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 38; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 42.

### NET-ALL-08 — Payer signs every amount deciding delivery
- old: net-aptos:L3, net-solana:L3 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-08 · superseded-by: —

**Rule.** Every amount chosen by the relayer that decides whether value arrives must be inside the payer's signature.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 39; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 43.

### NET-ALL-09 — Permanent submit refusals free the lane
- old: net-aptos:L4, net-solana:L4 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-09 · superseded-by: —

**Rule.** A permanent refusal at submit frees the lane at once
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 40; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 44.

### NET-ALL-10 — Crash-safe lanes never equivocate
- old: net-aptos:L5, net-solana:L5 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-10 · superseded-by: —

**Rule.** Lanes are crash-safe: no equivocation, no sequence used twice.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 41; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 45.

### NET-ALL-11 — Multi-key accounts survive origin change
- old: net-aptos:L6, net-solana:L6 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-11 · superseded-by: —

**Rule.** Multi-key accounts with origins and a guardian survive an origin change.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 42; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 46.

### NET-ALL-12 — Coins sent to accounts stay spendable
- old: net-aptos:L7, net-solana:L7 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-12 · superseded-by: —

**Rule.** Coins sent directly to an account or contract address stay spendable.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 43; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 47.

### NET-ALL-13 — No shared object serialises all markets
- old: net-aptos:L8, net-solana:L8 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-13 · superseded-by: —

**Rule.** No shared object serialises all markets.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 44; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 48.

### NET-ALL-14 — ERP verifies only keys it can prove
- old: net-aptos:L9, net-solana:L9 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-14 · superseded-by: —

**Rule.** A client verifies a signature only with a key it can prove belongs to the payer
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 45; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 49.

### NET-ALL-15 — Lane state prunable, storage refunded
- old: net-aptos:L10, net-solana:L10 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-15 · superseded-by: —

**Rule.** Lane and nonce state is prunable and its storage is refunded.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 46; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 50.

### NET-ALL-16 — Never case-fold base58 addresses or ids
- old: net-solana:L11 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-16 · superseded-by: —

**Rule.** Base58 addresses and ids are never case-folded.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 51.

### NET-ALL-17 — Asset suite on EVM and Hedera
- old: R215 · status: current · owner: no · date: 2026-10-06 · normative: networks/README.md#NET-ALL-17 · superseded-by: —

**Rule.** The asset suite is specified for EVM and Hedera only.
**Source.** [history/specs/2026-10-06-asset-suite-design.md](history/specs/2026-10-06-asset-suite-design.md) line 184.

### NET-ALL-18 — Tender on EVM and Hedera first
- old: R188 · status: current · owner: yes · date: 2026-10-07 · normative: networks/README.md#NET-ALL-18 · superseded-by: —

**Rule.** The sealed-bid tender ships on EVM and Hedera first
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 121.

### NET-ALL-19 — Wrappers v2 on EVM and Hedera only
- old: R145 · status: current · owner: no · date: 2026-10-06 · normative: networks/README.md#NET-ALL-19 · superseded-by: —

**Rule.** Token wrappers v2 are EVM and Hedera only
**Source.** [history/specs/2026-10-06-token-wrappers-v2.md](history/specs/2026-10-06-token-wrappers-v2.md) line 152.

### NET-ALL-20 — Per-family UA registries share kind table
- old: R314, UA:Q12 · status: current · owner: yes · date: 2026-10-07 · normative: networks/README.md#NET-ALL-20 · superseded-by: —

**Why.** TON calls are asynchronous, and owner consent alone would let a wallet claim someone else's key. Owner-confirmed.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 303; [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 1412.

### NET-ALL-21 — Non-EVM passkey owners = UA id, URN only
- old: R315, UA:Q13 · status: current · owner: yes · date: 2026-10-07 · normative: networks/README.md#NET-ALL-21 · superseded-by: —

**Why.** a 20-byte form is exactly the truncation the UA id space forbids (2^80 collision work against secp256k1 accounts, CTR-UA-03); an account-shaped form invites native sends to a keyless address.
**Cost if wrong.** dev passkey accounts re-open; users copy a URN, not an address. Owner-confirmed.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 311; [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 1413.

### NET-ALL-22 — Chain identified by (chain_key, chain_uid)
- old: R330 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-22 · superseded-by: —

**Why.** chain ids are a registry convention, not unique — 9000 is also Evmos Testnet, which is why the private chain moved to 7622 (NET-EVM-02).
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 340.

### NET-ALL-23 — Sui/Solana wallet signatures readable, passkey-first
- old: CR-WSF-1 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-23 · superseded-by: —

**Rule.** Solana and Sui wallet-key signatures: no blind blobs; origin binding through the passkey path or an opt-in account policy.
**Source.** [history/specs/round3-wallet-signing-formats.md](history/specs/round3-wallet-signing-formats.md) line 343.

### NET-ALL-80 — R36-R49 reserved for round 3, never used
- old: R36, R37, R38, R39, R40, R41, R42, R43, R44, R45, R46, R47, R48, R49 · status: unused · owner: no · date: 2026-10-03 · normative: — · superseded-by: —

R36-R49 reserved for round 3, never used.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 4.

## EVM

### NET-EVM-01 — Celo fee currency (CIP-64)
- old: req:blockchain.md:celo-fee-currency · status: open · owner: yes · date: 2026-10-07 · normative: networks/evm.md#NET-EVM-01 · superseded-by: —

**Rule.** Celo fee-currency support (CIP-64) for relayer lanes is an open owner requirement.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 184.

### NET-EVM-02 — Private reference chain id is 7622
- old: CR-PD-6, owner:2026-10-07:chain-7622 · status: current · owner: yes · date: 2026-10-07 · normative: networks/evm.md#NET-EVM-02 · superseded-by: —

**Rule.** The private reference chain is chain id 7622; its identity is the pair (chain id 7622, genesis hash `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`), profile `private7622`.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 918; [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 39.

### NET-EVM-03 — First target chain is the private PoA chain
- old: UD:§16, UD:§16:roadmap · status: current · owner: yes · date: 2026-08-30 · normative: networks/evm.md#NET-EVM-03 · superseded-by: —

**Rule.** The first target chain is the private PoA chain; public chains follow, and CI builds the `private7622` profile.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 889; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 929.

### NET-EVM-04 — Single-signer PoA must be named honestly
- old: UD:§16:single-signer · status: current · owner: yes · date: 2026-08-30 · normative: networks/evm.md#NET-EVM-04 · superseded-by: —

**Rule.** A single-signer PoA chain is named honestly.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 917.

### NET-EVM-80 — First chain Gnosis, then Celo
- old: UD:§1:first-chain · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: NET-EVM-03

It said: First chain Gnosis, then Celo; replaced by NET-EVM-03.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 41.

### NET-EVM-81 — Raise the private chain block gas limit
- old: UD:§16:gas-limit · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-PQZ-11

It said: Raise the private chain block gas limit; replaced by CTR-PQZ-11.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 904.

### NET-EVM-82 — Chain 9000 genesis keys silently ignored
- old: UD:§18 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: NET-EVM-02

It said: Chain 9000 genesis keys silently ignored; replaced by NET-EVM-02.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 997.

## Hedera

### NET-HED-01 — Hedera HCS anchoring
- old: req:blockchain.md:hcs-anchoring · status: open · owner: yes · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-01 · superseded-by: —

**Rule.** HCS anchoring is an open owner requirement.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 235.

### NET-HED-02 — Hedera Schedule Service
- old: req:blockchain.md:hedera-schedule · status: open · owner: yes · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-02 · superseded-by: —

**Rule.** The Hedera Schedule Service is an open owner requirement.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 242.

### NET-HED-03 — ED25519 owners pay via executeAsOwnerRaw
- old: CR-ADW-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-03 · superseded-by: —

**Rule.** An ED25519 owner pays from its `MandateWallet` only through `executeAsOwnerRaw`.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 303.

### NET-HED-04 — Hedera = Solidity on HSCS + HIP-632
- old: R63 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-04 · superseded-by: —

**Rule.** Hedera is the EVM family on the Hedera Smart Contract Service: the same Solidity contracts behind a Hedera JSON-RPC relay, plus HIP-632 for ED25519 accounts; the payer-sponsored path is not used.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 536.

### NET-HED-05 — Hedera status code to outcome class table
- old: R6-7 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-05 · superseded-by: —

**Rule.** Each Hedera status code maps to one outcome class; a billed failure is never requeued without limit
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 162.

### NET-HED-06 — v1 HTS wrapper fee check in initialize
- old: R6-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-06 · superseded-by: —

**Why.** an HTS underlying with any fixed, fractional or royalty fee breaks a wrapper — `MetaToken.wrap` measures what actually arrived (fine for receiver-side fees) but `unwrap` sends exactly `amount` (`MetaToken.sol:134-139`), so a fixed fee in the same token or a fractional fee with `netOfTransfers = true` is taken from the wrapper again (`balanceOf(this) < totalSupply`, the last redeemer is stuck), and a fixed fee in HBAR makes every `unwrap` revert (the wrapper holds no HBAR), locking the reserve. v2 refuses these; the built v1 `HederaMetaToken` only associates (the permissionless `associateUnderlying()` calling `0x167 associateToken(this, underlying)`), is still registered as `META v1` (`DeployHedera.s.sol:29-30`), and anyone may create it through the open factory (`OpenFactory.createMetaToken`, permissionless, `:91-96`; `deprecate` does not block creation — `_registered` checks only non-zero, `:167-170`). Fix (SPECIFIED): `MetaToken.initialize` calls an `internal virtual _checkUnderlying(u)` hook (empty by default); `HederaMetaToken` overrides it with `HederaHts.checkAndAssociate(u)` and reverts `UnderlyingInvalid` on any fee; `associateUnderlying()` is deleted (association inside `initialize` means a token that cannot associate is never born, and the auto-association slot is no longer a detour); a new implementation is deployed, registered as a new META version on the Hedera factory, and `deprecate(META, 1)` follows. Until then the wizard and the node's token registry refuse a v1 Hedera token whose underlying is an HTS token with custom fees. Forge tests (mock `0x167`): v1 on an underlying with fixed/fractional/royalty fees ⇒ creation reverts; no fee ⇒ associated once, wrap/unwrap conserve the reserve; `isToken` failure ⇒ `HtsQueryFailed`.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 201.

### NET-HED-07 — Wallets warn on HTS issuer keys
- old: R6-9 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-07 · superseded-by: —

**Rule.** Wizards and wallets read every key of the HTS issuer and warn before a wrapper is created.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 215.

### NET-HED-08 — Hedera runs lane_runner, one tx per lane
- old: R6-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/hedera.md#NET-HED-08 · superseded-by: —

**Rule.** Hedera runs `lane_runner` (one transaction in flight per lane), with no pipeline, replacement or gap-fill.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 289.

### NET-HED-09 — HederaMetaToken HIP-632 for 64-byte signatures
- old: R6-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/hedera.md#NET-HED-09 · superseded-by: —

**Rule.** `HederaMetaToken` verifies a 64-byte signature from an account without code through HIP-632 `isAuthorizedRaw`; a precompile revert means "not authorised"; everything else is `MetaToken`.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 291.

### NET-HED-10 — HashPack signMessage and KeyList are seams
- old: R6-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/hedera.md#NET-HED-10 · superseded-by: —

**Rule.** HashPack `signMessage` and threshold/KeyList accounts are seams.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 295.

### NET-HED-11 — Call HIP-632 system contract with CALL
- old: R6-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-11 · superseded-by: —

**Rule.** The HIP-632 system contract is called with `CALL`, never `STATICCALL`.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 298.

### NET-HED-12 — HederaAdapter reports tx_fee and lane_balance
- old: R6-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-12 · superseded-by: —

**Why.** as built the adapter implements neither (both default to `None`, `adapter.rs:112-118`; `hedera.rs` implements only `op_consumed/build/sign/submit/tx_status/…`), so neither `gas_budget` nor `min_relayer_balance` ever sees a Hedera sample; only the zero-balance check in `build` (`hedera.rs:163-166`) stops a drain loop. Tests: a failed receipt still adds to `spent`; a balance below the floor stops the lane taking work.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 307.

### NET-HED-13 — Mesh sig_kind hedera_ed25519 verified locally
- old: R6-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-13 · superseded-by: —

**Why.** as built, `sig_kind` is only `eoa`/`erc1271` and `check_evm` returns `Ok` for every non-EOA intent (`mesh/digest.rs:193-195`), so garbage intents force every peer to simulate.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 308.

### NET-HED-14 — Hedera v2 wrappers: fail-closed HTS checks
- old: R144 · status: current · owner: no · date: 2026-10-06 · normative: networks/hedera.md#NET-HED-14 · superseded-by: —

**Rule.** Hedera v2 wrappers check every underlying in `initialize`, fail-closed, through the HTS precompile `0x167`.
**Source.** [history/specs/2026-10-06-token-wrappers-v2.md](history/specs/2026-10-06-token-wrappers-v2.md) line 149.

### NET-HED-15 — Hedera ED25519 needs a raw signer
- old: CR-WSF-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-15 · superseded-by: —

**Rule.** Hedera ED25519 subjects need a raw signer.
**Source.** [history/specs/round3-wallet-signing-formats.md](history/specs/round3-wallet-signing-formats.md) line 363.

### NET-HED-80 — Permissionless associateUnderlying
- old: R6-5 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-HED-06, NET-HED-14

It said: Permissionless associateUnderlying; replaced by NET-HED-06, NET-HED-14.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 296.

## Cosmos

### NET-COS-01 — IBC ICS-20/27 transfers
- old: req:blockchain.md:ibc · status: open · owner: yes · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-01 · superseded-by: —

**Rule.** IBC token transfers (ICS-20) and interchain accounts (ICS-27) are an open owner requirement.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 293.

### NET-COS-02 — Cosmos CW20 + ADR-036, no authz
- old: R66 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-02 · superseded-by: —

**Rule.** Cosmos = a CW20 token with a contract-level meta operation signed through ADR-036; `x/authz` is never used and `x/feegrant` is only a seam.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 539.

### NET-COS-03 — Cosmos passkey bound to rpIdHash, origin and UV
- old: CR-R3-1(cosmos-binding) · status: current · owner: yes · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-03 · superseded-by: —

**Why.** as built the decoder checks only the UP flag (`ad[32] & 0x01`) and `type`/challenge by substring `contains` (`cosmos/metaop/src/lib.rs:130-148`; `metaop/src/lib.rs:131-144`; no low-s check before `secp256r1_verify`, `cosmos/metaop/src/lib.rs:147`), with no rpIdHash, origin, UV or low-s check, so any page that can obtain an assertion for the rpId (sibling subdomain, related origin, delegated iframe) signs any `MetaOp`. The low-s check closes signature malleability (the digest identity never depended on the signature).
**Cost if wrong.** Cosmos dev passkey accounts change.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 630.

### NET-COS-04 — Cosmos DEX has no Sweep
- old: CR-R3-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-04 · superseded-by: —

**Rule.** The Cosmos DEX has no `Sweep`
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 708.

### NET-COS-05 — Cosmos DEX fill-or-kill, batch all-or-nothing
- old: R9-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/cosmos.md#NET-COS-05 · superseded-by: —

**Rule.** Cosmos DEX orders are fill-or-kill, and a multi-pair batch is atomic as a whole.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 117.

### NET-COS-06 — Post-simulation grief metered; DEX rereads nonces
- old: R9-3 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-06 · superseded-by: —

**Rule.** Subject-caused grief after simulation is metered and throttled, not excluded; the DEX re-reads both legs' nonces before settling.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 233.

### NET-COS-07 — instantiate2 genesis salt; duplicate chain-id refused
- old: R9-4 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-07 · superseded-by: —

**Rule.** Cosmos contract addresses differ between chains, contracts are instantiated without an admin, and duplicate chain ids are refused.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 238.

### NET-COS-08 — contract and valid_until from signed payload
- old: R9-5 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-08 · superseded-by: —

**Rule.** `contract` and `valid_until` come from the signed payload
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 243.

### NET-COS-09 — Cosmos passkey checks stored rpIdHash and origins
- old: R9-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-09 · superseded-by: —

**Rule.** The Cosmos passkey verifier checks the stored relying-party hashes and origins.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 246.

### NET-COS-10 — Resubmit tx dropped from mempool
- old: R9-7 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-10 · superseded-by: —

**Rule.** A transaction dropped from the mempool is resent
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 249.

### NET-COS-11 — extra must be empty outside trade
- old: R9-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-11 · superseded-by: —

**Rule.** `extra` must be empty outside `trade`
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 252.

### NET-COS-80 — Cosmos passkey v1 derived address
- old: R9-1 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-ALL-21

It said: Cosmos passkey v1 derived address; replaced by NET-ALL-21.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 13.

### NET-COS-81 — Cosmos passkey v2 20-byte derived address
- old: CR-R3-1(cosmos-address) · status: superseded · owner: yes · date: 2026-10-07 · normative: — · superseded-by: NET-ALL-21

It said: Cosmos passkey v2 20-byte derived address; replaced by NET-ALL-21.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 630.

## Soroban

### NET-SOR-01 — Soroban native auth as meta-tx; fee-bump
- old: R65 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-01 · superseded-by: —

**Rule.** On Soroban the contract-level meta operation is the native Soroban authorization; a relayer lane is the transaction source, and fee-bump lets one lane pay for all.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 538.

### NET-SOR-02 — Ledger expiry computed without RPC
- old: R8-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-02 · superseded-by: —

**Rule.** The ledger expiry is computed without RPC as a safe upper bound.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 64.

### NET-SOR-03 — Soroban guardian recovery is a seam
- old: R8-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-03 · superseded-by: —

**Rule.** Soroban guardian recovery is a seam.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 96.

### NET-SOR-04 — Per-key permissions are a seam
- old: R8-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-04 · superseded-by: —

**Rule.** Per-key permissions are a seam.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 97.

### NET-SOR-05 — One signature settles once
- old: R8-3 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-05 · superseded-by: —

**Rule.** One signature settles once.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 137.

### NET-SOR-06 — No multi-pair batch per Soroban tx
- old: R8-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-06 · superseded-by: —

**Rule.** No multi-pair batch per Soroban transaction.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 139.

### NET-SOR-07 — DEX jobs carry two auth entries
- old: R8-5 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-07 · superseded-by: —

**Rule.** A relayed DEX job carries two auth entries.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 141.

### NET-SOR-08 — Token address is a per-family string
- old: R8-7 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-08 · superseded-by: —

**Rule.** A Soroban token address is a per-family string.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 182.

### NET-SOR-09 — pay_ref one-shot per (from, pay_ref)
- old: CR-R3-3(rule), R8-9 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-09 · superseded-by: —

**Why.** with a global key, a stranger's 0- or 1-unit `pay(attacker, receiver, …, victim_ref)` burns the victim's ref and blocks the victim's signed payment; booking already sums settlements per `entry_ref` and receiver, so a stranger's payment with someone else's ref is only money in (same direction as Cosmos, which never locks `pay_ref`, and the EVM `MetaToken`). SPECIFIED (as built the key is global, `token/src/lib.rs:203-209`, and `check_amount` accepts 0, `:113-117`). Tests: a third party `pay(self, x, 0, victim_ref)` ⇒ `NonPositiveAmount`; `pay(self, x, 1, victim_ref)` does not block the victim's `pay`; the same `from` paying the same `pay_ref` twice (two signatures) ⇒ `RefUsed`; `pay_under_mandate` cannot be burnt by a third party.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 658; [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 224.

### NET-SOR-10 — Soroban orders bind relayer, no open form
- old: R8-10, RS5-15(soroban) · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-10 · superseded-by: —

**Why.** the host only matches `dex.settle(order)` (`dex/src/lib.rs:158-159`); the counter-order and `maker_fill` (`:153`) are the submitter's choice, so anyone who sees a pending `settle` (transactions flood to every peer before the ledger closes) re-submits both auth entries with `maker_fill = 1`: both nonces are consumed for a dust fill, the real `settle` fails (the relayer pays) and both makers must sign again. Binding the settler means only the DEX operator's lane can spend the auth entries; roles and `maker_fill` are chosen by the (trusted) operator. Binding `(order, fill)` into the signature is not possible: a resting order is signed before its fill is known. SPECIFIED (as built `Order` has no relayer, `:35-47`). Test: a third party re-submits both auth entries with `maker_fill = 1` ⇒ fails; the right relayer settles.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 230; [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 438.

### NET-SOR-11 — TTL extension and RestoreFootprint retry
- old: R8-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-11 · superseded-by: —

**Rule.** Entries in daily use extend their TTL, and an archived footprint is restored by the lane and retried.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 233.

### NET-SOR-12 — op_consumed reads host nonce key
- old: R8-12 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-12 · superseded-by: —

**Rule.** `op_consumed` reads the host nonce key
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 236.

### NET-SOR-13 — Reject crossOrigin true and topOrigin
- old: R8-13 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-13 · superseded-by: —

**Rule.** The Soroban passkey verifier refuses `"crossOrigin":true` and any `topOrigin`
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 238.

### NET-SOR-14 — Soroban adapter reports tx_fee and lane_balance
- old: R8-14 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-14 · superseded-by: —

**Rule.** The Soroban adapter reports `tx_fee` (`feeCharged` from the `resultXdr` of `getTransaction`, for both `SUCCESS` and `FAILED`) and `lane_balance` (native balance of the lane and of the `fee_bump_lane`)
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 240.

### NET-SOR-15 — Signed fields read from invocation
- old: R8-15 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-15 · superseded-by: —

**Rule.** `build` takes `valid_until` (hence `TimeBounds.max_time` and the runner's expiry) and `contract` from the signed invocation
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 242.

### NET-SOR-80 — Non-positive pay refused with ZeroAmount
- old: CR-R3-3(error-name) · status: superseded · owner: yes · date: 2026-10-07 · normative: — · superseded-by: NET-SOR-09

It said: Non-positive pay refused with ZeroAmount; replaced by NET-SOR-09.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 658.

## Sui

### NET-SUI-01 — Sui shared Account<T> + personal message
- old: R64 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-01 · superseded-by: —

**Rule.** Sui = a shared `Account<T>` per subject holding the balance, signed through `signPersonalMessage`; DEX settlement is two signed legs.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 537.

### NET-SUI-02 — Sui keys per subject in Keys object
- old: CR-R3-5 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-02 · superseded-by: —

**Why.** as built keys live in each `Account<T>` (`meta.move:93-105`), so rotating a key on one coin type leaves the old key alive on another, and `dex::cancel`/`invalidate_nonces` accept any `Account<X>` of the maker (`dex.move:275-294`). A struct-layout change is a fresh package publish, and every publish is fresh and immutable anyway (NET-SUI-15). SPECIFIED. Tests: rotate a key on `Keys` ⇒ the old key fails on `Account<USDC>` and `Account<SUI>` and cannot cancel orders on any market. The `Keys.policy` bit `POLICY_PASSKEY_FOR_VALUE` is defined in NET-ALL-23.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 672.

### NET-SUI-03 — Account and Registry are derived objects
- old: RS7-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-03 · superseded-by: —

**Rule.** `Account<T>` and `Registry<T>` are derived objects.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 272.

### NET-SUI-04 — open_passkey requires an assertion
- old: RS7-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-04 · superseded-by: —

**Rule.** `open_passkey` requires an assertion; origin and rpIdHash come from that assertion.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 273.

### NET-SUI-05 — Many keys, origins, guardian per account
- old: RS7-3 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-05 · superseded-by: —

**Rule.** A Sui account has many keys, many origins and a guardian with delayed recovery.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 274.

### NET-SUI-06 — Sui DEX atomic PTB batch, no relayer fee
- old: RS7-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-06 · superseded-by: —

**Rule.** Sui DEX differences from EVM
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 275.

### NET-SUI-07 — Relayer builds PTB BCS locally
- old: RS7-5 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-07 · superseded-by: —

**Rule.** The relayer builds the PTB BCS locally and resends the same bytes.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 276.

### NET-SUI-08 — Indexer filters registered tokens
- old: RS7-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-08 · superseded-by: —

**Rule.** The Sui indexer filters by event type and by the registered tokens.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 277.

### NET-SUI-09 — One shared Market per pair
- old: RS7-8 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-09 · superseded-by: —

**Rule.** One shared `Market` per pair.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 279.

### NET-SUI-10 — No second tx on one gas coin version
- old: RS7-7, RS7-9 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-10 · superseded-by: —

**Why.** as built the journal is a local directory (`params.lane_journal/<chain>-lane<i>.json`, fsync + rename, written by `sign()` before the signed report and before sending) with **one** entry per lane — job B's `sign` overwrites job A's pending entry (`sui.rs:495-505, 693-707`), a failed resend of A is only logged (`sui.rs:523-527`), coin selection skips only the current entry's coin (`:657, 666`), so a later job can pick coin C1 vN again (the largest) and sign a second transaction on the same version — equivocation, C1 locked until the epoch ends; the directory (`:465-467`) does not follow the owner lock on failover; expiration is `None` (`sui.rs:317`). Tests: A `Unknown` + failed resend, B signed on C2, job C never picks C1 vN; a restart on a fresh disk with the same store ⇒ no equivocation; transactions carry an epoch expiration.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 278; [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 283.

### NET-SUI-11 — forward never returns to removed key
- old: RS7-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-11 · superseded-by: —

**Why.** as built `owner` never changes and `forward` is permissionless (`meta.move:257-261`), so after the owner removes a leaked first key (the main reason for key removal and recovery), anyone can forward objects sent to the account id (e.g. a `Coin<U>` of another type) to the leaked key's address. `Mandate.forward` (`mandate.move:118-120`) is not affected: a mandate's owner is the native address that created it. SPECIFIED. Move tests: remove the first key ⇒ `forward` aborts; `forward_signed` with a current key ⇒ sent to the right `to`.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 291.

### NET-SUI-12 — Lane prune with on-chain horizon
- old: RS7-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-12 · superseded-by: —

**Why.** as built there is no `prune` in `smartcontracts/move/sui/sources`; every lane is one dynamic field (`meta.move:285-287`) whose storage fee the lane pays and never recovers. SPECIFIED. Move tests: prune before the horizon aborts; after it deletes and rebates; `valid_until` beyond the horizon is refused.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 295.

### NET-SUI-13 — Grief after dry-run via node rules
- old: RS7-12 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-13 · superseded-by: —

**Rule.** Grief after dry-run uses the node rules, no Sui-specific mechanism.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 301.

### NET-SUI-14 — Mesh checks sui_op signature first
- old: RS7-13 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-14 · superseded-by: —

**Rule.** The mesh checks a `sui_op` signature before any dry-run
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 304.

### NET-SUI-15 — Sui package immutable at deploy
- old: RS7-14 · status: current · owner: yes · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-15 · superseded-by: —

**Rule.** The Sui package is immutable from deploy.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 306.

### NET-SUI-16 — KeyOp encoded byte-identical in Python, JS
- old: R261 · status: current · owner: no · date: 2026-10-06 · normative: networks/sui.md#NET-SUI-16 · superseded-by: —

**Rule.** KeyOp is encoded in every client language byte-identical to Move `keyop_digest`, with the domain as a parameter.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 200.

### NET-SUI-17 — One generator run feeds every vector
- old: R262 · status: current · owner: no · date: 2026-10-06 · normative: networks/sui.md#NET-SUI-17 · superseded-by: —

**Rule.** One generator run feeds every language's Sui vectors.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 208.

## Aptos

### NET-APT-01 — Object code deployment, one address
- old: RS11-13(deploy) · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-01 · superseded-by: —

**Rule.** The Aptos package is deployed as one object code deployment: one address for calls and event types.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 20.

### NET-APT-02 — Aptos Rejected table; scaas abort Reverted
- old: RS11-8(table) · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-02 · superseded-by: —

**Rule.** Aptos outcome classes: validation refusals free the lane; a `scaas` abort is `Reverted`.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 21.

### NET-APT-03 — Account keys, origins, three admin paths
- old: RS11-3 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-03 · superseded-by: —

**Rule.** An Aptos Account holds ≤ 8 ed25519 and WebAuthn P-256 keys and ≤ 8 origins; the first key must match the owner's live authentication key; three administration paths.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 22.

### NET-APT-04 — aptos:signMessage envelope parsed strictly
- old: RS11-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/aptos.md#NET-APT-04 · superseded-by: —

**Rule.** The main path is a contract-level meta-tx signed with `aptos:signMessage`, whose `fullMessage` envelope is parsed strictly
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 648.

### NET-APT-05 — One derived Account per subject
- old: RS11-2 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-05 · superseded-by: —

**Rule.** One derived `Account` object per subject holds every asset; its balance is the primary fungible store of the Account address — no internal ledger.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 651.

### NET-APT-06 — Lane table prunable after delay
- old: RS11-4 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-06 · superseded-by: —

**Rule.** The lane table is a `Table` with `valid_until`, prunable by anyone after the delay.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 656.

### NET-APT-07 — Domain = chain_id, Account, asset
- old: RS11-5 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-07 · superseded-by: —

**Rule.** The Aptos domain is the on-chain `chain_id`, the derived contract address and the explicit `asset`.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 658.

### NET-APT-08 — Relayer lane ed25519 sequence account
- old: RS11-6 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-08 · superseded-by: —

**Rule.** An Aptos relayer lane is an ed25519 account at `m/44'/637'/{i}'/0'/0'` sending sequence-number transactions, one in flight, paying its own fee.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 659.

### NET-APT-09 — Hand-written BCS, TS SDK vectors
- old: RS11-7 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-09 · superseded-by: —

**Rule.** Aptos transactions are hand-written BCS, hashed before sending, with vectors from the TS SDK.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 660.

### NET-APT-10 — Finality commit; REST scan by package
- old: RS11-9 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-10 · superseded-by: —

**Rule.** Aptos finality is commit (AptosBFT), indexed by block height; a block with missing transactions fails the range.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 662.

### NET-APT-11 — Aptos DEX Market per pair
- old: RS11-10 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-11 · superseded-by: —

**Rule.** Aptos DEX: one derived `Market` per pair, `min_nonce`/`filled` per market, a permissionless `sweep`, one pair per transaction.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 664.

### NET-APT-12 — Mandate opened by Account key
- old: RS11-11 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-12 · superseded-by: —

**Rule.** An Aptos mandate is opened by an Account key's signature, funded by an ordinary `pay`, and its `pay_ref` entries are prunable.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 666.

### NET-APT-13 — No disk tx journal on Aptos
- old: RS11-12 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-13 · superseded-by: —

**Rule.** No disk transaction journal on Aptos.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 667.

### NET-APT-14 — Pure-Move P-256 passkey verifier
- old: RS11-14 · status: current · owner: yes · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-14 · superseded-by: —

**Rule.** Aptos passkeys are WebAuthn P-256 verified by the pure-Move `scaas::p256`.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 672.

### NET-APT-15 — Indexer API as hint, reread fullnode
- old: RS11-15 · status: current · owner: yes · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-15 · superseded-by: —

**Rule.** The Aptos Indexer API is a hint; content is re-read from the fullnode, and the cursor never passes the indexer's processed version.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 675.

### NET-APT-16 — pay_check view for unopened Account
- old: RS11-16 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-16 · superseded-by: —

**Why.** aptos-node 9.6.0's REST `simulate` hangs on a transaction that both creates the Account object and spends from its pre-existing primary store (the real transaction runs normally); reported upstream if it persists. `relay_pay` runs every check (`pay_checked`) BEFORE opening the Account. BUILT; amended by NET-APT-23.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 677.

### NET-APT-17 — Passkey precomputed P-256 table
- old: RS11-17 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-17 · superseded-by: —

**Rule.** A passkey key is stored with its precomputed `p256::table`
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 679.

### NET-APT-18 — Mandate open, revoke, refund rules
- old: RS11-18 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-18 · superseded-by: —

**Rule.** Mandate open, revoke and refund rules.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 681.

### NET-APT-19 — Strict BCS orders; unordered pair market
- old: RS11-19 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-19 · superseded-by: —

**Rule.** DEX orders travel as BCS bytes parsed strictly, and a market is a named object of the unordered pair.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 683.

### NET-APT-20 — Aptos package immutable at deploy
- old: RS11-20 · status: current · owner: yes · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-20 · superseded-by: —

**Rule.** The Aptos package is immutable from deploy.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 688.

### NET-APT-21 — OOG rebuilt once at gas cap
- old: RS11-21 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-21 · superseded-by: —

**Rule.** A committed out-of-gas is rebuilt once at the gas cap, then `reverted`; every committed transaction is metered.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 695.

### NET-APT-22 — Lazy open requires application line
- old: RS11-22 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-22 · superseded-by: —

**Why.** opt-in was not enough — every client-opened Account starts without origins (`meta.move:345`; `check_envelope` requires `application` only when origins exist, `auth.move:132, 138`), and a phishing page that obtained a `signMessage` can submit `relay_pay` itself (relayer `0x0`) without passing the client.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 698.

### NET-APT-23 — Dispatchable assets refused on unopened path
- old: RS11-23 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-23 · superseded-by: —

**Rule.** Dispatchable assets are refused on the not-yet-opened path.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 700.

### NET-APT-24 — Every signing client honours lane horizon
- old: RS11-24 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-24 · superseded-by: —

**Rule.** Every signing client honours the lane horizon.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 702.

### NET-APT-25 — chainId line stays optional
- old: RS11-25 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-25 · superseded-by: —

**Rule.** The `chainId:` line stays optional.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 704.

### NET-APT-26 — Mesh verifies Aptos signatures locally
- old: RS11-26 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-26 · superseded-by: —

**Rule.** Mesh and gateway verify Aptos signatures locally before any simulation
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 706.

### NET-APT-80 — Upgrade policy compatible
- old: RS11-13(upgrade) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-APT-20

It said: Upgrade policy compatible; replaced by NET-APT-20.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 20.

### NET-APT-81 — Committed OOG requeued without limit
- old: RS11-8(oog) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-APT-21

It said: Committed OOG requeued without limit; replaced by NET-APT-21.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 21.

## Solana

### NET-SOL-01 — Solana network = build-time genesis hash
- old: CR-R3-4 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-01 · superseded-by: —

**Why.** today `initialize(network, admin)` stores any 32 bytes (`account.rs:28-34`), so a Config initialised with another cluster's hash makes that cluster's signatures valid here for the same PDA, for any relayer; our node is protected by the cross-check, third-party relayers are not.
**Cost if wrong.** one build per cluster (already one per program id). SPECIFIED. **Operator invariant until it lands:** never reuse a Solana program id across clusters, and keep the node's genesis cross-check on. Chains are keyed `solana:<genesis hash>`.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 663.

### NET-SOL-02 — Solana Rejected table; scaas errors Reverted
- old: RS12-16(table) · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-02 · superseded-by: —

**Rule.** Solana outcome classes: preflight refusals free the lane; a `scaas` error is `Reverted`; the adapter rebroadcasts.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 24.

### NET-SOL-03 — Program-level meta-tx; native fee payer lane-only
- old: RS12-1 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-03 · superseded-by: —

**Rule.** Solana uses a program-level meta-tx; the subject never sends a transaction on the hot path, and the native fee payer is only ever a relayer lane.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 697.

### NET-SOL-04 — Write-lock is the real lock
- old: RS12-2, net-solana:L12 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-04 · superseded-by: —

**Rule.** On Solana the write-lock is the real lock: the hot path writes only the operation's own new PDA and the two parties' token accounts, and a write-set disjointness test is mandatory.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 698; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 52.

### NET-SOL-05 — One SubjectAccount PDA per subject
- old: RS12-3 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-05 · superseded-by: —

**Rule.** One SubjectAccount PDA per subject holds every mint; its balance is the token accounts owned by the PDA — no internal ledger.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 700.

### NET-SOL-06 — Keys, origins, guardian; open needs assertion
- old: RS12-4 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-06 · superseded-by: —

**Rule.** A SubjectAccount holds ≤ 8 keys (ed25519 / P-256 WebAuthn), ≤ 8 origins and a guardian with a 2-day delay; a new origin under the same rpId is added by that passkey; `open_passkey` requires an assertion.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 701.

### NET-SOL-07 — BACKUP_REQUIRED policy bit, default off
- old: RS12-5 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-07 · superseded-by: —

**Rule.** The `BACKUP_REQUIRED` policy bit is optional and off by default.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 703.

### NET-SOL-08 — Lane PDA prunable, rent to rent_payer
- old: RS12-6 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-08 · superseded-by: —

**Rule.** A lane is a PDA per (account, lane), prunable by anyone after `valid_until + PRUNE_DELAY_S`, with the rent returned to the stored `rent_payer`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 704.

### NET-SOL-09 — Token-2022 extension policy
- old: RS12-7 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-09 · superseded-by: —

**Rule.** SPL Token and Token-2022 are both supported through `token_interface`; a mint that is `NonTransferable`, has an active transfer hook, or charges a transfer fee is refused at every transfer.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 706.

### NET-SOL-10 — Domain = genesis hash, node cross-check
- old: RS12-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-10 · superseded-by: —

**Rule.** The Solana domain is the genesis hash held by `Config` and cross-checked by the node, plus the PDA, the op and the asset.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 707.

### NET-SOL-11 — Raw and OCMS v1; passkey b64url digest
- old: RS12-9(formats) · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-11 · superseded-by: —

**Rule.** ed25519 is accepted as a raw message or an off-chain message v1; a passkey challenge is `base64url(digest)`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 708.

### NET-SOL-12 — Precompile introspection rules
- old: RS12-10 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-12 · superseded-by: —

**Rule.** Precompile introspection: the instruction is loaded through the checked sysvar, must be the right precompile, every instruction index must be `u16::MAX`, and pk + message are compared byte for byte.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 709.

### NET-SOL-13 — Mandate opened by Account key; mref PDA
- old: RS12-11 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-13 · superseded-by: —

**Rule.** A Solana mandate is opened by an Account key's signature; each `pay_ref` is consumed once through a prunable `mref` PDA.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 711.

### NET-SOL-14 — DEX settle checks both signatures
- old: RS12-12 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-14 · superseded-by: —

**Rule.** Solana `settle` verifies both signatures in the same transaction, with one `Fill` PDA per order and a fee vault per market; cancelling creates or closes the `Fill`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 712.

### NET-SOL-15 — Anchor 1.x with LiteSVM
- old: RS12-13 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-15 · superseded-by: —

**Rule.** The program uses Anchor 1.x, built with `cargo build-sbf` and tested with LiteSVM; no Anchor v2 alpha, no native/Pinocchio.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 713.

### NET-SOL-16 — Lane ed25519 with durable nonce
- old: RS12-14 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-16 · superseded-by: —

**Rule.** A Solana relayer lane is an ed25519 key at `m/44'/501'/{i}'/0'` with its own durable nonce account; `sequence` = the nonce value; one transaction in flight.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 714.

### NET-SOL-17 — Hand-written tx v1, kit vectors
- old: RS12-15 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-17 · superseded-by: —

**Rule.** Solana transactions are hand-written v1 transactions, with no `solana-sdk` and no new crate; vectors come from `@solana/kit`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 716.

### NET-SOL-18 — No disk journal; durable nonce suffices
- old: RS12-17 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-18 · superseded-by: —

**Rule.** No disk journal on Solana: the durable nonce and the shared `recover_lane` suffice.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 719.

### NET-SOL-19 — Finalized; standard JSON-RPC indexer
- old: RS12-18 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-19 · superseded-by: —

**Rule.** Solana finality is commitment `finalized` with the slot as cursor; the indexer uses standard JSON-RPC (`getSignaturesForAddress` + `getTransaction`), events through `emit_cpi!`, filtered by program id, event authority and the registered tokens; missing history is an error.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 721.

### NET-SOL-20 — Solana program immutable after initialize
- old: RS12-19 · status: current · owner: yes · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-20 · superseded-by: —

**Rule.** The Solana program is immutable after `initialize`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 726.

### NET-SOL-21 — Destination ATA must exist
- old: RS12-20 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-21 · superseded-by: —

**Why.** an ATA owner can `CloseAccount` it at zero balance and recover ~0.00204 SOL of rent (more for Token-2022 with extensions), and `to` is signer-chosen — loop: the SubjectAccount holds 1 unit; sign `pay(1, to = W)`; the lane creates ATA(W) (as built, `account.rs:210-218`, `util.rs:55-73`; `mandate.rs:170-178` likewise); W sends the unit back, closes ATA(W), keeps the rent; repeat — ≈ 0.002 SOL profit per round, stopped only by `min_relayer_balance` (the hourly breaker sees only fees, `adapter.rs:270-276`). The ERP path is safe (`to` = a fixed receiving wallet); mesh `pay` and the job API are not. Taking the rent from the SubjectAccount's lamports was rejected (gasless subjects hold no SOL). DEX ATAs owned by a SubjectAccount PDA (`dex.rs:252-254`) and the fee vault owned by the Market (`:264-265`) cannot be closed (the program has no `CloseAccount` path), so they are a one-time cost per (PDA, mint), metered and bounded by `max_deposit_per_job`, not a drain. SPECIFIED. LiteSVM: `relay_pay` to a missing ATA ⇒ `DestinationMissing`; to an existing ATA ⇒ runs, the lane pays no rent. Rust: missing destination + unconfigured `to` ⇒ `422`; configured `to` ⇒ the transaction carries the ATA creation; the pay → close → pay loop never creates a second ATA on lane money.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 730.

### NET-SOL-22 — On-chain MAX_TTL_S for expiries
- old: RS12-21 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-22 · superseded-by: —

**Why.** `u64::MAX` makes a PDA never prunable (`account.rs:204`, `dex.rs:199, 312`) — one `cancel_signed` for an invented order hash locks a `Fill`'s rent forever. Rent that never returns (lazy SubjectAccount open, `account.rs:189`, no close path; KeyOp growth through `util::grow`, `account.rs:365`, bounded by 8 keys + 8 origins and never shrinking, so once per Account; `MinNonce`, `dex.rs:327`; DEX ATAs of the PDA and vaults) stays lane-paid — subjects are gasless — but is metered (NODE-LANE-13) and bounded per job (NODE-LANE-18) and per subject (NODE-LANE-15). SPECIFIED. LiteSVM tests: `cancel_signed` with `expiry = u64::MAX` ⇒ error; `relay_pay` with `valid_until = now + 32 days` ⇒ error; every lane PDA created is prunable ≤ `MAX_TTL_S + PRUNE_DELAY_S` after creation.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 735.

### NET-SOL-23 — Out of CU rebuilt once at max_cu
- old: RS12-22 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-23 · superseded-by: —

**Rule.** Compute exhaustion is rebuilt once at `max_cu`, then `reverted`; lane-side faults retry once without grief.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 740.

### NET-SOL-24 — Reject crossOrigin true and topOrigin
- old: RS12-23 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-24 · superseded-by: —

**Rule.** The Solana passkey verifier refuses `"crossOrigin":true` and any `"topOrigin"`
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 742.

### NET-SOL-25 — Every signing client honours lane horizon
- old: RS12-24 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-25 · superseded-by: —

**Rule.** Every signing client honours the lane horizon
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 744.

### NET-SOL-26 — Mesh verifies Solana signatures locally
- old: RS12-25 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-26 · superseded-by: —

**Rule.** Mesh and gateway verify Solana signatures locally before any simulation
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 746.

### NET-SOL-27 — open requires the wallet own signature
- old: RS12-4a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-27 · superseded-by: —

**Rule.** `open` requires the wallet's own signature.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 883.

### NET-SOL-28 — Mandate delegate ed25519; revoke and close
- old: RS12-11a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-28 · superseded-by: —

**Rule.** The mandate delegate is ed25519; revoke only sets a flag; close returns the passed token accounts and closes the PDA.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 884.

### NET-SOL-29 — One pair per instruction; sweep rules
- old: RS12-12a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-29 · superseded-by: —

**Rule.** One pair per `settle` instruction; a batch is several instructions in one transaction; `sweep` is permissionless.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 887.

### NET-SOL-30 — Passkey blob length little-endian
- old: RS12-9a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-30 · superseded-by: —

**Rule.** In the passkey blob the `u16` authenticatorData length is little-endian.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 891.

### NET-SOL-31 — Restart advances nonce; error classes
- old: RS12-16a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-31 · superseded-by: —

**Rule.** On restart the Solana adapter advances each lane's nonce once, and errors are classed by instruction index.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 892.

### NET-SOL-32 — block_hash from last produced block
- old: RS12-18a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-32 · superseded-by: —

**Rule.** `block_hash(s)` is the hash of the last produced block ≤ s within a 2 048-slot window; `Config` is read at `confirmed`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 894.

### NET-SOL-80 — Out of CU requeued without limit
- old: RS12-16(cu) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-SOL-23

It said: Out of CU requeued without limit; replaced by NET-SOL-23.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 24.

### NET-SOL-81 — Signed text is domain plus hex digest
- old: RS12-9(text) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-ALL-23

It said: Signed text is domain plus hex digest; replaced by NET-ALL-23.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 708.

## TON

### NET-TON-01 — TON Tact jetton wallet; escrow DEX
- old: R67(core) · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-01 · superseded-by: —

**Rule.** TON = a Tact jetton whose custom wallet verifies signed operations; the DEX is an escrow.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 540.

### NET-TON-02 — TON per-wallet domain set on chain
- old: CR-R3-7, reorg:Q3 · status: current · owner: yes · date: 2026-10-07 · normative: networks/ton.md#NET-TON-02 · superseded-by: —

**Rule.** TON binds the `signData` domain on chain through a per-wallet domain set.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 693; [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1217.

### NET-TON-03 — TON bounced payouts claimable by owner
- old: CR-R3-9, reorg:Q4 · status: current · owner: yes · date: 2026-10-07 · normative: networks/ton.md#NET-TON-03 · superseded-by: —

**Why.** as built `bounced<JettonTransfer>` adds to `fees[master]` (`dex.tact:131-136`), which `WithdrawFees` withdraws (`:43,158`). SPECIFIED. Tests (sandbox): a bounced refund lands in `unclaimed`, `WithdrawFees` cannot take it, `Claim` pays the owner.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 703; [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1218.

### NET-TON-04 — Compact Tact Jetton with meta-tx wallet
- old: R10-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-04 · superseded-by: —

**Rule.** The token is a compact Tact rewrite of a TEP-74 Jetton (`ScaasJettonMaster` + `ScaasJettonWallet`) whose wallet adds `pubkey`, `passkey` and a `lanes` table; no off-the-shelf jetton is used.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 24.

### NET-TON-05 — TON Connect signData cell envelope
- old: R10-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-05 · superseded-by: —

**Rule.** The subject signs with TON Connect `signData` type `cell`; the contract rebuilds the exact envelope around the `MetaOp` cell and checks `CHKSIGNU` over the envelope cell hash; the seed signer builds the same envelope with `m/44'/607'/i'`.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 25.

### NET-TON-06 — Network domain = config 19 global id
- old: R10-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-06 · superseded-by: —

**Rule.** The TON network domain is the `global_id` read on chain from config parameter 19
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 27.

### NET-TON-07 — Lazy key bind via SignedOp stateInit
- old: R10-5 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-07 · superseded-by: —

**Rule.** The key binds lazily through the `SignedOp`'s optional `stateInit`.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 28.

### NET-TON-08 — One TON passkey set by set_key
- old: R10-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-08 · superseded-by: —

**Rule.** A TON wallet holds one passkey, attached or detached by `set_key`, which must carry a proof of possession of the attached key; origins match exactly.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 29.

### NET-TON-09 — TON DEX is fill-or-kill escrow
- old: R10-7 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-09 · superseded-by: —

**Rule.** The TON DEX is a fill-or-kill escrow.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 30.

### NET-TON-10 — Relayer lane = W5R1 wallet, one message
- old: R10-8 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-10 · superseded-by: —

**Rule.** A TON relayer lane is a W5R1 wallet with its own seqno, one external message in flight, and W5 `valid_until` = the payload's expiry.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 31.

### NET-TON-11 — Node uses TON Center API v3
- old: R10-9 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-11 · superseded-by: —

**Rule.** The node uses TON Center API v3
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 32.

### NET-TON-12 — Events authenticated by derived wallet address
- old: R10-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-12 · superseded-by: —

**Rule.** TON events are authenticated by the derived wallet address.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 33.

### NET-TON-13 — No relayer fee; forward TON capped
- old: R10-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-13 · superseded-by: —

**Rule.** No relayer fee on TON; the DEX ppm fee is signed in the order; gas TON is attached per message and the excess returns to the lane; forward TON is capped.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 34.

### NET-TON-14 — Forward TON capped on every path
- old: R10-12 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-14 · superseded-by: —

**Rule.** Forward TON is capped on every path (blocking).
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 225.

### NET-TON-15 — tx_id is TEP-467 normalized hash
- old: R10-13 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-15 · superseded-by: —

**Why.** as built the code returns `ext.hash()` of the message as sent (`ton.rs:743-750`, looked up raw at `:994-997`); for seqno 0 (with `init`) the two hashes differ, and anyone relaying the BOC (TON Center, a proxy, a mesh peer) can re-wrap it (the envelope is not inside the W5 signature), so `follow` reports `dead` while the money moved. SPECIFIED. Test: a seqno-0 message with `init` ⇒ `tx_id ≠ ext.hash()`, a fake API finds it by normalized hash; a re-wrapped copy still yields `Mined`.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 235.

### NET-TON-16 — Node checks TON domain at every door
- old: R10-14(node) · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-16 · superseded-by: —

**Rule.** The node checks the TON Connect domain at every door.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 239.

### NET-TON-17 — Simulation reads balance, checks passkey locally
- old: R10-15 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-17 · superseded-by: —

**Rule.** TON simulation reads the jetton balance and checks the passkey locally.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 245.

### NET-TON-18 — Revoke runs exactly once
- old: R10-16 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-18 · superseded-by: —

**Why.** as built the wallet accepts `next == nonce` or `nonce + 1` (`jetton.tact:229`) and the first form sets `next + 1`, so a resend of the **same** signature runs again in the second form, consuming `nonce + 1` and sending a `CancelTag`. SPECIFIED. Test: resending the same revoke ⇒ `E_NONCE`, no second `CancelTag`.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 248.

### NET-TON-19 — DEX keeps nothing not its own
- old: R10-17(cancel/fees) · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-19 · superseded-by: —

**Rule.** The TON DEX keeps nothing that is not its own.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 250.

### NET-TON-80 — TON BindKey message
- old: R67(bindkey) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NET-TON-07

It said: TON BindKey message; replaced by NET-TON-07.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 540.

### NET-TON-81 — Domain checked only in the ERP
- old: R10-3 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-TON-16, NET-TON-02

It said: Domain checked only in the ERP; replaced by NET-TON-16, NET-TON-02.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 16.

### NET-TON-82 — domainHash pinned in wallet init
- old: R10-14(contract) · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-TON-02

It said: domainHash pinned in wallet init; replaced by NET-TON-02.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 239.

### NET-TON-83 — Bounced payouts via admin RefundBounced
- old: R10-17(bounced) · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-TON-03

It said: Bounced payouts via admin RefundBounced; replaced by NET-TON-03.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 250.

## Signers and clientkeys

### CLI-SGN-01 — Ephemeral agent session keys (1-8 h)
- old: req:blockchain.md:session-keys · status: open · owner: yes · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-01 · superseded-by: —

**Rule.** Short-lived agent session keys (1–8 h) are an open owner requirement.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 328.

### CLI-SGN-02 — Seed vault DEK with passphrase and PRF envelopes
- old: RS4-8(vault) · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-02 · superseded-by: —

**Rule.** The vault encrypts the seed under a random data key wrapped by a passphrase envelope and, when available, a passkey PRF envelope.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 33.

### CLI-SGN-03 — Zether keys derived in clientkeys JS
- old: RS4-9(keys) · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-03 · superseded-by: —

**Rule.** Zether keys are derived in clientkeys JavaScript.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 35.

### CLI-SGN-04 — Random WebAuthn user handle per passkey
- old: RS4-11 · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-04 · superseded-by: —

**Rule.** Each passkey gets a random 16-byte WebAuthn user handle.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 48.

### CLI-SGN-05 — Client rebuilds operation before signing
- old: RS4-13 · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-05 · superseded-by: —

**Rule.** A client never signs server-built typed data as is; it rebuilds the operation first.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 57.

### CLI-SGN-06 — WalletConnect is a seam behind a flag
- old: R21 · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-06 · superseded-by: —

**Why.** the SDK is ~400 KB, needs a pinned version + SRI, cannot be tested in offline CI, and a third-party script inside a payment page is supply-chain surface.
**Cost if wrong.** mobile wallets need a small add-on that registers the factory (pinned `@walletconnect/ethereum-provider` + SRI) first. The same holds for Hedera HashPack (also a seam) and the TON Connect HTTP bridge.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 192.

### CLI-SGN-07 — Subject-account seed keys use role path
- old: CR-ADW-3 · status: current · owner: no · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-07 · superseded-by: —

**Rule.** New seed keys of subject accounts use the role path.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 310.

### CLI-SGN-08 — checkPayment pins expected token client-side
- old: CR-ADW-4 · status: current · owner: no · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-08 · superseded-by: —

**Rule.** `checkPayment` pins the expected token client-side.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 316.

### CLI-SGN-09 — Portal and mobile subjects sign with passkeys
- old: R31(client) · status: current · owner: yes · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-09 · superseded-by: —

**Rule.** Portal and mobile subjects sign value operations with WebAuthn P-256 passkeys.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 519.

### CLI-SGN-10 — Zether keys from seed, own paths
- old: R33(keys) · status: current · owner: yes · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-10 · superseded-by: —

**Rule.** Zether confidential keys come from the same seed on their own paths.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 521.

### CLI-SGN-11 — Client-side seed vault, multi-key accounts
- old: R32(vault) · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-11 · superseded-by: —

**Rule.** A non-custodial seed wallet lives on the client, and one subject account holds several keys (passkey + seed).
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 522.

### CLI-SGN-12 — Backup key required is one switch
- old: R250 · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-12 · superseded-by: —

**Rule.** "Backup key required" is one boolean deployment switch, default off.
**Cost if wrong.** per-company rules later would need a company field. SPECIFIED.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 77.

### CLI-SGN-13 — Backup predicate: distinct keys or guardian
- old: R251 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-13 · superseded-by: —

**Why.** duplicates and self-guardians are exactly the false "backed up" state the switch exists to prevent.
**Cost if wrong.** two passkeys in one password manager still count as two (CLI-SGN-16 warns).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 85.

### CLI-SGN-14 — Backup enforced by clients and issuers
- old: R252 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-14 · superseded-by: —

**Why.** the switch protects users from loss and is not a security control.
**Cost if wrong.** a third-party client ignores it, by design.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 99.

### CLI-SGN-15 — Exits are never blocked
- old: R253 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-15 · superseded-by: —

**Why.** rescue is never throttled.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 112.

### CLI-SGN-16 — Non-blocking BE/BS warnings
- old: R254 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-16 · superseded-by: —

**Why.** the flags are the only sync signal and are self-reported (`attestation: 'none'`).
**Cost if wrong.** a misreporting authenticator mislabels a key; counting is unaffected.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 123.

### CLI-SGN-17 — Vault v2 under non-extractable device key
- old: R255 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-17 · superseded-by: —

**Rule.** Vault v2 is an outer AES-256-GCM layer under a per-origin non-extractable device key, wrapped around the unchanged v1 vault.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 135.

### CLI-SGN-18 — Device binding relaxes nothing
- old: R256 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-18 · superseded-by: —

**Rule.** Device binding relaxes nothing.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 144.

### CLI-SGN-19 — Vault storage, precedence and migration
- old: R257 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-19 · superseded-by: —

**Rule.** Vault storage, precedence and migration.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 153.

### CLI-SGN-20 — Device-loss recovery via phrase only
- old: R258 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-20 · superseded-by: —

**Why.** a re-reveal path would undermine "written down" (CLI-SGN-13).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 165.

### CLI-SGN-21 — scrypt N=2^17 for new envelopes
- old: R259, RS4-14 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-21 · superseded-by: —

**Why.** one number in code and docs, and no device locked out by its own upgrade.
**Cost if wrong.** very low-memory phones use a paper backup or an extension wallet. BUILT (parameters and re-wrap); the failure, marker and bounds tests SPECIFIED.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 173; [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 61.

### CLI-SGN-22 — Seed signers sign family envelopes
- old: R263 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-22 · superseded-by: —

**Why.** the seed signs silently. SPECIFIED for Soroban, Aptos, Solana.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 217.

### CLI-SGN-23 — One WebAuthn ceremony, per-family encoders
- old: R264 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-23 · superseded-by: —

**Why.** verifier maturity.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 227.

### CLI-SGN-24 — Passkey challenge = b64url op digest
- old: R265 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-24 · superseded-by: —

**Rule.** The passkey challenge is base64url (no padding) of the family's op digest.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 231.

### CLI-SGN-25 — Added seed keys are role keys
- old: R269 · status: current · owner: no · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-25 · superseded-by: —

**Why.** a backup in the same browser profile as the primary key is not a backup.
**Cost if wrong.** one derivation per role; wallets show the role.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 235.

### CLI-SGN-26 — One connector implementation in clientkeys
- old: R266 · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-26 · superseded-by: —

**Rule.** One connector implementation in clientkeys, shared by the app and every portal.
**Cost if wrong.** clientkeys gains browser glue. SPECIFIED (as built, the portal connectors are seven node-tested scripts that nothing loads; the portal's payment script is EVM only — EIP-6963, EIP-1193 fallback, the WalletConnect seam, `eth_signTypedData_v4`, the `wallet_kind` hint — and reads `start.typed_data.message.validUntil`, which a non-EVM start lacks; the issuer side is already family-ready: `{family, valid_until, payload_hex, digest, …terms}` plus `public_key`).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 254.

### CLI-SGN-27 — Check, then sign what was checked
- old: R267 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-27 · superseded-by: —

**Rule.** Check, then sign exactly what was checked.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 263.

### CLI-SGN-28 — Signers spec adds no ids or kinds
- old: R268 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-28 · superseded-by: —

**Rule.** The signer rules add no account id, registry or key kind.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 279.

### CLI-SGN-29 — One key one purpose: wallet layer
- old: R298(1) · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-29 · superseded-by: —

**Why.** ECDSA and Schnorr over one secp256k1 key leak through nonce relations; a Schnorr signing oracle on an ElGamal key is a decryption-adjacent oracle; untagged digests replay across protocols. Owner decision.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 166.

### CLI-SGN-30 — EOA path EOA-only; role tree m/7622
- old: R300, S4F:Q1, UA:Q6 · status: current · owner: yes · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-30 · superseded-by: —

**Rule.** The EVM seed path is the EOA only; every subject-account key that is not the native owner and every derived kind comes from the UA tree `m/7622'/0'/<account>'/<kindNo>'/<i>'`.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 181; [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 784; [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 1398.

### CLI-SGN-31 — Key oracle keeps no persistent state
- old: UD:§23.10 · status: current · owner: yes · date: 2026-08-31 · normative: clients/signers-clientkeys.md#CLI-SGN-31 · superseded-by: —

**Rule.** The key oracle keeps no persistent state.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2356.

### CLI-SGN-32 — Oracle lane only when an organization holds Zether
- old: UD:§23.11, canon:D7 · status: current · owner: yes · date: 2026-08-31 · normative: clients/signers-clientkeys.md#CLI-SGN-32 · superseded-by: —

**Rule.** A server-side key-oracle lane exists only when an organization holds a Zether account.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2416; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 861.

### CLI-SGN-80 — Vault PIN scrypt N=2^15
- old: RS4-8(scrypt) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-21

It said: Vault PIN scrypt N=2^15; replaced by CLI-SGN-21.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 33.

### CLI-SGN-81 — Zether PoP bound to subject account
- old: RS4-9(pop) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-07

It said: Zether PoP bound to subject account; replaced by CTR-UA-07.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 35.

### CLI-SGN-82 — Per-subject localStorage vault
- old: RS4-15 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-19

It said: Per-subject localStorage vault; replaced by CLI-SGN-19.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 65.

### CLI-SGN-83 — Zether on chain stays deferred
- old: R33(deferred) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-ZTH-01, CTR-ZTH-18, CTR-ZTH-19, CTR-UA-02, CTR-UA-16, CTR-UA-22, INT-ERP-11

It said: Zether on chain stays deferred; replaced by CTR-ZTH-01, CTR-ZTH-18, CTR-ZTH-19, CTR-UA-02, CTR-UA-16, CTR-UA-22, INT-ERP-11.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 521.

### CLI-SGN-84 — Zether PoP bound to caller account
- old: R33(pop) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-07

It said: Zether PoP bound to caller account; replaced by CTR-UA-07.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 521.

### CLI-SGN-85 — Account seed keys on EOA path
- old: R32(path) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-30

It said: Account seed keys on EOA path; replaced by CLI-SGN-30.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 522.

### CLI-SGN-86 — Seed vault scrypt N=2^15 with PIN
- old: R32(scrypt) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-21

It said: Seed vault scrypt N=2^15 with PIN; replaced by CLI-SGN-21.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 522.

### CLI-SGN-87 — Custody tier A/B, HSM or MPC
- old: UD:§15:D7 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CLI-SGN-32

It said: Custody tier A/B, HSM or MPC; replaced by CLI-SGN-32.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 861.

## SCaaS app

### CLI-APP-01 — One SPA, two halves, one build
- old: R150 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-01 · superseded-by: —

**Why.** chain features work without login; one artefact to test and pin.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 104.

### CLI-APP-02 — React, TanStack Query, hash routes
- old: R151 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-02 · superseded-by: —

**Why.** server state dominates; hash routing removes SPA-fallback rules from every host and from the node.
**Cost if wrong.** deep links look like `/#/…`.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 105.

### CLI-APP-03 — App has no server and no secrets
- old: R152 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-03 · superseded-by: —

**Why.** machine credentials and admin credentials never cross (NODE-ADM-06).
**Cost if wrong.** public gateways run with auth `none` behind a host proxy with rate limits.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 106.

### CLI-APP-04 — One adapter interface per family
- old: R153 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-04 · superseded-by: —

**Why.** family SDKs are most of the bytes.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 107.

### CLI-APP-05 — App builds and decodes every signed byte
- old: R154 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-05 · superseded-by: —

**Why.** display and bytes cannot diverge silently; one JS implementation is shared with portals.
**Cost if wrong.** clientkeys grows to all families.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 108.

### CLI-APP-06 — App signer set and key paths
- old: R155 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-06 · superseded-by: —

**Why.** one wallet-glue implementation; one key, one purpose.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 109.

### CLI-APP-07 — Relayed submission for Hedera and non-EVM
- old: APP:Q1, R156 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-07 · superseded-by: —

**Why.** with gateway submission a user needs no native gas on any family.
**Cost if wrong.** until those routes exist, Hedera and non-EVM are self-paid only.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 1029; [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 110.

### CLI-APP-08 — Intent status is chain truth
- old: R157 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-08 · superseded-by: —

**Why.** the node is trusted for liveness, not truth.
**Cost if wrong.** one read per poll.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 111.

### CLI-APP-09 — Signing review from decoded bytes
- old: R158 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-09 · superseded-by: —

**Why.** extension wallets show hex for most families; the app's review is the only real check.
**Cost if wrong.** non-curated tokens take an explicit-add step.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 112.

### CLI-APP-10 — Static mode config.json and CSP
- old: R161 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-10 · superseded-by: —

**Why.** one build, every host.
**Cost if wrong.** a host without headers runs the weaker meta CSP.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 115.

### CLI-APP-11 — Admin tokens in memory only
- old: R162 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-11 · superseded-by: —

**Rule.** Admin tokens live in memory only, per node.
**Cost if wrong.** built-in users retype the password after a reload.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 116.

### CLI-APP-12 — OIDC public client with PKCE
- old: R163 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-12 · superseded-by: —

**Why.** no hand-rolled OAuth.
**Cost if wrong.** IdPs without SPA refresh tokens bounce the page once per token lifetime.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 117.

### CLI-APP-13 — Zether runs in a session worker
- old: R164 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-13 · superseded-by: —

**Rule.** Zether runs in one session worker.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 118.

### CLI-APP-14 — Passkeys origin-bound; backup de-duplication
- old: R165 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-14 · superseded-by: —

**Why.** the two deployment modes are two origins.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 119.

### CLI-APP-15 — Pinned supply chain, one dev flag
- old: R166 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-15 · superseded-by: —

**Why.** every dependency has signing reach.
**Cost if wrong.** upgrades are deliberate.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 120.

### CLI-APP-16 — Risk disclosures English beside translation
- old: APP:Q3, R167 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-16 · superseded-by: —

**Rule.** English is the default and every string has a Vietnamese translation; risk disclosures show the English original beside the translation until the owner approves the text.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 1031; [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 121.

### CLI-APP-17 — Role gating is UI only
- old: R168 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-17 · superseded-by: —

**Rule.** Role gating in the app is UI only
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 122.

### CLI-APP-18 — Contract-held roles receive calldata
- old: R169 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-18 · superseded-by: —

**Rule.** Contract-held roles get calldata, not transactions.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 123.

### CLI-APP-19 — App dials only allowlisted origins
- old: R170 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-19 · superseded-by: —

**Why.** network-learned URLs are attacker-chosen, and SDKs issue their own requests.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 124.

### CLI-APP-20 — Metrics are a dashboard link
- old: R171 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-20 · superseded-by: —

**Rule.** Metrics are a dashboard link
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 125.

### CLI-APP-21 — Non-EVM DEX books after EVM
- old: APP:Q2, R172 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-21 · superseded-by: —

**Why.** only the EVM venue has a book.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 1030; [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 126.

### CLI-APP-22 — Chain identity and metadata verified
- old: R173, R173a, R173b, R173c · status: current · owner: no · date: 2026-10-07 · normative: clients/app.md#CLI-APP-22 · superseded-by: —

**Rule.** Chain identity and token metadata are verified, not trusted.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 127.

### CLI-APP-23 — approve spender allowlist
- old: R174 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-23 · superseded-by: —

**Why.** the contract-only spender rule (CTR-TOK-01) stops EOA spenders only, and anyone can deploy a contract.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 128.

### CLI-APP-24 — Keys run in a dedicated worker
- old: R175 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-24 · superseded-by: —

**Why.** a compromised transitive dependency in any SDK chunk could otherwise read an unlocked seed.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 129.

### CLI-APP-25 — Account model follows UA spec
- old: R176 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-25 · superseded-by: —

**Rule.** The account model follows the Universal Account design.
**Cost if wrong.** two account kinds to explain.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 130.

### CLI-APP-26 — Token kinds decoded from versionOf
- old: R177 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-26 · superseded-by: —

**Rule.** Token kinds are decoded from `versionOf(token)`, values 0–7.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 131.

### CLI-APP-27 — Untrusted text sanitised
- old: R179 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-27 · superseded-by: —

**Why.** with an open factory anyone can deploy "USDC".
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 133.

## ERP integration

### INT-ERP-01 — 24 h cooling-off for new receiving wallets
- old: R22 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-01 · superseded-by: —

**Rule.** A newly approved receiving wallet is usable only after a cooling-off of 24 h
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 193.

### INT-ERP-02 — Custodial partner payer wallet needs license_ref
- old: R24 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-02 · superseded-by: —

**Rule.** A `custodial` paying wallet of a non-company partner requires `license_ref`.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 195.

### INT-ERP-03 — Contract wallets: ERP defers to node simulation
- old: R27 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-03 · superseded-by: —

**Rule.** Contract wallets: the ERP defers to node simulation.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 200.

### INT-ERP-04 — MandateWallet deployed outside the ERP
- old: R29 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-04 · superseded-by: —

**Rule.** A `MandateWallet` is deployed outside the ERP
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 204.

### INT-ERP-05 — Outbox call jobs immutable, operator read-only
- old: CR-PD-1(a/b) · status: current · owner: no · date: 2026-10-07 · normative: integration.md#INT-ERP-05 · superseded-by: —

**Rule.** Outbox `call` jobs are immutable and operators are read-only.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 247.

### INT-ERP-06 — Portal terms fee NONE, relayer restricted
- old: R10 · status: current · owner: no · date: 2026-10-05 · normative: integration.md#INT-ERP-06 · superseded-by: —

**Rule.** Self-service payment terms use fee `NONE` and `MODE_RESTRICT_RELAYER` to the company relayer, `fee = 0`, and a server-chosen validity (default 300 s).
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 696.

### INT-ERP-07 — No FX: token currency equals order currency
- old: R17 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-07 · superseded-by: —

**Rule.** No FX: the token's currency equals the order currency.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 730.

### INT-ERP-08 — ERP-held env: custody dev-only, OpenSSL
- old: R50 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-08 · superseded-by: —

**Rule.** The ERP-held `env:` custody is dev-only and signs through OpenSSL.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 523.

### INT-ERP-09 — Journal per (company, token); drift A and C
- old: R56 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-09 · superseded-by: —

**Rule.** One journal per (company, token); drift A and drift C.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 529.

### INT-ERP-10 — ERP family-aware addresses and signed ops
- old: R61 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-10 · superseded-by: —

**Rule.** The ERP is family-aware: chains carry a family, addresses are stored in the family's normalised form, and non-EVM payments are signed ops.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 534.

### INT-ERP-11 — ERP confidential requests, disclosure reconciliation, audit keys
- old: R34(erp) · status: current · owner: yes · date: 2026-10-03 · normative: integration.md#INT-ERP-11 · superseded-by: —

**Rule.** Confidential payment requests are reconciled from disclosed amounts, with an audit key per company.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 546.

### INT-ERP-12 — ERP mirrors markets and books DEX fees
- old: R35(erp) · status: current · owner: yes · date: 2026-10-03 · normative: integration.md#INT-ERP-12 · superseded-by: —

**Rule.** The ERP mirrors DEX markets and books DEX fees.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 554.

### INT-ERP-13 — ERP verifies ED25519 for long-zero payers
- old: R6-3 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-13 · superseded-by: —

**Rule.** Hedera long-zero payers sign with their native ED25519 key.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 293.

### INT-ERP-14 — ERP verifies G… ed25519 via OpenSSL
- old: R8-6 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-14 · superseded-by: —

**Rule.** The ERP verifies Stellar `G…` ed25519 through OpenSSL.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 193.

### INT-ERP-15 — Bus scope is a per-tenant client setting
- old: R73 · status: current · owner: yes · date: 2026-10-06 · normative: integration.md#INT-ERP-15 · superseded-by: —

**Rule.** Bus scope is a per-tenant client setting delivered per job.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 73.

### INT-ERP-16 — One node per company and chain
- old: R97(routing) · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-16 · superseded-by: —

**Why.** one lane journal per signer is the double-spend guard.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 120.

### INT-ERP-17 — Client kills locally only if never pushed
- old: R98(client) · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-17 · superseded-by: —

**Rule.** The client kills a job locally only if it was never pushed; otherwise it cancels on the node, by uid or by origin.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 121.

### INT-ERP-18 — Client push and sync cadence
- old: R101 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-18 · superseded-by: —

**Why.** a client that cannot hold a long poll still sees status within seconds.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 125.

### INT-ERP-19 — Client halts sync on store change
- old: R110(store-loss) · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-19 · superseded-by: —

**Rule.** The client halts sync on a store change.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 135.

### INT-ERP-20 — Client status latency bounds
- old: NI:I4 · status: open · owner: no · date: 2026-10-07 · normative: integration.md#INT-ERP-20 · superseded-by: —

**Rule.** INT-ERP-20 — *Open (default applied).* Payment status latency is ≤ ~10 s while jobs are live and ≤ 1 min otherwise, from the cadence of INT-ERP-18. Owner confirmation pending; the default stands.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1613.

### INT-ERP-21 — ERP Sui verify follows lesson L9
- old: R260 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-21 · superseded-by: —

**Rule.** ERP verifiers are three-valued and verify only with a key provably bound to the payer
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 188.

### INT-ERP-22 — Client holds salts; chain only commitments
- old: R195 · status: current · owner: yes · date: 2026-10-06 · normative: integration.md#INT-ERP-22 · superseded-by: —

**Rule.** The client holds every salt and key; the chain holds only commitments; the node holds neither salts nor personal data.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 215.

### INT-ERP-23 — Commitment and Merkle formats
- old: R196 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-23 · superseded-by: —

**Rule.** Commitment and Merkle formats:
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 218.

### INT-ERP-24 — Per-subject DEK; erasure destroys it
- old: R197 · status: current · owner: no · date: 2026-10-07 · normative: integration.md#INT-ERP-24 · superseded-by: —

**Rule.** Salts and anchored payloads are encrypted under a per-subject data key (DEK); erasure destroys the DEK.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 224.

### INT-ERP-25 — References carry no personal data
- old: R198 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-25 · superseded-by: —

**Rule.** References carry no personal data and are not derived from business identifiers.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 234.

### INT-ERP-26 — Disclosure is opening a commitment
- old: R199 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-26 · superseded-by: —

**Rule.** Disclosure is opening a commitment.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 238.

### INT-ERP-27 — Payment mode is configuration, not hard-coded
- old: UD:§1:payment-mode · status: current · owner: yes · date: 2026-08-30 · normative: integration.md#INT-ERP-27 · superseded-by: —

**Rule.** The payment mode is configuration, not code.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 45.

## Example connector

### INT-ODOO-01 — Deploy job precedes pay via prerequisite
- old: RS4-6 · status: current · owner: no · date: 2026-10-06 · normative: integration-odoo-example.md#INT-ODOO-01 · superseded-by: —

**Rule.** The deploy job precedes payment through a prerequisite.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 28.

### INT-ODOO-02 — Owner-call nonce from mined jobs
- old: RS4-7 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-02 · superseded-by: —

**Rule.** The `executeAsOwner` nonce is the count of the account's `mined/final` owner-call jobs
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 31.

### INT-ODOO-03 — First key registered with HMAC challenge
- old: RS4-12 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-03 · superseded-by: —

**Rule.** The first key registers in two steps with an HMAC challenge.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 51.

### INT-ODOO-04 — Deploy job only for payer own account
- old: RS4-16 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-04 · superseded-by: —

**Rule.** A deploy job is created only for the account of the paying partner itself
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 67.

### INT-ODOO-05 — Payment addon depends on account_payment
- old: R28 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-05 · superseded-by: —

**Rule.** `dms_blockchain_payment` depends on `account_payment`
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 202.

### INT-ODOO-06 — No idempotency addon; natural UNIQUE keys
- old: R7 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-06 · superseded-by: —

**Rule.** No `bamboo_idempotency` dependency; dedup by UNIQUE natural keys.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 682.

### INT-ODOO-07 — Odoo addon split, no account addon
- old: R8, UD:§1:independent-addon · status: current · owner: yes · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-07 · superseded-by: —

**Rule.** The blockchain addons never depend on the DMS core; no accounting addon of their own.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 685; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 44.

### INT-ODOO-08 — Odoo verifies ECDSA signatures itself
- old: R13 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-08 · superseded-by: —

**Rule.** Odoo verifies ECDSA signatures itself
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 706.

### INT-ODOO-09 — Portal pay button calls model facade
- old: R14 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-09 · superseded-by: —

**Rule.** The portal pay button is plain JS calling the model facade
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 712.

### INT-ODOO-10 — Portal pays confirmed orders only
- old: R19 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-10 · superseded-by: —

**Rule.** The portal pays confirmed orders only
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 723.

### INT-ODOO-11 — One receiving-company seam; platform company
- old: R57 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-11 · superseded-by: —

**Rule.** One receiving-company seam and one "platform company".
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 530.

### INT-ODOO-12 — Late Matched after restore debits Odoo book
- old: RS5-20(odoo-book) · status: current · owner: no · date: 2026-10-07 · normative: integration-odoo-example.md#INT-ODOO-12 · superseded-by: —

**Rule.** A late `Matched` after a restore debits the Odoo-held book.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 449.

### INT-ODOO-13 — Odoo stores UAs as addresses
- old: R318 · status: current · owner: no · date: 2026-10-06 · normative: integration-odoo-example.md#INT-ODOO-13 · superseded-by: —

**Rule.** Odoo stores UAs as addresses of a new kind and never derives policy off chain.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 334.

### INT-ODOO-14 — Key registration is not the addon's job
- old: UD:§15:D14, canon:D14 · status: current · owner: yes · date: 2026-08-30 · normative: integration-odoo-example.md#INT-ODOO-14 · superseded-by: —

**Rule.** Key registration is not the addon's job.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 869.

### INT-ODOO-80 — Host company configuration parameter
- old: R23 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: INT-ODOO-11

It said: Host company configuration parameter; replaced by INT-ODOO-11.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 194.
