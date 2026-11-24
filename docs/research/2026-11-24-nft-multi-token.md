> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# NFT and multi-token kinds

Research of 2026-11-24 for the owner ("Bây giờ cần là xem xét NFT (multi NFT)": now we need to look at NFTs, multi-NFT).
Nothing here is built, specified or ruled. Every design below is a proposal. All SCaaS code named here is **UNAUDITED**
([ARCH-POS-14](../decisions.md#ARCH-POS-14)).

Tags:
- **[F]** a fact with its source: a SCaaS fact cites a repository path or a rule id, an external fact a URL in §9;
- **[I]** our inference;
- **[E]** an estimate.

EIP statuses were read on eips.ethereum.org on 2026-11-24.

**Contents**

1. [Why now: the use cases](#1-why-now-the-use-cases)
2. [The standards survey](#2-the-standards-survey)
3. [Non-EVM equivalents](#3-non-evm-equivalents)
4. [SCaaS constraints and what they imply](#4-scaas-constraints-and-what-they-imply)
5. [Design options and a recommendation](#5-design-options-and-a-recommendation)
6. [The relayer and SDK side](#6-the-relayer-and-sdk-side)
7. [The pre-freeze question](#7-the-pre-freeze-question)
8. [Open questions, TODO items, effort](#8-open-questions-todo-items-effort)
9. [Sources and what could not be verified](#9-sources-and-what-could-not-be-verified)

## 1. Why now: the use cases

**Today [F].**
- Items are `NORMAL` tokens with `decimals 0`: one token per item kind, recipes as burn and mint
  ([guides/item-economies.md](../guides/item-economies.md) §1, §6).
- "NFTs for unique items" is **PLANNED** there (§8), in [integration.md](../integration.md) (row "NFT kinds"), in
  [token-wrappers.md §13](../contracts/token-wrappers.md#13-limitations) and in
  [asset-suite.md](../contracts/asset-suite.md) ("Non-fungible in-app assets (ERC-721/1155 with meta-tx)").
- The features catalogue sends allocated lots to "the non-fungible kinds (ERC-721 / 1155, PLANNED)"
  ([token-features-catalogue.md](token-features-catalogue.md), row "Lot or serial tracking"). It sends partitions to "P3
  only as a future multi-token kind" (D11).

| Use case | Fungibility | Served today by `decimals 0`? |
|---|---|---|
| Game items, stackable (potions, ingots, arrows) | fungible per kind | **yes**: one token per kind (item-economies §5) |
| Game items with state (a sword with durability 37, a numbered axe) | non-fungible: each unit has its own state | no. The workaround is one kind per level (item-economies §7), which cannot carry per-unit state |
| Tickets and passes, unnumbered (general admission, ten-session pass) | fungible per event or tier | **yes** |
| Tickets, seated or numbered | non-fungible (seat, row) | no. One token per seat is possible but costs one clone each [I] |
| Certificates (diploma, course completion, warranty) | non-fungible: names one holder and one document | no |
| Soulbound credentials (membership, KYC badge) | non-fungible, non-transferable | partly: the receiver allowlist is SPECIFIED, not built (item-economies §7) |
| Allocated lots and serials (gold bars, warehouse lots) | non-fungible (bar number, assay) | no: the catalogue says "allocated lots wait for the non-fungible kinds" |
| Receivables and invoices, one token per claim | non-fungible (debtor, due date, amount) | no |
| RWA units (a share class, a bond tranche) | semi-fungible: fungible within a class, classes differ | yes, one token per class (D11: "a class is its own token") |
| Collectibles (art, editions of N) | unique (1 of 1), or semi-fungible (edition of N) | editions yes as one kind; 1-of-1 needs a token each |

**Inference [I].**
- The gap is not fungible items. It is **many distinct ids under one issuer**, often with **per-id state**: durability,
  seat, bar number, due date.
- A `NormalToken` clone per id is possible today. But it means a clone per id (~45,000 gas each,
  [CTR-TOK-18](../contracts/token-wrappers.md#CTR-TOK-18)), a factory record per id, and no atomic multi-id operation.
- So the need is a **multi-token** in which some ids have supply 1, more than a pure ERC-721.

## 2. The standards survey

Statuses and interface ids are from eips.ethereum.org on 2026-11-24 (§9) [F].

| Standard | Status | Approvals / operators | Receiver callbacks | Batch | Metadata | Notes |
|---|---|---|---|---|---|---|
| ERC-721 | Final | `approve(to, id)` (cleared on transfer), `setApprovalForAll` | `onERC721Received`, only on `safeTransferFrom` to a contract | none | `tokenURI` (extension `0x5b5e139f`) | id `0x80ac58cd`; plain `transferFrom` can strand a token in a contract |
| ERC-1155 | Final | `setApprovalForAll` only, no per-id approval | `onERC1155Received` / `onERC1155BatchReceived`, **mandatory** on every transfer and mint to a contract | `safeBatchTransferFrom`, `balanceOfBatch` | `uri(id)` with `{id}` substitution | id `0xd9b67a26`. The hook runs after the balance update, so it is a reentrancy point |
| **ERC-6909** | Final | `approve(spender, id, amount)`, `setOperator(spender, bool)`, `allowance`, `isOperator` | **none**, removed on purpose | **none**, removed on purpose | optional: `name/symbol/decimals(id)`, `contractURI()`, `tokenURI(id)`, `totalSupply(id)` | id `0x0f632fb3`. The order of the operator and allowance checks is left to the implementation |
| ERC-2981 | Final | — | — | — | — | `royaltyInfo(id, salePrice)`. The spec says payment "must be voluntary": nothing enforces it. id `0x2a55205a` |
| ERC-4906 | Final (extends 721) | — | — | `BatchMetadataUpdate(from, to)` | events `MetadataUpdate(id)` | id `0x49064906` (stated by the EIP, not recomputed by us) |
| ERC-5192 | Final (721) | — | — | — | — | minimal soulbound: `locked(id)`, events `Locked` / `Unlocked`. id `0xb45a3c0e` |
| ERC-5484 | Final (721) | — | — | — | — | consensual soulbound: `burnAuth(id)` ∈ {IssuerOnly, OwnerOnly, Both, Neither}, event `Issued` |
| ERC-4907 | Final (721) | `setUser(id, user, expires)` | — | — | — | rental: `userOf` is 0 once expired. id `0xad092b5c` |
| ERC-6551 | **Review** | the NFT holder is the account's signer | the account takes `receive()` and ERC-1271 | — | — | token-bound accounts from one registry. Known risks: a seller drains the account before a sale settles; ownership cycles lock assets |
| ERC-3525 | Final | `approve(tokenId, operator, value)`: value allowances | `onERC3525Received` | — | `contractURI`, `slotURI(slot)` | semi-fungible: ids carry a value and a slot; value moves between ids of one slot |
| ERC-7518 | **Review** | inherits ERC-1155 | inherits ERC-1155 | `batchPayout` | inherits ERC-1155 | partitions as ids on ERC-1155, with `freezeAddress`, `forceTransfer`, `restrictTransfer` and an EIP-712 voucher |
| ERC-404 | **not an EIP** (no page on eips.ethereum.org) | ERC-20 and ERC-721 approvals on one surface | — | — | — | "experimental … not fully tested or audited" (its README). Amounts and ids share one number space, so one `transferFrom` means either, decided by range: an integration that misses this can release an NFT the caller does not own. v1 minted and burned NFTs on fungible transfers (gas, pool whitelists) |

**Callbacks and reentrancy [F].**
- HypeBears (February 2022): the attacker re-entered `mintNFT` from `onERC721Received` before the per-address counter was
  written.
- Revest Finance (March 2022, about USD 2 M): the attacker re-entered `depositAdditionalToFNFT` from
  `onERC1155Received`.
- Both are mandatory-hook designs that call into the receiver mid-operation. ERC-6909 drops the hooks for this reason
  and for gas.

**Gas, by design [I].**
- ERC-721 keeps one owner slot per id, plus a balance counter per holder.
- ERC-1155 and ERC-6909 keep one balance slot per (holder, id).
- For a unique id moving to a fresh holder, 721 rewrites an existing owner slot. 1155 and 6909 create a new (holder, id)
  slot, at about 97,920 state gas under EIP-8037 ([pq-zero-knowledge.md](../contracts/pq-zero-knowledge.md), the new-slot
  figure) [F], and zero the sender's slot. See §4.6.

**Marketplaces [F].**
- Seaport needs approvals for the Seaport contract, or for a conduit, for every offered ERC-20, 721 or 1155 item.
- For 721 and 1155 that means `approve` or `setApprovalForAll`.
- Seaport's item types are native, ERC-20, ERC-721 and ERC-1155 (with criteria). ERC-6909 is not one of them.

## 3. Non-EVM equivalents

How SCaaS holds balances per family today [F]:

| Family | SCaaS holding today |
|---|---|
| Solana | SPL and Token-2022 through `token_interface`, in a program-level `SmartKeyAccount` PDA; a mint that is `NonTransferable`, has a transfer hook or a transfer fee is refused at every transfer ([NET-SOL-09](../networks/solana.md#NET-SOL-09)) |
| NEAR | per-token records; the relayer pays storage ([NET-NEAR-09](../networks/near.md#NET-NEAR-09)) |
| Algorand | **app boxes, not ASAs**: "An ASA needs the receiver's opt-in, which a UA id cannot give" ([algorand.md §1](../networks/algorand.md#overview)); `OptIn` refused everywhere ([NET-ALG-04](../networks/algorand.md#NET-ALG-04)) |
| Soroban | own SEP-41 contract; `approve` only to a contract spender ([soroban.md §4](../networks/soroban.md#contracts)) |
| Aptos | the `Account` object's primary fungible stores ([aptos.md §2](../networks/aptos.md#accounts)) |
| Sui | a shared `Account<T>` per subject ([NET-SUI-01](../networks/sui.md#overview)) |
| TON | a Tact jetton whose wallet verifies `SignedOp` ([NET-TON-04](../networks/ton.md#NET-TON-04)) |
| Cosmos | CW20 with a contract-level meta-op; allowances only to contract spenders ([cosmos.md §4](../networks/cosmos.md#contracts)) |
| Hedera | HTS only behind an EVM wrapper; HTS allowances cannot be restricted ([hedera.md §7](../networks/hedera.md#hts)) |

The native NFT standards (§9 sources) and how each maps:

| Family | Native standard (status) | Maps | Does not map |
|---|---|---|---|
| Solana | **Metaplex Core** (Metaplex: "the recommended NFT standard for new projects"): one account per asset, plugins (royalties enforced by default, freeze, permanent delegates), collections. **Token Metadata** (legacy): an SPL mint with supply 1 and 0 decimals, a metadata PDA, a master edition; pNFTs freeze the token account and route every operation through rule sets. **Bubblegum v2** compressed NFTs: leaves of a concurrent Merkle tree, read through the DAS API. **Token-2022**: `MetadataPointer` / `TokenMetadata`, `NonTransferable`, group and member pointers | Core assets owned by the `SmartKeyAccount` PDA and moved by its CPI [I]; a Token-2022 mint of supply 1 per unique id in the existing `token_interface` path [I] | `NonTransferable` mints are refused by NET-SOL-09 today, so a soulbound id needs that policy revisited for this kind. pNFT rule sets and the Bubblegum proofs are extra programs and accounts per operation. Bubblegum v2: Phantom, Solflare and Backpack can display but not transfer them yet; Magic Eden and Tensor do not support them yet |
| NEAR | **NEP-171** core (Final), NEP-177 metadata, NEP-178 approvals, NEP-181 enumeration, NEP-199 royalties (all Final). **NEP-245** multi-token (Final): `mt_transfer`, `mt_batch_transfer`, `mt_transfer_call` with `mt_on_transfer` | **NEP-245 maps almost 1:1 onto an ERC-6909-shaped kind**, batch included. The SCaaS path adds a signed `MetaOp` entry beside the native ones | NEP-178 approvals (refused for non-contracts, CTR-TOK-01's rule); `*_transfer_call` is a callback, off by default as on EVM; the native 1 yoctoNEAR deposit sits on the relayer's side |
| Algorand | **ASA** (total 1, decimals 0) with **ARC-3** (Final), **ARC-19** (Final; mutable CID in the reserve address), **ARC-69** (Final; JSON in the note). **ARC-72** (Living): an app-based NFT with `arc72_ownerOf`, `arc72_transferFrom`, optional approvals | **ARC-72's shape** in SCaaS app boxes, keyed (id, holder) [I] | **ASA-based NFTs do not map**: the receiver's opt-in, which a UA id cannot give (the same reason SCaaS tokens are not ASAs). No multi-token ARC was found |
| Soroban | **SEP-0050** (Draft v0.1.0): ERC-721-like, `approve(…, live_until_ledger)`, `approve_for_all`. **OpenZeppelin Stellar** NFT module (v0.8.0): Base, Enumerable or Consecutive, Burnable, Royalties | the SEP-50 shape for unique ids, signed through Soroban authorization ([NET-SOR-01](../networks/soroban.md#overview)) | `approve` / `approve_for_all` to non-contracts. No multi-token SEP was found |
| Aptos | **Digital Asset** standard: a token is an object in a collection; `object::transfer` without opt-in; soulbound by `disable_ungated_transfer` and `aptos_token::mint_soul_bound` | unique ids as objects owned by the SCaaS `Account` object; fungible ids as fungible assets in its primary stores [I] | royalty enforcement on chain (not stated in the docs) |
| Sui | objects with `key` (+ `store` for `public_transfer`). **Kiosk** and `TransferPolicy<T>`: a purchase returns a `TransferRequest` that must satisfy the policy's rules (royalty, for example); a policy enforces nothing by default | unique ids as objects held inside the subject's shared account (a dynamic object field), so a meta-op can move them as it moves `Balance<T>` today [I] | Kiosk sales would be a second path with its own policy; a `key`-only type cannot leave its module's rules |
| TON | **TEP-62**: one contract per item plus a collection; TEP-64 content; TEP-66 royalty parameters; **TEP-85** SBT | item contracts that verify a `SignedOp` as the GRAM wallet does [I]; fungible ids as one jetton master per id | one contract per item makes a 10,000-item collection 10,000 deploys; no on-chain owner query (asynchronous). No multi-token TEP was found |
| Cosmos | **CW-721** (cw-nfts v0.22.0, community-maintained): `TransferNft`, `SendNft` → `ReceiveNft`, per-token `Approve` with expiry, `ApproveAll`. **CW-1155** was removed from cw-plus in 2022 and is not in cw-nfts | the CW-721 shape for unique ids with a contract-level signed op | `Approve` / `ApproveAll` to non-contracts; `SendNft`'s hook (off by default). The multi-token would be our own |
| Hedera | HTS NFTs (not checked in this round, §9) | the EVM kind under `IS_HEDERA`, as for the token wrappers | an HTS NFT directly: protocol allowances cannot be restricted ([NET-HED-04](../networks/hedera.md#NET-HED-04)) |

**One rule on every chain [I].** The common rule is not a standard's ABI. It is:

1. A collection holds ids.
2. Each id has a supply cap (1 = unique), a metadata commitment and flags fixed when the id is defined.
3. Holders are UA ids.
4. Every move is a subject-signed typed operation, relayable at fee 0.
5. Approvals exist only between contracts.
6. There are no receiver callbacks by default.

Each family realises this in its own holding model. It uses the native NFT object where that object can sit under a SCaaS
account (Solana, Aptos, Sui), and a ledger in the contract where it cannot (Algorand, Soroban, Cosmos, NEAR's NEP-245
contract). Wallet display of the native standards is a by-product, not the rule.

## 4. SCaaS constraints and what they imply

### 4.1 No `approve`, no `setApprovalForAll`

The rule [F]:
- **[CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01):** only a contract may call `approve`, a spender must be a
  contract, and only a contract may call `transferFrom`. No permit, no meta-tx `approve`. A UA has no `uaApprove`
  ([CTR-UA-27](../contracts/accounts.md#CTR-UA-27)).
- Contract accounts (a Safe, `SmartKeyAccount`) approve through their own call path.

What replaces allowances today [F]:
- **service pull** ([CTR-MTX-32](../contracts/metatx.md#CTR-MTX-32)): one signed transfer bound to the service and one
  operation;
- **mandates** ([CTR-ACC-06](../contracts/mandates.md#CTR-ACC-06)): a `MandateWallet` pays under caps;
- **DEX orders** ([CTR-DEX-15](../contracts/dex.md#CTR-DEX-15)): the sell token verifies the order and moves funds only
  into `dex`;
- **liquidity orders** ([CTR-DEX-30](../contracts/dex.md#CTR-DEX-30)), which also refuse `setApprovalForAll`
  (`0xa22cb465`) in every DEX interaction.

**What interop is lost [I].**
- An EOA or UA holder cannot list on OpenSea / Seaport, because Seaport needs an approval to its contract or conduit (§2).
- A contract-wallet holder could approve a Seaport conduit, which is a contract and therefore allowed by CTR-TOK-01.
  That works only if the kind speaks ERC-721 or 1155.
- Blur-style operator listings are lost the same way.
- Wallet galleries and indexers that read ERC-721 / 1155 events lose the kind unless it emits those events.

**What SCaaS offers instead [I].**
- A signed listing: the seller's typed `IdSaleOrder` in the collection's domain, settled by a SCaaS market contract (§4.7).
- An offer: the buyer's pay-token `UAMetaTransfer` bound to that market as a service pull.
- Both relayable at fee 0, PQ-signed, and with no standing approval anywhere.
- For Seaport reach: an opt-in adapter (option B's adapter, §5) that the holder enters and leaves knowingly.

### 4.2 Holders, receivers and callbacks

Holders [F]:
- Holders are UA ids (`bytes32`). Derived UAs live in a separate `bytes32` ledger, seen by ERC-20 observers as the
  sub-ledger of `UA_POOL` ([CTR-UA-18](../contracts/accounts.md#CTR-UA-18)).
- Every operation open to a native id is open to a registered signing UA, sender and receiver alike
  ([CTR-UA-27](../contracts/accounts.md#CTR-UA-27)).
- A 7702-delegated caller is refused (`CallerDelegated`, [CTR-UA-24](../contracts/accounts.md#CTR-UA-24)).

Receivers [I]:
- Under no-7702, a receiver that runs code is a deployed contract, never an EOA. A derived UA has no code at all.
- So a callback could reach only real contracts, which are exactly the services that should take custody by service pull
  instead: the service executes the holder's signed transfer and then acts in the same call.
- Callbacks therefore add a reentrancy point (Revest, HypeBears) and buy nothing the service pull lacks. Recommendation:
  **no callbacks** in the kind.
- The ERC-6909 risk of stranding an id in a contract that cannot move it stays, as with every ERC-20. Two mitigations:
  - the registry already refuses a receive to an unregistered derived id ([accounts.md §1](../contracts/accounts.md));
  - wallets warn on contract receivers.

### 4.3 Metadata and media

Today [F]:
- The integration's commitment format: `commitment = keccak256(abi.encode(REC_TAG, salt, payloadHash))`, where
  `payloadHash = SHA-256(JCS(payload))` ([INT-ERP-23](../integration.md#INT-ERP-23)).
- A hash of a guessable payload is not a commitment.

Proposal [I]:
- **A content hash beside every URI, never a URI alone.** Per id: `metadataHash` (`bytes32`, SHA-256 of the canonical
  JSON) and `uri` (a string). Defining an id with a URI and a zero hash is refused.
- Public metadata needs no salt. Private metadata uses the salted commitment above, with the document shared by KEM
  (§4.8).
- **Mutable or frozen, per id.**
  - The metadata is a version list: each `setMetadata(id, hash, uri)` appends a version and emits a `MetadataUpdate`-shaped
    event.
  - `freezeMetadata(id)` is one-way, and a collection may be created with every id frozen at definition.
  - Nothing deployed changes its code. Only data versions move, visibly, as PqVault keeps item versions
    ([pqvault.md](../contracts/pqvault.md)).
- **Per-unit state (durability)** belongs in the game's own contract, keyed by (collection, id), not in the NFT kind. The
  kind stays generic and its audit surface small.

**Arweave [F].** [ARCH-POS-19](../decisions.md#ARCH-POS-19) makes Arweave "a store of ciphertext only": PqChat messages and
images, and files in messages and vault items, encrypted on the client.
- Public NFT media on Arweave is **outside that ruling**: owner question Q3.
- The Arweave credit payer in [sponsorship.md](../node/sponsorship.md) is SPECIFIED, nothing built.
- An Arweave transaction id does not commit to the content by itself [I]. The on-chain `metadataHash` stays the check
  whatever store holds the bytes: Arweave, IPFS (whose CID is a content hash) or a web server.

### 4.4 The factory catalogue and the kind

The factory today [F]:
- `TokenKind` is a fixed enum 0–13 in `IOpenFactory.sol`.
- The generic catalogue takes **a new class or kind without a factory change**: `ReleaseId {contractClass ≥ 3, kind,
  version}`, `publishClassEnv`, `deployImplementation`, `setClassKindEnabled`, `createInstance`
  ([CTR-TOK-28](../contracts/token-wrappers.md#CTR-TOK-28)).
- Class 3 is `PqChat` ([CTR-CHAT-02](../contracts/pqchat.md#CTR-CHAT-02)) and class 4 is `PqVault` (owner 2026-11-17, O6
  (a)).
- Every instance is a clone with its `ChainEnv` appended ([CTR-TOK-29](../contracts/token-wrappers.md#CTR-TOK-29)).

The kind [I]:
- The kind is a **new generic class**, for example class 5, `MultiToken`, kind 0, or a kind per variant (plain,
  regulated). It is never a token kind 14, which would need a factory change.
- **One instance per collection**, with ids inside, not one instance per item kind. Reasons:
  - one clone per collection instead of per id;
  - atomic multi-id operations (a recipe that burns three ids and mints one is one contract's internal move);
  - one EIP-712 domain per collection.
- A game may still keep its fungible currencies as `NORMAL` tokens. The guide's one-token-per-kind items stay valid.

**Features and bits** [F for the bit table, `smartcontracts/vectors/governance/governance_bits.json`; [CTR-GOV-10](../decisions.md#ctr-gov-10--bit-bands-0-127-one-meaning-128-255-per-application-none-refused);
the rest I]:

| Feature | Bit | Notes |
|---|---|---|
| Define ids, mint | 1 `MINTABLE` (power) | minting is by holders of the role. Defining a new id could be the same power or a new one (Q5) |
| Holder burn / role burn | 2 `BURNABLE` / 30 `BURNER` | exclusive, as on tokens ([CTR-GOV-29](../decisions.md#CTR-GOV-29)); the recipe contract holds `BURNER` |
| Supply cap per id | none: an immutable field of the id's definition | cap 1 = unique; cap 0 refused or "uncapped" (Q5) |
| Non-transferable (soulbound) | **new capability bit**, plus a per-id flag at definition | the contract-wide bit allows the per-id flag. ERC-5192 `locked(id)` is a 721 extension; we would expose the view without claiming the id |
| Regulated (freeze, pause, allow / deny, KYC) | 5, 7, 8, 9, 28 | only in a regulated variant, as for tokens ([CTR-GOV-03](../decisions.md#ctr-gov-03--a-plain-transfer-stays-0-one-regulated-implementation-per-kind-never-per-feature)); per-id freeze would be a new meaning of 5, so a separate bit |
| Royalties | **new power bit** | `royaltyInfo(id, price)` per ERC-2981, voluntary by the EIP's own words; enforced only by the SCaaS market (§4.7) |
| Per-id metadata freeze | **new power bit** (set and append versions), its freeze one-way | locked at creation means "metadata frozen at definition" |
| Recipes | none in the kind | a recipe contract holds `MINTABLE` and `BURNER` (item-economies §6); inside one collection it is one call |
| Rescue | 17 `RESCUABLE` | as on every kind |

- Free bits: 13, 14 and 33–127 (the JSON lists 0–32 with 13 and 14 "unused").
- Allocating a bit is a data and doc change: the JSON row plus the bit's constant in the new release. No deployed contract
  changes [I].

### 4.5 Size

[F]:
- `NormalToken` is 14,100 B runtime and its body module `NormalTokenA` 25,073 B; `PqVault` is 31,786 B
  (`smartcontracts/evm/size-baseline.json`).
- The ceiling is 131,072 B on the reset chain ([CTR-TOK-24](../contracts/token-wrappers.md#CTR-TOK-24)).
- Every release fits one transaction and no release needs a code limit above 65,536 B
  ([CTR-TOK-30](../contracts/token-wrappers.md#CTR-TOK-30)).
- Sepolia accepts 65,536 B runtime ([networks/evm.md](../networks/evm.md)).

Estimate [E]:
- A multi-token on `UAMetaTxBase` and `GovernanceBase`, with the id ledger, the metadata versions and about ten typed
  entries, is 20–35 KB runtime, split into a stub and one module as the tokens are.
- It fits 64 KiB on every profile. It gets its own size-gate row; `size-baseline.json` is a ratchet, so the first row is
  a new baseline with its reason.

### 4.6 Gas and EIP-8037

[F]:
- A new slot costs about 97,920 state gas
  ([pq-zero-knowledge.md](../contracts/pq-zero-knowledge.md), the EIP-8037 figure).
- A transaction fits only if regular + state gas fits the block limit (AGENTS.md, "EIP-8037").
- Named `mtxTransfer` costs 33,681 execution gas ([token-wrappers.md §9](../contracts/token-wrappers.md#9-gas)).

Inference [I]:
- With a pure ERC-6909 ledger, each transfer of a unique id to a new holder creates one (holder, id) slot (≈ 98 k state
  gas) and zeroes another.
- An ERC-721-style **owner slot for ids with cap 1** rewrites one existing slot instead. The cost depends on whether the
  holder keeps a counter, which ERC-6909 does not need.
- Proposal: **ids with cap 1 store `ownerOf[id]`; other ids store `balance[holder][id]`**. `balanceOf(holder, id)`
  answers both. The saving is to be measured before it is relied on.
- **A batch** holds at most N items (N to measure; 32 is a placeholder). Each item is its own named fields, with no packed
  bytes.

### 4.7 The DEX

[F]:
- `TradeOrder` / `UATradeOrder` carry `receiveToken` (an address) and amounts, **no id** (`src/trade/ITradeToken.sol`).
- The sell token verifies the order ([CTR-DEX-15](../contracts/dex.md#CTR-DEX-15)).
- The DEX is class 2 with its own typed catalogue path ([CTR-TOK-28](../contracts/token-wrappers.md#CTR-TOK-28): "tokens
  and the DEX keep their typed paths").

Inference [I]:
- Today's DEX cannot trade ids.
- Fungible ids would need a new DEX release whose order names `(collection, id)`, with the collection verifying the seller
  as a SCaaS token does. Existing DEX instances stay as they are.
- Unique ids fit an order book badly. A small **id market** contract fits better, as its own generic class:
  - a fixed-price listing (the seller's typed order in the collection's domain);
  - an offer (the buyer's service pull in the pay token);
  - ERC-2981 royalties paid at settlement, which is where royalties can be enforced at all.
- Both are later items; the kind does not wait for them.

### 4.8 Confidential NFTs

[F]:
- PQZ and Zether are separate layers on the token kinds 2–5 and 10–13
  ([CTR-TOK-21](../contracts/token-wrappers.md#CTR-TOK-21)).
- Ciphertexts stay in state (AGENTS.md "Never lose ciphertext").
- Nothing decrypts a ciphertext someone else chose ([ARCH-POS-13](../decisions.md#ARCH-POS-13)).

Inference [I]. Later work, in two different problems:
- **Hidden amounts of a fungible id.** A PQZ layer per (holder, id): one ciphertext per holder per id in state, in the
  shape of today's per-token layer. Per id, state gas grows with the PQZ ciphertext size. It needs a statement that binds
  the id, so a new relation and a new `proofSystemId`, new vectors in every client and a full gate.
- **Hidden ownership of a unique id.** This hides *which* id moves, and the id is in the calldata of every account-based
  move. It needs a note-based design (commitments and nullifiers, an anonymity set), which is neither today's PQZ nor
  today's Zether.
- Zether would be a separate classical design with the same split. Keep the two apart.
- What can be private today without new cryptography: the metadata document. Store a salted commitment on chain and share
  the document by the hybrid KEM, which is outside ARCH-POS-13 by its Change of 2026-11-13.

## 5. Design options and a recommendation

| | (A) ERC-6909-shaped, typed `mtx*`, no callbacks | (B) ERC-1155-compatible with callbacks, plus an adapter | (C) ERC-721 for unique ids, beside `decimals 0` | (D) hybrid: an id class is fungible or unique (ERC-3525 slots) |
|---|---|---|---|---|
| Interop | ERC-6909 readers; no Seaport; NEP-245 alike | wallets and Seaport for contract-wallet holders only (CTR-TOK-01 still bars EOAs) | widest wallet display; Seaport for contract-wallet holders only | ERC-3525 readers are few |
| Safety | no hook, no reentrancy point added | mandatory hook on every transfer and mint to a contract | hook only on `safeTransferFrom`; the kind could offer only `transferFrom` | ERC-3525 has `onERC3525Received` |
| Gas | one slot per (holder, id); with the cap-1 owner slot of §4.6, as 721 for unique ids | as A plus the hook call | one owner slot per id; cheapest for unique ids | value moves between ids add writes |
| Code size [E] | smallest: no hooks, no `{id}` URI logic | larger: hooks, batch hooks, ERC-1155 metadata | small, but a second kind is needed for fungible ids | largest: slots, value allowances |
| Fit with no-approve and typed entries | natural: `approve` / `setOperator` exist for contracts only, every move is a named entry | `setApprovalForAll` is the only approval, so the ABI is mostly refusals for SCaaS holders | `approve` per id for contracts only | value approvals for contracts only; three transfer forms |
| Non-EVM mapping | NEP-245 1:1; ledgers elsewhere; native objects for cap-1 ids | the same, the hooks off | NEP-171, CW-721, SEP-50, Aptos DA, Core: closest to each family's native NFT | no native equivalent |

**Recommendation: (A), with (D)'s one useful idea folded in [I].** The kind:
- is an ERC-6909-shaped multi-token, one instance per collection, a new generic class;
- defines each id with a cap, where cap 1 means unique and is stored as an owner slot;
- gives each id a metadata hash and URI and a soulbound flag;
- has typed `mtx*` entries for every state change, relayable at fee 0;
- has no callbacks;
- allows `approve` / `setOperator` only between contracts, as CTR-TOK-01 does for tokens.

Reasons:
1. One collection serves stackable, numbered and unique ids alike.
2. It adds no reentrancy point and is the smallest of the four.
3. It matches the existing token rules almost word for word.
4. NEAR has the same standard (NEP-245).

(C) wins on wallet display for unique ids, but needs a second kind for fungible ids and still cannot reach Seaport for EOA
or UA holders. That limit comes from CTR-TOK-01, not from the standard.

**ERC-165 [I].** The kind reports:
- `0x01ffc9a7` (ERC-165) and `0x0f632fb3` (ERC-6909). The CTR-TOK-01 restriction is disclosed as for SCaaS ERC-20s,
  whose `approve` is likewise contract-only;
- `0x2a55205a` (ERC-2981) only when the royalty bit is set.

It does **not** report 721, 1155, 4906 or 5192, whose shapes it does not have. The ERC-6909 content-URI and metadata
extensions are implemented as functions. Whether they have their own interface ids was not checked (§9).

**The adapter (later, optional) [I].** An ERC-721 / 1155 wrapper instance holds a SCaaS id and mints a plain ERC-721 /
1155 twin for Seaport. The holder enters it by a service pull and leaves it by burning the twin. The disclosure says that
the twin follows ERC rules (approvals, hooks), not SCaaS rules.

## 6. The relayer and SDK side

Node [F, rules; the rows are I]:
- The node builds every call from named fields and refuses hex (`HEX_DATA_REFUSED`,
  [NODE-JOB-20](../node/job-api.md#NODE-JOB-20)).
- Allow-lists stay equal to the contract's per kind, in both directions: `typed.rs` `TYPED` / `PLAIN` rows and
  `guard.rs` against `mtxSelectors`, `_uaAllowed` and `selector_audit.json` (AGENTS.md "Node").
- The kind brings new rows: `defineId`, `mint`, `transfer`, `batchTransfer`, `burn`, `setMetadata`, `freezeMetadata`,
  `setRoyalty`, and the instance check "class 5, version ≠ 0", as PqChat's class 3 check.
- Every untrusted decode is bounded by length and depth.

Indexer [F]:
- The normalized event is `{event, contract, …, from, to, amount, fee, …}`, with **no id field**
  ([indexer-feeds.md §2](../node/indexer-feeds.md#event-normalization)).
- The kind needs a `token_id` field and its `Transfer(caller, sender, receiver, id, amount)` events normalized. An
  ownership feed answers "who holds id X" and "what does UA Y hold", through finality and the event-set quorum
  ([NODE-IDX-02](../node/indexer-feeds.md#NODE-IDX-02)).
- Job shape changes need a note for operators (AGENTS.md "Traps").

SDK and clients [F, rules]:
- `ua-rs` signs every SCaaS kind; `clientkeys` is the JS reference.
- Vectors are generated once in `smartcontracts/vectors/` and read by every language. Editing one reproducer alone is a
  defect (AGENTS.md "Clients and vectors").
- Reproducing a digest zeroes the unbound `relayer` / `feeRecipient` like `MetaTxLib.canon`.
- New: the typehashes and their pins, the domain (its own name, for example `"SCaaS MultiToken"`), an SDK surface (define,
  mint, transfer, batch, burn, metadata, read ownership), and a wallet display of the id's metadata after its hash is
  checked.
- Fees [F]: `MetaTxBase`'s `_chargeFee` reverts unless the fee mode is `NONE`
  ([CTR-MTX-22](../contracts/metatx.md#CTR-MTX-22)). A token fee for the relayer goes through `RelayFeeRouter`
  ([CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27)). Fee 0 is always relayable.

## 7. The pre-freeze question

**Can come after the freeze, as a new catalogue class, with no change to deployed contracts:**
- the factory: the generic path takes class ≥ 3 with no factory change, [F] CTR-TOK-28;
- the UA registry: a chain-bound signature for any contract and purpose already works
  ([CTR-UA-45](../contracts/accounts.md#CTR-UA-45) path (B)), and the `metatx` purpose covers `UAMetaTransaction`
  ([accounts.md §1.5](../contracts/accounts.md#15-keys-purposes-tags)). No new purpose is needed [I];
- the bits: data plus the new release's constants [I];
- the DEX and an id market: new releases;
- the node, the SDK and the clients: not frozen.

**The one item that needs a decision before the freeze: the governance router [F, then I].**

The facts [F]:
- A role holder that is a derived UA, a PQ key or an `msig` acts through the chain's `GovernanceRouter`, which
  authenticates it and calls the target. The token reads `_govSubject()` ([CTR-TOK-22](../contracts/token-wrappers.md#CTR-TOK-22)).
- The router's ops are a **closed table**. Its mint is `mtxMint` for `mint(to, amount, chainUid_)`; no op takes an id. The
  governance spec says "a closed table takes none later"
  ([2026-11-02-governance.md](../superpowers/specs/2026-11-02-governance.md) §3.2, "Another router").
- The router is set once per chain by `configureChain` and appended to every clone's `ChainEnv` (`OpenFactory.sol`,
  CTR-TOK-29).
- The admin ops (`mtxGrantRole`, `mtxRevokeRole`, `mtxSetGrant`, `mtxDisableFeature`, `mtxTransferAdmin`, …) take a
  `target` and already work on any governed contract.

The options [I]:
- **P1.** Add id-aware role ops to the router before the freeze: `mtxMintId`, `mtxDefineId`, `mtxSetMetadata`,
  `mtxFreezeMetadata`, `mtxSetRoyalty`. The router is code that freezes, so this must land first. It also fixes the kind's
  ABI before the kind is specified.
- **P2.** The kind's role holders act directly when native. A derived or PQ holder acts through an issuer contract (as the
  recipe contract does) that checks the UA itself through `requireAuthorized`. No router change, but parity
  (CTR-UA-27) then rests on that contract.
- **P3.** A second router, "another child of `GovernanceRouterBase` with one typed entry per power"
  (governance spec §3.2). The kind's release would read it from its own env `deps` instead of `ChainEnv.govRouter`. It
  inherits every admin op. This needs no change to deployed code if a generic release may name its router in `deps`;
  that is to be checked against `validateEnv` and the module checks of CTR-TOK-28 / CTR-TOK-30.

**Answer [I].** Nothing *must* land before the EVM freeze **if P3 holds**. The kind is a new catalogue class after the
freeze. Only the bit numbers and the class number should be reserved early, as documentation. If P3 does not hold, P1 is
the only path that keeps parity without a contract in the middle, and P1 is pre-freeze work. The owner's choice is Q1.

## 8. Open questions, TODO items, effort

**Open questions for the owner** (no rulings here):

- **Q1.** The router: P1 (ops before the freeze), P2 (issuer contracts), or P3 (a second router through the release's
  env)?
- **Q2.** The shape: option (A) as recommended, or (C) / (B) for wallet display and Seaport reach?
- **Q3.** Public NFT media on Arweave: does ARCH-POS-19 (ciphertext only) extend to public, unencrypted media? Or does
  public media stay off Arweave (IPFS or a web host, with the on-chain hash either way)?
- **Q4.** Royalties: a power bit with ERC-2981 only (voluntary), or also enforced in a SCaaS id market?
- **Q5.** Ids: may the role define new ids after creation (open collection), or are all ids fixed at creation? Is cap 0
  "uncapped" or refused?
- **Q6.** Soulbound on Solana: NET-SOL-09 refuses `NonTransferable` mints. Should the multi-token kind take its own
  extension policy there?
- **Q7.** Family order: which non-EVM families get the kind, and when (NEAR's NEP-245 is the closest fit)?
- **Q8.** A regulated variant (freeze, force, KYC per id) in the first release, or later?
- **Q9.** Confidential amounts per id (PQZ): wanted at all, and in which order against the other PQZ work?

**Proposed TODO items:**

| # | Item | Depends on | Effort [E] |
|---|---|---|---|
| N1 | Owner rulings on Q1–Q5 | — | — |
| N2 | Check P3: a generic release naming its router in `deps` (code reading, one test) | — | 1–2 days |
| N3 | Spec `docs/contracts/multi-token.md`: class, ids, entries, typehashes, bits, events, metadata versions; decisions entry | N1, N2 | 1 week |
| N4 | Reserve the class number and the bits (JSON rows, governance doc) | N3 | 1 day |
| N5 | (P1 only) router ops and their typehash pins, before the freeze | N1 | 3–5 days |
| N6 | EVM release: contract, module split, tests, mutants, layout and typehash pins, size-gate row, gas table (cap-1 owner slot against a balance slot) | N3 (N5 under P1) | 2–3 weeks |
| N7 | Node: `typed.rs` / `guard.rs` rows, instance check, indexer `token_id`, ownership feed, e2e | N6 | 1–1.5 weeks |
| N8 | Vectors and clients: generator rows, `clientkeys`, `ua-rs` and every `ua-*`, wallet metadata check | N6 | 1.5–2 weeks |
| N9 | SDK operations and docs; integration row "NFT kinds" from PLANNED to SPECIFIED / BUILT; item-economies guide update | N7, N8 | 1 week |
| N10 | Id market contract (listing, offer, royalties at settlement) | N6 | 2 weeks |
| N11 | DEX release with id-aware orders for fungible ids | N6 | 1.5–2 weeks |
| N12 | Per family: NEAR (NEP-245), Solana (Core or Token-2022), Aptos, Sui, Soroban, Algorand (ARC-72 shape), Cosmos, TON | N3, Q7 | 1–3 weeks each |
| N13 | Opt-in ERC-721 / 1155 adapter | N6, Q2 | 1–1.5 weeks |
| N14 | AI audit round for the new release ([ARCH-POS-14](../decisions.md#ARCH-POS-14)) | N6 | per the audit plan |
| N15 | Confidential ids (PQZ): research note first | Q9 | later |

## 9. Sources and what could not be verified

Read on 2026-11-24.

- ERC-721 <https://eips.ethereum.org/EIPS/eip-721>; ERC-1155 <https://eips.ethereum.org/EIPS/eip-1155>; ERC-6909
  <https://eips.ethereum.org/EIPS/eip-6909>; ERC-2981 <https://eips.ethereum.org/EIPS/eip-2981>; ERC-4906
  <https://eips.ethereum.org/EIPS/eip-4906>; ERC-5192 <https://eips.ethereum.org/EIPS/eip-5192>; ERC-5484
  <https://eips.ethereum.org/EIPS/eip-5484>; ERC-4907 <https://eips.ethereum.org/EIPS/eip-4907>; ERC-6551
  <https://eips.ethereum.org/EIPS/eip-6551>; ERC-3525 <https://eips.ethereum.org/EIPS/eip-3525>; ERC-7518
  <https://eips.ethereum.org/EIPS/eip-7518>.
- ERC-404: <https://github.com/Pandora-Labs-Org/erc404>; <https://forklog.com/en/security-concerns-arise-over-erc-404-tokens/>.
- Callback incidents: <https://blocksecteam.medium.com/when-safemint-becomes-unsafe-lessons-from-the-hypebears-security-incident-2965209bda2a>;
  <https://rekt.news/revest-finance-rekt>; <https://slowmist.medium.com/revest-finance-incident-analysis-6fcd9b6be207>.
- Seaport: <https://github.com/ProjectOpenSea/seaport/blob/main/docs/SeaportDocumentation.md>.
- Solana: <https://metaplex.com/docs/core>; <https://metaplex.com/docs/core/plugins>; <https://metaplex.com/docs/token-metadata>;
  <https://metaplex.com/docs/token-metadata/pnfts>; <https://metaplex.com/docs/bubblegum-v2>;
  <https://www.solana-program.com/docs/token-2022/extensions>.
- NEAR: <https://github.com/near/NEPs/blob/master/neps/nep-0171.md>; <https://github.com/near/NEPs/blob/master/neps/nep-0245.md>;
  <https://github.com/near/NEPs/blob/master/README.md>.
- Algorand: <https://dev.algorand.co/concepts/assets/asset-operations/>; <https://dev.algorand.co/arc-standards/arc-0003>;
  <https://dev.algorand.co/arc-standards/arc-0019>; <https://dev.algorand.co/arc-standards/arc-0069>;
  <https://dev.algorand.co/arc-standards/arc-0072>.
- Stellar: <https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0050.md>;
  <https://docs.openzeppelin.com/stellar-contracts/tokens/non-fungible/non-fungible>.
- Aptos: <https://aptos.dev/build/smart-contracts/digital-asset>. Sui: <https://docs.sui.io/standards/kiosk>;
  <https://docs.sui.io/develop/objects/transfers/transfer-policies>.
- TON: <https://github.com/ton-blockchain/TEPs/blob/master/text/0062-nft-standard.md>;
  <https://github.com/ton-blockchain/TEPs/tree/master/text>.
- Cosmos: <https://github.com/public-awesome/cw-nfts/blob/main/packages/cw721/README.md>;
  <https://github.com/CosmWasm/cw-plus/commits/main> (the 2022-10-18 removal of cw1155).

**Not verified:**
- ERC-4906's `0x49064906` was taken from the EIP, not recomputed.
- Who may call ERC-4907 `setUser`.
- Whether the ERC-6909 metadata and content-URI extensions have their own ERC-165 ids.
- A primary write-up of an ERC-404 `transferFrom` exploit; only the README warning and press were found.
- OpenSea's default conduit.
- Aptos on-chain royalty enforcement.
- Sui `public_transfer` of a `store` object outside a Kiosk policy.
- Whether a maintained CW-1155 exists outside cw-plus and cw-nfts.
- Hedera HTS NFT details (HIP-17): not read in this round.
- No multi-token standard was found for Algorand, Soroban or TON. That is "not found", not "does not exist".
- All gas and size figures marked [E] are unmeasured.
