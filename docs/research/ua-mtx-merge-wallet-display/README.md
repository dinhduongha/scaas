> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Wallet display harness (ua-mtx-merge T20)

A local page that asks MetaMask for five `eth_signTypedData_v4` signatures over the merged structs, for the display test of
plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` Task T20. Results go to
[`../ua-mtx-merge-wallet-display.md`](../ua-mtx-merge-wallet-display.md). Owner 2026-11-12: MetaMask only (the plan's two
browser wallets and one hardware wallet narrowed to one).

| File | What it is |
|---|---|
| `derive.mjs` | Writes `rows.json` from the generated vectors through the clientkeys builders; refuses unless each source row rebuilds to its vector digest |
| `rows.json` | The five requests: typed data, expected digest, source row, overrides |
| `index.html`, `app.js` | The page: one button per request, the JSON sent, the signature, the signer recovered over the expected digest |
| `check.mjs` | Headless check with a throwaway key made at run time (no wallet) |

## The five requests

All on chain id 7622 (SCaaS testnet): the vectors are on context A (chain 31337) and MetaMask signs typed data only for its
active chain, so each row is the same vector row rebuilt on context B of `ua/structures.json` (chain 7622). `from` is the
vector key's id, not your account: the check is that your signature recovers to your account over our digest.

| Request | Source | Overrides beyond the chain | `bytes32` fields to watch |
|---|---|---|---|
| `UAMetaTransfer` | `ua/metatx3.json` `transfer[native]` | relayer unbound (mode bit 0 cleared, 0) | `from`, `to` |
| `UASetMandate` (the `UA<Op>` row) | `typed/typed_ops.json` `ops.UASetMandate`, `SCaaS MandateWallet` | relayer unbound | `from`, `delegate` |
| `UATradeOrder` | `ua/uatrade_kat.json` `rows[native]` | relayer 0 (open); `destination` = `rows[webauthn-p256].from`, a derived UA | `from`, `destination` |
| `UARelayFee` | `typed/typed_ops.json` `ops.UARelayFee`, `SCaaS MetaToken` | none: its `relayer` is the router by construction (CTR-MTX-27), it has no unbound form | `from`, `payee` |
| `UAPayUnderMandate` | `typed/typed_ops.json` `ops.UAPayUnderMandate`, `SCaaS MandateWallet` | relayer unbound | `from`, `payee` |

## Run

```sh
cd docs/research/ua-mtx-merge-wallet-display
python3 -m http.server --bind 127.0.0.1 8765
```

Open `http://127.0.0.1:8765/` in the browser with MetaMask, on a **test account only**. Then:

1. **Connect wallet**, then **Switch to SCaaS testnet** (chain 7622). If MetaMask does not know the network it offers to add it with
   the RPC in the field (the testnet's `http://127.0.0.1:8545` by default); approve in MetaMask. Signing reads nothing from the chain.
2. Press each **Sign** button. Before approving, record what MetaMask shows (below). Approve; the page shows `MATCH` when the
   signature recovers to your account over the expected digest.
3. **Copy all results** and paste the text (signatures, `MATCH` per row, MetaMask version) with your notes.

Screenshots stay local: not in the repo.

## What to record (T20 Step 3), per request

- The **primary type title** MetaMask shows (`UAMetaTransfer`, …) and the domain lines (name, chain, verifying contract).
- For each `bytes32` field (`from`, `to`, `destination`, `payee`, `delegate`): shown as full hex, shortened, or as an address;
  whether a checksum (mixed case) or an address-book name / identicon applies. Two forms occur: a native address zero-padded
  (top 96 bits 0: every `from`, `to`, `delegate`, `UARelayFee.payee`) and a full 32-byte id (`UATradeOrder.destination`,
  `UAPayUnderMandate.payee`).
- Any warning MetaMask shows (security alert, unknown contract).
- Whether a clear-signing descriptor can render `bytes32` as an address: not checked unless you check it.

## Checks without a wallet

```sh
node docs/research/ua-mtx-merge-wallet-display/derive.mjs        # needs clients/clientkeys/node_modules
curl -sSfLo <tmp>/ethers.umd.min.js https://cdnjs.cloudflare.com/ajax/libs/ethers/6.13.4/ethers.umd.min.js
node docs/research/ua-mtx-merge-wallet-display/check.mjs <tmp>/ethers.umd.min.js
```

`derive.mjs` leaves `rows.json` unchanged (`git diff --exit-code`). `check.mjs`: ethers' digest of the exact JSON sent equals
each row's digest, a throwaway key's `signTypedData` recovers over it, and a one-bit change of a field does not.
