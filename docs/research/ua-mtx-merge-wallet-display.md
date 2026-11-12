> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# ua-mtx-merge: real-wallet display of the merged structs (T20)

Plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` Task T20 (Q5, owner-assisted): how a real wallet shows the 32-byte ids
of the merged `UA*` structs. Owner 2026-11-12: **MetaMask only** (the plan's two browser wallets and one hardware wallet narrowed).
Test account only, nothing submitted to a chain.

The five requests, their sources and how to run the page: [`ua-mtx-merge-wallet-display/README.md`](ua-mtx-merge-wallet-display/README.md).
Each is a generated vector row rebuilt on chain 7622 (SCaaS testnet) through the clientkeys builders; the page recovers the
signer over our expected digest, so `MATCH` means MetaMask signed the digest our renderer computes.

## Results

MetaMask version: 13.55.0 (Firefox 158, Linux). Signed on: 2026-11-12, chain 7622. Raw results: [`results-metamask.json`](ua-mtx-merge-wallet-display/results-metamask.json). **All five `MATCH`**: each signature recovers the test account over the digest in `rows.json`, so MetaMask signs the bytes our clientkeys builders compute.

Display recorded from the owner's screenshot of the `UAMetaTransfer` request; the other four were signed (all `MATCH`) but their popups were not recorded: the rows below for them assume MetaMask's per-type rule seen here (not observed one by one). MetaMask renders by the field's EIP-712 type, not by its name:

- `bytes32` (`from`, `to`, `destination`, `payee` of `UAPayUnderMandate`, `delegate`, `entryRef`): the full 64-hex-digit value on its own line, zero-padded native addresses included (`0x000000000000000000000000fc7e…89f9`). No shortening, no checksum, no address-book name, no "unknown address" icon.
- `address` (`relayer`, `feeRecipient`, the domain's `verifyingContract` as "Interacting with"): shortened `0x00000…00FEE` with the address icon, so the address book and the contract lookup apply only to these.
- `uint256` `batch` as a 77-digit decimal; `mode` as a decimal (`34`), its bits not explained.
- The header shows the network name, the requesting origin and the verifying contract; the domain `name` / `version` are not shown in the main view.

| Request | Primary type title shown | Field | Value form | Shown as | Checksum / address book | Signature recovers (`MATCH`) |
|---|---|---|---|---|---|---|
| `UAMetaTransfer` | shown ("Primary type: UAMetaTransfer") | `from` | padded native address | full 64-hex bytes32, own line | none | yes |
|  |  | `to` | padded native address | full 64-hex bytes32, own line | none |  |
| `UASetMandate` | shown ("Primary type: UASetMandate") | `from` | padded native address | full 64-hex bytes32, own line | none | yes |
|  |  | `delegate` | padded native address | full 64-hex bytes32, own line | none |  |
| `UATradeOrder` | shown ("Primary type: UATradeOrder") | `from` | padded native address | full 64-hex bytes32, own line | none | yes |
|  |  | `destination` | full 32-byte id (derived UA) | full 64-hex bytes32, own line | none |  |
| `UARelayFee` | shown ("Primary type: UARelayFee") | `from` | padded native address | full 64-hex bytes32, own line | none | yes |
|  |  | `payee` | padded native address (the router) | full 64-hex bytes32, own line | none |  |
| `UAPayUnderMandate` | shown ("Primary type: UAPayUnderMandate") | `from` | padded native address | full 64-hex bytes32, own line | none | yes |
|  |  | `payee` | full 32-byte id | full 64-hex bytes32, own line | none |  |

Warnings shown: only "HTTP" on the request origin (`http://127.0.0.1:8765`, no TLS); none about the message or its fields.

Clear-signing descriptor rendering `bytes32` as an address: not checked.

**Reading.** The 32-byte ids are legible as hex: a padded native address can be read off the last 40 digits, but the wallet gives no checksum, no address book and no name for them, unlike the `address` fields beside them. A derived UA (`destination`) is opaque. This is the known cost of `bytes32` ids; it does not change the signed bytes. Input for the ERC-1271 wrap choice (Safe-style one-level wrap would show only `hash: 0x…`; ERC-7739 nested typed data keeps these fields visible).
