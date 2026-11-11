> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# ua-mtx-merge: real-wallet display of the merged structs (T20)

Plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` Task T20 (Q5, owner-assisted): how a real wallet shows the 32-byte ids
of the merged `UA*` structs. Owner 2026-11-12: **MetaMask only** (the plan's two browser wallets and one hardware wallet narrowed).
Test account only, nothing submitted to a chain.

The five requests, their sources and how to run the page: [`ua-mtx-merge-wallet-display/README.md`](ua-mtx-merge-wallet-display/README.md).
Each is a generated vector row rebuilt on chain 7622 (SCaaS testnet) through the clientkeys builders; the page recovers the
signer over our expected digest, so `MATCH` means MetaMask signed the digest our renderer computes.

## Results

MetaMask version: _(from "Copy all results")_. Signed on: _(date)_.

| Request | Primary type title shown | Field | Value form | Shown as | Checksum / address book | Signature recovers (`MATCH`) |
|---|---|---|---|---|---|---|
| `UAMetaTransfer` | | `from` | padded native address | | | |
| | | `to` | padded native address | | | |
| `UASetMandate` | | `from` | padded native address | | | |
| | | `delegate` | padded native address | | | |
| `UATradeOrder` | | `from` | padded native address | | | |
| | | `destination` | full 32-byte id (derived UA) | | | |
| `UARelayFee` | | `from` | padded native address | | | |
| | | `payee` | padded native address (the router) | | | |
| `UAPayUnderMandate` | | `from` | padded native address | | | |
| | | `payee` | full 32-byte id | | | |

Warnings shown: _(none recorded yet)_.

Clear-signing descriptor rendering `bytes32` as an address: not checked.
