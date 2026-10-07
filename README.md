# SCaaS — SmartContract as a Service

SCaaS, a SmartContract-as-a-Service stack: on-chain code, the relayer node, signers and provers.
It does not depend on Odoo; the Odoo addons (`dms_blockchain*`, in the bamboo-dms repo) are one client.

| Path | What |
|---|---|
| `smartcontracts/` | On-chain code by network family: `evm/` (Foundry; Gnosis, Celo, private chain, Hedera), `move/{aptos,sui}`, `soroban/`, `cosmos/`, `ton/`, `solana/`; `scripts/{build,test,deploy,devnet}.sh <family>`. See `smartcontracts/README.md` |
| `scaas-node/` | Rust relayer node: gateway, submit lanes, indexer, admin; mesh (round 4) |
| `zether-prover/` | Rust/WASM Zether prover |
| `app/` | React + Vite console and dApp (planned): contracts, wallets, DEX book, Zether, node admin over OIDC |
| `clientkeys/` | Browser signers (passkey, seed vault); its bundle is vendored into `dms_blockchain_bridge/static/lib/clientkeys` |
| `docs/` | Product docs — start at [`docs/README.md`](docs/README.md) (reading order, map, precedence): [`SCaaS-v2.md`](docs/SCaaS-v2.md) → [`architecture.md`](docs/architecture.md) → component docs `node/`, `contracts/`, `networks/`, `clients/`, `integration.md`; rulings and old-id aliases in [`decisions.md`](docs/decisions.md); frozen specs, plans and the old `SCaaS.md`/`integration.md` in `docs/history/`; background in `docs/research/`; new drafts in `docs/superpowers/`; reviews in `docs/reviews/` (git-ignored). Check: `python3 scripts/docs_check.py check` |
| `docs/history/blockchain.md` | Original requirements note (source input for the specs); requirement trace in [`docs/history/blockchain-trace.md`](docs/history/blockchain-trace.md) |
| `scripts/capped` | Run one heavy build in a 4 GB systemd scope, one at a time machine-wide |

Checked out as an independent nested repository at `bamboo-dms/scaas/` (ignored by bamboo-dms).
