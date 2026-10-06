# SCaaS — SmartContract as a Service

SCaaS, the blockchain stack behind Bamboo DMS: on-chain code, the relayer node, signers and provers.
It does not depend on Odoo; the Odoo addons (`dms_blockchain*`, in the bamboo-dms repo) are one client.

| Path | What |
|---|---|
| `smartcontracts/` | On-chain code by network family: `evm/` (Foundry; Gnosis, Celo, private chain, Hedera), `move/{aptos,sui}`, `soroban/`, `cosmos/`, `ton/`, `solana/`; `scripts/{build,test,deploy,devnet}.sh <family>`. See `smartcontracts/README.md` |
| `scaas-node/` | Rust relayer node: gateway, submit lanes, indexer, admin; mesh (round 4) |
| `zether-prover/` | Rust/WASM Zether prover |
| `app/` | React + Vite console and dApp (planned): contracts, wallets, DEX book, Zether, node admin over OIDC |
| `clientkeys/` | Browser signers (passkey, seed vault); its bundle is vendored into `dms_blockchain_bridge/static/lib/clientkeys` |
| `docs/superpowers/` | Specs (`specs/`, research in `specs/blockchain-research/`), plans, reviews, `HANDOFF-blockchain.md` |
| `blockchain.md` | Original requirements note |
| `scripts/capped` | Run one heavy build in a 4 GB systemd scope, one at a time machine-wide |

Checked out as an independent nested repository at `bamboo-dms/scaas/` (ignored by bamboo-dms).
