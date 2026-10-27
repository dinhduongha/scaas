# smartcontracts

On-chain code of `dms_blockchain`, one directory per network family. Each family keeps its
native layout and tool; `scripts/` is the one place to build, test, deploy and run a devnet.

```
smartcontracts/
├── evm/          Foundry (forge): src/ test/ script/; real EVM chains = FOUNDRY_PROFILE
│                 (private7622, gnosis, celo); Hedera lives here too (src|test|script/hedera)
├── move/aptos/   Aptos Move package `scaas` (+ testfa/, wrapcheck/); scripts/devnet.sh, vector generators
├── move/sui/     Sui Move package `scaas` (+ demo_coin/); scripts/gen_vectors.py
├── soroban/      Stellar Soroban cargo workspace (contracts/*)
├── cosmos/       CosmWasm cargo workspace; build-wasm.sh -> artifacts/
├── ton/          Tact + jest (npm); shim/ = sandbox server for the e2e
├── solana/       cargo workspace (programs/*), LiteSVM tests; scripts/devnet.sh, scripts/deploy.sh
├── near/         NEAR cargo workspace (cargo-near wasm -> target/near/<crate>/), near-workspaces sandbox tests
└── scripts/      build.sh, test.sh, deploy.sh, devnet.sh
```

```bash
S=smartcontracts/scripts; C=scripts/capped        # from the repo root; heavy commands go under capped
$C $S/build.sh <evm|aptos|sui|soroban|cosmos|ton|solana|near|all>
$C $S/test.sh  <family|all>
$S/deploy.sh <family> <network> [args…]           # see the header of deploy.sh for what <network> means
$C $S/devnet.sh <aptos|solana> up|down|status     # other families: the e2e starts its own node
```

Node e2e against real localnets: `cd scaas-node && cargo test --test e2e_<family> -- --ignored --test-threads=1`.
Shared cross-implementation vectors live in `evm/test/vectors/` (EVM, Odoo, node) and per family
(`move/*/tests/vectors.move`, `solana/programs/scaas/tests/vectors.rs`, `ton/vectors/`, `cosmos/tests/tests/vector.txt`).

Details per family: `evm/README.md` (contract model, EVM profiles).
