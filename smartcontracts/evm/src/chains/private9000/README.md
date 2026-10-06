# chain 9000 — Nethermind private, Clique

Chain đích **đầu tiên** cho Zether (quyết định #5: gas không phải ràng buộc, nên
chạy private trước).

| | |
|---|---|
| chainId | 9000 (`0x2328`) today; **moving to 7622** (owner 2026-10-07: 9000 is also Evmos Testnet). Migration pending (stream CHAINID: genesis reset, directory and foundry-profile rename, node and Odoo chain records, genesis-hash binding) |
| client | Nethermind 1.39.0 |
| consensus | Clique, period 5s, **một** signer `0xdE36845C…` |
| gasLimit | `0x1000000` = 16.777.216 |
| EVM thực tế | **through Fusaka + BPO2** (since the 2026-08-31 chainspec fix) |
| MinGasPrice | 0 (base fee 0, gas free) |

## Forks (current state)

The chain runs every fork through Fusaka + BPO2: PUSH0, TSTORE/TLOAD, MCOPY, BASEFEE and CLZ are live; all seven
BLS12-381 precompiles (EIP-2537) answer with the right byte counts; EIP-7951 (secp256r1 at `0x100`), EIP-7825
(16,777,216 gas per-transaction cap), EIP-7623 and EIP-7934 are active. Build with `FOUNDRY_PROFILE=private9000`
(`evm_version = "prague"`, `foundry.toml`). The precompiles for both Zether curves (bn254 and BLS12-381) are available.

History: before 2026-08-31 the genesis declared Geth-style fork keys (`londonBlock: 0`, `pragueBlock: 0`, …) that
Nethermind silently ignores, so the chain ran pre-London (no base fee, no PUSH0, no EIP-2537) and this profile had to
be `berlin`. The chainspec was rewritten with Nethermind keys; details in
`/home/dockers/mba-chain-nethermind/README-chainspec.md`. Lesson kept: Nethermind ignores unknown transition keys
without a log line, so every activation is **probed**, never trusted (`TRAPS.md` §"Private chain").

Classical Zether is still gated to dev chains 31337/1337 (RS2-1; owner question Z3). This chain is the only target
of post-quantum Zether (`docs/superpowers/specs/2026-10-06-pq-zether-design.md`, precompiles `0x…0F01`/`0x…0F10`).

## gasLimit có đủ không

Đủ cho spike đo gas per-transaction. Một `transferConfidential` với ring = 2 nằm
dưới 16,7 M. Nếu sau này bật batch lớn hoặc ring lớn thì phải nâng — nâng gasLimit
trên Clique làm được **không cần reset** (signer vote), khác với đổi genesis.
