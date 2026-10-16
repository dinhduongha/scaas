# PQZ e2e on chain 7622 (P6g)

Plan: [2026-10-16-p6g-contracts.md](../../../../docs/superpowers/plans/2026-10-16-p6g-contracts.md) (D7, D15).
Deploys the PQZ stack with raw transactions (forge's EVM has no `PQZ` / `MLDSA*` precompile, so `forge script`
cannot simulate it) and runs the life cycle with real proofs: registry gen 1 (`mldsa44`, `mldsa65` on the
precompiles, `pqz-mlwe`, `msig`), `OpenFactory`, `NONE_PQZ` / `UNDERLYING_PQZ`, register, shield, transfer, rollover,
inline credits, burn, refresh, disclosure (all three kinds), v1 and v3 relayed transfers, wrap-shield, commit-reveal
`R_TX0`, unshield-unwrap.

```sh
scripts/capped forge build                                                   # smartcontracts/evm/out
(cd pqz-core/ffi && scripts/capped cargo build --release --offline -j2 --features prove --example pqz_prove)
python3 -I smartcontracts/evm/script/pqz/e2e.py --rpc http://127.0.0.1:8545 --log smartcontracts/evm/runs/<date>-p6g-7622.txt
```

- `e2e.py`: the driver (Python stdlib; `pqz-core/nethermind/chain/eth.py` signs, `smartcontracts/vectors/pqz/pqz_kat.py`
  does KeyGen / Enc / Dec / witnesses). Statements come from the token's views. Test keys `0x…01`–`0x…03` of the 7622
  genesis; test seeds `keccak256("p6g-e2e-7622/<name>")`.
- `mldsa.mjs`: ML-DSA keys and signatures, `@noble/post-quantum` 0.7.1 from `clients/clientkeys/node_modules`.
- `pqz-core/ffi/examples/pqz_prove.rs`: `prove` / `verify` jobs on stdin.
