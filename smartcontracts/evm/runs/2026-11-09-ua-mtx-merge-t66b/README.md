# T66b Steps 1 and 2: deploy gas, forward cost and the size map at the tip after 3h

Plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` task T66b; spec
`docs/superpowers/specs/2026-11-09-t66b-library-organisation.md`. Measurement only: nothing in `src/` changed. Forge 1.8.5,
solc 0.8.37, optimizer 200, legacy codegen, Amsterdam, default set `n2304-kmax4096`; forge gas is deterministic (no timing or
gas calibration). Full forge output stays in git-ignored `.log` files. UNAUDITED.

| File | What |
|---|---|
| `DeployGas.t.sol` | Step 1: every deployed contract's CREATE2 as its own transaction (T10's formula), and the factory frame of a release |
| `ForwardGas.t.sol` | Step 2: what a forward stub adds per call (calldata copy, memory, DELEGATECALL, return copy), cold and warm module, by calldata size |
| `size-map.out` | the library study's `size_map.py` at the tip: every contract by domain, functions across the twelve kinds, entries per domain, kinds 0 and 13 entry by entry, library top functions, coders |
| `token-forms.txt` | each kind today, V6, V7 (the forward form), V8, and the floor (the whole ABI as stubs) |
| `modules.out` | body-module bounds per kind (`mod_est.py`: the complement builds less the forwarded stubs; the V8 column is the residue) |
| `registry-dex-factory-entries.out` | `UARegistry`, `UARegistryLib`, `SCaaSDex`, `OpenFactory`: entries by exclusive / reachable bytes and top labels |
| `hedera-codesize.txt` | the public Hedera testnet's runtime code limit, probed by simulation |

## Rerun

```bash
cd smartcontracts/evm
FOUNDRY_TEST=runs/2026-11-09-ua-mtx-merge-t66b FOUNDRY_OUT=out/t66b-gas FOUNDRY_CACHE_PATH=cache/t66b-gas \
  ../../scripts/capped forge test -vv          # T66B, FRAME and FWD lines
```

The size map, the spikes and the module bounds use the tools of `runs/2026-11-07-ua-mtx-merge-size-study/` (its README) in a
scratch detached worktree of the tip with real `lib/` directories: `forge build src --force --build-info`, `solc_full.py`
("contracts 189 differ 0"), `size_map.py`, `gen_floor.py` for the twelve kinds, `run_fwd.sh` with V6, V7, V8 and the module
sets MA, MB, MC, MD, MD1, MD2, MD3, MAB, Mpay (the complement of each module's domains forwarded), then `mod_est.py`.
