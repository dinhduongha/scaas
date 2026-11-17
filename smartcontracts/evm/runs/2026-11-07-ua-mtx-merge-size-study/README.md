# T66b part 4 size study: the measured map, the forward spikes, the projection

Plan `docs/superpowers/plans/2026-11-04-ua-mtx-merge.md` task T66b part 4; the note is
`docs/research/evm-library-organisation.md`. Research harness, kept (git-tracked); full forge output stays in git-ignored
`.log` files. Every build ran in a scratch detached worktree of `ua-mtx-merge` at `937b454f`, never in the branch's worktree;
nothing in `src/` was committed. Forge 1.8.5, solc 0.8.37, optimizer 200, legacy code generation, Amsterdam, default set
`n2304-kmax4096`. Sizes are deterministic builds; no timing or gas calibration; UNAUDITED.

## Files

| File | What |
|---|---|
| `solc_full.py` | reruns solc on forge's newest build-info with the outputs forge drops (`generatedSources`, `functionDebugData`); checks every runtime object equals forge's |
| `evmmap.py` | runtime attribution: source map to function / modifier / Yul utility, and a static control-flow closure per entry |
| `size_map.py` | the map (`size-map.out`): every contract by domain, functions across the 12 kinds, shared vs unique, entries per domain, the entries of kinds 0 and 13, library top functions, Yul coders |
| `gen_floor.py` | variant A's floor: a kind's whole ABI as forward-only stubs (`floor.out`); `--fallback` writes the comparison form |
| `fwd_spike.py` | the token-side spike: the chosen domains' entry bodies become one forward of their calldata; prints what it forwarded and what stayed whole |
| `run_fwd.sh` | one `forge build src --sizes --json` per move set, through `scripts/capped`; writes `spikes/fwd-<name>.{patch,txt,json}`; resumes (a finished set is skipped) |
| `mod_est.py` | body-module bounds from the complement builds (`modules.out`, `spikes/modules.json`) |
| `cmp.py` | sizes of the spike builds against HEAD (`fwd-sizes.out`) |
| `project.py` | runtime and `asked` of every contract against 60 M: today's form with growth, V6, V7, the modules, the release totals (`projection.out`) |
| `spikes/` | each spike's patch (`git apply` on `937b454f` reproduces its tree), forwarded list, sizes JSON; `sizes-head.json` (forge), `sizes-head-all.json` (solc, libraries included), `floor-sizes.json` |

Move sets (domains as `size_map.entry_domain` names them): V1 `pay`; V2 `trade`; V3 `pay,trade,named-transfer`; V4
`governance`; V5 V3 + V4 + `init,tables,token-meta`; V6 V5 + `wrapped,zether,pqz,regulated,kind-normal`; V7 V6 + `pipeline`
(all but `erc20-core`); V8 every domain. Module builds forward everything except their own domains: MA
`pipeline,named-transfer,pay`; MB `trade`; MC `governance,init,tables,token-meta,kind-normal`; MD `wrapped,zether,pqz,regulated`;
MD1 `pqz`; MD2 `wrapped,regulated`; MD3 `zether`; Mpay `pay`; MAB `pipeline,named-transfer,pay,trade`.

## Rerun

```bash
git worktree add --detach <scratch>/size-study 937b454f
cd <scratch>/size-study && scripts/evm_libs.sh install && scripts/evm_libs.sh check
cd smartcontracts/evm && ../../scripts/capped forge build src --sizes --json > <scratch>/sizes-head.json
R=<repo>/smartcontracts/evm/runs/2026-11-07-ua-mtx-merge-size-study
../../scripts/capped python3 $R/solc_full.py . <scratch>/solc-head.json        # "contracts 187 differ 0"
python3 $R/size_map.py <scratch>/solc-head.json > size-map.out
python3 $R/gen_floor.py out src/zz_floor NormalToken WrappedPqzRegulatedToken  # then forge build src/zz_floor --sizes --json; remove src/zz_floor
$R/run_fwd.sh <scratch>/solc-head.json . <scratch>/fwd V1=pay V7=pay,trade,named-transfer,governance,init,tables,token-meta,wrapped,zether,pqz,regulated,kind-normal,pipeline
python3 $R/mod_est.py <scratch>/solc-head.json <floor-sizes.json> --json modules.json MA=pipeline,named-transfer,pay=<scratch>/fwd/fwd-MA.json V8=none=<scratch>/fwd/fwd-V8.json
python3 $R/project.py <sizes-head-all.json> <fwd-V7.json> <fwd-V6.json> <modules.json>
git worktree remove --force <scratch>/size-study
```

`run_fwd.sh` restores `src/` after each set (`git checkout -- src`). A cold `forge build src` took about 1.7 min and 1 GB
under `scripts/capped`; the solc rerun 79 s and 1.2 GB.

## Limits

The module figures are bounds (the complement build keeps a residue of 4.1–9.9 KB no real module holds). The spike's forward
target is not deployed, so no spike was run under `forge test`; per-call gas is paper arithmetic (the note's §5.5).
