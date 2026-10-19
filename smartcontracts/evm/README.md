# smartcontracts/evm

The SCaaS contracts of the EVM family (Foundry; the other families are under `smartcontracts/<family>/`). Normative
rules: `docs/contracts/` (start at `docs/contracts/README.md`); reasons and old ids: `docs/decisions.md`
(`python3 scripts/docs_check.py resolve <id>`). **Unaudited — not for production funds.**

## What is here

| Area | Files (`src/`) | Status |
|---|---|---|
| Token kinds `NONE` / `UNDERLYING` | `metatx/NoUnderlyingToken.sol`, `metatx/UnderlyingToken.sol` on `MetaTokenBase` (`MetaTxBase`, `ERC20MetaTx`, `UnderlyingLib`, `AdminLib`) | built; EIP-1167 clones; meta-tx (address path and UA path), UA ledger, wrapper legs ([token-wrappers.md](../../docs/contracts/token-wrappers.md), [metatx.md](../../docs/contracts/metatx.md)) |
| Zether kinds `NONE_ZETHER` / `UNDERLYING_ZETHER` | `zether/` (`ZetherLayer`, `ZetherLib`, `ZetherStatements`, `ZetherVerifierBn254`, `ZetherVerifierBls12381`, `ZetherDisclosure`) | built; dev chains 31337 / 1337 only (`ZetherSafety`) ([zether.md](../../docs/contracts/zether.md)) |
| PQZ kinds `NONE_PQZ` / `UNDERLYING_PQZ` | `pqz/` (`PqzLayer`, `PqzLib`, `PqzCt`, `UAPqzVerifier`, `PqzSafety`) | built; chains 31337 / 1337 / 7622 (`PqzSafety`); op 7 multi-recipient transfers (`pqzTransfer*`) and op 1 single (`pqzTransferSingle*`) over the `PQZ` precompile ([pq-zero-knowledge.md](../../docs/contracts/pq-zero-knowledge.md)) |
| Factory | `factory/OpenFactory.sol` (`IOpenFactory`, `IFactoryToken`) | built; open creation, versioned catalogue, the Zether / PQZ gates |
| Universal Accounts | `ua/UARegistry.sol`, `ua/UAKinds.sol`, `ua/verifiers/`, the PQ verifiers (`MlDsa`, `FnDsa`, `SlhDsa`) | built; admin-free registry, kinds `0x0100`–`0x0108`, groups, `msig`, Zether / PQZ kinds, per-kind list ([accounts.md](../../docs/contracts/accounts.md)) |
| DEX | `dex/SCaaSDex.sol` (`DexPuller`), `trade/` | built; clone per DEX, `mtxSettle` one taker / many makers ([dex.md](../../docs/contracts/dex.md)) |
| Accounts and wallets | `account/SmartKeyAccount.sol` (+ factory), `wallet/MandateWallet.sol` | built |
| Hedera | `hedera/` | built; HIP-632 / long-zero helpers for the Hedera profile ([networks/hedera.md](../../docs/networks/hedera.md)) |
| Shared | `common/` (`MetaTxLib`, `FeePolicy`, `SigCheck`, `SaltedEIP712`, `SSTORE2`, curves and hashes) | built |
| Chain notes | `chains/{private7622,gnosis,celo}/` | notes |

`legacy/` keeps superseded lines for reference (`legacy/README.md`): not compiled, not tested, never deployed.

## Model: an open factory, no upgrades

Anyone can create a token, and anyone can wrap an asset; two wrappers of the same asset by two creators are both real,
and `IERC20(asset).balanceOf(wrapper)` shows what each holds. `getWrapper` keys on `(creator, underlying)`.

- **No upgrade path.** Tokens are EIP-1167 clones; no proxy, no admin over code. Versions live in the factory's
  append-only catalogue; a token stays on the version it was created with. A bug in a version stays in every token of
  it; the way out is a new token on a new version and a voluntary move.
- **Provenance instead of a gate.** `factory()`, `creator()`, `underlying()`, `verifier()` are immutable and public;
  `isToken()` checks the reverse.
- **Every curve the chain supports.** Verifiers are passed in; points are `bytes` (bn254 G1 64 B, BLS12-381 G1 128 B).
  On Gnosis, MSM at k = 277: bn254 1.70 M gas, BLS12-381 1.74 M (≈ 2 % more), k = 1: 6,000 vs 12,357; bn254 ≈ 100-bit
  and on every EVM chain, BLS12-381 ≈ 126-bit and only where EIP-2537 is live.

## Build and test

```bash
forge build
forge test                                # the whole suite
forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'   # gas bounds, cold
FOUNDRY_PROFILE=private7622 forge build
```

On a shared machine run heavy jobs under `scripts/capped` (repo root). `lib/` is not committed; the libraries are
pinned by commit and source checksum in `scripts/evm_libs.sh` (CTR-GEN-01): OpenZeppelin `fda6b85f` (master between
v5.2.0 and v5.3.0), forge-std `88c8a288`. `../../scripts/evm_libs.sh install` fetches them (CI does), `check` compares
whatever `lib/` holds (a checkout, a symlink) with the pins; run it before a build that will be deployed.

**Size gate** (CTR-TOK-24), as CI runs it — `src/` only, never with the test helpers:

```bash
forge build src --sizes --json > /tmp/sizes.json
python3 ../../scripts/size_gate.py /tmp/sizes.json size-baseline.json
```

Limits: token implementations 20,480 B, other contracts 24,576 B (EIP-170), init code 49,152 B (EIP-3860).
`size-baseline.json` lists the contracts allowed over their limit at a recorded size that may only shrink (owner
2026-10-11: size work waits for Glamsterdam; test chains such as 7622 allow 65,536 / 131,072 B). Logic in `public` /
`external` library functions (`PqzLib`, `ZetherLib`, `UnderlyingLib`, `AdminLib`, …) is a separately deployed contract
reached by DELEGATECALL and does not count towards a token's size; `internal` library functions are copied into it.

## EVM profiles

| Profile | EVM | Why |
|---|---|---|
| `default`, `private7622` | osaka | chain 7622: private Nethermind (Clique, one signer), Fusaka + BPO2, EIP-2537 live, the `PQZ` and ML-DSA precompiles (`src/chains/private7622/`) |
| `gnosis`, `celo` | osaka | Pectra, then Fusaka; EIP-2537 measured live |
| `bsc`, `polygon`, `base` | osaka | drafts ([networks/evm.md](../../docs/networks/evm.md) §1) |
| `zether` | osaka | the Zether suite (`FOUNDRY_PROFILE=zether forge test --match-path 'test/zether/*'`) |

## Deploying

`script/Deploy.s.sol` (with `DeployBase.sol`) deploys the factory, the token catalogue, the UA registry generation 1
with the per-chain kinds (`UAPrecompileProbe`) and writes `deployments/<chainid>.json`; `script/ZetherE2E.s.sol` for
the dev chains. Chain 7622's PQZ stack is deployed and exercised end to end by `script/pqz/e2e.py` (logs in `runs/`,
e.g. the live addresses of the latest run at the end of each log).

## Design notes

- **EIP-712, not `personal_sign`**: wallets show the struct. Signatures are low-s, `ecrecover` is never used raw.
- **The `mode` bitmask** (`common/MetaTxLib.sol`, `supportedModes() = 0xF3`) is signed; an unbound `relayer` /
  `feeRecipient` is hashed as `address(0)`, so a signature never validates under another mode
  ([metatx.md](../../docs/contracts/metatx.md#digest)).
- **No `isEOA`.** `extcodesize == 0` is true for undeployed wallets, contracts in their constructor and (EIP-7702)
  delegated EOAs; contracts accept both kinds of signer through ERC-1271 (`SigCheck`). Allowances are only between
  contracts (`ERC20MetaTx`: `approve` refuses a non-contract spender, `transferFrom` a non-contract caller).
- **Fees in ppm** (1e6), hard cap 1 % = 10,000 ppm.
