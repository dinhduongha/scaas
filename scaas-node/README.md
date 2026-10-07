# scaas-node

The SCaaS relayer and indexer: **one Rust binary** whose modules are switched on in config — `submit` (lanes:
simulate, sign the outer transaction, broadcast, replace stuck transactions, fill nonce gaps), `indexer` (finality-gated
event reading with an RPC quorum), `gateway` (open HTTP door for signed intents, `/v1/metatx`, DEX `/v1/dex/*`) and
`mesh`. The node never holds subject funds or subject keys; lane keys hold gas only and never a contract role.

The normative description is [`docs/node/`](../docs/node/README.md) — start with its README (roles, listeners,
invariants, the built-vs-target table), then [store](../docs/node/store.md), [job API](../docs/node/job-api.md),
[submit lanes](../docs/node/submit-lanes.md), [indexer and feeds](../docs/node/indexer-feeds.md),
[gateway](../docs/node/gateway.md), [operations](../docs/node/ops.md) and [runbooks](../docs/node/runbooks.md). Every
ruling's rationale and the old-id aliases used in code comments (`R91`, `_USER-DECISIONS` §23, …) are in
[`docs/decisions.md`](../docs/decisions.md): `python3 ../scripts/docs_check.py resolve <old id>`.

**Transitional (BUILT).** Today's binary still takes jobs over the legacy *pull* path (it leases rows from a client's
outbox over JSON-RPC with two separate service credentials, relay and indexer) and keeps its journal there; the target
is the node-owned store and job API (push), switched per chain and then removed in one step
([job-api.md#legacy-pull](../docs/node/job-api.md#legacy-pull), [runbooks.md#cutover](../docs/node/runbooks.md#cutover)).

## Build and test

```bash
cargo build --release          # rustc 1.90; alloy pinned to 1.6 through the MSRV-aware resolver (.cargo/config.toml)
cargo test                     # unit
cargo test --test e2e -- --ignored --nocapture   # needs anvil + forge on PATH
```

Heavy builds go through `../scripts/capped` (one at a time per machine).

## Configuration

See [`node.example.toml`](node.example.toml) and [store.md](../docs/node/store.md#NODE-STO-03). The file holds no
secrets, only the names of environment variables, files or keystores that do; RPC endpoints live only there and must
number at least `finality.quorum`. Lane keys: [submit-lanes.md#lane-keys](../docs/node/submit-lanes.md#lane-keys).
