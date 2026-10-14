#!/bin/sh
# P6e Task 6 round (docs/research/pqzh-ligero.md §14): the crate on pqz-stmt, client / reference presets / float code
# behind `bench`. Run alone under the machine lock: scripts/capped pqz-core/pqzh/ligero/runs/stmt.sh <tag>   (e.g. l14)
# 1. cargo test (default features)  2. the production build: --no-default-features tests, examples / bins (none
# without bench), clippy (-D clippy::float_arithmetic; and the default lints), the dependency tree, and the rlib's
# object code scanned for scalar float instructions (default features and production)  3. native bench, proven, 5 proofs per relation
# (fnv_by_seed: seed 1 vs runs/l14-base-fnv.jsonl, made by the base commit 9f55013; seed 4 vs runs/l13-proven.jsonl)
# 4. wasm32 build (compile check).
set -u
cd "$(dirname "$0")/.."
tag=${1:-l14}
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
{ cargo test --release --offline --no-default-features && cargo build --release --offline --no-default-features --examples --bins; } \
  > runs/$tag-nobench.txt 2>&1 || exit 1
{
  echo "## cargo clippy --no-default-features -- -D clippy::float_arithmetic"
  cargo clippy --release --offline --no-default-features -- -D clippy::float_arithmetic; echo "rc=$?"
  echo "## cargo clippy --all-targets (default features, the crate's own lints)"
  cargo clippy --release --offline --all-targets; echo "rc=$?"
} > runs/$tag-clippy.txt 2>&1
{
  echo "## cargo tree --no-default-features -e normal"; cargo tree --offline --no-default-features -e normal
  echo "## cargo tree (default features, all edges)"; cargo tree --offline
  echo "## wasm/ cargo tree"; (cd wasm && cargo tree --offline)
  scan() { objdump -d target/release/libpqzh_ligero.rlib 2>/dev/null | grep -cE '\b(cvt[a-z0-9]*|add|sub|mul|div|sqrt)s[sd]\b'; }
  echo "## scalar float instructions (objdump -d | grep -cE '(cvt[a-z0-9]*|add|sub|mul|div|sqrt)s[sd]') in the rlib of"
  cargo build --release --offline --lib 2>&1 | tail -1
  echo "default features (bench): $(scan)"
  cargo build --release --offline --no-default-features --lib 2>&1 | tail -1
  echo "--no-default-features (production): $(scan)"
} > runs/$tag-deps.txt 2>&1
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt) || exit 1
runs/bench.sh $tag-proven --rel all --regime proven --r431 1 --np 5 --nv 10 --nadv 4
