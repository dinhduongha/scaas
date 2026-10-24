# syntax=docker/dockerfile:1
# P6f D13: scaas/nethermind-pqz:2.2.0-pqz<n> = the pinned Nethermind 2.2.0 image + /nethermind/plugins/{Nethermind.Pqz.dll,
# libpqz_ffi.so, NOTICE-pqz.txt, NOTICE-pqz-core.txt, LICENSE-lazer.txt}. Built locally by build-image.sh (context = the repo root), never pushed. Targets:
#   ffi   - libpqz_ffi.so (release, default features: the set n2304-kmax4096, no prove, no test-hooks)
#   node  - the node image (default)
#   calib - the node image + /opt/pqz-calibrate (Calibrate.dll, fresh proofs, the corpus): Task 6 only, never run as a node
# BuildKit runs outside scripts/capped, so the stages cap themselves: cargo -j 2, dotnet -m:2.
ARG BASE=nethermind/nethermind:2.2.0@sha256:5cc0061e6a317e9249e1e1f537a0a40a2036525c62f1cb250943432f4c000a38
ARG RUST=rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97
ARG SDK=mcr.microsoft.com/dotnet/sdk:10.0.402-resolute@sha256:6924c5c6564690089a67509f5a6ae85d7afa28d7f0f6466ec1b8a5439764ca92

FROM ${BASE} AS base

# the library's sources (review W-G): this build context, or, when build-image.sh runs with FFI_REV=<commit>, that
# commit's tree (--build-context ffisrc=<dir>): the plugin follows the work tree, the library stays the reviewed one
FROM scratch AS ffisrc
COPY . /

FROM ${RUST} AS rust
# clang pinned to exact Debian 12 versions (review W-G, 2026-10-19); a version the archive no longer serves fails the build
RUN apt-get update && apt-get install -y --no-install-recommends clang=1:14.0-55.7~deb12u1 clang-14=1:14.0.6-12 \
      libclang-cpp14=1:14.0.6-12 libllvm14=1:14.0.6-12 && rm -rf /var/lib/apt/lists/*
# the toolchain file names wasm32 too; the image's 1.97.1 is the toolchain, nothing to install
ENV RUSTUP_TOOLCHAIN=1.97.1 CARGO_BUILD_JOBS=2
WORKDIR /src
COPY --from=ffisrc /LICENSE ./
COPY --from=ffisrc /pqz-core/pqzl/check_symbols.sh pqz-core/pqzl/
COPY --from=ffisrc /pqz-core/pqzl/src pqz-core/pqzl/src
COPY --from=ffisrc /pqz-core/pqzl/lazer pqz-core/pqzl/lazer
COPY --from=ffisrc /pqz-core/pqzl/params pqz-core/pqzl/params
# the parameter sets (the crates #[path]-include the chosen set's generated files; pqz-ffi's default n2304-kmax4096)
COPY --from=ffisrc /pqz-core/params/sets pqz-core/params/sets
# pqz-ffi's default PQZL backend (CTR-PQZ-09, 2026-10-18): the Rust crate pqzl; the C sources above stay for pqzl-c
COPY --from=ffisrc /pqz-core/pqzl/rust pqz-core/pqzl/rust
COPY --from=ffisrc /pqz-core/stmt pqz-core/stmt
COPY --from=ffisrc /pqz-core/pqzh/ligero pqz-core/pqzh/ligero
COPY --from=ffisrc /pqz-core/ffi pqz-core/ffi
# the self-test's compiled-in REGISTER proofs (ffi/build.rs): the default set's vectors
COPY --from=ffisrc /smartcontracts/vectors/pqz/n2304-kmax4096/proof_pqzl.json /smartcontracts/vectors/pqz/n2304-kmax4096/proof_pqzh.json smartcontracts/vectors/pqz/n2304-kmax4096/

FROM rust AS ffi
RUN cd pqz-core/ffi && cargo build --release --locked -j 2 && mkdir /out && cp target/release/libpqz_ffi.so /out/ \
 && sha256sum /out/libpqz_ffi.so

FROM scratch AS ffi-export
COPY --from=ffi /out/ /

FROM rust AS fresh
COPY pqz-core/nethermind/fresh-proofs pqz-core/nethermind/fresh-proofs
ARG FRESH=20
RUN cd pqz-core/nethermind/fresh-proofs && cargo build --release --locked -j 2 \
 && mkdir /out && ./target/release/pqz-fresh-proofs ${FRESH} > /out/fresh.jsonl

FROM ${SDK} AS plugin
WORKDIR /src/pqz-core/nethermind
COPY --from=base /nethermind ref
COPY pqz-core/nethermind/Directory.Build.props pqz-core/nethermind/Directory.Build.targets ./
COPY pqz-core/nethermind/Nethermind.Pqz Nethermind.Pqz
RUN dotnet build Nethermind.Pqz/Nethermind.Pqz.csproj -c Release -m:2 -o /out \
 && ls -la /out

FROM plugin AS calibtool
COPY pqz-core/nethermind/Calibrate Calibrate
RUN dotnet build Calibrate/Calibrate.csproj -c Release -m:2 -o /opt/pqz-calibrate

FROM ${BASE} AS node
ARG COMMIT=unknown
ARG FFI_SHA256
COPY --from=plugin /out/Nethermind.Pqz.dll /nethermind/plugins/
COPY --from=ffi /out/libpqz_ffi.so /nethermind/plugins/
COPY pqz-core/nethermind/NOTICE-pqz.txt /nethermind/plugins/
COPY pqz-core/NOTICE /nethermind/plugins/NOTICE-pqz-core.txt
COPY pqz-core/pqzl/lazer/LICENSE /nethermind/plugins/LICENSE-lazer.txt
RUN echo "${FFI_SHA256}  /nethermind/plugins/libpqz_ffi.so" | sha256sum -c -
LABEL scaas.pqz.commit="${COMMIT}" \
      scaas.pqz.ffi.sha256="${FFI_SHA256}" \
      scaas.pqz.selftest="23d7a1db653449c52bfed0ebbfe664867bf2400261f8999406799dc1040c97c0" \
      org.opencontainers.image.title="scaas/nethermind-pqz" \
      org.opencontainers.image.description="Nethermind 2.2.0 + the SCaaS PQZ / ML-DSA precompile plugin (local only, never pushed)"

FROM node AS calib
COPY --from=calibtool /opt/pqz-calibrate /opt/pqz-calibrate
COPY --from=fresh /out/fresh.jsonl /opt/pqz-calibrate/data/
COPY pqz-core/nethermind/bin/corpus.jsonl /opt/pqz-calibrate/data/
COPY smartcontracts/vectors/ua/pq_external.json /opt/pqz-calibrate/data/ua/
RUN cp /nethermind/plugins/libpqz_ffi.so /opt/pqz-calibrate/
ENTRYPOINT ["dotnet", "/opt/pqz-calibrate/Calibrate.dll"]

FROM node
