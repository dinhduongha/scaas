# pqz-core reproducibility image, PQZL and PQZH (README.md). Build context = the repository root, narrowed by
# Dockerfile.dockerignore to pqz-core/ and the two vector directories the PQZH checks read:
#   docker build -t pqz-core-artifact -f pqz-core/artifact/Dockerfile .
#   docker run --rm --network none -v "$PWD/pqz-out:/out" -e OUT=/out/quick pqz-core-artifact   # quick
#   docker run --rm -v "$PWD/pqz-out:/out" -e OUT=/out/full pqz-core-artifact --full
#   docker run --rm --init -p 127.0.0.1:8000:8000 pqz-core-artifact --serve             # then http://127.0.0.1:8000/
#   docker run --rm -v "$PWD/pqz-out:/out" -e OUT=/out/upstream pqz-core-artifact --upstream
# Built locally by the reader; no image is published. Pinned: the base image by digest, apt packages by version from
# the Ubuntu snapshot archive (APT_SNAPSHOT), node by version + sha256, LaZer (for --upstream) by commit, rustup-init
# by version + sha256 and the Rust toolchain by version (rustup checks each component against the channel manifest's
# sha256), the crates by Cargo.lock (fetched here with --locked; the runs are offline and need no network).
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ARG APT_SNAPSHOT=20261013T000000Z
ARG NODE_VERSION=26.8.1
ARG NODE_SHA256=3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d
ARG LAZER_COMMIT=3330e487228f633eceb322807b13a596b516770f
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
# = pqzh/rust-toolchain.toml (PQZH-Ligero, pqz-stmt): 1.97.1 + wasm32-unknown-unknown; clippy for the float lint
ARG RUST_VERSION=1.97.1

# clang 18 + lld 18 (wasm-ld-18): the measured toolchain (host: Ubuntu 24.04, clang 18.1.3); gcc 13, cmake, GMP /
# MPFR headers and libraries: only for --upstream (upstream LaZer, built from source in the container)
# The snapshot archive is HTTPS-only, so ca-certificates (root certificates only) comes from the live archive first.
# Acquire::Retries: snapshot.ubuntu.com answers 500 / 502 / 503 now and then (runs/art2-docker-build-*-failed-*).
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates \
 && apt-get update -qq -o Acquire::Retries=20 --snapshot "$APT_SNAPSHOT" \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends -o Acquire::Retries=20 --snapshot "$APT_SNAPSHOT" \
      clang-18=1:18.1.3-1ubuntu1 lld-18=1:18.1.3-1ubuntu1 llvm-18=1:18.1.3-1ubuntu1 \
      gcc-13=13.3.0-6ubuntu2~24.04.1 g++-13=13.3.0-6ubuntu2~24.04.1 build-essential make cmake=3.28.3-1build7 \
      libgmp-dev libmpfr-dev python3 git unzip ca-certificates curl xz-utils \
 && ln -s /usr/bin/clang-18 /usr/local/bin/clang \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
 && echo "$NODE_SHA256  /tmp/node.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --exclude='*/include' --exclude='*/share' \
 && rm /tmp/node.tar.xz

# LaZer source for --upstream (source only; built at run time, never part of the image's pqz-core build)
RUN git clone -q https://github.com/lazer-crypto/lazer /opt/lazer && git -C /opt/lazer checkout -q "$LAZER_COMMIT"

# Rust (PQZH): rustup-init by sha256, the pinned toolchain, minimal profile; world-writable so docker run -u works
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl -fsSLo /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init" \
 && echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c - && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y -q --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION" \
      --target wasm32-unknown-unknown --component clippy \
 && rm /tmp/rustup-init && rustc --version && cargo --version && chmod -R a+rwX "$RUSTUP_HOME" "$CARGO_HOME"

COPY . /src
WORKDIR /src/pqz-core
# the crates' dependencies by Cargo.lock, into the image (the runs use --offline); ffi/ and vecgen/ when present
RUN for d in pqzh/ligero pqzh/ligero/wasm stmt ffi ffi/wasm vecgen vecgen/wasm; do \
      [ ! -f "$d/Cargo.lock" ] || (cd "$d" && cargo fetch --locked) || exit 1; done \
 && chmod -R a+rwX "$CARGO_HOME"
# build once at image build time (the same build reproduce.sh repeats); world-writable so docker run -u works
RUN ./build.sh all && chmod -R a+rwX /src
ENV LAZER_SRC=/opt/lazer BIND=0.0.0.0 HOME=/tmp
RUN git config --system --add safe.directory '*'
ENTRYPOINT ["artifact/reproduce.sh"]
