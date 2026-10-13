# pqz-core reproducibility image (README.md). Build context = pqz-core/:
#   docker build -t pqz-core-artifact -f pqz-core/artifact/Dockerfile pqz-core
#   docker run --rm -v "$PWD/pqz-out:/out" -e OUT=/out/quick pqz-core-artifact              # quick
#   docker run --rm -v "$PWD/pqz-out:/out" -e OUT=/out/full pqz-core-artifact --full
#   docker run --rm -p 127.0.0.1:8000:8000 pqz-core-artifact --serve                    # then http://127.0.0.1:8000/
#   docker run --rm -v "$PWD/pqz-out:/out" -e OUT=/out/upstream pqz-core-artifact --upstream
# Built locally by the reader; no image is published. Pinned: the base image by digest, apt packages by version from
# the Ubuntu snapshot archive (APT_SNAPSHOT), node by version + sha256, LaZer (for --upstream) by commit.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ARG APT_SNAPSHOT=20261014T000000Z
ARG NODE_VERSION=26.8.1
ARG NODE_SHA256=3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d
ARG LAZER_COMMIT=3330e487228f633eceb322807b13a596b516770f

# clang 18 + lld 18 (wasm-ld-18): the measured toolchain (host: Ubuntu 24.04, clang 18.1.3); gcc 13, cmake, GMP /
# MPFR headers and libraries: only for --upstream (upstream LaZer, built from source in the container)
RUN apt-get update -qq --snapshot "$APT_SNAPSHOT" \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends --snapshot "$APT_SNAPSHOT" \
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

COPY . /src/pqz-core
WORKDIR /src/pqz-core
# build once at image build time (the same build reproduce.sh repeats); world-writable so docker run -u works
RUN ./build.sh all && chmod -R a+rwX /src
ENV LAZER_SRC=/opt/lazer BIND=0.0.0.0 HOME=/tmp
RUN git config --system --add safe.directory '*'
ENTRYPOINT ["artifact/reproduce.sh"]
