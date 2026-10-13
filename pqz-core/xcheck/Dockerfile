# Upstream LaZer build image for the cross-check (recorded 2026-10-13; the image was made with `docker commit`
# from this one command on ubuntu:24.04). Build: docker build -t p6d-lazer-build:ubuntu24.04 pqz-core/xcheck
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential cmake libgmp-dev \
    libmpfr-dev git unzip python3 >/dev/null && gcc --version | head -1 && cmake --version | head -1 && \
    dpkg -l libgmp-dev libmpfr-dev | tail -2
