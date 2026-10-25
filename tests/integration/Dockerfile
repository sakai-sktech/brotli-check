# Integration image: a distribution base plus known-unfixed and known-fixed copies of the
# Brotli decoder. Nothing here crafts or downloads attack data.
ARG BASE=ubuntu:24.04
FROM ${BASE}

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libbrotli1 python3-brotli python3 python3-venv ca-certificates curl xz-utils binutils \
 && rm -rf /var/lib/apt/lists/*

# Official Node.js tarballs, verified against SHASUMS256.txt.
COPY fetch-node.sh /usr/local/sbin/fetch-node
RUN fetch-node 22.23.3 && fetch-node 22.23.4

# PyPI Brotli before and after the fix, each in its own virtual environment.
RUN python3 -m venv /srv/venv-old && /srv/venv-old/bin/pip install --no-cache-dir --only-binary=:all: 'brotli==1.2.0' \
 && python3 -m venv /srv/venv-new && /srv/venv-new/bin/pip install --no-cache-dir --only-binary=:all: 'brotli==1.2.1'

RUN useradd -m tester
COPY brotli-cve-check /usr/local/bin/brotli-cve-check
