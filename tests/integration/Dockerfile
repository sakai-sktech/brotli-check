# Integration image: a distribution base plus known-unfixed and known-fixed copies of the
# Brotli decoder. Nothing here crafts or downloads attack data.
ARG BASE=ubuntu:24.04
FROM ${BASE}

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libbrotli1 python3-brotli python3 python3-venv ca-certificates curl xz-utils binutils \
 && rm -rf /var/lib/apt/lists/*

# The distribution's web servers (C11). The ngx_brotli modules are not in Ubuntu 22.04's archive.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx apache2 haproxy \
 && if apt-cache show libnginx-mod-http-brotli-filter >/dev/null 2>&1; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static; \
    fi \
 && rm -rf /var/lib/apt/lists/*

# An in-house package, kept aside and installed only in the run that expects it (run.sh).
RUN mkdir -p /tmp/acme/DEBIAN /tmp/acme/usr/local/sbin \
 && cp /bin/true /tmp/acme/usr/local/sbin/nginx \
 && printf 'Package: acme-internal-nginx\nVersion: 1.2.3-1\nArchitecture: all\nMaintainer: Acme <ops@acme.example>\nDescription: in-house build for the C11 test\n' >/tmp/acme/DEBIAN/control \
 && dpkg-deb -b /tmp/acme /usr/local/share/acme-internal-nginx.deb \
 && rm -rf /tmp/acme

# Official Node.js tarballs, verified against SHASUMS256.txt.
COPY fetch-node.sh /usr/local/sbin/fetch-node
RUN sh /usr/local/sbin/fetch-node 22.23.3 && sh /usr/local/sbin/fetch-node 22.23.4

# PyPI Brotli before and after the fix, each in its own virtual environment. urllib3 next to
# the old one gives the EXPOSURE hint something to find.
RUN python3 -m venv /srv/venv-old && /srv/venv-old/bin/pip install --no-cache-dir --only-binary=:all: 'brotli==1.2.0' urllib3 \
 && python3 -m venv /srv/venv-new && /srv/venv-new/bin/pip install --no-cache-dir --only-binary=:all: 'brotli==1.2.1'

RUN useradd -m tester
COPY brotli-cve-check /usr/local/bin/brotli-cve-check
