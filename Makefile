# brotli-cve-check - development tasks.
#   make lint   shellcheck (zero warnings expected)
#   make test   bats unit tests
#   make dist   single-file build + SHA256SUMS in dist/
#   make integration   container matrix (needs docker; see tests/integration/README.md)

SHELLCHECK ?= shellcheck
BATS ?= bats
LIBS := $(sort $(wildcard lib/*.sh))

.PHONY: all lint test dist integration clean

all: lint test dist

dist/brotli-cve-check: bin/brotli-cve-check $(LIBS) data/advisories.tsv scripts/build-dist.sh
	@mkdir -p dist
	bash scripts/build-dist.sh > $@.tmp
	chmod 755 $@.tmp
	mv $@.tmp $@

dist/SHA256SUMS: dist/brotli-cve-check
	cd dist && sha256sum brotli-cve-check > SHA256SUMS

dist: dist/SHA256SUMS

# Per-file runs cannot see globals defined in other files (SC2034) or associative
# arrays declared elsewhere (SC2004); the single-file build is checked with everything on.
lint: dist/brotli-cve-check
	$(SHELLCHECK) -s bash bin/brotli-cve-check scripts/*.sh tests/integration/*.sh
	$(SHELLCHECK) -s bash -e SC2034,SC2004 $(LIBS)
	$(SHELLCHECK) -s bash dist/brotli-cve-check
	$(SHELLCHECK) -s bash -e SC2030,SC2031,SC2034,SC2154 tests/unit/*.bats tests/unit/test_helper.bash

test:
	$(BATS) tests/unit

integration: dist/brotli-cve-check
	bash tests/integration/run.sh

clean:
	rm -rf dist tests/tmp
