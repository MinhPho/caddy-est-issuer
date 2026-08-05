GO ?= go
CADDY_VERSION ?= v2.11.4
MODULE := github.com/MinhPho/caddy-est-issuer

# go.mod's `go` line is a language floor, not a build instruction. Analysing or
# building against the floor reports every stdlib CVE fixed in a later patch
# release, so the `toolchain` line decides what actually compiles here.
GO_TOOLCHAIN := $(shell awk '/^toolchain /{print $$2; exit}' go.mod)

# Pinned so two builds of the same commit produce the same binary. CADDY_VERSION
# must match the github.com/caddyserver/caddy/v2 requirement in go.mod.
XCADDY_PKG := github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6
GOVULNCHECK_PKG := golang.org/x/vuln/cmd/govulncheck@v1.1.4

# The reference EST server used as the lab CA. See lab/README.md for why the lab
# is not a production CA.
EST_SERVER_PKG := github.com/globalsign/est/cmd/estserver@v1.0.7

RELEASE_OS ?= linux
RELEASE_ARCH ?= amd64
DIST_DIR := dist
TOOLS_DIR := .tools
REVISION := $(shell git rev-parse --short HEAD 2>/dev/null || echo unversioned)
RELEASE_NAME := caddy-$(CADDY_VERSION)-est-$(REVISION)-$(RELEASE_OS)-$(RELEASE_ARCH)

CHANGELOG := CHANGELOG.md

.PHONY: help tidy fmt fmt-check vet lint test test-integration cover build vuln \
	check caddy caddy-verify caddy-release lab clean release-check release-notes

help:  ## List the available targets
	@grep -hE '^[a-z][a-zA-Z0-9_-]*:.*## ' $(MAKEFILE_LIST) \
		| sort \
		| awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

tidy:  ## Sync go.mod and go.sum
	$(GO) mod tidy

fmt:  ## Format Go sources in place
	gofmt -w .

# Separate from fmt so CI verifies without writing: an unformatted contribution
# fails the gate instead of being silently rewritten.
fmt-check:  ## Verify Go sources are gofmt-clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	$(GO) vet ./...

lint: fmt-check vet  ## Static checks - formatting and go vet

test:  ## Run the unit test suite
	$(GO) test ./...

test-integration:  ## Run the end-to-end tests against a live EST server (needs make lab)
	$(GO) test -tags=integration -count=1 ./...

cover:  ## Run tests and report coverage per package
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

build:  ## Compile the module
	$(GO) build ./...

# govulncheck type-checks with the standard library of the toolchain that built
# it, and `go run pkg@version` builds in the tool's own module context, so it
# would otherwise be built by whatever Go happens to be on PATH.
vuln:  ## Check dependencies against the Go vulnerability database
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run $(GOVULNCHECK_PKG) ./...

check: lint build test  ## Everything CI runs, in CI's order

caddy:  ## Build a Caddy binary for this machine with the module linked in
	$(GO) run $(XCADDY_PKG) build $(CADDY_VERSION) --with $(MODULE)=.

# A plugin that compiles is not a plugin that loads: Caddy resolves modules
# through a registry at init, so only running the binary proves it registered.
caddy-verify: caddy  ## Build a Caddy binary and assert the module registered
	./caddy list-modules | grep -qx tls.issuance.est
	@echo "tls.issuance.est is registered in $$(./caddy version)"

$(TOOLS_DIR)/xcaddy:
	# Built for this machine on purpose: caddy-release sets GOOS for the Caddy
	# build, and go run would cross-compile xcaddy itself with it.
	GOBIN=$(CURDIR)/$(TOOLS_DIR) $(GO) install $(XCADDY_PKG)

caddy-release: $(TOOLS_DIR)/xcaddy  ## Cross-compile a Caddy binary into dist/ with a checksum
	mkdir -p $(DIST_DIR)
	GOOS=$(RELEASE_OS) GOARCH=$(RELEASE_ARCH) $(TOOLS_DIR)/xcaddy build $(CADDY_VERSION) \
		--with $(MODULE)=. \
		--output $(DIST_DIR)/$(RELEASE_NAME)
	@cd $(DIST_DIR) && { \
		command -v sha256sum >/dev/null 2>&1 \
			&& sha256sum $(RELEASE_NAME) \
			|| shasum -a 256 $(RELEASE_NAME); \
	} > $(RELEASE_NAME).sha256
	@cat $(DIST_DIR)/$(RELEASE_NAME).sha256

lab:  ## Run the lab EST server in the foreground on https://127.0.0.1:8443
	GOTOOLCHAIN=auto $(GO) run $(EST_SERVER_PKG)

# The release workflow runs these two, so a release can be rehearsed locally before a tag
# exists. A tag is the only thing that publishes a Go module, and it cannot be moved once
# the proxy has served it, so the checks belong before tagging rather than after.
release-check:  ## Verify the changelog documents a release (make release-check VERSION=0.1.0)
	@test -n "$(VERSION)" || { echo "VERSION is required, e.g. make release-check VERSION=0.1.0"; exit 1; }
	@grep -qE '^## \[$(VERSION)\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$$' $(CHANGELOG) || { \
		echo "$(CHANGELOG) has no dated section for $(VERSION); move the Unreleased entries into one"; \
		exit 1; \
	}
	@test -n "$$($(MAKE) --no-print-directory release-notes VERSION=$(VERSION))" || { \
		echo "the $(VERSION) section of $(CHANGELOG) is empty"; exit 1; \
	}
	@echo "$(CHANGELOG) documents $(VERSION)"

release-notes:  ## Print the changelog section for VERSION, for use as release notes
	@test -n "$(VERSION)" || { echo "VERSION is required"; exit 1; }
	@awk '/^## \[$(VERSION)\]/{flag=1; next} /^## \[/{flag=0} flag' $(CHANGELOG)

clean:  ## Remove build output
	rm -rf $(DIST_DIR) $(TOOLS_DIR) caddy coverage.out
