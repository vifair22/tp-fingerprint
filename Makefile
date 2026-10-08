# Build, test and lint t480-fingerprint. Everything generated lands under
# build/: binaries in build/bin, coverage data in build/coverage.

GO        ?= go
PKG       := git.airies.net/vifair22/t480-fingerprint
SEMVER    := $(shell cat release_version)
STAMP     := $(shell date +%Y%m%d.%H%M)
BIN       := build/bin
COVDIR    := build/coverage
COVER_MIN ?= 80

CMDS := fpctl

# $(1) is the build type baked into the version string.
version_ldflags = -X $(PKG)/internal/version.semver=$(SEMVER) \
                  -X $(PKG)/internal/version.stamp=$(STAMP) \
                  -X $(PKG)/internal/version.buildType=$(1)

.PHONY: all release debug race test cover lint fmt clean

all: release

release:
	@mkdir -p $(BIN)
	$(foreach c,$(CMDS),$(GO) build -trimpath -ldflags '-s -w $(call version_ldflags,release)' -o $(BIN)/$(c) ./cmd/$(c) &&) true

debug:
	@mkdir -p $(BIN)
	$(foreach c,$(CMDS),$(GO) build -gcflags 'all=-N -l' -ldflags '$(call version_ldflags,debug)' -o $(BIN)/$(c).debug ./cmd/$(c) &&) true

race:
	@mkdir -p $(BIN)
	$(foreach c,$(CMDS),$(GO) build -race -ldflags '$(call version_ldflags,race)' -o $(BIN)/$(c).race ./cmd/$(c) &&) true

test:
	$(GO) test -race ./...

cover:
	@mkdir -p $(COVDIR)
	$(GO) test -race -covermode=atomic -coverprofile=$(COVDIR)/cover.out ./...
	$(GO) tool cover -html=$(COVDIR)/cover.out -o $(COVDIR)/cover.html
	@$(GO) tool cover -func=$(COVDIR)/cover.out | awk -v min=$(COVER_MIN) \
		'/^total:/ { sub(/%/, "", $$3); printf "total coverage %s%% (minimum %s%%)\n", $$3, min; \
		  if ($$3 + 0 < min) exit 1 }'

# golangci-lint is not packaged on every dev box; CI always has it.
lint:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null; then golangci-lint run; \
	 else echo "WARN: golangci-lint not installed, skipped" >&2; fi

fmt:
	gofmt -w .

clean:
	rm -rf build
