# Build, test and lint t480-fingerprint: the Go programs (fpd, fpctl) and
# the C PAM module. Everything generated lands under build/: binaries in
# build/bin, the module in build/lib, coverage data in build/coverage.

GO        ?= go
PKG       := git.airies.net/vifair22/t480-fingerprint
SEMVER    := $(shell cat release_version)
STAMP     := $(shell date +%Y%m%d.%H%M)
BIN       := build/bin
COVDIR    := build/coverage
COVER_MIN ?= 80

CMDS := fpctl fpd

# $(1) is the build type baked into the version string.
version_ldflags = -X $(PKG)/internal/version.semver=$(SEMVER) \
                  -X $(PKG)/internal/version.stamp=$(STAMP) \
                  -X $(PKG)/internal/version.buildType=$(1)

.PHONY: all release debug race test cover lint fmt clean install uninstall

# Local installation, until the ebuild exists. PAM finds the module by its
# absolute path in /etc/pam.d, so it stays out of the package-managed
# /usr/lib64/security.
PREFIX  ?= /usr/local
DESTDIR ?=
SBINDIR := $(PREFIX)/sbin
BINDIR  := $(PREFIX)/bin
PAMDIR  := $(PREFIX)/lib64/security
UNITDIR ?= /etc/systemd/system

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

test: pam-test
	$(GO) test -race ./...

cover: pam-coverage
	@mkdir -p $(COVDIR)
	$(GO) test -race -covermode=atomic -coverprofile=$(COVDIR)/cover.out ./...
	$(GO) tool cover -html=$(COVDIR)/cover.out -o $(COVDIR)/cover.html
	@$(GO) tool cover -func=$(COVDIR)/cover.out | awk -v min=$(COVER_MIN) \
		'/^total:/ { sub(/%/, "", $$3); printf "total coverage %s%% (minimum %s%%)\n", $$3, min; \
		  if ($$3 + 0 < min) exit 1 }'

# golangci-lint is not packaged on every dev box; CI always has it.
lint: pam-analyze pam-tidy
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null; then golangci-lint run; \
	 else echo "WARN: golangci-lint not installed, skipped" >&2; fi

fmt:
	gofmt -w .

# Copies what `make` built; it does not build, so `sudo make install` never
# leaves root-owned files in build/.
install:
	@test -x $(BIN)/fpd -a -x $(BIN)/fpctl -a -f $(PAM_LIB) || \
	    { echo "nothing built: run make first (as yourself, not root)" >&2; exit 1; }
	install -D -m 0755 $(BIN)/fpd $(DESTDIR)$(SBINDIR)/fpd
	install -D -m 0755 $(BIN)/fpctl $(DESTDIR)$(BINDIR)/fpctl
	install -D -m 0755 $(PAM_LIB) $(DESTDIR)$(PAMDIR)/pam_fpd.so
	install -d $(DESTDIR)$(UNITDIR)
	sed 's|@SBINDIR@|$(SBINDIR)|' packaging/fpd.service > $(DESTDIR)$(UNITDIR)/fpd.service
	chmod 0644 $(DESTDIR)$(UNITDIR)/fpd.service

# Leaves /var/lib/fpd alone: the host secret and calibration are state.
uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/fpd $(DESTDIR)$(BINDIR)/fpctl \
	    $(DESTDIR)$(PAMDIR)/pam_fpd.so $(DESTDIR)$(UNITDIR)/fpd.service

clean:
	rm -rf build

# ---------------------------------------------------------------------------
# pam_fpd.so (C11)
# ---------------------------------------------------------------------------

# make's builtin CC is `cc`; take gcc unless CC was really overridden.
ifeq ($(origin CC),default)
CC := gcc
endif

PAM_SRCS  := pam/src/client.c pam/src/pam_fpd.c
PAM_TESTS := pam/tests/test_client.c pam/tests/test_pam_fpd.c
PAM_LIB   := build/lib/pam_fpd.so

# The standard strict set; -Werror because a warning allowed to persist
# stops being read.
C_WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wunused -Wunused-function \
              -Wunused-variable -Wunused-parameter -Wunused-result \
              -Wdouble-promotion -Wformat=2 -Wformat-truncation \
              -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations \
              -Wcast-align -Wcast-qual -Wnull-dereference -Wconversion \
              -Wsign-conversion
C_HARDENING := -fstack-protector-strong -fstack-clash-protection
C_CPPFLAGS  := -Ipam/include -D_GNU_SOURCE
C_FLAGS     := -std=c11 $(C_WARNINGS) $(C_HARDENING) -Werror -fPIC
# Only pam_sm_* are exported; everything else stays inside the module.
PAM_LDFLAGS := -shared -fvisibility=hidden -Wl,-z,relro,-z,now,-z,defs -lpam

# Tests link the sources directly, under ASan and UBSan, with libpam's
# entry points supplied by the test itself and a short client grace period.
C_TEST_FLAGS := -Og -g3 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
                -DFPD_GRACE_MS=300U -pthread

.PHONY: pam pam-test pam-test-junit pam-coverage pam-analyze pam-tidy pamcheck

all: pam

pam: $(PAM_LIB)

$(PAM_LIB): $(PAM_SRCS) pam/include/*.h
	@mkdir -p $(dir $@)
	$(CC) $(C_CPPFLAGS) $(C_FLAGS) -O3 -flto -DNDEBUG -o $@ $(PAM_SRCS) $(PAM_LDFLAGS)

build/pam-test/test_%: pam/tests/test_%.c pam/tests/fake_fpd.c $(PAM_SRCS) pam/include/*.h
	@mkdir -p $(dir $@)
	$(CC) $(C_CPPFLAGS) -Ipam/tests $(C_FLAGS) $(C_TEST_FLAGS) -o $@ \
	    $< pam/tests/fake_fpd.c $(if $(findstring test_client,$@),pam/src/client.c,$(PAM_SRCS)) -lcmocka

PAM_TEST_BINS := $(patsubst pam/tests/%.c,build/pam-test/%,$(PAM_TESTS))

pam-test: $(PAM_TEST_BINS)
	@fail=0; for t in $(PAM_TEST_BINS); do echo "== $$t"; $$t || fail=1; done; exit $$fail

# cmocka's XML mode replaces stdout, so CI gets its own target.
pam-test-junit: $(PAM_TEST_BINS)
	@mkdir -p build/junit
	@for t in $(PAM_TEST_BINS); do \
	    CMOCKA_MESSAGE_OUTPUT=xml CMOCKA_XML_FILE=build/junit/$$(basename $$t).junit.xml $$t || true; \
	done

pam-coverage:
	@mkdir -p build/pam-coverage
	@for t in $(PAM_TESTS); do \
	    n=$$(basename $$t .c); \
	    $(CC) $(C_CPPFLAGS) -Ipam/tests -std=c11 -Og -g --coverage -DFPD_GRACE_MS=300U -pthread \
	        -o build/pam-coverage/$$n $$t pam/tests/fake_fpd.c \
	        $$( [ $$n = test_client ] && echo pam/src/client.c || echo $(PAM_SRCS) ) -lcmocka || exit 1; \
	    build/pam-coverage/$$n >/dev/null || exit 1; \
	done
	@gcovr --root . --filter 'pam/src/.*' --object-directory build/pam-coverage \
	    --fail-under-line $(COVER_MIN) --print-summary

# A driver for trying the module end to end without editing /etc/pam.d.
pamcheck: build/bin/pamcheck

build/bin/pamcheck: pam/tools/pamcheck.c
	@mkdir -p $(dir $@)
	$(CC) $(C_FLAGS) -O2 -o $@ $< -lpam

pam-analyze:
	@echo "== cppcheck"
	@cppcheck --enable=warning,performance,portability --check-level=exhaustive \
	    --inline-suppr --error-exitcode=1 --quiet --suppress=missingIncludeSystem \
	    --suppress=checkersReport -Ipam/include pam/src
	@echo "== gcc -fanalyzer"
	@$(CC) $(C_CPPFLAGS) $(C_FLAGS) -O2 -fanalyzer -fsyntax-only $(PAM_SRCS)
	@echo "== stack usage (limit 65536 bytes per function)"
	@mkdir -p build/pam-stack
	@for f in $(PAM_SRCS); do \
	    $(CC) $(C_CPPFLAGS) $(C_FLAGS) -O2 -fstack-usage -c $$f \
	        -o build/pam-stack/$$(basename $$f .c).o || exit 1; \
	done
	@awk -F'\t' '{ split($$1, a, ":"); if ($$2 + 0 > 65536 || $$3 !~ /static/) { print "stack: " $$0; bad = 1 } } \
	    END { exit bad }' build/pam-stack/*.su && echo "all functions static and under the limit"

pam-tidy:
	@clang-tidy --config-file=pam/.clang-tidy $(PAM_SRCS) -- $(C_CPPFLAGS) -std=c11
