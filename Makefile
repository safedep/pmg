GO := go
BIN_DIR := bin

# Platform detection
ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
	# Detect if we are in a Unix-like shell on Windows (e.g. Git Bash)
	# If 'uname' is available, we assume a Unix-like shell
	ifneq ($(shell uname -s 2>/dev/null),)
		MKDIR_P := mkdir -p $(BIN_DIR)
		RM_RF := rm -rf $(BIN_DIR)
	else
		MKDIR_P := if not exist $(BIN_DIR) mkdir $(BIN_DIR)
		RM_RF := if exist $(BIN_DIR) rmdir /s /q $(BIN_DIR)
	endif
else
	BINARY_EXT :=
	MKDIR_P := mkdir -p $(BIN_DIR)
	RM_RF := rm -rf $(BIN_DIR)
	SHELL := /bin/bash
endif

BIN := $(BIN_DIR)/pmg$(BINARY_EXT)
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

GO_CFLAGS=-X 'github.com/safedep/pmg/internal/version.Commit=$(GITCOMMIT)' -X 'github.com/safedep/pmg/internal/version.Version=$(VERSION)'
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

.PHONY: all pmg create_bin clean test sandbox-e2e

all: pmg

pmg: create_bin
	$(GO) build ${GO_LDFLAGS} -o $(BIN) main.go

create_bin:
	$(MKDIR_P)

clean:
	$(RM_RF)

test:
	$(GO) test ./...

# Runs the sandbox E2E tests with seeded env canaries, mirroring the
# pmg-e2e.yml sandbox jobs. Requires node and a supported sandbox driver
# (Seatbelt on macOS, Bubblewrap or Landlock on Linux).
sandbox-e2e: pmg
	E2E_ENV_SEEDED=1 \
	GITHUB_TOKEN=pmg-e2e-canary \
	gh_token=pmg-e2e-canary \
	AWS_SECRET_ACCESS_KEY=pmg-e2e-canary \
	OP_SERVICE_ACCOUNT_TOKEN=pmg-e2e-canary \
	CLOUDFLARE_API_TOKEN=pmg-e2e-canary \
	TWINE_PASSWORD=pmg-e2e-canary \
	NPM_TOKEN=pmg-e2e-keep \
	NODE_AUTH_TOKEN=pmg-e2e-keep \
	./$(BIN) --sandbox --sandbox-enforce npm exec -- node ./test/sandbox-e2e.js

fmt:
	$(GO) fmt ./...

lint:
	golangci-lint run
