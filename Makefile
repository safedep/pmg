GO := go
BIN_DIR := bin
BIN_NAME := pmg
SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

GO_CFLAGS=-X 'github.com/safedep/pmg/cmd/version.commit=$(GITCOMMIT)' -X 'github.com/safedep/pmg/cmd/version.version=$(VERSION)'
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

# Detect current platform
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Set extension for Windows
ifeq ($(GOOS),windows)
	EXT := .exe
else
	EXT :=
endif

.PHONY: all clean test pmg create_bin

all: pmg

pmg: create_bin
	$(GO) build ${GO_LDFLAGS} -o $(BIN_DIR)/$(BIN_NAME)$(EXT) main.go

create_bin:
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)

test:
	go test ./...
