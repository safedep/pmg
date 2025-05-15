GO := go
BIN_DIR := bin
BIN := $(BIN_DIR)/pmg
SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

GO_CFLAGS=-X 'github.com/safedep/pmg/cmd/version.commit=$(GITCOMMIT)' -X 'github.com/safedep/pmg/cmd/version.version=$(VERSION)'
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

.PHONY: all

all: pmg

pmg: create_bin
	$(GO) build ${GO_LDFLAGS} -o $(BIN) main.go

create_bin:
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)

test:
	go test ./...
