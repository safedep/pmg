GO := go
BIN_DIR := bin
BIN_NAME := pmg
SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

GO_CFLAGS=-X 'github.com/safedep/pmg/cmd/version.commit=$(GITCOMMIT)' -X 'github.com/safedep/pmg/cmd/version.version=$(VERSION)'
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

.PHONY: all clean test pmg pmg-windows create_bin

all: pmg

pmg: create_bin
	GOOS=linux GOARCH=amd64 $(GO) build ${GO_LDFLAGS} -o $(BIN_DIR)/$(BIN_NAME) main.go

pmg-windows: create_bin
	GOOS=windows GOARCH=amd64 $(GO) build ${GO_LDFLAGS} -o $(BIN_DIR)/$(BIN_NAME).exe main.go

create_bin:
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)

test:
	go test ./...
