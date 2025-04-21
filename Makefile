GO := go
BIN_DIR := bin
BIN := $(BIN_DIR)/pmg

.PHONY: all

all: pmg

pmg: create_bin
	$(GO) build -o $(BIN) main.go

create_bin:
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)
