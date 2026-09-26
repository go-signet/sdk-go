GO ?= go
TOOLS_MOD := -modfile=go.tools.mod
TAGS ?=

## test: run tests
test:
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## coverage: view test coverage in browser
coverage: test
	$(GO) tool cover -html=coverage.txt

## install-tools: download tool dependencies
install-tools:
	$(GO) mod download $(TOOLS_MOD)

## install-golangci-lint: compatibility alias for install-tools
install-golangci-lint: install-tools

## fmt: format go files using golangci-lint
fmt:
	$(GO) tool $(TOOLS_MOD) golangci-lint fmt

## lint: run golangci-lint to check for issues
lint:
	$(GO) tool $(TOOLS_MOD) golangci-lint run

## clean: remove test coverage
clean:
	rm -f coverage.txt

## mod-download: download go module dependencies
mod-download:
	$(GO) mod download

## mod-tidy: tidy go module dependencies
mod-tidy:
	$(GO) mod tidy

## mod-verify: verify go module dependencies
mod-verify:
	$(GO) mod verify

## check-tools: verify required tools are installed
check-tools:
	@command -v $(GO) >/dev/null 2>&1 || (echo "Go not found" && exit 1)

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: help test coverage fmt lint clean
.PHONY: install-golangci-lint mod-download mod-tidy mod-verify check-tools

.PHONY: install-tools
