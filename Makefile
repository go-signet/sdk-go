GO ?= go
TAGS ?=

## test: run tests
test:
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## coverage: view test coverage in browser
coverage: test
	$(GO) tool cover -html=coverage.txt

## install-golangci-lint: install golangci-lint if not present
install-golangci-lint:
	@command -v golangci-lint >/dev/null 2>&1 || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin v2.7.2

## fmt: format go files using golangci-lint
fmt: install-golangci-lint
	golangci-lint fmt

## lint: run golangci-lint to check for issues
lint: install-golangci-lint
	golangci-lint run

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
	@command -v golangci-lint >/dev/null 2>&1 || echo "golangci-lint not installed (run: make install-golangci-lint)"

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: help test coverage fmt lint clean
.PHONY: install-golangci-lint mod-download mod-tidy mod-verify check-tools
