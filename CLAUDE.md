# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go SDK for Signet — currently provides the `credstore` package for secure credential storage with OS keyring integration and file-based fallback.

Module: `github.com/go-signet/sdk-go` (Go 1.25+)

The `jwksauth` package's default private-claim prefix is `"extra"`, matching the upstream Signet `JWT_PRIVATE_CLAIM_PREFIX` default; deployments that override the server-side value must pass the same string via `jwksauth.WithPrivateClaimPrefix(...)`.

## Common Commands

```bash
make test          # Run all tests with coverage
make lint          # Run golangci-lint v2 (auto-installs if missing)
make fmt           # Format code with golangci-lint (gofmt + gofumpt + golines)
```

## Code Style & Linting

- golangci-lint v2 config in `.golangci.yml` with strict settings
- Formatting: gofumpt with extra rules + golines
- Banned packages: `io/ioutil`, `golang.org/x/exp`, `github.com/pkg/errors` — use stdlib equivalents
- `nolintlint` requires explanation and specific linter name for any `//nolint` directive
- Error wrapping uses `fmt.Errorf` with `%w` verb (not `pkg/errors`)
- File permissions for credential files: `0o600`

## Before Committing

All code **must** pass `make lint` and `make fmt` before committing. Fix any lint errors or formatting issues before creating a commit.
