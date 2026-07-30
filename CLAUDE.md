# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go SDK for Signet. Module: `github.com/go-signet/sdk-go` (Go 1.25+)

Packages:

| Package       | Role                                                                             |
| ------------- | -------------------------------------------------------------------------------- |
| `credstore`   | Credential storage: OS keyring with an encrypted file fallback                    |
| `discovery`   | OIDC auto-discovery with caching                                                  |
| `oauth`       | OAuth 2.0 HTTP client (token, revoke, introspect, userinfo, tokeninfo)            |
| `authflow`    | CLI flow orchestration (Device Code, Auth Code + PKCE, auto-refresh TokenSource)  |
| `clientcreds` | Client Credentials token source for M2M                                          |
| `middleware`  | `net/http` Bearer validation, online (tokeninfo / introspection per request)      |
| `jwksauth`    | `net/http` Bearer validation, offline (cached JWKS, single + multi-issuer)        |
| `bearerauth`  | Framework-neutral verifier for JWT **or** `sgk_…` Personal API Key on one route   |

Cross-cutting notes:

- The `jwksauth` package's default private-claim prefix is `"extra"`, matching the upstream Signet `JWT_PRIVATE_CLAIM_PREFIX` default; deployments that override the server-side value must pass the same string via `jwksauth.WithPrivateClaimPrefix(...)`.
- Every retry client used for form POSTs must install `oauth.RewindBodyMiddleware`; build defaults via `oauth.NewDefaultHTTPClient()` rather than calling `retry.NewRealtimeClient` directly. go-httpretry clones the request per attempt but shares the consumed body reader, so without it retried POSTs are rejected by `net/http` before they leave the process.
- go-httpretry returns a non-nil `*http.Response` alongside its error once retries are exhausted. Every `httpClient.Get`/`Post` call site must close that body on the error path or it leaks the body and its connection.

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
