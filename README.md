# Signet SDK for Go

[![Lint and Testing](https://github.com/go-signet/sdk-go/actions/workflows/testing.yml/badge.svg)](https://github.com/go-signet/sdk-go/actions/workflows/testing.yml)
[![CodeQL](https://github.com/go-signet/sdk-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/go-signet/sdk-go/actions/workflows/codeql.yml)
[![Trivy Security Scan](https://github.com/go-signet/sdk-go/actions/workflows/security.yml/badge.svg)](https://github.com/go-signet/sdk-go/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/go-signet/sdk-go/branch/main/graph/badge.svg)](https://codecov.io/gh/go-signet/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-signet/sdk-go.svg)](https://pkg.go.dev/github.com/go-signet/sdk-go)

Go SDK for [Signet](https://github.com/go-signet). Requires Go 1.25+.

## Installation

```bash
go get github.com/go-signet/sdk-go
```

## Packages

| Package                     | Description                                                                                                      |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [credstore](credstore/)     | Secure credential storage with OS keyring integration and file-based fallback                                    |
| [oauth](oauth/)             | OAuth 2.0 token client (Device Code, Auth Code, Client Credentials, Refresh, Revoke, Introspect, UserInfo)       |
| [discovery](discovery/)     | OIDC auto-discovery from `/.well-known/openid-configuration` with caching                                        |
| [authflow](authflow/)       | CLI flow orchestration (Device Code polling, Auth Code + PKCE, auto-refresh TokenSource with persistent storage) |
| [middleware](middleware/)   | `net/http` Bearer token validation middleware (online: tokeninfo / introspection per request)                    |
| [jwksauth](jwksauth/)       | `net/http` Bearer token validation middleware (offline: cached JWKS, single + multi-issuer)                      |
| [clientcreds](clientcreds/) | Thread-safe Client Credentials token source with auto-cache, `HTTPClient()` and `RoundTripper()` for M2M         |

### Package dependency graph

```txt
credstore (storage)     discovery (OIDC endpoint URLs)
    |    \                  |
    |     \                 v
    |      +----> oauth <---+
    |              / | \
    |             /  |  \
    v            v   v   v
    +------> authflow  middleware  clientcreds

jwksauth — standalone (wraps coreos/go-oidc); no dependency on the OAuth client stack
```

### Online vs. offline token validation

`middleware` and `jwksauth` solve the same problem (validate an incoming
`Authorization: Bearer …` header) with different trade-offs:

| Concern                       | `jwksauth` (offline JWKS)        | `middleware` (online endpoint)     |
| ----------------------------- | -------------------------------- | ---------------------------------- |
| Per-request round-trips       | None (signature math only)       | One per request (tokeninfo/introspect) |
| Verification latency          | Microseconds                     | 10–50 ms + auth-server tail        |
| Revocation visibility         | After `exp` of the access token  | Instant                            |
| Survives auth-server outage   | Yes (after first JWKS fetch)     | No                                 |
| Opaque (non-JWT) tokens       | Not supported                    | Supported                          |
| Multi-issuer support          | Built-in (`MultiVerifier`)       | One client per issuer              |

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Format code
make fmt
```

## License

See the [LICENSE](LICENSE) file for details.
