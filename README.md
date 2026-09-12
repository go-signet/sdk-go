# Signet SDK for Go

[![Lint and Testing](https://github.com/go-signet/sdk-go/actions/workflows/testing.yml/badge.svg)](https://github.com/go-signet/sdk-go/actions/workflows/testing.yml)
[![CodeQL](https://github.com/go-signet/sdk-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/go-signet/sdk-go/actions/workflows/codeql.yml)
[![Trivy Security Scan](https://github.com/go-signet/sdk-go/actions/workflows/security.yml/badge.svg)](https://github.com/go-signet/sdk-go/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/go-signet/sdk-go/branch/main/graph/badge.svg)](https://codecov.io/gh/go-signet/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-signet/sdk-go.svg)](https://pkg.go.dev/github.com/go-signet/sdk-go)
[![GitHub release](https://img.shields.io/github/v/release/go-signet/sdk-go?include_prereleases)](https://github.com/go-signet/sdk-go/releases)

Go SDK for [Signet](https://github.com/go-signet). Requires Go 1.25+.

## Installation

```bash
go get github.com/go-signet/sdk-go
```

## Packages

| Package                     | Description                                                                                                      |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [credstore](credstore/)     | Secure credential storage with OS keyring integration and file-based fallback                                    |
| [oauth](oauth/)             | OAuth 2.0 token client (resource indicators, OBO, Device/Auth Code, Client Credentials, Refresh, Introspect)    |
| [discovery](discovery/)     | OIDC auto-discovery from `/.well-known/openid-configuration` with caching                                        |
| [authflow](authflow/)       | CLI flow orchestration (Device Code polling, Auth Code + PKCE, auto-refresh TokenSource with persistent storage) |
| [middleware](middleware/)   | `net/http` Bearer token validation middleware (online: tokeninfo / introspection per request)                    |
| [jwksauth](jwksauth/)       | `net/http` Bearer token validation middleware (offline: cached JWKS, single + multi-issuer)                      |
| [bearerauth](bearerauth/)   | Framework-neutral verifier for routes accepting either a JWT (offline) or a `sgk_…` Personal API Key (online)    |
| [clientcreds](clientcreds/) | Thread-safe Client Credentials token source with auto-cache, `HTTPClient()` and `RoundTripper()` for M2M         |

### Package dependency graph

```txt
credstore (storage)     discovery (OIDC endpoint URLs)
    |    \                  |
    |     \                 v
    |      +----> oauth <---+
    |             / | \  \
    |            /  |  \  \
    v           v   v   v  v
    +---> authflow  middleware  clientcreds  bearerauth
                                                  ^
jwksauth — standalone (wraps coreos/go-oidc)      |
    |                                             |
    +---------------------------------------------+
      (bearerauth injects a jwksauth.TokenVerifier,
       reuses oauth.Client for sgk_ keys, and uses
       discovery in its one-call New constructor)
```

### Online vs. offline token validation

`middleware`, `jwksauth`, and `bearerauth` all validate an incoming
`Authorization: Bearer …` credential, with different trade-offs:

| Concern                     | `jwksauth` (offline JWKS)       | `middleware` (online endpoint)         | `bearerauth` (mixed)                  |
| --------------------------- | ------------------------------- | -------------------------------------- | ------------------------------------- |
| Per-request round-trips     | None (signature math only)      | One per request (tokeninfo/introspect) | None for JWTs, one per `sgk_…` key    |
| Verification latency        | Microseconds                    | 10–50 ms + auth-server tail            | Microseconds / 10–50 ms by credential |
| Revocation visibility       | After `exp` of the access token | Instant                                | After `exp` (JWT) / instant (key)     |
| Survives auth-server outage | Yes (after first JWKS fetch)    | No                                     | JWT routes yes, key routes no         |
| Opaque (non-JWT) tokens     | Not supported                   | Supported                              | Signet Personal API Keys (`sgk_…`)    |
| Multi-issuer support        | Built-in (`MultiVerifier`)      | One client per issuer                  | No — `Policy` pins exactly one issuer |
| HTTP integration            | `net/http` middleware           | `net/http` middleware                  | None — `Verify(ctx, raw)` only        |

Reach for `bearerauth` when one route must accept both credential kinds, or
when you need a verifier that plugs into a non-`net/http` router (gin, echo,
fiber, connect) without the SDK writing responses for you.

### Resource indicators and OBO

All token grants accept RFC 8707 resource indicators. Interactive flows and the
root `signet.New` facade use `WithResources`; the client-credentials token
source has its own option of the same name. API A performs Signet's single-hop
OBO exchange through `oauth.Client.ExchangeOnBehalfOf`.

API B should validate delegated JWTs locally with `jwksauth` or `bearerauth` so
it can enforce the signed audience, user subject, scopes, and `act` actor. Under
Signet's default ownership gate, introspection by API B returns an active-only
verdict; use that verdict only as an optional live revocation/lineage check,
not as identity metadata.

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
