# discovery

OIDC auto-discovery client. Fetches and caches provider metadata from `/.well-known/openid-configuration`, so other packages don't need to manually configure endpoint URLs.

## Usage

```go
import (
    "github.com/go-signet/sdk-go/discovery"
    "github.com/go-signet/sdk-go/oauth"
)

disco, err := discovery.NewClient("https://auth.example.com")
if err != nil {
    log.Fatal(err)
}

meta, err := disco.Fetch(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Println(meta.Issuer)
fmt.Println(meta.TokenEndpoint)
fmt.Println(meta.ScopesSupported)

// Convert to oauth.Endpoints for use with the oauth package:
endpoints := meta.Endpoints()
client, err := oauth.NewClient("client-id", endpoints)
if err != nil {
    log.Fatal(err)
}
```

## Options

| Option             | Description                                  |
| ------------------ | -------------------------------------------- |
| `WithHTTPClient()` | Set custom `*retry.Client` for HTTP requests |
| `WithCacheTTL()`   | Set cache duration (default: 1 hour)         |

## Types

- `Metadata` — subset of OIDC Provider Metadata covering the fields used by Signet SDK (issuer, token_endpoint, authorization_endpoint, device_authorization_endpoint, scopes_supported, etc.)
- `Client` — discovery client with built-in caching

## Behavior

- Caches metadata for the configured TTL (default 1 hour)
- Thread-safe — multiple goroutines can call `Fetch()` concurrently
- Returns a deep copy — callers may safely modify the returned `Metadata` (including slice fields) without affecting the cache
- Validates that the returned issuer matches the expected URL (OIDC Discovery 1.0 §4.3)
- Automatically derives `device_authorization_endpoint` and `introspection_endpoint` from the issuer URL when not explicitly advertised (Signet uses fixed paths)
