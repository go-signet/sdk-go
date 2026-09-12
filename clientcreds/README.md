# clientcreds

Thread-safe Client Credentials token source for service-to-service (M2M) authentication. Automatically caches tokens and refreshes them before expiry.

## Usage

```go
import "github.com/go-signet/sdk-go/clientcreds"

ts := clientcreds.NewTokenSource(oauthClient,
    clientcreds.WithScopes("read", "write"),
    clientcreds.WithResources("https://api.internal"),
    clientcreds.WithExpiryDelta(30 * time.Second),
)
```

### Get a token directly

```go
token, _ := ts.Token(ctx)
fmt.Println(token.AccessToken)
```

### Auto-authenticated HTTP client

Returns an `*http.Client` that automatically attaches a valid Bearer token to every request:

```go
httpClient := ts.HTTPClient()
resp, _ := httpClient.Get("https://api.internal/data")
```

### Composable RoundTripper

Wrap an existing transport to add Bearer token authentication:

```go
client := &http.Client{
    Transport: ts.RoundTripper(customTransport),
}
```

## Options

| Option              | Description                                           |
| ------------------- | ----------------------------------------------------- |
| `WithScopes()`      | Set scopes to request                                 |
| `WithResources()`   | Set RFC 8707 resource indicators                      |
| `WithExpiryDelta()` | Refresh this long before actual expiry (default: 30s) |

## Behavior

- Thread-safe — safe for concurrent use from multiple goroutines
- Caches the token and reuses it until it's about to expire
- Fetches a new token automatically when the cached one expires (or is within the expiry delta)
- No refresh tokens — Client Credentials grant always issues a new access token
