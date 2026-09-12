# authflow

Token caches use a versioned key encoding both client ID and resource set,
including when resources are omitted. Earlier client-ID-only and resource-key
entries are not reused; users authenticate again once after upgrading. Old
entries remain in the store and the stored token format is unchanged.

High-level CLI authentication flow orchestration. Handles Device Code polling, Authorization Code + PKCE (with local callback server and browser opening), and automatic token refresh with persistent storage.

## Usage

### Device Code Flow

```go
import (
    "github.com/go-signet/sdk-go/authflow"
    "github.com/go-signet/sdk-go/oauth"
)

token, _ := authflow.RunDeviceFlow(ctx, client, []string{"read", "write"},
    authflow.WithOpenBrowser(true),
    authflow.WithResources("https://api.example.com"),
)
```

### Authorization Code + PKCE Flow

Starts a local callback server, opens the browser, and exchanges the code automatically:

```go
token, _ := authflow.RunAuthCodeFlow(ctx, client, []string{"openid", "profile"},
    authflow.WithResources("https://api.example.com"),
)
```

### Auto-refresh TokenSource

Loads tokens from a persistent store, refreshes when expired, and saves the new token back:

```go
import "github.com/go-signet/sdk-go/credstore"

store := credstore.DefaultTokenSecureStore("my-app", ".tokens.json")
ts := authflow.NewTokenSource(client,
    authflow.WithStore(store),
    authflow.WithTokenResources("https://api.example.com"),
)

token, _ := ts.Token(ctx) // auto-loads from cache, refreshes if expired
```

### PKCE Generation

```go
pkce, _ := authflow.NewPKCE()
fmt.Println(pkce.Verifier)  // random code verifier
fmt.Println(pkce.Challenge) // BASE64URL(SHA256(verifier))
fmt.Println(pkce.Method)    // "S256"
```

### Browser Detection

```go
if authflow.CheckBrowserAvailability() {
    // use Auth Code flow
} else {
    // fallback to Device Code flow (e.g., SSH sessions)
}
```

## Options

### Interactive flows

| Option                    | Description                              |
| ------------------------- | ---------------------------------------- |
| `WithOpenBrowser(bool)`   | Automatically open verification URI      |
| `WithDeviceFlowHandler()` | Custom handler for displaying user codes |
| `WithLocalPort(int)`      | Local callback port for Auth Code + PKCE  |
| `WithResources(...string)` | RFC 8707 resource indicators             |

### TokenSource

| Option        | Description                         |
| ------------- | ----------------------------------- |
| `WithStore()`          | Set credstore for token persistence        |
| `WithTokenResources()` | Resources for refresh and cache isolation  |

## Types

- `PKCE` — verifier + challenge pair (RFC 7636)
- `DeviceFlowHandler` — interface for displaying device codes
- `TokenSource` — auto-refresh with persistent storage
