# authflow

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
)
```

### Authorization Code + PKCE Flow

Starts a local callback server, opens the browser, and exchanges the code automatically:

```go
token, _ := authflow.RunAuthCodeFlow(ctx, client, []string{"openid", "profile"})
```

### Auto-refresh TokenSource

Loads tokens from a persistent store, refreshes when expired, and saves the new token back:

```go
import "github.com/go-signet/sdk-go/credstore"

store := credstore.DefaultTokenSecureStore("my-app", ".tokens.json")
ts := authflow.NewTokenSource(client,
    authflow.WithStore(store),
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

### RunDeviceFlow

| Option                    | Description                              |
| ------------------------- | ---------------------------------------- |
| `WithOpenBrowser(bool)`   | Automatically open verification URI      |
| `WithDeviceFlowHandler()` | Custom handler for displaying user codes |

### TokenSource

| Option        | Description                         |
| ------------- | ----------------------------------- |
| `WithStore()` | Set credstore for token persistence |

## Types

- `PKCE` — verifier + challenge pair (RFC 7636)
- `DeviceFlowHandler` — interface for displaying device codes
- `TokenSource` — auto-refresh with persistent storage
