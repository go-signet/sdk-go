# middleware

Standard `net/http` middleware for Bearer token validation. Compatible with any Go HTTP framework (gin, echo, chi, stdlib).

## Usage

```go
import "github.com/go-signet/sdk-go/middleware"

mux := http.NewServeMux()
mux.Handle("/api/data",
    middleware.BearerAuth(
        middleware.WithOAuthClient(oauthClient),
        middleware.WithRequiredScopes("read"),
    )(handler),
)
```

### Access token info in handlers

```go
func handler(w http.ResponseWriter, r *http.Request) {
    info, ok := middleware.TokenInfoFromContext(r.Context())
    if ok {
        fmt.Println(info.UserID, info.Scope, info.SubjectType)
    }
}
```

### Scope checking

```go
// Convenience function
if middleware.HasScope(r.Context(), "admin") {
    // ...
}

// Or as separate middleware (chain after BearerAuth)
mux.Handle("/admin",
    middleware.BearerAuth(middleware.WithOAuthClient(client))(
        middleware.RequireScope("admin")(adminHandler),
    ),
)
```

### Introspection mode

By default, tokens are validated via the tokeninfo endpoint. Use introspection for RFC 7662 compliance:

```go
middleware.BearerAuth(
    middleware.WithOAuthClient(oauthClient),
    middleware.WithIntrospection(),
)
```

## Options

| Option                 | Description                                          |
| ---------------------- | ---------------------------------------------------- |
| `WithOAuthClient()`    | Set the OAuth client for token validation (required) |
| `WithIntrospection()`  | Use introspection endpoint instead of tokeninfo      |
| `WithRequiredScopes()` | Require specific scopes on every request             |
| `WithErrorHandler()`   | Custom error handler for auth failures               |

## Types

- `TokenInfo` — UserID, ClientID, Scope, SubjectType, ExpiresAt
- `ErrorHandler` — `func(w http.ResponseWriter, r *http.Request, err error)`
