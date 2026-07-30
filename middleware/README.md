# middleware

Standard `net/http` middleware for Bearer token validation. Compatible with any Go HTTP framework (gin, echo, chi, stdlib).

## Choosing between `middleware` and `bearerauth`

This package is the all-online path: **every** token — JWT or opaque — costs one
tokeninfo/introspection round-trip, and the middleware writes the HTTP error
response itself.

[`bearerauth/`](../bearerauth/) is the newer, framework-neutral verifier for
routes that accept either a JWT **or** a Signet Personal API Key (`sgk_…`). It
verifies JWTs offline through an injected `jwksauth.TokenVerifier`, keeps
Personal API Keys online on every request, applies one shared issuer / Client
App / scope policy to both, and returns a typed `Identity` or error instead of
touching the response.

|                         | `middleware`                            | `bearerauth`                                |
| ----------------------- | --------------------------------------- | ------------------------------------------- |
| Round-trips per request | Always one                              | None for JWTs, one per `sgk_…` key          |
| HTTP integration        | `net/http` middleware, writes responses | None — `Verify(ctx, raw)` only              |
| Credential kinds        | Any token the endpoint accepts          | JWT access tokens and `sgk_…` keys          |
| Policy                  | Required scopes                         | Exact issuer + Client App + required scopes |

Existing `middleware` deployments keep working unchanged; nothing here is
deprecated.

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
