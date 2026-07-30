# oauth

OAuth 2.0 token client for Signet. Pure HTTP layer — no storage, polling, or UI.

## Usage

```go
import "github.com/go-signet/sdk-go/oauth"

client, err := oauth.NewClient("client-id", oauth.Endpoints{
    TokenURL:               "https://auth.example.com/oauth/token",
    DeviceAuthorizationURL: "https://auth.example.com/oauth/device/code",
})
if err != nil {
    log.Fatal(err)
}

// Or use the discovery package to populate endpoints automatically:
//
//   import "github.com/go-signet/sdk-go/discovery"
//
//   disco, err := discovery.NewClient("https://auth.example.com")
//   meta, err := disco.Fetch(ctx)
//   client, err := oauth.NewClient("client-id", meta.Endpoints())
```

### Device Code Flow

```go
auth, err := client.RequestDeviceCode(ctx, []string{"read", "write"})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Open %s and enter code: %s\n", auth.VerificationURI, auth.UserCode)

token, err := client.ExchangeDeviceCode(ctx, auth.DeviceCode)
if err != nil {
    log.Fatal(err)
}
```

### Authorization Code + PKCE

```go
token, err := client.ExchangeAuthCode(ctx, code, redirectURI, codeVerifier)
if err != nil {
    log.Fatal(err)
}
```

### Client Credentials

```go
client, err := oauth.NewClient("client-id", endpoints, oauth.WithClientSecret("secret"))
if err != nil {
    log.Fatal(err)
}
token, err := client.ClientCredentials(ctx, []string{"read"})
if err != nil {
    log.Fatal(err)
}
```

### Personal API Keys (`sgk_…`)

`PersonalAPIKeyTokenInfoRequest` verifies a complete Signet Personal API Key
through the tokeninfo endpoint. It sends only `Authorization: Bearer <key>` —
no client ID, no secret, and nothing in the query string:

```go
info, err := client.PersonalAPIKeyTokenInfoRequest(ctx, "sgk_...")
if err != nil {
    log.Fatal(err)
}
if info.Active && info.TokenType == "personal_api_key" {
    fmt.Println(info.UserID, info.ClientID, info.Scope)
}
```

Signet collapses unknown, malformed, revoked, expired, and disabled keys — and
its own validator failures — into a uniform `401 invalid_token`, so those cases
are not distinguishable from each other.

The result type is separate from `TokenInfo` because Personal API Key responses
additionally carry `token_type`, which must be checked before the rest of the
payload is trusted. For a policy-aware verifier that handles both this and JWTs,
use [`bearerauth/`](../bearerauth/) rather than calling this directly.

### Refresh / Revoke / Introspect / UserInfo

```go
token, err := client.RefreshToken(ctx, refreshToken)
if err != nil {
    log.Fatal(err)
}

if err := client.Revoke(ctx, token.AccessToken); err != nil {
    log.Fatal(err)
}

result, err := client.Introspect(ctx, token.AccessToken)
if err != nil {
    log.Fatal(err)
}

info, err := client.UserInfo(ctx, token.AccessToken)
if err != nil {
    log.Fatal(err)
}
```

## Options

| Option               | Description                                  |
| -------------------- | -------------------------------------------- |
| `WithClientSecret()` | Set client secret (confidential clients)     |
| `WithHTTPClient()`   | Set custom `*retry.Client` for HTTP requests |

The default retry client disables logging, replays form bodies on retries, and
refuses redirects so credentials cannot be forwarded to another host.
`NewDefaultHTTPClient` accepts `retry.Option` values after those defaults; an
explicit `retry.WithHTTPClient` can replace the redirect policy when required.
Callers that do so are responsible for preventing credential-bearing requests
from following untrusted redirects.

## Types

- `Token` — access_token, refresh_token, token_type, expires_in, scope, id_token
- `DeviceAuth` — device_code, user_code, verification_uri, interval
- `IntrospectionResult` — active, scope, client_id, username, exp, etc.
- `UserInfo` — sub, name, email, preferred_username, etc.
- `TokenInfo` — active, user_id, client_id, scope, subject_type
- `PersonalAPIKeyTokenInfo` — the above plus `token_type`, for `sgk_…` keys
- `Error` — OAuth error code + description
- `Endpoints` — all endpoint URLs
