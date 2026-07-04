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

## Types

- `Token` — access_token, refresh_token, token_type, expires_in, scope, id_token
- `DeviceAuth` — device_code, user_code, verification_uri, interval
- `IntrospectionResult` — active, scope, client_id, username, exp, etc.
- `UserInfo` — sub, name, email, preferred_username, etc.
- `TokenInfo` — active, user_id, client_id, scope, subject_type
- `Error` — OAuth error code + description
- `Endpoints` — all endpoint URLs
