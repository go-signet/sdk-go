# bearerauth

Framework-neutral verification for a Bearer credential that may be **either** a
JWT access token **or** a complete Signet Personal API Key (`sgk_…`). Both
produce the same `Identity` and pass the same policy.

`Verify(ctx, rawCredential) (*Identity, error)` is the whole surface. It does
not parse an `*http.Request`, write a response, populate a request context, or
register middleware — routing and status codes stay with your adapter.

## Usage

```go
import "github.com/go-signet/sdk-go/bearerauth"

// Once at startup. Discovery derives the JWT verifier, the canonical policy
// issuer, and the tokeninfo endpoint from the issuer URL.
verifier, err := bearerauth.New(ctx, "https://auth.example.com", bearerauth.Config{
    Audience:       "api://orders",
    ClientID:       "orders-api",
    RequiredScopes: []string{"orders.read"},
})
if err != nil {
    log.Fatal(err)
}

// Per request. credential is the value after "Bearer ".
identity, err := verifier.Verify(ctx, credential)
```

Switching Personal API Keys to introspection is two more fields:

```go
bearerauth.Config{
    Audience:       "api://orders",
    ClientID:       "orders-api",
    RequiredScopes: []string{"orders.read"},

    IntrospectionClientID:     "orders-api",
    IntrospectionClientSecret: os.Getenv("ORDERS_API_CLIENT_SECRET"),
}
```

Setting only one of the two is rejected at construction rather than silently
downgraded to an unauthenticated introspection request.

### Explicit construction

`New` is a convenience wrapper. Use the explicit constructors when you need to
inject your own `jwksauth.TokenVerifier` (a `MultiVerifier`, or a test double),
point at a non-standard endpoint, or avoid discovery entirely.

Note that injecting a `MultiVerifier` does **not** make this package
multi-issuer: `Policy` pins exactly one issuer and `evaluate` compares it
byte-for-byte, so a token from any other issuer the `MultiVerifier` trusts
verifies successfully and is then rejected with `ErrUntrustedIssuer`. Build one
`Verifier` per issuer instead.

```go
jwtVerifier, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "api://orders")
if err != nil {
    log.Fatal(err)
}

verifier, err := bearerauth.NewTokenInfoVerifier(
    jwtVerifier,
    "https://auth.example.com/oauth/tokeninfo",
    bearerauth.Policy{
        Issuer:         jwtVerifier.Issuer(), // byte-for-byte, never normalized
        ClientID:       "orders-api",
        RequiredScopes: []string{"orders.read"},
    },
)
```

`New` costs two startup round-trips (its own discovery fetch plus the JWT
verifier's); the explicit path costs one. Neither affects the `Verify` hot path.
Use [`discovery/`](../discovery/) if you want to resolve endpoints yourself.

Build the verifier **once** and share it. Signet rate-limits the discovery
endpoint, so calling `New` per request returns a 429 as a construction error.
The result is immutable and concurrency-safe — one instance per policy is the
intended shape.

## Two online modes, chosen at construction

Personal API Keys carry no signature, so they are verified online on **every**
request. Pick exactly one endpoint up front — there is no runtime fallback.

|                    | `NewTokenInfoVerifier`                           | `NewIntrospectionVerifier`              |
| ------------------ | ------------------------------------------------ | --------------------------------------- |
| Request            | `GET /oauth/tokeninfo`, key as Bearer            | `POST /oauth/introspect`, key in form   |
| Client credentials | None                                             | Client ID **and** secret, both required |
| Ownership          | Any caller                                       | Must normally own the key's Client App  |
| Failure detail     | All key failures collapse to `401 invalid_token` | Inactive keys return `{"active":false}` |

With Signet's default ownership gate, introspecting a key owned by another
Client App returns a metadata-stripped `{"active":true}`. That is treated as an
incomplete response and fails closed as `ErrVerifierUnavailable` — it never
becomes an empty `Identity`. In practice the introspection client must be the
same Client App the policy pins.

## Identity

| Field            | Verified JWT                            | tokeninfo `sgk_…`       | introspection `sgk_…`   |
| ---------------- | --------------------------------------- | ----------------------- | ----------------------- |
| `Subject`        | `sub`                                   | `user_id`               | `sub`                   |
| `SubjectType`    | `client` for `client:<id>`, else `user` | `user`                  | `user`                  |
| `Issuer`         | `iss`                                   | `iss`                   | `iss`                   |
| `ClientID`       | `client_id`                             | `client_id`             | `client_id`             |
| `Scopes`         | verified scopes                         | `strings.Fields(scope)` | `strings.Fields(scope)` |
| `ExpiresAt`      | verified expiry                         | Unix `exp`              | Unix `exp`              |
| `CredentialType` | `jwt`                                   | `personal_api_key`      | `personal_api_key`      |

Scopes from all three paths are cloned, de-duplicated, and sorted, so
semantically identical grants compare equal regardless of wire order. Nothing
path-specific (raw claims, `username`, `jti`, audience) reaches `Identity`.

A JWT must additionally carry the signed claim `type=access`. Signet refresh
tokens share the issuer's signing keys and would otherwise satisfy signature,
issuer, audience, and expiry checks.

## Shared policy

After either path produces an `Identity`:

1. `Identity.Issuer` must equal `Policy.Issuer` byte-for-byte. Supply the
   issuer Signet discovery reported (`(*jwksauth.Verifier).Issuer()`); the
   constructor validates but never normalizes it, so no trailing slash is added
   or removed for you.
2. `Identity.ClientID` must equal `Policy.ClientID` exactly and
   case-sensitively.
3. Every entry in `Policy.RequiredScopes` must be present (all-of, exact,
   case-sensitive). Order and duplicates in the policy do not matter.

The JWT verifier's own `iss`/`aud` checks are defense in depth, not a
replacement — an online Personal API Key verdict never went through them.

Same policy does not mean same freshness. A JWT's scope is an issuance-time
snapshot and offline verification cannot see a revocation before `exp`; a key's
scope comes from its Client App at Signet cache-fill time and its lifecycle
state is observed online, subject to Signet's cache behavior.

## Errors

Every failure matches exactly one sentinel under `errors.Is`, and no partial
`Identity` is ever returned.

| Sentinel                 | Cause                                                                                                                                       | Typical HTTP mapping     |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `ErrInvalidCredential`   | Empty/malformed credential, inactive key, tokeninfo `401`, invalid JWT, wrong JWT `type`, expired identity                                  | 401 `invalid_token`      |
| `ErrUntrustedIssuer`     | Issuer ≠ `Policy.Issuer`                                                                                                                    | 401 `invalid_token`      |
| `ErrClientAppNotAllowed` | Client App ≠ `Policy.ClientID`                                                                                                              | 401 `invalid_token`      |
| `ErrInsufficientScope`   | A required scope is missing                                                                                                                 | 403 `insufficient_scope` |
| `ErrVerifierUnavailable` | Transport failure, exhausted 429/5xx retries, refused redirect, rejected introspection credentials, malformed/oversized/incomplete response | 503                      |

Scope failures are also `*InsufficientScopeError`, whose `MissingScope` is the
first missing scope in the canonicalized required list — stable enough to put
straight into an RFC 6750 `scope="…"` challenge.

`ErrVerifierUnavailable` means the verdict is _unknown_, not negative: ask the
client to retry rather than to re-authenticate.

Caller cancellation stays detectable — such an error satisfies both
`errors.Is(err, ErrVerifierUnavailable)` and `errors.Is(err, context.Canceled)`
or `context.DeadlineExceeded`.

Errors never contain the raw JWT, the full key, the Authorization value, the
form body, the client secret, or an unsanitized upstream/custom-verifier error.
Constructor validation errors are configuration errors and match none of the
five sentinels.

### Known limitation

Signet intentionally maps Personal API Key validator and store failures to the
same `401 invalid_token` as an unknown key, so `ErrInvalidCredential` from
tokeninfo cannot always be distinguished from a server-side fault.

## Transport and retries

Online calls share one `go-httpretry` realtime client:

- two retries after the first attempt, short jittered exponential backoff;
- a per-attempt timeout, with overall duration governed by the caller context;
- retries only for transport errors, 429, and 5xx — never for other 4xx or a
  `2xx` `active=false`;
- logging disabled;
- redirects refused (`CheckRedirect` returns `http.ErrUseLastResponse`), so no
  3xx can forward the Bearer key or the secret-bearing form to another host;
- the introspection form is replayed in full on every retry;
- responses capped at 1 MiB and always closed, including on retry exhaustion.

These apply to the online Personal API Key calls and to `New`'s discovery
fetch. They do **not** cover the JWT path: `jwksauth` delegates discovery and
JWKS fetching to `go-oidc`, which uses `http.DefaultClient` and follows
redirects. `WithHTTPClient` cannot reach it.

Verdicts are never cached and requests are never coalesced: a revoked key stops
working on the next call.

Inject your own client with `WithHTTPClient` for deployment-specific timeouts,
metrics, or tracing:

```go
httpClient, err := retry.NewRealtimeClient(
    retry.WithNoLogging(),
    retry.WithPerAttemptTimeout(2*time.Second),
    retry.WithHTTPClient(&http.Client{
        CheckRedirect: func(*http.Request, []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }),
)
verifier, err := bearerauth.NewTokenInfoVerifier(jwtVerifier, url, policy,
    bearerauth.WithHTTPClient(httpClient))
```

An injected client must be safe for concurrent use, must not be mutated after
construction, must enforce its own redirect policy, and its callbacks must
redact the `Authorization` header and form bodies.

Body replay is supplied by the default client through a per-attempt middleware:
go-httpretry clones the request per attempt, and a clone shares the consumed
body reader, so without it a retried introspection POST is rejected by
`net/http` before it ever reaches the server. If you inject a client and use
introspection, install the same middleware — it is exported as
`oauth.RewindBodyMiddleware`:

```go
retry.WithPerAttemptMiddleware(oauth.RewindBodyMiddleware)
```

This package emits no logs and no global metrics. Typed errors are the entire
observability boundary.

## Concurrency

A constructed `Verifier` is immutable and safe for concurrent use. The built-in
`*jwksauth.Verifier`, `*jwksauth.MultiVerifier`, and the default retry client
are shareable; a custom injected verifier, retry client, transport, or callback
must be concurrency-safe itself.

## API

| Symbol                                                                        | Description                                                      |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `New(ctx, issuerURL, Config{...}, opts...)`                                   | Build everything from the issuer URL via discovery               |
| `Config`                                                                      | Audience, Client App, scopes, optional introspection credentials |
| `NewTokenInfoVerifier(jwt, url, policy, opts...)`                             | Verify keys via tokeninfo; no client credentials                 |
| `NewIntrospectionVerifier(jwt, url, clientID, clientSecret, policy, opts...)` | Verify keys via RFC 7662 introspection                           |
| `WithHTTPClient(*retry.Client)`                                               | Replace the default online HTTP client                           |
| `(*Verifier).Verify(ctx, raw)`                                                | Verify one credential                                            |
| `Identity` / `(Identity).HasScope(string)`                                    | Normalized result                                                |
| `Policy`                                                                      | Issuer, Client App, and required scopes                          |
| `InsufficientScopeError`                                                      | Carries the first missing scope                                  |

## Related packages

- [`jwksauth/`](../jwksauth/) — the offline JWT verifier injected here, plus
  its own `net/http` middleware for JWT-only routes.
- [`middleware/`](../middleware/) — the legacy all-online `net/http`
  middleware. It validates _every_ token against tokeninfo/introspection and
  writes responses itself; `bearerauth` verifies JWTs offline, keeps Personal
  API Keys online, and stays framework-neutral.
- [`discovery/`](../discovery/) — resolve the tokeninfo/introspection URLs.
