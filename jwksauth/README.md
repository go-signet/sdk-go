# jwksauth

Offline JWT/JWKS validation for Signet resource servers. Validate tokens
locally against cached signing keys — no per-request callback to the issuer.

## Online vs. offline validation

This package complements [`middleware/`](../middleware/), which calls the
issuer's tokeninfo or introspection endpoint per request. Pick the model
that matches your latency/revocation trade-off:

| Concern                            | `jwksauth` (offline)            | `middleware` (online)          |
| ---------------------------------- | ------------------------------- | ------------------------------ |
| Per-request network round-trips    | None (signature math only)      | One per request                |
| Verification latency               | Microseconds                    | 10–50 ms + auth-server tail    |
| Revocation visibility              | After `exp` of the access token | Instant                        |
| Survives auth-server outage        | Yes (after first JWKS fetch)    | No                             |
| Works with opaque (non-JWT) tokens | No — JWT only                   | Yes                            |
| Edge / air-gapped deployments      | Suitable                        | Requires reachable auth server |

Common pattern: short access-token lifetimes (5–15 min) + offline JWKS for
the hot path, online introspection for revocation-sensitive mutations.

### Routes that also accept Personal API Keys

The verifiers here handle JWTs only. If a route must accept either a JWT **or**
a complete Signet Personal API Key (`sgk_…`), inject a `jwksauth.TokenVerifier`
into [`bearerauth/`](../bearerauth/): JWTs stay offline here, keys are verified
online on every request, and one shared issuer / Client App / scope policy is
applied to both. `bearerauth` is also the option to reach for when your router
is not `net/http` — it returns a typed `Identity` instead of writing responses.

## Single issuer

```go
import "github.com/go-signet/sdk-go/jwksauth"

ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()
v, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "https://api.example.com")
if err != nil { log.Fatal(err) }

mux := http.NewServeMux()
mux.Handle("/api/profile",
    jwksauth.Middleware(v, jwksauth.AccessRule{})(http.HandlerFunc(profile)))
mux.Handle("/api/data",
    jwksauth.Middleware(v, jwksauth.AccessRule{Scopes: []string{"email"}})(http.HandlerFunc(data)))
```

If your issuer doesn't emit `aud` on access tokens, use `NewVerifierSkipAudience`
to opt out explicitly. The audience-required-by-default API prevents silent
misconfiguration.

In your handler:

```go
func profile(w http.ResponseWriter, r *http.Request) {
    info, ok := jwksauth.TokenInfoFromContext(r.Context())
    if !ok {
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }
    // info embeds *oidc.IDToken — use info.Subject, info.Audience, info.Expiry, etc.
    // info.Claims carries the Signet custom claims.
    json.NewEncoder(w).Encode(map[string]any{
        "subject": info.Subject,
        "scope":   info.Claims.Scope,
    })
}
```

## Server-attested private claims and the prefix

Signet may emit up to four private claims on a token: **Domain**,
**Project**, **ServiceAccount**, **UID**. Each is optional — tokens that
don't need a given dimension simply omit the claim. When present they
appear in the payload under a configurable prefix (default `extra`), so
the JWT keys are `extra_domain`, `extra_project`,
`extra_service_account`, and `extra_uid`. The SDK reads them out of the
box. UID carries the username for user-bearing flows (Authorization
Code + PKCE, Device Authorization Grant); Client Credentials tokens have
no user, so `Claims.UID` is the empty string for those tokens.

```json
{
  "iss": "https://auth.example.com",
  "extra_domain": "oa",
  "extra_project": "p1",
  "extra_service_account": "sync-bot@oa.local",
  "extra_uid": "alice"
}
```

If your Signet deployment overrides `JWT_PRIVATE_CLAIM_PREFIX`, pass the
same value to the verifier:

```go
v, err := jwksauth.NewVerifier(ctx, issuerURL, audience,
    jwksauth.WithPrivateClaimPrefix("acme")) // reads acme_domain, acme_project, acme_service_account, acme_uid
```

Server and SDK must agree byte-for-byte. Reading with the wrong prefix
yields empty Domain / Project / ServiceAccount / UID. For the three
dimensions `AccessRule` checks (Domain, Project, ServiceAccount), this
fails closed. UID is identity, not authorization — `AccessRule` does
not gate on it, so callers must check `info.Claims.UID` in their
handler when they want to restrict by user.

### Caller-supplied keys (Extras)

Any other non-standard payload keys — for example a caller-supplied
`tenant` — are surfaced on `Claims.Extras`. Read them with
`TokenInfo.Extra`:

```go
if v, ok := info.Extra("tenant"); ok {
    if s, ok := v.(string); ok {
        // use the caller-supplied tenant value
        _ = s
    }
}
```

`AccessRule` and the cross-issuer Domain pinning never look at Extras —
caller-supplied keys are not server-attested, so they cannot be used to
gate access. Apply your own checks in the handler when needed.

## Multiple issuers

For multi-region / multi-domain / migration deployments, build a
`MultiVerifier`. It runs OIDC discovery for every issuer in parallel
(bounded by a single total timeout) and routes each request to the right
verifier based on the token's `iss` claim.

```go
mv, err := jwksauth.NewMultiVerifier(ctx,
    []string{"https://auth-a.example.com", "https://auth-b.example.com"},
    "https://api.example.com")
if err != nil { log.Fatal(err) }

// Optional: pin each issuer to the Domain codes it owns. With short
// domain codes ("oa" / "hwrd" / "swrd") this stops a compromised issuer
// from minting tokens that claim a Domain owned by another issuer.
//
// Caller-supplied keys (surfaced via Claims.Extras) are not part of the
// cross-issuer pinning — only the server-attested Domain participates.
if err := mv.SetIssuerDomains(
    "https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd",
); err != nil {
    log.Fatal(err)
}

mux.Handle("/api/admin", jwksauth.Middleware(mv, jwksauth.AccessRule{
    Domains:         []string{"oa"},
    ServiceAccounts: []string{"sync-bot@oa.local"},
    Projects:        []string{"admin-tools"},
})(http.HandlerFunc(admin)))
```

`SetIssuerDomains` validates strictly:

- Every issuer registered with the verifier must appear in the string.
- A Domain must be owned by exactly one issuer.
- Same-issuer duplicates (`oa,oa`) are reported as typos so the error points
  at the actual mistake rather than a confusing cross-issuer overlap message.

## AccessRule

Per-route policy; an empty slice means "this dimension is not checked".
The "Required claim" column shows the JWT payload key under the default
prefix (`extra`); under a custom prefix the keys become
`<prefix>_domain` etc.

| Field             | Required claim          | Match     | Notes                                                                           |
| ----------------- | ----------------------- | --------- | ------------------------------------------------------------------------------- |
| `Scopes`          | `scope`                 | space-set | Reports `403 insufficient_scope` and advertises the scope on `WWW-Authenticate` |
| `Domains`         | `extra_domain`          | case-fold | SDK lower-cases the rule on registration                                        |
| `ServiceAccounts` | `extra_service_account` | exact     | Case-sensitive                                                                  |
| `Projects`        | `extra_project`         | exact     | Case-sensitive                                                                  |

Caller-supplied keys (any payload key not in the SDK's reserved-key set
and not one of the three server-attested `<prefix>_domain` /
`<prefix>_project` / `<prefix>_service_account` keys) are not part of the
allowlist surface. They surface on `Claims.Extras`; read individual values
with `TokenInfo.Extra(key)` and apply your own logic in the handler when
needed. Note that OIDC standard claims the SDK does not name explicitly
(for example `email`, `name`) will also land in Extras if the issuer
emits them.

Allowlist mismatches return `401 invalid_token` (generic) so the allowlist
itself is not probeable. The full reason is logged server-side via the
configured logger (defaults to `slog.Default()`; override with
`jwksauth.WithLogger`).

The `Logger` interface mirrors `log/slog`, so `*slog.Logger` satisfies it
directly:

```go
type Logger interface {
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
}

logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
mw := jwksauth.Middleware(v, rule, jwksauth.WithLogger(logger))
```

Other structured loggers (logrus, zap, zerolog) work via a thin adapter —
e.g. for `*logrus.Logger`:

```go
type logrusAdapter struct{ l *logrus.Logger }

func (a logrusAdapter) Warn(msg string, args ...any) {
    a.l.WithFields(toFields(args)).Warn(msg)
}
func (a logrusAdapter) Error(msg string, args ...any) {
    a.l.WithFields(toFields(args)).Error(msg)
}
// toFields converts slog-style alternating key/value args into a
// logrus.Fields map; implement once and reuse.
```

## RFC 6750 error responses

The middleware emits standards-compliant `WWW-Authenticate` challenges:

| Situation                                       | Status | `WWW-Authenticate`                                                            |
| ----------------------------------------------- | ------ | ----------------------------------------------------------------------------- |
| Missing Authorization (or non-Bearer scheme)    | 401    | `Bearer`                                                                      |
| Bearer header malformed (no token, junk)        | 400    | `Bearer error="invalid_request", error_description="..."`                     |
| Token verification fails                        | 401    | `Bearer error="invalid_token", error_description="invalid token"`             |
| Transient verifier failure (deadline, JWKS net) | 503    | `Bearer error="temporarily_unavailable", error_description="..."`             |
| Required scope missing                          | 403    | `Bearer error="insufficient_scope", error_description="...", scope="<scope>"` |

`ExtractBearerToken` and `WriteAuthError` are exported so applications can
reuse them in custom handlers without duplicating the parser/writer.

## Server hardening

When using `MultiVerifier`, bound the Authorization header well below the
Go default (1 MiB) so the unverified-payload base64 decode (used to read
`iss` for routing) cannot be coerced into large allocations:

```go
srv := &http.Server{
    Handler:        mux,
    MaxHeaderBytes: 8 << 10, // real access tokens are typically <2 KiB
}
```

## Why "read iss before verifying" is safe (multi-issuer)

`UnverifiedIssuer` reads `iss` from the JWT payload **without** validating
the signature. The result is used only to pick which verifier to dispatch
to; the chosen verifier then authoritatively re-checks signature, `iss`,
`aud`, `exp`, and `nbf`. An attacker who claims `iss=trustedA` but signs
with their own key fails signature verification.
