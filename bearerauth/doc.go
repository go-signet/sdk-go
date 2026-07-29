// Package bearerauth verifies an incoming Bearer credential that may be
// either a JWT access token or a complete Signet Personal API Key (`sgk_…`),
// and returns one normalized [Identity] for both.
//
// It is framework-neutral by design: [Verifier.Verify] takes a context and the
// raw credential string and returns an Identity or a typed error. It does not
// parse an *http.Request, write a response, populate a request context, or
// register middleware — those decisions belong to the adapter for whichever
// router you use.
//
// # Getting started
//
// [New] takes an issuer URL and derives the rest through discovery — the JWT
// verifier, the canonical policy issuer, and the online endpoint:
//
//	verifier, err := bearerauth.New(ctx, "https://auth.example.com", bearerauth.Config{
//		Audience:       "api://orders",
//		ClientAppID:    "orders-api",
//		RequiredScopes: []string{"orders.read"},
//	})
//	if err != nil {
//		return err
//	}
//
//	identity, err := verifier.Verify(ctx, rawCredential)
//
// Use [NewTokenInfoVerifier] or [NewIntrospectionVerifier] directly when you
// need to inject your own
// [github.com/go-signet/sdk-go/jwksauth.TokenVerifier] (a MultiVerifier, say,
// or a test double), point at a non-standard endpoint, or avoid discovery.
//
// # Choosing a mode
//
// JWTs are verified offline through an injected
// [github.com/go-signet/sdk-go/jwksauth.TokenVerifier]. Personal API Keys have
// no signature to check locally, so they are verified online on every request
// through exactly one endpoint chosen at construction:
//
//   - tokeninfo calls `GET /oauth/tokeninfo` with the key as the Bearer
//     credential. No client credentials are needed. This is what [New] selects
//     by default, and what [NewTokenInfoVerifier] builds.
//   - introspection calls `POST /oauth/introspect` with the key in a form body
//     plus a confidential client ID and secret. Signet's default ownership
//     gate strips the response metadata when the introspecting client does not
//     own the key's Client App, so the configured client normally must be the
//     same Client App as [Policy.ClientAppID]. Select it by setting
//     [Config.IntrospectionClientID] and [Config.IntrospectionClientSecret],
//     or by calling [NewIntrospectionVerifier].
//
// The two modes are mutually exclusive and there is no runtime fallback
// between them. Verdicts are never cached and requests are never coalesced: a
// revoked key stops working on the next call.
//
// # One policy, two paths
//
// Whichever path produced the Identity, the same [Policy] is applied to it
// afterwards: the issuer must match byte-for-byte, the Client App must match
// exactly, and every required scope must be present. A JWT additionally has to
// carry the signed claim `type=access`, because Signet refresh tokens share
// the issuer's signing keys and would otherwise pass signature, issuer,
// audience, and expiry checks.
//
// Identical policy does not mean identical freshness. A JWT's scope is an
// issuance-time snapshot and offline verification cannot observe a revocation
// before the token expires; a Personal API Key's scope comes from its Client
// App at Signet cache-fill time and its lifecycle state is observed online,
// subject to Signet's cache behavior.
//
// # Errors
//
// Every failure matches exactly one of [ErrInvalidCredential],
// [ErrUntrustedIssuer], [ErrClientAppNotAllowed], [ErrInsufficientScope], or
// [ErrVerifierUnavailable] under errors.Is, and never carries a partial
// Identity. Insufficient-scope failures are additionally an
// *[InsufficientScopeError] carrying the first missing scope, which an adapter
// can advertise in an RFC 6750 challenge.
//
// Errors never contain the raw JWT, the full Personal API Key, the
// Authorization value, the introspection form body, the client secret, or an
// unsanitized upstream error — including one produced by a hostile custom
// verifier. When the caller's context is cancelled or its deadline expires,
// the error satisfies both errors.Is against [ErrVerifierUnavailable] and
// against [context.Canceled] or [context.DeadlineExceeded].
//
// # Transport
//
// Online calls use one shared [github.com/appleboy/go-httpretry] realtime
// client: two retries after the first attempt, short jittered exponential
// backoff, a per-attempt timeout, retries limited to transport errors, 429,
// and 5xx, logging disabled, and redirects refused so no 3xx can forward a
// credential elsewhere. Overall duration stays governed by the caller's
// context. Invalid-credential responses (401, `active=false`) are never
// retried.
//
// The introspection form is replayed in full on every retry, and every
// response body is closed — including the one go-httpretry leaves open when
// retries are exhausted.
//
// Inject your own client with [WithHTTPClient] to attach metrics, tracing, or
// retry callbacks. Such a client must be safe for concurrent use, must not be
// mutated after construction, must enforce its own redirect policy, and its
// callbacks must redact the Authorization header and form bodies. It must also
// supply its own body-replay middleware if it retries introspection; see
// rewindBody in verifier.go, which is what the default client installs.
//
// Redirect refusal is a property of the default client, not something this
// package can enforce on an injected one. A client that follows redirects will
// forward the Bearer Personal API Key — or the introspection form carrying the
// client secret — to whatever host a 307/308 names, and will accept that host's
// answer as the verification verdict. Always set CheckRedirect to return
// [net/http.ErrUseLastResponse].
//
// These transport guarantees cover the online Personal API Key calls and
// [New]'s discovery fetch only. The JWT path runs through jwksauth, which
// delegates OIDC discovery and JWKS fetching to go-oidc; go-oidc uses
// http.DefaultClient and follows redirects, and [WithHTTPClient] cannot reach
// it.
//
// # Concurrency
//
// A constructed [Verifier] is immutable and safe for concurrent use by many
// goroutines. The built-in *jwksauth.Verifier, *jwksauth.MultiVerifier, and
// the default retry client are shareable; a custom injected verifier, retry
// client, transport, or callback must be concurrency-safe itself.
//
// This package adds no global metrics or logging. Typed errors are its entire
// observability surface.
package bearerauth
