// Package jwksauth provides offline JWT/JWKS validation for resource servers.
//
// Use this package on the resource-server side of an Signet deployment to
// validate access tokens locally — no per-request callback to the issuer.
// Construction performs OIDC discovery; the JWKS itself is fetched lazily
// by go-oidc on the first verification (and again whenever a token header
// carries a previously-unknown key id), then cached in process so
// subsequent verifications are network-free.
//
// # When to choose offline vs. online validation
//
// This package complements the [github.com/go-signet/sdk-go/middleware]
// package, which validates tokens by calling the issuer's tokeninfo or
// introspection endpoint per request. The trade-off is:
//
//   - Offline (this package): zero round-trips per request, microsecond
//     verification, scales horizontally, works in air-gapped regions after the
//     first JWKS fetch. A revoked token stays valid until its `exp`.
//   - Online (middleware): instant revocation visibility, but every request
//     pays a network round-trip to the issuer.
//
// Pick offline when access-token lifetimes are short (minutes) and you can
// tolerate the revocation window equalling the lifetime. Pick online when you
// need instant revocation.
//
// # Routes that also accept Personal API Keys
//
// A [Verifier] or [MultiVerifier] validates JWTs only. If a route must also
// accept a complete Signet Personal API Key (`sgk_…`), inject this package's
// [TokenVerifier] into
// [github.com/go-signet/sdk-go/bearerauth]: it keeps JWT verification offline
// here, verifies keys online on every request, and applies one shared issuer,
// Client App, and scope policy to both. That package is framework-neutral —
// use it instead of [Middleware] when you are not on net/http, or when one
// route has to handle both credential kinds.
//
// # Single issuer
//
// For a service that trusts one Signet:
//
//	v, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "https://api.example.com")
//	if err != nil { log.Fatal(err) }
//	mux.Handle("/api/profile", jwksauth.Middleware(v, jwksauth.AccessRule{})(profileHandler))
//	mux.Handle("/api/data",    jwksauth.Middleware(v, jwksauth.AccessRule{Scopes: []string{"email"}})(dataHandler))
//
// # Server-attested private claims and the prefix
//
// Signet emits four private claims — Domain, Project, ServiceAccount,
// and UID — under a configurable prefix (default "extra"), so the JWT
// payload keys are "extra_domain", "extra_project", "extra_service_account",
// and "extra_uid". The SDK reads them out of the box; if your Signet
// deployment has overridden JWT_PRIVATE_CLAIM_PREFIX, pass the same value
// via [WithPrivateClaimPrefix]. UID carries the username for tokens
// issued by user-bearing flows (Authorization Code + PKCE, Device
// Authorization Grant); the Client Credentials flow has no user, so UID
// is the empty string for those tokens.
//
// Any other non-standard payload keys (for example a caller-supplied
// "tenant") are surfaced via [Claims.Extras]; read them with
// [TokenInfo.Extra]. Caller-supplied keys are not part of [AccessRule] or
// the cross-issuer Domain pinning.
//
// # Multiple issuers (multi-region / multi-domain / migration)
//
// For a service that accepts tokens from several Signets:
//
//	mv, err := jwksauth.NewMultiVerifier(ctx,
//	    []string{"https://auth-a.example.com", "https://auth-b.example.com"},
//	    "https://api.example.com")
//	if err != nil { log.Fatal(err) }
//	// Optional cross-domain defense — strongly recommended with short
//	// domain codes. Only Domain participates; caller-supplied claims do
//	// not enter the cross-issuer pinning.
//	if err := mv.SetIssuerDomains("https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd"); err != nil {
//	    log.Fatal(err)
//	}
//	mux.Handle("/api/admin", jwksauth.Middleware(mv, jwksauth.AccessRule{
//	    Domains:         []string{"oa"},
//	    ServiceAccounts: []string{"sync-bot@oa.local"},
//	    Projects:        []string{"admin-tools"},
//	})(adminHandler))
//
// # Why "read iss before verifying" is safe (multi-issuer routing)
//
// When dispatching by issuer, the `iss` claim is read from the unverified
// JWT payload only to PICK the correct verifier. The chosen verifier then
// authoritatively validates the signature against ITS issuer's JWKS and
// re-checks the `iss` claim. An attacker who claims iss=trustedA but signs
// with their own key fails signature verification.
package jwksauth
