package bearerauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/jwksauth"
)

var (
	errIssuerURLEmpty        = errors.New("bearerauth: issuerURL must not be empty")
	errConfigClientIDEmpty   = errors.New("bearerauth: Config.ClientID must not be empty")
	errConfigAudienceMissing = errors.New(
		"bearerauth: Config.Audience must not be empty " +
			"(set Config.SkipAudience to opt out)",
	)
	errConfigAudienceConflict = errors.New(
		"bearerauth: Config.Audience and Config.SkipAudience are mutually exclusive",
	)
	errConfigIntrospectionHalf = errors.New(
		"bearerauth: Config.IntrospectionClientID and Config.IntrospectionClientSecret " +
			"must be set together",
	)
)

// Config is the declarative input to [New]. It replaces the three things the
// explicit constructors make you assemble by hand — the JWT verifier, the
// canonical issuer, and the endpoint URL — all of which are derivable from the
// issuer URL.
//
// The Personal API Key mode is chosen by the introspection credentials:
// leaving both empty selects tokeninfo, setting both selects introspection.
// Setting only one is rejected rather than silently downgraded to an
// unauthenticated request.
type Config struct {
	// Audience is the `aud` claim every JWT access token must carry.
	// Required unless SkipAudience is set.
	Audience string

	// SkipAudience disables JWT audience validation. Use it only for issuers
	// whose access tokens genuinely have no audience binding; making the
	// opt-out explicit keeps it from happening by accident.
	SkipAudience bool

	// ClientID is the OAuth client_id of the single Signet Client App every
	// credential must belong to.
	// Required.
	ClientID string

	// RequiredScopes are the all-of scopes every credential must carry.
	RequiredScopes []string

	// IntrospectionClientID and IntrospectionClientSecret select RFC 7662
	// introspection for Personal API Keys. Both empty selects tokeninfo.
	//
	// With Signet's default ownership gate these credentials normally have to
	// belong to the same Client App as ClientID; see
	// [NewIntrospectionVerifier].
	IntrospectionClientID     string
	IntrospectionClientSecret string

	// JWKSOptions are passed through to the JWT verifier built by [New]
	// (for example [github.com/go-signet/sdk-go/jwksauth.WithVerifyTimeout]).
	//
	// The private-claim prefix does not need configuring here: this package
	// reads only standard and Signet-reserved claims from a JWT, never the
	// prefixed server-attested ones.
	JWKSOptions []jwksauth.Option
}

// New builds a [Verifier] from an issuer URL alone.
//
// It runs OIDC discovery, builds a [github.com/go-signet/sdk-go/jwksauth.Verifier]
// for the JWT path, takes [Policy.Issuer] from the issuer that discovery
// reported, and derives the tokeninfo or introspection endpoint — so the
// canonical issuer cannot be mistyped and the endpoint path cannot drift.
//
//	verifier, err := bearerauth.New(ctx, "https://auth.example.com", bearerauth.Config{
//		Audience:       "api://orders",
//		ClientID:       "orders-api",
//		RequiredScopes: []string{"orders.read"},
//	})
//
// Use [NewTokenInfoVerifier] or [NewIntrospectionVerifier] instead when you
// need to supply your own [github.com/go-signet/sdk-go/jwksauth.TokenVerifier]
// (a MultiVerifier, say, or a test double), point at a non-standard endpoint,
// or avoid discovery entirely.
//
// Construction performs two startup round-trips — one for this package's
// discovery fetch and one for the JWT verifier's own — and the JWKS itself is
// fetched lazily on first use. ctx bounds construction only; it does not
// govern later [Verifier.Verify] calls. Any injected [WithHTTPClient] is used
// for the discovery fetch as well as for later online calls.
//
// Call New once at startup and share the result. Signet rate-limits the
// discovery endpoint, so calling New per request — or even per test — earns a
// 429 that surfaces here as a construction failure, not as a verification
// error. The returned [Verifier] is immutable and safe for concurrent use, so
// one instance per policy is the intended shape.
func New(
	ctx context.Context,
	issuerURL string,
	cfg Config,
	opts ...Option,
) (*Verifier, error) {
	issuerURL = strings.TrimSpace(issuerURL)
	if issuerURL == "" {
		return nil, errIssuerURLEmpty
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Resolve the client up front so discovery, the online calls, and the
	// delegated constructor all share exactly one. config holds only this one
	// field, so the delegated constructor is handed the resolved client
	// directly rather than the whole option list to re-resolve.
	httpClient, err := resolveHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	opts = []Option{WithHTTPClient(httpClient)}

	disco, err := discovery.NewClient(issuerURL, discovery.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("bearerauth: create discovery client: %w", err)
	}
	meta, err := disco.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("bearerauth: discover %s: %w", issuerURL, err)
	}
	endpoints := meta.Endpoints()

	jwtVerifier, err := cfg.newJWTVerifier(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	// Issuer comes from the verifier's own discovery, byte-for-byte, so the
	// exact-match policy cannot be defeated by a hand-typed trailing slash.
	policy := Policy{
		Issuer:         jwtVerifier.Issuer(),
		ClientID:       strings.TrimSpace(cfg.ClientID),
		RequiredScopes: cfg.RequiredScopes,
	}

	// Mode selection must use the same predicate Config.validate used, or a
	// whitespace-only client ID is accepted there as "tokeninfo" and dispatched
	// here as "introspection".
	if strings.TrimSpace(cfg.IntrospectionClientID) != "" {
		endpoint, err := requireSameOrigin(
			endpoints.IntrospectionURL,
			jwtVerifier.Issuer(),
			"introspection",
		)
		if err != nil {
			return nil, err
		}
		return NewIntrospectionVerifier(
			jwtVerifier,
			endpoint,
			cfg.IntrospectionClientID,
			cfg.IntrospectionClientSecret,
			policy,
			opts...,
		)
	}
	return NewTokenInfoVerifier(jwtVerifier, endpoints.TokenInfoURL, policy, opts...)
}

// requireSameOrigin rejects a discovery-advertised endpoint that does not live
// on the issuer's own origin.
//
// Only introspection needs this: discovery derives the tokeninfo URL from the
// (already issuer-matched) issuer string, but it copies introspection_endpoint
// straight out of the fetched document. Without this check, a document that
// advertises another host makes every Verify POST the caller's confidential
// client secret and the end user's complete Personal API Key to that host —
// and the caller only sees an ordinary ErrVerifierUnavailable.
func requireSameOrigin(endpoint, issuer, name string) (string, error) {
	got, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("bearerauth: invalid %s URL: %w", name, err)
	}
	want, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("bearerauth: invalid issuer URL: %w", err)
	}
	if got.Scheme != want.Scheme || got.Host != want.Host {
		return "", fmt.Errorf(
			"bearerauth: discovered %s endpoint is not on the issuer origin %s://%s",
			name, want.Scheme, want.Host,
		)
	}
	return strings.TrimSpace(endpoint), nil
}

// validate rejects the configurations that would otherwise resolve into a
// weaker verifier than the caller intended.
func (c Config) validate() error {
	hasAudience := strings.TrimSpace(c.Audience) != ""
	switch {
	case strings.TrimSpace(c.ClientID) == "":
		return errConfigClientIDEmpty
	case !hasAudience && !c.SkipAudience:
		return errConfigAudienceMissing
	case hasAudience && c.SkipAudience:
		return errConfigAudienceConflict
	}

	// Half-configured introspection must fail loudly: silently falling back to
	// tokeninfo would drop the client authentication the caller asked for, and
	// silently sending an empty secret would fail on every request instead.
	if (strings.TrimSpace(c.IntrospectionClientID) == "") !=
		(c.IntrospectionClientSecret == "") {
		return errConfigIntrospectionHalf
	}
	return nil
}

func (c Config) newJWTVerifier(
	ctx context.Context,
	issuerURL string,
) (*jwksauth.Verifier, error) {
	var (
		v   *jwksauth.Verifier
		err error
	)
	if c.SkipAudience {
		v, err = jwksauth.NewVerifierSkipAudience(ctx, issuerURL, c.JWKSOptions...)
	} else {
		v, err = jwksauth.NewVerifier(ctx, issuerURL, c.Audience, c.JWKSOptions...)
	}
	if err != nil {
		return nil, fmt.Errorf("bearerauth: build jwt verifier: %w", err)
	}
	return v, nil
}
