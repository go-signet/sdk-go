package jwksauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Compile-time guard that *Verifier satisfies [TokenVerifier].
var _ TokenVerifier = (*Verifier)(nil)

var (
	errAudienceRequired = errors.New("jwksauth: audience must be non-empty")
	errIssuerURLEmpty   = errors.New("jwksauth: issuerURL must be non-empty")
)

// Verifier validates Signet access tokens issued by a single OIDC issuer.
//
// Construction performs OIDC discovery (one HTTP round-trip to the
// well-known endpoint) and prepares a remote key set. The JWKS itself is
// fetched lazily by go-oidc on the first [Verifier.Verify] call and cached
// in process; subsequent verifications are network-free unless a token
// header carries a previously-unknown key id, at which point go-oidc
// transparently refetches the JWKS.
//
// A Verifier is safe for concurrent use by many goroutines.
type Verifier struct {
	verifier *oidc.IDTokenVerifier

	// canonicalIssuer is the issuer string the provider reported during
	// discovery. The verifier already pins to this value internally; we
	// retain it for [Verifier.Issuer] and for diagnostics.
	canonicalIssuer string

	timeout time.Duration

	// keys are the resolved server-attested payload keys; see
	// [WithPrivateClaimPrefix].
	keys claimKeys
}

// NewVerifier builds a single-issuer Verifier that requires the `aud`
// claim of every token to equal audience.
//
// audience must be non-empty. If the deployment uses an issuer that does
// not emit an `aud` claim on access tokens, use [NewVerifierSkipAudience]
// instead — making the audience opt-out explicit at the API level prevents
// silent misconfiguration.
//
// Discovery is bounded by [WithDiscoveryTimeout] (default 15s). The context
// passed in is only used for discovery; the long-lived JWKS keyset has its
// own internal context so the deadline does not leak into future refreshes.
func NewVerifier(
	ctx context.Context,
	issuerURL, audience string,
	opts ...Option,
) (*Verifier, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return nil, fmt.Errorf("%w (use NewVerifierSkipAudience to opt out)", errAudienceRequired)
	}
	return newVerifier(ctx, issuerURL, audience, false, opts...)
}

// NewVerifierSkipAudience builds a single-issuer Verifier that does NOT
// validate the `aud` claim. Use this only for issuers whose access tokens
// genuinely have no audience binding (rare in modern Signet deployments)
// — every other use case should call [NewVerifier] with an audience.
func NewVerifierSkipAudience(
	ctx context.Context,
	issuerURL string,
	opts ...Option,
) (*Verifier, error) {
	return newVerifier(ctx, issuerURL, "", true, opts...)
}

func newVerifier(
	ctx context.Context,
	issuerURL, audience string,
	skipAudience bool,
	opts ...Option,
) (*Verifier, error) {
	issuerURL = strings.TrimSpace(issuerURL)
	if issuerURL == "" {
		return nil, errIssuerURLEmpty
	}
	cfg := defaultVerifierConfig()
	for _, o := range opts {
		if o != nil {
			o.apply(&cfg)
		}
	}
	if err := validatePrivateClaimPrefix(cfg.privateClaimPrefix); err != nil {
		return nil, fmt.Errorf("jwksauth: invalid private claim prefix: %w", err)
	}

	discoverCtx, cancel := context.WithTimeout(ctx, cfg.discoveryTimeout)
	defer cancel()

	canonical, oidcVerifier, err := discoverVerifier(discoverCtx, issuerURL, audience, skipAudience)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		verifier:        oidcVerifier,
		canonicalIssuer: canonical,
		timeout:         cfg.verifyTimeout,
		keys:            newClaimKeys(cfg.privateClaimPrefix),
	}, nil
}

// discoverVerifier runs OIDC discovery against issuerURL and returns the
// provider's canonical issuer string together with a verifier configured for
// the given audience. Both single- and multi-issuer constructors funnel
// through here so the discovery contract — and the iss-pinning that
// [oidc.NewProvider] enforces against the URL it was asked about — has a
// single source of truth.
func discoverVerifier(
	ctx context.Context,
	issuerURL, audience string,
	skipAudience bool,
) (string, *oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", nil, fmt.Errorf("jwksauth: discover %s: %w", issuerURL, err)
	}
	var meta struct {
		Issuer string `json:"issuer"`
	}
	if err := provider.Claims(&meta); err != nil {
		return "", nil, fmt.Errorf("jwksauth: read metadata for %s: %w", issuerURL, err)
	}
	return meta.Issuer, provider.Verifier(&oidc.Config{
		ClientID:          audience,
		SkipClientIDCheck: skipAudience,
	}), nil
}

// Issuer returns the canonical issuer string discovered at construction.
// This is the value tokens will carry in their `iss` claim, byte-for-byte;
// it may differ from the URL passed to [NewVerifier] if the provider
// normalizes (e.g. trailing-slash handling).
func (v *Verifier) Issuer() string { return v.canonicalIssuer }

// Verify checks the JWT signature, iss/aud/exp/nbf claims, and decodes the
// Signet-specific extras. The supplied context is wrapped with the verify
// timeout configured via [WithVerifyTimeout]; pass r.Context() from the
// HTTP layer so client cancellation propagates.
func (v *Verifier) Verify(ctx context.Context, raw string) (*TokenInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	// Verify performs signature, iss, aud, exp, nbf checks. It rejects
	// alg=none and algorithms inconsistent with the JWK type, defending
	// against JWT confusion attacks. The return type is *oidc.IDToken by
	// library convention, but we are verifying access tokens — same RFC
	// 7519 claims and signature path.
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	return newTokenInfo(tok, v.keys)
}
