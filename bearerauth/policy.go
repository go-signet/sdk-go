package bearerauth

import (
	"errors"
	"fmt"
	"strings"
)

var (
	errPolicyIssuerEmpty      = errors.New("bearerauth: Policy.Issuer must not be empty")
	errPolicyIssuerWhitespace = errors.New(
		"bearerauth: Policy.Issuer must not have surrounding whitespace",
	)
	errPolicyClientIDEmpty      = errors.New("bearerauth: Policy.ClientID must not be empty")
	errPolicyClientIDWhitespace = errors.New(
		"bearerauth: Policy.ClientID must not have surrounding whitespace",
	)
)

// Policy is the single authorization rule both credential paths are judged
// against. It is copied and canonicalized at construction, so mutating the
// value (or the RequiredScopes slice) afterwards has no effect on a built
// [Verifier].
//
// v1 pins exactly one issuer and exactly one Client App; there is no
// allowlist. There is also no audience dimension: Signet does not return an
// audience for Personal API Keys, so JWT audience validation stays the
// responsibility of the injected [github.com/go-signet/sdk-go/jwksauth.TokenVerifier].
type Policy struct {
	// Issuer is the canonical Signet issuer string, compared byte-for-byte
	// against every normalized identity.
	//
	// The narrow TokenVerifier interface cannot report it, so the caller is
	// the source of truth: pass the issuer Signet discovery reported. For a
	// concrete *jwksauth.Verifier that is Verifier.Issuer(). It is validated
	// but never normalized — a trailing slash is neither added nor removed.
	Issuer string

	// ClientID is the OAuth client_id of the single Signet Client App every
	// credential must belong to. Matching is exact and case-sensitive.
	ClientID string

	// RequiredScopes are all-of: every entry must be present on the
	// identity. Matching is exact and case-sensitive; order and duplicates
	// in this slice do not affect the result.
	RequiredScopes []string
}

// canonicalPolicy is the validated, immutable form of a [Policy] held by a
// [Verifier].
type canonicalPolicy struct {
	issuer         string
	clientID       string
	requiredScopes []string
}

// canonical validates the policy and returns its immutable form. Scope entries
// are cloned and canonicalized here so [InsufficientScopeError.MissingScope]
// is deterministic and so a later caller mutation cannot race with Verify.
func (p Policy) canonical() (canonicalPolicy, error) {
	switch {
	case strings.TrimSpace(p.Issuer) == "":
		return canonicalPolicy{}, errPolicyIssuerEmpty
	case strings.TrimSpace(p.Issuer) != p.Issuer:
		return canonicalPolicy{}, errPolicyIssuerWhitespace
	case strings.TrimSpace(p.ClientID) == "":
		return canonicalPolicy{}, errPolicyClientIDEmpty
	// Matched byte-for-byte against the credential's client_id, exactly like
	// Issuer. A value carrying stray whitespace — the shape an env file or a
	// ConfigMap yields — would construct cleanly and then deny every single
	// request with no startup signal.
	case strings.TrimSpace(p.ClientID) != p.ClientID:
		return canonicalPolicy{}, errPolicyClientIDWhitespace
	}

	return canonicalPolicy{
		issuer:         p.Issuer,
		clientID:       p.ClientID,
		requiredScopes: canonicalScopes(p.RequiredScopes),
	}, nil
}

// evaluate applies the shared issuer, Client App, and scope rules to an
// already-normalized identity. Both credential paths funnel through here, so
// the two paths cannot drift apart.
//
// The JWT verifier's own iss/aud checks are defense in depth, not a substitute
// for this pass: an online Personal API Key verdict never went through them.
func (p canonicalPolicy) evaluate(id *Identity) error {
	if id.Issuer != p.issuer {
		return fmt.Errorf(
			"%w: issuer does not match the configured policy issuer",
			ErrUntrustedIssuer,
		)
	}
	if id.ClientID != p.clientID {
		return fmt.Errorf(
			"%w: credential belongs to a different client app",
			ErrClientAppNotAllowed,
		)
	}
	for _, want := range p.requiredScopes {
		if !id.HasScope(want) {
			return &InsufficientScopeError{MissingScope: want}
		}
	}
	return nil
}
