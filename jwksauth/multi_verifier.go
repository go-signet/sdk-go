package jwksauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/sync/errgroup"
)

// Compile-time guard that *MultiVerifier satisfies [TokenVerifier].
var _ TokenVerifier = (*MultiVerifier)(nil)

var (
	errNoIssuers = errors.New("jwksauth: at least one issuer is required")

	// ErrUntrustedIssuer is returned by [MultiVerifier.Verify] when the token's
	// `iss` claim does not match any configured issuer. Wrapped with %w so
	// callers can detect it via errors.Is.
	ErrUntrustedIssuer = errors.New("untrusted issuer")
)

// MultiVerifier dispatches verification to the right per-issuer verifier
// based on the token's `iss` claim. Discovery is performed concurrently for
// every issuer at construction time; on the hot path the dispatcher is a
// single map lookup followed by the chosen verifier's signature check.
//
// A MultiVerifier is safe for concurrent use after construction.
// [MultiVerifier.SetIssuerDomains] swaps the pinning configuration via an
// atomic pointer, so it is also safe to call concurrently with Verify.
type MultiVerifier struct {
	verifiers map[string]*oidc.IDTokenVerifier

	// issuerDomains pins each issuer to the lower-cased domain codes it is
	// permitted to sign for. A nil pointer means enforcement is disabled.
	// Loaded atomically so SetIssuerDomains can be called after Verify
	// goroutines are already running, without a data race.
	issuerDomains atomic.Pointer[map[string][]string]

	timeout time.Duration

	// keys are the resolved server-attested payload keys; see
	// [WithPrivateClaimPrefix].
	keys claimKeys
}

// NewMultiVerifier builds a multi-issuer verifier. Every issuer in issuers
// must serve a valid OIDC discovery document; discovery happens in parallel
// and is bounded by a single total timeout (default 15s) so one slow issuer
// cannot multiply startup time by N.
//
// audience must be non-empty. Use [NewMultiVerifierSkipAudience] for the
// rare case of issuers that do not emit an `aud` claim on access tokens.
//
// Duplicate issuer URLs in the input are rejected up front. After discovery,
// the canonical issuer string each provider reports (post-normalization) is
// used as the dispatch key — that is what tokens will carry in `iss`.
func NewMultiVerifier(
	ctx context.Context,
	issuers []string,
	audience string,
	opts ...Option,
) (*MultiVerifier, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return nil, fmt.Errorf(
			"%w (use NewMultiVerifierSkipAudience to opt out)",
			errAudienceRequired,
		)
	}
	return newMultiVerifier(ctx, issuers, audience, false, opts...)
}

// NewMultiVerifierSkipAudience is the audience-opt-out counterpart of
// [NewMultiVerifier]. See [NewVerifierSkipAudience] for the trade-off.
func NewMultiVerifierSkipAudience(
	ctx context.Context,
	issuers []string,
	opts ...Option,
) (*MultiVerifier, error) {
	return newMultiVerifier(ctx, issuers, "", true, opts...)
}

func newMultiVerifier(
	ctx context.Context,
	issuers []string,
	audience string,
	skipAudience bool,
	opts ...Option,
) (*MultiVerifier, error) {
	cleaned, err := dedupIssuers(issuers)
	if err != nil {
		return nil, err
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

	verifiers, err := buildVerifiers(discoverCtx, cleaned, audience, skipAudience)
	if err != nil {
		return nil, err
	}
	return &MultiVerifier{
		verifiers: verifiers,
		timeout:   cfg.verifyTimeout,
		keys:      newClaimKeys(cfg.privateClaimPrefix),
	}, nil
}

// SetIssuerDomains enables cross-domain defense by pinning each issuer to
// the domain codes it is permitted to sign for. The encoding is:
//
//	iss1=domainA,domainB;iss2=domainC
//
// The issuer keys on the left-hand side must exactly match the canonical
// issuer strings returned by [MultiVerifier.Issuers]. These are the values
// each provider reported during OIDC discovery, which may differ from the
// URLs originally passed to NewMultiVerifier (for example, if the provider
// normalizes a trailing slash). Call [MultiVerifier.Issuers] to log or
// generate the expected keys.
//
// Every issuer registered with the verifier must appear exactly once in
// raw, and a domain must be owned by exactly one issuer. Both rules are
// enforced strictly so a typo or operational mistake fails fast at
// configuration time rather than silently disabling the check.
//
// Cross-issuer enforcement is Domain-level only. Caller-supplied claims
// surfaced via [Claims.Extras] are not part of cross-domain enforcement —
// only the server-attested Domain participates here.
//
// Pass an empty string to disable cross-domain enforcement; safe to call
// concurrently with [MultiVerifier.Verify] (the swap is atomic).
func (v *MultiVerifier) SetIssuerDomains(raw string) error {
	parsed, err := ParseIssuerDomains(raw, v.Issuers())
	if err != nil {
		return err
	}
	if parsed == nil {
		v.issuerDomains.Store(nil)
		return nil
	}
	v.issuerDomains.Store(&parsed)
	return nil
}

// Issuers returns the canonical issuer strings registered with this
// verifier, sorted lexicographically for stable output. Callers may use it
// to log or render configuration; the returned slice is freshly allocated.
func (v *MultiVerifier) Issuers() []string {
	out := make([]string, 0, len(v.verifiers))
	for k := range v.verifiers {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// IssuerDomains returns the configured cross-domain allowlist keyed by
// canonical issuer, or nil when enforcement is disabled — whether
// [MultiVerifier.SetIssuerDomains] was never called or was last called
// with an empty string. The returned map and its slices may be modified
// by callers (a defensive copy is made).
func (v *MultiVerifier) IssuerDomains() map[string][]string {
	cur := v.issuerDomains.Load()
	if cur == nil {
		return nil
	}
	out := make(map[string][]string, len(*cur))
	for k, vs := range *cur {
		out[k] = slices.Clone(vs)
	}
	return out
}

// Verify routes raw to the matching per-issuer verifier and returns the
// decoded [TokenInfo] on success. The supplied context is wrapped with the
// verify timeout configured via [WithVerifyTimeout]; pass r.Context() so
// client cancellation propagates.
//
// The flow is:
//  1. Parse the unverified payload to read `iss` (selection only).
//  2. Reject tokens whose iss is not registered ([ErrUntrustedIssuer]).
//  3. Run the chosen verifier, which authoritatively re-checks signature,
//     iss, aud, exp, nbf.
//  4. If [MultiVerifier.SetIssuerDomains] was configured, enforce that
//     this issuer is allowed to sign for the token's domain.
//
// Errors are intentionally low-detail to limit information disclosure to
// callers that bypass [Middleware]; full diagnostic context is available
// through [MultiVerifier.IssuerDomains] and the canonical issuer list.
func (v *MultiVerifier) Verify(ctx context.Context, raw string) (*TokenInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	iss, err := UnverifiedIssuer(raw)
	if err != nil {
		return nil, err
	}
	verifier, ok := v.verifiers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: iss=%q", ErrUntrustedIssuer, iss)
	}
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	info, err := newTokenInfo(tok, v.keys)
	if err != nil {
		return nil, err
	}

	// Use tok.Issuer (post-verification) rather than the unverified iss —
	// Verify already proved them equal, but reading the verified value
	// keeps the trust boundary self-evident.
	if cur := v.issuerDomains.Load(); cur != nil {
		allowed := (*cur)[tok.Issuer]
		if !slices.Contains(allowed, info.Domain()) {
			// Don't echo the allowlist back: callers that bypass Middleware
			// would otherwise probe the configured domains by feeding tokens.
			return nil, fmt.Errorf(
				"issuer not permitted for this domain: domain=%q",
				info.Claims.Domain,
			)
		}
	}

	return info, nil
}

// dedupIssuers trims and validates the input issuer list.
func dedupIssuers(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		iss := strings.TrimSpace(raw)
		if iss == "" {
			continue
		}
		if _, dup := seen[iss]; dup {
			return nil, fmt.Errorf("jwksauth: duplicate issuer in input: %s", iss)
		}
		seen[iss] = struct{}{}
		out = append(out, iss)
	}
	if len(out) == 0 {
		return nil, errNoIssuers
	}
	return out, nil
}

// buildVerifiers performs OIDC discovery for every trusted issuer in
// parallel. The map is keyed by the canonical issuer string each provider
// reports, since that is what tokens will carry in `iss`.
func buildVerifiers(
	ctx context.Context,
	issuers []string,
	audience string,
	skipAudience bool,
) (map[string]*oidc.IDTokenVerifier, error) {
	type result struct {
		canonical string
		verifier  *oidc.IDTokenVerifier
	}
	results := make([]result, len(issuers))

	// errgroup.WithContext cancels the shared ctx as soon as any goroutine
	// returns an error, so a hung discovery for one issuer doesn't keep
	// startup blocked once a different issuer has already failed.
	g, gctx := errgroup.WithContext(ctx)
	for i, issuer := range issuers {
		g.Go(func() error {
			canonical, oidcVerifier, err := discoverVerifier(gctx, issuer, audience, skipAudience)
			if err != nil {
				return err
			}
			results[i] = result{canonical: canonical, verifier: oidcVerifier}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	out := make(map[string]*oidc.IDTokenVerifier, len(issuers))
	for _, r := range results {
		if _, dup := out[r.canonical]; dup {
			return nil, fmt.Errorf(
				"jwksauth: duplicate issuer in configured issuers after discovery: %s",
				r.canonical,
			)
		}
		out[r.canonical] = r.verifier
	}
	return out, nil
}
