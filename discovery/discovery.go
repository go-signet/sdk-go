// Package discovery provides OIDC auto-discovery from /.well-known/openid-configuration.
//
// It fetches and caches the provider metadata, making all endpoint URLs
// available without manual configuration.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"golang.org/x/sync/singleflight"

	"github.com/go-signet/sdk-go/oauth"
)

const (
	wellKnownPath   = "/.well-known/openid-configuration"
	defaultCacheTTL = 1 * time.Hour

	// fetchTimeout caps the singleflight discovery round-trip. Because the shared
	// fetch context is detached from the caller's deadline (context.WithoutCancel),
	// this bound prevents a hung server from making the shared fetch goroutine
	// outlive every caller indefinitely.
	fetchTimeout = 30 * time.Second

	// maxResponseBytes caps the discovery response read size.
	maxResponseBytes = 1 << 20 // 1 MB

	// Signet-specific endpoint paths derived from the issuer URL
	// when not advertised in the discovery document.
	deviceCodePath    = "/oauth/device/code"
	introspectionPath = "/oauth/introspect"
	tokenInfoPath     = "/oauth/tokeninfo"
)

// errResponseTooLarge is returned when a discovery response exceeds
// maxResponseBytes. Exposed as a package-level sentinel so callers can
// detect the condition via errors.Is.
var errResponseTooLarge = fmt.Errorf(
	"discovery: response body exceeds %d bytes",
	maxResponseBytes,
)

// Metadata represents a subset of the OIDC Provider Metadata (RFC 8414)
// tailored to the fields used by the Signet SDK.
type Metadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint,omitempty"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

// cloneMetadata returns a deep copy of the Metadata, including all slice fields.
func cloneMetadata(m *Metadata) *Metadata {
	cp := *m
	cp.ResponseTypesSupported = slices.Clone(m.ResponseTypesSupported)
	cp.SubjectTypesSupported = slices.Clone(m.SubjectTypesSupported)
	cp.IDTokenSigningAlgValuesSupported = slices.Clone(m.IDTokenSigningAlgValuesSupported)
	cp.ScopesSupported = slices.Clone(m.ScopesSupported)
	cp.TokenEndpointAuthMethods = slices.Clone(m.TokenEndpointAuthMethods)
	cp.GrantTypesSupported = slices.Clone(m.GrantTypesSupported)
	cp.ClaimsSupported = slices.Clone(m.ClaimsSupported)
	cp.CodeChallengeMethodsSupported = slices.Clone(m.CodeChallengeMethodsSupported)
	return &cp
}

// Endpoints converts the metadata to an oauth.Endpoints struct.
func (m *Metadata) Endpoints() oauth.Endpoints {
	ep := oauth.Endpoints{
		TokenURL:               m.TokenEndpoint,
		AuthorizeURL:           m.AuthorizationEndpoint,
		RevocationURL:          m.RevocationEndpoint,
		IntrospectionURL:       m.IntrospectionEndpoint,
		UserinfoURL:            m.UserinfoEndpoint,
		DeviceAuthorizationURL: m.DeviceAuthorizationEndpoint,
	}

	// TokenInfoURL is always derived from issuer (not part of standard OIDC discovery)
	if m.Issuer != "" {
		ep.TokenInfoURL = strings.TrimRight(m.Issuer, "/") + tokenInfoPath
	}

	return ep
}

// Client is an OIDC discovery client with caching.
type Client struct {
	issuerURL  string
	httpClient *retry.Client
	cacheTTL   time.Duration

	mu        sync.RWMutex
	cached    *Metadata
	fetchedAt time.Time
	group     singleflight.Group
}

// Option configures a discovery Client.
type Option func(*Client)

// WithHTTPClient sets a custom retry HTTP client.
// If nil is provided, the default client is kept.
func WithHTTPClient(httpClient *retry.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithCacheTTL sets the cache time-to-live for discovery metadata.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Client) {
		c.cacheTTL = ttl
	}
}

// NewClient creates a new OIDC discovery client.
// A default retry HTTP client is created only when no client is provided via WithHTTPClient.
func NewClient(issuerURL string, opts ...Option) (*Client, error) {
	c := &Client{
		issuerURL: strings.TrimRight(issuerURL, "/"),
		cacheTTL:  defaultCacheTTL,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	if c.httpClient == nil {
		httpClient, err := retry.NewRealtimeClient(retry.WithNoLogging())
		if err != nil {
			return nil, fmt.Errorf("discovery: create http client: %w", err)
		}
		c.httpClient = httpClient
	}

	return c, nil
}

// Fetch retrieves the OIDC provider metadata, using the cache if still valid.
// The returned Metadata is a copy; callers may safely modify it without
// affecting the cached value.
func (c *Client) Fetch(ctx context.Context) (*Metadata, error) {
	c.mu.RLock()
	if c.cached != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		cp := cloneMetadata(c.cached)
		c.mu.RUnlock()
		return cp, nil
	}
	c.mu.RUnlock()

	return c.refresh(ctx)
}

// refresh fetches fresh metadata from the discovery endpoint.
// singleflight coalesces concurrent misses into one HTTP request; the lock is
// held only for the cache check and cache update, not during the network call.
// The shared function returns the canonical (never-mutated) *Metadata; each
// caller clones it below so every Fetch receives its own copy.
//
// The shared fetch runs under a context detached from the caller's
// cancellation (context.WithoutCancel) and bounded by fetchTimeout, so the
// first caller's deadline cannot abort the fetch for every concurrent waiter.
// Each caller still honors its own cancellation via the select on ctx.Done.
func (c *Client) refresh(ctx context.Context) (*Metadata, error) {
	ch := c.group.DoChan("fetch", func() (any, error) {
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		defer cancel()

		// Double-check after coalescing into the singleflight slot.
		c.mu.RLock()
		if c.cached != nil && time.Since(c.fetchedAt) < c.cacheTTL {
			cached := c.cached
			c.mu.RUnlock()
			return cached, nil
		}
		c.mu.RUnlock()

		// HTTP fetch happens outside any lock.
		discoveryURL := c.issuerURL + wellKnownPath
		resp, err := c.httpClient.Get(fetchCtx, discoveryURL)
		if err != nil {
			return nil, fmt.Errorf("discovery: fetch %s: %w", discoveryURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf(
				"discovery: unexpected status %d from %s",
				resp.StatusCode,
				discoveryURL,
			)
		}

		var meta Metadata
		lr := &io.LimitedReader{R: resp.Body, N: maxResponseBytes + 1}
		if err := json.NewDecoder(lr).Decode(&meta); err != nil {
			if lr.N == 0 {
				return nil, fmt.Errorf("%w: %w", errResponseTooLarge, err)
			}
			return nil, fmt.Errorf("discovery: decode response: %w", err)
		}
		if lr.N == 0 {
			return nil, errResponseTooLarge
		}

		// Validate issuer matches the expected URL (OIDC Discovery 1.0 §4.3)
		issuer := strings.TrimRight(meta.Issuer, "/")
		if issuer != c.issuerURL {
			return nil, fmt.Errorf(
				"discovery: issuer mismatch: got %q, expected %q",
				meta.Issuer,
				c.issuerURL,
			)
		}

		// Signet uses a fixed device authorization path. Derive it from issuer
		// when not explicitly advertised in the discovery response.
		if meta.DeviceAuthorizationEndpoint == "" {
			meta.DeviceAuthorizationEndpoint = issuer + deviceCodePath
		}

		// Signet has /oauth/introspect but doesn't yet advertise it in discovery
		if meta.IntrospectionEndpoint == "" {
			meta.IntrospectionEndpoint = issuer + introspectionPath
		}

		c.mu.Lock()
		c.cached = &meta
		c.fetchedAt = time.Now()
		c.mu.Unlock()

		return &meta, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		// Clone per caller: singleflight hands the same value to every coalesced
		// caller, so cloning here keeps Fetch's "returned Metadata is a copy" contract.
		return cloneMetadata(res.Val.(*Metadata)), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
