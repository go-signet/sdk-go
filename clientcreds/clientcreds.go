// Package clientcreds provides a thread-safe TokenSource for the
// OAuth 2.0 Client Credentials grant (RFC 6749 §4.4).
//
// It automatically caches tokens and refreshes them before expiry,
// making it ideal for service-to-service (M2M) authentication.
package clientcreds

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/go-signet/sdk-go/oauth"
)

const defaultExpiryDelta = 30 * time.Second

// fetchTimeout caps the singleflight client-credentials round-trip. Because the
// shared fetch is detached from the first caller's context (see Token), this
// bound is what stops a hung server from making the shared goroutine outlive
// every caller. Mirrors authflow.refreshTimeout.
const fetchTimeout = 30 * time.Second

// Option configures a TokenSource.
type Option func(*TokenSource)

// WithScopes sets the scopes to request.
func WithScopes(scopes ...string) Option {
	return func(ts *TokenSource) {
		ts.scopes = scopes
	}
}

// WithExpiryDelta sets how early before expiry to refresh the token.
func WithExpiryDelta(d time.Duration) Option {
	return func(ts *TokenSource) {
		ts.expiryDelta = d
	}
}

// TokenSource is a thread-safe, auto-caching token source for client credentials.
type TokenSource struct {
	client      *oauth.Client
	scopes      []string
	expiryDelta time.Duration

	mu    sync.RWMutex
	token *oauth.Token
	group singleflight.Group
}

// NewTokenSource creates a new client credentials TokenSource.
func NewTokenSource(client *oauth.Client, opts ...Option) *TokenSource {
	ts := &TokenSource{
		client:      client,
		expiryDelta: defaultExpiryDelta,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(ts)
		}
	}
	return ts
}

// Token returns a valid access token, fetching a new one if the cached token
// is expired or about to expire. Concurrent callers share a single in-flight
// fetch request via singleflight.
func (ts *TokenSource) Token(ctx context.Context) (*oauth.Token, error) {
	// Fast path: read-lock to check cache
	ts.mu.RLock()
	if ts.isValid() {
		tok := ts.token
		ts.mu.RUnlock()
		return tok, nil
	}
	ts.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Slow path: coalesce concurrent fetches via singleflight. DoChan (not Do)
	// plus the select below lets each caller honor its own cancellation, and
	// context.WithoutCancel detaches the shared fetch from the first caller's
	// ctx so one caller's cancellation cannot fail every waiter. The bounded
	// fetchTimeout replaces the deadline that WithoutCancel strips. Mirrors
	// authflow.TokenSource.Token.
	ch := ts.group.DoChan("token", func() (any, error) {
		// Re-check cache: another goroutine's singleflight may have just
		// populated it before this call started.
		ts.mu.RLock()
		if ts.isValid() {
			tok := ts.token
			ts.mu.RUnlock()
			return tok, nil
		}
		ts.mu.RUnlock()

		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		defer cancel()

		// Network call happens outside any lock
		token, fetchErr := ts.client.ClientCredentials(fetchCtx, ts.scopes)
		if fetchErr != nil {
			return nil, fmt.Errorf("clientcreds: fetch token: %w", fetchErr)
		}

		ts.mu.Lock()
		ts.token = token
		ts.mu.Unlock()

		return token, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*oauth.Token), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// isValid reports whether the cached token is still usable.
// Must be called with ts.mu held (read or write).
func (ts *TokenSource) isValid() bool {
	if ts.token == nil || ts.token.AccessToken == "" {
		return false
	}
	if ts.token.ExpiresAt.IsZero() {
		return true
	}
	return time.Now().Add(ts.expiryDelta).Before(ts.token.ExpiresAt)
}

// HTTPClient returns an *http.Client that automatically attaches a valid
// Bearer token to every request.
func (ts *TokenSource) HTTPClient() *http.Client {
	return &http.Client{
		Transport: ts.RoundTripper(http.DefaultTransport),
	}
}

// RoundTripper returns an http.RoundTripper that attaches a Bearer token
// to every request. It wraps the given base transport.
func (ts *TokenSource) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return &tokenTransport{
		source: ts,
		base:   base,
	}
}

type tokenTransport struct {
	source *TokenSource
	base   http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.source.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("clientcreds: get token for request: %w", err)
	}

	// Clone the request to avoid mutating the original
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return t.base.RoundTrip(r2)
}
