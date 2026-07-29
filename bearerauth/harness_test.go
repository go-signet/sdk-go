package bearerauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/go-signet/sdk-go/bearerauth"
	"github.com/go-signet/sdk-go/jwksauth"
)

const (
	testAudience    = "api://test"
	testClientApp   = "my-client-app"
	validKey        = "sgk_" + "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"
	introspectionID = "my-client-app"
	introspectionPW = "s3cr3t-value-do-not-leak"
)

// ---------------------------------------------------------------------------
// In-process JWKS issuer
// ---------------------------------------------------------------------------

// fakeIssuer is a real in-process OIDC issuer: it serves a discovery document
// and a JWKS, and mints signed tokens. Verification in these tests therefore
// exercises actual signature/iss/aud/exp checking rather than a stub.
type fakeIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	signer jose.Signer

	// online serves /oauth/tokeninfo and /oauth/introspect on the same host,
	// so tests can exercise the discovery-driven [bearerauth.New] against a
	// single origin the way a real Signet deployment looks.
	online *recorder

	// discoveryExtra is merged into the discovery document, so a test can make
	// the issuer advertise endpoints it would not normally publish.
	discoveryExtra map[string]any
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	kid := fmt.Sprintf("kid-%d", time.Now().UnixNano())
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	fi := &fakeIssuer{
		key:    key,
		kid:    kid,
		signer: signer,
		online: &recorder{handler: func(http.ResponseWriter, *http.Request) {}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fi.discovery)
	mux.HandleFunc("/jwks.json", fi.jwks)
	mux.Handle("/oauth/tokeninfo", fi.online)
	mux.Handle("/oauth/introspect", fi.online)
	fi.server = httptest.NewServer(mux)
	t.Cleanup(fi.server.Close)
	return fi
}

// serveOnline installs the handler for this issuer's own tokeninfo and
// introspection endpoints and resets the recorded requests.
func (f *fakeIssuer) serveOnline(h http.HandlerFunc) {
	f.online.mu.Lock()
	defer f.online.mu.Unlock()
	f.online.handler = h
	f.online.reqs = nil
}

func (f *fakeIssuer) URL() string { return f.server.URL }

func (f *fakeIssuer) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                f.server.URL,
		"jwks_uri":                              f.server.URL + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	maps.Copy(doc, f.discoveryExtra)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIssuer) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &f.key.PublicKey,
		KeyID:     f.kid,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}}})
}

// sign mints a token with Signet-shaped defaults; extra overrides any claim,
// and a negative ttl produces a deterministically expired token.
func (f *fakeIssuer) sign(t *testing.T, ttl time.Duration, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":       f.server.URL,
		"sub":       "user-1",
		"aud":       testAudience,
		"iat":       now.Unix(),
		"nbf":       now.Add(-30 * time.Second).Unix(),
		"exp":       now.Add(ttl).Unix(),
		"type":      "access",
		"client_id": testClientApp,
		"scope":     "read write",
	}
	maps.Copy(claims, extra)
	raw, err := jwt.Signed(f.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func (f *fakeIssuer) verifier(t *testing.T) *jwksauth.Verifier {
	t.Helper()
	v, err := jwksauth.NewVerifier(t.Context(), f.URL(), testAudience)
	if err != nil {
		t.Fatalf("jwksauth.NewVerifier: %v", err)
	}
	return v
}

// ---------------------------------------------------------------------------
// JWT verifier decorators
// ---------------------------------------------------------------------------

// countingVerifier records how many times the JWT path was entered, which is
// how the tests prove an `sgk_` candidate never falls through to it.
type countingVerifier struct {
	inner jwksauth.TokenVerifier
	calls atomic.Int64
}

func (c *countingVerifier) Verify(
	ctx context.Context,
	raw string,
) (*jwksauth.TokenInfo, error) {
	c.calls.Add(1)
	return c.inner.Verify(ctx, raw)
}

// stubVerifier returns a fixed result, including the hostile shapes a custom
// TokenVerifier implementation may produce.
type stubVerifier struct {
	info *jwksauth.TokenInfo
	err  error
}

func (s stubVerifier) Verify(context.Context, string) (*jwksauth.TokenInfo, error) {
	return s.info, s.err
}

// typedNilVerifier exists only so a test can pass a nil *typedNilVerifier as a
// non-nil interface value. Its method is never reached: the constructor has to
// reject the typed nil before any request can call it.
type typedNilVerifier struct{}

var errUnreachableVerifier = errors.New("verify must not be called")

func (*typedNilVerifier) Verify(context.Context, string) (*jwksauth.TokenInfo, error) {
	return nil, errUnreachableVerifier
}

// ---------------------------------------------------------------------------
// In-process Signet online endpoints
// ---------------------------------------------------------------------------

// recordedRequest captures what actually reached the online endpoint so tests
// can assert the wire shape (method, header, absence of a query credential)
// and the exact upstream attempt count.
type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Form   url.Values
}

// recorder is an http.Handler that records every request before delegating.
// It is mounted both standalone (onlineServer) and on the fake issuer's own
// mux, so both wiring styles report attempt counts the same way.
type recorder struct {
	mu      sync.Mutex
	reqs    []recordedRequest
	handler http.HandlerFunc
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := recordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.RawQuery,
		Auth:   r.Header.Get("Authorization"),
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		rec.Form = r.PostForm
	}

	rc.mu.Lock()
	rc.reqs = append(rc.reqs, rec)
	handler := rc.handler
	rc.mu.Unlock()

	handler(w, r)
}

func (rc *recorder) requests() []recordedRequest {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]recordedRequest(nil), rc.reqs...)
}

func (rc *recorder) count() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.reqs)
}

type onlineServer struct {
	*recorder

	server *httptest.Server
}

// newOnlineServer starts a server whose response is decided by handler.
func newOnlineServer(t *testing.T, handler http.HandlerFunc) *onlineServer {
	t.Helper()
	s := &onlineServer{recorder: &recorder{handler: handler}}
	s.server = httptest.NewServer(s.recorder)
	t.Cleanup(s.server.Close)
	return s
}

func (s *onlineServer) tokenInfoURL() string     { return s.server.URL + "/oauth/tokeninfo" }
func (s *onlineServer) introspectionURL() string { return s.server.URL + "/oauth/introspect" }

// writeJSON is the shared success-response helper.
func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// activeTokenInfo is the tokeninfo payload Signet returns for a healthy
// Personal API Key.
func activeTokenInfo(issuer string, overrides map[string]any) map[string]any {
	body := map[string]any{
		"active":       true,
		"user_id":      "user-1",
		"client_id":    testClientApp,
		"scope":        "write read",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"iss":          issuer,
		"subject_type": "user",
		"token_type":   "personal_api_key",
	}
	maps.Copy(body, overrides)
	return body
}

// activeIntrospection is the introspection payload Signet returns for a
// healthy Personal API Key owned by the introspecting client.
func activeIntrospection(issuer string, overrides map[string]any) map[string]any {
	body := map[string]any{
		"active":     true,
		"sub":        "user-1",
		"client_id":  testClientApp,
		"scope":      "write read",
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Add(-time.Minute).Unix(),
		"iss":        issuer,
		"jti":        "jti-should-not-surface",
		"username":   "username-should-not-surface",
		"token_type": "personal_api_key",
	}
	maps.Copy(body, overrides)
	return body
}

// ---------------------------------------------------------------------------
// Verifier construction helpers
// ---------------------------------------------------------------------------

func defaultPolicy(issuer string, scopes ...string) bearerauth.Policy {
	return bearerauth.Policy{
		Issuer:         issuer,
		ClientAppID:    testClientApp,
		RequiredScopes: scopes,
	}
}

func newTokenInfoVerifier(
	t *testing.T,
	jv jwksauth.TokenVerifier,
	s *onlineServer,
	policy bearerauth.Policy,
	opts ...bearerauth.Option,
) *bearerauth.Verifier {
	t.Helper()
	v, err := bearerauth.NewTokenInfoVerifier(jv, s.tokenInfoURL(), policy, opts...)
	if err != nil {
		t.Fatalf("NewTokenInfoVerifier: %v", err)
	}
	return v
}

func newIntrospectionVerifier(
	t *testing.T,
	jv jwksauth.TokenVerifier,
	s *onlineServer,
	policy bearerauth.Policy,
	opts ...bearerauth.Option,
) *bearerauth.Verifier {
	t.Helper()
	v, err := bearerauth.NewIntrospectionVerifier(
		jv, s.introspectionURL(), introspectionID, introspectionPW, policy, opts...,
	)
	if err != nil {
		t.Fatalf("NewIntrospectionVerifier: %v", err)
	}
	return v
}

// assertNoSecrets fails when a user-visible error string echoes any credential
// material. Errors are the only thing this package hands to a framework
// adapter, so they are the leak surface that matters.
func assertNoSecrets(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(msg, s) {
			t.Errorf("error leaked credential material %q: %s", s, msg)
		}
	}
}

// countingTransport counts round-trips so a test can prove which HTTP client
// carried a given request.
type countingTransport struct {
	calls atomic.Int64
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return http.DefaultTransport.RoundTrip(req)
}

func newTrackedRetryClient(t *testing.T, transport http.RoundTripper) *retry.Client {
	t.Helper()
	client, err := retry.NewRealtimeClient(
		retry.WithNoLogging(),
		retry.WithHTTPClient(&http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}),
	)
	if err != nil {
		t.Fatalf("retry.NewRealtimeClient: %v", err)
	}
	return client
}
