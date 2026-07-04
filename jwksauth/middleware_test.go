package jwksauth

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
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIssuer is a minimal in-process OIDC issuer for tests. It serves a
// discovery document, a JWKS endpoint, and exposes Sign() so tests can
// mint tokens. Real JWKS-based verification (signature, iss/aud/exp/nbf)
// runs against it — this is not a stub.
type fakeIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	signer jose.Signer
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

	fi := &fakeIssuer{t: t, key: key, kid: kid, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fi.discovery)
	mux.HandleFunc("/jwks.json", fi.jwks)
	fi.server = httptest.NewServer(mux)
	t.Cleanup(fi.server.Close)
	return fi
}

func (f *fakeIssuer) URL() string { return f.server.URL }

func (f *fakeIssuer) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.server.URL,
		"jwks_uri":                              f.server.URL + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (f *fakeIssuer) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	jwk := jose.JSONWebKey{
		Key:       &f.key.PublicKey,
		KeyID:     f.kid,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

// Sign issues a JWT with the given claims. A negative ttl produces a
// past-`exp` (deterministically expired); audience="" omits the `aud`
// claim entirely (used to test SkipAudience).
func (f *fakeIssuer) Sign(
	t *testing.T,
	audience string,
	ttl time.Duration,
	extra map[string]any,
) string {
	t.Helper()
	now := time.Now()
	std := map[string]any{
		"iss": f.server.URL,
		"sub": "sub-1",
		"iat": now.Unix(),
		"nbf": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if audience != "" {
		std["aud"] = audience
	}
	maps.Copy(std, extra)
	raw, err := jwt.Signed(f.signer).Claims(std).Serialize()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return raw
}

func TestVerifier_HappyPath(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://example")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://example", 5*time.Minute, map[string]any{
		"client_id":             "cli",
		"scope":                 "email profile",
		"extra_domain":          "OA",
		"tenant":                "A76",
		"extra_service_account": "sync@oa",
		"extra_project":         "p1",
		"extra_uid":             "alice",
	})
	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.ClientID != "cli" {
		t.Errorf("ClientID = %q", info.Claims.ClientID)
	}
	if !info.HasScope("email") || !info.HasScope("profile") {
		t.Errorf("scopes = %v", info.Scopes)
	}
	if info.Domain() != "oa" {
		t.Errorf("Domain() = %q, want lower-cased 'oa'", info.Domain())
	}
	if info.Claims.UID != "alice" {
		t.Errorf("Claims.UID = %q, want alice", info.Claims.UID)
	}
	got, ok := info.Extra("tenant")
	if !ok {
		t.Errorf("Extra(\"tenant\") missing, want \"A76\"")
	} else if s, isStr := got.(string); !isStr || s != "A76" {
		t.Errorf("Extra(\"tenant\") = %v (%T), want \"A76\" (string)", got, got)
	}
}

// Client Credentials flow has no user, so the token does not carry
// extra_uid. Verify must succeed, Claims.UID must be empty (not panic,
// not pulled from anywhere else), and an empty AccessRule lets the
// request through with 200.
func TestVerifier_ClientCredentialsShape_UIDEmpty(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
		"client_id":     "cli",
		"scope":         "email",
		"extra_domain":  "oa",
		"extra_project": "p1",
	})

	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.UID != "" {
		t.Errorf(
			"Claims.UID = %q, want empty string (Client Credentials token has no user)",
			info.Claims.UID,
		)
	}

	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (AccessRule{} does not check UID)", rec.Code)
	}
}

func TestNewVerifier_RejectsEmptyAudience(t *testing.T) {
	cases := []string{"", "   ", "\t\n"}
	for _, aud := range cases {
		t.Run(fmt.Sprintf("aud=%q", aud), func(t *testing.T) {
			_, err := NewVerifier(t.Context(), "https://example.com", aud)
			if err == nil {
				t.Fatal("expected error for empty/whitespace audience")
			}
		})
	}
}

func TestNewMultiVerifier_RejectsEmptyAudience(t *testing.T) {
	cases := []string{"", "   "}
	for _, aud := range cases {
		t.Run(fmt.Sprintf("aud=%q", aud), func(t *testing.T) {
			_, err := NewMultiVerifier(t.Context(), []string{"https://example.com"}, aud)
			if err == nil {
				t.Fatal("expected error for empty/whitespace audience")
			}
		})
	}
}

func TestVerifierSkipAudience_AcceptsTokenWithoutAud(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifierSkipAudience(t.Context(), fi.URL())
	if err != nil {
		t.Fatalf("NewVerifierSkipAudience: %v", err)
	}
	// Sign a token without an `aud` claim by passing an empty audience.
	tok := fi.Sign(t, "", time.Minute, nil)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify rejected an aud-less token: %v", err)
	}
}

func TestVerifier_RejectsWrongAudience(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://expected")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://other", time.Minute, nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", -time.Minute, nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestMiddleware_AuthorizationHeaderHandling(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tests := []struct {
		name           string
		header         string // empty = no Authorization header at all
		wantStatus     int
		wantWWWAuth    string // exact match if non-empty
		wantWWWAuthSub string // substring match if non-empty
	}{
		// RFC 6750 §3: no credentials supplied → bare Bearer, no error attr.
		{"missing", "", http.StatusUnauthorized, "Bearer", ""},
		{"basic-scheme", "Basic dXNlcjpwYXNz", http.StatusUnauthorized, "Bearer", ""},
		// RFC 6750 §3.1: credentials supplied for Bearer but the request
		// itself is malformed → invalid_request (HTTP 400). invalid_token
		// is reserved for tokens that parsed but failed validation.
		{"bearer-no-token", "Bearer", http.StatusBadRequest, "", `error="invalid_request"`},
		{
			"bearer-trailing-junk",
			"Bearer abc def",
			http.StatusBadRequest,
			"",
			`error="invalid_request"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
				if tc.header != "" {
					req.Header.Set("Authorization", tc.header)
				}
			})
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			got := rec.Header().Get("WWW-Authenticate")
			if tc.wantWWWAuth != "" && got != tc.wantWWWAuth {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.wantWWWAuth)
			}
			if tc.wantWWWAuthSub != "" && !strings.Contains(got, tc.wantWWWAuthSub) {
				t.Errorf("WWW-Authenticate %q missing %q", got, tc.wantWWWAuthSub)
			}
		})
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer not.a.jwt")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("missing invalid_token challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestMiddleware_InsufficientScope(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"scope": "email"})
	rec := runMiddleware(t, v, AccessRule{Scopes: []string{"profile"}}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	want := []string{`error="insufficient_scope"`, `scope="profile"`}
	for _, s := range want {
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), s) {
			t.Errorf("WWW-Authenticate missing %q: %q", s, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestMiddleware_DomainAllowlist(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tests := []struct {
		name     string
		domain   string
		rule     []string
		wantCode int
	}{
		// Reject branch (already covered): 401 invalid_token, generic body.
		{"reject", "swrd", []string{"oa"}, http.StatusUnauthorized},
		// Accept branch: case-folded match (rule "OA" matches token "oa").
		{"accept_case_folded", "oa", []string{"OA"}, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": tc.domain})
			rec := runMiddleware(t, v, AccessRule{Domains: tc.rule}, func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tok)
			})
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}

func TestMiddleware_HappyPath_InjectsContext(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
		"scope":        "email",
		"extra_domain": "OA",
		"tenant":       "A76",
	})
	called := false
	handler := Middleware(v, AccessRule{
		Scopes:  []string{"email"},
		Domains: []string{"oa"},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("TokenInfoFromContext returned !ok")
			return
		}
		if info.Domain() != "oa" {
			t.Errorf("Domain = %q, want oa", info.Domain())
		}
		got, ok := info.Extra("tenant")
		if !ok {
			t.Errorf("Extra(\"tenant\") missing, want \"A76\"")
		} else if s, isStr := got.(string); !isStr || s != "A76" {
			t.Errorf("Extra(\"tenant\") = %v (%T), want \"A76\" (string)", got, got)
		}
		if info.Claims.Domain != "OA" {
			t.Errorf("Claims.Domain = %q, want OA", info.Claims.Domain)
		}
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
}

// TestMiddleware_DomainPresent_NoExtras pins the contract that a token
// carrying only the server-attested Domain (and no caller-supplied keys)
// is accepted when the Domain is in the allowlist; the handler observes
// a nil Claims.Extras map (newTokenInfo only allocates the map when at
// least one non-reserved key is present).
func TestMiddleware_DomainPresent_NoExtras(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "oa"})
	called := false
	handler := Middleware(v, AccessRule{
		Domains: []string{"oa"},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("TokenInfoFromContext returned !ok")
			return
		}
		if _, ok := info.Extra("tenant"); ok {
			t.Errorf("Extra(\"tenant\") = ok, want absent")
		}
		if info.Claims.Extras != nil {
			t.Errorf("Claims.Extras = %v, want nil", info.Claims.Extras)
		}
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestMiddleware_AcceptsTokenWithNoCustomClaims pins the contract that
// the SDK verifies any Signet-issued token regardless of which custom
// claims it carries. With AccessRule{} (no allowlists) and no
// SetIssuerDomains enforcement, only signature, iss, aud, exp, and nbf
// are checked — guaranteeing the SDK works regardless of whether the
// server emits any private claims at all.
func TestMiddleware_AcceptsTokenWithNoCustomClaims(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, nil)
	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMultiVerifier_RoutesByIssuer(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t)
	mv, err := NewMultiVerifier(t.Context(), []string{a.URL(), b.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}

	tokA := a.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "oa"})
	infoA, err := mv.Verify(context.Background(), tokA)
	if err != nil {
		t.Fatalf("Verify A: %v", err)
	}
	if infoA.Issuer != a.URL() {
		t.Errorf("issuer = %q, want %q", infoA.Issuer, a.URL())
	}

	tokB := b.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "swrd"})
	infoB, err := mv.Verify(context.Background(), tokB)
	if err != nil {
		t.Fatalf("Verify B: %v", err)
	}
	if infoB.Issuer != b.URL() {
		t.Errorf("issuer = %q, want %q", infoB.Issuer, b.URL())
	}
}

func TestMultiVerifier_RejectsUntrustedIssuer(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t) // built but not registered with mv

	mv, err := NewMultiVerifier(t.Context(), []string{a.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}
	tok := b.Sign(t, "api://x", time.Minute, nil)
	_, err = mv.Verify(context.Background(), tok)
	if !errors.Is(err, ErrUntrustedIssuer) {
		t.Fatalf("error = %v, want ErrUntrustedIssuer", err)
	}
}

func TestMultiVerifier_CrossDomainDefense(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t)
	mv, err := NewMultiVerifier(t.Context(), []string{a.URL(), b.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}
	if err := mv.SetIssuerDomains(fmt.Sprintf("%s=oa;%s=swrd", a.URL(), b.URL())); err != nil {
		t.Fatalf("SetIssuerDomains: %v", err)
	}

	// Issuer A claims domain 'swrd' (which belongs to B) → reject. The
	// error must not echo back the configured allowlist for this issuer.
	tok := a.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "swrd"})
	_, rejErr := mv.Verify(context.Background(), tok)
	if rejErr == nil {
		t.Fatal("expected cross-domain rejection")
	}
	if strings.Contains(rejErr.Error(), "[oa]") || strings.Contains(rejErr.Error(), "allowed=") {
		t.Errorf("error leaks the allowlist: %v", rejErr)
	}

	// Same issuer, its own domain → accept.
	tok = a.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "oa"})
	if _, err := mv.Verify(context.Background(), tok); err != nil {
		t.Fatalf("legit token rejected: %v", err)
	}
}

// TestMultiVerifier_SetIssuerDomainsRace exercises the documented contract
// that SetIssuerDomains is safe to call concurrently with Verify (the swap
// is atomic). Run with `go test -race ./jwksauth/`.
func TestMultiVerifier_SetIssuerDomainsRace(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t)
	mv, err := NewMultiVerifier(t.Context(), []string{a.URL(), b.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}
	tok := a.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "oa"})

	stop := make(chan struct{})
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = mv.Verify(context.Background(), tok)
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		cfg := fmt.Sprintf("%s=oa;%s=swrd", a.URL(), b.URL())
		for i := range 50 {
			if i%2 == 0 {
				_ = mv.SetIssuerDomains(cfg)
			} else {
				_ = mv.SetIssuerDomains("")
			}
		}
	}()

	<-done
	close(stop)
	<-done
}

// stubVerifier is a TokenVerifier that always returns the configured err
// — used to drive Middleware down the transient-vs-validation branch.
type stubVerifier struct{ err error }

func (s stubVerifier) Verify(_ context.Context, _ string) (*TokenInfo, error) {
	return nil, s.err
}

func TestMiddleware_TransientVerifierError(t *testing.T) {
	v := stubVerifier{err: context.DeadlineExceeded}
	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		// Real-looking JWT shape so ExtractBearerToken treats it as present.
		req.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	want := `error="temporarily_unavailable"`
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, want) {
		t.Errorf("WWW-Authenticate %q missing %q", got, want)
	}
}

func TestMiddleware_NonTransientVerifierError(t *testing.T) {
	v := stubVerifier{err: errors.New("signature: invalid")}
	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	want := `error="invalid_token"`
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, want) {
		t.Errorf("WWW-Authenticate %q missing %q", got, want)
	}
}

// runMiddleware wires up a Middleware around a 200-OK inner handler and
// returns the recorded response. modify can mutate the request before send.
func runMiddleware(
	t *testing.T,
	v TokenVerifier,
	rule AccessRule,
	modify func(*http.Request),
	opts ...MiddlewareOption,
) *httptest.ResponseRecorder {
	t.Helper()
	handler := Middleware(v, rule, opts...)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if modify != nil {
		modify(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

type capturedLog struct {
	level string
	msg   string
	args  []any
}

type captureLogger struct {
	records []capturedLog
}

func (c *captureLogger) Warn(msg string, args ...any) {
	c.records = append(c.records, capturedLog{level: "warn", msg: msg, args: args})
}

func (c *captureLogger) Error(msg string, args ...any) {
	c.records = append(c.records, capturedLog{level: "error", msg: msg, args: args})
}

// argValue looks up the value paired with key in slog-style alternating
// key/value args, returning (value, true) on match or (nil, false) when
// the key is absent. Test args are well-formed by construction, so the
// helper does not separately signal malformed input.
func argValue(args []any, key string) (any, bool) {
	for i := 0; i+1 < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			return nil, false
		}
		if k == key {
			return args[i+1], true
		}
	}
	return nil, false
}

func TestMiddleware_HappyPath_ProducesNoLog(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, nil)

	cl := &captureLogger{}
	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	}, WithLogger(cl))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if len(cl.records) != 0 {
		t.Errorf("expected no log records, got %+v", cl.records)
	}
}

func TestMiddleware_LogsTokenVerificationFailure(t *testing.T) {
	verifyErr := errors.New("signature: invalid")
	cl := &captureLogger{}
	rec := runMiddleware(t, stubVerifier{err: verifyErr}, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
	}, WithLogger(cl))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if len(cl.records) != 1 {
		t.Fatalf("want 1 log record, got %d: %+v", len(cl.records), cl.records)
	}
	rec0 := cl.records[0]
	if rec0.level != "warn" {
		t.Errorf("level = %q, want warn", rec0.level)
	}
	if rec0.msg != "jwksauth: token verification failed" {
		t.Errorf("msg = %q", rec0.msg)
	}
	got, ok := argValue(rec0.args, "err")
	if !ok {
		t.Fatalf("missing err arg in %+v", rec0.args)
	}
	if got != verifyErr {
		t.Errorf("err arg = %v, want %v", got, verifyErr)
	}
}

func TestMiddleware_LogsPolicyReject(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "swrd"})

	cl := &captureLogger{}
	rec := runMiddleware(t, v, AccessRule{Domains: []string{"oa"}}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	}, WithLogger(cl))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate %q missing invalid_token", rec.Header().Get("WWW-Authenticate"))
	}
	if len(cl.records) != 1 {
		t.Fatalf("want 1 log record, got %d: %+v", len(cl.records), cl.records)
	}
	rec0 := cl.records[0]
	if rec0.level != "warn" {
		t.Errorf("level = %q, want warn", rec0.level)
	}
	if rec0.msg != "jwksauth: policy reject" {
		t.Errorf("msg = %q", rec0.msg)
	}
	for _, key := range []string{"reason", "sub", "iss"} {
		if _, ok := argValue(rec0.args, key); !ok {
			t.Errorf("missing %q in args %+v", key, rec0.args)
		}
	}
	if iss, _ := argValue(rec0.args, "iss"); iss != fi.URL() {
		t.Errorf("iss arg = %v, want %q", iss, fi.URL())
	}
}
