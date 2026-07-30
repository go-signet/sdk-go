package bearerauth_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/bearerauth"
	"github.com/go-signet/sdk-go/jwksauth"
)

// ---------------------------------------------------------------------------
// Acceptance test 1 — happy path, both credential kinds, one policy
// ---------------------------------------------------------------------------

func TestVerifyHappyPathBothCredentialKinds(t *testing.T) {
	modes := []struct {
		name          string
		buildVerifier func(
			*testing.T, jwksauth.TokenVerifier, *onlineServer, bearerauth.Policy,
			...bearerauth.Option,
		) *bearerauth.Verifier
		handler func(issuer string) http.HandlerFunc
	}{
		{
			name:          "tokeninfo",
			buildVerifier: newTokenInfoVerifier,
			handler: func(issuer string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
				}
			},
		},
		{
			name:          "introspection",
			buildVerifier: newIntrospectionVerifier,
			handler: func(issuer string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusOK, activeIntrospection(issuer, nil))
				}
			},
		},
	}

	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			fi := newFakeIssuer(t)
			jv := fi.verifier(t)
			issuer := jv.Issuer()
			counting := &countingVerifier{inner: jv}

			srv := newOnlineServer(t, mode.handler(issuer))
			v := mode.buildVerifier(t, counting, srv, defaultPolicy(issuer, "read"))

			jwtIdentity, err := v.Verify(t.Context(), fi.sign(t, time.Hour, nil))
			if err != nil {
				t.Fatalf("Verify(jwt): %v", err)
			}
			keyIdentity, err := v.Verify(t.Context(), validKey)
			if err != nil {
				t.Fatalf("Verify(personal api key): %v", err)
			}

			// Fields both wire contracts define must be identical.
			if jwtIdentity.Subject != keyIdentity.Subject {
				t.Errorf("Subject: jwt=%q key=%q", jwtIdentity.Subject, keyIdentity.Subject)
			}
			if jwtIdentity.SubjectType != keyIdentity.SubjectType {
				t.Errorf(
					"SubjectType: jwt=%q key=%q",
					jwtIdentity.SubjectType, keyIdentity.SubjectType,
				)
			}
			if jwtIdentity.Issuer != keyIdentity.Issuer {
				t.Errorf("Issuer: jwt=%q key=%q", jwtIdentity.Issuer, keyIdentity.Issuer)
			}
			if jwtIdentity.ClientID != keyIdentity.ClientID {
				t.Errorf(
					"ClientID: jwt=%q key=%q",
					jwtIdentity.ClientID, keyIdentity.ClientID,
				)
			}
			if !slices.Equal(jwtIdentity.Scopes, keyIdentity.Scopes) {
				t.Errorf("Scopes: jwt=%v key=%v", jwtIdentity.Scopes, keyIdentity.Scopes)
			}

			// Scopes are canonicalized, so the JWT's "read write" and the
			// online "write read" collapse to the same sorted slice.
			if want := []string{"read", "write"}; !slices.Equal(jwtIdentity.Scopes, want) {
				t.Errorf("Scopes = %v, want %v", jwtIdentity.Scopes, want)
			}
			for _, id := range []*bearerauth.Identity{jwtIdentity, keyIdentity} {
				if !id.HasScope("read") || !id.HasScope("write") {
					t.Errorf("HasScope: %v missing a granted scope", id.Scopes)
				}
				if id.HasScope("admin") || id.HasScope("READ") {
					t.Errorf("HasScope: %v matched an ungranted scope", id.Scopes)
				}
				if id.SubjectType != bearerauth.SubjectUser {
					t.Errorf("SubjectType = %q, want %q", id.SubjectType, bearerauth.SubjectUser)
				}
				if id.Issuer != issuer {
					t.Errorf("Issuer = %q, want %q", id.Issuer, issuer)
				}
				if !id.ExpiresAt.After(time.Now()) {
					t.Errorf("ExpiresAt = %v, want a future time", id.ExpiresAt)
				}
			}

			// The credential kinds stay distinguishable.
			if jwtIdentity.CredentialType != bearerauth.CredentialJWT {
				t.Errorf("CredentialType = %q, want jwt", jwtIdentity.CredentialType)
			}
			if keyIdentity.CredentialType != bearerauth.CredentialPersonalAPIKey {
				t.Errorf(
					"CredentialType = %q, want personal_api_key",
					keyIdentity.CredentialType,
				)
			}

			// One JWT verification, exactly one upstream call.
			if got := counting.calls.Load(); got != 1 {
				t.Errorf("jwt verifier calls = %d, want 1", got)
			}
			if got := srv.count(); got != 1 {
				t.Errorf("upstream requests = %d, want 1", got)
			}
		})
	}
}

func TestVerifyJWTClientSubject(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	srv := newOnlineServer(t, func(http.ResponseWriter, *http.Request) {})
	v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))

	raw := fi.sign(t, time.Hour, map[string]any{"sub": "client:" + testClientApp})
	id, err := v.Verify(t.Context(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.SubjectType != bearerauth.SubjectClient {
		t.Errorf("SubjectType = %q, want %q", id.SubjectType, bearerauth.SubjectClient)
	}
	if id.Subject != "client:"+testClientApp {
		t.Errorf("Subject = %q", id.Subject)
	}
}

// ---------------------------------------------------------------------------
// Request shape
// ---------------------------------------------------------------------------

func TestTokenInfoRequestShape(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, activeTokenInfo(jv.Issuer(), nil))
	})
	v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))

	if _, err := v.Verify(t.Context(), validKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	req := reqs[0]
	if req.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.Path != "/oauth/tokeninfo" {
		t.Errorf("Path = %q", req.Path)
	}
	if req.Auth != "Bearer "+validKey {
		t.Errorf("Authorization = %q, want canonical Bearer header", req.Auth)
	}
	if req.Query != "" {
		t.Errorf("Query = %q, want no query string", req.Query)
	}
	if strings.Contains(req.Query, "sgk_") {
		t.Error("personal API key appeared in the query string")
	}
}

func TestIntrospectionRequestShape(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, activeIntrospection(jv.Issuer(), nil))
	})
	v := newIntrospectionVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))

	if _, err := v.Verify(t.Context(), validKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	req := reqs[0]
	if req.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.Path != "/oauth/introspect" {
		t.Errorf("Path = %q", req.Path)
	}
	if got := req.Form.Get("token"); got != validKey {
		t.Errorf("form token = %q, want the personal API key", got)
	}
	if got := req.Form.Get("client_id"); got != introspectionID {
		t.Errorf("form client_id = %q, want %q", got, introspectionID)
	}
	if got := req.Form.Get("client_secret"); got != introspectionPW {
		t.Errorf("form client_secret = %q, want the configured secret", got)
	}
	if _, ok := req.Form["token_type_hint"]; ok {
		t.Error("form carried token_type_hint, want it omitted")
	}
	if req.Query != "" {
		t.Errorf("Query = %q, want credentials only in the body", req.Query)
	}
	if req.Auth != "" {
		t.Errorf("Authorization = %q, want form-based client authentication", req.Auth)
	}
}

// ---------------------------------------------------------------------------
// Acceptance test 2 — credential rejection, no cross-path fallback
// ---------------------------------------------------------------------------

func TestVerifyCredentialRejection(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	issuer := jv.Issuer()
	other := newFakeIssuer(t)

	tests := []struct {
		name         string
		credential   func(*testing.T) string
		handler      http.HandlerFunc
		wantJWTCalls int64
		wantUpstream int
	}{
		{
			name:       "empty credential",
			credential: func(*testing.T) string { return "" },
		},
		{
			name:       "whitespace only credential",
			credential: func(*testing.T) string { return "   " },
		},
		{
			name:       "personal api key wrong length",
			credential: func(*testing.T) string { return "sgk_short" },
		},
		{
			name:       "personal api key uppercase",
			credential: func(*testing.T) string { return "sgk_" + strings.ToUpper(validKey[4:]) },
		},
		{
			name: "personal api key invalid base32 character",
			credential: func(*testing.T) string {
				return "sgk_" + strings.Repeat("a", 51) + "1"
			},
		},
		{
			name:       "personal api key display hint",
			credential: func(*testing.T) string { return "sgk_abcd…wxyz" },
		},
		{
			name:       "personal api key with surrounding whitespace",
			credential: func(*testing.T) string { return validKey + " " },
		},
		{
			name:       "inactive personal api key",
			credential: func(*testing.T) string { return validKey },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{"active": false})
			},
			wantUpstream: 1,
		},
		{
			name:       "revoked personal api key",
			credential: func(*testing.T) string { return validKey },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error":             "invalid_token",
					"error_description": "token is invalid",
				})
			},
			wantUpstream: 1,
		},
		{
			name: "expired jwt",
			credential: func(t *testing.T) string {
				return fi.sign(t, -time.Minute, nil)
			},
			wantJWTCalls: 1,
		},
		{
			name: "jwt signed by another issuer",
			credential: func(t *testing.T) string {
				return other.sign(t, time.Hour, nil)
			},
			wantJWTCalls: 1,
		},
		{
			name:         "garbage jwt",
			credential:   func(*testing.T) string { return "not-a-jwt" },
			wantJWTCalls: 1,
		},
		{
			name: "refresh jwt",
			credential: func(t *testing.T) string {
				return fi.sign(t, time.Hour, map[string]any{"type": "refresh"})
			},
			wantJWTCalls: 1,
		},
		{
			name: "jwt without type claim",
			credential: func(t *testing.T) string {
				return fi.sign(t, time.Hour, map[string]any{"type": nil})
			},
			wantJWTCalls: 1,
		},
		{
			name: "jwt without client id",
			credential: func(t *testing.T) string {
				return fi.sign(t, time.Hour, map[string]any{"client_id": ""})
			},
			wantJWTCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					t.Error("upstream endpoint must not be called")
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
			srv := newOnlineServer(t, handler)
			counting := &countingVerifier{inner: jv}
			v := newTokenInfoVerifier(t, counting, srv, defaultPolicy(issuer))

			credential := tt.credential(t)
			id, err := v.Verify(t.Context(), credential)
			if id != nil {
				t.Errorf("Verify returned an identity %+v, want nil", id)
			}
			if !errors.Is(err, bearerauth.ErrInvalidCredential) {
				t.Fatalf("err = %v, want ErrInvalidCredential", err)
			}
			assertNoSecrets(t, err, credential, validKey, introspectionPW)

			if got := counting.calls.Load(); got != tt.wantJWTCalls {
				t.Errorf("jwt verifier calls = %d, want %d", got, tt.wantJWTCalls)
			}
			if got := srv.count(); got != tt.wantUpstream {
				t.Errorf("upstream requests = %d, want %d", got, tt.wantUpstream)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Acceptance test 3 — policy parity across both credential paths
// ---------------------------------------------------------------------------

func TestVerifyPolicyParity(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	issuer := jv.Issuer()

	cases := []struct {
		name         string
		policy       bearerauth.Policy
		jwtClaims    map[string]any
		onlineExtra  map[string]any
		wantSentinel error
		wantMissing  string
	}{
		{
			name: "issuer mismatch",
			policy: bearerauth.Policy{
				Issuer:   issuer + "/other",
				ClientID: testClientApp,
			},
			wantSentinel: bearerauth.ErrUntrustedIssuer,
		},
		{
			name:         "client app mismatch",
			policy:       bearerauth.Policy{Issuer: issuer, ClientID: "another-app"},
			wantSentinel: bearerauth.ErrClientAppNotAllowed,
		},
		{
			name:         "client app differs only by case",
			policy:       bearerauth.Policy{Issuer: issuer, ClientID: "MY-CLIENT-APP"},
			wantSentinel: bearerauth.ErrClientAppNotAllowed,
		},
		{
			name:         "missing scope",
			policy:       defaultPolicy(issuer, "write", "admin", "read"),
			wantSentinel: bearerauth.ErrInsufficientScope,
			wantMissing:  "admin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The same policy failure must come out of both paths.
			paths := []struct {
				name   string
				verify func(*testing.T) (*bearerauth.Identity, error)
			}{
				{
					name: "jwt",
					verify: func(t *testing.T) (*bearerauth.Identity, error) {
						srv := newOnlineServer(t, func(http.ResponseWriter, *http.Request) {
							t.Error("jwt path must not call the online endpoint")
						})
						v := newTokenInfoVerifier(t, jv, srv, tc.policy)
						return v.Verify(t.Context(), fi.sign(t, time.Hour, tc.jwtClaims))
					},
				},
				{
					name: "personal api key",
					verify: func(t *testing.T) (*bearerauth.Identity, error) {
						srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
							writeJSON(w, http.StatusOK, activeTokenInfo(issuer, tc.onlineExtra))
						})
						v := newTokenInfoVerifier(t, jv, srv, tc.policy)
						return v.Verify(t.Context(), validKey)
					},
				},
			}

			for _, path := range paths {
				t.Run(path.name, func(t *testing.T) {
					id, err := path.verify(t)
					if id != nil {
						t.Errorf("Verify returned a partial identity %+v, want nil", id)
					}
					if !errors.Is(err, tc.wantSentinel) {
						t.Fatalf("err = %v, want %v", err, tc.wantSentinel)
					}
					if tc.wantMissing != "" {
						var scopeErr *bearerauth.InsufficientScopeError
						if !errors.As(err, &scopeErr) {
							t.Fatalf("err = %v, want *InsufficientScopeError", err)
						}
						if scopeErr.MissingScope != tc.wantMissing {
							t.Errorf(
								"MissingScope = %q, want %q",
								scopeErr.MissingScope, tc.wantMissing,
							)
						}
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

func TestConstructorValidation(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	good := defaultPolicy(jv.Issuer())
	const endpoint = "https://auth.example.com/oauth/tokeninfo"

	t.Run("tokeninfo", func(t *testing.T) {
		tests := []struct {
			name     string
			verifier jwksauth.TokenVerifier
			url      string
			policy   bearerauth.Policy
			wantIn   string
		}{
			{name: "nil verifier", verifier: nil, url: endpoint, policy: good},
			{
				name:     "typed nil verifier",
				verifier: (*typedNilVerifier)(nil),
				url:      endpoint,
				policy:   good,
			},
			{name: "empty url", verifier: jv, url: "", policy: good},
			{name: "blank url", verifier: jv, url: "   ", policy: good},
			{name: "relative url", verifier: jv, url: "/oauth/tokeninfo", policy: good},
			{name: "no host", verifier: jv, url: "https://", policy: good},
			{name: "wrong scheme", verifier: jv, url: "ftp://example.com", policy: good},
			{
				name:     "empty issuer",
				verifier: jv,
				url:      endpoint,
				policy:   bearerauth.Policy{ClientID: testClientApp},
			},
			{
				name:     "issuer with whitespace",
				verifier: jv,
				url:      endpoint,
				policy: bearerauth.Policy{
					Issuer:   " https://auth.example.com ",
					ClientID: testClientApp,
				},
			},
			{
				name:     "empty client app",
				verifier: jv,
				url:      endpoint,
				policy:   bearerauth.Policy{Issuer: jv.Issuer()},
				wantIn:   "Policy.ClientID",
			},
			{
				// Compared byte-for-byte against the credential's client_id,
				// exactly like Issuer. A ConfigMap or env-file value carrying a
				// stray newline would otherwise construct cleanly and then deny
				// 100% of traffic with no startup signal.
				name:     "client app with whitespace",
				verifier: jv,
				url:      endpoint,
				policy: bearerauth.Policy{
					Issuer:   jv.Issuer(),
					ClientID: testClientApp + "\n",
				},
				wantIn: "Policy.ClientID",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				v, err := bearerauth.NewTokenInfoVerifier(tt.verifier, tt.url, tt.policy)
				if err == nil {
					t.Fatalf("NewTokenInfoVerifier = %v, want an error", v)
				}
				if v != nil {
					t.Errorf("verifier = %v, want nil", v)
				}
				if tt.wantIn != "" && !strings.Contains(err.Error(), tt.wantIn) {
					t.Errorf("err = %v, want it to mention %q", err, tt.wantIn)
				}
				// Configuration errors are not Verify categories.
				for _, sentinel := range []error{
					bearerauth.ErrInvalidCredential,
					bearerauth.ErrUntrustedIssuer,
					bearerauth.ErrClientAppNotAllowed,
					bearerauth.ErrInsufficientScope,
					bearerauth.ErrVerifierUnavailable,
				} {
					if errors.Is(err, sentinel) {
						t.Errorf("constructor error matched Verify sentinel %v", sentinel)
					}
				}
			})
		}
	})

	t.Run("introspection requires client credentials", func(t *testing.T) {
		tests := []struct {
			name         string
			clientID     string
			clientSecret string
		}{
			{name: "missing both"},
			{name: "missing secret", clientID: introspectionID},
			// A secret file or env var holding only a newline is the realistic
			// shape here: it is non-empty, so a bare == "" check accepts it and
			// the deployment 401s on every request forever.
			{name: "blank secret", clientID: introspectionID, clientSecret: " \n\t"},
			{name: "missing id", clientSecret: introspectionPW},
			{name: "blank id", clientID: "  ", clientSecret: introspectionPW},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				v, err := bearerauth.NewIntrospectionVerifier(
					jv, endpoint, tt.clientID, tt.clientSecret, good,
				)
				if err == nil {
					t.Fatalf("NewIntrospectionVerifier = %v, want an error", v)
				}
				assertNoSecrets(t, err, introspectionPW)
			})
		}
	})

	t.Run("tokeninfo takes no client credentials", func(t *testing.T) {
		// A compile-time property: the tokeninfo constructor has no client
		// ID/secret parameters, so it cannot be handed confidential
		// credentials by mistake. Assert the resulting request carries none.
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, activeTokenInfo(jv.Issuer(), nil))
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))
		if _, err := v.Verify(t.Context(), validKey); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		req := srv.requests()[0]
		if req.Query != "" || req.Form != nil {
			t.Errorf("tokeninfo request carried extra parameters: %+v", req)
		}
	})
}

func TestPolicyScopesClonedAtConstruction(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, activeTokenInfo(jv.Issuer(), nil))
	})

	scopes := []string{"read", "write"}
	v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer(), scopes...))

	// Mutating the caller's slice after construction must not change policy.
	scopes[0] = "admin"

	if _, err := v.Verify(t.Context(), validKey); err != nil {
		t.Fatalf("Verify(personal api key): %v", err)
	}
	if _, err := v.Verify(t.Context(), fi.sign(t, time.Hour, nil)); err != nil {
		t.Fatalf("Verify(jwt): %v", err)
	}
}

func TestPolicyScopeCanonicalizationIsStable(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	srv := newOnlineServer(t, func(http.ResponseWriter, *http.Request) {})

	// Duplicates and unsorted input must not change which scope is reported.
	v := newTokenInfoVerifier(
		t, jv, srv,
		defaultPolicy(jv.Issuer(), " write ", "zeta", "admin", "admin", "", "read"),
	)

	_, err := v.Verify(t.Context(), fi.sign(t, time.Hour, nil))
	var scopeErr *bearerauth.InsufficientScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("err = %v, want *InsufficientScopeError", err)
	}
	if scopeErr.MissingScope != "admin" {
		t.Errorf("MissingScope = %q, want %q", scopeErr.MissingScope, "admin")
	}
	if !errors.Is(err, bearerauth.ErrInsufficientScope) {
		t.Errorf("err = %v, want ErrInsufficientScope", err)
	}
}

// ---------------------------------------------------------------------------
// Hostile / broken custom JWT verifiers
// ---------------------------------------------------------------------------

func TestVerifyBrokenJWTVerifier(t *testing.T) {
	const hostileSecret = "super-secret-token-value"

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		stub stubVerifier
		// callerCtx overrides t.Context(). A context sentinel may only reach
		// the caller when the caller's own context is what ended the call.
		callerCtx   context.Context
		wantErr     error
		wantContext error
		leakText    string
	}{
		{
			name:    "nil result and nil error",
			stub:    stubVerifier{},
			wantErr: bearerauth.ErrInvalidCredential,
		},
		{
			name:    "nil embedded id token",
			stub:    stubVerifier{info: &jwksauth.TokenInfo{}},
			wantErr: bearerauth.ErrInvalidCredential,
		},
		{
			name: "error echoing the raw token",
			stub: stubVerifier{
				err: errors.New("verify failed for token " + hostileSecret),
			},
			wantErr:  bearerauth.ErrInvalidCredential,
			leakText: hostileSecret,
		},
		{
			name:        "caller cancelled the context",
			stub:        stubVerifier{err: context.Canceled},
			callerCtx:   cancelled,
			wantErr:     bearerauth.ErrVerifierUnavailable,
			wantContext: context.Canceled,
		},
		{
			// The verifier's own internal timeout — jwksauth's
			// WithVerifyTimeout, for instance — also surfaces as a context
			// error while the caller is still waiting. That is an availability
			// problem, but re-exporting the sentinel would tell an adapter the
			// client hung up, so only ErrVerifierUnavailable may match.
			name:    "verifier timed out while the caller is still alive",
			stub:    stubVerifier{err: context.DeadlineExceeded},
			wantErr: bearerauth.ErrVerifierUnavailable,
		},
		{
			name:    "verifier cancelled while the caller is still alive",
			stub:    stubVerifier{err: context.Canceled},
			wantErr: bearerauth.ErrVerifierUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newOnlineServer(t, func(http.ResponseWriter, *http.Request) {
				t.Error("jwt failure must not trigger an online call")
			})
			v := newTokenInfoVerifier(
				t, tt.stub, srv, defaultPolicy("https://auth.example.com"),
			)

			ctx := tt.callerCtx
			if ctx == nil {
				ctx = t.Context()
			}

			id, err := v.Verify(ctx, "a.jwt.value")
			if id != nil {
				t.Errorf("identity = %+v, want nil", id)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			assertNoSecrets(t, err, tt.leakText)
			if srv.count() != 0 {
				t.Errorf("upstream requests = %d, want 0", srv.count())
			}

			if tt.wantContext != nil && !errors.Is(err, tt.wantContext) {
				t.Errorf("err = %v, want it to also match %v", err, tt.wantContext)
			}
			if tt.wantContext == nil {
				for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
					if errors.Is(err, sentinel) {
						t.Errorf(
							"err = %v, want no %v identity: the caller was still alive",
							err, sentinel,
						)
					}
				}
			}
		})
	}
}
