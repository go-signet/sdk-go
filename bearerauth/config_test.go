package bearerauth_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/bearerauth"
)

// TestNewFromIssuer covers the discovery-driven convenience constructor
// end to end: one issuer URL in, a verifier that handles both credential
// kinds out, with the canonical issuer and both endpoint paths derived rather
// than hand-typed.
func TestNewFromIssuer(t *testing.T) {
	tests := []struct {
		name     string
		cfg      func() bearerauth.Config
		handler  func(issuer string) http.HandlerFunc
		wantPath string
		wantForm bool
	}{
		{
			name: "tokeninfo mode",
			cfg: func() bearerauth.Config {
				return bearerauth.Config{
					Audience:       testAudience,
					ClientID:       testClientApp,
					RequiredScopes: []string{"read"},
				}
			},
			handler: func(issuer string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
				}
			},
			wantPath: "/oauth/tokeninfo",
		},
		{
			name: "introspection mode",
			cfg: func() bearerauth.Config {
				return bearerauth.Config{
					Audience:                  testAudience,
					ClientID:                  testClientApp,
					RequiredScopes:            []string{"read"},
					IntrospectionClientID:     introspectionID,
					IntrospectionClientSecret: introspectionPW,
				}
			},
			handler: func(issuer string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusOK, activeIntrospection(issuer, nil))
				}
			},
			wantPath: "/oauth/introspect",
			wantForm: true,
		},
		{
			name: "skip audience",
			cfg: func() bearerauth.Config {
				return bearerauth.Config{
					SkipAudience: true,
					ClientID:     testClientApp,
				}
			},
			handler: func(issuer string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
				}
			},
			wantPath: "/oauth/tokeninfo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := newFakeIssuer(t)
			fi.serveOnline(tt.handler(fi.URL()))

			v, err := bearerauth.New(t.Context(), fi.URL(), tt.cfg())
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			// Both credential kinds work through the one constructed verifier.
			jwtIdentity, err := v.Verify(t.Context(), fi.sign(t, time.Hour, nil))
			if err != nil {
				t.Fatalf("Verify(jwt): %v", err)
			}
			keyIdentity, err := v.Verify(t.Context(), validKey)
			if err != nil {
				t.Fatalf("Verify(personal api key): %v", err)
			}

			// The policy issuer was taken from discovery, not typed by hand.
			if jwtIdentity.Issuer != fi.URL() || keyIdentity.Issuer != fi.URL() {
				t.Errorf(
					"Issuer: jwt=%q key=%q, want %q",
					jwtIdentity.Issuer, keyIdentity.Issuer, fi.URL(),
				)
			}
			if jwtIdentity.CredentialType != bearerauth.CredentialJWT {
				t.Errorf("CredentialType = %q, want jwt", jwtIdentity.CredentialType)
			}
			if keyIdentity.CredentialType != bearerauth.CredentialPersonalAPIKey {
				t.Errorf(
					"CredentialType = %q, want personal_api_key",
					keyIdentity.CredentialType,
				)
			}

			// The endpoint path was derived from the issuer, and only the key
			// path went online.
			reqs := fi.online.requests()
			if len(reqs) != 1 {
				t.Fatalf("online requests = %d, want 1 (jwt must stay offline)", len(reqs))
			}
			if reqs[0].Path != tt.wantPath {
				t.Errorf("path = %q, want %q", reqs[0].Path, tt.wantPath)
			}
			if tt.wantForm {
				if got := reqs[0].Form.Get("client_secret"); got != introspectionPW {
					t.Errorf("client_secret = %q, want the configured secret", got)
				}
			} else if reqs[0].Auth != "Bearer "+validKey {
				t.Errorf("Authorization = %q, want the key as a Bearer credential", reqs[0].Auth)
			}
		})
	}
}

// TestNewRejectsAudienceMismatch confirms New really wires the audience
// through to the JWT verifier rather than accepting it as decoration.
func TestNewRejectsAudienceMismatch(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := bearerauth.New(t.Context(), fi.URL(), bearerauth.Config{
		Audience: "api://other",
		ClientID: testClientApp,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.Verify(t.Context(), fi.sign(t, time.Hour, nil))
	if !errors.Is(err, bearerauth.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestNewConfigValidation(t *testing.T) {
	fi := newFakeIssuer(t)

	tests := []struct {
		name      string
		issuerURL string
		cfg       bearerauth.Config
		wantIn    string
	}{
		{
			name:      "empty issuer url",
			issuerURL: "  ",
			cfg:       bearerauth.Config{Audience: testAudience, ClientID: testClientApp},
			wantIn:    "issuerURL",
		},
		{
			name:      "empty client app",
			issuerURL: fi.URL(),
			cfg:       bearerauth.Config{Audience: testAudience},
			wantIn:    "ClientID",
		},
		{
			name:      "missing audience",
			issuerURL: fi.URL(),
			cfg:       bearerauth.Config{ClientID: testClientApp},
			wantIn:    "Audience",
		},
		{
			name:      "audience and skip together",
			issuerURL: fi.URL(),
			cfg: bearerauth.Config{
				Audience:     testAudience,
				SkipAudience: true,
				ClientID:     testClientApp,
			},
			wantIn: "mutually exclusive",
		},
		{
			name:      "introspection id without secret",
			issuerURL: fi.URL(),
			cfg: bearerauth.Config{
				Audience:              testAudience,
				ClientID:              testClientApp,
				IntrospectionClientID: introspectionID,
			},
			wantIn: "must be set together",
		},
		{
			name:      "introspection secret without id",
			issuerURL: fi.URL(),
			cfg: bearerauth.Config{
				Audience:                  testAudience,
				ClientID:                  testClientApp,
				IntrospectionClientSecret: introspectionPW,
			},
			wantIn: "must be set together",
		},
		{
			name:      "unreachable issuer",
			issuerURL: "http://127.0.0.1:1",
			cfg:       bearerauth.Config{Audience: testAudience, ClientID: testClientApp},
			wantIn:    "bearerauth:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := bearerauth.New(t.Context(), tt.issuerURL, tt.cfg)
			if err == nil {
				t.Fatalf("New = %v, want an error", v)
			}
			if v != nil {
				t.Errorf("verifier = %v, want nil", v)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("err = %v, want it to mention %q", err, tt.wantIn)
			}
			// Configuration errors must never be mistaken for Verify verdicts.
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
			assertNoSecrets(t, err, introspectionPW)
		})
	}
}

// TestNewSharesOneHTTPClient checks that an injected client is used for the
// discovery fetch as well as for the later online calls.
func TestNewSharesOneHTTPClient(t *testing.T) {
	fi := newFakeIssuer(t)
	fi.serveOnline(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, activeTokenInfo(fi.URL(), nil))
	})

	tracker := &countingTransport{}
	httpClient := newTrackedRetryClient(t, tracker)

	v, err := bearerauth.New(t.Context(), fi.URL(), bearerauth.Config{
		Audience: testAudience,
		ClientID: testClientApp,
	}, bearerauth.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	discoveryCalls := tracker.calls.Load()
	if discoveryCalls == 0 {
		t.Fatal("injected client was not used for the discovery fetch")
	}

	if _, err := v.Verify(t.Context(), validKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := tracker.calls.Load(); got <= discoveryCalls {
		t.Errorf("injected client was not used for the online call (calls stayed at %d)", got)
	}
}

// TestNewRejectsForeignIntrospectionEndpoint pins the same-origin binding on
// the one endpoint discovery does not derive from the (already issuer-matched)
// issuer string: introspection_endpoint is copied verbatim out of the fetched
// document. Without the check, a document advertising another host makes every
// Verify POST the confidential client secret and the end user's complete
// Personal API Key to that host, and the caller sees only a routine
// ErrVerifierUnavailable.
func TestNewRejectsForeignIntrospectionEndpoint(t *testing.T) {
	attacker := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fi := newFakeIssuer(t)
	fi.discoveryExtra = map[string]any{
		"introspection_endpoint": attacker.introspectionURL(),
	}

	_, err := bearerauth.New(t.Context(), fi.URL(), bearerauth.Config{
		Audience:                  testAudience,
		ClientID:                  testClientApp,
		IntrospectionClientID:     introspectionID,
		IntrospectionClientSecret: introspectionPW,
	})
	if err == nil {
		t.Fatal("New accepted an introspection endpoint on a foreign origin")
	}
	if !strings.Contains(err.Error(), "issuer origin") {
		t.Errorf("err = %v, want it to name the origin mismatch", err)
	}
	assertNoSecrets(t, err, introspectionPW)

	if got := attacker.count(); got != 0 {
		t.Errorf("foreign host received %d requests, want 0", got)
	}
}

// TestNewAcceptsSameOriginIntrospectionEndpoint is the companion: an
// explicitly advertised endpoint on the issuer's own origin still works, so
// the guard does not break a deployment that publishes the endpoint properly.
func TestNewAcceptsSameOriginIntrospectionEndpoint(t *testing.T) {
	fi := newFakeIssuer(t)
	fi.discoveryExtra = map[string]any{
		"introspection_endpoint": fi.URL() + "/oauth/introspect",
	}
	fi.serveOnline(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, activeIntrospection(fi.URL(), nil))
	})

	v, err := bearerauth.New(t.Context(), fi.URL(), bearerauth.Config{
		Audience:                  testAudience,
		ClientID:                  testClientApp,
		IntrospectionClientID:     introspectionID,
		IntrospectionClientSecret: introspectionPW,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(t.Context(), validKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
