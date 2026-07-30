package bearerauth_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/bearerauth"
)

// TestOnlineFailureClassification pins the mapping from an upstream condition
// to a stable error category. The split that matters: only tokeninfo's 401 is
// a statement about the presented key — every other online fault is a
// verifier-availability problem, so a legitimate caller is never told its
// credential is bad because the deployment is misconfigured.
func TestOnlineFailureClassification(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	issuer := jv.Issuer()

	oversized := strings.Repeat("x", 1<<20)

	tests := []struct {
		name          string
		introspection bool
		handler       http.HandlerFunc
		want          error
	}{
		{
			name: "tokeninfo 401 invalid_token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": "invalid_token",
				})
			},
			want: bearerauth.ErrInvalidCredential,
		},
		{
			name: "tokeninfo 400",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error": "invalid_request",
				})
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo malformed json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"active": tru`))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo response above 1 MiB",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeTokenInfo(issuer, map[string]any{
					"padding": oversized,
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo wrong token type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeTokenInfo(issuer, map[string]any{
					"token_type": "access_token",
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo unexpected subject type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeTokenInfo(issuer, map[string]any{
					"subject_type": "client",
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo missing user id",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeTokenInfo(issuer, map[string]any{
					"user_id": "",
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo missing expiry",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeTokenInfo(issuer, map[string]any{
					"exp": 0,
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name: "tokeninfo already expired key",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeTokenInfo(issuer, map[string]any{
					"exp": time.Now().Add(-time.Minute).Unix(),
				}))
			},
			want: bearerauth.ErrInvalidCredential,
		},
		{
			name:          "introspection 401 rejects our client credentials",
			introspection: true,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": "invalid_client",
				})
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name:          "introspection inactive",
			introspection: true,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{"active": false})
			},
			want: bearerauth.ErrInvalidCredential,
		},
		{
			name:          "introspection ownership-stripped response",
			introspection: true,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{"active": true})
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name:          "introspection wrong token type",
			introspection: true,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeIntrospection(issuer, map[string]any{
					"token_type": "Bearer",
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
		{
			name:          "introspection missing subject",
			introspection: true,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, activeIntrospection(issuer, map[string]any{
					"sub": "",
				}))
			},
			want: bearerauth.ErrVerifierUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newOnlineServer(t, tt.handler)
			var v *bearerauth.Verifier
			if tt.introspection {
				v = newIntrospectionVerifier(t, jv, srv, defaultPolicy(issuer))
			} else {
				v = newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))
			}

			id, err := v.Verify(t.Context(), validKey)
			if id != nil {
				t.Errorf("identity = %+v, want nil", id)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			assertNoSecrets(t, err, validKey, introspectionPW, oversized)
		})
	}
}

// TestOnlineTransportFailure covers the case where no HTTP response is
// produced at all.
func TestOnlineTransportFailure(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)

	// Port 1 is reserved and never listening, so every attempt is refused.
	v, err := bearerauth.NewTokenInfoVerifier(
		jv, "http://127.0.0.1:1/oauth/tokeninfo", defaultPolicy(jv.Issuer()),
	)
	if err != nil {
		t.Fatalf("NewTokenInfoVerifier: %v", err)
	}

	id, verr := v.Verify(t.Context(), validKey)
	if id != nil {
		t.Errorf("identity = %+v, want nil", id)
	}
	if !errors.Is(verr, bearerauth.ErrVerifierUnavailable) {
		t.Fatalf("err = %v, want ErrVerifierUnavailable", verr)
	}
	assertNoSecrets(t, verr, validKey)
}

// TestOnlineRedirectRefused proves the default client will not forward a
// Personal API Key — or an introspection form carrying the client secret — to
// a location named by the auth server's response.
func TestOnlineRedirectRefused(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)

	var followed atomic.Int64
	target := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		writeJSON(w, http.StatusOK, activeTokenInfo(jv.Issuer(), nil))
	})

	for _, status := range []int{
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			followed.Store(0)
			srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.tokenInfoURL())
				w.WriteHeader(status)
			})
			v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))

			id, err := v.Verify(t.Context(), validKey)
			if id != nil {
				t.Errorf("identity = %+v, want nil", id)
			}
			if !errors.Is(err, bearerauth.ErrVerifierUnavailable) {
				t.Fatalf("err = %v, want ErrVerifierUnavailable", err)
			}
			if got := followed.Load(); got != 0 {
				t.Errorf("redirect target received %d requests, want 0", got)
			}
			assertNoSecrets(t, err, validKey)
		})
	}
}

// TestOnlineRetryBehavior pins which upstream conditions cost extra attempts.
func TestOnlineRetryBehavior(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	issuer := jv.Issuer()

	t.Run("503 then success", func(t *testing.T) {
		var attempts atomic.Int64
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if attempts.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))

		if _, err := v.Verify(t.Context(), validKey); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got := srv.count(); got != 2 {
			t.Errorf("upstream attempts = %d, want 2", got)
		}
	})

	t.Run("429 then success", func(t *testing.T) {
		var attempts atomic.Int64
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if attempts.Add(1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))

		if _, err := v.Verify(t.Context(), validKey); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got := srv.count(); got != 2 {
			t.Errorf("upstream attempts = %d, want 2", got)
		}
	})

	t.Run("introspection replays its form on retry", func(t *testing.T) {
		var attempts atomic.Int64
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if attempts.Add(1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
				return
			}
			writeJSON(w, http.StatusOK, activeIntrospection(issuer, nil))
		})
		v := newIntrospectionVerifier(t, jv, srv, defaultPolicy(issuer))

		if _, err := v.Verify(t.Context(), validKey); err != nil {
			t.Fatalf("Verify: %v", err)
		}

		reqs := srv.requests()
		if len(reqs) != 2 {
			t.Fatalf("upstream attempts = %d, want 2", len(reqs))
		}
		// The retried POST must carry the complete form, not an empty body.
		for i, req := range reqs {
			if got := req.Form.Get("token"); got != validKey {
				t.Errorf("attempt %d form token = %q, want the full key", i+1, got)
			}
			if got := req.Form.Get("client_secret"); got != introspectionPW {
				t.Errorf("attempt %d form client_secret = %q, want it replayed", i+1, got)
			}
		}
	})

	t.Run("exhausted 5xx retries", func(t *testing.T) {
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))

		_, err := v.Verify(t.Context(), validKey)
		if !errors.Is(err, bearerauth.ErrVerifierUnavailable) {
			t.Fatalf("err = %v, want ErrVerifierUnavailable", err)
		}
		// Realtime preset: initial attempt plus two retries.
		if got := srv.count(); got != 3 {
			t.Errorf("upstream attempts = %d, want 3", got)
		}
	})

	t.Run("401 is not retried", func(t *testing.T) {
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))

		_, err := v.Verify(t.Context(), validKey)
		if !errors.Is(err, bearerauth.ErrInvalidCredential) {
			t.Fatalf("err = %v, want ErrInvalidCredential", err)
		}
		if got := srv.count(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})

	t.Run("inactive key is not retried", func(t *testing.T) {
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))

		_, err := v.Verify(t.Context(), validKey)
		if !errors.Is(err, bearerauth.ErrInvalidCredential) {
			t.Fatalf("err = %v, want ErrInvalidCredential", err)
		}
		if got := srv.count(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})
}

// TestOnlineContextPropagation checks that a cancelled or expired caller
// context stays detectable through the category wrapper.
func TestOnlineContextPropagation(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)

	t.Run("cancelled", func(t *testing.T) {
		srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, activeTokenInfo(jv.Issuer(), nil))
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := v.Verify(ctx, validKey)
		if !errors.Is(err, bearerauth.ErrVerifierUnavailable) {
			t.Fatalf("err = %v, want ErrVerifierUnavailable", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want it to also match context.Canceled", err)
		}
		assertNoSecrets(t, err, validKey)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		release := make(chan struct{})
		// Released with defer, not t.Cleanup: newOnlineServer registers its own
		// t.Cleanup(srv.Close), cleanups run LIFO, and Close waits for
		// outstanding requests. Registering the release as a cleanup here would
		// make Close run first and leave the handler parked, so the test would
		// only unblock via the client disconnect cancelling r.Context().
		defer close(release)
		srv := newOnlineServer(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusOK)
		})
		v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()

		_, err := v.Verify(ctx, validKey)
		if !errors.Is(err, bearerauth.ErrVerifierUnavailable) {
			t.Fatalf("err = %v, want ErrVerifierUnavailable", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want it to also match context.DeadlineExceeded", err)
		}
	})
}

// TestVerifierIsConcurrencySafe shares one verifier across many goroutines and
// asserts the per-call I/O contract: exactly one upstream request per Personal
// API Key verification and none at all for a JWT.
func TestVerifierIsConcurrencySafe(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	issuer := jv.Issuer()

	srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
	})
	counting := &countingVerifier{inner: jv}
	v := newTokenInfoVerifier(t, counting, srv, defaultPolicy(issuer, "read", "write"))

	// Warm the JWKS cache so the shared verifier is in its steady state.
	rawJWT := fi.sign(t, time.Hour, nil)
	if _, err := v.Verify(t.Context(), rawJWT); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	const (
		goroutines = 24
		perRoutine = 8
	)
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perRoutine)
	for i := range goroutines {
		wg.Go(func() {
			for j := range perRoutine {
				credential := rawJWT
				if (i+j)%2 == 0 {
					credential = validKey
				}
				id, err := v.Verify(t.Context(), credential)
				if err != nil {
					errs <- err
					return
				}
				if id.Subject != "user-1" || id.ClientID != testClientApp {
					errs <- errors.New("unexpected identity: " + id.Subject)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Verify: %v", err)
	}

	total := goroutines * perRoutine
	keyCalls := 0
	for i := range goroutines {
		for j := range perRoutine {
			if (i+j)%2 == 0 {
				keyCalls++
			}
		}
	}
	// +1 for the warmup JWT, which must not have gone online.
	if got := counting.calls.Load(); got != int64(total-keyCalls+1) {
		t.Errorf("jwt verifier calls = %d, want %d", got, total-keyCalls+1)
	}
	if got := srv.count(); got != keyCalls {
		t.Errorf("upstream requests = %d, want %d (one per key verification)", got, keyCalls)
	}
}

// TestVerdictsAreNotCached proves a key revoked between two calls stops
// working immediately.
func TestVerdictsAreNotCached(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)
	issuer := jv.Issuer()

	var revoked atomic.Bool
	srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if revoked.Load() {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
			return
		}
		writeJSON(w, http.StatusOK, activeTokenInfo(issuer, nil))
	})
	v := newTokenInfoVerifier(t, jv, srv, defaultPolicy(issuer))

	if _, err := v.Verify(t.Context(), validKey); err != nil {
		t.Fatalf("Verify before revocation: %v", err)
	}
	revoked.Store(true)
	if _, err := v.Verify(t.Context(), validKey); !errors.Is(
		err, bearerauth.ErrInvalidCredential,
	) {
		t.Fatalf("Verify after revocation: err = %v, want ErrInvalidCredential", err)
	}
	if got := srv.count(); got != 2 {
		t.Errorf("upstream requests = %d, want 2 (no cached verdict)", got)
	}
}

// TestErrorsDoNotEchoUpstreamBodies checks that a hostile auth server cannot
// get its own response text — which may quote the Authorization header — into
// the error this package hands to a framework adapter.
func TestErrorsDoNotEchoUpstreamBodies(t *testing.T) {
	fi := newFakeIssuer(t)
	jv := fi.verifier(t)

	hostile := "leaked-marker " + validKey + " " + introspectionPW
	srv := newOnlineServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": hostile,
		})
	})

	// The constructors call t.Fatalf, so they must receive the subtest's own
	// *testing.T — calling FailNow on the parent from a subtest goroutine
	// reports an opaque "test executed panic(nil) or runtime.Goexit" instead of
	// the real construction error.
	for _, tc := range []struct {
		name string
		v    func(*testing.T) *bearerauth.Verifier
	}{
		{
			name: "tokeninfo",
			v: func(t *testing.T) *bearerauth.Verifier {
				return newTokenInfoVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))
			},
		},
		{
			name: "introspection",
			v: func(t *testing.T) *bearerauth.Verifier {
				return newIntrospectionVerifier(t, jv, srv, defaultPolicy(jv.Issuer()))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.v(t).Verify(t.Context(), validKey)
			if !errors.Is(err, bearerauth.ErrVerifierUnavailable) {
				t.Fatalf("err = %v, want ErrVerifierUnavailable", err)
			}
			assertNoSecrets(t, err, validKey, introspectionPW, "leaked-marker")
		})
	}
}
