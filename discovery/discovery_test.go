package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestServer(t *testing.T, meta Metadata) *httptest.Server {
	t.Helper()
	// Use a two-phase approach: create server first, then set issuer to server URL
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wellKnownPath {
			http.NotFound(w, r)
			return
		}
		// Override issuer with actual server URL so issuer validation passes
		m := meta
		m.Issuer = serverURL
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m)
	}))
	serverURL = server.URL
	t.Cleanup(server.Close)
	return server
}

func TestFetch(t *testing.T) {
	meta := Metadata{
		AuthorizationEndpoint: "https://auth.example.com/oauth/authorize",
		TokenEndpoint:         "https://auth.example.com/oauth/token",
		UserinfoEndpoint:      "https://auth.example.com/oauth/userinfo",
		RevocationEndpoint:    "https://auth.example.com/oauth/revoke",
		GrantTypesSupported: []string{
			"authorization_code",
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
			"client_credentials",
		},
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	server := newTestServer(t, meta)

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if result.Issuer != server.URL {
		t.Errorf("Issuer = %q, want %q", result.Issuer, server.URL)
	}
	if result.TokenEndpoint != meta.TokenEndpoint {
		t.Errorf("TokenEndpoint = %q, want %q", result.TokenEndpoint, meta.TokenEndpoint)
	}
	if result.DeviceAuthorizationEndpoint == "" {
		t.Error("DeviceAuthorizationEndpoint should be derived from issuer")
	}
	if result.IntrospectionEndpoint == "" {
		t.Error("IntrospectionEndpoint should be derived from issuer")
	}
}

func TestFetch_Cache(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        "will-be-overridden",
			TokenEndpoint: "https://auth.example.com/oauth/token",
		})
	}))
	t.Cleanup(server.Close)

	// Patch the handler to return the correct issuer
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        server.URL,
			TokenEndpoint: "https://auth.example.com/oauth/token",
		})
	})
	callCount.Store(0)

	client, err := NewClient(server.URL, WithCacheTTL(1*time.Hour))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 1: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 2: %v", err)
	}

	if count := callCount.Load(); count != 1 {
		t.Errorf("server called %d times, want 1 (cached)", count)
	}
}

func TestFetch_CacheCopy(t *testing.T) {
	server := newTestServer(t, Metadata{
		TokenEndpoint:   "https://auth.example.com/oauth/token",
		ScopesSupported: []string{"openid", "profile"},
	})

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result1, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 1: %v", err)
	}

	// Mutate scalar field
	result1.TokenEndpoint = "mutated"

	// Mutate slice contents
	if len(result1.ScopesSupported) > 0 {
		result1.ScopesSupported[0] = "corrupted"
	}

	result2, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 2: %v", err)
	}

	// Cache should not be affected by scalar mutation
	if result2.TokenEndpoint == "mutated" {
		t.Error("scalar mutation of returned Metadata should not affect cache")
	}

	// Cache should not be affected by slice mutation
	if len(result2.ScopesSupported) > 0 && result2.ScopesSupported[0] == "corrupted" {
		t.Error("slice mutation of returned Metadata should not affect cache")
	}
}

func TestFetch_Concurrent(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        "", // placeholder
			TokenEndpoint: "https://auth.example.com/oauth/token",
		})
	}))
	t.Cleanup(server.Close)

	// Patch handler to return correct issuer
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        server.URL,
			TokenEndpoint: "https://auth.example.com/oauth/token",
		})
	})
	callCount.Store(0)

	client, err := NewClient(server.URL, WithCacheTTL(1*time.Hour))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for range goroutines {
		wg.Go(func() {
			_, fetchErr := client.Fetch(context.Background())
			if fetchErr != nil {
				errs <- fetchErr
			}
		})
	}

	wg.Wait()
	close(errs)

	for fetchErr := range errs {
		t.Errorf("Fetch error: %v", fetchErr)
	}

	if count := callCount.Load(); count != 1 {
		t.Errorf("server called %d times, want 1 (concurrent cache)", count)
	}
}

// TestFetch_ConcurrentCancellation verifies that a caller cancelling its
// context does not abort the shared singleflight fetch. Because the shared
// fetch runs under context.WithoutCancel, the cancellation must surface only
// to that caller; the fetch completes and populates the cache, so a subsequent
// Fetch succeeds without a second server round-trip.
func TestFetch_ConcurrentCancellation(t *testing.T) {
	var (
		callCount atomic.Int32
		serverURL string
		once      sync.Once
	)
	started := make(chan struct{})
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		once.Do(func() { close(started) })
		<-release // hold the request open until the test releases it
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        serverURL,
			TokenEndpoint: serverURL + "/oauth/token",
		})
	}))
	serverURL = server.URL
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithCacheTTL(1*time.Hour))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Caller A cancels its context while the shared fetch is in flight.
	ctxA, cancelA := context.WithCancel(context.Background())
	errA := make(chan error, 1)
	go func() {
		_, e := client.Fetch(ctxA)
		errA <- e
	}()

	// Synchronize on the server handler: the shared HTTP request is now in
	// flight and the singleflight slot is held, so cancelling A cannot race
	// ahead of the fetch starting.
	<-started

	// Cancel A: must surface to A without aborting the shared fetch.
	cancelA()
	if e := <-errA; !errors.Is(e, context.Canceled) {
		t.Errorf("caller A error = %v, want context.Canceled", e)
	}

	// Release the server: the detached shared fetch completes and caches the
	// metadata even though its initiating caller canceled.
	close(release)

	// A subsequent fetch must succeed from the completed shared fetch (cache
	// hit, or coalesced into the still-in-flight call) with no second server
	// round-trip — proving A's cancellation did not abort the shared fetch.
	meta, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch after canceled caller: %v", err)
	}
	if meta == nil || meta.TokenEndpoint != serverURL+"/oauth/token" {
		t.Errorf("metadata = %+v, want TokenEndpoint %q", meta, serverURL+"/oauth/token")
	}
	if count := callCount.Load(); count != 1 {
		t.Errorf("server called %d times, want 1 (shared fetch not restarted)", count)
	}
}

func TestEndpoints(t *testing.T) {
	meta := &Metadata{
		Issuer:                      "https://auth.example.com",
		AuthorizationEndpoint:       "https://auth.example.com/oauth/authorize",
		TokenEndpoint:               "https://auth.example.com/oauth/token",
		UserinfoEndpoint:            "https://auth.example.com/oauth/userinfo",
		RevocationEndpoint:          "https://auth.example.com/oauth/revoke",
		IntrospectionEndpoint:       "https://auth.example.com/oauth/introspect",
		DeviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/code",
	}

	ep := meta.Endpoints()

	if ep.TokenURL != meta.TokenEndpoint {
		t.Errorf("TokenURL = %q, want %q", ep.TokenURL, meta.TokenEndpoint)
	}
	if ep.AuthorizeURL != meta.AuthorizationEndpoint {
		t.Errorf("AuthorizeURL = %q, want %q", ep.AuthorizeURL, meta.AuthorizationEndpoint)
	}
	if ep.DeviceAuthorizationURL != meta.DeviceAuthorizationEndpoint {
		t.Errorf(
			"DeviceAuthorizationURL = %q, want %q",
			ep.DeviceAuthorizationURL,
			meta.DeviceAuthorizationEndpoint,
		)
	}
	if ep.TokenInfoURL != "https://auth.example.com/oauth/tokeninfo" {
		t.Errorf("TokenInfoURL = %q", ep.TokenInfoURL)
	}
}

func TestFetch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithCacheTTL(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestFetch_ResponseBodyTooLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Valid JSON whose total length exceeds maxResponseBytes so the
		// LimitedReader is exhausted while decoding.
		w.Write([]byte(`{"issuer":"`))
		padding := make([]byte, maxResponseBytes+1)
		for i := range padding {
			padding[i] = 'A'
		}
		w.Write(padding)
		w.Write([]byte(`"}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithCacheTTL(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for oversized discovery response")
	}
	if !errors.Is(err, errResponseTooLarge) {
		t.Errorf("expected errResponseTooLarge, got: %v", err)
	}
}

func TestFetch_IssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        "https://evil.example.com",
			TokenEndpoint: "https://evil.example.com/oauth/token",
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}
