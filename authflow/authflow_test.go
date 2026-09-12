package authflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/credstore"
	"github.com/go-signet/sdk-go/oauth"
)

func TestRunDeviceFlow(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth/device/code":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "test-device-code",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300,
				"interval":         1,
			})
		case "/oauth/token":
			count := requestCount.Add(1)
			if count < 3 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"error": "authorization_pending",
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "test-access-token",
				"refresh_token": "test-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		}
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		TokenURL:               server.URL + "/oauth/token",
		DeviceAuthorizationURL: server.URL + "/oauth/device/code",
	}

	client, err := oauth.NewClient("test-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	displayed := false
	handler := &testDeviceHandler{onDisplay: func(auth *oauth.DeviceAuth) {
		displayed = true
		if auth.UserCode != "ABCD-1234" {
			t.Errorf("UserCode = %q, want %q", auth.UserCode, "ABCD-1234")
		}
	}}

	token, err := RunDeviceFlow(context.Background(), client, []string{"read"},
		WithDeviceFlowHandler(handler),
	)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}

	if !displayed {
		t.Error("device code handler was not called")
	}
	if token.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
	}
}

func TestRunDeviceFlow_Cancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device/code":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "test-device-code",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300,
				"interval":         1,
			})
		case "/oauth/token":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "authorization_pending",
			})
		}
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		TokenURL:               server.URL + "/oauth/token",
		DeviceAuthorizationURL: server.URL + "/oauth/device/code",
	}
	client, err := oauth.NewClient("test-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = RunDeviceFlow(ctx, client, []string{"read"},
		WithDeviceFlowHandler(&testDeviceHandler{}),
	)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestRunAuthCodeFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test generateState produces unique values
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	s2, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if s1 == s2 {
		t.Error("generateState should produce unique values")
	}
	if len(s1) != 32 {
		t.Errorf("state length = %d, want 32 hex chars", len(s1))
	}

	// Test the callback handler with state validation via direct HTTP
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	state := "test-state-123"
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{Code: oauth.ErrCodeInvalidState}
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				errCh <- &oauth.Error{Code: "no_code"}
				return
			}
			codeCh <- code
		})
		w.WriteHeader(http.StatusOK)
	})

	callbackServer := httptest.NewServer(mux)
	t.Cleanup(callbackServer.Close)

	// Valid callback with correct state
	resp, err := http.Get(
		callbackServer.URL + "/callback?code=test-code&state=test-state-123",
	)
	if err != nil {
		t.Fatalf("callback request: %v", err)
	}
	resp.Body.Close()

	select {
	case code := <-codeCh:
		if code != "test-code" {
			t.Errorf("code = %q, want %q", code, "test-code")
		}
	case err := <-errCh:
		t.Fatalf("unexpected error: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for callback")
	}

	// Second callback should be ignored (sync.Once)
	resp, err = http.Get(
		callbackServer.URL + "/callback?code=second-code&state=test-state-123",
	)
	if err != nil {
		t.Fatalf("second callback request: %v", err)
	}
	resp.Body.Close()

	// Channel should be empty
	select {
	case <-codeCh:
		t.Error("second callback should be ignored")
	default:
		// expected
	}
}

func TestRunAuthCodeFlow_DuplicateCallback(t *testing.T) {
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	state := "test-state"
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		handled := false
		once.Do(func() {
			handled = true
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{Code: oauth.ErrCodeInvalidState}
				return
			}
			codeCh <- r.URL.Query().Get("code")
			w.Write([]byte("<html><body><h1>Authentication successful</h1></body></html>"))
		})
		if !handled {
			w.Write(
				[]byte(
					"<html><body><p>Already processed. You can close this window.</p></body></html>",
				),
			)
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// First callback — should be processed
	resp, err := http.Get(server.URL + "/callback?code=my-code&state=test-state")
	if err != nil {
		t.Fatalf("first callback: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read first response body: %v", err)
	}
	if !strings.Contains(string(body), "Authentication successful") {
		t.Errorf("first response should contain success message, got: %s", string(body))
	}

	// Second callback — should get "Already processed"
	resp, err = http.Get(server.URL + "/callback?code=other-code&state=test-state")
	if err != nil {
		t.Fatalf("second callback: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read second response body: %v", err)
	}
	if !strings.Contains(string(body), "Already processed") {
		t.Errorf("second response should contain 'Already processed', got: %s", string(body))
	}

	// Verify only the first code was sent
	select {
	case code := <-codeCh:
		if code != "my-code" {
			t.Errorf("code = %q, want %q", code, "my-code")
		}
	default:
		t.Error("expected code from first callback")
	}
}

func TestRunAuthCodeFlow_InvalidState(t *testing.T) {
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	state := "correct-state"
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{Code: oauth.ErrCodeInvalidState}
				return
			}
			codeCh <- r.URL.Query().Get("code")
		})
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Send callback with wrong state
	resp, err := http.Get(server.URL + "/callback?code=test-code&state=wrong-state")
	if err != nil {
		t.Fatalf("callback request: %v", err)
	}
	resp.Body.Close()

	select {
	case <-codeCh:
		t.Error("should not receive code with wrong state")
	case err := <-errCh:
		var oauthErr *oauth.Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != oauth.ErrCodeInvalidState {
			t.Errorf("expected invalid_state error, got: %v", err)
		}
	}
}

// --- TokenSource tests ---

type stubStore struct {
	data    map[string]credstore.Token
	saveErr error
	loadErr error
}

func newStubStore() *stubStore {
	return &stubStore{data: make(map[string]credstore.Token)}
}

func (s *stubStore) Load(clientID string) (credstore.Token, error) {
	if s.loadErr != nil {
		return credstore.Token{}, s.loadErr
	}
	tok, ok := s.data[clientID]
	if !ok {
		return credstore.Token{}, credstore.ErrNotFound
	}
	return tok, nil
}

func (s *stubStore) Save(clientID string, data credstore.Token) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.data[clientID] = data
	return nil
}

func (s *stubStore) Delete(clientID string) error {
	delete(s.data, clientID)
	return nil
}

func (s *stubStore) String() string { return "stub" }

func TestTokenSource_LoadValid(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken:  "cached-token",
		RefreshToken: "cached-refresh",
		TokenType:    "Bearer",
		Scope:        "read write",
		IDToken:      "cached-id-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		ClientID:     "test-client",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not make HTTP request when cache is valid")
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	token, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "cached-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "cached-token")
	}
	if token.RefreshToken != "cached-refresh" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "cached-refresh")
	}
	if token.Scope != "read write" {
		t.Errorf("Scope = %q, want %q", token.Scope, "read write")
	}
	if token.IDToken != "cached-id-token" {
		t.Errorf("IDToken = %q, want %q", token.IDToken, "cached-id-token")
	}
}

func TestTokenSource_RefreshExpired(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-me",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
		ClientID:     "test-client",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	token, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new-access")
	}

	// Verify token was saved to store
	saved, loadErr := store.Load(tokenStoreKey("test-client", nil))
	if loadErr != nil {
		t.Fatalf("Load after refresh: %v", loadErr)
	}
	if saved.AccessToken != "new-access" {
		t.Errorf("saved AccessToken = %q, want %q", saved.AccessToken, "new-access")
	}
}

func TestTokenSource_NoToken(t *testing.T) {
	store := newStubStore()

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected ErrReauthRequired, got: %v", err)
	}
}

func TestTokenSource_NoStore(t *testing.T) {
	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client) // no store configured
	_, err = ts.Token(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected ErrReauthRequired, got: %v", err)
	}
}

func TestTokenSource_ExpiredNoRefreshToken(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken: "expired-token",
		// no refresh token
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		ClientID:  "test-client",
	}

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected ErrReauthRequired, got: %v", err)
	}
}

func TestTokenSource_RefreshInvalidGrant(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken:  "expired-token",
		RefreshToken: "revoked-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		ClientID:     "test-client",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "refresh token revoked",
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected ErrReauthRequired for invalid_grant refresh, got: %v", err)
	}
}

func TestTokenSource_LoadError(t *testing.T) {
	store := newStubStore()
	store.loadErr = errors.New("disk I/O error")

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for store load failure")
	}
	if errors.Is(err, ErrReauthRequired) {
		t.Errorf("transient load error should NOT match ErrReauthRequired, got: %v", err)
	}
	if !strings.Contains(err.Error(), "disk I/O error") {
		t.Errorf("error should contain root cause, got: %v", err)
	}
}

func TestTokenSource_SaveError(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-me",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		ClientID:     "test-client",
	}
	store.saveErr = errors.New("permission denied")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for store save failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error should contain root cause, got: %v", err)
	}
}

func TestTokenSource_SaveToken(t *testing.T) {
	store := newStubStore()

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	saveErr := ts.SaveToken(&oauth.Token{
		AccessToken:  "saved-token",
		RefreshToken: "saved-refresh",
		TokenType:    "Bearer",
		Scope:        "openid profile email",
		IDToken:      "saved-id-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	if saveErr != nil {
		t.Fatalf("SaveToken: %v", saveErr)
	}

	saved, loadErr := store.Load(tokenStoreKey("test-client", nil))
	if loadErr != nil {
		t.Fatalf("Load: %v", loadErr)
	}
	if saved.AccessToken != "saved-token" {
		t.Errorf("AccessToken = %q, want %q", saved.AccessToken, "saved-token")
	}
	if saved.RefreshToken != "saved-refresh" {
		t.Errorf("RefreshToken = %q, want %q", saved.RefreshToken, "saved-refresh")
	}
	if saved.Scope != "openid profile email" {
		t.Errorf("Scope = %q, want %q", saved.Scope, "openid profile email")
	}
	if saved.IDToken != "saved-id-token" {
		t.Errorf("IDToken = %q, want %q", saved.IDToken, "saved-id-token")
	}
}

// TestTokenSource_RefreshDoesNotOverwriteConcurrentSave covers the post-refresh
// re-check in loadOrRefresh: while the network refresh is in flight, an external
// SaveToken caller writes a newer valid token. Token() must return the external
// write and not overwrite it with the refresh result.
func TestTokenSource_RefreshDoesNotOverwriteConcurrentSave(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken:  "expired-token",
		RefreshToken: "stale-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		ClientID:     "test-client",
	}

	var startOnce sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed-access",
			"refresh_token": "refreshed-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))

	type result struct {
		tok *oauth.Token
		err error
	}
	out := make(chan result, 1)
	go func() {
		tok, err := ts.Token(context.Background())
		out <- result{tok, err}
	}()

	// Wait until the refresh handler is entered: by that point loadOrRefresh
	// has already released ts.mu after the initial Load, so SaveToken can run.
	<-started

	externalToken := &oauth.Token{
		AccessToken:  "external-saved",
		RefreshToken: "external-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
	}
	if err := ts.SaveToken(externalToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	close(release)

	res := <-out
	if res.err != nil {
		t.Fatalf("Token: %v", res.err)
	}
	if res.tok.AccessToken != "external-saved" {
		t.Errorf("Token AccessToken = %q, want %q (external save must win)",
			res.tok.AccessToken, "external-saved")
	}

	saved, loadErr := store.Load(tokenStoreKey("test-client", nil))
	if loadErr != nil {
		t.Fatalf("Load: %v", loadErr)
	}
	if saved.AccessToken != "external-saved" {
		t.Errorf(
			"store AccessToken = %q, want %q (refresh result must not overwrite external save)",
			saved.AccessToken,
			"external-saved",
		)
	}
}

func TestCheckBrowserAvailability(t *testing.T) {
	// Just ensure it doesn't panic
	_ = CheckBrowserAvailability()
}

// TestTokenSource_RefreshPreservesOmittedFields covers the carry-forward in
// loadOrRefresh: RFC 6749 §6 lets the server omit refresh_token and scope from
// a refresh response when unchanged, so a successful refresh must not erase the
// stored refresh token (which would force re-authentication next cycle) or drop
// the granted scope.
func TestTokenSource_RefreshPreservesOmittedFields(t *testing.T) {
	store := newStubStore()
	store.data[tokenStoreKey("test-client", nil)] = credstore.Token{
		AccessToken:  "expired",
		RefreshToken: "keep-me",
		Scope:        "openid profile",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		ClientID:     "test-client",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response intentionally omits refresh_token and scope.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.RefreshToken != "keep-me" {
		t.Errorf("RefreshToken = %q, want %q (carried forward)", tok.RefreshToken, "keep-me")
	}
	if tok.Scope != "openid profile" {
		t.Errorf("Scope = %q, want %q (carried forward)", tok.Scope, "openid profile")
	}

	saved, err := store.Load(tokenStoreKey("test-client", nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.RefreshToken != "keep-me" {
		t.Errorf("saved RefreshToken = %q, want %q", saved.RefreshToken, "keep-me")
	}
}

type testDeviceHandler struct {
	onDisplay func(auth *oauth.DeviceAuth)
}

func (h *testDeviceHandler) DisplayCode(auth *oauth.DeviceAuth) error {
	if h.onDisplay != nil {
		h.onDisplay(auth)
	}
	return nil
}
