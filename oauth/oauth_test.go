package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	retry "github.com/appleboy/go-httpretry"
)

func setupTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	endpoints := Endpoints{
		TokenURL:               server.URL + "/oauth/token",
		AuthorizeURL:           server.URL + "/oauth/authorize",
		DeviceAuthorizationURL: server.URL + "/oauth/device/code",
		RevocationURL:          server.URL + "/oauth/revoke",
		IntrospectionURL:       server.URL + "/oauth/introspect",
		UserinfoURL:            server.URL + "/oauth/userinfo",
		TokenInfoURL:           server.URL + "/oauth/tokeninfo",
	}

	client, err := NewClient("test-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, client
}

func TestRequestDeviceCode(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/device/code" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("client_id") != "test-client" {
			t.Errorf("unexpected client_id: %s", r.PostForm.Get("client_id"))
		}
		if r.PostForm.Get("scope") != "read write" {
			t.Errorf("unexpected scope: %s", r.PostForm.Get("scope"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-code-123",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://auth.example.com/device",
			"verification_uri_complete": "https://auth.example.com/device?user_code=ABCD-1234",
			"expires_in":                900,
			"interval":                  5,
		})
	})

	auth, err := client.RequestDeviceCode(context.Background(), []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}

	if auth.DeviceCode != "dev-code-123" {
		t.Errorf("DeviceCode = %q, want %q", auth.DeviceCode, "dev-code-123")
	}
	if auth.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want %q", auth.UserCode, "ABCD-1234")
	}
	if auth.Interval != 5 {
		t.Errorf("Interval = %d, want 5", auth.Interval)
	}
	if auth.ExpiresIn != 900 {
		t.Errorf("ExpiresIn = %d, want 900", auth.ExpiresIn)
	}
}

func TestExchangeDeviceCode(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}

		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-123",
			"refresh_token": "refresh-token-456",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "read write",
		})
	})

	token, err := client.ExchangeDeviceCode(context.Background(), "dev-code-123", nil)
	if err != nil {
		t.Fatalf("ExchangeDeviceCode: %v", err)
	}

	if token.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "access-token-123")
	}
	if token.RefreshToken != "refresh-token-456" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "refresh-token-456")
	}
	if token.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
	}
	if token.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if !token.IsValid() {
		t.Error("token should be valid")
	}
}

func TestExchangeDeviceCode_AuthorizationPending(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "authorization_pending",
			"error_description": "",
		})
	})

	_, err := client.ExchangeDeviceCode(context.Background(), "dev-code-123", nil)
	if err == nil {
		t.Fatal("expected error")
	}

	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if oauthErr.Code != "authorization_pending" {
		t.Errorf("error code = %q, want %q", oauthErr.Code, "authorization_pending")
	}
}

func TestExchangeAuthCode(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("code") != "auth-code-789" {
			t.Errorf("unexpected code: %s", r.PostForm.Get("code"))
		}
		if r.PostForm.Get("code_verifier") != "verifier-abc" {
			t.Errorf("unexpected code_verifier: %s", r.PostForm.Get("code_verifier"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-auth",
			"refresh_token": "refresh-token-auth",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid profile",
			"id_token":      "eyJhbGciOiJIUzI1NiJ9.test.sig",
		})
	})

	token, err := client.ExchangeAuthCode(
		context.Background(),
		"auth-code-789",
		"http://localhost/callback",
		"verifier-abc",
		nil,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthCode: %v", err)
	}

	if token.AccessToken != "access-token-auth" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "access-token-auth")
	}
	if token.IDToken != "eyJhbGciOiJIUzI1NiJ9.test.sig" {
		t.Errorf("IDToken = %q", token.IDToken)
	}
}

func TestClientCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("client_secret") != "test-secret" {
			t.Errorf("unexpected client_secret: %s", r.PostForm.Get("client_secret"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cc-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read",
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(
		"test-client",
		Endpoints{TokenURL: server.URL + "/oauth/token"},
		WithClientSecret("test-secret"),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	token, err := client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}

	if token.AccessToken != "cc-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "cc-access-token")
	}
}

func TestClientCredentials_EmptySecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Has("client_secret") {
			t.Errorf(
				"client_secret should not be sent when empty, got %q",
				r.PostForm.Get("client_secret"),
			)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cc-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient("test-client", Endpoints{TokenURL: server.URL + "/oauth/token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	token, err := client.ClientCredentials(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if token.AccessToken != "cc-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "cc-access-token")
	}
}

func TestIntrospect_EmptySecret(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Has("client_secret") {
			t.Errorf(
				"client_secret should not be sent when empty, got %q",
				r.PostForm.Get("client_secret"),
			)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":    true,
			"scope":     "read",
			"client_id": "test-client",
			"sub":       "user-123",
		})
	})

	result, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !result.Active {
		t.Error("expected active=true")
	}
}

func TestRefreshToken(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("grant_type") != "refresh_token" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("refresh_token") != "old-refresh" {
			t.Errorf("unexpected refresh_token: %s", r.PostForm.Get("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	token, err := client.RefreshToken(context.Background(), "old-refresh", nil)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}

	if token.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new-access")
	}
	if token.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "new-refresh")
	}
}

func TestRevoke(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})

	err := client.Revoke(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestIntrospect(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":     true,
			"scope":      "read write",
			"client_id":  "test-client",
			"username":   "testuser",
			"token_type": "Bearer",
			"exp":        1700000000,
			"sub":        "user-123",
			"aud":        "https://api-b.example.com",
			"act":        map[string]string{"sub": "client:api-a"},
		})
	})

	result, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}

	if !result.Active {
		t.Error("expected active=true")
	}
	if result.Username != "testuser" {
		t.Errorf("Username = %q, want %q", result.Username, "testuser")
	}
	if result.Sub != "user-123" {
		t.Errorf("Sub = %q, want %q", result.Sub, "user-123")
	}
	if !slices.Equal(result.Audience, Audience{"https://api-b.example.com"}) {
		t.Errorf("Audience = %v", result.Audience)
	}
	if result.Actor == nil || result.Actor.Subject != "client:api-a" {
		t.Errorf("Actor = %+v", result.Actor)
	}
}

func TestUserInfo(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-access-token" {
			t.Errorf("unexpected Authorization: %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":                "user-123",
			"name":               "Test User",
			"preferred_username": "testuser",
			"email":              "test@example.com",
		})
	})

	info, err := client.UserInfo(context.Background(), "my-access-token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}

	if info.Sub != "user-123" {
		t.Errorf("Sub = %q, want %q", info.Sub, "user-123")
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q, want %q", info.Name, "Test User")
	}
	if info.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "test@example.com")
	}
}

func TestTokenInfoRequest(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":       true,
			"user_id":      "user-123",
			"client_id":    "test-client",
			"scope":        "read write",
			"exp":          1700000000,
			"subject_type": "user",
			"aud":          []string{"https://api-a.example.com", "https://api-b.example.com"},
		})
	})

	info, err := client.TokenInfoRequest(context.Background(), "my-token")
	if err != nil {
		t.Fatalf("TokenInfoRequest: %v", err)
	}

	if !info.Active {
		t.Error("expected active=true")
	}
	if info.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", info.UserID, "user-123")
	}
	if !slices.Equal(info.Audience, Audience{
		"https://api-a.example.com", "https://api-b.example.com",
	}) {
		t.Errorf("Audience = %v", info.Audience)
	}
}

func TestTokenIsExpired(t *testing.T) {
	tok := &Token{AccessToken: "test"}
	if tok.IsExpired() {
		t.Error("token with zero ExpiresAt should not be expired")
	}

	tok.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if !tok.IsExpired() {
		t.Error("token with past ExpiresAt should be expired")
	}

	tok.ExpiresAt = time.Now().Add(1 * time.Hour)
	if tok.IsExpired() {
		t.Error("token with future ExpiresAt should not be expired")
	}
}

func TestTokenIsValid(t *testing.T) {
	tok := &Token{}
	if tok.IsValid() {
		t.Error("empty token should not be valid")
	}

	tok.AccessToken = "test"
	if !tok.IsValid() {
		t.Error("token with access token and no expiry should be valid")
	}

	tok.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if tok.IsValid() {
		t.Error("expired token should not be valid")
	}
}

func TestOAuthError(t *testing.T) {
	err := &Error{Code: ErrCodeInvalidGrant, Description: "Token expired"}
	if err.Error() != "oauth: invalid_grant: Token expired" {
		t.Errorf("unexpected error: %s", err.Error())
	}

	err2 := &Error{Code: ErrCodeServerError}
	if err2.Error() != "oauth: server_error" {
		t.Errorf("unexpected error: %s", err2.Error())
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	ep := Endpoints{TokenURL: "https://example.com/token"}
	client, err := NewClient("my-client", ep, WithClientSecret("my-secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.ClientID() != "my-client" {
		t.Errorf("ClientID = %q, want %q", client.ClientID(), "my-client")
	}
	if client.clientSecret != "my-secret" {
		t.Errorf("clientSecret = %q, want %q", client.clientSecret, "my-secret")
	}
}

func TestRequestDeviceCode_NoEndpoint(t *testing.T) {
	client, err := NewClient("test", Endpoints{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.RequestDeviceCode(context.Background(), []string{"read"}, nil)
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestResponseBodyTooLarge(t *testing.T) {
	// Serve a JSON response larger than maxResponseBytes (1 MB)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid JSON prefix followed by a huge padding string
		w.Write([]byte(`{"access_token":"`))
		padding := make([]byte, maxResponseBytes+1)
		for i := range padding {
			padding[i] = 'A'
		}
		w.Write(padding)
		w.Write([]byte(`"}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient("test", Endpoints{TokenURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ClientCredentials(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !errors.Is(err, errResponseTooLarge) {
		t.Errorf("expected errResponseTooLarge, got: %v", err)
	}
}

func TestErrorResponseBodyTooLarge(t *testing.T) {
	// Serve an error response larger than maxResponseBytes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		padding := make([]byte, maxResponseBytes+1)
		for i := range padding {
			padding[i] = 'X'
		}
		w.Write(padding)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient("test", Endpoints{TokenURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ClientCredentials(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error for oversized error response")
	}
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if oauthErr.Description != "error response body exceeds size limit" {
		t.Errorf("unexpected description: %s", oauthErr.Description)
	}
}

// TestResponseBodyExactlyAtBoundary covers the case where the body is valid
// JSON whose total length equals maxResponseBytes+1: Decode succeeds and
// consumes the LimitedReader's sentinel byte (lr.N == 0). Without a post-decode
// size check the response would be silently accepted despite exceeding the cap.
func TestResponseBodyExactlyAtBoundary(t *testing.T) {
	const prefix = `{"access_token":"`
	const suffix = `"}`
	padLen := maxResponseBytes + 1 - len(prefix) - len(suffix)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(prefix))
		padding := make([]byte, padLen)
		for i := range padding {
			padding[i] = 'A'
		}
		w.Write(padding)
		w.Write([]byte(suffix))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient("test", Endpoints{TokenURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ClientCredentials(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error for response at boundary")
	}
	if !errors.Is(err, errResponseTooLarge) {
		t.Errorf("expected errResponseTooLarge, got: %v", err)
	}
}

// TestConfidentialClientAuth verifies that every confidential-client request
// carries client_id and client_secret. RefreshToken, ExchangeDeviceCode, and
// Revoke previously omitted the secret (Revoke omitted client_id too), so a
// client built with WithClientSecret could not refresh, complete the device
// flow, or revoke against a server that requires client authentication.
func TestConfidentialClientAuth(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{"ExchangeAuthCode", func(c *Client) error {
			_, err := c.ExchangeAuthCode(context.Background(), "code", "uri", "verifier", nil)
			return err
		}},
		{"ExchangeDeviceCode", func(c *Client) error {
			_, err := c.ExchangeDeviceCode(context.Background(), "dev-code", nil)
			return err
		}},
		{"ClientCredentials", func(c *Client) error {
			_, err := c.ClientCredentials(context.Background(), nil, nil)
			return err
		}},
		{"RefreshToken", func(c *Client) error {
			_, err := c.RefreshToken(context.Background(), "refresh", nil)
			return err
		}},
		{"Introspect", func(c *Client) error {
			_, err := c.Introspect(context.Background(), "tok")
			return err
		}},
		{"Revoke", func(c *Client) error {
			return c.Revoke(context.Background(), "tok")
		}},
		{"RequestDeviceCode", func(c *Client) error {
			_, err := c.RequestDeviceCode(context.Background(), nil, nil)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						t.Fatalf("ParseForm: %v", err)
					}
					if got := r.PostForm.Get("client_id"); got != "cid" {
						t.Errorf("client_id = %q, want %q", got, "cid")
					}
					if got := r.PostForm.Get("client_secret"); got != "secret" {
						t.Errorf("client_secret = %q, want %q", got, "secret")
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "a",
						"token_type":   "Bearer",
						"active":       true,
					})
				}),
			)
			t.Cleanup(server.Close)

			client, err := NewClient("cid", Endpoints{
				TokenURL:               server.URL + "/token",
				RevocationURL:          server.URL + "/revoke",
				IntrospectionURL:       server.URL + "/introspect",
				DeviceAuthorizationURL: server.URL + "/device",
			}, WithClientSecret("secret"))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if err := tt.call(client); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
		})
	}
}

func TestPersonalAPIKeyTokenInfoRequest(t *testing.T) {
	const key = "sgk_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"

	// Guarded: the handler runs on the server's goroutine and the assertions
	// below run on the test's, and the HTTP round-trip alone is not a
	// happens-before edge the race detector recognizes.
	var (
		mu        sync.Mutex
		gotMethod string
		gotAuth   string
		gotQuery  string
	)
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":       true,
			"user_id":      "user-123",
			"client_id":    "test-client",
			"scope":        "read write",
			"exp":          1700000000,
			"iss":          "https://auth.example.com",
			"subject_type": "user",
			"token_type":   "personal_api_key",
		})
	})

	info, err := client.PersonalAPIKeyTokenInfoRequest(context.Background(), key)
	if err != nil {
		t.Fatalf("PersonalAPIKeyTokenInfoRequest: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotAuth != "Bearer "+key {
		t.Errorf("Authorization = %q, want the key as a Bearer credential", gotAuth)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want the key kept out of the URL", gotQuery)
	}

	want := PersonalAPIKeyTokenInfo{
		Active:      true,
		UserID:      "user-123",
		ClientID:    "test-client",
		Scope:       "read write",
		Exp:         1700000000,
		Iss:         "https://auth.example.com",
		SubjectType: "user",
		TokenType:   "personal_api_key",
	}
	if *info != want {
		t.Errorf("info = %+v, want %+v", *info, want)
	}
}

func TestPersonalAPIKeyTokenInfoRequest_NoEndpoint(t *testing.T) {
	client, err := NewClient("cid", Endpoints{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := client.PersonalAPIKeyTokenInfoRequest(context.Background(), "sgk_x"); err == nil {
		t.Fatal("expected an error when the tokeninfo endpoint is not configured")
	}
}

type trackedRequestBody struct {
	io.Reader
	closed   atomic.Bool
	closeErr error
}

func (b *trackedRequestBody) Close() error {
	b.closed.Store(true)
	return b.closeErr
}

func TestRewindBodyMiddlewareBodyLifecycle(t *testing.T) {
	newRequest := func(t *testing.T, body io.ReadCloser) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"https://auth.example.com/oauth/introspect",
			body,
		)
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		return req
	}

	t.Run("closes replaced body before downstream", func(t *testing.T) {
		original := &trackedRequestBody{Reader: strings.NewReader("original")}
		replacement := &trackedRequestBody{Reader: strings.NewReader("replacement")}
		req := newRequest(t, original)
		req.GetBody = func() (io.ReadCloser, error) {
			if !original.closed.Load() {
				t.Error("original body was not closed before GetBody")
			}
			return replacement, nil
		}

		next := retry.RoundTripperFunc(
			func(got *http.Request) (*http.Response, error) {
				if got == req {
					t.Error("middleware forwarded the original request instead of a clone")
				}
				if got.Body != replacement {
					t.Error("downstream did not receive the replacement body")
				}
				if replacement.closed.Load() {
					t.Error("replacement body was closed before downstream received it")
				}
				body, err := io.ReadAll(got.Body)
				if err != nil {
					t.Errorf("ReadAll: %v", err)
				}
				if string(body) != "replacement" {
					t.Errorf("body = %q, want replacement", body)
				}
				if err := got.Body.Close(); err != nil {
					t.Errorf("Close replacement body: %v", err)
				}
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       http.NoBody,
					Header:     make(http.Header),
					Request:    got,
				}, nil
			},
		)

		resp, err := RewindBodyMiddleware(next).RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})
		if req.Body != original {
			t.Error("middleware mutated the original request Body field")
		}
		if !original.closed.Load() {
			t.Error("original body was not closed")
		}
		if !replacement.closed.Load() {
			t.Error("downstream did not close the replacement body")
		}
	})

	t.Run("GetBody failure closes original and skips downstream", func(t *testing.T) {
		original := &trackedRequestBody{Reader: strings.NewReader("original")}
		req := newRequest(t, original)
		wantErr := errors.New("cannot reopen body")
		req.GetBody = func() (io.ReadCloser, error) {
			return nil, wantErr
		}

		var downstreamCalled atomic.Bool
		next := retry.RoundTripperFunc(
			func(*http.Request) (*http.Response, error) {
				downstreamCalled.Store(true)
				return nil, errors.New("unexpected downstream call")
			},
		)

		resp, err := RewindBodyMiddleware(next).RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
			t.Errorf("response = %+v, want nil", resp)
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
		if !original.closed.Load() {
			t.Error("original body was not closed")
		}
		if downstreamCalled.Load() {
			t.Error("downstream was called after GetBody failed")
		}
	})

	t.Run("Close failure does not block replay", func(t *testing.T) {
		closeErr := errors.New("close failed")
		original := &trackedRequestBody{
			Reader:   strings.NewReader("original"),
			closeErr: closeErr,
		}
		replacement := &trackedRequestBody{Reader: strings.NewReader("replacement")}
		req := newRequest(t, original)
		req.GetBody = func() (io.ReadCloser, error) {
			return replacement, nil
		}

		var downstreamCalled atomic.Bool
		next := retry.RoundTripperFunc(
			func(got *http.Request) (*http.Response, error) {
				downstreamCalled.Store(true)
				_ = got.Body.Close()
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       http.NoBody,
					Header:     make(http.Header),
					Request:    got,
				}, nil
			},
		)

		resp, err := RewindBodyMiddleware(next).RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip propagated the Body.Close error: %v", err)
		}
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})
		if !original.closed.Load() {
			t.Error("original body Close was not attempted")
		}
		if !downstreamCalled.Load() {
			t.Error("downstream was not called after Body.Close failed")
		}
	})

	t.Run("without GetBody passes through unchanged", func(t *testing.T) {
		original := &trackedRequestBody{Reader: strings.NewReader("original")}
		req := newRequest(t, original)

		next := retry.RoundTripperFunc(
			func(got *http.Request) (*http.Response, error) {
				if got != req {
					t.Error("middleware cloned a request without GetBody")
				}
				if original.closed.Load() {
					t.Error("middleware closed a body it did not replace")
				}
				_ = got.Body.Close()
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       http.NoBody,
					Header:     make(http.Header),
					Request:    got,
				}, nil
			},
		)

		resp, err := RewindBodyMiddleware(next).RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})
		if !original.closed.Load() {
			t.Error("downstream did not close the original body")
		}
	})
}

// trackingTransport records every response body it hands back so a test can
// assert none were leaked.
type trackingTransport struct {
	mu     sync.Mutex
	bodies []*trackedBody
}

type trackedBody struct {
	io.ReadCloser
	closed atomic.Bool
}

func (b *trackedBody) Close() error {
	b.closed.Store(true)
	return b.ReadCloser.Close()
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	tb := &trackedBody{ReadCloser: resp.Body}
	resp.Body = tb

	t.mu.Lock()
	t.bodies = append(t.bodies, tb)
	t.mu.Unlock()

	return resp, nil
}

func (t *trackingTransport) assertAllClosed(tb testing.TB, wantCount int) {
	tb.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.bodies) != wantCount {
		tb.Errorf("upstream responses = %d, want %d", len(t.bodies), wantCount)
	}
	for i, b := range t.bodies {
		if !b.closed.Load() {
			tb.Errorf("response body %d was never closed", i)
		}
	}
}

// newTrackingClient builds a client whose retry behavior is fast enough for a
// unit test, that refuses redirects, and whose response bodies are all
// observable.
func newTrackingClient(t *testing.T, endpoints Endpoints) (*Client, *trackingTransport) {
	t.Helper()
	tracker := &trackingTransport{}
	httpClient, err := retry.NewClient(
		retry.WithNoLogging(),
		retry.WithMaxRetries(2),
		retry.WithInitialRetryDelay(time.Millisecond),
		retry.WithMaxRetryDelay(2*time.Millisecond),
		// The same body-replay middleware the package default installs.
		// Without it a retried POST is rejected by net/http before it reaches
		// the server and the later attempts produce no response at all — which
		// would hide exactly the body leak this test is about.
		retry.WithPerAttemptMiddleware(RewindBodyMiddleware),
		retry.WithHTTPClient(&http.Client{
			Transport: tracker,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}),
	)
	if err != nil {
		t.Fatalf("retry.NewClient: %v", err)
	}
	client, err := NewClient("cid", endpoints,
		WithClientSecret("secret"),
		WithHTTPClient(httpClient),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client, tracker
}

// TestResponseBodyClosedOnRetryExhaustion covers the shape go-httpretry
// returns once retries run out: a non-nil response together with a non-nil
// *retry.RetryError. Returning early on the error alone used to leak the final
// attempt's body and its connection.
func TestResponseBodyClosedOnRetryExhaustion(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{"getJSON via TokenInfoRequest", func(c *Client) error {
			_, err := c.TokenInfoRequest(context.Background(), "tok")
			return err
		}},
		{"getJSON via PersonalAPIKeyTokenInfoRequest", func(c *Client) error {
			_, err := c.PersonalAPIKeyTokenInfoRequest(context.Background(), "sgk_x")
			return err
		}},
		{"postForm via Introspect", func(c *Client) error {
			_, err := c.Introspect(context.Background(), "tok")
			return err
		}},
		{"Revoke", func(c *Client) error {
			return c.Revoke(context.Background(), "tok")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
				}),
			)
			t.Cleanup(server.Close)

			client, tracker := newTrackingClient(t, Endpoints{
				TokenInfoURL:     server.URL + "/tokeninfo",
				IntrospectionURL: server.URL + "/introspect",
				RevocationURL:    server.URL + "/revoke",
			})

			if err := tt.call(client); err == nil {
				t.Fatal("expected an error after exhausted retries")
			}
			// Initial attempt plus two retries, every body closed.
			tracker.assertAllClosed(t, 3)
		})
	}
}

// TestResponseBodyClosedOnEveryOutcome checks the non-retry paths still close
// their bodies: success, a non-2xx error response, a decode failure, and an
// oversized payload.
func TestResponseBodyClosedOnEveryOutcome(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
			},
		},
		{
			name: "non-2xx",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			},
			wantErr: true,
		},
		{
			name: "decode failure",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"active":`))
			},
			wantErr: true,
		},
		{
			name: "oversized payload",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"scope":"`))
				_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
				_, _ = w.Write([]byte(`"}`))
			},
			wantErr: true,
		},
		{
			name: "redirect refused by a non-redirecting client",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://elsewhere.example.com/tokeninfo")
				w.WriteHeader(http.StatusTemporaryRedirect)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			t.Cleanup(server.Close)

			client, tracker := newTrackingClient(t, Endpoints{
				TokenInfoURL: server.URL + "/tokeninfo",
			})

			_, err := client.PersonalAPIKeyTokenInfoRequest(context.Background(), "sgk_x")
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			tracker.assertAllClosed(t, 1)
		})
	}
}

// TestDefaultClientReplaysFormBodyOnRetry pins the property that made retries
// on every POST path a no-op before RewindBodyMiddleware was installed in the
// package default: go-httpretry clones the request per attempt, but a clone
// shares the already-consumed Body reader, so attempts 2..N were rejected by
// net/http with "ContentLength=N with Body length 0" before leaving the
// process. The upstream error was replaced by that one, so callers could no
// longer match it with errors.As against *Error.
func TestDefaultClientReplaysFormBodyOnRetry(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)

			mu.Lock()
			bodies = append(bodies, string(body))
			attempt := len(bodies)
			mu.Unlock()

			// Fail the first attempt with a retryable status, then succeed.
			if attempt == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "user-1"})
		}),
	)
	t.Cleanup(server.Close)

	// No WithHTTPClient: exercise exactly the client NewClient builds.
	client, err := NewClient("cid", Endpoints{IntrospectionURL: server.URL + "/introspect"},
		WithClientSecret("secret"),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, err := client.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !res.Active || res.Sub != "user-1" {
		t.Errorf("result = %+v, want the retried response to be decoded", res)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("upstream attempts = %d, want 2 (the retry never reached the server)", len(bodies))
	}
	if bodies[0] == "" || bodies[1] != bodies[0] {
		t.Errorf("attempt bodies = %q, want the form replayed identically on the retry", bodies)
	}
	if !strings.Contains(bodies[1], "token=tok") {
		t.Errorf("retried body = %q, want it to carry the form fields", bodies[1])
	}
}

func TestDefaultHTTPClientRedirectPolicy(t *testing.T) {
	t.Run("refuses redirects by default", func(t *testing.T) {
		for _, status := range []int{
			http.StatusMovedPermanently,
			http.StatusFound,
			http.StatusSeeOther,
			http.StatusTemporaryRedirect,
			http.StatusPermanentRedirect,
		} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				var targetCalls atomic.Int64
				target := httptest.NewServer(http.HandlerFunc(
					func(w http.ResponseWriter, _ *http.Request) {
						targetCalls.Add(1)
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
					},
				))
				t.Cleanup(target.Close)

				source := httptest.NewServer(http.HandlerFunc(
					func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Location", target.URL+"/capture")
						w.WriteHeader(status)
					},
				))
				t.Cleanup(source.Close)

				client, err := NewClient(
					"client-id",
					Endpoints{IntrospectionURL: source.URL + "/introspect"},
					WithClientSecret("client-secret"),
				)
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}

				if _, err := client.Introspect(t.Context(), "token"); err == nil {
					t.Fatal("Introspect error = nil, want refused redirect")
				}
				if got := targetCalls.Load(); got != 0 {
					t.Errorf("redirect target calls = %d, want 0", got)
				}
			})
		}
	})

	t.Run("explicit HTTP client override can follow redirects", func(t *testing.T) {
		type capturedForm struct {
			clientID     string
			clientSecret string
			token        string
		}
		captured := make(chan capturedForm, 1)
		target := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm: %v", err)
				}
				captured <- capturedForm{
					clientID:     r.PostForm.Get("client_id"),
					clientSecret: r.PostForm.Get("client_secret"),
					token:        r.PostForm.Get("token"),
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
			},
		))
		t.Cleanup(target.Close)

		source := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.URL+"/capture")
				w.WriteHeader(http.StatusTemporaryRedirect)
			},
		))
		t.Cleanup(source.Close)

		retryClient, err := NewDefaultHTTPClient(
			retry.WithHTTPClient(&http.Client{}),
		)
		if err != nil {
			t.Fatalf("NewDefaultHTTPClient: %v", err)
		}
		client, err := NewClient(
			"client-id",
			Endpoints{IntrospectionURL: source.URL + "/introspect"},
			WithClientSecret("client-secret"),
			WithHTTPClient(retryClient),
		)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}

		res, err := client.Introspect(t.Context(), "token")
		if err != nil {
			t.Fatalf("Introspect: %v", err)
		}
		if !res.Active {
			t.Errorf("result = %+v, want active response from redirect target", res)
		}

		got := <-captured
		want := capturedForm{
			clientID:     "client-id",
			clientSecret: "client-secret",
			token:        "token",
		}
		if got != want {
			t.Errorf("redirected form = %+v, want %+v", got, want)
		}
	})
}
