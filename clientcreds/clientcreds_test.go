package clientcreds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/oauth"
)

func setupCCServer(t *testing.T) (*httptest.Server, *oauth.Client) {
	t.Helper()
	var tokenCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}

		count := tokenCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cc-token-" + r.PostForm.Get("scope") + "-" + strconv.Itoa(int(count)),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.PostForm.Get("scope"),
		})
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		TokenURL: server.URL + "/oauth/token",
	}
	client, err := oauth.NewClient("test-client", endpoints, oauth.WithClientSecret("test-secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, client
}

func TestTokenSource_Token(t *testing.T) {
	_, oauthClient := setupCCServer(t)

	ts := NewTokenSource(oauthClient, WithScopes("read", "write"))

	token, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if !token.IsValid() {
		t.Error("token should be valid")
	}
}

func TestTokenSource_Resources(t *testing.T) {
	var got []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		got = append(got, r.PostForm["resource"]...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":300}`))
	}))
	t.Cleanup(server.Close)
	client, err := oauth.NewClient("client", oauth.Endpoints{TokenURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ts := NewTokenSource(client, WithResources("https://api-a.example.com"))
	if _, err := ts.Token(t.Context()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if len(got) != 1 || got[0] != "https://api-a.example.com" {
		t.Fatalf("resources = %v", got)
	}
}

func TestTokenSource_Cache(t *testing.T) {
	_, oauthClient := setupCCServer(t)

	ts := NewTokenSource(oauthClient, WithScopes("read"))

	token1, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token 1: %v", err)
	}

	token2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token 2: %v", err)
	}

	if token1.AccessToken != token2.AccessToken {
		t.Error("second call should return cached token")
	}
}

func TestTokenSource_ExpiryDelta(t *testing.T) {
	var tokenCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := tokenCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-" + strconv.Itoa(int(count)),
			"token_type":   "Bearer",
			"expires_in":   1, // expires in 1 second
			"scope":        "read",
		})
	}))
	t.Cleanup(server.Close)

	oauthClient, err := oauth.NewClient(
		"test",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
		oauth.WithClientSecret("s"),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// With a large expiry delta, the token will be considered "about to expire" immediately
	ts := NewTokenSource(oauthClient, WithExpiryDelta(1*time.Hour))

	token1, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token 1: %v", err)
	}

	token2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token 2: %v", err)
	}

	if token1.AccessToken == token2.AccessToken {
		t.Error("expired token should trigger a new fetch")
	}
}

func TestTokenSource_HTTPClient(t *testing.T) {
	_, oauthClient := setupCCServer(t)
	ts := NewTokenSource(oauthClient, WithScopes("read"))

	// Get a token first so the transport has one cached
	_, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	httpClient := ts.HTTPClient()
	if httpClient == nil {
		t.Fatal("HTTPClient should not be nil")
	}

	// Create a test server that checks for Authorization header
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("missing Authorization header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(echoServer.Close)

	resp, err := httpClient.Get(echoServer.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestTokenSource_RoundTripper(t *testing.T) {
	_, oauthClient := setupCCServer(t)
	ts := NewTokenSource(oauthClient, WithScopes("read"))

	rt := ts.RoundTripper(http.DefaultTransport)
	if rt == nil {
		t.Fatal("RoundTripper should not be nil")
	}
}
