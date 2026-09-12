package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExchangeOnBehalfOf(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		want := map[string]string{
			"grant_type":          GrantTypeJWTBearer,
			"requested_token_use": RequestedTokenUseOnBehalfOf,
			"assertion":           "source-token",
			"resource":            "https://api-b.example.com",
			"scope":               "orders.read orders.write",
			"client_id":           "api-a",
			"client_secret":       "secret",
		}
		for key, value := range want {
			if got := r.PostForm[key]; !slices.Equal(got, []string{value}) {
				t.Errorf("%s = %q, want exactly %q", key, got, value)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "delegated-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"scope":        "orders.read orders.write",
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient("api-a", Endpoints{TokenURL: server.URL}, WithClientSecret("secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	token, err := client.ExchangeOnBehalfOf(t.Context(), OnBehalfOfRequest{
		Assertion: "source-token",
		Resource:  " https://api-b.example.com ",
		Scopes:    []string{" orders.read ", "", "orders.write"},
	})
	if err != nil {
		t.Fatalf("ExchangeOnBehalfOf: %v", err)
	}
	if token.AccessToken != "delegated-token" || token.RefreshToken != "" || token.IDToken != "" {
		t.Fatalf("unexpected token: %+v", token)
	}
}

func TestExchangeOnBehalfOfRejectsInvalidLocalInput(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient("api-a", Endpoints{TokenURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tests := []OnBehalfOfRequest{
		{Resource: "https://api-b.example.com", Scopes: []string{"read"}},
		{Assertion: "source", Scopes: []string{"read"}},
		{Assertion: "source", Resource: "https://api-b.example.com"},
		{Assertion: "source", Resource: "https://api-b.example.com", Scopes: []string{" \t "}},
	}
	for _, req := range tests {
		_, err := client.ExchangeOnBehalfOf(context.Background(), req)
		var oauthErr *Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != ErrCodeInvalidRequest {
			t.Fatalf("error = %v, want invalid_request", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestExchangeOnBehalfOfPreservesOAuthErrorsWithoutSecrets(t *testing.T) {
	for _, code := range []string{
		ErrCodeInvalidGrant,
		ErrCodeInvalidScope,
		ErrCodeInvalidTarget,
		ErrCodeUnauthorizedClient,
		ErrCodeInvalidClient,
		ErrCodeUnsupportedGrantType,
	} {
		t.Run(code, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
			})
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)
			client, err := NewClient(
				"api-a",
				Endpoints{TokenURL: server.URL},
				WithClientSecret("client-secret-value"),
			)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, err = client.ExchangeOnBehalfOf(t.Context(), OnBehalfOfRequest{
				Assertion: "source-token-value",
				Resource:  "https://api-b.example.com",
				Scopes:    []string{"read"},
			})
			var oauthErr *Error
			if !errors.As(err, &oauthErr) || oauthErr.Code != code {
				t.Fatalf("error = %v, want %q", err, code)
			}
			if strings.Contains(err.Error(), "source-token-value") ||
				strings.Contains(err.Error(), "client-secret-value") {
				t.Fatalf("error leaked credentials: %v", err)
			}
		})
	}
}

func TestAudienceUnmarshalJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want Audience
	}{
		{name: "string", raw: `"https://api.example.com"`, want: Audience{"https://api.example.com"}},
		{name: "array", raw: `["api:a","api:b"]`, want: Audience{"api:a", "api:b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got Audience
			if err := json.Unmarshal([]byte(tc.raw), &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("audience = %v, want %v", got, tc.want)
			}
		})
	}
	for _, raw := range []string{`null`, `{}`, `[]`, `["ok",""]`, `42`} {
		var got Audience
		if err := json.Unmarshal([]byte(raw), &got); err == nil {
			t.Errorf("Unmarshal(%s) succeeded, want error", raw)
		}
	}
}

func TestOAuthGrantMethodsSendResources(t *testing.T) {
	var captured [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		captured = append(captured, slices.Clone(r.PostForm["resource"]))
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "device") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "device", "user_code": "code",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300, "interval": 1,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token", "token_type": "Bearer", "expires_in": 300,
		})
	}))
	t.Cleanup(server.Close)
	client, err := NewClient("client", Endpoints{
		TokenURL: server.URL + "/token", DeviceAuthorizationURL: server.URL + "/device",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resources := []string{" https://api-a.example.com ", "https://api-b.example.com"}
	if _, err = client.RequestDeviceCode(t.Context(), nil, resources); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ExchangeDeviceCode(t.Context(), "device", resources); err != nil {
		t.Fatal(err)
	}
	_, err = client.ExchangeAuthCode(
		t.Context(), "code", "redirect", "verifier", resources,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.ClientCredentials(t.Context(), nil, resources); err != nil {
		t.Fatal(err)
	}
	if _, err = client.RefreshToken(t.Context(), "refresh", resources); err != nil {
		t.Fatal(err)
	}
	want := []string{"https://api-a.example.com", "https://api-b.example.com"}
	if len(captured) != 5 {
		t.Fatalf("captured requests = %d, want 5", len(captured))
	}
	for i, got := range captured {
		if !slices.Equal(got, want) {
			t.Errorf("request %d resources = %v, want %v", i, got, want)
		}
	}
}
