package authflow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/oauth"
)

func TestWithResourcesCopiesAndValidates(t *testing.T) {
	resources := []string{" https://api-a.example.com "}
	opt := WithResources(resources...)
	resources[0] = "https://mutated.example.com"
	cfg := &flowConfig{}
	opt(cfg)
	got, err := validateResources(cfg.resources)
	if err != nil {
		t.Fatalf("validateResources: %v", err)
	}
	if !slices.Equal(got, []string{"https://api-a.example.com"}) {
		t.Fatalf("resources = %v", got)
	}

	for _, resources := range [][]string{{""}, {"https://api.example.com", " \t "}} {
		_, err := validateResources(resources)
		var oauthErr *oauth.Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != oauth.ErrCodeInvalidRequest {
			t.Fatalf("error = %v, want invalid_request", err)
		}
	}
}

func TestAuthorizationParametersCarryEveryResource(t *testing.T) {
	values := url.Values{"scope": {"read"}}
	addResources(values, []string{"https://api-a.example.com", "https://api-b.example.com"})
	if got := values["resource"]; !slices.Equal(got, []string{
		"https://api-a.example.com", "https://api-b.example.com",
	}) {
		t.Fatalf("resources = %v", got)
	}
}

func TestRunDeviceFlowSendsResourcesOnBothRequests(t *testing.T) {
	var forms [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		forms = append(forms, slices.Clone(r.PostForm["resource"]))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device":
			_, _ = w.Write([]byte(`{
				"device_code":"device-code","user_code":"ABCD",
				"verification_uri":"https://auth.example.com/device",
				"expires_in":5,"interval":1
			}`))
		case "/token":
			_, _ = w.Write([]byte(`{
				"access_token":"token","token_type":"Bearer","expires_in":300
			}`))
		}
	}))
	t.Cleanup(server.Close)
	client, err := oauth.NewClient("client", oauth.Endpoints{
		DeviceAuthorizationURL: server.URL + "/device",
		TokenURL:               server.URL + "/token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = RunDeviceFlow(t.Context(), client, []string{"read"},
		WithResources("https://api-a.example.com"),
		WithDeviceFlowHandler(&testDeviceHandler{}),
	)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if len(forms) != 2 {
		t.Fatalf("requests = %d, want 2", len(forms))
	}
	for i, got := range forms {
		if !slices.Equal(got, []string{"https://api-a.example.com"}) {
			t.Errorf("request %d resources = %v", i, got)
		}
	}
}

func TestTokenSourceSeparatesResourceCachesAndRefreshesResource(t *testing.T) {
	store := newStubStore()
	client, err := oauth.NewClient("client", oauth.Endpoints{TokenURL: "http://unused"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	a := NewTokenSource(client, WithStore(store), WithTokenResources("https://api-a.example.com"))
	b := NewTokenSource(client, WithStore(store), WithTokenResources("https://api-b.example.com"))
	aReordered := NewTokenSource(client, WithStore(store), WithTokenResources(
		"https://api-c.example.com", "https://api-a.example.com",
	))
	aCanonical := NewTokenSource(client, WithStore(store), WithTokenResources(
		"https://api-a.example.com", "https://api-c.example.com",
	))
	token := &oauth.Token{AccessToken: "token-a", ExpiresAt: time.Now().Add(time.Hour)}
	if err := a.SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if a.storeKey() == b.storeKey() || a.storeKey() == client.ClientID() {
		t.Fatalf("resource store keys are not isolated: %q %q", a.storeKey(), b.storeKey())
	}
	if aReordered.storeKey() != aCanonical.storeKey() {
		t.Fatalf("resource-set order changed cache key: %q %q",
			aReordered.storeKey(), aCanonical.storeKey())
	}
	got, err := a.Token(context.Background())
	if err != nil || got.AccessToken != "token-a" {
		t.Fatalf("resource A cache = %+v, %v", got, err)
	}
	if _, err := b.Token(context.Background()); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("resource B error = %v, want ErrReauthRequired", err)
	}
}

func TestTokenSourceResourceDelimiterDoesNotAliasCache(t *testing.T) {
	store := newStubStore()
	client, err := oauth.NewClient("client", oauth.Endpoints{TokenURL: "http://unused"})
	if err != nil {
		t.Fatal(err)
	}
	joined := NewTokenSource(client, WithStore(store), WithTokenResources("a\x00b"))
	separate := NewTokenSource(client, WithStore(store), WithTokenResources("a", "b"))
	if err := joined.SaveToken(&oauth.Token{
		AccessToken: "wrong-audience-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := separate.Token(t.Context()); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("separate resources error = %v, want ErrReauthRequired", err)
	}
}

func TestInvalidFlowResourceFailsBeforeNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid resource must fail before network I/O")
	}))
	t.Cleanup(server.Close)
	client, err := oauth.NewClient("client", oauth.Endpoints{
		DeviceAuthorizationURL: server.URL,
		TokenURL:               server.URL,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = RunDeviceFlow(t.Context(), client, nil, WithResources(" "))
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != oauth.ErrCodeInvalidRequest {
		t.Fatalf("error = %v, want invalid_request", err)
	}
}
