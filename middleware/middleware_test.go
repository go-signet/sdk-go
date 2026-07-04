package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-signet/sdk-go/oauth"
)

func setupTokenInfoServer(t *testing.T) (*httptest.Server, *oauth.Client) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer valid-token" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"active":       true,
				"user_id":      "user-123",
				"client_id":    "my-client",
				"scope":        "read write",
				"exp":          1900000000,
				"subject_type": "user",
			})
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_token",
			"error_description": "Token is invalid",
		})
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		TokenInfoURL: server.URL + "/oauth/tokeninfo",
	}
	client, err := oauth.NewClient("my-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, client
}

func setupIntrospectionServer(t *testing.T) (*httptest.Server, *oauth.Client) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			return
		}
		token := r.PostForm.Get("token")

		w.Header().Set("Content-Type", "application/json")
		if token == "valid-token" {
			json.NewEncoder(w).Encode(map[string]any{
				"active":     true,
				"scope":      "read write",
				"client_id":  "my-client",
				"username":   "testuser",
				"token_type": "Bearer",
				"exp":        1900000000,
				"sub":        "user-123",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"active": false,
		})
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		IntrospectionURL: server.URL + "/oauth/introspect",
	}
	client, err := oauth.NewClient("my-client", endpoints, oauth.WithClientSecret("secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, client
}

func TestBearerAuth_ValidToken(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("TokenInfoFromContext returned false")
			return
		}
		if info.UserID != "user-123" {
			t.Errorf("UserID = %q, want %q", info.UserID, "user-123")
		}
		if info.Scope != "read write" {
			t.Errorf("Scope = %q, want %q", info.Scope, "read write")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBearerAuth_CaseInsensitiveBearer(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// RFC 6750: auth scheme is case-insensitive
	for _, scheme := range []string{"bearer valid-token", "BEARER valid-token", "Bearer valid-token"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", scheme)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("scheme %q: status = %d, want %d", scheme, rec.Code, http.StatusOK)
		}
	}
}

func TestBearerAuth_MissingToken(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBearerAuth_InvalidToken(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBearerAuth_RequiredScopes(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
		WithRequiredScopes("admin"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for missing scope")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestBearerAuth_RequiredScopes_CustomErrorHandler(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	var gotErr error
	handler := BearerAuth(
		WithOAuthClient(oauthClient),
		WithRequiredScopes("admin"),
		WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			gotErr = err
			w.WriteHeader(http.StatusTeapot)
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for missing scope")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf(
			"status = %d, want %d (custom handler should be invoked)",
			rec.Code,
			http.StatusTeapot,
		)
	}

	var oauthErr *oauth.Error
	if !errors.As(gotErr, &oauthErr) {
		t.Fatalf("error handler received %v, want *oauth.Error", gotErr)
	}
	if oauthErr.Code != oauth.ErrCodeInsufficientScope {
		t.Errorf("error code = %q, want %q", oauthErr.Code, oauth.ErrCodeInsufficientScope)
	}
}

func TestBearerAuth_RequiredScopes_Satisfied(t *testing.T) {
	_, oauthClient := setupTokenInfoServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
		WithRequiredScopes("read"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBearerAuth_Introspection_ValidToken(t *testing.T) {
	_, oauthClient := setupIntrospectionServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
		WithIntrospection(),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("TokenInfoFromContext returned false")
			return
		}
		if info.UserID != "user-123" {
			t.Errorf("UserID = %q, want %q", info.UserID, "user-123")
		}
		if info.Scope != "read write" {
			t.Errorf("Scope = %q, want %q", info.Scope, "read write")
		}
		if info.SubjectType != "user" {
			t.Errorf("SubjectType = %q, want %q", info.SubjectType, "user")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBearerAuth_Introspection_InactiveToken(t *testing.T) {
	_, oauthClient := setupIntrospectionServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
		WithIntrospection(),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer inactive-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBearerAuth_Introspection_RequiredScopes(t *testing.T) {
	_, oauthClient := setupIntrospectionServer(t)

	handler := BearerAuth(
		WithOAuthClient(oauthClient),
		WithIntrospection(),
		WithRequiredScopes("admin"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for missing scope")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestBearerAuth_ServerError_NoClient(t *testing.T) {
	handler := BearerAuth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestRequireScope(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireScope("write")(inner)

	// Test without token info
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Test with matching scope
	info := &TokenInfo{Scope: "read write"}
	ctx := context.WithValue(context.Background(), contextKey{}, info)
	req = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Test with missing scope
	handler2 := RequireScope("admin")(inner)
	req = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	handler2.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// An empty required scope must fail closed: strings.Fields never yields
	// "", so the token can never carry it.
	handler3 := RequireScope("")(inner)
	req = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	handler3.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("empty required scope: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestTokenInfo_firstMissingScope(t *testing.T) {
	tests := []struct {
		name        string
		tokenScope  string
		required    []string
		wantScope   string
		wantMissing bool
	}{
		{
			name:        "no required scopes",
			tokenScope:  "read write",
			required:    nil,
			wantScope:   "",
			wantMissing: false,
		},
		{
			name:        "all present",
			tokenScope:  "read write admin",
			required:    []string{"read", "admin"},
			wantScope:   "",
			wantMissing: false,
		},
		{
			name:        "first missing reported",
			tokenScope:  "read",
			required:    []string{"write", "admin"},
			wantScope:   "write",
			wantMissing: true,
		},
		{
			name:        "empty required scope fails closed",
			tokenScope:  "read write",
			required:    []string{""},
			wantScope:   "",
			wantMissing: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &TokenInfo{Scope: tt.tokenScope}
			scope, missing := info.firstMissingScope(tt.required)
			if scope != tt.wantScope || missing != tt.wantMissing {
				t.Errorf(
					"firstMissingScope() = (%q, %t), want (%q, %t)",
					scope, missing, tt.wantScope, tt.wantMissing,
				)
			}
		})
	}
}

func TestTokenInfo_HasScope(t *testing.T) {
	info := &TokenInfo{Scope: "read write admin"}

	if !info.HasScope("read") {
		t.Error("should have read scope")
	}
	if !info.HasScope("write") {
		t.Error("should have write scope")
	}
	if !info.HasScope("admin") {
		t.Error("should have admin scope")
	}
	if info.HasScope("delete") {
		t.Error("should not have delete scope")
	}
}

func TestHasScope_Convenience(t *testing.T) {
	ctx := context.Background()
	if HasScope(ctx, "read") {
		t.Error("should return false without token info")
	}

	info := &TokenInfo{Scope: "read write"}
	ctx = context.WithValue(ctx, contextKey{}, info)
	if !HasScope(ctx, "read") {
		t.Error("should return true for matching scope")
	}
}

func TestBearerAuth_CustomErrorHandler(t *testing.T) {
	customCalled := false
	handler := BearerAuth(
		WithOAuthClient(nil),
		WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			customCalled = true
			w.WriteHeader(http.StatusTeapot)
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !customCalled {
		t.Error("custom error handler was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}
