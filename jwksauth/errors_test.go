package jwksauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteAuthError_InvalidToken(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteAuthError(rec, ErrCodeInvalidToken, "bad token")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	got := rec.Header().Get("WWW-Authenticate")
	wantSubs := []string{`Bearer error="invalid_token"`, `error_description="bad token"`}
	for _, s := range wantSubs {
		if !strings.Contains(got, s) {
			t.Errorf("WWW-Authenticate %q missing %q", got, s)
		}
	}
	if strings.Contains(got, "scope=") {
		t.Errorf("WWW-Authenticate %q should not advertise scope on invalid_token", got)
	}
}

func TestWriteAuthError_InsufficientScope(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteAuthError(rec, ErrCodeInsufficientScope, "required scope: email", "email")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	got := rec.Header().Get("WWW-Authenticate")
	wantSubs := []string{
		`Bearer error="insufficient_scope"`,
		`error_description="required scope: email"`,
		`scope="email"`,
	}
	for _, s := range wantSubs {
		if !strings.Contains(got, s) {
			t.Errorf("WWW-Authenticate %q missing %q", got, s)
		}
	}
}

func TestWriteAuthError_InvalidRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteAuthError(rec, ErrCodeInvalidRequest, "malformed Authorization header")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	got := rec.Header().Get("WWW-Authenticate")
	wantSubs := []string{
		`Bearer error="invalid_request"`,
		`error_description="malformed Authorization header"`,
	}
	for _, s := range wantSubs {
		if !strings.Contains(got, s) {
			t.Errorf("WWW-Authenticate %q missing %q", got, s)
		}
	}
}

func TestWriteAuthError_DropsScopeOnNonInsufficientCode(t *testing.T) {
	// Per RFC 6750 §3.1 the scope attribute is only defined for
	// insufficient_scope; passing scopes with another code must not produce
	// a non-compliant challenge.
	for _, code := range []string{ErrCodeInvalidToken, ErrCodeInvalidRequest, ErrCodeServerError} {
		t.Run(code, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteAuthError(rec, code, "boom", "email", "profile")
			got := rec.Header().Get("WWW-Authenticate")
			if strings.Contains(got, "scope=") {
				t.Errorf("WWW-Authenticate %q must not include scope= for code %q", got, code)
			}
		})
	}
}

func TestWriteAuthError_MultipleScopes(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteAuthError(rec, ErrCodeInsufficientScope, "missing scopes", "email", "profile")

	got := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(got, `scope="email profile"`) {
		t.Errorf("WWW-Authenticate %q should join scopes with space", got)
	}
}
