package jwksauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseBearerHeader(t *testing.T) {
	tests := []struct {
		name      string
		hdr       string
		wantToken string
		wantState authState
	}{
		// Missing: no header, or any non-Bearer scheme. RFC 6750 §3 keeps
		// the challenge bare (no `error` attribute) for these cases.
		{"empty", "", "", authMissing},
		{"basic", "Basic dXNlcjpwYXNz", "", authMissing},
		{"unknown scheme", "MyScheme abc", "", authMissing},
		// Malformed: Bearer scheme present but token unparseable. RFC 6750
		// §3.1 reserves invalid_request for this case (the request is
		// malformed); the middleware maps it to HTTP 400.
		{"no token", "Bearer", "", authMalformed},
		{"trailing junk", "Bearer abc def", "", authMalformed},
		// Present: a usable token was extracted.
		{"plain", "Bearer abc.def.ghi", "abc.def.ghi", authPresent},
		{"lower scheme", "bearer abc.def.ghi", "abc.def.ghi", authPresent},
		{"upper scheme", "BEARER abc.def.ghi", "abc.def.ghi", authPresent},
		{"extra spaces", "Bearer    abc.def.ghi", "abc.def.ghi", authPresent},
		{"tab separator", "Bearer\tabc.def.ghi", "abc.def.ghi", authPresent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.hdr != "" {
				req.Header.Set("Authorization", tc.hdr)
			}
			gotToken, gotState := parseBearerHeader(req)
			if gotToken != tc.wantToken || gotState != tc.wantState {
				t.Errorf("parseBearerHeader() = (%q, %d), want (%q, %d)",
					gotToken, gotState, tc.wantToken, tc.wantState)
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		want string
	}{
		{"empty", "", ""},
		{"plain bearer", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"lower-case scheme", "bearer abc.def.ghi", "abc.def.ghi"},
		{"upper-case scheme", "BEARER abc.def.ghi", "abc.def.ghi"},
		{"extra spaces", "Bearer    abc.def.ghi", "abc.def.ghi"},
		{"tab-separated", "Bearer\tabc.def.ghi", "abc.def.ghi"},
		{"missing token", "Bearer", ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz", ""},
		{"three parts", "Bearer abc more", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.hdr != "" {
				req.Header.Set("Authorization", tc.hdr)
			}
			if got := ExtractBearerToken(req); got != tc.want {
				t.Errorf("ExtractBearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}
