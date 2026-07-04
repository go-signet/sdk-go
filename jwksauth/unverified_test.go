package jwksauth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// makeJWT assembles a syntactically-valid JWT (no signature math) with the
// given payload JSON. It is enough for testing UnverifiedIssuer; we never
// validate the signature here.
func makeJWT(t *testing.T, payloadJSON string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".sig"
}

func TestUnverifiedIssuer_Happy(t *testing.T) {
	tok := makeJWT(t, `{"iss":"https://auth.example.com","sub":"u1"}`)
	got, err := UnverifiedIssuer(tok)
	if err != nil {
		t.Fatalf("UnverifiedIssuer: %v", err)
	}
	if got != "https://auth.example.com" {
		t.Errorf("iss = %q, want https://auth.example.com", got)
	}
}

func TestUnverifiedIssuer_Errors(t *testing.T) {
	missingIssToken := makeJWT(t, `{"sub":"u1"}`)
	nonJSONPayload := "abc." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".ghi"
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"one segment", "abc"},
		{"two segments", "abc.def"},
		{"too many segments", "a.b.c.d.e.f"},
		{"bad base64 payload", "abc.@@@.ghi"},
		{"non-json payload", nonJSONPayload},
		{"missing iss claim", missingIssToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnverifiedIssuer(tc.raw)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			// Public contract: every error path wraps ErrMalformedJWT so
			// callers can detect "not a JWT" with one errors.Is check.
			if !errors.Is(err, ErrMalformedJWT) {
				t.Errorf("error %v does not wrap ErrMalformedJWT", err)
			}
		})
	}
}

func TestUnverifiedIssuer_MissingIssMessage(t *testing.T) {
	tok := makeJWT(t, `{"sub":"u1"}`)
	_, err := UnverifiedIssuer(tok)
	if err == nil || !strings.Contains(err.Error(), "iss") {
		t.Fatalf("expected missing-iss error, got %v", err)
	}
}

// TestUnverifiedIssuer_ManyDots ensures the SplitN cap prevents pathological
// inputs from succeeding. A JWT with extra dots inside its payload segment
// is still 3-part if encoded properly; the test below uses 4+ parts to
// exercise the early reject.
func TestUnverifiedIssuer_ManyDots(t *testing.T) {
	raw := strings.Repeat("a.", 100) + "b"
	_, err := UnverifiedIssuer(raw)
	if err == nil {
		t.Fatal("expected error for many-dot input")
	}
}

// TestUnverifiedIssuer_OversizedRaw asserts the size cap rejects a JWT
// large enough to force a meaningful payload allocation, defending the
// unverified parse path against header-stuffing.
func TestUnverifiedIssuer_OversizedRaw(t *testing.T) {
	raw := strings.Repeat("A", maxRawJWTSize+1)
	_, err := UnverifiedIssuer(raw)
	if !errors.Is(err, ErrMalformedJWT) {
		t.Fatalf("error = %v, want wrap of ErrMalformedJWT", err)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error message should mention size: %v", err)
	}
}

// TestUnverifiedIssuer_OversizedPayload asserts an inner segment over the
// payload cap is rejected before base64 decoding runs.
func TestUnverifiedIssuer_OversizedPayload(t *testing.T) {
	// Build a 3-segment token where segment 2 exceeds maxJWTPayloadSize but
	// the overall length stays under maxRawJWTSize.
	bigPayload := strings.Repeat("A", maxJWTPayloadSize+1)
	raw := "h." + bigPayload + ".s"
	_, err := UnverifiedIssuer(raw)
	if !errors.Is(err, ErrMalformedJWT) {
		t.Fatalf("error = %v, want wrap of ErrMalformedJWT", err)
	}
	if !strings.Contains(err.Error(), "payload too large") {
		t.Errorf("error message should mention payload size: %v", err)
	}
}
