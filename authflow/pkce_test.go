package authflow

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/go-signet/sdk-go/oauth"
)

func TestNewPKCE(t *testing.T) {
	pkce, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}

	if pkce.Method != oauth.PKCEMethodS256 {
		t.Errorf("Method = %q, want %q", pkce.Method, oauth.PKCEMethodS256)
	}

	if len(pkce.Verifier) < 43 {
		t.Errorf("Verifier too short: %d chars", len(pkce.Verifier))
	}

	// Verify that challenge matches verifier
	h := sha256.Sum256([]byte(pkce.Verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	if pkce.Challenge != expected {
		t.Errorf("Challenge mismatch: got %q, want %q", pkce.Challenge, expected)
	}
}

func TestNewPKCE_Uniqueness(t *testing.T) {
	pkce1, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE 1: %v", err)
	}
	pkce2, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE 2: %v", err)
	}

	if pkce1.Verifier == pkce2.Verifier {
		t.Error("two PKCE verifiers should be different")
	}
	if pkce1.Challenge == pkce2.Challenge {
		t.Error("two PKCE challenges should be different")
	}
}
