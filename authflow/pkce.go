package authflow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/go-signet/sdk-go/oauth"
)

// PKCE holds a code verifier and its corresponding code challenge (RFC 7636).
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string // always "S256"
}

// NewPKCE generates a new PKCE verifier and challenge pair.
func NewPKCE() (*PKCE, error) {
	// RFC 7636 §4.1: code_verifier = 43-128 chars from [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// RFC 7636 §4.2: code_challenge = BASE64URL(SHA256(code_verifier))
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &PKCE{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    oauth.PKCEMethodS256,
	}, nil
}
