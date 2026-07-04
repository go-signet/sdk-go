package credstore_test

import (
	"testing"
	"time"

	"github.com/go-signet/sdk-go/credstore"
)

func TestToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "expired token",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "not expired token",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "zero expiry (no expiry)",
			expiresAt: time.Time{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &credstore.Token{
				AccessToken: "test-token",
				ExpiresAt:   tt.expiresAt,
			}
			if got := token.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_IsValid(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
		expiresAt   time.Time
		want        bool
	}{
		{
			name:        "valid token with future expiry",
			accessToken: "test-token",
			expiresAt:   time.Now().Add(1 * time.Hour),
			want:        true,
		},
		{
			name:        "valid token with zero expiry",
			accessToken: "test-token",
			expiresAt:   time.Time{},
			want:        true,
		},
		{
			name:        "expired token",
			accessToken: "test-token",
			expiresAt:   time.Now().Add(-1 * time.Hour),
			want:        false,
		},
		{
			name:        "empty access token",
			accessToken: "",
			expiresAt:   time.Now().Add(1 * time.Hour),
			want:        false,
		},
		{
			name:        "empty access token and expired",
			accessToken: "",
			expiresAt:   time.Now().Add(-1 * time.Hour),
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &credstore.Token{
				AccessToken: tt.accessToken,
				ExpiresAt:   tt.expiresAt,
			}
			if got := token.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
