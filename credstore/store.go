package credstore

import (
	"errors"
	"time"
)

// ErrNotFound indicates that no data was found for the given client ID.
var ErrNotFound = errors.New("not found")

// ErrEmptyClientID is returned when an empty client ID is passed to Save.
var ErrEmptyClientID = errors.New("client ID cannot be empty")

// Store defines the interface for loading, saving, and deleting data by client ID.
type Store[T any] interface {
	Load(clientID string) (T, error)
	Save(clientID string, data T) error
	Delete(clientID string) error
	String() string
}

// Lister is an optional interface for stores that support listing stored client IDs.
type Lister interface {
	List() ([]string, error)
}

// Token represents saved tokens for a specific client.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id"`
}

// IsExpired reports whether the token has expired.
// Returns false if ExpiresAt is zero (token has no expiry).
func (t *Token) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// IsValid reports whether the token has a non-empty access token and is not expired.
func (t *Token) IsValid() bool {
	return t.AccessToken != "" && !t.IsExpired()
}

// NewTokenFileStore creates a FileStore for Token values using JSON encoding.
func NewTokenFileStore(filePath string) *FileStore[Token] {
	return NewFileStore[Token](filePath, JSONCodec[Token]{})
}

// NewTokenKeyringStore creates a KeyringStore for Token values using JSON encoding.
func NewTokenKeyringStore(serviceName string) *KeyringStore[Token] {
	return NewKeyringStore[Token](serviceName, JSONCodec[Token]{})
}

// NewStringFileStore creates a FileStore for plain string values.
func NewStringFileStore(filePath string) *FileStore[string] {
	return NewFileStore[string](filePath, StringCodec{})
}

// NewStringKeyringStore creates a KeyringStore for plain string values.
func NewStringKeyringStore(serviceName string) *KeyringStore[string] {
	return NewKeyringStore[string](serviceName, StringCodec{})
}

// NewTokenEncryptedFileStore creates an EncryptedFileStore for Token values
// using JSON encoding. The master key is stored in the OS keyring under
// serviceName; the encrypted tokens are written to filePath.
func NewTokenEncryptedFileStore(serviceName, filePath string) *EncryptedFileStore[Token] {
	return NewEncryptedFileStore[Token](serviceName, filePath, JSONCodec[Token]{})
}

// DefaultTokenSecureStore creates a SecureStore for Token values with sensible defaults.
// Tokens are AES-256-GCM-encrypted to filePath+".enc" with the master key in
// the OS keyring; see DefaultSecureStore for details.
func DefaultTokenSecureStore(
	serviceName, filePath string,
	opts ...SecureStoreOption[Token],
) *SecureStore[Token] {
	return DefaultSecureStore[Token](serviceName, filePath, JSONCodec[Token]{}, opts...)
}
