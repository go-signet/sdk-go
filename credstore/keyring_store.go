package credstore

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const probeUser = "__signet_probe__"

// KeyringStore stores values in the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).
type KeyringStore[T any] struct {
	serviceName string
	codec       Codec[T]
}

// NewKeyringStore creates a new KeyringStore with the given codec.
// Panics if codec is nil.
func NewKeyringStore[T any](serviceName string, codec Codec[T]) *KeyringStore[T] {
	if codec == nil {
		panic("credstore: NewKeyringStore called with nil codec")
	}
	return &KeyringStore[T]{serviceName: serviceName, codec: codec}
}

// Probe tests whether the OS keyring is available by setting and deleting a test entry.
func (k *KeyringStore[T]) Probe() bool {
	if err := keyring.Set(k.serviceName, probeUser, "probe"); err != nil {
		return false
	}
	if err := keyring.Delete(k.serviceName, probeUser); err != nil {
		return false
	}
	return true
}

// Load loads data from the keyring for the given client ID.
func (k *KeyringStore[T]) Load(clientID string) (T, error) {
	var zero T
	data, err := keyring.Get(k.serviceName, clientID)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return zero, ErrNotFound
		}
		return zero, fmt.Errorf("failed to read from keyring: %w", err)
	}

	decoded, err := k.codec.Decode(data)
	if err != nil {
		return zero, fmt.Errorf("failed to decode keyring data: %w", err)
	}
	return decoded, nil
}

// Save saves data to the keyring for the given client ID.
func (k *KeyringStore[T]) Save(clientID string, data T) error {
	if clientID == "" {
		return ErrEmptyClientID
	}

	encoded, err := k.codec.Encode(data)
	if err != nil {
		return fmt.Errorf("failed to encode data for keyring: %w", err)
	}

	if err := keyring.Set(k.serviceName, clientID, encoded); err != nil {
		return fmt.Errorf("failed to save to keyring: %w", err)
	}

	return nil
}

// Delete removes data for the given client ID from the keyring.
func (k *KeyringStore[T]) Delete(clientID string) error {
	err := keyring.Delete(k.serviceName, clientID)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("failed to delete from keyring: %w", err)
	}
	return nil
}

// ServiceName returns the keyring service name.
func (k *KeyringStore[T]) ServiceName() string {
	return k.serviceName
}

// String returns a description of this store.
func (k *KeyringStore[T]) String() string {
	return "keyring: " + k.serviceName
}
