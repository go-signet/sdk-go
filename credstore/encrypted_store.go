package credstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// masterKeySize is the AES-256 key length in bytes.
const masterKeySize = 32

// masterKeyUser is the keyring account name under which the master key is stored.
const masterKeyUser = "__signet_master_key__"

// sealedPrefix versions the on-disk encrypted value format so a future
// algorithm change can be detected instead of guessed at.
const sealedPrefix = "v1:"

// masterKey manages a per-service AES-256 key held in the OS keyring and
// caches the derived AEAD in memory. See EncryptedFileStore for why only the
// key lives in the keyring.
type masterKey struct {
	store *KeyringStore[string]

	mu   sync.Mutex
	aead cipher.AEAD // cached after the first successful load or create
}

// loadLocked returns the cached or keyring-held AEAD. It returns ErrNotFound
// unwrapped when no key exists yet so callers can distinguish "no key" from
// "keyring unavailable". m.mu must be held.
func (m *masterKey) loadLocked() (cipher.AEAD, error) {
	if m.aead != nil {
		return m.aead, nil
	}

	encoded, err := m.store.Load(masterKeyUser)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, err
		}
		// e.g. Linux headless without Secret Service, or keyring locked.
		return nil, fmt.Errorf("failed to read master key: %w", err)
	}

	key, decodeErr := base64.StdEncoding.DecodeString(encoded)
	if decodeErr != nil || len(key) != masterKeySize {
		return nil, errors.New("corrupted master key in keyring")
	}
	return m.cacheLocked(key)
}

// cacheLocked builds the AEAD for key and caches it. m.mu must be held.
func (m *masterKey) cacheLocked(key []byte) (cipher.AEAD, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	m.aead = aead
	return aead, nil
}

// load returns the AEAD without ever creating a key, so decryption paths
// cannot mint a key that has no chance of opening existing ciphertext.
func (m *masterKey) load() (cipher.AEAD, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked()
}

// get returns the AEAD, generating and persisting a new key on first use.
func (m *masterKey) get() (cipher.AEAD, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	aead, err := m.loadLocked()
	if err == nil {
		return aead, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// First use: generate and persist a new key.
	key := make([]byte, masterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	if err := m.store.Save(masterKeyUser, base64.StdEncoding.EncodeToString(key)); err != nil {
		return nil, fmt.Errorf("failed to store master key: %w", err)
	}
	return m.cacheLocked(key)
}

// available reports whether the keyring can serve the master key without
// creating one: a cached or stored valid key counts, and so does a clean
// not-found (the key is generated lazily on first Save). A corrupted key or
// an unreachable keyring does not.
func (m *masterKey) available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.loadLocked()
	return err == nil || errors.Is(err, ErrNotFound)
}

// delete removes the master key from the keyring and drops the in-memory copy.
func (m *masterKey) delete() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aead = nil
	return m.store.Delete(masterKeyUser)
}

// newGCM creates an AES-256-GCM AEAD for the given key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

// sealValue encrypts plaintext with AES-256-GCM and returns
// "v1:" + base64(nonce || ciphertext).
func sealValue(aead cipher.AEAD, plaintext string) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	// Seal appends ciphertext+tag to nonce, so the stored value is self-contained.
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return sealedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// openValue decrypts a value produced by sealValue.
func openValue(aead cipher.AEAD, encoded string) (string, error) {
	rest, ok := strings.CutPrefix(encoded, sealedPrefix)
	if !ok {
		return "", errors.New("unrecognized encrypted value format")
	}
	data, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted value: %w", err)
	}
	if len(data) < aead.NonceSize() {
		return "", errors.New("encrypted value too short")
	}
	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Wrong key or tampered value — GCM authentication failed.
		return "", fmt.Errorf("failed to decrypt value (key mismatch or tampering): %w", err)
	}
	return string(plaintext), nil
}

// encryptedCodec wraps an inner codec with AES-256-GCM encryption using a
// keyring-held master key.
type encryptedCodec[T any] struct {
	inner Codec[T]
	key   *masterKey
}

// Encode encodes v with the inner codec and encrypts the result.
func (c encryptedCodec[T]) Encode(v T) (string, error) {
	aead, err := c.key.get()
	if err != nil {
		return "", err
	}
	plaintext, err := c.inner.Encode(v)
	if err != nil {
		return "", err
	}
	return sealValue(aead, plaintext)
}

// Decode decrypts s and decodes the plaintext with the inner codec.
func (c encryptedCodec[T]) Decode(s string) (T, error) {
	var zero T
	aead, err := c.key.load()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Deliberately not wrapping ErrNotFound: the value exists but
			// cannot be decrypted, which must not read as "no data stored".
			return zero, errors.New("cannot decrypt stored value: master key not found in keyring")
		}
		return zero, err
	}
	plaintext, err := openValue(aead, s)
	if err != nil {
		return zero, err
	}
	return c.inner.Decode(plaintext)
}

// EncryptedFileStore stores values encrypted with AES-256-GCM in a JSON file,
// keeping only the 32-byte master key in the OS keyring. The keyring payload
// is a constant 44 bytes (base64) regardless of value size, so it never hits
// the Windows Credential Manager 2560-byte blob limit or the macOS/Linux
// keyring item size limits. The values themselves (which can be several KB
// for tokens with groups claims) are encrypted into a file with 0600
// permissions, file locking, and atomic writes.
//
// EncryptedFileStore implements Store[T], Lister, and Prober.
type EncryptedFileStore[T any] struct {
	file *FileStore[T]
	key  *masterKey
}

// NewEncryptedFileStore creates an EncryptedFileStore. serviceName is the
// keyring service under which the master key is stored; filePath is the
// encrypted data file. Panics if codec is nil.
func NewEncryptedFileStore[T any](
	serviceName, filePath string,
	codec Codec[T],
) *EncryptedFileStore[T] {
	if codec == nil {
		panic("credstore: NewEncryptedFileStore called with nil codec")
	}
	key := &masterKey{store: NewStringKeyringStore(serviceName)}
	return &EncryptedFileStore[T]{
		file: NewFileStore[T](filePath, encryptedCodec[T]{inner: codec, key: key}),
		key:  key,
	}
}

// Probe reports whether the OS keyring can serve the master key. It is
// read-only: the key itself is generated lazily on the first Save. Once the
// key is cached in memory, Probe keeps reporting true even if the keyring
// later becomes unavailable, because the store remains operational with the
// cached key.
func (e *EncryptedFileStore[T]) Probe() bool {
	return e.key.available()
}

// Load loads and decrypts data for the given client ID.
func (e *EncryptedFileStore[T]) Load(clientID string) (T, error) {
	return e.file.Load(clientID)
}

// Save encrypts and saves data for the given client ID.
func (e *EncryptedFileStore[T]) Save(clientID string, data T) error {
	return e.file.Save(clientID, data)
}

// Delete removes data for the given client ID from the file.
func (e *EncryptedFileStore[T]) Delete(clientID string) error {
	return e.file.Delete(clientID)
}

// List returns all stored client IDs, sorted alphabetically.
func (e *EncryptedFileStore[T]) List() ([]string, error) {
	return e.file.List()
}

// DeleteMasterKey removes the master key from the OS keyring and drops the
// in-memory copy. Existing encrypted data becomes permanently unreadable; a
// fresh key is generated on the next Save. Intended for logout flows after
// the stored credentials have been deleted.
func (e *EncryptedFileStore[T]) DeleteMasterKey() error {
	return e.key.delete()
}

// FilePath returns the encrypted data file path.
func (e *EncryptedFileStore[T]) FilePath() string {
	return e.file.FilePath()
}

// ServiceName returns the keyring service name holding the master key.
func (e *EncryptedFileStore[T]) ServiceName() string {
	return e.key.store.ServiceName()
}

// String returns a description of this store.
func (e *EncryptedFileStore[T]) String() string {
	return "encrypted-file: " + e.file.FilePath()
}
