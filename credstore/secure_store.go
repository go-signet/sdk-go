package credstore

import "sync"

// Prober is an optional interface that a Store can implement to test
// whether its backend is available.
type Prober interface {
	Probe() bool
}

// BackendChangeFunc is called whenever the active backend changes.
// backend is the newly-active store's String() description.
// It fires both when falling back to file storage and when recovering to keyring.
// Always called outside the mutex lock.
type BackendChangeFunc func(backend string)

// Diagnostics is a point-in-time snapshot of SecureStore state.
type Diagnostics struct {
	Backend    string // active store's String() description
	UseKeyring bool   // true if the keyring-backed primary store is active
	CanProbe   bool   // true if Refresh() can switch backends
}

// SecureStoreOption[T] is a functional option for NewSecureStore.
type SecureStoreOption[T any] func(*SecureStore[T])

// WithBackendChangeHandler registers fn as the backend-change callback.
// It is called whenever the active backend switches — both on fallback to file
// and on recovery back to keyring. Passing nil is a no-op.
func WithBackendChangeHandler[T any](fn BackendChangeFunc) SecureStoreOption[T] {
	return func(s *SecureStore[T]) {
		s.onChange = fn
	}
}

// DefaultSecureStore creates a SecureStore with the given codec and sensible defaults.
// The primary backend is an EncryptedFileStore writing to filePath+".enc"
// with its master key in the OS keyring; see EncryptedFileStore for why only
// the key lives there. When the keyring is unavailable, it falls back to
// plaintext file storage at filePath.
func DefaultSecureStore[T any](
	serviceName, filePath string,
	codec Codec[T],
	opts ...SecureStoreOption[T],
) *SecureStore[T] {
	return NewSecureStore[T](
		NewEncryptedFileStore[T](serviceName, filePath+".enc", codec),
		NewFileStore[T](filePath, codec),
		opts...)
}

// SecureStore is a composite Store that tries the keyring-backed primary
// store first and falls back to file-based storage if the keyring is
// unavailable.
// Both stores are retained so that Refresh() can switch between them.
// All methods are safe for concurrent use.
type SecureStore[T any] struct {
	mu         sync.RWMutex
	kr         Store[T]
	file       Store[T]
	prober     Prober // nil if kr does not implement Prober
	useKeyring bool
	onChange   BackendChangeFunc // optional; called outside the lock
}

// NewSecureStore creates a SecureStore. If kr implements Prober and the probe
// succeeds, kr is used as the primary store. Otherwise, file is used as the
// fallback. Both stores are retained for use by Refresh(). The onChange
// callback (if set via WithBackendChangeHandler) is called when the file backend
// is selected at construction time.
func NewSecureStore[T any](kr, file Store[T], opts ...SecureStoreOption[T]) *SecureStore[T] {
	s := &SecureStore[T]{kr: kr, file: file}
	s.prober, _ = kr.(Prober)
	for _, opt := range opts {
		if opt != nil {
			opt(s) // apply before probe so callback is registered first
		}
	}
	if s.prober != nil && s.prober.Probe() {
		// keyring is the intended path, not a fallback: no callback fires
		s.useKeyring = true
		return s
	}
	// Fall back to file storage. useKeyring is already false (zero value).
	if s.onChange != nil {
		s.onChange(file.String()) // safe: struct not yet shared
	}
	return s
}

// active returns the current primary store under a read lock.
// The lock is released before the caller uses the returned store,
// so long-running store operations do not block Refresh().
func (s *SecureStore[T]) active() Store[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.useKeyring {
		return s.kr
	}
	return s.file
}

// Refresh re-probes the keyring backend and switches the active store if the
// availability has changed. It returns true if the active backend changed,
// false if it remained the same. No data is migrated between backends.
// Probe() is called outside the lock to avoid holding it during a potentially
// slow OS call. The onChange callback is called outside the lock to prevent
// deadlocks.
func (s *SecureStore[T]) Refresh() bool {
	if s.prober == nil {
		return false
	}

	keyringAvailable := s.prober.Probe() // outside the lock (slow OS call)

	s.mu.Lock()
	if keyringAvailable == s.useKeyring {
		s.mu.Unlock()
		return false
	}
	s.useKeyring = keyringAvailable
	var newBackend string
	if keyringAvailable {
		newBackend = s.kr.String()
	} else {
		newBackend = s.file.String()
	}
	cb := s.onChange // capture under the lock
	s.mu.Unlock()    // release BEFORE calling callback (prevent deadlock)

	if cb != nil {
		cb(newBackend)
	}
	return true
}

// UseKeyring reports whether the secure store is using the keyring backend.
func (s *SecureStore[T]) UseKeyring() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.useKeyring
}

// Diagnostic returns a point-in-time snapshot of the SecureStore's backend state.
func (s *SecureStore[T]) Diagnostic() Diagnostics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	backend := s.file
	if s.useKeyring {
		backend = s.kr
	}
	return Diagnostics{
		Backend:    backend.String(),
		UseKeyring: s.useKeyring,
		CanProbe:   s.prober != nil,
	}
}

// Load loads data from the active store.
func (s *SecureStore[T]) Load(clientID string) (T, error) {
	return s.active().Load(clientID)
}

// Save saves data to the active store.
func (s *SecureStore[T]) Save(clientID string, data T) error {
	return s.active().Save(clientID, data)
}

// Delete removes data from the active store.
func (s *SecureStore[T]) Delete(clientID string) error {
	return s.active().Delete(clientID)
}

// String returns a description of the active store.
func (s *SecureStore[T]) String() string {
	return s.active().String()
}
