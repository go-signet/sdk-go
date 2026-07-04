package credstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// storageMap manages encoded values for multiple clients.
type storageMap struct {
	Data map[string]string `json:"data"` // clientID -> encoded value
}

// FileStore stores values in a JSON file with file locking and atomic writes.
type FileStore[T any] struct {
	filePath string
	codec    Codec[T]
}

// NewFileStore creates a new FileStore with the given codec.
// Panics if codec is nil.
func NewFileStore[T any](filePath string, codec Codec[T]) *FileStore[T] {
	if codec == nil {
		panic("credstore: NewFileStore called with nil codec")
	}
	return &FileStore[T]{filePath: filePath, codec: codec}
}

// readStorageMap reads and unmarshals the storage map from the file.
// Returns an empty initialized map if the file does not exist.
func (f *FileStore[T]) readStorageMap() (storageMap, error) {
	var m storageMap
	data, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			m.Data = make(map[string]string)
			return m, nil
		}
		return m, fmt.Errorf("failed to read file %q: %w", f.filePath, err)
	}

	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("failed to parse file %q: %w", f.filePath, err)
	}
	if m.Data == nil {
		m.Data = make(map[string]string)
	}
	return m, nil
}

// ensureDir creates the parent directory of the store file if it does not exist.
func (f *FileStore[T]) ensureDir() error {
	if err := os.MkdirAll(filepath.Dir(f.filePath), 0o700); err != nil {
		return fmt.Errorf("failed to create store directory: %w", err)
	}
	return nil
}

// writeStorageMap marshals and atomically writes the storage map to the file.
func (f *FileStore[T]) writeStorageMap(m storageMap) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	tempFile := f.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0o600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, f.filePath); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// withFileLock acquires a file lock, runs fn, and releases the lock.
func (f *FileStore[T]) withFileLock(fn func() error) error {
	lock, err := acquireFileLock(f.filePath)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer lock.release() //nolint:errcheck // best-effort cleanup; lock file has stale detection

	return fn()
}

// Load loads data from the file for the given client ID.
// No file lock is needed: Save uses atomic rename, so reads always see a
// consistent snapshot on POSIX systems.
func (f *FileStore[T]) Load(clientID string) (T, error) {
	var zero T
	m, err := f.readStorageMap()
	if err != nil {
		return zero, err
	}

	encoded, ok := m.Data[clientID]
	if !ok {
		return zero, ErrNotFound
	}

	decoded, err := f.codec.Decode(encoded)
	if err != nil {
		return zero, fmt.Errorf("failed to decode value from %q: %w", f.filePath, err)
	}
	return decoded, nil
}

// Save saves data to the file for the given client ID.
// Uses file locking to prevent race conditions.
// Automatically creates parent directories if they do not exist.
func (f *FileStore[T]) Save(clientID string, data T) error {
	if clientID == "" {
		return ErrEmptyClientID
	}

	encoded, err := f.codec.Encode(data)
	if err != nil {
		return fmt.Errorf("failed to encode value for storage: %w", err)
	}

	if err := f.ensureDir(); err != nil {
		return err
	}

	return f.withFileLock(func() error {
		m, err := f.readStorageMap()
		if err != nil {
			return err
		}

		m.Data[clientID] = encoded

		return f.writeStorageMap(m)
	})
}

// Delete removes data for the given client ID from the file.
func (f *FileStore[T]) Delete(clientID string) error {
	return f.withFileLock(func() error {
		m, err := f.readStorageMap()
		if err != nil {
			return err
		}

		if _, ok := m.Data[clientID]; !ok {
			return nil
		}

		delete(m.Data, clientID)

		return f.writeStorageMap(m)
	})
}

// List returns all stored client IDs, sorted alphabetically.
// No file lock is needed: Save uses atomic rename, so reads always see a
// consistent snapshot on POSIX systems.
func (f *FileStore[T]) List() ([]string, error) {
	m, err := f.readStorageMap()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(m.Data))
	for id := range m.Data {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

// FilePath returns the configured file path.
func (f *FileStore[T]) FilePath() string {
	return f.filePath
}

// String returns a description of this store.
func (f *FileStore[T]) String() string {
	return "file: " + f.filePath
}
