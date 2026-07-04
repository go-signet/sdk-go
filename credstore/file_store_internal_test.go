package credstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReadStorageMap_FileNotExist(t *testing.T) {
	store := NewFileStore[Token](filepath.Join(t.TempDir(), "missing.json"), JSONCodec[Token]{})

	m, err := store.readStorageMap()
	if err != nil {
		t.Fatalf("readStorageMap() error = %v", err)
	}
	if m.Data == nil {
		t.Fatal("Data map should be initialized, got nil")
	}
	if len(m.Data) != 0 {
		t.Errorf("Data map should be empty, got %d entries", len(m.Data))
	}
}

func TestReadStorageMap_ValidFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")

	codec := JSONCodec[Token]{}
	encoded, err := codec.Encode(Token{AccessToken: "tok-1", ClientID: "client-1"})
	if err != nil {
		t.Fatal(err)
	}

	m := storageMap{Data: map[string]string{
		"client-1": encoded,
	}}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore[Token](fp, codec)
	got, err := store.readStorageMap()
	if err != nil {
		t.Fatalf("readStorageMap() error = %v", err)
	}

	decoded, err := codec.Decode(got.Data["client-1"])
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.AccessToken != "tok-1" {
		t.Errorf("AccessToken = %v, want tok-1", decoded.AccessToken)
	}
}

func TestReadStorageMap_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(fp, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore[Token](fp, JSONCodec[Token]{})
	_, err := store.readStorageMap()
	if err == nil {
		t.Fatal("readStorageMap() should return error for invalid JSON")
	}
}

func TestReadStorageMap_NullDataField(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(fp, []byte(`{"data": null}`), 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore[Token](fp, JSONCodec[Token]{})
	m, err := store.readStorageMap()
	if err != nil {
		t.Fatalf("readStorageMap() error = %v", err)
	}
	if m.Data == nil {
		t.Fatal("Data map should be initialized even when JSON has null")
	}
}

func TestWriteStorageMap_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	codec := JSONCodec[Token]{}
	store := NewFileStore[Token](fp, codec)

	encoded, err := codec.Encode(Token{AccessToken: "a1", ClientID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	m := storageMap{Data: map[string]string{"c1": encoded}}
	if err := store.writeStorageMap(m); err != nil {
		t.Fatalf("writeStorageMap() error = %v", err)
	}

	data, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var got storageMap
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	decoded, err := codec.Decode(got.Data["c1"])
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.AccessToken != "a1" {
		t.Errorf("AccessToken = %v, want a1", decoded.AccessToken)
	}
}

func TestWriteStorageMap_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	codec := JSONCodec[Token]{}
	store := NewFileStore[Token](fp, codec)

	enc1, err := codec.Encode(Token{AccessToken: "v1", ClientID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	m1 := storageMap{Data: map[string]string{"c1": enc1}}
	if err := store.writeStorageMap(m1); err != nil {
		t.Fatal(err)
	}

	enc2, err := codec.Encode(Token{AccessToken: "v2", ClientID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	m2 := storageMap{Data: map[string]string{"c1": enc2}}
	if err := store.writeStorageMap(m2); err != nil {
		t.Fatal(err)
	}

	got, err := store.readStorageMap()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.Decode(got.Data["c1"])
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.AccessToken != "v2" {
		t.Errorf("AccessToken = %v, want v2", decoded.AccessToken)
	}
}

func TestWriteStorageMap_NoTempFileLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	m := storageMap{Data: make(map[string]string)}
	if err := store.writeStorageMap(m); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(fp + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful write")
	}
}

func TestWithFileLock_ExecutesFn(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	called := false
	err := store.withFileLock(func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("withFileLock() error = %v", err)
	}
	if !called {
		t.Error("fn was not called")
	}
}

func TestWithFileLock_PropagatesError(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	sentinel := errors.New("test error")
	err := store.withFileLock(func() error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("withFileLock() error = %v, want %v", err, sentinel)
	}
}

func TestWithFileLock_ReleasesLockAfterFn(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	err := store.withFileLock(func() error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Lock file should be cleaned up; acquiring again should succeed immediately
	err = store.withFileLock(func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("second withFileLock() error = %v; lock was not released", err)
	}
}

func TestWithFileLock_ReleasesLockOnError(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	_ = store.withFileLock(func() error {
		return errors.New("fail")
	})

	// Should still be able to acquire lock after error
	err := store.withFileLock(func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("withFileLock() after error error = %v; lock was not released", err)
	}
}

func TestWithFileLock_MutualExclusion(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	const goroutines = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrent := 0

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := store.withFileLock(func() error {
				mu.Lock()
				concurrent++
				if concurrent > 1 {
					t.Errorf("goroutine %d: concurrent holders = %d", idx, concurrent)
				}
				mu.Unlock()

				mu.Lock()
				concurrent--
				mu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("goroutine %d: withFileLock() error = %v", idx, err)
			}
		}(i)
	}

	wg.Wait()
}

func TestDeleteSkipsWriteWhenKeyAbsent(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tokens.json")
	store := NewFileStore[Token](fp, JSONCodec[Token]{})

	// Save one token
	if err := store.Save("c1", Token{AccessToken: "tok", ClientID: "c1"}); err != nil {
		t.Fatal(err)
	}

	info1, _ := os.Stat(fp)

	// Delete a nonexistent key — file should not be rewritten
	if err := store.Delete("nonexistent"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	info2, _ := os.Stat(fp)

	// The file's mod time should remain the same (no rewrite)
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("file was rewritten even though deleted key did not exist")
	}
}
