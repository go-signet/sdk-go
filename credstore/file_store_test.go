package credstore_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/credstore"
)

func TestFileStore_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	tok := credstore.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Truncate(time.Second),
		ClientID:     "test-client",
	}

	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %v, want %v", loaded.AccessToken, tok.AccessToken)
	}
	if loaded.RefreshToken != tok.RefreshToken {
		t.Errorf("RefreshToken = %v, want %v", loaded.RefreshToken, tok.RefreshToken)
	}
	if loaded.ClientID != tok.ClientID {
		t.Errorf("ClientID = %v, want %v", loaded.ClientID, tok.ClientID)
	}
}

func TestFileStore_LoadNotFound(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	_, err := store.Load("nonexistent")
	if err != credstore.ErrNotFound {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestFileStore_LoadFromExistingFileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tokens.json")
	store := credstore.NewTokenFileStore(filePath)

	// Save one client
	if err := store.Save("client-1", credstore.Token{
		AccessToken: "token-1",
		ClientID:    "client-1",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load a different client
	_, err := store.Load("client-2")
	if err != credstore.ErrNotFound {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestFileStore_Delete(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	tok := credstore.Token{
		AccessToken: "test-token",
		ClientID:    "test-client",
	}
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.Delete("test-client"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := store.Load("test-client")
	if err != credstore.ErrNotFound {
		t.Errorf("Load() after Delete() error = %v, want ErrNotFound", err)
	}
}

func TestFileStore_DeleteNonexistent(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	// Should not error when deleting from nonexistent file
	if err := store.Delete("nonexistent"); err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

func TestFileStore_DeletePreservesOtherClients(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	// Save two clients
	for _, id := range []string{"client-1", "client-2"} {
		if err := store.Save(id, credstore.Token{
			AccessToken: "token-" + id,
			ClientID:    id,
		}); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// Delete one
	if err := store.Delete("client-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Other should still exist
	loaded, err := store.Load("client-2")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "token-client-2" {
		t.Errorf("AccessToken = %v, want %v", loaded.AccessToken, "token-client-2")
	}
}

func TestFileStore_ConcurrentWrites(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tokens.json")
	store := credstore.NewTokenFileStore(filePath)

	const goroutines = 10
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()

			tok := credstore.Token{
				AccessToken:  fmt.Sprintf("access-token-%d", id),
				RefreshToken: fmt.Sprintf("refresh-token-%d", id),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				ClientID:     fmt.Sprintf("client-%d", id),
			}

			if err := store.Save(tok.ClientID, tok); err != nil {
				t.Errorf("Goroutine %d: Save() error = %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all tokens were saved by loading each one
	for i := range goroutines {
		clientID := fmt.Sprintf("client-%d", i)
		loaded, err := store.Load(clientID)
		if err != nil {
			t.Errorf("Load(%s) error = %v", clientID, err)
			continue
		}
		expectedAccessToken := fmt.Sprintf("access-token-%d", i)
		if loaded.AccessToken != expectedAccessToken {
			t.Errorf(
				"Client %s: AccessToken = %v, want %v",
				clientID,
				loaded.AccessToken,
				expectedAccessToken,
			)
		}
	}

	// Verify no lock files remain
	lockPath := filePath + ".lock"
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("Lock file still exists after all saves completed")
	}
}

func TestFileStore_SaveEmptyClientID(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	err := store.Save("", credstore.Token{AccessToken: "tok"})
	if err != credstore.ErrEmptyClientID {
		t.Errorf("Save(empty clientID) error = %v, want ErrEmptyClientID", err)
	}
}

func TestFileStore_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission test is not applicable on Windows")
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tokens.json")
	store := credstore.NewTokenFileStore(filePath)

	if err := store.Save("c1", credstore.Token{
		AccessToken: "tok",
		ClientID:    "c1",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permission = %o, want 0600", perm)
	}
}

func TestFileStore_SaveCreatesParentDirectories(t *testing.T) {
	tempDir := t.TempDir()
	nestedPath := filepath.Join(tempDir, "a", "b", "c", "tokens.json")
	store := credstore.NewTokenFileStore(nestedPath)

	if err := store.Save("c1", credstore.Token{
		AccessToken: "tok",
		ClientID:    "c1",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("c1")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "tok" {
		t.Errorf("AccessToken = %v, want tok", loaded.AccessToken)
	}
}

func TestFileStore_List(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewTokenFileStore(filepath.Join(tempDir, "tokens.json"))

	// Empty store returns empty slice
	ids, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("List() on empty store returned %d items, want 0", len(ids))
	}

	// Save some tokens
	for _, id := range []string{"charlie", "alpha", "bravo"} {
		if err := store.Save(id, credstore.Token{
			AccessToken: "tok-" + id,
			ClientID:    id,
		}); err != nil {
			t.Fatalf("Save(%s) error = %v", id, err)
		}
	}

	ids, err = store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	expected := []string{"alpha", "bravo", "charlie"}
	if len(ids) != len(expected) {
		t.Fatalf("List() returned %d items, want %d", len(ids), len(expected))
	}
	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("List()[%d] = %v, want %v", i, id, expected[i])
		}
	}
}

func TestFileStore_String(t *testing.T) {
	store := credstore.NewTokenFileStore("/path/to/tokens.json")
	expected := "file: /path/to/tokens.json"
	if store.String() != expected {
		t.Errorf("String() = %v, want %v", store.String(), expected)
	}
}

func TestFileStore_StringCodec(t *testing.T) {
	tempDir := t.TempDir()
	store := credstore.NewStringFileStore(filepath.Join(tempDir, "tokens.json"))

	if err := store.Save("my-client", "eyJhbGciOiJSUzI1NiJ9"); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("my-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded != "eyJhbGciOiJSUzI1NiJ9" {
		t.Errorf("Load() = %v, want eyJhbGciOiJSUzI1NiJ9", loaded)
	}
}
