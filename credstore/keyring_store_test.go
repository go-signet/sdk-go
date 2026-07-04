package credstore_test

import (
	"testing"
	"time"

	"github.com/go-signet/sdk-go/credstore"
	"github.com/zalando/go-keyring"
)

func TestKeyringStore_SaveAndLoad(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

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

func TestKeyringStore_LoadNotFound(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

	_, err := store.Load("nonexistent")
	if err != credstore.ErrNotFound {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestKeyringStore_Delete(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

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

func TestKeyringStore_DeleteNonexistent(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

	// Should not error when deleting nonexistent key
	if err := store.Delete("nonexistent"); err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

func TestKeyringStore_OverwriteExisting(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

	if err := store.Save("test-client", credstore.Token{
		AccessToken: "token-v1",
		ClientID:    "test-client",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.Save("test-client", credstore.Token{
		AccessToken: "token-v2",
		ClientID:    "test-client",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "token-v2" {
		t.Errorf("AccessToken = %v, want token-v2", loaded.AccessToken)
	}
}

func TestKeyringStore_MultipleClients(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

	for _, id := range []string{"client-1", "client-2"} {
		if err := store.Save(id, credstore.Token{
			AccessToken: "token-" + id,
			ClientID:    id,
		}); err != nil {
			t.Fatalf("Save(%s) error = %v", id, err)
		}
	}

	for _, id := range []string{"client-1", "client-2"} {
		loaded, err := store.Load(id)
		if err != nil {
			t.Fatalf("Load(%s) error = %v", id, err)
		}
		expected := "token-" + id
		if loaded.AccessToken != expected {
			t.Errorf("Load(%s) AccessToken = %v, want %v", id, loaded.AccessToken, expected)
		}
	}
}

func TestKeyringStore_SaveEmptyClientID(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewTokenKeyringStore("test-service")

	err := store.Save("", credstore.Token{AccessToken: "tok"})
	if err != credstore.ErrEmptyClientID {
		t.Errorf("Save(empty clientID) error = %v, want ErrEmptyClientID", err)
	}
}

func TestKeyringStore_String(t *testing.T) {
	store := credstore.NewTokenKeyringStore("my-service")
	expected := "keyring: my-service"
	if store.String() != expected {
		t.Errorf("String() = %v, want %v", store.String(), expected)
	}
}

func TestKeyringStore_StringCodec(t *testing.T) {
	keyring.MockInit()
	store := credstore.NewStringKeyringStore("test-service")

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
