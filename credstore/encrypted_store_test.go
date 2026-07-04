package credstore_test

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-signet/sdk-go/credstore"
	"github.com/zalando/go-keyring"
)

// newLargeTestToken builds a token whose access token is several KB,
// mimicking real JWTs with large groups claims that exceed the Windows
// Credential Manager 2560-byte blob limit.
func newLargeTestToken(clientID string) credstore.Token {
	tok := newTestToken(clientID)
	tok.AccessToken = "header." + strings.Repeat("groups-claim-payload-", 300) + ".sig"
	return tok
}

func newTestEncryptedStore(t *testing.T) (*credstore.EncryptedFileStore[credstore.Token], string) {
	t.Helper()
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "tokens.enc")
	return credstore.NewTokenEncryptedFileStore("test-service", path), path
}

func TestEncryptedFileStore_SaveAndLoad(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	tok := newLargeTestToken("test-client")
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != tok.AccessToken {
		t.Error("AccessToken mismatch after round-trip")
	}
	if loaded.RefreshToken != tok.RefreshToken {
		t.Errorf("RefreshToken = %v, want %v", loaded.RefreshToken, tok.RefreshToken)
	}
	if !loaded.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", loaded.ExpiresAt, tok.ExpiresAt)
	}
}

func TestEncryptedFileStore_FileContainsNoPlaintext(t *testing.T) {
	store, path := newTestEncryptedStore(t)

	tok := newLargeTestToken("test-client")
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "groups-claim-payload") {
		t.Error("encrypted file contains plaintext access token")
	}
	if strings.Contains(string(raw), tok.RefreshToken) {
		t.Error("encrypted file contains plaintext refresh token")
	}
}

func TestEncryptedFileStore_KeyringHoldsOnlySmallMasterKey(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	tok := newLargeTestToken("test-client")
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// The token itself must not be in the keyring.
	if _, err := keyring.Get("test-service", "test-client"); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("keyring entry for client exists, want ErrNotFound (got err = %v)", err)
	}

	// Only the 44-byte base64 master key may live in the keyring —
	// well under the Windows Credential Manager 2560-byte blob limit.
	encoded, err := keyring.Get("test-service", credstore.MasterKeyUser)
	if err != nil {
		t.Fatalf("keyring.Get(master key) error = %v", err)
	}
	if len(encoded) != 44 {
		t.Errorf("keyring payload = %d bytes, want 44", len(encoded))
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("master key is not valid base64: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("decoded master key = %d bytes, want 32", len(key))
	}
}

func TestEncryptedFileStore_LoadNotFound(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	_, err := store.Load("nonexistent")
	if !errors.Is(err, credstore.ErrNotFound) {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestEncryptedFileStore_Delete(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	tok := newLargeTestToken("test-client")
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := store.Delete("test-client"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := store.Load("test-client")
	if !errors.Is(err, credstore.ErrNotFound) {
		t.Errorf("Load() after Delete() error = %v, want ErrNotFound", err)
	}
}

func TestEncryptedFileStore_SaveEmptyClientID(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	err := store.Save("", newLargeTestToken("x"))
	if !errors.Is(err, credstore.ErrEmptyClientID) {
		t.Errorf("Save(empty clientID) error = %v, want ErrEmptyClientID", err)
	}
}

func TestEncryptedFileStore_List(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	for _, id := range []string{"bravo", "alpha"} {
		if err := store.Save(id, newLargeTestToken(id)); err != nil {
			t.Fatalf("Save(%s) error = %v", id, err)
		}
	}

	var lister credstore.Lister = store
	ids, err := lister.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(ids) != 2 || ids[0] != "alpha" || ids[1] != "bravo" {
		t.Errorf("List() = %v, want [alpha bravo]", ids)
	}
}

func TestEncryptedFileStore_Probe(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	var prober credstore.Prober = store
	if !prober.Probe() {
		t.Error("Probe() = false, want true with mock keyring")
	}
}

func TestEncryptedFileStore_DeleteMasterKeyInvalidatesData(t *testing.T) {
	store, _ := newTestEncryptedStore(t)

	tok := newLargeTestToken("test-client")
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.DeleteMasterKey(); err != nil {
		t.Fatalf("DeleteMasterKey() error = %v", err)
	}

	// Load must fail with a decrypt error rather than return garbage or
	// mint a fresh key that could never open the old ciphertext.
	_, err := store.Load("test-client")
	if err == nil {
		t.Fatal("Load() after DeleteMasterKey() succeeded, want decrypt error")
	}
	if errors.Is(err, credstore.ErrNotFound) {
		t.Errorf("Load() error = ErrNotFound, want decrypt failure")
	}

	// Saving again works with the regenerated key.
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() after DeleteMasterKey() error = %v", err)
	}
	if _, err := store.Load("test-client"); err != nil {
		t.Fatalf("Load() after re-save error = %v", err)
	}
}

func TestEncryptedFileStore_Accessors(t *testing.T) {
	store, path := newTestEncryptedStore(t)

	if store.FilePath() != path {
		t.Errorf("FilePath() = %v, want %v", store.FilePath(), path)
	}
	if store.ServiceName() != "test-service" {
		t.Errorf("ServiceName() = %v, want test-service", store.ServiceName())
	}
	if store.String() != "encrypted-file: "+path {
		t.Errorf("String() = %v, want encrypted-file: %v", store.String(), path)
	}
}

func TestEncryptedFileStore_NilCodecPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewEncryptedFileStore(nil codec) did not panic")
		}
	}()
	credstore.NewEncryptedFileStore[string]("svc", "path", nil)
}

func TestDefaultTokenSecureStore_KeepsTokenOutOfKeyring(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "tokens.json")
	store := credstore.DefaultTokenSecureStore("test-service", plainPath)

	if !store.UseKeyring() {
		t.Fatal("UseKeyring() = false, want true with mock keyring")
	}

	tok := newLargeTestToken("test-client")
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != tok.AccessToken {
		t.Error("AccessToken mismatch after round-trip")
	}

	// The multi-KB token must live in the encrypted file, not the keyring.
	if _, err := os.Stat(plainPath + ".enc"); err != nil {
		t.Errorf("encrypted file missing at %s.enc: %v", plainPath, err)
	}
	if _, err := os.Stat(plainPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plaintext fallback file should not exist, stat err = %v", err)
	}
	if _, err := keyring.Get("test-service", "test-client"); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("token stored in keyring, want only the master key (err = %v)", err)
	}
}
