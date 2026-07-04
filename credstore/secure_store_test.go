package credstore

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// mockStore is a simple mock implementing Store[T] for testing.
// A mutex guards data so mockStore is safe for concurrent use in race tests.
type mockStore[T any] struct {
	mu   sync.Mutex
	data map[string]T
	name string
	err  error
}

func newMockStore[T any](name string) *mockStore[T] {
	return &mockStore[T]{
		data: make(map[string]T),
		name: name,
	}
}

func (m *mockStore[T]) Load(clientID string) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		var zero T
		return zero, m.err
	}
	data, ok := m.data[clientID]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}
	return data, nil
}

func (m *mockStore[T]) Save(clientID string, data T) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.data[clientID] = data
	return nil
}

func (m *mockStore[T]) Delete(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	delete(m.data, clientID)
	return nil
}

func (m *mockStore[T]) String() string {
	return m.name
}

// mockProberStore implements both Store[T] and Prober.
// probeResult uses atomic.Bool so it is safe to read/write from concurrent goroutines.
type mockProberStore[T any] struct {
	mockStore[T]
	probeResult atomic.Bool
}

func newMockProberStore[T any](name string, probeResult bool) *mockProberStore[T] {
	m := &mockProberStore[T]{
		mockStore: mockStore[T]{data: make(map[string]T), name: name},
	}
	m.probeResult.Store(probeResult)
	return m
}

func (m *mockProberStore[T]) Probe() bool {
	return m.probeResult.Load()
}

// mockListerStore implements Store[T] and Lister.
type mockListerStore[T any] struct {
	mockStore[T]
}

func newMockListerStore[T any](name string) *mockListerStore[T] {
	return &mockListerStore[T]{
		mockStore: mockStore[T]{data: make(map[string]T), name: name},
	}
}

func (m *mockListerStore[T]) List() ([]string, error) {
	ids := make([]string, 0, len(m.data))
	for id := range m.data {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func TestSecureStore_UsesKeyringWhenProbeSucceeds(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")

	store := NewSecureStore[Token](kr, file)

	tok := Token{
		AccessToken: "test-token",
		ClientID:    "test-client",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Should be in keyring, not file
	if _, ok := kr.data["test-client"]; !ok {
		t.Error("Token not found in keyring store")
	}
	if _, ok := file.data["test-client"]; ok {
		t.Error("Token should not be in file store")
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "test-token" {
		t.Errorf("AccessToken = %v, want test-token", loaded.AccessToken)
	}

	if store.String() != "keyring: test" {
		t.Errorf("String() = %v, want keyring: test", store.String())
	}

	if !store.UseKeyring() {
		t.Error("UseKeyring() = false, want true")
	}
}

func TestSecureStore_FallsBackToFileWhenProbeFails(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")

	store := NewSecureStore[Token](kr, file)

	tok := Token{
		AccessToken: "test-token",
		ClientID:    "test-client",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Should be in file, not keyring
	if _, ok := file.data["test-client"]; !ok {
		t.Error("Token not found in file store")
	}
	if _, ok := kr.data["test-client"]; ok {
		t.Error("Token should not be in keyring store")
	}

	if store.String() != "file: test" {
		t.Errorf("String() = %v, want file: test", store.String())
	}

	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false")
	}
}

func TestSecureStore_FallsBackWhenKrNotProber(t *testing.T) {
	// kr does not implement Prober, should fall back to file
	kr := newMockStore[Token]("keyring: test")
	file := newMockStore[Token]("file: test")

	store := NewSecureStore[Token](kr, file)

	if store.String() != "file: test" {
		t.Errorf("String() = %v, want file: test", store.String())
	}
}

func TestDefaultTokenSecureStore(t *testing.T) {
	keyring.MockInit() // avoid touching the real OS keyring
	store := DefaultTokenSecureStore("test-service", t.TempDir()+"/tokens.json")
	if store == nil {
		t.Fatal("DefaultTokenSecureStore() returned nil")
	}
}

func TestSecureStore_ListWithLister(t *testing.T) {
	file := newMockListerStore[Token]("file: test")
	file.data["bravo"] = Token{ClientID: "bravo"}
	file.data["alpha"] = Token{ClientID: "alpha"}

	kr := newMockProberStore[Token]("keyring: test", false)
	store := NewSecureStore[Token](kr, file)

	// *SecureStore does NOT satisfy Lister — the underlying file store does.
	if _, ok := any(store).(Lister); ok {
		t.Fatal("*SecureStore should not satisfy Lister")
	}

	// The underlying FileStore (mockListerStore) satisfies Lister directly.
	lister, ok := any(file).(Lister)
	if !ok {
		t.Fatal("mockListerStore should satisfy Lister")
	}
	ids, err := lister.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("List() returned %d items, want 2", len(ids))
	}
	if ids[0] != "alpha" || ids[1] != "bravo" {
		t.Errorf("List() = %v, want [alpha bravo]", ids)
	}
}

func TestSecureStore_ListNotSupported(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	// *SecureStore never satisfies Lister, regardless of backend.
	if _, ok := any(store).(Lister); ok {
		t.Fatal("*SecureStore should not satisfy Lister")
	}
}

func TestSecureStore_Refresh_NoChangeWhenKeyringStillAvailable(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	changed := store.Refresh()

	if changed {
		t.Error("Refresh() = true, want false (keyring still available)")
	}
	if !store.UseKeyring() {
		t.Error("UseKeyring() = false, want true after no-op refresh")
	}
}

func TestSecureStore_Refresh_SwitchesToFileWhenKeyringBecomesUnavailable(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	kr.probeResult.Store(false)
	changed := store.Refresh()

	if !changed {
		t.Error("Refresh() = false, want true (keyring became unavailable)")
	}
	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false after keyring went down")
	}
	if store.String() != "file: test" {
		t.Errorf("String() = %v, want file: test", store.String())
	}
}

func TestSecureStore_Refresh_SwitchesToKeyringWhenKeyringBecomesAvailable(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	kr.probeResult.Store(true)
	changed := store.Refresh()

	if !changed {
		t.Error("Refresh() = false, want true (keyring recovered)")
	}
	if !store.UseKeyring() {
		t.Error("UseKeyring() = false, want true after keyring recovered")
	}
	if store.String() != "keyring: test" {
		t.Errorf("String() = %v, want keyring: test", store.String())
	}
}

func TestSecureStore_Refresh_NoOpWhenKrNotProber(t *testing.T) {
	kr := newMockStore[Token]("keyring: test")
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	changed := store.Refresh()

	if changed {
		t.Error("Refresh() = true, want false (kr does not implement Prober)")
	}
	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false (non-prober kr always falls back)")
	}
}

func TestSecureStore_Refresh_NoChangeWhenFileStillActive(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	changed := store.Refresh()

	if changed {
		t.Error("Refresh() = true, want false (file still active, probe still false)")
	}
	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false")
	}
}

func TestSecureStore_Refresh_OperatesOnCorrectBackendAfterSwitch(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	tok := Token{AccessToken: "file-token", ClientID: "client1"}
	if err := store.Save(tok.ClientID, tok); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Switch to keyring
	kr.probeResult.Store(true)
	if !store.Refresh() {
		t.Fatal("Refresh() = false, want true")
	}

	// Save to new primary (keyring)
	tok2 := Token{AccessToken: "keyring-token", ClientID: "client2"}
	if err := store.Save(tok2.ClientID, tok2); err != nil {
		t.Fatalf("Save() after switch error = %v", err)
	}

	if _, ok := kr.data["client2"]; !ok {
		t.Error("client2 not found in keyring store after switch")
	}
	if _, ok := file.data["client2"]; ok {
		t.Error("client2 should not be in file store after switch")
	}
}

func TestSecureStore_Refresh_ConcurrentSafe(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = store.Refresh()
		}()
		go func() {
			defer wg.Done()
			_ = store.Save("client", Token{AccessToken: "t", ClientID: "client"})
		}()
		go func() {
			defer wg.Done()
			_, _ = store.Load("client")
		}()
	}
	wg.Wait()
}

func TestWithBackendChangeHandler_CalledAtConstruction(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")

	var called []string
	store := NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](func(backend string) {
		called = append(called, backend)
	}))

	if len(called) != 1 {
		t.Fatalf("callback called %d times, want 1", len(called))
	}
	if called[0] != "file: test" {
		t.Errorf("callback backend = %q, want %q", called[0], "file: test")
	}
	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false")
	}
}

func TestWithBackendChangeHandler_NotCalledWhenKeyringSucceeds(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")

	var called int
	_ = NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](func(_ string) {
		called++
	}))

	if called != 0 {
		t.Errorf("callback called %d times, want 0", called)
	}
}

func TestWithBackendChangeHandler_CalledOnRefreshFallback(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")

	var called []string
	store := NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](func(backend string) {
		called = append(called, backend)
	}))

	// No callback at construction (keyring succeeded).
	if len(called) != 0 {
		t.Fatalf("unexpected callback at construction: %v", called)
	}

	kr.probeResult.Store(false)
	if !store.Refresh() {
		t.Fatal("Refresh() = false, want true")
	}

	if len(called) != 1 {
		t.Fatalf("callback called %d times after Refresh, want 1", len(called))
	}
	if called[0] != "file: test" {
		t.Errorf("callback backend = %q, want %q", called[0], "file: test")
	}
}

func TestWithBackendChangeHandler_CalledOnRefreshRecovery(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")

	var called []string
	store := NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](func(backend string) {
		called = append(called, backend)
	}))

	// callback fired at construction (file fallback).
	if len(called) != 1 {
		t.Fatalf("expected 1 callback at construction, got %d", len(called))
	}

	kr.probeResult.Store(true)
	if !store.Refresh() {
		t.Fatal("Refresh() = false, want true")
	}

	if len(called) != 2 {
		t.Fatalf("callback called %d times total, want 2", len(called))
	}
	if called[1] != "keyring: test" {
		t.Errorf("callback backend on recovery = %q, want %q", called[1], "keyring: test")
	}
}

func TestWithBackendChangeHandler_NotCalledOnNoOpRefresh(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")

	var called int
	store := NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](func(_ string) {
		called++
	}))

	// Probe still succeeds — no change.
	if store.Refresh() {
		t.Error("Refresh() = true, want false (no change)")
	}
	if called != 0 {
		t.Errorf("callback called %d times, want 0", called)
	}
}

func TestWithBackendChangeHandler_NilHandlerIsNoOp(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", false)
	file := newMockStore[Token]("file: test")

	// Must not panic.
	store := NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](nil))
	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false")
	}
}

func TestDiagnostic_KeyringActive(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: svc", true)
	file := newMockStore[Token]("file: /tmp/t.json")
	store := NewSecureStore[Token](kr, file)

	d := store.Diagnostic()

	if d.Backend != "keyring: svc" {
		t.Errorf("Backend = %q, want %q", d.Backend, "keyring: svc")
	}
	if !d.UseKeyring {
		t.Error("UseKeyring = false, want true")
	}
	if !d.CanProbe {
		t.Error("CanProbe = false, want true")
	}
}

func TestDiagnostic_FileFallback(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: svc", false)
	file := newMockStore[Token]("file: /tmp/t.json")
	store := NewSecureStore[Token](kr, file)

	d := store.Diagnostic()

	if d.Backend != "file: /tmp/t.json" {
		t.Errorf("Backend = %q, want %q", d.Backend, "file: /tmp/t.json")
	}
	if d.UseKeyring {
		t.Error("UseKeyring = true, want false")
	}
	if !d.CanProbe {
		t.Error("CanProbe = false, want true")
	}
}

func TestDiagnostic_NoProber(t *testing.T) {
	kr := newMockStore[Token]("keyring: svc")
	file := newMockStore[Token]("file: /tmp/t.json")
	store := NewSecureStore[Token](kr, file)

	d := store.Diagnostic()

	if d.CanProbe {
		t.Error("CanProbe = true, want false (kr does not implement Prober)")
	}
	if d.UseKeyring {
		t.Error("UseKeyring = true, want false")
	}
}

func TestDiagnostic_UpdatesAfterRefresh(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: svc", true)
	file := newMockStore[Token]("file: /tmp/t.json")
	store := NewSecureStore[Token](kr, file)

	d1 := store.Diagnostic()
	if !d1.UseKeyring {
		t.Fatal("initial UseKeyring = false, want true")
	}

	kr.probeResult.Store(false)
	if !store.Refresh() {
		t.Fatal("Refresh() = false, want true")
	}

	d2 := store.Diagnostic()
	if d2.UseKeyring {
		t.Error("UseKeyring = true after fallback, want false")
	}
	if d2.Backend != "file: /tmp/t.json" {
		t.Errorf("Backend = %q, want %q", d2.Backend, "file: /tmp/t.json")
	}
}

func TestWithBackendChangeHandler_ConcurrentSafe(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file, WithBackendChangeHandler[Token](func(_ string) {}))

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			kr.probeResult.Store(!kr.probeResult.Load())
			_ = store.Refresh()
		}()
		go func() {
			defer wg.Done()
			_ = store.Diagnostic()
		}()
		go func() {
			defer wg.Done()
			_ = store.Save("client", Token{AccessToken: "t", ClientID: "client"})
		}()
	}
	wg.Wait()
}

func TestSecureStore_Delete(t *testing.T) {
	kr := newMockProberStore[Token]("keyring: test", true)
	file := newMockStore[Token]("file: test")
	store := NewSecureStore[Token](kr, file)

	tok := Token{
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
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Load() after Delete() error = %v, want ErrNotFound", err)
	}
}
