# credstore

Secure storage for OAuth tokens and arbitrary credentials, with OS keyring integration and file-based fallback.

## Features

- **Generic Storage** — store `Token`, plain `string`, or any custom type
- **Encrypted File Storage** — AES-256-GCM-encrypted data file with only a 32-byte master key in the OS keyring, so large tokens never hit keyring size limits (e.g. the Windows Credential Manager 2560-byte blob limit)
- **OS Keyring Integration** — uses macOS Keychain, Linux Secret Service, or Windows Credential Manager
- **Automatic Fallback** — falls back to plaintext file storage when keyring is unavailable
- **Thread-Safe** — file locking with stale lock detection for concurrent access
- **Atomic Writes** — uses temp file + rename pattern to prevent corruption
- **Cross-Platform** — works on macOS, Linux, and Windows

## Quick Start

```go
package main

import (
  "fmt"
  "time"

  "github.com/go-signet/sdk-go/credstore"
)

func main() {
  // Create a secure store with keyring + file fallback (one-liner)
  store := credstore.DefaultTokenSecureStore("my-app", "/tmp/my-app-tokens.json")

  fmt.Println("Using backend:", store.String())

  // Save a token
  token := credstore.Token{
    AccessToken:  "eyJhbGciOi...",
    RefreshToken: "dGhpcyBpcyBh...",
    TokenType:    "Bearer",
    ExpiresAt:    time.Now().Add(1 * time.Hour),
    ClientID:     "my-client-id",
  }

  if err := store.Save(token.ClientID, token); err != nil {
    panic(err)
  }

  // Load a token
  loaded, err := store.Load("my-client-id")
  if err != nil {
    panic(err)
  }
  fmt.Println("Access token:", loaded.AccessToken)

  // Delete a token
  if err := store.Delete("my-client-id"); err != nil {
    panic(err)
  }
}
```

## Usage

### Store Interface

All stores implement the generic `Store[T]` interface:

```go
type Store[T any] interface {
  Load(clientID string) (T, error)
  Save(clientID string, data T) error
  Delete(clientID string) error
  String() string
}
```

### Token

```go
type Token struct {
  AccessToken  string    `json:"access_token"`
  RefreshToken string    `json:"refresh_token"`
  TokenType    string    `json:"token_type"`
  ExpiresAt    time.Time `json:"expires_at"`
  ClientID     string    `json:"client_id"`
}
```

### Token Helpers

Tokens provide convenience methods for checking validity:

```go
loaded, err := store.Load("my-client-id")
if err != nil {
  // handle error
}

// Check if token has expired
if loaded.IsExpired() {
  // refresh the token
}

// Check if token is usable (non-empty access token and not expired)
if loaded.IsValid() {
  // use the token
}
```

### Listing Tokens

`FileStore` and `EncryptedFileStore` implement the optional `Lister` interface:

```go
type Lister interface {
  List() ([]string, error)
}
```

Use a type assertion to check listing support at runtime:

```go
if lister, ok := store.(credstore.Lister); ok {
  ids, err := lister.List()
  if err != nil {
    panic(err)
  }
  fmt.Println("Stored client IDs:", ids) // sorted alphabetically
}
```

> Note: `*SecureStore` does **not** implement `Lister`. If you need listing, use `*FileStore` or `*EncryptedFileStore` directly.

### FileStore

Stores data in a JSON file with file locking and atomic writes. Parent directories are created automatically.

```go
// Token store (convenience constructor)
store := credstore.NewTokenFileStore("~/.config/my-app/tokens.json")

// Plain string store
store := credstore.NewStringFileStore("~/.config/my-app/tokens.json")

// Custom type with JSON encoding
store := credstore.NewFileStore[MyCredentials]("~/.config/my-app/creds.json", credstore.JSONCodec[MyCredentials]{})
```

> **⚠ Breaking change (file format):** The on-disk JSON format changed from
> `{"tokens":{...}}` to `{"data":{...}}`. Files written by a previous version
> will fail to parse and must be deleted before first use.

### KeyringStore

Stores data in the OS keyring. Implements the `Prober` interface to test keyring availability.

```go
// Token store (convenience constructor)
store := credstore.NewTokenKeyringStore("my-app")

// Plain string store
store := credstore.NewStringKeyringStore("my-app")

// Check if keyring is available
if store.Probe() {
  fmt.Println("Keyring is available")
}
```

> **⚠ Keyring size limits:** OS keyrings reject large payloads — Windows
> Credential Manager caps blobs at 2560 bytes, and macOS/Linux backends have
> limits too. Tokens with groups claims easily exceed that. For large values,
> use `EncryptedFileStore` instead, which keeps only a 32-byte key in the
> keyring.

### EncryptedFileStore

Stores values AES-256-GCM-encrypted in a JSON file. Only the 32-byte master key lives in the OS keyring (44 bytes base64-encoded — constant size, regardless of how large the stored values grow). The master key is generated automatically on first use. Implements `Store[T]`, `Lister`, and `Prober`.

```go
// Token store (convenience constructor)
store := credstore.NewTokenEncryptedFileStore("my-app", "~/.config/my-app/tokens.enc")

// Custom type with JSON encoding
store := credstore.NewEncryptedFileStore[MyCredentials](
  "my-app", "~/.config/my-app/creds.enc", credstore.JSONCodec[MyCredentials]{})

// Logout flow: delete the data, then the master key
_ = store.Delete("my-client-id")
_ = store.DeleteMasterKey() // existing ciphertext becomes unreadable
```

The file layout is the same `{"data": {clientID: value}}` map as `FileStore`, but each value is `v1:base64(nonce || AES-256-GCM ciphertext)` (the `v1:` prefix versions the format for future algorithm migration). Files are written with `0600` permissions using file locking and atomic renames.

### SecureStore

A composite store that automatically selects the best available backend. The default setup keeps payloads out of the keyring entirely:

- **Keyring available** — data is AES-256-GCM-encrypted to `filePath + ".enc"` via `EncryptedFileStore`; the keyring holds only the 32-byte master key
- **Keyring unavailable** (e.g. headless Linux) — falls back to plaintext file storage at `filePath`

```go
// Quick setup with defaults (Token)
store := credstore.DefaultTokenSecureStore("my-app", "/path/to/tokens.json")

// Or let the SDK pick a conventional, OS-appropriate path
path, err := credstore.DefaultStorePath("my-app", "tokens.json")
if err != nil {
  panic(err)
}
store := credstore.DefaultTokenSecureStore("my-app", path)

// Or configure manually
enc := credstore.NewTokenEncryptedFileStore("my-app", "/path/to/tokens.enc")
file := credstore.NewTokenFileStore("/path/to/tokens.json")
store := credstore.NewSecureStore(enc, file)

if store.UseKeyring() {
  fmt.Println("Using encrypted file (master key in OS keyring)")
} else {
  fmt.Println("Using plaintext file storage")
}

// Generic setup with custom codec
store := credstore.DefaultSecureStore[MyCredentials]("my-app", "/path/to/creds.json", credstore.JSONCodec[MyCredentials]{})
```

> **⚠ Breaking change (storage layout):** `DefaultSecureStore` and
> `DefaultTokenSecureStore` no longer write token payloads into the OS
> keyring. With the keyring available, data now lives encrypted in
> `filePath + ".enc"` and the keyring holds only the master key. Tokens
> saved into the keyring by previous versions are not migrated — users
> re-authenticate once. The plaintext fallback file at `filePath` is
> unaffected.

### Default Paths

`DefaultStorePath` returns a conventional, OS-appropriate file path —
`filepath.Join(os.UserConfigDir(), appName, fileName)` — so you don't have to
hard-code locations or expand `~` yourself:

```go
path, err := credstore.DefaultStorePath("my-app", "tokens.json")
// macOS:   ~/Library/Application Support/my-app/tokens.json
// Linux:   $XDG_CONFIG_HOME/my-app/tokens.json (else ~/.config/my-app/tokens.json)
// Windows: %AppData%\my-app\tokens.json
```

For the common token case, `DefaultTokenStorePath` is a shorthand that fixes the
file name to `tokens.json` (exported as `DefaultTokenFileName`):

```go
path, err := credstore.DefaultTokenStorePath("my-app")
// => <UserConfigDir>/my-app/tokens.json
store := credstore.DefaultTokenSecureStore("my-app", path)
```

Parent directories are not created by these helpers; the file-backed stores
create them on first `Save`. With keyring available, `DefaultTokenSecureStore`
encrypts to `path + ".enc"` (see [SecureStore](#securestore)).

### Codec

`Codec[T]` handles serialization between values and the strings stored in the backend:

```go
type Codec[T any] interface {
  Encode(v T) (string, error)
  Decode(s string) (T, error)
}
```

Built-in implementations:

| Codec          | Type     | Description                        |
| -------------- | -------- | ---------------------------------- |
| `JSONCodec[T]` | any      | Marshals/unmarshals T as JSON      |
| `StringCodec`  | `string` | Identity — stores the string as-is |

Custom codecs can be used for encryption, compression, or any other encoding:

```go
type EncryptedCodec struct{ key []byte }

func (c EncryptedCodec) Encode(v string) (string, error) { /* encrypt */ }
func (c EncryptedCodec) Decode(s string) (string, error) { /* decrypt */ }

store := credstore.NewFileStore[string]("/path/to/store.json", EncryptedCodec{key: myKey})
```

### Error Handling

```go
import "errors"

_, err := store.Load("client-id")
if errors.Is(err, credstore.ErrNotFound) {
  // Data not found — trigger a new OAuth flow
}
```

| Error              | Description                             |
| ------------------ | --------------------------------------- |
| `ErrNotFound`      | No data found for the given client ID   |
| `ErrEmptyClientID` | An empty client ID was passed to `Save` |

## Benchmarks

Tested on Apple M4 Pro, Go 1.24. KeyringStore uses an in-memory mock; real OS keyring performance will vary (typically a few hundred microseconds to a few milliseconds due to IPC overhead).

### FileStore vs KeyringStore

| Operation | FileStore           | KeyringStore (mock)  | Ratio |
| --------- | ------------------- | -------------------- | ----- |
| Save      | ~196 µs / 42 allocs | ~0.31 µs / 3 allocs  | ~630x |
| Load      | ~12 µs / 23 allocs  | ~0.85 µs / 10 allocs | ~14x  |
| Delete    | ~391 µs / 75 allocs | ~0.49 µs / 8 allocs  | ~800x |

FileStore is slower because every Save/Delete requires file lock acquisition, full JSON read-modify-write, and an atomic rename. Load is faster since it skips the file lock.

### FileStore scaling by number of stored clients

| Clients | Save latency | Allocs |
| ------- | ------------ | ------ |
| 1       | 196 µs       | 42     |
| 10      | 213 µs       | 126    |
| 50      | 310 µs       | 490    |

Allocations grow linearly because the entire data map is deserialized and re-serialized on each write.

Run benchmarks yourself:

```bash
go test ./credstore/... -bench=. -benchmem -count=3 -run=^$
```
