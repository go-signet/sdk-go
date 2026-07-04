package credstore_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-signet/sdk-go/credstore"
)

// Example shows the recommended production setup: tokens are encrypted to
// the conventional OS-appropriate path with the master key in the OS
// keyring, falling back to plaintext file storage when the keyring is
// unavailable.
func Example() {
	path, err := credstore.DefaultTokenStorePath("my-app")
	if err != nil {
		log.Fatal(err)
	}

	store := credstore.DefaultTokenSecureStore("my-app", path)

	err = store.Save("my-client-id", credstore.Token{
		AccessToken: "example-access-token",
		TokenType:   "Bearer",
	})
	if err != nil {
		log.Fatal(err)
	}

	token, err := store.Load("my-client-id")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(store.UseKeyring(), token.AccessToken)
}

// ExampleNewTokenFileStore demonstrates a Save → Load round-trip of OAuth
// tokens with a JSON file store.
func ExampleNewTokenFileStore() {
	dir, err := os.MkdirTemp("", "credstore-example")
	if err != nil {
		log.Fatal(err)
	}

	store := credstore.NewTokenFileStore(filepath.Join(dir, "tokens.json"))

	err = store.Save("my-client-id", credstore.Token{
		AccessToken: "example-access-token",
		TokenType:   "Bearer",
	})
	if err != nil {
		log.Fatal(err)
	}

	token, err := store.Load("my-client-id")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.AccessToken)

	os.RemoveAll(dir)
	// Output:
	// example-access-token
}

// ExampleNewStringFileStore demonstrates storing plain string values,
// such as API keys, in a file store.
func ExampleNewStringFileStore() {
	dir, err := os.MkdirTemp("", "credstore-example")
	if err != nil {
		log.Fatal(err)
	}

	store := credstore.NewStringFileStore(filepath.Join(dir, "secrets.txt"))

	if err := store.Save("my-client-id", "example-api-key"); err != nil {
		log.Fatal(err)
	}

	secret, err := store.Load("my-client-id")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(secret)

	os.RemoveAll(dir)
	// Output:
	// example-api-key
}
