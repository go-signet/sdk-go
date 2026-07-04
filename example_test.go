package signet_test

import (
	"context"
	"fmt"
	"log"

	signet "github.com/go-signet/sdk-go"
)

// Example demonstrates the one-call SDK facade: it discovers endpoints,
// reuses or refreshes a cached token, and falls back to an interactive
// authentication flow when no valid token exists.
func Example() {
	ctx := context.Background()

	client, token, err := signet.New(ctx,
		"https://auth.example.com",
		"my-client-id",
		signet.WithScopes("profile", "email"),
		signet.WithServiceName("my-app"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(client.ClientID(), token.AccessToken)
}
