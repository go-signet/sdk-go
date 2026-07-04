package oauth_test

import (
	"context"
	"fmt"
	"log"

	"github.com/go-signet/sdk-go/oauth"
)

// Example demonstrates a confidential client requesting a token via the
// Client Credentials grant.
func Example() {
	client, err := oauth.NewClient("my-client-id",
		oauth.Endpoints{
			TokenURL: "https://auth.example.com/oauth/token",
		},
		oauth.WithClientSecret("my-client-secret"),
	)
	if err != nil {
		log.Fatal(err)
	}

	token, err := client.ClientCredentials(context.Background(), []string{"read", "write"})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.AccessToken)
}

// ExampleNewClient shows the minimal construction of a public client with
// only the token endpoint configured.
func ExampleNewClient() {
	client, err := oauth.NewClient("my-client-id", oauth.Endpoints{
		TokenURL: "https://auth.example.com/oauth/token",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(client.ClientID())
	// Output:
	// my-client-id
}
