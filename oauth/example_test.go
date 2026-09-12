package oauth_test

import (
	"context"
	"fmt"
	"log"
	"os"

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

	token, err := client.ClientCredentials(
		context.Background(),
		[]string{"read", "write"},
		[]string{"https://api.example.com"},
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.AccessToken)
}

// ExampleClient_ExchangeOnBehalfOf demonstrates API A exchanging a user token
// for a short-lived token addressed to API B.
func ExampleClient_ExchangeOnBehalfOf() {
	client, err := oauth.NewClient("api-a", oauth.Endpoints{
		TokenURL: "https://auth.example.com/oauth/token",
	}, oauth.WithClientSecret(os.Getenv("API_A_CLIENT_SECRET")))
	if err != nil {
		log.Fatal(err)
	}

	token, err := client.ExchangeOnBehalfOf(context.Background(), oauth.OnBehalfOfRequest{
		Assertion: "signet-user-access-token-for-api-a",
		Resource:  "https://api-b.example.com",
		Scopes:    []string{"orders.read"},
	})
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
