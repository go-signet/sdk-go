package authflow_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/go-signet/sdk-go/authflow"
	"github.com/go-signet/sdk-go/credstore"
	"github.com/go-signet/sdk-go/oauth"
)

// ExampleNewTokenSource demonstrates combining an oauth client with a
// credstore store to build a TokenSource that loads cached tokens and
// refreshes them automatically, falling back to an interactive flow when
// re-authentication is required.
func ExampleNewTokenSource() {
	ctx := context.Background()

	client, err := oauth.NewClient("my-client-id", oauth.Endpoints{
		AuthorizeURL: "https://auth.example.com/oauth/authorize",
		TokenURL:     "https://auth.example.com/oauth/token",
	})
	if err != nil {
		log.Fatal(err)
	}

	path, err := credstore.DefaultTokenStorePath("my-app")
	if err != nil {
		log.Fatal(err)
	}
	store := credstore.DefaultTokenSecureStore("my-app", path)
	const resource = "https://api.example.com"
	ts := authflow.NewTokenSource(client,
		authflow.WithStore(store),
		authflow.WithTokenResources(resource),
	)

	// Token loads from the store and refreshes expired tokens automatically.
	token, err := ts.Token(ctx)
	if errors.Is(err, authflow.ErrReauthRequired) {
		// No cached or refreshable token: run an interactive flow and
		// persist the result for next time.
		token, err = authflow.RunAuthCodeFlow(ctx, client, []string{"profile"},
			authflow.WithResources(resource),
		)
		if err == nil {
			err = ts.SaveToken(token)
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.AccessToken)
}

// ExampleNewPKCE demonstrates generating a PKCE verifier/challenge pair
// (RFC 7636) for the Authorization Code flow.
func ExampleNewPKCE() {
	pkce, err := authflow.NewPKCE()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pkce.Method)
	fmt.Println(pkce.Verifier != "")
	// Output:
	// S256
	// true
}

// ExampleRunAuthCodeFlow demonstrates the Authorization Code + PKCE flow:
// it starts a local callback server, opens the browser, and exchanges the
// authorization code automatically.
func ExampleRunAuthCodeFlow() {
	client, err := oauth.NewClient("my-client-id", oauth.Endpoints{
		AuthorizeURL: "https://auth.example.com/oauth/authorize",
		TokenURL:     "https://auth.example.com/oauth/token",
	})
	if err != nil {
		log.Fatal(err)
	}

	token, err := authflow.RunAuthCodeFlow(context.Background(), client,
		[]string{"openid", "profile"},
		authflow.WithLocalPort(8088),
		authflow.WithResources("https://api.example.com"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.AccessToken)
}

// ExampleRunDeviceFlow demonstrates the Device Code flow (RFC 8628):
// request a device code, show it to the user, and poll until authorized.
func ExampleRunDeviceFlow() {
	client, err := oauth.NewClient("my-client-id", oauth.Endpoints{
		TokenURL:               "https://auth.example.com/oauth/token",
		DeviceAuthorizationURL: "https://auth.example.com/oauth/device/code",
	})
	if err != nil {
		log.Fatal(err)
	}

	// The verification URI and user code are printed to stdout by the
	// default handler; use WithDeviceFlowHandler to render them differently.
	token, err := authflow.RunDeviceFlow(context.Background(), client,
		[]string{"read", "write"},
		authflow.WithResources("https://api.example.com"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.AccessToken)
}
