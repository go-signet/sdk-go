package signet_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"testing"

	signet "github.com/go-signet/sdk-go"
	"github.com/go-signet/sdk-go/oauth"
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
		signet.WithResources("https://api.example.com"),
		signet.WithServiceName("my-app"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(client.ClientID(), token.AccessToken)
}

func TestNewRejectsBlankResourceBeforeDiscovery(t *testing.T) {
	_, _, err := signet.New(t.Context(), "http://127.0.0.1:1", "client",
		signet.WithResources(" "),
	)
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != oauth.ErrCodeInvalidRequest {
		t.Fatalf("error = %v, want invalid_request", err)
	}
}
