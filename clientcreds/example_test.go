package clientcreds_test

import (
	"fmt"
	"log"

	"github.com/go-signet/sdk-go/clientcreds"
	"github.com/go-signet/sdk-go/oauth"
)

// ExampleNewTokenSource demonstrates service-to-service (M2M)
// authentication: the TokenSource caches Client Credentials tokens and
// refreshes them before expiry.
func ExampleNewTokenSource() {
	client, err := oauth.NewClient("my-service",
		oauth.Endpoints{TokenURL: "https://auth.example.com/oauth/token"},
		oauth.WithClientSecret("my-client-secret"),
	)
	if err != nil {
		log.Fatal(err)
	}

	ts := clientcreds.NewTokenSource(client,
		clientcreds.WithScopes("read", "write"),
	)

	// HTTPClient attaches a valid Bearer token to every request. To wrap a
	// custom base transport (proxy, tracing, TLS) instead, set
	// ts.RoundTripper(base) as an http.Client's Transport.
	resp, err := ts.HTTPClient().Get("https://api.internal.example.com/data")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.Status)
	resp.Body.Close()
}
