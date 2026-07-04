package discovery_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-signet/sdk-go/discovery"
)

// ExampleNewClient demonstrates discovering OAuth endpoints from an issuer's
// /.well-known/openid-configuration document and converting them for use
// with the oauth package.
func ExampleNewClient() {
	disco, err := discovery.NewClient("https://auth.example.com",
		discovery.WithCacheTTL(10*time.Minute),
	)
	if err != nil {
		log.Fatal(err)
	}

	meta, err := disco.Fetch(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Convert the discovered metadata to endpoints for oauth.NewClient.
	endpoints := meta.Endpoints()

	fmt.Println(meta.Issuer, endpoints.TokenURL)
}
