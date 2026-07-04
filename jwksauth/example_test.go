package jwksauth_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-signet/sdk-go/jwksauth"
)

// ExampleNewVerifier demonstrates offline JWT validation for a resource
// server that trusts a single Signet issuer.
func ExampleNewVerifier() {
	ctx := context.Background()

	v, err := jwksauth.NewVerifier(ctx,
		"https://auth.example.com", // issuer
		"https://api.example.com",  // audience: this service
	)
	if err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	mux := http.NewServeMux()
	// An empty AccessRule admits any valid token from the issuer.
	mux.Handle("/api/profile", jwksauth.Middleware(v, jwksauth.AccessRule{})(handler))
	// This route additionally requires the "email" scope.
	mux.Handle("/api/data", jwksauth.Middleware(v, jwksauth.AccessRule{
		Scopes: []string{"email"},
	})(handler))

	log.Fatal(http.ListenAndServe(":8080", mux))
}

// ExampleMiddleware demonstrates enforcing scope and claim allowlists on a
// route and reading the verified claims inside the handler.
func ExampleMiddleware() {
	v, err := jwksauth.NewVerifier(context.Background(),
		"https://auth.example.com",
		"https://api.example.com",
	)
	if err != nil {
		log.Fatal(err)
	}

	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := jwksauth.TokenInfoFromContext(r.Context())
		if !ok {
			// Middleware always attaches TokenInfo; reaching here means the
			// handler was registered without it.
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, info.Subject, info.Claims.Domain, info.Claims.Project)
	})

	mux := http.NewServeMux()
	mux.Handle("/api/admin", jwksauth.Middleware(v, jwksauth.AccessRule{
		Scopes:  []string{"admin"},
		Domains: []string{"oa"},
	})(adminHandler))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
