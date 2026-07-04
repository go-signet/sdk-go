package middleware_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-signet/sdk-go/middleware"
	"github.com/go-signet/sdk-go/oauth"
)

// ExampleBearerAuth demonstrates protecting an http.ServeMux route with
// Bearer token validation and a required scope.
func ExampleBearerAuth() {
	client, err := oauth.NewClient("my-service", oauth.Endpoints{
		TokenInfoURL: "https://auth.example.com/oauth/tokeninfo",
	})
	if err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "authenticated")
	})

	mux := http.NewServeMux()
	mux.Handle("/api/data", middleware.BearerAuth(
		middleware.WithOAuthClient(client),
		middleware.WithRequiredScopes("read"),
	)(handler))

	log.Fatal(http.ListenAndServe(":8080", mux))
}

// ExampleRequireScope demonstrates chaining RequireScope after BearerAuth
// and reading the validated token info from the request context.
func ExampleRequireScope() {
	client, err := oauth.NewClient("my-service", oauth.Endpoints{
		TokenInfoURL: "https://auth.example.com/oauth/tokeninfo",
	})
	if err != nil {
		log.Fatal(err)
	}

	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := middleware.TokenInfoFromContext(r.Context())
		if !ok {
			http.Error(w, "no token info", http.StatusUnauthorized)
			return
		}
		fmt.Fprintln(w, "hello", info.UserID)
	})

	mux := http.NewServeMux()
	mux.Handle("/admin", middleware.BearerAuth(
		middleware.WithOAuthClient(client),
	)(middleware.RequireScope("admin")(adminHandler)))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
