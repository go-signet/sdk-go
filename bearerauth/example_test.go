package bearerauth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"

	"github.com/go-signet/sdk-go/bearerauth"
	"github.com/go-signet/sdk-go/jwksauth"
)

// Example verifies a credential that may be either a JWT access token or a
// Signet Personal API Key. [New] takes the issuer URL and derives everything
// else — the JWT verifier, the canonical policy issuer, and the tokeninfo
// endpoint — from discovery.
func Example() {
	ctx := context.Background()

	verifier, err := bearerauth.New(ctx, "https://auth.example.com", bearerauth.Config{
		Audience:       "api://orders",
		ClientID:       "orders-api",
		RequiredScopes: []string{"orders.read"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The argument is the value after "Bearer " in the Authorization header.
	identity, err := verifier.Verify(ctx, "sgk_...")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(identity.Subject, identity.CredentialType, identity.HasScope("orders.read"))
}

// ExampleNew_introspection switches the Personal API Key path to RFC 7662
// introspection by supplying confidential client credentials. Everything else
// is unchanged.
func ExampleNew_introspection() {
	ctx := context.Background()

	verifier, err := bearerauth.New(ctx, "https://auth.example.com", bearerauth.Config{
		Audience:       "api://orders",
		ClientID:       "orders-api",
		RequiredScopes: []string{"orders.read"},

		// Signet's ownership gate means these normally have to belong to the
		// same Client App as ClientID above.
		IntrospectionClientID:     "orders-api",
		IntrospectionClientSecret: os.Getenv("ORDERS_API_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}

	identity, err := verifier.Verify(ctx, "sgk_...")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(identity.Subject, identity.Scopes)
}

// ExampleNewTokenInfoVerifier builds the same verifier without discovery, for
// callers that already hold a JWT verifier — a *jwksauth.MultiVerifier, say —
// or that need a non-standard endpoint.
func ExampleNewTokenInfoVerifier() {
	ctx := context.Background()

	jwtVerifier, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "api://orders")
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := bearerauth.NewTokenInfoVerifier(
		jwtVerifier,
		"https://auth.example.com/oauth/tokeninfo",
		bearerauth.Policy{
			// Pass the issuer Signet discovery reported, byte-for-byte.
			Issuer:         jwtVerifier.Issuer(),
			ClientID:       "orders-api",
			RequiredScopes: []string{"orders.read"},
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	identity, err := verifier.Verify(ctx, "sgk_...")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(identity.Subject)
}

// ExampleNewIntrospectionVerifier verifies Personal API Keys through RFC 7662
// introspection.
//
// Signet's default ownership gate strips the response metadata when the
// introspecting client does not own the key's Client App, and this package
// fails closed on such a response — so the configured client normally has to
// be the same Client App the policy pins.
func ExampleNewIntrospectionVerifier() {
	ctx := context.Background()

	jwtVerifier, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "api://orders")
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := bearerauth.NewIntrospectionVerifier(
		jwtVerifier,
		"https://auth.example.com/oauth/introspect",
		"orders-api",        // client ID of the owning Client App
		"orders-api-secret", // client secret; never appears in errors
		bearerauth.Policy{
			Issuer:         jwtVerifier.Issuer(),
			ClientID:       "orders-api",
			RequiredScopes: []string{"orders.read", "orders.write"},
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	identity, err := verifier.Verify(ctx, "sgk_...")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(identity.Subject, identity.Scopes)
}

// ExampleVerifier_Verify shows how to turn the five stable error categories
// into HTTP responses. Framework adapters own this mapping; the package itself
// never writes a response.
func ExampleVerifier_Verify() {
	// verifier is built once at startup and shared by every request.
	var verifier *bearerauth.Verifier

	authorize := func(w http.ResponseWriter, r *http.Request, credential string) {
		identity, err := verifier.Verify(r.Context(), credential)
		switch {
		case err == nil:
			fmt.Fprintln(w, "authorized:", identity.Subject)

		case errors.Is(err, bearerauth.ErrInsufficientScope):
			// Advertise what to request next time (RFC 6750 §3.1).
			var scopeErr *bearerauth.InsufficientScopeError
			errors.As(err, &scopeErr)
			w.Header().Set(
				"WWW-Authenticate",
				`Bearer error="insufficient_scope", scope="`+scopeErr.MissingScope+`"`,
			)
			w.WriteHeader(http.StatusForbidden)

		case errors.Is(err, bearerauth.ErrInvalidCredential),
			errors.Is(err, bearerauth.ErrUntrustedIssuer),
			errors.Is(err, bearerauth.ErrClientAppNotAllowed):
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)

		case errors.Is(err, bearerauth.ErrVerifierUnavailable):
			// The verdict is unknown, not negative: ask the client to retry
			// instead of telling it to re-authenticate.
			w.WriteHeader(http.StatusServiceUnavailable)

		default:
			// Fail closed. Without this arm an unrecognized error would fall
			// through having written nothing, and net/http would answer 200 OK
			// for a request that was never authorized.
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	http.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		credential, ok := bearerCredential(r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authorize(w, r, credential)
	})
}

// bearerCredential extracts the credential from an Authorization header.
//
// RFC 6750 §2.1 makes the scheme name case-insensitive, and RFC 9110 allows
// extra whitespace between it and the credential, so a plain
// strings.TrimPrefix(auth, "Bearer ") would reject a legitimate
// `authorization: bearer sgk_…` — the form HTTP/2 lowercasing and several
// client libraries produce.
func bearerCredential(header string) (string, bool) {
	scheme, credential, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	credential = strings.TrimSpace(credential)
	return credential, credential != ""
}

// ExampleWithHTTPClient injects a go-httpretry client so the online Personal
// API Key call can carry deployment-specific timeouts, metrics, or tracing.
//
// An injected client must be safe for concurrent use, must not be mutated
// after construction, must refuse redirects, and its callbacks must redact the
// Authorization header and the introspection form body.
func ExampleWithHTTPClient() {
	httpClient, err := retry.NewRealtimeClient(
		retry.WithNoLogging(),
		retry.WithMaxRetries(1),
		retry.WithPerAttemptTimeout(2*time.Second),
		retry.WithHTTPClient(&http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	jwtVerifier, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "api://orders")
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := bearerauth.NewTokenInfoVerifier(
		jwtVerifier,
		"https://auth.example.com/oauth/tokeninfo",
		bearerauth.Policy{Issuer: jwtVerifier.Issuer(), ClientID: "orders-api"},
		bearerauth.WithHTTPClient(httpClient),
	)
	if err != nil {
		log.Fatal(err)
	}

	identity, err := verifier.Verify(ctx, "sgk_...")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(identity.Subject)
}

// ExampleIdentity_HasScope shows the normalized identity both credential paths
// produce. Scopes are de-duplicated and sorted, so matching is order
// independent — but exact and case-sensitive.
func ExampleIdentity_HasScope() {
	identity := bearerauth.Identity{
		Subject:        "user-42",
		SubjectType:    bearerauth.SubjectUser,
		Issuer:         "https://auth.example.com",
		ClientID:       "orders-api",
		Scopes:         []string{"orders.read", "orders.write"},
		ExpiresAt:      time.Now().Add(time.Hour),
		CredentialType: bearerauth.CredentialPersonalAPIKey,
	}

	fmt.Println(identity.HasScope("orders.read"))
	fmt.Println(identity.HasScope("orders.delete"))
	fmt.Println(identity.HasScope("Orders.Read"))
	// Output:
	// true
	// false
	// false
}
