// Package signet provides a one-call entry point for authenticating with
// a Signet server and obtaining an OAuth token.
package signet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-signet/sdk-go/authflow"
	"github.com/go-signet/sdk-go/credstore"
	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/oauth"
)

// FlowMode controls the authentication flow selection strategy.
type FlowMode int

const (
	// FlowModeAuto detects browser availability: uses AuthCode if available, Device otherwise.
	FlowModeAuto FlowMode = iota
	// FlowModeBrowser forces Authorization Code + PKCE flow.
	FlowModeBrowser
	// FlowModeDevice forces Device Code flow.
	FlowModeDevice
)

type config struct {
	scopes      []string
	serviceName string
	storePath   string
	localPort   int
	flowMode    FlowMode
	resources   []string
}

// Option configures the New function.
type Option func(*config)

// WithScopes sets the OAuth scopes to request.
func WithScopes(scopes ...string) Option {
	return func(cfg *config) {
		cfg.scopes = scopes
	}
}

// WithResources sets the RFC 8707 resource indicators for authentication and
// token refresh. Values are copied so callers may safely reuse their slice.
func WithResources(resources ...string) Option {
	resources = slices.Clone(resources)
	return func(cfg *config) {
		cfg.resources = slices.Clone(resources)
	}
}

// WithServiceName sets the keyring service name for token storage.
func WithServiceName(name string) Option {
	return func(cfg *config) {
		cfg.serviceName = name
	}
}

// WithStorePath sets the file fallback path for token storage.
func WithStorePath(path string) Option {
	return func(cfg *config) {
		cfg.storePath = path
	}
}

// WithLocalPort sets the local redirect port for the Authorization Code flow.
func WithLocalPort(port int) Option {
	return func(cfg *config) {
		cfg.localPort = port
	}
}

// WithFlowMode specifies which authentication flow to use.
func WithFlowMode(mode FlowMode) Option {
	return func(cfg *config) {
		cfg.flowMode = mode
	}
}

// New authenticates with the Signet server and returns a ready-to-use OAuth
// client and token. Cached tokens are reused automatically; expired tokens are
// refreshed. When no valid token exists, the flow is determined by flowMode.
//
//	client, token, err := signet.New(ctx,
//	    os.Getenv("SIGNET_URL"),
//	    os.Getenv("CLIENT_ID"),
//	    signet.WithScopes("profile", "email"),
//	)
func New(
	ctx context.Context,
	signetURL, clientID string,
	opts ...Option,
) (*oauth.Client, *oauth.Token, error) {
	if signetURL == "" {
		return nil, nil, errors.New("signet: signetURL is required")
	}
	if clientID == "" {
		return nil, nil, errors.New("signet: clientID is required")
	}

	cfg := &config{
		serviceName: "signet",
		storePath:   ".signet-tokens.json",
		localPort:   8088,
		flowMode:    FlowModeAuto,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	for _, resource := range cfg.resources {
		if strings.TrimSpace(resource) == "" {
			return nil, nil, &oauth.Error{
				Code:        oauth.ErrCodeInvalidRequest,
				Description: "OAuth resources must not be blank",
			}
		}
	}

	// 1. Create a shared HTTP client for both discovery and OAuth
	httpClient, err := oauth.NewDefaultHTTPClient()
	if err != nil {
		return nil, nil, fmt.Errorf("signet: create http client: %w", err)
	}

	// 2. Discover endpoints
	disco, err := discovery.NewClient(signetURL, discovery.WithHTTPClient(httpClient))
	if err != nil {
		return nil, nil, fmt.Errorf("signet: discovery client: %w", err)
	}
	meta, err := disco.Fetch(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("signet: fetch discovery: %w", err)
	}

	// 3. Create OAuth client
	client, err := oauth.NewClient(clientID, meta.Endpoints(), oauth.WithHTTPClient(httpClient))
	if err != nil {
		return nil, nil, fmt.Errorf("signet: oauth client: %w", err)
	}

	// 4. Set up token store and source
	store := credstore.DefaultTokenSecureStore(cfg.serviceName, cfg.storePath)
	ts := authflow.NewTokenSource(
		client,
		authflow.WithStore(store),
		authflow.WithTokenResources(cfg.resources...),
	)

	// 5. Return a cached/refreshed token if available. Only ErrReauthRequired
	// drops through to the interactive flow; other errors (transient store
	// or refresh failures) propagate so callers don't surprise users with an
	// unwanted browser pop-up.
	token, err := ts.Token(ctx)
	if err == nil {
		return client, token, nil
	}
	if !errors.Is(err, authflow.ErrReauthRequired) {
		return nil, nil, fmt.Errorf("signet: get token: %w", err)
	}

	// 6. No valid token — run the appropriate authentication flow.
	// Treat any non-Device value as auto-detect: explicit Browser forces
	// the auth-code flow, while Auto (and any unknown value) probes for a
	// usable browser before falling back to the device flow.
	useBrowser := cfg.flowMode == FlowModeBrowser ||
		(cfg.flowMode != FlowModeDevice && authflow.CheckBrowserAvailability())
	if useBrowser {
		token, err = authflow.RunAuthCodeFlow(ctx, client, cfg.scopes,
			authflow.WithLocalPort(cfg.localPort),
			authflow.WithResources(cfg.resources...),
		)
	} else {
		token, err = authflow.RunDeviceFlow(
			ctx,
			client,
			cfg.scopes,
			authflow.WithResources(cfg.resources...),
		)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("signet: authenticate: %w", err)
	}

	// 7. Persist the new token
	if saveErr := ts.SaveToken(token); saveErr != nil {
		return nil, nil, fmt.Errorf("signet: save token: %w", saveErr)
	}

	return client, token, nil
}
