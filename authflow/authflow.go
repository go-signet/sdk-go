// Package authflow provides high-level CLI authentication flow orchestration.
//
// It handles Device Code polling, Authorization Code + PKCE with a local
// callback server and browser opening, and automatic token refresh with
// persistent storage via credstore.
package authflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/go-signet/sdk-go/credstore"
	"github.com/go-signet/sdk-go/oauth"
)

// ErrReauthRequired is returned by TokenSource.Token when interactive
// re-authentication is required. This covers all cases where the
// TokenSource cannot produce a token without user interaction:
//   - no store is configured;
//   - the store has no token for this client;
//   - the stored token is expired and has no refresh token;
//   - the refresh token has been revoked or has expired.
//
// Callers should fall back to an interactive authentication flow
// when they see this error.
var ErrReauthRequired = errors.New("authflow: re-authentication required")

const (
	htmlAuthSuccess = "<html><body><h1>Authentication successful</h1><p>You can close this window.</p></body></html>"
	htmlAuthFailed  = "<html><body><h1>Authentication failed</h1><p>You can close this window.</p></body></html>"
	htmlStateError  = "<html><body><h1>Authentication failed</h1><p>State mismatch. You can close this window.</p></body></html>"
)

// refreshTimeout caps the singleflight token-refresh round-trip (including
// the network call and any retries). Real refresh responses are well under
// this limit; the cap prevents a hung or unresponsive server from making
// the shared refresh goroutine outlive every caller indefinitely.
const refreshTimeout = 30 * time.Second

// DeviceFlowHandler is called to display the device code to the user.
type DeviceFlowHandler interface {
	DisplayCode(auth *oauth.DeviceAuth) error
}

// DefaultDeviceFlowHandler prints the user code and verification URI to stdout.
type DefaultDeviceFlowHandler struct{}

// DisplayCode prints instructions for the user.
func (h DefaultDeviceFlowHandler) DisplayCode(auth *oauth.DeviceAuth) error {
	fmt.Printf(
		"Open %s in your browser and enter code: %s\n",
		auth.VerificationURI,
		auth.UserCode,
	)
	return nil
}

// DeviceFlowOption configures RunDeviceFlow.
type DeviceFlowOption func(*deviceFlowConfig)

type deviceFlowConfig struct {
	handler     DeviceFlowHandler
	openBrowser bool
}

// WithDeviceFlowHandler sets a custom handler for displaying the device code.
func WithDeviceFlowHandler(h DeviceFlowHandler) DeviceFlowOption {
	return func(cfg *deviceFlowConfig) {
		cfg.handler = h
	}
}

// WithOpenBrowser controls whether to automatically open the verification URI.
func WithOpenBrowser(open bool) DeviceFlowOption {
	return func(cfg *deviceFlowConfig) {
		cfg.openBrowser = open
	}
}

// RunDeviceFlow executes the complete Device Code flow (RFC 8628):
// request device code, display user code, poll for token.
func RunDeviceFlow(
	ctx context.Context,
	client *oauth.Client,
	scopes []string,
	opts ...DeviceFlowOption,
) (*oauth.Token, error) {
	cfg := &deviceFlowConfig{
		handler: DefaultDeviceFlowHandler{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	auth, err := client.RequestDeviceCode(ctx, scopes)
	if err != nil {
		return nil, fmt.Errorf("authflow: request device code: %w", err)
	}

	if err := cfg.handler.DisplayCode(auth); err != nil {
		return nil, fmt.Errorf("authflow: display code: %w", err)
	}

	if cfg.openBrowser {
		uri := auth.VerificationURIComplete
		if uri == "" {
			uri = auth.VerificationURI
		}
		_ = openBrowser(uri)
	}

	return pollDeviceCode(ctx, client, auth)
}

// pollDeviceCode polls the token endpoint until the user authorizes or the code expires.
func pollDeviceCode(
	ctx context.Context,
	client *oauth.Client,
	auth *oauth.DeviceAuth,
) (*oauth.Token, error) {
	interval := time.Duration(auth.Interval) * time.Second
	if interval < 1*time.Second {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		// Pre-check guards against an already-past deadline (e.g., a slow
		// previous ExchangeDeviceCode call) so we don't wait another interval
		// before returning expired.
		if time.Now().After(deadline) {
			return nil, errors.New("authflow: device code expired")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}

		// Re-check after the timer fires to close the near-deadline race.
		if time.Now().After(deadline) {
			return nil, errors.New("authflow: device code expired")
		}

		token, err := client.ExchangeDeviceCode(ctx, auth.DeviceCode)
		if err != nil {
			var oauthErr *oauth.Error
			if errors.As(err, &oauthErr) {
				switch oauthErr.Code {
				case oauth.ErrCodeAuthorizationPending:
					timer.Reset(interval)
					continue
				case oauth.ErrCodeSlowDown:
					interval += 5 * time.Second
					timer.Reset(interval)
					continue
				case oauth.ErrCodeExpiredToken:
					return nil, errors.New("authflow: device code expired")
				case oauth.ErrCodeAccessDenied:
					return nil, errors.New("authflow: access denied by user")
				}
			}
			return nil, fmt.Errorf("authflow: exchange device code: %w", err)
		}

		return token, nil
	}
}

// generateState produces a cryptographically random state string for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AuthCodeFlowOption configures RunAuthCodeFlow.
type AuthCodeFlowOption func(*authCodeFlowConfig)

type authCodeFlowConfig struct {
	localPort int // 0 means pick a random free port
}

// WithLocalPort sets the local port for the callback server.
// By default a random free port is used.
func WithLocalPort(port int) AuthCodeFlowOption {
	return func(cfg *authCodeFlowConfig) {
		cfg.localPort = port
	}
}

// RunAuthCodeFlow executes the Authorization Code + PKCE flow:
// generate PKCE + state, start local callback server, open browser, exchange code.
func RunAuthCodeFlow(
	ctx context.Context,
	client *oauth.Client,
	scopes []string,
	opts ...AuthCodeFlowOption,
) (*oauth.Token, error) {
	cfg := &authCodeFlowConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	pkce, err := NewPKCE()
	if err != nil {
		return nil, fmt.Errorf("authflow: generate PKCE: %w", err)
	}

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("authflow: generate state: %w", err)
	}

	// Start the callback server on the configured (or random) port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.localPort))
	if err != nil {
		return nil, fmt.Errorf("authflow: listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeCh := make(chan string, 1)
	// Buffer of 2 protects errCh against blocked sends: the callback handler
	// and the Serve goroutine can both attempt to send before the main
	// goroutine drains the channel.
	errCh := make(chan error, 2)

	// sync.Once ensures only the first callback is processed; browser retries
	// or user refreshes receive a simple acknowledgement.
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		handled := false
		once.Do(func() {
			handled = true
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{
					Code:        oauth.ErrCodeInvalidState,
					Description: "State parameter mismatch",
				}
				fmt.Fprint(w, htmlStateError)
				return
			}

			code := r.URL.Query().Get("code")
			if code == "" {
				errMsg := r.URL.Query().Get("error")
				errDesc := r.URL.Query().Get("error_description")
				if errMsg == "" {
					errMsg = "no code received"
				}
				errCh <- &oauth.Error{Code: errMsg, Description: errDesc}
				fmt.Fprint(w, htmlAuthFailed)
				return
			}
			codeCh <- code
			fmt.Fprint(w, htmlAuthSuccess)
		})
		if !handled {
			fmt.Fprint(
				w,
				"<html><body><p>Already processed. You can close this window.</p></body></html>",
			)
		}
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if srvErr := server.Serve(listener); srvErr != nil &&
			!errors.Is(srvErr, http.ErrServerClosed) {
			select {
			case errCh <- fmt.Errorf("authflow: callback server: %w", srvErr):
			default:
			}
		}
	}()

	endpoints := client.Endpoints()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID()},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	authURL := endpoints.AuthorizeURL + "?" + params.Encode()

	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Open this URL in your browser:\n%s\n", authURL)
	}

	// shutdown uses a detached context with a short timeout so that a canceled
	// parent ctx does not cause Shutdown to return immediately and leave the
	// listener bound (RFC 7230 §6.6 — graceful close with bounded wait).
	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
	}

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		shutdown()
		return nil, err
	case <-ctx.Done():
		shutdown()
		return nil, ctx.Err()
	}

	shutdown()

	token, err := client.ExchangeAuthCode(ctx, code, redirectURI, pkce.Verifier)
	if err != nil {
		return nil, fmt.Errorf("authflow: exchange auth code: %w", err)
	}
	return token, nil
}

// TokenSourceOption configures a TokenSource.
type TokenSourceOption func(*TokenSource)

// WithStore sets the credential store for token persistence.
func WithStore(store credstore.Store[credstore.Token]) TokenSourceOption {
	return func(ts *TokenSource) {
		ts.store = store
	}
}

// TokenSource provides automatic token refresh with optional persistent storage.
// Concurrent Token() callers share a single in-flight refresh via singleflight;
// mu additionally serializes store I/O so external SaveToken writes that race
// with an in-flight refresh are not silently overwritten — see loadOrRefresh.
type TokenSource struct {
	client *oauth.Client
	store  credstore.Store[credstore.Token]
	mu     sync.Mutex
	group  singleflight.Group
}

// NewTokenSource creates a new TokenSource that automatically refreshes tokens.
func NewTokenSource(client *oauth.Client, opts ...TokenSourceOption) *TokenSource {
	ts := &TokenSource{
		client: client,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(ts)
		}
	}
	return ts
}

// Token returns a valid token, refreshing from store or server as needed.
// Returns ErrReauthRequired when no valid or refreshable token is available.
//
// Fast path: a read of an already-valid stored token bypasses singleflight so
// callers are not blocked behind an unrelated in-flight refresh. Slow path:
// refreshes are coalesced via singleflight and selected against ctx.Done so
// each caller can honor its own cancellation while the inner refresh runs.
func (ts *TokenSource) Token(ctx context.Context) (*oauth.Token, error) {
	if ts.store != nil {
		ts.mu.Lock()
		stored, err := ts.store.Load(ts.client.ClientID())
		ts.mu.Unlock()
		if err == nil && stored.IsValid() {
			return credstoreToOAuth(&stored), nil
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Detach the ctx that singleflight passes into loadOrRefresh from the
	// caller's cancellation. singleflight runs the function once with the
	// first caller's ctx, so without this the first caller's timeout would
	// abort the shared refresh for every concurrent waiter. context.WithoutCancel
	// also strips the caller's deadline, so wrap the inner ctx with a bounded
	// internal timeout — otherwise a hung server could let the refresh run
	// forever after every caller has returned. Each caller still honors its
	// own cancellation via the select below.
	ch := ts.group.DoChan("token", func() (any, error) {
		innerCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		defer cancel()
		return ts.loadOrRefresh(innerCtx)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*oauth.Token), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// loadOrRefresh acquires ts.mu only around store I/O so the network refresh
// call does not block external SaveToken callers. singleflight guarantees at
// most one loadOrRefresh runs at a time, so there is no concurrent refresh.
func (ts *TokenSource) loadOrRefresh(ctx context.Context) (*oauth.Token, error) {
	if ts.store == nil {
		return nil, ErrReauthRequired
	}

	ts.mu.Lock()
	stored, err := ts.store.Load(ts.client.ClientID())
	ts.mu.Unlock()
	if err != nil {
		if errors.Is(err, credstore.ErrNotFound) {
			return nil, ErrReauthRequired
		}
		return nil, fmt.Errorf("authflow: load token: %w", err)
	}

	if stored.IsValid() {
		return credstoreToOAuth(&stored), nil
	}

	if stored.RefreshToken == "" {
		return nil, ErrReauthRequired
	}

	refreshed, err := ts.client.RefreshToken(ctx, stored.RefreshToken)
	if err != nil {
		// invalid_grant / invalid_token mean the refresh token is no longer
		// usable (revoked or expired). Surface as ErrReauthRequired so callers
		// fall back to interactive re-authentication.
		var oauthErr *oauth.Error
		if errors.As(err, &oauthErr) &&
			(oauthErr.Code == oauth.ErrCodeInvalidGrant || oauthErr.Code == oauth.ErrCodeInvalidToken) {
			return nil, fmt.Errorf("%w: %w", ErrReauthRequired, err)
		}
		return nil, fmt.Errorf("authflow: refresh token: %w", err)
	}

	// RFC 6749 §6 permits the server to omit refresh_token (and scope) from a
	// refresh response when they are unchanged. Carry the prior values forward
	// so a successful refresh never erases a still-valid refresh token — which
	// would force interactive re-authentication on the next expiry — or drop
	// the granted scope.
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = stored.RefreshToken
	}
	if refreshed.Scope == "" {
		refreshed.Scope = stored.Scope
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Re-check the store under the lock. While ts.mu was released for the
	// network refresh, an external SaveToken caller may have written a newer
	// token. If any of the fields we care about have changed (access token,
	// refresh token, or expiry) AND the new token is itself valid, trust
	// the external write and return it instead of overwriting it. If the
	// concurrent write produced an invalid/expired token, fall through and
	// save our freshly refreshed result.
	current, currentErr := ts.store.Load(ts.client.ClientID())
	if currentErr == nil && current.IsValid() &&
		(current.AccessToken != stored.AccessToken ||
			current.RefreshToken != stored.RefreshToken ||
			!current.ExpiresAt.Equal(stored.ExpiresAt)) {
		return credstoreToOAuth(&current), nil
	}

	if err := ts.saveToken(refreshed); err != nil {
		return nil, fmt.Errorf("authflow: save refreshed token: %w", err)
	}
	return refreshed, nil
}

// SaveToken persists a token to the store (if configured).
func (ts *TokenSource) SaveToken(token *oauth.Token) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.saveToken(token)
}

// saveToken assumes ts.mu is held by the caller.
func (ts *TokenSource) saveToken(token *oauth.Token) error {
	if ts.store == nil {
		return nil
	}
	return ts.store.Save(ts.client.ClientID(), oauthToCredstore(token, ts.client.ClientID()))
}

func credstoreToOAuth(t *credstore.Token) *oauth.Token {
	return &oauth.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Scope:        t.Scope,
		IDToken:      t.IDToken,
		ExpiresAt:    t.ExpiresAt,
	}
}

func oauthToCredstore(t *oauth.Token, clientID string) credstore.Token {
	return credstore.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Scope:        t.Scope,
		IDToken:      t.IDToken,
		ExpiresAt:    t.ExpiresAt,
		ClientID:     clientID,
	}
}

// openBrowser opens a URL in the default browser.
func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "linux":
		return exec.Command("xdg-open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// CheckBrowserAvailability checks whether a browser can be opened.
// Returns false in SSH sessions or environments without a display.
func CheckBrowserAvailability() bool {
	// Detect SSH sessions across all platforms
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}

	switch runtime.GOOS {
	case "darwin":
		return true
	case "linux":
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return false
		}
		// Require a display server (X11 or Wayland)
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "windows":
		return true
	default:
		return false
	}
}
