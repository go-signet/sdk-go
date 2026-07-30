// Package oauth provides an OAuth 2.0 token client for Signet.
//
// It encapsulates all HTTP request/response logic for Device Code,
// Authorization Code + PKCE, Client Credentials, Refresh, Revoke,
// Introspect, and UserInfo flows. This is a pure HTTP client layer
// that does not handle storage, polling, or UI interactions.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
)

// maxResponseBytes caps the amount of data read from any single HTTP response
// to prevent denial-of-service via unbounded response bodies.
const maxResponseBytes = 1 << 20 // 1 MB

// errResponseTooLarge is returned when a server response exceeds maxResponseBytes.
var errResponseTooLarge = fmt.Errorf("oauth: response body exceeds %d bytes", maxResponseBytes)

// limitedBody returns an io.Reader that reads up to maxResponseBytes+1 from r.
// Reading one extra byte lets us distinguish a body of exactly maxResponseBytes
// (valid, leaving N == 1) from one that exceeds the cap (reading at least
// maxResponseBytes+1 bytes, leaving N == 0).
func limitedBody(r io.Reader) *io.LimitedReader {
	return &io.LimitedReader{R: r, N: maxResponseBytes + 1}
}

// checkLimitExceeded returns errResponseTooLarge when the LimitedReader was
// fully exhausted (N == 0), meaning the response body exceeded maxResponseBytes.
// This must be called even on a successful decode: a body that is exactly
// maxResponseBytes+1 of valid JSON decodes cleanly while still violating the
// cap, so relying solely on decode errors would let oversized payloads pass.
// op identifies the calling operation (e.g., "userinfo") so the resulting
// error carries enough context for debugging. When decodeErr is non-nil it is
// wrapped via %w alongside errResponseTooLarge so callers can use errors.Is/As
// against either sentinel.
func checkLimitExceeded(lr *io.LimitedReader, op string, decodeErr error) error {
	if lr.N == 0 {
		if decodeErr != nil {
			return fmt.Errorf("%w (%s): %w", errResponseTooLarge, op, decodeErr)
		}
		return fmt.Errorf("%w (%s)", errResponseTooLarge, op)
	}
	return decodeErr
}

// OAuth 2.0 grant types (RFC 6749 / RFC 8628).
const (
	// GrantTypeAuthorizationCode is the Authorization Code grant (RFC 6749 §4.1).
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeClientCredentials is the Client Credentials grant (RFC 6749 §4.4).
	GrantTypeClientCredentials = "client_credentials"
	// GrantTypeRefreshToken exchanges a refresh token for a new access token (RFC 6749 §6).
	GrantTypeRefreshToken = "refresh_token"
	// GrantTypeDeviceCode is the Device Authorization grant (RFC 8628 §3.4).
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
)

// PKCEMethodS256 is the SHA-256 PKCE code-challenge method (RFC 7636 §4.3).
const PKCEMethodS256 = "S256"

// Error codes used in error responses. Most are RFC-defined OAuth 2.0 codes
// (RFC 6749 §5.2 & §4.1.2.1, RFC 6750 §3.1, RFC 8628 §3.5); ErrCodeInvalidState
// is an SDK-defined extension (see its doc comment below).
const (
	// ErrCodeAuthorizationPending signals the user has not yet completed device authorization (RFC 8628 §3.5).
	ErrCodeAuthorizationPending = "authorization_pending"
	// ErrCodeSlowDown asks the client to increase its device-code polling interval (RFC 8628 §3.5).
	ErrCodeSlowDown = "slow_down"
	// ErrCodeExpiredToken indicates the device_code has expired before authorization completed (RFC 8628 §3.5).
	ErrCodeExpiredToken = "expired_token"
	// ErrCodeAccessDenied signals the user denied the authorization request (RFC 6749 §4.1.2.1).
	ErrCodeAccessDenied = "access_denied"
	// ErrCodeInvalidGrant indicates the grant (auth code, refresh token, etc.) is invalid, expired, or revoked (RFC 6749 §5.2).
	ErrCodeInvalidGrant = "invalid_grant"
	// ErrCodeInvalidToken indicates the access token is invalid, expired, or revoked (RFC 6750 §3.1).
	ErrCodeInvalidToken = "invalid_token"
	// ErrCodeInsufficientScope indicates the token lacks a scope required to access the resource (RFC 6750 §3.1).
	ErrCodeInsufficientScope = "insufficient_scope"
	// ErrCodeInvalidRequest is the RFC 6749 §5.2 "invalid_request" code. This SDK
	// also reuses it for local precondition failures such as an endpoint that has
	// not been configured.
	ErrCodeInvalidRequest = "invalid_request"
	// ErrCodeInvalidState is an SDK-defined (non-standard) code signalling that an
	// authorization-callback state parameter did not match the expected value
	// (CSRF protection). It is not defined by the OAuth RFCs.
	ErrCodeInvalidState = "invalid_state"
	// ErrCodeServerError indicates an unexpected server-side condition, or a local
	// failure handling the server's response (e.g., an unreadable or oversized error
	// body), prevented fulfilling the request (RFC 6749 §4.1.2.1).
	ErrCodeServerError = "server_error"
)

// Token represents an OAuth 2.0 token response (RFC 6749 §5.1).
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`

	// ExpiresAt is computed from ExpiresIn at response parse time.
	ExpiresAt time.Time `json:"-"`
}

// IsExpired reports whether the token has expired.
func (t *Token) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// IsValid reports whether the token has a non-empty access token and is not expired.
func (t *Token) IsValid() bool {
	return t.AccessToken != "" && !t.IsExpired()
}

// DeviceAuth represents a device authorization response (RFC 8628 §3.2).
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// IntrospectionResult represents a token introspection response (RFC 7662 §2.2).
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

// UserInfo represents the OIDC UserInfo response (OIDC Core 1.0 §5.3).
type UserInfo struct {
	Sub               string `json:"sub"`
	Iss               string `json:"iss,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	SubjectType       string `json:"subject_type,omitempty"`
}

// TokenInfo represents the tokeninfo response from Signet.
type TokenInfo struct {
	Active      bool   `json:"active"`
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	Exp         int64  `json:"exp"`
	Iss         string `json:"iss"`
	SubjectType string `json:"subject_type"`
}

// PersonalAPIKeyTokenInfo represents the tokeninfo response Signet returns for
// a complete Personal API Key (`sgk_…`).
//
// It is deliberately a separate type from [TokenInfo]: Personal API Key
// responses additionally carry `token_type`, which a resource server must check
// before trusting the rest of the payload, and adding an exported field to the
// existing [TokenInfo] would break callers using unkeyed struct literals.
type PersonalAPIKeyTokenInfo struct {
	Active      bool   `json:"active"`
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	Exp         int64  `json:"exp"`
	Iss         string `json:"iss"`
	SubjectType string `json:"subject_type"`
	TokenType   string `json:"token_type"`
}

// Error represents an OAuth 2.0 error response (RFC 6749 §5.2).
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	StatusCode  int    `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Description != "" {
		return "oauth: " + e.Code + ": " + e.Description
	}
	return "oauth: " + e.Code
}

// Endpoints holds all OAuth 2.0 endpoint URLs.
type Endpoints struct {
	TokenURL               string
	AuthorizeURL           string
	DeviceAuthorizationURL string
	RevocationURL          string
	IntrospectionURL       string
	UserinfoURL            string
	TokenInfoURL           string
}

// Client is an OAuth 2.0 HTTP client.
type Client struct {
	clientID     string
	clientSecret string
	endpoints    Endpoints
	httpClient   *retry.Client
}

// Option configures a Client.
type Option func(*Client)

// WithClientSecret sets the client secret for confidential clients.
func WithClientSecret(secret string) Option {
	return func(c *Client) {
		c.clientSecret = secret
	}
}

// WithHTTPClient sets a custom retry HTTP client.
// If nil is provided, the default client is kept.
func WithHTTPClient(httpClient *retry.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// RewindBodyMiddleware restores a replayable request body before every retry
// attempt. Install it with [retry.WithPerAttemptMiddleware]
// on any retry client used for form POSTs.
//
// go-httpretry clones the original request per attempt, but a clone shares the
// already-consumed Body reader; only Request.GetBody can produce a fresh one.
// Without this, a form POST is sent in full on the first attempt and as zero
// bytes on every retry, which net/http rejects before the request leaves the
// process ("ContentLength=N with Body length 0"). That makes retries a no-op
// for every 429/5xx and — worse — replaces the real upstream error with the
// ContentLength error, so callers can no longer match it with errors.As
// against *[Error].
//
// When a body is replayed, the incoming Body is closed before a fresh copy is
// installed on a cloned request. The wrapped RoundTripper owns that fresh copy
// under the standard net/http body lifecycle.
//
// It is a no-op for bodyless requests such as the tokeninfo/userinfo GETs.
func RewindBodyMiddleware(next http.RoundTripper) http.RoundTripper {
	return retry.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.GetBody == nil {
			return next.RoundTrip(req)
		}
		if req.Body != nil {
			// go-httpretry shallow-clones the original request for every
			// attempt, so retries may close the same Body more than once.
			// Match net/http's rewind behavior and ignore Close errors.
			_ = req.Body.Close()
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		// Clone rather than mutate: RoundTrip must not modify its argument.
		req = req.Clone(req.Context())
		req.Body = body
		return next.RoundTrip(req)
	})
}

// NewDefaultHTTPClient builds the retry client this package uses when the
// caller supplies none: the go-httpretry realtime preset with logging disabled
// and [RewindBodyMiddleware] installed so retried form POSTs replay their body.
// Redirects are refused so a 307/308 cannot forward a credential-bearing form
// to another host.
//
// It is exported so every package in the SDK — and any caller assembling its
// own client — shares one transport policy instead of re-deriving it. Options
// are applied after these defaults, so a caller can intentionally replace the
// underlying *http.Client (and therefore its redirect policy) with
// [retry.WithHTTPClient].
func NewDefaultHTTPClient(opts ...retry.Option) (*retry.Client, error) {
	httpClient := *http.DefaultClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defaults := []retry.Option{
		retry.WithNoLogging(),
		retry.WithPerAttemptMiddleware(RewindBodyMiddleware),
		// Preserve any process-wide Transport, Timeout, or Jar configured on
		// http.DefaultClient at construction time while replacing its unsafe
		// redirect policy without mutating the global client.
		retry.WithHTTPClient(&httpClient),
	}
	client, err := retry.NewRealtimeClient(append(defaults, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("oauth: create http client: %w", err)
	}
	return client, nil
}

// NewClient creates a new OAuth 2.0 client.
// A default retry HTTP client is created only when no client is provided via WithHTTPClient.
func NewClient(clientID string, endpoints Endpoints, opts ...Option) (*Client, error) {
	c := &Client{
		clientID:  clientID,
		endpoints: endpoints,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	if c.httpClient == nil {
		httpClient, err := NewDefaultHTTPClient()
		if err != nil {
			return nil, err
		}
		c.httpClient = httpClient
	}

	return c, nil
}

// ClientID returns the client ID.
func (c *Client) ClientID() string {
	return c.clientID
}

// Endpoints returns the endpoint URLs.
func (c *Client) Endpoints() Endpoints {
	return c.endpoints
}

// setClientAuth attaches client-authentication parameters to a token or
// token-management request. client_id is always sent; client_secret is added
// only when one was configured via WithClientSecret (confidential clients).
// Routing every request through this single helper keeps confidential-client
// credentials from being silently dropped on an individual endpoint — the
// per-method copy-paste it replaces is exactly what left RefreshToken,
// ExchangeDeviceCode, and Revoke unauthenticated.
func (c *Client) setClientAuth(data url.Values) {
	data.Set("client_id", c.clientID)
	if c.clientSecret != "" {
		data.Set("client_secret", c.clientSecret)
	}
}

// requireEndpoint returns an invalid_request *Error when endpoint is empty.
// name is the human-readable label used in the error description (e.g.
// "device authorization").
func requireEndpoint(endpoint, name string) *Error {
	if endpoint == "" {
		return &Error{
			Code:        ErrCodeInvalidRequest,
			Description: name + " endpoint not configured",
		}
	}
	return nil
}

// RequestDeviceCode initiates a device authorization request (RFC 8628 §3.1).
func (c *Client) RequestDeviceCode(ctx context.Context, scopes []string) (*DeviceAuth, error) {
	if err := requireEndpoint(
		c.endpoints.DeviceAuthorizationURL,
		"device authorization",
	); err != nil {
		return nil, err
	}

	data := url.Values{}
	c.setClientAuth(data)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	var auth DeviceAuth
	if err := c.postForm(ctx, c.endpoints.DeviceAuthorizationURL, data, &auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

// ExchangeDeviceCode exchanges a device code for tokens (RFC 8628 §3.4).
func (c *Client) ExchangeDeviceCode(ctx context.Context, deviceCode string) (*Token, error) {
	data := url.Values{
		"grant_type":  {GrantTypeDeviceCode},
		"device_code": {deviceCode},
	}

	return c.tokenRequest(ctx, data)
}

// ExchangeAuthCode exchanges an authorization code for tokens (RFC 6749 §4.1.3).
func (c *Client) ExchangeAuthCode(
	ctx context.Context,
	code, redirectURI, codeVerifier string,
) (*Token, error) {
	data := url.Values{
		"grant_type":   {GrantTypeAuthorizationCode},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	return c.tokenRequest(ctx, data)
}

// ClientCredentials requests a token using client credentials (RFC 6749 §4.4).
func (c *Client) ClientCredentials(ctx context.Context, scopes []string) (*Token, error) {
	data := url.Values{
		"grant_type": {GrantTypeClientCredentials},
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	return c.tokenRequest(ctx, data)
}

// RefreshToken exchanges a refresh token for new tokens (RFC 6749 §6).
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	data := url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {refreshToken},
	}

	return c.tokenRequest(ctx, data)
}

// Revoke revokes a token (RFC 7009).
func (c *Client) Revoke(ctx context.Context, token string) error {
	if err := requireEndpoint(c.endpoints.RevocationURL, "revocation"); err != nil {
		return err
	}

	data := url.Values{
		"token": {token},
	}
	c.setClientAuth(data)

	resp, err := c.httpClient.Post(ctx, c.endpoints.RevocationURL,
		retry.WithBody("application/x-www-form-urlencoded", strings.NewReader(data.Encode())),
	)
	if err != nil {
		closeRetryResponse(resp)
		return fmt.Errorf("oauth: revoke request: %w", err)
	}
	defer resp.Body.Close()

	// RFC 7009 §2.2: The server responds with 200 for both success and invalid tokens.
	// However, non-200 responses (e.g., 500) indicate a server error.
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}

	return nil
}

// Introspect introspects a token (RFC 7662).
func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResult, error) {
	if err := requireEndpoint(c.endpoints.IntrospectionURL, "introspection"); err != nil {
		return nil, err
	}

	data := url.Values{
		"token": {token},
	}
	c.setClientAuth(data)

	var result IntrospectionResult
	if err := c.postForm(ctx, c.endpoints.IntrospectionURL, data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UserInfo fetches user information from the UserInfo endpoint (OIDC Core 1.0 §5.3).
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if err := requireEndpoint(c.endpoints.UserinfoURL, "userinfo"); err != nil {
		return nil, err
	}

	var info UserInfo
	if err := c.getJSON(ctx, c.endpoints.UserinfoURL, accessToken, "userinfo", &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// TokenInfoRequest fetches token information from the tokeninfo endpoint.
func (c *Client) TokenInfoRequest(ctx context.Context, accessToken string) (*TokenInfo, error) {
	if err := requireEndpoint(c.endpoints.TokenInfoURL, "tokeninfo"); err != nil {
		return nil, err
	}

	var info TokenInfo
	if err := c.getJSON(
		ctx,
		c.endpoints.TokenInfoURL,
		accessToken,
		"tokeninfo",
		&info,
	); err != nil {
		return nil, err
	}
	return &info, nil
}

// PersonalAPIKeyTokenInfoRequest verifies a complete Signet Personal API Key
// (`sgk_…`) through the tokeninfo endpoint.
//
// The request carries only `Authorization: Bearer <personalAPIKey>` — no client
// ID and no client secret — and the key never appears in the URL or query
// string. Signet collapses unknown, malformed, revoked, expired, and disabled
// keys into a uniform `401 invalid_token`, so callers cannot distinguish those
// cases from each other.
func (c *Client) PersonalAPIKeyTokenInfoRequest(
	ctx context.Context,
	personalAPIKey string,
) (*PersonalAPIKeyTokenInfo, error) {
	if err := requireEndpoint(c.endpoints.TokenInfoURL, "tokeninfo"); err != nil {
		return nil, err
	}

	var info PersonalAPIKeyTokenInfo
	if err := c.getJSON(
		ctx,
		c.endpoints.TokenInfoURL,
		personalAPIKey,
		"tokeninfo",
		&info,
	); err != nil {
		return nil, err
	}
	return &info, nil
}

// closeRetryResponse closes resp.Body when the retry client returned both a
// response and an error.
//
// go-httpretry keeps the final attempt's body open and returns
// (non-nil *http.Response, non-nil *retry.RetryError) once retries are
// exhausted. Returning early on err without this call leaks that body and its
// connection. It is a no-op on the (nil, err) transport-failure shape.
func closeRetryResponse(resp *http.Response) {
	// net/http guarantees a non-nil Body on any response a client returns.
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// getJSON sends an authenticated GET request and decodes a JSON response,
// applying the same response-size cap as postForm. op identifies the operation
// (e.g., "userinfo", "tokeninfo") for error messages and oversize reporting.
func (c *Client) getJSON(ctx context.Context, endpoint, accessToken, op string, result any) error {
	resp, err := c.httpClient.Get(ctx, endpoint,
		retry.WithHeader("Authorization", "Bearer "+accessToken),
	)
	if err != nil {
		closeRetryResponse(resp)
		return fmt.Errorf("oauth: %s request: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}

	lr := limitedBody(resp.Body)
	decodeErr := json.NewDecoder(lr).Decode(result)
	if decodeErr != nil {
		decodeErr = fmt.Errorf("oauth: decode %s response: %w", op, decodeErr)
	}
	return checkLimitExceeded(lr, op, decodeErr)
}

// tokenRequest sends a token request and parses the response.
func (c *Client) tokenRequest(ctx context.Context, data url.Values) (*Token, error) {
	if err := requireEndpoint(c.endpoints.TokenURL, "token"); err != nil {
		return nil, err
	}
	c.setClientAuth(data)

	var tok Token
	if err := c.postForm(ctx, c.endpoints.TokenURL, data, &tok); err != nil {
		return nil, err
	}

	// Compute ExpiresAt from ExpiresIn
	if tok.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}

	return &tok, nil
}

// postForm sends a POST request with form-encoded body and decodes the JSON response.
func (c *Client) postForm(ctx context.Context, endpoint string, data url.Values, result any) error {
	resp, err := c.httpClient.Post(ctx, endpoint,
		retry.WithBody("application/x-www-form-urlencoded", strings.NewReader(data.Encode())),
	)
	if err != nil {
		closeRetryResponse(resp)
		return fmt.Errorf("oauth: request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}

	lr := limitedBody(resp.Body)
	decodeErr := json.NewDecoder(lr).Decode(result)
	if decodeErr != nil {
		decodeErr = fmt.Errorf("oauth: decode response from %s: %w", endpoint, decodeErr)
	}
	return checkLimitExceeded(lr, endpoint, decodeErr)
}

// parseErrorResponse reads an OAuth error response body.
func parseErrorResponse(resp *http.Response) error {
	lr := limitedBody(resp.Body)
	body, err := io.ReadAll(lr)
	if err != nil {
		return &Error{
			Code:        ErrCodeServerError,
			Description: "failed to read error response",
			StatusCode:  resp.StatusCode,
		}
	}

	// If the read exceeded the limit (N == 0 means the extra sentinel byte
	// was consumed), return a dedicated error instead of propagating a huge
	// truncated body in the error description.
	if lr.N == 0 {
		return &Error{
			Code:        ErrCodeServerError,
			Description: "error response body exceeds size limit",
			StatusCode:  resp.StatusCode,
		}
	}

	var oauthErr Error
	if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Code != "" {
		oauthErr.StatusCode = resp.StatusCode
		return &oauthErr
	}

	// Body is not an OAuth-shaped error (no `error` field). Keep the raw body
	// in the description, but for 5xx derive ErrCodeServerError so callers can
	// still tell a server-side failure from a client/token error — otherwise a
	// bare status-text Code (e.g. "Service Unavailable") slips past the
	// middleware's transient-vs-invalid check and a valid client is told its
	// token is bad during an upstream outage.
	code := http.StatusText(resp.StatusCode)
	if resp.StatusCode >= http.StatusInternalServerError {
		code = ErrCodeServerError
	}
	return &Error{
		Code:        code,
		Description: string(body),
		StatusCode:  resp.StatusCode,
	}
}
