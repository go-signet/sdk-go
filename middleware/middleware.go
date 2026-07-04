// Package middleware provides net/http middleware for Bearer token validation.
//
// It validates tokens using either the tokeninfo or introspection endpoint
// and injects the token information into the request context.
// Compatible with any Go HTTP framework that supports http.Handler.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-signet/sdk-go/oauth"
)

type contextKey struct{}

// clientSubjectPrefix is the prefix used by Signet to identify client (M2M) subjects.
const clientSubjectPrefix = "client:"

func newTokenNotActiveErr() *oauth.Error {
	return &oauth.Error{Code: oauth.ErrCodeInvalidToken, Description: "Token is not active"}
}

// TokenInfo holds validated token information extracted from the request.
type TokenInfo struct {
	UserID      string
	ClientID    string
	Scope       string
	SubjectType string
	ExpiresAt   int64
}

// HasScope checks whether the token has a specific scope.
func (ti *TokenInfo) HasScope(scope string) bool {
	return slices.Contains(strings.Fields(ti.Scope), scope)
}

// firstMissingScope returns the first required scope absent from the token and
// true, or ("", false) when every required scope is present. The bool (rather
// than an empty-string sentinel) keeps an empty required scope fail-closed, as
// HasScope("") would be. It splits the token scope once instead of per scope.
func (ti *TokenInfo) firstMissingScope(required []string) (string, bool) {
	if len(required) == 0 {
		return "", false
	}
	granted := strings.Fields(ti.Scope)
	for _, scope := range required {
		if !slices.Contains(granted, scope) {
			return scope, true
		}
	}
	return "", false
}

// TokenInfoFromContext extracts the validated token info from the request context.
func TokenInfoFromContext(ctx context.Context) (*TokenInfo, bool) {
	info, ok := ctx.Value(contextKey{}).(*TokenInfo)
	return info, ok
}

// HasScope is a convenience function that checks if the context's token has a scope.
func HasScope(ctx context.Context, scope string) bool {
	info, ok := TokenInfoFromContext(ctx)
	if !ok {
		return false
	}
	return info.HasScope(scope)
}

// ErrorHandler is called when authentication fails.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Option configures BearerAuth middleware.
type Option func(*config)

type validationMode int

const (
	modeTokenInfo validationMode = iota
	modeIntrospection
)

type config struct {
	client         *oauth.Client
	mode           validationMode
	requiredScopes []string
	errorHandler   ErrorHandler
}

// WithOAuthClient sets the OAuth client used for token validation.
func WithOAuthClient(client *oauth.Client) Option {
	return func(cfg *config) {
		cfg.client = client
	}
}

// WithIntrospection uses the introspection endpoint instead of tokeninfo.
func WithIntrospection() Option {
	return func(cfg *config) {
		cfg.mode = modeIntrospection
	}
}

// WithRequiredScopes sets scopes that must be present on the token.
func WithRequiredScopes(scopes ...string) Option {
	return func(cfg *config) {
		cfg.requiredScopes = scopes
	}
}

// WithErrorHandler sets a custom error handler for authentication failures.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(cfg *config) {
		cfg.errorHandler = handler
	}
}

// errorResponse is used to produce safe JSON error bodies.
type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	var oauthErr *oauth.Error
	if errors.As(err, &oauthErr) {
		switch oauthErr.Code {
		case oauth.ErrCodeServerError:
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error:       oauthErr.Code,
				Description: oauthErr.Description,
			})
			return
		case oauth.ErrCodeInsufficientScope:
			writeInsufficientScope(w, oauthErr.Description)
			return
		}

		// All other OAuth errors → 401 with WWW-Authenticate
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error:       oauthErr.Code,
			Description: oauthErr.Description,
		})
		return
	}

	// Non-OAuth errors are server-side issues
	writeJSON(w, http.StatusInternalServerError, errorResponse{
		Error:       oauth.ErrCodeServerError,
		Description: "Internal server error",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeInsufficientScope writes a 403 insufficient_scope response with the
// RFC 6750 §3 WWW-Authenticate challenge.
func writeInsufficientScope(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error:       oauth.ErrCodeInsufficientScope,
		Description: description,
	})
}

// BearerAuth returns middleware that validates Bearer tokens.
func BearerAuth(opts ...Option) func(http.Handler) http.Handler {
	cfg := &config{
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				cfg.errorHandler(
					w,
					r,
					&oauth.Error{Code: "missing_token", Description: "Bearer token required"},
				)
				return
			}

			info, err := validateToken(r.Context(), cfg, token)
			if err != nil {
				cfg.errorHandler(w, r, err)
				return
			}

			// Check required scopes. Route through the configured error handler
			// so a custom ErrorHandler still sees scope failures.
			if scope, missing := info.firstMissingScope(cfg.requiredScopes); missing {
				cfg.errorHandler(w, r, &oauth.Error{
					Code:        oauth.ErrCodeInsufficientScope,
					Description: "Token does not have required scope: " + scope,
				})
				return
			}

			ctx := context.WithValue(r.Context(), contextKey{}, info)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns middleware that checks for specific scopes.
// Must be used after BearerAuth.
func RequireScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, ok := TokenInfoFromContext(r.Context())
			if !ok {
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:       "unauthorized",
					Description: "No token info in context",
				})
				return
			}

			if scope, missing := info.firstMissingScope(scopes); missing {
				writeInsufficientScope(w, "Token does not have required scope: "+scope)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the token from the Authorization header.
// The "Bearer" scheme is matched case-insensitively per RFC 6750.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}

func validateToken(ctx context.Context, cfg *config, token string) (*TokenInfo, error) {
	if cfg.client == nil {
		return nil, &oauth.Error{
			Code:        oauth.ErrCodeServerError,
			Description: "OAuth client not configured",
		}
	}

	switch cfg.mode {
	case modeIntrospection:
		return validateViaIntrospection(ctx, cfg.client, token)
	default:
		return validateViaTokenInfo(ctx, cfg.client, token)
	}
}

func validateViaTokenInfo(
	ctx context.Context,
	client *oauth.Client,
	token string,
) (*TokenInfo, error) {
	result, err := client.TokenInfoRequest(ctx, token)
	if err != nil {
		return nil, err
	}

	if !result.Active {
		return nil, newTokenNotActiveErr()
	}

	return &TokenInfo{
		UserID:      result.UserID,
		ClientID:    result.ClientID,
		Scope:       result.Scope,
		SubjectType: result.SubjectType,
		ExpiresAt:   result.Exp,
	}, nil
}

func validateViaIntrospection(
	ctx context.Context,
	client *oauth.Client,
	token string,
) (*TokenInfo, error) {
	result, err := client.Introspect(ctx, token)
	if err != nil {
		return nil, err
	}

	if !result.Active {
		return nil, newTokenNotActiveErr()
	}

	subjectType := "user"
	if strings.HasPrefix(result.Sub, clientSubjectPrefix) {
		subjectType = "client"
	}

	return &TokenInfo{
		UserID:      result.Sub,
		ClientID:    result.ClientID,
		Scope:       result.Scope,
		SubjectType: subjectType,
		ExpiresAt:   result.Exp,
	}, nil
}
