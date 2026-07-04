package jwksauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// TokenVerifier is the contract [Middleware] uses to validate tokens. Both
// [Verifier] (single issuer) and [MultiVerifier] satisfy it; tests and
// custom integrations can supply alternate implementations.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (*TokenInfo, error)
}

// Logger is the minimal logging surface [Middleware] needs. The interface
// mirrors [log/slog]: *slog.Logger satisfies it directly. Other structured
// loggers (logrus, zap, zerolog) can be adapted with a thin wrapper that
// translates the slog-style key/value args into the target API.
//
// args follows slog's convention: alternating string keys and values, e.g.
// logger.Warn("msg", "err", err, "sub", subject). Implementations should
// never leak args back to the HTTP client — clients only see the generic
// RFC 6750 challenge.
//
// Implementations must be safe for concurrent use: [Middleware] is invoked
// from HTTP handlers and may call Warn/Error from many goroutines at once.
// *slog.Logger is concurrency-safe out of the box; custom adapters around
// loggers that are not (e.g. some logrus configurations) must add their
// own synchronization.
type Logger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// MiddlewareOption configures [Middleware].
type MiddlewareOption interface {
	apply(*middlewareConfig)
}

type middlewareConfig struct {
	logger Logger
}

type middlewareOptionFunc func(*middlewareConfig)

func (f middlewareOptionFunc) apply(c *middlewareConfig) { f(c) }

// WithLogger sets the logger used for server-side reporting of verification
// failures and policy rejects. Defaults to [slog.Default]. Passing nil
// leaves the default in place. Failures are always logged with full detail
// server-side; clients receive the generic RFC 6750 challenge so verifier
// internals (expected issuer, audience, allowlist contents) do not leak.
func WithLogger(l Logger) MiddlewareOption {
	return middlewareOptionFunc(func(c *middlewareConfig) {
		if l != nil {
			c.logger = l
		}
	})
}

// Middleware returns an HTTP middleware that verifies the Authorization
// Bearer token and enforces rule before delegating to next.
//
// Behavior on each request:
//   - No Authorization header: 401 with bare `WWW-Authenticate: Bearer`
//     (RFC 6750 §3 — error attribute is reserved for cases where credentials
//     were supplied but rejected).
//   - Token verification fails: 401 invalid_token. Full error logged
//     server-side; client gets a generic description.
//   - Required scope missing: 403 insufficient_scope, advertising the
//     missing scope so the client can request it next time.
//   - Custom-claim allowlist mismatch: 401 invalid_token. Reason is logged
//     server-side; client sees a generic message so the allowlist itself
//     is not probeable.
//   - All checks pass: [TokenInfo] is attached to the request context; use
//     [TokenInfoFromContext] in your handler to read it.
//
// rule is canonicalized once on construction (Domains lower-cased, slices
// cloned), so callers may safely mutate their input afterwards.
func Middleware(
	v TokenVerifier,
	rule AccessRule,
	opts ...MiddlewareOption,
) func(http.Handler) http.Handler {
	cfg := middlewareConfig{logger: slog.Default()}
	for _, o := range opts {
		if o != nil {
			o.apply(&cfg)
		}
	}
	rule = rule.canonical()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, state := parseBearerHeader(r)
			switch state {
			case authMissing:
				// RFC 6750 §3: no credentials supplied (header missing or
				// non-Bearer scheme) — challenge MUST NOT include error.
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			case authMalformed:
				// Credentials were supplied for the Bearer scheme but the
				// header is unparseable — RFC 6750 §3.1 reserves
				// invalid_request (HTTP 400) for malformed requests, vs.
				// invalid_token (401) for tokens that parsed but failed
				// validation.
				WriteAuthError(w, ErrCodeInvalidRequest, "malformed Authorization header")
				return
			}
			info, err := v.Verify(r.Context(), raw)
			if err != nil {
				cfg.logger.Warn("jwksauth: token verification failed", "err", err)
				// Distinguish transient server-side failures we can reliably
				// detect (context cancellation/deadline while go-oidc is
				// fetching the JWKS or doing signature math) from real
				// token-validation failures, so retry-aware clients back off
				// instead of being pushed into a fresh authentication.
				if isTransientVerifyError(r.Context(), err) {
					WriteAuthError(w, ErrCodeServerError, "verifier unavailable")
					return
				}
				WriteAuthError(w, ErrCodeInvalidToken, "invalid token")
				return
			}
			for _, scope := range rule.Scopes {
				if !info.HasScope(scope) {
					WriteAuthError(
						w,
						ErrCodeInsufficientScope,
						"required scope: "+scope,
						scope,
					)
					return
				}
			}
			if reason, ok := rule.checkClaims(info); !ok {
				cfg.logger.Warn(
					"jwksauth: policy reject",
					"reason", reason,
					"sub", info.Subject,
					"iss", info.Issuer,
				)
				WriteAuthError(
					w,
					ErrCodeInvalidToken,
					"token not authorized for this resource",
				)
				return
			}
			next.ServeHTTP(w, r.WithContext(withTokenInfo(r.Context(), info)))
		})
	}
}

// isTransientVerifyError reports whether err looks like a server-side
// problem rather than a real token-validation failure. Per request, the
// only transient failure modes the SDK can reliably detect from go-oidc
// are context cancellation and deadline expiry while waiting on a JWKS
// refresh; token-validation failures don't wrap those.
//
// The check on the request's own context narrows the call to "the request
// is still alive" — without it, a Verify error after the client itself
// disconnected would surface as transient even though the upstream is fine.
func isTransientVerifyError(reqCtx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return reqCtx.Err() == nil
	}
	return false
}
