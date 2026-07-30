package bearerauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// The five stable failure categories returned by [Verifier.Verify]. Every
// non-nil verification error matches exactly one of them with [errors.Is],
// which is what lets a framework adapter map a result to an HTTP status code
// and an RFC 6750 challenge without knowing whether a JWT or a Personal API
// Key was presented.
//
// Constructor validation failures are startup/configuration errors and
// deliberately match none of these sentinels.
var (
	// ErrInvalidCredential means the credential itself was rejected: it was
	// empty or malformed, the Personal API Key was inactive or refused by
	// tokeninfo, the JWT failed verification, the JWT was not an access
	// token, or the resulting identity had already expired.
	ErrInvalidCredential = errors.New("bearerauth: invalid credential")

	// ErrUntrustedIssuer means the normalized identity issuer did not match
	// [Policy.Issuer] byte-for-byte.
	ErrUntrustedIssuer = errors.New("bearerauth: untrusted issuer")

	// ErrClientAppNotAllowed means the normalized identity's OAuth client_id
	// did not exactly match [Policy.ClientID].
	ErrClientAppNotAllowed = errors.New("bearerauth: client app not allowed")

	// ErrInsufficientScope means the credential is valid but is missing at
	// least one scope in [Policy.RequiredScopes]. Errors in this category are
	// always a *[InsufficientScopeError].
	ErrInsufficientScope = errors.New("bearerauth: insufficient scope")

	// ErrVerifierUnavailable means the verdict could not be established: a
	// transport failure, exhausted 429/5xx retries, a refused redirect,
	// rejected introspection client credentials, or a malformed, oversized,
	// or incomplete successful response from the online endpoint.
	//
	// When the caller's context was cancelled or its deadline expired, the
	// returned error additionally satisfies errors.Is against
	// [context.Canceled] or [context.DeadlineExceeded].
	ErrVerifierUnavailable = errors.New("bearerauth: verifier unavailable")
)

// InsufficientScopeError reports the first required scope the credential did
// not carry, so an adapter can advertise it in an RFC 6750 §3.1
// `WWW-Authenticate: Bearer … scope="…"` challenge.
//
// MissingScope is taken from the constructor-canonicalized (trimmed,
// de-duplicated, lexicographically sorted) required-scope list, so it is
// stable across calls and independent of the order the caller configured. It
// is caller-supplied configuration, never credential material.
type InsufficientScopeError struct {
	MissingScope string
}

// Error implements the error interface.
func (e *InsufficientScopeError) Error() string {
	return ErrInsufficientScope.Error() + ": missing scope " + strconv.Quote(e.MissingScope)
}

// Unwrap returns [ErrInsufficientScope] so both errors.Is against the sentinel
// and errors.As against *InsufficientScopeError are stable contracts.
func (e *InsufficientScopeError) Unwrap() error { return ErrInsufficientScope }

// invalidCredential wraps [ErrInvalidCredential] with static context. detail
// must never be derived from the credential, an upstream response body, or a
// dependency error string.
func invalidCredential(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidCredential, detail)
}

// unavailable wraps [ErrVerifierUnavailable] with static context, retaining
// only the *caller's* context cancellation/deadline identity.
//
// cause is inspected but never wrapped: an arbitrary transport, OAuth, or
// custom-verifier error may echo the Authorization header, the introspection
// form body, or the client secret in its message, and it may carry a concrete
// type that would leak through errors.As. Only the two context sentinels —
// which have fixed, credential-free messages — survive into the result.
//
// ctx is what makes the sentinel meaningful. Several timeouts below this layer
// also produce context.DeadlineExceeded — jwksauth's WithVerifyTimeout and
// go-httpretry's per-attempt timeout among them — and re-exporting those would
// tell an adapter "the client gave up" when the client is still waiting. The
// sentinel is therefore attached only when ctx itself is done.
//
// ctx must be non-nil; it is always the caller's context from
// [Verifier.Verify]. Call sites that have no caller context use
// [unavailableStatic] instead.
func unavailable(ctx context.Context, cause error, detail string) error {
	if err := ctx.Err(); errors.Is(cause, err) {
		switch err {
		case context.Canceled:
			return fmt.Errorf("%w: %s: %w", ErrVerifierUnavailable, detail, context.Canceled)
		case context.DeadlineExceeded:
			return fmt.Errorf(
				"%w: %s: %w",
				ErrVerifierUnavailable,
				detail,
				context.DeadlineExceeded,
			)
		}
	}
	return unavailableStatic(detail)
}

// unavailableStatic is [unavailable] for the call sites that have no caller
// context and no cause to inspect — a malformed or incomplete response from an
// online endpoint, say, where the verdict is simply unobtainable.
func unavailableStatic(detail string) error {
	return fmt.Errorf("%w: %s", ErrVerifierUnavailable, detail)
}

// isContextError reports whether err carries a caller cancellation or deadline
// identity, which must be categorized as [ErrVerifierUnavailable] rather than
// as a bad credential.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
