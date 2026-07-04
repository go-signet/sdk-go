package jwksauth

import "context"

// ctxKey is the unexported context key used to carry [TokenInfo] through the
// request lifecycle. Using an unexported zero-size struct guarantees no
// collision with other context users.
type ctxKey struct{}

// withTokenInfo returns a derived context that carries the verified
// TokenInfo. Used by the middleware after a successful Verify; tests and
// custom handlers should normally retrieve it via [TokenInfoFromContext].
func withTokenInfo(ctx context.Context, info *TokenInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

// TokenInfoFromContext retrieves the [TokenInfo] stored on the request
// context by [Middleware]. It returns ok=false if the middleware was not
// applied (or applied at the wrong layer); handlers should treat that as a
// server-side misconfiguration and respond 500, since the auth chain is
// supposed to make this never happen for client-side reasons.
func TokenInfoFromContext(ctx context.Context) (info *TokenInfo, ok bool) {
	info, ok = ctx.Value(ctxKey{}).(*TokenInfo)
	return info, ok
}
