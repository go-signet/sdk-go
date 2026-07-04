package jwksauth

import (
	"net/http"
	"strings"
)

// ExtractBearerToken returns the token from the Authorization header, or
// the empty string if the header is missing, uses an unsupported scheme,
// or is otherwise malformed.
//
// The parser splits on any whitespace so it tolerates odd Authorization
// headers in the wild (extra spaces, tabs) while still enforcing the
// two-part scheme + token shape and case-insensitive "Bearer" per
// RFC 6750 §2.1.
//
// For middleware that needs to distinguish the missing-header case from
// the supplied-but-malformed case (RFC 6750 §3 mandates different
// challenges), use [Middleware] which makes the distinction internally.
func ExtractBearerToken(r *http.Request) string {
	tok, _ := parseBearerHeader(r)
	return tok
}

// authState reports whether and how the Authorization header was supplied,
// so [Middleware] can pick the right RFC 6750 §3 response: bare Bearer
// challenge for "no credentials supplied", invalid_request (HTTP 400) for
// "credentials were supplied for the Bearer scheme but the request itself
// is malformed", and invalid_token (HTTP 401) for tokens that parse but
// fail validation.
type authState int

const (
	// authMissing — no Authorization header, an empty header, or a header
	// whose scheme is not Bearer. Per RFC 6750 §3 the challenge MUST NOT
	// include an `error` attribute in this case.
	authMissing authState = iota

	// authMalformed — the Authorization header uses the Bearer scheme but
	// the token portion is missing or shaped wrong (e.g. "Bearer", or
	// "Bearer foo bar"). Credentials WERE supplied, just unparseable, so
	// per RFC 6750 §3.1 the challenge advertises invalid_request.
	authMalformed

	// authPresent — a non-empty Bearer token was extracted.
	authPresent
)

func parseBearerHeader(r *http.Request) (string, authState) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 0 || !strings.EqualFold(parts[0], "Bearer") {
		return "", authMissing
	}
	if len(parts) != 2 || parts[1] == "" {
		return "", authMalformed
	}
	return parts[1], authPresent
}
