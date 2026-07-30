package bearerauth

import "strings"

const (
	// personalAPIKeyPrefix is the fixed marker Signet puts on every complete
	// Personal API Key. Its presence — not the key's validity — permanently
	// classifies a bearer value, so a malformed `sgk_…` can never fall
	// through to JWT verification and be judged by the wrong rules.
	personalAPIKeyPrefix = "sgk_"

	// personalAPIKeyBodyLen is the number of unpadded-base32 characters that
	// follow the prefix.
	personalAPIKeyBodyLen = 52

	// personalAPIKeyLen is the exact byte length of a complete key.
	personalAPIKeyLen = len(personalAPIKeyPrefix) + personalAPIKeyBodyLen

	// personalAPIKeyTokenType is the `token_type` Signet reports for a
	// Personal API Key on both online endpoints.
	personalAPIKeyTokenType = "personal_api_key"
)

// isPersonalAPIKeyCandidate reports whether raw is claimed as a Personal API
// Key. This is intentionally prefix-only and does no validation: dispatch must
// be decided before, and independently of, whether the value is well-formed.
func isPersonalAPIKeyCandidate(raw string) bool {
	return strings.HasPrefix(raw, personalAPIKeyPrefix)
}

// hasPersonalAPIKeySyntax reports whether raw is exactly `sgk_` followed by 52
// lowercase unpadded-base32 characters (a–z, 2–7).
//
// This zero-I/O gate runs before any online call so display hints, truncated
// copies, upper-cased values, and values with surrounding whitespace cost the
// auth server nothing.
func hasPersonalAPIKeySyntax(raw string) bool {
	if len(raw) != personalAPIKeyLen || !strings.HasPrefix(raw, personalAPIKeyPrefix) {
		return false
	}
	for i := len(personalAPIKeyPrefix); i < len(raw); i++ {
		switch c := raw[i]; {
		case c >= 'a' && c <= 'z', c >= '2' && c <= '7':
		default:
			return false
		}
	}
	return true
}
