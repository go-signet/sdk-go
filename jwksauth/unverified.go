package jwksauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrMalformedJWT indicates the Authorization header value cannot be parsed
// as a JWT — wrong number of segments, undecodable base64 payload, invalid
// JSON, or missing `iss` claim. Every error path in [UnverifiedIssuer]
// wraps this sentinel so callers can detect "not a JWT" with a single
// errors.Is check.
var ErrMalformedJWT = errors.New("malformed JWT")

// Bounds applied on this unverified parse path so a maliciously crafted
// Authorization header cannot force unbounded work or allocations before
// the chosen verifier rejects the token. Real access tokens are typically
// well under 2 KiB; these caps leave generous headroom.
const (
	maxRawJWTSize     = 8 << 10 // 8 KiB total token length
	maxJWTPayloadSize = 6 << 10 // 6 KiB encoded middle segment (checked before base64 decode)
)

// UnverifiedIssuer extracts the `iss` claim from a JWT payload WITHOUT
// validating the signature. The returned value MUST only be used to choose
// which verifier to dispatch to; it must never drive trust decisions on its
// own. The chosen verifier subsequently re-checks `iss` together with the
// signature.
//
// To bound work on this unverified parse path, the parser rejects:
//   - inputs over [maxRawJWTSize] bytes,
//   - any input that does not have exactly three dot-separated segments,
//   - encoded payload segments over [maxJWTPayloadSize] bytes (checked
//     before base64 decode, so we never allocate the decoded form for
//     payloads that would have been rejected anyway).
//
// All errors wrap [ErrMalformedJWT] and are detectable with errors.Is.
func UnverifiedIssuer(raw string) (string, error) {
	if len(raw) > maxRawJWTSize {
		return "", fmt.Errorf("%w: token too large", ErrMalformedJWT)
	}
	// Cap=4 so a 4+ segment token fails the len==3 check below before any
	// base64 work happens.
	parts := strings.SplitN(raw, ".", 4)
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: wrong number of segments", ErrMalformedJWT)
	}
	if len(parts[1]) > maxJWTPayloadSize {
		return "", fmt.Errorf("%w: payload too large", ErrMalformedJWT)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: decode payload: %w", ErrMalformedJWT, err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("%w: parse payload: %w", ErrMalformedJWT, err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("%w: missing iss claim", ErrMalformedJWT)
	}
	return c.Iss, nil
}
