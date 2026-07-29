package bearerauth

import "github.com/go-signet/sdk-go/jwksauth"

const (
	// jwtTypeAccess is the only value this package accepts. Refresh tokens
	// share the issuer's signing keys and can otherwise satisfy signature,
	// iss, aud, and exp checks, so the injected verifier alone cannot tell
	// them apart.
	jwtTypeAccess = "access"
)

// identityFromJWT normalizes an already-verified token into the common
// [Identity].
//
// It reads nothing but verified material, and it treats every unexpected shape
// — a nil result from a custom verifier, a nil embedded ID token, unreadable
// claims — as an invalid credential rather than panicking or fabricating an
// empty identity.
func identityFromJWT(info *jwksauth.TokenInfo) (*Identity, error) {
	if info == nil || info.IDToken == nil {
		return nil, invalidCredential("jwt verification returned no verified token")
	}

	// The `type` claim is in jwksauth's reserved-key set, so it appears
	// neither as a named Claims field nor in Claims.Extras; read it from the
	// verified payload directly. Decoding into a one-field struct rather than a
	// map[string]any keeps this off the allocation hot path — the map form
	// re-boxes every claim in the payload on every request.
	var claims struct {
		Type string `json:"type"`
	}
	if err := info.IDToken.Claims(&claims); err != nil {
		return nil, invalidCredential("jwt payload is not readable")
	}
	if claims.Type != jwtTypeAccess {
		return nil, invalidCredential(`jwt is not an access token (claim "type" must be "access")`)
	}

	return &Identity{
		Subject:        info.Subject,
		SubjectType:    subjectTypeOf(info.Subject),
		Issuer:         info.Issuer,
		ClientAppID:    info.Claims.ClientID,
		Scopes:         canonicalScopes(info.Scopes),
		ExpiresAt:      info.Expiry,
		CredentialType: CredentialJWT,
	}, nil
}
