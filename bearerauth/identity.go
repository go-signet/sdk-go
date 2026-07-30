package bearerauth

import (
	"slices"
	"strings"
	"time"
)

// CredentialType names the kind of credential a verified [Identity] came from.
type CredentialType string

const (
	// CredentialJWT is a JWT access token verified offline against a JWKS.
	CredentialJWT CredentialType = "jwt"

	// CredentialPersonalAPIKey is a complete Signet Personal API Key
	// (`sgk_…`) verified online on this request.
	CredentialPersonalAPIKey CredentialType = "personal_api_key"
)

// SubjectType distinguishes a human subject from a machine subject.
type SubjectType string

const (
	// SubjectUser is a human end user. Personal API Keys are always
	// SubjectUser.
	SubjectUser SubjectType = "user"

	// SubjectClient is a machine subject, which Signet encodes as a
	// `client:<client_id>` JWT subject.
	SubjectClient SubjectType = "client"
)

// signetClientSubjectPrefix is the `sub` prefix Signet uses for machine
// subjects issued through the Client Credentials grant.
const signetClientSubjectPrefix = "client:"

// subjectTypeOf classifies a verified JWT subject string. Personal API Keys
// are user-owned regardless of whether their user ID happens to begin with
// Signet's machine-subject prefix.
func subjectTypeOf(subject string) SubjectType {
	if strings.HasPrefix(subject, signetClientSubjectPrefix) {
		return SubjectClient
	}
	return SubjectUser
}

// Identity is the normalized result of a successful verification. Both the
// offline JWT path and the two online Personal API Key modes produce the same
// shape, so a handler never needs to branch on how the caller authenticated.
//
// Identity deliberately carries no raw credential, no raw claim map, and no
// path-specific extras (username, JTI, audience); read only what is below.
// Values are freshly allocated per call and are safe to retain, but should be
// treated as read-only.
type Identity struct {
	// Subject is the verified subject: the JWT `sub`, the tokeninfo
	// `user_id`, or the introspection `sub`.
	Subject string

	// SubjectType is [SubjectClient] only for Signet's `client:<client_id>`
	// JWT subject form; every other credential yields [SubjectUser].
	SubjectType SubjectType

	// Issuer is the verified issuer, compared byte-for-byte against
	// [Policy.Issuer].
	Issuer string

	// ClientID is the OAuth client_id of the Signet Client App that owns the
	// credential.
	ClientID string

	// Scopes is the granted scope list, de-duplicated and lexicographically
	// sorted so semantically identical grants compare equal regardless of
	// wire order.
	Scopes []string

	// ExpiresAt is the credential expiry. It is always in the future for a
	// returned Identity.
	ExpiresAt time.Time

	// CredentialType records which path produced this Identity.
	CredentialType CredentialType
}

// HasScope reports whether the identity carries the named scope. Matching is
// exact and case-sensitive.
func (i Identity) HasScope(scope string) bool {
	return slices.Contains(i.Scopes, scope)
}

// canonicalScopes returns a freshly allocated, de-duplicated, lexicographically
// sorted copy of in, with every entry split on whitespace.
//
// Splitting matters because scopes travel space-delimited everywhere else in
// this SDK (oauth.Token.Scope, the tokeninfo/introspection `scope` field), so a
// caller naturally writes RequiredScopes: []string{"orders.read orders.write"}.
// Treating that as one opaque scope token would make it unmatchable against any
// identity and deny 100% of traffic.
//
// Cloning matters twice: at construction it stops a caller from mutating the
// policy's required scopes while Verify is running, and on the verify path it
// stops an Identity from aliasing a slice owned by the JWT verifier.
//
// De-duplication is sort-then-compact rather than a scan per entry: the granted
// scope list comes from an upstream response bounded only by oauth's 1 MB
// response cap, and an O(n^2) dedup over ~130k fields would pin a core for
// seconds on a single request.
func canonicalScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.Fields(s)...)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return slices.Clip(out)
}

// ensureUsable is the last fail-closed gate before policy evaluation. Every
// path must have produced a complete, unexpired identity; anything else is a
// bad credential, not a policy denial.
func ensureUsable(id *Identity) error {
	switch {
	case id == nil:
		return invalidCredential("verification produced no identity")
	case id.Subject == "":
		return invalidCredential("verified credential has no subject")
	case id.Issuer == "":
		return invalidCredential("verified credential has no issuer")
	case id.ClientID == "":
		return invalidCredential("verified credential has no client app")
	case id.ExpiresAt.IsZero():
		return invalidCredential("verified credential has no expiry")
	case !id.ExpiresAt.After(time.Now()):
		return invalidCredential("verified credential has expired")
	default:
		return nil
	}
}
