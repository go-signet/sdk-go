package bearerauth

import (
	"time"

	"github.com/go-signet/sdk-go/oauth"
)

// identityFromTokenInfo normalizes a tokeninfo verdict for a Personal API Key.
//
// Two failure categories are deliberately distinct. `active=false` is a
// statement about the credential, so it is [ErrInvalidCredential]. A response
// that claims to be active but is missing or contradicts required metadata is
// a statement about the endpoint — a wrong URL, a proxy, or a contract change —
// so it is [ErrVerifierUnavailable] and never becomes a partial Identity.
func identityFromTokenInfo(info *oauth.PersonalAPIKeyTokenInfo) (*Identity, error) {
	if info == nil {
		return nil, unavailableStatic("tokeninfo returned no result")
	}
	// The active check must stay ahead of the token_type gate: RFC 7662 §2.2
	// requires an inactive token to be reported as a bare {"active": false}
	// with no other members, so demanding token_type first would turn every
	// genuinely inactive key into ErrVerifierUnavailable.
	//
	// The cost is that a 200 response carrying unrelated JSON — an API gateway
	// answering an unknown path with {"message": "not found"} rather than a
	// 404 — also decodes to Active == false and is reported as
	// ErrInvalidCredential. Telling the caller its key is bad during a routing
	// misconfiguration is the lesser evil only because the alternative
	// mis-handles a real, expected response; distinguishing the two needs
	// `active` to be a *bool so an absent key is observable.
	if !info.Active {
		return nil, invalidCredential("personal API key is not active")
	}
	if info.TokenType != personalAPIKeyTokenType {
		return nil, unavailableStatic("tokeninfo result is not a personal API key")
	}
	// Personal API Keys are always user-owned. Any other subject_type means
	// the endpoint described something this path must not authorize.
	if info.SubjectType != string(SubjectUser) {
		return nil, unavailableStatic("tokeninfo result has an unexpected subject type")
	}
	if info.UserID == "" || info.Iss == "" || info.ClientID == "" || info.Exp == 0 {
		return nil, unavailableStatic("tokeninfo result is missing required fields")
	}

	return &Identity{
		Subject:        info.UserID,
		SubjectType:    SubjectUser,
		Issuer:         info.Iss,
		ClientAppID:    info.ClientID,
		Scopes:         canonicalScopes([]string{info.Scope}),
		ExpiresAt:      time.Unix(info.Exp, 0),
		CredentialType: CredentialPersonalAPIKey,
	}, nil
}

// identityFromIntrospection normalizes an introspection verdict for a Personal
// API Key.
//
// With Signet's default ownership gate, a client introspecting a key it does
// not own receives a metadata-stripped `{"active":true}`. That response is
// treated as incomplete and fails closed as [ErrVerifierUnavailable]; the
// configured introspection client normally has to be the policy Client App.
func identityFromIntrospection(res *oauth.IntrospectionResult) (*Identity, error) {
	if res == nil {
		return nil, unavailableStatic("introspection returned no result")
	}
	// Same ordering rationale as identityFromTokenInfo: RFC 7662 §2.2 requires
	// an inactive token to come back as a bare {"active": false}.
	if !res.Active {
		return nil, invalidCredential("personal API key is not active")
	}
	if res.TokenType != personalAPIKeyTokenType {
		return nil, unavailableStatic("introspection result is not a personal API key")
	}
	if res.Sub == "" || res.Iss == "" || res.ClientID == "" || res.Exp == 0 {
		return nil, unavailableStatic(
			"introspection result is missing required fields (is the introspection client " +
				"the owner of the key's client app?)",
		)
	}

	return &Identity{
		Subject:        res.Sub,
		SubjectType:    SubjectUser,
		Issuer:         res.Iss,
		ClientAppID:    res.ClientID,
		Scopes:         canonicalScopes([]string{res.Scope}),
		ExpiresAt:      time.Unix(res.Exp, 0),
		CredentialType: CredentialPersonalAPIKey,
	}, nil
}
