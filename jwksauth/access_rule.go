package jwksauth

import (
	"fmt"
	"slices"
	"strings"
)

// AccessRule is a per-route policy: the OAuth scopes the caller must hold
// plus optional allowlists for the three server-attested private claims
// (Domain, ServiceAccount, Project) that Signet emits under the
// configured prefix. Caller-supplied keys surfaced via [Claims.Extras] do
// not participate in AccessRule comparisons; if you need to filter on a
// custom dimension, read it from Extras and check it in your handler.
//
// Semantics:
//   - An empty slice means "this dimension is not checked".
//   - A populated slice is fail-closed: the token's value must appear in
//     the slice (a missing claim is treated as not-in-allowlist).
//   - Domains is matched case-insensitively. Callers may supply values in
//     any case; [Middleware] canonicalizes the rule on construction by
//     lower-casing domain allowlist entries.
//   - ServiceAccounts and Projects are matched exactly (case-sensitive).
//
// Construct rules per-route, not globally — different endpoints typically
// have different allowlists.
type AccessRule struct {
	// Scopes are the OAuth scopes that must be present. Missing scopes are
	// reported via RFC 6750 §3.1 insufficient_scope (HTTP 403) so the
	// client knows what to request next time.
	Scopes []string

	// Domains is the allowlist of domain codes (case-insensitive).
	Domains []string

	// ServiceAccounts is the allowlist of service-account identifiers
	// (case-sensitive, exact match).
	ServiceAccounts []string

	// Projects is the allowlist of project identifiers (case-sensitive,
	// exact match).
	Projects []string
}

// canonical returns a copy of the rule with allowlist values normalized
// and slices cloned so callers can safely mutate theirs after registration.
//
// Every entry is trimmed and empty results are dropped — otherwise a stray
// "" (e.g. from a trailing comma in operator config) would let a token
// whose claim is missing/empty pass the allowlist, silently breaking the
// documented fail-closed semantics for missing claims.
//
// Domains are additionally lower-cased so [AccessRule.Domains] comparisons
// are case-insensitive at the rule side.
func (r AccessRule) canonical() AccessRule {
	return AccessRule{
		Scopes:          trimNonEmpty(r.Scopes, false),
		Domains:         trimNonEmpty(r.Domains, true),
		ServiceAccounts: trimNonEmpty(r.ServiceAccounts, false),
		Projects:        trimNonEmpty(r.Projects, false),
	}
}

func trimNonEmpty(in []string, lower bool) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if lower {
			s = strings.ToLower(s)
		}
		out = append(out, s)
	}
	return out
}

// checkClaims validates the non-scope dimensions and returns a server-log
// reason on failure. Scope checks live in [Middleware] proper because
// they need to advertise the missing scope on the WWW-Authenticate header.
func (r AccessRule) checkClaims(info *TokenInfo) (reason string, ok bool) {
	if len(r.Domains) > 0 && !slices.Contains(r.Domains, info.Domain()) {
		return fmt.Sprintf("domain=%q not in allowlist", info.Claims.Domain), false
	}
	if len(r.ServiceAccounts) > 0 &&
		!slices.Contains(r.ServiceAccounts, info.Claims.ServiceAccount) {
		return fmt.Sprintf("service_account=%q not in allowlist", info.Claims.ServiceAccount), false
	}
	if len(r.Projects) > 0 && !slices.Contains(r.Projects, info.Claims.Project) {
		return fmt.Sprintf("project=%q not in allowlist", info.Claims.Project), false
	}
	return "", true
}
