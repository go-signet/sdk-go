package jwksauth

import (
	"fmt"
	"slices"
	"strings"
)

// ParseIssuerDomains parses the cross-domain pinning configuration. The
// encoding is:
//
//	iss1=domainA,domainB;iss2=domainC,domainD
//
// known is the set of canonical issuers permitted as left-hand sides; pass
// [MultiVerifier.Issuers]() so a typo in the variable is caught at startup.
//
// Rules enforced:
//   - Every entry's left-hand side must appear in known.
//   - Every issuer in known must appear exactly once in raw — a silent gap
//     would let one issuer mint tokens for any domain.
//   - A domain must be owned by exactly one issuer.
//   - Same-issuer duplicates ("oa,oa") are reported as typos so the error
//     points at the actual mistake rather than a confusing cross-issuer
//     overlap message.
//
// Domain codes are lower-cased so [AccessRule] and the cross-domain
// allowlist enforcement can compare domains case-insensitively.
//
// Returns nil with no error when raw is empty — the caller can treat that
// as "cross-domain enforcement disabled".
func ParseIssuerDomains(raw string, known []string) (map[string][]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// nil map is the documented signal for "enforcement disabled" —
		// callers that want strict checking can pass a non-empty raw.
		return nil, nil //nolint:nilnil // intentional: nil map = enforcement disabled
	}
	knownSet := make(map[string]struct{}, len(known))
	for _, k := range known {
		knownSet[k] = struct{}{}
	}

	out := make(map[string][]string)
	for entry := range strings.SplitSeq(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		iss, domainsRaw, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf(
				"malformed ISSUER_DOMAINS entry %q (want iss=domainA,domainB)",
				entry,
			)
		}
		iss = strings.TrimSpace(iss)
		if _, found := knownSet[iss]; !found {
			canonical := slices.Clone(known)
			slices.Sort(canonical)
			return nil, fmt.Errorf(
				"ISSUER_DOMAINS issuer %q is not a registered issuer (known: %v)",
				iss, canonical,
			)
		}

		domains := trimNonEmpty(strings.Split(domainsRaw, ","), true)
		if len(domains) == 0 {
			return nil, fmt.Errorf("issuer %q in ISSUER_DOMAINS has no domains", iss)
		}
		if _, dup := out[iss]; dup {
			return nil, fmt.Errorf("duplicate issuer in ISSUER_DOMAINS: %s", iss)
		}
		out[iss] = domains
	}

	for _, iss := range known {
		if _, ok := out[iss]; !ok {
			return nil, fmt.Errorf(
				"issuer %q is missing from ISSUER_DOMAINS (every registered issuer must be listed when ISSUER_DOMAINS is set)",
				iss,
			)
		}
	}

	// A domain must be owned by exactly ONE issuer; otherwise the cross-
	// domain defense degrades silently. Distinguish "same domain listed
	// twice for the same issuer" (typo, e.g. "oa,oa") from a true cross-
	// issuer overlap so the error message points at the actual mistake.
	domainOwner := make(map[string]string, len(out))
	for iss, domains := range out {
		for _, d := range domains {
			if other, dup := domainOwner[d]; dup {
				if other == iss {
					return nil, fmt.Errorf(
						"domain %q listed twice for issuer %q in ISSUER_DOMAINS — drop the duplicate",
						d,
						iss,
					)
				}
				return nil, fmt.Errorf(
					"domain %q listed under multiple issuers in ISSUER_DOMAINS (%q and %q) — a domain must be owned by exactly one issuer",
					d,
					other,
					iss,
				)
			}
			domainOwner[d] = iss
		}
	}
	return out, nil
}
