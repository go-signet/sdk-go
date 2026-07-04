---
name: jwksauth multi-domain refactor plan
description: Rename Tenant → Domain throughout jwksauth and add a new optional Tenant sub-claim, so the SDK matches Signet's actual hierarchy (Issuer → Domain → Tenant?).
---

# Plan: jwksauth multi-domain hierarchy

## Goal

The `jwksauth` package today exposes a single `Tenant` dimension, but the
team's mental model is two-level: a **Domain** (`oa`, `swrd`, `hwrd`) is the
big partition, and an optional **Tenant** (`a76`, `a78`) is a sub-room
inside a Domain. The current SDK's `Tenant` field is being used as if it
were Domain (the existing README example `auth-a=oa,hwrd;auth-b=swrd`
matches Domain semantics, not the team's Tenant semantics), so the names
no longer match reality.

Done means:

1. `Claims` exposes both `Domain` (renamed from current `Tenant`) and a new
   optional `Tenant` (the sub-room).
2. `AccessRule` filters on `Domains` only — Tenant filtering at the rule
   level is out of scope (Q4).
3. `MultiVerifier`'s cross-issuer pinning operates on **Domains** (renamed),
   because issuers map to one or many Domains, never down to Tenant level
   (Q3).
4. JWT shape: two independent claims, `domain` and `tenant` (Q2). When a
   Domain has no Tenant concept, the `tenant` claim is empty/omitted (Q5).
5. README and doc.go re-explain the hierarchy with the new vocabulary.
6. All existing tests pass after rename; new tests cover Domain+Tenant
   tokens and the "Tenant absent" case.

This is a **breaking API change** (Q1 chose option A, no deprecation
alias). The SDK has no v1 tag yet, so consumers update their imports in
lockstep.

## Scope

### May modify

- `jwksauth/claims.go` — rename `Tenant` → `Domain`, add `Tenant` (sub),
  rename `Tenant()` → `Domain()`, add new `Tenant()` method.
- `jwksauth/access_rule.go` — rename `Tenants` → `Domains`, update
  `canonical()` and `checkClaims()` and the doc comments.
- `jwksauth/access_rule_test.go` — rename helper `newInfo` signature,
  rename test cases, add Domain+Tenant token cases.
- `jwksauth/issuer_tenants.go` → **rename file to** `issuer_domains.go`.
  `ParseIssuerTenants` → `ParseIssuerDomains`. All error messages that
  say "tenant"/"ISSUER_TENANTS" change to "domain"/"ISSUER_DOMAINS".
- `jwksauth/issuer_tenants_test.go` → **rename to** `issuer_domains_test.go`.
  Update all assertion strings.
- `jwksauth/multi_verifier.go` — rename `SetIssuerTenants` →
  `SetIssuerDomains`, `IssuerTenants` → `IssuerDomains`, internal field
  `issuerTenants` → `issuerDomains`. The Verify-time enforcement reads
  `info.Domain()` instead of `info.Tenant()`. Update error messages
  ("issuer not permitted for this tenant" → "...for this domain").
- `jwksauth/middleware.go` — no functional change expected; spot-check
  that no doc comments or error wrappers reference the old names.
- `jwksauth/middleware_test.go` — update any test that constructs
  `Claims{Tenant: ...}` or `AccessRule{Tenants: ...}`.
- `jwksauth/doc.go` — package-level docs: update the multi-issuer
  example, replace "tenant" with "domain" where appropriate, add a
  short note explaining that the optional `Tenant` claim is a sub-room
  inside a Domain.
- `jwksauth/README.md` — re-write the "Multiple issuers" section, the
  AccessRule table, and the "Why read iss before verifying" prose so
  the vocabulary aligns with the new model. Add an example showing a
  Domain-only token vs. a Domain+Tenant token.

### Must not modify

- `jwksauth/verifier.go` — single-issuer path doesn't touch the
  hierarchy.
- `jwksauth/bearer.go`, `bearer_test.go`, `errors.go`, `errors_test.go`,
  `unverified.go`, `unverified_test.go`, `context.go` — orthogonal
  concerns (RFC 6750 wire format, header parsing, context plumbing).
- `jwksauth/options.go` — option helpers don't reference Tenant/Domain.
- `credstore/` and any other top-level package — out of scope.

If during implementation a "must not modify" file turns out to need a
trivial doc-comment fix, surface it before editing.

## Existing patterns to follow

- **Case folding**: current `Tenant()` lower-cases via `strings.ToLower`.
  Follow the same pattern for both new accessors:
  - `TokenInfo.Domain()` lower-cases `Claims.Domain`.
  - `TokenInfo.Tenant()` lower-cases `Claims.Tenant`.
  Tenant codes (`a76`, `a78`) are short and operationally entered by
  humans, so case-insensitive matching is the same trade-off that
  motivated lower-casing today.
- **Fail-closed allowlists**: `AccessRule.Domains` keeps the existing
  `trimNonEmpty(..., true)` lower-casing in `canonical()` so a stray
  empty entry can't sneak past a missing claim. Mirror the test
  `TestAccessRule_CanonicalDropsEmpty`.
- **Error message style**: `fmt.Errorf` with `%w` wrapping; client-facing
  errors stay generic to avoid probing (see existing comment at
  `multi_verifier.go:222` — "Don't echo the allowlist back").
- **Atomic config swap**: `MultiVerifier.issuerDomains` keeps the
  `atomic.Pointer[map[string][]string]` pattern unchanged; only the
  field name and method names move.
- **Test naming**: existing tests use `TestParseIssuerTenants_*` and
  `TestAccessRule_*Tenant*`; rename in lockstep so test names also
  describe the new Domain semantics.

## Constraints

- **Breaking change is allowed** (Q1: option A). No deprecation alias,
  no v1 backwards-compat shim — readers will see one consistent name.
- **No new third-party dependencies.** All renames use stdlib + the
  already-imported `coreos/go-oidc`, `golang.org/x/sync/errgroup`.
- **Must pass `make lint` and `make fmt`** (see CLAUDE.md). Watch for
  golines wrapping long error message strings; the existing file
  layout already wraps `fmt.Errorf` calls and we must preserve that.
- **`Claims` JSON tags must match the auth server's wire format.**
  - `Claims.Domain` → `json:"domain,omitempty"`.
  - `Claims.Tenant` → `json:"tenant,omitempty"`.
  Both `omitempty` so a Domain-only token (no `tenant` claim) decodes
  to an empty string, which is the documented "no sub-room" signal
  (Q5).
- **`AccessRule.Domains` semantics with missing claim**: if the
  allowlist is non-empty and the token has no `domain` claim, reject
  (existing fail-closed contract for missing claims). Same as today.
- **MultiVerifier cross-issuer enforcement** is Domain-level only.
  Tenants are not part of the pinning encoding (one issuer covers many
  Domains, but Tenants live entirely inside a Domain — there is no
  cross-issuer Tenant exposure to defend against).

## Verification

Before any commits, three end-to-end-ish tests must pass:

1. **Happy path — Domain+Tenant token round-trip.**
   Construct a `TokenInfo` with `Claims{Domain:"oa", Tenant:"a76"}`,
   pass it through `Middleware` with `AccessRule{Domains:["oa"]}` and a
   downstream handler that reads `TokenInfoFromContext`. Assert the
   handler sees `info.Claims.Domain == "oa"` and
   `info.Claims.Tenant == "a76"`, and that `info.Domain() == "oa"` /
   `info.Tenant() == "a76"`.

2. **Error case — Domain not in allowlist.**
   Token has `Claims{Domain:"swrd"}`. AccessRule has
   `Domains:["oa","hwrd"]`. Middleware returns 401 invalid_token,
   server log line records `domain="swrd" not in allowlist` (rename of
   the existing `tenant=...` log line).

3. **Edge case — Domain present, Tenant absent.**
   Token has `Claims{Domain:"oa"}` with no `tenant` claim at all.
   AccessRule `Domains:["oa"]` accepts it; handler observes
   `info.Claims.Tenant == ""` and `info.Tenant() == ""`. This pins the
   Q5 contract: missing tenant is allowed and is not the same as a
   tenant the operator forgot to allowlist (since AccessRule doesn't
   filter on tenant at all in this scope).

Plus rename-coverage tests:

4. `ParseIssuerDomains` keeps every existing rule from
   `ParseIssuerTenants` (unknown issuer, missing issuer, duplicate
   typo vs. cross-issuer overlap, malformed entry, lower-casing,
   empty disables enforcement). Rename the test functions, keep the
   coverage matrix identical.

5. `MultiVerifier.SetIssuerDomains` followed by a `Verify` call
   confirms that a token with a Domain not allowed for the issuing
   `iss` is rejected with the new error message.

### Manual verification

After code changes:

- `make fmt && make lint && make test` — all green.
- `git grep -i tenant -- 'jwksauth/*'` returns only references to the
  new `Tenant` (sub-room) field/method, never the old usage.
- `go vet ./...` clean.

## Done definition

- [ ] `Claims` has both `Domain` and `Tenant` fields with correct JSON
      tags and doc comments.
- [ ] `TokenInfo` has `Domain()` and `Tenant()` accessors, both
      case-folded.
- [ ] `AccessRule.Domains` replaces `AccessRule.Tenants` everywhere
      (struct field, `canonical()`, `checkClaims()`, doc comments).
- [ ] `MultiVerifier.SetIssuerDomains` / `IssuerDomains` /
      `ParseIssuerDomains` exist; old names deleted (no aliases).
- [ ] `issuer_tenants.go` and `issuer_tenants_test.go` renamed to
      `issuer_domains.go` / `issuer_domains_test.go` (use `git mv`).
- [ ] `doc.go` and `README.md` describe Domain + optional Tenant with
      working code examples and the AccessRule table updated.
- [ ] All five verification tests above pass; existing tests renamed
      to match.
- [ ] `make fmt && make lint && make test` clean.
- [ ] `git grep` audit confirms no stale "tenant" references remain
      where "domain" is meant.

## Risks & rollback

- **Risk: external consumers of the SDK break on update.** The module
  is `github.com/go-signet/sdk-go` and has no v1 tag in `go.mod`, so
  semver allows breaking changes. Mitigation: after merge, write a
  CHANGELOG entry that lists every renamed symbol and shows a one-line
  sed migration:
  `s/Claims\.Tenant/Claims.Domain/g; s/AccessRule\.Tenants/AccessRule.Domains/g; ...`
- **Risk: auth server still emits only `tenant` (the old Domain
  meaning).** If the server hasn't been updated to emit a separate
  `domain` claim, existing tokens decode to `Claims{Domain:""}` and
  every `AccessRule.Domains` check fails closed. Mitigation: confirm
  with the auth-server team **before merging** that the new claim
  shape is live (or land both changes in a coordinated release).
- **Risk: silent semantic drift in middleware error logs.** The log
  line `tenant=%q not in allowlist` has likely been ingested by
  alerts/dashboards. Mitigation: change to `domain=%q not in
  allowlist` deliberately and notify whoever owns those alerts.
- **Rollback**: revert the PR. The changes are all in one package; no
  database migrations, no on-disk format changes.

## Open questions (resolve during implementation if they surface)

- Does the auth server already emit `domain` and `tenant` as two
  separate claims? If only `tenant` ships today, the SDK rename has
  to land in the same release as the server-side change — surface
  this before merging.
- Are there other callers in the org that depend on
  `ParseIssuerTenants` / `SetIssuerTenants` from outside this repo?
  A quick `gh search code 'SetIssuerTenants org:<org>'` before
  cutting the rename is cheap insurance.
- Should the new `Tenant()` accessor return `""` for absent claim
  (current plan) or `(string, bool)` so callers can disambiguate
  "absent" vs. "explicit empty"? Default to `""` since the JSON tag
  `omitempty` already collapses both, and no AccessRule check
  depends on the distinction.
