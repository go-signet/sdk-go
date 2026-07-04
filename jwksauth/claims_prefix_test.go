package jwksauth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Happy path with the default prefix. Token carries
// extra_domain / extra_project / extra_service_account plus an arbitrary
// caller-supplied "tenant" key; AccessRule on all three server-attested
// dimensions hits, and the caller-supplied key surfaces via Extras.
func TestPrefixedClaims_DefaultPrefix_HappyPath(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
		"extra_domain":          "oa",
		"extra_project":         "p1",
		"extra_service_account": "sync@oa",
		"extra_uid":             "alice",
		"tenant":                "a76",
	})
	rule := AccessRule{
		Domains:         []string{"oa"},
		Projects:        []string{"p1"},
		ServiceAccounts: []string{"sync@oa"},
	}
	rec := runMiddleware(t, v, rule, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Domain() != "oa" {
		t.Errorf("Domain() = %q, want oa", info.Domain())
	}
	if info.Claims.Project != "p1" {
		t.Errorf("Project = %q, want p1", info.Claims.Project)
	}
	if info.Claims.ServiceAccount != "sync@oa" {
		t.Errorf("ServiceAccount = %q, want sync@oa", info.Claims.ServiceAccount)
	}
	if info.Claims.UID != "alice" {
		t.Errorf("UID = %q, want alice", info.Claims.UID)
	}
	got, ok := info.Extra("tenant")
	if !ok {
		t.Fatalf("Extra(\"tenant\") missing")
	}
	if s, _ := got.(string); s != "a76" {
		t.Errorf("Extra(\"tenant\") = %v, want a76", got)
	}
}

// WithPrivateClaimPrefix("acme") makes the SDK read the "acme_*"
// server-attested keys ("acme_domain", "acme_project",
// "acme_service_account", "acme_uid") only; hard cutover means a token
// signed under the default "extra_*" prefix against an "acme"-configured
// verifier yields empty server-attested fields and is rejected by
// AccessRule (no fallback to bare or default keys).
func TestPrefixedClaims_CustomPrefix(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x", WithPrivateClaimPrefix("acme"))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	t.Run("acme_prefix_hits", func(t *testing.T) {
		tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
			"acme_domain": "oa",
			"acme_uid":    "alice",
		})
		rec := runMiddleware(t, v, AccessRule{Domains: []string{"oa"}}, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+tok)
		})
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		info, err := v.Verify(context.Background(), tok)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if info.Claims.Domain != "oa" {
			t.Errorf("Claims.Domain = %q, want oa", info.Claims.Domain)
		}
		if info.Claims.UID != "alice" {
			t.Errorf("Claims.UID = %q, want alice", info.Claims.UID)
		}
	})

	t.Run("default_prefix_no_fallback", func(t *testing.T) {
		tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
			"extra_domain": "oa",
			"extra_uid":    "alice",
		})
		info, err := v.Verify(context.Background(), tok)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if info.Claims.Domain != "" {
			t.Errorf(
				"Claims.Domain = %q, want empty (wrong prefix must not fall back)",
				info.Claims.Domain,
			)
		}
		if info.Claims.UID != "" {
			t.Errorf(
				"Claims.UID = %q, want empty (wrong prefix must not fall back)",
				info.Claims.UID,
			)
		}
		got, ok := info.Extra("extra_domain")
		if !ok {
			t.Fatalf("extra_domain should land in Extras when prefix is acme")
		}
		if s, _ := got.(string); s != "oa" {
			t.Errorf("Extras[extra_domain] = %v, want \"oa\"", got)
		}
		got, ok = info.Extra("extra_uid")
		if !ok {
			t.Fatalf("extra_uid should land in Extras when prefix is acme")
		}
		if s, _ := got.(string); s != "alice" {
			t.Errorf("Extras[extra_uid] = %v, want \"alice\"", got)
		}

		rec := runMiddleware(t, v, AccessRule{Domains: []string{"oa"}}, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+tok)
		})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (Domain decoded as empty under wrong prefix)", rec.Code)
		}
	})
}

// A token carrying only the bare "domain" key (no extra_domain) must be
// rejected by an AccessRule on Domains. The bare key is not lost — it
// surfaces via Extras["domain"] — but it is not treated as server-attested.
func TestPrefixedClaims_BareDomainIgnored(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"domain": "oa"})

	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.Domain != "" {
		t.Errorf(
			"Claims.Domain = %q, want empty (bare key must not be read as server-attested)",
			info.Claims.Domain,
		)
	}
	got, ok := info.Extra("domain")
	if !ok {
		t.Fatalf("Extra(\"domain\") missing — bare key must still surface via Extras")
	}
	if s, _ := got.(string); s != "oa" {
		t.Errorf("Extras[domain] = %v, want \"oa\"", got)
	}

	rec := runMiddleware(t, v, AccessRule{Domains: []string{"oa"}}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf(
			"status = %d, want 401 (bare \"domain\" must not satisfy Domain allowlist)",
			rec.Code,
		)
	}
}

// A token carrying only the bare "uid" key (no extra_uid) must not be
// promoted to Claims.UID. The bare key is not lost — it surfaces via
// Extras["uid"] — but it is not treated as server-attested.
func TestPrefixedClaims_BareUIDIgnored(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"uid": "alice"})

	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.UID != "" {
		t.Errorf(
			"Claims.UID = %q, want empty (bare key must not be read as server-attested)",
			info.Claims.UID,
		)
	}
	got, ok := info.Extra("uid")
	if !ok {
		t.Fatalf("Extra(\"uid\") missing — bare key must still surface via Extras")
	}
	if s, _ := got.(string); s != "alice" {
		t.Errorf("Extras[uid] = %v, want \"alice\"", got)
	}
}

// Caller-supplied keys outside the server-attested registry never leak
// into the typed Claims fields, regardless of whether they collide with
// the prefix space. Both extra_foo and foo land in Extras under their
// own keys.
func TestPrefixedClaims_CallerSuppliedKeysDoNotPromote(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
		"extra_foo": "bar",
		"foo":       "baz",
	})

	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got, ok := info.Extra("foo")
	if s, isStr := got.(string); !ok || !isStr || s != "baz" {
		t.Errorf("Extra(\"foo\") = %v (%T), ok=%v; want \"baz\" (string), ok=true", got, got, ok)
	}
	got, ok = info.Extra("extra_foo")
	if s, isStr := got.(string); !ok || !isStr || s != "bar" {
		t.Errorf(
			"Extra(\"extra_foo\") = %v (%T), ok=%v; want \"bar\" (string), ok=true",
			got,
			got,
			ok,
		)
	}
	if info.Claims.Domain != "" || info.Claims.Project != "" || info.Claims.ServiceAccount != "" {
		t.Errorf(
			"server-attested fields populated by caller-supplied keys: Domain=%q Project=%q ServiceAccount=%q",
			info.Claims.Domain,
			info.Claims.Project,
			info.Claims.ServiceAccount,
		)
	}
}

// validatePrivateClaimPrefix table-driven positive and negative cases.
// The negatives mirror upstream validateJWTPrivateClaimPrefix rules:
// start with letter, [a-zA-Z0-9_]*, length 1-15, not ending in _.
func TestValidatePrivateClaimPrefix(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []string{
			"extra",
			"acme",
			"a",
			"a_b",
			"X9",
			strings.Repeat("a", 15), // exactly the upper bound
		}
		for _, p := range cases {
			t.Run(p, func(t *testing.T) {
				if err := validatePrivateClaimPrefix(p); err != nil {
					t.Errorf("validatePrivateClaimPrefix(%q) = %v, want nil", p, err)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		cases := []struct {
			name string
			in   string
		}{
			{"empty", ""},
			{"digit_first", "1abc"},
			{"hyphen", "a-b"},
			{"trailing_underscore", "abc_"},
			{"too_long", strings.Repeat("a", 16)},
			{"contains_space", "a b"},
			{"contains_chinese", "中文"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := validatePrivateClaimPrefix(tc.in); err == nil {
					t.Errorf("validatePrivateClaimPrefix(%q) = nil, want error", tc.in)
				}
			})
		}
	})
}

// NewVerifier and NewMultiVerifier propagate prefix validation as errors
// at construction time rather than panicking or silently using a bad
// prefix.
func TestNewVerifier_RejectsInvalidPrefix(t *testing.T) {
	fi := newFakeIssuer(t)

	t.Run("Verifier", func(t *testing.T) {
		_, err := NewVerifier(
			t.Context(), fi.URL(), "api://x",
			WithPrivateClaimPrefix("a-b"),
		)
		if err == nil {
			t.Fatal("expected error for invalid prefix")
		}
		if !strings.Contains(err.Error(), "private claim prefix") {
			t.Errorf("error = %v, want mention of \"private claim prefix\"", err)
		}
	})

	t.Run("MultiVerifier", func(t *testing.T) {
		_, err := NewMultiVerifier(
			t.Context(), []string{fi.URL()}, "api://x",
			WithPrivateClaimPrefix("a-b"),
		)
		if err == nil {
			t.Fatal("expected error for invalid prefix")
		}
		if !strings.Contains(err.Error(), "private claim prefix") {
			t.Errorf("error = %v, want mention of \"private claim prefix\"", err)
		}
	})
}

// WithPrivateClaimPrefix trims surrounding whitespace before validation so
// values sourced from env/config don't trip the format check, and treats
// whitespace-only input the same as empty (use default).
func TestWithPrivateClaimPrefix_TrimsWhitespace(t *testing.T) {
	fi := newFakeIssuer(t)

	t.Run("trimmed_prefix_decodes", func(t *testing.T) {
		v, err := NewVerifier(
			t.Context(), fi.URL(), "api://x",
			WithPrivateClaimPrefix("  acme  "),
		)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"acme_domain": "oa"})
		info, err := v.Verify(t.Context(), tok)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if info.Claims.Domain != "oa" {
			t.Errorf(
				"Claims.Domain = %q, want oa (trimmed prefix should resolve to acme)",
				info.Claims.Domain,
			)
		}
	})

	t.Run("whitespace_only_uses_default", func(t *testing.T) {
		v, err := NewVerifier(
			t.Context(), fi.URL(), "api://x",
			WithPrivateClaimPrefix("   "),
		)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"extra_domain": "oa"})
		info, err := v.Verify(t.Context(), tok)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if info.Claims.Domain != "oa" {
			t.Errorf(
				"Claims.Domain = %q, want oa (whitespace-only should fall back to default \"extra\")",
				info.Claims.Domain,
			)
		}
	})
}
