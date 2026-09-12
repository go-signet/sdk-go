package jwksauth

import (
	"strings"
	"testing"
	"time"
)

func TestDelegatedActorClaim(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "https://api-b.example.com")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	token := fi.Sign(t, "https://api-b.example.com", time.Minute, map[string]any{
		"client_id": "api-a",
		"scope":     "orders.read",
		"act":       map[string]any{"sub": "client:api-a"},
		"may_act":   map[string]any{"sub": "ignored-reserved-value"},
		"tenant":    "tenant-1",
	})
	info, err := v.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.Actor == nil || info.Claims.Actor.Subject != "client:api-a" {
		t.Fatalf("actor = %+v", info.Claims.Actor)
	}
	if _, ok := info.Extra("act"); ok {
		t.Error("act surfaced in Extras")
	}
	if _, ok := info.Extra("may_act"); ok {
		t.Error("may_act surfaced in Extras")
	}
	if got, ok := info.Extra("tenant"); !ok || got != "tenant-1" {
		t.Fatalf("tenant extra = %v, %v", got, ok)
	}
}

func TestDelegatedActorClaimFailsClosed(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "https://api-b.example.com")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tests := map[string]any{
		"null":          nil,
		"string":        "client:api-a",
		"missing sub":   map[string]any{},
		"blank client":  map[string]any{"sub": "client:"},
		"wrong subject": map[string]any{"sub": "user:api-a"},
		"extra member":  map[string]any{"sub": "client:api-a", "iss": "nested"},
		"nested actor": map[string]any{
			"sub": "client:api-a",
			"act": map[string]any{"sub": "client:f"},
		},
		"spaced subject": map[string]any{"sub": " client:api-a "},
	}
	for name, actor := range tests {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{"act": actor}
			token := fi.Sign(t, "https://api-b.example.com", time.Minute, claims)
			_, err := v.Verify(t.Context(), token)
			if err == nil || !strings.Contains(err.Error(), "invalid act") {
				t.Fatalf("Verify error = %v, want invalid act", err)
			}
		})
	}
}

func TestOrdinaryTokenHasNoActor(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	info, err := v.Verify(t.Context(), fi.Sign(t, "api://x", time.Minute, nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.Actor != nil {
		t.Fatalf("actor = %+v, want nil", info.Claims.Actor)
	}
}
