package bearerauth_test

import (
	"net/http"
	"testing"
	"time"
)

func TestJWTIdentityCarriesDelegatedActor(t *testing.T) {
	fi := newFakeIssuer(t)
	srv := newOnlineServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("JWT verification must not call the online endpoint")
	})
	v := newTokenInfoVerifier(t, fi.verifier(t), srv, defaultPolicy(fi.URL()))

	id, err := v.Verify(t.Context(), fi.sign(t, time.Minute, map[string]any{
		"act": map[string]any{"sub": "client:my-client-app"},
	}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Actor == nil || id.Actor.Subject != "client:my-client-app" {
		t.Fatalf("actor = %+v", id.Actor)
	}
}
