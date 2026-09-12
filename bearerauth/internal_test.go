package bearerauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/jwksauth"
	"github.com/go-signet/sdk-go/oauth"
)

// stubTokenVerifier and valueTokenVerifier exercise the pointer and non-pointer
// shapes isNilVerifier has to tell apart.
type stubTokenVerifier struct{}

func (*stubTokenVerifier) Verify(context.Context, string) (*jwksauth.TokenInfo, error) {
	return nil, errNotCalled
}

type valueTokenVerifier struct{}

func (valueTokenVerifier) Verify(context.Context, string) (*jwksauth.TokenInfo, error) {
	return nil, errNotCalled
}

// errNotCalled marks a stub whose Verify is never expected to run.
var errNotCalled = errors.New("verify must not be called")

// hostileError models a dependency error that both echoes credential material
// in its message and carries a concrete type errors.As could latch onto.
type hostileError struct{ err error }

func (e hostileError) Error() string { return "upstream said: " + e.err.Error() }

func (e hostileError) Unwrap() error { return e.err }

func TestHasPersonalAPIKeySyntax(t *testing.T) {
	const body = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "valid 56 byte key", in: "sgk_" + body, want: true},
		{name: "all digits in range", in: "sgk_" + strings.Repeat("2", 52), want: true},
		{name: "wrong prefix", in: "sgt_" + body},
		{name: "no prefix", in: body},
		{name: "one char short", in: "sgk_" + body[:51]},
		{name: "one char long", in: "sgk_" + body + "a"},
		{name: "uppercase body", in: "sgk_" + strings.ToUpper(body)},
		{name: "digit outside base32 alphabet", in: "sgk_" + strings.Repeat("a", 51) + "1"},
		{name: "padding character", in: "sgk_" + strings.Repeat("a", 51) + "="},
		{name: "leading whitespace", in: " sgk_" + body[:51]},
		{name: "trailing whitespace", in: "sgk_" + body + " "},
		{name: "display hint", in: "sgk_abcd…wxyz"},
		{name: "empty", in: ""},
		{name: "prefix only", in: "sgk_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPersonalAPIKeySyntax(tt.in); got != tt.want {
				t.Errorf("hasPersonalAPIKeySyntax(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsPersonalAPIKeyCandidate(t *testing.T) {
	// Classification is by prefix alone: a malformed key must stay on the
	// Personal API Key path rather than being retried as a JWT.
	for _, in := range []string{"sgk_", "sgk_short", "sgk_" + strings.Repeat("A", 52)} {
		if !isPersonalAPIKeyCandidate(in) {
			t.Errorf("isPersonalAPIKeyCandidate(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "eyJhbGciOi.x.y", "SGK_abc", " sgk_abc"} {
		if isPersonalAPIKeyCandidate(in) {
			t.Errorf("isPersonalAPIKeyCandidate(%q) = true, want false", in)
		}
	}
}

func TestCanonicalScopes(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil"},
		{name: "blank entries only", in: []string{"", "   "}},
		{
			name: "sorted deduplicated trimmed",
			in:   []string{"write", " read ", "write", "", "admin"},
			want: []string{"admin", "read", "write"},
		},
		{
			name: "case sensitive",
			in:   []string{"Read", "read"},
			want: []string{"Read", "read"},
		},
		{
			// Scopes are space-delimited on the wire everywhere else in this
			// SDK, so a caller naturally writes them that way in
			// Policy.RequiredScopes. Treating the whole string as one opaque
			// scope token would make it unmatchable and deny every request.
			name: "splits a space-delimited entry",
			in:   []string{"orders.read orders.write"},
			want: []string{"orders.read", "orders.write"},
		},
		{
			name: "splits and de-duplicates across entries",
			in:   []string{"b  a", "\ta\nc "},
			want: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalScopes(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("canonicalScopes(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}

	t.Run("clones the input", func(t *testing.T) {
		in := []string{"read", "write"}
		got := canonicalScopes(in)
		in[0] = "admin"
		if !slices.Equal(got, []string{"read", "write"}) {
			t.Errorf("canonicalScopes aliased its input: %v", got)
		}
	})
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "https",
			in:   "https://auth.example.com/oauth/tokeninfo",
			want: "https://auth.example.com/oauth/tokeninfo",
		},
		{
			name: "http",
			in:   "http://127.0.0.1:8080/oauth/introspect",
			want: "http://127.0.0.1:8080/oauth/introspect",
		},
		{
			name: "trims surrounding space",
			in:   "  https://a.example/x  ",
			want: "https://a.example/x",
		},
		{name: "empty", in: "", wantErr: true},
		{name: "blank", in: "\t\n", wantErr: true},
		{name: "relative", in: "/oauth/tokeninfo", wantErr: true},
		{name: "no host", in: "https://", wantErr: true},
		{name: "wrong scheme", in: "ftp://example.com/x", wantErr: true},
		{name: "control character", in: "https://example.com/\x7f", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateEndpoint(tt.in, "tokeninfo")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateEndpoint(%q) = %q, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEndpoint(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("validateEndpoint(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUnavailablePreservesOnlyContextIdentity(t *testing.T) {
	hostile := hostileError{err: errors.New("upstream said: Bearer sgk_secret")}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(
		context.Background(),
		time.Now().Add(-time.Second),
	)
	defer cancelExpired()

	tests := []struct {
		name string
		// ctx is the *caller's* context. Only a sentinel that matches it may
		// survive into the returned error.
		ctx         context.Context
		cause       error
		wantContext error
	}{
		{name: "nil cause", ctx: context.Background()},
		{name: "hostile cause", ctx: context.Background(), cause: hostile},
		{
			name:        "cancelled by the caller",
			ctx:         cancelled,
			cause:       hostileError{err: context.Canceled},
			wantContext: context.Canceled,
		},
		{
			name:        "caller deadline expired",
			ctx:         expired,
			cause:       hostileError{err: context.DeadlineExceeded},
			wantContext: context.DeadlineExceeded,
		},
		{
			// An internal timeout (jwksauth's WithVerifyTimeout, go-httpretry's
			// per-attempt timeout) also yields context.DeadlineExceeded. The
			// caller is still waiting, so re-exporting the sentinel would tell
			// an adapter the client gave up when it did not.
			name:  "internal deadline while the caller is still alive",
			ctx:   context.Background(),
			cause: hostileError{err: context.DeadlineExceeded},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := unavailable(tt.ctx, tt.cause, "tokeninfo request failed")
			if !errors.Is(err, ErrVerifierUnavailable) {
				t.Fatalf("err = %v, want ErrVerifierUnavailable", err)
			}
			if strings.Contains(err.Error(), "sgk_secret") {
				t.Errorf("error leaked the cause's message: %s", err)
			}
			if _, ok := errors.AsType[hostileError](err); ok {
				t.Errorf("errors.As exposed the upstream error type through %v", err)
			}
			if tt.wantContext != nil && !errors.Is(err, tt.wantContext) {
				t.Errorf("err = %v, want it to match %v", err, tt.wantContext)
			}
			if tt.wantContext == nil && isContextError(err) {
				t.Errorf("err = %v, want no context identity", err)
			}
		})
	}
}

func TestInsufficientScopeErrorContract(t *testing.T) {
	err := error(&InsufficientScopeError{MissingScope: "admin"})

	if !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("errors.Is(err, ErrInsufficientScope) = false")
	}
	var scopeErr *InsufficientScopeError
	if !errors.As(err, &scopeErr) || scopeErr.MissingScope != "admin" {
		t.Errorf("errors.As did not recover MissingScope from %v", err)
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Errorf("Error() = %q, want it to name the missing scope", err)
	}
	// The five categories must stay mutually exclusive.
	for _, other := range []error{
		ErrInvalidCredential, ErrUntrustedIssuer,
		ErrClientAppNotAllowed, ErrVerifierUnavailable,
	} {
		if errors.Is(err, other) {
			t.Errorf("insufficient-scope error also matched %v", other)
		}
	}
}

func TestIsNilVerifier(t *testing.T) {
	var typedNil *stubTokenVerifier
	if !isNilVerifier(nil) {
		t.Error("isNilVerifier(nil) = false, want true")
	}
	if !isNilVerifier(typedNil) {
		t.Error("isNilVerifier(typed nil pointer) = false, want true")
	}
	if isNilVerifier(&stubTokenVerifier{}) {
		t.Error("isNilVerifier(usable verifier) = true, want false")
	}
	if isNilVerifier(valueTokenVerifier{}) {
		t.Error("isNilVerifier(value verifier) = true, want false")
	}
}

func TestVerifierVerifyRejectsTypedNilJWTVerifier(t *testing.T) {
	var typedNil *stubTokenVerifier
	v := &Verifier{
		jwt:         typedNil,
		oauthClient: &oauth.Client{},
		mode:        modeTokenInfo,
	}

	id, err := v.Verify(t.Context(), "not-a-jwt")
	if id != nil {
		t.Fatalf("Verify returned Identity %+v, want nil", id)
	}
	if !errors.Is(err, ErrVerifierUnavailable) {
		t.Fatalf("Verify error = %v, want ErrVerifierUnavailable", err)
	}
	if errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify error = %v, must not blame the credential", err)
	}
}

func TestPersonalAPIKeySubjectTypeAlwaysUser(t *testing.T) {
	const subject = "client:user-id-that-resembles-a-machine-subject"
	exp := time.Now().Add(time.Hour).Unix()
	tests := []struct {
		name      string
		normalize func() (*Identity, error)
	}{
		{
			name: "tokeninfo",
			normalize: func() (*Identity, error) {
				return identityFromTokenInfo(&oauth.PersonalAPIKeyTokenInfo{
					Active:      true,
					UserID:      subject,
					ClientID:    "client-app",
					Exp:         exp,
					Iss:         "https://issuer.example",
					SubjectType: string(SubjectUser),
					TokenType:   personalAPIKeyTokenType,
				})
			},
		},
		{
			name: "introspection",
			normalize: func() (*Identity, error) {
				return identityFromIntrospection(&oauth.IntrospectionResult{
					Active:    true,
					ClientID:  "client-app",
					TokenType: personalAPIKeyTokenType,
					Exp:       exp,
					Sub:       subject,
					Iss:       "https://issuer.example",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := tt.normalize()
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if id.Subject != subject {
				t.Errorf("Subject = %q, want %q", id.Subject, subject)
			}
			if id.SubjectType != SubjectUser {
				t.Errorf("SubjectType = %q, want %q", id.SubjectType, SubjectUser)
			}
		})
	}
}
