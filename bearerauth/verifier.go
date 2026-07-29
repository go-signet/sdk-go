package bearerauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	retry "github.com/appleboy/go-httpretry"

	"github.com/go-signet/sdk-go/jwksauth"
	"github.com/go-signet/sdk-go/oauth"
)

var (
	errNilJWTVerifier   = errors.New("bearerauth: jwt verifier must not be nil")
	errClientIDEmpty    = errors.New("bearerauth: introspection clientID must not be empty")
	errClientSecretMiss = errors.New(
		"bearerauth: introspection clientSecret must not be empty",
	)
)

// mode is the construction-time choice of online Personal API Key endpoint.
// There is no runtime fallback between the two: tokeninfo needs only the
// incoming key, while introspection additionally sends confidential client
// credentials, and silently switching between them would either leak the
// secret or downgrade the request.
type mode int

const (
	modeTokenInfo mode = iota + 1
	modeIntrospection
)

func (m mode) String() string {
	if m == modeIntrospection {
		return "introspection"
	}
	return "tokeninfo"
}

// config holds the options applied at construction.
type config struct {
	httpClient *retry.Client
}

// Option configures a [Verifier] at construction time.
type Option func(*config)

// WithHTTPClient injects the go-httpretry client used for the online Personal
// API Key call, replacing the package default. A nil client is ignored.
//
// The injected client, its transport, and any logging/metrics/tracing
// callbacks must be safe for concurrent use and must not be mutated after
// construction. Callbacks must redact the Authorization header and the
// introspection form body — both carry credentials.
//
// The client MUST refuse redirects (CheckRedirect returning
// [http.ErrUseLastResponse]). This cannot be enforced here — a *retry.Client
// does not expose the *http.Client it wraps — and getting it wrong is an
// authentication bypass, not a slow path: a 307/308 forwards the Personal API
// Key or the client secret to the host the response names, and that host's
// reply becomes the verification verdict, letting it choose the subject and
// scopes this package returns.
//
// The client must also install [github.com/go-signet/sdk-go/oauth.RewindBodyMiddleware]
// if it retries, or every retried introspection POST is rejected by net/http
// before it leaves the process.
func WithHTTPClient(client *retry.Client) Option {
	return func(c *config) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// Verifier verifies either a JWT access token or a complete Signet Personal
// API Key against one shared policy.
//
// A Verifier is immutable after construction and safe for concurrent use by
// many goroutines, provided the injected JWT verifier and any injected HTTP
// client are too. The built-in *jwksauth.Verifier, *jwksauth.MultiVerifier,
// and the default retry client all are.
type Verifier struct {
	jwt         jwksauth.TokenVerifier
	oauthClient *oauth.Client
	mode        mode
	policy      canonicalPolicy
}

// NewTokenInfoVerifier builds a verifier that checks Personal API Keys through
// the Signet tokeninfo endpoint.
//
// tokeninfo is the mode to prefer when the resource server holds no
// confidential client credentials: the request carries only the incoming
// `sgk_…` as a Bearer credential. Signet collapses unknown, malformed,
// revoked, expired, and disabled keys — and its own validator failures — into
// a uniform `401 invalid_token`, so [ErrInvalidCredential] here cannot be
// distinguished from a server-side validation fault.
//
// jwt is the offline verifier used for every credential that is not a Personal
// API Key; it must be non-nil and must not be an interface holding a typed nil
// pointer. tokenInfoURL must be an absolute http(s) URL, typically obtained
// from the discovery package. See [Policy] for the issuer contract.
func NewTokenInfoVerifier(
	jwt jwksauth.TokenVerifier,
	tokenInfoURL string,
	policy Policy,
	opts ...Option,
) (*Verifier, error) {
	endpoint, canonical, httpClient, err := prepare(jwt, tokenInfoURL, "tokeninfo", policy, opts)
	if err != nil {
		return nil, err
	}

	oauthClient, err := oauth.NewClient("",
		oauth.Endpoints{TokenInfoURL: endpoint},
		oauth.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("bearerauth: build tokeninfo client: %w", err)
	}

	return &Verifier{
		jwt:         jwt,
		oauthClient: oauthClient,
		mode:        modeTokenInfo,
		policy:      canonical,
	}, nil
}

// NewIntrospectionVerifier builds a verifier that checks Personal API Keys
// through the RFC 7662 introspection endpoint using confidential client
// credentials.
//
// Both clientID and clientSecret are required; the constructor never silently
// downgrades to an unauthenticated introspection request. With Signet's
// default ownership gate, a client introspecting a key that belongs to another
// Client App receives a metadata-stripped `{"active":true}`, which this
// package fails closed as [ErrVerifierUnavailable] — so in practice the
// configured client must be the same Client App as [Policy.ClientAppID].
//
// The client secret is retained privately for future requests and never
// appears in an [Identity], an error, or a URL.
func NewIntrospectionVerifier(
	jwt jwksauth.TokenVerifier,
	introspectionURL string,
	clientID string,
	clientSecret string,
	policy Policy,
	opts ...Option,
) (*Verifier, error) {
	endpoint, canonical, httpClient, err := prepare(
		jwt,
		introspectionURL,
		"introspection",
		policy,
		opts,
	)
	if err != nil {
		return nil, err
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errClientIDEmpty
	}
	// The secret itself is never trimmed — a real secret may legitimately end
	// in whitespace — but a whitespace-only value is a misconfiguration (an
	// unset env var, a secret file holding a bare newline) that would otherwise
	// construct cleanly and then 401 on every single request, which
	// classifyOnlineError correctly refuses to blame on the caller's key. The
	// result would be a permanent 503 with no startup signal.
	if strings.TrimSpace(clientSecret) == "" {
		return nil, errClientSecretMiss
	}

	oauthClient, err := oauth.NewClient(clientID,
		oauth.Endpoints{IntrospectionURL: endpoint},
		oauth.WithClientSecret(clientSecret),
		oauth.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("bearerauth: build introspection client: %w", err)
	}

	return &Verifier{
		jwt:         jwt,
		oauthClient: oauthClient,
		mode:        modeIntrospection,
		policy:      canonical,
	}, nil
}

// prepare runs the validation both constructors share and resolves the HTTP
// client exactly once, so a built Verifier is fully immutable.
func prepare(
	jwt jwksauth.TokenVerifier,
	endpointURL, endpointName string,
	policy Policy,
	opts []Option,
) (string, canonicalPolicy, *retry.Client, error) {
	if isNilVerifier(jwt) {
		return "", canonicalPolicy{}, nil, errNilJWTVerifier
	}

	endpoint, err := validateEndpoint(endpointURL, endpointName)
	if err != nil {
		return "", canonicalPolicy{}, nil, err
	}

	canonical, err := policy.canonical()
	if err != nil {
		return "", canonicalPolicy{}, nil, err
	}

	httpClient, err := resolveHTTPClient(opts)
	if err != nil {
		return "", canonicalPolicy{}, nil, err
	}

	return endpoint, canonical, httpClient, nil
}

// resolveHTTPClient applies opts and falls back to the package default. It is
// called once per construction so the built Verifier holds a fixed client.
func resolveHTTPClient(opts []Option) (*retry.Client, error) {
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.httpClient != nil {
		return cfg.httpClient, nil
	}
	return newDefaultHTTPClient()
}

// newDefaultHTTPClient builds the shared online client: the go-httpretry
// realtime preset (two retries after the first attempt, short jittered
// exponential backoff, per-attempt timeout, retries limited to transport
// errors, 429, and 5xx) with logging disabled.
//
// Redirects are refused rather than followed. A followed 307/308 would replay
// the Bearer Personal API Key — or the introspection form carrying the client
// secret — against whatever host the response named, so every 3xx is treated
// as an endpoint misconfiguration instead.
func newDefaultHTTPClient() (*retry.Client, error) {
	client, err := oauth.NewDefaultHTTPClient(
		retry.WithHTTPClient(&http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("bearerauth: create http client: %w", err)
	}
	return client, nil
}

// isNilVerifier reports whether v is unusable. A plain `v == nil` check is not
// enough: passing a typed nil (var p *myVerifier; NewTokenInfoVerifier(p, …))
// yields a non-nil interface that panics on first use, which would turn a
// wiring mistake into a runtime crash on a live request instead of a startup
// error.
func isNilVerifier(v jwksauth.TokenVerifier) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice,
		reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

// validateEndpoint requires an absolute http(s) URL with a host.
func validateEndpoint(raw, name string) (string, error) {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return "", fmt.Errorf("bearerauth: %s URL must not be empty", name)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("bearerauth: invalid %s URL: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("bearerauth: %s URL must use http or https", name)
	}
	if u.Host == "" {
		return "", fmt.Errorf("bearerauth: %s URL must include a host", name)
	}
	return endpoint, nil
}

// Verify checks rawBearer — the credential alone, without the "Bearer "
// prefix — and returns the normalized [Identity] it authorizes.
//
// Dispatch is decided by the `sgk_` prefix and is permanent: a Personal API
// Key candidate is never retried as a JWT, and a JWT failure never triggers an
// online call. Personal API Keys are verified online on every call; no verdict,
// positive or negative, is cached.
//
// On failure the returned error matches exactly one of [ErrInvalidCredential],
// [ErrUntrustedIssuer], [ErrClientAppNotAllowed], [ErrInsufficientScope], or
// [ErrVerifierUnavailable], and no partial Identity is returned. Errors never
// contain the credential, the Authorization value, the introspection form, the
// client secret, or an unsanitized upstream error.
func (v *Verifier) Verify(ctx context.Context, rawBearer string) (*Identity, error) {
	// A Verifier that did not come from a constructor (a nil pointer, or a
	// zero-value bearerauth.Verifier embedded in a struct a constructor forgot
	// to populate) has no JWT verifier and no oauth client. Fail closed here
	// rather than nil-panicking on the first authenticated request.
	if v == nil || v.jwt == nil || v.oauthClient == nil || v.mode == 0 {
		return nil, unavailableStatic("verifier was not built by a constructor")
	}

	// Reject an empty (or whitespace-only) credential before touching either
	// verifier: it can never be valid, and forwarding it only burns an
	// upstream request or a custom verifier call.
	if strings.TrimSpace(rawBearer) == "" {
		return nil, invalidCredential("empty bearer credential")
	}

	var (
		id  *Identity
		err error
	)
	if isPersonalAPIKeyCandidate(rawBearer) {
		id, err = v.verifyPersonalAPIKey(ctx, rawBearer)
	} else {
		id, err = v.verifyJWT(ctx, rawBearer)
	}
	if err != nil {
		return nil, err
	}

	if err := ensureUsable(id); err != nil {
		return nil, err
	}
	if err := v.policy.evaluate(id); err != nil {
		return nil, err
	}
	return id, nil
}

// verifyJWT runs the offline path. The injected verifier's error is inspected
// but never wrapped: a custom implementation may echo the raw token in its
// message or expose a concrete type through errors.As.
func (v *Verifier) verifyJWT(ctx context.Context, raw string) (*Identity, error) {
	info, err := v.jwt.Verify(ctx, raw)
	if err != nil {
		// A context error whose origin is the caller's own context is a
		// cancellation; one raised while the caller's context is still alive
		// came from the verifier's internal timeout (jwksauth's
		// WithVerifyTimeout, say) and is an availability problem, not a
		// statement about the credential. Only the former may carry the
		// context sentinel out to the caller — see [unavailable].
		if isContextError(err) {
			return nil, unavailable(ctx, err, "jwt verification interrupted")
		}
		return nil, invalidCredential("jwt verification failed")
	}
	return identityFromJWT(info)
}

// verifyPersonalAPIKey runs the online path for the mode chosen at
// construction.
func (v *Verifier) verifyPersonalAPIKey(ctx context.Context, raw string) (*Identity, error) {
	if !hasPersonalAPIKeySyntax(raw) {
		return nil, invalidCredential("malformed personal API key")
	}

	if v.mode == modeIntrospection {
		res, err := v.oauthClient.Introspect(ctx, raw)
		if err != nil {
			return nil, v.classifyOnlineError(ctx, err)
		}
		return identityFromIntrospection(res)
	}

	info, err := v.oauthClient.PersonalAPIKeyTokenInfoRequest(ctx, raw)
	if err != nil {
		return nil, v.classifyOnlineError(ctx, err)
	}
	return identityFromTokenInfo(info)
}

// classifyOnlineError maps an oauth-client failure onto a stable category.
//
// Only tokeninfo's 401 is a statement about the presented key; Signet
// deliberately collapses every Personal API Key failure into it. An
// introspection 401 means *our* client credentials were rejected — a
// deployment fault, not a bad key — so it must not tell a legitimate caller
// its credential is invalid. Every other status, including a refused 3xx,
// is an endpoint problem.
func (v *Verifier) classifyOnlineError(ctx context.Context, err error) error {
	var oauthErr *oauth.Error
	if errors.As(err, &oauthErr) {
		if v.mode == modeTokenInfo && oauthErr.StatusCode == http.StatusUnauthorized {
			return invalidCredential("personal API key rejected by the tokeninfo endpoint")
		}
		// A local precondition failure (oauth.requireEndpoint) carries no HTTP
		// status; reporting "HTTP 0" would be actively misleading.
		if oauthErr.StatusCode == 0 {
			return unavailable(ctx, err, v.mode.String()+" request could not be sent")
		}
		return unavailable(ctx, err, v.mode.String()+" endpoint returned HTTP "+
			strconv.Itoa(oauthErr.StatusCode))
	}
	return unavailable(ctx, err, v.mode.String()+" request failed")
}
