package jwkfetch_test

import (
	"context"
	"crypto/tls"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func jwksServer(t *testing.T) *httptest.Server {
	t.Helper()
	key := generateRsaJwk(t)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = jsonv2.MarshalWrite(w, set)
	}))
}

func TestClientFetchDefaultAllowsAllURLs(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	// No WithWhitelist — should permit by default (v3-compatible).
	c, err := jwkfetch.NewClient(jwkfetch.WithHTTPClient(srv.Client()))
	require.NoError(t, err, `NewClient should succeed`)

	set, err := c.Fetch(context.Background(), srv.URL)
	require.NoError(t, err, `Client with no whitelist should permit every URL`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

func TestClientFetchInsecureWhitelistAllows(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	// Explicit InsecureWhitelist{} matches the default, but exercise
	// the option path too.
	c, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}),
	)
	require.NoError(t, err, `NewClient should succeed`)

	set, err := c.Fetch(context.Background(), srv.URL)
	require.NoError(t, err, `fetch should succeed with InsecureWhitelist`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

func TestClientFetchMapWhitelistAllowsListed(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	c, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(srv.URL)),
	)
	require.NoError(t, err, `NewClient should succeed`)

	set, err := c.Fetch(context.Background(), srv.URL)
	require.NoError(t, err, `fetch should succeed for listed URL`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

func TestClientFetchMapWhitelistRejectsUnlisted(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	c, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add("https://allowed.example/jwks.json")),
	)
	require.NoError(t, err, `NewClient should succeed`)

	_, err = c.Fetch(context.Background(), srv.URL)
	require.Error(t, err, `fetch should fail for unlisted URL`)
	require.ErrorIs(t, err, jwkfetch.WhitelistError())
}

func TestClientFetchBlockAllWhitelist(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	c, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.BlockAllWhitelist{}),
	)
	require.NoError(t, err, `NewClient should succeed`)

	_, err = c.Fetch(context.Background(), srv.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, jwkfetch.WhitelistError())
}

func TestClientFetchNonExistentHost(t *testing.T) {
	c, err := jwkfetch.NewClient(
		jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}),
	)
	require.NoError(t, err, `NewClient should succeed`)
	_, err = c.Fetch(context.Background(), "http://127.0.0.1:1/jwks.json")
	require.Error(t, err)
	// Should NOT be a whitelist error — it's a transport failure.
	require.False(t, errors.Is(err, jwkfetch.WhitelistError()))
}

// A hostile JWKS host must not be able to redirect the Client into a
// URL that falls outside the caller's Whitelist. The Whitelist is
// applied to every redirect target, not just the initial URL.
func TestClientFetchRedirectRejectedByWhitelist(t *testing.T) {
	// Attacker-controlled target, carrying a completely different
	// JWKS. If the Client follows the redirect and parses this body,
	// the attacker has substituted their own keys.
	attacker := jwksServer(t)
	defer attacker.Close()

	// Origin that pretends to be the trusted JWKS URL but 302s to
	// the attacker's server.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	defer origin.Close()

	// Whitelist only the origin URL — the redirect target should be
	// blocked, even though the Client got the origin URL past the
	// initial whitelist check.
	c, err := jwkfetch.NewClient(
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(origin.URL)),
	)
	require.NoError(t, err, `NewClient should succeed`)

	_, err = c.Fetch(context.Background(), origin.URL)
	require.Error(t, err, `fetch should reject an off-whitelist redirect target`)
	require.ErrorIs(t, err, jwkfetch.WhitelistError(),
		`redirect rejection should surface as WhitelistError`)
}

// Counterpart to the above: when the whitelist covers both the
// origin and the redirect target, following the redirect should
// succeed.
func TestClientFetchRedirectPermittedWhenWhitelisted(t *testing.T) {
	target := jwksServer(t)
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	c, err := jwkfetch.NewClient(
		jwkfetch.WithWhitelist(
			jwkfetch.NewMapWhitelist().Add(origin.URL).Add(target.URL),
		),
	)
	require.NoError(t, err, `NewClient should succeed`)

	set, err := c.Fetch(context.Background(), origin.URL)
	require.NoError(t, err, `fetch should follow a redirect whose target is whitelisted`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

// HTTP status failures must surface as jwkfetch.HTTPStatusError so
// callers can branch retry/alert policy on the observed status code
// without string-matching the error message.
func TestClientFetchHTTPStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := jwkfetch.NewClient(jwkfetch.WithHTTPClient(srv.Client()))
	require.NoError(t, err, `NewClient should succeed`)
	_, err = c.Fetch(context.Background(), srv.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, jwkfetch.HTTPStatusError{})

	var statusErr jwkfetch.HTTPStatusError
	require.True(t, errors.As(err, &statusErr), `errors.As should extract HTTPStatusError`)
	require.Equal(t, http.StatusNotFound, statusErr.StatusCode)
	require.Equal(t, srv.URL, statusErr.URL)
}

// Body-size cap enforcement must surface as jwkfetch.BodyTooLargeError
// so callers can distinguish "JWKS is absurdly big" from transient
// network errors.
func TestClientFetchBodyTooLargeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a body larger than the configured cap below.
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	const limit int64 = 128
	c, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithMaxBodySize(limit),
	)
	require.NoError(t, err, `NewClient should succeed`)
	_, err = c.Fetch(context.Background(), srv.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, jwkfetch.BodyTooLargeError{})

	var sizeErr jwkfetch.BodyTooLargeError
	require.True(t, errors.As(err, &sizeErr), `errors.As should extract BodyTooLargeError`)
	require.Equal(t, limit, sizeErr.Limit)
	require.Equal(t, srv.URL, sizeErr.URL)
}

// http.Client.Do failures (unreachable host, closed listener, etc.)
// must surface as jwkfetch.TransportError with the underlying error
// still reachable via Unwrap so callers can match on net.Error and
// friends.
func TestClientFetchTransportError(t *testing.T) {
	// 127.0.0.1:1 is reserved; connection must fail.
	const target = "http://127.0.0.1:1/jwks.json"
	c, err := jwkfetch.NewClient(jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}))
	require.NoError(t, err, `NewClient should succeed`)
	_, err = c.Fetch(context.Background(), target)
	require.Error(t, err)
	require.ErrorIs(t, err, jwkfetch.TransportError{})

	var tErr jwkfetch.TransportError
	require.True(t, errors.As(err, &tErr), `errors.As should extract TransportError`)
	require.Equal(t, target, tErr.URL)
	require.NotNil(t, tErr.Err, `Unwrap target must be populated`)
	require.False(t, errors.Is(err, jwkfetch.WhitelistError()),
		`transport failure must not look like a whitelist rejection`)
}

// Malformed JSON bodies must surface as jwkfetch.ParseError, while the
// underlying jwk parse error remains reachable via Unwrap so callers
// that already match on jwk.ParseError() continue to work.
func TestClientFetchParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c, err := jwkfetch.NewClient(jwkfetch.WithHTTPClient(srv.Client()))
	require.NoError(t, err, `NewClient should succeed`)
	_, err = c.Fetch(context.Background(), srv.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, jwkfetch.ParseError{})

	var pErr jwkfetch.ParseError
	require.True(t, errors.As(err, &pErr), `errors.As should extract ParseError`)
	require.Equal(t, srv.URL, pErr.URL)
	require.NotNil(t, pErr.Err, `Unwrap target must be populated`)
}

// DefaultHTTPClient must install a dedicated *http.Transport — not
// rely on the process-global http.DefaultTransport — so the JWKS
// fetcher does not inherit HTTP_PROXY / HTTPS_PROXY env vars (SSRF
// pivot) and pins an explicit TLS floor. Each call must also return
// a fresh transport so different fetchers do not share connection
// pools or TLS session state.
func TestDefaultHTTPClientDedicatedTransport(t *testing.T) {
	client := jwkfetch.DefaultHTTPClient()
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, `DefaultHTTPClient Transport must be a *http.Transport`)
	require.NotSame(t, http.DefaultTransport, client.Transport,
		`DefaultHTTPClient transport must not be http.DefaultTransport`)
	require.Nil(t, tr.Proxy,
		`DefaultHTTPClient transport must not inherit HTTP_PROXY / HTTPS_PROXY`)
	require.NotNil(t, tr.TLSClientConfig,
		`DefaultHTTPClient transport must set TLSClientConfig explicitly`)
	require.GreaterOrEqual(t, int(tr.TLSClientConfig.MinVersion), int(tls.VersionTLS12),
		`DefaultHTTPClient transport must pin TLS 1.2 or higher`)

	other := jwkfetch.DefaultHTTPClient()
	require.NotSame(t, client.Transport, other.Transport,
		`DefaultHTTPClient must return a fresh transport per call`)
}

// WithWhitelist(nil) is almost always a configuration bug — silently
// treating it as allow-all would turn a hardened deployment into an
// SSRF tool. NewClient must reject it loudly. Callers that want
// allow-all explicitly should pass InsecureWhitelist{}.
func TestNewClientRejectsNilWhitelist(t *testing.T) {
	t.Run("explicit nil", func(t *testing.T) {
		c, err := jwkfetch.NewClient(jwkfetch.WithWhitelist(nil))
		require.Error(t, err, `NewClient must reject WithWhitelist(nil)`)
		require.Nil(t, c, `NewClient must not return a partially-constructed Client`)
		require.Contains(t, err.Error(), "WithWhitelist requires a non-nil Whitelist",
			`error message should name the option`)
	})

	t.Run("nil typed Whitelist via interface", func(t *testing.T) {
		var w jwkfetch.Whitelist
		c, err := jwkfetch.NewClient(jwkfetch.WithWhitelist(w))
		require.Error(t, err, `NewClient must reject a nil Whitelist interface value`)
		require.Nil(t, c)
	})

	t.Run("explicit InsecureWhitelist still works", func(t *testing.T) {
		c, err := jwkfetch.NewClient(jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}))
		require.NoError(t, err, `WithWhitelist(InsecureWhitelist{}) is the supported allow-all opt-in`)
		require.NotNil(t, c)
	})

	t.Run("no WithWhitelist still defaults to allow-all", func(t *testing.T) {
		c, err := jwkfetch.NewClient()
		require.NoError(t, err, `NewClient with no options keeps the documented allow-all default`)
		require.NotNil(t, c)
	})
}
