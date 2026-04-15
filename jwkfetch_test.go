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
	c := jwkfetch.NewClient(jwkfetch.WithHTTPClient(srv.Client()))

	set, err := c.Fetch(context.Background(), srv.URL)
	require.NoError(t, err, `Client with no whitelist should permit every URL`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

func TestClientFetchInsecureWhitelistAllows(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	// Explicit InsecureWhitelist{} matches the default, but exercise
	// the option path too.
	c := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}),
	)

	set, err := c.Fetch(context.Background(), srv.URL)
	require.NoError(t, err, `fetch should succeed with InsecureWhitelist`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

func TestClientFetchMapWhitelistAllowsListed(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	c := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(srv.URL)),
	)

	set, err := c.Fetch(context.Background(), srv.URL)
	require.NoError(t, err, `fetch should succeed for listed URL`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
}

func TestClientFetchMapWhitelistRejectsUnlisted(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	c := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add("https://allowed.example/jwks.json")),
	)

	_, err := c.Fetch(context.Background(), srv.URL)
	require.Error(t, err, `fetch should fail for unlisted URL`)
	require.ErrorIs(t, err, jwkfetch.WhitelistError())
}

func TestClientFetchBlockAllWhitelist(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	c := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.BlockAllWhitelist{}),
	)

	_, err := c.Fetch(context.Background(), srv.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, jwkfetch.WhitelistError())
}

func TestClientFetchNonExistentHost(t *testing.T) {
	c := jwkfetch.NewClient(
		jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}),
	)
	_, err := c.Fetch(context.Background(), "http://127.0.0.1:1/jwks.json")
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
	c := jwkfetch.NewClient(
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(origin.URL)),
	)

	_, err := c.Fetch(context.Background(), origin.URL)
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

	c := jwkfetch.NewClient(
		jwkfetch.WithWhitelist(
			jwkfetch.NewMapWhitelist().Add(origin.URL).Add(target.URL),
		),
	)

	set, err := c.Fetch(context.Background(), origin.URL)
	require.NoError(t, err, `fetch should follow a redirect whose target is whitelisted`)
	require.Equal(t, 1, set.Len(), `set should have one key`)
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
