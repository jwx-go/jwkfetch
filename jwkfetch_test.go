package jwkfetch_test

import (
	"context"
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

func TestClientFetchDefaultDeniesEveryURL(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

	// No WithWhitelist — should deny by default.
	c := jwkfetch.NewClient(jwkfetch.WithHTTPClient(srv.Client()))

	_, err := c.Fetch(context.Background(), srv.URL)
	require.Error(t, err, `Client with no whitelist should deny every URL`)
	require.ErrorIs(t, err, jwkfetch.WhitelistError(),
		`error should be a WhitelistError`)
}

func TestClientFetchInsecureWhitelistAllows(t *testing.T) {
	srv := jwksServer(t)
	defer srv.Close()

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
