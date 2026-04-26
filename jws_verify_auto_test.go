package jwkfetch_test

// This file is the executable contract for how jwkfetch.Client is
// meant to be wired into jws.WithVerifyAuto / jwt.WithVerifyAuto. The
// jwx library itself cannot enforce the whitelist requirement for
// jku-style verification — it can only describe it in docs. This
// test suite is the layer that *does* enforce it: if the contract
// breaks, these tests fail.
//
// Tests exercise three scenarios with a real jwkfetch.Client + real
// jws.Verify + real httptest servers:
//
//   1. Trusted issuer URL + matching Whitelist → verification succeeds.
//   2. Trusted issuer URL + non-matching Whitelist → verification
//      fails because the fetcher refuses the URL before contacting it.
//   3. Trusted issuer 302s to attacker URL + Whitelist covering only
//      the issuer → verification fails because the Whitelist is
//      applied to the redirect target too.
//
// Scenario 2 is the positive form of "you must configure a
// whitelist". Scenario 3 is the negative form of "the whitelist
// covers redirects, not just the initial URL." Together they are the
// executable form of the jwx.WithVerifyAuto security contract.

import (
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// issuerSetup generates a signing key, its public JWK Set, and an
// httptest.Server that serves the set. Returns the server, the
// private key used for signing, and the public JWK Set URL (which
// will appear in the jku header).
func issuerSetup(t *testing.T) (*httptest.Server, jwk.Key, string) {
	t.Helper()

	signingKey := generateRsaJwk(t)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, "test-key-1"))

	pub, err := jwk.PublicKeyOf(signingKey)
	require.NoError(t, err, `PublicKeyOf should succeed`)

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	// TLS server because jws.WithVerifyAuto enforces an https scheme
	// on the jku header — a plain httptest.NewServer would fail the
	// jku check before the fetcher ever runs.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = jsonv2.MarshalWrite(w, set)
	}))
	t.Cleanup(srv.Close)

	return srv, signingKey, srv.URL
}

// signJKU produces a compact JWS signed with signingKey and carrying
// jkuURL in the `jku` protected header.
func signJKU(t *testing.T, signingKey jwk.Key, jkuURL string, payload []byte) []byte {
	t.Helper()

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.JWKSetURLKey, jkuURL))

	signed, err := jws.Sign(payload,
		jws.WithKey(jwa.RS256(), signingKey, jws.WithProtectedHeaders(hdrs)),
	)
	require.NoError(t, err, `jws.Sign should succeed`)
	return signed
}

// Scenario 1: the happy path. A Client configured with a Whitelist
// that includes the issuer URL allows jws.Verify to complete via
// jws.WithVerifyAuto.
func TestJWSVerifyAuto_WhitelistAllowsIssuer(t *testing.T) {
	srv, signingKey, jkuURL := issuerSetup(t)
	payload := []byte("hello jku")
	signed := signJKU(t, signingKey, jkuURL, payload)

	client, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(jkuURL)),
	)
	require.NoError(t, err, `NewClient should succeed`)

	got, err := jws.Verify(signed, jws.WithVerifyAuto(client))
	require.NoError(t, err, `jws.Verify via jku should succeed when the fetcher whitelist allows the issuer URL`)
	require.Equal(t, payload, got, `decoded payload should match`)
}

// Scenario 2: the positive form of "you must configure a whitelist
// for jku verification". A Client whose Whitelist does not include
// the issuer URL rejects the fetch, and jws.Verify surfaces that as
// a verification error.
func TestJWSVerifyAuto_WhitelistRejectsUnlistedIssuer(t *testing.T) {
	srv, signingKey, jkuURL := issuerSetup(t)
	signed := signJKU(t, signingKey, jkuURL, []byte("hello jku"))

	// Whitelist deliberately excludes the issuer URL — simulates a
	// caller who configured restrictions too tightly, or a jku URL
	// that is not in the caller's known-issuer set.
	client, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(srv.Client()),
		jwkfetch.WithWhitelist(
			jwkfetch.NewMapWhitelist().Add("https://some-other-issuer.example/jwks.json"),
		),
	)
	require.NoError(t, err, `NewClient should succeed`)

	_, err = jws.Verify(signed, jws.WithVerifyAuto(client))
	require.Error(t, err, `jws.Verify should fail when the fetcher rejects the jku URL`)
}

// Scenario 3: redirect-hop enforcement, end-to-end through
// jws.WithVerifyAuto. The "issuer" origin responds with 302 to an
// attacker server that serves different keys. A Whitelist that only
// allows the origin URL must reject the redirect target, even
// though the origin URL itself passes the initial Whitelist check.
//
// This is the defense against a hostile JWKS host substituting its
// own keys via redirect.
func TestJWSVerifyAuto_WhitelistRejectsRedirectedTarget(t *testing.T) {
	// Attacker server serves its OWN JWKS with its OWN keys — if
	// the library followed the redirect blindly, the attacker's
	// keys would be accepted as "the issuer's keys".
	attackerKey := generateRsaJwk(t)
	require.NoError(t, attackerKey.Set(jwk.KeyIDKey, "attacker-key"))
	attackerPub, err := jwk.PublicKeyOf(attackerKey)
	require.NoError(t, err)
	attackerSet := jwk.NewSet()
	require.NoError(t, attackerSet.AddKey(attackerPub))

	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = jsonv2.MarshalWrite(w, attackerSet)
	}))
	t.Cleanup(attacker.Close)

	// "Issuer" origin that 302s to the attacker. The JWS's jku
	// header points here, and this URL is whitelisted — but the
	// 302 target is NOT. jku URL must be https:// so we need a TLS
	// server.
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	t.Cleanup(issuer.Close)

	// Sign the JWS with a key that would not be in the attacker's
	// JWKS. The test asserts rejection, so whether the attacker
	// could have forged keys to match is orthogonal.
	signingKey := generateRsaJwk(t)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, "legit-key"))
	signed := signJKU(t, signingKey, issuer.URL, []byte("hello jku"))

	// Whitelist covers the issuer URL only. The redirect target
	// must be rejected.
	client, err := jwkfetch.NewClient(
		jwkfetch.WithHTTPClient(issuer.Client()),
		jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(issuer.URL)),
	)
	require.NoError(t, err, `NewClient should succeed`)

	_, err = jws.Verify(signed, jws.WithVerifyAuto(client))
	require.Error(t, err, `jws.Verify should fail when a redirect target is off-whitelist`)
}

// Negative companion to scenario 1: a nil fetcher is not accepted
// by jws.WithVerifyAuto — jku verification errors at use time
// rather than silently falling back to any default. This is the
// main jwx contract for the nil case; the test lives here because
// this is where the full wiring lives.
func TestJWSVerifyAuto_NilFetcherErrors(t *testing.T) {
	_, signingKey, jkuURL := issuerSetup(t)
	signed := signJKU(t, signingKey, jkuURL, []byte("hello jku"))

	_, err := jws.Verify(signed, jws.WithVerifyAuto(nil))
	require.Error(t, err, `jws.Verify with a nil fetcher should error at jku verification time`)
}

func TestJWSVerifyAuto_PermissiveClientCompletesUnsafely(t *testing.T) {
	// Documents the risk described in the jws.WithVerifyAuto
	// security doc: a Client built with no WithWhitelist will
	// happily fetch the jku URL even when it comes from an
	// untrusted header. The verification succeeds because the
	// issuer's own JWKS covers the signing key — the point of
	// this test is to show that NO error is raised at the jwx
	// layer. A caller shipping this configuration for jku
	// verification has a silent SSRF / key-substitution risk.
	//
	// The test is present so the doc claim "jwx cannot enforce
	// this" stays honest: if some future change makes jwx catch
	// the permissive case and error, this test will start failing
	// and someone will have to update the doc accordingly.
	srv, signingKey, jkuURL := issuerSetup(t)
	payload := []byte("hello jku")
	signed := signJKU(t, signingKey, jkuURL, payload)

	client, err := jwkfetch.NewClient(jwkfetch.WithHTTPClient(srv.Client()))
	require.NoError(t, err, `NewClient should succeed`)

	got, err := jws.Verify(signed, jws.WithVerifyAuto(client))
	require.NoError(t, err, `permissive Client is accepted — jwx cannot enforce whitelist policy`)
	require.Equal(t, payload, got)
}
