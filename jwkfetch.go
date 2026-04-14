// Package jwkfetch provides HTTP-based JWK Set retrieval for
// github.com/lestrrat-go/jwx/v4. It offers two complementary types,
// both of which implement jwk.Fetcher:
//
//   - Client: a one-shot HTTP JWKS fetcher with whitelist, body-size
//     cap, and per-fetch parse options. Use it for ad-hoc or jku-style
//     verification where the URL may be attacker-controllable.
//   - Cache: an httprc-backed store that keeps a fixed set of
//     registered JWKS URLs hot with background refresh. Use it when
//     you have a small, trusted list of JWKS endpoints and want to
//     amortize fetch cost across verifications.
//
// This package was extracted from the main jwk module so that the
// core jwx module does not depend on net/http or httprc.
package jwkfetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/option/v3"
)

// HTTPClient is the minimal HTTP client interface used by both Client
// and the httprc-backed Cache. It is a type alias for
// httprc.HTTPClient so either type accepts the same values; *http.Client
// satisfies it.
type HTTPClient = httprc.HTTPClient

// ErrorSink is the httprc error sink interface, re-exported for
// convenience when configuring an httprc.Client for use with Cache.
type ErrorSink = httprc.ErrorSink

// TraceSink is the httprc trace sink interface, re-exported for
// convenience when configuring an httprc.Client for use with Cache.
type TraceSink = httprc.TraceSink

// defaultClientMaxBodySize is the default maximum number of bytes read
// from an HTTP response body when Client.MaxBodySize is not set. The
// same default is used by Cache's internal Transformer when
// Cache.Client.MaxBodySize is zero.
const defaultClientMaxBodySize int64 = 10 * 1024 * 1024

// defaultFetchTimeout is the default timeout applied to the HTTP
// client constructed by DefaultHTTPClient. It prevents malicious or
// unresponsive JWKS endpoints from hanging indefinitely (e.g.
// slowloris-style DoS).
const defaultFetchTimeout = 30 * time.Second

// defaultMaxRedirects is the maximum number of HTTP redirects the
// default fetch client will follow. Intentionally lower than Go's
// default of 10 to limit redirect chain abuse.
const defaultMaxRedirects = 5

// Client is a one-shot JWKS fetcher. It implements jwk.Fetcher.
//
// A Client is constructed via NewClient with functional options. Its
// internal state is immutable after construction and safe to share
// across goroutines.
//
// A Client constructed with no options denies every URL — callers
// must opt into a permissive or specific whitelist via WithWhitelist.
type Client struct {
	httpClient   HTTPClient
	whitelist    Whitelist
	maxBodySize  int64
	parseOptions []jwk.ParseOption
}

// NewClient constructs a one-shot JWKS fetcher. The returned Client
// implements jwk.Fetcher.
//
// Safety: a Client constructed with no WithWhitelist option denies
// every URL (BlockAllWhitelist semantics). This is the safe default
// for attacker-controllable inputs such as `jku` headers. Callers
// with a fixed, trusted JWKS URL must opt in via
// jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{}) or a specific
// MapWhitelist/RegexpWhitelist.
func NewClient(options ...ClientOption) *Client {
	c := &Client{}
	for _, opt := range options {
		switch opt.Ident() {
		case identHTTPClient{}:
			c.httpClient = option.MustGet[HTTPClient](opt)
		case identWhitelist{}:
			c.whitelist = option.MustGet[Whitelist](opt)
		case identMaxBodySize{}:
			c.maxBodySize = option.MustGet[int64](opt)
		case identParseOptions{}:
			c.parseOptions = option.MustGet[[]jwk.ParseOption](opt)
		}
	}
	return c
}

// Fetch retrieves a JWK Set from the given URL. It implements
// jwk.Fetcher.
//
// The URL is validated against the Client's configured Whitelist
// before any network request is made. A Client constructed without
// WithWhitelist rejects every URL.
func (c *Client) Fetch(ctx context.Context, u string) (jwk.Set, error) {
	wl := c.whitelist
	if wl == nil {
		wl = BlockAllWhitelist{}
	}
	if !wl.IsAllowed(u) {
		return nil, whitelistError{fmt.Errorf(`jwkfetch.Client.Fetch: url %q has been rejected by whitelist`, u)}
	}

	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}

	maxBodySize := c.maxBodySize
	if maxBodySize <= 0 {
		maxBodySize = defaultClientMaxBodySize
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf(`jwkfetch.Client.Fetch: failed to create new request: %w`, err)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(`jwkfetch.Client.Fetch: request failed: %w`, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(`jwkfetch.Client.Fetch: request returned status %d, expected 200`, res.StatusCode)
	}

	// LimitReader caps memory at maxBodySize+1; reading +1 byte lets us detect
	// oversized responses. We intentionally skip a Content-Length pre-check because
	// the header is untrustworthy (server-controlled, absent in chunked transfers).
	// Slow-trickle attacks are mitigated by context deadlines and http.Client.Timeout.
	buf, err := io.ReadAll(io.LimitReader(res.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf(`jwkfetch.Client.Fetch: failed to read response body for %q: %w`, u, err)
	}
	if int64(len(buf)) > maxBodySize {
		return nil, fmt.Errorf(`jwkfetch.Client.Fetch: response body for %q exceeded max size of %d bytes`, u, maxBodySize)
	}

	return jwk.Parse(buf, c.parseOptions...)
}

// DefaultHTTPClient returns a new *http.Client configured with the
// defaults used by jwkfetch: a 30-second timeout, a redirect policy
// that blocks HTTPS-to-HTTP scheme downgrades, and a maximum of 5
// redirects.
//
// Useful for callers who want to start from the library's default
// protections and wrap them (e.g. adding a custom Transport).
func DefaultHTTPClient() *http.Client {
	return WrapHTTPClientDefaults(&http.Client{})
}

// WrapHTTPClientDefaults returns a shallow copy of the given
// *http.Client with the library's default safety behaviors applied.
// Existing client settings (Transport, Jar, etc.) are preserved.
//
//   - Timeout: applied only when the client has no timeout set
//     (zero value).
//   - CheckRedirect: if the client already has one, the library's
//     redirect policy runs first; if it passes, the original
//     CheckRedirect is called. If the client has no CheckRedirect,
//     the library's policy is used directly.
//
// Useful when callers need to bring their own *http.Client (e.g. for
// custom TLS configuration) but still want the library's redirect
// hardening.
func WrapHTTPClientDefaults(client *http.Client) *http.Client {
	cloned := *client
	if cloned.Timeout == 0 {
		cloned.Timeout = defaultFetchTimeout
	}
	orig := cloned.CheckRedirect
	if orig == nil {
		cloned.CheckRedirect = defaultCheckRedirect
	} else {
		cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := defaultCheckRedirect(req, via); err != nil {
				return err
			}
			return orig(req, via)
		}
	}
	return &cloned
}

// defaultCheckRedirect is the CheckRedirect policy for the default
// HTTP client. It prevents HTTPS-to-HTTP scheme downgrades and caps
// the total number of redirects.
//
// This does NOT protect against redirects to private/internal IP
// addresses. For full SSRF protection, callers should provide a custom
// http.Client via Client.HTTPClient whose Transport.DialContext
// validates destination IPs.
func defaultCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= defaultMaxRedirects {
		return fmt.Errorf(`jwkfetch: stopped after %d redirects`, defaultMaxRedirects)
	}

	// Prevent HTTPS → HTTP scheme downgrade at any hop.
	// via[len(via)-1] is the immediately previous request in the chain.
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf(`jwkfetch: redirect from HTTPS to non-HTTPS URL %q is not allowed`, req.URL.Redacted())
	}
	return nil
}
