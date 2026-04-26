package jwkfetch

import (
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/option/v3"
)

// Option is the base type for every jwkfetch option.
type Option = option.Interface

// ClientOption is passed to NewClient. Options that configure HTTP
// fetch policy (e.g. WithHTTPClient, WithMaxBodySize, WithParseOptions)
// also satisfy ClientOption — they are shared between Client and
// Cache construction. WithWhitelist only satisfies ClientOption
// because the Cache does not enforce whitelists.
type ClientOption interface {
	Option
	clientOption()
}

type clientOption struct{ Option }

func (*clientOption) clientOption() {}

// CacheOption is passed to NewCache. Options that configure HTTP
// fetch policy satisfy CacheOption via GlobalFetchOption; per-URL
// knobs like WithWaitReady do NOT (they are RegisterOption values
// passed to Cache.Register).
type CacheOption interface {
	Option
	cacheOption()
}

// GlobalFetchOption is an option that configures HTTP fetch policy
// and applies to both Client and Cache construction. Values returned
// by WithHTTPClient, WithMaxBodySize, and WithParseOptions satisfy
// GlobalFetchOption, and therefore satisfy both ClientOption and
// CacheOption.
type GlobalFetchOption interface {
	Option
	clientOption()
	cacheOption()
}

type globalFetchOption struct{ Option }

func (*globalFetchOption) clientOption() {}
func (*globalFetchOption) cacheOption()  {}

// RegisterOption is passed per-URL to Cache.Register. It controls
// only cache-specific knobs (wait-ready, refresh interval). HTTP
// transport, body-size cap, and parse options are set once on the
// Cache itself via NewCache and apply uniformly to every URL.
type RegisterOption interface {
	Option
	registerOption()
}

type registerOption struct{ Option }

func (*registerOption) registerOption() {}

type (
	identHTTPClient     struct{}
	identMaxBodySize    struct{}
	identParseOptions   struct{}
	identWhitelist      struct{}
	identWaitReady      struct{}
	identResourceOption struct{}
)

// WithHTTPClient configures the HTTP client used for JWKS fetches.
// If not set, DefaultHTTPClient is used. Valid for both NewClient and
// NewCache.
func WithHTTPClient(c HTTPClient) GlobalFetchOption {
	return &globalFetchOption{option.New(identHTTPClient{}, c)}
}

// WithMaxBodySize configures the maximum number of bytes read from a
// JWKS HTTP response. Zero or negative means use the package default
// (10 MB). Valid for both NewClient and NewCache.
func WithMaxBodySize(n int64) GlobalFetchOption {
	return &globalFetchOption{option.New(identMaxBodySize{}, n)}
}

// WithParseOptions configures the jwk.ParseOption values passed to
// jwk.Parse when decoding a fetched JWKS. Valid for both NewClient and
// NewCache.
func WithParseOptions(opts ...jwk.ParseOption) GlobalFetchOption {
	return &globalFetchOption{option.New(identParseOptions{}, opts)}
}

// WithWhitelist configures the URL allowlist consulted by
// Client.Fetch before any network request. Only valid for NewClient —
// Cache does not enforce whitelists because registration is the trust
// boundary.
//
// Passing a nil Whitelist causes NewClient to return an error: nil is
// almost always a configuration bug, and silently treating it as
// allow-all would turn a hardened deployment into an SSRF tool. To
// configure allow-all explicitly, pass InsecureWhitelist{}; for
// deny-all, pass BlockAllWhitelist{}.
//
// Omitting WithWhitelist entirely keeps the documented default
// (allow-all, equivalent to InsecureWhitelist{}) — see NewClient.
func WithWhitelist(w Whitelist) ClientOption {
	return &clientOption{option.New(identWhitelist{}, w)}
}

// WithWaitReady specifies whether Register should wait until the
// first fetch completes. Default is true.
func WithWaitReady(v bool) RegisterOption {
	return &registerOption{option.New(identWaitReady{}, v)}
}

// WithConstantInterval sets a constant refresh interval for a
// registered URL.
func WithConstantInterval(d time.Duration) RegisterOption {
	return &registerOption{option.New(identResourceOption{}, httprc.WithConstantInterval(d))}
}

// WithMinInterval sets the minimum refresh interval for a registered
// URL.
func WithMinInterval(d time.Duration) RegisterOption {
	return &registerOption{option.New(identResourceOption{}, httprc.WithMinInterval(d))}
}

// WithMaxInterval sets the maximum refresh interval for a registered
// URL.
func WithMaxInterval(d time.Duration) RegisterOption {
	return &registerOption{option.New(identResourceOption{}, httprc.WithMaxInterval(d))}
}
