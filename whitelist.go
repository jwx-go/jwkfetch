package jwkfetch

import (
	"errors"
	"regexp"
)

var errDefaultWhitelistError = whitelistError{errors.New(`rejected by whitelist`)}

// Whitelist describes an interface for a URL whitelist that can be used
// to restrict URLs that jwkfetch.Client.Fetch can access.
type Whitelist interface {
	IsAllowed(string) bool
}

// WhitelistFunc is a function-based implementation of Whitelist.
type WhitelistFunc func(string) bool

func (f WhitelistFunc) IsAllowed(u string) bool {
	return f(u)
}

// InsecureWhitelist is a Whitelist implementation that allows every URL.
// It is the implicit default when a Client is constructed without a
// WithWhitelist option — the right choice for hard-coded or trusted-
// config JWKS URLs.
//
// Do NOT use InsecureWhitelist in any code path where the URL originates
// from untrusted input (for example, the `jku` header of a JWS). For
// those paths, construct a MapWhitelist, RegexpWhitelist, or custom
// Whitelist via WithWhitelist.
type InsecureWhitelist struct{}

func (InsecureWhitelist) IsAllowed(string) bool { return true }

// BlockAllWhitelist is a Whitelist that rejects every URL. Use it to
// construct a Client that explicitly refuses to fetch anything — for
// tests, safety assertions, or intentionally-disabled code paths.
type BlockAllWhitelist struct{}

func (BlockAllWhitelist) IsAllowed(string) bool { return false }

// MapWhitelist is a whitelist backed by a map of allowed URLs.
type MapWhitelist struct {
	urls map[string]struct{}
}

func NewMapWhitelist() MapWhitelist {
	return MapWhitelist{urls: make(map[string]struct{})}
}

func (wl MapWhitelist) Add(u string) MapWhitelist {
	wl.urls[u] = struct{}{}
	return wl
}

func (wl MapWhitelist) IsAllowed(u string) bool {
	_, ok := wl.urls[u]
	return ok
}

// RegexpWhitelist is a whitelist that uses regular expressions to match URLs.
type RegexpWhitelist struct {
	patterns []*regexp.Regexp
}

func NewRegexpWhitelist() *RegexpWhitelist {
	return &RegexpWhitelist{}
}

func (wl *RegexpWhitelist) Add(pat *regexp.Regexp) *RegexpWhitelist {
	wl.patterns = append(wl.patterns, pat)
	return wl
}

func (wl *RegexpWhitelist) IsAllowed(u string) bool {
	for _, pat := range wl.patterns {
		if pat.MatchString(u) {
			return true
		}
	}
	return false
}

type whitelistError struct {
	error
}

func (e whitelistError) Unwrap() error { return e.error }

func (whitelistError) Is(err error) bool {
	_, ok := err.(whitelistError)
	return ok
}

// WhitelistError returns an error sentinel that can be passed to
// errors.Is to check if an error was caused by a URL being rejected
// by a Whitelist.
func WhitelistError() error {
	return errDefaultWhitelistError
}
