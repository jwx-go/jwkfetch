# JWK Fetch Extension for JWX

## Overview

This module (`github.com/jwx-go/jwkfetch/v4`) provides HTTP-based JWK Set
retrieval for `github.com/lestrrat-go/jwx/v4`. It offers two
complementary types, both of which implement `jwk.Fetcher`:

- **`Client`** — a one-shot HTTP JWKS fetcher. Use it for ad-hoc
  retrievals and `jku`-style JWS verification where the URL may be
  attacker-controllable (whitelist defaults to deny-all).
- **`Cache`** — an httprc-backed store that keeps a fixed set of
  registered JWKS URLs hot with background refresh. Use it when you
  have a small, trusted list of JWKS endpoints and want to amortize
  fetch cost.

This package was extracted from the main `jwk` module so the core jwx
module has no dependency on `net/http` or `httprc`. All HTTP fetch
surface that used to live in `jwk` (`jwk.Fetch`, `jwk.HTTPClient`,
`jwk.Whitelist`, etc.) was moved here.

## Architecture

Both `Client` and `Cache` are **closed structs** — all fields are
unexported, and construction is via functional options. Configuration
that is meaningful to both types is exposed as `GlobalFetchOption`
values (`WithHTTPClient`, `WithMaxBodySize`, `WithParseOptions`) that
satisfy both `ClientOption` and `CacheOption`. `WithWhitelist` is a
`ClientOption` only — `Cache` treats `Register` as the trust boundary
and does not enforce a whitelist, so passing `WithWhitelist` to
`NewCache` is a compile-time error.

`Cache` wraps an `httprc.Controller` and delegates background refresh
to httprc. An internal `transformer` converts each HTTP response to a
`jwk.Set` using the cache's configured body-size cap and parse
options.

### Key types

| Type | Purpose |
|------|---------|
| `Client` | One-shot HTTP JWKS fetcher; implements `jwk.Fetcher` |
| `Cache` | Background-refreshed JWKS store; implements `jwk.Fetcher` |
| `CachedSet` / `NewCachedSet` | Read-only `jwk.Set` view backed by an httprc resource (used internally by `Cache.CachedSet`) |
| `Whitelist`, `InsecureWhitelist`, `BlockAllWhitelist`, `MapWhitelist`, `RegexpWhitelist`, `WhitelistFunc` | URL allowlist policies consulted by `Client.Fetch` |
| `HTTPClient` | Type alias for `httprc.HTTPClient`; `*http.Client` satisfies it |
| `DefaultHTTPClient`, `WrapHTTPClientDefaults` | Helpers for building `*http.Client` values with the library's 30s timeout and redirect hardening |
| `WhitelistError` | Error sentinel returned by `Client.Fetch` when a URL is rejected by the whitelist |

### Option interfaces

| Interface | Where it's accepted | What it configures |
|-----------|--------------------|--------------------|
| `ClientOption` | `NewClient` | Client-specific or shared fetch policy |
| `CacheOption` | `NewCache` | Cache-specific or shared fetch policy |
| `GlobalFetchOption` | both `NewClient` and `NewCache` | Shared HTTP/parse policy (`WithHTTPClient`, `WithMaxBodySize`, `WithParseOptions`) |
| `RegisterOption` | `Cache.Register` (per URL) | Cache refresh interval, wait-ready |

### Safety defaults

- `NewClient()` with no `WithWhitelist` denies every URL
  (`BlockAllWhitelist` semantics). This is stricter than v3's
  `jwk.Fetch`, which defaulted to `InsecureWhitelist`. Callers with
  hard-coded trusted URLs must opt in via
  `jwkfetch.WithWhitelist(jwkfetch.InsecureWhitelist{})`.
- `Cache` does not enforce a whitelist. Registration is the trust
  boundary: if you call `Cache.Register(ctx, url, ...)`, that URL is
  trusted thereafter. Cache callers who need per-fetch policy should
  use `Client` via `jwk.Fetcher` instead.
- `NewClient` / `NewCache` with no `WithHTTPClient` use
  `DefaultHTTPClient()`, which has a 30-second timeout, a 5-redirect
  cap, and a redirect policy that blocks HTTPS→HTTP scheme
  downgrades.

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `jwkfetch.go` | Package doc, `Client` struct + `Fetch`, `HTTPClient`/`ErrorSink`/`TraceSink` aliases, `DefaultHTTPClient`, `WrapHTTPClientDefaults`, constants |
| `jwkfetch_test.go` | `Client` tests (whitelist defaults, allow/deny paths, transport errors) |
| `cache.go` | `Cache` struct + `NewCache` + `Register` + `Fetch` + `Lookup` family + internal `transformer` |
| `cache_test.go` | Cache refresh/backoff/concurrency tests |
| `cachedset.go` | `NewCachedSet` + internal `cachedSet` read-only `jwk.Set` wrapper |
| `whitelist.go` | `Whitelist`, `InsecureWhitelist`, `BlockAllWhitelist`, `MapWhitelist`, `RegexpWhitelist`, `WhitelistFunc`, `WhitelistError` sentinel |
| `options.go` | Option interface types and constructors (`WithHTTPClient`, `WithMaxBodySize`, `WithParseOptions`, `WithWhitelist`, `WithWaitReady`, `WithConstantInterval`, `WithMinInterval`, `WithMaxInterval`) |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
