# jwkfetch

HTTP-based JWK Set retrieval for
[github.com/lestrrat-go/jwx/v4](https://github.com/lestrrat-go/jwx).

This module provides two `jwk.Fetcher` implementations:

- **`Client`** — one-shot HTTPS fetches with whitelist, body-size cap,
  and parse-option control. Use it for ad-hoc retrieval or
  `jku`-style JWS verification.
- **`Cache`** — background-refreshed JWKS store backed by
  [httprc](https://github.com/lestrrat-go/httprc). Use it when you
  have a small, trusted set of JWKS URLs and want to amortize fetch
  cost across verifications.

It was extracted from the `jwk` package in jwx v4 so that the core
jwx module depends on neither `net/http` nor `httprc`.

## Install

```
go get github.com/jwx-go/jwkfetch/v4
```

Requires `GOEXPERIMENT=jsonv2`.

## Usage

### One-shot fetch with `Client`

```go
client := jwkfetch.NewClient(
    jwkfetch.WithWhitelist(
        jwkfetch.NewMapWhitelist().Add("https://issuer.example/jwks.json"),
    ),
)

set, err := client.Fetch(ctx, "https://issuer.example/jwks.json")
```

A `Client` constructed with no `WithWhitelist` denies every URL
(`BlockAllWhitelist` semantics). This is the safe default for
`jku`-style inputs. Callers with hard-coded trusted URLs must opt in
via `WithWhitelist(jwkfetch.InsecureWhitelist{})` or a specific
allowlist.

Wire a `Client` into `jws.WithVerifyAuto` or `jwt.WithVerifyAuto`:

```go
_, err := jws.Verify(signed, jws.WithVerifyAuto(client))
```

### Background-refreshed cache with `Cache`

```go
cache, err := jwkfetch.NewCache(ctx, httprc.NewClient())
if err != nil { ... }

err = cache.Register(ctx, "https://issuer.example/jwks.json",
    jwkfetch.WithMinInterval(5*time.Minute),
)

// Cache implements jwk.Fetcher:
_, err = jws.Verify(signed, jws.WithVerifyAuto(cache))
```

`Cache` does not enforce a whitelist — registration is the trust
boundary for cached URLs. Use `Client` if you need per-fetch policy.

## Options

Options that configure HTTP fetch policy work for both `NewClient` and
`NewCache`:

| Option | Description |
|--------|-------------|
| `WithHTTPClient(c)` | Override the `*http.Client` used for fetches (default: `DefaultHTTPClient()` — 30s timeout, 5-redirect cap, HTTPS-downgrade block) |
| `WithMaxBodySize(n)` | Maximum response body bytes (default: 10 MB) |
| `WithParseOptions(...)` | `jwk.ParseOption` values passed through to `jwk.Parse` |

`Client`-only:

| Option | Description |
|--------|-------------|
| `WithWhitelist(w)` | URL allowlist consulted before every fetch (default: deny-all) |

`Cache.Register` per-URL options:

| Option | Description |
|--------|-------------|
| `WithWaitReady(bool)` | Whether `Register` blocks until the first fetch completes (default: `true`) |
| `WithConstantInterval(d)` | Use a fixed refresh interval |
| `WithMinInterval(d)` | Minimum refresh interval |
| `WithMaxInterval(d)` | Maximum refresh interval |

## Whitelist types

`Client.Whitelist` accepts any implementation of `jwkfetch.Whitelist`:

- `InsecureWhitelist{}` — allow every URL (opt-in permissive)
- `BlockAllWhitelist{}` — deny every URL (the nil-Whitelist default)
- `NewMapWhitelist().Add(url1).Add(url2)` — fixed allow-list
- `NewRegexpWhitelist().Add(pattern)` — pattern-based allow-list
- `WhitelistFunc(func(string) bool)` — custom predicate

Errors returned when a URL is rejected match
`errors.Is(err, jwkfetch.WhitelistError())`.

## `Cache.CachedSet`

`Cache.CachedSet(url)` returns a read-only `jwk.Set` whose contents
always reflect the latest cached data. All mutation methods on the
returned set return errors.
