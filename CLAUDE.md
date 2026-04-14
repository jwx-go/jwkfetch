# JWK Cache Extension for JWX

## Overview

This module (`github.com/jwx-go/jwkfetch/v4`) provides JWK Set caching backed by `github.com/lestrrat-go/httprc` for `github.com/lestrrat-go/jwx`.

It was extracted from the jwk package to keep the core jwx module free of the httprc dependency. The cache automatically fetches and refreshes JWK Sets from remote URLs in the background. It also provides a read-only `CachedSet` that implements `jwk.Set` and a `Fetcher` that implements `jwk.Fetcher`.

## Architecture

The `Cache` type wraps an `httprc.Controller` to manage HTTP resources. A `Transformer` converts HTTP responses into `jwk.Set` objects. Registration options control per-URL settings such as refresh intervals, HTTP client, body size limits, and whether to wait for the first fetch.

### Key Types

| Type | Purpose |
|------|---------|
| `Cache` | Manages cached JWK Sets by URL via httprc |
| `Transformer` | Converts `*http.Response` to `jwk.Set` |
| `CachedSet` | Read-only `jwk.Set` backed by a cached resource |
| `Fetcher` | Implements `jwk.Fetcher` using a `Cache` |

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `jwkfetch.go` | Package doc, `Cache`, `Transformer`, `CachedSet`, `Fetcher` |
| `options.go` | `RegisterOption` and option constructors (`WithHTTPClient`, `WithWaitReady`, etc.) |
| `jwkfetch_test.go` | Tests |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
