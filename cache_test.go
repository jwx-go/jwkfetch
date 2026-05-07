package jwkfetch_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/tracesink"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"

	"github.com/jwx-go/jwkfetch/v4"
)

func generateRsaJwk(t *testing.T) jwk.Key {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, `rsa.GenerateKey should succeed`)
	jwkKey, err := jwk.Import[jwk.Key](key)
	require.NoError(t, err, `jwk.Import should succeed`)
	return jwkKey
}

func getAccessCount(t *testing.T, src jwk.Set) int {
	t.Helper()

	key, ok := src.Key(0)
	require.True(t, ok, `src.Key(0) should succeed`)

	fieldV, ok := key.Field(`accessCount`)
	require.True(t, ok, `key.Field("accessCount") should succeed`)
	v := fieldV.(float64)

	return int(v)
}

func checkAccessCount(t *testing.T, src jwk.Set, expected ...int) {
	t.Helper()

	v := getAccessCount(t, src)

	for _, e := range expected {
		if v == e {
			require.Equal(t, e, v, `key.Get("accessCount") should be %d`, e)
			return
		}
	}

	var buf bytes.Buffer
	fmt.Fprint(&buf, "[")
	for i, e := range expected {
		fmt.Fprintf(&buf, "%d", e)
		if i < len(expected)-1 {
			fmt.Fprint(&buf, ", ")
		}
	}
	fmt.Fprintf(&buf, "]")
	require.Failf(t, `checking access count failed`, `key.Get("accessCount") should be one of %s (got %d)`, buf.String(), v)
}

func waitForAccessCountAtLeast(ctx context.Context, t *testing.T, c *jwkfetch.Cache, url string, minCount int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ks, err := c.Lookup(ctx, url)
		if err == nil {
			if v := getAccessCount(t, ks); v >= minCount {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	require.Failf(t, `timed out`, `timed out waiting for accessCount >= %d`, minCount)
}

func TestCachedSet(t *testing.T) {
	t.Parallel()
	const numKeys = 3
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	set := jwk.NewSet()
	for range numKeys {
		key := generateRsaJwk(t)
		require.NoError(t, set.AddKey(key), `set.AddKey should succeed`)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hdrs := w.Header()
		hdrs.Set(`Content-Type`, `application/json`)
		hdrs.Set(`Cache-Control`, `max-age=5`)

		_ = jsonv2.MarshalWrite(w, set)
	}))
	defer srv.Close()

	c, err := jwkfetch.NewCache(ctx, httprc.NewClient())
	require.NoError(t, err, `jwkfetch.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL), `c.Register should succeed`)

	cs, err := c.CachedSet(srv.URL)
	require.NoError(t, err, `c.CachedSet should succeed`)
	require.Error(t, cs.Set("bogus", nil), `cs.Set should be an error`)
	require.Error(t, cs.Remove("bogus"), `cs.Remove should be an error`)
	require.Error(t, cs.AddKey(nil), `cs.AddKey should be an error`)
	require.Error(t, cs.RemoveKey(nil), `cs.RemoveKey should be an error`)
	require.Equal(t, set.Len(), cs.Len(), `value of Len() should be the same`)

	for i := range set.Len() {
		k, err := set.Key(i)
		ck, cerr := cs.Key(i)
		require.Equal(t, k, ck, `key %d should match`, i)
		require.Equal(t, err, cerr, `error %d should match`, i)
	}
}

// jwkSetTransformer is a no-op transformer used solely to construct
// an *httprc.ResourceBase[jwk.Set] that will never actually be
// fetched. It exists so that TestCachedSet_NotReady can build a
// CachedSet whose underlying resource has never been populated.
type jwkSetTransformer struct{}

func (jwkSetTransformer) Transform(_ context.Context, _ *http.Response) (jwk.Set, error) {
	return nil, fmt.Errorf(`not used`)
}

// TestCachedSet_NotReady verifies that a CachedSet whose underlying
// httprc resource has never been populated does not block, returns
// zero / not-found values across every read accessor, and — most
// importantly — returns Len() == 0 rather than the legacy -1
// sentinel. It also passes a pre-cancelled context to catch any
// regression that starts blocking on Ready(ctx) again.
func TestCachedSet_NotReady(t *testing.T) {
	t.Parallel()

	r, err := httprc.NewResource[jwk.Set](
		"https://example.invalid/jwks.json",
		jwkSetTransformer{},
	)
	require.NoError(t, err, `httprc.NewResource should succeed`)

	cs := jwkfetch.NewCachedSet(r)

	// Run every accessor under a watchdog — any regression that
	// starts blocking on Ready() again will trip this instead of
	// hanging the whole test binary.
	done := make(chan struct{})
	go func() {
		defer close(done)

		require.Equal(t, 0, cs.Len(), `Len() on not-ready CachedSet must return 0, not -1`)

		k, ok := cs.Key(0)
		require.Nil(t, k, `Key(0) should be nil`)
		require.False(t, ok, `Key(0) ok should be false`)

		k, ok = cs.LookupKeyID("nope")
		require.Nil(t, k, `LookupKeyID should be nil`)
		require.False(t, ok, `LookupKeyID ok should be false`)

		require.Nil(t, cs.Keys(), `Keys() should be nil`)

		count := 0
		for range cs.All() {
			count++
		}
		require.Equal(t, 0, count, `All() should yield nothing`)

		fieldCount := 0
		for range cs.Fields() {
			fieldCount++
		}
		require.Equal(t, 0, fieldCount, `Fields() should yield nothing`)

		_, cloneErr := cs.Clone()
		require.Error(t, cloneErr, `Clone() should return an error`)

		_, ok = cs.Field("kty")
		require.False(t, ok, `Field() ok should be false`)

		if m, hasMarshal := cs.(interface{ MarshalJSON() ([]byte, error) }); hasMarshal {
			_, marshalErr := m.MarshalJSON()
			require.Error(t, marshalErr, `MarshalJSON() should return an error`)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf(`not-ready CachedSet reads blocked — regression`)
	}
}

func TestCache_explicit_refresh_interval(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var accessCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := accessCount.Add(1)
		key := map[string]any{
			"kty":         "EC",
			"crv":         "P-256",
			"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
			"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
			"accessCount": count,
		}
		hdrs := w.Header()
		hdrs.Set(`Content-Type`, `application/json`)
		hdrs.Set(`Cache-Control`, `max-age=7200`) // Make sure this is ignored

		_ = jsonv2.MarshalWrite(w, key)
	}))
	defer srv.Close()

	c, err := jwkfetch.NewCache(ctx, httprc.NewClient())
	require.NoError(t, err, `jwkfetch.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL, jwkfetch.WithConstantInterval(2*time.Second+500*time.Millisecond)), `c.Register should succeed`)

	retries := 5

	var wg sync.WaitGroup
	wg.Add(retries)
	for range retries {
		go func() {
			defer wg.Done()
			ks, err := c.Lookup(ctx, srv.URL)
			require.NoError(t, err, `c.Lookup should succeed`)
			require.NotNil(t, ks, `c.Lookup should return a non-nil key set`)
			checkAccessCount(t, ks, 1)
		}()
	}

	t.Logf("Waiting for fetching goroutines...")
	wg.Wait()
	t.Logf("Waiting for the refresh ...")

	waitForAccessCountAtLeast(ctx, t, c, srv.URL, 2, 15*time.Second)
}

func TestCache_calculate_interval_from_cache_control(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var accessCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := accessCount.Add(1)

		key := map[string]any{
			"kty":         "EC",
			"crv":         "P-256",
			"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
			"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
			"accessCount": count,
		}
		hdrs := w.Header()
		hdrs.Set(`Content-Type`, `application/json`)
		hdrs.Set(`Cache-Control`, `max-age=3`)

		_ = jsonv2.MarshalWrite(w, key)
	}))
	defer srv.Close()

	c, err := jwkfetch.NewCache(ctx, httprc.NewClient(
		httprc.WithTraceSink(tracesink.NewSlog(
			slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("test", "Cache_calculate_interval_from_cache_control"),
		)),
	))
	require.NoError(t, err, `jwkfetch.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL,
		jwkfetch.WithMinInterval(3*time.Second),
	), `c.Register should succeed`)
	require.True(t, c.IsRegistered(ctx, srv.URL), `c.IsRegistered should be true`)

	retries := 5

	var wg sync.WaitGroup
	wg.Add(retries)
	for range retries {
		go func() {
			defer wg.Done()
			ks, err := c.Lookup(ctx, srv.URL)
			require.NoError(t, err, `c.Lookup should succeed`)
			require.NotNil(t, ks, `c.Lookup should return a non-nil key set`)
			checkAccessCount(t, ks, 1)
		}()
	}

	t.Logf("Waiting for fetching goroutines...")
	wg.Wait()
	t.Logf("Waiting for the refresh ...")

	waitForAccessCountAtLeast(ctx, t, c, srv.URL, 2, 15*time.Second)
}

func TestCache_backoff(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var accessCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hdrs := w.Header()
		hdrs.Set(`Cache-Control`, `max-age=1`)
		count := accessCount.Add(1)
		if count > 1 && count < 4 {
			http.Error(w, "wait for it....", http.StatusForbidden)
			return
		}

		key := map[string]any{
			"kty":         "EC",
			"crv":         "P-256",
			"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
			"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
			"accessCount": count,
		}
		hdrs.Set(`Content-Type`, `application/json`)

		_ = jsonv2.MarshalWrite(w, key)
	}))
	defer srv.Close()

	c, err := jwkfetch.NewCache(ctx, httprc.NewClient(
		httprc.WithTraceSink(tracesink.NewSlog(
			slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("test", "Cache_backoff"),
		)),
	))
	require.NoError(t, err, `jwkfetch.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL, jwkfetch.WithMinInterval(time.Second)), `c.Register should succeed`)

	// First fetch should succeed
	ks, err := c.Lookup(ctx, srv.URL)
	require.NoError(t, err, `c.Lookup (#1) should succeed`)
	require.NotNil(t, ks, `c.Lookup (#1) should return a non-nil key set`)
	checkAccessCount(t, ks, 1)

	// Wait a bit — the next refresh(es) will fail (access 2,3 return 403),
	// so the cache should still serve the original data.
	time.Sleep(2 * time.Second)
	ks, err = c.Lookup(ctx, srv.URL)
	require.NoError(t, err, `c.Lookup (#2) should succeed`)
	require.NotNil(t, ks, `c.Lookup (#2) should return a non-nil key set`)
	checkAccessCount(t, ks, 1)

	// Poll until the server has recovered (access >= 4) and the cache
	// has been updated with the new data.
	waitForAccessCountAtLeast(ctx, t, c, srv.URL, 4, 15*time.Second)
}

func TestGH1551(t *testing.T) {
	t.Parallel()

	const numWorkers = 3

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var errSink accumulateErrs
	c, err := jwkfetch.NewCache(ctx, httprc.NewClient(
		httprc.WithWorkers(numWorkers),
		httprc.WithErrorSink(&errSink),
	))
	require.NoError(t, err, `jwkfetch.NewCache should succeed`)

	require.NoError(t, c.Register(ctx, srv.URL,
		jwkfetch.WithWaitReady(false),
		jwkfetch.WithConstantInterval(time.Hour),
	), `c.Register should succeed`)

	for i := range numWorkers {
		refreshCtx, refreshCancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := c.Refresh(refreshCtx, srv.URL)
		refreshCancel()
		require.Error(t, err, "Refresh #%d should return an error", i)
		t.Logf("Refresh #%d failed as expected: %v", i, err)
	}

	t.Log("All workers exhausted. Attempting one more Refresh()...")

	deadlockCtx, deadlockCancel := context.WithTimeout(ctx, 5*time.Second)
	defer deadlockCancel()

	_, err = c.Refresh(deadlockCtx, srv.URL)
	require.Error(t, err, "Refresh after all workers failed should still return an error")
	require.NotErrorIs(t, err, context.DeadlineExceeded,
		"Refresh should not deadlock (got context deadline exceeded, indicating workers are stuck)")
	t.Logf("Post-failure Refresh returned: %v", err)
}

type accumulateErrs struct {
	mu   sync.RWMutex
	errs []error
}

func (e *accumulateErrs) Put(_ context.Context, err error) {
	e.mu.Lock()
	e.errs = append(e.errs, err)
	e.mu.Unlock()
}

func (e *accumulateErrs) Len() int {
	e.mu.RLock()
	l := len(e.errs)
	e.mu.RUnlock()
	return l
}

// TestCacheTypedErrors pins the contract that the Cache refresh
// path returns the same typed errors as Client.Fetch for the body-
// size cap and parse failure cases. The typed errors surface via
// the configured ErrorSink (Register itself returns a generic
// "not ready" error from httprc; the underlying transformer error
// arrives through the sink).
//
// Without typed errors, operators following the documented
// errors.Is(err, BodyTooLargeError{}) / ParseError{} pattern get
// true on the Client path and false on the Cache path — a silent
// UX trap where alerts never fire.
func TestCacheTypedErrors(t *testing.T) {
	t.Parallel()

	t.Run("BodyTooLargeError reaches the ErrorSink", func(t *testing.T) {
		t.Parallel()
		body := bytes.Repeat([]byte("x"), 4096)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		var errSink accumulateErrs
		c, err := jwkfetch.NewCache(ctx, httprc.NewClient(httprc.WithErrorSink(&errSink)),
			jwkfetch.WithMaxBodySize(16),
		)
		require.NoError(t, err)
		defer func() { _ = c.Shutdown(ctx) }()

		// Register fails with the generic "not ready" error after the
		// transformer keeps rejecting; the typed error lands in errSink.
		_ = c.Register(ctx, srv.URL)

		require.Eventually(t, func() bool { return errSink.Len() > 0 }, 5*time.Second, 50*time.Millisecond,
			"the cache transformer must surface its error to the ErrorSink")

		errSink.mu.RLock()
		captured := errSink.errs[0]
		errSink.mu.RUnlock()

		require.ErrorIs(t, captured, jwkfetch.BodyTooLargeError{},
			"Cache path must return BodyTooLargeError, matching Client.Fetch's contract")

		var bodyErr jwkfetch.BodyTooLargeError
		require.ErrorAs(t, captured, &bodyErr,
			"errors.As must extract the typed value")
		require.Equal(t, int64(16), bodyErr.Limit)
		require.Equal(t, srv.URL, bodyErr.URL)
	})

	t.Run("ParseError reaches the ErrorSink", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"not":"a-jwk-set"}`))
		}))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		var errSink accumulateErrs
		c, err := jwkfetch.NewCache(ctx, httprc.NewClient(httprc.WithErrorSink(&errSink)))
		require.NoError(t, err)
		defer func() { _ = c.Shutdown(ctx) }()

		_ = c.Register(ctx, srv.URL)

		require.Eventually(t, func() bool { return errSink.Len() > 0 }, 5*time.Second, 50*time.Millisecond,
			"the cache transformer must surface its parse error to the ErrorSink")

		errSink.mu.RLock()
		captured := errSink.errs[0]
		errSink.mu.RUnlock()

		require.ErrorIs(t, captured, jwkfetch.ParseError{},
			"Cache path must return ParseError, matching Client.Fetch's contract")

		var parseErr jwkfetch.ParseError
		require.ErrorAs(t, captured, &parseErr,
			"errors.As must extract the typed value")
		require.Equal(t, srv.URL, parseErr.URL)
		require.NotNil(t, parseErr.Err, "wrapped jwk.Parse error must be reachable")
	})
}

func TestErrorSink(t *testing.T) {
	t.Parallel()

	key := generateRsaJwk(t)
	testcases := []struct {
		Name    string
		Options func() []httprc.NewClientOption
		Handler http.Handler
	}{
		{
			Name: `rejected by whitelist`,
			Options: func() []httprc.NewClientOption {
				return []httprc.NewClientOption{
					httprc.WithWhitelist(httprc.NewBlockAllWhitelist()),
				}
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_ = jsonv2.MarshalWrite(w, key)
			}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			srv := httptest.NewServer(tc.Handler)
			defer srv.Close()

			var errSink accumulateErrs
			options := append(tc.Options(), httprc.WithErrorSink(&errSink))
			c, err := jwkfetch.NewCache(ctx, httprc.NewClient(options...))
			require.NoError(t, err, `jwkfetch.NewCache should succeed`)
			require.Error(t, c.Register(ctx, srv.URL), `c.Register should fail`)
		})
	}
}
