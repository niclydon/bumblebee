package output

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestHTTPSink_RejectsPlainHTTPToRemote(t *testing.T) {
	_, err := NewHTTPSink(HTTPConfig{URL: "http://example.com/ingest"})
	if err == nil || !strings.Contains(err.Error(), "refusing plain http") {
		t.Fatalf("expected plain-http refusal, got %v", err)
	}
}

func fakeRetryClock(sink *HTTPSink) *[]time.Duration {
	now := time.Unix(1000, 0)
	waits := []time.Duration{}
	sink.now = func() time.Time { return now }
	sink.sleep = func(d time.Duration) { waits = append(waits, d); now = now.Add(d) }
	return &waits
}

func TestHTTPSink_RetriesTransientStatusWithSameBodyAndFreshHMAC(t *testing.T) {
	var bodies [][]byte
	var timestamps []string
	var signatures []string
	var diagnostics bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		timestamps = append(timestamps, r.Header.Get("X-Inventory-Timestamp"))
		signatures = append(signatures, r.Header.Get("X-Inventory-Signature"))
		if len(bodies) < 3 {
			w.WriteHeader(http.StatusBadGateway)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, Gzip: true,
		RetryMaxElapsed: time.Minute, Diagnostics: &diagnostics, RunID: "test-run",
		Auth: HTTPAuth{Mode: "hmac-sha256", HMACKey: []byte("test-key"), TimestampHeader: "X-Inventory-Timestamp"}})
	if err != nil {
		t.Fatal(err)
	}
	waits := fakeRetryClock(sink)
	if _, err := sink.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[1]) || !bytes.Equal(bodies[1], bodies[2]) {
		t.Fatalf("wanted three identical attempts, got %d", len(bodies))
	}
	if timestamps[0] == timestamps[1] || timestamps[1] == timestamps[2] || signatures[0] == signatures[1] {
		t.Fatal("HMAC timestamp/signature was not regenerated for each attempt")
	}
	if len(*waits) != 2 || !strings.Contains(diagnostics.String(), "http sink retry attempt=2 status=502") {
		t.Fatalf("missing retry waits/diagnostic: waits=%v diag=%s", *waits, diagnostics.String())
	}
	if got := sink.Stats(); got.HTTPBatchesAttempted != 1 || got.HTTPBatchesSucceeded != 1 || got.HTTPBatchesFailed != 0 || got.HTTPLastStatus != 200 {
		t.Fatalf("wrong logical batch stats: %+v", got)
	}
}

type retryTransport func(*http.Request) (*http.Response, error)

func (f retryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPSink_RetriesTransportError(t *testing.T) {
	posts := 0
	client := &http.Client{Transport: retryTransport(func(r *http.Request) (*http.Response, error) {
		posts++
		if posts == 1 {
			return nil, errors.New("connection refused")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	sink, err := NewHTTPSink(HTTPConfig{URL: "https://example.com/ingest", BatchSize: 1, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	fakeRetryClock(sink)
	if _, err := sink.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if posts != 2 || sink.Stats().HTTPBatchesFailed != 0 {
		t.Fatalf("posts=%d stats=%+v", posts, sink.Stats())
	}
}

func TestHTTPSink_RetryAfterAndBudget(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.Header().Set("Retry-After", "7")
		if posts == 1 {
			w.WriteHeader(429)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, RetryMaxElapsed: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	waits := fakeRetryClock(sink)
	if _, err := sink.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if posts != 2 || len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Fatalf("posts=%d waits=%v", posts, *waits)
	}

	posts = 0
	sink, err = NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, RetryMaxElapsed: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fakeRetryClock(sink)
	// Retry-After exceeds the remaining budget: no second request.
	if _, err := sink.Write([]byte("{}\n")); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want last 429, got %v", err)
	}
	if posts != 1 || sink.Stats().HTTPBatchesFailed != 1 {
		t.Fatalf("posts=%d stats=%+v", posts, sink.Stats())
	}
}

func TestHTTPSink_NonRetryableAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		status int
		budget time.Duration
	}{{400, 0}, {500, 0}, {502, -1}} {
		posts := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts++; w.WriteHeader(tc.status) }))
		sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, RetryMaxElapsed: tc.budget})
		if err != nil {
			t.Fatal(err)
		}
		fakeRetryClock(sink)
		_, err = sink.Write([]byte("{}\n"))
		if err == nil || posts != 1 || sink.Stats().HTTPBatchesFailed != 1 {
			t.Fatalf("status=%d posts=%d err=%v", tc.status, posts, err)
		}
		srv.Close()
	}
}

func TestHTTPSink_AllowsLoopbackPlainHTTP(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://127.0.0.1:8080/ingest"}); err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://localhost:8080/ingest"}); err != nil {
		t.Fatalf("localhost http should be allowed: %v", err)
	}
}

func TestHTTPSink_RequiresAuthCredentials(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "bearer"}}); err == nil {
		t.Fatal("expected error for bearer with empty token")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "hmac-sha256"}}); err == nil {
		t.Fatal("expected error for hmac with empty key")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "nonsense"}}); err == nil {
		t.Fatal("expected error for unknown auth mode")
	}
}

type captured struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  [][]byte
}

func (c *captured) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.headers = append(c.headers, r.Header.Clone())
		c.bodies = append(c.bodies, body)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}
}

func TestHTTPSink_BearerAuth_BatchAndFlush(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:       srv.URL,
		Auth:      HTTPAuth{Mode: "bearer", Token: "shh"},
		BatchSize: 2,
		UserAgent: "bumblebee/test",
	})
	if err != nil {
		t.Fatal(err)
	}

	e := New(sink, io.Discard, "run-1")
	for i := 0; i < 3; i++ {
		if _, err := e.Emit(model.Record{
			Ecosystem:      "npm",
			NormalizedName: "a",
			Version:        []string{"1.0.0", "1.0.1", "1.0.2"}[i],
			SourceType:     "npm-lockfile",
			SourceFile:     "/x",
		}); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if len(cap.bodies) != 2 {
		t.Fatalf("want 2 POSTs (batch=2 + flush), got %d", len(cap.bodies))
	}
	// First batch: 2 lines. Second: 1.
	if got := bytes.Count(cap.bodies[0], []byte{'\n'}); got != 2 {
		t.Fatalf("first batch lines = %d, want 2", got)
	}
	if got := bytes.Count(cap.bodies[1], []byte{'\n'}); got != 1 {
		t.Fatalf("second batch lines = %d, want 1", got)
	}
	for _, h := range cap.headers {
		if h.Get("Authorization") != "Bearer shh" {
			t.Errorf("missing/incorrect bearer header: %q", h.Get("Authorization"))
		}
		if h.Get("Content-Type") != contentTypeNDJSON {
			t.Errorf("bad content-type: %q", h.Get("Content-Type"))
		}
		if h.Get("User-Agent") != "bumblebee/test" {
			t.Errorf("bad user-agent: %q", h.Get("User-Agent"))
		}
	}
	stats := sink.Stats()
	if stats.HTTPBatchesAttempted != 2 || stats.HTTPBatchesSucceeded != 2 || stats.HTTPBatchesFailed != 0 || stats.HTTPLastStatus != http.StatusOK {
		t.Fatalf("unexpected sink stats: %+v", stats)
	}
}

func TestHTTPSink_HMACSignsBody(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	key := []byte("supersecret")
	sink, err := NewHTTPSink(HTTPConfig{
		URL: srv.URL,
		Auth: HTTPAuth{
			Mode:            "hmac-sha256",
			HMACKey:         key,
			TimestampHeader: "X-Inventory-Timestamp",
		},
		BatchSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	e := New(sink, io.Discard, "run-1")
	if _, err := e.Emit(model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/x",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("want 1 POST, got %d", len(cap.bodies))
	}
	ts := cap.headers[0].Get("X-Inventory-Timestamp")
	if ts == "" {
		t.Fatal("missing timestamp header")
	}
	sig := cap.headers[0].Get("X-Inventory-Signature")
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("missing/incorrect signature header: %q", sig)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(cap.bodies[0])
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", sig, want)
	}
}

// TestHTTPSink_GzipEncodesBody verifies that --http-gzip puts gzip on
// the wire (Content-Encoding header + inflatable body) and that the
// inflated body matches what the emitter produced. This is the path
// that lets fleet-scale deployments cut ingest bytes 8-15x without
// changing the record schema.
func TestHTTPSink_GzipEncodesBody(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:       srv.URL,
		BatchSize: 10,
		Gzip:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := New(sink, io.Discard, "run-1")
	for i := 0; i < 3; i++ {
		if _, err := e.Emit(model.Record{
			Ecosystem:      "npm",
			NormalizedName: "lodash",
			Version:        []string{"1.0.0", "1.0.1", "1.0.2"}[i],
			SourceType:     "npm-lockfile",
			SourceFile:     "/x",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("want 1 POST, got %d", len(cap.bodies))
	}
	if ce := cap.headers[0].Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want %q", ce, "gzip")
	}
	if ct := cap.headers[0].Get("Content-Type"); ct != contentTypeNDJSON {
		t.Fatalf("Content-Type = %q, want %q", ct, contentTypeNDJSON)
	}
	zr, err := gzip.NewReader(bytes.NewReader(cap.bodies[0]))
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	inflated, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if got := bytes.Count(inflated, []byte{'\n'}); got != 3 {
		t.Fatalf("inflated NDJSON lines = %d, want 3 (body=%q)", got, inflated)
	}
}

// TestHTTPSink_GzipPlusHMACSignsCompressedBody pins down the auth/gzip
// interaction: with both enabled, the signature must be over the
// on-the-wire bytes, since that is what the receiver verifies before
// inflating. Changing this would break receiver implementations.
func TestHTTPSink_GzipPlusHMACSignsCompressedBody(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	key := []byte("k")
	sink, err := NewHTTPSink(HTTPConfig{
		URL: srv.URL,
		Auth: HTTPAuth{
			Mode:            "hmac-sha256",
			HMACKey:         key,
			TimestampHeader: "X-Inventory-Timestamp",
		},
		BatchSize: 10,
		Gzip:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := New(sink, io.Discard, "run-1")
	if _, err := e.Emit(model.Record{
		Ecosystem: "npm", NormalizedName: "lodash", Version: "1",
		SourceType: "npm-lockfile", SourceFile: "/x",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("want 1 POST, got %d", len(cap.bodies))
	}
	ts := cap.headers[0].Get("X-Inventory-Timestamp")
	if ts == "" {
		t.Fatal("missing timestamp header")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(cap.bodies[0]) // compressed body, exactly as POSTed
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := cap.headers[0].Get("X-Inventory-Signature"); got != want {
		t.Fatalf("signature mismatch\n got %s\nwant %s", got, want)
	}
}

func TestHTTPSink_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	e := New(sink, io.Discard, "run-1")
	_, _ = e.Emit(model.Record{
		Ecosystem: "npm", NormalizedName: "a", Version: "1",
		SourceType: "npm-lockfile", SourceFile: "/x",
	})
	closeErr := e.Close()
	// Either Emit or Close should surface the server error; the sink
	// caches the error on Write so subsequent operations fail too.
	if closeErr == nil && sink.err == nil {
		t.Fatal("expected error from non-2xx server response")
	}
	stats := sink.Stats()
	if stats.HTTPBatchesAttempted != 1 || stats.HTTPBatchesSucceeded != 0 || stats.HTTPBatchesFailed != 1 || stats.HTTPLastStatus != http.StatusInternalServerError {
		t.Fatalf("unexpected sink stats after non-2xx: %+v", stats)
	}
}
