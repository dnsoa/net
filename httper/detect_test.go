package httper

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestSupportsHTTP3_AltSvc(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", "h3=\":443\"; ma=60")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ok, err := SupportsHTTP3(ctx, ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected true")
	}
}

func TestSupportsHTTP3_NoAltSvc(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ok, err := SupportsHTTP3(ctx, ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected false")
	}
}

func TestSupportsHTTP2_TLSALPN(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	tr, ok := ts.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type")
	}
	if tr.TLSClientConfig == nil {
		t.Fatalf("expected TLSClientConfig")
	}
	// Clone to avoid mutation.
	tlsCfg := tr.TLSClientConfig.Clone()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	support, err := SupportsHTTP2(ctx, ts.URL, WithTLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !support {
		t.Fatalf("expected true")
	}
}

func TestSupportsHTTP2_NoHTTP2(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	ts.EnableHTTP2 = false
	ts.StartTLS()
	defer ts.Close()

	tr, ok := ts.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type")
	}
	if tr.TLSClientConfig == nil {
		t.Fatalf("expected TLSClientConfig")
	}
	// Clone to avoid mutation.
	tlsCfg := tr.TLSClientConfig.Clone()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	support, err := SupportsHTTP2(ctx, ts.URL, WithTLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if support {
		t.Fatalf("expected false")
	}
}

func TestSupportsHTTP2_WithHostIPPort(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Use a domain-like target, but force dialing to the local test server.
	support, err := SupportsHTTP2(
		ctx,
		"https://example.com",
		WithHost("example.com"),
		WithIP("127.0.0.1"),
		WithPort(port),
		WithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !support {
		t.Fatalf("expected true")
	}
}

func TestSupportsHTTP3_WithHostIPPort(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", "h3=\":443\"; ma=60")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ok, err := SupportsHTTP3(
		ctx,
		"https://example.com/",
		WithHost("example.com"),
		WithIP("127.0.0.1"),
		WithPort(port),
		WithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected true")
	}
}
