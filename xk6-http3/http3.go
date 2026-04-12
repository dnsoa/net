// Package xk6http3 provides a k6 extension module for making HTTP/3 requests.
package xk6http3

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.k6.io/k6/js/modules"
	"go.k6.io/k6/metrics"
)

func init() {
	modules.Register("k6/x/http3", New())
}

// RootModule stores metrics registered once per test run.
type RootModule struct {
	metricsOnce sync.Once
	m           *http3Metrics
}

type http3Metrics struct {
	reqDuration  *metrics.Metric
	reqWaiting   *metrics.Metric
	reqReceiving *metrics.Metric
}

func New() *RootModule {
	return &RootModule{}
}

func (rm *RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	rm.metricsOnce.Do(func() {
		reg := vu.InitEnv().Registry
		rm.m = &http3Metrics{
			reqDuration:  reg.MustNewMetric("http3_req_duration", metrics.Trend, metrics.Time),
			reqWaiting:   reg.MustNewMetric("http3_req_waiting", metrics.Trend, metrics.Time),
			reqReceiving: reg.MustNewMetric("http3_req_receiving", metrics.Trend, metrics.Time),
		}
	})
	return &ModuleInstance{vu: vu, m: rm.m}
}

type ModuleInstance struct {
	vu     modules.VU
	client *http.Client
	rt     *http3.Transport
	once   sync.Once
	m      *http3Metrics
}

func newTransport(options map[string]any) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: getBoolOption(options, "insecureSkipTLSVerify", false),
			ServerName:         getStringOption(options, "serverName", ""),
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: getDurationOption(options, "handshakeIdleTimeout", 3*time.Second),
			MaxIdleTimeout:       getDurationOption(options, "maxIdleTimeout", 5*time.Second),
			KeepAlivePeriod:      getDurationOption(options, "keepAlivePeriod", 2*time.Second),
		},
	}
}

// getOrCreateClient returns (client, cleanup).
// When noReuse: client uses a disposable transport; cleanup closes it after body is read.
// Otherwise: returns the per-VU cached client with a no-op cleanup.
func (mi *ModuleInstance) getOrCreateClient(options map[string]any) (*http.Client, func()) {
	if getBoolOption(options, "noReuse", false) {
		rt := newTransport(options)
		return &http.Client{Transport: rt}, func() { rt.Close() }
	}
	mi.once.Do(func() {
		mi.rt = newTransport(options)
		mi.client = &http.Client{Transport: mi.rt}
	})
	return mi.client, func() {}
}

func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{
		Named: map[string]any{
			"request": mi.request,
			"get":     mi.get,
			"post":    mi.post,
			"put":     mi.put,
			"del":     mi.del,
			"patch":   mi.patch,
		},
	}
}

// emitMetrics pushes timing samples to k6's metrics pipeline.
// Safe to call when state is nil (init phase) — emits nothing.
func (mi *ModuleInstance) emitMetrics(ttfb, receiving time.Duration, method, url, statusTag string) {
	state := mi.vu.State()
	if state == nil || mi.m == nil {
		return
	}
	ctx := mi.vu.Context()
	tags := state.Tags.GetCurrentValues()

	reqTags := tags.Tags.
		With("method", method).
		With("url", url).
		With("status", statusTag).
		With("proto", "HTTP/3")

	now := time.Now()
	samples := metrics.Samples{
		{
			TimeSeries: metrics.TimeSeries{Metric: mi.m.reqDuration, Tags: reqTags},
			Time:       now,
			Value:      metrics.D(ttfb + receiving),
			Metadata:   tags.Metadata,
		},
		{
			TimeSeries: metrics.TimeSeries{Metric: mi.m.reqWaiting, Tags: reqTags},
			Time:       now,
			Value:      metrics.D(ttfb),
			Metadata:   tags.Metadata,
		},
		{
			TimeSeries: metrics.TimeSeries{Metric: mi.m.reqReceiving, Tags: reqTags},
			Time:       now,
			Value:      metrics.D(receiving),
			Metadata:   tags.Metadata,
		},
	}
	metrics.PushIfNotDone(ctx, state.Samples, samples)
}

func makeErrorResult(ttfb, receiving time.Duration, status int, errMsg string) map[string]any {
	return map[string]any{
		"status": status,
		"error":  errMsg,
		"timings": map[string]any{
			"duration":  metrics.D(ttfb + receiving),
			"waiting":   metrics.D(ttfb),
			"receiving": metrics.D(receiving),
		},
	}
}

func (mi *ModuleInstance) request(method, url, body string, options map[string]any) map[string]any {
	if options == nil {
		options = make(map[string]any)
	}

	client, cleanup := mi.getOrCreateClient(options)
	defer cleanup() // close disposable transport AFTER body is read (LIFO: body.Close() runs first)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	// Use VU context as base so k6 test cancellation propagates to in-flight requests.
	timeout := getDurationOption(options, "timeout", 60*time.Second)
	ctx, cancel := context.WithTimeout(mi.vu.Context(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return makeErrorResult(0, 0, 0, fmt.Sprintf("failed to create request: %v", err))
	}

	if headers, ok := options["headers"].(map[string]any); ok {
		for k, v := range headers {
			if str, ok := v.(string); ok {
				req.Header.Set(k, str)
			}
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(start)
	if err != nil {
		mi.emitMetrics(ttfb, 0, method, url, "0")
		return makeErrorResult(ttfb, 0, 0, fmt.Sprintf("request failed: %v", err))
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	receiving := time.Since(start) - ttfb
	statusTag := fmt.Sprintf("%d", resp.StatusCode)
	if err != nil {
		mi.emitMetrics(ttfb, receiving, method, url, statusTag)
		return makeErrorResult(ttfb, receiving, resp.StatusCode, fmt.Sprintf("failed to read body: %v", err))
	}

	mi.emitMetrics(ttfb, receiving, method, url, statusTag)

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = strings.Join(v, ", ")
		}
	}

	return map[string]any{
		"status": resp.StatusCode,
		"body":   string(bodyBytes),
		"timings": map[string]any{
			"duration":  metrics.D(ttfb + receiving),
			"waiting":   metrics.D(ttfb),
			"receiving": metrics.D(receiving),
		},
		"headers":  headers,
		"proto":    "HTTP/3",
		"protocol": "HTTP/3",
	}
}

func (mi *ModuleInstance) get(url string, options map[string]any) map[string]any {
	return mi.request("GET", url, "", options)
}

func (mi *ModuleInstance) post(url string, body string, options map[string]any) map[string]any {
	return mi.request("POST", url, body, options)
}

func (mi *ModuleInstance) put(url string, body string, options map[string]any) map[string]any {
	return mi.request("PUT", url, body, options)
}

func (mi *ModuleInstance) del(url string, options map[string]any) map[string]any {
	return mi.request("DELETE", url, "", options)
}

func (mi *ModuleInstance) patch(url string, body string, options map[string]any) map[string]any {
	return mi.request("PATCH", url, body, options)
}

func getBoolOption(options map[string]any, key string, defaultValue bool) bool {
	if val, ok := options[key].(bool); ok {
		return val
	}
	return defaultValue
}

func getDurationOption(options map[string]any, key string, defaultValue time.Duration) time.Duration {
	if val, ok := options[key].(string); ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultValue
}

func getStringOption(options map[string]any, key string, defaultValue string) string {
	if val, ok := options[key].(string); ok {
		return val
	}
	return defaultValue
}
