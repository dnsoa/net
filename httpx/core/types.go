package core

import (
	"bytes"
	"time"
)

type Method uint8

const (
	MethodGet Method = iota
	MethodPost
	MethodPut
	MethodDelete
	MethodPatch
	MethodHead
	MethodOptions
	MethodTrace
	MethodConnect
	MethodCustom
)

var methodNames = [...]string{
	MethodGet:     "GET",
	MethodPost:    "POST",
	MethodPut:     "PUT",
	MethodDelete:  "DELETE",
	MethodPatch:   "PATCH",
	MethodHead:    "HEAD",
	MethodOptions: "OPTIONS",
	MethodTrace:   "TRACE",
	MethodConnect: "CONNECT",
	MethodCustom:  "CUSTOM",
}

func (m Method) String() string {
	if int(m) >= len(methodNames) {
		return methodNames[MethodCustom]
	}
	return methodNames[m]
}

func ParseMethodBytes(raw []byte) (Method, bool) {
	switch len(raw) {
	case 3:
		if bytes.EqualFold(raw, []byte("GET")) {
			return MethodGet, true
		}
		if bytes.EqualFold(raw, []byte("PUT")) {
			return MethodPut, true
		}
	case 4:
		if bytes.EqualFold(raw, []byte("POST")) {
			return MethodPost, true
		}
		if bytes.EqualFold(raw, []byte("HEAD")) {
			return MethodHead, true
		}
	case 5:
		if bytes.EqualFold(raw, []byte("PATCH")) {
			return MethodPatch, true
		}
		if bytes.EqualFold(raw, []byte("TRACE")) {
			return MethodTrace, true
		}
	case 6:
		if bytes.EqualFold(raw, []byte("DELETE")) {
			return MethodDelete, true
		}
	case 7:
		if bytes.EqualFold(raw, []byte("CONNECT")) {
			return MethodConnect, true
		}
		if bytes.EqualFold(raw, []byte("OPTIONS")) {
			return MethodOptions, true
		}
	}
	return MethodCustom, false
}

func (m Method) IsIdempotent() bool {
	switch m {
	case MethodGet, MethodHead, MethodPut, MethodDelete, MethodOptions, MethodTrace:
		return true
	default:
		return false
	}
}

func (m Method) IsSafe() bool {
	switch m {
	case MethodGet, MethodHead, MethodOptions, MethodTrace:
		return true
	default:
		return false
	}
}

func (m Method) HasRequestBody() bool {
	switch m {
	case MethodPost, MethodPut, MethodPatch:
		return true
	default:
		return false
	}
}

type Version uint8

const (
	VersionHTTP10 Version = iota
	VersionHTTP11
	VersionHTTP2
	VersionHTTP3
)

var versionNames = [...]string{
	VersionHTTP10: "HTTP/1.0",
	VersionHTTP11: "HTTP/1.1",
	VersionHTTP2:  "HTTP/2",
	VersionHTTP3:  "HTTP/3",
}

func (v Version) String() string {
	if int(v) >= len(versionNames) {
		return versionNames[VersionHTTP11]
	}
	return versionNames[v]
}

func ParseVersionBytes(raw []byte) (Version, bool) {
	for idx, name := range versionNames {
		if bytes.EqualFold(raw, []byte(name)) {
			return Version(idx), true
		}
	}
	if bytes.EqualFold(raw, []byte("HTTP/2.0")) {
		return VersionHTTP2, true
	}
	if bytes.EqualFold(raw, []byte("HTTP/3.0")) {
		return VersionHTTP3, true
	}
	return VersionHTTP11, false
}

func (v Version) SupportsMultiplexing() bool {
	return v == VersionHTTP2 || v == VersionHTTP3
}

func (v Version) UsesQUIC() bool {
	return v == VersionHTTP3
}

func (v Version) RequiresTLS() bool {
	return v == VersionHTTP2 || v == VersionHTTP3
}

type Timeouts struct {
	Connect   time.Duration
	Read      time.Duration
	Write     time.Duration
	KeepAlive time.Duration
	Idle      time.Duration
	Request   time.Duration
}

func UniformTimeouts(d time.Duration) Timeouts {
	return Timeouts{
		Connect:   d,
		Read:      d,
		Write:     d,
		KeepAlive: d * 2,
		Idle:      d * 4,
	}
}

type RetryPolicy struct {
	MaxRetries             uint32
	InitialDelay           time.Duration
	MaxDelay               time.Duration
	BackoffMultiplier      float64
	RetryOnStatus          []int
	RetryOnConnectionError bool
	RetryOnlyIdempotent    bool
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:             3,
		InitialDelay:           time.Second,
		MaxDelay:               30 * time.Second,
		BackoffMultiplier:      2,
		RetryOnStatus:          []int{429, 500, 502, 503, 504},
		RetryOnConnectionError: true,
		RetryOnlyIdempotent:    true,
	}
}

func (p RetryPolicy) Delay(attempt uint32) time.Duration {
	if attempt == 0 {
		return 0
	}
	delay := float64(p.InitialDelay)
	for i := uint32(1); i < attempt; i++ {
		delay *= p.BackoffMultiplier
	}
	out := time.Duration(delay)
	if out > p.MaxDelay {
		return p.MaxDelay
	}
	return out
}

func (p RetryPolicy) ShouldRetryStatus(code int) bool {
	for _, status := range p.RetryOnStatus {
		if status == code {
			return true
		}
	}
	return false
}

type RedirectPolicy struct {
	MaxRedirects     uint32
	FollowRedirects  bool
	PreserveMethod   bool
	PreserveHeaders  bool
	AllowCrossOrigin bool
}

func DefaultRedirectPolicy() RedirectPolicy {
	return RedirectPolicy{
		MaxRedirects:     10,
		FollowRedirects:  true,
		PreserveHeaders:  true,
		AllowCrossOrigin: true,
	}
}

func (p RedirectPolicy) RedirectMethod(statusCode int, original Method) Method {
	if p.PreserveMethod {
		return original
	}
	switch statusCode {
	case 301, 302, 303:
		return MethodGet
	case 307, 308:
		return original
	default:
		return original
	}
}
