package core

import "bytes"

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
