package core

import (
	"io"

	gosync "github.com/dnsoa/go/sync"
)

type Request struct {
	Method        Method
	Version       Version
	URI           URI
	Headers       Headers
	Trailers      Headers
	Body          io.ReadCloser
	ContentLength int64
}

var requestPool = gosync.NewPool(func() *Request {
	return &Request{
		Version:  VersionHTTP11,
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
	}
})

func AcquireRequest() *Request {
	req := requestPool.Get()
	req.Reset()
	return req
}

func ReleaseRequest(req *Request) {
	if req == nil {
		return
	}
	requestPool.Put(req)
}

func (r *Request) Host() []byte {
	if len(r.URI.Host) > 0 {
		return r.URI.Host
	}
	return r.Headers.Get("Host")
}

func (r *Request) Reset() {
	r.Headers.Reset()
	r.Trailers.Reset()
	r.URI.Reset()
	if r.Body != nil {
		r.Body.Close()
		r.Body = nil
	}
	r.Method = MethodGet
	r.Version = VersionHTTP11
	r.ContentLength = 0
}

// SetBody sets the request body. The caller is responsible for setting
// ContentLength and Content-Length header when the size is known.
func (r *Request) SetBody(body io.ReadCloser) {
	if r.Body != nil {
		r.Body.Close()
	}
	r.Body = body
}

func (r *Request) ReadAll() ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}
