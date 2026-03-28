package core

import (
	"io"

	"github.com/dnsoa/go/allocator"
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
	alloc         *allocator.Allocator
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

func (r *Request) SetAllocator(alloc *allocator.Allocator) {
	r.alloc = alloc
	r.URI.SetAllocator(alloc)
	r.Headers.SetAllocator(alloc)
	r.Trailers.SetAllocator(alloc)
}

func (r *Request) Reset() {
	alloc := r.alloc
	r.Headers.Reset()
	r.Trailers.Reset()
	r.URI.Reset()
	if r.Body != nil {
		r.Body.Close()
		r.Body = nil
	}
	*r = Request{
		Version:  VersionHTTP11,
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
	}
	if alloc != nil {
		r.SetAllocator(alloc)
	}
}

func (r *Request) Init(method Method, rawURL string) error {
	r.Method = method
	r.Version = VersionHTTP11
	if err := r.URI.ParseString(rawURL); err != nil {
		return err
	}
	if len(r.URI.Host) > 0 {
		r.Headers.Set(HeaderHost, r.URI.Host)
	}
	return nil
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
