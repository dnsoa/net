package core

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/dnsoa/go/allocator"
	gosync "github.com/dnsoa/go/sync"
)

type Response struct {
	Version       Version
	Status        Status
	Headers       Headers
	Trailers      Headers
	Body          io.ReadCloser
	ContentLength int64
	alloc         *allocator.Allocator
}

var responsePool = gosync.NewPool(func() *Response {
	return &Response{
		Version:  VersionHTTP11,
		Status:   NewStatus(200),
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
	}
})

func AcquireResponse() *Response {
	resp := responsePool.Get()
	resp.Reset()
	return resp
}

func ReleaseResponse(resp *Response) {
	if resp == nil {
		return
	}
	responsePool.Put(resp)
}

func (r *Response) SetAllocator(alloc *allocator.Allocator) {
	r.alloc = alloc
	r.Headers.SetAllocator(alloc)
	r.Trailers.SetAllocator(alloc)
}

func (r *Response) Reset() {
	alloc := r.alloc
	r.Headers.Reset()
	r.Trailers.Reset()
	if r.Body != nil {
		r.Body.Close()
		r.Body = nil
	}
	*r = Response{
		Version:  VersionHTTP11,
		Status:   NewStatus(200),
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
	}
	if alloc != nil {
		r.SetAllocator(alloc)
	}
}

// SetBody sets the response body. The caller is responsible for setting
// ContentLength and Content-Length header when the size is known.
func (r *Response) SetBody(body io.ReadCloser) {
	if r.Body != nil {
		r.Body.Close()
	}
	r.Body = body
}

func (r *Response) SetJSONBody(v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.Headers.Set(HeaderContentType, []byte("application/json"))
	r.ContentLength = int64(len(encoded))
	r.Headers.Set(HeaderContentLength, AppendInt(nil, len(encoded)))
	r.SetBody(io.NopCloser(bytes.NewReader(encoded)))
	return nil
}

func (r *Response) ReadAll() ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func (r *Response) OK() bool {
	return r.Status.IsSuccess()
}
