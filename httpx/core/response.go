package core

import (
	"io"

	gosync "github.com/dnsoa/go/sync"
)

type Response struct {
	Version       Version
	Status        Status
	Headers       Headers
	Trailers      Headers
	Body          io.ReadCloser
	ContentLength int64
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

func (r *Response) Reset() {
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
}

// SetBody sets the response body. The caller is responsible for setting
// ContentLength and Content-Length header when the size is known.
func (r *Response) SetBody(body io.ReadCloser) {
	if r.Body != nil {
		r.Body.Close()
	}
	r.Body = body
}

func (r *Response) ReadAll() ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}
