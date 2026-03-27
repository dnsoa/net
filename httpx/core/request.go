package core

import "encoding/json"

type Request struct {
	Method       Method
	Version      Version
	URI          URI
	Headers      Headers
	Trailers     Headers
	Body         []byte
	bodyExternal bool
	pool         *BytePool
}

var requestPool = SyncPool[*Request]{new: func() *Request {
	return &Request{
		Version:  VersionHTTP11,
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
		pool:     DefaultBytePool,
	}
}}

func AcquireRequest() *Request {
	req := requestPool.Get()
	req.Reset()
	return req
}

func ReleaseRequest(req *Request) {
	if req == nil {
		return
	}
	req.Reset()
	requestPool.Put(req)
}

func (r *Request) Reset() {
	pool := r.pool
	if pool == nil {
		pool = DefaultBytePool
	}
	r.Headers.Reset()
	r.Trailers.Reset()
	r.URI.Reset()
	if !r.bodyExternal {
		pool.Put(r.Body)
	}
	*r = Request{
		Version:  VersionHTTP11,
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
		pool:     pool,
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

func (r *Request) SetBody(body []byte) {
	if !r.bodyExternal {
		r.pool.Put(r.Body)
	}
	owned := r.pool.GetEmpty(len(body))
	owned = append(owned, body...)
	r.Body = owned
	r.bodyExternal = false
	r.Headers.Set(HeaderContentLength, AppendInt(nil, len(body)))
}

func (r *Request) SetOwnedBody(body []byte) {
	if !r.bodyExternal {
		r.pool.Put(r.Body)
	}
	r.Body = body
	r.bodyExternal = false
	r.Headers.Set(HeaderContentLength, AppendInt(nil, len(body)))
}

func (r *Request) SetJSONBody(v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.Headers.Set(HeaderContentType, []byte("application/json"))
	r.SetBody(encoded)
	return nil
}

func (r *Request) Serialize(dst []byte) []byte {
	dst = append(dst, r.Method.String()...)
	dst = append(dst, ' ')
	dst = r.URI.RequestTarget(dst)
	dst = append(dst, ' ')
	dst = append(dst, r.Version.String()...)
	dst = append(dst, '\r', '\n')
	dst = r.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	dst = append(dst, r.Body...)
	return dst
}
