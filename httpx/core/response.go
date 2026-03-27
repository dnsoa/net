package core

import "encoding/json"

type Response struct {
	Version      Version
	Status       Status
	Headers      Headers
	Trailers     Headers
	Body         []byte
	bodyExternal bool
	pool         *BytePool
}

var responsePool = SyncPool[*Response]{new: func() *Response {
	return &Response{
		Version:  VersionHTTP11,
		Status:   NewStatus(200),
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
		pool:     DefaultBytePool,
	}
}}

func AcquireResponse() *Response {
	resp := responsePool.Get()
	resp.Reset()
	return resp
}

func ReleaseResponse(resp *Response) {
	if resp == nil {
		return
	}
	resp.Reset()
	responsePool.Put(resp)
}

func (r *Response) Reset() {
	pool := r.pool
	if pool == nil {
		pool = DefaultBytePool
	}
	r.Headers.Reset()
	r.Trailers.Reset()
	if !r.bodyExternal {
		pool.Put(r.Body)
	}
	*r = Response{
		Version:  VersionHTTP11,
		Status:   NewStatus(200),
		Headers:  NewHeaders(),
		Trailers: NewHeaders(),
		pool:     pool,
	}
}

func (r *Response) SetBody(body []byte) {
	if !r.bodyExternal {
		r.pool.Put(r.Body)
	}
	owned := r.pool.GetEmpty(len(body))
	owned = append(owned, body...)
	r.Body = owned
	r.bodyExternal = false
	r.Headers.Set(HeaderContentLength, AppendInt(nil, len(body)))
}

func (r *Response) SetOwnedBody(body []byte) {
	if !r.bodyExternal {
		r.pool.Put(r.Body)
	}
	r.Body = body
	r.bodyExternal = false
	r.Headers.Set(HeaderContentLength, AppendInt(nil, len(body)))
}

func (r *Response) SetJSONBody(v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.Headers.Set(HeaderContentType, []byte("application/json"))
	r.SetBody(encoded)
	return nil
}

func (r *Response) OK() bool {
	return r.Status.IsSuccess()
}

func (r *Response) Serialize(dst []byte) []byte {
	dst = append(dst, r.Version.String()...)
	dst = append(dst, ' ')
	dst = AppendInt(dst, r.Status.Code)
	dst = append(dst, ' ')
	dst = append(dst, r.Status.Phrase()...)
	dst = append(dst, '\r', '\n')
	dst = r.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	dst = append(dst, r.Body...)
	return dst
}
