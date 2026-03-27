package upstream

import (
	"errors"

	"github.com/dnsoa/net/httpx/core"
	protohttp1 "github.com/dnsoa/net/httpx/protocol/http1"
	protohttp2 "github.com/dnsoa/net/httpx/protocol/http2"
	protohttp3 "github.com/dnsoa/net/httpx/protocol/http3"
)

type Transport interface {
	RoundTrip(req *core.Request) (*core.Response, error)
}

type HTTP1Transport struct {
	conn *protohttp1.Conn
}

func NewHTTP1Transport(conn *protohttp1.Conn) *HTTP1Transport {
	return &HTTP1Transport{conn: conn}
}

func (t *HTTP1Transport) RoundTrip(req *core.Request) (*core.Response, error) {
	if t.conn == nil {
		return nil, errors.New("http1 upstream transport is nil")
	}
	if err := t.conn.WriteRequest(req); err != nil {
		return nil, err
	}
	return t.conn.ReadResponse()
}

type HTTP2Transport struct {
	session *protohttp2.Session
}

func NewHTTP2Transport(session *protohttp2.Session) *HTTP2Transport {
	return &HTTP2Transport{session: session}
}

func (t *HTTP2Transport) RoundTrip(req *core.Request) (*core.Response, error) {
	if t.session == nil {
		return nil, errors.New("http2 upstream transport is nil")
	}
	streamID, err := t.session.WriteRequest(req)
	if err != nil {
		return nil, err
	}
	respStreamID, resp, err := t.session.ReadResponse()
	if err != nil {
		return nil, err
	}
	if respStreamID != streamID {
		core.ReleaseResponse(resp)
		return nil, errors.New("http2 response stream mismatch")
	}
	return resp, nil
}

type HTTP3Transport struct {
	transport *protohttp3.Transport
}

func NewHTTP3Transport(transport *protohttp3.Transport) *HTTP3Transport {
	return &HTTP3Transport{transport: transport}
}

func (t *HTTP3Transport) RoundTrip(req *core.Request) (*core.Response, error) {
	if t.transport == nil {
		return nil, errors.New("http3 upstream transport is nil")
	}
	return t.transport.RoundTrip(req)
}
