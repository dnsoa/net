package http1

import (
	"errors"
	"io"
	"strconv"

	"github.com/dnsoa/net/httpx/core"
	rootprotocol "github.com/dnsoa/net/httpx/protocol"
)

type Conn struct {
	reader         io.Reader
	writer         io.Writer
	pool           *core.BytePool
	readBuf        []byte
	maxMessageSize int
	keepAlive      bool
}

func NewConn(reader io.Reader, writer io.Writer) *Conn {
	pool := core.DefaultBytePool
	return &Conn{
		reader:         reader,
		writer:         writer,
		pool:           pool,
		readBuf:        pool.Get(16 * 1024),
		maxMessageSize: 100 * 1024 * 1024,
		keepAlive:      true,
	}
}

func (c *Conn) Close() {
	if c.pool != nil {
		c.pool.Put(c.readBuf)
	}
	c.readBuf = nil
}

func FormatRequest(req *core.Request, dst []byte) []byte {
	if req.Headers.IsChunked() {
		return formatChunkedRequest(req, dst)
	}
	ensureRequestContentLength(req)
	return req.Serialize(dst)
}

func FormatResponse(resp *core.Response, dst []byte) []byte {
	if resp.Headers.IsChunked() {
		return formatChunkedResponse(resp, dst)
	}
	ensureResponseContentLength(resp)
	return resp.Serialize(dst)
}

func (c *Conn) WriteRequest(req *core.Request) error {
	if c.writer == nil {
		return errors.New("http1 writer is nil")
	}
	buf := c.pool.GetEmpty(512 + len(req.Body))
	defer c.pool.Put(buf)
	buf = FormatRequest(req, buf)
	c.keepAlive = req.Headers.IsKeepAlive(req.Version)
	_, err := c.writer.Write(buf)
	return err
}

func (c *Conn) WriteResponse(resp *core.Response) error {
	if c.writer == nil {
		return errors.New("http1 writer is nil")
	}
	buf := c.pool.GetEmpty(512 + len(resp.Body))
	defer c.pool.Put(buf)
	buf = FormatResponse(resp, buf)
	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)
	_, err := c.writer.Write(buf)
	return err
}

func (c *Conn) ReadRequest() (*core.Request, error) {
	msg, err := c.readMessage(rootprotocol.ParserModeRequest)
	if err != nil {
		return nil, err
	}
	req := msg.(*core.Request)
	c.keepAlive = req.Headers.IsKeepAlive(req.Version)
	return req, nil
}

func (c *Conn) ReadResponse() (*core.Response, error) {
	msg, err := c.readMessage(rootprotocol.ParserModeResponse)
	if err != nil {
		return nil, err
	}
	resp := msg.(*core.Response)
	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)
	return resp, nil
}

func (c *Conn) ShouldKeepAlive() bool {
	return c.keepAlive
}

// ReadStreamResponse reads only the response headers from the connection.
// It returns a partially filled Response (Version, Status, Headers populated, Body is nil)
// and an io.Reader that provides direct access to the remaining body data on the connection.
// The caller must read the body to completion before returning the connection to the pool.
func (c *Conn) ReadStreamResponse() (*core.Response, io.Reader, error) {
	if c.reader == nil {
		return nil, nil, errors.New("http1 reader is nil")
	}

	p := rootprotocol.AcquireParser(rootprotocol.ParserModeResponse)

	// Read until headers are complete
	totalRead := 0
	for !p.HeaderComplete() && !p.Complete() {
		n, err := c.reader.Read(c.readBuf)
		if n > 0 {
			totalRead += n
			if totalRead > c.maxMessageSize {
				rootprotocol.ReleaseParser(p)
				return nil, nil, errors.New("http1 message too large")
			}
			if _, feedErr := p.Feed(c.readBuf[:n]); feedErr != nil {
				rootprotocol.ReleaseParser(p)
				return nil, nil, feedErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				p.FinishEOF()
				break
			}
			rootprotocol.ReleaseParser(p)
			return nil, nil, err
		}
	}

	// Build response from headers only
	resp := core.AcquireResponse()
	resp.Version = p.Version
	resp.Status = core.NewStatus(p.StatusCode)
	resp.Headers = p.Headers
	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)

	contentLength := p.ContentLength()
	isChunked := p.IsChunked()

	rootprotocol.ReleaseParser(p)

	// Create a limited reader for body based on content-length or chunked encoding
	var bodyReader io.Reader = c.reader
	if contentLength > 0 {
		bodyReader = io.LimitReader(c.reader, int64(contentLength))
	}
	// Note: for chunked encoding, the caller must handle chunk decoding

	_ = isChunked // TODO: add chunked reader support when needed

	return resp, bodyReader, nil
}

// WriteResponseHead writes only the HTTP response status line and headers
// to the connection. It returns an io.Writer that the caller can use
// to write body data directly.
func (c *Conn) WriteResponseHead(resp *core.Response) (io.Writer, error) {
	if c.writer == nil {
		return nil, errors.New("http1 writer is nil")
	}

	// Format and write status line + headers only (no body)
	buf := make([]byte, 0, 512)
	buf = append(buf, resp.Version.String()...)
	buf = append(buf, ' ')
	buf = strconv.AppendInt(buf, int64(resp.Status.Code), 10)
	buf = append(buf, ' ')
	buf = append(buf, resp.Status.Phrase()...)
	buf = append(buf, '\r', '\n')
	buf = resp.Headers.Serialize(buf)
	buf = append(buf, '\r', '\n')

	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)

	if _, err := c.writer.Write(buf); err != nil {
		return nil, err
	}

	return c.writer, nil
}

func (c *Conn) readMessage(mode rootprotocol.ParserMode) (any, error) {
	if c.reader == nil {
		return nil, errors.New("http1 reader is nil")
	}
	p := rootprotocol.AcquireParser(mode)
	defer rootprotocol.ReleaseParser(p)

	totalRead := 0
	for !p.Complete() {
		n, err := c.reader.Read(c.readBuf)
		if n > 0 {
			totalRead += n
			if totalRead > c.maxMessageSize {
				return nil, errors.New("http1 message too large")
			}
			if _, feedErr := p.Feed(c.readBuf[:n]); feedErr != nil {
				return nil, feedErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				p.FinishEOF()
				break
			}
			return nil, err
		}
	}

	if !p.Complete() {
		return nil, errors.New("http1 message incomplete")
	}

	if mode == rootprotocol.ParserModeRequest {
		return p.BuildRequest()
	}
	return p.BuildResponse()
}

func ensureRequestContentLength(req *core.Request) {
	if req.Headers.Get("Content-Length") != nil || req.Headers.IsChunked() {
		return
	}
	if len(req.Body) == 0 {
		return
	}
	req.Headers.Set(core.HeaderContentLength, []byte(strconv.Itoa(len(req.Body))))
}

func ensureResponseContentLength(resp *core.Response) {
	if resp.Headers.Get("Content-Length") != nil || resp.Headers.IsChunked() {
		return
	}
	if !resp.Status.MayHaveBody() {
		return
	}
	resp.Headers.Set(core.HeaderContentLength, []byte(strconv.Itoa(len(resp.Body))))
}

func formatChunkedRequest(req *core.Request, dst []byte) []byte {
	req.Headers.RemoveAll(core.HeaderContentLength)
	ensureTrailerDeclaration(&req.Headers, &req.Trailers)
	dst = append(dst, req.Method.String()...)
	dst = append(dst, ' ')
	dst = req.URI.RequestTarget(dst)
	dst = append(dst, ' ')
	dst = append(dst, req.Version.String()...)
	dst = append(dst, '\r', '\n')
	dst = req.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	dst = appendChunkedBody(dst, req.Body, &req.Trailers)
	return dst
}

func formatChunkedResponse(resp *core.Response, dst []byte) []byte {
	resp.Headers.RemoveAll(core.HeaderContentLength)
	ensureTrailerDeclaration(&resp.Headers, &resp.Trailers)
	dst = append(dst, resp.Version.String()...)
	dst = append(dst, ' ')
	dst = strconv.AppendInt(dst, int64(resp.Status.Code), 10)
	dst = append(dst, ' ')
	dst = append(dst, resp.Status.Phrase()...)
	dst = append(dst, '\r', '\n')
	dst = resp.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	dst = appendChunkedBody(dst, resp.Body, &resp.Trailers)
	return dst
}

func appendChunkedBody(dst, body []byte, trailers *core.Headers) []byte {
	if len(body) == 0 && (trailers == nil || trailers.Count() == 0) {
		return append(dst, '0', '\r', '\n', '\r', '\n')
	}
	chunkSize := 4096
	for offset := 0; offset < len(body); {
		length := len(body) - offset
		if length > chunkSize {
			length = chunkSize
		}
		dst = strconv.AppendInt(dst, int64(length), 16)
		dst = append(dst, '\r', '\n')
		dst = append(dst, body[offset:offset+length]...)
		dst = append(dst, '\r', '\n')
		offset += length
	}
	dst = append(dst, '0', '\r', '\n')
	if trailers != nil && trailers.Count() > 0 {
		dst = trailers.Serialize(dst)
	}
	dst = append(dst, '\r', '\n')
	return dst
}

func ensureTrailerDeclaration(headers, trailers *core.Headers) {
	if trailers == nil || trailers.Count() == 0 {
		return
	}
	if headers.Get("Trailer") != nil {
		return
	}
	entries := trailers.Entries()
	decl := make([]byte, 0, len(entries)*16)
	for idx, entry := range entries {
		if idx > 0 {
			decl = append(decl, ',', ' ')
		}
		decl = append(decl, entry.Name...)
	}
	headers.Set([]byte("Trailer"), decl)
}
