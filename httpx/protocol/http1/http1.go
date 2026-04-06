// Package http1 provides HTTP/1.x encoding and parsing helpers.
package http1

import (
	"bytes"
	"errors"
	"io"
	"strconv"

	"github.com/dnsoa/net/httpx/core"
	rootprotocol "github.com/dnsoa/net/httpx/protocol"
)

const maxTrailerLineBytes = 8 * 1024

// ErrMessageIncomplete is returned when the HTTP/1.x parser reaches EOF
// before the message is complete (e.g. client disconnects mid-request).
var ErrMessageIncomplete = errors.New("http1 message incomplete")

type Conn struct {
	reader         io.Reader
	writer         io.Writer
	readBuf        []byte
	pending        []byte
	writeBuf       []byte
	maxMessageSize int
	keepAlive      bool
}

func NewConn(reader io.Reader, writer io.Writer) *Conn {
	return &Conn{
		reader:         reader,
		writer:         writer,
		readBuf:        make([]byte, 16*1024),
		maxMessageSize: 100 * 1024 * 1024,
		keepAlive:      true,
	}
}

func (c *Conn) Close() {
	c.readBuf = nil
	c.pending = nil
}

func FormatRequest(req *core.Request, body []byte, dst []byte) []byte {
	if req.Headers.IsChunked() {
		return formatChunkedRequest(req, body, dst)
	}
	ensureRequestContentLength(req, len(body))
	return formatRequestHead(req, dst, body)
}

func FormatResponse(resp *core.Response, body []byte, dst []byte) []byte {
	if resp.Headers.IsChunked() {
		return formatChunkedResponse(resp, body, dst)
	}
	ensureResponseContentLength(resp, len(body))
	return formatResponseHead(resp, dst, body)
}

func formatRequestHead(req *core.Request, dst []byte, body []byte) []byte {
	dst = append(dst, req.Method.String()...)
	dst = append(dst, ' ')
	dst = req.URI.RequestTarget(dst)
	dst = append(dst, ' ')
	dst = append(dst, req.Version.String()...)
	dst = append(dst, '\r', '\n')
	dst = req.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	dst = append(dst, body...)
	return dst
}

func formatResponseHead(resp *core.Response, dst []byte, body []byte) []byte {
	dst = append(dst, resp.Version.String()...)
	dst = append(dst, ' ')
	dst = core.AppendInt(dst, resp.Status.Code)
	dst = append(dst, ' ')
	dst = append(dst, resp.Status.Phrase()...)
	dst = append(dst, '\r', '\n')
	dst = resp.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	dst = append(dst, body...)
	return dst
}

func (c *Conn) WriteRequest(req *core.Request) error {
	if c.writer == nil {
		return errors.New("http1 writer is nil")
	}
	c.keepAlive = req.Headers.IsKeepAlive(req.Version)

	// Ensure framing headers are present when body exists.
	declaredTrailers := false
	if req.Body != nil && req.Headers.IsChunked() {
		req.Headers.RemoveAll(core.HeaderContentLength)
		ensureTrailerDeclaration(&req.Headers, &req.Trailers)
		declaredTrailers = req.Headers.Get("Trailer") != nil
	} else if req.Body != nil && req.ContentLength > 0 {
		ensureRequestContentLength(req, int(req.ContentLength))
	}

	// Write request line + headers (no body)
	if cap(c.writeBuf) < 512 {
		c.writeBuf = make([]byte, 0, 512)
	}
	dst := append(c.writeBuf[:0], req.Method.String()...)
	dst = append(dst, ' ')
	dst = req.URI.RequestTarget(dst)
	dst = append(dst, ' ')
	dst = append(dst, req.Version.String()...)
	dst = append(dst, '\r', '\n')
	dst = req.Headers.Serialize(dst)
	dst = append(dst, '\r', '\n')
	if _, err := c.writer.Write(dst); err != nil {
		return err
	}

	// Stream body if present
	if req.Body != nil {
		if req.Headers.IsChunked() {
			return writeChunkedBody(c.writer, req.Body, &req.Trailers, declaredTrailers)
		}
		if _, err := io.Copy(c.writer, req.Body); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) WriteResponse(resp *core.Response) error {
	if c.writer == nil {
		return errors.New("http1 writer is nil")
	}
	body, err := resp.ReadAll()
	if err != nil {
		return err
	}
	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)
	if cap(c.writeBuf) < 512+len(body) {
		c.writeBuf = make([]byte, 0, 512+len(body))
	}
	c.writeBuf = FormatResponse(resp, body, c.writeBuf[:0])
	_, err = c.writer.Write(c.writeBuf)
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

func (c *Conn) ReadStreamResponse() (*core.Response, io.Reader, error) {
	if c.reader == nil {
		return nil, nil, errors.New("http1 reader is nil")
	}

	p := rootprotocol.AcquireParser(rootprotocol.ParserModeResponse)

	totalRead := 0
	for !p.HeaderComplete() && !p.Complete() {
		data, err := c.readNextChunk()
		n := len(data)
		if n > 0 {
			totalRead += n
			if totalRead > c.maxMessageSize {
				rootprotocol.ReleaseParser(p)
				return nil, nil, errors.New("http1 message too large")
			}
			consumed, feedErr := p.Feed(data)
			if consumed < len(data) {
				c.unread(data[consumed:])
			}
			if feedErr != nil {
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

	resp := core.AcquireResponse()
	resp.Version = p.Version
	resp.Status = core.NewStatus(p.StatusCode)
	resp.Headers = p.Headers
	p.Headers = core.NewHeaders()
	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)

	contentLength := p.ContentLength()
	isChunked := p.IsChunked()
	bufferedBody := p.DrainBodyBuffer()

	if isChunked {
		bodyReader := c.newChunkedBodyReader(p, resp, bufferedBody)
		return resp, bodyReader, nil
	}

	rootprotocol.ReleaseParser(p)

	// RFC 7230 §3.3: responses with status codes 1xx, 204, and 304
	// MUST NOT have a body. Return an empty reader immediately to avoid
	// blocking on a keep-alive connection waiting for EOF that never comes.
	if !resp.Status.MayHaveBody() {
		return resp, bytes.NewReader(nil), nil
	}

	var bodyReader io.Reader = bytes.NewReader(bufferedBody)
	if contentLength > len(bufferedBody) {
		bodyReader = io.MultiReader(bodyReader, io.LimitReader(c.reader, int64(contentLength-len(bufferedBody))))
	} else if contentLength == 0 {
		// HTTP/1.x responses without Content-Length or chunked framing are EOF-delimited.
		bodyReader = io.MultiReader(bodyReader, c.reader)
	}

	return resp, bodyReader, nil
}

func (c *Conn) newChunkedBodyReader(p *rootprotocol.Parser, resp *core.Response, bufferedBody []byte) io.Reader {
	return &chunkedBodyReader{
		conn:     c,
		p:        p,
		resp:     resp,
		buffered: bufferedBody,
	}
}

type chunkedBodyReader struct {
	conn           *Conn
	p              *rootprotocol.Parser
	resp           *core.Response
	buffered       []byte
	bufferedOffset int
	trailersDone   bool
	released       bool
	terminalErr    error
}

func (r *chunkedBodyReader) Read(p []byte) (int, error) {
	if r.released {
		if r.terminalErr != nil {
			return 0, r.terminalErr
		}
		return 0, io.EOF
	}

	// 先从已缓冲的数据读取
	if r.bufferedOffset < len(r.buffered) {
		n := copy(p, r.buffered[r.bufferedOffset:])
		r.bufferedOffset += n
		return n, nil
	}

	// 从连接读取并解析
	for {
		if r.p.Complete() {
			return r.finishRead()
		}

		data, err := r.conn.readNextChunk()
		if len(data) > 0 {
			consumed, feedErr := r.p.Feed(data)
			if consumed < len(data) {
				r.conn.unread(data[consumed:])
			}
			if feedErr != nil {
				r.releaseParser(feedErr)
				return 0, feedErr
			}
			// 检查是否有解码后的数据
			r.buffered = r.p.DrainBodyBuffer()
			r.bufferedOffset = 0
			if len(r.buffered) > 0 {
				n := copy(p, r.buffered)
				r.bufferedOffset = n
				return n, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				r.p.FinishEOF()
				if r.p.Complete() {
					return r.finishRead()
				}
			}
			r.releaseParser(err)
			return 0, err
		}
	}
}

func (r *chunkedBodyReader) Close() error {
	r.releaseParser(nil)
	return nil
}

func (r *chunkedBodyReader) finishRead() (int, error) {
	if !r.trailersDone {
		r.trailersDone = true
		if err := r.conn.consumeTrailerSection(&r.resp.Trailers); err != nil {
			r.releaseParser(err)
			return 0, err
		}
	}
	r.releaseParser(io.EOF)
	return 0, io.EOF
}

func (r *chunkedBodyReader) releaseParser(err error) {
	if r.released {
		return
	}
	if err != nil {
		r.terminalErr = err
	}
	if r.p != nil {
		rootprotocol.ReleaseParser(r.p)
		r.p = nil
	}
	r.released = true
}

func (c *Conn) WriteResponseHead(resp *core.Response) (io.Writer, error) {
	if c.writer == nil {
		return nil, errors.New("http1 writer is nil")
	}

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
		data, err := c.readNextChunk()
		n := len(data)
		if n > 0 {
			totalRead += n
			if totalRead > c.maxMessageSize {
				return nil, errors.New("http1 message too large")
			}
			consumed, feedErr := p.Feed(data)
			if consumed < len(data) {
				c.unread(data[consumed:])
			}
			if feedErr != nil {
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
		return nil, ErrMessageIncomplete
	}

	if mode == rootprotocol.ParserModeRequest {
		return p.BuildRequest()
	}
	return p.BuildResponse()
}

func ensureRequestContentLength(req *core.Request, bodyLen int) {
	if req.Headers.Get("Content-Length") != nil || req.Headers.IsChunked() {
		return
	}
	if bodyLen == 0 {
		return
	}
	req.Headers.Set(core.HeaderContentLength, []byte(strconv.Itoa(bodyLen)))
}

func ensureResponseContentLength(resp *core.Response, bodyLen int) {
	if resp.Headers.Get("Content-Length") != nil || resp.Headers.IsChunked() {
		return
	}
	if !resp.Status.MayHaveBody() {
		return
	}
	resp.Headers.Set(core.HeaderContentLength, []byte(strconv.Itoa(bodyLen)))
}

func formatChunkedRequest(req *core.Request, body []byte, dst []byte) []byte {
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
	dst = appendChunkedBody(dst, body, &req.Trailers)
	return dst
}

func (c *Conn) readNextChunk() ([]byte, error) {
	if len(c.pending) > 0 {
		data := c.pending
		c.pending = nil
		return data, nil
	}
	n, err := c.reader.Read(c.readBuf)
	if n == 0 {
		return nil, err
	}
	return c.readBuf[:n], err
}

func (c *Conn) unread(data []byte) {
	if len(data) == 0 {
		return
	}
	c.pending = append(c.pending[:0], data...)
}

func (c *Conn) consumeTrailerSection(trailers *core.Headers) error {
	var lineBuf []byte
	for {
		data, err := c.readNextChunk()
		if len(data) > 0 {
			if idx := bytes.Index(data, []byte("\r\n")); idx >= 0 {
				line := append(lineBuf, data[:idx]...)
				lineBuf = nil
				if idx+2 < len(data) {
					c.unread(data[idx+2:])
				}
				if len(line) > maxTrailerLineBytes {
					return errors.New("http1 trailer line too large")
				}
				if len(line) == 0 {
					return nil
				}
				if err := appendTrailerHeader(trailers, line); err != nil {
					return err
				}
				continue
			}
			lineBuf = append(lineBuf, data...)
			if len(lineBuf) > maxTrailerLineBytes {
				return errors.New("http1 trailer line too large")
			}
		}
		if err != nil {
			return err
		}
	}
}

func appendTrailerHeader(trailers *core.Headers, line []byte) error {
	sep := bytes.IndexByte(line, ':')
	if sep <= 0 {
		return errors.New("invalid trailer")
	}
	name := bytes.TrimSpace(line[:sep])
	value := bytes.TrimSpace(line[sep+1:])
	trailers.Append(name, value)
	return nil
}

func formatChunkedResponse(resp *core.Response, body []byte, dst []byte) []byte {
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
	dst = appendChunkedBody(dst, body, &resp.Trailers)
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

func writeChunkedBody(w io.Writer, body io.Reader, trailers *core.Headers, writeTrailers bool) error {
	if w == nil {
		return errors.New("http1 writer is nil")
	}
	if body == nil {
		_, err := io.WriteString(w, "0\r\n\r\n")
		return err
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, writeErr := io.WriteString(w, strconv.FormatInt(int64(n), 16)); writeErr != nil {
				return writeErr
			}
			if _, writeErr := io.WriteString(w, "\r\n"); writeErr != nil {
				return writeErr
			}
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			if _, writeErr := io.WriteString(w, "\r\n"); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}

	if _, err := io.WriteString(w, "0\r\n"); err != nil {
		return err
	}
	if writeTrailers && trailers != nil && trailers.Count() > 0 {
		if _, err := w.Write(trailers.Serialize(nil)); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
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
