// Package http1 provides HTTP/1.x encoding and parsing helpers.
package http1

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"sync"

	"github.com/dnsoa/net/httpx/core"
	rootprotocol "github.com/dnsoa/net/httpx/protocol"
)

const maxTrailerLineBytes = 8 * 1024

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
	body, err := req.ReadAll()
	if err != nil {
		return err
	}
	c.keepAlive = req.Headers.IsKeepAlive(req.Version)
	if cap(c.writeBuf) < 512+len(body) {
		c.writeBuf = make([]byte, 0, 512+len(body))
	}
	c.writeBuf = FormatRequest(req, body, c.writeBuf[:0])
	_, err = c.writer.Write(c.writeBuf)
	return err
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
	c.keepAlive = resp.Headers.IsKeepAlive(resp.Version)

	contentLength := p.ContentLength()
	isChunked := p.IsChunked()
	bufferedBody := p.DrainBodyBuffer()

	if isChunked {
		bodyReader := c.newChunkedBodyReader(p, resp, bufferedBody)
		return resp, bodyReader, nil
	}

	rootprotocol.ReleaseParser(p)

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
	pr, pw := io.Pipe()
	p.SetBodyWriter(pw)
	bodyReader := &chunkedBodyReader{
		reader: pr,
	}
	if closer, ok := c.reader.(io.Closer); ok {
		bodyReader.sourceCloser = closer
	}

	go func() {
		defer rootprotocol.ReleaseParser(p)
		defer bodyReader.markCompleted()
		for !p.Complete() {
			data, err := c.readNextChunk()
			if len(data) > 0 {
				consumed, feedErr := p.Feed(data)
				if consumed < len(data) {
					c.unread(data[consumed:])
				}
				if feedErr != nil {
					_ = pw.CloseWithError(feedErr)
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					p.FinishEOF()
					if p.Complete() {
						break
					}
				}
				_ = pw.CloseWithError(err)
				return
			}
		}
		if err := c.consumeTrailerSection(&resp.Trailers); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	if len(bufferedBody) == 0 {
		return bodyReader
	}
	bodyReader.prefix = bytes.NewReader(bufferedBody)
	return bodyReader
}

type chunkedBodyReader struct {
	prefix        io.Reader
	reader        *io.PipeReader
	sourceCloser  io.Closer
	completed     bool
	closeOnce     sync.Once
	completeMutex sync.Mutex
}

func (r *chunkedBodyReader) Read(p []byte) (int, error) {
	if r.prefix != nil {
		n, err := r.prefix.Read(p)
		if errors.Is(err, io.EOF) {
			r.prefix = nil
			if n > 0 {
				return n, nil
			}
		} else {
			return n, err
		}
	}
	return r.reader.Read(p)
}

func (r *chunkedBodyReader) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.completeMutex.Lock()
		completed := r.completed
		r.completeMutex.Unlock()
		if !completed && r.sourceCloser != nil {
			_ = r.sourceCloser.Close()
		}
		err = r.reader.Close()
	})
	return err
}

func (r *chunkedBodyReader) markCompleted() {
	r.completeMutex.Lock()
	r.completed = true
	r.completeMutex.Unlock()
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
		return nil, errors.New("http1 message incomplete")
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
