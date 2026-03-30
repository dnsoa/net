// Package protocol provides HTTP message parsing primitives.
package protocol

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"sync"

	"github.com/dnsoa/net/httpx/core"
)

type ParserMode uint8

const (
	ParserModeRequest ParserMode = iota
	ParserModeResponse
)

type parserState uint8

const (
	parserStateStartLine parserState = iota
	parserStateHeaders
	parserStateBody
	parserStateChunkSize
	parserStateChunkData
	parserStateChunkCRLF
	parserStateComplete
	parserStateError
)

type Parser struct {
	Mode            ParserMode
	state           parserState
	Version         core.Version
	Method          core.Method
	StatusCode      int
	target          []byte
	Headers         core.Headers
	body            []byte
	line            []byte
	contentLength   int
	chunked         bool
	currentChunkLen int
	bodyRead        int
	Err             error
	maxHeaderBytes  int
	bodyWriter      io.Writer
}

var parserPool = sync.Pool{
	New: func() any {
		return &Parser{
			Headers:        core.NewHeaders(),
			maxHeaderBytes: 8192,
			state:          parserStateStartLine,
		}
	},
}

func AcquireParser(mode ParserMode) *Parser {
	p := parserPool.Get().(*Parser)
	p.Reset(mode)
	return p
}

func ReleaseParser(p *Parser) {
	if p == nil {
		return
	}
	p.Reset(p.Mode)
	parserPool.Put(p)
}

func (p *Parser) Reset(mode ParserMode) {
	p.Headers.Reset()
	*p = Parser{
		Mode:           mode,
		state:          parserStateStartLine,
		Version:        core.VersionHTTP11,
		Headers:        p.Headers,
		maxHeaderBytes: 8192,
	}
}

func (p *Parser) Complete() bool {
	return p.state == parserStateComplete
}

func (p *Parser) HeaderComplete() bool {
	return p.state >= parserStateBody
}

func (p *Parser) SetBodyWriter(w io.Writer) {
	p.bodyWriter = w
}

func (p *Parser) ContentLength() int {
	return p.contentLength
}

func (p *Parser) IsChunked() bool {
	return p.chunked
}

func (p *Parser) DrainBodyBuffer() []byte {
	if len(p.body) == 0 {
		return nil
	}
	body := append([]byte(nil), p.body...)
	p.body = nil
	return body
}

func (p *Parser) Feed(data []byte) (int, error) {
	consumed := 0
	for consumed < len(data) && p.state != parserStateComplete && p.state != parserStateError {
		switch p.state {
		case parserStateStartLine:
			n, line, ok, err := p.readLine(data[consumed:])
			consumed += n
			if err != nil {
				return consumed, p.fail(err)
			}
			if !ok {
				return consumed, nil
			}
			if err := p.parseStartLine(line); err != nil {
				return consumed, p.fail(err)
			}
			p.state = parserStateHeaders
		case parserStateHeaders:
			n, line, ok, err := p.readLine(data[consumed:])
			consumed += n
			if err != nil {
				return consumed, p.fail(err)
			}
			if !ok {
				return consumed, nil
			}
			if len(line) == 0 {
				p.decideBodyState()
				continue
			}
			if err := p.parseHeader(line); err != nil {
				return consumed, p.fail(err)
			}
		case parserStateBody:
			need := p.contentLength - p.bodyRead
			if p.contentLength == 0 {
				if p.bodyWriter != nil {
					if len(data[consumed:]) > 0 {
						p.bodyWriter.Write(data[consumed:])
					}
				} else {
					p.body = append(p.body, data[consumed:]...)
				}
				consumed = len(data)
				return consumed, nil
			}
			if need <= 0 {
				p.state = parserStateComplete
				continue
			}
			if need > len(data)-consumed {
				need = len(data) - consumed
			}
			if p.bodyWriter != nil {
				p.bodyWriter.Write(data[consumed : consumed+need])
			} else {
				p.body = append(p.body, data[consumed:consumed+need]...)
			}
			consumed += need
			p.bodyRead += need
			if p.bodyRead == p.contentLength {
				p.state = parserStateComplete
			}
		case parserStateChunkSize:
			n, line, ok, err := p.readLine(data[consumed:])
			consumed += n
			if err != nil {
				return consumed, p.fail(err)
			}
			if !ok {
				return consumed, nil
			}
			semi := bytes.IndexByte(line, ';')
			if semi >= 0 {
				line = line[:semi]
			}
			size, err := strconv.ParseInt(string(bytes.TrimSpace(line)), 16, 64)
			if err != nil {
				return consumed, p.fail(err)
			}
			p.currentChunkLen = int(size)
			if p.currentChunkLen == 0 {
				p.state = parserStateComplete
				continue
			}
			p.state = parserStateChunkData
		case parserStateChunkData:
			need := p.currentChunkLen
			if need > len(data)-consumed {
				need = len(data) - consumed
			}
			if p.bodyWriter != nil {
				p.bodyWriter.Write(data[consumed : consumed+need])
			} else {
				p.body = append(p.body, data[consumed:consumed+need]...)
			}
			consumed += need
			p.currentChunkLen -= need
			if p.currentChunkLen == 0 {
				p.state = parserStateChunkCRLF
			}
		case parserStateChunkCRLF:
			if len(data)-consumed < 2 {
				return consumed, nil
			}
			if data[consumed] != '\r' || data[consumed+1] != '\n' {
				return consumed, p.fail(errors.New("invalid chunk terminator"))
			}
			consumed += 2
			p.state = parserStateChunkSize
		}
	}
	return consumed, p.Err
}

func (p *Parser) FinishEOF() {
	if p.state == parserStateBody && p.Mode == ParserModeResponse && p.contentLength == 0 && !p.chunked {
		p.state = parserStateComplete
	}
}

func (p *Parser) BuildRequest() (*core.Request, error) {
	if p.Mode != ParserModeRequest || !p.Complete() {
		return nil, errors.New("request parser incomplete")
	}
	req := core.AcquireRequest()
	req.Method = p.Method
	req.Version = p.Version
	req.Headers = p.Headers
	p.Headers = core.NewHeaders()
	if err := req.URI.ParseOwned(p.target); err != nil {
		core.ReleaseRequest(req)
		return nil, err
	}
	p.target = nil
	body := p.body
	p.body = nil
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return req, nil
}

func (p *Parser) BuildResponse() (*core.Response, error) {
	if p.Mode != ParserModeResponse || !p.Complete() {
		return nil, errors.New("response parser incomplete")
	}
	resp := core.AcquireResponse()
	resp.Version = p.Version
	resp.Status = core.NewStatus(p.StatusCode)
	resp.Headers = p.Headers
	p.Headers = core.NewHeaders()
	body := p.body
	p.body = nil
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func (p *Parser) parseStartLine(line []byte) error {
	parts := bytes.SplitN(line, []byte{' '}, 3)
	if len(parts) < 3 {
		return errors.New("invalid start line")
	}
	if p.Mode == ParserModeRequest {
		method, ok := core.ParseMethodBytes(parts[0])
		if ok {
			p.Method = method
		} else {
			p.Method = core.MethodCustom
		}
		version, ok := core.ParseVersionBytes(parts[2])
		if !ok {
			return errors.New("invalid http version")
		}
		p.Version = version
		p.target = make([]byte, len(parts[1]))
		copy(p.target, parts[1])
		return nil
	}
	version, ok := core.ParseVersionBytes(parts[0])
	if !ok {
		return errors.New("invalid http version")
	}
	p.Version = version
	statusCode, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return err
	}
	p.StatusCode = statusCode
	return nil
}

func (p *Parser) parseHeader(line []byte) error {
	sep := bytes.IndexByte(line, ':')
	if sep <= 0 {
		return errors.New("invalid header")
	}
	name := bytes.TrimSpace(line[:sep])
	value := bytes.TrimSpace(line[sep+1:])
	p.Headers.Append(name, value)
	if bytes.EqualFold(name, core.HeaderContentLength) {
		if n, err := strconv.Atoi(string(value)); err == nil {
			p.contentLength = n
		}
	} else if bytes.EqualFold(name, core.HeaderTransferEncoding) {
		p.chunked = bytes.Contains(bytes.ToLower(value), []byte("chunked"))
	}
	return nil
}

func (p *Parser) decideBodyState() {
	if p.chunked {
		p.state = parserStateChunkSize
		return
	}
	if p.contentLength > 0 {
		p.state = parserStateBody
		return
	}
	if p.Mode == ParserModeResponse {
		p.state = parserStateBody
		return
	}
	p.state = parserStateComplete
}

func (p *Parser) readLine(data []byte) (int, []byte, bool, error) {
	if idx := bytes.Index(data, []byte("\r\n")); idx >= 0 {
		if len(p.line) == 0 {
			return idx + 2, data[:idx], true, nil
		}
		p.line = append(p.line, data[:idx]...)
		line := p.line
		p.line = nil
		return idx + 2, line, true, nil
	}
	if len(p.line)+len(data) > p.maxHeaderBytes {
		return len(data), nil, false, errors.New("line too large")
	}
	p.line = append(p.line, data...)
	return len(data), nil, false, nil
}

func (p *Parser) fail(err error) error {
	p.state = parserStateError
	p.Err = err
	return err
}
