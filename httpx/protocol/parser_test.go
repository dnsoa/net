package protocol

import (
	"io"
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

func TestParserRequestIncremental(t *testing.T) {
	p := AcquireParser(ParserModeRequest)
	defer ReleaseParser(p)
	chunks := [][]byte{
		[]byte("GET /search?q=zig HTTP/1.1\r\nHost: exa"),
		[]byte("mple.com\r\nContent-Length: 5\r\n\r\nhello"),
	}
	for _, chunk := range chunks {
		if _, err := p.Feed(chunk); err != nil {
			t.Fatalf("feed parser: %v", err)
		}
	}
	if !p.Complete() {
		t.Fatal("parser did not complete")
	}
	req, err := p.BuildRequest()
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	defer core.ReleaseRequest(req)
	if string(req.URI.Path) != "/search" {
		t.Fatalf("unexpected path %q", req.URI.Path)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected body %q", body)
	}
}

func TestParserResponseChunked(t *testing.T) {
	p := AcquireParser(ParserModeResponse)
	defer ReleaseParser(p)
	payload := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
	if _, err := p.Feed(payload); err != nil {
		t.Fatalf("feed parser: %v", err)
	}
	if !p.Complete() {
		t.Fatal("parser did not complete")
	}
	resp, err := p.BuildResponse()
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	defer core.ReleaseResponse(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected body %q", body)
	}
}
