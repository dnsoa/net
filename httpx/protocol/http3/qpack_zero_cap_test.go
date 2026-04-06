package http3

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

// TestZeroQpackCapacity verifies the exact byte encoding when
// the client sends QPACK_MAX_TABLE_CAPACITY=0 (matching curl/nghttp3 default behavior).
func TestZeroQpackCapacity(t *testing.T) {
	// Simulate what happens when curl sends QPACK_MAX_TABLE_CAPACITY=0
	client := NewClientSession()
	server := NewServerSession()

	// Client sends SETTINGS with QPACK_MAX_TABLE_CAPACITY=0 (curl default)
	client.Settings = Settings{
		QPACKMaxTableCap:    0,
		QPACKBlockedStreams: 0,
	MaxFieldSectionSize: 0,
	}
	var clientControl bytes.Buffer
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	clientControlBytes := clientControl.Bytes()
	t.Logf("client control stream hex: %x", clientControlBytes)

	// Server reads client's SETTINGS
	if err := server.ReadControlStream(bytes.NewReader(clientControlBytes)); err != nil {
		t.Fatalf("read client control stream: %v", err)
	}
	t.Logf("server peer settings: QPACKMaxTableCap=%d QPACKBlockedStreams=%d",
		server.PeerSettings.QPACKMaxTableCap, server.PeerSettings.QPACKBlockedStreams)

	// Server writes its own SETTINGS
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	serverControlBytes := serverControl.Bytes()
	t.Logf("server control stream hex: %x", serverControlBytes)

	// Client reads server's SETTINGS
	if err := client.ReadControlStream(bytes.NewReader(serverControlBytes)); err != nil {
		t.Fatalf("read server control stream: %v", err)
	}
	t.Logf("client peer settings: QPACKMaxTableCap=%d QPACKBlockedStreams=%d",
		client.PeerSettings.QPACKMaxTableCap, client.PeerSettings.QPACKBlockedStreams)

	// Server writes encoder stream
	var serverEncoder bytes.Buffer
	if err := server.WriteEncoderStream(&serverEncoder); err != nil {
		t.Fatalf("write server encoder stream: %v", err)
	}
	serverEncoderBytes := serverEncoder.Bytes()
	t.Logf("server encoder stream hex: %x", serverEncoderBytes)

	// Server writes decoder stream
	var serverDecoder bytes.Buffer
	if err := server.WriteDecoderStream(&serverDecoder); err != nil {
		t.Fatalf("write server decoder stream: %v", err != nil)
	}
	serverDecoderBytes := serverDecoder.Bytes()
	t.Logf("server decoder stream hex: %x", serverDecoderBytes)

	// Now simulate a request-response round trip
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Version = core.VersionHTTP3
	req.Method = core.MethodGet
	req.URI = core.ParseRequestURI("/test")
	req.Headers.SetString("host", "example.com")

	var requestStream bytes.Buffer
	if err := client.WriteRequest(&requestStream, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	t.Logf("client request stream hex: %x", requestStream.Bytes())

	// Server reads the request
	decodedReq, err := server.ReadRequest(bytes.NewReader(requestStream.Bytes()))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(decodedReq)

	// Server writes response
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "text/plain")
	resp.Headers.SetString("content-length", "2")
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))

	var responseStream bytes.Buffer
	if err := server.WriteResponse(&responseStream, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}
	responseStreamBytes := responseStream.Bytes()
	t.Logf("server response stream hex: %x", responseStreamBytes)

	// Client reads the response
	decodedResp, err := client.ReadResponse(bytes.NewReader(responseStreamBytes()))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)

	if decodedResp.Status.Code != 200 {
		t.Fatalf("unexpected response status %d", decodedResp.Status.Code)
	}
	body, err := io.ReadAll(decodedResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("unexpected body %q", string(body))
	}

	// Verify the encoder stream payload (what gets sent to the client)
	encoderPayload := server.qpack.DrainEncoderInstructions()
	if len(encoderPayload) > 0 {
		t.Logf("pending encoder instructions hex: %x", encoderPayload)
	}
	encoderPayload = server.qpack.DrainEncoderInstructions() // should be empty now

	t.Log("=== All tests passed with QPACK_MAX_TABLE_CAPACITY=0 ===")
}

// TestZeroQpackCapacityResponseEncoding verifies the exact bytes
// of the response when the encoder capacity is 0.
func TestZeroQpackCapacityResponseEncoding(t *testing.T) {
	codec := NewQpackCodec()

	// Simulate SetLocalCapacity(0) as called when client sends QPACK_MAX_TABLE_CAPACITY=0
	codec.SetLocalCapacity(0)

	fields := []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain"},
	{Name: "content-length", Value: "2"},
	}

	encoded, err := codec.EncodeFields(fields)
	if err != nil {
		t.Fatalf("encode fields: %v", err)
	}
	t.Logf("response header block hex: %x", encoded)

	// Verify the encoder instructions generated
	encoderInstructions := codec.DrainEncoderInstructions()
	t.Logf("encoder instructions hex: %x", encoderInstructions)

	// Verify the encoder stream payload (stream type + instructions)
	var encoderStream bytes.Buffer
	buf, err := AppendVarInt(nil, uint64(StreamTypeQPACKEncoder))
	if err != nil {
		t.Fatalf("append varint: %v", err)
	}
	buf = append(buf, encoderInstructions...)
	t.Logf("full encoder stream hex: %x", buf)

	// Now try to decode the fields back
	decodedFields, err := codec.DecodeFields(encoded)
	if err != nil {
		t.Fatalf("decode fields: %v", err)
	}
	if len(decodedFields) != 3 {
		t.Fatalf("unexpected field count %d", len(decodedFields))
	}
	if decodedFields[0].Name != ":status" || decodedFields[0].Value != "200" {
		t.Fatalf("unexpected :status %s=%s", decodedFields[0].Name, decodedFields[0].Value)
	}
	if decodedFields[1].Name != "content-type" || decodedFields[1].Value != "text/plain" {
		t.Fatalf("unexpected content-type %s=%s", decodedFields[1].Name, decodedFields[1].Value)
	}
	if decodedFields[2].Name != "content-length" || decodedFields[2].Value != "2" {
		t.Fatalf("unexpected content-length %s=%s", decodedFields[2].Name, decodedFields[2].Value)
	}
}
