package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/dnsoa/net/httpx/core"
)

type testControlOpener struct {
	localWriter io.Writer
	remoteData  []byte
}

func (o testControlOpener) OpenControlStream() (io.Writer, error) {
	return o.localWriter, nil
}

func (o testControlOpener) AcceptControlStream() (io.Reader, error) {
	return bytes.NewReader(o.remoteData), nil
}

type lifecycleTestStream struct {
	streamID         uint64
	request          bytes.Buffer
	response         []byte
	readOffset       int
	blockReads       bool
	unblockRead      chan struct{}
	writeClosed      chan struct{}
	readCancelErr    error
	closeWriteCalls  atomic.Int32
	closeReadCalls   atomic.Int32
	closeCalls       atomic.Int32
	cancelReadCalls  atomic.Int32
	cancelWriteCalls atomic.Int32
	builtResponse    atomic.Bool
}

func newLifecycleTestStream(response []byte) *lifecycleTestStream {
	return &lifecycleTestStream{
		streamID:    0,
		response:    response,
		unblockRead: make(chan struct{}),
		writeClosed: make(chan struct{}),
	}
}

func (s *lifecycleTestStream) RequestStreamID() uint64 {
	return s.streamID
}

func (s *lifecycleTestStream) Write(p []byte) (int, error) {
	return s.request.Write(p)
}

func (s *lifecycleTestStream) Read(p []byte) (int, error) {
	if s.blockReads {
		<-s.unblockRead
		if s.readCancelErr != nil {
			return 0, s.readCancelErr
		}
	}
	if s.readOffset >= len(s.response) {
		return 0, io.EOF
	}
	n := copy(p, s.response[s.readOffset:])
	s.readOffset += n
	return n, nil
}

func (s *lifecycleTestStream) CloseWrite() error {
	s.closeWriteCalls.Add(1)
	select {
	case <-s.writeClosed:
	default:
		close(s.writeClosed)
	}
	return nil
}

func (s *lifecycleTestStream) CloseRead() error {
	s.closeReadCalls.Add(1)
	return nil
}

func (s *lifecycleTestStream) Close() error {
	s.closeCalls.Add(1)
	select {
	case <-s.unblockRead:
	default:
		close(s.unblockRead)
	}
	return nil
}

func (s *lifecycleTestStream) CancelRead(code ErrorCode) error {
	_ = code
	s.cancelReadCalls.Add(1)
	select {
	case <-s.unblockRead:
	default:
		close(s.unblockRead)
	}
	return nil
}

func (s *lifecycleTestStream) CancelWrite(code ErrorCode) error {
	_ = code
	s.cancelWriteCalls.Add(1)
	return nil
}

type lifecycleStreamOpener struct {
	stream *lifecycleTestStream
}

func (o lifecycleStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	return o.stream, nil
}

type incrementalQpackPipe struct {
	buf bytes.Buffer
}

func (p *incrementalQpackPipe) Write(data []byte) (int, error) {
	return p.buf.Write(data)
}

func (p *incrementalQpackPipe) Read(data []byte) (int, error) {
	return p.buf.Read(data)
}

func (p *incrementalQpackPipe) ReadQPACKChunk() ([]byte, error) {
	if p.buf.Len() == 0 {
		return nil, nil
	}
	out := append([]byte(nil), p.buf.Bytes()...)
	p.buf.Reset()
	return out, nil
}

func (p *incrementalQpackPipe) Len() int {
	return p.buf.Len()
}

func (p *incrementalQpackPipe) Reset() {
	p.buf.Reset()
}

type scriptedQpackReader struct {
	chunks [][]byte
	index  int
}

func (r *scriptedQpackReader) ReadQPACKChunk() ([]byte, error) {
	if r.index >= len(r.chunks) {
		return nil, nil
	}
	chunk := append([]byte(nil), r.chunks[r.index]...)
	r.index++
	return chunk, nil
}

func (r *scriptedQpackReader) Read(data []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	if len(chunk) == 0 {
		r.index++
		return 0, io.EOF
	}
	n := copy(data, chunk)
	r.chunks[r.index] = r.chunks[r.index][n:]
	if len(r.chunks[r.index]) == 0 {
		r.index++
	}
	return n, nil
}

type qpackLoopbackOpener struct {
	clientToServerEncoder incrementalQpackPipe
	serverToClientEncoder incrementalQpackPipe
	clientToServerDecoder incrementalQpackPipe
	serverToClientDecoder incrementalQpackPipe
	serverControl         []byte
	clientControl         bytes.Buffer
	openEncoderCalls      atomic.Int32
	acceptEncoderCalls    atomic.Int32
	openDecoderCalls      atomic.Int32
	acceptDecoderCalls    atomic.Int32
}

type cancelTrackingRequestStream struct {
	memoryStream
	cancelReadCalls  atomic.Int32
	cancelWriteCalls atomic.Int32
	lastCancelCode   ErrorCode
	lastWriteCode    ErrorCode
}

func (s *cancelTrackingRequestStream) CancelRead(code ErrorCode) error {
	s.lastCancelCode = code
	s.cancelReadCalls.Add(1)
	return nil
}

func (s *cancelTrackingRequestStream) CancelWrite(code ErrorCode) error {
	s.lastWriteCode = code
	s.cancelWriteCalls.Add(1)
	return s.memoryStream.CancelWrite(code)
}

type cancelTrackingPacketAssembler struct {
	stream       *cancelTrackingRequestStream
	localControl bytes.Buffer
	localEncoder bytes.Buffer
	localDecoder bytes.Buffer
}

func (a *cancelTrackingPacketAssembler) OpenControlStream() (io.Writer, error) {
	a.localControl.Reset()
	return &a.localControl, nil
}

func (a *cancelTrackingPacketAssembler) AcceptControlStream() (io.Reader, error) {
	return bytes.NewReader(nil), nil
}

func (a *cancelTrackingPacketAssembler) OpenRequestStream() (io.ReadWriter, error) {
	if a.stream == nil {
		a.stream = &cancelTrackingRequestStream{}
	}
	return a.stream, nil
}

func (a *cancelTrackingPacketAssembler) OpenEncoderStream() (io.Writer, error) {
	a.localEncoder.Reset()
	return &a.localEncoder, nil
}

func (a *cancelTrackingPacketAssembler) AcceptEncoderStream() (io.Reader, error) {
	return bytes.NewReader(nil), nil
}

func (a *cancelTrackingPacketAssembler) OpenDecoderStream() (io.Writer, error) {
	a.localDecoder.Reset()
	return &a.localDecoder, nil
}

func (a *cancelTrackingPacketAssembler) AcceptDecoderStream() (io.Reader, error) {
	return bytes.NewReader(nil), nil
}

func (a *cancelTrackingPacketAssembler) IngestControlPayload(offset uint64, payload []byte) error {
	_ = offset
	_ = payload
	return errors.New("unused")
}

func (a *cancelTrackingPacketAssembler) IngestEncoderPayload(offset uint64, payload []byte) error {
	_ = offset
	_ = payload
	return errors.New("unused")
}

func (a *cancelTrackingPacketAssembler) IngestDecoderPayload(offset uint64, payload []byte) error {
	_ = offset
	_ = payload
	return errors.New("unused")
}

func (a *cancelTrackingPacketAssembler) IngestRequestPayload(streamID uint64, offset uint64, payload []byte) (RequestStreamBuffer, error) {
	if a.stream == nil {
		a.stream = &cancelTrackingRequestStream{}
	}
	a.stream.id = streamID
	if err := a.stream.writeAt(payload, offset); err != nil {
		return nil, err
	}
	return a.stream, nil
}

func (a *cancelTrackingPacketAssembler) SnapshotControlPayload() []byte {
	return nil
}

func (a *cancelTrackingPacketAssembler) SnapshotEncoderPayload() []byte {
	return nil
}

func (a *cancelTrackingPacketAssembler) SnapshotDecoderPayload() []byte {
	return nil
}

func (a *cancelTrackingPacketAssembler) RequestStream(streamID uint64) RequestStreamBuffer {
	if a.stream == nil || a.stream.id != streamID {
		return nil
	}
	return a.stream
}

func (o *qpackLoopbackOpener) OpenControlStream() (io.Writer, error) {
	o.clientControl.Reset()
	return &o.clientControl, nil
}

func (o *qpackLoopbackOpener) AcceptControlStream() (io.Reader, error) {
	return bytes.NewReader(o.serverControl), nil
}

func (o *qpackLoopbackOpener) OpenEncoderStream() (io.Writer, error) {
	o.openEncoderCalls.Add(1)
	return &o.clientToServerEncoder, nil
}

func (o *qpackLoopbackOpener) AcceptEncoderStream() (io.Reader, error) {
	o.acceptEncoderCalls.Add(1)
	return &o.serverToClientEncoder, nil
}

func (o *qpackLoopbackOpener) OpenDecoderStream() (io.Writer, error) {
	o.openDecoderCalls.Add(1)
	return &o.clientToServerDecoder, nil
}

func (o *qpackLoopbackOpener) AcceptDecoderStream() (io.Reader, error) {
	o.acceptDecoderCalls.Add(1)
	return &o.serverToClientDecoder, nil
}

type qpackRoundTripLoopbackStream struct {
	streamID    uint64
	request     bytes.Buffer
	response    bytes.Reader
	built       bool
	handler     func(requestBytes []byte) ([]byte, error)
	closeWrites atomic.Int32
	closeReads  atomic.Int32
	closes      atomic.Int32
}

func (s *qpackRoundTripLoopbackStream) Write(p []byte) (int, error) {
	if s.built {
		return 0, io.ErrClosedPipe
	}
	return s.request.Write(p)
}

func (s *qpackRoundTripLoopbackStream) Read(p []byte) (int, error) {
	if !s.built {
		response, err := s.handler(append([]byte(nil), s.request.Bytes()...))
		if err != nil {
			return 0, err
		}
		s.response = *bytes.NewReader(response)
		s.built = true
	}
	return s.response.Read(p)
}

func (s *qpackRoundTripLoopbackStream) RequestStreamID() uint64 {
	return s.streamID
}

func (s *qpackRoundTripLoopbackStream) CloseWrite() error {
	s.closeWrites.Add(1)
	return nil
}

func (s *qpackRoundTripLoopbackStream) CloseRead() error {
	s.closeReads.Add(1)
	return nil
}

func (s *qpackRoundTripLoopbackStream) Close() error {
	s.closes.Add(1)
	return nil
}

type qpackRoundTripStreamOpener struct {
	streams []*qpackRoundTripLoopbackStream
	handler func(requestBytes []byte) ([]byte, error)
	nextID  uint64
}

func buildQUICStreamFrame(streamID, offset uint64, payload []byte, fin bool) ([]byte, error) {
	frameType := quicStreamFrameTypeBase | 0x04 | 0x02
	if fin {
		frameType |= 0x01
	}
	buf := []byte{frameType}
	var err error
	buf, err = AppendVarInt(buf, streamID)
	if err != nil {
		return nil, err
	}
	buf, err = AppendVarInt(buf, offset)
	if err != nil {
		return nil, err
	}
	buf, err = AppendVarInt(buf, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	buf = append(buf, payload...)
	return buf, nil
}

func buildPendingControlStreamFrames(extraPayloadSize int) ([]byte, []byte, error) {
	prefix, err := AppendVarInt(nil, uint64(StreamTypeControl))
	if err != nil {
		return nil, nil, err
	}
	settingsPayload, err := EncodeSettings(Settings{QPACKMaxTableCap: 128}, nil)
	if err != nil {
		return nil, nil, err
	}
	settingsHeader, err := FrameHeader{Type: uint64(FrameSettings), Length: uint64(len(settingsPayload))}.Encode(nil)
	if err != nil {
		return nil, nil, err
	}
	controlStreamPayload := append(prefix, settingsHeader...)
	controlStreamPayload = append(controlStreamPayload, settingsPayload...)
	if extraPayloadSize > 0 {
		extraHeader, err := FrameHeader{Type: 0x21, Length: uint64(extraPayloadSize)}.Encode(nil)
		if err != nil {
			return nil, nil, err
		}
		controlStreamPayload = append(controlStreamPayload, extraHeader...)
		controlStreamPayload = append(controlStreamPayload, bytes.Repeat([]byte("x"), extraPayloadSize)...)
	}
	pendingFrame, err := buildQUICStreamFrame(2, uint64(len(prefix)), controlStreamPayload[len(prefix):], false)
	if err != nil {
		return nil, nil, err
	}
	prefixFrame, err := buildQUICStreamFrame(2, 0, prefix, false)
	if err != nil {
		return nil, nil, err
	}
	return pendingFrame, prefixFrame, nil
}

func buildResetStreamPacket(streamID uint64, code ErrorCode, finalSize uint64) ([]byte, error) {
	buf := []byte{quicFrameTypeResetStream}
	var err error
	buf, err = AppendVarInt(buf, streamID)
	if err != nil {
		return nil, err
	}
	buf, err = AppendVarInt(buf, uint64(code))
	if err != nil {
		return nil, err
	}
	buf, err = AppendVarInt(buf, finalSize)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func buildStopSendingPacket(streamID uint64, code ErrorCode) ([]byte, error) {
	buf := []byte{quicFrameTypeStopSending}
	var err error
	buf, err = AppendVarInt(buf, streamID)
	if err != nil {
		return nil, err
	}
	buf, err = AppendVarInt(buf, uint64(code))
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func buildConnectionClosePacket(code ErrorCode) ([]byte, error) {
	buf := []byte{quicFrameTypeConnectionCloseApp}
	var err error
	buf, err = AppendVarInt(buf, uint64(code))
	if err != nil {
		return nil, err
	}
	buf, err = AppendVarInt(buf, 0)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (o *qpackRoundTripStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	stream := &qpackRoundTripLoopbackStream{handler: o.handler, streamID: o.nextID}
	o.nextID += 4
	o.streams = append(o.streams, stream)
	return stream, nil
}

func TestServerConnFlushesPendingControlStreamPackets(t *testing.T) {
	pendingFrame, prefixFrame, err := buildPendingControlStreamFrames(1024)
	if err != nil {
		t.Fatalf("build pending control stream frames: %v", err)
	}

	server := NewServerSession()
	streams := NewMemoryStreamOpenerFactory().NewStreamOpener()
	conn := NewServerConn(server, streams)

	snapshot, err := conn.HandlePacket(context.Background(), pendingFrame, nil)
	if err != nil {
		t.Fatalf("handle pending control packet: %v", err)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepStreamTypePending {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if len(conn.state.pendingPeerPackets[2]) != 1 {
		t.Fatalf("expected one pending packet, got %d", len(conn.state.pendingPeerPackets[2]))
	}

	snapshot, err = conn.HandlePacket(context.Background(), prefixFrame, nil)
	if err != nil {
		t.Fatalf("handle control prefix packet: %v", err)
	}
	if !snapshot.PeerSettingsReady {
		t.Fatal("expected peer settings to be ready after flush")
	}
	if snapshot.LastControlStreamID != 2 {
		t.Fatalf("unexpected control stream id %d", snapshot.LastControlStreamID)
	}
	if _, ok := conn.state.pendingPeerPackets[2]; ok {
		t.Fatal("expected pending control packets to be cleared after flush")
	}
}

func TestServerConnHandlesResetStreamTransportFrame(t *testing.T) {
	server := NewServerSession()
	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	if _, err := streams.IngestRequestPayload(0, 0, []byte("hello")); err != nil {
		t.Fatalf("ingest request payload: %v", err)
	}
	conn.markActiveRequest(0)

	packet, err := buildResetStreamPacket(0, ErrRequestCancelled, 5)
	if err != nil {
		t.Fatalf("build reset packet: %v", err)
	}

	snapshot, err := conn.HandlePacket(context.Background(), packet, nil)
	if err != nil {
		t.Fatalf("handle reset packet: %v", err)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepRequestStreamReset {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to exist")
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("expected one cancel read, got %d", got)
	}
	if got := streams.stream.cancelWriteCalls.Load(); got != 1 {
		t.Fatalf("expected one cancel write, got %d", got)
	}
	if streams.stream.lastCancelCode != ErrRequestCancelled {
		t.Fatalf("unexpected cancel read code %x", uint64(streams.stream.lastCancelCode))
	}
	if streams.stream.lastWriteCode != ErrRequestCancelled {
		t.Fatalf("unexpected cancel write code %x", uint64(streams.stream.lastWriteCode))
	}
	if !conn.RequestStreamComplete(0) {
		t.Fatal("expected request stream to be completed after reset")
	}
}

func TestServerConnHandlesStopSendingTransportFrame(t *testing.T) {
	server := NewServerSession()
	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	if _, err := streams.IngestRequestPayload(0, 0, []byte("hello")); err != nil {
		t.Fatalf("ingest request payload: %v", err)
	}
	conn.markActiveRequest(0)

	packet, err := buildStopSendingPacket(0, ErrRequestCancelled)
	if err != nil {
		t.Fatalf("build stop_sending packet: %v", err)
	}

	snapshot, err := conn.HandlePacket(context.Background(), packet, nil)
	if err != nil {
		t.Fatalf("handle stop_sending packet: %v", err)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepRequestStreamStopSending {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to exist")
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 0 {
		t.Fatalf("expected cancel read to stay at 0, got %d", got)
	}
	if got := streams.stream.cancelWriteCalls.Load(); got != 1 {
		t.Fatalf("expected one cancel write, got %d", got)
	}
	if streams.stream.lastWriteCode != ErrRequestCancelled {
		t.Fatalf("unexpected cancel write code %x", uint64(streams.stream.lastWriteCode))
	}
	if !conn.RequestStreamComplete(0) {
		t.Fatal("expected request stream to be completed after stop_sending")
	}
}

func TestServerConnHandlesConnectionCloseTransportFrame(t *testing.T) {
	server := NewServerSession()
	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	if _, err := streams.IngestRequestPayload(0, 0, []byte("hello")); err != nil {
		t.Fatalf("ingest request payload: %v", err)
	}
	conn.markActiveRequest(0)

	packet, err := buildConnectionClosePacket(ErrNoError)
	if err != nil {
		t.Fatalf("build connection_close packet: %v", err)
	}

	snapshot, err := conn.HandlePacket(context.Background(), packet, nil)
	if err != nil {
		t.Fatalf("handle connection_close packet: %v", err)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepConnectionClose {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if !conn.PeerConnectionClosed() {
		t.Fatal("expected peer connection to be marked closed")
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to exist")
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("expected one cancel read, got %d", got)
	}
	if got := streams.stream.cancelWriteCalls.Load(); got != 1 {
		t.Fatalf("expected one cancel write, got %d", got)
	}
	if !conn.RequestStreamComplete(0) {
		t.Fatal("expected request stream to be completed after connection close")
	}
}

func TestServerConnCountsInitialAndHandshakePackets(t *testing.T) {
	server := NewServerSession()
	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	dcid := bytes.Repeat([]byte{0x11}, 8)
	scid := bytes.Repeat([]byte{0x22}, 8)

	initialPacket := buildTestQUICInitialPacket(t, dcid, scid, []byte{0x01})
	snapshot, err := conn.HandlePacket(context.Background(), initialPacket, nil)
	if err != nil {
		t.Fatalf("handle initial packet: %v", err)
	}
	if snapshot.InitialPackets != 1 {
		t.Fatalf("expected 1 initial packet, got %d", snapshot.InitialPackets)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepQUICInitial {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if snapshot.LastStreamType != ServerConnStreamTypeQUICInitial {
		t.Fatalf("unexpected stream type %q", snapshot.LastStreamType)
	}

	handshakePacket := buildTestQUICHandshakePacket(t, dcid, scid, []byte{0x01})
	snapshot, err = conn.HandlePacket(context.Background(), handshakePacket, nil)
	if err != nil {
		t.Fatalf("handle handshake packet: %v", err)
	}
	if snapshot.HandshakePackets != 1 {
		t.Fatalf("expected 1 handshake packet, got %d", snapshot.HandshakePackets)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepQUICHandshake {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if snapshot.LastStreamType != ServerConnStreamTypeQUICHandshake {
		t.Fatalf("unexpected stream type %q", snapshot.LastStreamType)
	}
}

func TestServerConnProcessesOneRTTPayload(t *testing.T) {
	pendingControlPacket, prefixPacket, err := buildPendingControlStreamFrames(0)
	if err != nil {
		t.Fatalf("build control stream frame: %v", err)
	}
	dcid := bytes.Repeat([]byte{0x33}, DefaultShortHeaderDestinationConnectionIDLength)
	oneRTTPacket := buildTestQUIC1RTTPacket(dcid, append(prefixPacket, pendingControlPacket...))

	server := NewServerSession()
	streams := NewMemoryStreamOpenerFactory().NewStreamOpener()
	conn := NewServerConn(server, streams)

	snapshot, err := conn.HandlePacket(context.Background(), oneRTTPacket, nil)
	if err != nil {
		t.Fatalf("handle 1-rtt packet: %v", err)
	}
	if snapshot.OneRTTPackets != 1 {
		t.Fatalf("expected 1 1-rtt packet, got %d", snapshot.OneRTTPackets)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepControlStream {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if !snapshot.PeerSettingsReady {
		t.Fatal("expected peer settings to be ready after 1-rtt control payload")
	}
	if snapshot.LastControlStreamID != 2 {
		t.Fatalf("unexpected control stream id %d", snapshot.LastControlStreamID)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	settings := Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 4096, QPACKBlockedStreams: 32, EnableConnectProto: true, EnableDatagrams: true}
	encoded, err := EncodeSettings(settings, nil)
	if err != nil {
		t.Fatalf("encode settings: %v", err)
	}
	decoded, err := DecodeSettings(encoded)
	if err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if decoded != settings {
		t.Fatalf("unexpected decoded settings %+v", decoded)
	}
}

func TestReadControlStreamRequiresSettingsFirst(t *testing.T) {
	session := NewServerSession()
	stream, err := AppendVarInt(nil, uint64(StreamTypeControl))
	if err != nil {
		t.Fatalf("append stream type: %v", err)
	}
	frame, err := FrameHeader{Type: uint64(FrameGoAway), Length: 0}.Encode(nil)
	if err != nil {
		t.Fatalf("encode frame header: %v", err)
	}
	stream = append(stream, frame...)
	if err := session.ReadControlStream(bytes.NewReader(stream)); err == nil {
		t.Fatal("expected first non-settings frame to fail")
	}
}

func TestReadControlStreamRejectsDuplicateSettings(t *testing.T) {
	session := NewServerSession()
	stream, err := AppendVarInt(nil, uint64(StreamTypeControl))
	if err != nil {
		t.Fatalf("append stream type: %v", err)
	}
	payload, err := EncodeSettings(Settings{QPACKMaxTableCap: 128}, nil)
	if err != nil {
		t.Fatalf("encode settings payload: %v", err)
	}
	header, err := FrameHeader{Type: uint64(FrameSettings), Length: uint64(len(payload))}.Encode(nil)
	if err != nil {
		t.Fatalf("encode frame header: %v", err)
	}
	stream = append(stream, header...)
	stream = append(stream, payload...)
	stream = append(stream, header...)
	stream = append(stream, payload...)
	if err := session.ReadControlStream(bytes.NewReader(stream)); err == nil {
		t.Fatal("expected duplicate settings to fail")
	}
}

func TestQpackRequestResponseRoundTrip(t *testing.T) {
	codec := NewQpackCodec()
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://example.com/video/seg.ts?part=1")
	req.Headers.SetString("accept-encoding", "gzip, deflate, br")
	req.Headers.SetString("x-cache-key", "video:seg")
	block, err := codec.EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	decodedReq, err := codec.DecodeRequest(block)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	defer core.ReleaseRequest(decodedReq)
	if decodedReq.Method != core.MethodGet {
		t.Fatalf("unexpected method %v", decodedReq.Method)
	}
	if string(decodedReq.URI.Path) != "/video/seg.ts" {
		t.Fatalf("unexpected path %q", decodedReq.URI.Path)
	}
	if string(decodedReq.Headers.Get("x-cache-key")) != "video:seg" {
		t.Fatalf("unexpected header %q", decodedReq.Headers.Get("x-cache-key"))
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(206)
	resp.Headers.SetString("content-type", "video/mp2t")
	respBlock, err := codec.EncodeResponse(resp)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	decodedResp, err := codec.DecodeResponse(respBlock)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)
	if decodedResp.Status.Code != 206 {
		t.Fatalf("unexpected status %d", decodedResp.Status.Code)
	}
}

func TestQpackDynamicTableRoundTrip(t *testing.T) {
	encoder := NewQpackCodec()
	decoder := NewQpackCodec()
	encoder.SetLocalCapacity(256)
	decoder.SetRemoteCapacity(256)

	firstBlock, err := encoder.EncodeFields([]HeaderField{{Name: "x-cache-key", Value: "video:seg:1"}})
	if err != nil {
		t.Fatalf("encode first block: %v", err)
	}
	encoderStream := encoder.DrainEncoderInstructions()
	if len(encoderStream) == 0 {
		t.Fatal("expected encoder instructions for first block")
	}
	if err := decoder.ApplyEncoderInstructions(encoderStream); err != nil {
		t.Fatalf("apply encoder instructions: %v", err)
	}
	decodedFirst, err := decoder.DecodeFields(firstBlock)
	if err != nil {
		t.Fatalf("decode first block: %v", err)
	}
	if len(decodedFirst) != 1 || decodedFirst[0].Name != "x-cache-key" || decodedFirst[0].Value != "video:seg:1" {
		t.Fatalf("unexpected first decode %+v", decodedFirst)
	}
	decoderStream := decoder.DrainDecoderInstructions()
	if len(decoderStream) == 0 {
		t.Fatal("expected decoder instructions after first decode")
	}
	if err := encoder.ApplyDecoderInstructions(decoderStream); err != nil {
		t.Fatalf("apply decoder instructions: %v", err)
	}

	secondBlock, err := encoder.EncodeFields([]HeaderField{{Name: "x-cache-key", Value: "video:seg:1"}})
	if err != nil {
		t.Fatalf("encode second block: %v", err)
	}
	if len(secondBlock) < 3 || secondBlock[2]&0x80 == 0 || secondBlock[2]&0x40 != 0 {
		t.Fatalf("expected dynamic indexed field in second block: %v", secondBlock)
	}
	if err := decoder.ApplyEncoderInstructions(encoder.DrainEncoderInstructions()); err != nil {
		t.Fatalf("apply second encoder instructions: %v", err)
	}
	decodedSecond, err := decoder.DecodeFields(secondBlock)
	if err != nil {
		t.Fatalf("decode second block: %v", err)
	}
	if len(decodedSecond) != 1 || decodedSecond[0].Value != "video:seg:1" {
		t.Fatalf("unexpected second decode %+v", decodedSecond)
	}
}

func TestQpackDecodeFieldsAcceptsHuffmanString(t *testing.T) {
	codec := NewQpackCodec()

	block := appendPrefixedInt(nil, 8, 0x00, 0)
	block = appendPrefixedInt(block, 7, 0x00, 0)
	block = appendPrefixedInt(block, 4, 0x50, 95)
	value := "curl/8.0"
	block = appendPrefixedInt(block, 7, 0x80, hpack.HuffmanEncodeLength(value))
	block = hpack.AppendHuffmanString(block, value)

	fields, err := codec.DecodeFields(block)
	if err != nil {
		t.Fatalf("decode huffman block: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("unexpected field count %d", len(fields))
	}
	if fields[0].Name != "user-agent" || fields[0].Value != value {
		t.Fatalf("unexpected decoded field %+v", fields[0])
	}
}

func TestQpackDecodeFieldsNegativeDeltaBase(t *testing.T) {
	codec := NewQpackCodec()
	codec.SetRemoteCapacity(256)
	if _, ok := codec.remoteTable.insert("x-a", "v1"); !ok {
		t.Fatal("insert x-a into remote table")
	}
	if _, ok := codec.remoteTable.insert("x-b", "v2"); !ok {
		t.Fatal("insert x-b into remote table")
	}

	block := appendPrefixedInt(nil, 8, 0x00, 2)
	block = appendPrefixedInt(block, 7, 0x80, 0)
	block = appendPrefixedInt(block, 4, 0x10, 0)

	fields, err := codec.DecodeFields(block)
	if err != nil {
		t.Fatalf("decode negative delta base block: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("unexpected field count %d", len(fields))
	}
	if fields[0].Name != "x-b" || fields[0].Value != "v2" {
		t.Fatalf("unexpected decoded field %+v", fields[0])
	}
}

func TestQpackApplyEncoderInstructionsAcceptsZigLiteralInsert(t *testing.T) {
	codec := NewQpackCodec()
	codec.SetRemoteCapacity(256)

	instruction := appendPrefixedInt(nil, 5, 0x60, hpack.HuffmanEncodeLength("x-zig-key"))
	instruction = hpack.AppendHuffmanString(instruction, "x-zig-key")
	instruction = appendPrefixedInt(instruction, 7, 0x80, hpack.HuffmanEncodeLength("v-zig"))
	instruction = hpack.AppendHuffmanString(instruction, "v-zig")

	if err := codec.ApplyEncoderInstructions(instruction); err != nil {
		t.Fatalf("apply zig literal insert: %v", err)
	}

	block := appendPrefixedInt(nil, 8, 0x00, 1)
	block = appendPrefixedInt(block, 7, 0x00, 0)
	block = appendPrefixedInt(block, 6, 0x80, 0)

	fields, err := codec.DecodeFields(block)
	if err != nil {
		t.Fatalf("decode field referencing inserted entry: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("unexpected field count %d", len(fields))
	}
	if fields[0].Name != "x-zig-key" || fields[0].Value != "v-zig" {
		t.Fatalf("unexpected decoded field %+v", fields[0])
	}
}

func TestQpackDecodeFieldsWithStreamQueuesSectionAck(t *testing.T) {
	codec := NewQpackCodec()
	codec.SetRemoteCapacity(256)
	if _, ok := codec.remoteTable.insert("x-a", "v1"); !ok {
		t.Fatal("insert dynamic table entry")
	}

	block := appendPrefixedInt(nil, 8, 0x00, 1)
	block = appendPrefixedInt(block, 7, 0x00, 0)
	block = appendPrefixedInt(block, 6, 0x80, 0)

	streamID := uint64(8)
	fields, err := codec.decodeFields(block, &streamID)
	if err != nil {
		t.Fatalf("decode fields with stream id: %v", err)
	}
	if len(fields) != 1 || fields[0].Name != "x-a" || fields[0].Value != "v1" {
		t.Fatalf("unexpected decoded fields %+v", fields)
	}

	decoder := codec.DrainDecoderInstructions()
	want := appendPrefixedInt(nil, 7, 0x80, streamID)
	if !bytes.Equal(decoder, want) {
		t.Fatalf("unexpected decoder instructions %v want %v", decoder, want)
	}
}

func TestQpackWriteEncoderStreamWritesStreamTypeOnce(t *testing.T) {
	session := NewClientSession()
	session.qpack.SetLocalCapacity(256)
	if _, err := session.qpack.EncodeFields([]HeaderField{{Name: "x-a", Value: "v1"}}); err != nil {
		t.Fatalf("encode first fields: %v", err)
	}

	var stream bytes.Buffer
	if err := session.WriteEncoderStream(&stream); err != nil {
		t.Fatalf("write first encoder chunk: %v", err)
	}
	firstLen := stream.Len()
	prefix, err := AppendVarInt(nil, uint64(StreamTypeQPACKEncoder))
	if err != nil {
		t.Fatalf("encode stream type prefix: %v", err)
	}
	if !bytes.HasPrefix(stream.Bytes(), prefix) {
		t.Fatalf("expected first encoder chunk to start with stream type, got %v", stream.Bytes())
	}

	if _, err := session.qpack.EncodeFields([]HeaderField{{Name: "x-b", Value: "v2"}}); err != nil {
		t.Fatalf("encode second fields: %v", err)
	}
	if err := session.WriteEncoderStream(&stream); err != nil {
		t.Fatalf("write second encoder chunk: %v", err)
	}
	secondChunk := stream.Bytes()[firstLen:]
	if bytes.HasPrefix(secondChunk, prefix) {
		t.Fatalf("expected second encoder chunk without repeated stream type, got %v", secondChunk)
	}
}

func TestQpackReadEncoderStreamAcceptsContinuedChunks(t *testing.T) {
	writer := NewClientSession()
	reader := NewServerSession()
	writer.qpack.SetLocalCapacity(256)
	reader.qpack.SetRemoteCapacity(256)

	if _, err := writer.qpack.EncodeFields([]HeaderField{{Name: "x-a", Value: "v1"}}); err != nil {
		t.Fatalf("encode first fields: %v", err)
	}
	var first bytes.Buffer
	if err := writer.WriteEncoderStream(&first); err != nil {
		t.Fatalf("write first encoder stream chunk: %v", err)
	}
	if err := reader.ReadEncoderStream(bytes.NewReader(first.Bytes())); err != nil {
		t.Fatalf("read first encoder stream chunk: %v", err)
	}

	if _, err := writer.qpack.EncodeFields([]HeaderField{{Name: "x-b", Value: "v2"}}); err != nil {
		t.Fatalf("encode second fields: %v", err)
	}
	var second bytes.Buffer
	if err := writer.WriteEncoderStream(&second); err != nil {
		t.Fatalf("write second encoder stream chunk: %v", err)
	}
	if err := reader.ReadEncoderStream(bytes.NewReader(second.Bytes())); err != nil {
		t.Fatalf("read second encoder stream chunk: %v", err)
	}

	block := appendPrefixedInt(nil, 8, 0x00, 2)
	block = appendPrefixedInt(block, 7, 0x00, 0)
	block = appendPrefixedInt(block, 6, 0x80, 0)
	fields, err := reader.qpack.DecodeFields(block)
	if err != nil {
		t.Fatalf("decode dynamic field after continued chunks: %v", err)
	}
	if len(fields) != 1 || fields[0].Name != "x-b" || fields[0].Value != "v2" {
		t.Fatalf("unexpected decoded fields %+v", fields)
	}
}

func TestQpackReadEncoderStreamAcceptsSplitInstructionChunks(t *testing.T) {
	writer := NewClientSession()
	reader := NewServerSession()
	writer.qpack.SetLocalCapacity(256)
	reader.qpack.SetRemoteCapacity(256)

	if _, err := writer.qpack.EncodeFields([]HeaderField{{Name: "x-split", Value: "value-split"}}); err != nil {
		t.Fatalf("encode fields: %v", err)
	}
	var encoded bytes.Buffer
	if err := writer.WriteEncoderStream(&encoded); err != nil {
		t.Fatalf("write encoder stream: %v", err)
	}

	data := encoded.Bytes()
	if len(data) < 3 {
		t.Fatalf("expected longer encoded stream, got %v", data)
	}
	readerStream := &scriptedQpackReader{
		chunks: [][]byte{append([]byte(nil), data[:len(data)-1]...), append([]byte(nil), data[len(data)-1:]...)},
	}

	if err := reader.ReadEncoderStream(readerStream); err != nil {
		t.Fatalf("read first split chunk: %v", err)
	}
	if reader.qpack.remoteTable.insertCount != 0 {
		t.Fatalf("expected no committed insert after partial chunk, got %d", reader.qpack.remoteTable.insertCount)
	}
	if err := reader.ReadEncoderStream(readerStream); err != nil {
		t.Fatalf("read second split chunk: %v", err)
	}
	if reader.qpack.remoteTable.insertCount == 0 {
		t.Fatal("expected insert to apply after completed split chunks")
	}
}

func TestTransportCachesQPACKStreams(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}
	server.Settings = Settings{QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}

	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	opener := &qpackLoopbackOpener{serverControl: append([]byte(nil), serverControl.Bytes()...)}
	streamOpener := &qpackRoundTripStreamOpener{}

	var serverSeenClientControl bool
	streamOpener.handler = func(requestBytes []byte) ([]byte, error) {
		if !serverSeenClientControl {
			if err := server.ReadControlStream(bytes.NewReader(opener.clientControl.Bytes())); err != nil {
				return nil, err
			}
			serverSeenClientControl = true
		}
		if opener.clientToServerEncoder.Len() > 0 {
			if err := server.ReadEncoderStream(&opener.clientToServerEncoder); err != nil {
				return nil, err
			}
		}
		req, err := server.ReadRequest(bytes.NewReader(requestBytes))
		if err != nil {
			return nil, err
		}
		defer core.ReleaseRequest(req)
		if err := server.WriteDecoderStream(&opener.serverToClientDecoder); err != nil {
			return nil, err
		}

		resp := core.AcquireResponse()
		defer core.ReleaseResponse(resp)
		resp.Version = core.VersionHTTP3
		resp.Status = core.NewStatus(200)
		resp.Headers.SetString("x-cache-key", string(req.Headers.Get("x-cache-key")))
		resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))

		var response bytes.Buffer
		if err := server.WriteResponse(&response, resp); err != nil {
			return nil, err
		}
		if err := server.WriteEncoderStream(&opener.serverToClientEncoder); err != nil {
			return nil, err
		}
		return response.Bytes(), nil
	}

	transport := NewTransport(client, opener, streamOpener)
	for i := 0; i < 2; i++ {
		req := core.AcquireRequest()
		initRequest(req, core.MethodGet, "https://cdn.example.com/video/seg.ts")
		req.Version = core.VersionHTTP3
		req.Headers.SetString("x-cache-key", "asset:42")
		resp, err := transport.RoundTrip(req)
		core.ReleaseRequest(req)
		if err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
		core.ReleaseResponse(resp)
	}

	if got := opener.openEncoderCalls.Load(); got != 1 {
		t.Fatalf("unexpected open encoder calls %d", got)
	}
	if got := opener.acceptEncoderCalls.Load(); got != 1 {
		t.Fatalf("unexpected accept encoder calls %d", got)
	}
	if got := opener.openDecoderCalls.Load(); got != 1 {
		t.Fatalf("unexpected open decoder calls %d", got)
	}
	if got := opener.acceptDecoderCalls.Load(); got != 1 {
		t.Fatalf("unexpected accept decoder calls %d", got)
	}
}

func TestSessionControlAndMessageRoundTrip(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 4096, QPACKBlockedStreams: 64}

	var clientControl bytes.Buffer
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("read control stream: %v", err)
	}
	if server.PeerSettings.QPACKBlockedStreams != 64 {
		t.Fatalf("unexpected peer settings %+v", server.PeerSettings)
	}

	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("read server control stream: %v", err)
	}

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://origin.example.com/cache/fill?id=1")
	req.SetBody(io.NopCloser(bytes.NewReader([]byte("chunk-a"))))
	req.Trailers.SetString("x-origin-etag", "abc")

	var requestStream bytes.Buffer
	if err := client.WriteRequest(&requestStream, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	decodedReq, err := server.ReadRequest(bytes.NewReader(requestStream.Bytes()))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(decodedReq)
	decodedBody, err := io.ReadAll(decodedReq.Body)
	if err != nil {
		t.Fatalf("read decoded request body: %v", err)
	}
	if string(decodedBody) != "chunk-a" {
		t.Fatalf("unexpected request body %q", decodedBody)
	}
	if string(decodedReq.Trailers.Get("x-origin-etag")) != "abc" {
		t.Fatalf("unexpected request trailer %q", decodedReq.Trailers.Get("x-origin-etag"))
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "application/octet-stream")
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("payload"))))
	resp.Trailers.SetString("x-cache", "hit")

	var responseStream bytes.Buffer
	if err := server.WriteResponse(&responseStream, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}
	decodedResp, err := client.ReadResponse(bytes.NewReader(responseStream.Bytes()))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)
	if decodedResp.Status.Code != 200 {
		t.Fatalf("unexpected response status %d", decodedResp.Status.Code)
	}
	if string(decodedResp.Trailers.Get("x-cache")) != "hit" {
		t.Fatalf("unexpected response trailer %q", decodedResp.Trailers.Get("x-cache"))
	}
	respBody, err := io.ReadAll(decodedResp.Body)
	if err != nil {
		t.Fatalf("read decoded response body: %v", err)
	}
	if string(respBody) != "payload" {
		t.Fatalf("unexpected response body %q", respBody)
	}
}

func TestSessionWriteResponseStreamsBodyAcrossMultipleDataFrames(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()

	var clientControl bytes.Buffer
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("read client control stream: %v", err)
	}

	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("read server control stream: %v", err)
	}

	bodyReader, bodyWriter := io.Pipe()
	go func() {
		_, _ = bodyWriter.Write([]byte("hello"))
		_, _ = bodyWriter.Write([]byte("world"))
		_ = bodyWriter.Close()
	}()

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "text/plain")
	resp.SetBody(bodyReader)
	resp.Trailers.SetString("x-cache", "hit")

	var responseStream bytes.Buffer
	if err := server.WriteResponse(&responseStream, resp); err != nil {
		t.Fatalf("write streaming response: %v", err)
	}

	dataFrames := 0
	framePayload := responseStream.Bytes()
	for len(framePayload) > 0 {
		header, consumed, err := DecodeFrameHeader(framePayload)
		if err != nil {
			t.Fatalf("decode frame header: %v", err)
		}
		frameLen := consumed + int(header.Length)
		if frameLen > len(framePayload) {
			t.Fatalf("frame exceeds payload: frameLen=%d payload=%d", frameLen, len(framePayload))
		}
		if FrameType(header.Type) == FrameData {
			dataFrames++
		}
		framePayload = framePayload[frameLen:]
	}
	if dataFrames < 2 {
		t.Fatalf("expected multiple DATA frames, got %d", dataFrames)
	}

	decodedResp, err := client.ReadResponse(bytes.NewReader(responseStream.Bytes()))
	if err != nil {
		t.Fatalf("read streaming response: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)
	if decodedResp.Status.Code != 200 {
		t.Fatalf("unexpected response status %d", decodedResp.Status.Code)
	}
	if string(decodedResp.Trailers.Get("x-cache")) != "hit" {
		t.Fatalf("unexpected response trailer %q", decodedResp.Trailers.Get("x-cache"))
	}
	body, err := io.ReadAll(decodedResp.Body)
	if err != nil {
		t.Fatalf("read streamed response body: %v", err)
	}
	if string(body) != "helloworld" {
		t.Fatalf("unexpected streamed response body %q", body)
	}
}

func TestReadResponseRejectsDataAfterTrailers(t *testing.T) {
	session := NewClientSession()
	session.settingsReceived = true

	resp := core.AcquireResponse()
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	headersBlock, err := session.qpack.EncodeResponse(resp)
	core.ReleaseResponse(resp)
	if err != nil {
		t.Fatalf("encode response headers: %v", err)
	}

	trailers := core.NewHeaders()
	trailers.SetString("x-cache", "hit")
	trailerBlock, err := session.qpack.EncodeTrailers(&trailers)
	if err != nil {
		t.Fatalf("encode trailers: %v", err)
	}

	var stream bytes.Buffer
	if err := writeFrame(&stream, FrameHeaders, headersBlock); err != nil {
		t.Fatalf("write headers frame: %v", err)
	}
	if err := writeFrame(&stream, FrameHeaders, trailerBlock); err != nil {
		t.Fatalf("write trailer frame: %v", err)
	}
	if err := writeFrame(&stream, FrameData, []byte("late")); err != nil {
		t.Fatalf("write late data frame: %v", err)
	}

	decoded, err := session.ReadResponse(bytes.NewReader(stream.Bytes()))
	if decoded != nil {
		core.ReleaseResponse(decoded)
	}
	if err == nil {
		t.Fatal("expected data after trailers to fail")
	}
}

func TestReadResponseRejectsSettingsFrameOnMessageStream(t *testing.T) {
	session := NewClientSession()
	session.settingsReceived = true

	resp := core.AcquireResponse()
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	headersBlock, err := session.qpack.EncodeResponse(resp)
	core.ReleaseResponse(resp)
	if err != nil {
		t.Fatalf("encode response headers: %v", err)
	}

	var stream bytes.Buffer
	if err := writeFrame(&stream, FrameHeaders, headersBlock); err != nil {
		t.Fatalf("write headers frame: %v", err)
	}
	if err := writeFrame(&stream, FrameSettings, nil); err != nil {
		t.Fatalf("write settings frame: %v", err)
	}

	decoded, err := session.ReadResponse(bytes.NewReader(stream.Bytes()))
	if decoded != nil {
		core.ReleaseResponse(decoded)
	}
	if err == nil {
		t.Fatal("expected settings frame on message stream to fail")
	}
}

func TestSessionQpackStreamsRoundTrip(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}
	server.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}

	var clientControl bytes.Buffer
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("read client control stream: %v", err)
	}
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("read server control stream: %v", err)
	}

	makeRequest := func() *core.Request {
		req := core.AcquireRequest()
		initRequest(req, core.MethodGet, "https://origin.example.com/cache/item.ts")
		req.Headers.SetString("x-cache-key", "asset:42")
		return req
	}

	firstReq := makeRequest()
	defer core.ReleaseRequest(firstReq)
	var firstRequestStream bytes.Buffer
	if err := client.WriteRequest(&firstRequestStream, firstReq); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	var encoderStream bytes.Buffer
	if err := client.WriteEncoderStream(&encoderStream); err != nil {
		t.Fatalf("write encoder stream: %v", err)
	}
	if encoderStream.Len() == 0 {
		t.Fatal("expected non-empty qpack encoder stream")
	}
	if err := server.ReadEncoderStream(bytes.NewReader(encoderStream.Bytes())); err != nil {
		t.Fatalf("read encoder stream: %v", err)
	}
	decodedFirstReq, err := server.ReadRequest(bytes.NewReader(firstRequestStream.Bytes()))
	if err != nil {
		t.Fatalf("read first request: %v", err)
	}
	defer core.ReleaseRequest(decodedFirstReq)
	if string(decodedFirstReq.Headers.Get("x-cache-key")) != "asset:42" {
		t.Fatalf("unexpected first request header %q", decodedFirstReq.Headers.Get("x-cache-key"))
	}
	var decoderStream bytes.Buffer
	if err := server.WriteDecoderStream(&decoderStream); err != nil {
		t.Fatalf("write decoder stream: %v", err)
	}
	if decoderStream.Len() == 0 {
		t.Fatal("expected non-empty qpack decoder stream")
	}
	if err := client.ReadDecoderStream(bytes.NewReader(decoderStream.Bytes())); err != nil {
		t.Fatalf("read decoder stream: %v", err)
	}

	secondReq := makeRequest()
	defer core.ReleaseRequest(secondReq)
	var secondRequestStream bytes.Buffer
	if err := client.WriteRequest(&secondRequestStream, secondReq); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	if secondRequestStream.Len() >= firstRequestStream.Len() {
		t.Fatalf("expected second request stream to benefit from dynamic qpack: first=%d second=%d", firstRequestStream.Len(), secondRequestStream.Len())
	}
	var secondEncoderStream bytes.Buffer
	if err := client.WriteEncoderStream(&secondEncoderStream); err != nil {
		t.Fatalf("write second encoder stream: %v", err)
	}
	if secondEncoderStream.Len() != 0 {
		t.Fatalf("expected no additional encoder instructions, got %d bytes", secondEncoderStream.Len())
	}
	decodedSecondReq, err := server.ReadRequest(bytes.NewReader(secondRequestStream.Bytes()))
	if err != nil {
		t.Fatalf("read second request: %v", err)
	}
	defer core.ReleaseRequest(decodedSecondReq)
	if string(decodedSecondReq.Headers.Get("x-cache-key")) != "asset:42" {
		t.Fatalf("unexpected second request header %q", decodedSecondReq.Headers.Get("x-cache-key"))
	}
}

func TestTransportRoundTripLifecycleClosesStream(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()

	var clientControl bytes.Buffer
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("server read client control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("client read server control stream: %v", err)
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))
	var response bytes.Buffer
	if err := server.WriteResponse(&response, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}

	stream := newLifecycleTestStream(response.Bytes())
	transport := NewTransport(
		client,
		testControlOpener{localWriter: &clientControl, remoteData: serverControl.Bytes()},
		lifecycleStreamOpener{stream: stream},
	)
	transport.bootstrapped = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://cdn.example.com/object")
	gotResp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer core.ReleaseResponse(gotResp)
	gotBody, err := io.ReadAll(gotResp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(gotBody) != "ok" {
		t.Fatalf("unexpected response body %q", gotBody)
	}
	if got := stream.closeWriteCalls.Load(); got != 1 {
		t.Fatalf("unexpected close write calls %d", got)
	}
	if got := stream.closeReadCalls.Load(); got != 1 {
		t.Fatalf("unexpected close read calls %d", got)
	}
	if got := stream.closeCalls.Load(); got != 1 {
		t.Fatalf("unexpected close calls %d", got)
	}
	if got := stream.cancelWriteCalls.Load(); got != 0 {
		t.Fatalf("unexpected cancel write calls %d", got)
	}
	if got := stream.cancelReadCalls.Load(); got != 0 {
		t.Fatalf("unexpected cancel read calls %d", got)
	}
}

func TestTransportRoundTripContextCancelsStream(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()

	var clientControl bytes.Buffer
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("server read client control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("client read server control stream: %v", err)
	}

	stream := newLifecycleTestStream(nil)
	stream.blockReads = true
	stream.readCancelErr = errors.New("stream canceled")
	transport := NewTransport(
		client,
		testControlOpener{localWriter: &clientControl, remoteData: serverControl.Bytes()},
		lifecycleStreamOpener{stream: stream},
	)
	transport.bootstrapped = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://cdn.example.com/cancel-me")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := transport.RoundTripContext(ctx, req)
		errCh <- err
	}()
	<-stream.writeClosed
	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if got := stream.cancelWriteCalls.Load(); got == 0 {
		t.Fatal("expected cancel write to be called")
	}
	if got := stream.cancelReadCalls.Load(); got == 0 {
		t.Fatal("expected cancel read to be called")
	}
	if got := stream.closeCalls.Load(); got != 1 {
		t.Fatalf("unexpected close calls %d", got)
	}
}

func TestTransportRoundTripIntegratesQPACKStreams(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}
	server.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}

	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	opener := &qpackLoopbackOpener{serverControl: append([]byte(nil), serverControl.Bytes()...)}
	streamOpener := &qpackRoundTripStreamOpener{}

	var serverSeenClientControl bool
	streamOpener.handler = func(requestBytes []byte) ([]byte, error) {
		if !serverSeenClientControl {
			if err := server.ReadControlStream(bytes.NewReader(opener.clientControl.Bytes())); err != nil {
				return nil, err
			}
			serverSeenClientControl = true
		}
		if opener.clientToServerEncoder.Len() > 0 {
			if err := server.ReadEncoderStream(&opener.clientToServerEncoder); err != nil {
				return nil, err
			}
		}
		req, err := server.ReadRequest(bytes.NewReader(requestBytes))
		if err != nil {
			return nil, err
		}
		defer core.ReleaseRequest(req)
		if err := server.WriteDecoderStream(&opener.serverToClientDecoder); err != nil {
			return nil, err
		}

		resp := core.AcquireResponse()
		defer core.ReleaseResponse(resp)
		resp.Version = core.VersionHTTP3
		resp.Status = core.NewStatus(200)
		resp.Headers.SetString("x-cache-node", "edge-1")
		resp.Headers.SetString("x-cache-key", string(req.Headers.Get("x-cache-key")))
		resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))

		var response bytes.Buffer
		if err := server.WriteResponse(&response, resp); err != nil {
			return nil, err
		}
		if err := server.WriteEncoderStream(&opener.serverToClientEncoder); err != nil {
			return nil, err
		}
		return response.Bytes(), nil
	}

	transport := NewTransport(client, opener, streamOpener)

	makeRequest := func() *core.Request {
		req := core.AcquireRequest()
		initRequest(req, core.MethodGet, "https://cdn.example.com/video/seg.ts")
		req.Version = core.VersionHTTP3
		req.Headers.SetString("x-cache-key", "asset:42")
		req.Headers.SetString("x-origin-name", "origin-a")
		return req
	}

	firstReq := makeRequest()
	firstResp, err := transport.RoundTrip(firstReq)
	if err != nil {
		core.ReleaseRequest(firstReq)
		t.Fatalf("first round trip: %v", err)
	}
	core.ReleaseRequest(firstReq)
	core.ReleaseResponse(firstResp)

	secondReq := makeRequest()
	secondResp, err := transport.RoundTrip(secondReq)
	if err != nil {
		core.ReleaseRequest(secondReq)
		t.Fatalf("second round trip: %v", err)
	}
	core.ReleaseRequest(secondReq)
	core.ReleaseResponse(secondResp)

	if len(streamOpener.streams) != 2 {
		t.Fatalf("expected 2 opened request streams, got %d", len(streamOpener.streams))
	}
	firstLen := streamOpener.streams[0].request.Len()
	secondLen := streamOpener.streams[1].request.Len()
	if secondLen >= firstLen {
		t.Fatalf("expected second request to use qpack dynamic references: first=%d second=%d", firstLen, secondLen)
	}
	if streamOpener.streams[0].closeWrites.Load() == 0 || streamOpener.streams[1].closeWrites.Load() == 0 {
		t.Fatal("expected transport to close write side for both request streams")
	}
	if opener.clientToServerDecoder.Len() == 0 {
		t.Fatal("expected client decoder stream to be written after response decode")
	}
	if got := opener.openEncoderCalls.Load(); got != 1 {
		t.Fatalf("unexpected open encoder calls %d", got)
	}
	if got := opener.acceptEncoderCalls.Load(); got != 1 {
		t.Fatalf("unexpected accept encoder calls %d", got)
	}
}

func TestServerConnDispatchesSafeRequestBeforeFIN(t *testing.T) {
	client := NewClientSession()
	client.settingsSent = true

	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://cdn.example.com/video/seg.ts")

	var encoded bytes.Buffer
	if err := client.WriteRequest(&encoded, req); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	var handlerCalls atomic.Int32
	started := make(chan struct{}, 1)
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		handlerCalls.Add(1)
		started <- struct{}{}
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	if err := conn.handleRequestStream(context.Background(), applicationPacket{Payload: encoded.Bytes()}, handler); err != nil {
		t.Fatalf("handle request stream: %v", err)
	}
	select {
	case <-started:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected safe request handler to start")
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("expected handler to run once, got %d", got)
	}
	snapshot := conn.Snapshot()
	if snapshot.RequestsHandled != 1 {
		t.Fatalf("expected 1 handled request, got %d", snapshot.RequestsHandled)
	}
	if snapshot.ResponsesWritten != 1 {
		t.Fatalf("expected 1 written response, got %d", snapshot.ResponsesWritten)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepRequestStreamResponse {
		t.Fatalf("unexpected machine step %q", snapshot.LastMachineStep)
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to be recorded")
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("expected cancel read after response, got %d", got)
	}
	if streams.stream.lastCancelCode != ErrNoError {
		t.Fatalf("unexpected cancel read code %x", uint64(streams.stream.lastCancelCode))
	}

	if err := conn.handleRequestStream(context.Background(), applicationPacket{Payload: []byte("ignored-late-body")}, handler); err != nil {
		t.Fatalf("handle trailing packet: %v", err)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("expected trailing packet to be ignored, handler calls=%d", got)
	}
	if snapshot := conn.Snapshot(); snapshot.LastMachineStep != ServerConnMachineStepRequestStreamIgnored {
		t.Fatalf("expected ignored trailing packet, got %q", snapshot.LastMachineStep)
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("expected no extra cancel read on ignored packet, got %d", got)
	}
}

func TestServerConnBuffersRequestUntilPeerSettingsReady(t *testing.T) {
	client := NewClientSession()
	client.settingsSent = true

	server := NewServerSession()
	server.settingsSent = true

	streams := NewMemoryStreamOpenerFactory().NewStreamOpener()
	conn := NewServerConn(server, streams)

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://cdn.example.com/video/seg.ts")

	var encodedRequest bytes.Buffer
	if err := client.WriteRequest(&encodedRequest, req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	requestFrame, err := buildQUICStreamFrame(0, 0, encodedRequest.Bytes(), true)
	if err != nil {
		t.Fatalf("build request frame: %v", err)
	}

	var handlerCalls atomic.Int32
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		handlerCalls.Add(1)
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	snapshot, err := conn.HandlePacket(context.Background(), requestFrame, handler)
	if err != nil {
		t.Fatalf("handle request before settings: %v", err)
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("expected buffered request before settings, got %d handler calls", got)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepRequestStreamPending {
		t.Fatalf("expected pending machine step before settings, got %q", snapshot.LastMachineStep)
	}
	if snapshot.PeerSettingsReady {
		t.Fatal("expected peer settings to remain unavailable before control stream")
	}

	pendingControlFrame, prefixControlFrame, err := buildPendingControlStreamFrames(0)
	if err != nil {
		t.Fatalf("build control stream frames: %v", err)
	}
	snapshot, err = conn.HandlePacket(context.Background(), append(prefixControlFrame, pendingControlFrame...), handler)
	if err != nil {
		t.Fatalf("handle control stream after buffered request: %v", err)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("expected buffered request to replay after settings, got %d handler calls", got)
	}
	if !snapshot.PeerSettingsReady {
		t.Fatal("expected peer settings to be ready after control stream")
	}
	if snapshot.RequestsHandled != 1 {
		t.Fatalf("expected 1 handled request after replay, got %d", snapshot.RequestsHandled)
	}
	if snapshot.ResponsesWritten != 1 {
		t.Fatalf("expected 1 written response after replay, got %d", snapshot.ResponsesWritten)
	}
	if snapshot.LastMachineStep != ServerConnMachineStepRequestStreamResponse {
		t.Fatalf("expected request response machine step after replay, got %q", snapshot.LastMachineStep)
	}
}

func TestServerConnStreamsPotentialBodyRequestBeforeFIN(t *testing.T) {
	client := NewClientSession()
	client.settingsSent = true

	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://cdn.example.com/upload")
	body := []byte("payload")
	req.Headers.Set(core.HeaderContentLength, []byte("7"))
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	var encoded bytes.Buffer
	if err := client.WriteRequest(&encoded, req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	headersFrame, consumed, err := DecodeFrameHeader(encoded.Bytes())
	if err != nil {
		t.Fatalf("decode headers frame: %v", err)
	}
	headersEnd := consumed + int(headersFrame.Length)
	if headersEnd >= encoded.Len() {
		t.Fatalf("expected encoded request to contain body frame, len=%d headersEnd=%d", encoded.Len(), headersEnd)
	}
	bodyBytes := encoded.Bytes()[headersEnd:]
	firstBodyChunkLen := len(bodyBytes) / 2
	if firstBodyChunkLen == 0 {
		firstBodyChunkLen = 1
	}

	var handlerCalls atomic.Int32
	started := make(chan struct{}, 1)
	bodyRead := make(chan []byte, 1)
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		handlerCalls.Add(1)
		started <- struct{}{}
		data, err := io.ReadAll(got.Body)
		if err != nil {
			return nil, err
		}
		bodyRead <- data
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	packet := applicationPacket{StreamID: 0, IsStreamFrame: true, Payload: encoded.Bytes()[:headersEnd]}
	if err := conn.handleRequestStream(context.Background(), packet, handler); err != nil {
		t.Fatalf("handle headers packet: %v", err)
	}
	select {
	case <-started:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected handler to start before fin")
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("expected handler to start once, got %d calls", got)
	}
	if snapshot := conn.Snapshot(); snapshot.LastMachineStep != ServerConnMachineStepRequestStreamActive {
		t.Fatalf("expected active machine step, got %q", snapshot.LastMachineStep)
	}
	if !conn.isActiveRequest(0) {
		t.Fatal("expected stream to be marked active after headers packet")
	}
	if streams.stream != nil {
		if got := streams.stream.cancelReadCalls.Load(); got != 0 {
			t.Fatalf("expected no cancel read before response completes, got %d", got)
		}
	}

	packet.StreamOffset = uint64(headersEnd)
	packet.Payload = bodyBytes[:firstBodyChunkLen]
	if err := conn.handleRequestStream(context.Background(), packet, handler); err != nil {
		t.Fatalf("handle request body chunk without fin: %v", err)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("expected no duplicate handler dispatch before fin, got %d calls", got)
	}
	if snapshot := conn.Snapshot(); snapshot.LastMachineStep != ServerConnMachineStepRequestStreamActive {
		t.Fatalf("expected active machine step after body chunk, got %q", snapshot.LastMachineStep)
	}
	select {
	case gotBody := <-bodyRead:
		t.Fatalf("expected body read to block before fin, got %q", gotBody)
	default:
	}

	packet.StreamOffset = uint64(headersEnd + firstBodyChunkLen)
	packet.Payload = bodyBytes[firstBodyChunkLen:]
	packet.Fin = true
	if err := conn.handleRequestStream(context.Background(), packet, handler); err != nil {
		t.Fatalf("handle request with fin: %v", err)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("expected single handler dispatch after fin, got %d calls", got)
	}
	select {
	case gotBody := <-bodyRead:
		if string(gotBody) != string(body) {
			t.Fatalf("unexpected streamed body %q", gotBody)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected body read to finish after fin")
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for conn.isActiveRequest(0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.isActiveRequest(0) {
		t.Fatal("expected active marker to clear after final response")
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to be recorded")
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("expected cancel read after final response, got %d", got)
	}
}

func TestServerConnDefersBadRequestUntilFIN(t *testing.T) {
	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	var malformed bytes.Buffer
	if err := writeFrame(&malformed, FrameData, []byte("not-headers")); err != nil {
		t.Fatalf("encode malformed request: %v", err)
	}

	var handlerCalls atomic.Int32
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		handlerCalls.Add(1)
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	packet := applicationPacket{Payload: malformed.Bytes()}
	if err := conn.handleRequestStream(context.Background(), packet, handler); err != nil {
		t.Fatalf("handle malformed request without fin: %v", err)
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("expected malformed request to be deferred before fin, got %d handler calls", got)
	}
	if snapshot := conn.Snapshot(); snapshot.LastMachineStep != ServerConnMachineStepRequestStreamPending {
		t.Fatalf("expected pending machine step before fin, got %q", snapshot.LastMachineStep)
	}
	if streams.stream != nil {
		if got := streams.stream.cancelReadCalls.Load(); got != 0 {
			t.Fatalf("expected no cancel read before fin, got %d", got)
		}
	}

	packet.Fin = true
	if err := conn.handleRequestStream(context.Background(), packet, handler); err != nil {
		t.Fatalf("handle malformed request with fin: %v", err)
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("expected malformed request to skip handler, got %d calls", got)
	}
	if snapshot := conn.Snapshot(); snapshot.LastResponseStatus != 400 {
		t.Fatalf("expected 400 after fin, got %d", snapshot.LastResponseStatus)
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to be recorded")
	}
	if got := streams.stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("expected cancel read after final bad request response, got %d", got)
	}
}

func TestServerConnStreamingBodyIgnoresNonCriticalFrames(t *testing.T) {
	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://cdn.example.com/upload")

	var request bytes.Buffer
	headersBlock, err := server.qpack.EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode headers: %v", err)
	}
	if err := writeFrame(&request, FrameHeaders, headersBlock); err != nil {
		t.Fatalf("write headers frame: %v", err)
	}
	if err := writeFrame(&request, FrameData, []byte("pay")); err != nil {
		t.Fatalf("write first data frame: %v", err)
	}
	if err := writeFrame(&request, FrameCancelPush, []byte{0x00}); err != nil {
		t.Fatalf("write ignorable frame: %v", err)
	}
	if err := writeFrame(&request, FrameData, []byte("load")); err != nil {
		t.Fatalf("write second data frame: %v", err)
	}

	var bodyRead []byte
	bodyDone := make(chan struct{}, 1)
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		data, err := io.ReadAll(got.Body)
		if err != nil {
			return nil, err
		}
		bodyRead = append([]byte(nil), data...)
		bodyDone <- struct{}{}
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	if err := conn.handleRequestStream(context.Background(), applicationPacket{StreamID: 0, IsStreamFrame: true, Payload: request.Bytes(), Fin: true}, handler); err != nil {
		t.Fatalf("handle streaming request: %v", err)
	}
	select {
	case <-bodyDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected body reader to finish with ignored non-critical frame")
	}
	if string(bodyRead) != "payload" {
		t.Fatalf("unexpected streamed body %q", bodyRead)
	}
}

func TestServerConnStreamingBodyIgnoresMalformedTrailers(t *testing.T) {
	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://cdn.example.com/upload")

	var request bytes.Buffer
	headersBlock, err := server.qpack.EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode headers: %v", err)
	}
	if err := writeFrame(&request, FrameHeaders, headersBlock); err != nil {
		t.Fatalf("write headers frame: %v", err)
	}
	if err := writeFrame(&request, FrameData, []byte("payload")); err != nil {
		t.Fatalf("write data frame: %v", err)
	}
	if err := writeFrame(&request, FrameHeaders, []byte{0xff, 0xff, 0xff}); err != nil {
		t.Fatalf("write malformed trailer frame: %v", err)
	}

	var bodyRead []byte
	bodyDone := make(chan struct{}, 1)
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		data, err := io.ReadAll(got.Body)
		if err != nil {
			return nil, err
		}
		bodyRead = append([]byte(nil), data...)
		bodyDone <- struct{}{}
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	if err := conn.handleRequestStream(context.Background(), applicationPacket{StreamID: 0, IsStreamFrame: true, Payload: request.Bytes(), Fin: true}, handler); err != nil {
		t.Fatalf("handle request with malformed trailers: %v", err)
	}
	select {
	case <-bodyDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected body reader to ignore malformed trailers")
	}
	if string(bodyRead) != "payload" {
		t.Fatalf("unexpected streamed body %q", bodyRead)
	}
	if streams.stream == nil {
		t.Fatal("expected request stream to be recorded")
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for conn.isRequestStreamComplete(0) == false && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !conn.isRequestStreamComplete(0) {
		t.Fatal("expected request stream to complete after malformed trailers are ignored")
	}
}

func TestServerConnStreamingBodyIncompleteReturns400(t *testing.T) {
	client := NewClientSession()
	client.settingsSent = true

	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://cdn.example.com/upload")
	req.Headers.Set(core.HeaderContentLength, []byte("7"))
	req.Body = io.NopCloser(bytes.NewReader([]byte("payload")))
	req.ContentLength = 7

	var encoded bytes.Buffer
	if err := client.WriteRequest(&encoded, req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	headersFrame, consumed, err := DecodeFrameHeader(encoded.Bytes())
	if err != nil {
		t.Fatalf("decode headers frame: %v", err)
	}
	headersEnd := consumed + int(headersFrame.Length)
	bodyBytes := encoded.Bytes()[headersEnd:]
	if len(bodyBytes) < 2 {
		t.Fatalf("expected body bytes, got %d", len(bodyBytes))
	}

	bodyErr := make(chan error, 1)
	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		_, err := io.ReadAll(got.Body)
		bodyErr <- err
		if err != nil {
			return nil, err
		}
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	if err := conn.handleRequestStream(context.Background(), applicationPacket{StreamID: 0, IsStreamFrame: true, Payload: encoded.Bytes()[:headersEnd]}, handler); err != nil {
		t.Fatalf("handle headers packet: %v", err)
	}
	if err := conn.handleRequestStream(context.Background(), applicationPacket{StreamID: 0, IsStreamFrame: true, StreamOffset: uint64(headersEnd), Payload: bodyBytes[:len(bodyBytes)-1], Fin: true}, handler); err != nil {
		t.Fatalf("handle truncated body packet: %v", err)
	}

	select {
	case err := <-bodyErr:
		if !errors.Is(err, errStreamingRequestBodyIncomplete) {
			t.Fatalf("expected incomplete body error, got %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected handler body read to fail on incomplete request body")
	}

	deadline := time.Now().Add(100 * time.Millisecond)
	for !conn.isRequestStreamComplete(0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !conn.isRequestStreamComplete(0) {
		t.Fatal("expected request stream to complete after incomplete body handling")
	}
	if snapshot := conn.Snapshot(); snapshot.LastResponseStatus != 400 {
		t.Fatalf("expected 400 for incomplete body, got %d", snapshot.LastResponseStatus)
	}
}
