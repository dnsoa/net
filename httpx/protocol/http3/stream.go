package http3

import (
	"errors"
	"io"
	"sync"
)

type StreamType uint64

const (
	StreamTypeControl      StreamType = 0x00
	StreamTypePush         StreamType = 0x01
	StreamTypeQPACKEncoder StreamType = 0x02
	StreamTypeQPACKDecoder StreamType = 0x03
)

type ControlStreamOpener interface {
	OpenControlStream() (io.Writer, error)
	AcceptControlStream() (io.Reader, error)
}

type RequestStreamOpener interface {
	OpenRequestStream() (io.ReadWriter, error)
}

type RequestStreamIDProvider interface {
	RequestStreamID() uint64
}

type RequestStreamWriteCloser interface {
	CloseWrite() error
}

type RequestStreamReadCloser interface {
	CloseRead() error
}

type RequestStreamCanceler interface {
	CancelRead(code ErrorCode) error
	CancelWrite(code ErrorCode) error
}

type RequestStreamCloser interface {
	Close() error
}

type RequestStreamResetter interface {
	Reset() error
}

type RequestStreamReserver interface {
	Reserve(totalLen int) error
}

type RequestStreamDiscarder interface {
	DiscardBefore(offset int) error
}

type RequestStreamBuffer interface {
	io.ReadWriter
	RequestStreamIDProvider
	RequestStreamWriteCloser
	RequestStreamReadCloser
	RequestStreamCanceler
	RequestStreamCloser
	RequestStreamResetter
	RequestStreamReserver
	RequestStreamDiscarder
	Snapshot() []byte
	WaitForData(minLen int) ([]byte, bool, error)
	WaitForDataLen(minLen int) (int, bool, error)
	ReadRange(start, end int) ([]byte, error)
	ReadRangeInto(start, end int, dst []byte) ([]byte, error)
}

type QPACKStreamOpener interface {
	OpenEncoderStream() (io.Writer, error)
	AcceptEncoderStream() (io.Reader, error)
	OpenDecoderStream() (io.Writer, error)
	AcceptDecoderStream() (io.Reader, error)
}

// TransportStreamOpener groups the stream opener capabilities required by an
// HTTP/3 transport implementation that manages control, request, and QPACK
// streams together.
type TransportStreamOpener interface {
	ControlStreamOpener
	RequestStreamOpener
	QPACKStreamOpener
}

// PacketStreamAssembler exposes the additional buffering operations needed by a
// server-side HTTP/3 packet processor that reassembles peer streams from QUIC
// STREAM frames before handing them to higher-level request handling.
type PacketStreamAssembler interface {
	TransportStreamOpener
	IngestControlPayload(offset uint64, payload []byte) error
	IngestEncoderPayload(offset uint64, payload []byte) error
	IngestDecoderPayload(offset uint64, payload []byte) error
	IngestRequestPayload(streamID uint64, offset uint64, payload []byte) (RequestStreamBuffer, error)
	SnapshotControlPayload() []byte
	SnapshotEncoderPayload() []byte
	SnapshotDecoderPayload() []byte
	RequestStream(streamID uint64) RequestStreamBuffer
}

type QPACKChunkReader interface {
	ReadQPACKChunk() ([]byte, error)
}

type QPACKChunkStateReader interface {
	ReadQPACKChunkState() ([]byte, bool, error)
}

func readQPACKChunk(r io.Reader) ([]byte, bool, error) {
	if chunkReader, ok := r.(QPACKChunkStateReader); ok {
		return chunkReader.ReadQPACKChunkState()
	}
	if chunkReader, ok := r.(QPACKChunkReader); ok {
		chunk, err := chunkReader.ReadQPACKChunk()
		return chunk, false, err
	}
	chunk, err := io.ReadAll(r)
	return chunk, false, err
}

func consumeQPACKStreamType(buf []byte, expected StreamType, mismatchMessage string) ([]byte, bool, error) {
	if len(buf) == 0 {
		return buf, false, nil
	}
	length := 1 << (buf[0] >> 6)
	if len(buf) < length {
		return buf, false, nil
	}
	streamType, _, err := DecodeVarInt(buf[:length])
	if err != nil {
		return nil, false, err
	}
	if StreamType(streamType) != expected {
		return nil, false, errors.New(mismatchMessage)
	}
	return discardConsumedPrefix(buf, length), true, nil
}

func discardConsumedPrefix(buf []byte, consumed int) []byte {
	if consumed <= 0 {
		return buf
	}
	if consumed >= len(buf) {
		return buf[:0]
	}
	copy(buf, buf[consumed:])
	return buf[:len(buf)-consumed]
}

func requestStreamID(stream any) *uint64 {
	provider, ok := stream.(RequestStreamIDProvider)
	if !ok || provider == nil {
		return nil
	}
	id := provider.RequestStreamID()
	return &id
}

type requestStreamLifecycle struct {
	stream   io.ReadWriter
	mu       sync.Mutex
	closed   bool
	readEOF  bool
	writeEOF bool
}

func newRequestStreamLifecycle(stream io.ReadWriter) *requestStreamLifecycle {
	return &requestStreamLifecycle{stream: stream}
}

func (l *requestStreamLifecycle) closeWrite() {
	l.mu.Lock()
	if l.writeEOF {
		l.mu.Unlock()
		return
	}
	l.writeEOF = true
	l.mu.Unlock()
	if stream, ok := l.stream.(RequestStreamWriteCloser); ok {
		_ = stream.CloseWrite()
	}
}

func (l *requestStreamLifecycle) closeRead() {
	l.mu.Lock()
	if l.readEOF {
		l.mu.Unlock()
		return
	}
	l.readEOF = true
	l.mu.Unlock()
	if stream, ok := l.stream.(RequestStreamReadCloser); ok {
		_ = stream.CloseRead()
	}
}

func (l *requestStreamLifecycle) cancel(code ErrorCode) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	if stream, ok := l.stream.(RequestStreamCanceler); ok {
		_ = stream.CancelWrite(code)
		_ = stream.CancelRead(code)
	}
}

func (l *requestStreamLifecycle) close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.mu.Unlock()
	if stream, ok := l.stream.(RequestStreamCloser); ok {
		_ = stream.Close()
	}
}
