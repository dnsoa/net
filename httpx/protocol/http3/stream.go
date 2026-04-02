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

type QPACKStreamOpener interface {
	OpenEncoderStream() (io.Writer, error)
	AcceptEncoderStream() (io.Reader, error)
	OpenDecoderStream() (io.Writer, error)
	AcceptDecoderStream() (io.Reader, error)
}

type QPACKChunkReader interface {
	ReadQPACKChunk() ([]byte, error)
}

func readQPACKChunk(r io.Reader) ([]byte, error) {
	if chunkReader, ok := r.(QPACKChunkReader); ok {
		return chunkReader.ReadQPACKChunk()
	}
	return io.ReadAll(r)
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
