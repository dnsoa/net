package http3

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

type MemoryStreamOpenerFactory struct{}

type MemoryStreamOpener struct {
	mu                  sync.Mutex
	localControlStream  *memoryStream
	remoteControlStream *memoryStream
	localEncoderStream  *memoryStream
	remoteEncoderStream *memoryStream
	localDecoderStream  *memoryStream
	remoteDecoderStream *memoryStream
	requestStreams      map[uint64]*memoryStream
	nextStreamID        uint64
}

type memoryStream struct {
	mu          sync.Mutex
	cond        *sync.Cond
	buf         bytes.Buffer
	baseOffset  int
	id          uint64
	finReceived bool
	finOffset   uint64
	readClosed  bool
	writeClosed bool
}

var _ TransportStreamOpener = (*MemoryStreamOpener)(nil)
var _ PacketStreamAssembler = (*MemoryStreamOpener)(nil)
var _ RequestStreamBuffer = (*memoryStream)(nil)

func NewMemoryStreamOpenerFactory() *MemoryStreamOpenerFactory {
	return &MemoryStreamOpenerFactory{}
}

func (*MemoryStreamOpenerFactory) NewStreamOpener() *MemoryStreamOpener {
	return &MemoryStreamOpener{
		localControlStream:  &memoryStream{},
		remoteControlStream: &memoryStream{},
		localEncoderStream:  &memoryStream{},
		remoteEncoderStream: &memoryStream{},
		localDecoderStream:  &memoryStream{},
		remoteDecoderStream: &memoryStream{},
		requestStreams:      make(map[uint64]*memoryStream),
	}
}

func (o *MemoryStreamOpener) OpenControlStream() (io.Writer, error) {
	if o == nil || o.localControlStream == nil {
		return nil, errors.New("http3 memory control stream is nil")
	}
	return o.localControlStream, nil
}

func (o *MemoryStreamOpener) AcceptControlStream() (io.Reader, error) {
	if o == nil || o.remoteControlStream == nil {
		return nil, errors.New("http3 memory remote control stream is nil")
	}
	return o.remoteControlStream, nil
}

func (o *MemoryStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	if o == nil {
		return nil, errors.New("http3 memory opener is nil")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	stream := &memoryStream{id: o.nextStreamID}
	o.requestStreams[stream.id] = stream
	o.nextStreamID += 4
	return stream, nil
}

func (o *MemoryStreamOpener) OpenEncoderStream() (io.Writer, error) {
	if o == nil || o.localEncoderStream == nil {
		return nil, errors.New("http3 memory local encoder stream is nil")
	}
	return o.localEncoderStream, nil
}

func (o *MemoryStreamOpener) AcceptEncoderStream() (io.Reader, error) {
	if o == nil || o.remoteEncoderStream == nil {
		return nil, errors.New("http3 memory remote encoder stream is nil")
	}
	return o.remoteEncoderStream, nil
}

func (o *MemoryStreamOpener) OpenDecoderStream() (io.Writer, error) {
	if o == nil || o.localDecoderStream == nil {
		return nil, errors.New("http3 memory local decoder stream is nil")
	}
	return o.localDecoderStream, nil
}

func (o *MemoryStreamOpener) AcceptDecoderStream() (io.Reader, error) {
	if o == nil || o.remoteDecoderStream == nil {
		return nil, errors.New("http3 memory remote decoder stream is nil")
	}
	return o.remoteDecoderStream, nil
}

func (o *MemoryStreamOpener) IngestControlPayload(offset uint64, payload []byte) error {
	if o == nil || o.remoteControlStream == nil {
		return errors.New("http3 memory remote control stream is nil")
	}
	return o.remoteControlStream.writeAt(payload, offset)
}

func (o *MemoryStreamOpener) IngestEncoderPayload(offset uint64, payload []byte) error {
	if o == nil || o.remoteEncoderStream == nil {
		return errors.New("http3 memory remote encoder stream is nil")
	}
	return o.remoteEncoderStream.writeAt(payload, offset)
}

func (o *MemoryStreamOpener) IngestDecoderPayload(offset uint64, payload []byte) error {
	if o == nil || o.remoteDecoderStream == nil {
		return errors.New("http3 memory remote decoder stream is nil")
	}
	return o.remoteDecoderStream.writeAt(payload, offset)
}

func (o *MemoryStreamOpener) IngestRequestPayload(streamID uint64, offset uint64, payload []byte) (RequestStreamBuffer, error) {
	if o == nil {
		return nil, errors.New("http3 memory opener is nil")
	}
	stream := o.getOrCreateRequestStream(streamID)
	if err := stream.writeAt(payload, offset); err != nil {
		return nil, err
	}
	return stream, nil
}

func (o *MemoryStreamOpener) RequestStream(streamID uint64) RequestStreamBuffer {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.requestStreams[streamID]
}

func (o *MemoryStreamOpener) SnapshotControlPayload() []byte {
	if o == nil || o.remoteControlStream == nil {
		return nil
	}
	return o.remoteControlStream.Snapshot()
}

func (o *MemoryStreamOpener) SnapshotEncoderPayload() []byte {
	if o == nil || o.remoteEncoderStream == nil {
		return nil
	}
	return o.remoteEncoderStream.Snapshot()
}

func (o *MemoryStreamOpener) SnapshotDecoderPayload() []byte {
	if o == nil || o.remoteDecoderStream == nil {
		return nil
	}
	return o.remoteDecoderStream.Snapshot()
}

func (o *MemoryStreamOpener) SnapshotLocalControlPayload() []byte {
	if o == nil || o.localControlStream == nil {
		return nil
	}
	return o.localControlStream.Snapshot()
}

func (o *MemoryStreamOpener) SnapshotLocalEncoderPayload() []byte {
	if o == nil || o.localEncoderStream == nil {
		return nil
	}
	return o.localEncoderStream.Snapshot()
}

func (o *MemoryStreamOpener) SnapshotLocalDecoderPayload() []byte {
	if o == nil || o.localDecoderStream == nil {
		return nil
	}
	return o.localDecoderStream.Snapshot()
}

func (o *MemoryStreamOpener) getOrCreateRequestStream(streamID uint64) *memoryStream {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.requestStreams == nil {
		o.requestStreams = make(map[uint64]*memoryStream)
	}
	if stream, ok := o.requestStreams[streamID]; ok {
		stream.id = streamID
		return stream
	}
	stream := &memoryStream{id: streamID}
	o.requestStreams[streamID] = stream
	return stream
}

func (s *memoryStream) Write(p []byte) (int, error) {
	if s == nil {
		return 0, errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeClosed {
		return len(p), nil
	}
	n, err := s.buf.Write(p)
	s.cond.Broadcast()
	return n, err
}

func (s *memoryStream) Read(p []byte) (int, error) {
	if s == nil {
		return 0, errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf.Len() == 0 {
		return 0, io.EOF
	}
	return s.buf.Read(p)
}

func (s *memoryStream) RequestStreamID() uint64 {
	if s == nil {
		return 0
	}
	return s.id
}

func (s *memoryStream) CloseWrite() error { return nil }
func (s *memoryStream) CloseRead() error  { return nil }
func (s *memoryStream) Close() error      { return nil }

func (s *memoryStream) CancelRead(code ErrorCode) error {
	_ = code
	if s == nil {
		return errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readClosed = true
	s.cond.Broadcast()
	return nil
}

func (s *memoryStream) CancelWrite(code ErrorCode) error {
	_ = code
	if s == nil {
		return errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeClosed = true
	s.cond.Broadcast()
	return nil
}

func (s *memoryStream) ReadQPACKChunk() ([]byte, error) {
	if s == nil {
		return nil, errors.New("http3 memory stream is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf.Len() == 0 {
		return nil, nil
	}
	out := append([]byte(nil), s.buf.Bytes()...)
	s.buf.Reset()
	return out, nil
}

func (s *memoryStream) Reset() error {
	if s == nil {
		return errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
	s.baseOffset = 0
	s.cond.Broadcast()
	return nil
}

func (s *memoryStream) Reserve(totalLen int) error {
	if s == nil {
		return errors.New("http3 memory stream is nil")
	}
	if totalLen <= 0 {
		return nil
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	if totalLen <= s.absoluteLenLocked() {
		return nil
	}
	windowLen := totalLen - s.baseOffset
	if windowLen <= s.buf.Cap() {
		return nil
	}
	s.buf.Grow(windowLen - s.buf.Len())
	return nil
}

func (s *memoryStream) DiscardBefore(offset int) error {
	if s == nil {
		return errors.New("http3 memory stream is nil")
	}
	if offset <= 0 {
		return nil
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset <= s.baseOffset {
		return nil
	}
	absoluteLen := s.absoluteLenLocked()
	if offset >= absoluteLen {
		s.buf.Reset()
		s.baseOffset = offset
		s.cond.Broadcast()
		return nil
	}
	discard := offset - s.baseOffset
	if discard > 0 {
		_ = s.buf.Next(discard)
		s.baseOffset = offset
		if s.buf.Len() == 0 {
			s.buf.Reset()
		}
	}
	s.cond.Broadcast()
	return nil
}

func (s *memoryStream) Snapshot() []byte {
	if s == nil {
		return nil
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

func (s *memoryStream) WaitForData(minLen int) ([]byte, bool, error) {
	if s == nil {
		return nil, false, errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.readClosed && !s.finReceived && s.absoluteLenLocked() < minLen {
		s.cond.Wait()
	}
	if s.readClosed && !s.finReceived && s.absoluteLenLocked() < minLen {
		return append([]byte(nil), s.buf.Bytes()...), false, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), s.buf.Bytes()...), s.finReceived, nil
}

func (s *memoryStream) WaitForDataLen(minLen int) (int, bool, error) {
	if s == nil {
		return 0, false, errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.readClosed && !s.finReceived && s.absoluteLenLocked() < minLen {
		s.cond.Wait()
	}
	if s.readClosed && !s.finReceived && s.absoluteLenLocked() < minLen {
		return s.absoluteLenLocked(), false, io.ErrUnexpectedEOF
	}
	return s.absoluteLenLocked(), s.finReceived, nil
}

func (s *memoryStream) ReadRange(start, end int) ([]byte, error) {
	if s == nil {
		return nil, errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	relStart := start - s.baseOffset
	relEnd := end - s.baseOffset
	if start < s.baseOffset || relStart < 0 || relEnd < relStart || relEnd > s.buf.Len() {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]byte, end-start)
	copy(out, s.buf.Bytes()[relStart:relEnd])
	return out, nil
}

func (s *memoryStream) ReadRangeInto(start, end int, dst []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	relStart := start - s.baseOffset
	relEnd := end - s.baseOffset
	if start < s.baseOffset || relStart < 0 || relEnd < relStart || relEnd > s.buf.Len() {
		return nil, io.ErrUnexpectedEOF
	}
	need := end - start
	if cap(dst) < need {
		dst = make([]byte, need)
	} else {
		dst = dst[:need]
	}
	copy(dst, s.buf.Bytes()[relStart:relEnd])
	return dst, nil
}

func (s *memoryStream) MarkFIN(offset uint64) {
	if s == nil {
		return
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finReceived = true
	s.finOffset = offset
	s.cond.Broadcast()
}

func (s *memoryStream) FINReceived() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finReceived
}

func (s *memoryStream) writeAt(payload []byte, offset uint64) error {
	if s == nil {
		return errors.New("http3 memory stream is nil")
	}
	s.ensureCond()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readClosed {
		s.cond.Broadcast()
		return nil
	}
	start := int(offset)
	end := start + len(payload)
	if end < 0 {
		return errors.New("http3 memory stream offset overflow")
	}
	if len(payload) == 0 {
		s.cond.Broadcast()
		return nil
	}
	if end <= s.baseOffset {
		s.cond.Broadcast()
		return nil
	}
	if start < s.baseOffset {
		payload = payload[s.baseOffset-start:]
		start = s.baseOffset
	}
	relStart := start - s.baseOffset
	current := s.buf.Bytes()
	currentLen := len(current)
	if relStart > currentLen {
		gap := relStart - currentLen
		if gap > 0 {
			_, err := s.buf.Write(make([]byte, gap))
			if err != nil {
				return err
			}
		}
		_, err := s.buf.Write(payload)
		s.cond.Broadcast()
		return err
	}
	if relStart == currentLen {
		_, err := s.buf.Write(payload)
		s.cond.Broadcast()
		return err
	}
	copy(current[relStart:min(relStart+len(payload), currentLen)], payload[:min(len(payload), currentLen-relStart)])
	if relStart+len(payload) > currentLen {
		_, err := s.buf.Write(payload[currentLen-relStart:])
		if err != nil {
			return err
		}
	}
	s.cond.Broadcast()
	return nil
}

func (s *memoryStream) absoluteLenLocked() int {
	return s.baseOffset + s.buf.Len()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *memoryStream) ensureCond() {
	if s == nil || s.cond != nil {
		return
	}
	s.cond = sync.NewCond(&s.mu)
}
