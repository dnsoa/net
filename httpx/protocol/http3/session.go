package http3

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/dnsoa/net/httpx/core"
)

type StreamType uint64

const (
	StreamTypeControl      StreamType = 0x00
	StreamTypePush         StreamType = 0x01
	StreamTypeQPACKEncoder StreamType = 0x02
	StreamTypeQPACKDecoder StreamType = 0x03
)

const (
	SettingQPACKMaxTableCapacity uint64 = 0x01
	SettingMaxFieldSectionSize   uint64 = 0x06
	SettingQPACKBlockedStreams   uint64 = 0x07
)

type Session struct {
	IsClient         bool
	Settings         Settings
	PeerSettings     Settings
	qpack            *QpackCodec
	settingsSent     bool
	settingsReceived bool
}

type ControlStreamOpener interface {
	OpenControlStream() (io.Writer, error)
	AcceptControlStream() (io.Reader, error)
}

type RequestStreamOpener interface {
	OpenRequestStream() (io.ReadWriter, error)
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

type Transport struct {
	session       *Session
	controlOpener ControlStreamOpener
	requestOpener RequestStreamOpener
	qpackOpener   QPACKStreamOpener
	bootstrapped  bool
	bootstrapping bool
	bootstrapCond *sync.Cond
	bootstrapErr  error
	mu            sync.Mutex
}

func NewClientSession() *Session {
	return newSession(true)
}

func NewServerSession() *Session {
	return newSession(false)
}

func newSession(isClient bool) *Session {
	return &Session{
		IsClient: isClient,
		Settings: Settings{
			QPACKMaxTableCap:    4096,
			QPACKBlockedStreams: 100,
		},
		qpack: NewQpackCodec(),
	}
}

func NewTransport(session *Session, controlOpener ControlStreamOpener, requestOpener RequestStreamOpener) *Transport {
	t := &Transport{
		session:       session,
		controlOpener: controlOpener,
		requestOpener: requestOpener,
	}
	if qpackOpener, ok := controlOpener.(QPACKStreamOpener); ok {
		t.qpackOpener = qpackOpener
	}
	t.bootstrapCond = sync.NewCond(&t.mu)
	return t
}

func (t *Transport) Bootstrap() error {
	t.mu.Lock()
	if t.bootstrapCond == nil {
		t.bootstrapCond = sync.NewCond(&t.mu)
	}
	for t.bootstrapping {
		t.bootstrapCond.Wait()
	}
	if t.bootstrapped {
		t.mu.Unlock()
		return nil
	}
	t.bootstrapping = true
	t.mu.Unlock()

	err := t.bootstrapOnce()

	t.mu.Lock()
	t.bootstrapping = false
	if err == nil {
		t.bootstrapped = true
		t.bootstrapErr = nil
	} else {
		t.bootstrapErr = err
	}
	t.bootstrapCond.Broadcast()
	t.mu.Unlock()
	return err
}

func (t *Transport) RoundTrip(req *core.Request) (*core.Response, error) {
	return t.RoundTripContext(context.Background(), req)
}

func (t *Transport) RoundTripContext(ctx context.Context, req *core.Request) (*core.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := t.Bootstrap(); err != nil {
		return nil, err
	}
	if t.requestOpener == nil {
		return nil, errors.New("http3 request opener is nil")
	}
	if err := t.readRemoteQPACKDecoder(); err != nil {
		return nil, err
	}
	stream, err := t.requestOpener.OpenRequestStream()
	if err != nil {
		return nil, err
	}
	lifecycle := newRequestStreamLifecycle(stream)
	defer lifecycle.close()
	if err := ctx.Err(); err != nil {
		lifecycle.cancel(ErrRequestCancelled)
		return nil, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			lifecycle.cancel(ErrRequestCancelled)
		case <-done:
		}
	}()
	if err := t.session.WriteRequest(stream, req); err != nil {
		lifecycle.cancel(ErrRequestCancelled)
		return nil, err
	}
	if err := t.writeLocalQPACKEncoder(); err != nil {
		lifecycle.cancel(ErrRequestCancelled)
		return nil, err
	}
	lifecycle.closeWrite()
	if err := t.readRemoteQPACKEncoder(); err != nil {
		lifecycle.cancel(ErrRequestCancelled)
		return nil, err
	}
	resp, err := t.session.ReadResponse(stream)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		lifecycle.cancel(ErrRequestCancelled)
		return nil, err
	}
	if err := t.writeLocalQPACKDecoder(); err != nil {
		lifecycle.cancel(ErrRequestCancelled)
		core.ReleaseResponse(resp)
		return nil, err
	}
	if err := t.readRemoteQPACKDecoder(); err != nil {
		lifecycle.cancel(ErrRequestCancelled)
		core.ReleaseResponse(resp)
		return nil, err
	}
	lifecycle.closeRead()
	return resp, nil
}

func (t *Transport) bootstrapOnce() error {
	if t.session == nil {
		return errors.New("http3 transport session is nil")
	}
	if t.controlOpener == nil {
		return errors.New("http3 control opener is nil")
	}
	localControl, err := t.controlOpener.OpenControlStream()
	if err != nil {
		return err
	}
	if err := t.session.WriteControlStream(localControl); err != nil {
		return err
	}
	remoteControl, err := t.controlOpener.AcceptControlStream()
	if err != nil {
		return err
	}
	if err := t.session.ReadControlStream(remoteControl); err != nil {
		return err
	}
	if err := t.writeLocalQPACKEncoder(); err != nil {
		return err
	}
	if err := t.readRemoteQPACKEncoder(); err != nil {
		return err
	}
	return nil
}

func (t *Transport) writeLocalQPACKEncoder() error {
	if t.qpackOpener == nil {
		return nil
	}
	writer, err := t.qpackOpener.OpenEncoderStream()
	if err != nil {
		return err
	}
	if writer == nil {
		return nil
	}
	return t.session.WriteEncoderStream(writer)
}

func (t *Transport) readRemoteQPACKEncoder() error {
	if t.qpackOpener == nil {
		return nil
	}
	reader, err := t.qpackOpener.AcceptEncoderStream()
	if err != nil {
		return err
	}
	if reader == nil {
		return nil
	}
	return t.session.ReadEncoderStream(reader)
}

func (t *Transport) writeLocalQPACKDecoder() error {
	if t.qpackOpener == nil {
		return nil
	}
	writer, err := t.qpackOpener.OpenDecoderStream()
	if err != nil {
		return err
	}
	if writer == nil {
		return nil
	}
	return t.session.WriteDecoderStream(writer)
}

func (t *Transport) readRemoteQPACKDecoder() error {
	if t.qpackOpener == nil {
		return nil
	}
	reader, err := t.qpackOpener.AcceptDecoderStream()
	if err != nil {
		return err
	}
	if reader == nil {
		return nil
	}
	return t.session.ReadDecoderStream(reader)
}

func (s *Session) WriteControlStream(w io.Writer) error {
	s.qpack.SetRemoteCapacity(s.Settings.QPACKMaxTableCap)
	if s.settingsSent {
		return nil
	}
	buf, err := AppendVarInt(nil, uint64(StreamTypeControl))
	if err != nil {
		return err
	}
	payload, err := EncodeSettings(s.Settings, nil)
	if err != nil {
		return err
	}
	headers, err := FrameHeader{Type: uint64(FrameSettings), Length: uint64(len(payload))}.Encode(nil)
	if err != nil {
		return err
	}
	buf = append(buf, headers...)
	buf = append(buf, payload...)
	_, err = w.Write(buf)
	if err == nil {
		s.settingsSent = true
	}
	return err
}

func (s *Session) ReadControlStream(r io.Reader) error {
	streamType, err := readVarIntFromReader(r)
	if err != nil {
		return err
	}
	if StreamType(streamType) != StreamTypeControl {
		return errors.New("http3 unexpected unidirectional stream type")
	}
	for {
		frame, err := readNextFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if FrameType(frame.Header.Type) != FrameSettings {
			continue
		}
		settings, err := DecodeSettings(frame.Payload)
		if err != nil {
			return err
		}
		s.PeerSettings = settings
		s.qpack.SetLocalCapacity(settings.QPACKMaxTableCap)
		s.settingsReceived = true
		return nil
	}
	return errors.New("http3 control stream missing settings frame")
}

func (s *Session) WriteEncoderStream(w io.Writer) error {
	payload := s.qpack.DrainEncoderInstructions()
	if len(payload) == 0 {
		return nil
	}
	buf, err := AppendVarInt(nil, uint64(StreamTypeQPACKEncoder))
	if err != nil {
		return err
	}
	buf = append(buf, payload...)
	_, err = w.Write(buf)
	return err
}

func (s *Session) ReadEncoderStream(r io.Reader) error {
	streamType, err := readVarIntFromReader(r)
	if err != nil {
		return err
	}
	if StreamType(streamType) != StreamTypeQPACKEncoder {
		return errors.New("http3 unexpected qpack encoder stream type")
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return s.qpack.ApplyEncoderInstructions(payload)
}

func (s *Session) WriteDecoderStream(w io.Writer) error {
	payload := s.qpack.DrainDecoderInstructions()
	if len(payload) == 0 {
		return nil
	}
	buf, err := AppendVarInt(nil, uint64(StreamTypeQPACKDecoder))
	if err != nil {
		return err
	}
	buf = append(buf, payload...)
	_, err = w.Write(buf)
	return err
}

func (s *Session) ReadDecoderStream(r io.Reader) error {
	streamType, err := readVarIntFromReader(r)
	if err != nil {
		return err
	}
	if StreamType(streamType) != StreamTypeQPACKDecoder {
		return errors.New("http3 unexpected qpack decoder stream type")
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return s.qpack.ApplyDecoderInstructions(payload)
}

func (s *Session) WriteRequest(w io.Writer, req *core.Request) error {
	if !s.settingsSent {
		return errors.New("http3 settings not sent")
	}
	headersBlock, err := s.qpack.EncodeRequest(req)
	if err != nil {
		return err
	}
	if err := writeFrame(w, FrameHeaders, headersBlock); err != nil {
		return err
	}
	if len(req.Body) > 0 {
		if err := writeFrame(w, FrameData, req.Body); err != nil {
			return err
		}
	}
	if req.Trailers.Count() > 0 {
		trailerBlock, err := s.qpack.EncodeTrailers(&req.Trailers)
		if err != nil {
			return err
		}
		if err := writeFrame(w, FrameHeaders, trailerBlock); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) ReadRequest(r io.Reader) (*core.Request, error) {
	if !s.settingsReceived {
		return nil, errors.New("http3 peer settings not received")
	}
	message, err := s.readRequestOrResponse(r, true)
	if err != nil {
		return nil, err
	}
	return message.(*core.Request), nil
}

func (s *Session) WriteResponse(w io.Writer, resp *core.Response) error {
	if !s.settingsSent {
		return errors.New("http3 settings not sent")
	}
	headersBlock, err := s.qpack.EncodeResponse(resp)
	if err != nil {
		return err
	}
	if err := writeFrame(w, FrameHeaders, headersBlock); err != nil {
		return err
	}
	if len(resp.Body) > 0 && resp.Status.MayHaveBody() {
		if err := writeFrame(w, FrameData, resp.Body); err != nil {
			return err
		}
	}
	if resp.Trailers.Count() > 0 {
		trailerBlock, err := s.qpack.EncodeTrailers(&resp.Trailers)
		if err != nil {
			return err
		}
		if err := writeFrame(w, FrameHeaders, trailerBlock); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) ReadResponse(r io.Reader) (*core.Response, error) {
	if !s.settingsReceived {
		return nil, errors.New("http3 peer settings not received")
	}
	message, err := s.readRequestOrResponse(r, false)
	if err != nil {
		return nil, err
	}
	return message.(*core.Response), nil
}

func EncodeSettings(settings Settings, dst []byte) ([]byte, error) {
	var err error
	if settings.QPACKMaxTableCap > 0 {
		dst, err = appendSetting(dst, SettingQPACKMaxTableCapacity, settings.QPACKMaxTableCap)
		if err != nil {
			return nil, err
		}
	}
	if settings.MaxFieldSectionSize > 0 {
		dst, err = appendSetting(dst, SettingMaxFieldSectionSize, settings.MaxFieldSectionSize)
		if err != nil {
			return nil, err
		}
	}
	if settings.QPACKBlockedStreams > 0 {
		dst, err = appendSetting(dst, SettingQPACKBlockedStreams, settings.QPACKBlockedStreams)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func DecodeSettings(payload []byte) (Settings, error) {
	var settings Settings
	offset := 0
	for offset < len(payload) {
		id, n, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return Settings{}, err
		}
		offset += n
		value, n, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return Settings{}, err
		}
		offset += n
		switch id {
		case SettingQPACKMaxTableCapacity:
			settings.QPACKMaxTableCap = value
		case SettingMaxFieldSectionSize:
			settings.MaxFieldSectionSize = value
		case SettingQPACKBlockedStreams:
			settings.QPACKBlockedStreams = value
		}
	}
	return settings, nil
}

type DecodedFrame struct {
	Header  FrameHeader
	Payload []byte
}

func writeFrame(w io.Writer, frameType FrameType, payload []byte) error {
	encoded, err := FrameHeader{Type: uint64(frameType), Length: uint64(len(payload))}.Encode(nil)
	if err != nil {
		return err
	}
	buf := append(encoded, payload...)
	_, err = w.Write(buf)
	return err
}

func appendSetting(dst []byte, id uint64, value uint64) ([]byte, error) {
	var err error
	dst, err = AppendVarInt(dst, id)
	if err != nil {
		return nil, err
	}
	return AppendVarInt(dst, value)
}

func appendBody(dst, chunk []byte) []byte {
	if len(chunk) == 0 {
		return dst
	}
	return append(dst, chunk...)
}

func (s *Session) readRequestOrResponse(r io.Reader, isRequest bool) (any, error) {
	frame, err := readNextFrame(r)
	if err != nil {
		return nil, err
	}
	if FrameType(frame.Header.Type) != FrameHeaders {
		return nil, errors.New("http3 message stream missing headers")
	}
	if isRequest {
		req, err := s.qpack.DecodeRequest(frame.Payload)
		if err != nil {
			return nil, err
		}
		for {
			frame, err := readNextFrame(r)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return req, nil
				}
				core.ReleaseRequest(req)
				return nil, err
			}
			switch FrameType(frame.Header.Type) {
			case FrameData:
				req.Body = appendBody(req.Body, frame.Payload)
			case FrameHeaders:
				trailers, err := s.qpack.DecodeTrailers(frame.Payload)
				if err != nil {
					core.ReleaseRequest(req)
					return nil, err
				}
				req.Trailers = trailers
			}
		}
	}
	resp, err := s.qpack.DecodeResponse(frame.Payload)
	if err != nil {
		return nil, err
	}
	for {
		frame, err := readNextFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return resp, nil
			}
			core.ReleaseResponse(resp)
			return nil, err
		}
		switch FrameType(frame.Header.Type) {
		case FrameData:
			resp.Body = appendBody(resp.Body, frame.Payload)
		case FrameHeaders:
			trailers, err := s.qpack.DecodeTrailers(frame.Payload)
			if err != nil {
				core.ReleaseResponse(resp)
				return nil, err
			}
			resp.Trailers = trailers
		}
	}
}

func readNextFrame(r io.Reader) (DecodedFrame, error) {
	frameType, err := readVarIntFromReader(r)
	if err != nil {
		return DecodedFrame{}, err
	}
	length, err := readVarIntFromReader(r)
	if err != nil {
		return DecodedFrame{}, err
	}
	if length > uint64(^uint(0)>>1) {
		return DecodedFrame{}, errors.New("http3 frame payload too large")
	}
	payload := make([]byte, int(length))
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return DecodedFrame{}, err
		}
	}
	return DecodedFrame{Header: FrameHeader{Type: frameType, Length: length}, Payload: payload}, nil
}

func readVarIntFromReader(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	prefix := first[0] >> 6
	length := 1 << prefix
	buf := make([]byte, length)
	buf[0] = first[0]
	if length > 1 {
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, err
		}
	}
	value, _, err := DecodeVarInt(buf)
	return value, err
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
