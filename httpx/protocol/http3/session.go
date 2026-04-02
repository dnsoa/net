package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/dnsoa/net/httpx/core"
)

const (
	SettingQPACKMaxTableCapacity uint64 = 0x01
	SettingMaxFieldSectionSize   uint64 = 0x06
	SettingQPACKBlockedStreams   uint64 = 0x07
	SettingEnableConnectProtocol uint64 = 0x08
	SettingH3Datagram            uint64 = 0x33
)

type Session struct {
	IsClient         bool
	Settings         Settings
	PeerSettings     Settings
	qpack            *QpackCodec
	settingsSent     bool
	settingsReceived bool
	encoderWriteInit bool
	encoderReadInit  bool
	decoderWriteInit bool
	decoderReadInit  bool
	encoderReadBuf   []byte
	decoderReadBuf   []byte
}

type Transport struct {
	session       *Session
	controlOpener ControlStreamOpener
	requestOpener RequestStreamOpener
	qpackOpener   QPACKStreamOpener
	encoderWriter io.Writer
	encoderReader io.Reader
	decoderWriter io.Writer
	decoderReader io.Reader
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
	resp, err := t.session.ReadResponseOnStream(stream, stream)
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
	writer, err := t.getEncoderWriter()
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
	reader, err := t.getEncoderReader()
	if err != nil {
		return err
	}
	if reader == nil {
		return nil
	}
	err = t.session.ReadEncoderStream(reader)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (t *Transport) writeLocalQPACKDecoder() error {
	if t.qpackOpener == nil {
		return nil
	}
	writer, err := t.getDecoderWriter()
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
	reader, err := t.getDecoderReader()
	if err != nil {
		return err
	}
	if reader == nil {
		return nil
	}
	err = t.session.ReadDecoderStream(reader)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (t *Transport) getEncoderWriter() (io.Writer, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.encoderWriter != nil {
		return t.encoderWriter, nil
	}
	writer, err := t.qpackOpener.OpenEncoderStream()
	if err != nil {
		return nil, err
	}
	t.encoderWriter = writer
	return writer, nil
}

func (t *Transport) getEncoderReader() (io.Reader, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.encoderReader != nil {
		return t.encoderReader, nil
	}
	reader, err := t.qpackOpener.AcceptEncoderStream()
	if err != nil {
		return nil, err
	}
	t.encoderReader = reader
	return reader, nil
}

func (t *Transport) getDecoderWriter() (io.Writer, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.decoderWriter != nil {
		return t.decoderWriter, nil
	}
	writer, err := t.qpackOpener.OpenDecoderStream()
	if err != nil {
		return nil, err
	}
	t.decoderWriter = writer
	return writer, nil
}

func (t *Transport) getDecoderReader() (io.Reader, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.decoderReader != nil {
		return t.decoderReader, nil
	}
	reader, err := t.qpackOpener.AcceptDecoderStream()
	if err != nil {
		return nil, err
	}
	t.decoderReader = reader
	return reader, nil
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
	if s.settingsReceived {
		return errors.New("http3 control stream settings already received")
	}
	streamType, err := readVarIntFromReader(r)
	if err != nil {
		return err
	}
	if StreamType(streamType) != StreamTypeControl {
		return errors.New("http3 unexpected unidirectional stream type")
	}
	frame, err := readNextFrame(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("http3 control stream missing settings frame")
		}
		return err
	}
	if FrameType(frame.Header.Type) != FrameSettings {
		return errors.New("http3 control stream first frame must be settings")
	}
	settings, err := DecodeSettings(frame.Payload)
	if err != nil {
		return err
	}
	s.PeerSettings = settings
	s.qpack.SetLocalCapacity(settings.QPACKMaxTableCap)
	s.settingsReceived = true
	for {
		frame, err := readNextFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if FrameType(frame.Header.Type) == FrameSettings {
			return errors.New("http3 control stream must not contain duplicate settings")
		}
	}
}

func (s *Session) WriteEncoderStream(w io.Writer) error {
	payload := s.qpack.DrainEncoderInstructions()
	if len(payload) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(payload)+8)
	if !s.encoderWriteInit {
		var err error
		buf, err = AppendVarInt(buf, uint64(StreamTypeQPACKEncoder))
		if err != nil {
			return err
		}
		s.encoderWriteInit = true
	}
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

func (s *Session) ReadEncoderStream(r io.Reader) error {
	chunk, err := readQPACKChunk(r)
	if err != nil {
		return err
	}
	if len(chunk) == 0 && len(s.encoderReadBuf) == 0 {
		return nil
	}
	s.encoderReadBuf = append(s.encoderReadBuf, chunk...)
	if !s.encoderReadInit {
		remaining, ok, err := consumeQPACKStreamType(s.encoderReadBuf, StreamTypeQPACKEncoder, "http3 unexpected qpack encoder stream type")
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		s.encoderReadBuf = remaining
		s.encoderReadInit = true
	}
	if len(s.encoderReadBuf) == 0 {
		return nil
	}
	consumed, err := s.qpack.consumeEncoderInstructions(s.encoderReadBuf)
	if err != nil {
		return err
	}
	s.encoderReadBuf = discardConsumedPrefix(s.encoderReadBuf, consumed)
	return nil
}

func (s *Session) WriteDecoderStream(w io.Writer) error {
	payload := s.qpack.DrainDecoderInstructions()
	if len(payload) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(payload)+8)
	if !s.decoderWriteInit {
		var err error
		buf, err = AppendVarInt(buf, uint64(StreamTypeQPACKDecoder))
		if err != nil {
			return err
		}
		s.decoderWriteInit = true
	}
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

func (s *Session) ReadDecoderStream(r io.Reader) error {
	chunk, err := readQPACKChunk(r)
	if err != nil {
		return err
	}
	if len(chunk) == 0 && len(s.decoderReadBuf) == 0 {
		return nil
	}
	s.decoderReadBuf = append(s.decoderReadBuf, chunk...)
	if !s.decoderReadInit {
		remaining, ok, err := consumeQPACKStreamType(s.decoderReadBuf, StreamTypeQPACKDecoder, "http3 unexpected qpack decoder stream type")
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		s.decoderReadBuf = remaining
		s.decoderReadInit = true
	}
	if len(s.decoderReadBuf) == 0 {
		return nil
	}
	consumed, err := s.qpack.consumeDecoderInstructions(s.decoderReadBuf)
	if err != nil {
		return err
	}
	s.decoderReadBuf = discardConsumedPrefix(s.decoderReadBuf, consumed)
	return nil
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
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	if len(body) > 0 {
		if err := writeFrame(w, FrameData, body); err != nil {
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
	return s.ReadRequestOnStream(nil, r)
}

func (s *Session) ReadRequestOnStream(stream any, r io.Reader) (*core.Request, error) {
	if !s.settingsReceived {
		return nil, errors.New("http3 peer settings not received")
	}
	message, err := s.readRequestOrResponse(r, true, requestStreamID(stream))
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
	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if len(body) > 0 && resp.Status.MayHaveBody() {
		if err := writeFrame(w, FrameData, body); err != nil {
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
	return s.ReadResponseOnStream(nil, r)
}

func (s *Session) ReadResponseOnStream(stream any, r io.Reader) (*core.Response, error) {
	if !s.settingsReceived {
		return nil, errors.New("http3 peer settings not received")
	}
	message, err := s.readRequestOrResponse(r, false, requestStreamID(stream))
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
	if settings.EnableConnectProto {
		dst, err = appendSetting(dst, SettingEnableConnectProtocol, 1)
		if err != nil {
			return nil, err
		}
	}
	if settings.EnableDatagrams {
		dst, err = appendSetting(dst, SettingH3Datagram, 1)
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
		case SettingEnableConnectProtocol:
			settings.EnableConnectProto = value != 0
		case SettingH3Datagram:
			settings.EnableDatagrams = value != 0
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

func isInvalidMessageFrame(frameType FrameType) bool {
	switch frameType {
	case FrameCancelPush, FrameSettings, FrameGoAway, FrameMaxPushID:
		return true
	default:
		return false
	}
}

func (s *Session) readRequestOrResponse(r io.Reader, isRequest bool, streamID *uint64) (any, error) {
	frame, err := readNextFrame(r)
	if err != nil {
		return nil, err
	}
	if FrameType(frame.Header.Type) != FrameHeaders {
		return nil, errors.New("http3 message stream missing headers")
	}
	if isRequest {
		req, err := s.qpack.decodeRequest(frame.Payload, streamID)
		if err != nil {
			return nil, err
		}
		var bodyData []byte
		seenTrailers := false
		for {
			frame, err := readNextFrame(r)
			if err != nil {
				if errors.Is(err, io.EOF) {
					req.Body = io.NopCloser(bytes.NewReader(bodyData))
					req.ContentLength = int64(len(bodyData))
					return req, nil
				}
				core.ReleaseRequest(req)
				return nil, err
			}
			frameType := FrameType(frame.Header.Type)
			switch frameType {
			case FrameData:
				if seenTrailers {
					core.ReleaseRequest(req)
					return nil, errors.New("http3 message stream must not contain data after trailers")
				}
				bodyData = appendBody(bodyData, frame.Payload)
			case FrameHeaders:
				if seenTrailers {
					core.ReleaseRequest(req)
					return nil, errors.New("http3 message stream must not contain multiple trailer sections")
				}
				trailers, err := s.qpack.decodeTrailers(frame.Payload, streamID)
				if err != nil {
					core.ReleaseRequest(req)
					return nil, err
				}
				req.Trailers = trailers
				seenTrailers = true
			default:
				if isInvalidMessageFrame(frameType) {
					core.ReleaseRequest(req)
					return nil, errors.New("http3 message stream contains invalid frame type")
				}
			}
		}
	}
	resp, err := s.qpack.decodeResponse(frame.Payload, streamID)
	if err != nil {
		return nil, err
	}
	var bodyData []byte
	seenTrailers := false
	for {
		frame, err := readNextFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				resp.Body = io.NopCloser(bytes.NewReader(bodyData))
				resp.ContentLength = int64(len(bodyData))
				return resp, nil
			}
			core.ReleaseResponse(resp)
			return nil, err
		}
		frameType := FrameType(frame.Header.Type)
		switch frameType {
		case FrameData:
			if seenTrailers {
				core.ReleaseResponse(resp)
				return nil, errors.New("http3 message stream must not contain data after trailers")
			}
			bodyData = appendBody(bodyData, frame.Payload)
		case FrameHeaders:
			if seenTrailers {
				core.ReleaseResponse(resp)
				return nil, errors.New("http3 message stream must not contain multiple trailer sections")
			}
			trailers, err := s.qpack.decodeTrailers(frame.Payload, streamID)
			if err != nil {
				core.ReleaseResponse(resp)
				return nil, err
			}
			resp.Trailers = trailers
			seenTrailers = true
		default:
			if isInvalidMessageFrame(frameType) {
				core.ReleaseResponse(resp)
				return nil, errors.New("http3 message stream contains invalid frame type")
			}
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
