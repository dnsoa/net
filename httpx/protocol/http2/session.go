package http2

import (
	"errors"
	"io"

	"github.com/dnsoa/net/httpx/core"
)

type Session struct {
	conn              *Conn
	streams           *StreamManager
	maxReadFrameSize  int
	pool              *core.BytePool
	incomingRequests  map[uint32]*incomingRequest
	incomingResponses map[uint32]*incomingResponse
}

type incomingRequest struct {
	request  *core.Request
	body     []byte
	seenData bool
}

type incomingResponse struct {
	response *core.Response
	body     []byte
	seenData bool
}

func NewClientSession(reader io.Reader, writer io.Writer) *Session {
	conn := NewConn(reader, writer)
	conn.IsClient = true
	return newSession(conn, true)
}

func NewServerSession(reader io.Reader, writer io.Writer) *Session {
	conn := NewConn(reader, writer)
	conn.IsClient = false
	conn.NextStreamID = 2
	return newSession(conn, false)
}

func newSession(conn *Conn, isClient bool) *Session {
	return &Session{
		conn:              conn,
		streams:           NewStreamManager(isClient, conn.Settings, conn.PeerSettings),
		maxReadFrameSize:  int(conn.PeerSettings.MaxFrameSize),
		pool:              core.DefaultBytePool,
		incomingRequests:  make(map[uint32]*incomingRequest),
		incomingResponses: make(map[uint32]*incomingResponse),
	}
}

func (s *Session) WriteRequest(req *core.Request) (uint32, error) {
	stream, err := s.streams.OpenStream()
	if err != nil {
		return 0, err
	}
	hasTrailers := req.Trailers.Count() > 0
	endStream := len(req.Body) == 0 && !hasTrailers
	headers, err := s.streams.BuildRequestHeaderFrames(stream.ID, req, endStream)
	if err != nil {
		return 0, err
	}
	for _, frame := range headers {
		if err := s.writeFrame(frame, true); err != nil {
			return 0, err
		}
	}
	if endStream {
		return stream.ID, nil
	}
	if len(req.Body) > 0 {
		dataFrames, err := s.streams.BuildDataFrames(stream.ID, req.Body, !hasTrailers)
		if err != nil {
			return 0, err
		}
		for _, frame := range dataFrames {
			if err := s.writeFrame(frame, false); err != nil {
				return 0, err
			}
		}
	}
	if hasTrailers {
		trailerFrames, err := s.streams.BuildTrailerFrames(stream.ID, &req.Trailers, true)
		if err != nil {
			return 0, err
		}
		for _, frame := range trailerFrames {
			if err := s.writeFrame(frame, true); err != nil {
				return 0, err
			}
		}
	}
	return stream.ID, nil
}

func (s *Session) ReadRequest() (uint32, *core.Request, error) {
	for {
		frame, err := s.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch frame.Header.Type {
		case FrameHeaders, FrameContinuation:
			decoded, err := s.streams.ReceiveHeaderBlockFrame(frame)
			if err != nil {
				return 0, nil, err
			}
			if decoded == nil {
				continue
			}
			if pending := s.incomingRequests[decoded.StreamID]; pending != nil {
				trailers, err := s.streams.DecodeTrailerHeaderBlock(decoded.Fields)
				if err != nil {
					return 0, nil, err
				}
				pending.request.Trailers = trailers
				if decoded.EndStream {
					pending.request.Body = pending.body
					delete(s.incomingRequests, decoded.StreamID)
					return decoded.StreamID, pending.request, nil
				}
				continue
			}
			req, err := s.streams.DecodeRequestHeaderBlock(decoded.Fields)
			if err != nil {
				return 0, nil, err
			}
			if decoded.EndStream {
				return decoded.StreamID, req, nil
			}
			s.incomingRequests[decoded.StreamID] = &incomingRequest{request: req}
		case FrameData:
			pending := s.incomingRequests[frame.Header.StreamID]
			if pending == nil {
				return 0, nil, errors.New("http2 data frame without pending request")
			}
			if err := s.streams.ApplyReceivedFrame(frame); err != nil {
				return 0, nil, err
			}
			pending.seenData = true
			pending.body = appendBody(s.pool, pending.body, frame.Payload)
			if frame.Header.Flags&FlagEndStream != 0 {
				pending.request.Body = pending.body
				delete(s.incomingRequests, frame.Header.StreamID)
				return frame.Header.StreamID, pending.request, nil
			}
		case FrameRSTStream:
			if err := s.streams.ApplyReceivedFrame(frame); err != nil {
				return 0, nil, err
			}
			delete(s.incomingRequests, frame.Header.StreamID)
		case FrameSettings:
			if err := s.applyRemoteSettings(frame); err != nil {
				return 0, nil, err
			}
		default:
			if err := s.streams.ApplyReceivedFrame(frame); err != nil {
				return 0, nil, err
			}
		}
	}
}

func (s *Session) WriteResponse(streamID uint32, resp *core.Response) error {
	hasTrailers := resp.Trailers.Count() > 0
	endStream := (len(resp.Body) == 0 || !resp.Status.MayHaveBody()) && !hasTrailers
	headers, err := s.streams.BuildResponseHeaderFrames(streamID, resp, endStream)
	if err != nil {
		return err
	}
	for _, frame := range headers {
		if err := s.writeFrame(frame, true); err != nil {
			return err
		}
	}
	if endStream {
		return nil
	}
	if len(resp.Body) > 0 && resp.Status.MayHaveBody() {
		dataFrames, err := s.streams.BuildDataFrames(streamID, resp.Body, !hasTrailers)
		if err != nil {
			return err
		}
		for _, frame := range dataFrames {
			if err := s.writeFrame(frame, false); err != nil {
				return err
			}
		}
	}
	if hasTrailers {
		trailerFrames, err := s.streams.BuildTrailerFrames(streamID, &resp.Trailers, true)
		if err != nil {
			return err
		}
		for _, frame := range trailerFrames {
			if err := s.writeFrame(frame, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Session) ReadResponse() (uint32, *core.Response, error) {
	for {
		frame, err := s.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch frame.Header.Type {
		case FrameHeaders, FrameContinuation:
			decoded, err := s.streams.ReceiveHeaderBlockFrame(frame)
			if err != nil {
				return 0, nil, err
			}
			if decoded == nil {
				continue
			}
			if pending := s.incomingResponses[decoded.StreamID]; pending != nil {
				trailers, err := s.streams.DecodeTrailerHeaderBlock(decoded.Fields)
				if err != nil {
					return 0, nil, err
				}
				pending.response.Trailers = trailers
				if decoded.EndStream {
					pending.response.Body = pending.body
					delete(s.incomingResponses, decoded.StreamID)
					return decoded.StreamID, pending.response, nil
				}
				continue
			}
			resp, err := s.streams.DecodeResponseHeaderBlock(decoded.Fields)
			if err != nil {
				return 0, nil, err
			}
			if decoded.EndStream {
				return decoded.StreamID, resp, nil
			}
			s.incomingResponses[decoded.StreamID] = &incomingResponse{response: resp}
		case FrameData:
			pending := s.incomingResponses[frame.Header.StreamID]
			if pending == nil {
				return 0, nil, errors.New("http2 data frame without pending response")
			}
			if err := s.streams.ApplyReceivedFrame(frame); err != nil {
				return 0, nil, err
			}
			pending.seenData = true
			pending.body = appendBody(s.pool, pending.body, frame.Payload)
			if frame.Header.Flags&FlagEndStream != 0 {
				pending.response.Body = pending.body
				delete(s.incomingResponses, frame.Header.StreamID)
				return frame.Header.StreamID, pending.response, nil
			}
		case FrameRSTStream:
			if err := s.streams.ApplyReceivedFrame(frame); err != nil {
				return 0, nil, err
			}
			delete(s.incomingResponses, frame.Header.StreamID)
		case FrameSettings:
			if err := s.applyRemoteSettings(frame); err != nil {
				return 0, nil, err
			}
		default:
			if err := s.streams.ApplyReceivedFrame(frame); err != nil {
				return 0, nil, err
			}
		}
	}
}

func (s *Session) writeFrame(frame Frame, applyState bool) error {
	if applyState {
		if err := s.streams.ApplySentFrame(frame); err != nil {
			return err
		}
	}
	return s.conn.WriteFrame(frame.Header, frame.Payload)
}

func (s *Session) readFrame() (Frame, error) {
	maxSize := s.maxReadFrameSize
	if maxSize <= 0 {
		maxSize = int(s.streams.LocalSettings.MaxFrameSize)
	}
	if maxSize <= 0 {
		maxSize = 16384
	}
	return s.conn.ReadFrame(maxSize)
}

func (s *Session) applyRemoteSettings(frame Frame) error {
	if frame.Header.StreamID != 0 {
		return errors.New("http2 settings frame must use stream 0")
	}
	if frame.Header.Flags&FlagAck != 0 {
		return nil
	}
	if err := ApplySettingsPayload(&s.conn.PeerSettings, frame.Payload); err != nil {
		return err
	}
	s.streams.PeerSettings = s.conn.PeerSettings
	s.streams.encoder.SetMaxDynamicTableSizeLimit(s.conn.PeerSettings.HeaderTableSize)
	if size := int(s.conn.PeerSettings.MaxFrameSize); size > 0 {
		s.maxReadFrameSize = size
	}
	if s.conn.writer != nil {
		return s.conn.WriteFrame(FrameHeader{Type: FrameSettings, Flags: FlagAck, StreamID: 0}, nil)
	}
	return nil
}

func appendBody(pool *core.BytePool, dst, chunk []byte) []byte {
	if len(chunk) == 0 {
		return dst
	}
	if pool == nil {
		pool = core.DefaultBytePool
	}
	dst = pool.Grow(dst, len(chunk))
	return append(dst, chunk...)
}
