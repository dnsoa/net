package http3

import (
	"errors"
	"fmt"
	"io"

	"github.com/dnsoa/go/allocator"
	"github.com/dnsoa/net/httpx/core"
)

var (
	errStreamingRequestBody           = errors.New("http3 streaming request body error")
	errStreamingRequestBodyIncomplete = errors.New("http3 streaming request body incomplete")
	errStreamingRequestBodyMalformed  = errors.New("http3 streaming request body malformed")
)

type requestBodyReader struct {
	req           *core.Request
	session       *Session
	stream        RequestStreamBuffer
	streamID      *uint64
	flowControl   requestBodyFlowController
	offset        int
	dataStart     int
	dataEnd       int
	trailerBufPtr *allocator.Buffer
	totalRead     int
	seenTrailers  bool
	closed        bool
	eof           bool
}

type requestBodyFlowController interface {
	ConsumeStreamData(streamID uint64, consumedThrough uint64)
}

func newRequestBodyReader(req *core.Request, session *Session, stream RequestStreamBuffer, bodyOffset int, flowControl requestBodyFlowController) *requestBodyReader {
	if req == nil || session == nil || stream == nil {
		return nil
	}
	return &requestBodyReader{
		req:         req,
		session:     session,
		stream:      stream,
		streamID:    requestStreamID(stream),
		flowControl: flowControl,
		offset:      bodyOffset,
	}
}

func (r *requestBodyReader) Read(p []byte) (int, error) {
	if r == nil || r.closed {
		return 0, io.EOF
	}
	total := 0
	for len(p) > 0 {
		if r.dataStart < r.dataEnd {
			n := min(len(p), r.dataEnd-r.dataStart)
			chunk, err := r.stream.ReadRangeInto(r.dataStart, r.dataStart+n, p[:0])
			if err != nil {
				return total, wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
			}
			n = len(chunk)
			r.dataStart += n
			r.totalRead += n
			total += n
			p = p[n:]
			if r.dataStart >= r.dataEnd {
				if err := r.discardBefore(r.dataEnd); err != nil {
					return total, wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
				}
				r.dataStart = 0
				r.dataEnd = 0
			}
			continue
		}
		if err := r.fill(); err != nil {
			if err == io.EOF {
				if total > 0 {
					return total, nil
				}
			}
			return total, err
		}
	}
	return total, nil
}

func (r *requestBodyReader) Close() error {
	if r == nil {
		return nil
	}
	r.closed = true
	r.releaseTrailerBuffer()
	return nil
}

func (r *requestBodyReader) fill() error {
	for {
		availableLen, finReceived, err := r.stream.WaitForDataLen(r.offset + 1)
		if err != nil {
			return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
		}
		if r.offset >= availableLen {
			if finReceived {
				return r.finishEOF()
			}
			continue
		}
		headerLimit := availableLen
		if maxHeaderEnd := r.offset + 16; headerLimit > maxHeaderEnd {
			headerLimit = maxHeaderEnd
		}
		var headerScratch [16]byte
		headerBuf, err := r.stream.ReadRangeInto(r.offset, headerLimit, headerScratch[:0])
		if err != nil {
			return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
		}
		frame, consumed, err := DecodeFrameHeader(headerBuf)
		if err != nil {
			if !finReceived && isPartialData(err) {
				continue
			}
			if finReceived && isPartialData(err) {
				return wrapStreamingRequestBodyError(errStreamingRequestBodyIncomplete, io.ErrUnexpectedEOF)
			}
			return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
		}
		payloadStart := r.offset + consumed
		payloadEnd := payloadStart + int(frame.Length)
		availableLen, finReceived, err = r.stream.WaitForDataLen(payloadEnd)
		if err != nil {
			return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
		}
		if payloadEnd > availableLen {
			if !finReceived {
				continue
			}
			return wrapStreamingRequestBodyError(errStreamingRequestBodyIncomplete, io.ErrUnexpectedEOF)
		}
		r.offset = payloadEnd
		switch FrameType(frame.Type) {
		case FrameData:
			if r.seenTrailers {
				if err := r.discardBefore(r.offset); err != nil {
					return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
				}
				continue
			}
			if frame.Length == 0 {
				if err := r.discardBefore(r.offset); err != nil {
					return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
				}
				continue
			}
			r.dataStart = payloadStart
			r.dataEnd = payloadEnd
			return nil
		case FrameHeaders:
			payload, err := r.readRangePooled(payloadStart, payloadEnd, &r.trailerBufPtr)
			if err != nil {
				return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
			}
			if r.seenTrailers || isConnectTunnelRequest(r.req) {
				if err := r.discardBefore(r.offset); err != nil {
					return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
				}
				continue
			}
			trailers, err := r.session.qpack.decodeTrailers(payload, r.streamID)
			if err == nil {
				r.req.Trailers = trailers
			}
			r.seenTrailers = true
			if err := r.discardBefore(r.offset); err != nil {
				return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
			}
		default:
			if err := r.discardBefore(r.offset); err != nil {
				return wrapStreamingRequestBodyError(errStreamingRequestBodyMalformed, err)
			}
			continue
		}
	}
}

func (r *requestBodyReader) discardBefore(offset int) error {
	if err := r.stream.DiscardBefore(offset); err != nil {
		return err
	}
	if r.flowControl != nil && r.streamID != nil {
		r.flowControl.ConsumeStreamData(*r.streamID, uint64(offset))
	}
	return nil
}

func wrapStreamingRequestBodyError(kind error, err error) error {
	if err == nil {
		return kind
	}
	return fmt.Errorf("%w: %w", kind, err)
}

func (r *requestBodyReader) finishEOF() error {
	if r.eof {
		return io.EOF
	}
	r.eof = true
	r.releaseTrailerBuffer()
	if err := validateMessageContentLength(r.req.Headers, r.totalRead, true); err != nil {
		r.req.Headers.RemoveAllString("Content-Length")
	}
	r.req.ContentLength = int64(r.totalRead)
	return io.EOF
}

func (r *requestBodyReader) readRangePooled(start, end int, bufPtr **allocator.Buffer) ([]byte, error) {
	if r == nil || bufPtr == nil {
		return nil, io.ErrUnexpectedEOF
	}
	need := end - start
	if need <= 0 {
		if *bufPtr != nil {
			return (**bufPtr)[:0], nil
		}
		return nil, nil
	}
	alloc := core.DefaultAllocator()
	if *bufPtr == nil || cap(**bufPtr) < need {
		if *bufPtr != nil {
			_ = alloc.Put(*bufPtr)
		}
		*bufPtr = alloc.Get(need)
	}
	buf := (**bufPtr)[:need]
	return r.stream.ReadRangeInto(start, end, buf)
}

func (r *requestBodyReader) releaseTrailerBuffer() {
	if r == nil {
		return
	}
	if r.trailerBufPtr != nil {
		_ = core.DefaultAllocator().Put(r.trailerBufPtr)
		r.trailerBufPtr = nil
	}
}
