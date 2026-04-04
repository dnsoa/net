package http3

import (
	"fmt"
	"log"
	"sort"
)

const (
	quicFrameTypeMaxData           byte = 0x10
	quicFrameTypeMaxStreamData     byte = 0x11
	quicFrameTypeDataBlocked       byte = 0x14
	quicFrameTypeStreamDataBlocked byte = 0x15

	quicInitialConnectionReceiveWindow = 1 << 20
	quicInitialStreamReceiveWindow     = 1 << 20
)

type QUICMaxDataFrame struct {
	MaximumData uint64
}

type QUICMaxStreamDataFrame struct {
	StreamID          uint64
	MaximumStreamData uint64
}

type QUICStreamFlowControlSnapshot struct {
	HighestReceived uint64
	ConsumedBytes   uint64
	LocalMaxData    uint64
	PeerMaxData     uint64
	HighestSent     uint64
	PendingMaxData  bool
}

type QUICFlowControlSnapshot struct {
	ReceivedBytes  uint64
	ConsumedBytes  uint64
	LocalMaxData   uint64
	PeerMaxData    uint64
	SentBytes      uint64
	PendingMaxData bool
	Streams        map[uint64]QUICStreamFlowControlSnapshot
}

type quicFlowControlState struct {
	localMaxData    uint64
	localStreamData uint64
	peerMaxData     uint64
	receivedBytes   uint64
	consumedBytes   uint64
	sentBytes       uint64
	pendingMaxData  bool
	streams         map[uint64]*quicFlowControlStream
}

type quicFlowControlStream struct {
	highestReceived uint64
	consumedBytes   uint64
	localMaxData    uint64
	peerMaxData     uint64
	highestSent     uint64
	pendingMaxData  bool
}

func ParseQUICMaxDataFrame(payload []byte) (QUICMaxDataFrame, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeMaxData {
		return QUICMaxDataFrame{}, 0, fmt.Errorf("http3 invalid max_data frame")
	}
	maximumData, consumed, err := DecodeVarInt(payload[1:])
	if err != nil {
		return QUICMaxDataFrame{}, 0, err
	}
	return QUICMaxDataFrame{MaximumData: maximumData}, consumed + 1, nil
}

func AppendQUICMaxDataFrame(dst []byte, maximumData uint64) ([]byte, error) {
	dst = append(dst, quicFrameTypeMaxData)
	return AppendVarInt(dst, maximumData)
}

func ParseQUICMaxStreamDataFrame(payload []byte) (QUICMaxStreamDataFrame, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeMaxStreamData {
		return QUICMaxStreamDataFrame{}, 0, fmt.Errorf("http3 invalid max_stream_data frame")
	}
	offset := 1
	streamID, consumed, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICMaxStreamDataFrame{}, 0, err
	}
	offset += consumed
	maximumData, consumed, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICMaxStreamDataFrame{}, 0, err
	}
	offset += consumed
	return QUICMaxStreamDataFrame{StreamID: streamID, MaximumStreamData: maximumData}, offset, nil
}

func AppendQUICMaxStreamDataFrame(dst []byte, streamID uint64, maximumData uint64) ([]byte, error) {
	dst = append(dst, quicFrameTypeMaxStreamData)
	var err error
	dst, err = AppendVarInt(dst, streamID)
	if err != nil {
		return nil, err
	}
	return AppendVarInt(dst, maximumData)
}

func parseQUICDataBlockedFrame(payload []byte) (uint64, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeDataBlocked {
		return 0, 0, fmt.Errorf("http3 invalid data_blocked frame")
	}
	value, consumed, err := DecodeVarInt(payload[1:])
	if err != nil {
		return 0, 0, err
	}
	return value, consumed + 1, nil
}

func parseQUICStreamDataBlockedFrame(payload []byte) (uint64, uint64, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeStreamDataBlocked {
		return 0, 0, 0, fmt.Errorf("http3 invalid stream_data_blocked frame")
	}
	offset := 1
	streamID, consumed, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, err
	}
	offset += consumed
	limit, consumed, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, err
	}
	offset += consumed
	return streamID, limit, offset, nil
}

func (s *quicFlowControlState) observeReceivedStream(streamID uint64, offset uint64, payloadLen int) error {
	if payloadLen < 0 {
		return fmt.Errorf("http3 invalid stream payload length %d", payloadLen)
	}
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	end := offset + uint64(payloadLen)
	if end <= stream.highestReceived {
		return nil
	}
	delta := end - stream.highestReceived
	if end > stream.localMaxData {
		return fmt.Errorf("http3 flow control exceeded: code=0x%x stream=%d max=%d got=%d", uint64(ErrFlowControl), streamID, stream.localMaxData, end)
	}
	if s.receivedBytes+delta > s.localMaxData {
		return fmt.Errorf("http3 connection flow control exceeded: code=0x%x max=%d got=%d", uint64(ErrFlowControl), s.localMaxData, s.receivedBytes+delta)
	}
	stream.highestReceived = end
	s.receivedBytes += delta
	return nil
}

func (s *quicFlowControlState) consumeStream(streamID uint64, consumedThrough uint64) {
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	if consumedThrough <= stream.consumedBytes {
		return
	}
	if consumedThrough > stream.highestReceived {
		consumedThrough = stream.highestReceived
	}
	if consumedThrough <= stream.consumedBytes {
		return
	}
	delta := consumedThrough - stream.consumedBytes
	stream.consumedBytes = consumedThrough
	s.consumedBytes += delta
	stream.localMaxData += delta
	s.localMaxData += delta
	stream.pendingMaxData = true
	s.pendingMaxData = true
}

func (s *quicFlowControlState) consumeAllStream(streamID uint64) {
	if s == nil {
		return
	}
	stream := s.ensureStream(streamID)
	// Clear the stream-level pending flag: the stream is finishing so there
	// is no point advertising a larger receive window to the peer.
	stream.pendingMaxData = false
	consumedThrough := stream.highestReceived
	if consumedThrough <= stream.consumedBytes {
		return
	}
	delta := consumedThrough - stream.consumedBytes
	stream.consumedBytes = consumedThrough
	s.consumedBytes += delta
	stream.localMaxData += delta
	s.localMaxData += delta
	s.pendingMaxData = true
}

func (s *quicFlowControlState) observeMaxData(maximumData uint64) {
	s.ensureDefaults()
	if maximumData > s.peerMaxData {
		s.peerMaxData = maximumData
	}
}

func (s *quicFlowControlState) observeMaxStreamData(streamID uint64, maximumData uint64) {
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	if maximumData > stream.peerMaxData {
		stream.peerMaxData = maximumData
	}
}

func (s *quicFlowControlState) setPeerMaxData(maxData uint64) {
	if s == nil {
		return
	}
	s.ensureDefaults()
	if maxData > 0 {
		s.peerMaxData = maxData
	}
}

func (s *quicFlowControlState) setPeerStreamMaxData(streamID uint64, maxData uint64) {
	if s == nil {
		return
	}
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	if maxData > 0 {
		stream.peerMaxData = maxData
	}
}

func (s *quicFlowControlState) observeSentPacket(packet QUICSentPacket) error {
	if s == nil {
		return nil
	}
	s.ensureDefaults()
	for _, frame := range packet.Frames {
		if !isQUICStreamFrame(frame.FrameType) {
			continue
		}
		if err := s.observeSentStream(frame.StreamID, frame.Offset, len(frame.Payload)); err != nil {
			return err
		}
	}
	return nil
}

func (s *quicFlowControlState) observeSentStream(streamID uint64, offset uint64, payloadLen int) error {
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	end := offset + uint64(payloadLen)
	if end <= stream.highestSent {
		return nil
	}
	delta := end - stream.highestSent
	if end > stream.peerMaxData {
		return fmt.Errorf("http3 peer stream flow control exceeded: code=0x%x stream=%d max=%d got=%d", uint64(ErrFlowControl), streamID, stream.peerMaxData, end)
	}
	if s.sentBytes+delta > s.peerMaxData {
		return fmt.Errorf("http3 peer connection flow control exceeded: code=0x%x max=%d got=%d", uint64(ErrFlowControl), s.peerMaxData, s.sentBytes+delta)
	}
	stream.highestSent = end
	s.sentBytes += delta
	return nil
}

// ObserveSentPacketForStream logs the flow control state for STREAM frames
// to help diagnose ERR_CLOSING issues. It returns the same result as
// observeSentPacket.
func (s *quicFlowControlState) ObserveSentPacketForStream(streamID uint64, offset, payloadLen int) error {
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	highestSentBefore := stream.highestSent
	err := s.observeSentStream(streamID, uint64(offset), payloadLen)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	log.Printf("http3 flow control: stream=%d offset=%d len=%d end=%d highest_sent_before=%d peer_max_data=%d conn_sent=%d err=%s",
		streamID, offset, payloadLen, uint64(offset)+uint64(payloadLen), highestSentBefore, stream.peerMaxData, s.sentBytes, errStr)
	return err
}
func (s *quicFlowControlState) canSendStream(streamID uint64, offset uint64, payloadLen int) bool {
	if s == nil {
		return false
	}
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	end := offset + uint64(payloadLen)
	if end <= stream.highestSent {
		return true
	}
	delta := end - stream.highestSent
	return end <= stream.peerMaxData && s.sentBytes+delta <= s.peerMaxData
}

func (s *quicFlowControlState) availableStreamWindow(streamID uint64) uint64 {
	if s == nil {
		return 0
	}
	s.ensureDefaults()
	stream := s.ensureStream(streamID)
	streamRemaining := uint64(0)
	if stream.peerMaxData > stream.highestSent {
		streamRemaining = stream.peerMaxData - stream.highestSent
	}
	connectionRemaining := uint64(0)
	if s.peerMaxData > s.sentBytes {
		connectionRemaining = s.peerMaxData - s.sentBytes
	}
	if streamRemaining < connectionRemaining {
		return streamRemaining
	}
	return connectionRemaining
}

func (s *quicFlowControlState) drainPendingMaxFrames() ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	s.ensureDefaults()
	if !s.pendingMaxData && len(s.streams) == 0 {
		return nil, nil
	}
	var out []byte
	var err error
	if s.pendingMaxData {
		out, err = AppendQUICMaxDataFrame(out, s.localMaxData)
		if err != nil {
			return nil, err
		}
		s.pendingMaxData = false
	}
	streamIDs := make([]uint64, 0, len(s.streams))
	for streamID, stream := range s.streams {
		if stream.pendingMaxData {
			streamIDs = append(streamIDs, streamID)
		}
	}
	sort.Slice(streamIDs, func(i, j int) bool { return streamIDs[i] < streamIDs[j] })
	for _, streamID := range streamIDs {
		stream := s.streams[streamID]
		out, err = AppendQUICMaxStreamDataFrame(out, streamID, stream.localMaxData)
		if err != nil {
			return nil, err
		}
		stream.pendingMaxData = false
	}
	return out, nil
}

func (s *quicFlowControlState) snapshot() QUICFlowControlSnapshot {
	if s == nil {
		return QUICFlowControlSnapshot{}
	}
	s.ensureDefaults()
	snapshot := QUICFlowControlSnapshot{
		ReceivedBytes:  s.receivedBytes,
		ConsumedBytes:  s.consumedBytes,
		LocalMaxData:   s.localMaxData,
		PeerMaxData:    s.peerMaxData,
		SentBytes:      s.sentBytes,
		PendingMaxData: s.pendingMaxData,
	}
	if len(s.streams) > 0 {
		snapshot.Streams = make(map[uint64]QUICStreamFlowControlSnapshot, len(s.streams))
		for streamID, stream := range s.streams {
			snapshot.Streams[streamID] = QUICStreamFlowControlSnapshot{
				HighestReceived: stream.highestReceived,
				ConsumedBytes:   stream.consumedBytes,
				LocalMaxData:    stream.localMaxData,
				PeerMaxData:     stream.peerMaxData,
				HighestSent:     stream.highestSent,
				PendingMaxData:  stream.pendingMaxData,
			}
		}
	}
	return snapshot
}

func (s *quicFlowControlState) ensureDefaults() {
	if s.localMaxData == 0 {
		s.localMaxData = quicInitialConnectionReceiveWindow
	}
	if s.localStreamData == 0 {
		s.localStreamData = quicInitialStreamReceiveWindow
	}
	if s.peerMaxData == 0 {
		s.peerMaxData = ^uint64(0)
	}
	if s.streams == nil {
		s.streams = make(map[uint64]*quicFlowControlStream)
	}
}

func (s *quicFlowControlState) ensureStream(streamID uint64) *quicFlowControlStream {
	s.ensureDefaults()
	stream, ok := s.streams[streamID]
	if ok {
		return stream
	}
	stream = &quicFlowControlStream{localMaxData: s.localStreamData, peerMaxData: ^uint64(0)}
	s.streams[streamID] = stream
	return stream
}
