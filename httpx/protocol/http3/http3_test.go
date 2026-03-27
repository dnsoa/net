package http3

import "testing"

func TestVarIntRoundTrip(t *testing.T) {
	values := []uint64{25, 15293, 494878333, 151288809941952652}
	for _, value := range values {
		encoded, err := AppendVarInt(nil, value)
		if err != nil {
			t.Fatalf("encode %d: %v", value, err)
		}
		decoded, n, err := DecodeVarInt(encoded)
		if err != nil {
			t.Fatalf("decode %d: %v", value, err)
		}
		if decoded != value || n != len(encoded) {
			t.Fatalf("roundtrip mismatch value=%d decoded=%d n=%d encoded=%v", value, decoded, n, encoded)
		}
	}
}

func TestFrameHeaderRoundTrip(t *testing.T) {
	header := FrameHeader{Type: uint64(FrameHeaders), Length: 1234}
	encoded, err := header.Encode(nil)
	if err != nil {
		t.Fatalf("encode frame header: %v", err)
	}
	decoded, n, err := DecodeFrameHeader(encoded)
	if err != nil {
		t.Fatalf("decode frame header: %v", err)
	}
	if decoded != header || n != len(encoded) {
		t.Fatalf("frame header mismatch got=%+v n=%d want=%+v len=%d", decoded, n, header, len(encoded))
	}
}
