package core

import (
	"bytes"
	"strconv"

	"github.com/dnsoa/go/allocator"
)

var (
	HeaderContentLength    = []byte("Content-Length")
	HeaderTransferEncoding = []byte("Transfer-Encoding")
	HeaderConnection       = []byte("Connection")
	HeaderContentType      = []byte("Content-Type")
	HeaderLocation         = []byte("Location")
	HeaderHost             = []byte("Host")
)

type HeaderEntry struct {
	Name  []byte
	Value []byte
	buf   *allocator.Buffer
}

type Headers struct {
	entries []HeaderEntry
}

type bufferState struct {
	buf     *allocator.Buffer
	kept    bool
	removed bool
}

func NewHeaders() Headers {
	return Headers{}
}

func (h *Headers) Reset() {
	releaseUniqueBuffers(h.entries)
	for i := range h.entries {
		h.entries[i] = HeaderEntry{}
	}
	h.entries = h.entries[:0]
}

func releaseUniqueBuffers(entries []HeaderEntry) {
	if len(entries) == 0 {
		return
	}
	var seenBufs [8]*allocator.Buffer
	seen := seenBufs[:0]
	for i := range entries {
		buf := entries[i].buf
		if buf == nil {
			continue
		}
		duplicate := false
		for _, known := range seen {
			if known == buf {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		seen = append(seen, buf)
		_ = allocator.Release(buf)
	}
}

func markBufferState(states []bufferState, buf *allocator.Buffer, kept bool) []bufferState {
	if buf == nil {
		return states
	}
	for i := range states {
		if states[i].buf != buf {
			continue
		}
		if kept {
			states[i].kept = true
		} else {
			states[i].removed = true
		}
		return states
	}
	state := bufferState{buf: buf}
	if kept {
		state.kept = true
	} else {
		state.removed = true
	}
	return append(states, state)
}

func releaseRemovedExclusiveBuffers(states []bufferState) {
	if len(states) == 0 {
		return
	}
	for i := range states {
		if !states[i].removed || states[i].kept || states[i].buf == nil {
			continue
		}
		_ = allocator.Release(states[i].buf)
	}
}

func (h *Headers) Count() int {
	return len(h.entries)
}

func (h *Headers) Entries() []HeaderEntry {
	return h.entries
}

func (h *Headers) Append(name, value []byte) {
	totalLen := len(name) + len(value)
	buf := allocator.Get(totalLen)
	nLen := len(name)
	copy((*buf)[:nLen], name)
	copy((*buf)[nLen:], value)
	h.entries = append(h.entries, HeaderEntry{
		Name:  (*buf)[:nLen],
		Value: (*buf)[nLen:],
		buf:   buf,
	})
}

// AppendString appends a header entry with string name and value.
// Avoids temporary []byte allocations by converting directly into the owned buffer.
func (h *Headers) AppendString(name, value string) {
	totalLen := len(name) + len(value)
	buf := allocator.Get(totalLen)
	nLen := len(name)
	copy((*buf)[:nLen], name)
	copy((*buf)[nLen:], value)
	h.entries = append(h.entries, HeaderEntry{
		Name:  (*buf)[:nLen],
		Value: (*buf)[nLen:],
		buf:   buf,
	})
}

func (h *Headers) Set(name, value []byte) {
	h.RemoveAll(name)
	h.Append(name, value)
}

// SetString sets a header entry with string name and value.
func (h *Headers) SetString(name, value string) {
	h.RemoveAllString(name)
	h.AppendString(name, value)
}

// equalFoldString compares a []byte with a string case-insensitively
// without allocating a temporary []byte from the string.
func equalFoldString(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		cb := b[i]
		cs := s[i]
		if cb >= 'A' && cb <= 'Z' {
			cb += 0x20
		}
		if cs >= 'A' && cs <= 'Z' {
			cs += 0x20
		}
		if cb != cs {
			return false
		}
	}
	return true
}

func (h *Headers) Get(name string) []byte {
	for i := range h.entries {
		if equalFoldString(h.entries[i].Name, name) {
			return h.entries[i].Value
		}
	}
	return nil
}

func (h *Headers) Contains(name string) bool {
	return h.Get(name) != nil
}

func (h *Headers) GetAll(name string) [][]byte {
	values := make([][]byte, 0, 2)
	for i := range h.entries {
		if equalFoldString(h.entries[i].Name, name) {
			values = append(values, h.entries[i].Value)
		}
	}
	return values
}

func (h *Headers) RemoveAll(name []byte) {
	if len(h.entries) == 0 {
		return
	}
	var stateBuf [8]bufferState
	states := stateBuf[:0]
	out := h.entries[:0]
	for _, entry := range h.entries {
		removed := bytes.EqualFold(entry.Name, name)
		states = markBufferState(states, entry.buf, !removed)
		if removed {
			continue
		}
		out = append(out, entry)
	}
	for i := len(out); i < len(h.entries); i++ {
		h.entries[i] = HeaderEntry{}
	}
	releaseRemovedExclusiveBuffers(states)
	h.entries = out
}

// RemoveAllString removes all entries with the given header name (string).
// Avoids temporary []byte allocation from string conversion.
func (h *Headers) RemoveAllString(name string) {
	if len(h.entries) == 0 {
		return
	}
	var stateBuf [8]bufferState
	states := stateBuf[:0]
	out := h.entries[:0]
	for _, entry := range h.entries {
		removed := equalFoldString(entry.Name, name)
		states = markBufferState(states, entry.buf, !removed)
		if removed {
			continue
		}
		out = append(out, entry)
	}
	for i := len(out); i < len(h.entries); i++ {
		h.entries[i] = HeaderEntry{}
	}
	releaseRemovedExclusiveBuffers(states)
	h.entries = out
}

func (h *Headers) Clone() Headers {
	if len(h.entries) == 0 {
		return NewHeaders()
	}

	totalLen := 0
	for _, entry := range h.entries {
		totalLen += len(entry.Name) + len(entry.Value)
	}

	buf := allocator.Get(totalLen)
	entries := make([]HeaderEntry, len(h.entries))
	offset := 0
	for i, entry := range h.entries {
		nameLen := len(entry.Name)
		valueLen := len(entry.Value)
		copy((*buf)[offset:offset+nameLen], entry.Name)
		copy((*buf)[offset+nameLen:offset+nameLen+valueLen], entry.Value)
		entries[i] = HeaderEntry{
			Name:  (*buf)[offset : offset+nameLen],
			Value: (*buf)[offset+nameLen : offset+nameLen+valueLen],
			buf:   buf,
		}
		offset += nameLen + valueLen
	}
	return Headers{entries: entries}
}

func (h *Headers) ContentLength() (int, bool) {
	value := h.Get("Content-Length")
	if value == nil {
		return 0, false
	}
	n, err := strconv.Atoi(string(value))
	if err != nil {
		return 0, false
	}
	return n, true
}

func (h *Headers) IsChunked() bool {
	value := h.Get("Transfer-Encoding")
	return value != nil && ContainsTokenCI(value, []byte("chunked"))
}

func (h *Headers) IsKeepAlive(version Version) bool {
	value := h.Get("Connection")
	if value != nil {
		if ContainsTokenCI(value, []byte("close")) {
			return false
		}
		if ContainsTokenCI(value, []byte("keep-alive")) {
			return true
		}
	}
	return version == VersionHTTP11 || version == VersionHTTP2 || version == VersionHTTP3
}

func (h *Headers) Serialize(dst []byte) []byte {
	for _, entry := range h.entries {
		dst = append(dst, entry.Name...)
		dst = append(dst, ':', ' ')
		dst = append(dst, entry.Value...)
		dst = append(dst, '\r', '\n')
	}
	return dst
}
