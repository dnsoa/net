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
	alloc   *allocator.Allocator
}

func NewHeaders() Headers {
	return Headers{}
}

func (h *Headers) SetAllocator(alloc *allocator.Allocator) {
	h.alloc = alloc
}

func (h *Headers) Reset() {
	for i := range h.entries {
		if h.entries[i].buf != nil && h.alloc != nil {
			h.alloc.Put(h.entries[i].buf)
		}
		h.entries[i] = HeaderEntry{}
	}
	h.entries = h.entries[:0]
}

func (h *Headers) Count() int {
	return len(h.entries)
}

func (h *Headers) Entries() []HeaderEntry {
	return h.entries
}

func (h *Headers) Append(name, value []byte) {
	totalLen := len(name) + len(value)
	if h.alloc != nil {
		buf := h.alloc.Get(totalLen)
		nLen := len(name)
		copy((*buf)[:nLen], name)
		copy((*buf)[nLen:], value)
		h.entries = append(h.entries, HeaderEntry{
			Name:  (*buf)[:nLen],
			Value: (*buf)[nLen:],
			buf:   buf,
		})
	} else {
		owned := make([]byte, totalLen)
		copy(owned[:len(name)], name)
		copy(owned[len(name):], value)
		h.entries = append(h.entries, HeaderEntry{
			Name:  owned[:len(name)],
			Value: owned[len(name):],
		})
	}
}

func (h *Headers) AppendString(name, value string) {
	h.Append([]byte(name), []byte(value))
}

func (h *Headers) Set(name, value []byte) {
	h.RemoveAll(name)
	h.Append(name, value)
}

func (h *Headers) SetString(name, value string) {
	h.Set([]byte(name), []byte(value))
}

func (h *Headers) Get(name string) []byte {
	needle := []byte(name)
	for i := range h.entries {
		if bytes.EqualFold(h.entries[i].Name, needle) {
			return h.entries[i].Value
		}
	}
	return nil
}

func (h *Headers) Contains(name string) bool {
	return h.Get(name) != nil
}

func (h *Headers) GetAll(name string) [][]byte {
	needle := []byte(name)
	values := make([][]byte, 0, 2)
	for i := range h.entries {
		if bytes.EqualFold(h.entries[i].Name, needle) {
			values = append(values, h.entries[i].Value)
		}
	}
	return values
}

func (h *Headers) RemoveAll(name []byte) {
	out := h.entries[:0]
	for _, entry := range h.entries {
		if bytes.EqualFold(entry.Name, name) {
			if entry.buf != nil && h.alloc != nil {
				h.alloc.Put(entry.buf)
			}
			continue
		}
		out = append(out, entry)
	}
	h.entries = out
}

func (h *Headers) Clone() Headers {
	clone := NewHeaders()
	clone.alloc = h.alloc
	for _, entry := range h.entries {
		clone.Append(entry.Name, entry.Value)
	}
	return clone
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
	return value != nil && bytes.Contains(bytes.ToLower(value), []byte("chunked"))
}

func (h *Headers) IsKeepAlive(version Version) bool {
	value := h.Get("Connection")
	if value != nil {
		lower := bytes.ToLower(value)
		if bytes.Contains(lower, []byte("close")) {
			return false
		}
		if bytes.Contains(lower, []byte("keep-alive")) {
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
