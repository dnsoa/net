// Package http3 implements HTTP/3 primitives used by the Go port.
package http3

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/dnsoa/net/httpx/core"
)

type HeaderField struct {
	Name  string
	Value string
}

type qpackStaticEntry struct {
	name  string
	value string
}

type qpackDynamicEntry struct {
	name          string
	value         string
	absoluteIndex uint64
	size          uint64
}

type qpackDynamicTable struct {
	entries     []qpackDynamicEntry
	currentSize uint64
	maxSize     uint64
	insertCount uint64
}

func (t *qpackDynamicTable) setMaxSize(maxSize uint64) {
	t.maxSize = maxSize
	for t.currentSize > t.maxSize && len(t.entries) > 0 {
		t.evictOldest()
	}
}

func (t *qpackDynamicTable) evictOldest() {
	if len(t.entries) == 0 {
		return
	}
	last := len(t.entries) - 1
	t.currentSize -= t.entries[last].size
	t.entries = t.entries[:last]
}

func (t *qpackDynamicTable) insert(name, value string) (uint64, bool) {
	entrySize := uint64(len(name) + len(value) + 32)
	if t.maxSize == 0 || entrySize > t.maxSize {
		return 0, false
	}
	for t.currentSize+entrySize > t.maxSize && len(t.entries) > 0 {
		t.evictOldest()
	}
	absoluteIndex := t.insertCount
	t.entries = append([]qpackDynamicEntry{{
		name:          name,
		value:         value,
		absoluteIndex: absoluteIndex,
		size:          entrySize,
	}}, t.entries...)
	t.currentSize += entrySize
	t.insertCount++
	return absoluteIndex, true
}

func (t *qpackDynamicTable) getRelative(index uint64) (qpackDynamicEntry, bool) {
	if index >= uint64(len(t.entries)) {
		return qpackDynamicEntry{}, false
	}
	return t.entries[index], true
}

func (t *qpackDynamicTable) getAbsolute(index uint64) (qpackDynamicEntry, bool) {
	for _, entry := range t.entries {
		if entry.absoluteIndex == index {
			return entry, true
		}
	}
	return qpackDynamicEntry{}, false
}

func (t *qpackDynamicTable) findNameValue(name, value string, insertCountLimit uint64) (qpackDynamicEntry, bool) {
	for _, entry := range t.entries {
		if entry.absoluteIndex >= insertCountLimit {
			continue
		}
		if entry.name == name && entry.value == value {
			return entry, true
		}
	}
	return qpackDynamicEntry{}, false
}

func (t *qpackDynamicTable) findName(name string, insertCountLimit uint64) (qpackDynamicEntry, bool) {
	for _, entry := range t.entries {
		if entry.absoluteIndex >= insertCountLimit {
			continue
		}
		if entry.name == name {
			return entry, true
		}
	}
	return qpackDynamicEntry{}, false
}

var qpackStaticTable = []qpackStaticEntry{
	{name: ":authority", value: ""},
	{name: ":path", value: "/"},
	{name: "age", value: "0"},
	{name: "content-disposition", value: ""},
	{name: "content-length", value: "0"},
	{name: "cookie", value: ""},
	{name: "date", value: ""},
	{name: "etag", value: ""},
	{name: "if-modified-since", value: ""},
	{name: "if-none-match", value: ""},
	{name: "last-modified", value: ""},
	{name: "link", value: ""},
	{name: "location", value: ""},
	{name: "referer", value: ""},
	{name: "set-cookie", value: ""},
	{name: ":method", value: "CONNECT"},
	{name: ":method", value: "DELETE"},
	{name: ":method", value: "GET"},
	{name: ":method", value: "HEAD"},
	{name: ":method", value: "OPTIONS"},
	{name: ":method", value: "POST"},
	{name: ":method", value: "PUT"},
	{name: ":scheme", value: "http"},
	{name: ":scheme", value: "https"},
	{name: ":status", value: "103"},
	{name: ":status", value: "200"},
	{name: ":status", value: "304"},
	{name: ":status", value: "404"},
	{name: ":status", value: "503"},
	{name: "accept", value: "*/*"},
	{name: "accept", value: "application/dns-message"},
	{name: "accept-encoding", value: "gzip, deflate, br"},
	{name: "accept-ranges", value: "bytes"},
	{name: "access-control-allow-headers", value: "cache-control"},
	{name: "access-control-allow-headers", value: "content-type"},
	{name: "access-control-allow-origin", value: "*"},
	{name: "cache-control", value: "max-age=0"},
	{name: "cache-control", value: "max-age=2592000"},
	{name: "cache-control", value: "max-age=604800"},
	{name: "cache-control", value: "no-cache"},
	{name: "cache-control", value: "no-store"},
	{name: "cache-control", value: "public, max-age=31536000"},
	{name: "content-encoding", value: "br"},
	{name: "content-encoding", value: "gzip"},
	{name: "content-type", value: "application/dns-message"},
	{name: "content-type", value: "application/javascript"},
	{name: "content-type", value: "application/json"},
	{name: "content-type", value: "application/x-www-form-urlencoded"},
	{name: "content-type", value: "image/gif"},
	{name: "content-type", value: "image/jpeg"},
	{name: "content-type", value: "image/png"},
	{name: "content-type", value: "text/css"},
	{name: "content-type", value: "text/html; charset=utf-8"},
	{name: "content-type", value: "text/plain"},
	{name: "content-type", value: "text/plain;charset=utf-8"},
	{name: "range", value: "bytes=0-"},
	{name: "strict-transport-security", value: "max-age=31536000"},
	{name: "strict-transport-security", value: "max-age=31536000; includesubdomains"},
	{name: "strict-transport-security", value: "max-age=31536000; includesubdomains; preload"},
	{name: "vary", value: "accept-encoding"},
	{name: "vary", value: "origin"},
	{name: "x-content-type-options", value: "nosniff"},
	{name: "x-xss-protection", value: "1; mode=block"},
	{name: ":status", value: "100"},
	{name: ":status", value: "204"},
	{name: ":status", value: "206"},
	{name: ":status", value: "302"},
	{name: ":status", value: "400"},
	{name: ":status", value: "403"},
	{name: ":status", value: "421"},
	{name: ":status", value: "425"},
	{name: ":status", value: "500"},
	{name: "accept-language", value: ""},
	{name: "access-control-allow-credentials", value: "FALSE"},
	{name: "access-control-allow-credentials", value: "TRUE"},
	{name: "access-control-allow-headers", value: "*"},
	{name: "access-control-allow-methods", value: "get"},
	{name: "access-control-allow-methods", value: "get, post, options"},
	{name: "access-control-allow-methods", value: "options"},
	{name: "access-control-expose-headers", value: "content-length"},
	{name: "access-control-request-headers", value: "content-type"},
	{name: "access-control-request-method", value: "get"},
	{name: "access-control-request-method", value: "post"},
	{name: "alt-svc", value: "clear"},
	{name: "authorization", value: ""},
	{name: "content-security-policy", value: "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{name: "early-data", value: "1"},
	{name: "expect-ct", value: ""},
	{name: "forwarded", value: ""},
	{name: "if-range", value: ""},
	{name: "origin", value: ""},
	{name: "purpose", value: "prefetch"},
	{name: "server", value: ""},
	{name: "timing-allow-origin", value: "*"},
	{name: "upgrade-insecure-requests", value: "1"},
	{name: "user-agent", value: ""},
	{name: "x-forwarded-for", value: ""},
	{name: "x-frame-options", value: "deny"},
	{name: "x-frame-options", value: "sameorigin"},
}

type QpackCodec struct {
	mu                 sync.Mutex
	localTable         qpackDynamicTable
	remoteTable        qpackDynamicTable
	pendingEncoder     []byte
	pendingDecoder     []byte
	knownReceivedCount uint64
	decoderAckCount    uint64
	localCapacity      uint64
	remoteCapacity     uint64
	localCapacitySent  bool
}

func NewQpackCodec() *QpackCodec {
	return &QpackCodec{}
}

func (c *QpackCodec) SetLocalCapacity(capacity uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localTable.setMaxSize(capacity)
	if c.localCapacity == capacity && c.localCapacitySent {
		return
	}
	c.localCapacity = capacity
	c.localCapacitySent = true
	c.pendingEncoder = appendPrefixedInt(c.pendingEncoder, 5, 0x20, capacity)
	if c.knownReceivedCount > c.localTable.insertCount {
		c.knownReceivedCount = c.localTable.insertCount
	}
}

func (c *QpackCodec) SetRemoteCapacity(capacity uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteCapacity = capacity
	c.remoteTable.setMaxSize(capacity)
	if c.decoderAckCount > c.remoteTable.insertCount {
		c.decoderAckCount = c.remoteTable.insertCount
	}
}

func (c *QpackCodec) DrainEncoderInstructions() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingEncoder) == 0 {
		return nil
	}
	out := append([]byte(nil), c.pendingEncoder...)
	c.pendingEncoder = c.pendingEncoder[:0]
	return out
}

func (c *QpackCodec) DrainDecoderInstructions() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingDecoder) == 0 {
		return nil
	}
	out := append([]byte(nil), c.pendingDecoder...)
	c.pendingDecoder = c.pendingDecoder[:0]
	return out
}

func (c *QpackCodec) ApplyEncoderInstructions(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	startInsertCount := c.remoteTable.insertCount
	offset := 0
	for offset < len(data) {
		first := data[offset]
		switch {
		case first&0x80 != 0:
			isStatic := first&0x40 != 0
			index, consumed, err := decodePrefixedInt(data[offset:], 6)
			if err != nil {
				return err
			}
			offset += consumed
			value, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return err
			}
			offset += read
			var name string
			if isStatic {
				if int(index) >= len(qpackStaticTable) {
					return errors.New("http3 qpack static name index out of range")
				}
				name = qpackStaticTable[index].name
			} else {
				entry, ok := c.remoteTable.getRelative(index)
				if !ok {
					return errors.New("http3 qpack dynamic name index out of range")
				}
				name = entry.name
			}
			c.remoteTable.insert(name, value)
		case first&0x40 != 0:
			offset++
			name, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return err
			}
			offset += read
			value, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return err
			}
			offset += read
			c.remoteTable.insert(name, value)
		case first&0x20 != 0:
			capacity, consumed, err := decodePrefixedInt(data[offset:], 5)
			if err != nil {
				return err
			}
			offset += consumed
			c.remoteTable.setMaxSize(capacity)
		case first&0xE0 == 0x00:
			index, consumed, err := decodePrefixedInt(data[offset:], 5)
			if err != nil {
				return err
			}
			offset += consumed
			entry, ok := c.remoteTable.getRelative(index)
			if !ok {
				return errors.New("http3 qpack duplicate index out of range")
			}
			c.remoteTable.insert(entry.name, entry.value)
		default:
			return errors.New("http3 unsupported qpack encoder instruction")
		}
	}
	if c.remoteTable.insertCount > startInsertCount && c.remoteTable.insertCount > c.decoderAckCount {
		c.pendingDecoder = appendPrefixedInt(c.pendingDecoder, 6, 0x00, c.remoteTable.insertCount-c.decoderAckCount)
		c.decoderAckCount = c.remoteTable.insertCount
	}
	return nil
}

func (c *QpackCodec) ApplyDecoderInstructions(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	offset := 0
	for offset < len(data) {
		first := data[offset]
		switch {
		case first&0x80 != 0:
			_, consumed, err := decodePrefixedInt(data[offset:], 7)
			if err != nil {
				return err
			}
			offset += consumed
		case first&0x40 != 0:
			_, consumed, err := decodePrefixedInt(data[offset:], 6)
			if err != nil {
				return err
			}
			offset += consumed
		default:
			increment, consumed, err := decodePrefixedInt(data[offset:], 6)
			if err != nil {
				return err
			}
			offset += consumed
			c.knownReceivedCount += increment
			if c.knownReceivedCount > c.localTable.insertCount {
				c.knownReceivedCount = c.localTable.insertCount
			}
		}
	}
	return nil
}

func (c *QpackCodec) EncodeRequest(req *core.Request) ([]byte, error) {
	fields := make([]HeaderField, 0, req.Headers.Count()+4)
	fields = append(fields,
		HeaderField{Name: ":method", Value: req.Method.String()},
		HeaderField{Name: ":scheme", Value: http3RequestScheme(req)},
		HeaderField{Name: ":authority", Value: http3RequestAuthority(req)},
		HeaderField{Name: ":path", Value: string(req.URI.RequestTarget(nil))},
	)
	for _, entry := range req.Headers.Entries() {
		name := strings.ToLower(string(entry.Name))
		if shouldSkipHTTP3Header(name) {
			continue
		}
		fields = append(fields, HeaderField{Name: name, Value: string(entry.Value)})
	}
	return c.EncodeFields(fields)
}

func (c *QpackCodec) EncodeResponse(resp *core.Response) ([]byte, error) {
	fields := make([]HeaderField, 0, resp.Headers.Count()+1)
	fields = append(fields, HeaderField{Name: ":status", Value: strconv.Itoa(resp.Status.Code)})
	for _, entry := range resp.Headers.Entries() {
		name := strings.ToLower(string(entry.Name))
		if shouldSkipHTTP3Header(name) {
			continue
		}
		fields = append(fields, HeaderField{Name: name, Value: string(entry.Value)})
	}
	return c.EncodeFields(fields)
}

func (c *QpackCodec) EncodeTrailers(trailers *core.Headers) ([]byte, error) {
	fields := make([]HeaderField, 0, trailers.Count())
	for _, entry := range trailers.Entries() {
		name := strings.ToLower(string(entry.Name))
		if shouldSkipHTTP3Header(name) {
			return nil, errors.New("http3 trailers contain disallowed header")
		}
		fields = append(fields, HeaderField{Name: name, Value: string(entry.Value)})
	}
	return c.EncodeFields(fields)
}

func (c *QpackCodec) DecodeRequest(block []byte) (*core.Request, error) {
	fields, err := c.DecodeFields(block)
	if err != nil {
		return nil, err
	}
	var method string
	var scheme string
	var authority string
	var path string
	req := core.AcquireRequest()
	req.Version = core.VersionHTTP3
	for _, field := range fields {
		switch field.Name {
		case ":method":
			method = field.Value
		case ":scheme":
			scheme = field.Value
		case ":authority":
			authority = field.Value
		case ":path":
			path = field.Value
		default:
			req.Headers.AppendString(field.Name, field.Value)
		}
	}
	parsedMethod, ok := core.ParseMethodBytes([]byte(method))
	if !ok {
		core.ReleaseRequest(req)
		return nil, errors.New("http3 unsupported request method")
	}
	req.Method = parsedMethod
	if path == "" {
		path = "/"
	}
	if scheme == "" {
		scheme = "https"
	}
	uri := path
	if authority != "" {
		uri = scheme + "://" + authority + path
	}
	if err := req.URI.ParseString(uri); err != nil {
		core.ReleaseRequest(req)
		return nil, err
	}
	if authority != "" && req.Headers.Get("Host") == nil {
		req.Headers.Set(core.HeaderHost, []byte(authority))
	}
	return req, nil
}

func (c *QpackCodec) DecodeResponse(block []byte) (*core.Response, error) {
	fields, err := c.DecodeFields(block)
	if err != nil {
		return nil, err
	}
	resp := core.AcquireResponse()
	resp.Version = core.VersionHTTP3
	for _, field := range fields {
		if field.Name == ":status" {
			code, err := strconv.Atoi(field.Value)
			if err != nil {
				core.ReleaseResponse(resp)
				return nil, errors.New("http3 invalid status")
			}
			resp.Status = core.NewStatus(code)
			continue
		}
		resp.Headers.AppendString(field.Name, field.Value)
	}
	return resp, nil
}

func (c *QpackCodec) DecodeTrailers(block []byte) (core.Headers, error) {
	fields, err := c.DecodeFields(block)
	if err != nil {
		return core.Headers{}, err
	}
	trailers := core.NewHeaders()
	for _, field := range fields {
		if strings.HasPrefix(field.Name, ":") {
			trailers.Reset()
			return core.Headers{}, errors.New("http3 trailers must not contain pseudo headers")
		}
		trailers.AppendString(field.Name, field.Value)
	}
	return trailers, nil
}

func (c *QpackCodec) EncodeFields(fields []HeaderField) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body := make([]byte, 0, len(fields)*16)
	requiredInsertCount := uint64(0)
	for _, field := range fields {
		if idx, ok := findStaticNameValue(field.Name, field.Value); ok {
			body = appendPrefixedInt(body, 6, 0xC0, uint64(idx))
			continue
		}
		if c.knownReceivedCount > 0 {
			if entry, ok := c.localTable.findNameValue(field.Name, field.Value, c.knownReceivedCount); ok {
				requiredInsertCount = c.knownReceivedCount
				body = appendPrefixedInt(body, 6, 0x80, requiredInsertCount-entry.absoluteIndex-1)
				continue
			}
			if entry, ok := c.localTable.findName(field.Name, c.knownReceivedCount); ok {
				requiredInsertCount = c.knownReceivedCount
				body = appendPrefixedInt(body, 4, 0x40, requiredInsertCount-entry.absoluteIndex-1)
				body = appendQpackString(body, field.Value)
				continue
			}
		}
		if c.shouldInsertDynamic(field) {
			c.queueInsertLocked(field)
		}
		if idx, ok := findStaticName(field.Name); ok {
			body = appendPrefixedInt(body, 4, 0x50, uint64(idx))
			body = appendQpackString(body, field.Value)
			continue
		}
		body = append(body, 0x20)
		body = appendQpackString(body, field.Name)
		body = appendQpackString(body, field.Value)
	}
	head := appendPrefixedInt(nil, 8, 0x00, requiredInsertCount)
	head = appendPrefixedInt(head, 7, 0x00, 0)
	return append(head, body...), nil
}

func (c *QpackCodec) DecodeFields(data []byte) ([]HeaderField, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(data) < 2 {
		return nil, errors.New("http3 invalid qpack block")
	}
	requiredInsertCount, n, err := decodePrefixedInt(data, 8)
	if err != nil {
		return nil, err
	}
	if len(data[n:]) == 0 {
		return nil, errors.New("http3 invalid qpack base")
	}
	deltaBase, consumed, err := decodePrefixedInt(data[n:], 7)
	if err != nil {
		return nil, err
	}
	offset := n + consumed
	base, err := computeQpackBase(requiredInsertCount, deltaBase, false)
	if err != nil {
		return nil, err
	}
	if requiredInsertCount > c.remoteTable.insertCount {
		return nil, errors.New("http3 qpack required insert count unavailable")
	}
	fields := make([]HeaderField, 0, 8)
	for offset < len(data) {
		first := data[offset]
		switch {
		case first&0x80 != 0:
			idx, consumed, err := decodePrefixedInt(data[offset:], 6)
			if err != nil {
				return nil, err
			}
			offset += consumed
			if first&0x40 != 0 {
				if int(idx) >= len(qpackStaticTable) {
					return nil, errors.New("http3 static index out of range")
				}
				entry := qpackStaticTable[idx]
				fields = append(fields, HeaderField{Name: entry.name, Value: entry.value})
				continue
			}
			entry, ok := resolvePreBaseEntry(c.remoteTable, base, idx)
			if !ok {
				return nil, errors.New("http3 dynamic index out of range")
			}
			fields = append(fields, HeaderField{Name: entry.name, Value: entry.value})
		case first&0x40 != 0:
			idx, consumed, err := decodePrefixedInt(data[offset:], 4)
			if err != nil {
				return nil, err
			}
			offset += consumed
			var name string
			if first&0x10 != 0 {
				if int(idx) >= len(qpackStaticTable) {
					return nil, errors.New("http3 static name index out of range")
				}
				name = qpackStaticTable[idx].name
			} else {
				entry, ok := resolvePreBaseEntry(c.remoteTable, base, idx)
				if !ok {
					return nil, errors.New("http3 dynamic name index out of range")
				}
				name = entry.name
			}
			value, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return nil, err
			}
			offset += read
			fields = append(fields, HeaderField{Name: name, Value: value})
		case first&0x20 != 0:
			offset++
			name, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return nil, err
			}
			offset += read
			value, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return nil, err
			}
			offset += read
			fields = append(fields, HeaderField{Name: name, Value: value})
		case first&0x10 != 0:
			idx, consumed, err := decodePrefixedInt(data[offset:], 4)
			if err != nil {
				return nil, err
			}
			offset += consumed
			entry, ok := resolvePostBaseEntry(c.remoteTable, base, idx)
			if !ok {
				return nil, errors.New("http3 post-base index out of range")
			}
			fields = append(fields, HeaderField{Name: entry.name, Value: entry.value})
		default:
			idx, consumed, err := decodePrefixedInt(data[offset:], 3)
			if err != nil {
				return nil, err
			}
			offset += consumed
			entry, ok := resolvePostBaseEntry(c.remoteTable, base, idx)
			if !ok {
				return nil, errors.New("http3 post-base name index out of range")
			}
			value, read, err := decodeQpackString(data[offset:])
			if err != nil {
				return nil, err
			}
			offset += read
			fields = append(fields, HeaderField{Name: entry.name, Value: value})
		}
	}
	if requiredInsertCount > c.decoderAckCount {
		c.pendingDecoder = appendPrefixedInt(c.pendingDecoder, 6, 0x00, requiredInsertCount-c.decoderAckCount)
		c.decoderAckCount = requiredInsertCount
	}
	return fields, nil
}

func (c *QpackCodec) shouldInsertDynamic(field HeaderField) bool {
	if c.localCapacity == 0 || strings.HasPrefix(field.Name, ":") {
		return false
	}
	if _, ok := findStaticNameValue(field.Name, field.Value); ok {
		return false
	}
	if _, ok := c.localTable.findNameValue(field.Name, field.Value, c.localTable.insertCount); ok {
		return false
	}
	return true
}

func (c *QpackCodec) queueInsertLocked(field HeaderField) {
	start := len(c.pendingEncoder)
	if idx, ok := findStaticName(field.Name); ok {
		c.pendingEncoder = appendPrefixedInt(c.pendingEncoder, 6, 0xC0, uint64(idx))
		c.pendingEncoder = appendQpackString(c.pendingEncoder, field.Value)
	} else {
		c.pendingEncoder = append(c.pendingEncoder, 0x40)
		c.pendingEncoder = appendQpackString(c.pendingEncoder, field.Name)
		c.pendingEncoder = appendQpackString(c.pendingEncoder, field.Value)
	}
	if _, ok := c.localTable.insert(field.Name, field.Value); ok {
		return
	}
	c.pendingEncoder = c.pendingEncoder[:start]
}

func computeQpackBase(requiredInsertCount uint64, deltaBase uint64, negative bool) (uint64, error) {
	if negative {
		if requiredInsertCount == 0 || deltaBase >= requiredInsertCount {
			return 0, errors.New("http3 invalid qpack base")
		}
		return requiredInsertCount - deltaBase - 1, nil
	}
	return requiredInsertCount + deltaBase, nil
}

func resolvePreBaseEntry(table qpackDynamicTable, base uint64, relativeIndex uint64) (qpackDynamicEntry, bool) {
	if relativeIndex >= base {
		return qpackDynamicEntry{}, false
	}
	return table.getAbsolute(base - relativeIndex - 1)
}

func resolvePostBaseEntry(table qpackDynamicTable, base uint64, postBaseIndex uint64) (qpackDynamicEntry, bool) {
	return table.getAbsolute(base + postBaseIndex)
}

func findStaticNameValue(name, value string) (int, bool) {
	for idx, entry := range qpackStaticTable {
		if entry.name == name && entry.value == value {
			return idx, true
		}
	}
	return 0, false
}

func findStaticName(name string) (int, bool) {
	for idx, entry := range qpackStaticTable {
		if entry.name == name {
			return idx, true
		}
	}
	return 0, false
}

func appendQpackString(dst []byte, value string) []byte {
	dst = appendPrefixedInt(dst, 7, 0x00, uint64(len(value)))
	return append(dst, value...)
}

func decodeQpackString(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, errors.New("http3 truncated qpack string")
	}
	if data[0]&0x80 != 0 {
		return "", 0, errors.New("http3 huffman qpack strings not supported")
	}
	length, consumed, err := decodePrefixedInt(data, 7)
	if err != nil {
		return "", 0, err
	}
	start := consumed
	end := start + int(length)
	if end > len(data) {
		return "", 0, errors.New("http3 truncated qpack string payload")
	}
	return string(data[start:end]), end, nil
}

func appendPrefixedInt(dst []byte, prefixBits uint8, prefixMask byte, value uint64) []byte {
	maxFirst := uint64((1 << prefixBits) - 1)
	if value < maxFirst {
		return append(dst, prefixMask|byte(value))
	}
	dst = append(dst, prefixMask|byte(maxFirst))
	value -= maxFirst
	for value >= 128 {
		dst = append(dst, byte(value%128+128))
		value /= 128
	}
	return append(dst, byte(value))
}

func decodePrefixedInt(data []byte, prefixBits uint8) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("http3 truncated integer")
	}
	prefixMask := byte((1 << prefixBits) - 1)
	value := uint64(data[0] & prefixMask)
	if value < uint64(prefixMask) {
		return value, 1, nil
	}
	consumed := 1
	shift := uint(0)
	for {
		if consumed >= len(data) {
			return 0, 0, errors.New("http3 truncated integer continuation")
		}
		b := data[consumed]
		consumed++
		value += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return value, consumed, nil
}

func http3RequestScheme(req *core.Request) string {
	if len(req.URI.Scheme) > 0 {
		return string(req.URI.Scheme)
	}
	if req.URI.IsTLS() {
		return "https"
	}
	return "https"
}

func http3RequestAuthority(req *core.Request) string {
	if len(req.URI.Host) == 0 {
		if host := req.Headers.Get("Host"); host != nil {
			return string(host)
		}
		return ""
	}
	authority := string(req.URI.Host)
	if req.URI.HasPort {
		authority += ":" + strconv.Itoa(int(req.URI.Port))
	}
	return authority
}

func shouldSkipHTTP3Header(name string) bool {
	switch name {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "host":
		return true
	default:
		return false
	}
}
