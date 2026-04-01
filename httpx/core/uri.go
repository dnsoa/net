package core

import (
	"bytes"
	"errors"
	"strconv"

	"github.com/dnsoa/go/allocator"
)

type URI struct {
	Raw      []byte
	Scheme   []byte
	UserInfo []byte
	Host     []byte
	Path     []byte
	Query    []byte
	Fragment []byte
	Port     uint16
	HasPort  bool
	rawBuf   *allocator.Buffer
}

func (u *URI) Reset() {
	alloc := getDefaultAllocator()
	if u.rawBuf != nil {
		alloc.Put(u.rawBuf)
	}
	*u = URI{Path: []byte("/")}
}

func (u *URI) ParseString(raw string) error {
	alloc := getDefaultAllocator()
	if u.rawBuf != nil {
		alloc.Put(u.rawBuf)
	}
	buf := alloc.Get(len(raw))
	copy(*buf, raw)
	u.rawBuf = buf
	u.parse(*buf)
	return nil
}

func (u *URI) ParseOwned(raw []byte) error {
	alloc := getDefaultAllocator()
	if u.rawBuf != nil {
		alloc.Put(u.rawBuf)
	}
	buf := alloc.Get(len(raw))
	copy(*buf, raw)
	u.rawBuf = buf
	u.parse(*buf)
	return nil
}

func (u *URI) parse(raw []byte) {
	u.Raw = raw
	u.Scheme = nil
	u.UserInfo = nil
	u.Host = nil
	u.Query = nil
	u.Fragment = nil
	u.Port = 0
	u.HasPort = false
	u.Path = []byte("/")

	remaining := raw
	if idx := bytes.Index(remaining, []byte("://")); idx >= 0 {
		u.Scheme = remaining[:idx]
		remaining = remaining[idx+3:]
	}
	if idx := bytes.IndexByte(remaining, '#'); idx >= 0 {
		u.Fragment = remaining[idx+1:]
		remaining = remaining[:idx]
	}
	if idx := bytes.IndexByte(remaining, '?'); idx >= 0 {
		u.Query = remaining[idx+1:]
		remaining = remaining[:idx]
	}
	if idx := bytes.IndexByte(remaining, '/'); idx >= 0 {
		u.Path = remaining[idx:]
		remaining = remaining[:idx]
	}
	if idx := bytes.IndexByte(remaining, '@'); idx >= 0 {
		u.UserInfo = remaining[:idx]
		remaining = remaining[idx+1:]
	}
	if len(remaining) > 0 && remaining[0] == '[' {
		if idx := bytes.IndexByte(remaining, ']'); idx >= 0 {
			u.Host = remaining[1:idx]
			remaining = remaining[idx+1:]
		}
	}
	if idx := bytes.LastIndexByte(remaining, ':'); idx >= 0 {
		if port, err := strconv.Atoi(string(remaining[idx+1:])); err == nil {
			u.Port = uint16(port)
			u.HasPort = true
			remaining = remaining[:idx]
		}
	}
	if len(remaining) > 0 && u.Host == nil {
		u.Host = remaining
	}
	if len(u.Path) == 0 {
		u.Path = []byte("/")
	}
}

func (u URI) EffectivePort() uint16 {
	if u.HasPort {
		return u.Port
	}
	if bytes.EqualFold(u.Scheme, []byte("https")) || bytes.EqualFold(u.Scheme, []byte("wss")) {
		return 443
	}
	if bytes.EqualFold(u.Scheme, []byte("ftp")) {
		return 21
	}
	return 80
}

func (u URI) IsTLS() bool {
	return bytes.EqualFold(u.Scheme, []byte("https")) || bytes.EqualFold(u.Scheme, []byte("wss"))
}

func (u URI) RequestTarget(dst []byte) []byte {
	if len(u.Path) == 0 {
		dst = append(dst, '/')
	} else {
		dst = append(dst, u.Path...)
	}
	if len(u.Query) > 0 {
		dst = append(dst, '?')
		dst = append(dst, u.Query...)
	}
	return dst
}

func (u URI) Format(dst []byte) []byte {
	if len(u.Scheme) > 0 {
		dst = append(dst, u.Scheme...)
		dst = append(dst, "://"...)
	}
	if len(u.UserInfo) > 0 {
		dst = append(dst, u.UserInfo...)
		dst = append(dst, '@')
	}
	if len(u.Host) > 0 {
		dst = append(dst, u.Host...)
	}
	if u.HasPort {
		dst = append(dst, ':')
		dst = strconv.AppendInt(dst, int64(u.Port), 10)
	}
	if len(u.Path) > 0 {
		dst = append(dst, u.Path...)
	}
	if len(u.Query) > 0 {
		dst = append(dst, '?')
		dst = append(dst, u.Query...)
	}
	if len(u.Fragment) > 0 {
		dst = append(dst, '#')
		dst = append(dst, u.Fragment...)
	}
	return dst
}

func ParseURI(raw string) (URI, error) {
	var uri URI
	if err := uri.ParseString(raw); err != nil {
		return URI{}, err
	}
	if len(uri.Raw) == 0 {
		return URI{}, errors.New("empty uri")
	}
	return uri, nil
}
