package core

import (
	"math/bits"
	"sync"
)

const defaultMaxPoolBits = 18

type BytePool struct {
	maxBits int
	maxSize int
	pools   []sync.Pool
}

func NewBytePool(maxBits int) *BytePool {
	if maxBits <= 0 {
		maxBits = defaultMaxPoolBits
	}
	p := &BytePool{
		maxBits: maxBits,
		maxSize: 1 << maxBits,
		pools:   make([]sync.Pool, maxBits+1),
	}
	for idx := range p.pools {
		size := 1 << idx
		p.pools[idx].New = func() any {
			return make([]byte, size)
		}
	}
	return p
}

func (p *BytePool) Get(size int) []byte {
	if size <= 0 {
		return nil
	}
	if size > p.maxSize {
		return make([]byte, size)
	}
	idx := bits.Len(uint(size - 1))
	b := p.pools[idx].Get().([]byte)
	return b[:size]
}

func (p *BytePool) GetEmpty(capacity int) []byte {
	if capacity <= 0 {
		return nil
	}
	return p.Get(capacity)[:0]
}

func (p *BytePool) Put(buf []byte) {
	if buf == nil {
		return
	}
	capacity := cap(buf)
	if capacity == 0 || capacity > p.maxSize || capacity&(capacity-1) != 0 {
		return
	}
	idx := bits.Len(uint(capacity)) - 1
	p.pools[idx].Put(buf[:capacity])
}

func (p *BytePool) Grow(buf []byte, extra int) []byte {
	if extra <= 0 {
		return buf
	}
	if cap(buf)-len(buf) >= extra {
		return buf
	}
	newBuf := p.GetEmpty(len(buf) + extra)
	newBuf = append(newBuf, buf...)
	p.Put(buf)
	return newBuf
}

var DefaultBytePool = NewBytePool(defaultMaxPoolBits)
