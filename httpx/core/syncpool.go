package core

import "sync"

type SyncPool[T any] struct {
	p   sync.Pool
	new func() T
}

func NewSyncPool[T any](newFn func() T) SyncPool[T] {
	return SyncPool[T]{new: newFn}
}

func (p *SyncPool[T]) Get() T {
	if v := p.p.Get(); v != nil {
		return v.(T)
	}
	return p.new()
}

func (p *SyncPool[T]) Put(v T) {
	p.p.Put(v)
}
