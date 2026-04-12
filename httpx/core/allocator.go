package core

import (
	"sync"
	"sync/atomic"

	"github.com/dnsoa/go/allocator"
)

var (
	defaultAlloc = sync.OnceValue(func() *allocator.Allocator {
		return allocator.New()
	})
	defaultAllocPtr atomic.Pointer[allocator.Allocator]
)

// SetDefaultAllocator sets the global default allocator for the core package.
// After calling this, all AcquireRequest/AcquireResponse objects and Parser-built
// objects will automatically use pooled buffers for header/URI allocations.
// Should be called once during program initialization.
func SetDefaultAllocator(a *allocator.Allocator) {
	if a == nil {
		return
	}
	defaultAllocPtr.Store(a)
}

// DefaultAllocator returns the package-level allocator shared by core objects.
func DefaultAllocator() *allocator.Allocator {
	if p := defaultAllocPtr.Load(); p != nil {
		return p
	}
	p := defaultAlloc()
	if defaultAllocPtr.CompareAndSwap(nil, p) {
		return p
	}
	return defaultAllocPtr.Load()
}
