package core

import (
	"sync"

	"github.com/dnsoa/go/allocator"
)

// defaultAlloc is the package-level allocator set explicitly via SetDefaultAllocator.
var defaultAlloc *allocator.Allocator

var (
	defaultAllocOnce sync.Once
	defaultAllocAuto *allocator.Allocator
)

// SetDefaultAllocator sets the global default allocator for the core package.
// After calling this, all AcquireRequest/AcquireResponse objects and Parser-built
// objects will automatically use pooled buffers for header/URI allocations.
// Should be called once during program initialization.
func SetDefaultAllocator(a *allocator.Allocator) {
	defaultAlloc = a
}

// getDefaultAllocator returns the package-level allocator.
// If SetDefaultAllocator was never called, a default allocator is lazily created.
func getDefaultAllocator() *allocator.Allocator {
	if defaultAlloc != nil {
		return defaultAlloc
	}
	defaultAllocOnce.Do(func() {
		defaultAllocAuto = allocator.New()
	})
	return defaultAllocAuto
}
