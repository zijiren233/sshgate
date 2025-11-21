package informer

import "errors"

var (
	// ErrCacheSyncFailed is returned when informer cache sync fails
	ErrCacheSyncFailed = errors.New("failed to sync informer caches")
)
