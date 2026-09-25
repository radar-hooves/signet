//go:build !windows

// lock_unix_test.go: the bounded wait on the cross-process mint lock. A
// blocking flock with no timeout hangs forever behind a holder that never
// releases (a hung broker call with no deadline, a bug mid-mint); these tests
// prove the wait is bounded and that hitting the bound is reported, not
// silently swallowed.
package attest

import (
	"errors"
	"testing"
	"time"
)

// shrinkLockWait replaces lockWait with a test-sized value for the duration of
// the test, so a timeout test runs in milliseconds, not 30s.
func shrinkLockWait(t *testing.T, wait time.Duration) {
	t.Helper()
	saved := lockWait
	lockWait = wait
	t.Cleanup(func() { lockWait = saved })
}

// TestLockCache_WaitsThenSucceeds proves a caller that arrives while another
// holds the lock waits for it, then acquires it the moment it is released —
// the normal contended case, not the timeout.
func TestLockCache_WaitsThenSucceeds(t *testing.T) {
	setTempHome(t)
	shrinkLockWait(t, time.Second)

	unlock1, err := lockCache("https://broker", "fp")
	if err != nil {
		t.Fatalf("first lockCache: %v", err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		unlock1()
		close(released)
	}()

	start := time.Now()
	unlock2, err := lockCache("https://broker", "fp")
	if err != nil {
		t.Fatalf("second lockCache: %v", err)
	}
	defer unlock2()

	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("second caller acquired the lock after %s, want it to wait for the release", elapsed)
	}
	<-released
}

// TestLockCache_TimesOutOnStaleHolder proves a holder that never releases
// produces a bounded wait and a typed *ErrLockTimeout naming the identity,
// rather than blocking the waiter forever.
func TestLockCache_TimesOutOnStaleHolder(t *testing.T) {
	setTempHome(t)
	shrinkLockWait(t, 20*time.Millisecond)

	unlock1, err := lockCache("https://broker", "fp")
	if err != nil {
		t.Fatalf("first lockCache: %v", err)
	}
	defer unlock1() // held for the whole test — models the stuck process

	start := time.Now()
	release2, err := lockCache("https://broker", "fp")
	defer release2()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("lockCache: want ErrLockTimeout, got nil (the never-released holder should have blocked this waiter out)")
	}
	var timeoutErr *ErrLockTimeout
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("lockCache error = %v (%T), want *ErrLockTimeout", err, err)
	}
	if timeoutErr.BrokerURL != "https://broker" || timeoutErr.Fingerprint != "fp" {
		t.Errorf("ErrLockTimeout = %+v, want it to name the broker and fingerprint it timed out on", timeoutErr)
	}
	if elapsed < 20*time.Millisecond {
		t.Errorf("timed out after %s, want at least lockWait (20ms)", elapsed)
	}
}
