// piv_busy_test.go: hardware-free tests for openFirstYubiKey's retry against a
// transient PC/SC sharing violation (0x8010000B) — another process (this
// host's SSH agent, or a concurrent signet identity on the same physical
// YubiKey) briefly holding the PC/SC-exclusive connection. Exercises the
// pivOpen/pivCards/pivSleep seams with a fake card; no real hardware needed.
package signer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// withPIVOpenSeams swaps pivCards/pivOpen/pivSleep/pivBusyRetries for the
// duration of a test and restores them afterwards.
func withPIVOpenSeams(t *testing.T, open func(string) (*piv.YubiKey, error), retries int) {
	t.Helper()
	savedCards, savedOpen, savedSleep, savedRetries := pivCards, pivOpen, pivSleep, pivBusyRetries
	pivCards = func() ([]string, error) { return []string{"fake reader"}, nil }
	pivOpen = open
	pivSleep = func(time.Duration) {} // tests never actually wait out the backoff
	pivBusyRetries = retries
	t.Cleanup(func() {
		pivCards, pivOpen, pivSleep, pivBusyRetries = savedCards, savedOpen, savedSleep, savedRetries
	})
}

// A sharing violation that clears after a couple of attempts must be ridden
// out silently: the caller gets a successful open, never an error.
func TestOpenFirstYubiKey_RetriesTransientSharingViolationThenSucceeds(t *testing.T) {
	var attempts int32
	withPIVOpenSeams(t, func(string) (*piv.YubiKey, error) {
		if atomic.AddInt32(&attempts, 1) <= 2 {
			return nil, errors.New(pivSharingViolation)
		}
		return nil, nil // stand-in success; downstream card use is out of scope here
	}, 6)

	if _, err := openFirstYubiKey(); err != nil {
		t.Fatalf("openFirstYubiKey: want nil error once contention clears, got %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("attempts = %d, want 3 (2 failures + 1 success)", got)
	}
}

// Contention that never clears must give up after the bounded retry budget
// with a distinctly typed "card busy" error, never hang forever and never be
// silently reported as a hardware fault.
func TestOpenFirstYubiKey_ExhaustsRetriesReturnsCardBusy(t *testing.T) {
	var attempts int32
	withPIVOpenSeams(t, func(string) (*piv.YubiKey, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, errors.New(pivSharingViolation)
	}, 3)

	_, err := openFirstYubiKey()
	if err == nil {
		t.Fatal("openFirstYubiKey: want an error when contention never clears")
	}
	if want := int32(4); atomic.LoadInt32(&attempts) != want { // 1 initial + 3 retries
		t.Fatalf("attempts = %d, want %d", attempts, want)
	}
	if !IsCardBusy(err) {
		t.Fatalf("IsCardBusy(%v) = false, want true", err)
	}
	if !strings.Contains(err.Error(), pivSharingViolation) {
		t.Fatalf("error %q must still carry the underlying PC/SC message", err)
	}
}

// A non-transient open failure (no card present, a reader vanishing mid-call)
// must surface immediately, unretried, and must never be classified as busy —
// a genuinely absent card is not "try again in a moment".
func TestOpenFirstYubiKey_NonTransientErrorNotRetried(t *testing.T) {
	var attempts int32
	withPIVOpenSeams(t, func(string) (*piv.YubiKey, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, errors.New("the operation requires a Smart Card, but no Smart Card is currently in the device")
	}, 6)

	_, err := openFirstYubiKey()
	if err == nil {
		t.Fatal("openFirstYubiKey: want an error when the card is genuinely absent")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("attempts = %d, want 1 (a non-transient error must not be retried)", got)
	}
	if IsCardBusy(err) {
		t.Fatalf("a non-transient error must not be classified as card busy: %v", err)
	}
}

// The realistic case this fix targets: a burst of concurrent openers (a
// Claude Code session fanning out ~85 MCP server spawns) racing against an
// external contender for the same physical card (modelled here as a CAS-guarded
// flag, standing in for this host's SSH agent grabbing the card mid-burst).
// Every opener must eventually succeed — none may surface the sharing
// violation to its caller.
func TestOpenFirstYubiKey_BurstSucceedsDespiteConcurrentContention(t *testing.T) {
	var held int32 // 0 = free, 1 = held by the "external" process for this instant
	withPIVOpenSeams(t, func(string) (*piv.YubiKey, error) {
		if !atomic.CompareAndSwapInt32(&held, 0, 1) {
			return nil, errors.New(pivSharingViolation)
		}
		defer atomic.StoreInt32(&held, 0)
		return nil, nil
	}, 500) // no real backoff wait in this test, so a generous ceiling costs nothing

	const n = 90
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = openFirstYubiKey()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("opener %d failed despite retry: %v", i, err)
		}
	}
}

func TestIsCardBusy(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"card busy marker", fmt.Errorf("PIV: open %q: card busy (gave up after 6 retries): %s", "x", pivSharingViolation), true},
		{"raw sharing violation, no marker", errors.New(pivSharingViolation), false},
		{"unrelated error", errors.New("no key in slot 9c"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsCardBusy(c.err); got != c.want {
				t.Errorf("IsCardBusy(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
