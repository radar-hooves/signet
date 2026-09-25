//go:build !windows

// lock_unix.go: the cross-process single-flight lock guarding a cold or expired
// bearer cache.
//
// The lock is taken on the CACHE FILE ITSELF, not a companion lockfile: key
// custody permits exactly two on-disk artefacts (`20-key-custody.md` §3), and a
// third one — even an empty one — invites the reader to wonder which rule it
// sits under. flock is advisory and costs nothing here.
package attest

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockWait bounds how long a caller waits for another process's mint before
// giving up on the lock. It is long enough for one real mint under
// contention — a broker round trip plus a hardware signature, the thing
// every waiter is actually queued behind — so a caller still inside it is
// waiting on ordinary work, not a stuck one. A package var so a test can
// shrink it without a real 30s wait.
var lockWait = 30 * time.Second

// ErrLockTimeout is returned when lockWait elapses without acquiring the mint
// lock: another process has held it the whole time, which is longer than one
// real mint takes, so that holder is stuck rather than merely slow (a hung
// broker call with no deadline, a crash between opening the file and
// releasing — flock itself is released on process exit, so a genuinely dead
// holder cannot cause this; a live, wedged one can). It names the identity the
// lock guards since flock exposes no holder PID to name instead.
type ErrLockTimeout struct {
	BrokerURL   string
	Fingerprint string
	Waited      time.Duration
}

func (e *ErrLockTimeout) Error() string {
	return fmt.Sprintf(
		"signet: waited %s for another process to finish minting a bearer for %s (key %s), which is longer than one mint should take; that process is still holding the lock",
		e.Waited, e.BrokerURL, e.Fingerprint)
}

// lockCache waits up to lockWait for this process to hold the cache file's
// lock, returning the release function and, on a timeout, a *ErrLockTimeout.
// Every OTHER failure path returns a no-op release and a nil error: the lock
// only ever saves a redundant attestation, so being unable to even attempt one
// (a permission error, a missing directory) must never stop a caller getting
// its bearer. A timeout is different — the lock IS held, by a process that has
// had long enough to finish — so it is reported rather than silently
// swallowed, even though the caller still proceeds unlocked afterwards.
//
// The wait is a blocking Flock on a background goroutine, raced against
// lockWait, not a poll loop: flock has no wait-with-timeout syscall, and
// polling either sleeps too long per waiter (adding that sleep to every one of
// a 60-wide herd's drain time) or burns a busy CPU spin. A blocking Flock lets
// the kernel wake the very next waiter the instant the holder releases, which
// is what lets 60 waiters drain in the order they arrived rather than one poll
// tick at a time. On a timeout the goroutine is left running against the
// original fd — it either succeeds, harmlessly locking and never unlocking an
// fd nothing else references, or blocks forever — closed out only when this
// one-shot process exits, which every caller of lockCache does shortly after.
func lockCache(brokerURL, fingerprint string) (func(), error) {
	path, err := cachePath(brokerURL, fingerprint)
	if err != nil {
		return func() {}, nil
	}
	// O_CREATE: on a cold start there is no cache file yet, and the waiters
	// still need something to serialise on. saveCache replaces this inode by
	// rename, which is why the holder writes BEFORE releasing — a waiter that
	// acquires the old inode's lock then re-reads the path sees the new file.
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return func() {}, nil
	}
	release := func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}

	acquired := make(chan error, 1)
	go func() { acquired <- syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }()

	select {
	case err := <-acquired:
		if err != nil {
			f.Close()
			return func() {}, nil
		}
		return release, nil
	case <-time.After(lockWait):
		return func() {}, &ErrLockTimeout{BrokerURL: brokerURL, Fingerprint: fingerprint, Waited: lockWait}
	}
}
